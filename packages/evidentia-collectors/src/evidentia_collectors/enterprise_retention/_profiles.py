"""Trusted profile snapshots, exact actor grants and bounded local file reads."""

from __future__ import annotations

import ipaddress
import os
import re
import ssl
import stat
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Literal, Never
from urllib.parse import urlsplit

from ._contracts import ProviderName
from ._credentials import CredentialResolver, EnvironmentCredentialResolver, checked_provider, checked_reference
from ._parsing import parse_strict_json

PROFILE_FILE_LIMIT = 65_536
CA_FILE_LIMIT = 1_048_576
PROFILE_SCHEMA = "enterprise-retention-profiles/v1"
_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_PRIVATE = tuple(ipaddress.ip_network(item) for item in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"))
_PUBLIC4_DENY = tuple(
    ipaddress.ip_network(item)
    for item in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)
_PUBLIC6_ROOT = ipaddress.ip_network("2000::/3")
_PUBLIC6_DENY = tuple(ipaddress.ip_network(item) for item in ("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20"))
_METADATA6 = tuple(ipaddress.ip_address(item) for item in ("fd00:ec2::254", "fd20:ce::254"))


class ProfileError(ValueError):
    """Report invalid operator configuration without paths or values."""

    def __init__(self) -> None:
        super().__init__("profile_configuration_invalid")


class ProfileUnavailable(ValueError):
    """Use one refusal for unknown, wrong-provider and unauthorized profiles."""

    def __init__(self) -> None:
        super().__init__("profile_unavailable")


class AddressPolicyError(ValueError):
    def __init__(self) -> None:
        super().__init__("destination_refused")


def _contained(network: Network, root: Network) -> bool:
    if isinstance(network, ipaddress.IPv4Network) and isinstance(root, ipaddress.IPv4Network):
        return network.subnet_of(root)
    if isinstance(network, ipaddress.IPv6Network) and isinstance(root, ipaddress.IPv6Network):
        return network.subnet_of(root)
    return False


def _canonical_network(value: object) -> Network:
    if type(value) is not str or not 1 <= len(value) <= 43 or not value.isascii() or "%" in value:
        raise AddressPolicyError()
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise AddressPolicyError() from None
    if str(network) != value:
        raise AddressPolicyError()
    return network


def _public_network(network: Network) -> bool:
    if network.version == 4:
        return not any(network.overlaps(block) for block in _PUBLIC4_DENY)
    return _contained(network, _PUBLIC6_ROOT) and not any(network.overlaps(block) for block in _PUBLIC6_DENY)


@dataclass(frozen=True, slots=True, repr=False)
class AddressPolicy:
    mode: Literal["public", "private"]
    cidrs: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if type(self.mode) is not str or self.mode not in ("public", "private") or type(self.cidrs) is not tuple:
            raise AddressPolicyError()
        if len(self.cidrs) > 32 or (self.mode == "private" and not self.cidrs):
            raise AddressPolicyError()
        networks = tuple(_canonical_network(item) for item in self.cidrs)
        if len(set(self.cidrs)) != len(self.cidrs):
            raise AddressPolicyError()
        allowed = (
            all(any(_contained(network, root) for root in _PRIVATE) for network in networks)
            if self.mode == "private"
            else all(_public_network(network) for network in networks)
        )
        if not allowed:
            raise AddressPolicyError()

    def __repr__(self) -> str:
        return "AddressPolicy(<redacted>)"


def validated_policy(value: object) -> AddressPolicy:
    try:
        if type(value) is not AddressPolicy:
            raise AddressPolicyError()
        return AddressPolicy(value.mode, value.cidrs)
    except (AttributeError, TypeError, ValueError):
        raise AddressPolicyError() from None


def _address(value: object) -> Address:
    if type(value) is not str or not 1 <= len(value) <= 45 or not value.isascii() or "%" in value:
        raise AddressPolicyError()
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise AddressPolicyError() from None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        raise AddressPolicyError()
    return parsed


def classify_answers(policy: AddressPolicy, values: object) -> tuple[str, ...]:
    """Approve the complete answer set before making any address available to a pin."""
    checked = validated_policy(policy)
    if type(values) is not tuple or not values:
        raise AddressPolicyError()
    networks = tuple(_canonical_network(item) for item in checked.cidrs)
    accepted: list[str] = []
    for item in values:
        address = _address(item)
        if checked.mode == "private":
            allowed = address not in _METADATA6 and any(address in network for network in _PRIVATE)
        elif address.version == 4:
            allowed = not any(address in network for network in _PUBLIC4_DENY)
        else:
            allowed = address in _PUBLIC6_ROOT and not any(address in network for network in _PUBLIC6_DENY)
        if not allowed or (networks and not any(address in network for network in networks)):
            raise AddressPolicyError()
        canonical = str(address)
        if canonical not in accepted:
            accepted.append(canonical)
    return tuple(accepted)


def _alias(value: object) -> str:
    if type(value) is not str or _ALIAS.fullmatch(value) is None:
        raise ProfileError()
    return value


def _principal(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 1024 or not value.strip():
        raise ProfileError()
    try:
        if len(value.encode("utf-8")) > 1024:
            raise ProfileError()
    except UnicodeError:
        raise ProfileError() from None
    return value


def _origin(value: object) -> tuple[str, str, int]:
    if type(value) is not str or not 1 <= len(value) <= 300 or any(c < "!" or c > "~" for c in value):
        raise ProfileError()
    if "\\" in value or "%" in value:
        raise ProfileError()
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
        if (
            parts.scheme != "https"
            or not host
            or port is None
            or not 1 <= port <= 65535
            or parts.username is not None
            or parts.password is not None
            or parts.path
            or parts.query
            or parts.fragment
        ):
            raise ProfileError()
        try:
            parsed = _address(host)
        except AddressPolicyError:
            labels = host.split(".")
            if (
                len(host) > 253
                or host != host.lower()
                or not re.search(r"[a-z]", labels[-1])
                or any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels)
                or (len(labels) == 1 and re.fullmatch(r"0x[0-9a-f]+", host) is not None)
            ):
                raise ProfileError() from None
            canonical_host = host
        else:
            if str(parsed) != host:
                raise ProfileError()
            canonical_host = "[" + host + "]" if parsed.version == 6 else host
        canonical = f"https://{canonical_host}:{port}"
        if canonical != value:
            raise ProfileError()
        return canonical, host, port
    except (ValueError, TypeError):
        raise ProfileError() from None


def _pem_framing(text: str) -> None:
    """Scan certificate framing once without overlapping regular-expression paths."""
    whitespace = " \t\r\n"
    base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n"
    begin = "-----BEGIN CERTIFICATE-----"
    end = "-----END CERTIFICATE-----"
    cursor = 0
    count = 0
    while cursor < len(text):
        while cursor < len(text) and text[cursor] in whitespace:
            cursor += 1
        if cursor == len(text):
            break
        if not text.startswith(begin, cursor):
            raise ProfileError()
        cursor += len(begin)
        if text.startswith("\r\n", cursor):
            cursor += 2
        elif text.startswith("\n", cursor):
            cursor += 1
        else:
            raise ProfileError()
        finish = text.find(end, cursor)
        if finish <= cursor or any(char not in base64_chars for char in text[cursor:finish]):
            raise ProfileError()
        cursor = finish + len(end)
        count += 1
    if count == 0:
        raise ProfileError()


def _pem_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    if type(value) is not bytes or not 1 <= len(value) <= CA_FILE_LIMIT:
        raise ProfileError()
    try:
        text = value.decode("ascii", errors="strict")
        _pem_framing(text)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=text)
        if context.cert_store_stats()["x509"] < 1:
            raise ProfileError()
        return value
    except (OSError, ValueError, UnicodeError):
        raise ProfileError() from None


@dataclass(frozen=True, slots=True, repr=False)
class FrozenProfile:
    alias: str
    provider: ProviderName
    origin: str
    credential_ref: str
    address_policy: AddressPolicy
    ca_bytes: bytes | None = None
    api_principals: frozenset[str] = frozenset()
    allow_local_cli: bool = False

    def __post_init__(self) -> None:
        try:
            _alias(self.alias)
            checked_provider(self.provider)
            checked_reference(self.credential_ref)
            origin, host, _ = _origin(self.origin)
            policy = validated_policy(self.address_policy)
            try:
                ipaddress.ip_address(host)
            except ValueError:
                pass
            else:
                classify_answers(policy, (host,))
            if self.provider == "google-vault" and (
                origin != "https://vault.googleapis.com:443" or policy.mode != "public"
            ):
                raise ProfileError()
            if type(self.api_principals) is not frozenset or len(self.api_principals) > 128:
                raise ProfileError()
            principals = frozenset(_principal(item) for item in self.api_principals)
            if type(self.allow_local_cli) is not bool:
                raise ProfileError()
            object.__setattr__(self, "address_policy", policy)
            object.__setattr__(self, "api_principals", principals)
            object.__setattr__(self, "ca_bytes", _pem_bytes(self.ca_bytes))
        except (ValueError, TypeError, AttributeError):
            raise ProfileError() from None

    def __repr__(self) -> str:
        return "FrozenProfile(<redacted>)"

    @property
    def host(self) -> str:
        return _origin(self.origin)[1]

    @property
    def port(self) -> int:
        return _origin(self.origin)[2]


def validated_profile(value: object) -> FrozenProfile:
    try:
        if type(value) is not FrozenProfile:
            raise ProfileError()
        return FrozenProfile(
            value.alias,
            value.provider,
            value.origin,
            value.credential_ref,
            value.address_policy,
            value.ca_bytes,
            value.api_principals,
            value.allow_local_cli,
        )
    except (AttributeError, TypeError, ValueError):
        raise ProfileError() from None


def ssl_context(profile: FrozenProfile) -> ssl.SSLContext:
    try:
        selected = validated_profile(profile)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if selected.ca_bytes is None:
            context.load_default_certs(ssl.Purpose.SERVER_AUTH)
        else:
            context.load_verify_locations(cadata=selected.ca_bytes.decode("ascii"))
        if (
            context.verify_mode != ssl.CERT_REQUIRED
            or not context.check_hostname
            or context.keylog_filename is not None
        ):
            raise ProfileError()
        return context
    except (OSError, ValueError, TypeError):
        raise ProfileError() from None


@dataclass(frozen=True, slots=True, repr=False)
class ProfileRegistry:
    profiles: tuple[FrozenProfile, ...] = ()
    resolver: CredentialResolver = field(default_factory=EnvironmentCredentialResolver)

    def __post_init__(self) -> None:
        if type(self.profiles) is not tuple or len(self.profiles) > 32:
            raise ProfileError()
        detached = tuple(validated_profile(item) for item in self.profiles)
        if len({item.alias for item in detached}) != len(detached) or not callable(
            getattr(self.resolver, "resolve", None)
        ):
            raise ProfileError()
        object.__setattr__(self, "profiles", detached)

    def __repr__(self) -> str:
        return "ProfileRegistry(<redacted>)"


def validated_registry(value: object) -> ProfileRegistry:
    try:
        if type(value) is not ProfileRegistry:
            raise ProfileError()
        return ProfileRegistry(value.profiles, value.resolver)
    except (AttributeError, TypeError, ValueError):
        raise ProfileError() from None


class AuthorizedProfile:
    """Carry a detached profile and its trusted in-process resolver after an actor grant."""

    __slots__ = ("_profile", "_resolver")
    _profile: FrozenProfile
    _resolver: CredentialResolver

    def __init__(self, profile: FrozenProfile, resolver: CredentialResolver) -> None:
        object.__setattr__(self, "_profile", validated_profile(profile))
        if not callable(getattr(resolver, "resolve", None)):
            raise ProfileError()
        object.__setattr__(self, "_resolver", resolver)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_profile_capability")

    def __repr__(self) -> str:
        return "AuthorizedProfile(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_profile")

    @property
    def profile(self) -> FrozenProfile:
        return validated_profile(self._profile)

    @property
    def resolver(self) -> CredentialResolver:
        return self._resolver


def _selected(registry: ProfileRegistry, provider: object, alias: object) -> tuple[FrozenProfile, CredentialResolver]:
    try:
        name = _alias(alias)
        kind = checked_provider(provider)
        checked = validated_registry(registry)
    except ValueError:
        raise ProfileUnavailable() from None
    for profile in checked.profiles:
        if profile.alias == name and profile.provider == kind:
            return profile, checked.resolver
    raise ProfileUnavailable()


def authorize_api_profile(
    registry: ProfileRegistry,
    *,
    provider: ProviderName,
    alias: str,
    principal: str,
) -> AuthorizedProfile:
    try:
        actor = _principal(principal)
    except ValueError:
        raise ProfileUnavailable() from None
    profile, resolver = _selected(registry, provider, alias)
    if actor not in profile.api_principals:
        raise ProfileUnavailable()
    return AuthorizedProfile(profile, resolver)


def authorize_cli_profile(registry: ProfileRegistry, *, provider: ProviderName, alias: str) -> AuthorizedProfile:
    profile, resolver = _selected(registry, provider, alias)
    if not profile.allow_local_cli:
        raise ProfileUnavailable()
    return AuthorizedProfile(profile, resolver)


def _fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def _bad_component(part: str) -> bool:
    base = part.partition(".")[0].rstrip(" ").upper()
    return (
        part.endswith((" ", "."))
        or any(c in '<>:"|?*' or ord(c) < 32 for c in part)
        or base in {"CON", "CONIN$", "CONOUT$", "PRN", "AUX", "NUL"}
        or (len(base) == 4 and base[:3] in {"COM", "LPT"} and base[3] in "123456789\u00b9\u00b2\u00b3")
    )


def _local_path(path: Path) -> Path:
    if type(path) is not type(Path()):
        raise ProfileError()
    text = os.fspath(path)
    win = PureWindowsPath(text)
    if (
        not 1 <= len(text) <= 32_768
        or text == "-"
        or "\x00" in text
        or text.startswith(("\\", "//"))
        or (win.drive and not win.root)
        or (os.name == "nt" and path.root and not path.drive)
        or any(_bad_component(part) for part in path.parts if part not in {path.anchor, ".", ".."})
    ):
        raise ProfileError()
    return path if path.is_absolute() else Path.cwd() / path


def _available_identity(info: os.stat_result) -> None:
    if type(info.st_dev) is not int or info.st_dev < 0 or type(info.st_ino) is not int or info.st_ino <= 0:
        raise ProfileError()


def _regular_file(path: Path) -> os.stat_result:
    for parent in reversed(path.parents):
        info = parent.lstat()
        if _reparse(info) or not stat.S_ISDIR(info.st_mode):
            raise ProfileError()
    info = path.lstat()
    _available_identity(info)
    if _reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ProfileError()
    return info


def _read_file(path: Path, *, limit: int) -> bytes:
    descriptor: int | None = None
    try:
        source = _local_path(path)
        before = _regular_file(source)
        if not 0 <= before.st_size <= limit:
            raise ProfileError()
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(source, flags)
        opened = os.fstat(descriptor)
        _available_identity(opened)
        current = _regular_file(source)
        if (
            _reparse(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _fingerprint(opened)[:4] != _fingerprint(before)[:4]
            or _fingerprint(current) != _fingerprint(before)
        ):
            raise ProfileError()
        content = bytearray()
        while chunk := os.read(descriptor, min(8192, limit + 1 - len(content))):
            content.extend(chunk)
            if len(content) > limit:
                raise ProfileError()
        final = os.fstat(descriptor)
        _available_identity(final)
        current = _regular_file(source)
        if (
            _fingerprint(final) != _fingerprint(opened)
            or _fingerprint(current) != _fingerprint(before)
            or final.st_nlink != 1
            or len(content) != opened.st_size
        ):
            raise ProfileError()
        return bytes(content)
    except (OSError, ValueError, TypeError):
        raise ProfileError() from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise ProfileError() from None


def _profile_from_json(value: object, *, base: Path) -> FrozenProfile:
    required = {"alias", "provider", "origin", "credential_ref", "address_policy"}
    optional = {"ca_file", "api_principals", "allow_local_cli"}
    if type(value) is not dict or not required <= value.keys() or value.keys() - required - optional:
        raise ProfileError()
    policy = value["address_policy"]
    if type(policy) is not dict or set(policy) != {"mode", "cidrs"} or type(policy["cidrs"]) is not list:
        raise ProfileError()
    principals = value.get("api_principals", [])
    if type(principals) is not list or len(principals) > 128:
        raise ProfileError()
    checked = [_principal(item) for item in principals]
    if len(set(checked)) != len(checked):
        raise ProfileError()
    ca = value.get("ca_file")
    if ca is not None and (type(ca) is not str or not 1 <= len(ca) <= 32_768):
        raise ProfileError()
    # Validate all scalar/profile fields before opening an optional trusted CA file.
    profile = FrozenProfile(
        value["alias"],
        value["provider"],
        value["origin"],
        value["credential_ref"],
        AddressPolicy(policy["mode"], tuple(policy["cidrs"])),
        api_principals=frozenset(checked),
        allow_local_cli=value.get("allow_local_cli", False),
    )
    if ca is None:
        return profile
    ca_path = Path(ca)
    _local_path(ca_path)
    if not ca_path.is_absolute():
        ca_path = base / ca_path
    content = _read_file(ca_path, limit=CA_FILE_LIMIT)
    return FrozenProfile(
        profile.alias,
        profile.provider,
        profile.origin,
        profile.credential_ref,
        profile.address_policy,
        content,
        profile.api_principals,
        profile.allow_local_cli,
    )


def load_profile_registry(path: Path) -> ProfileRegistry:
    """Read one strict operator configuration snapshot without resolving credentials."""
    try:
        source = _local_path(path)
        value = parse_strict_json(_read_file(source, limit=PROFILE_FILE_LIMIT), max_bytes=PROFILE_FILE_LIMIT)
        if type(value) is not dict or set(value) != {"schema_version", "profiles"}:
            raise ProfileError()
        if value["schema_version"] != PROFILE_SCHEMA:
            raise ProfileError()
        profiles = value["profiles"]
        if type(profiles) is not list or len(profiles) > 32:
            raise ProfileError()
        return ProfileRegistry(tuple(_profile_from_json(item, base=source.parent) for item in profiles))
    except (OSError, ValueError, TypeError):
        raise ProfileError() from None
