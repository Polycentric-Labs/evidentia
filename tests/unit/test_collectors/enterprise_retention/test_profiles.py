"""Trusted configuration grants, bounded local snapshots and address restrictions."""

from __future__ import annotations

import dataclasses
import json
import os
import socket
import ssl
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from evidentia_collectors.enterprise_retention import _profiles as p
from evidentia_collectors.enterprise_retention._contracts import ProviderName

# Authored synthetic CA; its ephemeral signing key was never saved.
CA_PEM = """-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIBATANBgkqhkiG9w0BAQsFADAxMS8wLQYDVQQDDCZTeW50
aGV0aWMgZW50ZXJwcmlzZSByZXRlbnRpb24gdGVzdCBDQTAeFw0yMDAxMDEwMDAw
MDBaFw00MDAxMDEwMDAwMDBaMDExLzAtBgNVBAMMJlN5bnRoZXRpYyBlbnRlcnBy
aXNlIHJldGVudGlvbiB0ZXN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAkZGoJHyq1fQRP8YESGQQLc43CubPRNeTjcFXV8Feh2U41PoiKktKHpzT
y5H+QE3ucyv4ub5IWPY2N8/rRjrRGxqZfHnjyUGg89bLG+xlauUMHnNmPnCZ+KcU
o6r7tLYcK3sGo0QnpjapcCF4GHY9UxYFCyxWy4zfKE0PeoWtvphsqz9JN9UkDBV7
0+GUFp+FnihH5RjSbtvIZA1z8N45z5YRIYePFOHDs3HARbGfg2xydaRDxhzhCN/H
CI0qIf5sm8ym/Vd2MwQvgpoUtfFG8axDShSLCV5nyFPXWO6Ddb/l9xH6HDgbjh1O
00rmDMvQ3Alzrgj4IWUMd6nXFq9qcQIDAQABoxYwFDASBgNVHRMBAf8ECDAGAQH/
AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAqAbmeqJAcJTtxWWTUVtph0SxvaUAZ0y/G
DRrvrAcKLjZXpAwIXgwXe5VPRIh3BrBPcykUG7PWN8ZDXoMy3vLAVj3DJV3dnH65
cG16cak+5yfhmQynUbKicq4K/LMzOeyBqXOFFsZQwkkhPPwmTb2sbtlogNaqL7DD
bYdAXN9WHJq60/HVDhLP9y6Cysyd2I850PuuaVLzaEbjsK+L1SReBqkS47zLULqZ
vrfO+wJy7nagkqZWVU57PaTp5w08uKYcVS5AbeHtYpP6th5Tb2y4TOvxLFFXPvk+
12VdBQqF0WyRlg5Rk6Kbd2UXfGUgH0CDnT5Qur9FOHr/ctpPq35F
-----END CERTIFICATE-----
"""


def profile(**changes: Any) -> p.FrozenProfile:
    values: dict[str, Any] = {
        "alias": "selected",
        "provider": "splunk-enterprise",
        "origin": "https://splunk.example.invalid:8089",
        "credential_ref": "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        "address_policy": p.AddressPolicy("public"),
    }
    return p.FrozenProfile(**(values | changes))


def config(**changes: Any) -> dict[str, Any]:
    return {
        "alias": "selected",
        "provider": "splunk-enterprise",
        "origin": "https://splunk.example.invalid:8089",
        "credential_ref": "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        "address_policy": {"mode": "public", "cidrs": []},
    } | changes


def write_registry(path: Path, profiles: list[dict[str, Any]]) -> None:
    path.write_bytes(json.dumps({"schema_version": p.PROFILE_SCHEMA, "profiles": profiles}).encode())


@pytest.mark.parametrize(
    "mode,cidrs",
    [
        ("public", ()),
        ("public", ("8.8.8.0/24", "2606:4700::/32")),
        ("private", ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")),
    ],
)
def test_policy_accepts_only_supported_whole_ranges(mode: Any, cidrs: tuple[str, ...]) -> None:
    policy = p.AddressPolicy(mode, cidrs)
    assert p.validated_policy(policy) == policy


@pytest.mark.parametrize(
    "mode,cidrs",
    [
        ("private", ()),
        ("unknown", ()),
        (False, ()),
        ("public", []),
        ("public", ("8.8.8.0/24", "8.8.8.0/24")),
        ("public", ("128.0.0.0/2",)),
        ("public", ("2000::/3",)),
        ("public", ("192.88.99.0/24",)),
        ("public", ("10.0.0.0/8",)),
        ("private", ("8.8.8.0/24",)),
        ("private", ("10.0.0.0/7",)),
        ("private", ("172.0.0.0/11",)),
        ("private", ("192.168.0.0/15",)),
        ("private", ("fc00::/6",)),
        ("private", ("fc00::1/64",)),
        ("private", ("FC00::/7",)),
        ("private", ("fc00::/07",)),
        ("public", ("8.8.8.1/24",)),
        ("public", ("8.8.8.0/255.255.255.0",)),
        ("public", ("8.8.8.0/24 ",)),
        ("public", ("::ffff:808:808/128",)),
        ("private", tuple(f"10.0.{i}.0/24" for i in range(33))),
    ],
)
def test_policy_refuses_mixed_noncanonical_or_overbroad_ranges(mode: Any, cidrs: Any) -> None:
    with pytest.raises(p.AddressPolicyError):
        p.AddressPolicy(mode, cidrs)


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "169.254.169.254",
        "100.100.100.200",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "10.0.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "203.0.113.1",
        "192.0.0.9",
        "192.88.99.2",
        "::1",
        "::",
        "fe80::1",
        "fec0::1",
        "fd00::1",
        "2001:db8::1",
        "2002::1",
        "3fff::1",
        "::ffff:8.8.8.8",
        "2606:4700::1%1",
        "bad",
        "",
        None,
    ],
)
def test_any_bad_public_answer_refuses_the_entire_pin(address: Any) -> None:
    for values in ((address, "8.8.8.8"), ("8.8.8.8", address)):
        with pytest.raises(p.AddressPolicyError):
            p.classify_answers(p.AddressPolicy("public"), values)


def test_policy_preserves_valid_dual_stack_and_deduplicates_only_after_admission() -> None:
    assert p.classify_answers(p.AddressPolicy("public"), ("8.8.8.8", "2606:4700::1", "8.8.8.8")) == (
        "8.8.8.8",
        "2606:4700::1",
    )
    policy = p.AddressPolicy("private", ("10.0.0.0/8", "fc00::/7"))
    assert p.classify_answers(policy, ("10.1.2.3", "fd01::1")) == ("10.1.2.3", "fd01::1")
    for address in ("fd00:ec2::254", "fd20:ce::254", "8.8.8.8", "172.16.0.1", "::ffff:10.1.2.3"):
        with pytest.raises(p.AddressPolicyError):
            p.classify_answers(policy, ("10.1.2.3", address))


@pytest.mark.parametrize(
    "origin",
    [
        "http://splunk.example.invalid:8089",
        "https://splunk.example.invalid",
        "https://SPLUNK.example.invalid:8089",
        "https://splunk.example.invalid.:8089",
        "https://splunk.example.invalid:08089",
        "https://splunk.example.invalid:0",
        "https://splunk.example.invalid:65536",
        "https://splunk.example.invalid:8089/",
        "https://splunk.example.invalid:8089?x=1",
        "https://splunk.example.invalid:8089#x",
        "https://u@splunk.example.invalid:8089",
        "https://splunk%2eexample.invalid:8089",
        "https://127.1:8089",
        "https://2130706433:8089",
        "https://0x7f000001:8089",
        "https://127.0.0.1:8089",
        "https://[::ffff:8.8.8.8]:8089",
        "https://[fe80::1%25x]:8089",
        "https://[2606:4700:0:0:0:0:0:1]:443",
        "https://splunk.example.invalid:8089\n",
        " https://splunk.example.invalid:8089",
    ],
)
def test_profiles_refuse_ambiguous_or_unsupported_origins(origin: str) -> None:
    with pytest.raises(p.ProfileError):
        profile(origin=origin)


def test_private_literal_and_vault_origin_are_explicit() -> None:
    selected = profile(origin="https://10.1.2.3:8443", address_policy=p.AddressPolicy("private", ("10.0.0.0/8",)))
    assert selected.host == "10.1.2.3" and selected.port == 8443
    assert profile(provider="google-vault", origin="https://vault.googleapis.com:443")
    with pytest.raises(p.ProfileError):
        profile(provider="google-vault")
    with pytest.raises(p.ProfileError):
        profile(
            provider="google-vault",
            origin="https://vault.googleapis.com:443",
            address_policy=p.AddressPolicy("private", ("10.0.0.0/8",)),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"alias": ""},
        {"alias": "x\n"},
        {"alias": "x" * 65},
        {"allow_local_cli": 1},
        {"allow_local_cli": "true"},
        {"provider": "unknown"},
        {"credential_ref": "OTHER_TOKEN"},
        {"credential_ref": "ENTERPRISE_RETENTION__TOKEN"},
        {"api_principals": {"actor"}},
        {"api_principals": frozenset({" "})},
        {"api_principals": frozenset({"x" * 1025})},
        {"api_principals": frozenset({"\u00e9" * 513})},
        {"api_principals": frozenset(str(i) for i in range(129))},
        {"ca_bytes": b"not a certificate"},
    ],
)
def test_profile_native_types_and_fixed_configuration_errors(changes: dict[str, Any]) -> None:
    with pytest.raises(p.ProfileError, match=r"^profile_configuration_invalid$"):
        profile(**changes)


def test_exact_principal_and_cli_grants_are_independent() -> None:
    actor = " Actor@@Tenant "
    registry = p.ProfileRegistry((profile(api_principals=frozenset({actor})),))
    cap = p.authorize_api_profile(registry, provider="splunk-enterprise", alias="selected", principal=actor)
    assert cap.profile.alias == "selected"
    for principal in ("Actor@@Tenant", actor.lower(), " Actor ", "", " "):
        with pytest.raises(p.ProfileUnavailable, match=r"^profile_unavailable$"):
            p.authorize_api_profile(registry, provider="splunk-enterprise", alias="selected", principal=principal)
    with pytest.raises(p.ProfileUnavailable):
        p.authorize_cli_profile(registry, provider="splunk-enterprise", alias="selected")
    local = p.ProfileRegistry((profile(allow_local_cli=True),))
    assert p.authorize_cli_profile(local, provider="splunk-enterprise", alias="selected")
    with pytest.raises(p.ProfileUnavailable):
        p.authorize_api_profile(local, provider="splunk-enterprise", alias="selected", principal=actor)


def test_unknown_wrong_provider_and_ungranted_profile_have_identical_errors() -> None:
    registry = p.ProfileRegistry((profile(),))
    errors = []
    cases: tuple[tuple[ProviderName, str], ...] = (
        ("google-vault", "selected"),
        ("splunk-enterprise", "missing"),
        ("splunk-enterprise", "selected"),
    )
    for provider, alias in cases:
        with pytest.raises(p.ProfileUnavailable) as raised:
            p.authorize_api_profile(registry, provider=provider, alias=alias, principal="actor")
        errors.append(str(raised.value))
    assert errors == ["profile_unavailable"] * 3


def test_registry_and_capability_detach_and_revalidate_mutated_configuration() -> None:
    original = profile(api_principals=frozenset({"actor"}), allow_local_cli=True)
    registry = p.ProfileRegistry((original,))
    cap = p.authorize_cli_profile(registry, provider="splunk-enterprise", alias="selected")
    object.__setattr__(original, "origin", "https://evil.example.invalid:443")
    object.__setattr__(registry.profiles[0], "allow_local_cli", False)
    assert cap.profile.origin == "https://splunk.example.invalid:8089"
    assert cap.profile.allow_local_cli is True
    detached = cap.profile
    object.__setattr__(detached, "origin", "not an origin")
    assert cap.profile.origin == "https://splunk.example.invalid:8089"
    with pytest.raises(p.ProfileError):
        p.validated_profile(detached)
    with pytest.raises(p.ProfileError):
        dataclasses.replace(profile(), allow_local_cli=cast(bool, 1))


def test_profiles_are_redacted_and_capabilities_not_automatically_serialized() -> None:
    selected = profile(allow_local_cli=True)
    registry = p.ProfileRegistry((selected,))
    cap = p.authorize_cli_profile(registry, provider="splunk-enterprise", alias="selected")
    for value in (selected, registry, cap, selected.address_policy):
        assert "splunk.example.invalid" not in repr(value)
        assert "ENTERPRISE_RETENTION" not in repr(value)
    with pytest.raises(TypeError):
        json.dumps(cap)
    with pytest.raises(TypeError):
        vars(cap)


def test_ca_snapshot_is_pem_verified_and_independent_of_original_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_bytes(CA_PEM.encode())
    registry_file = tmp_path / "profiles.json"
    write_registry(registry_file, [config(ca_file="ca.pem", allow_local_cli=True)])
    registry = p.load_profile_registry(registry_file)
    ca.write_bytes(b"changed after the trusted snapshot")
    monkeypatch.setenv("SSLKEYLOGFILE", str(tmp_path / "must-not-exist.log"))
    context = p.ssl_context(registry.profiles[0])
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.keylog_filename is None
    assert context.cert_store_stats()["x509_ca"] == 1
    assert not (tmp_path / "must-not-exist.log").exists()
    assert registry.profiles[0].ca_bytes == CA_PEM.encode()


def test_profile_loading_and_authorization_do_not_resolve_dns_or_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_collectors.enterprise_retention import _credentials as credentials

    def unexpected(*args: object, **kwargs: object) -> None:
        raise AssertionError("premature external work")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    monkeypatch.setattr(credentials, "_environment_value", unexpected)
    path = tmp_path / "profiles.json"
    write_registry(path, [config(allow_local_cli=True)])
    registry = p.load_profile_registry(path)
    assert p.authorize_cli_profile(registry, provider="splunk-enterprise", alias="selected")


@pytest.mark.parametrize(
    "bad",
    [
        b"{}",
        b'{"schema_version":"wrong","profiles":[]}',
        b'{"schema_version":"enterprise-retention-profiles/v1","profiles":[],"profiles":[]}',
        b'{"schema_version":"enterprise-retention-profiles/v1","profiles":[],"extra":true}',
        b"\xef\xbb\xbf{}",
        b'{"profiles":NaN}',
        b'"\xff"',
    ],
)
def test_invalid_registry_wire_has_fixed_errors(tmp_path: Path, bad: bytes) -> None:
    path = tmp_path / "profiles.json"
    path.write_bytes(bad)
    with pytest.raises(p.ProfileError, match=r"^profile_configuration_invalid$"):
        p.load_profile_registry(path)


def test_registry_duplicate_and_count_limits(tmp_path: Path) -> None:
    path = tmp_path / "profiles.json"
    for entries in (
        [config(), config()],
        [config(alias=f"a{i}") for i in range(33)],
        [config(api_principals=["actor", "actor"])],
        [config(extra=True)],
    ):
        write_registry(path, entries)
        with pytest.raises(p.ProfileError):
            p.load_profile_registry(path)


def test_exact_file_byte_limit_and_plus_one_refusal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "profiles.json"
    wire = json.dumps({"schema_version": p.PROFILE_SCHEMA, "profiles": []}).encode()
    path.write_bytes(wire + b" " * (p.PROFILE_FILE_LIMIT - len(wire)))
    assert p.load_profile_registry(path).profiles == ()
    path.write_bytes(path.read_bytes() + b" ")
    opened = []
    real = os.open

    def tracked(*args: Any, **kwargs: Any) -> int:
        opened.append(True)
        return real(*args, **kwargs)

    monkeypatch.setattr(os, "open", tracked)
    with pytest.raises(p.ProfileError):
        p.load_profile_registry(path)
    assert not opened


@pytest.mark.parametrize(
    "name", ["CON", "NUL.txt", "COM1.pem", "LPT2", "CONIN$", "CONOUT$", "ca.pem:stream", "trailing.", "trailing "]
)
def test_ambiguous_file_names_refuse_before_metadata(
    tmp_path: Path, name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(self: Path) -> os.stat_result:
        raise AssertionError("ambiguous path reached metadata")

    monkeypatch.setattr(Path, "lstat", unexpected)
    with pytest.raises(p.ProfileError):
        p.load_profile_registry(tmp_path / name)


def test_hard_link_and_directory_inputs_refuse(tmp_path: Path) -> None:
    original = tmp_path / "profiles.json"
    write_registry(original, [])
    link = tmp_path / "link.json"
    os.link(original, link)
    for path in (original, link, tmp_path):
        with pytest.raises(p.ProfileError):
            p.load_profile_registry(path)


def test_read_detects_in_place_change_and_closes_descriptor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "profiles.json"
    write_registry(path, [])
    real_read = os.read
    real_close = os.close
    changed = False
    closed = []

    def racing_read(descriptor: int, length: int) -> bytes:
        nonlocal changed
        data = real_read(descriptor, length)
        if not changed:
            changed = True
            with path.open("ab") as handle:
                handle.write(b" ")
        return data

    def close(descriptor: int) -> None:
        closed.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(os, "read", racing_read)
    monkeypatch.setattr(os, "close", close)
    with pytest.raises(p.ProfileError):
        p.load_profile_registry(path)
    assert len(closed) == 1
    with pytest.raises(OSError):
        os.fstat(closed[0])


@pytest.mark.parametrize("padding", [1024, 16_384, 65_536, 1_000_000])
def test_malformed_pem_suffix_is_bounded_and_refused_before_openssl(
    padding: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unexpected(*args: object, **kwargs: object) -> None:
        raise AssertionError("invalid PEM framing reached OpenSSL")

    monkeypatch.setattr(ssl, "SSLContext", unexpected)
    data = CA_PEM.encode() + b" " * padding + b"!"
    assert len(data) < p.CA_FILE_LIMIT
    with pytest.raises(p.ProfileError, match=r"^profile_configuration_invalid$"):
        profile(ca_bytes=data)


@pytest.mark.parametrize(
    "suffix",
    [None, "-----BEGIN UNKNOWN-----", "\x00", "unrelated"],
    ids=("suffix-1", "suffix-2", "suffix-3", "suffix-4"),
)
def test_ca_parser_refuses_unrelated_pem_or_trailing_content(suffix: str | None) -> None:
    with pytest.raises(p.ProfileError):
        profile(
            ca_bytes=CA_PEM.encode()
            + (
                suffix.encode()
                if suffix is not None
                else Ed25519PrivateKey.generate().private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        )


def test_ca_bundle_keeps_exact_bytes_and_accepts_crlf_framing() -> None:
    data = (" \t\r\n" + CA_PEM.replace("\n", "\r\n") + "\n" + CA_PEM).encode()
    selected = profile(ca_bytes=data)
    assert selected.ca_bytes == data
    assert p.ssl_context(selected).cert_store_stats()["x509_ca"] == 1


def test_default_trust_load_failure_remains_fixed_and_nondisclosing(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed(self: ssl.SSLContext, purpose: ssl.Purpose) -> None:
        raise OSError("synthetic-sensitive-marker")

    monkeypatch.setattr(ssl.SSLContext, "load_default_certs", failed)
    with pytest.raises(p.ProfileError, match=r"^profile_configuration_invalid$"):
        p.ssl_context(profile())


def test_second_custom_ca_context_failure_remains_fixed(monkeypatch: pytest.MonkeyPatch) -> None:
    selected = profile(ca_bytes=CA_PEM.encode("ascii"))
    original = ssl.SSLContext.load_verify_locations
    count = 0

    def failed_second(self: ssl.SSLContext, *args: Any, **kwargs: Any) -> None:
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("synthetic-sensitive-marker")
        original(self, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", failed_second)
    with pytest.raises(p.ProfileError, match=r"^profile_configuration_invalid$"):
        p.ssl_context(selected)


@pytest.mark.parametrize("identity", [0, None])
def test_unavailable_inode_metadata_cannot_establish_file_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, identity: Any
) -> None:
    source = tmp_path / "profiles.json"
    write_registry(source, [config()])
    original_lstat = Path.lstat
    original_fstat = os.fstat
    original_open = os.open
    selected_fds: set[int] = set()

    def without_identity(info: os.stat_result) -> os.stat_result:
        fields = list(info)
        fields[1] = identity
        return os.stat_result(
            fields,
            {
                "st_atime_ns": info.st_atime_ns,
                "st_mtime_ns": info.st_mtime_ns,
                "st_ctime_ns": info.st_ctime_ns,
                "st_file_attributes": getattr(info, "st_file_attributes", 0),
            },
        )

    def tracked_open(path: Path, flags: int) -> int:
        descriptor = original_open(path, flags)
        selected_fds.add(descriptor)
        return descriptor

    def lstat(self: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        info = original_lstat(self, *args, **kwargs)
        return without_identity(info) if self == source else info

    def fstat(descriptor: int) -> os.stat_result:
        info = original_fstat(descriptor)
        return without_identity(info) if descriptor in selected_fds else info

    monkeypatch.setattr(os, "open", tracked_open)
    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr(os, "fstat", fstat)
    with pytest.raises(p.ProfileError, match=r"^profile_configuration_invalid$"):
        p.load_profile_registry(source)
