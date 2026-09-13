"""Bind an exact incident request to trusted profile and actor grants."""

from __future__ import annotations

import hashlib
import re
import weakref
from pathlib import Path
from typing import Any, Never, cast
from urllib.parse import urlsplit
from uuid import UUID

from evidentia_collectors.enterprise_retention._profiles import _read_file

from ._clock import Provider
from ._contracts import (
    IncidentClockRequest,
    PublishedClockDefinition,
    _alias,
    _native,
    bounded_text,
    published_definition,
    valid_record_id,
    validated_request,
)
from ._parsing import PROFILE_BYTE_LIMIT, canonical_json, checked_json, parse_strict_json


class ProfileError(ValueError):
    def __init__(self) -> None:
        super().__init__("profile_configuration_invalid")


class ProfileUnavailable(ValueError):
    """Keep alias, provider, scope and actor refusals indistinguishable."""

    def __init__(self) -> None:
        super().__init__("profile_unavailable")


def credential_reference(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"INCIDENT_CLOCK_[A-Z0-9_]{1,48}_TOKEN", value) is None:
        raise ProfileError()
    return value


def canonical_origin(value: object) -> str:
    text = bounded_text(value, 300, nonblank=True)
    if not text.isascii() or "\\" in text or "%" in text:
        raise ProfileError()
    parts = urlsplit(text)
    host = parts.hostname
    if (
        parts.scheme != "https"
        or not host
        or parts.port not in (None, 443)
        or parts.username is not None
        or parts.password is not None
        or parts.path
        or parts.query
        or parts.fragment
    ):
        raise ProfileError()
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or not re.search(r"[a-z]", labels[-1]):
        raise ProfileError()
    if any(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None for label in labels):
        raise ProfileError()
    canonical = "https://" + host
    if text not in (canonical, canonical + ":443"):
        raise ProfileError()
    return canonical


def _profile(value: object) -> dict[str, Any]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ProfileError()
    required = {"alias", "provider", "credential_ref", "record_ids", "clocks"}
    optional = {"api_principals", "allow_local_cli"}
    provider = value.get("provider")
    if type(provider) is not str or provider not in ("servicenow", "jira", "pagerduty"):
        raise ProfileError()
    extra = {"origin"} if provider == "servicenow" else {"cloud_id"} if provider == "jira" else set()
    if not required | extra <= set(value) or set(value) - required - optional - extra:
        raise ProfileError()
    _alias(value["alias"])
    credential_reference(value["credential_ref"])
    if provider == "servicenow":
        canonical_origin(value["origin"])
    elif provider == "jira":
        cloud_id = bounded_text(value["cloud_id"], 36, nonblank=True)
        if str(UUID(cloud_id)) != cloud_id:
            raise ProfileError()
    principals = value.get("api_principals", [])
    if type(principals) is not list or len(principals) > 64:
        raise ProfileError()
    actors = [bounded_text(actor, 1024, nonblank=True) for actor in principals]
    if (
        any("*" in actor for actor in actors)
        or len(set(actors)) != len(actors)
        or type(value.get("allow_local_cli", False)) is not bool
    ):
        raise ProfileError()
    records = value["record_ids"]
    if type(records) is not list or not 1 <= len(records) <= 128:
        raise ProfileError()
    ids = [valid_record_id(cast(Provider, provider), record) for record in records]
    if len(set(ids)) != len(ids):
        raise ProfileError()
    clocks = value["clocks"]
    if type(clocks) is not list or not 1 <= len(clocks) <= 16:
        raise ProfileError()
    aliases = [published_definition(cast(Provider, provider), clock).clock_alias for clock in clocks]
    if len(set(aliases)) != len(aliases):
        raise ProfileError()
    return value


def _store(value: object) -> dict[str, Any]:
    try:
        data = checked_json(value, max_bytes=PROFILE_BYTE_LIMIT)
        if type(data) is not dict or set(data) != {"schema_version", "profiles"} or data["schema_version"] != "1":
            raise ProfileError()
        profiles = data["profiles"]
        if type(profiles) is not list or len(profiles) > 32:
            raise ProfileError()
        aliases = [_profile(profile)["alias"] for profile in profiles]
        if len(set(aliases)) != len(aliases):
            raise ProfileError()
        return data
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        raise ProfileError() from None


class ProfileStore:
    """Retain only a validated immutable configuration byte snapshot."""

    __slots__ = ("_content",)

    def __init__(self, value: object) -> None:
        object.__setattr__(self, "_content", canonical_json(_store(value), max_bytes=PROFILE_BYTE_LIMIT))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_profile_store")

    def __repr__(self) -> str:
        return "ProfileStore(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_profile_store")


def load_profile_store(path: Path) -> ProfileStore:
    """Read one bounded regular local file through stable identity checks."""
    try:
        return ProfileStore(parse_strict_json(_read_file(path, limit=PROFILE_BYTE_LIMIT), max_bytes=PROFILE_BYTE_LIMIT))
    except (AttributeError, TypeError, ValueError, OSError):
        raise ProfileError() from None


_CAPABILITIES: weakref.WeakKeyDictionary[AuthorizedSelection, bytes] = weakref.WeakKeyDictionary()


class AuthorizedSelection:
    """Expose detached selected facts only for an issued in-process capability."""

    __slots__ = ("__weakref__",)

    def __new__(cls) -> AuthorizedSelection:
        raise ProfileUnavailable()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_selection")

    def __repr__(self) -> str:
        return "AuthorizedSelection(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_selection")

    @property
    def request(self) -> IncidentClockRequest:
        return validated_request(_selection(self)["request"])

    @property
    def definition(self) -> PublishedClockDefinition:
        data = _selection(self)
        return published_definition(data["provider"], data["definition"])

    @property
    def provider(self) -> Provider:
        return cast(Provider, _selection(self)["provider"])

    @property
    def origin(self) -> str:
        return cast(str, _selection(self)["origin"])

    @property
    def cloud_id(self) -> str | None:
        return cast(str | None, _selection(self)["cloud_id"])

    @property
    def credential_ref(self) -> str:
        return cast(str, _selection(self)["credential_ref"])

    @property
    def profile_binding_sha256(self) -> str:
        return cast(str, _selection(self)["profile_binding_sha256"])


def _selection(value: object) -> dict[str, Any]:
    if type(value) is not AuthorizedSelection:
        raise ProfileUnavailable()
    content = _CAPABILITIES.get(value)
    if type(content) is not bytes:
        raise ProfileUnavailable()
    data = parse_strict_json(content, max_bytes=131072)
    if type(data) is not dict:
        raise ProfileUnavailable()
    return data


def validated_selection(value: object, request: object) -> AuthorizedSelection:
    """Recheck the entire request before credentials or network work starts."""
    try:
        data = _selection(value)
        actual = validated_request(request)
        if actual != validated_request(data["request"]):
            raise ProfileUnavailable()
        return cast(AuthorizedSelection, value)
    except (AttributeError, TypeError, ValueError, RuntimeError, RecursionError):
        raise ProfileUnavailable() from None


def _authorize(
    store: ProfileStore, request: IncidentClockRequest, *, principal: str | None, local_cli: bool
) -> AuthorizedSelection:
    try:
        if type(store) is not ProfileStore:
            raise ProfileUnavailable()
        selected = validated_request(request)
        data = _store(parse_strict_json(object.__getattribute__(store, "_content"), max_bytes=PROFILE_BYTE_LIMIT))
        profile = next(
            (
                profile
                for profile in data["profiles"]
                if profile["alias"] == selected.profile_alias and profile["provider"] == selected.provider
            ),
            None,
        )
        if profile is None or selected.record_id not in profile["record_ids"]:
            raise ProfileUnavailable()
        raw_clock = next((clock for clock in profile["clocks"] if clock["clock_alias"] == selected.clock_alias), None)
        if raw_clock is None:
            raise ProfileUnavailable()
        if local_cli:
            if not profile.get("allow_local_cli", False):
                raise ProfileUnavailable()
        elif principal is None or bounded_text(principal, 1024, nonblank=True) not in profile.get("api_principals", []):
            raise ProfileUnavailable()
        definition = published_definition(selected.provider, raw_clock)
        origin = (
            canonical_origin(profile["origin"])
            if selected.provider == "servicenow"
            else "https://api.atlassian.com"
            if selected.provider == "jira"
            else "https://api.pagerduty.com"
        )
        binding = {
            "provider": selected.provider,
            "origin": origin,
            "cloud_id": profile.get("cloud_id"),
            "record_id": selected.record_id,
            "definition": _native(definition),
        }
        snapshot = {
            **binding,
            "request": _native(selected),
            "credential_ref": profile["credential_ref"],
            "profile_binding_sha256": hashlib.sha256(canonical_json(binding)).hexdigest(),
        }
        capability = object.__new__(AuthorizedSelection)
        _CAPABILITIES[capability] = canonical_json(snapshot, max_bytes=131072)
        return capability
    except (AttributeError, KeyError, StopIteration, TypeError, ValueError, RuntimeError, RecursionError):
        raise ProfileUnavailable() from None


def authorize_api_selection(
    store: ProfileStore, request: IncidentClockRequest, *, principal: str
) -> AuthorizedSelection:
    return _authorize(store, request, principal=principal, local_cli=False)


def authorize_cli_selection(store: ProfileStore, request: IncidentClockRequest) -> AuthorizedSelection:
    return _authorize(store, request, principal=None, local_cli=True)
