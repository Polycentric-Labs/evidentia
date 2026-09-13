"""Resolve selected runtime credentials without publishing token material."""

from __future__ import annotations

import os
import re
import weakref
from datetime import datetime
from typing import Literal, Never

from ._clock import ExactInstant, elapsed_seconds, parse_instant
from ._contracts import utc_clock
from ._profiles import AuthorizedSelection, _selection, credential_reference

CredentialCode = Literal["credential_missing", "credential_invalid", "credential_expired"]
CredentialValidity = Literal["expiry_checked", "expiry_unknown"]
MAX_TOKEN_BYTES = 16384
_TOKEN = re.compile(r"[A-Za-z0-9._~+/-]+={0,2}")
_PLACEHOLDERS = frozenset(
    ("token", "bearer", "apikey", "api_key", "placeholder", "changeme", "your_token", "your-token", "example")
)


class CredentialError(ValueError):
    """Expose only a finite local credential outcome."""

    def __init__(self, code: CredentialCode = "credential_invalid") -> None:
        if type(code) is not str or code not in ("credential_missing", "credential_invalid", "credential_expired"):
            code = "credential_invalid"
        self.code = code
        super().__init__(code)


# Material is attached to an issued capability, never copied into model fields.
_MATERIALS: weakref.WeakKeyDictionary[CredentialMaterial, tuple[str, ExactInstant | None, AuthorizedSelection]] = (
    weakref.WeakKeyDictionary()
)


class CredentialMaterial:
    __slots__ = ("__weakref__",)

    def __new__(cls) -> CredentialMaterial:
        raise CredentialError()

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_credential")

    def __repr__(self) -> str:
        return "CredentialMaterial(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_credential")

    @property
    def credential_validity(self) -> CredentialValidity:
        return "expiry_unknown" if _material(self)[1] is None else "expiry_checked"


def _material(value: object) -> tuple[str, ExactInstant | None, AuthorizedSelection]:
    if type(value) is not CredentialMaterial:
        raise CredentialError()
    data = _MATERIALS.get(value)
    if data is None:
        raise CredentialError()
    return data


def _token(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= MAX_TOKEN_BYTES or not value.isascii():
        raise CredentialError()
    if _TOKEN.fullmatch(value) is None or value.lower() in _PLACEHOLDERS:
        raise CredentialError()
    return value


def _now(value: datetime) -> ExactInstant:
    checked = utc_clock(value)
    return parse_instant(checked.isoformat(timespec="microseconds").replace("+00:00", "Z"), "pagerduty")


def _not_expired(expiry: ExactInstant | None, now: ExactInstant) -> None:
    if expiry is not None:
        remaining = elapsed_seconds(now, expiry)
        if remaining is None or remaining == "0":
            raise CredentialError("credential_expired")


def _environment_value(reference: str) -> str | None:
    return os.getenv(reference)


def resolve_material(selection: AuthorizedSelection, now: datetime) -> CredentialMaterial:
    """Read only the issued selection's token and companion expiry references."""
    try:
        selected = _selection(selection)
        current = _now(now)
        reference = credential_reference(selected["credential_ref"])
        value = _environment_value(reference)
        if value is None:
            raise CredentialError("credential_missing")
        token = _token(value)
        raw_expiry = _environment_value(reference.removesuffix("_TOKEN") + "_EXPIRES_AT")
        expiry = None if raw_expiry is None else parse_instant(raw_expiry, "pagerduty")
        if expiry is None and selected["provider"] != "pagerduty":
            raise CredentialError()
        _not_expired(expiry, current)
        material = object.__new__(CredentialMaterial)
        _MATERIALS[material] = (token, expiry, selection)
        return material
    except CredentialError:
        raise
    except Exception:
        raise CredentialError() from None


def authorization_header(material: CredentialMaterial, selection: AuthorizedSelection, now: datetime) -> str:
    """Recheck selection identity and expiry immediately before the selected GET."""
    try:
        token, expiry, issued_selection = _material(material)
        if issued_selection is not selection:
            raise CredentialError()
        provider = _selection(selection)["provider"]
        _not_expired(expiry, _now(now))
        return ("Token token=" if provider == "pagerduty" else "Bearer ") + token
    except CredentialError:
        raise
    except Exception:
        raise CredentialError() from None
