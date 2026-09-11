"""Selected credential references and immutable runtime-only token snapshots."""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, Never, Protocol

from ._contracts import ProviderName

if TYPE_CHECKING:
    from ._profiles import FrozenProfile

MAX_TOKEN_BYTES = 16_384
_CREDENTIAL_REFERENCE = re.compile(r"ENTERPRISE_RETENTION_[A-Z0-9_]{1,48}_TOKEN")
CredentialCode = Literal[
    "credential_missing", "credential_invalid", "credential_expired", "credential_resolution_failed"
]


class CredentialError(ValueError):
    """Report a fixed credential state without material or reference names."""

    def __init__(self, code: CredentialCode = "credential_invalid") -> None:
        if type(code) is not str or code not in (
            "credential_missing",
            "credential_invalid",
            "credential_expired",
            "credential_resolution_failed",
        ):
            code = "credential_invalid"
        self.code = code
        super().__init__(code)


def checked_reference(value: object) -> str:
    if type(value) is not str or _CREDENTIAL_REFERENCE.fullmatch(value) is None:
        raise CredentialError()
    return value


def checked_provider(value: object) -> ProviderName:
    if type(value) is not str or value not in ("google-vault", "splunk-enterprise", "elastic-ilm"):
        raise CredentialError()
    if value == "google-vault":
        return "google-vault"
    if value == "splunk-enterprise":
        return "splunk-enterprise"
    return "elastic-ilm"


def _expiry(value: object) -> datetime | None:
    if value is None:
        return None
    try:
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise CredentialError()
        return value.astimezone(UTC)
    except Exception:
        raise CredentialError() from None


class CredentialMaterial:
    """Keep validated header material out of automatic record serializers."""

    __slots__ = ("_expires_at", "_provider", "_value")
    _provider: ProviderName
    _value: str
    _expires_at: datetime | None

    def __init__(self, provider: ProviderName, value: str, expires_at: datetime | None = None) -> None:
        checked = checked_provider(provider)
        if (
            type(value) is not str
            or not 1 <= len(value) <= MAX_TOKEN_BYTES
            or any(char < "!" or char > "~" for char in value)
            or value.lower() in ("bearer", "apikey", "basic")
        ):
            raise CredentialError()
        object.__setattr__(self, "_provider", checked)
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "_expires_at", _expiry(expires_at))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_credential")

    def __repr__(self) -> str:
        return "CredentialMaterial(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_credential")

    @property
    def provider(self) -> ProviderName:
        return self._provider

    @property
    def value(self) -> str:
        return self._value

    @property
    def expires_at(self) -> datetime | None:
        return self._expires_at


def validated_material(value: object, *, provider: ProviderName, now: datetime) -> CredentialMaterial:
    """Detach material and check the selected provider and current expiry."""
    try:
        expected = checked_provider(provider)
        if type(value) is not CredentialMaterial:
            raise CredentialError()
        detached = CredentialMaterial(value.provider, value.value, value.expires_at)
        if detached.provider != expected:
            raise CredentialError()
        checked_now = _expiry(now)
        if checked_now is None:
            raise CredentialError()
        if detached.expires_at is not None and detached.expires_at <= checked_now:
            raise CredentialError("credential_expired")
        return detached
    except CredentialError:
        raise
    except (ValueError, TypeError, AttributeError):
        raise CredentialError() from None


class CredentialResolver(Protocol):
    def resolve(self, profile: FrozenProfile) -> CredentialMaterial: ...


def _environment_value(reference: str) -> str | None:
    return os.getenv(reference)


class EnvironmentCredentialResolver:
    """Read exactly the selected profile reference when the session requests it."""

    def resolve(self, profile: FrozenProfile) -> CredentialMaterial:
        from ._profiles import validated_profile

        try:
            selected = validated_profile(profile)
            reference = checked_reference(selected.credential_ref)
        except ValueError:
            raise CredentialError() from None
        try:
            value = _environment_value(reference)
        except Exception:
            raise CredentialError("credential_resolution_failed") from None
        if value is None:
            raise CredentialError("credential_missing")
        return CredentialMaterial(selected.provider, value)
