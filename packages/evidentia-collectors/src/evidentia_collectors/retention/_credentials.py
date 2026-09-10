"""Validated credential snapshots and fixed environment references."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol

MAX_KEY_CHARACTERS = 2048
MAX_TOKEN_CHARACTERS = 16384
_CONFIGURATION_DIAGNOSTICS = frozenset({"configuration_missing", "configuration_invalid", "credential_unavailable"})


def _checked_text(value: object, maximum: int) -> str:
    if (
        type(value) is not str
        or not 1 <= len(value) <= maximum
        or any(character < "!" or character > "~" for character in value)
    ):
        raise ValueError("configuration_invalid")
    return value


def _checked_expiry(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    try:
        if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError
        return value.astimezone(UTC)
    except Exception:
        raise ValueError("configuration_invalid") from None


@dataclass(frozen=True, slots=True, repr=False)
class AwsCredentials:
    """Explicit ASCII material; expiry is a detached UTC instant when known."""

    access_key_id: str
    secret_access_key: str
    session_token: str | None = None
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _checked_text(self.access_key_id, MAX_KEY_CHARACTERS)
        _checked_text(self.secret_access_key, MAX_KEY_CHARACTERS)
        if self.session_token is not None:
            _checked_text(self.session_token, MAX_TOKEN_CHARACTERS)
        object.__setattr__(self, "expires_at", _checked_expiry(self.expires_at))

    def __repr__(self) -> str:
        return "AwsCredentials(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class BearerCredentials:
    """A literal ASCII token without whitespace or header control characters."""

    token: str
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        _checked_text(self.token, MAX_TOKEN_CHARACTERS)
        object.__setattr__(self, "expires_at", _checked_expiry(self.expires_at))

    def __repr__(self) -> str:
        return "BearerCredentials(<redacted>)"


@dataclass(frozen=True, slots=True, repr=False)
class CredentialResolution:
    """Either detached material or one fixed configuration diagnostic."""

    material: AwsCredentials | BearerCredentials | None
    diagnostic: str | None

    def __post_init__(self) -> None:
        if self.material is None:
            if type(self.diagnostic) is not str or self.diagnostic not in _CONFIGURATION_DIAGNOSTICS:
                raise ValueError("configuration_invalid")
            return
        if self.diagnostic is not None:
            raise ValueError("configuration_invalid")
        try:
            if type(self.material) is AwsCredentials:
                copied: AwsCredentials | BearerCredentials = AwsCredentials(
                    self.material.access_key_id,
                    self.material.secret_access_key,
                    self.material.session_token,
                    self.material.expires_at,
                )
            elif type(self.material) is BearerCredentials:
                copied = BearerCredentials(self.material.token, self.material.expires_at)
            else:
                raise ValueError("configuration_invalid")
        except (AttributeError, TypeError, ValueError):
            raise ValueError("configuration_invalid") from None
        object.__setattr__(self, "material", copied)

    def __repr__(self) -> str:
        return "CredentialResolution(<redacted>)"


class StorageCredentialProvider(Protocol):
    def resolve(self, provider: Literal["s3", "azure", "gcs"]) -> CredentialResolution: ...


def _environment_value(name: str) -> str | None:
    return os.getenv(name)


class EnvironmentCredentialProvider:
    """Read only the selected provider's fixed references, without discovery."""

    def resolve(self, provider: Literal["s3", "azure", "gcs"]) -> CredentialResolution:
        if type(provider) is not str or provider not in {"s3", "azure", "gcs"}:
            return CredentialResolution(None, "configuration_invalid")
        names = (
            ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
            if provider == "s3"
            else (f"STORAGE_RETENTION_{provider.upper()}_ACCESS_TOKEN",)
        )
        try:
            values = tuple(_environment_value(name) for name in names)
        except Exception:
            return CredentialResolution(None, "credential_unavailable")
        if all(value is None for value in values):
            return CredentialResolution(None, "configuration_missing")
        try:
            if provider == "s3":
                access, secret, token = values
                if access is None or secret is None:
                    raise ValueError
                material: AwsCredentials | BearerCredentials = AwsCredentials(access, secret, token)
            else:
                bearer = values[0]
                if bearer is None:
                    raise ValueError
                material = BearerCredentials(bearer)
            return CredentialResolution(material, None)
        except ValueError:
            return CredentialResolution(None, "configuration_invalid")
