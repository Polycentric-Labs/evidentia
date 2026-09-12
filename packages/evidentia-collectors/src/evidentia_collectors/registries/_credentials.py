"""Resolve the single server-owned SAM reference only after destination approval."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, Never, SupportsIndex, cast

SAM_KEY_REFERENCE = "EVIDENTIA_REGISTRY_SAM_API_KEY"


class CredentialError(ValueError):
    def __init__(self, code: Literal["missing_credential", "invalid_credential"] = "invalid_credential") -> None:
        if type(code) is not str or code not in {"missing_credential", "invalid_credential"}:
            code = "invalid_credential"
        self.code = code
        super().__init__(code)


def _material(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 4096 or any(char < "!" or char > "~" for char in value):
        raise CredentialError()
    return value


def _clock(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is not UTC:
        raise CredentialError()
    return value


class SamCredential:
    """Keep query material out of representation and serialization."""

    __slots__ = ("_expires_at", "_material")

    def __init__(self, material: str, *, expires_at: datetime | None = None) -> None:
        object.__setattr__(self, "_material", _material(material))
        object.__setattr__(self, "_expires_at", None if expires_at is None else _clock(expires_at))

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_credential")

    def __repr__(self) -> str:
        return "SamCredential(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("credential_serialization_refused")

    def __getstate__(self) -> Never:
        raise TypeError("credential_serialization_refused")

    def _checked_copy(self, now: datetime) -> SamCredential:
        if type(self) is not SamCredential:
            raise CredentialError()
        observed = _clock(now)
        material = _material(object.__getattribute__(self, "_material"))
        expires_at = object.__getattribute__(self, "_expires_at")
        if expires_at is not None and _clock(expires_at) <= observed:
            raise CredentialError()
        return SamCredential(material, expires_at=expires_at)

    def _for_query(self, now: datetime) -> str:
        checked = self._checked_copy(now)
        return cast(str, object.__getattribute__(checked, "_material"))


Resolver = Callable[[str], SamCredential | None]


def environment_resolver(reference: str) -> SamCredential | None:
    if type(reference) is not str or reference != SAM_KEY_REFERENCE:
        raise CredentialError()
    material = os.environ.get(SAM_KEY_REFERENCE)
    return None if material is None else SamCredential(material)


class SamCredentialCache:
    """Resolve once, then recheck the copied credential after every callback."""

    def __init__(self, resolver: Resolver) -> None:
        self._resolver = resolver
        self._attempted = False
        self._credential: SamCredential | None = None
        self._failure: Literal["missing_credential", "invalid_credential"] = "missing_credential"

    def __repr__(self) -> str:
        return "SamCredentialCache(<redacted>)"

    def resolve(self, utc_now: Callable[[], datetime]) -> SamCredential:
        if not self._attempted:
            self._attempted = True
            candidate: SamCredential | None = None
            failed = False
            try:
                candidate = self._resolver(SAM_KEY_REFERENCE)
            except Exception:
                failed = True
            if failed or (candidate is not None and type(candidate) is not SamCredential):
                self._failure = "invalid_credential"
            elif candidate is not None:
                self._failure = "invalid_credential"
                # The clock follows the resolver; an old pre-callback time is unsafe.
                self._credential = candidate._checked_copy(utc_now())
        if self._credential is None:
            raise CredentialError(self._failure)
        return self._credential._checked_copy(utc_now())
