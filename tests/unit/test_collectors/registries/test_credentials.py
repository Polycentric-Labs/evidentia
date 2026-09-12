"""Check late credential resolution without real configuration or secret material."""

from __future__ import annotations

import json
import pickle
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from evidentia_collectors.registries._credentials import (
    SAM_KEY_REFERENCE,
    CredentialError,
    SamCredential,
    SamCredentialCache,
    environment_resolver,
)

NOW = datetime(2026, 9, 11, tzinfo=UTC)
MARKER = "synthetic" + "-registry-query-material"


@pytest.mark.parametrize("action", [repr, str])
def test_credential_representations_exclude_material(action: Any) -> None:
    assert MARKER not in action(SamCredential(MARKER))


@pytest.mark.parametrize("action", [json.dumps, pickle.dumps, lambda value: value.__getstate__()])
def test_credential_serialization_refuses_material(action: Any) -> None:
    with pytest.raises(TypeError) as raised:
        action(SamCredential(MARKER))
    assert MARKER not in str(raised.value)


@pytest.mark.parametrize(
    "material",
    ["", "with space", "line\nfeed", "x" * 4097, 12, True, b"bytes"],
    ids=["empty", "space", "newline", "byte-limit", "integer", "boolean", "bytes"],
)
def test_invalid_material_is_refused_without_echo(material: Any) -> None:
    with pytest.raises(CredentialError, match=r"^invalid_credential$"):
        SamCredential(material)


def test_one_resolution_and_detached_material() -> None:
    calls: list[str] = []
    credential = SamCredential(MARKER)

    def resolve(reference: str) -> SamCredential:
        calls.append(reference)
        return credential

    cache = SamCredentialCache(resolve)
    first = cache.resolve(lambda: NOW)
    object.__setattr__(credential, "_material", "changed-synthetic-value")
    second = cache.resolve(lambda: NOW)
    assert first is not second
    assert first._for_query(NOW) == second._for_query(NOW) == MARKER
    assert calls == [SAM_KEY_REFERENCE]


def test_expiry_uses_post_resolver_time() -> None:
    current = NOW

    def resolve(reference: str) -> SamCredential:
        nonlocal current
        current += timedelta(seconds=2)
        return SamCredential(MARKER, expires_at=NOW + timedelta(seconds=1))

    with pytest.raises(CredentialError):
        SamCredentialCache(resolve).resolve(lambda: current)


def test_cached_credential_expiry_is_rechecked() -> None:
    cache = SamCredentialCache(lambda _: SamCredential(MARKER, expires_at=NOW + timedelta(seconds=1)))
    credential = cache.resolve(lambda: NOW)
    with pytest.raises(CredentialError):
        credential._for_query(NOW + timedelta(seconds=1))
    with pytest.raises(CredentialError):
        cache.resolve(lambda: NOW + timedelta(seconds=1))


def test_resolver_failure_is_fixed_without_exception_context() -> None:
    calls: list[str] = []

    def resolve(reference: str) -> SamCredential:
        calls.append(reference)
        raise RuntimeError(MARKER)

    cache = SamCredentialCache(resolve)
    for _ in range(2):
        with pytest.raises(CredentialError, match=r"^invalid_credential$") as raised:
            cache.resolve(lambda: NOW)
        assert raised.value.__context__ is None
    assert calls == [SAM_KEY_REFERENCE]


def test_resolver_cancellation_is_preserved() -> None:
    cancellation = KeyboardInterrupt()

    def resolve(reference: str) -> SamCredential:
        raise cancellation

    with pytest.raises(KeyboardInterrupt) as raised:
        SamCredentialCache(resolve).resolve(lambda: NOW)
    assert raised.value is cancellation


def test_missing_reference_resolves_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("evidentia_collectors.registries._credentials.os.environ", {})
    cache = SamCredentialCache(environment_resolver)
    with pytest.raises(CredentialError, match=r"^missing_credential$"):
        cache.resolve(lambda: NOW)
    monkeypatch.setenv(SAM_KEY_REFERENCE, MARKER)
    with pytest.raises(CredentialError, match=r"^missing_credential$"):
        cache.resolve(lambda: NOW)
    assert SamCredentialCache(environment_resolver).resolve(lambda: NOW)._for_query(NOW) == MARKER
    with pytest.raises(CredentialError):
        environment_resolver("request-selected-reference")
