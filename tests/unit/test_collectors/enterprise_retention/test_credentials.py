"""Credential material, selected-reference reads and expiry boundaries."""

from __future__ import annotations

import dataclasses
import json
import pickle
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest
from evidentia_collectors.enterprise_retention import _credentials as c
from evidentia_collectors.enterprise_retention import _profiles as p

if TYPE_CHECKING:
    from _typeshed import DataclassInstance

NOW = datetime(2030, 1, 1, tzinfo=UTC)


def profile() -> p.FrozenProfile:
    return p.FrozenProfile(
        "selected",
        "elastic-ilm",
        "https://elastic.example.invalid:9200",
        "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        p.AddressPolicy("public"),
        allow_local_cli=True,
    )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "x ",
        " x",
        "x\n",
        "x\r",
        "x\t",
        "x\x00",
        "x\x7f",
        "\u00e9",
        "Bearer token",
        "ApiKey token",
        "bearer",
        "APIKEY",
        "basic",
        "x" * 16_385,
        1,
        True,
        None,
    ],
)
def test_invalid_header_material_is_fixed_and_never_printed(value: Any) -> None:
    with pytest.raises(c.CredentialError, match=r"^credential_invalid$"):
        c.CredentialMaterial("elastic-ilm", value)


def test_material_native_bounds_expiry_and_runtime_only_representation() -> None:
    material = c.CredentialMaterial("elastic-ilm", "x" * 16_384, NOW + timedelta(seconds=1))
    assert c.validated_material(material, provider="elastic-ilm", now=NOW).value == "x" * 16_384
    assert repr(material) == "CredentialMaterial(<redacted>)"
    for encode in (json.dumps, pickle.dumps, dataclasses.asdict, vars):
        with pytest.raises(TypeError):
            encode(cast("DataclassInstance", material))
    with pytest.raises(AttributeError):
        material._value = "changed"
    with pytest.raises(c.CredentialError, match=r"^credential_expired$"):
        c.validated_material(material, provider="elastic-ilm", now=NOW + timedelta(seconds=1))
    with pytest.raises(c.CredentialError, match=r"^credential_invalid$"):
        c.validated_material(material, provider="google-vault", now=NOW)


def test_material_normalizes_only_known_expiry_and_detaches() -> None:
    offset = timezone(timedelta(hours=3))
    instant = NOW.astimezone(offset)
    source = c.CredentialMaterial("elastic-ilm", "synthetic-token", instant + timedelta(seconds=1))
    copied = c.validated_material(source, provider="elastic-ilm", now=NOW)
    assert copied.expires_at == NOW + timedelta(seconds=1)
    assert copied.expires_at.tzinfo is UTC
    object.__setattr__(source, "_value", "changed")
    assert copied.value == "synthetic-token"
    unknown = c.CredentialMaterial("elastic-ilm", "synthetic-token")
    assert c.validated_material(unknown, provider="elastic-ilm", now=NOW).expires_at is None
    with pytest.raises(c.CredentialError):
        c.CredentialMaterial("elastic-ilm", "synthetic-token", datetime(2030, 1, 1))


def test_mutated_material_and_unsupported_objects_reject_without_callbacks() -> None:
    class Hostile:
        @property
        def value(self) -> str:
            raise AssertionError("source property ran")

    with pytest.raises(c.CredentialError):
        c.validated_material(Hostile(), provider="elastic-ilm", now=NOW)
    material = c.CredentialMaterial("elastic-ilm", "synthetic-token")
    object.__setattr__(material, "_value", Hostile())
    with pytest.raises(c.CredentialError):
        c.validated_material(material, provider="elastic-ilm", now=NOW)


def test_only_selected_environment_reference_is_read_on_explicit_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    lookups = []

    def lookup(name: str) -> str:
        lookups.append(name)
        return "synthetic-token"

    monkeypatch.setattr(c, "_environment_value", lookup)
    selected = profile()
    registry = p.ProfileRegistry((selected,))
    cap = p.authorize_cli_profile(registry, provider="elastic-ilm", alias="selected")
    assert not lookups
    material = cap.resolver.resolve(cap.profile)
    assert material.provider == "elastic-ilm" and material.value == "synthetic-token"
    assert lookups == ["ENTERPRISE_RETENTION_SYNTHETIC_TOKEN"]


@pytest.mark.parametrize(
    "value,code", [(None, "credential_missing"), ("", "credential_invalid"), ("bad token", "credential_invalid")]
)
def test_missing_and_invalid_environment_values_are_distinct(
    monkeypatch: pytest.MonkeyPatch, value: Any, code: str
) -> None:
    monkeypatch.setattr(c, "_environment_value", lambda name: value)
    with pytest.raises(c.CredentialError, match="^" + code + "$"):
        c.EnvironmentCredentialResolver().resolve(profile())


def test_resolver_failure_does_not_expose_exception_or_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed(name: str) -> str:
        raise RuntimeError("synthetic-source-marker")

    monkeypatch.setattr(c, "_environment_value", failed)
    with pytest.raises(c.CredentialError) as raised:
        c.EnvironmentCredentialResolver().resolve(profile())
    assert str(raised.value) == "credential_resolution_failed"
    assert "synthetic-source-marker" not in str(raised.value)


@pytest.mark.parametrize(
    "value",
    [
        "OTHER_TOKEN",
        "ENTERPRISE_RETENTION__TOKEN",
        "ENTERPRISE_RETENTION_lower_TOKEN",
        "ENTERPRISE_RETENTION_" + "X" * 49 + "_TOKEN",
        "ENTERPRISE_RETENTION_OK_TOKEN\n",
        1,
    ],
)
def test_only_exact_fixed_reference_grammar_is_supported(value: Any) -> None:
    with pytest.raises(c.CredentialError):
        c.checked_reference(value)
