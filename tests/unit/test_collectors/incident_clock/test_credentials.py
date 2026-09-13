"""Keep synthetic credential material in memory and require exact issued scope."""

from __future__ import annotations

import pickle
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from evidentia_collectors.incident_clock import _credentials as credentials
from evidentia_collectors.incident_clock import _profiles as profiles
from evidentia_collectors.incident_clock._contracts import validated_request


def selection(provider: str = "pagerduty") -> profiles.AuthorizedSelection:
    start: dict[str, Any] = {"label": "Start", "meaning": "Recorded start"}
    end: dict[str, Any] = {"label": "End", "meaning": "Recorded end"}
    record_id = "P1"
    extra: dict[str, str] = {}
    if provider == "jira":
        record_id = "10001"
        extra["cloud_id"] = "11111111-1111-1111-1111-111111111111"
        start.update(
            field_id="status", **{"from": {"state": "null", "value": None}, "to": {"state": "value", "value": "100"}}
        )
        end.update(
            field_id="status", **{"from": {"state": "value", "value": "100"}, "to": {"state": "value", "value": "200"}}
        )
    elif provider == "servicenow":
        record_id = "1" * 32
        extra["origin"] = "https://instance.example.org"
        start["field"] = "u_start"
        end["field"] = "u_end"
    else:
        start["event_type"] = "acknowledge_log_entry"
        end["event_type"] = "resolve_log_entry"
    raw = {
        "schema_version": "1",
        "profiles": [
            {
                "alias": "selected",
                "provider": provider,
                "credential_ref": "INCIDENT_CLOCK_DEMO_TOKEN",
                "allow_local_cli": True,
                "record_ids": [record_id],
                **extra,
                "clocks": [
                    {
                        "clock_alias": "workflow",
                        "label": "Workflow",
                        "mapping_reference": "Runbook",
                        "declared_workflow_meaning": "Operational observation",
                        "start": start,
                        "end": end,
                    }
                ],
            }
        ],
    }
    requested = {"provider": provider, "profile_alias": "selected", "clock_alias": "workflow", "record_id": record_id}
    if provider == "pagerduty":
        requested.update(since="2024-01-01T00:00:00Z", until="2024-01-02T00:00:00Z")
    return profiles.authorize_cli_selection(profiles.ProfileStore(raw), validated_request(requested))


def environment(monkeypatch: pytest.MonkeyPatch, token: object, expiry: object = None) -> list[str]:
    references: list[str] = []

    def read(reference: str) -> object:
        references.append(reference)
        return token if reference == "INCIDENT_CLOCK_DEMO_TOKEN" else expiry

    monkeypatch.setattr(credentials, "_environment_value", read)
    return references


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_selected_material_and_only_two_allowed_environment_reads(
    provider: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = secrets.token_urlsafe(24)
    references = environment(monkeypatch, token, "2024-01-01T00:00:01Z")
    granted = selection(provider)
    material = credentials.resolve_material(granted, datetime(2024, 1, 1, tzinfo=UTC))
    header = credentials.authorization_header(material, granted, datetime(2024, 1, 1, tzinfo=UTC))
    matches = header == ("Token token=" if provider == "pagerduty" else "Bearer ") + token
    del header, token
    assert matches
    assert material.credential_validity == "expiry_checked"
    assert references == ["INCIDENT_CLOCK_DEMO_TOKEN", "INCIDENT_CLOCK_DEMO_EXPIRES_AT"]


def test_unknown_expiry_is_only_supported_for_pagerduty(monkeypatch: pytest.MonkeyPatch) -> None:
    environment(monkeypatch, secrets.token_urlsafe(24))
    now = datetime(2024, 1, 1, tzinfo=UTC)
    assert credentials.resolve_material(selection(), now).credential_validity == "expiry_unknown"
    for provider in ("jira", "servicenow"):
        with pytest.raises(credentials.CredentialError, match=r"^credential_invalid$"):
            credentials.resolve_material(selection(provider), now)


@pytest.mark.parametrize(
    "expiry,expected",
    [
        ("2023-12-31T23:59:59Z", "credential_expired"),
        ("2024-01-01T00:00:00Z", "credential_expired"),
        ("2024-01-01T00:00:01", "credential_invalid"),
        ("", "credential_invalid"),
        (True, "credential_invalid"),
    ],
)
def test_invalid_or_expired_material_has_fixed_outcome(
    expiry: object, expected: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    environment(monkeypatch, secrets.token_urlsafe(24), expiry)
    with pytest.raises(credentials.CredentialError) as error:
        credentials.resolve_material(selection(), datetime(2024, 1, 1, tzinfo=UTC))
    assert error.value.code == expected and str(error.value) == expected


def test_expiry_is_rechecked_before_each_request_without_rounding(monkeypatch: pytest.MonkeyPatch) -> None:
    environment(monkeypatch, secrets.token_urlsafe(24), "2024-01-01T00:00:00.000000001Z")
    granted = selection("jira")
    now = datetime(2024, 1, 1, tzinfo=UTC)
    material = credentials.resolve_material(granted, now)
    credentials.authorization_header(material, granted, now)
    with pytest.raises(credentials.CredentialError, match=r"^credential_expired$"):
        credentials.authorization_header(material, granted, now + timedelta(microseconds=1))


@pytest.mark.parametrize(
    "name",
    [
        "empty",
        "space",
        "control",
        "del",
        "quote",
        "comma",
        "semicolon",
        "backslash",
        "prefix",
        "unicode",
        "too-long",
        "trailing-padding",
        "internal-padding",
        "native-subclass",
        "object",
    ],
)
def test_unsupported_token_values_are_refused_before_header_construction(
    name: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    values: dict[str, object] = {
        "empty": "",
        "space": "a b",
        "control": "a" + chr(0),
        "del": "a" + chr(127),
        "quote": 'a"b',
        "comma": "a,b",
        "semicolon": "a;b",
        "backslash": "a\\b",
        "prefix": "Bearer value",
        "unicode": chr(0xE9),
        "too-long": "a" * 16385,
        "trailing-padding": "a===",
        "internal-padding": "a=b",
        "native-subclass": type("TextChild", (str,), {})("value"),
        "object": object(),
    }
    references = environment(monkeypatch, values[name])
    with pytest.raises(credentials.CredentialError, match=r"^credential_invalid$"):
        credentials.resolve_material(selection(), datetime(2024, 1, 1, tzinfo=UTC))
    assert references == ["INCIDENT_CLOCK_DEMO_TOKEN"]


@pytest.mark.parametrize(
    "placeholder",
    ["token", "BEARER", "ApiKey", "api_key", "placeholder", "changeme", "your_token", "your-token", "example"],
)
def test_placeholders_are_refused(placeholder: str, monkeypatch: pytest.MonkeyPatch) -> None:
    environment(monkeypatch, placeholder)
    with pytest.raises(credentials.CredentialError):
        credentials.resolve_material(selection(), datetime(2024, 1, 1, tzinfo=UTC))


def test_missing_material_stops_before_expiry_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    references = environment(monkeypatch, None)
    with pytest.raises(credentials.CredentialError, match=r"^credential_missing$"):
        credentials.resolve_material(selection(), datetime(2024, 1, 1, tzinfo=UTC))
    assert references == ["INCIDENT_CLOCK_DEMO_TOKEN"]


def test_material_cannot_be_rebound_to_another_issued_selection(monkeypatch: pytest.MonkeyPatch) -> None:
    environment(monkeypatch, secrets.token_urlsafe(24))
    original = selection()
    now = datetime(2024, 1, 1, tzinfo=UTC)
    material = credentials.resolve_material(original, now)
    with pytest.raises(credentials.CredentialError):
        credentials.authorization_header(material, selection(), now)


def test_unissued_selection_is_refused_before_environment_access(monkeypatch: pytest.MonkeyPatch) -> None:
    references = environment(monkeypatch, secrets.token_urlsafe(24))
    with pytest.raises(credentials.CredentialError):
        credentials.resolve_material(object.__new__(profiles.AuthorizedSelection), datetime(2024, 1, 1, tzinfo=UTC))
    assert references == []


def test_material_remains_runtime_only_and_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    environment(monkeypatch, secrets.token_urlsafe(24))
    material = credentials.resolve_material(selection(), datetime(2024, 1, 1, tzinfo=UTC))
    assert repr(material) == "CredentialMaterial(<redacted>)" and str(material) == "CredentialMaterial(<redacted>)"
    with pytest.raises(TypeError):
        pickle.dumps(material)
    with pytest.raises(AttributeError):
        material.extra = "value"  # type: ignore[attr-defined]
    with pytest.raises(credentials.CredentialError):
        credentials.CredentialMaterial()
    with pytest.raises(credentials.CredentialError):
        credentials.authorization_header(
            object.__new__(credentials.CredentialMaterial), selection(), datetime(2024, 1, 1, tzinfo=UTC)
        )


def test_foreign_clock_and_resolver_failure_are_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    references = environment(monkeypatch, secrets.token_urlsafe(24))
    with pytest.raises(credentials.CredentialError):
        credentials.resolve_material(selection(), cast(datetime, "now"))
    assert references == []

    def failed(_reference: str) -> None:
        raise RuntimeError("synthetic resolver failure detail")

    monkeypatch.setattr(credentials, "_environment_value", failed)
    with pytest.raises(credentials.CredentialError, match=r"^credential_invalid$"):
        credentials.resolve_material(selection(), datetime(2024, 1, 1, tzinfo=UTC))
