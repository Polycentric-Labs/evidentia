"""Exercise trusted profile admission and request-bound capabilities."""

from __future__ import annotations

import json
import os
import pickle
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.incident_clock import _profiles as profiles
from evidentia_collectors.incident_clock._contracts import validated_request


def payload(*, api: bool = True, cli: bool = False) -> dict[str, Any]:
    return {
        "schema_version": "1",
        "profiles": [
            {
                "alias": "selected",
                "provider": "pagerduty",
                "credential_ref": "INCIDENT_CLOCK_DEMO_TOKEN",
                "api_principals": ["operator-1"] if api else [],
                "allow_local_cli": cli,
                "record_ids": ["P1", "P2"],
                "clocks": [
                    {
                        "clock_alias": "workflow",
                        "label": "Workflow observation",
                        "mapping_reference": "Runbook v1",
                        "declared_workflow_meaning": "Two selected operational events",
                        "start": {
                            "label": "Start",
                            "meaning": "Recorded acknowledgement",
                            "event_type": "acknowledge_log_entry",
                        },
                        "end": {"label": "End", "meaning": "Recorded resolution", "event_type": "resolve_log_entry"},
                    }
                ],
            }
        ],
    }


def requested(**changes: Any) -> Any:
    value = {
        "provider": "pagerduty",
        "profile_alias": "selected",
        "clock_alias": "workflow",
        "record_id": "P1",
        "since": "2024-01-01T00:00:00Z",
        "until": "2024-01-02T00:00:00Z",
    }
    value.update(changes)
    return validated_request(value)


def test_api_capability_is_bound_to_complete_selected_request() -> None:
    store = profiles.ProfileStore(payload())
    request = requested()
    selected = profiles.authorize_api_selection(store, request, principal="operator-1")
    assert selected.provider == "pagerduty" and selected.origin == "https://api.pagerduty.com"
    assert selected.cloud_id is None and selected.request == request and selected.definition.clock_alias == "workflow"
    assert profiles.validated_selection(selected, request) is selected
    for changed in (
        requested(record_id="P2"),
        requested(since="2024-01-01T00:00:00.1Z"),
        requested(start_occurrence={"event_id": "E1"}),
    ):
        with pytest.raises(profiles.ProfileUnavailable):
            profiles.validated_selection(selected, changed)


def test_api_and_local_cli_authority_do_not_substitute() -> None:
    api_only = profiles.ProfileStore(payload())
    cli_only = profiles.ProfileStore(payload(api=False, cli=True))
    profiles.authorize_api_selection(api_only, requested(), principal="operator-1")
    profiles.authorize_cli_selection(cli_only, requested())
    with pytest.raises(profiles.ProfileUnavailable):
        profiles.authorize_cli_selection(api_only, requested())
    with pytest.raises(profiles.ProfileUnavailable):
        profiles.authorize_api_selection(cli_only, requested(), principal="operator-1")


@pytest.mark.parametrize("change", ["alias", "provider", "record", "clock", "actor", "actor-case"])
def test_scope_and_actor_refusals_are_uniform(change: str) -> None:
    request = requested()
    principal = "operator-1"
    if change == "alias":
        request = requested(profile_alias="unknown")
    elif change == "record":
        request = requested(record_id="P3")
    elif change == "clock":
        request = requested(clock_alias="unknown")
    elif change == "provider":
        request = validated_request(
            {"provider": "jira", "profile_alias": "selected", "clock_alias": "workflow", "record_id": "10001"}
        )
    else:
        principal = "Operator-1" if change == "actor-case" else "unknown"
    with pytest.raises(profiles.ProfileUnavailable, match=r"^profile_unavailable$"):
        profiles.authorize_api_selection(profiles.ProfileStore(payload()), request, principal=principal)


def test_capability_snapshot_detaches_store_and_returned_models() -> None:
    raw = payload()
    store = profiles.ProfileStore(raw)
    selected = profiles.authorize_api_selection(store, requested(), principal="operator-1")
    binding = selected.profile_binding_sha256
    raw["profiles"][0]["record_ids"].clear()
    object.__setattr__(store, "_content", b"invalid")
    detached = selected.request
    object.__setattr__(detached, "record_id", "P2")
    returned_definition = selected.definition
    object.__setattr__(returned_definition, "label", "Changed")
    assert selected.request.record_id == "P1" and selected.definition.label == "Workflow observation"
    assert selected.profile_binding_sha256 == binding


def test_profile_binding_excludes_credentials_and_unrelated_grants() -> None:
    before = payload()
    after = payload()
    profile = after["profiles"][0]
    profile["credential_ref"] = "INCIDENT_CLOCK_REPLACED_TOKEN"
    profile["record_ids"].append("P3")
    profile["api_principals"].append("another-operator")
    first = profiles.authorize_api_selection(profiles.ProfileStore(before), requested(), principal="operator-1")
    second = profiles.authorize_api_selection(profiles.ProfileStore(after), requested(), principal="operator-1")
    assert first.profile_binding_sha256 == second.profile_binding_sha256
    after["profiles"][0]["clocks"][0]["declared_workflow_meaning"] = "Changed selected meaning"
    third = profiles.authorize_api_selection(profiles.ProfileStore(after), requested(), principal="operator-1")
    assert third.profile_binding_sha256 != first.profile_binding_sha256


def test_unissued_capability_and_subclasses_are_refused() -> None:
    with pytest.raises(profiles.ProfileUnavailable):
        profiles.AuthorizedSelection()
    with pytest.raises(profiles.ProfileUnavailable):
        profiles.validated_selection(object.__new__(profiles.AuthorizedSelection), requested())

    class Child(profiles.AuthorizedSelection):
        pass

    with pytest.raises(profiles.ProfileUnavailable):
        profiles.validated_selection(object.__new__(Child), requested())


def test_runtime_capabilities_are_redacted_immutable_and_unpickleable() -> None:
    store = profiles.ProfileStore(payload(cli=True))
    selected = profiles.authorize_cli_selection(store, requested())
    assert repr(selected) == "AuthorizedSelection(<redacted>)"
    assert repr(store) == "ProfileStore(<redacted>)"
    for value in (store, selected):
        with pytest.raises((AttributeError, TypeError)):
            value.extra = "value"  # type: ignore[attr-defined]
        with pytest.raises(TypeError):
            pickle.dumps(value)


@pytest.mark.parametrize(
    "key,value",
    [
        ("origin", "https://example.org"),
        ("api_principals", ["operator-1", "operator-1"]),
        ("api_principals", ["*"]),
        ("allow_local_cli", 1),
        ("record_ids", []),
        ("record_ids", ["P1", "P1"]),
        ("record_ids", ["P" + str(index) for index in range(129)]),
        ("clocks", []),
        ("credential_ref", "OTHER_TOKEN"),
        ("credential_ref", "INCIDENT_CLOCK_lower_TOKEN"),
    ],
)
def test_invalid_profile_values(key: str, value: object) -> None:
    raw = payload()
    raw["profiles"][0][key] = value
    with pytest.raises(profiles.ProfileError):
        profiles.ProfileStore(raw)


def test_profile_and_clock_aliases_must_be_unique() -> None:
    raw = payload()
    raw["profiles"].append(raw["profiles"][0])
    with pytest.raises(profiles.ProfileError):
        profiles.ProfileStore(raw)
    raw = payload()
    raw["profiles"][0]["clocks"] *= 2
    with pytest.raises(profiles.ProfileError):
        profiles.ProfileStore(raw)


@pytest.mark.parametrize(
    "origin",
    [
        "http://instance.example.org",
        "https://instance.example.org:444",
        "https://instance.example.org/path",
        "https://name@instance.example.org",
        "https://127.0.0.1",
        "https://[::1]",
        "https://INSTANCE.example.org",
        "https://instance.example.org?",
        "https://instance.example.org#",
        "https://instance.example.org/",
        "https://instance.example.org\\path",
    ],
)
def test_trusted_origin_refuses_unsupported_authority_or_url_parts(origin: str) -> None:
    with pytest.raises((profiles.ProfileError, ValueError)):
        profiles.canonical_origin(origin)


def test_trusted_origin_has_one_canonical_https_port() -> None:
    assert profiles.canonical_origin("https://instance.example.org:443") == "https://instance.example.org"
    assert profiles.canonical_origin("https://instance.example.org") == "https://instance.example.org"


def test_profile_load_is_bounded_and_detached(tmp_path: Path) -> None:
    source = tmp_path / "profiles.json"
    source.write_bytes(json.dumps(payload(cli=True)).encode("utf-8"))
    store = profiles.load_profile_store(source)
    source.write_bytes(b"{}")
    assert profiles.authorize_cli_selection(store, requested()).request.record_id == "P1"
    source.write_bytes(b" " * 65537)
    with pytest.raises(profiles.ProfileError):
        profiles.load_profile_store(source)


@pytest.mark.parametrize("name", ["CON", "NUL", "profiles.json:stream", "//server/share/profiles.json", "-"])
def test_special_file_names_are_refused_before_open(name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("File open reached for forbidden path")

    monkeypatch.setattr(os, "open", forbidden)
    with pytest.raises(profiles.ProfileError):
        profiles.load_profile_store(Path(name))


def test_load_rejects_directory_and_duplicate_json_keys(tmp_path: Path) -> None:
    with pytest.raises(profiles.ProfileError):
        profiles.load_profile_store(tmp_path)
    source = tmp_path / "duplicate.json"
    source.write_bytes(b'{"schema_version":"1","profiles":[],"profiles":[]}')
    with pytest.raises(profiles.ProfileError):
        profiles.load_profile_store(source)
