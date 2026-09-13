"""Exercise the installed jira adapter against indexed synthetic source bytes."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from evidentia_collectors.incident_clock import _client as client
from evidentia_collectors.incident_clock import _contracts as contract
from evidentia_collectors.incident_clock import _profiles as profiles
from evidentia_collectors.incident_clock import jira as adapter
from evidentia_collectors.incident_clock._http import HTTPReceipt
from evidentia_collectors.incident_clock.collector import IncidentClockCollector


def selection(provider: str = "jira") -> profiles.AuthorizedSelection:
    request: dict[str, Any] = {
        "provider": provider,
        "profile_alias": "session-test",
        "clock_alias": "workflow",
        "record_id": "10001",
    }
    start: dict[str, Any] = {"label": "Start", "meaning": "Configured workflow start"}
    end: dict[str, Any] = {"label": "End", "meaning": "Configured workflow end"}
    if provider == "servicenow":
        request["record_id"] = "1" * 32
        start["field"], end["field"] = "u_start", "u_end"
    elif provider == "jira":
        start.update(
            field_id="status", **{"from": {"state": "null", "value": None}, "to": {"state": "value", "value": "100"}}
        )
        end.update(
            field_id="status", **{"from": {"state": "value", "value": "100"}, "to": {"state": "value", "value": "200"}}
        )
    else:
        request.update(record_id="P-123", since="2024-01-01T00:00:00Z", until="2025-01-01T00:00:00Z")
        start["event_type"], end["event_type"] = "acknowledge_log_entry", "resolve_log_entry"
    configured: dict[str, Any] = {
        "alias": "session-test",
        "provider": provider,
        "credential_ref": "INCIDENT_CLOCK_SESSION_TEST_TOKEN",
        "allow_local_cli": True,
        "record_ids": [request["record_id"]],
        "clocks": [
            {
                "clock_alias": "workflow",
                "label": "Workflow",
                "mapping_reference": "Synthetic runbook",
                "declared_workflow_meaning": "Two operational events",
                "start": start,
                "end": end,
            }
        ],
    }
    if provider == "jira":
        configured["cloud_id"] = "11111111-1111-1111-1111-111111111111"
    elif provider == "servicenow":
        configured["origin"] = "https://instance.example.org"
    return profiles.authorize_cli_selection(
        profiles.ProfileStore({"schema_version": "1", "profiles": [configured]}), contract.validated_request(request)
    )


PROVIDER = "jira"
FILES = ["accessible-resources.json", "issue.json", "changelog-page1.json", "changelog-page2.json"]


def prepare(
    monkeypatch: pytest.MonkeyPatch, *, refuse_last: bool = False
) -> tuple[list[tuple[str, int | None]], list[str]]:
    base = Path(__file__).resolve().parents[3] / "fixtures" / "incident_clock" / PROVIDER
    bodies = [(base / name).read_bytes() for name in FILES]
    hashes = [hashlib.sha256(body).hexdigest() for body in bodies]
    calls: list[tuple[str, int | None]] = []
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN", "Synthetic-" + str(12345))
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_EXPIRES_AT", "2099-01-01T00:00:00Z")

    def receive(
        selected: Any, material: Any, template: str, start: int | None, deadline: float, budget: Any
    ) -> HTTPReceipt:
        calls.append((template, start))
        body = bodies.pop(0)
        if refuse_last and not bodies:
            return HTTPReceipt(403, datetime.now(UTC), None, 0, 128, "http_forbidden")
        budget.body_bytes += len(body)
        budget.wire_bytes += len(body) + 128
        return HTTPReceipt(200, datetime.now(UTC), body, len(body), len(body) + 128, None)

    monkeypatch.setattr(client, "get_identity", receive)
    return calls, hashes


def test_installed_adapter_preserves_exact_selected_sources(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, hashes = prepare(monkeypatch)
    selected = selection(PROVIDER)
    with IncidentClockCollector(selected) as collector:
        result = collector.collect_v2(selected.request)
    assert result.source_state == "complete" and result.clock.elapsed_seconds == "1"
    assert [read.body_sha256 for read in result.source_reads] == hashes
    assert len(calls) == len(FILES) and len(result.events) == 2
    assert result.request == selected.request
    assert contract.IncidentClockResult.model_validate_json(contract.result_bytes(result)) == result


def test_partial_source_stops_and_keeps_accepted_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, hashes = prepare(monkeypatch, refuse_last=True)
    session = client.IncidentReadSession(selection(PROVIDER))
    result = adapter.collect(session)
    assert result.source_state != "complete" and result.clock.state == "incomplete_source"
    assert [read.body_sha256 for read in result.source_reads[:-1]] == hashes[:-1]
    assert not result.source_reads[-1].accepted and len(calls) == len(FILES)
    assert client._session(session).closed and client._session(session).material is None
    assert contract.result_bytes(result)


def test_missing_credential_never_traverses(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, _ = prepare(monkeypatch)
    monkeypatch.delenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN")
    result = adapter.collect(client.IncidentReadSession(selection(PROVIDER)))
    assert result.source_state == "unavailable" and result.source_reads == []
    assert calls == []


def test_wrong_provider_refuses_before_read_and_closes_owned_session(monkeypatch: pytest.MonkeyPatch) -> None:
    calls, _ = prepare(monkeypatch)
    session = client.IncidentReadSession(selection("jira" if PROVIDER != "jira" else "servicenow"))
    with pytest.raises(client.IncidentReadError):
        adapter.collect(session)
    assert calls == [] and client._session(session).closed and client._session(session).material is None


def test_custom_session_is_rejected_before_callback() -> None:
    calls: list[str] = []

    class Custom:
        @property
        def provider(self) -> str:
            calls.append("provider")
            return PROVIDER

        def close(self) -> None:
            calls.append("close")

    with pytest.raises(client.IncidentReadError):
        adapter.collect(Custom())
    assert calls == []


@pytest.mark.parametrize("error", [KeyboardInterrupt, SystemExit, RuntimeError])
def test_read_failure_drops_owned_material(monkeypatch: pytest.MonkeyPatch, error: type[BaseException]) -> None:
    prepare(monkeypatch)
    session = client.IncidentReadSession(selection(PROVIDER))

    def fail(*args: Any) -> Any:
        raise error()

    monkeypatch.setattr(client.IncidentReadSession, "read_record", fail)
    with pytest.raises(error):
        adapter.collect(session)
    assert client._session(session).closed and client._session(session).material is None
