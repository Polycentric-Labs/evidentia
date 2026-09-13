"""Check request authorization and owned-session correspondence at the collector boundary."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from evidentia_collectors.incident_clock import _client as client
from evidentia_collectors.incident_clock import _contracts as contract
from evidentia_collectors.incident_clock import _profiles as profiles
from evidentia_collectors.incident_clock import collector
from evidentia_collectors.incident_clock._http import HTTPReceipt


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


def wire(monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    sessions: list[Any] = []
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN", "Synthetic-" + str(12345))
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_EXPIRES_AT", "2099-01-01T00:00:00Z")
    body = json.dumps(
        {"result": {"sys_id": "1" * 32, "u_start": "2024-01-01 00:00:00", "u_end": "2024-01-01 00:00:01"}}
    ).encode()

    def receive(*args: Any) -> HTTPReceipt:
        return HTTPReceipt(200, datetime.now(UTC), body, len(body), len(body) + 128, None)

    def adapter(session: Any) -> Any:
        sessions.append(session)
        session.read_record()
        return contract.make_result(session.finish())

    monkeypatch.setattr(client, "get_identity", receive)
    monkeypatch.setattr(collector, "import_module", lambda name: SimpleNamespace(collect=adapter))
    return sessions


def test_collector_constructs_no_credentials_and_revalidates_request_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = selection("servicenow")
    calls: list[str] = []

    def forbidden(*args: Any) -> Any:
        calls.append("called")
        raise AssertionError("request refusal must precede work")

    monkeypatch.setattr(collector, "import_module", forbidden)
    monkeypatch.setattr(client, "resolve_material", forbidden)
    instance = collector.IncidentClockCollector(selected)
    for change in ({"record_id": "2" * 32}, {"clock_alias": "other"}, {"provider": "jira"}):
        request = selected.request.model_dump()
        request.update(change)
        with pytest.raises(profiles.ProfileUnavailable):
            instance.collect_v2(request)
    assert calls == []


def test_custom_selection_has_no_callback_before_uniform_refusal() -> None:
    calls: list[str] = []

    class Custom:
        @property
        def request(self) -> Any:
            calls.append("request")
            return {}

    with pytest.raises(profiles.ProfileUnavailable):
        collector.IncidentClockCollector(Custom())
    assert calls == []


def test_collector_accepts_only_its_own_session_and_retains_complete_result(monkeypatch: pytest.MonkeyPatch) -> None:
    sessions = wire(monkeypatch)
    selected = selection("servicenow")
    with collector.IncidentClockCollector(selected) as instance:
        result = instance.collect_v2(selected.request)
        assert result.clock.elapsed_seconds == "1" and len(result.events) == 2
        assert len(instance.collect(selected.request)) == 1
    assert len(sessions) == 2
    assert all(client._session(session).closed and client._session(session).material is None for session in sessions)
    with pytest.raises(ValueError, match="collector_closed"):
        instance.collect_v2(selected.request)


@pytest.mark.parametrize("mode", ["changed", "unissued", "another-run", "unexpected-error", "cancel"])
def test_adapter_failure_cannot_substitute_or_mutate_a_result(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    wire(monkeypatch)
    selected = selection("servicenow")
    old = collector.IncidentClockCollector(selected).collect_v2(selected.request)
    seen: list[Any] = []

    def adapter(session: Any) -> Any:
        seen.append(session)
        session.read_record()
        if mode == "unexpected-error":
            raise RuntimeError("synthetic private exception text")
        if mode == "cancel":
            raise KeyboardInterrupt()
        if mode == "another-run":
            return old
        result = contract.make_result(session.finish())
        if mode == "changed":
            result.events.clear()
            return result
        return contract.IncidentClockResult.model_validate_json(contract.result_bytes(result))

    monkeypatch.setattr(collector, "import_module", lambda name: SimpleNamespace(collect=adapter))
    if mode == "cancel":
        with pytest.raises(KeyboardInterrupt):
            collector.IncidentClockCollector(selected).collect_v2(selected.request)
    else:
        with pytest.raises(ValueError, match=r"^collector_failed$"):
            collector.IncidentClockCollector(selected).collect_v2(selected.request)
    assert seen and all(client._session(item).material is None and client._session(item).closed for item in seen)


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_indexed_synthetic_fixtures_pass_the_owned_session_and_collector(
    monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    import hashlib
    from pathlib import Path

    fixture_root = Path(__file__).resolve().parents[3] / "fixtures" / "incident_clock"
    index = json.loads((fixture_root / "source-index.json").read_bytes())
    assert len(index["fixtures"]) == 9
    for entry in index["fixtures"]:
        content = (fixture_root / entry["path"]).read_bytes()
        assert entry["kind"] == "authored_synthetic_response"
        assert len(content) == entry["bytes"] and hashlib.sha256(content).hexdigest() == entry["sha256"]
    names = {
        "servicenow": ["servicenow/record.json"],
        "jira": [
            "jira/accessible-resources.json",
            "jira/issue.json",
            "jira/changelog-page1.json",
            "jira/changelog-page2.json",
        ],
        "pagerduty": ["pagerduty/incident.json", "pagerduty/logs-page1.json", "pagerduty/logs-page2.json"],
    }[provider]
    pending = [(fixture_root / name).read_bytes() for name in names]
    hashes = [hashlib.sha256(content).hexdigest() for content in pending]
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN", "Synthetic-" + str(12345))
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_EXPIRES_AT", "2099-01-01T00:00:00Z")

    def receive(*args: Any) -> HTTPReceipt:
        content = pending.pop(0)
        return HTTPReceipt(200, datetime.now(UTC), content, len(content), len(content) + 128, None)

    def adapter(session: Any) -> Any:
        page = session.read_record()
        while page.accepted and not page.terminal:
            page = session.read_history_page(page.next_start)
        return contract.make_result(session.finish())

    monkeypatch.setattr(client, "get_identity", receive)
    monkeypatch.setattr(collector, "import_module", lambda name: SimpleNamespace(collect=adapter))
    selected = selection(provider)
    result = collector.IncidentClockCollector(selected).collect_v2(selected.request)
    assert result.source_state == "complete" and result.clock.elapsed_seconds == "1" and pending == []
    assert [read.body_sha256 for read in result.source_reads] == hashes
