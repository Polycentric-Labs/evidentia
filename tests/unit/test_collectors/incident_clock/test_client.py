"""Exercise owned traversal with synthetic complete HTTP receipts and no provider calls."""

from __future__ import annotations

import hashlib
import json
import pickle
from datetime import UTC, datetime
from typing import Any

import pytest
from evidentia_collectors.incident_clock import _client as client
from evidentia_collectors.incident_clock import _contracts as contract
from evidentia_collectors.incident_clock import _profiles as profiles
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


def sources(provider: str = "jira") -> list[Any]:
    if provider == "servicenow":
        return [
            {
                "result": {
                    "sys_id": "1" * 32,
                    "u_start": "2024-01-01 00:00:00",
                    "u_end": "2024-01-01 00:00:01",
                    "unrelated": "excluded",
                }
            }
        ]
    if provider == "jira":
        return [
            [{"id": "11111111-1111-1111-1111-111111111111", "scopes": ["read:jira-work"], "name": "excluded site"}],
            {"id": "10001", "fields": {"created": "2023-12-01T00:00:00Z", "unrelated": "excluded"}},
            {
                "startAt": 0,
                "maxResults": 100,
                "total": 2,
                "isLast": True,
                "values": [
                    {
                        "id": "H1",
                        "created": "2024-01-01T00:00:00Z",
                        "items": [{"fieldId": "status", "from": None, "to": "100"}],
                    },
                    {
                        "id": "H2",
                        "created": "2024-01-01T00:00:01Z",
                        "items": [{"fieldId": "status", "from": "100", "to": "200"}],
                    },
                ],
            },
        ]
    return [
        {"incident": {"id": "P-123", "created_at": "2023-12-01T00:00:00Z", "unrelated": "excluded"}},
        {
            "offset": 0,
            "limit": 100,
            "total": 2,
            "more": False,
            "log_entries": [
                {
                    "id": "E1",
                    "type": "acknowledge_log_entry",
                    "created_at": "2024-01-01T00:00:00Z",
                    "incident": {"id": "P-123"},
                },
                {
                    "id": "E2",
                    "type": "resolve_log_entry",
                    "created_at": "2024-01-01T00:00:01Z",
                    "incident": {"id": "P-123"},
                },
            ],
        },
    ]


def transport(monkeypatch: pytest.MonkeyPatch, payloads: list[Any]) -> list[tuple[str, int | None]]:
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN", "Synthetic-" + str(12345))
    monkeypatch.setenv("INCIDENT_CLOCK_SESSION_TEST_EXPIRES_AT", "2099-01-01T00:00:00Z")
    calls: list[tuple[str, int | None]] = []

    def receive(
        selected: Any, material: Any, template: str, start: int | None, deadline: float, budget: Any
    ) -> HTTPReceipt:
        calls.append((template, start))
        payload = payloads.pop(0)
        if type(payload) is HTTPReceipt:
            return payload
        body = payload if type(payload) is bytes else json.dumps(payload, separators=(",", ":")).encode()
        budget.body_bytes += len(body)
        budget.wire_bytes += len(body) + 128
        return HTTPReceipt(200, datetime.now(UTC), body, len(body), len(body) + 128, None)

    monkeypatch.setattr(client, "get_identity", receive)
    return calls


def collect(session: client.IncidentReadSession) -> contract.IncidentClockResult:
    try:
        page = session.read_record()
        while page.accepted and not page.terminal:
            assert page.next_start is not None
            page = session.read_history_page(page.next_start)
        return contract.make_result(session.finish())
    finally:
        session.close()


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_native_source_is_projected_and_issued_without_unrelated_fields(
    monkeypatch: pytest.MonkeyPatch, provider: str
) -> None:
    payloads = sources(provider)
    expected = [hashlib.sha256(json.dumps(item, separators=(",", ":")).encode()).hexdigest() for item in payloads]
    calls = transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection(provider)))
    assert result.clock.state == "computed" and result.clock.elapsed_seconds == "1"
    assert result.source_state == "complete" and result.manifest.is_complete
    assert [read.body_sha256 for read in result.source_reads] == expected
    assert all(read.accepted and read.received_records is not None for read in result.source_reads)
    assert len(result.events) == 2 and len(calls) == len(expected)
    assert b"excluded" not in contract.result_bytes(result)
    assert result.manifest.total_findings == 1


@pytest.mark.parametrize(
    "problem",
    ["id", "unknown-item", "later-item", "duplicate", "total", "terminal", "cursor", "limit", "empty-nonterminal"],
)
def test_entire_bad_history_page_is_rejected_with_count_and_hash(monkeypatch: pytest.MonkeyPatch, problem: str) -> None:
    payloads = sources()
    page = payloads[-1]
    if problem == "id":
        page["values"][1]["id"] = None
    elif problem == "unknown-item":
        page["values"][1]["items"] = [{}]
    elif problem == "later-item":
        page["values"][1]["items"].append({"fieldId": "status", "from": [], "to": "200"})
    elif problem == "duplicate":
        page["values"][1]["id"] = "H1"
    elif problem == "total":
        page["total"] = "2"
    elif problem == "terminal":
        page["isLast"] = False
    elif problem == "cursor":
        page["startAt"] = 1
    elif problem == "limit":
        page["maxResults"] = True
    else:
        page["values"], page["isLast"] = [], False
    count = len(page["values"])
    digest = hashlib.sha256(json.dumps(page, separators=(",", ":")).encode()).hexdigest()
    calls = transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    assert result.source_state == "incomplete" and result.clock.state == "incomplete_source"
    assert result.events == [] and len(calls) == 3
    last = result.source_reads[-1]
    assert not last.accepted and last.body_complete and last.body_sha256 == digest
    assert last.received_records == count and last.admitted_events == 0 and last.pagination is None


@pytest.mark.parametrize("body", [b'{"a":1,"a":2}', b'{"values":NaN}', b'{"values":[', b'{"values":1e999}'])
def test_json_refusal_keeps_full_body_hash_and_unknown_count(monkeypatch: pytest.MonkeyPatch, body: bytes) -> None:
    payloads = sources()
    payloads[-1] = body
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    last = result.source_reads[-1]
    assert last.body_complete and last.body_sha256 == hashlib.sha256(body).hexdigest()
    assert last.received_records is None and last.diagnostic_codes == ["invalid_json"]
    assert result.events == []


@pytest.mark.parametrize("provider", ["jira", "pagerduty"])
def test_rejected_10001_outer_rows_are_counted_honestly(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    payloads = sources(provider)
    key = "values" if provider == "jira" else "log_entries"
    payloads[-1][key] = [{} for _ in range(10001)]
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection(provider)))
    last = result.source_reads[-1]
    assert last.received_records == 10001 and last.admitted_events == 0
    assert last.diagnostic_codes == ["event_limit"] and result.events == []


def test_later_page_refusal_preserves_earlier_whole_page(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = sources()
    first = payloads[-1]
    later = {**first, "startAt": 1, "values": [first["values"][1]]}
    first.update(isLast=False, values=[first["values"][0]])
    later["values"][0]["items"].append({})
    payloads.append(later)
    calls = transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    assert len(result.events) == 1 and result.events[0].occurrence.history_id == "H1"
    assert result.clock.start.candidate_event_ids == [result.events[0].event_id]
    assert result.clock.start.selected_event_id is None
    assert [read.accepted for read in result.source_reads] == [True, True, True, False]
    assert calls[-2:] == [("jira_changelog", 0), ("jira_changelog", 1)]


@pytest.mark.parametrize("grant", ["missing", "confluence-only", "conflicting", "duplicate-scope", "unknown-shape"])
def test_jira_site_grant_stops_before_the_record(monkeypatch: pytest.MonkeyPatch, grant: str) -> None:
    payloads = sources()
    first = payloads[0][0]
    if grant == "missing":
        payloads[0] = []
    elif grant == "confluence-only":
        first["scopes"] = ["read:confluence-content.all"]
    elif grant == "conflicting":
        payloads[0].append({**first, "scopes": ["read:jira-work", "write:jira-work"]})
    elif grant == "duplicate-scope":
        first["scopes"] *= 2
    else:
        first["scopes"] = None
    calls = transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    assert calls == [("jira_accessible_resources", None)]
    assert result.source_state == "unavailable" and result.record is None and result.events == []
    assert not result.source_reads[0].accepted


def test_matching_cloud_id_in_other_resource_type_does_not_invent_jira_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = sources()
    payloads[0].append({**payloads[0][0], "scopes": ["read:confluence-content.all"]})
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    assert result.source_state == "complete" and result.source_reads[0].received_records == 2


@pytest.mark.parametrize("value,expected", [(None, "null"), ("", "empty"), ("unparseable", "unsupported_timestamp")])
def test_servicenow_distinct_timestamp_states_survive(
    monkeypatch: pytest.MonkeyPatch, value: Any, expected: str
) -> None:
    payloads = sources("servicenow")
    payloads[0]["result"]["u_start"] = value
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection("servicenow")))
    assert result.source_state == "complete" and result.clock.start.state == expected
    assert result.events[0].timestamp.value == value


def test_servicenow_acl_hidden_field_stays_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = sources("servicenow")
    del payloads[0]["result"]["u_start"]
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection("servicenow")))
    assert result.events[0].timestamp.state == "missing"
    assert result.clock.start.state == "missing" and result.clock.elapsed_seconds is None


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_wrong_record_never_admits_creation_or_events(monkeypatch: pytest.MonkeyPatch, provider: str) -> None:
    payloads = sources(provider)
    row = (
        payloads[0]["result"]
        if provider == "servicenow"
        else payloads[1]
        if provider == "jira"
        else payloads[0]["incident"]
    )
    row["sys_id" if provider == "servicenow" else "id"] = "another-record"
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection(provider)))
    assert result.record is None and result.events == [] and result.source_state == "unavailable"
    assert result.source_reads[-1].diagnostic_codes == ["record_mismatch"]


def test_missing_credential_has_no_fake_read_and_no_material_in_output(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = transport(monkeypatch, [])
    monkeypatch.delenv("INCIDENT_CLOCK_SESSION_TEST_TOKEN")
    result = collect(client.IncidentReadSession(selection()))
    assert calls == [] and result.source_reads == [] and result.credential_validity == "not_established"
    assert result.source_state == "unavailable" and result.diagnostics[0].code == "credential_missing"


def test_page_and_session_cannot_be_constructed_copied_or_given_success_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    transport(monkeypatch, sources("servicenow"))
    session = client.IncidentReadSession(selection("servicenow"))
    page = session.read_record()
    for value in (session, page):
        with pytest.raises(AttributeError):
            value.accepted = True
        with pytest.raises(TypeError):
            pickle.dumps(value)
    with pytest.raises(client.IncidentReadError):
        client.AdmittedPage()
    with pytest.raises(client.IncidentReadError):
        client._page(object.__new__(client.AdmittedPage))
    with pytest.raises(client.IncidentReadError):
        session.read_record()
    result = contract.make_result(session.finish())
    assert result.source_state == "complete"
    assert session.finish() is session.finish()
    session.close()


def test_session_seals_immutable_authority_and_drops_credential_reference(monkeypatch: pytest.MonkeyPatch) -> None:
    transport(monkeypatch, sources("servicenow"))
    session = client.IncidentReadSession(selection("servicenow"))
    session.read_record()
    state = client._session(session)
    authority = session.finish()
    assert state.material is None
    state.events.clear()
    state.reads.clear()
    result = contract.make_result(authority)
    assert len(result.events) == 2 and len(result.source_reads) == 1 and result.clock.elapsed_seconds == "1"


def test_deadline_before_read_preserves_reserved_publication_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = transport(monkeypatch, [])
    tick = [100.0]
    monkeypatch.setattr(client.time, "monotonic", lambda: tick[0])
    session = client.IncidentReadSession(selection())
    tick[0] = 150.0
    result = collect(session)
    assert calls == [] and result.source_reads == []
    assert result.diagnostics[0].code == "deadline_exceeded" and result.source_state == "unavailable"


def test_expired_publication_budget_refuses_instead_of_issuing_late_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    transport(monkeypatch, sources("servicenow"))
    tick = [100.0]
    monkeypatch.setattr(client.time, "monotonic", lambda: tick[0])
    session = client.IncidentReadSession(selection("servicenow"))
    session.read_record()
    tick[0] = 160.0
    with pytest.raises(ValueError, match="deadline_exceeded"):
        session.finish()
    assert client._session(session).material is None


@pytest.mark.parametrize("complete", [True, False])
def test_http_refusal_does_not_parse_the_body(monkeypatch: pytest.MonkeyPatch, complete: bool) -> None:
    payloads = sources()
    body = b"{}" if complete else None
    payloads[-1] = HTTPReceipt(200, datetime.now(UTC), body, 2, 130, "deadline_exceeded")
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    last = result.source_reads[-1]
    assert last.body_complete == complete and last.received_records is None and not last.accepted
    assert last.body_sha256 == (hashlib.sha256(b"{}").hexdigest() if complete else None)


@pytest.mark.parametrize("changed", [True, False])
def test_duplicate_history_identity_in_unselected_fields_cannot_hide_across_pages(
    monkeypatch: pytest.MonkeyPatch, changed: bool
) -> None:
    payloads = sources()
    first = payloads[-1]
    row = {"id": "H1", "created": "2024-01-01T00:00:00Z", "items": [{"fieldId": "unselected", "from": "a", "to": "b"}]}
    first.update(isLast=False, values=[row])
    later_row = json.loads(json.dumps(row))
    if changed:
        later_row["items"][0]["to"] = "c"
    payloads.append({**first, "startAt": 1, "isLast": True, "values": [later_row]})
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    assert result.source_state == "incomplete" and result.events == []
    assert result.source_reads[-1].diagnostic_codes == ["source_conflict" if changed else "duplicate_occurrence"]


def test_late_factory_cannot_publish_an_earlier_sealed_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    transport(monkeypatch, sources("servicenow"))
    tick = [100.0]
    monkeypatch.setattr(client.time, "monotonic", lambda: tick[0])
    session = client.IncidentReadSession(selection("servicenow"))
    session.read_record()
    authority = session.finish()
    tick[0] = 160.0
    with pytest.raises(contract.IncidentInputError):
        contract.make_result(authority)


def test_deadline_crossed_during_factory_is_not_published(monkeypatch: pytest.MonkeyPatch) -> None:
    transport(monkeypatch, sources("servicenow"))
    tick = [100.0]
    monkeypatch.setattr(client.time, "monotonic", lambda: tick[0])
    session = client.IncidentReadSession(selection("servicenow"))
    session.read_record()
    authority = session.finish()
    original = contract._assemble_snapshot

    def slow(snapshot: Any) -> Any:
        result = original(snapshot)
        tick[0] = 160.0
        return result

    monkeypatch.setattr(contract, "_assemble_snapshot", slow)
    with pytest.raises(contract.IncidentInputError):
        contract.make_result(authority)


@pytest.mark.parametrize(
    "value,code", [(None, "event_null"), ("", "event_empty"), ("unsupported", "timestamp_unsupported")]
)
def test_incomplete_traversal_retains_observed_timestamp_problem(
    monkeypatch: pytest.MonkeyPatch, value: Any, code: str
) -> None:
    payloads = sources()
    page = payloads[-1]
    first = page["values"][0]
    first["created"] = value
    page.update(isLast=False, values=[first])
    payloads.append({"startAt": 1, "maxResults": 100, "total": 2, "isLast": True, "values": [{}]})
    transport(monkeypatch, payloads)
    result = collect(client.IncidentReadSession(selection()))
    assert result.clock.state == "incomplete_source" and result.clock.start.selected_event_id is None
    assert any(
        item.code == code and item.side == "start" and item.read_id == result.events[0].read_id
        for item in result.diagnostics
    )
    assert code in result.source_reads[2].diagnostic_codes
    assert result.events[0].timestamp.value == value


@pytest.mark.parametrize("stage", ["record", "history"])
@pytest.mark.parametrize("signal", [KeyboardInterrupt, SystemExit])
def test_read_cancellation_closes_owned_session_before_propagation(
    monkeypatch: pytest.MonkeyPatch, stage: str, signal: type[BaseException]
) -> None:
    provider = "servicenow" if stage == "record" else "jira"
    transport(monkeypatch, sources(provider))
    session = client.IncidentReadSession(selection(provider))
    if stage == "history":
        assert session.read_record().accepted

    def cancel(*args: Any) -> Any:
        raise signal()

    monkeypatch.setattr(client, "get_identity", cancel)
    with pytest.raises(signal):
        if stage == "record":
            session.read_record()
        else:
            session.read_history_page(0)
    state = client._session(session)
    assert state.material is None and state.closed and state.stopped
    with pytest.raises(client.IncidentReadError):
        session.finish()


@pytest.mark.parametrize("mode", ["already-expired", "during-serialization"])
def test_final_serialization_checks_originating_deadline_on_both_sides(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    transport(monkeypatch, sources("servicenow"))
    tick = [100.0]
    monkeypatch.setattr(client.time, "monotonic", lambda: tick[0])
    session = client.IncidentReadSession(selection("servicenow"))
    session.read_record()
    result = contract.make_result(session.finish())
    if mode == "already-expired":
        tick[0] = 160.0
    else:
        original = contract.result_json_bytes

        def late(value: Any) -> bytes:
            content = original(value)
            tick[0] = 160.0
            return content

        monkeypatch.setattr(contract, "result_json_bytes", late)
    with pytest.raises(contract.IncidentInputError):
        contract.result_bytes(result)


def _capacity_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _capacity_cell(value: str | None, *, missing: bool = False) -> dict[str, Any]:
    return {
        "state": "missing" if missing else "null" if value is None else "empty" if value == "" else "value",
        "value": value,
    }


def _capacity_read_id(req: dict[str, Any], ordinal: int) -> str:
    identity = hashlib.sha256(_capacity_json(req)).hexdigest()
    return "read-" + hashlib.sha256(_capacity_json({"request_identity": identity, "ordinal": ordinal})).hexdigest()


def _capacity_event(req: dict[str, Any], history: dict[str, Any], index: int, ordinal: int) -> dict[str, Any]:
    item = history["items"][index]
    occurrence = {"history_id": history["id"], "item_index": index}
    event_identity = {
        "provider": "jira",
        "profile_alias": req["profile_alias"],
        "record_id": req["record_id"],
        "occurrence": occurrence,
    }
    native = {key: _capacity_cell(item.get(key), missing=key not in item) for key in ("fieldId", "from", "to")}
    native["created"] = _capacity_cell(history.get("created"), missing="created" not in history)
    matches = ["start"] if item.get("from") is None and item.get("to") == "100" else []
    return {
        "event_id": "event-" + hashlib.sha256(_capacity_json(event_identity)).hexdigest(),
        "record_id": req["record_id"],
        "read_id": _capacity_read_id(req, ordinal),
        "occurrence": occurrence,
        "timestamp": native["created"],
        "native_fields": native,
        "matches": matches,
    }


def _capacity_case() -> tuple[list[Any], dict[str, Any], dict[str, Any], bytes, bytes]:
    req = selection("jira").request.model_dump(mode="json", by_alias=True)
    record = {
        "provider": "jira",
        "record_id": "10001",
        "read_id": _capacity_read_id(req, 1),
        "fields": {"id": _capacity_cell("10001"), "fields.created": _capacity_cell("2023-12-01T00:00:00Z")},
    }

    def prepare(count: int) -> tuple[list[dict[str, Any]], dict[str, Any], list[dict[str, Any]]]:
        first = []
        remaining = count - 1
        while remaining:
            take = min(256, remaining)
            first.append(
                {
                    "id": f"H{len(first):04d}",
                    "created": "t" * 2048,
                    "items": [{"fieldId": "status", "from": None, "to": "100"} for _ in range(take)],
                }
            )
            remaining -= take
        last = {"id": "FINAL", "created": "t" * 2048, "items": [{"fieldId": "status", "from": "x", "to": "100"}]}
        events = [_capacity_event(req, row, index, 2) for row in first for index in range(len(row["items"]))] + [
            _capacity_event(req, last, 0, 3)
        ]
        return first, last, events

    count = 2600
    first, last, events = prepare(count)
    initial = _capacity_json({"record": record, "events": events})
    unit = len(_capacity_json(events[-1])) + 1
    count += (12582912 - len(initial)) // unit
    first, last, events = prepare(count)
    initial = _capacity_json({"record": record, "events": events})
    while len(initial) > 12582912:
        count -= 1
        first, last, events = prepare(count)
        initial = _capacity_json({"record": record, "events": events})
    padding = 12582912 - len(initial)
    assert 0 <= padding < 65536
    last["items"][0]["from"] += "x" * padding
    events[-1] = _capacity_event(req, last, 0, 3)
    exact = _capacity_json({"record": record, "events": events})
    before = _capacity_json({"record": record, "events": events[:-1]})
    assert len(exact) == 12582912 and len(events) <= 10000 and len(first) < 100
    values = sources()[:2]
    values.append({"startAt": 0, "maxResults": 100, "total": len(first) + 1, "isLast": False, "values": first})
    last_page = {"startAt": len(first), "maxResults": 100, "total": len(first) + 1, "isLast": True, "values": [last]}
    return values, last_page, record, before, exact


@pytest.mark.parametrize("excess", [0, 1], ids=["exact-12mib", "plus-one"])
def test_projection_capacity_uses_whole_page_admission_and_a_real_deadline(
    monkeypatch: pytest.MonkeyPatch, excess: int
) -> None:
    import time

    values, last, expected_record, before, exact = _capacity_case()
    if excess:
        last["values"][0]["items"][0]["from"] += "x"
    transport(monkeypatch, [*values, last])
    started = time.monotonic()
    session = client.IncidentReadSession(selection())
    try:
        assert session.read_record().accepted
        assert session.read_history_page(0).accepted
        state = client._session(session)
        prior = _capacity_json(
            {
                "record": state.record.model_dump(mode="json", by_alias=True),
                "events": [event.model_dump(mode="json", by_alias=True) for event in state.events],
            }
        )
        assert prior == before
        page = session.read_history_page(last["startAt"])
        assert page.accepted == (excess == 0)
        result = contract.make_result(session.finish())
        content = contract.result_bytes(result)
        completed = time.monotonic()
        assert completed - started < 60 and completed < client._seed(state.seed).deadline
        wire = json.loads(content)
        assert wire["record"] == expected_record
        projected = _capacity_json({"record": wire["record"], "events": wire["events"]})
        assert projected == (before if excess else exact)
        assert len(exact) == 12582912 and len(content) <= 16777216
        if excess:
            assert result.source_reads[-1].diagnostic_codes == ["result_limit"]
            assert result.source_reads[-1].admitted_events == 0
        assert state.closed and state.material is None
    finally:
        session.close()


@pytest.mark.parametrize("boundary", ["direct", "collector"])
@pytest.mark.parametrize("cancel", [KeyboardInterrupt, SystemExit], ids=["interrupt", "exit"])
def test_constructor_cancellation_releases_material_before_ownership_transfer(
    monkeypatch: pytest.MonkeyPatch, boundary: str, cancel: type[BaseException]
) -> None:
    from types import SimpleNamespace

    from evidentia_collectors.incident_clock import collector

    selected = selection("servicenow")
    calls = transport(monkeypatch, [])
    observed: list[Any] = []
    original_check = client._check_time

    def checked(state: Any, *, publishing: bool = False) -> None:
        if state.material is not None:
            observed.append(state)
            raise cancel("synthetic constructor interruption")
        original_check(state, publishing=publishing)

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("adapter ran before construction completed")

    monkeypatch.setattr(client, "_check_time", checked)
    monkeypatch.setattr(collector, "import_module", lambda name: SimpleNamespace(collect=forbidden))
    try:
        with pytest.raises(cancel):
            if boundary == "direct":
                client.IncidentReadSession(selected)
            else:
                collector.IncidentClockCollector(selected).collect_v2(selected.request)
        assert len(observed) == 1 and calls == []
        assert observed[0].material is None and observed[0].stopped and observed[0].closed
    finally:
        for state in observed:
            state.material = None
            state.stopped = True
            state.closed = True
