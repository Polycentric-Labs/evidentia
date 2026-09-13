"""Check exact request scope and preserved workflow mapping values."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from pathlib import Path
from typing import Any, cast, get_args

import pytest
from evidentia_collectors.incident_clock import _contracts as contract
from pydantic import ValidationError


def request(provider: str = "jira") -> dict[str, Any]:
    value = {"provider": provider, "profile_alias": "test-profile", "clock_alias": "workflow", "record_id": "10001"}
    if provider == "servicenow":
        value["record_id"] = "1" * 32
    elif provider == "pagerduty":
        value.update(record_id="P-123", since="2024-01-01T00:00:00Z", until="2025-01-01T00:00:00Z")
    return value


def definition(provider: str = "jira") -> dict[str, Any]:
    start: dict[str, Any] = {"label": "Started", "meaning": "Recorded start of the configured workflow"}
    end: dict[str, Any] = {"label": "Ended", "meaning": "Recorded end of the configured workflow"}
    if provider == "servicenow":
        start["field"] = "u_workflow_start"
        end["field"] = "u_workflow_end"
    elif provider == "jira":
        start.update(
            field_id="status", **{"from": {"state": "null", "value": None}, "to": {"state": "value", "value": "100"}}
        )
        end.update(
            field_id="status", **{"from": {"state": "value", "value": "100"}, "to": {"state": "value", "value": "200"}}
        )
    else:
        start["event_type"] = "acknowledge_log_entry"
        end["event_type"] = "resolve_log_entry"
    return {
        "clock_alias": "workflow",
        "label": "Configured workflow",
        "mapping_reference": "Organization runbook v1",
        "declared_workflow_meaning": "Two configured operational events",
        "start": start,
        "end": end,
    }


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_request_round_trip_and_detached_identity(provider: str) -> None:
    raw = request(provider)
    admitted = contract.validated_request(raw)
    wire = json.dumps(raw).encode("utf-8")
    assert contract.parse_request(wire) == admitted
    assert contract.validated_request(admitted) == admitted
    expected = hashlib.sha256(
        json.dumps(admitted.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert contract.request_identity(admitted) == expected
    raw["record_id"] = "changed"
    assert admitted.record_id != "changed"


@pytest.mark.parametrize(
    "key,value",
    [
        ("provider", "Jira"),
        ("provider", 1),
        ("profile_alias", ""),
        ("profile_alias", "x" * 65),
        ("profile_alias", "bad/profile"),
        ("clock_alias", True),
        ("record_id", 10001),
        ("record_id", "010001"),
        ("record_id", "TEST-1"),
        ("record_id", "1" * 33),
        ("record_id", "10001\n"),
        ("origin", "https://example.org"),
        ("principal", "caller"),
        ("profiles_file", "local.json"),
        ("start_occurrence", {"history_id": "H", "item_index": True}),
        ("start_occurrence", {"history_id": "H", "item_index": "1"}),
        ("start_occurrence", {"history_id": "H", "item_index": 256}),
        ("start_occurrence", {"history_id": "H", "item_index": -1}),
        ("start_occurrence", {"history_id": " ", "item_index": 0}),
        ("start_occurrence", {"history_id": "H" + chr(0), "item_index": 0}),
        ("start_occurrence", {"history_id": chr(0xE9) * 129, "item_index": 0}),
        ("start_occurrence", {"history_id": "H", "item_index": 0, "extra": 1}),
    ],
)
def test_request_rejects_out_of_scope_or_coercible_values(key: str, value: object) -> None:
    raw = request()
    raw[key] = value
    with pytest.raises(contract.IncidentInputError, match=r"^invalid_request$"):
        contract.validated_request(raw)


def test_nested_native_types_hold_even_with_lax_pydantic_call() -> None:
    raw = request()
    raw["start_occurrence"] = {"history_id": "H", "item_index": "1"}
    with pytest.raises(ValidationError):
        contract.JiraRequest.model_validate(raw, strict=False)
    with pytest.raises(ValidationError):
        contract.JiraOccurrence.model_validate({"history_id": "H", "item_index": True}, strict=False)


def test_native_opaque_identity_keeps_case_and_internal_spacing() -> None:
    raw = request()
    raw["start_occurrence"] = {"history_id": " H i ", "item_index": 255}
    result = contract.validated_request(raw)
    assert type(result) is contract.JiraRequest and result.start_occurrence is not None
    assert result.start_occurrence.history_id == " H i "
    assert result.start_occurrence.item_index == 255


def test_provider_occurrence_shapes_cannot_cross() -> None:
    for provider, occurrence in [
        ("servicenow", {"field": "u_start"}),
        ("jira", {"event_id": "E"}),
        ("pagerduty", {"history_id": "H", "item_index": 0}),
    ]:
        raw = request(provider)
        raw["start_occurrence"] = occurrence
        with pytest.raises(contract.IncidentInputError):
            contract.validated_request(raw)


@pytest.mark.parametrize(
    "since,until",
    [
        ("2024-01-01T00:00:00Z", "2025-01-01T00:00:00.000000001Z"),
        ("2025-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
        ("2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
        ("2024-01-01T00:00:00", "2024-01-02T00:00:00Z"),
    ],
)
def test_requested_interval_is_explicit_ordered_and_bounded(since: str, until: str) -> None:
    raw = request("pagerduty")
    raw.update(since=since, until=until)
    with pytest.raises(contract.IncidentInputError):
        contract.validated_request(raw)


def test_request_wire_limit_and_duplicate_keys() -> None:
    raw = request()
    wire = json.dumps(raw).encode("ascii")
    assert contract.parse_request(wire + b" " * (16384 - len(wire))) == contract.validated_request(raw)
    for invalid in (wire + b" " * (16385 - len(wire)), wire[:-1] + b',"provider":"jira"}'):
        with pytest.raises(contract.IncidentInputError):
            contract.parse_request(invalid)


def test_foreign_model_callbacks_are_never_used() -> None:
    called: list[str] = []

    def forbidden(*_args: object, **_kwargs: object) -> None:
        called.append("callback")
        raise AssertionError("Foreign callback executed")

    meta = type("ForeignMeta", (type,), {"__hash__": forbidden, "__eq__": forbidden})
    value = meta("Foreign", (), {"model_dump": forbidden})()
    with pytest.raises(contract.IncidentInputError):
        contract.validated_request(value)
    raw = request()
    raw["profile_alias"] = type("ForeignText", (str,), {})("test-profile")
    with pytest.raises(contract.IncidentInputError):
        contract.validated_request(raw)
    assert called == []


def test_mutated_known_request_is_reconstructed() -> None:
    admitted = contract.validated_request(request())
    object.__setattr__(admitted, "record_id", "OTHER-1")
    with pytest.raises(contract.IncidentInputError):
        contract.validated_request(admitted)
    with pytest.raises(contract.IncidentInputError):
        contract.request_identity(admitted)


def test_extra_internal_fields_and_uninitialized_models_are_refused() -> None:
    admitted = contract.validated_request(request())
    object.__setattr__(admitted, "extra", 1)
    for value in (admitted, object.__new__(contract.JiraRequest)):
        with pytest.raises(contract.IncidentInputError):
            contract.validated_request(value)


@pytest.mark.parametrize(
    "raw,state,value",
    [({}, "missing", None), ({"x": None}, "null", None), ({"x": ""}, "empty", ""), ({"x": " V "}, "value", " V ")],
)
def test_native_cells_preserve_distinct_source_states(raw: dict[str, object], state: str, value: str | None) -> None:
    cell = contract.native_text_cell(raw, "x")
    assert cell.state == state and cell.value == value


@pytest.mark.parametrize("value", [0, True, [], {}, type("TextChild", (str,), {})("value")])
def test_declared_source_cell_refuses_non_native_text(value: object) -> None:
    with pytest.raises(contract.IncidentInputError):
        contract.native_text_cell({"x": value}, "x")


@pytest.mark.parametrize(
    "state,value", [("missing", ""), ("null", "null"), ("empty", None), ("value", ""), ("value", None)]
)
def test_native_cell_cannot_mislabel_value(state: str, value: str | None) -> None:
    with pytest.raises(ValidationError):
        contract.NativeTextCell.model_validate({"state": state, "value": value})


def test_cell_bound_uses_utf8_and_keeps_literal_controls() -> None:
    literal = chr(0xE9) * 1024
    assert contract.native_text_cell({"x": literal}, "x", maximum=2048).value == literal
    with pytest.raises(contract.IncidentInputError):
        contract.native_text_cell({"x": literal + "x"}, "x", maximum=2048)
    assert contract.native_text_cell({"x": "before" + chr(0) + "after"}, "x").value == "before" + chr(0) + "after"


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_definition_digest_binds_complete_declared_meaning(provider: str) -> None:
    raw = definition(provider)
    expected = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    admitted = contract.published_definition(cast(contract.Provider, provider), raw)
    assert admitted.definition_sha256 == expected
    assert contract.published_definition(cast(contract.Provider, provider), admitted) == admitted
    raw["declared_workflow_meaning"] = "Different operational meaning"
    assert contract.published_definition(cast(contract.Provider, provider), raw).definition_sha256 != expected
    object.__setattr__(admitted, "declared_workflow_meaning", "Changed without rebinding")
    with pytest.raises(contract.IncidentInputError):
        contract.published_definition(cast(contract.Provider, provider), admitted)


def test_same_servicenow_fields_and_unknown_pagerduty_types_are_refused() -> None:
    raw = definition("servicenow")
    raw["end"]["field"] = raw["start"]["field"]
    with pytest.raises(contract.IncidentInputError):
        contract.published_definition("servicenow", raw)
    raw = definition("pagerduty")
    raw["start"]["event_type"] = "legal_determination"
    with pytest.raises(contract.IncidentInputError):
        contract.published_definition("pagerduty", raw)


def test_jira_definition_preserves_exact_transition_and_rejects_missing_cells() -> None:
    raw = definition()
    raw["start"]["to"]["value"] = " Case Preserved "
    admitted = contract.published_definition("jira", raw)
    assert type(admitted.start) is contract.JiraMapping and admitted.start.to.value == " Case Preserved "
    raw["start"]["from"] = {"state": "missing", "value": None}
    with pytest.raises(contract.IncidentInputError):
        contract.published_definition("jira", raw)


def test_definition_provider_and_transition_byte_caps() -> None:
    with pytest.raises(contract.IncidentInputError):
        contract.published_definition("pagerduty", definition("jira"))
    raw = definition()
    raw["start"]["to"]["value"] = "a" * 65536
    assert contract.published_definition("jira", raw).start is not None
    raw["start"]["to"]["value"] += "b"
    with pytest.raises(contract.IncidentInputError):
        contract.published_definition("jira", raw)


def test_wall_clock_requires_native_aware_utc() -> None:
    now = datetime(2024, 1, 1, tzinfo=UTC)
    assert contract.utc_clock(now) == now
    for invalid in ("2024-01-01T00:00:00Z", datetime(2024, 1, 1), now.replace(tzinfo=timezone(timedelta(hours=1)))):
        with pytest.raises(contract.IncidentInputError):
            contract.utc_clock(invalid)


def source_event(
    provider: str, identity: str, side: str, literal: str | None, *, missing: bool = False
) -> contract.SourceEvent:
    selected = contract.validated_request(request(provider))
    timestamp = {
        "state": "missing" if missing else "null" if literal is None else "empty" if literal == "" else "value",
        "value": literal,
    }

    def cell(value: str) -> dict[str, str]:
        return {"state": "value", "value": value}

    if provider == "jira":
        occurrence: contract.Occurrence = contract.JiraOccurrence(history_id=identity, item_index=0)
        fields = {
            "fieldId": cell("status"),
            "from": {"state": "null", "value": None} if side == "start" else cell("100"),
            "to": cell("100" if side == "start" else "200"),
            "created": timestamp,
        }
    elif provider == "pagerduty":
        occurrence = contract.PagerDutyOccurrence(event_id=identity)
        fields = {
            "id": cell(identity),
            "type": cell("acknowledge_log_entry" if side == "start" else "resolve_log_entry"),
            "created_at": timestamp,
            "incident.id": cell(selected.record_id),
        }
    else:
        occurrence = contract.ServiceNowOccurrence(field="u_workflow_start" if side == "start" else "u_workflow_end")
        fields = {"field": cell(occurrence.field), "value": timestamp}
    return contract.SourceEvent.model_validate(
        {
            "event_id": contract.event_identity(selected, occurrence),
            "record_id": selected.record_id,
            "read_id": contract.read_identity(selected, 0 if provider == "servicenow" else 2),
            "occurrence": occurrence,
            "timestamp": timestamp,
            "native_fields": fields,
            "matches": [side],
        }
    )


def read_data() -> dict[str, Any]:
    return {
        "read_id": "read-" + "1" * 64,
        "ordinal": 2,
        "kind": "history",
        "template": "jira_changelog",
        "state": "admitted",
        "http_status": 200,
        "retrieved_at": datetime(2024, 1, 1, tzinfo=UTC),
        "body_bytes": 100,
        "body_complete": True,
        "body_sha256": "2" * 64,
        "accepted": True,
        "pagination": {"start": 0, "limit": 100, "total": 2, "terminal": True, "returned": 2},
        "received_records": 2,
        "admitted_events": 2,
        "diagnostic_codes": [],
        "wire_bytes": 160,
    }


def test_admitted_read_and_rejected_large_observed_count() -> None:
    value = contract.SourceRead.model_validate(read_data())
    assert value.accepted and value.received_records == 2
    raw = read_data()
    raw.update(
        state="rejected",
        accepted=False,
        pagination=None,
        received_records=10001,
        admitted_events=0,
        diagnostic_codes=["event_limit"],
    )
    rejected = contract.SourceRead.model_validate(raw)
    assert rejected.received_records == 10001 and rejected.body_sha256 == "2" * 64
    raw.update(body_complete=False, body_sha256=None, received_records=None)
    assert contract.SourceRead.model_validate(raw).received_records is None


@pytest.mark.parametrize(
    "key,value",
    [
        ("ordinal", True),
        ("ordinal", 102),
        ("ordinal", -1),
        ("body_bytes", 1048578),
        ("body_bytes", -1),
        ("wire_bytes", 1179650),
        ("wire_bytes", 99),
        ("received_records", 100001),
        ("received_records", -1),
        ("received_records", True),
        ("admitted_events", 10001),
        ("admitted_events", -1),
        ("http_status", 600),
        ("http_status", 99),
        ("http_status", True),
        ("body_complete", 1),
        ("body_sha256", None),
        ("state", "rejected"),
        ("kind", "record"),
        ("template", "custom_endpoint"),
        ("diagnostic_codes", ["event_limit", "event_limit"]),
        ("diagnostic_codes", ["raw_exception"]),
        ("pagination", None),
        ("received_records", 3),
        ("body_bytes", 1048577),
        ("http_status", 404),
    ],
)
def test_source_read_native_and_consistency_boundaries(key: str, value: object) -> None:
    raw = read_data()
    raw[key] = value
    with pytest.raises(ValidationError):
        contract.SourceRead.model_validate(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"start": -1},
        {"start": 10001},
        {"limit": 0},
        {"limit": 101},
        {"returned": 101},
        {"total": 1000000001},
        {"total": 1},
        {"terminal": False},
        {"returned": True},
        {"returned": 0, "terminal": False},
    ],
)
def test_pagination_requires_exact_bounded_counters(changes: dict[str, object]) -> None:
    raw = {"start": 0, "limit": 100, "total": 2, "terminal": True, "returned": 2}
    raw.update(changes)
    with pytest.raises(ValidationError):
        contract.DeclaredPagination.model_validate(raw)


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_complete_selected_events_compute_exact_elapsed(provider: str) -> None:
    start_literal = "2024-01-01 00:00:00" if provider == "servicenow" else "2024-01-01T00:00:00.1Z"
    end_literal = "2024-01-01 00:00:01" if provider == "servicenow" else "2024-01-01T00:00:00.3Z"
    events = [source_event(provider, "H1", "start", start_literal), source_event(provider, "H2", "end", end_literal)]
    clock = contract.derive_clock(
        contract.validated_request(request(provider)),
        contract.published_definition(cast(contract.Provider, provider), definition(provider)),
        "complete",
        events,
    )
    assert clock.state == "computed" and clock.elapsed_seconds == ("1" if provider == "servicenow" else "0.2")
    assert clock.start.source_literal == start_literal and clock.end.source_literal == end_literal


@pytest.mark.parametrize("state", ["incomplete", "unavailable"])
def test_incomplete_source_only_exposes_provisional_candidates(state: str) -> None:
    events = [
        source_event("jira", "H1", "start", "2024-01-01T00:00:00Z"),
        source_event("jira", "H2", "end", "2024-01-01T00:00:01Z"),
    ]
    clock = contract.derive_clock(
        contract.validated_request(request()),
        contract.published_definition("jira", definition()),
        cast(contract.SourceState, state),
        events,
    )
    assert clock.state == "incomplete_source" and clock.elapsed_seconds is None
    for selected, event in [(clock.start, events[0]), (clock.end, events[1])]:
        assert selected.state == "incomplete" and selected.candidate_event_ids == [event.event_id]
        assert selected.selected_event_id is None and selected.source_literal is None and selected.utc_seconds is None


def test_repeated_matches_require_explicit_supported_occurrence() -> None:
    selected = contract.validated_request(request())
    bound = contract.published_definition("jira", definition())
    events = [
        source_event("jira", "H1", "start", None),
        source_event("jira", "H2", "start", "2024-01-01T00:00:00Z"),
        source_event("jira", "H3", "end", "2024-01-01T00:00:01Z"),
    ]
    assert contract.derive_clock(selected, bound, "complete", events).start.state == "ambiguous"
    raw = request()
    raw["start_occurrence"] = {"history_id": "H1", "item_index": 0}
    clock = contract.derive_clock(contract.validated_request(raw), bound, "complete", events)
    assert clock.start.state == "null" and clock.start.selected_event_id == events[0].event_id
    raw["start_occurrence"] = {"history_id": "H2", "item_index": 0}
    assert contract.derive_clock(contract.validated_request(raw), bound, "complete", events).elapsed_seconds == "1"
    raw["start_occurrence"] = {"history_id": "H3", "item_index": 0}
    assert (
        contract.derive_clock(contract.validated_request(raw), bound, "complete", events).start.state
        == "occurrence_not_found"
    )


@pytest.mark.parametrize(
    "literal,expected", [(None, "null"), ("", "empty"), ("not a timestamp", "unsupported_timestamp")]
)
def test_selected_unusable_timestamp_is_preserved(literal: str | None, expected: str) -> None:
    event = source_event("jira", "H1", "start", literal)
    clock = contract.derive_clock(
        contract.validated_request(request()), contract.published_definition("jira", definition()), "complete", [event]
    )
    assert clock.start.state == expected and clock.start.source_literal == literal
    assert clock.start.selected_event_id == event.event_id and clock.start.utc_seconds is None
    assert clock.state == "unresolved_events" and clock.end.state == "missing"


def test_missing_servicenow_field_is_distinct_from_missing_candidate() -> None:
    event = source_event("servicenow", "ignored", "start", None, missing=True)
    clock = contract.derive_clock(
        contract.validated_request(request("servicenow")),
        contract.published_definition("servicenow", definition("servicenow")),
        "complete",
        [event],
    )
    assert clock.start.state == "missing" and clock.start.selected_event_id == event.event_id
    assert clock.end.state == "missing" and clock.end.selected_event_id is None


def test_reversed_source_events_do_not_clamp_or_take_absolute_value() -> None:
    events = [
        source_event("jira", "H1", "start", "2024-01-01T00:00:02Z"),
        source_event("jira", "H2", "end", "2024-01-01T00:00:01Z"),
    ]
    clock = contract.derive_clock(
        contract.validated_request(request()), contract.published_definition("jira", definition()), "complete", events
    )
    assert clock.state == "reversed_order" and clock.elapsed_seconds is None


def test_duplicate_identity_and_adapter_supplied_match_tampering_are_refused() -> None:
    event = source_event("jira", "H1", "start", "2024-01-01T00:00:00Z")
    selected = contract.validated_request(request())
    bound = contract.published_definition("jira", definition())
    with pytest.raises(contract.IncidentInputError):
        contract.derive_clock(selected, bound, "complete", [event, event])
    object.__setattr__(event, "matches", ["end"])
    with pytest.raises(contract.IncidentInputError):
        contract.derive_clock(selected, bound, "complete", [event])


@pytest.mark.parametrize(
    "text",
    ["+1", "01", "-0", "1.0", "1e0", "0.00", "-0.00", "253402300800", "-62135596800.1", "0." + "1" * 2001],
    ids=[
        "plus",
        "leading-zero",
        "negative-zero",
        "trailing-zero",
        "exponent",
        "zero-fraction",
        "negative-zero-fraction",
        "upper-year",
        "lower-year",
        "fraction-limit",
    ],
)
def test_noncanonical_or_out_of_range_epoch_decimal(text: str) -> None:
    with pytest.raises(contract.IncidentInputError):
        contract._decimal_bound(text, signed=True)


def test_canonical_epoch_decimal_preserves_subsecond_negative_instant() -> None:
    assert contract._decimal_bound("-0.9", signed=True) == "-0.9"
    with pytest.raises(contract.IncidentInputError):
        contract._decimal_bound("-0.9", signed=False)


@pytest.mark.parametrize("operation", ["clock", "read"])
@pytest.mark.parametrize("raises", [False, True])
def test_custom_timezone_is_rejected_before_callbacks(operation: str, raises: bool) -> None:
    calls: list[str] = []

    class ForeignZone(tzinfo):
        def utcoffset(self, value: datetime | None) -> timedelta:
            calls.append("utcoffset")
            if raises:
                raise RuntimeError("untrusted_timezone")
            return timedelta(0)

        def dst(self, value: datetime | None) -> timedelta:
            calls.append("dst")
            return timedelta(0)

    value = datetime(2024, 1, 1, tzinfo=ForeignZone())
    with pytest.raises((contract.IncidentInputError, ValidationError)):
        if operation == "clock":
            contract.utc_clock(value)
        else:
            contract.SourceRead.model_validate({**read_data(), "retrieved_at": value})
    assert calls == []


@pytest.mark.parametrize("mode", ["unreceived", "incomplete", "invalid-json"])
@pytest.mark.parametrize("count", [0, 1])
def test_unknown_source_count_stays_null(mode: str, count: int) -> None:
    data = read_data()
    data.update(state="rejected", accepted=False, pagination=None, admitted_events=0, received_records=count)
    if mode == "unreceived":
        data.update(
            state="unavailable",
            http_status=None,
            body_complete=False,
            body_sha256=None,
            body_bytes=0,
            wire_bytes=0,
            diagnostic_codes=["dns_failure"],
        )
    elif mode == "incomplete":
        data.update(body_complete=False, body_sha256=None, diagnostic_codes=["read_timeout"])
    else:
        data["diagnostic_codes"] = ["invalid_json"]
    with pytest.raises(ValidationError):
        contract.SourceRead.model_validate(data)
    data["received_records"] = None
    assert contract.SourceRead.model_validate(data).received_records is None


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_definition_alias_is_bound_before_derivation(provider: str) -> None:
    data = definition(provider)
    data["clock_alias"] = "other-workflow"
    with pytest.raises(contract.IncidentInputError):
        contract.derive_clock(
            contract.validated_request(request(provider)), contract.published_definition(provider, data), "complete", []
        )


def test_source_clock_json_round_trip_and_python_native_boundary() -> None:
    source = contract.SourceRead.model_validate(read_data())
    wire = source.model_dump_json()
    assert contract.SourceRead.model_validate_json(wire) == source
    data = source.model_dump(mode="json")
    assert data["retrieved_at"] == "2024-01-01T00:00:00.000000Z"
    with pytest.raises(ValidationError):
        contract.SourceRead.model_validate(data)
    for value in [
        "2024-01-01T00:00:00.000000+00:00",
        "2024-01-01T00:00:00.0000001Z",
        "2024-02-30T00:00:00.000000Z",
        "2024-01-01T00:00:00.000000Zx",
        0,
    ]:
        data["retrieved_at"] = value
        with pytest.raises(ValidationError):
            contract.SourceRead.model_validate_json(json.dumps(data))
    named_utc = datetime(2024, 1, 1, tzinfo=timezone(timedelta(0), "native UTC"))
    assert contract.utc_clock(named_utc).tzinfo is UTC


def publication_source(provider: str = "jira") -> tuple[Any, list[Any], Any, list[Any]]:
    from evidentia_collectors.incident_clock import _profiles as profiles

    selected = contract.validated_request(request(provider))
    configured = {
        "alias": selected.profile_alias,
        "provider": provider,
        "credential_ref": "INCIDENT_CLOCK_PUBLICATION_TEST_TOKEN",
        "allow_local_cli": True,
        "record_ids": [selected.record_id],
        "clocks": [definition(provider)],
    }
    if provider == "jira":
        configured["cloud_id"] = "11111111-1111-1111-1111-111111111111"
    elif provider == "servicenow":
        configured["origin"] = "https://instance.example.org"
    capability = profiles.authorize_cli_selection(
        profiles.ProfileStore({"schema_version": "1", "profiles": [configured]}), selected
    )
    record_ordinal = 1 if provider == "jira" else 0
    event_ordinal = record_ordinal if provider == "servicenow" else record_ordinal + 1
    first = "2024-01-01 00:00:00" if provider == "servicenow" else "2024-01-01T00:00:00Z"
    last = first.replace("00:00:00", "00:00:01")
    events = [source_event(provider, "H1", "start", first), source_event(provider, "H2", "end", last)]
    events = [event.model_copy(update={"read_id": contract.read_identity(selected, event_ordinal)}) for event in events]
    fields = {"sys_id" if provider == "servicenow" else "id": {"state": "value", "value": selected.record_id}}
    if provider == "servicenow":
        fields.update(
            u_workflow_start=contract._native(events[0].timestamp), u_workflow_end=contract._native(events[1].timestamp)
        )
    else:
        fields["fields.created" if provider == "jira" else "created_at"] = {"state": "value", "value": first}
    record = contract.SelectedRecordProjection.model_validate(
        {
            "provider": provider,
            "record_id": selected.record_id,
            "read_id": contract.read_identity(selected, record_ordinal),
            "fields": fields,
        }
    )
    reads = []
    templates = (
        ["jira_accessible_resources", "jira_issue", "jira_changelog"]
        if provider == "jira"
        else ["servicenow_record"]
        if provider == "servicenow"
        else ["pagerduty_incident", "pagerduty_log_entries"]
    )
    for ordinal, template in enumerate(templates):
        is_history = template in ("jira_changelog", "pagerduty_log_entries")
        data = read_data()
        data.update(
            read_id=contract.read_identity(selected, ordinal),
            ordinal=ordinal,
            template=template,
            kind="history" if is_history else "jira_access" if template == "jira_accessible_resources" else "record",
            pagination={"start": 0, "limit": 100, "total": 2, "terminal": True, "returned": 2} if is_history else None,
            received_records=2 if is_history else 1,
            admitted_events=2 if ordinal == event_ordinal else 0,
        )
        reads.append(contract.SourceRead.model_validate(data))
    return capability, reads, record, events


def issued_publication(provider: str = "jira") -> tuple[Any, Any, list[Any], Any, list[Any]]:
    from evidentia_collectors.incident_clock import _client as client

    selected, reads, record, events = publication_source(provider)
    seed = client._new_seed(selected)
    authority = client._issue_authority(
        seed, credential_validity="expiry_checked", reads=reads, record=record, events=events, diagnostics=[]
    )
    return authority, contract.make_result(authority), reads, record, events


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_issued_publication_reconstructs_inherited_fields_and_round_trips(provider: str) -> None:
    from uuid import NAMESPACE_URL, uuid5

    from evidentia_core.audit.provenance import CollectionContext, CollectionManifest, CoverageCount
    from evidentia_core.models.finding import SecurityFinding

    _, result, _, _, _ = issued_publication(provider)
    wire = contract.result_bytes(result)
    detached = json.loads(wire)
    assert result.source_state == "complete" and result.clock.elapsed_seconds == "1"
    assert result.manifest.is_complete and result.manifest.errors == [] and result.manifest.total_findings == 1
    finding = result.findings[0]
    assert isinstance(finding, SecurityFinding) and isinstance(finding.collection_context, CollectionContext)
    assert isinstance(result.manifest, CollectionManifest) and isinstance(
        result.manifest.coverage_counts[0], CoverageCount
    )
    expected_id = str(
        uuid5(
            NAMESPACE_URL,
            "evidentia:incident-clock:"
            + contract.request_identity(result.request)
            + ":"
            + result.profile_binding_sha256,
        )
    )
    assert finding.id == expected_id and finding.source_finding_id is None
    assert finding.collection_context.credential_identity == "not-established"
    assert finding.first_observed == finding.last_observed == finding.collection_context.collected_at
    assert finding.compliance_status == "unknown" and finding.control_mappings == []
    assert finding.raw_data.definition_sha256 == result.definition.definition_sha256
    assert set(detached["findings"][0]["raw_data"]) == set(contract.IncidentClockSummary.model_fields)
    restored = contract.IncidentClockResult.model_validate_json(wire)
    assert contract._json_values(restored) == detached
    with pytest.raises(contract.IncidentInputError):
        contract.result_bytes(restored)


def test_original_source_mutation_cannot_change_issued_authority() -> None:
    authority, original, reads, record, events = issued_publication()
    content = contract.result_bytes(original)
    object.__setattr__(reads[0], "received_records", 99)
    object.__setattr__(record, "fields", {})
    object.__setattr__(events[0], "matches", [])
    assert contract.result_bytes(contract.make_result(authority)) == content


@pytest.mark.parametrize(
    "field",
    [
        "run_id",
        "request",
        "definition",
        "source_state",
        "clock",
        "events",
        "record",
        "source_reads",
        "diagnostics",
        "findings",
        "manifest",
        "profile_binding_sha256",
        "credential_validity",
    ],
)
def test_every_result_section_is_bound_to_issued_evidence(field: str) -> None:
    _, result, _, _, _ = issued_publication()
    object.__setattr__(result, field, None)
    with pytest.raises(contract.IncidentInputError):
        contract.result_bytes(result)


@pytest.mark.parametrize("kind", ["context", "coverage", "manifest", "finding"])
def test_every_inherited_publication_field_is_required(kind: str) -> None:
    _, result, _, _, _ = issued_publication()
    instance = {
        "context": result.findings[0].collection_context,
        "coverage": result.manifest.coverage_counts[0],
        "manifest": result.manifest,
        "finding": result.findings[0],
    }[kind]
    data = contract._native(instance)
    assert all(field.is_required() for field in type(instance).model_fields.values())
    for name in data:
        incomplete = {key: value for key, value in data.items() if key != name}
        with pytest.raises((ValueError, ValidationError)):
            type(instance).model_validate(incomplete)


def test_legacy_migration_unknown_fields_and_foreign_callbacks_are_refused() -> None:
    _, result, _, _, _ = issued_publication()
    data = contract._native(result.findings[0])
    calls: list[str] = []

    class Foreign:
        def __str__(self) -> str:
            calls.append("str")
            return "unexpected"

    for value in ([], [Foreign()]):
        with pytest.raises((ValueError, ValidationError)):
            contract.IncidentClockFinding.model_validate({**data, "control_ids": value})
    for model, field in [
        (result.manifest, "filters_applied"),
        (result.findings[0].collection_context, "filter_applied"),
    ]:
        altered = contract._native(model)
        altered[field]["unrelated"] = "unselected"
        with pytest.raises((ValueError, ValidationError)):
            type(model).model_validate(altered)
    assert calls == []


def test_publication_json_refuses_duplicates_nonfinite_and_oversized_inputs() -> None:
    _, result, _, _, _ = issued_publication()
    wire = contract.result_bytes(result)
    with pytest.raises(ValueError):
        contract.IncidentClockResult.model_validate_json(b'{"schema_version":"1",' + wire[1:])
    with pytest.raises(ValueError):
        contract.IncidentClockResult.model_validate_json(b'{"value":NaN}')
    with pytest.raises(ValueError):
        contract.IncidentClockResult.model_validate_json(b" " * (contract.RESULT_BYTE_LIMIT + 1))


def test_no_record_publishes_zero_coverage_and_no_manufactured_finding() -> None:
    from evidentia_collectors.incident_clock import _client as client

    selected, _, _, _ = publication_source()
    seed = client._new_seed(selected)
    authority = client._issue_authority(
        seed,
        credential_validity="not_established",
        reads=[],
        record=None,
        events=[],
        diagnostics=[contract.Diagnostic(code="credential_missing", read_id=None, side=None)],
    )
    result = contract.make_result(authority)
    assert result.source_state == "unavailable" and result.findings == [] and result.record is None
    assert result.clock.state == "incomplete_source" and result.clock.elapsed_seconds is None
    assert result.manifest.errors == ["credential_missing"] and not result.manifest.is_complete
    assert result.manifest.empty_categories == [] and result.manifest.coverage_counts[0].collected == 0


def test_partial_history_preserves_observations_without_selected_candidates() -> None:
    from evidentia_collectors.incident_clock import _client as client

    selected, reads, record, events = publication_source()
    reads[-1] = reads[-1].model_copy(
        update={"pagination": {"start": 0, "limit": 100, "total": 3, "terminal": False, "returned": 2}}
    )
    authority = client._issue_authority(
        client._new_seed(selected),
        credential_validity="expiry_checked",
        reads=reads,
        record=record,
        events=events,
        diagnostics=[],
    )
    result = contract.make_result(authority)
    assert result.source_state == "incomplete" and result.manifest.errors == ["incomplete_source"]
    assert result.clock.start.candidate_event_ids == [events[0].event_id]
    assert result.clock.start.selected_event_id is None and result.clock.elapsed_seconds is None
    assert len(result.events) == 2 and len(result.findings) == 1


def test_run_authority_has_no_direct_constructor_or_pickle_form() -> None:
    import pickle

    from evidentia_collectors.incident_clock import _client as client

    with pytest.raises(client.IncidentReadError):
        client.RunAuthority()
    forged = object.__new__(client.RunAuthority)
    with pytest.raises((client.IncidentReadError, contract.IncidentInputError)):
        contract.make_result(forged)
    authority, _, _, _, _ = issued_publication()
    with pytest.raises(TypeError):
        pickle.dumps(authority)


def _terminal_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _terminal_cell(value: str) -> dict[str, Any]:
    return {"state": "value", "value": value}


def terminal_upper(provider: str) -> dict[str, Any]:
    digest, run, utc = "f" * 64, "7" + "Z" * 25, "9999-12-31T23:59:59.999999Z"
    alias, version, opaque = "a" * 64, "9" * 64, "\\" * 256
    occurrence = (
        {"field": "z" * 80}
        if provider == "servicenow"
        else {"history_id": opaque, "item_index": 255}
        if provider == "jira"
        else {"event_id": opaque}
    )
    record_id = "f" * 32 if provider == "servicenow" else "9" * 32 if provider == "jira" else "z" * 128
    req = {"provider": provider, "profile_alias": alias, "clock_alias": alias, "record_id": record_id}
    if provider != "servicenow":
        req.update(start_occurrence=occurrence, end_occurrence=occurrence)
    if provider == "pagerduty":
        req.update(since="9" * 2048, until="9" * 2048)
    mapping = {"label": "\\" * 128, "meaning": "\\" * 512}
    if provider == "jira":
        mapping.update(field_id=opaque, **{"from": _terminal_cell("\0" * 65536), "to": _terminal_cell("\0" * 65536)})
    elif provider == "servicenow":
        mapping.update(field="z" * 80)
    else:
        mapping.update(event_type=max(get_args(contract.PagerDutyEventType), key=len))
    definition = {
        "clock_alias": alias,
        "label": "\\" * 128,
        "mapping_reference": "\\" * 512,
        "declared_workflow_meaning": "\\" * 1024,
        "definition_sha256": digest,
        "start": mapping,
        "end": mapping,
    }
    codes = list(get_args(contract.DiagnosticCode))
    longest = max(codes, key=len)
    reads = []
    for ordinal in range(102):
        reads.append(
            {
                "read_id": "read-" + f"{ordinal:064x}",
                "ordinal": ordinal,
                "kind": "jira_access",
                "template": "jira_accessible_resources",
                "state": "unavailable",
                "http_status": 599,
                "retrieved_at": utc,
                "body_bytes": 1048577,
                "body_complete": False,
                "body_sha256": digest,
                "accepted": False,
                "pagination": {"start": 10000, "limit": 100, "total": 1000000000, "terminal": False, "returned": 100},
                "received_records": 100000,
                "admitted_events": 10000,
                "diagnostic_codes": codes,
                "wire_bytes": 1179649,
            }
        )
    diagnostics = [{"code": longest, "read_id": reads[index]["read_id"], "side": "start"} for index in range(64)]
    candidates = ["event-" + f"{index:064x}" for index in range(10000)]
    selection = {
        "state": "unsupported_timestamp",
        "candidate_event_ids": candidates,
        "selected_event_id": candidates[0],
        "explicit_occurrence": occurrence,
        "source_literal": "\0" * 2048,
        "utc_seconds": "9" * 2024,
    }
    clock = {"state": "incomplete_source", "start": selection, "end": selection, "elapsed_seconds": "9" * 2024}
    system = "incident-clock:" + provider + ":" + digest
    filters = {
        "observation_scope": "selected_incident_clock",
        "request": req,
        "profile_binding_sha256": digest,
        "definition_sha256": digest,
    }
    context = {
        "collector_id": "incident-clock",
        "collector_version": version,
        "run_id": run,
        "collected_at": utc,
        "credential_identity": "not-established",
        "source_system_id": system,
        "filter_applied": filters,
        "pagination_context": None,
        "evidentia_version": version,
    }
    summary = {
        "observation_scope": "selected_incident_clock",
        "source_state": "unavailable",
        "clock_state": "incomplete_source",
        "elapsed_seconds": "9" * 2024,
        "start_event_id": candidates[0],
        "end_event_id": candidates[0],
        "start_occurrence": occurrence,
        "end_occurrence": occurrence,
        "definition_sha256": digest,
        "profile_binding_sha256": digest,
    }
    finding = {
        "id": "ffffffff-ffff-5fff-bfff-ffffffffffff",
        "title": "Incident clock observation",
        "description": "\\" * 256,
        "severity": "informational",
        "status": "active",
        "compliance_status": "unknown",
        "remediation": None,
        "source_system": "incident-clock",
        "source_finding_id": None,
        "resource_type": "selected_incident_clock",
        "resource_id": record_id,
        "resource_region": None,
        "resource_account": None,
        "control_mappings": [],
        "collection_context": context,
        "raw_data": summary,
        "first_observed": utc,
        "last_observed": utc,
        "resolved_at": None,
    }
    manifest = {
        "run_id": run,
        "collector_id": "incident-clock",
        "collector_version": version,
        "collection_started_at": utc,
        "collection_finished_at": utc,
        "source_system_ids": [system],
        "filters_applied": filters,
        "coverage_counts": [
            {"resource_type": "selected_incident_clock", "scanned": 1, "matched_filter": 1, "collected": 1}
        ],
        "total_findings": 1,
        "is_complete": False,
        "incomplete_reason": "selected_source_unavailable",
        "empty_categories": [],
        "warnings": ["selected_scope_only", "workflow_mapping_only", "credential_expiry_unknown"],
        "errors": codes,
        "evidentia_version": version,
    }
    return {
        "schema_version": "1",
        "provider": provider,
        "request": req,
        "run_id": run,
        "observation_scope": "selected_incident_clock",
        "definition": definition,
        "source_state": "unavailable",
        "clock": clock,
        "source_reads": reads,
        "diagnostics": diagnostics,
        "findings": [finding],
        "manifest": manifest,
        "profile_binding_sha256": digest,
        "credential_validity": "not_established",
    }


@pytest.mark.parametrize("provider", ["servicenow", "jira", "pagerduty"])
def test_conservative_maximum_terminal_envelope(provider: str, tmp_path: Path) -> None:
    # This combines independent maxima, including mutually exclusive fields.
    # It is an upper-bound object, never an issued or schema-valid result claim.
    # Every cross-field or parser constraint can only reduce its byte size.
    term = terminal_upper(provider)
    assert set(term) == set(contract.IncidentClockResult.model_fields) - {"record", "events"}
    for key, model in (
        ("manifest", contract.IncidentClockManifest),
        ("definition", contract.PublishedClockDefinition),
        ("clock", contract.ClockOutcome),
    ):
        assert set(term[key]) == set(model.model_fields)
    finding = term["findings"][0]
    assert set(finding) == set(contract.IncidentClockFinding.model_fields)
    assert set(finding["collection_context"]) == set(contract.IncidentClockContext.model_fields)
    assert set(finding["raw_data"]) == set(contract.IncidentClockSummary.model_fields)
    assert all(set(row) == set(contract.SourceRead.model_fields) for row in term["source_reads"])
    encoded = _terminal_json(term)
    # Worst escaped byte is six ASCII bytes per input UTF8 byte for cells.
    assert len(_terminal_json("\0" * 65536)) == 6 * 65536 + 2
    assert len(_terminal_json("\\" * 1024)) == 2 * 1024 + 2
    assert len(encoded) < 4194304
    projection_example = {"record": None, "events": []}
    assert (
        len(_terminal_json({**term, **projection_example}))
        == len(encoded) + len(_terminal_json(projection_example)) - 1
    )
    facts = {
        "provider": provider,
        "terminal_upper_bytes": len(encoded),
        "reserve_bytes": 4194304,
        "margin_bytes": 4194304 - len(encoded),
        "canonical_sha256": hashlib.sha256(encoded).hexdigest(),
        "candidate_lists": [10000, 10000],
        "source_reads": 102,
        "global_diagnostics": 64,
        "distinct_per_read_codes": len(get_args(contract.DiagnosticCode)),
        "definition_cell_bytes": 65536 if provider == "jira" else 0,
        "scope": "Conservative union of individual ratified field maxima with all inherited keys; not a schema-valid or issued result. Cross-field, profile-file and canonical-definition constraints further reduce size.",
    }
    (tmp_path / "terminal-capacity.json").write_text(json.dumps(facts, indent=2) + "\n", encoding="utf-8")
