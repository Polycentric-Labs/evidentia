"""Admission, terminal-state and accounting boundaries."""

from datetime import timedelta

import pytest
from evidentia_collectors.entra_m365 import _contracts as c

from ._ledger_support import NOW, diagnostics, event, reading, start


def test_request_and_admitted_source_are_detached_from_caller_mutation():
    ctx, original, _clock = start(max_items=1)
    original.max_items = 10000
    original.capabilities.append("managed-devices")
    assert ctx.request.max_items == 1
    assert ctx.request.capabilities == ["sign-ins"]
    read = reading(ctx)
    row = event("a", status={"errorCode": 0})
    read.admit_page([row], continuation=False)
    row.fields["id"] = "changed"
    row.fields["status"]["errorCode"] = 1
    result = read.finish_source()
    assert result.records[0].source_id == "a"
    assert result.records[0].fields["status"] == {"errorCode": 0}


def test_invalid_first_page_does_not_admit_valid_prefix():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.consume(47, 47)
    bad = c.EntraM365SourceRecord("graph", "bad", {"id": "bad", "createdDateTime": "bad-time"}, None)
    with pytest.raises(ValueError, match="invalid_record"):
        read.admit_page([event("valid"), bad], continuation=False)
    assert (read.pages, read.scanned, read.duplicates, ctx.slots_used) == (0, 0, 0, 0)
    assert (read.attempts, read.raw_bytes, read.decoded_bytes, ctx.decoded_bytes) == (1, 47, 47, 47)
    read.add_diagnostic("invalid_record")
    result = read.finish_source()
    assert result.capability.state == "unavailable" and result.records == ()


def test_rejected_later_page_cannot_quarantine_accepted_identity():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.admit_page([event("a")], continuation=True)
    read.note_attempt()
    bad = c.EntraM365SourceRecord("graph", "bad", {"id": "bad"}, None)
    with pytest.raises(ValueError, match="invalid_record"):
        read.admit_page([event("a", status={"errorCode": 1}), bad], continuation=False)
    assert (read.pages, read.scanned, read.duplicates, ctx.slots_used) == (1, 1, 0, 1)
    read.add_diagnostic("invalid_record")
    result = read.finish_source()
    assert [row.source_id for row in result.records] == ["a"]
    assert diagnostics(result.capability) == {("invalid_record", None): 1}


def test_validation_finishing_at_elapsed_limit_is_atomic(monkeypatch):
    ctx, _, clock = start()
    read = reading(ctx)
    original_copy = c._copy_record

    def delayed_copy(name, record):
        checked = original_copy(name, record)
        clock.value = 60
        return checked

    monkeypatch.setattr(c, "_copy_record", delayed_copy)
    with pytest.raises(ValueError, match="capability_budget"):
        read.admit_page([event("a")], continuation=False)
    assert (read.pages, read.scanned, ctx.slots_used) == (0, 0, 0)


def test_known_duplicate_variants_stay_quarantined_without_reopening_slots():
    ctx, _, _clock = start(max_items=2)
    read = reading(ctx)
    variants = [event("a", status={"errorCode": code}) for code in (0, 1, 2)]
    read.admit_page([variants[0], variants[1], variants[0], variants[2], variants[1], event("b")], continuation=False)
    result = read.finish_source()
    assert [row.source_id for row in result.records] == ["b"]
    assert (result.capability.scanned, result.capability.duplicate_records, ctx.slots_used) == (6, 2, 2)
    assert diagnostics(result.capability) == {("conflicting_duplicate", None): 1}


def test_conflict_removes_future_and_missing_detail_counts():
    ctx, _, _clock = start()
    read = reading(ctx)
    future = event("future", "2026-01-31T00:00:00.000000000001Z")
    missing = c.project_record("sign-ins", {"id": "missing", "createdDateTime": "2026-01-15T00:00:00Z"})
    read.admit_page([future, missing], continuation=True)
    read.note_attempt()
    read.admit_page([event("future"), event("missing"), event("kept")], continuation=False)
    result = read.finish_source()
    assert [row.source_id for row in result.records] == ["kept"]
    assert diagnostics(result.capability) == {("conflicting_duplicate", None): 2}
    assert all(sum(value.model_dump().values()) == 1 for value in result.capability.field_coverage.values())


@pytest.mark.parametrize("continuation,expected", [(False, "complete"), (True, "partial")])
def test_exact_item_cap_obeys_terminal_state(continuation, expected):
    ctx, _, _clock = start(max_items=1)
    read = reading(ctx)
    read.admit_page([event("a"), event("a")], continuation=continuation)
    result = read.finish_source()
    assert result.capability.state == expected
    assert ctx.slots_used == 1 and result.capability.duplicate_records == 1


def test_nonterminal_page_is_not_a_complete_enumeration():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.admit_page([event("a")], continuation=True)
    try:
        result = read.finish_source()
    except ValueError:
        return
    assert result.capability.state != "complete"


def test_terminal_page_prevents_additional_attempts():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.admit_page([], continuation=False)
    with pytest.raises(ValueError):
        read.note_attempt()
    assert read.attempts == 1


def test_terminal_page_prevents_additional_page_admission():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.admit_page([event("a")], continuation=False)
    with pytest.raises(ValueError):
        read.admit_page([event("b")], continuation=False)
    assert read.pages == 1 and ctx.slots_used == 1


def test_failed_finalization_does_not_duplicate_derived_diagnostics():
    ctx, _, clock = start()
    read = reading(ctx)
    missing = c.project_record("sign-ins", {"id": "missing", "createdDateTime": "2026-01-15T00:00:00Z"})
    read.admit_page([event("future", "2026-01-31T00:00:00.000000000001Z"), missing], continuation=False)
    clock.wall = NOW - timedelta(seconds=1)
    with pytest.raises(ValueError):
        read.finish_source()
    clock.wall = NOW
    result = read.finish_source()
    assert diagnostics(result.capability) == {
        ("future_timestamp", None): 1,
        ("conditional_access_detail_unavailable", None): 1,
    }


def test_out_of_range_integer_clock_has_fixed_error():
    ctx, _, clock = start()
    read = reading(ctx)
    clock.value = 10**400
    with pytest.raises(ValueError, match="internal_error"):
        read.remaining()


def test_snapshot_survives_mutation_of_returned_source_and_capability():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.admit_page([event("a", status={"errorCode": 0})], continuation=False)
    source = read.finish_source()
    source.records[0].fields["status"]["errorCode"] = 99
    source.capability.field_coverage["id"].known = 99
    source.capability.state = "partial"
    saved = ctx._snapshot(source)
    assert saved.records[0].fields["status"]["errorCode"] == 0
    # Check the ledger snapshot before finding creation and final public assembly.
    result = ctx._finish_without_findings(source, findings=[])
    assert result.capability.state == "complete"
    assert result.capability.field_coverage["id"].known == 1
    with pytest.raises(ValueError, match="invalid_source_read"):
        ctx._finish_without_findings(source, findings=[])


@pytest.mark.parametrize("value", [True, -1, 1.0, "1"])
def test_invalid_byte_charge_is_rejected_without_counter_mutation(value):
    ctx, _, _clock = start()
    read = reading(ctx)
    with pytest.raises(ValueError, match="internal_error"):
        read.consume(value, 0)
    assert (read.raw_bytes, read.decoded_bytes, ctx.decoded_bytes) == (0, 0, 0)


def test_byte_overrun_keeps_consumed_counts_and_refuses_next_attempt():
    ctx, _, _clock = start()
    read = reading(ctx)
    read.consume(33554432, 33554432)
    with pytest.raises(ValueError, match="byte_limit"):
        read.consume(1, 1)
    assert (read.raw_bytes, read.decoded_bytes, ctx.decoded_bytes) == (33554433, 33554433, 33554433)
    with pytest.raises(ValueError, match="byte_limit"):
        read.note_attempt()
    assert read.attempts == 1


def test_run_byte_limit_blocks_later_capability_without_activity():
    names = ("conditional-access", "authentication-registration", "sign-ins", "managed-devices", "retention-labels")
    ctx, _, _clock = start(names)
    for name in names[:4]:
        read = ctx.begin(name, "application")
        for page in range(8):
            read.note_attempt()
            read.consume(4194304, 4194304)
            read.admit_page([], continuation=page != 7)
        assert read.finish_source().capability.state == "complete"
    assert ctx.decoded_bytes == 134217728
    blocked = ctx.begin("retention-labels", "delegated").finish_source()
    assert blocked.capability.state == "unavailable" and blocked.capability.started_at is None
    assert blocked.capability.requests_attempted == 0
    assert diagnostics(blocked.capability) == {("byte_limit", None): 1}


def test_run_item_limit_charges_distinct_capability_identities():
    names = ("conditional-access", "authentication-registration", "sign-ins", "directory-roles", "managed-devices")
    ctx, _, _clock = start(names)
    for name in names[:4]:
        rows = [event(str(i)) if name == "sign-ins" else c.project_record(name, {"id": str(i)}) for i in range(10000)]
        read = reading(ctx, name)
        assert read.admit_page(rows, continuation=False)
        assert len(read.finish_source().records) == 10000
    assert ctx.slots_used == 40000
    blocked = ctx.begin("managed-devices", "application").finish_source()
    assert blocked.capability.state == "unavailable" and blocked.capability.started_at is None
    assert diagnostics(blocked.capability) == {("item_limit", None): 1}


@pytest.mark.parametrize("elapsed,code", [(60, "capability_budget"), (300, "run_budget")])
def test_exact_elapsed_limit_refuses_another_attempt(elapsed, code):
    ctx, _, clock = start()
    read = reading(ctx)
    clock.value = elapsed
    with pytest.raises(ValueError, match=code):
        read.note_attempt()
    assert read.attempts == 1


def test_retry_wait_does_not_sleep_past_remaining_budget():
    ctx, _, clock = start()
    read = reading(ctx)
    clock.value = 59.5
    with pytest.raises(ValueError, match="retry_after_budget"):
        read.wait(1)
    assert clock.sleeps == [] and clock.value == 59.5


def test_run_budget_blocks_later_capability_and_retains_event_window():
    ctx, _, clock = start(("sign-ins", "defender-alerts"))
    clock.value = 300
    result = ctx.begin("defender-alerts", "application").finish_source()
    assert result.capability.state == "unavailable" and result.capability.started_at is None
    assert result.capability.requested_window_start == NOW - timedelta(days=30)
    assert result.capability.requested_window_end == NOW
    assert diagnostics(result.capability) == {("run_budget", None): 1}


def test_dlp_kinds_are_distinct_even_when_guids_match():
    ctx, _, _clock = start(("dlp-export",), max_items=2)
    source = dict(
        kind="authored-synthetic",
        producer="synthetic",
        producer_version=None,
        captured_at=None,
        parent_sha256=None,
        source_uri=None,
        sanitization="synthetic",
    )
    policy = dict(
        Guid="same",
        Name="policy",
        Mode="Enable",
        DistributionStatus="Pending",
        Workload=None,
        Enabled=True,
        IsValid=True,
    )
    rule = dict(
        Guid="same",
        Policy="same",
        ParentPolicyName="policy",
        Mode="Enforce",
        Workload=None,
        Disabled=False,
        IsValid=True,
    )
    export = c.EntraM365DlpExport(schema_version=1, source=source, policies=[policy], rules=[rule])
    result = ctx.admit_dlp_export(export)
    assert [row.kind for row in result.records] == ["dlp-policy", "dlp-rule"]
    assert ctx.slots_used == 2 and result.capability.matched_filter == 2
    assert result.capability.field_coverage["policies.Guid"].known == 1
    assert result.capability.field_coverage["rules.Guid"].known == 1
    export.policies[0].Name = "changed"
    assert result.records[0].fields["Name"] == "policy"
