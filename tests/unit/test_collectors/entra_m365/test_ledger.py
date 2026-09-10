"""Synthetic admission and accounting through the shared run context."""

from datetime import UTC, datetime

import pytest
from evidentia_collectors.entra_m365 import _contracts as c

from ._contract_support import RECORDED_DLP_PATH

NOW = datetime(2026, 9, 10, tzinfo=UTC)


class Clock:
    value = 0.0
    wall = NOW

    def monotonic(self):
        return self.value

    def utc(self):
        return self.wall

    def sleep(self, seconds):
        self.value += seconds


def start(names=None, **kw):
    clock = Clock()
    request = c.EntraM365CollectRequest(tenant_label="synthetic", capabilities=names or ["sign-ins"], **kw)
    ctx = c.EntraM365RunContext.start(
        request,
        utc_clock=clock.utc,
        monotonic_clock=clock.monotonic,
        sleep=clock.sleep,
        run_id_factory=lambda: "synthetic-run",
    )
    return ctx, request, clock


def event(identifier, when="2026-09-09T00:00:00Z", **fields):
    return c.project_record(
        "sign-ins", {"id": identifier, "createdDateTime": when, "appliedConditionalAccessPolicies": [], **fields}
    )


def reading(ctx, name="sign-ins"):
    result = ctx.begin(name, "application")
    result.note_attempt()
    return result


def test_empty_success_and_not_requested_have_distinct_evidence():
    ctx, _request, _clock = start()
    read = reading(ctx)
    assert read.admit_page([], continuation=False)
    source = read.finish_source()
    assert source.records == ()
    assert source.capability.state == "complete"
    assert source.capability.pages_completed == 1
    assert ctx.not_requested("directory-roles").capability.state == "not_requested"


def test_exact_duplicates_and_conflict_recompute_window_and_extrema():
    ctx, _request, _clock = start(max_items=3)
    read = reading(ctx)
    a = event("a", "2026-09-09T00:00:00.000000001Z")
    b = event("b", "2026-09-09T00:00:00.0000000001Z")
    read.admit_page([a, b, a], continuation=True)
    read.note_attempt()
    read.admit_page([event("a", "2026-09-09T00:00:00.1Z"), a], continuation=False)
    source = read.finish_source()
    assert [x.source_id for x in source.records] == ["b"]
    assert source.capability.scanned == 5
    assert source.capability.duplicate_records == 2
    assert source.capability.matched_filter == 1
    assert source.capability.state == "partial"
    assert source.capability.observed_first == b.event_time.utc
    assert source.capability.observed_last == b.event_time.utc
    assert ctx.slots_used == 2
    assert [(d.code, d.count) for d in source.capability.diagnostics] == [("conflicting_duplicate", 1)]


def test_cap_page_still_quarantines_existing_identity_after_unadmitted_row():
    ctx, _request, _clock = start(max_items=1)
    read = reading(ctx)
    assert not read.admit_page([event("a"), event("b"), event("a", status={"errorCode": 0})], continuation=False)
    source = read.finish_source()
    assert not source.records and source.capability.scanned == 3
    assert ctx.slots_used == 1
    assert {d.code for d in source.capability.diagnostics} == {"item_limit", "conflicting_duplicate"}


def test_exact_cap_without_new_id_or_continuation_is_complete():
    ctx, _request, _clock = start(max_items=1)
    read = reading(ctx)
    assert read.admit_page([event("a"), event("a")], continuation=False)
    assert read.finish_source().capability.state == "complete"


@pytest.mark.parametrize("value", [None, "absent"])
def test_missing_sign_in_detail_only_counts_final_in_window(value):
    ctx, _request, _clock = start()
    read = reading(ctx)
    row = {"id": "a", "createdDateTime": "2026-09-09T00:00:00Z"}
    if value is None:
        row["appliedConditionalAccessPolicies"] = None
    old = row | {"id": "old", "createdDateTime": "2020-01-01T00:00:00Z"}
    read.admit_page([c.project_record("sign-ins", row), c.project_record("sign-ins", old)], continuation=False)
    source = read.finish_source()
    assert source.capability.matched_filter == 1
    assert [(d.code, d.count) for d in source.capability.diagnostics] == [("conditional_access_detail_unavailable", 1)]


def test_future_and_equal_instant_precision_do_not_inflate_from_duplicates():
    ctx, _request, _clock = start()
    read = reading(ctx)
    future = event("future", "2026-09-10T00:00:00.000000000001Z")
    read.admit_page(
        [event("a", "2026-09-09T00:00:00.1Z"), event("b", "2026-09-09T00:00:00.1000Z"), future, future],
        continuation=False,
    )
    source = read.finish_source()
    assert source.capability.matched_filter == 2
    assert source.capability.observed_first == source.capability.observed_last == "2026-09-09T00:00:00.1000Z"
    assert [(d.code, d.count) for d in source.capability.diagnostics] == [("future_timestamp", 1)]
    assert source.capability.state == "complete"


def test_type_sensitive_duplicate_comparison_and_detached_records():
    ctx, _request, _clock = start(["conditional-access"])
    read = reading(ctx, "conditional-access")
    first = c.project_record("conditional-access", {"id": "literal ", "conditions": {"x": False}})
    second = c.project_record("conditional-access", {"id": "literal ", "conditions": {"x": 0}})
    read.admit_page([first, second], continuation=False)
    first.fields["conditions"]["x"] = "mutation"
    source = read.finish_source()
    assert not source.records
    assert source.capability.duplicate_records == 0
    assert source.capability.diagnostics[0].code == "conflicting_duplicate"


def test_field_presence_uses_reviewed_enum_and_child_shape():
    ctx, _request, _clock = start()
    read = reading(ctx)
    read.admit_page(
        [
            event("a", conditionalAccessStatus="success", status={"errorCode": 0}),
            event("b", conditionalAccessStatus="futureVendor", status=None),
            event("c", conditionalAccessStatus=None, status={}),
        ],
        continuation=False,
    )
    source = read.finish_source()
    assert source.capability.field_coverage["conditionalAccessStatus"].model_dump() == dict(
        absent=0, null=1, known=1, unknown=1
    )
    assert source.capability.field_coverage["status.errorCode"].model_dump() == dict(
        absent=1, null=1, known=1, unknown=0
    )
    assert all(sum(count.model_dump().values()) == 3 for count in source.capability.field_coverage.values())


def test_elapsed_and_consumed_bytes_are_counted_before_refusal():
    ctx, _request, _clock = start()
    read = reading(ctx)
    read.consume(10, 10)
    _clock.value = 60
    with pytest.raises(ValueError, match="capability_budget"):
        read.consume(1, 1)
    assert read.raw_bytes == read.decoded_bytes == 11
    _clock.value = 61
    with pytest.raises(ValueError, match="capability_budget"):
        read.remaining()


@pytest.mark.parametrize("later", [-1, float("nan"), float("inf")])
def test_invalid_monotonic_values_never_reset_budget(later):
    ctx, _request, _clock = start()
    read = reading(ctx)
    _clock.value = later
    with pytest.raises(ValueError, match="internal_error"):
        read.remaining()


def test_source_snapshot_cannot_be_reused_or_finished_under_another_run():
    ctx, _request, _clock = start()
    read = reading(ctx)
    read.admit_page([event("a")], continuation=False)
    source = read.finish_source()
    other, _, _ = start()
    with pytest.raises(ValueError, match="invalid_source_read"):
        other.finish_read(source, findings=[])
    with pytest.raises(ValueError):
        read.admit_page([], continuation=False)


def test_dlp_uses_kind_qualified_denominators_and_policy_first_admission():
    ctx, _request, _clock = start(["dlp-export"], max_items=12)
    export = c.EntraM365DlpExport.model_validate_json(RECORDED_DLP_PATH.read_bytes())
    source = ctx.admit_dlp_export(export)
    assert len(source.records) == 12
    assert [r.kind for r in source.records] == ["dlp-policy"] * 11 + ["dlp-rule"]
    assert source.capability.scanned == 26
    assert source.capability.requests_attempted == 0
    assert source.capability.state == "partial"
    for name, count in source.capability.field_coverage.items():
        assert sum(count.model_dump().values()) == (11 if name.startswith("policies.") else 1)
    assert set(source.capability.field_coverage) == {"policies." + k for k in type(export.policies[0]).model_fields} | {
        "rules." + k for k in type(export.rules[0]).model_fields
    }
