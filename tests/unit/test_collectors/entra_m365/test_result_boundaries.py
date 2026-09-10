"""Positive boundaries for the remaining result-consistency corrections."""

from __future__ import annotations

import json

import pytest

from .test_result_consistency import graph_result
from .test_result_integrity import c, export, f, graph_source, policy, rule, start


def test_registration_aggregate_represents_multiple_records_once() -> None:
    ctx, _clock = start(["authentication-registration"])
    source = graph_source(ctx, "authentication-registration", [{"id": "a"}, {"id": "b"}])
    finding = ctx.make_finding(source, "authentication-registration-summary", source_id=None, raw_data={})
    result = ctx.build_result([ctx.finish_read(source, findings=[finding])])
    restored = f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.capabilities[1].matched_filter == 2
    assert restored.capabilities[1].collected == 1


def test_resolved_dlp_rule_does_not_require_a_separate_finding() -> None:
    ctx, _clock = start(["dlp-export"])
    source = ctx.admit_dlp_export(export([policy("same-id")], [rule("same-id", "same-id")]))
    finding = ctx.make_finding(source, "dlp-policy-configuration", source_id="same-id", raw_data={})
    result = ctx.build_result([ctx.finish_read(source, findings=[finding])])
    restored = f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.capabilities[6].matched_filter == 2
    assert restored.capabilities[6].collected == 1
    assert restored.findings[0].resource_type == "MicrosoftPurview::DlpPolicy"


def test_exact_event_extrema_use_longest_fraction_spelling_on_equal_instants() -> None:
    ctx, _clock = start(["defender-alerts"])
    timestamps = (
        "2026-09-09T00:00:00.1234567Z",
        "2026-09-09T02:00:00.123456700+02:00",
        "2026-09-09T00:00:00.1234567000Z",
    )
    source = graph_source(
        ctx,
        "defender-alerts",
        [{"id": str(index), "createdDateTime": value} for index, value in enumerate(timestamps)],
    )
    findings = [
        ctx.make_finding(source, "defender-alert-observation", source_id=str(index), raw_data={}) for index in range(3)
    ]
    result = ctx.build_result([ctx.finish_read(source, findings=findings)])
    restored = f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.capabilities[7].observed_first == "2026-09-09T00:00:00.1234567000Z"
    assert restored.capabilities[7].observed_last == "2026-09-09T00:00:00.1234567000Z"
    assert [item.raw_data["source"]["createdDateTime"] for item in restored.findings] == list(timestamps)


def test_partial_duplicate_source_emits_final_unique_observation_once() -> None:
    ctx, _clock = start(["conditional-access"])
    source = graph_source(ctx, "conditional-access", [{"id": "a"}, {"id": "a"}])
    finding = ctx.make_finding(source, "conditional-access-policy", source_id="a", raw_data={})
    diagnostic = c.EntraM365Diagnostic(code="page_limit", count=1, http_status=None)
    result = ctx.build_result([ctx.finish_read(source, findings=[finding], diagnostics=[diagnostic])])
    restored = f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.status == "partial"
    assert restored.capabilities[0].scanned == 2
    assert restored.capabilities[0].duplicate_records == 1
    assert restored.capabilities[0].matched_filter == restored.capabilities[0].collected == 1
    assert restored.manifest.empty_categories == []


@pytest.mark.parametrize(
    "stamp", ["2026-09-10T00:00:00Z", "2026-09-10T00:00:00.000000000Z", "2026-09-10T02:00:00.000000+02:00"]
)
def test_exactly_representable_context_clock_forms_remain_valid(stamp: str) -> None:
    data = graph_result("conditional-access", "conditional-access-policy")
    data["findings"][0]["collection_context"]["collected_at"] = stamp
    restored = f.EntraM365CollectResult.model_validate_json(json.dumps(data))
    assert restored.findings[0].collection_context.collected_at == restored.findings[0].first_observed
