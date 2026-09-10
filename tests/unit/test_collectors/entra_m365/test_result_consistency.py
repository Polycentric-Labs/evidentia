"""Small result-consistency probes around the corrected factory validators."""

from __future__ import annotations

import json
from typing import Any

import pytest

from .test_result_integrity import c, export, f, graph_source, policy, rule, start

GRAPH_RULES = (
    ("conditional-access", "conditional-access-policy"),
    ("authentication-registration", "authentication-registration-summary"),
    ("sign-ins", "sign-in-observation"),
    ("directory-roles", "directory-role-inventory"),
    ("managed-devices", "managed-device-state"),
    ("retention-labels", "retention-label-configuration"),
    ("defender-alerts", "defender-alert-observation"),
    ("defender-incidents", "defender-incident-observation"),
)


def graph_result(name: str, finding_rule: str) -> dict[str, Any]:
    ctx, _clock = start([name])
    row: dict[str, Any] = {"id": "synthetic-source"}
    if name in {"sign-ins", "defender-alerts", "defender-incidents"}:
        row["createdDateTime"] = "2026-09-09T00:00:00.123456789Z"
    if name == "sign-ins":
        row["appliedConditionalAccessPolicies"] = []
    source = graph_source(ctx, name, [row])
    finding = ctx.make_finding(
        source,
        finding_rule,
        source_id=None if name == "authentication-registration" else "synthetic-source",
        raw_data={},
    )
    result = ctx.build_result([ctx.finish_read(source, findings=[finding])])
    data: dict[str, Any] = json.loads(result.model_dump_json())
    f.EntraM365CollectResult.model_validate_json(json.dumps(data))
    return data


@pytest.mark.parametrize("name,finding_rule", GRAPH_RULES)
def test_wire_cannot_drop_all_findings_and_claim_complete_empty(name: str, finding_rule: str) -> None:
    data = graph_result(name, finding_rule)
    assert data["capabilities"][list(c.CAPABILITIES).index(name)]["matched_filter"] == 1
    data["findings"] = []
    data["capabilities"][list(c.CAPABILITIES).index(name)]["collected"] = 0
    data["manifest"]["total_findings"] = 0
    data["manifest"]["coverage_counts"][0]["collected"] = 0
    data["manifest"]["empty_categories"] = [name]
    with pytest.raises(ValueError):
        f.EntraM365CollectResult.model_validate_json(json.dumps(data))


def test_wire_cannot_omit_dlp_policy_with_policy_coverage_remaining() -> None:
    ctx, _clock = start(["dlp-export"])
    source = ctx.admit_dlp_export(export([policy()], [rule()]))
    findings = [
        ctx.make_finding(source, "dlp-policy-configuration", source_id="p", raw_data={}),
        ctx.make_finding(source, "dlp-unresolved-rule", source_id="r", raw_data={}),
    ]
    diagnostic = c.EntraM365Diagnostic(code="unresolved_parent", count=1, http_status=None)
    result = ctx.build_result([ctx.finish_read(source, findings=findings, diagnostics=[diagnostic])])
    data = json.loads(result.model_dump_json())
    f.EntraM365CollectResult.model_validate_json(json.dumps(data))
    assert data["capabilities"][6]["field_coverage"]["policies.Guid"]["known"] == 1
    data["findings"] = [data["findings"][1]]
    data["capabilities"][6]["collected"] = 1
    data["manifest"]["total_findings"] = 1
    data["manifest"]["coverage_counts"][0]["collected"] = 1
    with pytest.raises(ValueError):
        f.EntraM365CollectResult.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "field,value",
    [
        ("observed_first", "2026-09-08T23:59:59.999999999Z"),
        ("observed_last", "2026-09-09T00:00:00.123456790Z"),
    ],
)
def test_wire_source_extrema_must_describe_returned_event(field: str, value: str) -> None:
    data = graph_result("defender-alerts", "defender-alert-observation")
    assert data["findings"][0]["raw_data"]["source"]["createdDateTime"] == "2026-09-09T00:00:00.123456789Z"
    data["capabilities"][7][field] = value
    with pytest.raises(ValueError):
        f.EntraM365CollectResult.model_validate_json(json.dumps(data))


def test_wire_context_clock_cannot_truncate_before_exact_equality_check() -> None:
    data = graph_result("conditional-access", "conditional-access-policy")
    assert data["findings"][0]["first_observed"] == "2026-09-10T00:00:00.000000Z"
    data["findings"][0]["collection_context"]["collected_at"] = "2026-09-10T00:00:00.0000001Z"
    with pytest.raises(ValueError):
        f.EntraM365CollectResult.model_validate_json(json.dumps(data))
