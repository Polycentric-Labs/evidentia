"""Independent synthetic acceptance tests for the shared finding factory."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

import pytest
from evidentia_collectors.entra_m365 import _contracts as c
from evidentia_collectors.entra_m365 import _contracts as f
from evidentia_core.models import common
from evidentia_core.models import finding as finding_models

NOW = datetime(2026, 9, 10, tzinfo=UTC)


class Clock:
    def __init__(self) -> None:
        self.wall = NOW
        self.tick = 0.0

    def utc(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.tick

    def sleep(self, seconds: float) -> None:
        self.tick += seconds


def start(names: list[str], **options: Any) -> tuple[Any, Clock]:
    clock = Clock()
    request = c.EntraM365CollectRequest(tenant_label="synthetic", capabilities=names, **options)
    ctx = f.EntraM365RunContext.start(
        request,
        utc_clock=clock.utc,
        monotonic_clock=clock.monotonic,
        sleep=clock.sleep,
        run_id_factory=lambda: "synthetic-independent-run",
    )
    return ctx, clock


def graph_source(ctx: Any, name: str, rows: list[dict[str, Any]]) -> Any:
    read = ctx.begin(name, "delegated" if name == "retention-labels" else "application")
    read.note_attempt()
    read.admit_page([c.project_record(name, row) for row in rows], continuation=False)
    return read.finish_source()


def setup_one() -> tuple[Any, Any, Any]:
    ctx, _clock = start(["conditional-access"])
    source = graph_source(ctx, "conditional-access", [{"id": " padded ", "conditions": {"users": ["a"]}}])
    finding = ctx.make_finding(
        source, "conditional-access-policy", source_id=" padded ", raw_data={"nested": [{"flag": False}]}
    )
    return ctx, source, finding


def result_one() -> Any:
    ctx, source, finding = setup_one()
    return ctx.build_result([ctx.finish_read(source, findings=[finding])])


def export(policies: list[dict[str, Any]], rules: list[dict[str, Any]]) -> Any:
    return c.EntraM365DlpExport.model_validate(
        {
            "schema_version": 1,
            "source": {
                "kind": "authored-synthetic",
                "producer": "synthetic-test-fixture",
                "producer_version": None,
                "captured_at": None,
                "parent_sha256": None,
                "source_uri": None,
                "sanitization": "synthetic",
            },
            "policies": policies,
            "rules": rules,
        }
    )


def policy(identifier: str = "p") -> dict[str, Any]:
    return {
        "Guid": identifier,
        "Name": "Synthetic policy " + identifier,
        "Mode": "Enable",
        "DistributionStatus": "Pending",
        "Workload": None,
        "Enabled": True,
        "IsValid": True,
    }


def rule(identifier: str = "r", parent: str | None = None) -> dict[str, Any]:
    return {
        "Guid": identifier,
        "Policy": parent,
        "ParentPolicyName": None,
        "Mode": "Enforce",
        "Workload": None,
        "Disabled": False,
        "IsValid": True,
    }


@pytest.mark.parametrize("transport", ["python", "json"])
def test_all_nine_complete_empty_retains_explicit_scope(transport: str) -> None:
    ctx, _clock = start(list(c.CAPABILITIES))
    reads = []
    for name in c.CAPABILITIES:
        source = ctx.admit_dlp_export(export([], [])) if name == "dlp-export" else graph_source(ctx, name, [])
        reads.append(ctx.finish_read(source, findings=[]))
    result = ctx.build_result(reads)
    restored = (
        f.EntraM365CollectResult.model_validate(result.model_dump())
        if transport == "python"
        else f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    )
    assert restored.status == "complete"
    assert restored.full_surface_complete is True
    assert restored.manifest.is_complete is True
    assert restored.manifest.empty_categories == list(c.CAPABILITIES)
    assert restored.manifest.total_findings == 0 and restored.findings == []
    assert restored.provenance.authenticated_identity_verified is False
    assert [cap.pages_completed for cap in restored.capabilities] == [1] * 9
    assert restored.capabilities[5].declared_auth_mode == "delegated"
    assert restored.capabilities[6].credential_basis == "unverified:dlp-export"


@pytest.mark.parametrize("transport", ["python", "json"])
def test_all_nine_unavailable_is_not_an_empty_observation(transport: str) -> None:
    ctx, _clock = start(list(c.CAPABILITIES))
    reads = []
    for name in c.CAPABILITIES:
        mode = None if name == "dlp-export" else "delegated" if name == "retention-labels" else "application"
        reading = ctx.begin(name, mode)
        reading.add_diagnostic("input_missing" if name == "dlp-export" else "credentials_missing")
        reads.append(ctx.finish_read(reading.finish_source(), findings=[]))
    result = ctx.build_result(reads)
    restored = (
        f.EntraM365CollectResult.model_validate(result.model_dump())
        if transport == "python"
        else f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    )
    assert restored.status == "unavailable"
    assert restored.full_surface_complete is False
    assert restored.manifest.is_complete is False
    assert restored.manifest.empty_categories == []
    assert len(restored.manifest.errors) == 9
    assert restored.manifest.total_findings == 0 and restored.findings == []
    assert all(cap.state == "unavailable" and cap.pages_completed == 0 for cap in restored.capabilities)


def test_partial_run_retains_successful_empty_capability_only() -> None:
    ctx, _clock = start(["conditional-access", "managed-devices"])
    good = ctx.finish_read(graph_source(ctx, "conditional-access", []), findings=[])
    reading = ctx.begin("managed-devices", "application")
    reading.note_attempt()
    reading.add_diagnostic("permission_denied", status=403)
    bad = ctx.finish_read(reading.finish_source(), findings=[])
    result = ctx.build_result([bad, good])
    restored = f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.status == "partial"
    assert restored.manifest.errors == ["managed-devices:permission_denied:403"]
    assert restored.manifest.empty_categories == ["conditional-access"]
    assert [cap.name for cap in restored.capabilities] == list(c.CAPABILITIES)


@pytest.mark.parametrize("identifier", [" padded ", "id:part", "id{source_id}", "\u03b1", "\tobject\n"])
def test_literal_identifier_and_actual_enums_survive_both_round_trips(identifier: str) -> None:
    ctx, _clock = start(["conditional-access"])
    source = graph_source(ctx, "conditional-access", [{"id": identifier}])
    finding = ctx.make_finding(source, "conditional-access-policy", source_id=identifier, raw_data={})
    result = ctx.build_result([ctx.finish_read(source, findings=[finding])])
    for restored in (
        f.EntraM365CollectResult.model_validate(result.model_dump()),
        f.EntraM365CollectResult.model_validate_json(result.model_dump_json()),
    ):
        actual = restored.findings[0]
        natural = "synthetic:conditional-access:" + identifier
        assert actual.source_finding_id == natural
        assert actual.resource_id == identifier
        assert actual.raw_data["source"]["id"] == identifier
        assert actual.id == common.deterministic_finding_id("entra-m365", natural)
        assert actual.severity is common.Severity.INFORMATIONAL
        assert actual.status is finding_models.FindingStatus.ACTIVE
        assert actual.compliance_status is finding_models.ComplianceStatus.UNKNOWN


@pytest.mark.parametrize(
    "raw,utc_text",
    [
        ("2026-09-09T02:00:00.123456789+02:00", "2026-09-09T00:00:00.123456789Z"),
        ("2026-09-10T01:00:00.0000000+01:00", "2026-09-10T00:00:00.0000000Z"),
        ("2026-08-11T00:00:00.000000000Z", "2026-08-11T00:00:00.000000000Z"),
    ],
)
def test_exact_source_extrema_and_raw_timestamp_survive_json(raw: str, utc_text: str) -> None:
    ctx, _clock = start(["defender-alerts"])
    source = graph_source(ctx, "defender-alerts", [{"id": "a", "createdDateTime": raw}])
    finding = ctx.make_finding(source, "defender-alert-observation", source_id="a", raw_data={})
    result = ctx.build_result([ctx.finish_read(source, findings=[finding])])
    restored = f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.capabilities[7].observed_first == utc_text
    assert restored.capabilities[7].observed_last == utc_text
    assert restored.findings[0].raw_data["source"]["createdDateTime"] == raw


@pytest.mark.parametrize("raw", ["2026-09-10T00:00:00.0000001Z", "2026-08-10T23:59:59.999999999Z"])
def test_source_outside_window_is_not_rounded_into_a_finding(raw: str) -> None:
    ctx, _clock = start(["defender-alerts"])
    source = graph_source(ctx, "defender-alerts", [{"id": "a", "createdDateTime": raw}])
    assert source.records == ()
    with pytest.raises(ValueError):
        ctx.make_finding(source, "defender-alert-observation", source_id="a", raw_data={})
    result = ctx.build_result([ctx.finish_read(source, findings=[])])
    assert result.findings == [] and result.capabilities[7].matched_filter == 0


@pytest.mark.parametrize("stage", ["issued", "finished"])
@pytest.mark.parametrize("field", ["mapping", "raw", "context", "status"])
def test_changed_evidence_is_rejected_before_next_transition(stage: str, field: str) -> None:
    ctx, source, finding = setup_one()
    target = finding
    read = None
    if stage == "finished":
        read = ctx.finish_read(source, findings=[finding])
        target = read.findings[0]
    if field == "mapping":
        target.control_mappings[0].control_id = "AC-99"
    elif field == "raw":
        target.raw_data["observation"]["nested"][0]["flag"] = True
    elif field == "context":
        target.collection_context.filter_applied["max_items"] = 1
    else:
        target.status = finding_models.FindingStatus.RESOLVED
    with pytest.raises(ValueError):
        if stage == "issued":
            ctx.finish_read(source, findings=[finding])
        else:
            ctx.build_result([read])


@pytest.mark.parametrize("source_object", ["issued", "finished", "result"])
@pytest.mark.parametrize("field", ["mapping", "raw", "context", "coverage"])
def test_nested_mutation_does_not_change_other_owned_results(source_object: str, field: str) -> None:
    ctx, source, finding = setup_one()
    read = ctx.finish_read(source, findings=[finding])
    result = ctx.build_result([read])
    before = [finding.model_dump_json(), read.findings[0].model_dump_json(), result.findings[0].model_dump_json()]
    cap_before = read.capability.model_dump_json()
    result_cap_before = result.capabilities[0].model_dump_json()
    index = {"issued": 0, "finished": 1, "result": 2}[source_object]
    targets = [finding, read.findings[0], result.findings[0]]
    if field == "mapping":
        targets[index].control_mappings[0].control_id = "AC-99"
    elif field == "raw":
        targets[index].raw_data["source"]["conditions"]["users"].append("changed")
        targets[index].raw_data["observation"]["nested"][0]["flag"] = True
    elif field == "context":
        targets[index].collection_context.filter_applied["capabilities"].append("dlp-export")
        targets[index].collection_context.pagination_context.total_pages = 99
    else:
        if source_object == "issued":
            source.capability.field_coverage["id"].known = 99
        elif source_object == "finished":
            read.capability.field_coverage["id"].known = 99
        else:
            result.capabilities[0].field_coverage["id"].known = 99
        if source_object != "finished":
            assert read.capability.model_dump_json() == cap_before
        if source_object != "result":
            assert result.capabilities[0].model_dump_json() == result_cap_before
    for other, expected in enumerate(before):
        if other != index or field == "coverage":
            assert targets[other].model_dump_json() == expected


def test_dlp_rule_cannot_substitute_for_an_admitted_policy() -> None:
    ctx, _clock = start(["dlp-export"])
    source = ctx.admit_dlp_export(export([policy()], [rule()]))
    unresolved = ctx.make_finding(source, "dlp-unresolved-rule", source_id="r", raw_data={})
    diagnostic = c.EntraM365Diagnostic(code="unresolved_parent", count=1, http_status=None)
    with pytest.raises(ValueError, match="missing_observation"):
        ctx.finish_read(source, findings=[unresolved], diagnostics=[diagnostic])


def test_dlp_policy_coverage_requires_each_policy_identity() -> None:
    ctx, _clock = start(["dlp-export"])
    source = ctx.admit_dlp_export(export([policy("p"), policy("q")], [rule("r"), rule("s")]))
    findings = [
        ctx.make_finding(source, "dlp-unresolved-rule", source_id=identifier, raw_data={}) for identifier in ("r", "s")
    ]
    diagnostic = c.EntraM365Diagnostic(code="unresolved_parent", count=2, http_status=None)
    with pytest.raises(ValueError, match="missing_observation"):
        ctx.finish_read(source, findings=findings, diagnostics=[diagnostic])


@pytest.mark.parametrize("raw", [None, 1, False, "text", ["value"], ("value",)])
def test_factory_raw_observation_requires_json_object(raw: object) -> None:
    other, _clock = start(["conditional-access"])
    source = graph_source(other, "conditional-access", [{"id": "new"}])
    with pytest.raises(ValueError):
        other.make_finding(source, "conditional-access-policy", source_id="new", raw_data=raw)


@pytest.mark.parametrize("resolved", ["2026-09-09T01:00:00.123456Z", "2026-09-09T03:00:00.123456000+02:00"])
def test_representable_resolution_accepts_exact_offset_normalization(resolved: str) -> None:
    ctx, _clock = start(["defender-alerts"])
    source = graph_source(
        ctx,
        "defender-alerts",
        [{"id": "a", "createdDateTime": "2026-09-09T00:00:00Z", "status": "resolved", "resolvedDateTime": resolved}],
    )
    stamp = datetime(2026, 9, 9, 3, 0, 0, 123456, tzinfo=timezone(timedelta(hours=2)))
    finding = ctx.make_finding(
        source,
        "defender-alert-observation",
        source_id="a",
        raw_data={},
        status=finding_models.FindingStatus.RESOLVED,
        resolved_at=stamp,
    )
    result = ctx.build_result([ctx.finish_read(source, findings=[finding])])
    restored = f.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.findings[0].resolved_at == stamp.astimezone(UTC)
    assert restored.findings[0].raw_data["source"]["resolvedDateTime"] == resolved


@pytest.mark.parametrize(
    "change",
    [
        "manifest_verified",
        "manifest_scope_missing",
        "manifest_bool_count",
        "manifest_string_bool",
        "warnings_missing",
        "context_credential",
        "context_scope",
        "context_pagination",
        "context_clock",
        "mapping",
        "resource",
        "non_defender_severity",
        "non_defender_resolved",
        "static_title",
        "source_suffix",
    ],
)
def test_result_rejects_contradictory_wire_claims(change: str) -> None:
    data = json.loads(result_one().model_dump_json())
    finding = data["findings"][0]
    if change == "manifest_verified":
        data["manifest"]["filters_applied"]["authenticated_identity_verified"] = True
    elif change == "manifest_scope_missing":
        del data["manifest"]["filters_applied"]["max_items"]
    elif change == "manifest_bool_count":
        data["manifest"]["total_findings"] = True
        data["manifest"]["coverage_counts"][0]["scanned"] = True
    elif change == "manifest_string_bool":
        data["manifest"]["is_complete"] = "true"
    elif change == "warnings_missing":
        data["manifest"]["warnings"] = []
    elif change == "context_credential":
        finding["collection_context"]["credential_identity"] = "verified:administrator"
    elif change == "context_scope":
        finding["collection_context"]["filter_applied"]["tenant_label"] = "other"
    elif change == "context_pagination":
        finding["collection_context"]["pagination_context"]["is_complete"] = False
        finding["collection_context"]["pagination_context"]["continuation_token"] = "opaque"
    elif change == "context_clock":
        finding["collection_context"]["collected_at"] = "2000-01-01T00:00:00Z"
    elif change == "mapping":
        finding["control_mappings"][0]["relationship"] = "equal-to"
    elif change == "resource":
        finding["resource_id"] = "unrelated"
    elif change == "non_defender_severity":
        finding["severity"] = "high"
    elif change == "non_defender_resolved":
        finding["status"] = "resolved"
        finding["resolved_at"] = "2000-01-01T00:00:00Z"
    elif change == "static_title":
        finding["title"] = "Tenant-wide compliance is proven"
    else:
        finding["source_finding_id"] = "synthetic:defender-alerts:unrelated"
        finding["id"] = common.deterministic_finding_id("entra-m365", finding["source_finding_id"])
    with pytest.raises(ValueError):
        f.EntraM365CollectResult.model_validate_json(json.dumps(data))


@pytest.mark.parametrize("change", ["status", "severity", "resolved_time"])
def test_result_defender_wire_state_remains_bound_to_literal_source(change: str) -> None:
    ctx, _clock = start(["defender-alerts"])
    source = graph_source(
        ctx,
        "defender-alerts",
        [{"id": "a", "createdDateTime": "2026-09-09T00:00:00Z", "status": "new", "severity": "low"}],
    )
    finding = ctx.make_finding(
        source, "defender-alert-observation", source_id="a", raw_data={}, severity=common.Severity.LOW
    )
    data = json.loads(ctx.build_result([ctx.finish_read(source, findings=[finding])]).model_dump_json())
    if change == "status":
        data["findings"][0]["status"] = "resolved"
    elif change == "severity":
        data["findings"][0]["severity"] = "high"
    else:
        data["findings"][0]["resolved_at"] = "2026-09-09T10:00:00Z"
    with pytest.raises(ValueError):
        f.EntraM365CollectResult.model_validate_json(json.dumps(data))


def test_issued_source_and_completed_read_cannot_be_fabricated() -> None:
    ctx, source, finding = setup_one()
    with pytest.raises(ValueError):
        ctx.make_finding(copy.deepcopy(source), "conditional-access-policy", source_id=" padded ", raw_data={})
    read = ctx.finish_read(source, findings=[finding])
    with pytest.raises(ValueError):
        ctx.build_result([copy.deepcopy(read)])
    with pytest.raises(ValueError):
        ctx.finish_read(source, findings=[finding])


def test_no_completed_reads_returns_fixed_validation_error() -> None:
    ctx, source, _finding = setup_one()
    fabricated = c.EntraM365CapabilityRead(source.capability, ())
    with pytest.raises(ValueError, match="invalid_capability_read"):
        ctx.build_result([fabricated])
