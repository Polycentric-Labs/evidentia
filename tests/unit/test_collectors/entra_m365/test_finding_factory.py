"""Finding and manifest tests bind output to admitted synthetic evidence."""

from datetime import UTC, datetime

import pytest
from evidentia_collectors.entra_m365 import _contracts as c
from evidentia_core.models.common import Severity, deterministic_finding_id
from evidentia_core.models.finding import FindingStatus

from ._factory_support import Clock


def setup(rows=None, name="conditional-access"):
    factory = c
    clock = Clock()
    request = c.EntraM365CollectRequest(tenant_label="synthetic", capabilities=[name])
    ctx = factory.EntraM365RunContext.start(
        request,
        utc_clock=clock.utc,
        monotonic_clock=clock.monotonic,
        sleep=clock.sleep,
        run_id_factory=lambda: "synthetic-run",
    )
    read = ctx.begin(name, "application")
    read.note_attempt()
    read.admit_page(
        [c.project_record(name, row) for row in (rows if rows is not None else [{"id": "padded "}])], continuation=False
    )
    return factory, ctx, read.finish_source()


def test_literal_natural_keys_survive_finding_and_result_json():
    _factory, ctx, source = setup()
    finding = ctx.make_finding(
        source, "conditional-access-policy", source_id="padded ", raw_data={"configuration": "observed"}
    )
    assert finding.source_finding_id == "synthetic:conditional-access:padded "
    assert finding.resource_id == "padded "
    assert finding.id == deterministic_finding_id("entra-m365", finding.source_finding_id)
    assert finding.raw_data["source"] == {"id": "padded "}
    assert finding.collection_context.run_id == ctx.run_id
    assert finding.compliance_status.value == "unknown"
    read = ctx.finish_read(source, findings=[finding])
    result = ctx.build_result([read])
    restored = _factory.EntraM365CollectResult.model_validate_json(result.model_dump_json())
    assert restored.findings[0].source_finding_id == finding.source_finding_id
    assert restored.findings[0].resource_id == "padded "
    assert restored.manifest.run_id == finding.collection_context.run_id
    assert restored.status == "complete" and not restored.full_surface_complete
    assert [cap.name for cap in restored.capabilities] == list(c.CAPABILITIES)


@pytest.mark.parametrize("change", ["foreign_id", "wrong_rule", "critical", "resolved", "raw_mutation", "foreign_run"])
def test_factory_rejects_unadmitted_or_changed_evidence(change):
    _factory, ctx, source = setup()
    args = dict(source_id="padded ", raw_data={})
    rule = "conditional-access-policy"
    if change == "foreign_id":
        args["source_id"] = "missing"
    if change == "wrong_rule":
        rule = "managed-device-state"
    if change == "critical":
        args["severity"] = Severity.CRITICAL
    if change == "resolved":
        args["status"] = FindingStatus.RESOLVED
    if change == "foreign_run":
        _, ctx, _ = setup()
    if change == "raw_mutation":
        finding = ctx.make_finding(source, rule, **args)
        finding.raw_data["source"]["id"] = "changed"
        with pytest.raises(ValueError):
            ctx.finish_read(source, findings=[finding])
    else:
        with pytest.raises(ValueError):
            ctx.make_finding(source, rule, **args)


def test_mutating_source_cannot_change_factory_snapshot():
    _factory, ctx, source = setup()
    source.records[0].fields["id"] = "mutated"
    source.capability.scanned = 999
    finding = ctx.make_finding(source, "conditional-access-policy", source_id="padded ", raw_data={})
    read = ctx.finish_read(source, findings=[finding])
    assert finding.raw_data["source"]["id"] == "padded "
    assert read.capability.scanned == 1


def test_partial_source_cannot_be_upgraded_and_has_no_empty_claim():
    _factory, ctx, source = setup([])
    diag = c.EntraM365Diagnostic(code="page_limit", count=1, http_status=None)
    read = ctx.finish_read(source, findings=[], diagnostics=[diag])
    result = ctx.build_result([read])
    assert result.status == "partial"
    assert not result.manifest.is_complete and result.manifest.errors
    assert result.manifest.empty_categories == []
    assert result.manifest.total_findings == 0


def test_complete_empty_has_manifest_category_and_all_required_wire_fields():
    _factory, ctx, source = setup([])
    result = ctx.build_result([ctx.finish_read(source, findings=[])])
    assert result.manifest.empty_categories == ["conditional-access"]
    assert result.manifest.is_complete and result.manifest.errors == []
    schema = _factory.EntraM365CollectResult.model_json_schema()
    assert set(schema["required"]) == set(schema["properties"])
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "change",
    ["status", "full_surface", "total", "coverage", "run_id", "order", "provenance_verified", "requested_scope"],
)
def test_result_rejects_contradictory_manifest_and_scope(change):
    _factory, ctx, source = setup([])
    result = ctx.build_result([ctx.finish_read(source, findings=[])])
    data = result.model_dump()
    if change == "status":
        data["status"] = "unavailable"
    if change == "full_surface":
        data["full_surface_complete"] = True
    if change == "total":
        data["manifest"]["total_findings"] = 1
    if change == "coverage":
        data["manifest"]["coverage_counts"] = []
    if change == "run_id":
        data["manifest"]["run_id"] = " "
    if change == "order":
        data["capabilities"].reverse()
    if change == "provenance_verified":
        data["provenance"]["authenticated_identity_verified"] = 0
    if change == "requested_scope":
        data["requested_capabilities"] = ["sign-ins"]
    with pytest.raises(ValueError):
        _factory.EntraM365CollectResult.model_validate(data)


def test_domain_cannot_silently_omit_an_admitted_graph_observation():
    _factory, ctx, source = setup()
    with pytest.raises(ValueError):
        ctx.finish_read(source, findings=[])


def test_unrepresentable_alert_resolution_keeps_status_and_exact_source():
    _factory, ctx, source = setup(
        [
            {
                "id": "a",
                "createdDateTime": "2026-09-09T00:00:00Z",
                "status": "resolved",
                "resolvedDateTime": "2026-09-09T01:00:00.0000001Z",
            }
        ],
        name="defender-alerts",
    )
    finding = ctx.make_finding(
        source, "defender-alert-observation", source_id="a", raw_data={}, status=FindingStatus.RESOLVED
    )
    assert finding.status == FindingStatus.RESOLVED and finding.resolved_at is None
    assert finding.raw_data["source"]["resolvedDateTime"].endswith(".0000001Z")
    with pytest.raises(ValueError):
        ctx.make_finding(
            source,
            "defender-alert-observation",
            source_id="a",
            raw_data={},
            status=FindingStatus.RESOLVED,
            resolved_at=datetime(2026, 9, 9, 1, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "source_status,source_severity,status,severity",
    [
        ("active", "high", FindingStatus.RESOLVED, Severity.HIGH),
        ("resolved", "unknown", FindingStatus.RESOLVED, Severity.HIGH),
        ("resolved", "high", FindingStatus.ACTIVE, Severity.HIGH),
    ],
)
def test_defender_state_cannot_contradict_literal_source(source_status, source_severity, status, severity):
    _factory, ctx, source = setup(
        [{"id": "a", "createdDateTime": "2026-09-09T00:00:00Z", "status": source_status, "severity": source_severity}],
        name="defender-alerts",
    )
    with pytest.raises(ValueError):
        ctx.make_finding(
            source, "defender-alert-observation", source_id="a", raw_data={}, status=status, severity=severity
        )


def test_result_and_finished_findings_own_their_nested_contexts():
    _factory, ctx, source = setup()
    original = ctx.make_finding(source, "conditional-access-policy", source_id="padded ", raw_data={})
    read = ctx.finish_read(source, findings=[original])
    result = ctx.build_result([read])
    original.collection_context.filter_applied["tenant_label"] = "mutated-original"
    read.findings[0].collection_context.filter_applied["tenant_label"] = "mutated-read"
    assert result.findings[0].collection_context.filter_applied["tenant_label"] == "synthetic"
    assert result.findings[0].collection_context is not original.collection_context
