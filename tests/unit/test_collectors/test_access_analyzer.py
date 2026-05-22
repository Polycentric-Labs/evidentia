"""Tests for :mod:`evidentia_collectors.aws.access_analyzer` (v0.7.0)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock

import pytest
from evidentia_collectors.aws.access_analyzer import (
    BLIND_SPOTS,
    COLLECTOR_ID,
    AccessAnalyzerCollector,
    AccessAnalyzerCollectorError,
)
from evidentia_core.models.common import OLIRRelationship
from evidentia_core.models.finding import SecurityFinding


def _make_collector(
    *, findings_pages: list[list[dict[str, Any]]] | None = None,
    fail_with: Exception | None = None,
) -> AccessAnalyzerCollector:
    """Build a collector with a mocked accessanalyzer client."""
    client = MagicMock()
    if fail_with is not None:
        client.list_findings.side_effect = fail_with
    else:
        pages = findings_pages or [[]]
        responses = []
        for i, page in enumerate(pages):
            response: dict[str, Any] = {"findings": page}
            if i < len(pages) - 1:
                response["nextToken"] = f"token-{i}"
            responses.append(response)
        client.list_findings.side_effect = responses

    return AccessAnalyzerCollector(
        analyzer_arn=(
            "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/grc"
        ),
        region="us-east-1",
        _clients={"accessanalyzer": client},
    )


def _make_raw_finding(**overrides: Any) -> dict[str, Any]:
    defaults: dict[str, Any] = {
        "id": "finding-abc123",
        "resource": "arn:aws:s3:::public-bucket",
        "resourceType": "AWS::S3::Bucket",
        "resourceOwnerAccount": "123456789012",
        "findingType": "ExternalAccess",
        "status": "ACTIVE",
        "isPublic": False,
        "createdAt": datetime.now(UTC),
        "updatedAt": datetime.now(UTC),
        "analyzedAt": datetime.now(UTC),
    }
    defaults.update(overrides)
    return defaults


# ── constructor validation ───────────────────────────────────────────────


def test_constructor_rejects_empty_analyzer_arn() -> None:
    with pytest.raises(AccessAnalyzerCollectorError, match="analyzer_arn"):
        AccessAnalyzerCollector(
            analyzer_arn="", region="us-east-1", _clients={}
        )


def test_constructor_accepts_valid_analyzer_arn() -> None:
    collector = _make_collector()
    assert collector.analyzer_arn.startswith("arn:aws:access-analyzer:")
    assert collector.region == "us-east-1"


# ── basic collection ─────────────────────────────────────────────────────


def test_collect_returns_empty_when_no_findings() -> None:
    collector = _make_collector(findings_pages=[[]])
    findings = collector.collect()
    assert findings == []


def test_collect_converts_raw_findings_to_security_findings() -> None:
    raw = _make_raw_finding(
        id="ext-1",
        resource="arn:aws:s3:::public-bucket",
        findingType="ExternalAccess",
        isPublic=True,
    )
    collector = _make_collector(findings_pages=[[raw]])
    findings = collector.collect()
    assert len(findings) == 1
    finding = findings[0]
    assert isinstance(finding, SecurityFinding)
    assert finding.source_system == "aws-access-analyzer"
    assert finding.source_finding_id == "ext-1"
    assert finding.resource_id == "arn:aws:s3:::public-bucket"


def test_collect_paginates_through_multiple_pages() -> None:
    page1 = [_make_raw_finding(id="f1")]
    page2 = [_make_raw_finding(id="f2")]
    page3 = [_make_raw_finding(id="f3")]
    collector = _make_collector(findings_pages=[page1, page2, page3])
    findings = collector.collect()
    ids = {f.source_finding_id for f in findings}
    assert ids == {"f1", "f2", "f3"}


# ── severity mapping ─────────────────────────────────────────────────────


def test_public_external_access_is_high_severity() -> None:
    raw = _make_raw_finding(isPublic=True, findingType="ExternalAccess")
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    assert finding.severity == "high"


def test_cross_account_external_access_is_medium_severity() -> None:
    raw = _make_raw_finding(isPublic=False, findingType="ExternalAccess")
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    assert finding.severity == "medium"


def test_unused_role_is_low_severity() -> None:
    raw = _make_raw_finding(findingType="UnusedIAMRole")
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    assert finding.severity == "low"


def test_unused_permission_is_low_severity() -> None:
    raw = _make_raw_finding(findingType="UnusedPermission")
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    assert finding.severity == "low"


# ── OLIR control mappings ────────────────────────────────────────────────


def test_external_access_maps_to_ac3_ac4_ac5_ac6_subset_of() -> None:
    raw = _make_raw_finding(findingType="ExternalAccess", isPublic=False)
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    control_ids = {m.control_id for m in finding.control_mappings}
    assert {"AC-3", "AC-4", "AC-6"}.issubset(control_ids)
    ac3 = next(m for m in finding.control_mappings if m.control_id == "AC-3")
    assert ac3.relationship == OLIRRelationship.SUBSET_OF
    assert "AC-3" in ac3.justification
    assert "Access Enforcement" in ac3.justification


def test_public_external_access_additionally_maps_to_sc7() -> None:
    raw = _make_raw_finding(findingType="ExternalAccess", isPublic=True)
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    control_ids = {m.control_id for m in finding.control_mappings}
    assert "SC-7" in control_ids


def test_unused_role_maps_to_ac6_subset_of() -> None:
    raw = _make_raw_finding(findingType="UnusedIAMRole")
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    control_ids = {m.control_id for m in finding.control_mappings}
    assert "AC-6" in control_ids
    ac6 = next(m for m in finding.control_mappings if m.control_id == "AC-6")
    assert ac6.relationship == OLIRRelationship.SUBSET_OF


def test_unused_credential_maps_to_ac2_ia2_ia5() -> None:
    raw = _make_raw_finding(findingType="UnusedIAMUserAccessKey")
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    control_ids = {m.control_id for m in finding.control_mappings}
    assert {"AC-2", "IA-2", "IA-5(1)"}.issubset(control_ids)


def test_unknown_finding_type_returns_empty_mappings() -> None:
    raw = _make_raw_finding(findingType="SomethingFutureAwsInvented")
    collector = _make_collector(findings_pages=[[raw]])
    finding = collector.collect()[0]
    assert finding.control_mappings == []


def test_every_mapping_has_nonempty_justification() -> None:
    """Per Q3=A, all Access Analyzer mappings must cite authority."""
    for finding_type in [
        "ExternalAccess", "UnusedIAMRole", "UnusedIAMUserAccessKey",
        "UnusedIAMUserPassword", "UnusedPermission",
    ]:
        raw = _make_raw_finding(findingType=finding_type)
        collector = _make_collector(findings_pages=[[raw]])
        finding = collector.collect()[0]
        for m in finding.control_mappings:
            assert m.justification, (
                f"Empty justification on {finding_type} mapping to "
                f"{m.control_id}"
            )


# ── manifest + provenance ────────────────────────────────────────────────


def test_collect_v2_returns_findings_and_manifest() -> None:
    raw = _make_raw_finding()
    collector = _make_collector(findings_pages=[[raw]])
    findings, manifest = collector.collect_v2()
    assert len(findings) == 1
    assert manifest.run_id
    assert manifest.collector_id == COLLECTOR_ID
    assert manifest.is_complete
    assert manifest.total_findings == 1


def test_collect_v2_emits_empty_set_attestation_when_no_findings() -> None:
    collector = _make_collector(findings_pages=[[]])
    _, manifest = collector.collect_v2()
    assert "aws-access-analyzer-active" in manifest.empty_categories


def test_collect_v2_manifest_warnings_include_blind_spots() -> None:
    collector = _make_collector(findings_pages=[[]])
    _, manifest = collector.collect_v2()
    # Every documented blind spot must surface as a warning.
    warning_ids = [w.split(":")[0] for w in manifest.warnings]
    for bs in BLIND_SPOTS:
        assert bs["id"] in warning_ids


def test_collect_v2_populates_collection_context_on_findings() -> None:
    raw = _make_raw_finding()
    collector = _make_collector(findings_pages=[[raw]])
    findings, manifest = collector.collect_v2()
    ctx = findings[0].collection_context
    assert ctx.collector_id == COLLECTOR_ID
    assert ctx.run_id == manifest.run_id
    assert "analyzer/grc" in ctx.credential_identity
    assert "access-analyzer" in ctx.source_system_id


# ── error handling ───────────────────────────────────────────────────────


def test_collect_v2_captures_exception_in_manifest() -> None:
    collector = _make_collector(
        fail_with=RuntimeError("simulated AWS error")
    )
    findings, manifest = collector.collect_v2()
    assert findings == []
    assert not manifest.is_complete
    assert "simulated AWS error" in (manifest.incomplete_reason or "")


# ── dry-run ──────────────────────────────────────────────────────────────


def test_dry_run_returns_empty_without_api_calls() -> None:
    client = MagicMock()
    collector = AccessAnalyzerCollector(
        analyzer_arn=(
            "arn:aws:access-analyzer:us-east-1:123456789012:analyzer/grc"
        ),
        region="us-east-1",
        _clients={"accessanalyzer": client},
    )
    findings = collector.collect(dry_run=True)
    assert findings == []
    client.list_findings.assert_not_called()


# ── blind-spot disclosures ───────────────────────────────────────────────


def test_blind_spots_are_well_formed() -> None:
    """Every BLIND_SPOTS entry has the three required fields."""
    required_keys = {"id", "title", "description"}
    for bs in BLIND_SPOTS:
        assert required_keys.issubset(bs.keys())
        assert bs["id"] and bs["title"] and bs["description"]
        # Description is substantive (≥ 100 chars) — a blind-spot
        # disclosure that's too terse undermines its audit value.
        assert len(bs["description"]) >= 100


def test_blind_spots_cover_known_coverage_gaps() -> None:
    """Critical blind spots per research are all present."""
    ids = {bs["id"] for bs in BLIND_SPOTS}
    # KMS grants, S3 ACLs vs BPA, service-linked roles, unsupported
    # resource types, finding latency — all required per Q7=Yes
    # research findings.
    required = {
        "kms-grants",
        "s3-acls-vs-block-public-access",
        "service-linked-roles",
        "unsupported-resource-types",
        "finding-latency",
    }
    assert required.issubset(ids)


# ── v0.10.0: compliance_status + OCSF round-trip ─────────────────────────


def test_access_analyzer_findings_are_fail() -> None:
    """Every Access Analyzer finding is an access-control concern."""
    from evidentia_core.models.finding import ComplianceStatus

    for finding_type in ("ExternalAccess", "UnusedIAMRole", "UnusedPermission"):
        raw = _make_raw_finding(findingType=finding_type)
        finding = _make_collector(findings_pages=[[raw]]).collect()[0]
        assert finding.compliance_status == ComplianceStatus.FAIL


def test_access_analyzer_finding_ocsf_round_trips() -> None:
    pytest.importorskip("py_ocsf_models")
    from evidentia_core.ocsf import finding_from_ocsf, finding_to_ocsf

    raw = _make_raw_finding(findingType="ExternalAccess", isPublic=True)
    finding = _make_collector(findings_pages=[[raw]]).collect()[0]
    assert finding_from_ocsf(finding_to_ocsf(finding)) == finding
