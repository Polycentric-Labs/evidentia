"""Tests for the v0.7.0 schema extensions (OLIR, SecurityFinding)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia_core.audit.provenance import CollectionContext, new_run_id
from evidentia_core.models.common import (
    ControlMapping,
    OLIRRelationship,
)
from evidentia_core.models.finding import ComplianceStatus, SecurityFinding
from evidentia_core.models.migrations.v0_6_to_v0_7 import (
    is_legacy_finding_payload,
    load_legacy_finding,
    migrate_findings_json,
)


def test_olir_relationship_values_match_nist_vocabulary() -> None:
    assert OLIRRelationship.EQUIVALENT_TO.value == "equivalent-to"
    assert OLIRRelationship.EQUAL_TO.value == "equal-to"
    assert OLIRRelationship.SUBSET_OF.value == "subset-of"
    assert OLIRRelationship.SUPERSET_OF.value == "superset-of"
    assert OLIRRelationship.INTERSECTS_WITH.value == "intersects-with"
    assert OLIRRelationship.RELATED_TO.value == "related-to"


def test_olir_relationship_covers_all_nist_drm_types() -> None:
    expected = {
        "equivalent-to",
        "equal-to",
        "subset-of",
        "superset-of",
        "intersects-with",
        "related-to",
    }
    actual = {r.value for r in OLIRRelationship}
    assert actual == expected


def test_control_mapping_defaults_to_related_to() -> None:
    m = ControlMapping(framework="nist-800-53-rev5", control_id="AC-2")
    assert m.relationship == OLIRRelationship.RELATED_TO
    assert m.justification == ""


def test_control_mapping_explicit_olir_and_justification() -> None:
    m = ControlMapping(
        framework="nist-800-53-rev5",
        control_id="AC-3",
        relationship=OLIRRelationship.SUBSET_OF,
        justification="FSBP S3.1 Related requirements cite AC-3.",
    )
    assert m.relationship == OLIRRelationship.SUBSET_OF
    assert "FSBP S3.1" in m.justification


def test_control_mapping_justification_length_cap() -> None:
    m = ControlMapping(
        framework="nist-800-53-rev5",
        control_id="AC-2",
        justification="x" * 1024,
    )
    assert len(m.justification) == 1024

    with pytest.raises(ValueError):
        ControlMapping(
            framework="nist-800-53-rev5",
            control_id="AC-2",
            justification="x" * 1025,
        )


def test_control_mapping_round_trip_preserves_olir() -> None:
    m = ControlMapping(
        framework="nist-800-53-rev5",
        control_id="AC-3",
        relationship=OLIRRelationship.SUBSET_OF,
        justification="test",
    )
    restored = ControlMapping.model_validate(m.model_dump(mode="json"))
    assert restored == m


def _make_context() -> CollectionContext:
    return CollectionContext(
        collector_id="test-collector",
        collector_version="0.7.0",
        run_id=new_run_id(),
        credential_identity="arn:aws:iam::123:role/test",
        source_system_id="aws-account:123:us-east-1",
    )


def test_security_finding_accepts_legacy_control_ids_kwarg() -> None:
    finding = SecurityFinding(
        title="test finding",
        description="desc",
        severity="high",
        source_system="aws-config",
        control_ids=["AC-2", "AC-6"],
    )
    assert len(finding.control_mappings) == 2
    assert all(m.framework == "nist-800-53-rev5" for m in finding.control_mappings)
    assert all(m.relationship == OLIRRelationship.RELATED_TO for m in finding.control_mappings)
    assert all("Pre-v0.7.0" in m.justification for m in finding.control_mappings)
    assert finding.control_ids == ["AC-2", "AC-6"]


def test_security_finding_accepts_explicit_control_mappings() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
        control_mappings=[
            ControlMapping(
                framework="nist-800-53-rev5",
                control_id="AC-3",
                relationship=OLIRRelationship.SUBSET_OF,
                justification="FSBP S3.1 cites AC-3",
            ),
        ],
    )
    assert finding.control_mappings[0].relationship == (OLIRRelationship.SUBSET_OF)


def test_security_finding_merges_both_inputs_without_duplicates() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
        control_mappings=[
            ControlMapping(
                framework="nist-800-53-rev5",
                control_id="AC-2",
                relationship=OLIRRelationship.SUBSET_OF,
                justification="explicit",
            ),
        ],
        control_ids=["AC-2", "AC-6"],
    )
    assert len(finding.control_mappings) == 2
    mappings_by_id = {m.control_id: m for m in finding.control_mappings}
    assert mappings_by_id["AC-2"].relationship == OLIRRelationship.SUBSET_OF
    assert mappings_by_id["AC-2"].justification == "explicit"
    assert mappings_by_id["AC-6"].relationship == OLIRRelationship.RELATED_TO


def test_security_finding_default_collection_context_is_synthetic_legacy() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
    )
    assert finding.collection_context.collector_id == "legacy-pre-v0.7.0"
    assert finding.collection_context.credential_identity == "legacy-pre-v0.7.0"


def test_security_finding_accepts_real_collection_context() -> None:
    ctx = _make_context()
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
        collection_context=ctx,
    )
    assert finding.collection_context.collector_id == "test-collector"
    assert finding.collection_context.run_id == ctx.run_id


def test_security_finding_round_trip_preserves_v07_fields() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
        control_mappings=[
            ControlMapping(
                framework="nist-800-53-rev5",
                control_id="AC-3",
                relationship=OLIRRelationship.SUBSET_OF,
                justification="x",
            ),
        ],
        collection_context=_make_context(),
    )
    restored = SecurityFinding.model_validate(finding.model_dump(mode="json"))
    assert restored.control_mappings == finding.control_mappings
    assert restored.collection_context == finding.collection_context


def test_is_legacy_finding_payload_detects_v06_shape() -> None:
    assert is_legacy_finding_payload({"id": "x", "control_ids": ["AC-2"], "title": "t"}) is True


def test_is_legacy_finding_payload_rejects_v07_shape() -> None:
    assert (
        is_legacy_finding_payload(
            {
                "id": "x",
                "control_mappings": [],
                "collection_context": {},
                "title": "t",
            }
        )
        is False
    )


def test_load_legacy_finding_synthesizes_v07_fields() -> None:
    v06_json = {
        "id": "11111111-1111-1111-1111-111111111111",
        "title": "Root account missing MFA",
        "description": "d",
        "severity": "high",
        "status": "active",
        "source_system": "aws-config",
        "control_ids": ["AC-6", "IA-2"],
    }
    finding = load_legacy_finding(v06_json)
    assert finding.id == "11111111-1111-1111-1111-111111111111"
    assert len(finding.control_mappings) == 2
    assert finding.collection_context.collector_id == "legacy-pre-v0.7.0"


def test_migrate_findings_json_single_finding(tmp_path: Path) -> None:
    path = tmp_path / "finding.json"
    path.write_text(
        json.dumps(
            {
                "title": "t",
                "description": "d",
                "severity": "low",
                "source_system": "aws-config",
                "control_ids": ["AC-2"],
            }
        )
    )
    findings = migrate_findings_json(path)
    assert len(findings) == 1
    assert findings[0].control_ids == ["AC-2"]


def test_migrate_findings_json_array(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_text(
        json.dumps(
            [
                {
                    "title": f"finding {i}",
                    "description": "d",
                    "severity": "low",
                    "source_system": "aws-config",
                    "control_ids": [f"AC-{i}"],
                }
                for i in range(3)
            ]
        )
    )
    findings = migrate_findings_json(path)
    assert len(findings) == 3
    assert findings[1].control_ids == ["AC-1"]


# ── v0.10.0 OCSF-alignment fields ────────────────────────────────────


def test_compliance_status_values() -> None:
    assert ComplianceStatus.PASS.value == "pass"
    assert ComplianceStatus.FAIL.value == "fail"
    assert ComplianceStatus.WARNING.value == "warning"
    assert ComplianceStatus.NOT_APPLICABLE.value == "not_applicable"
    assert ComplianceStatus.UNKNOWN.value == "unknown"
    assert {s.value for s in ComplianceStatus} == {
        "pass",
        "fail",
        "warning",
        "not_applicable",
        "unknown",
    }


def test_security_finding_compliance_status_defaults_to_unknown() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
    )
    assert finding.compliance_status == ComplianceStatus.UNKNOWN


def test_security_finding_remediation_defaults_to_none() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
    )
    assert finding.remediation is None


def test_security_finding_accepts_explicit_compliance_status() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
        compliance_status=ComplianceStatus.FAIL,
    )
    assert finding.compliance_status == ComplianceStatus.FAIL


def test_security_finding_accepts_remediation() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
        remediation="Enable MFA on the root account.",
    )
    assert finding.remediation == "Enable MFA on the root account."


def test_security_finding_round_trip_preserves_v010_fields() -> None:
    finding = SecurityFinding(
        title="t",
        description="d",
        severity="high",
        source_system="aws-config",
        compliance_status=ComplianceStatus.FAIL,
        remediation="Rotate the exposed key.",
        collection_context=_make_context(),
    )
    restored = SecurityFinding.model_validate(finding.model_dump(mode="json"))
    assert restored.compliance_status == ComplianceStatus.FAIL
    assert restored.remediation == "Rotate the exposed key."


def test_pre_v010_finding_json_parses_with_defaults() -> None:
    """A v0.9.x-shaped findings JSON (no v0.10.0 fields) re-parses, with
    compliance_status defaulting to UNKNOWN and remediation to None."""
    pre_v010 = {
        "id": "22222222-2222-2222-2222-222222222222",
        "title": "Root account missing MFA",
        "description": "d",
        "severity": "high",
        "status": "active",
        "source_system": "aws-config",
        "control_mappings": [],
    }
    finding = SecurityFinding.model_validate(pre_v010)
    assert finding.compliance_status == ComplianceStatus.UNKNOWN
    assert finding.remediation is None
