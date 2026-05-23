"""Tests for the v0.10.0 OCSF mapping layer (evidentia_core.ocsf)."""

from __future__ import annotations

import pytest

pytest.importorskip("py_ocsf_models")

from evidentia_core.models.common import (
    ControlMapping,
    OLIRRelationship,
    Severity,
)
from evidentia_core.models.finding import (
    ComplianceStatus,
    FindingStatus,
    SecurityFinding,
)
from evidentia_core.ocsf import (
    OCSFMappingError,
    finding_from_ocsf,
    finding_from_ocsf_detection,
    finding_to_ocsf,
)


def _rich_finding() -> SecurityFinding:
    """A SecurityFinding with every mappable field populated."""
    return SecurityFinding(
        title="Root account missing MFA",
        description="The AWS root account does not have MFA enabled.",
        severity=Severity.HIGH,
        status=FindingStatus.ACTIVE,
        compliance_status=ComplianceStatus.FAIL,
        remediation="Enable a hardware MFA device on the root account.",
        source_system="aws-config",
        source_finding_id="root-account-mfa-enabled:root",
        resource_type="AWS::IAM::User",
        resource_id="arn:aws:iam::123456789012:root",
        resource_region="us-east-1",
        control_mappings=[
            ControlMapping(
                framework="nist-800-53-rev5",
                control_id="IA-2",
                relationship=OLIRRelationship.SUBSET_OF,
                justification="Root MFA is the canonical IA-2(1) scenario.",
            ),
            ControlMapping(
                framework="nist-800-53-rev5",
                control_id="AC-6",
                relationship=OLIRRelationship.SUBSET_OF,
                justification="Root is the maximum-privilege principal.",
            ),
        ],
    )


def test_to_ocsf_emits_compliance_finding_class() -> None:
    ocsf = finding_to_ocsf(_rich_finding())
    assert ocsf["class_uid"] == 2003
    assert ocsf["category_uid"] == 2


def test_to_ocsf_output_validates_against_py_ocsf_models() -> None:
    from py_ocsf_models.events.findings.compliance_finding import ComplianceFinding

    # The dict must re-validate cleanly as a real OCSF Compliance Finding.
    ComplianceFinding.model_validate(finding_to_ocsf(_rich_finding()))


def test_to_ocsf_maps_severity_and_compliance_status() -> None:
    ocsf = finding_to_ocsf(_rich_finding())
    assert ocsf["severity_id"] == 4  # SeverityID.High
    assert ocsf["compliance"]["status_id"] == 3  # compliance StatusID.Fail
    assert ocsf["compliance"]["standards"] == ["nist-800-53-rev5"]
    assert sorted(ocsf["compliance"]["requirements"]) == ["AC-6", "IA-2"]


def test_round_trip_preserves_finding_exactly() -> None:
    original = _rich_finding()
    restored = finding_from_ocsf(finding_to_ocsf(original))
    assert restored == original


def test_round_trip_preserves_olir_relationship_and_justification() -> None:
    restored = finding_from_ocsf(finding_to_ocsf(_rich_finding()))
    by_id = {m.control_id: m for m in restored.control_mappings}
    assert by_id["IA-2"].relationship == OLIRRelationship.SUBSET_OF
    assert by_id["IA-2"].justification.startswith("Root MFA")
    assert by_id["AC-6"].relationship == OLIRRelationship.SUBSET_OF


def test_round_trip_minimal_finding() -> None:
    minimal = SecurityFinding(
        title="t", description="d", severity=Severity.LOW, source_system="github",
    )
    restored = finding_from_ocsf(finding_to_ocsf(minimal))
    assert restored == minimal
    assert restored.compliance_status == ComplianceStatus.UNKNOWN


def test_from_ocsf_ingests_third_party_compliance_finding() -> None:
    """A native OCSF Compliance Finding with no evidentia block is
    reconstructed best-effort from the standard OCSF fields."""
    third_party = {
        "activity_id": 1,
        "category_uid": 2,
        "class_uid": 2003,
        "type_uid": 200301,
        "time": 1_700_000_000_000,
        "severity_id": 5,
        "metadata": {
            "version": "1.5.0",
            "product": {"name": "SomeScanner", "vendor_name": "Acme"},
        },
        "finding_info": {"title": "Encryption disabled", "uid": "ext-1"},
        "compliance": {
            "status_id": 3,
            "standards": ["cis-aws"],
            "requirements": ["2.1.1"],
        },
    }
    restored = finding_from_ocsf(third_party)
    assert restored.title == "Encryption disabled"
    assert restored.severity == Severity.CRITICAL
    assert restored.compliance_status == ComplianceStatus.FAIL
    assert restored.source_system == "SomeScanner"
    assert restored.control_mappings[0].control_id == "2.1.1"
    assert restored.control_mappings[0].framework == "cis-aws"


def test_from_ocsf_rejects_invalid_input() -> None:
    with pytest.raises(OCSFMappingError):
        finding_from_ocsf({"not": "an ocsf compliance finding"})


# v0.10.1 — trust_unmapped parameter (closes F-V100-L1)


def test_from_ocsf_default_trust_uses_unmapped_block() -> None:
    """Default `trust_unmapped=True` honors the block — lossless round-trip."""
    original = _rich_finding()
    ocsf = finding_to_ocsf(original)
    # The block is present (finding_to_ocsf always emits it for round-trip).
    assert ocsf["unmapped"]["evidentia"]
    # Default path uses it -> exact equality.
    assert finding_from_ocsf(ocsf) == original


def test_from_ocsf_trust_unmapped_false_ignores_block() -> None:
    """Even when the block is present, `trust_unmapped=False` bypasses it
    and reconstructs from native OCSF fields only. This is the v0.10.1
    OCSF-ingestion-collector call path (where the OCSF doc's origin is
    not cryptographically verified)."""
    original = _rich_finding()
    ocsf = finding_to_ocsf(original)
    restored = finding_from_ocsf(ocsf, trust_unmapped=False)
    # The native-fields path keeps the visible OCSF state (title, severity,
    # compliance_status, control mappings) but cannot recover Evidentia-
    # native fields that have no OCSF home (source_finding_id,
    # CollectionContext, OLIR relationship + justification).
    assert restored.title == original.title
    assert restored.severity == original.severity
    assert restored.compliance_status == original.compliance_status
    # OLIR relationship + justification rode in the unmapped block;
    # bypassing it falls back to the RELATED_TO default with an
    # OCSF-import justification.
    assert restored.control_mappings[0].relationship == OLIRRelationship.RELATED_TO
    assert "Ingested from OCSF" in restored.control_mappings[0].justification


# v0.10.1 — finding_from_ocsf_detection (Detection Finding ingestion)


def _detection_finding_dict(
    *,
    severity_id: int = 4,
    product_name: str = "Prowler",
    title: str = "S3 bucket public read",
    uid: str = "test-detection-001",
) -> dict[str, object]:
    """Build a minimal valid OCSF Detection Finding dict (class_uid 2004)."""
    return {
        "activity_id": 1,
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": 2004,
        "type_uid": 200401,
        "time": 1_716_422_400_000,
        "severity_id": severity_id,
        "metadata": {
            "version": "1.5.0",
            "product": {"name": product_name, "vendor_name": "Acme"},
        },
        "finding_info": {"title": title, "uid": uid},
        "remediation": {"desc": "Apply the recommended fix."},
        "resources": [{"type": "AwsS3Bucket", "uid": "arn:aws:s3:::test", "region": "us-east-1"}],
    }


def test_from_ocsf_detection_basic() -> None:
    """Detection Finding maps title, severity, source_system, resource_*."""
    finding = finding_from_ocsf_detection(_detection_finding_dict())
    assert finding.title == "S3 bucket public read"
    assert finding.severity == Severity.HIGH
    assert finding.source_system == "Prowler"
    assert finding.resource_type == "AwsS3Bucket"
    assert finding.resource_id == "arn:aws:s3:::test"
    assert finding.resource_region == "us-east-1"
    assert finding.remediation == "Apply the recommended fix."


def test_from_ocsf_detection_synthesizes_compliance_status_from_severity() -> None:
    """Detection Finding has no `compliance` object — `compliance_status`
    comes from severity_id per the heuristic in
    `_DETECTION_SEVERITY_TO_COMPLIANCE`."""
    cases = [
        (5, ComplianceStatus.FAIL),         # Critical
        (4, ComplianceStatus.FAIL),         # High
        (3, ComplianceStatus.FAIL),         # Medium
        (2, ComplianceStatus.WARNING),      # Low
        (1, ComplianceStatus.UNKNOWN),      # Informational
        (0, ComplianceStatus.UNKNOWN),      # Unknown
    ]
    for sev_id, expected in cases:
        finding = finding_from_ocsf_detection(_detection_finding_dict(severity_id=sev_id))
        assert finding.compliance_status == expected, f"severity_id={sev_id}"


def test_from_ocsf_detection_starts_with_empty_control_mappings() -> None:
    """Detection Finding has no compliance.standards/requirements;
    control_mappings is empty (downstream collectors enrich)."""
    finding = finding_from_ocsf_detection(_detection_finding_dict())
    assert finding.control_mappings == []


def test_from_ocsf_detection_default_does_not_trust_unmapped() -> None:
    """Default `trust_unmapped=False` for Detection Finding — third-party
    is the expected source. A forged unmapped block must be ignored."""
    forged = _detection_finding_dict(severity_id=2)
    forged["unmapped"] = {
        "evidentia": {
            "id": "ATTACKER-FORGED-ID",
            "title": "Forged Evidentia title",
            "description": "d",
            "severity": "critical",
            "source_system": "aws-config",
        }
    }
    finding = finding_from_ocsf_detection(forged)
    # Native fields win.
    assert finding.id != "ATTACKER-FORGED-ID"
    assert finding.title == "S3 bucket public read"
    assert finding.severity == Severity.LOW


def test_from_ocsf_detection_trust_unmapped_true_honors_block() -> None:
    """When the operator IS producing the round-trip and flips
    trust_unmapped=True, the block is honored."""
    minimal = SecurityFinding(
        title="round-trip subject", description="d",
        severity=Severity.LOW, source_system="evidentia-detection-test",
    )
    detection_with_block = _detection_finding_dict()
    detection_with_block["unmapped"] = {"evidentia": minimal.model_dump(mode="json")}
    restored = finding_from_ocsf_detection(
        detection_with_block, trust_unmapped=True
    )
    assert restored == minimal


def test_from_ocsf_detection_rejects_invalid_input() -> None:
    with pytest.raises(OCSFMappingError):
        finding_from_ocsf_detection({"not": "a detection finding"})


def test_from_ocsf_trust_unmapped_false_blocks_unmapped_forgery() -> None:
    """A malicious OCSF producer could craft an `unmapped["evidentia"]`
    block to control the reconstructed SecurityFinding (identity /
    attribution forgery — CWE-345). With `trust_unmapped=False`, the
    forged block is ignored entirely — the native OCSF fields are the
    only source of truth. This is the close-out test for F-V100-L1."""
    forged = {
        "activity_id": 1,
        "category_uid": 2,
        "class_uid": 2003,
        "type_uid": 200301,
        "time": 1_700_000_000_000,
        "severity_id": 2,  # native says LOW
        "metadata": {
            "version": "1.5.0",
            "product": {"name": "MaliciousScanner", "vendor_name": "Attacker"},
        },
        "finding_info": {"title": "Native title", "uid": "native-uid"},
        "compliance": {"status_id": 3, "standards": ["cis-aws"]},
        # The forged block tries to impersonate an Evidentia finding
        # with elevated severity + a different source_system + a
        # different id. With trust_unmapped=False it MUST be ignored.
        "unmapped": {
            "evidentia": {
                "id": "ATTACKER-CONTROLLED-ID",
                "title": "Forged Evidentia title",
                "description": "d",
                "severity": "critical",
                "source_system": "aws-config",  # trusted source impersonation
            }
        },
    }
    restored = finding_from_ocsf(forged, trust_unmapped=False)
    # The native OCSF fields win; the forged block is dropped.
    assert restored.id != "ATTACKER-CONTROLLED-ID"
    assert restored.title == "Native title"
    assert restored.severity == Severity.LOW
    assert restored.source_system == "MaliciousScanner"
