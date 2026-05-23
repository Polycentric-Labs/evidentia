"""Tests for the v0.10.1 OCSF ingestion collector."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("py_ocsf_models")

from evidentia_collectors.ocsf import (
    OCSFIngestError,
    collect_ocsf_file,
    collect_ocsf_url,
)
from evidentia_core.models.common import OLIRRelationship, Severity
from evidentia_core.models.finding import ComplianceStatus

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "ocsf"


def test_collect_file_prowler_detection_finding() -> None:
    """Prowler-shaped Detection Finding ingests to a SecurityFinding."""
    findings = collect_ocsf_file(FIXTURES / "prowler-detection-finding.json")
    assert len(findings) == 1
    f = findings[0]
    assert f.title == "S3 Bucket Public Read"
    assert f.severity == Severity.HIGH
    # Detection Finding severity HIGH -> FAIL per the v0.10.1 heuristic.
    assert f.compliance_status == ComplianceStatus.FAIL
    assert f.source_system == "Prowler"
    assert f.resource_type == "AwsS3Bucket"
    assert f.resource_region == "us-east-1"
    assert "AllUsers" in (f.remediation or "")
    # Detection Finding has no compliance.standards/requirements.
    assert f.control_mappings == []


def test_collect_file_security_hub_detection_finding() -> None:
    """AWS Security Hub-shaped Detection Finding also ingests cleanly."""
    findings = collect_ocsf_file(FIXTURES / "security-hub-detection-finding.json")
    assert len(findings) == 1
    f = findings[0]
    # Severity MEDIUM -> compliance_status FAIL per the heuristic.
    assert f.severity == Severity.MEDIUM
    assert f.compliance_status == ComplianceStatus.FAIL
    assert f.source_system == "AWS Security Hub"


def test_collect_file_mixed_batch_dispatches_by_class_uid() -> None:
    """A JSON list with both class_uids dispatches each to the right path."""
    findings = collect_ocsf_file(FIXTURES / "mixed-batch.json")
    assert len(findings) == 2
    # First finding is Compliance Finding (class_uid 2003) with cis-aws standard.
    compliance = findings[0]
    assert compliance.title == "Encryption at rest disabled"
    assert compliance.compliance_status == ComplianceStatus.FAIL
    assert compliance.control_mappings[0].framework == "cis-aws"
    assert compliance.control_mappings[0].control_id == "2.1.1"
    # OLIR relationship defaults to RELATED_TO with an OCSF-import note,
    # because the unmapped block is bypassed via trust_unmapped=False.
    assert compliance.control_mappings[0].relationship == OLIRRelationship.RELATED_TO
    assert "Ingested from OCSF" in compliance.control_mappings[0].justification
    # Second finding is Detection Finding (class_uid 2004) with empty mappings.
    detection = findings[1]
    assert detection.title == "CloudTrail not multi-region"
    assert detection.control_mappings == []
    # Detection Finding severity LOW -> WARNING per the heuristic.
    assert detection.compliance_status == ComplianceStatus.WARNING


def test_collect_file_rejects_invalid_json(tmp_path: Path) -> None:
    bad = tmp_path / "broken.json"
    bad.write_text("not a json document", encoding="utf-8")
    with pytest.raises(OCSFIngestError) as exc:
        collect_ocsf_file(bad)
    assert "not valid JSON" in str(exc.value)


def test_collect_file_rejects_unsupported_class_uid(tmp_path: Path) -> None:
    """Anything other than 2003 / 2004 in the Findings category is refused."""
    bad = tmp_path / "wrong-class.json"
    bad.write_text(
        json.dumps({"class_uid": 9999, "category_uid": 2}), encoding="utf-8"
    )
    with pytest.raises(OCSFIngestError) as exc:
        collect_ocsf_file(bad)
    assert "unsupported OCSF class_uid" in str(exc.value)


def test_collect_file_rejects_non_object_root(tmp_path: Path) -> None:
    bad = tmp_path / "string-root.json"
    bad.write_text('"just a string"', encoding="utf-8")
    with pytest.raises(OCSFIngestError) as exc:
        collect_ocsf_file(bad)
    assert "JSON root must be an object or a list" in str(exc.value)


def test_collect_url_rejects_http() -> None:
    """URL mode is HTTPS-only — `http://` is refused before any network I/O."""
    with pytest.raises(OCSFIngestError) as exc:
        collect_ocsf_url("http://example.com/ocsf.json")
    assert "HTTPS-only" in str(exc.value)


def test_collect_url_rejects_ftp_and_other_schemes() -> None:
    """Any non-HTTPS scheme is refused."""
    for url in ("ftp://example.com/x", "file:///etc/passwd", "javascript:alert(1)"):
        with pytest.raises(OCSFIngestError):
            collect_ocsf_url(url)


def test_collect_file_does_not_trust_unmapped_block_by_default(
    tmp_path: Path,
) -> None:
    """Even a Compliance Finding with a forged unmapped block falls back
    to native fields — the collector passes trust_unmapped=False to the
    underlying mapping function. This is the v0.10.1 trust-boundary
    close-out exercised through the collector layer."""
    forged = {
        "activity_id": 1,
        "category_uid": 2,
        "class_uid": 2003,
        "type_uid": 200301,
        "time": 1_716_422_400_000,
        "severity_id": 2,
        "metadata": {
            "version": "1.5.0",
            "product": {"name": "MaliciousScanner", "vendor_name": "Attacker"},
        },
        "finding_info": {"title": "Native title", "uid": "native-uid"},
        "compliance": {"status_id": 3, "standards": ["cis-aws"]},
        "unmapped": {
            "evidentia": {
                "id": "ATTACKER-FORGED",
                "title": "Forged",
                "description": "d",
                "severity": "critical",
                "source_system": "aws-config",
            }
        },
    }
    path = tmp_path / "forged.json"
    path.write_text(json.dumps(forged), encoding="utf-8")
    findings = collect_ocsf_file(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.id != "ATTACKER-FORGED"
    assert f.title == "Native title"
    assert f.source_system == "MaliciousScanner"
    assert f.severity == Severity.LOW
