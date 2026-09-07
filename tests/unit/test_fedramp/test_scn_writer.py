"""Unit tests for the FedRAMP SCN-CSO-INF writer and validator (V13-17).

Round-trips ``SCRForm.to_scn_document()`` output through the vendored
``fedramp-significant-change-notifications-schema-2026-06-24.json``
(Draft 2020-12) with the offline ``$id`` registry, including a
negative case proving the validator resolves the schema's one
cross-document ``$ref`` into the vendored common-definitions schema.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from pathlib import Path

import pytest
from evidentia_core.ai_governance import DeploymentStatus
from evidentia_core.ai_governance.scr import SCRCategory, SCRForm
from evidentia_core.fedramp import validate_scn_document
from evidentia_core.fedramp.scn import SCN_SCHEMA_PATH

GOLDEN_PATH = Path(__file__).parent.parent.parent / "data" / "fedramp" / "significant-change-notification.golden.json"
UPSTREAM_PATH = SCN_SCHEMA_PATH.parent / "UPSTREAM.json"


def _full_form(**overrides: object) -> SCRForm:
    """Build a fully populated adaptive SCRForm with fixed values.

    Every optional field is set so ``to_scn_document()`` exercises
    every conditional key, and the identifiers are fixed so the
    output is reproducible for the golden file.
    """
    base: dict[str, object] = {
        "scr_id": "0b6d0e2a-4d4c-4d9a-9a1e-6b0a9d5c1f11",
        "system_id": "system-fedramp-scn-demo",
        "system_name": "FedRAMP SCN Demo System",
        "category": SCRCategory.ADAPTIVE,
        "proposed_date": date(2026, 10, 1),
        "summary": "Adds a redundant availability zone to the production deployment.",
        "customer_impact": "No customer-facing downtime; capacity increases only.",
        "plan_and_timeline": "Provision the zone, validate failover, then enable traffic.",
        "impacted_controls": ["AC-2", "CM-6"],
        "rollback_plan": "Disable the new zone and revert the load balancer weights.",
        "deployment_status_before": DeploymentStatus.PRODUCTION,
        "deployment_status_after": DeploymentStatus.PRODUCTION,
        "submitted_by": "grc-team@provider.example",
        "submitted_at": date(2026, 9, 7),
        "service_offering_fedramp_id": "FR-90210",
        "three_pao_name": "Acme Assessors LLC",
        "type_of_change": "Infrastructure capacity change",
        "related_poam": "POAM-2026-014",
        "reason_for_change": "Sustained load is approaching the current capacity ceiling.",
        "components_and_controls_affected": "Load balancer and application tier; AC-2, CM-6.",
        "business_security_impact_analysis": "Low risk; adds capacity without new external exposure.",
        "approver_name_and_title": "Jordan Rivera, CISO",
        "certification_package_overview_uri": "https://provider.example/fedramp/cpo.json",
        "change_type_explanation": "Adaptive because it changes infrastructure without a new system boundary.",
    }
    base.update(overrides)
    return SCRForm.model_validate(base)


class TestScnWriter:
    def test_adaptive_document_matches_golden(self) -> None:
        doc = _full_form().to_scn_document()
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        assert doc == golden
        assert list(doc) == list(golden)

    def test_golden_is_schema_valid(self) -> None:
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        assert validate_scn_document(golden) == []

    def test_transformative_document_is_schema_valid(self) -> None:
        form = SCRForm.model_validate(
            {
                "system_id": "system-scn-minimal",
                "system_name": "Minimal SCN System",
                "category": SCRCategory.TRANSFORMATIVE,
                "proposed_date": date(2026, 11, 1),
                "summary": "Moves the system to a new authorization boundary.",
                "customer_impact": "Customers see a new endpoint; no downtime is expected.",
                "plan_and_timeline": "Cut over during the announced maintenance window.",
                "deployment_status_after": DeploymentStatus.PRODUCTION,
                "certification_package_overview_uri": ("https://provider.example/fedramp/cpo-transformative.json"),
            }
        )
        doc = form.to_scn_document()
        assert validate_scn_document(doc) == []
        assert doc["changeType"] == "Transformative"
        for key in ("changeTypeExplanation", "reason", "impactAnalysis", "assessorName"):
            assert key not in doc

    def test_routine_recurring_raises(self) -> None:
        form = _full_form(category=SCRCategory.ROUTINE_RECURRING)
        with pytest.raises(ValueError, match="routine"):
            form.to_scn_document()

    def test_missing_certification_uri_raises(self) -> None:
        form = _full_form(certification_package_overview_uri=None)
        with pytest.raises(ValueError, match="certification_package_overview_uri"):
            form.to_scn_document()

    def test_validator_rejects_unknown_change_type(self) -> None:
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        golden["changeType"] = "Routine"
        errors = validate_scn_document(golden)
        assert len(errors) == 1
        assert errors[0].startswith("changeType:")

    def test_validator_resolves_cross_document_ref(self) -> None:
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        golden["certificationPackageOverviewUri"] = 7
        errors = validate_scn_document(golden)
        assert len(errors) == 1
        assert errors[0].startswith("certificationPackageOverviewUri:")

    def test_validator_requires_plan_summary(self) -> None:
        golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
        del golden["planAndTimeline"]["summary"]
        errors = validate_scn_document(golden)
        assert any(e.startswith("planAndTimeline:") for e in errors)

    def test_rfc_0007_writer_is_unchanged(self) -> None:
        notif = _full_form().to_oscal_scr_notification()
        assert "service_offering_fedramp_id" in notif
        assert "serviceOfferingFedrampId" not in notif


class TestVendoredSchemaProvenance:
    def test_sha256_matches_upstream_pin(self) -> None:
        upstream = json.loads(UPSTREAM_PATH.read_text(encoding="utf-8"))
        pin = upstream["schemas"]["vendored"][SCN_SCHEMA_PATH.name]
        digest = hashlib.sha256(SCN_SCHEMA_PATH.read_bytes()).hexdigest()
        assert digest == pin["sha256_upstream"]
