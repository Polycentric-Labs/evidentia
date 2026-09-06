"""Unit tests for evidentia_core.oscal.poam_exporter (v0.9.0 P2)."""

from __future__ import annotations

import base64
import json
from datetime import date

from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
    Milestone,
    POAMState,
)
from evidentia_core.oscal.poam_exporter import (
    EVIDENTIA_OSCAL_NS,
    gap_report_to_oscal_poam,
)


def _make_gap(
    control_id: str = "AC-2",
    severity: GapSeverity = GapSeverity.HIGH,
    milestones: list[Milestone] | None = None,
) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title="Account Management",
        control_description="Manage system accounts.",
        gap_severity=severity,
        implementation_status="missing",
        gap_description="No automated lifecycle.",
        remediation_guidance="Implement Okta lifecycle integration.",
        implementation_effort=ImplementationEffort.MEDIUM,
        poam_milestones=milestones or [],
    )


def _make_report(gaps: list[ControlGap]) -> GapAnalysisReport:
    return GapAnalysisReport(
        organization="Acme Corp",
        frameworks_analyzed=["nist-800-53-rev5"],
        total_controls_required=100,
        total_controls_in_inventory=80,
        total_gaps=len(gaps),
        critical_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.CRITICAL),
        high_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.HIGH),
        medium_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.MEDIUM),
        low_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.LOW),
        coverage_percentage=80.0,
        gaps=gaps,
    )


# ── top-level shape ────────────────────────────────────────────────


class TestTopLevelShape:
    def test_emits_plan_of_action_and_milestones_root(self) -> None:
        report = _make_report([_make_gap()])
        doc = gap_report_to_oscal_poam(report)
        assert "plan-of-action-and-milestones" in doc

    def test_metadata_carries_organization_title(self) -> None:
        report = _make_report([_make_gap()])
        doc = gap_report_to_oscal_poam(report)
        metadata = doc["plan-of-action-and-milestones"]["metadata"]
        assert "Acme Corp" in metadata["title"]
        # v0.9.6 P4.2: schema bumped from 1.1.2 to 1.2.1 via the
        # `OSCAL_SCHEMA_VERSION` single-source-of-truth constant.
        assert metadata["oscal-version"] == "1.2.1"

    def test_import_ssp_block_present(self) -> None:
        report = _make_report([_make_gap()])
        doc = gap_report_to_oscal_poam(report)
        poam = doc["plan-of-action-and-milestones"]
        assert "import-ssp" in poam
        assert poam["import-ssp"]["href"]

    def test_metadata_props_include_poam_count(self) -> None:
        report = _make_report(
            [
                _make_gap("AC-1", GapSeverity.CRITICAL),
                _make_gap("AC-2", GapSeverity.HIGH),
            ]
        )
        doc = gap_report_to_oscal_poam(report)
        props = doc["plan-of-action-and-milestones"]["metadata"]["props"]
        count_props = [p for p in props if p["name"] == "poam-item-count"]
        assert count_props
        assert count_props[0]["value"] == "2"


# ── default severity filter ────────────────────────────────────────


class TestDefaultSeverityFilter:
    def test_critical_and_high_materialized(self) -> None:
        report = _make_report(
            [
                _make_gap("AC-1", GapSeverity.LOW),
                _make_gap("AC-2", GapSeverity.CRITICAL),
                _make_gap("AC-3", GapSeverity.HIGH),
                _make_gap("AC-4", GapSeverity.MEDIUM),
            ]
        )
        doc = gap_report_to_oscal_poam(report)
        poam_items = doc["plan-of-action-and-milestones"]["poam-items"]
        assert len(poam_items) == 2

    def test_custom_severity_filter_passes_all(self) -> None:
        report = _make_report(
            [
                _make_gap("AC-1", GapSeverity.LOW),
                _make_gap("AC-2", GapSeverity.MEDIUM),
            ]
        )
        doc = gap_report_to_oscal_poam(report, severity_filter=lambda _: True)
        poam_items = doc["plan-of-action-and-milestones"]["poam-items"]
        assert len(poam_items) == 2


# ── poam-item structure ────────────────────────────────────────────


class TestPoamItemStructure:
    def test_each_item_has_uuid_and_cross_references(self) -> None:
        report = _make_report([_make_gap("AC-2", GapSeverity.HIGH)])
        doc = gap_report_to_oscal_poam(report)
        poam = doc["plan-of-action-and-milestones"]
        item = poam["poam-items"][0]
        assert item["uuid"]
        assert "related-observations" in item
        assert "related-risks" in item
        # Cross-references resolve
        risk_uuids = {r["uuid"] for r in poam["risks"]}
        obs_uuids = {o["uuid"] for o in poam["observations"]}
        for ref in item["related-risks"]:
            assert ref["risk-uuid"] in risk_uuids
        for ref in item["related-observations"]:
            assert ref["observation-uuid"] in obs_uuids

    def test_item_props_carry_evidentia_namespace(self) -> None:
        report = _make_report([_make_gap("AC-2", GapSeverity.HIGH)])
        doc = gap_report_to_oscal_poam(report)
        item = doc["plan-of-action-and-milestones"]["poam-items"][0]
        ev_props = [p for p in item["props"] if p.get("ns") == EVIDENTIA_OSCAL_NS]
        assert ev_props
        # framework + control-id + severity + milestone-count
        names = {p["name"] for p in ev_props}
        assert "framework" in names
        assert "control-id" in names
        assert "severity" in names
        assert "milestone-count" in names


# ── milestone → tracking-entry ────────────────────────────────────


class TestMilestoneMapping:
    def test_milestones_emit_as_tracking_entries(self) -> None:
        ms = Milestone(
            target_date=date(2026, 6, 30),
            description="Deliver Okta integration",
            status=POAMState.IN_PROGRESS,
        )
        report = _make_report([_make_gap("AC-2", GapSeverity.HIGH, milestones=[ms])])
        doc = gap_report_to_oscal_poam(report)
        risk = doc["plan-of-action-and-milestones"]["risks"][0]
        assert "remediations" in risk
        rem = risk["remediations"][0]
        assert "remediation-tracking" in rem
        entries = rem["remediation-tracking"]["tracking-entries"]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["uuid"] == ms.id
        assert "Deliver Okta integration" in entry["description"]

    def test_tracking_entry_carries_status_and_target_date_props(
        self,
    ) -> None:
        ms = Milestone(
            target_date=date(2026, 6, 30),
            description="phase 1",
            status=POAMState.IN_PROGRESS,
        )
        report = _make_report([_make_gap("AC-2", GapSeverity.HIGH, milestones=[ms])])
        doc = gap_report_to_oscal_poam(report)
        entry = doc["plan-of-action-and-milestones"]["risks"][0]["remediations"][0]["remediation-tracking"][
            "tracking-entries"
        ][0]
        prop_names = {p["name"]: p["value"] for p in entry["props"]}
        assert prop_names["status"] == "in_progress"
        assert prop_names["target-date"] == "2026-06-30"

    def test_evidence_ref_emits_when_set(self) -> None:
        ms = Milestone(
            target_date=date(2026, 6, 30),
            description="phase 1",
            evidence_ref="sigstore-bundle://abc123",
        )
        report = _make_report([_make_gap("AC-2", GapSeverity.HIGH, milestones=[ms])])
        doc = gap_report_to_oscal_poam(report)
        entry = doc["plan-of-action-and-milestones"]["risks"][0]["remediations"][0]["remediation-tracking"][
            "tracking-entries"
        ][0]
        prop_names = [p["name"] for p in entry["props"]]
        assert "evidence-ref" in prop_names

    def test_empty_milestone_list_omits_remediation_tracking(
        self,
    ) -> None:
        report = _make_report([_make_gap("AC-2", GapSeverity.HIGH, milestones=[])])
        doc = gap_report_to_oscal_poam(report)
        risk = doc["plan-of-action-and-milestones"]["risks"][0]
        rem = risk["remediations"][0]
        # No tracking-entries since milestones is empty
        assert "remediation-tracking" not in rem


# ── risk + observation ─────────────────────────────────────────────


class TestRiskAndObservation:
    def test_risk_uuid_matches_gap_id(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        report = _make_report([gap])
        doc = gap_report_to_oscal_poam(report)
        risk = doc["plan-of-action-and-milestones"]["risks"][0]
        assert risk["uuid"] == gap.id

    def test_risk_status_maps_correctly(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.status = GapStatus.REMEDIATED
        report = _make_report([gap])
        doc = gap_report_to_oscal_poam(report)
        risk = doc["plan-of-action-and-milestones"]["risks"][0]
        assert risk["status"] == "closed"

    def test_open_gap_maps_to_open_risk(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.status = GapStatus.OPEN
        report = _make_report([gap])
        doc = gap_report_to_oscal_poam(report)
        risk = doc["plan-of-action-and-milestones"]["risks"][0]
        assert risk["status"] == "open"


# ── back-matter integrity ──────────────────────────────────────────


class TestBackMatterIntegrity:
    def test_back_matter_resource_emitted_by_default(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        report = _make_report([gap])
        doc = gap_report_to_oscal_poam(report)
        bm = doc["plan-of-action-and-milestones"]["back-matter"]
        assert len(bm["resources"]) == 1
        resource = bm["resources"][0]
        assert resource["uuid"] == gap.id

    def test_back_matter_carries_sha256_digest(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        report = _make_report([gap])
        doc = gap_report_to_oscal_poam(report)
        resource = doc["plan-of-action-and-milestones"]["back-matter"]["resources"][0]
        rlinks = resource["rlinks"]
        assert rlinks
        hashes = rlinks[0]["hashes"]
        assert hashes
        assert hashes[0]["algorithm"] == "SHA-256"
        # format_digest returns "sha256:<64-hex>" per the v0.7.0
        # canonical encoding; total length 71 chars.
        assert hashes[0]["value"].startswith("sha256:")
        assert len(hashes[0]["value"].split(":", 1)[1]) == 64

    def test_back_matter_disabled_via_flag(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        report = _make_report([gap])
        doc = gap_report_to_oscal_poam(report, embed_back_matter=False)
        assert "back-matter" not in doc["plan-of-action-and-milestones"]

    def test_back_matter_base64_decodes_to_canonical_json(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        report = _make_report([gap])
        doc = gap_report_to_oscal_poam(report)
        resource = doc["plan-of-action-and-milestones"]["back-matter"]["resources"][0]
        encoded = resource["base64"]["value"]
        decoded = base64.b64decode(encoded)
        # Decodes as valid JSON matching the gap record
        record = json.loads(decoded)
        assert record["id"] == gap.id
        assert record["framework"] == "nist-800-53-rev5"
        assert record["control_id"] == "AC-2"


# ── deterministic JSON ─────────────────────────────────────────────


class TestDeterminism:
    def test_repeated_emit_produces_same_back_matter_digest(self) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        report = _make_report([gap])
        doc1 = gap_report_to_oscal_poam(report)
        doc2 = gap_report_to_oscal_poam(report)
        digest1 = doc1["plan-of-action-and-milestones"]["back-matter"]["resources"][0]["rlinks"][0]["hashes"][0][
            "value"
        ]
        digest2 = doc2["plan-of-action-and-milestones"]["back-matter"]["resources"][0]["rlinks"][0]["hashes"][0][
            "value"
        ]
        # Same record → same canonical JSON → same SHA-256.
        # (Other top-level UUIDs differ between emits — only the
        # back-matter digest is integrity-bound to the record.)
        assert digest1 == digest2


class TestEmptyArrayOmission:
    """OSCAL minItems=1: the optional ``observations`` and ``risks`` arrays
    are OMITTED when the severity filter selects no gaps, never emitted as
    ``[]`` (trestle >= 5.0 rejects empty arrays the 4.x line tolerated).
    ``poam-items`` is a REQUIRED field and stays as-is: a POA&M with no
    materialized items failing schema validation is correct signal, not a
    shape to paper over."""

    def test_filtered_to_empty_poam_omits_optional_arrays(self) -> None:
        # MEDIUM-only gaps: the default CRITICAL+HIGH filter selects none.
        report = _make_report([_make_gap(severity=GapSeverity.MEDIUM)])
        doc = gap_report_to_oscal_poam(report)
        poam = doc["plan-of-action-and-milestones"]
        assert "observations" not in poam
        assert "risks" not in poam
        assert poam["poam-items"] == []

    def test_selected_gaps_keep_observations_and_risks(self) -> None:
        report = _make_report([_make_gap(severity=GapSeverity.HIGH)])
        doc = gap_report_to_oscal_poam(report)
        poam = doc["plan-of-action-and-milestones"]
        assert len(poam["observations"]) == 1
        assert len(poam["risks"]) == 1
        assert len(poam["poam-items"]) == 1
