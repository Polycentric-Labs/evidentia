"""Unit tests for the v0.9.6 P3 federal AI-gov surfaces.

Covers:

- :mod:`evidentia_core.ai_governance.fips199` — FIPS 199
  categorization model + high-water-mark validator.
- :mod:`evidentia_core.ai_governance.omb_m_24_10` — OMB M-24-10
  impact category enum + ``triggers_minimum_practices`` helper.
- :mod:`evidentia_core.ai_governance.scr` — SCRForm Pydantic model,
  ``classify_change`` heuristic, ``emit_scr_form`` end-to-end.
- :mod:`evidentia_core.ai_governance.registry` — federal-field
  extension to ``AISystemRegistryEntry`` + ``ATOReference`` submodel.
"""

from __future__ import annotations

from datetime import date

import pytest
from evidentia_core.ai_governance import (
    AISystemDescriptor,
    AISystemRegistryEntry,
    ATOReference,
    DeploymentStatus,
    FIPS199Categorization,
    FIPS199Impact,
    OMBImpactCategory,
    classify,
    triggers_minimum_practices,
)
from evidentia_core.ai_governance.scr import (
    SCRCategory,
    SCRForm,
    classify_change,
    emit_scr_form,
)
from pydantic import ValidationError


def _make_entry(**overrides: object) -> AISystemRegistryEntry:
    """Construct a minimal registry entry for diff-based tests."""
    descriptor = AISystemDescriptor(
        name="test-system",
        purpose="Test purpose",
    )
    classification = classify(descriptor)
    base: dict[str, object] = {
        "descriptor": descriptor,
        "classification": classification,
        "provider": "self-built",
        "owner": "team-grc",
    }
    base.update(overrides)
    return AISystemRegistryEntry.model_validate(base)


# ── FIPS 199 model ─────────────────────────────────────────────────


class TestFIPS199Categorization:
    def test_high_water_mark_high_wins(self) -> None:
        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.LOW,
            integrity_impact=FIPS199Impact.HIGH,
            availability_impact=FIPS199Impact.MODERATE,
        )
        assert cat.overall == FIPS199Impact.HIGH

    def test_high_water_mark_all_low(self) -> None:
        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.LOW,
            integrity_impact=FIPS199Impact.LOW,
            availability_impact=FIPS199Impact.LOW,
        )
        assert cat.overall == FIPS199Impact.LOW

    def test_high_water_mark_all_moderate(self) -> None:
        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.MODERATE,
            integrity_impact=FIPS199Impact.MODERATE,
            availability_impact=FIPS199Impact.MODERATE,
        )
        assert cat.overall == FIPS199Impact.MODERATE

    def test_explicit_overall_must_match(self) -> None:
        with pytest.raises(ValidationError):
            FIPS199Categorization(
                confidentiality_impact=FIPS199Impact.LOW,
                integrity_impact=FIPS199Impact.HIGH,
                availability_impact=FIPS199Impact.LOW,
                overall=FIPS199Impact.LOW,  # wrong; max is HIGH
            )

    def test_explicit_overall_matching_accepted(self) -> None:
        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.LOW,
            integrity_impact=FIPS199Impact.HIGH,
            availability_impact=FIPS199Impact.LOW,
            overall=FIPS199Impact.HIGH,
        )
        assert cat.overall == FIPS199Impact.HIGH

    def test_rationale_optional(self) -> None:
        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.MODERATE,
            integrity_impact=FIPS199Impact.MODERATE,
            availability_impact=FIPS199Impact.MODERATE,
        )
        assert cat.rationale is None

    def test_rationale_populated(self) -> None:
        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.MODERATE,
            integrity_impact=FIPS199Impact.MODERATE,
            availability_impact=FIPS199Impact.MODERATE,
            rationale="Per SP 800-60 worked example for HR-data systems.",
        )
        assert "HR-data" in (cat.rationale or "")

    def test_impact_rank_order(self) -> None:
        assert FIPS199Impact.LOW.rank() < FIPS199Impact.MODERATE.rank()
        assert FIPS199Impact.MODERATE.rank() < FIPS199Impact.HIGH.rank()

    def test_string_coercion(self) -> None:
        """Operators may load raw strings from JSON / YAML — model_validate
        should coerce to FIPS199Impact via the enum's string base."""
        cat = FIPS199Categorization.model_validate(
            {
                "confidentiality_impact": "moderate",
                "integrity_impact": "high",
                "availability_impact": "low",
            }
        )
        assert cat.overall == FIPS199Impact.HIGH


# ── OMB M-24-10 ────────────────────────────────────────────────────


class TestOMBImpactCategory:
    def test_neither_does_not_trigger(self) -> None:
        assert not triggers_minimum_practices(OMBImpactCategory.NEITHER)

    def test_rights_triggers(self) -> None:
        assert triggers_minimum_practices(
            OMBImpactCategory.RIGHTS_IMPACTING
        )

    def test_safety_triggers(self) -> None:
        assert triggers_minimum_practices(
            OMBImpactCategory.SAFETY_IMPACTING
        )

    def test_both_triggers(self) -> None:
        assert triggers_minimum_practices(
            OMBImpactCategory.RIGHTS_AND_SAFETY_IMPACTING
        )

    def test_enum_values_stable(self) -> None:
        # String values are persisted in YAML; if these change,
        # operator inventories break.
        assert OMBImpactCategory.RIGHTS_IMPACTING.value == "rights_impacting"
        assert OMBImpactCategory.SAFETY_IMPACTING.value == "safety_impacting"
        assert (
            OMBImpactCategory.RIGHTS_AND_SAFETY_IMPACTING.value
            == "rights_and_safety_impacting"
        )
        assert OMBImpactCategory.NEITHER.value == "neither"


# ── ATOReference + registry extension ──────────────────────────────


class TestATOReference:
    def test_required_fields_only(self) -> None:
        ato = ATOReference(
            system_name="my-system",
            authorizing_official="Jane Doe, CIO",
            ato_date=date(2026, 1, 15),
        )
        assert ato.expiry_date is None
        assert ato.ato_letter_uri is None

    def test_all_fields(self) -> None:
        ato = ATOReference(
            system_name="my-system",
            authorizing_official="Jane Doe, CIO",
            ato_date=date(2026, 1, 15),
            expiry_date=date(2029, 1, 14),
            ato_letter_uri="https://example.gov/atos/my-system-v1.pdf",
            notes="3-year ATO; reauth Q1 2029.",
        )
        assert ato.expiry_date == date(2029, 1, 14)
        assert ato.notes is not None

    def test_cato_posture_expiry_none(self) -> None:
        ato = ATOReference(
            system_name="cato-system",
            authorizing_official="Bob",
            ato_date=date(2026, 5, 1),
            notes="cATO posture; continuous monitoring replaces fixed expiry.",
        )
        assert ato.expiry_date is None


class TestRegistryFederalExtension:
    def test_backward_compat_none_fields(self) -> None:
        entry = _make_entry()
        assert entry.fips_199_categorization is None
        assert entry.ato_reference is None
        assert entry.ssp_reference is None
        assert entry.omb_impact is None

    def test_round_trip_with_all_federal_fields(self) -> None:
        entry = _make_entry(
            fips_199_categorization=FIPS199Categorization(
                confidentiality_impact=FIPS199Impact.MODERATE,
                integrity_impact=FIPS199Impact.HIGH,
                availability_impact=FIPS199Impact.LOW,
            ),
            ato_reference=ATOReference(
                system_name="fed-system",
                authorizing_official="Authorizing Officer",
                ato_date=date(2026, 1, 1),
            ),
            ssp_reference="emass://12345",
            omb_impact=OMBImpactCategory.RIGHTS_IMPACTING,
        )
        json_blob = entry.model_dump_json()
        loaded = AISystemRegistryEntry.model_validate_json(json_blob)
        assert loaded.fips_199_categorization is not None
        assert loaded.fips_199_categorization.overall == FIPS199Impact.HIGH
        assert loaded.omb_impact == OMBImpactCategory.RIGHTS_IMPACTING
        assert loaded.ssp_reference == "emass://12345"
        assert loaded.ato_reference is not None
        assert loaded.ato_reference.system_name == "fed-system"

    def test_legacy_entry_json_loads(self) -> None:
        """v0.9.3 – v0.9.5 entries (pre-federal) should deserialize."""
        legacy = _make_entry()
        # Strip the federal fields as they would NOT exist in legacy
        # serialization.
        dumped = legacy.model_dump(mode="python")
        for field in (
            "fips_199_categorization",
            "ato_reference",
            "ssp_reference",
            "omb_impact",
        ):
            dumped.pop(field, None)
        loaded = AISystemRegistryEntry.model_validate(dumped)
        assert loaded.fips_199_categorization is None


# ── SCR classifier ─────────────────────────────────────────────────


class TestClassifyChange:
    def test_no_diff_is_routine_recurring(self) -> None:
        entry = _make_entry()
        assert classify_change(entry, entry) == SCRCategory.ROUTINE_RECURRING

    def test_provider_change_is_adaptive(self) -> None:
        prior = _make_entry()
        new = prior.model_copy(update={"provider": "different-vendor"})
        assert classify_change(prior, new) == SCRCategory.ADAPTIVE

    def test_owner_change_is_adaptive(self) -> None:
        prior = _make_entry()
        new = prior.model_copy(update={"owner": "new-team"})
        assert classify_change(prior, new) == SCRCategory.ADAPTIVE

    def test_ssp_change_is_adaptive(self) -> None:
        prior = _make_entry(ssp_reference="emass://old")
        new = prior.model_copy(update={"ssp_reference": "emass://new"})
        assert classify_change(prior, new) == SCRCategory.ADAPTIVE

    def test_pilot_to_production_is_transformative(self) -> None:
        prior = _make_entry(deployment_status=DeploymentStatus.PILOT)
        new = prior.model_copy(
            update={"deployment_status": DeploymentStatus.PRODUCTION}
        )
        assert classify_change(prior, new) == SCRCategory.TRANSFORMATIVE

    def test_proposed_to_in_dev_is_adaptive(self) -> None:
        prior = _make_entry(deployment_status=DeploymentStatus.PROPOSED)
        new = prior.model_copy(
            update={"deployment_status": DeploymentStatus.IN_DEVELOPMENT}
        )
        assert classify_change(prior, new) == SCRCategory.ADAPTIVE

    def test_fips_escalation_is_transformative(self) -> None:
        low_cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.LOW,
            integrity_impact=FIPS199Impact.LOW,
            availability_impact=FIPS199Impact.LOW,
        )
        high_cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact.HIGH,
            integrity_impact=FIPS199Impact.LOW,
            availability_impact=FIPS199Impact.LOW,
        )
        prior = _make_entry(fips_199_categorization=low_cat)
        new = prior.model_copy(update={"fips_199_categorization": high_cat})
        assert classify_change(prior, new) == SCRCategory.TRANSFORMATIVE

    def test_omb_escalation_to_rights_impacting_is_transformative(
        self,
    ) -> None:
        prior = _make_entry(omb_impact=OMBImpactCategory.NEITHER)
        new = prior.model_copy(
            update={"omb_impact": OMBImpactCategory.RIGHTS_IMPACTING}
        )
        assert classify_change(prior, new) == SCRCategory.TRANSFORMATIVE

    def test_omb_first_population_is_routine(self) -> None:
        """Populating OMB for the first time (None → IMPACTING) should
        NOT trigger a transformative SCR — operators backfilling the
        federal fields shouldn't get spurious change-requests."""
        prior = _make_entry(omb_impact=None)
        new = prior.model_copy(
            update={"omb_impact": OMBImpactCategory.RIGHTS_IMPACTING}
        )
        # Only the omb_impact field changed; no adaptive triggers
        # fired. Routine recurring.
        assert classify_change(prior, new) == SCRCategory.ROUTINE_RECURRING


# ── SCRForm emit ───────────────────────────────────────────────────


class TestEmitSCRForm:
    def test_minimal_no_diff_form(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        assert form.system_id == entry.system_id
        assert form.category == SCRCategory.ROUTINE_RECURRING
        assert "No field-level changes" in form.summary

    def test_form_carries_status_snapshots(self) -> None:
        prior = _make_entry(deployment_status=DeploymentStatus.PILOT)
        new = prior.model_copy(
            update={"deployment_status": DeploymentStatus.PRODUCTION}
        )
        form = emit_scr_form(prior, new)
        assert form.deployment_status_before == DeploymentStatus.PILOT
        assert form.deployment_status_after == DeploymentStatus.PRODUCTION

    def test_operator_override_summary(self) -> None:
        prior = _make_entry()
        new = prior.model_copy(update={"provider": "new"})
        form = emit_scr_form(
            prior, new, summary="Custom operator narrative."
        )
        assert form.summary == "Custom operator narrative."

    def test_category_override(self) -> None:
        prior = _make_entry()
        new = prior.model_copy(update={"provider": "new"})  # → ADAPTIVE
        form = emit_scr_form(
            prior,
            new,
            category_override=SCRCategory.TRANSFORMATIVE,
        )
        assert form.category == SCRCategory.TRANSFORMATIVE

    def test_to_markdown_includes_key_sections(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        md = form.to_markdown()
        assert "# Significant Change Request" in md
        assert "## Summary" in md
        assert "## Customer impact" in md
        assert "## Plan and timeline" in md

    def test_to_markdown_includes_impacted_controls(self) -> None:
        entry = _make_entry(linked_controls=["AC-3", "AC-6", "AU-9"])
        form = emit_scr_form(entry, entry)
        md = form.to_markdown()
        assert "## Impacted controls" in md
        assert "- AC-3" in md
        assert "- AC-6" in md
        assert "- AU-9" in md

    def test_to_markdown_omits_rollback_when_none(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        md = form.to_markdown()
        assert "## Rollback plan" not in md

    def test_to_markdown_includes_rollback_when_provided(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(
            entry, entry, rollback_plan="Roll back via git revert + redeploy."
        )
        md = form.to_markdown()
        assert "## Rollback plan" in md
        assert "git revert" in md

    def test_default_customer_impact_for_neither(self) -> None:
        entry = _make_entry(omb_impact=OMBImpactCategory.NEITHER)
        form = emit_scr_form(entry, entry)
        assert "Internal-only AI system" in form.customer_impact

    def test_default_customer_impact_for_rights_impacting(self) -> None:
        entry = _make_entry(omb_impact=OMBImpactCategory.RIGHTS_IMPACTING)
        form = emit_scr_form(entry, entry)
        assert "rights_impacting" in form.customer_impact

    def test_default_customer_impact_for_unset(self) -> None:
        entry = _make_entry(omb_impact=None)
        form = emit_scr_form(entry, entry)
        assert "not yet populated" in form.customer_impact

    def test_auto_summary_lists_changes(self) -> None:
        prior = _make_entry()
        new = prior.model_copy(
            update={"owner": "new-owner", "provider": "new-vendor"}
        )
        form = emit_scr_form(prior, new)
        assert "owner" in form.summary
        assert "provider" in form.summary

    def test_form_json_round_trip(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        blob = form.model_dump_json()
        loaded = SCRForm.model_validate_json(blob)
        assert loaded.scr_id == form.scr_id
        assert loaded.category == form.category


# ── RFC-0007 alignment (v0.9.7 P3) ─────────────────────────────────


class TestRFC0007Alignment:
    """v0.9.7 P3: SCRForm carries RFC-0007 SCN required fields +
    emits the canonical structured format via
    :meth:`SCRForm.to_oscal_scr_notification`.
    """

    def test_new_optional_fields_default_none(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        assert form.service_offering_fedramp_id is None
        assert form.three_pao_name is None
        assert form.type_of_change is None
        assert form.related_poam is None
        assert form.reason_for_change is None
        assert form.components_and_controls_affected is None
        assert form.business_security_impact_analysis is None
        assert form.approver_name_and_title is None

    def test_to_oscal_scr_notification_missing_required_raises(
        self,
    ) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        with pytest.raises(ValueError, match="required fields are None"):
            form.to_oscal_scr_notification()

    def test_to_oscal_scr_notification_lists_all_missing(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        # Only populate one field; all others are missing.
        form_with_partial = form.model_copy(
            update={
                "service_offering_fedramp_id": "FR-12345",
            }
        )
        try:
            form_with_partial.to_oscal_scr_notification()
            raise AssertionError("should have raised")
        except ValueError as exc:
            msg = str(exc)
            # 5 required fields still missing.
            assert "type_of_change" in msg
            assert "reason_for_change" in msg
            assert "approver_name_and_title" in msg

    def test_to_oscal_scr_notification_happy_path(self) -> None:
        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        populated = form.model_copy(
            update={
                "service_offering_fedramp_id": "FR-12345",
                "type_of_change": "AI system inventory entry",
                "reason_for_change": "New AI use case approval.",
                "components_and_controls_affected": (
                    "AC-3, AC-6 — access enforcement scope"
                ),
                "business_security_impact_analysis": (
                    "Low business impact; rights-impacting per OMB §5(b)(i)."
                ),
                "approver_name_and_title": "Jane Doe, CISO",
            }
        )
        notif = populated.to_oscal_scr_notification()
        assert notif["service_offering_fedramp_id"] == "FR-12345"
        assert notif["type_of_change"] == "AI system inventory entry"
        assert notif["approver_name_and_title"] == "Jane Doe, CISO"
        # Routine recurring → no Adaptive / Transformative extras.
        assert "date_of_change" not in notif
        assert "planned_change_date" not in notif

    def test_to_oscal_scr_notification_adaptive_adds_date(self) -> None:
        prior = _make_entry()
        new = prior.model_copy(update={"provider": "different-vendor"})
        form = emit_scr_form(prior, new)
        populated = form.model_copy(
            update={
                "service_offering_fedramp_id": "FR-12345",
                "type_of_change": "Provider change",
                "reason_for_change": "Vendor reorganization.",
                "components_and_controls_affected": "AC-3",
                "business_security_impact_analysis": "Low.",
                "approver_name_and_title": "Jane, CISO",
            }
        )
        notif = populated.to_oscal_scr_notification()
        assert notif["evidentia_category"] == SCRCategory.ADAPTIVE.value
        assert "date_of_change" in notif
        assert "verification_and_assessment_steps_summary" in notif

    def test_to_oscal_scr_notification_transformative_adds_rollback(
        self,
    ) -> None:
        prior = _make_entry(deployment_status=DeploymentStatus.PILOT)
        new = prior.model_copy(
            update={"deployment_status": DeploymentStatus.PRODUCTION}
        )
        form = emit_scr_form(
            prior,
            new,
            rollback_plan="Roll back via git revert + redeploy.",
        )
        populated = form.model_copy(
            update={
                "service_offering_fedramp_id": "FR-12345",
                "type_of_change": "Deployment promotion",
                "reason_for_change": "Pilot validation complete.",
                "components_and_controls_affected": "All system components",
                "business_security_impact_analysis": "Moderate; new control gates apply.",
                "approver_name_and_title": "Jane, CISO",
            }
        )
        notif = populated.to_oscal_scr_notification()
        assert notif["evidentia_category"] == SCRCategory.TRANSFORMATIVE.value
        assert "planned_change_date" in notif
        assert "control_verification_steps" in notif
        assert "rollback_plan" in notif
        assert "git revert" in notif["rollback_plan"]  # type: ignore[operator]

    def test_to_oscal_scr_notification_three_pao_conditional(self) -> None:
        prior = _make_entry(deployment_status=DeploymentStatus.PILOT)
        new = prior.model_copy(
            update={"deployment_status": DeploymentStatus.PRODUCTION}
        )
        form = emit_scr_form(prior, new)
        # Without three_pao_name set, it should NOT appear in the
        # notification.
        populated = form.model_copy(
            update={
                "service_offering_fedramp_id": "FR-12345",
                "type_of_change": "Promotion",
                "reason_for_change": "Pilot done.",
                "components_and_controls_affected": "All",
                "business_security_impact_analysis": "Moderate.",
                "approver_name_and_title": "Jane, CISO",
            }
        )
        notif = populated.to_oscal_scr_notification()
        assert "three_pao_name" not in notif
        # With three_pao_name set, it appears.
        with_3pao = populated.model_copy(
            update={"three_pao_name": "Acme 3PAO LLC"}
        )
        notif_with = with_3pao.to_oscal_scr_notification()
        assert notif_with["three_pao_name"] == "Acme 3PAO LLC"

    def test_oscal_scr_json_serializable(self) -> None:
        import json

        entry = _make_entry()
        form = emit_scr_form(entry, entry)
        populated = form.model_copy(
            update={
                "service_offering_fedramp_id": "FR-12345",
                "type_of_change": "Test",
                "reason_for_change": "Test.",
                "components_and_controls_affected": "All",
                "business_security_impact_analysis": "None.",
                "approver_name_and_title": "Jane, CISO",
            }
        )
        notif = populated.to_oscal_scr_notification()
        # Must be JSON-serializable directly (every value is a
        # primitive type or stringified enum).
        blob = json.dumps(notif)
        round_tripped = json.loads(blob)
        assert round_tripped == notif
