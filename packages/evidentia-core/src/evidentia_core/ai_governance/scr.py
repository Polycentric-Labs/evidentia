"""Significant Change Request (SCR) form emit (v0.9.6 P3).

Federal AI systems under continuous authorization must report
significant changes to the Authorizing Official (AO) per:

- `NIST SP 800-37 Rev 2 <https://csrc.nist.gov/pubs/sp/800/37/r2/final>`_
  §3.7 definition of a "significant change": *"a change that is
  likely to substantively affect the security or privacy posture of
  a system."*
- `FedRAMP Significant Change Policies + Procedures
  <https://www.fedramp.gov/assets/resources/documents/CSP_Significant_Change_Policies_and_Procedures.docx>`_
  + the published
  `Significant Change Form Template
  <https://www.fedramp.gov/assets/resources/templates/FedRAMP-Significant-Change-Form-Template.pdf>`_.
- `FedRAMP RFC-0007 Significant Change Notification Standard
  <https://www.fedramp.gov/rfcs/0007/>`_ (the v0.9.5 quarterly resync
  noted CR26 + RFC-0024 stabilization on this surface).

FedRAMP defines three categories of significant change:

  - **Routine Recurring**: planned maintenance with no impact on
    the security posture. Does NOT require AO review per
    Significant Change Policies §4.1.
  - **Transformative**: a change that substantively alters scope
    (new system boundary, new authorization tier, new
    information-type classification). Requires AO review +
    typically a fresh ATO decision.
  - **Adaptive**: minor architectural shift with potential
    security implications (provider change, configuration drift
    above threshold). Requires AO review.

This module ships :class:`SCRForm` (the Pydantic representation of
the FedRAMP PDF template's field set) + :func:`emit_scr_form`, which
diffs two :class:`AISystemRegistryEntry` snapshots (the pre + post
state of a lifecycle transition) and produces a populated SCRForm.

The auto-detected category follows a simple heuristic (see
:func:`classify_change`) that operators can override. The form is
emitted as JSON (machine-readable; CI consumption) + Markdown
(operator-facing; pastes into the FedRAMP PDF template fields).

**Threat-model boundary**: this is a paperwork-generation surface,
not an automated approval workflow. The AO still reviews and
approves; Evidentia just reduces the manual-paperwork burden of
producing a defensible SCR submission package.
"""

from __future__ import annotations

from datetime import date
from enum import Enum

from pydantic import Field

from evidentia_core.ai_governance.fips199 import (
    FIPS199Categorization,
    FIPS199Impact,
)
from evidentia_core.ai_governance.omb_m_24_10 import OMBImpactCategory
from evidentia_core.ai_governance.registry import (
    AISystemRegistryEntry,
    DeploymentStatus,
)
from evidentia_core.models.common import EvidentiaModel, new_id, utc_now


class SCRCategory(str, Enum):
    """FedRAMP SCR categorization per Significant Change Policies §4.1.

    Drives the AO review path: Routine Recurring bypasses formal
    review; Adaptive + Transformative both require AO sign-off
    with progressively more scrutiny.
    """

    ROUTINE_RECURRING = "routine_recurring"
    """Maintenance with no impact on security posture. Per
    FedRAMP Significant Change Policies §4.1, does NOT require
    AO review."""

    ADAPTIVE = "adaptive"
    """Minor architectural change with potential security
    implications. Provider change, configuration drift,
    deployment-tier promotion within existing scope. Requires
    AO review."""

    TRANSFORMATIVE = "transformative"
    """Substantive scope change. New system boundary, new
    authorization tier, FIPS 199 impact level increase, new
    Annex III high-risk domain, OMB M-24-10 category change.
    Requires AO review + typically a fresh ATO decision."""


def _impact_level_increased(
    prior: FIPS199Categorization | None,
    new: FIPS199Categorization | None,
) -> bool:
    """Return True iff the FIPS 199 overall increased between snapshots.

    None → anything is treated as "first-time categorization" — not
    an increase (the v0.9.6 cycle adds the field; pre-v0.9.6 entries
    populating it for the first time should not retroactively trigger
    a transformative SCR). Same-level + decrease + None → not an
    increase.
    """
    if new is None:
        return False
    if prior is None:
        return False

    def _resolve(c: FIPS199Categorization) -> FIPS199Impact:
        """Resolve overall to a FIPS199Impact enum (string coercion-safe)."""
        if c.overall is None:
            # The validator computes overall during construction;
            # this should never trigger.
            return FIPS199Impact.LOW
        if isinstance(c.overall, FIPS199Impact):
            return c.overall
        return FIPS199Impact(c.overall)

    return _resolve(new).rank() > _resolve(prior).rank()


def _omb_impact_escalated(
    prior: OMBImpactCategory | None,
    new: OMBImpactCategory | None,
) -> bool:
    """Return True iff the OMB M-24-10 category became more impactful.

    The rank order:
    NEITHER < (RIGHTS_IMPACTING or SAFETY_IMPACTING) < RIGHTS_AND_SAFETY_IMPACTING.

    First-time population (prior=None → new=anything) is NOT an
    escalation — same rationale as FIPS 199 (v0.9.6 adds the field;
    operators populating it for existing entries shouldn't retro-
    trigger transformative SCRs).
    """
    if prior is None or new is None:
        return False
    rank = {
        OMBImpactCategory.NEITHER: 0,
        OMBImpactCategory.RIGHTS_IMPACTING: 1,
        OMBImpactCategory.SAFETY_IMPACTING: 1,
        OMBImpactCategory.RIGHTS_AND_SAFETY_IMPACTING: 2,
    }

    def _resolve(c: OMBImpactCategory) -> int:
        coerced = c if isinstance(c, OMBImpactCategory) else OMBImpactCategory(c)
        return rank[coerced]

    return _resolve(new) > _resolve(prior)


def classify_change(
    prior: AISystemRegistryEntry,
    new: AISystemRegistryEntry,
) -> SCRCategory:
    """Heuristic SCR-category classifier for a registry-entry transition.

    Decision order (first match wins):

    1. **TRANSFORMATIVE** — any of:
       - EU AI Act tier changed
       - FIPS 199 overall impact increased
       - OMB M-24-10 category escalated
       - Annex III domain changed to a different Annex III value
       - PILOT → PRODUCTION transition (production posture is the
         canonical transformative trigger per FedRAMP §4.1)

    2. **ADAPTIVE** — any of:
       - Provider changed
       - SSP reference changed
       - ATO reference changed
       - Owner changed
       - Deployment status changed (not covered by case 1)

    3. **ROUTINE_RECURRING** — default if nothing in cases 1/2 fired.
       Covers no-op transitions (re-saving an unchanged entry,
       cosmetic ``last_assessed_at`` bumps, etc.).

    Operators can override the auto-classification by supplying
    ``category`` explicitly in :func:`emit_scr_form`.
    """
    # — case 1: transformative
    if prior.classification.eu_ai_act_tier != new.classification.eu_ai_act_tier:
        return SCRCategory.TRANSFORMATIVE
    if _impact_level_increased(
        prior.fips_199_categorization, new.fips_199_categorization
    ):
        return SCRCategory.TRANSFORMATIVE
    if _omb_impact_escalated(prior.omb_impact, new.omb_impact):
        return SCRCategory.TRANSFORMATIVE
    if (
        prior.descriptor.annex_iii_domain
        != new.descriptor.annex_iii_domain
    ):
        return SCRCategory.TRANSFORMATIVE
    if (
        prior.deployment_status == DeploymentStatus.PILOT
        and new.deployment_status == DeploymentStatus.PRODUCTION
    ):
        return SCRCategory.TRANSFORMATIVE

    # — case 2: adaptive
    if prior.provider != new.provider:
        return SCRCategory.ADAPTIVE
    if prior.ssp_reference != new.ssp_reference:
        return SCRCategory.ADAPTIVE
    if prior.ato_reference != new.ato_reference:
        return SCRCategory.ADAPTIVE
    if prior.owner != new.owner:
        return SCRCategory.ADAPTIVE
    if prior.deployment_status != new.deployment_status:
        return SCRCategory.ADAPTIVE

    return SCRCategory.ROUTINE_RECURRING


class SCRForm(EvidentiaModel):
    """FedRAMP Significant Change Request form (v0.9.6 P3 + v0.9.7 P3).

    Pydantic representation of the published FedRAMP Significant
    Change Form Template + v0.9.7 P3 alignment with RFC-0007
    Significant Change Notification Standard required fields.
    Mirrors the template's field structure so operators can render
    the form to JSON / Markdown / OSCAL-SCN structured format and
    paste into the AO submission package without re-keying.

    Three categories of fields:

    1. **Identification**: system + change references (auto-populated
       from the registry-entry diff).
    2. **Change narrative**: customer-impact summary + plan +
       timeline (operator-supplied OR LLM-drafted from the diff).
    3. **Verification plan**: which controls are impacted + how the
       operator will validate after the change.

    v0.9.7 P3 added 8 RFC-0007-aligned Optional fields (all
    backward-compat with v0.9.6 emissions) + a
    :meth:`to_oscal_scr_notification` method emitting the canonical
    RFC-0007 wire format. The existing :meth:`to_markdown` writer
    is unchanged.

    The :meth:`to_markdown` + :meth:`to_oscal_scr_notification` +
    ``model_dump_json()`` writers cover the three operator-facing
    emit paths.
    """

    scr_id: str = Field(
        default_factory=new_id,
        description="Stable UUID for cross-referencing the SCR across systems.",
    )
    system_id: str = Field(
        min_length=1,
        max_length=256,
        description="Reference to the AISystemRegistryEntry.system_id.",
    )
    system_name: str = Field(
        min_length=1,
        max_length=512,
        description="Human-readable system name from the descriptor.",
    )
    category: SCRCategory = Field(
        description=(
            "FedRAMP SCR categorization. Auto-detected via "
            ":func:`classify_change` unless operator-overridden."
        ),
    )
    proposed_date: date = Field(
        description="Date the change is planned to take effect.",
    )
    summary: str = Field(
        min_length=1,
        max_length=8000,
        description=(
            "Human-readable summary of the change. Required field "
            "per the FedRAMP SCR template minimum-information rule."
        ),
    )
    customer_impact: str = Field(
        min_length=1,
        max_length=8000,
        description=(
            "Customer-impact summary: changes to services + customer "
            "configuration responsibilities. Required field per the "
            "FedRAMP SCR template."
        ),
    )
    plan_and_timeline: str = Field(
        min_length=1,
        max_length=8000,
        description=(
            "Plan + timeline for the change including verification, "
            "assessment, and validation of impacted security controls. "
            "Required field per the FedRAMP SCR template."
        ),
    )
    impacted_controls: list[str] = Field(
        default_factory=list,
        description=(
            "Catalog control IDs the operator considers impacted by "
            "the change. Free-form; cross-references the parent "
            "system's SSP."
        ),
    )
    rollback_plan: str | None = Field(
        default=None,
        max_length=8000,
        description=(
            "Optional rollback plan if the change cannot be completed "
            "safely. Recommended for TRANSFORMATIVE changes."
        ),
    )
    deployment_status_before: DeploymentStatus | None = Field(
        default=None,
        description="Snapshot of deployment_status BEFORE the change.",
    )
    deployment_status_after: DeploymentStatus = Field(
        description="Snapshot of deployment_status AFTER the change.",
    )
    submitted_by: str | None = Field(
        default=None,
        max_length=256,
        description="Identity that submitted the SCR (operator email).",
    )
    submitted_at: date = Field(
        default_factory=lambda: utc_now().date(),
        description="Date the SCR was submitted.",
    )

    # ── RFC-0007 alignment (v0.9.7 P3) — all Optional, non-breaking ──
    # Per https://www.fedramp.gov/rfcs/0007/. Universal required
    # fields per the standard are modeled as Optional here so
    # backward-compat is preserved for v0.9.6 SCRForms that didn't
    # carry them. The :meth:`to_oscal_scr_notification` emitter
    # raises if any required-by-RFC-0007 field is missing.
    service_offering_fedramp_id: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "RFC-0007 universal required field. Unique FedRAMP "
            "identifier for the authorized service offering. "
            "Operators supply from their FedRAMP marketplace "
            "listing."
        ),
    )
    three_pao_name: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "RFC-0007 conditional field. Third-party assessment "
            "organization conducting review. Required for "
            "Transformative changes."
        ),
    )
    type_of_change: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "RFC-0007 universal required field. CSP-defined "
            "category label for the change. Distinct from the "
            "Evidentia-classified :class:`SCRCategory` (Routine "
            "/ Adaptive / Transformative) — this is the "
            "operator's free-text label that appears in the "
            "FedRAMP submission. Examples: 'AWS region addition', "
            "'TLS library upgrade', 'New AI-system inventory entry'."
        ),
    )
    related_poam: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "RFC-0007 conditional field. POA&M item ID associated "
            "with this change. Required when the change addresses "
            "an open POA&M finding."
        ),
    )
    reason_for_change: str | None = Field(
        default=None,
        max_length=8000,
        description=(
            "RFC-0007 universal required field. Business or "
            "security justification distinct from the change "
            "summary itself. Operators populate this with the "
            "'why now' rationale."
        ),
    )
    components_and_controls_affected: str | None = Field(
        default=None,
        max_length=8000,
        description=(
            "RFC-0007 universal required field. Summary of "
            "service components + controls touched. Operators "
            "supply or auto-populate from impacted_controls + "
            "system-architecture inventory."
        ),
    )
    business_security_impact_analysis: str | None = Field(
        default=None,
        max_length=16000,
        description=(
            "RFC-0007 universal required field. Detailed risk "
            "assessment with 3PAO concurrence for Transformative "
            "changes. Operators supply the analysis text or a "
            "URI / handle pointing at the assessment document."
        ),
    )
    approver_name_and_title: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "RFC-0007 universal required field. Name + title of "
            "the authorizing official who signed off on the "
            "change. Format: 'Name, Title'."
        ),
    )

    def to_oscal_scr_notification(self) -> dict[str, object]:
        """Emit the SCR in RFC-0007 Significant Change Notification format.

        Returns a JSON-serializable dict matching the field structure
        documented at https://www.fedramp.gov/rfcs/0007/. Operators
        submit this dict (or its JSON serialization) to the FedRAMP
        Significant Change Notification endpoint when CR26's
        machine-readable submission path is active (mandatory
        Jan 1 2027 per CR26 effective dates).

        Universal required fields per RFC-0007:
        - service_offering_fedramp_id
        - type_of_change
        - reason_for_change
        - components_and_controls_affected
        - business_security_impact_analysis
        - approver_name_and_title

        Raises:
            ValueError: When any universal required field is None.
                The error message lists every missing field so the
                operator can populate in one fix cycle.
        """
        missing: list[str] = []
        required_fields = [
            "service_offering_fedramp_id",
            "type_of_change",
            "reason_for_change",
            "components_and_controls_affected",
            "business_security_impact_analysis",
            "approver_name_and_title",
        ]
        for field in required_fields:
            if getattr(self, field) is None:
                missing.append(field)
        if missing:
            raise ValueError(
                f"Cannot emit RFC-0007 SCR notification: required "
                f"fields are None: {missing}. Populate via "
                f"emit_scr_form(...) overrides or set on the "
                f"SCRForm directly before emit."
            )
        out: dict[str, object] = {
            "scr_id": self.scr_id,
            "service_offering_fedramp_id": self.service_offering_fedramp_id,
            "type_of_change": self.type_of_change,
            "evidentia_category": self.category,  # Routine/Adaptive/Transformative
            "short_description": self.summary,
            "reason_for_change": self.reason_for_change,
            "components_and_controls_affected": self.components_and_controls_affected,
            "business_security_impact_analysis": self.business_security_impact_analysis,
            "approver_name_and_title": self.approver_name_and_title,
            "submitted_at": self.submitted_at.isoformat(),
        }
        # Conditional fields surfaced when populated.
        if self.three_pao_name:
            out["three_pao_name"] = self.three_pao_name
        if self.related_poam:
            out["related_poam"] = self.related_poam
        if self.submitted_by:
            out["submitted_by"] = self.submitted_by
        # Adaptive-specific fields per RFC-0007 (subset of what
        # Evidentia carries).
        if self.category == SCRCategory.ADAPTIVE.value:
            out["date_of_change"] = self.proposed_date.isoformat()
            out["verification_and_assessment_steps_summary"] = (
                self.plan_and_timeline
            )
        # Transformative pre-implementation fields per RFC-0007.
        elif self.category == SCRCategory.TRANSFORMATIVE.value:
            out["planned_change_date"] = self.proposed_date.isoformat()
            out["control_verification_steps"] = self.plan_and_timeline
            if self.rollback_plan:
                out["rollback_plan"] = self.rollback_plan
        return out

    def to_markdown(self) -> str:
        """Render the form as Markdown for AO submission packages."""
        lines: list[str] = [
            f"# Significant Change Request — {self.system_name}",
            "",
            f"- **SCR ID**: `{self.scr_id}`",
            f"- **System ID**: `{self.system_id}`",
            f"- **Category**: {self.category}",
            f"- **Proposed effective date**: {self.proposed_date.isoformat()}",
            f"- **Submitted**: {self.submitted_at.isoformat()}",
        ]
        if self.submitted_by:
            lines.append(f"- **Submitted by**: {self.submitted_by}")
        lines.extend(
            [
                f"- **Deployment status (before → after)**: "
                f"{self.deployment_status_before or 'n/a'} → "
                f"{self.deployment_status_after}",
                "",
                "## Summary",
                "",
                self.summary,
                "",
                "## Customer impact",
                "",
                self.customer_impact,
                "",
                "## Plan and timeline",
                "",
                self.plan_and_timeline,
                "",
            ]
        )
        if self.impacted_controls:
            lines.extend(
                [
                    "## Impacted controls",
                    "",
                    *(f"- {cid}" for cid in self.impacted_controls),
                    "",
                ]
            )
        if self.rollback_plan:
            lines.extend(
                [
                    "## Rollback plan",
                    "",
                    self.rollback_plan,
                    "",
                ]
            )
        return "\n".join(lines).rstrip() + "\n"


def emit_scr_form(
    prior: AISystemRegistryEntry,
    new: AISystemRegistryEntry,
    *,
    proposed_date: date | None = None,
    summary: str | None = None,
    customer_impact: str | None = None,
    plan_and_timeline: str | None = None,
    impacted_controls: list[str] | None = None,
    rollback_plan: str | None = None,
    submitted_by: str | None = None,
    category_override: SCRCategory | None = None,
) -> SCRForm:
    """Diff two registry-entry snapshots and produce a populated SCRForm.

    The diff is computed by :func:`classify_change` (auto-detected
    category) unless ``category_override`` is supplied. Free-text
    narrative fields (``summary``, ``customer_impact``,
    ``plan_and_timeline``, ``rollback_plan``) accept operator-
    supplied values; if omitted they default to a machine-generated
    summary of the field diff (sufficient for ROUTINE_RECURRING
    auto-emits; operators amend for ADAPTIVE / TRANSFORMATIVE).

    Args:
        prior: Snapshot of the entry BEFORE the change.
        new: Snapshot of the entry AFTER the change.
        proposed_date: Effective date of the change. Defaults to
            today.
        summary: Operator-supplied narrative. Defaults to auto-diff.
        customer_impact: Operator-supplied impact summary. Defaults
            to "Internal-only AI system; no external customer impact."
            for entries with ``OMBImpactCategory.NEITHER``, otherwise
            "Review required — see registry diff in summary."
        plan_and_timeline: Operator-supplied plan. Defaults to a
            generic template pointing at the proposed_date.
        impacted_controls: List of catalog control IDs. Defaults to
            the entry's existing ``linked_controls``.
        rollback_plan: Optional rollback narrative.
        submitted_by: Submitting identity.
        category_override: Skip the auto-classifier and use this
            value.

    Returns:
        A populated :class:`SCRForm` suitable for ``to_markdown()``
        or ``model_dump_json()`` emit.
    """
    category = category_override or classify_change(prior, new)
    auto_summary = _auto_summary(prior, new)
    return SCRForm(
        system_id=new.system_id,
        system_name=new.descriptor.name,
        category=category,
        proposed_date=proposed_date or utc_now().date(),
        summary=summary or auto_summary,
        customer_impact=(
            customer_impact
            or _default_customer_impact(new)
        ),
        plan_and_timeline=(
            plan_and_timeline
            or _default_plan_and_timeline(proposed_date or utc_now().date())
        ),
        impacted_controls=(
            impacted_controls
            if impacted_controls is not None
            else list(new.linked_controls)
        ),
        rollback_plan=rollback_plan,
        deployment_status_before=prior.deployment_status,
        deployment_status_after=new.deployment_status,
        submitted_by=submitted_by,
    )


def _auto_summary(
    prior: AISystemRegistryEntry,
    new: AISystemRegistryEntry,
) -> str:
    """Generate a default summary describing the field-level diff.

    Lists every field that changed between the two snapshots in
    plain English. Operators amend this for high-stakes
    submissions; for routine recurring changes the auto-summary
    is typically sufficient on its own.
    """
    changes: list[str] = []
    if prior.deployment_status != new.deployment_status:
        changes.append(
            f"deployment_status changed from {prior.deployment_status} "
            f"to {new.deployment_status}"
        )
    if prior.provider != new.provider:
        changes.append(
            f"provider changed from {prior.provider!r} to {new.provider!r}"
        )
    if prior.owner != new.owner:
        changes.append(
            f"owner changed from {prior.owner!r} to {new.owner!r}"
        )
    if prior.classification.eu_ai_act_tier != new.classification.eu_ai_act_tier:
        changes.append(
            f"EU AI Act tier changed from "
            f"{prior.classification.eu_ai_act_tier} to "
            f"{new.classification.eu_ai_act_tier}"
        )
    if prior.fips_199_categorization != new.fips_199_categorization:
        changes.append("FIPS 199 categorization updated")
    if prior.ato_reference != new.ato_reference:
        changes.append("ATO reference updated")
    if prior.ssp_reference != new.ssp_reference:
        changes.append(
            f"SSP reference changed from {prior.ssp_reference!r} to "
            f"{new.ssp_reference!r}"
        )
    if prior.omb_impact != new.omb_impact:
        changes.append(
            f"OMB M-24-10 impact changed from {prior.omb_impact} to "
            f"{new.omb_impact}"
        )
    if not changes:
        return "No field-level changes detected (no-op SCR emit)."
    return "Field-level changes: " + "; ".join(changes) + "."


def _default_customer_impact(entry: AISystemRegistryEntry) -> str:
    """Default customer-impact narrative based on OMB classification."""
    if entry.omb_impact == OMBImpactCategory.NEITHER:
        return (
            "Internal-only AI system per OMB M-24-10 §5(b); no external "
            "customer impact. Review required only for changes that "
            "would re-categorize the system as rights/safety-impacting."
        )
    if entry.omb_impact is None:
        return (
            "OMB M-24-10 categorization not yet populated; operator "
            "review required to determine customer-impact scope."
        )
    return (
        f"System is OMB M-24-10 {entry.omb_impact}-impacting; "
        "external customer impact assessment required per §5(c) "
        "minimum risk-management practices. Operator MUST review + "
        "amend this section before AO submission."
    )


def _default_plan_and_timeline(proposed_date: date) -> str:
    """Default plan + timeline template."""
    return (
        f"Proposed effective date: {proposed_date.isoformat()}. "
        "Operator-supplied verification + control-assessment plan "
        "required before AO submission. This auto-generated template "
        "is a placeholder; populate with: (a) the test plan for "
        "impacted controls, (b) the rollback trigger / criteria, and "
        "(c) the post-change monitoring cadence."
    )


__all__ = [
    "SCRCategory",
    "SCRForm",
    "classify_change",
    "emit_scr_form",
]
