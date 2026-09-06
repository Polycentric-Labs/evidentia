"""AI system inventory data model (v0.9.3 P2.4 + v0.9.6 P3 federal expansion).

Pydantic models for registering AI systems in the operator's
governance inventory. Each entry links a descriptor to its
classification + deployment status + responsible operator.

Storage lives in :mod:`evidentia_core.ai_governance.registry_store`
(JSON file-backed; mirrors v0.7.9 vendor_store + v0.9.0 poam_store
pattern).

v0.9.6 P3 adds four optional fields aligning the registry with
federal-tier inventory expectations:

- :class:`FIPS199Categorization` — operator-supplied impact rating
- :class:`ATOReference` — link to the parent system's Authorization
  to Operate decision
- ``ssp_reference`` — URI / handle pointing at the System Security
  Plan document
- :class:`OMBImpactCategory` — OMB M-24-10 Rights / Safety
  classification (DEPRECATED v0.10.12; see below)

All four fields are Optional → backward-compat with v0.9.3 – v0.9.5
entries that pre-date the federal expansion.

v0.10.12 adds a fifth optional field, ``omb_high_impact``
(:class:`OMBHighImpactAssessment`), modelling OMB M-25-21's single
"high-impact AI" category. M-25-21 (2025-04-03) rescinded M-24-10, so
``omb_impact`` is deprecated but retained (still loads/serializes);
both fields are independent and Optional.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum

from pydantic import Field

from evidentia_core.ai_governance.classification import (
    AISystemClassification,
    AISystemDescriptor,
)
from evidentia_core.ai_governance.fips199 import FIPS199Categorization
from evidentia_core.ai_governance.omb_m_24_10 import OMBImpactCategory
from evidentia_core.ai_governance.omb_m_25_21 import OMBHighImpactAssessment
from evidentia_core.models.common import EvidentiaModel, NonBlankStr, new_id, utc_now


class DeploymentStatus(str, Enum):
    """Operational lifecycle status of a registered AI system."""

    PROPOSED = "proposed"
    """Identified as a candidate; not yet in development."""

    IN_DEVELOPMENT = "in_development"
    """Active build / training / integration phase."""

    PILOT = "pilot"
    """Limited production use; observed via CONMON cadences."""

    PRODUCTION = "production"
    """Full deployment; subject to all applicable governance
    obligations (Article 9 risk management, etc. for HIGH tier)."""

    RETIRED = "retired"
    """No longer in use; record retained for audit history."""


class ATOReference(EvidentiaModel):
    """Reference to an Authorization to Operate (ATO) decision (v0.9.6 P3).

    OMB M-24-10 inventory entries link back to the parent federal
    information system's ATO. ATO decisions are issued by an
    Authorizing Official (AO) per NIST SP 800-37 Rev 2 §3.6 and have
    a finite lifecycle (initial → annual reauthorization → expiry).

    Evidentia carries the minimum fields needed for cross-reference:
    the system name as recorded in the SSP, the AO identity (who
    signed), the date the ATO took effect, and the expiry date
    (typically 3 years out under traditional RMF; OngoingAuth /
    cATO models replace the expiry with continuous monitoring
    cadence). Operators with cATO-style authorizations leave
    ``expiry_date`` as None and document the continuous-auth
    posture in ``notes``.
    """

    system_name: NonBlankStr = Field(
        max_length=256,
        description="System name as recorded in the SSP / ATO letter.",
    )
    authorizing_official: NonBlankStr = Field(
        max_length=256,
        description=(
            "Name + title of the Authorizing Official (AO) who issued "
            "the ATO. Free-form to accommodate org-specific title "
            "conventions."
        ),
    )
    ato_date: date = Field(
        description="Date the ATO took effect (ISO-8601 YYYY-MM-DD).",
    )
    expiry_date: date | None = Field(
        default=None,
        description=(
            "Date the ATO expires. None signals an ongoing-auth / "
            "cATO posture (continuous monitoring replaces fixed "
            "expiry)."
        ),
    )
    ato_letter_uri: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "Optional URI / handle pointing at the signed ATO letter "
            "in document storage (eMASS, SharePoint, etc.)."
        ),
    )
    notes: str | None = Field(
        default=None,
        max_length=4000,
        description=(
            "Free-text notes (cATO posture, scope caveats, conditional "
            "approvals, etc.)."
        ),
    )


class AISystemRegistryEntry(EvidentiaModel):
    """One AI system in the operator's governance inventory."""

    system_id: str = Field(
        default_factory=new_id,
        description="Stable UUID v4 string; assigned at registration time.",
    )
    descriptor: AISystemDescriptor = Field(
        description="Operator-supplied use-case attributes."
    )
    classification: AISystemClassification = Field(
        description=(
            "Result of running the classifier over the descriptor. "
            "Re-classify + persist via `evidentia ai-gov update` "
            "when the descriptor changes."
        ),
    )
    provider: NonBlankStr = Field(
        max_length=256,
        description=(
            "Who built or supplies the AI system (vendor name, "
            "in-house team name, or 'self-built')."
        ),
    )
    owner: NonBlankStr = Field(
        max_length=256,
        description="Responsible person or team within operator org.",
    )
    deployment_status: DeploymentStatus = Field(
        default=DeploymentStatus.PROPOSED,
        description="Where in the lifecycle this system sits.",
    )
    linked_controls: list[str] = Field(
        default_factory=list,
        description=(
            "Catalog control IDs (e.g., 'AIA.Art.9', 'GOVERN-1.1') "
            "the operator considers applicable to this system. "
            "Free-form; not validated against catalog content here."
        ),
    )
    last_assessed_at: datetime | None = Field(
        default=None,
        description=(
            "When the operator last reviewed the descriptor + "
            "classification against the live system. Null on "
            "initial registration; bump on each review."
        ),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        description="Registration timestamp; never mutated.",
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        description="Last persistence timestamp; bumped on save.",
    )

    # ── Federal expansion (v0.9.6 P3) ──────────────────────────────
    # All four fields Optional → backward-compat with v0.9.3 – v0.9.5
    # entries (deserialize as ``None`` for federal-tier fields).
    # Together they align Evidentia's AI inventory with OMB M-24-10
    # §5(a) inventory requirements + FedRAMP / NIST SP 800-37 RMF
    # cross-referencing.
    fips_199_categorization: FIPS199Categorization | None = Field(
        default=None,
        description=(
            "FIPS 199 impact categorization (C / I / A → high-water-"
            "mark overall) per NIST SP 800-60 worked-examples mapping. "
            "Required for federal systems; optional elsewhere."
        ),
    )
    ato_reference: ATOReference | None = Field(
        default=None,
        description=(
            "Reference to the parent federal information system's "
            "Authorization to Operate decision per NIST SP 800-37 "
            "Rev 2. Operators with cATO / ongoing-auth postures leave "
            "expiry_date as None."
        ),
    )
    ssp_reference: str | None = Field(
        default=None,
        max_length=2048,
        description=(
            "URI / handle pointing at the System Security Plan "
            "document. Format is operator-defined (eMASS link, "
            "internal docstore handle, etc.); Evidentia does NOT "
            "resolve or fetch it."
        ),
    )
    omb_impact: OMBImpactCategory | None = Field(
        default=None,
        description=(
            "DEPRECATED (v0.10.12): legacy OMB M-24-10 §5(b) impact "
            "category (rights / safety / both / neither). M-24-10 was "
            "rescinded 2025-04-03 by M-25-21 — use ``omb_high_impact``. "
            "Retained so persisted M-24-10 inventories keep loading; "
            "map forward with "
            "``omb_m_25_21.crosswalk_from_legacy``."
        ),
    )
    omb_high_impact: OMBHighImpactAssessment | None = Field(
        default=None,
        description=(
            "OMB M-25-21 high-impact AI assessment (determination + "
            "consequence bases). Supersedes ``omb_impact`` after the "
            "M-24-10 rescission. Optional → backward-compat with "
            "entries that pre-date the M-25-21 migration. Operators "
            "determine via their Chief AI Officer review path."
        ),
    )
