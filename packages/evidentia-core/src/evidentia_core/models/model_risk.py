"""Model Risk Management (MRM) models.

Introduced in v0.7.10 P0.6 per `docs/v0.7.10-plan.md`. The model-risk
module brings Evidentia into the regulated financial-services
model-risk domain by providing first-class model-inventory,
validation-finding, and AI-feature-linkage primitives that satisfy
SR 11-7 / OCC Bulletin 2011-12 (historical) and SR 26-02 / OCC
Bulletin 2026-13a (April 2026 active guidance).

The taxonomy aligns to the SR 11-7 framework structure that carries
forward into the 2026 guidance:

- **§III.A Conceptual Soundness** — `purpose` + `methodology` +
  `inputs` + `outputs` capture the model's design rationale.
- **§III.B Ongoing Monitoring** — `last_validation_date` +
  `next_validation_due` + `validation_findings` track the
  continuous-monitoring cadence and outcomes.
- **§III.C Outcomes Analysis** — operator-supplied via the
  `evidentia model-risk doc generate` Markdown / XLSX scaffold.
- **§III.D Validation** — independent validation captured via the
  `evidentia model-risk validation-report` scaffold.
- **§V Vendor Models** — when `vendor_or_internal=vendor`,
  `vendor_id` cross-links to the v0.7.9 TPRM `Vendor.id` so the
  model's vendor-risk posture flows from the same inventory.

The 2026 guidance explicit-exclusion of generative + agentic AI
from scope is the strategic positioning hook for Evidentia's
`GenerationContext` provenance chain (model + temperature +
prompt_hash + run_id + evidentia_version) — every `evidentia risk
generate` invocation can carry a `model_inventory_ref` pointing
at a ModelInventory entry, producing SR-replacement-grade audit
evidence for LLM-driven controls. See `docs/positioning-and-value.md`
§4.6 + §7 unclaimed gap #8.

ID convention: UUID v4 via `new_id()` to match the rest of the
model layer (gaps, evidence, findings, risks, vendors). The
v0.7.9-plan §P0.6.1 spec table proposed ULID; the model-layer
convention won out for consistency with `Vendor.id`. Each
ModelInventory record carries its own `created_at` + `updated_at`
timestamps so time-orderability isn't needed at the ID layer.
"""

from __future__ import annotations

import calendar
from datetime import date, datetime
from enum import Enum

from pydantic import Field, model_validator

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)
from evidentia_core.models.tprm import EvidenceRef

# ── Enums ──────────────────────────────────────────────────────────


class Methodology(str, Enum):
    """Model methodology classification per SR 11-7 §III.A.

    The classification drives which validation requirements apply.
    Statistical + ML models (esp. high-tier ones) require formal
    independent validation; rules-based + expert-judgment models
    follow a lighter outcomes-analysis cadence; LLM models are in
    the SR 26-02 / OCC 2026-13a explicit-exclusion zone and rely
    on Evidentia's GenerationContext provenance chain for
    SR-replacement-grade evidence.
    """

    STATISTICAL = "statistical"
    ML = "ml"
    RULES_BASED = "rules_based"
    LLM = "llm"
    EXPERT_JUDGMENT = "expert_judgment"
    HYBRID = "hybrid"


class Provenance(str, Enum):
    """Model provenance — who built it.

    Internal models follow SR 11-7 §III; vendor models additionally
    follow §V (vendor-risk overlay). Vendor-provenance models MUST
    set `vendor_id` to cross-link to the v0.7.9 TPRM Vendor record.
    """

    INTERNAL = "internal"
    VENDOR = "vendor"


class Tier(str, Enum):
    """SR 11-7 model criticality tier.

    Drives validation-cadence: Tier 1 = annual; Tier 2 = biennial;
    Tier 3 = triennial. Tier 1 models are high-impact + complex
    (e.g., capital-allocation, credit-decision, fair-lending);
    Tier 2 are moderate-impact (operational risk, marketing
    optimization); Tier 3 are low-impact (internal reporting,
    forecasting tools).

    The tier value also drives the documentation-detail level
    expected in the SR 11-7 §III.A "Conceptual Soundness"
    write-up — Tier 1 needs full theoretical justification +
    comparison to alternatives; Tier 3 may be a short paragraph.
    """

    TIER_1 = "tier_1"
    TIER_2 = "tier_2"
    TIER_3 = "tier_3"


class ValidationStatus(str, Enum):
    """Validation finding status."""

    OPEN = "open"
    REMEDIATED = "remediated"
    ACCEPTED = "accepted"
    DEFERRED = "deferred"


class ValidationSeverity(str, Enum):
    """Validation finding severity per SR 11-7 §III.D.

    HIGH findings should block the model from production use until
    remediated; MEDIUM findings warrant operator review +
    documented action plan; LOW findings are observations for the
    operator's awareness.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ── Sub-models ─────────────────────────────────────────────────────


class ModelInput(EvidentiaModel):
    """Documents one data source feeding the model.

    Per SR 11-7 §III.A.2 (Theory + Design + Data), every model
    invocation must trace back to its inputs. ModelInput captures
    the source-system reference + transformation lineage so the
    SR-11-7 §III.A.3 "implementation" write-up can auto-populate
    from the inventory rather than being authored from scratch.
    """

    name: str = Field(
        description="Human-readable input name (e.g., 'FICO score', 'transaction history')."
    )
    source_system: str = Field(
        description=(
            "Upstream source system identifier (e.g., 'snowflake-prod-warehouse', "
            "'experian-api', 'aws-s3-bucket-fraud-features')."
        )
    )
    transformation: str | None = Field(
        default=None,
        description=(
            "Description of any pre-processing applied (e.g., 'log-normalized', "
            "'one-hot encoded', 'PCA-reduced'). None = raw input."
        ),
    )
    data_classification: str | None = Field(
        default=None,
        description=(
            "Data sensitivity classification (e.g., 'PII', 'public', "
            "'confidential'). Drives access controls + retention."
        ),
    )
    refresh_cadence: str | None = Field(
        default=None,
        description=(
            "How often the input is refreshed (e.g., 'daily', 'real-time', "
            "'monthly batch'). Drives ongoing-monitoring expectations."
        ),
    )


class ModelOutput(EvidentiaModel):
    """Documents one output / decision the model produces.

    Per SR 11-7 §III.B.1 (Outcomes Analysis), the operator must
    track which decisions the model influences so back-testing
    + benchmarking can target them. ModelOutput captures the
    downstream consumer + decision type.
    """

    name: str = Field(
        description="Output / decision name (e.g., 'loan approval probability', 'fraud score')."
    )
    decision_type: str = Field(
        description=(
            "Type of decision the output drives (e.g., 'binary classification', "
            "'risk score 0-1', 'multi-class label', 'continuous prediction')."
        )
    )
    downstream_consumers: list[str] = Field(
        default_factory=list,
        description=(
            "List of downstream systems / business processes consuming this "
            "output (e.g., ['loan-origination-system', 'fraud-investigations-queue'])."
        ),
    )


class ValidationFinding(EvidentiaModel):
    """One finding from independent model validation.

    Per SR 11-7 §III.D, validation must be independent of model
    development. Findings document where the model fell short of
    expectations + what remediation is planned. Maps to OSCAL
    AssessmentResults `finding` shape for the
    `evidentia oscal export --model-risk` path (planned for
    v0.7.10 P0.6.5+).
    """

    id: str = Field(default_factory=new_id)
    title: str = Field(description="Short summary of the finding.")
    description: str = Field(
        description="Full finding description with reproduction steps."
    )
    severity: ValidationSeverity
    status: ValidationStatus = Field(default=ValidationStatus.OPEN)
    detected_at: date = Field(
        description="Date the finding was first detected during validation."
    )
    remediation_plan: str | None = Field(
        default=None,
        description=(
            "Operator's documented remediation plan. None = no plan yet "
            "(typically for newly-detected findings)."
        ),
    )
    remediation_due_date: date | None = Field(
        default=None,
        description="Target date for remediation completion.",
    )
    remediated_at: date | None = Field(
        default=None,
        description=(
            "Actual remediation completion date. None unless status is "
            "REMEDIATED."
        ),
    )


# ── Top-level: ModelInventory ──────────────────────────────────────


class ModelInventory(EvidentiaModel):
    """The Model Risk Management inventory record.

    One ModelInventory entry per managed model, satisfying SR 11-7 /
    SR 26-02 §III.A "Conceptual Soundness" inventory expectations.
    Cross-links to TPRM via `vendor_id` (when sourced from a
    third-party vendor) and to the AI-features path via
    `RiskStatement.model_inventory_ref` (introduced in v0.7.10 P0.6.4).
    """

    id: str = Field(default_factory=new_id)
    name: str = Field(
        description="Human-readable model name (e.g., 'FICO-style credit scorer v3', 'Fraud-detector LLM-v0.4')."
    )
    purpose: str = Field(
        description=(
            "Business purpose per SR 11-7 §III.A 'Conceptual Soundness'. "
            "Should describe what decisions the model influences and why "
            "it was built (e.g., 'Score consumer credit applications "
            "using behavioural + bureau features to support the loan-"
            "origination decision flow')."
        )
    )
    methodology: Methodology
    vendor_or_internal: Provenance
    vendor_id: str | None = Field(
        default=None,
        description=(
            "Cross-link to the v0.7.9 TPRM `Vendor.id` when "
            "`vendor_or_internal=vendor`. MUST be set for vendor-"
            "provenance models so SR 11-7 §V (vendor-risk overlay) "
            "applies. Validated via `@field_validator` per the "
            "two-mode contract."
        ),
    )
    tier: Tier
    owner: str = Field(
        description="Internal model owner (email or LDAP identifier)."
    )
    inputs: list[ModelInput] = Field(
        default_factory=list,
        description="Data sources feeding the model (SR 11-7 §III.A.2).",
    )
    outputs: list[ModelOutput] = Field(
        default_factory=list,
        description="Decisions the model produces (SR 11-7 §III.B.1).",
    )
    last_validation_date: date | None = Field(
        default=None,
        description="Date the model was most recently validated.",
    )
    validation_findings: list[ValidationFinding] = Field(
        default_factory=list,
        description=(
            "Open + closed findings from validation activities. "
            "Operator reviews open findings during validation-due "
            "cadence + before promoting model versions."
        ),
    )
    next_validation_due: date | None = Field(
        default=None,
        description=(
            "Auto-computed from `tier` + `last_validation_date` via "
            ":meth:`compute_next_validation_due`. Operators can also "
            "override via the CLI `--next-validation-due` flag."
        ),
    )
    retirement_plan: str | None = Field(
        default=None,
        description=(
            "Per SR 11-7 §III.C ongoing-monitoring expectations, models "
            "have a documented retirement / replacement plan. None = "
            "indefinite use; not best practice."
        ),
    )
    notes: str | None = Field(
        default=None,
        description="Free-text notes (operator observations, history, etc.).",
    )
    evidence_refs: list[EvidenceRef] = Field(
        default_factory=list,
        description=(
            "Sigstore-signed evidence chain (validation reports, "
            "back-test results, sensitivity-analysis outputs). Reuses "
            "the v0.7.9 TPRM EvidenceRef model — same artifact_id-or-"
            "file_path two-mode contract."
        ),
    )

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    evidentia_version: str = Field(default_factory=current_version)

    @model_validator(mode="after")
    def _enforce_vendor_id_two_mode(self) -> ModelInventory:
        """Vendor-provenance models MUST carry a vendor_id; internal-
        provenance models MUST NOT.

        Uses `mode="after"` (not `field_validator`) so the validator
        fires even when `vendor_id` defaults to None — a vendor-
        provenance model without `vendor_id=...` would otherwise
        silently violate the cross-link contract.
        """
        if (
            self.vendor_or_internal == Provenance.VENDOR
            and not self.vendor_id
        ):
            raise ValueError(
                "vendor-provenance models must set `vendor_id` to "
                "cross-link the TPRM Vendor inventory record"
            )
        if (
            self.vendor_or_internal == Provenance.INTERNAL
            and self.vendor_id
        ):
            raise ValueError(
                "internal-provenance models must not set `vendor_id` "
                "(it has no meaning for internal models)"
            )
        return self

    def compute_next_validation_due(self) -> date | None:
        """Auto-compute the next-validation-due date from tier + last_validation_date.

        Cadence per SR 11-7 §III.D + industry practice:

        - Tier 1: 12 months (annual)
        - Tier 2: 24 months (biennial)
        - Tier 3: 36 months (triennial)

        Returns None if `last_validation_date` is unset (cadence
        only computable after the first validation has occurred).

        Date arithmetic is calendar-aware via stdlib :mod:`calendar`:
        a Tier 1 model last-validated on Feb 29 of a leap year +
        12 months = Feb 28 of the following non-leap year (last-day
        clamp). Same year-roll handling pattern as
        :meth:`evidentia_core.models.tprm.Vendor.compute_next_review_due`.
        """
        if self.last_validation_date is None:
            return None
        months_by_tier = {
            Tier.TIER_1: 12,
            Tier.TIER_2: 24,
            Tier.TIER_3: 36,
        }
        months = months_by_tier[self.tier]
        anchor = self.last_validation_date
        new_year = anchor.year + (months // 12)
        # Tier values are all multiples of 12 months — no month
        # rollover needed in this implementation. Future-proof the
        # last-day clamp anyway in case sub-annual cadences are
        # added (e.g., a Tier 0 = 6-month for high-stakes models).
        new_month = anchor.month
        last_day = calendar.monthrange(new_year, new_month)[1]
        new_day = min(anchor.day, last_day)
        return date(new_year, new_month, new_day)
