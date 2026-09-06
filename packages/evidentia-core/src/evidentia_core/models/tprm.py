"""Third-Party Risk Management (TPRM) models.

Introduced in v0.7.9 P0.1 per `docs/releases/plans/v0.7.9-plan.md`. The TPRM module
brings Evidentia into the regulated financial-services compliance
domain by providing first-class vendor-inventory, fourth-party-
disclosure, and Sigstore-signed-evidence-reference primitives.

The taxonomy aligns to two regulatory substrates:

- **FFIEC Vendor Management** (per the FFIEC IT Examination Handbook
  Outsourcing booklet): criticality-tier model + due-diligence-cadence
  expectations. Critical/high vendors receive annual review;
  medium = biennial; low = triennial. Captured via
  :meth:`Vendor.compute_next_review_due`.

- **OCC Bulletin 2013-29 + FRB SR 13-19** (Third-Party Relationships /
  Vendor Risk Management): the regulatory-classification taxonomy
  (custody, clearing, model, data_processor, critical_third_party)
  surfaces enforcement-relevant vendor flags.

A vendor's `regulatory_classification: list[Literal['model']]` flag is
the cross-link to the v0.7.9 P0.6 Model Risk Management module
(`evidentia model-risk`) — see SR 26-02 + OCC 2026-13a (April 2026
active model-risk guidance, superseding SR 11-7 + OCC 2011-12, with
explicit generative-AI/agentic-AI exclusion noted in
`docs/releases/plans/v0.7.9-plan.md` §1).

ID convention: UUID v4 via `new_id()` to match the rest of the model
layer (gaps, evidence, findings, risks). The v0.7.9-plan §P0.1 spec
table proposed ULID; the model-layer convention won out for
consistency. Audit-loop sequence ordering uses ULID elsewhere
(`evidentia_core.audit.logger`) where time-orderability matters; the
TPRM vendor inventory does not require time-ordered IDs since each
vendor record carries its own `created_at` + `updated_at` timestamps.
"""

from __future__ import annotations

import calendar
from datetime import date, datetime
from enum import Enum

from pydantic import ConfigDict, Field, model_validator

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class VendorType(str, Enum):
    """Vendor taxonomy aligned to FFIEC + NIST 800-161 SCRM categories."""

    SAAS = "saas"
    """Hosted software-as-a-service (e.g., Salesforce, Snowflake, GitHub)."""

    SUBSERVICE_ORG = "subservice_org"
    """Subservice organization in the SOC 2 Type II sense — the vendor
    performs services that affect the user entity's controls. The
    user entity's auditor includes the subservice org's controls in
    the assessment scope (carve-in) or expects a separate SOC 2 from
    the vendor (carve-out)."""

    CONTRACTOR = "contractor"
    """Independent contractor or staffing agency providing personnel."""

    DATA_PROCESSOR = "data_processor"
    """GDPR Article 28 data processor — handles personal data on behalf
    of the controller (the user entity). Triggers DPA (data-processing
    agreement) requirements + transfer-impact-assessment scrutiny."""

    CLOUD_PROVIDER = "cloud_provider"
    """Hyperscaler / IaaS / PaaS infrastructure provider (AWS, Azure,
    GCP, Oracle Cloud, IBM Cloud). Often a 4th-party-disclosure
    parent for SAAS vendors."""

    OPEN_SOURCE = "open_source"
    """Open-source project consumed as a software dependency. Surfaced
    as a vendor for SBOM-aware concentration risk + supply-chain
    governance (SR 26-02 §V vendor-model expectations, NIST 800-161
    SCRM Practices)."""


class CriticalityTier(str, Enum):
    """FFIEC Vendor Management criticality tier.

    Drives the due-diligence-review cadence enforced by
    :meth:`Vendor.compute_next_review_due`:

    - ``critical`` → annual (12 months)
    - ``high`` → annual (12 months)
    - ``medium`` → biennial (24 months)
    - ``low`` → triennial (36 months)

    Operators may override by setting ``next_review_due`` directly.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RegulatoryClassification(str, Enum):
    """Regulatory flags that change a vendor's compliance treatment.

    Multiple classifications may apply (e.g., a stablecoin custody
    vendor that also runs an internal pricing model is both
    ``custody`` AND ``model``). Stored as a ``list`` on the vendor.
    """

    CUSTODY = "custody"
    """Vendor holds customer assets on behalf of the user entity.
    Triggers SEC Rule 17f-7 / Custody Rule scrutiny + SR 13-19 ‑
    enhanced due diligence."""

    CLEARING = "clearing"
    """Vendor clears or settles transactions. CFTC / SEC clearing-
    member oversight applies; concentration-risk thresholds in
    `evidentia tprm concentration-report` flag clearing-vendor
    over-reliance."""

    MODEL = "model"
    """Vendor supplies a model under SR 26-02 / OCC Bulletin 2026-13a
    (April 2026 active model-risk guidance — supersedes SR 11-7 /
    OCC 2011-12). Cross-links to the v0.7.9 P0.6 Model Risk
    Management module (`evidentia model-risk`). Note: the 2026
    guidance EXPLICITLY EXCLUDES generative + agentic AI from scope
    — see `docs/releases/plans/v0.7.9-plan.md` §1."""

    DATA_PROCESSOR = "data_processor"
    """GDPR Article 28 processor flag. Distinct from
    :attr:`VendorType.DATA_PROCESSOR` because a vendor may be
    classified as a processor for some data flows but not others
    — the regulatory flag captures the legal status, the type
    captures the business relationship."""

    CRITICAL_THIRD_PARTY = "critical_third_party"
    """OCC Bulletin 2013-29 / FRB SR 13-19 critical third-party
    designation — outage / failure would materially impact the
    user entity's safety + soundness. UK FCA also maintains a
    Critical Third Parties (CTP) regime under FSMA 2023; vendors
    carrying this flag receive enhanced ongoing monitoring."""


class FourthParty(EvidentiaModel):
    """Disclosed sub-processor or sub-service organization.

    Surfaced separately from the parent vendor so concentration-risk
    reporting (v0.7.9 P0.3) can roll up exposure across the 4th-party
    layer — e.g., to detect that 8 of your 10 ostensibly-independent
    SaaS vendors all run on the same hyperscaler region.
    """

    name: str = Field(description="Fourth-party legal name (e.g., 'Amazon Web Services').")
    type: VendorType = Field(description="Same taxonomy as the parent vendor's `type` field.")
    relationship: str = Field(
        description=(
            "Free-text description of the 4th-party relationship — "
            "e.g., 'underlying IaaS for vendor SaaS', "
            "'KYC/AML data provider', 'authentication identity provider'."
        ),
        max_length=512,
    )
    disclosed_at: date | None = Field(
        default=None,
        description=(
            "Date the parent vendor disclosed this 4th-party. Nullable "
            "for legacy entries imported without a disclosure date."
        ),
    )


class EvidenceRef(EvidentiaModel):
    """Reference to a Sigstore-signed evidence artifact attached to a vendor.

    Two-modes:

    1. **Internal reference** (preferred): set ``artifact_id`` to point
       at an existing :class:`evidentia_core.models.evidence.EvidenceArtifact`
       in the evidence-store. Sigstore signing is whatever the parent
       artifact already carries.

    2. **External reference** (fallback): set ``file_path`` + ``sha256``
       (+ ``sigstore_bundle_path`` if signed) for evidence stored
       outside the evidence-store. Useful for ad-hoc vendor uploads
       (SOC 2 reports, ISO 27001 certificates, completed SIG/CAIQ
       questionnaires) that haven't been formally ingested.

    At least one of (``artifact_id``, ``file_path``) must be set;
    enforced in :meth:`model_validator` below and mirrored into the
    published JSON Schema via ``json_schema_extra``.
    """

    model_config = ConfigDict(
        # JSON-Schema mirror of ``_enforce_reference_invariants``
        # below, so the published OpenAPI contract expresses the
        # two-mode rule instead of 422-ing schema-valid bodies
        # (2026-07-06 schemathesis RejectedPositiveData finding on
        # POST /api/model-risk/models). Each branch requires the field
        # present AND non-null, matching the validator's ``is None``
        # checks. Keep both in sync.
        json_schema_extra={
            "anyOf": [
                {
                    "required": ["artifact_id"],
                    "properties": {"artifact_id": {"type": "string"}},
                },
                {
                    "required": ["file_path"],
                    "properties": {"file_path": {"type": "string"}},
                },
            ],
            "if": {
                "required": ["file_path"],
                "properties": {"file_path": {"type": "string"}},
            },
            "then": {
                "required": ["sha256"],
                "properties": {"sha256": {"type": "string"}},
            },
        }
    )

    title: str = Field(
        description=(
            "Human-readable label — e.g., 'SOC 2 Type II Report — "
            "FY2025', 'ISO 27001 Cert (expires 2027-03)', 'Completed "
            "SIG-Lite questionnaire 2025-Q4'."
        )
    )
    artifact_id: str | None = Field(
        default=None,
        description=(
            "If set, points at an EvidenceArtifact ID in the evidence-"
            "store. Sigstore signing inherited from the parent artifact."
        ),
    )
    file_path: str | None = Field(
        default=None,
        description=("If set, path to an external evidence file. Combined with ``sha256`` for tamper detection."),
    )
    sha256: str | None = Field(
        default=None,
        description=("SHA-256 digest of the referenced file (lowercase hex). Required when ``file_path`` is set."),
        pattern=r"^[a-f0-9]{64}$",
    )
    sigstore_bundle_path: str | None = Field(
        default=None,
        description=(
            "Path to a Sigstore .sigstore.json bundle for this evidence "
            "(if independently signed). Optional — internal artifacts "
            "carry signing metadata themselves; external uploads may or "
            "may not be signed."
        ),
    )
    collected_at: datetime = Field(
        default_factory=utc_now,
        description="When this evidence reference was attached to the vendor.",
    )
    notes: str | None = Field(
        default=None,
        max_length=1024,
        description=(
            "Free-text rationale or context — e.g., the audit period "
            "the report covers, the auditor that issued it, residual-"
            "risk-impact notes."
        ),
    )

    @model_validator(mode="after")
    def _enforce_reference_invariants(self) -> EvidenceRef:
        """Enforce the two-mode contract documented in the class docstring.

        Catches the "neither artifact_id nor file_path" + "file_path
        without sha256" cases at construction time. Closes the v0.7.9
        Continuous-review H-1 finding (the docstring claimed this
        validator existed but the implementation was missing).
        """
        if self.artifact_id is None and self.file_path is None:
            raise ValueError(
                "EvidenceRef requires at least one of `artifact_id` "
                "(internal-store reference) or `file_path` (external "
                "evidence file). Both are None."
            )
        if self.file_path is not None and self.sha256 is None:
            raise ValueError("EvidenceRef.file_path requires a paired `sha256` digest for tamper detection.")
        return self


class Vendor(EvidentiaModel):
    """Third-party vendor inventory record.

    The atomic unit of the v0.7.9 TPRM module. Every other TPRM
    capability (DD-questionnaire generation, concentration reporting,
    vendor-risk collectors, OSCAL TPRM emit) operates on collections
    of these records.

    See `docs/releases/plans/v0.7.9-plan.md` §P0.1 for the canonical spec.
    """

    id: str = Field(
        default_factory=new_id,
        description="Unique identifier (UUID v4 per the model-layer convention).",
    )
    name: str = Field(
        description="Vendor legal name.",
    )
    type: VendorType = Field(
        description="Vendor taxonomy per FFIEC + NIST 800-161 categories.",
    )
    criticality_tier: CriticalityTier = Field(
        description=(
            "FFIEC Vendor Management criticality tier. Drives the "
            "due-diligence-review cadence (annual / biennial / triennial)."
        ),
    )
    relationship_owner: str = Field(
        description=(
            "Internal owner — typically an email address or LDAP "
            "identifier. The relationship-owner is responsible for "
            "ongoing monitoring + the next due-diligence review."
        ),
    )
    region: str | None = Field(
        default=None,
        description=(
            "Geographic region the vendor operates in (e.g., "
            "``us-east-1``, ``EU``, ``US-West``, ``APAC``). Free-text "
            "because region semantics vary by vendor type — AWS-style "
            "region IDs for cloud providers, ISO-3166 country codes for "
            "data processors, business-region designations for "
            "consultancies. Drives the v0.7.9 P0.3 concentration-risk "
            "reporting `--by region` aggregation. Nullable for legacy "
            "imports + vendors whose region is genuinely indeterminate."
        ),
        max_length=128,
    )
    contract_start_date: date = Field(
        description="Contract effective date.",
    )
    contract_end_date: date | None = Field(
        default=None,
        description=(
            "Contract end date. Null for indefinite / month-to-month "
            "engagements; expiry warnings ride on this field when set."
        ),
    )
    last_due_diligence_review: date | None = Field(
        default=None,
        description=(
            "Date of the most recent completed due-diligence review. "
            "Drives ``next_review_due`` via "
            ":meth:`compute_next_review_due`."
        ),
    )
    next_review_due: date | None = Field(
        default=None,
        description=(
            "Date the next DD review is due. Computed from "
            "``last_due_diligence_review`` + the criticality cadence "
            "via :meth:`compute_next_review_due` — but operators can "
            "override directly (e.g., per a regulator request)."
        ),
    )
    regulatory_classification: list[RegulatoryClassification] = Field(
        default_factory=list,
        description=(
            "Zero or more regulatory flags. Multiple may apply — e.g., "
            "a stablecoin custody vendor that runs an internal pricing "
            "model is both ``custody`` AND ``model``."
        ),
    )
    fourth_parties: list[FourthParty] = Field(
        default_factory=list,
        description=(
            "Disclosed sub-processors / sub-service organizations. "
            "Drives 4th-party concentration-risk roll-ups in v0.7.9 "
            "P0.3 reporting."
        ),
    )
    residual_risk_score: int = Field(
        default=0,
        ge=0,
        le=25,
        description=(
            "Residual risk score on a 1-25 inherent × control "
            "matrix (5 × 5). 0 = unscored. Operators set this from "
            "the DD review outcome."
        ),
    )
    notes: str | None = Field(
        default=None,
        max_length=4096,
        description="Free-text vendor notes — relationship history, escalations, etc.",
    )
    evidence_refs: list[EvidenceRef] = Field(
        default_factory=list,
        description=(
            "Sigstore-signed evidence references attached to this "
            "vendor — SOC 2 reports, ISO certs, completed "
            "questionnaires, etc."
        ),
    )

    # Stamping
    created_at: datetime = Field(
        default_factory=utc_now,
        description="When the vendor record was created.",
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        description="When the vendor record was last modified.",
    )
    evidentia_version: str = Field(
        default_factory=current_version,
        description="evidentia-core version that produced this record.",
    )

    def compute_next_review_due(self) -> date | None:
        """Compute the next due-diligence review date from criticality.

        Returns ``None`` if ``last_due_diligence_review`` is unset (no
        anchor to compute from). Otherwise returns the anchor + the
        criticality-tier cadence:

        - ``critical`` / ``high`` → 12 months
        - ``medium`` → 24 months
        - ``low`` → 36 months

        Month arithmetic is calendar-aware: rolls year correctly,
        clamps day to the last valid day of the target month
        (e.g., 2025-01-31 + 1 month → 2025-02-28, not an invalid date).

        Does NOT mutate ``self.next_review_due``; callers should
        assign the result if they want to persist it. Pure-function
        contract makes this safe for both online + batch use.
        """
        if self.last_due_diligence_review is None:
            return None
        # ``self.criticality_tier`` may have been serialized to a string
        # (per the EvidentiaModel ``use_enum_values=True`` config); accept
        # both the enum and the string form.
        tier_value = (
            self.criticality_tier.value if isinstance(self.criticality_tier, CriticalityTier) else self.criticality_tier
        )
        cadence_months = {
            CriticalityTier.CRITICAL.value: 12,
            CriticalityTier.HIGH.value: 12,
            CriticalityTier.MEDIUM.value: 24,
            CriticalityTier.LOW.value: 36,
        }[tier_value]
        base = self.last_due_diligence_review
        # Add ``cadence_months`` to the anchor date with proper year-roll
        # + last-day clamping. Stdlib-only; no dateutil dep.
        new_month = base.month + cadence_months
        new_year = base.year + (new_month - 1) // 12
        new_month = ((new_month - 1) % 12) + 1
        last_day_of_target_month = calendar.monthrange(new_year, new_month)[1]
        new_day = min(base.day, last_day_of_target_month)
        return date(new_year, new_month, new_day)
