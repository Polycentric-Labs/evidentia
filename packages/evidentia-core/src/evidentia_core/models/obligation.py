"""Privacy obligation catalog models — GDPR, CCPA, state privacy laws.

Privacy laws don't slot cleanly into the ``ControlCatalog`` shape: their
requirements are obligations (subject rights, notification deadlines,
applicability thresholds) rather than implementable controls. This
module models the obligation shape directly so state-privacy tracking
and cross-jurisdiction analysis work without forcing statute text into
control-catalog structure.

v0.2.0 uses this for ~15 US state privacy laws + EU GDPR + UK DPA 2018
+ Canada PIPEDA + a few others.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, PrivateAttr

from evidentia_core.models.common import EvidentiaModel

# Subject-rights vocabulary. Matches the common GDPR/CCPA/state-law framing.
SubjectRight = Literal[
    "access",  # Right to know / right of access
    "delete",  # Right to erasure / deletion
    "correct",  # Right to correction / rectification
    "portability",  # Right to data portability
    "opt-out-sale",  # Right to opt out of sale
    "opt-out-sharing",  # Right to opt out of sharing (CPRA-style)
    "opt-out-profiling",  # Right to opt out of automated profiling / significant decisions
    "limit-sensitive",  # Right to limit use of sensitive data
    "appeal",  # Right to appeal a denial
    "restrict-processing",  # GDPR Art. 18
    "object",  # GDPR Art. 21 — right to object
    "non-discrimination",  # Right not to be discriminated against for exercising rights
]


class PrivacyObligation(EvidentiaModel):
    """A single obligation from a privacy law or regulation.

    One record per distinct obligation. A state privacy law typically
    decomposes into 15-25 obligations (applicability, subject rights,
    notice requirements, DPIA, contract terms, breach notification).
    """

    id: str = Field(
        description="Obligation ID, e.g. 'CCPA-1798.100' for the statute section or 'CCPA.ACCESS' for a topical key",
    )
    title: str = Field(description="Short obligation title")
    description: str = Field(description="Obligation text or summary")
    citation: str | None = Field(
        default=None,
        description="Statute / regulation citation, e.g. 'Cal. Civ. Code § 1798.100'",
    )
    category: str | None = Field(
        default=None,
        description="Obligation category, e.g. 'subject-rights', 'notice', "
        "'applicability', 'breach-notification', 'vendor-management'",
    )
    applies_to: list[str] = Field(
        default_factory=list,
        description="Scope — entity types this obligation applies to",
    )
    references: list[str] = Field(default_factory=list, description="External reference URLs")
    placeholder: bool = Field(
        default=False,
        description="True if the description is a placeholder (not yet authored)",
    )


class PrivacyRegime(EvidentiaModel):
    """Metadata about the overall privacy regime this catalog represents.

    Distinct from ObligationCatalog's document-level metadata — captures
    threshold rules and regime-wide flags that affect applicability,
    not individual obligations.
    """

    jurisdiction: str = Field(
        description="Jurisdiction, e.g. 'US-CA', 'EU', 'UK', 'US-VA'",
    )
    effective_date: str | None = Field(default=None, description="Date the regime took effect (ISO 8601)")
    amendments: list[str] = Field(
        default_factory=list,
        description="Amendment names/dates (e.g. ['CPRA 2023'])",
    )
    subject_rights: list[SubjectRight] = Field(
        default_factory=list,
        description="Data-subject rights granted under this regime",
    )
    data_minimization_required: bool = Field(
        default=False,
        description="True if regime explicitly requires data minimization",
    )
    dpia_required: bool = Field(
        default=False,
        description="True if DPIAs (or equivalent risk assessments) are required",
    )
    breach_notification_threshold_days: int | None = Field(
        default=None,
        description="Days to notify regulators of a breach (None = no numeric threshold)",
    )
    breach_notification_to_subjects: bool = Field(
        default=False,
        description="True if individuals must also be notified of breaches",
    )
    private_right_of_action: bool = Field(
        default=False,
        description="True if individuals can sue for violations",
    )
    cure_period_days: int | None = Field(
        default=None,
        description="Days to cure violations before enforcement (None = no cure period)",
    )
    applicability_revenue_threshold_usd: int | None = Field(
        default=None,
        description="Annual revenue threshold in USD (approx) for applicability",
    )
    applicability_record_threshold: int | None = Field(
        default=None,
        description="Number of consumer records/year threshold for applicability",
    )
    applicability_revenue_share_from_data: float | None = Field(
        default=None,
        description="% of revenue from selling/sharing data that triggers applicability (0.5 = 50%)",
    )
    regulator: str | None = Field(
        default=None,
        description="Enforcement body name, e.g. 'California Privacy Protection Agency'",
    )
    notes: str | None = Field(default=None)


class ObligationCatalog(EvidentiaModel):
    """A catalog of privacy obligations under a specific regime."""

    framework_id: str = Field(description="Canonical ID, e.g. 'us-ca-ccpa-cpra'")
    framework_name: str = Field(description="Human-readable name")
    version: str = Field(description="Statute version or as-of date")
    source: str = Field(description="Authoritative source URL")
    category: Literal["obligation"] = Field(default="obligation")
    regime: PrivacyRegime = Field(description="Regime-wide metadata")
    obligations: list[PrivacyObligation] = Field(description="All obligations")
    tier: str | None = Field(default=None)
    license_required: bool = Field(default=False)
    license_terms: str | None = Field(default=None)
    license_url: str | None = Field(default=None)
    placeholder: bool = Field(default=False)

    _index: dict[str, PrivacyObligation] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Build obligation index."""
        self._index = {o.id.upper(): o for o in self.obligations}

    def get_obligation(self, obligation_id: str) -> PrivacyObligation | None:
        """Look up an obligation by ID (case-insensitive)."""
        return self._index.get(obligation_id.strip().upper())

    def by_category(self, category: str) -> list[PrivacyObligation]:
        """All obligations in a topical category."""
        return [o for o in self.obligations if o.category == category]

    @property
    def obligation_count(self) -> int:
        return len(self._index)
