"""FedRAMP CR26 Key Security Indicator (KSI) status models.

Operator-authored input for `evidentia conmon ksi`, which emits the
``keySecurityIndicators`` block of a CR26 **Security Decision Record**
(SDR) per ``fedramp-security-decision-record-schema-2026-06-24.json``
(vendored in :mod:`evidentia_core.fedramp.schemas` — see the UPSTREAM.json
provenance pins there).

Obligation anchor (FedRAMP Consolidated Rules for 2026, ``FedRAMP/rules``):

- **SDR-CSO-FRR** (MUST): the SDR is supplied in both human-readable and
  JSON forms, per the published schema, and "MUST include at least" an
  explanation, verification, validation, and related statements *for
  each applicable FedRAMP rule*. v0.12 added the ``requirements`` block
  below so the emitted ``fedRampRequirements`` array can carry them;
  through v0.11.x it was emitted empty, which satisfied the schema but
  not this rule.
- **SDR-CSX-KSI** (MUST, 20x): per-KSI high-level summaries — measures
  and objectives, the cycle for persistently implemented measures,
  verification, automation-accuracy verification, and validation.
- **SDR-CSO-MTD** (MUST): document metadata — version, date/time of last
  update, and source of update.

The models carry the operator's own statements; Evidentia assembles,
schema-validates, and reports KSI catalog coverage. It never invents
compliance prose.
"""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel

#: SDR evidence-type vocabulary (schema `$defs.evidence.evidenceType` enum).
KsiEvidenceType = Literal[
    "Log",
    "Report",
    "Screenshot",
    "Configuration",
    "Policy",
    "Procedure",
    "Audit Record",
]

#: SDR implementation-status vocabulary (schema `ksiImplementationStatus` enum).
KsiImplementationStatus = Literal[
    "Implemented",
    "Partially Implemented",
    "Not Implemented",
]


class KsiEvidenceItem(EvidentiaModel):
    """One piece of evidence backing a KSI (SDR ``$defs.evidence``)."""

    evidence_type: KsiEvidenceType = Field(
        description="Evidence type, from the SDR schema's evidenceType enum",
    )
    description: str = Field(
        description="Detailed description of the evidence",
    )
    location: str | None = Field(
        default=None,
        description="URI or file path to the evidence document",
    )
    text: str | None = Field(
        default=None,
        description="Evidence included as plain text (command output, log excerpt)",
    )
    last_updated: date | None = Field(
        default=None,
        description="Date the evidence was last updated",
    )


class KsiPersistenceCycle(EvidentiaModel):
    """CONMON cadence reference for a persistently implemented measure.

    SDR-CSX-KSI requires "the cycle for any measures that are implemented
    persistently". Referencing a cadence slug lets the emitter render the
    cycle statement (activity, frequency, last-completed / next-due when a
    ``--state-file`` is supplied) from the same CONMON calendar the rest of
    `evidentia conmon` runs on.
    """

    cadence_slug: str = Field(
        description="CONMON cadence slug (see `evidentia conmon list`)",
    )
    note: str | None = Field(
        default=None,
        description="Optional operator note appended to the rendered cycle statement",
    )


class KsiIndicatorEntry(EvidentiaModel):
    """Operator statements for a single Key Security Indicator."""

    status: KsiImplementationStatus | None = Field(
        default=None,
        description="KSI implementation status (optional in the SDR schema)",
    )
    implementation: list[str] = Field(
        min_length=1,
        description=(
            "Implementation statements (SDR-CSX-KSI measure summaries; "
            "Markdown allowed). At least one is required — an indicator "
            "entry with no implementation statement says nothing."
        ),
    )
    validation: list[str] = Field(
        default_factory=list,
        description="Validation statements (CSP-internal validation; Markdown allowed)",
    )
    assessment: list[str] = Field(
        default_factory=list,
        description="Assessment statements (independent assessor; Markdown allowed)",
    )
    tests: list[str] = Field(
        default_factory=list,
        description="Names of tests used to validate the KSI implementation",
    )
    evidence: list[KsiEvidenceItem] = Field(
        default_factory=list,
        description="Evidence items backing the KSI",
    )
    persistence_cycles: list[KsiPersistenceCycle] = Field(
        default_factory=list,
        description=(
            "CONMON cadences implementing this KSI persistently; rendered as cycle statements per SDR-CSX-KSI"
        ),
    )


#: SDR requirement-status vocabulary (schema `frrImplementationStatus` enum).
FrrImplementationStatus = Literal[
    "Implemented",
    "Partially Implemented",
    "Not Implemented",
]


class FrrRequirementEntry(EvidentiaModel):
    """Operator statements for a single provider-facing FedRAMP rule.

    Mirrors :class:`KsiIndicatorEntry` for the SDR's
    ``fedRampRequirements`` block (SDR-CSO-FRR). The schema item has no
    tests/evidence sub-structures, so neither does this entry.
    """

    status: FrrImplementationStatus | None = Field(
        default=None,
        description="Requirement implementation status (optional in the SDR schema)",
    )
    implementation: list[str] = Field(
        min_length=1,
        description=(
            "Implementation statements — how the rule is followed, or the "
            "reason and resulting customer risk for not following it "
            "(SDR-CSO-FRR; Markdown allowed). At least one is required — "
            "a requirement entry with no implementation statement says "
            "nothing."
        ),
    )
    validation: list[str] = Field(
        default_factory=list,
        description="Validation statements (CSP-internal; Markdown allowed)",
    )
    assessment: list[str] = Field(
        default_factory=list,
        description="Assessment statements (independent assessor; Markdown allowed)",
    )


class KsiStatusDocument(EvidentiaModel):
    """The operator's KSI status file (YAML) — input to `evidentia conmon ksi`."""

    certification_package_overview_uri: str = Field(
        description=("Full URI of the provider's Certification Package Overview document (SDR schema required field)"),
    )
    document_version: str = Field(
        description="SDR document version (SDR-CSO-MTD)",
    )
    source: str = Field(
        description="Source of this update — team, system, or person (SDR-CSO-MTD)",
    )
    indicators: dict[str, KsiIndicatorEntry] = Field(
        min_length=1,
        description=(
            "Per-KSI entries keyed by KSI indicator ID (e.g. 'KSI-CED-RAT'); "
            "IDs are checked against the bundled fedramp-ksi-2026 catalog"
        ),
    )
    requirements: dict[str, FrrRequirementEntry] = Field(
        default_factory=dict,
        description=(
            "Per-rule entries keyed by FedRAMP Requirement ID (e.g. "
            "'SDR-CSO-FRR'); IDs are checked against the bundled "
            "fedramp-frr-2026 catalog (provider-facing rules only). "
            "Optional so v0.11 status files keep loading, but SDR-CSO-FRR "
            "is a MUST — an SDR with an empty block is schema-valid and "
            "rule-incomplete; `conmon ksi` reports the coverage gap."
        ),
    )
