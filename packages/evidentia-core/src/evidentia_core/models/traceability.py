"""Control↔Threat traceability models — a signable mapping of security
controls to the threats they mitigate.

The matrix is emitted as a Sigstore-signable OSCAL **profile** (see
:mod:`evidentia_core.oscal.traceability_exporter`): the profile imports a
control catalog and adds a ``link rel="mitigates"`` + Evidentia-namespaced
properties to each control, pointing at integrity-hashed threat resources.

Representation decision (2026-06-17, multi-model labcoat): a static
control↔threat matrix is a profile, NOT Assessment Results (a semantic abuse)
and NOT the OSCAL ``mapping`` model (which is control↔control only). The
relationship vocabulary is a domain mitigation vocabulary, NOT NIST OLIR
(OLIR is concept-to-concept). v0.10.11 ships this signed-OSCAL slice; the MITRE
CTID Mappings-Explorer crosswalk ingest + the CycloneDX representation are v0.11.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel

#: Domain relationship vocabulary for a control→threat link. Deliberately NOT
#: the NIST OLIR concept-relationship set (supports / subset-of / …), which is
#: for control↔control / standard↔standard mappings, not control↔threat.
ThreatRelationship = Literal[
    "mitigates", "partially-mitigates", "compensating", "detects"
]

#: Source taxonomy of a threat identifier.
ThreatFramework = Literal["mitre-attack", "cwe", "capec"]

#: Coverage strength of a control over a threat.
CoverageLevel = Literal["full", "partial", "compensating"]


class ControlThreatMapping(EvidentiaModel):
    """A single control→threat relationship: a control mitigates a threat."""

    control_id: str = Field(
        description="Control ID from the imported catalog, e.g. 'AC-2'."
    )
    threat_id: str = Field(
        description="Canonical threat ID, e.g. 'T1078', 'CWE-79', 'CAPEC-66'."
    )
    threat_framework: ThreatFramework = Field(
        description="Source taxonomy of ``threat_id``."
    )
    relationship: ThreatRelationship = Field(
        default="mitigates",
        description="How the control relates to the threat.",
    )
    coverage: CoverageLevel = Field(
        default="full",
        description="Coverage strength (full / partial / compensating).",
    )
    threat_name: str | None = Field(
        default=None, description="Human-readable threat name."
    )
    mapping_id: str | None = Field(
        default=None,
        description=(
            "Stable per-mapping identifier (``urn:uuid:…``). Auto-derived "
            "deterministically on emit when absent."
        ),
    )
    notes: str | None = Field(
        default=None, description="Optional operator note / rationale."
    )


class TraceabilityMatrix(EvidentiaModel):
    """A Control↔Threat Traceability Matrix, emittable as a signed OSCAL profile."""

    title: str = Field(description="Human-readable matrix title.")
    catalog_href: str = Field(
        description=(
            "OSCAL href of the control catalog the profile imports (the "
            "matrix annotates this catalog's controls with threat links)."
        )
    )
    framework_id: str = Field(
        description="Framework identifier, e.g. 'nist-800-53-rev5-moderate'."
    )
    crosswalk_source: str = Field(
        default="self-attested",
        description=(
            "Provenance of the mappings, e.g. 'mitre-ctid-mappings-explorer' "
            "or 'self-attested'. Surfaced in the emitted profile so consumers "
            "can judge authority (CTID = authoritative-for-ATT&CK, illustrative "
            "for control coverage; NOT a NIST safe harbor)."
        ),
    )
    mappings: list[ControlThreatMapping] = Field(default_factory=list)

    @property
    def control_ids(self) -> list[str]:
        """Unique control IDs across all mappings, in first-seen order."""
        seen: set[str] = set()
        out: list[str] = []
        for m in self.mappings:
            if m.control_id not in seen:
                seen.add(m.control_id)
                out.append(m.control_id)
        return out
