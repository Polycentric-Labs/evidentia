"""Threat catalog models — ATT&CK techniques, CWE weaknesses, CAPEC patterns, CISA KEV.

Parallel to :class:`evidentia_core.models.catalog.ControlCatalog` but
distinct in shape: threats and vulnerabilities are not implementable
controls, they are adversary behaviors, weakness patterns, or specific
exploited CVEs that controls mitigate against.

These models enable gap analysis to answer: "What ATT&CK techniques are
we uncovered against?" or "Which KEV CVEs does our control posture
mitigate?" — questions the plain ``ControlCatalog`` can't express.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, PrivateAttr

from evidentia_core.models.common import EvidentiaModel

# Broad categories for threats, following common industry groupings.
ThreatCategory = Literal["technique", "weakness", "attack-pattern", "vulnerability"]


class AttackTechnique(EvidentiaModel):
    """A MITRE ATT&CK technique (or sub-technique).

    Modeled directly from STIX 2.1 ``attack-pattern`` objects as published
    by the mitre-attack/attack-stix-data repository.
    """

    id: str = Field(description="Technique ID, e.g. 'T1078' or 'T1078.001'")
    name: str = Field(description="Technique name")
    description: str = Field(description="Technique description")
    tactic_ids: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK tactic IDs (e.g. ['TA0001']) this technique belongs to",
    )
    tactic_names: list[str] = Field(
        default_factory=list,
        description="Tactic names (e.g. ['Initial Access', 'Persistence'])",
    )
    platforms: list[str] = Field(
        default_factory=list,
        description="Target platforms, e.g. ['Windows', 'Linux', 'macOS', 'Azure AD']",
    )
    data_sources: list[str] = Field(
        default_factory=list,
        description="Data sources useful for detecting this technique",
    )
    detection: str | None = Field(
        default=None,
        description="Detection guidance from the ATT&CK entry",
    )
    kill_chain_phases: list[str] = Field(
        default_factory=list,
        description="Kill-chain phase names (typically matches tactic names)",
    )
    mitigations: list[str] = Field(
        default_factory=list,
        description="Control/mitigation IDs that mitigate this technique (e.g. 'M1032')",
    )
    references: list[str] = Field(
        default_factory=list,
        description="External reference URLs (advisories, blog posts, CVEs)",
    )
    is_subtechnique: bool = Field(
        default=False,
        description="True if this entry is a sub-technique of another",
    )
    parent_technique_id: str | None = Field(
        default=None,
        description="Parent technique ID when is_subtechnique=true",
    )
    deprecated: bool = Field(
        default=False,
        description="True if ATT&CK has deprecated this technique",
    )


class TechniqueCatalog(EvidentiaModel):
    """A catalog of threat techniques (ATT&CK, CWE, CAPEC).

    Parallel to :class:`ControlCatalog` — separate model so gap-analysis
    tooling can dispatch on catalog type without type-checking hacks.
    """

    framework_id: str = Field(description="Canonical ID, e.g. 'mitre-attack-enterprise'")
    framework_name: str = Field(description="Human-readable name")
    version: str = Field(description="Catalog version, e.g. 'v15.1'")
    source: str = Field(description="Upstream source URL or citation")
    category: ThreatCategory = Field(
        default="technique",
        description="Threat category — technique/weakness/attack-pattern",
    )
    techniques: list[AttackTechnique] = Field(description="All entries in the catalog")
    tactics: list[str] = Field(
        default_factory=list,
        description="Distinct tactic names represented in the catalog",
    )
    tier: str | None = Field(default=None, description="Redistribution tier")
    license_required: bool = Field(default=False)
    license_terms: str | None = Field(default=None)
    license_url: str | None = Field(default=None)
    placeholder: bool = Field(default=False)

    _index: dict[str, AttackTechnique] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Build technique index."""
        self._index = {t.id.upper(): t for t in self.techniques}

    def get_technique(self, technique_id: str) -> AttackTechnique | None:
        """Look up a technique by ID (case-insensitive)."""
        return self._index.get(technique_id.strip().upper())

    def by_tactic(self, tactic_name: str) -> list[AttackTechnique]:
        """All techniques tagged with a given tactic name."""
        return [t for t in self.techniques if tactic_name in t.tactic_names]

    @property
    def technique_count(self) -> int:
        """Total techniques including sub-techniques."""
        return len(self._index)


class Vulnerability(EvidentiaModel):
    """A single known-exploited or published vulnerability.

    Modeled after the CISA KEV schema, but generic enough for NVD CVE
    records or vendor advisories.
    """

    cve_id: str = Field(description="CVE ID, e.g. 'CVE-2024-12345'")
    vendor: str = Field(description="Vendor or project name")
    product: str = Field(description="Product name")
    vulnerability_name: str | None = Field(
        default=None, description="Short name from KEV, e.g. 'Ivanti Authentication Bypass'"
    )
    description: str = Field(description="Vulnerability description")
    cwe_ids: list[str] = Field(
        default_factory=list,
        description="CWE weakness IDs underlying this vulnerability (e.g. ['CWE-22'])",
    )
    cvss_v3_score: float | None = Field(default=None, description="CVSS v3.1 base score")
    cvss_v4_score: float | None = Field(default=None, description="CVSS v4.0 base score")
    date_published: str | None = Field(default=None, description="Publication date (ISO 8601 date)")
    date_added: str | None = Field(
        default=None,
        description="Date added to KEV or discovered (ISO 8601 date)",
    )
    known_ransomware_use: bool | None = Field(
        default=None,
        description="True if KEV flags known ransomware-campaign use",
    )
    required_action: str | None = Field(
        default=None,
        description="KEV-required mitigation action (e.g. 'Apply vendor patch')",
    )
    due_date: str | None = Field(
        default=None,
        description="KEV federal-agency remediation deadline (ISO 8601 date)",
    )
    references: list[str] = Field(default_factory=list, description="External reference URLs")


class VulnerabilityCatalog(EvidentiaModel):
    """A catalog of vulnerabilities (CISA KEV, NVD subset, vendor feeds)."""

    framework_id: str = Field(description="Canonical ID, e.g. 'cisa-kev'")
    framework_name: str = Field(description="Human-readable name")
    version: str = Field(description="Catalog version or as-of date")
    source: str = Field(description="Upstream source URL")
    category: Literal["vulnerability"] = Field(default="vulnerability")
    vulnerabilities: list[Vulnerability] = Field(description="All entries")
    tier: str | None = Field(default=None)
    license_required: bool = Field(default=False)
    license_terms: str | None = Field(default=None)
    license_url: str | None = Field(default=None)
    placeholder: bool = Field(default=False)

    _index: dict[str, Vulnerability] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Build CVE index."""
        self._index = {v.cve_id.upper(): v for v in self.vulnerabilities}

    def get_vulnerability(self, cve_id: str) -> Vulnerability | None:
        """Look up a vulnerability by CVE ID."""
        return self._index.get(cve_id.strip().upper())

    @property
    def vulnerability_count(self) -> int:
        return len(self._index)
