"""Framework catalog models.

Represents the controls required by a compliance framework. These are
loaded from bundled OSCAL JSON catalogs and used as the "target state"
in gap analysis.

v0.2.0 expands the model to carry richer OSCAL data (guidance,
objective, examples, control class) and tier/license metadata for the
50-framework catalog expansion. All new fields are optional with safe
defaults — existing v0.1.x catalog JSONs continue to parse under
``extra="forbid"``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import date
from typing import Any, Literal, NamedTuple

from pydantic import Field, PrivateAttr

from evidentia_core.models.common import EvidentiaModel

# NIST publications render enhancement IDs as ``AC-2(1)(a)`` while NIST OSCAL
# content renders them as ``ac-2.1.a``. Both are valid. We normalize to the
# dotted, upper-case form for storage/lookup so either input convention
# resolves the same control. Added in v0.2.1 when bundling the full NIST
# OSCAL catalog revealed the dual-convention mismatch.
#
# The inner class is ``[^()]`` (excludes both parens) and is bounded to
# 16 characters so the engine can't backtrack quadratically on
# pathological input like ``((((((((((`` — the bound matches real-world
# control IDs (longest enhancement is < 8 chars: ``(a)(1)(b)``).
_PAREN_TO_DOT = re.compile(r"\(([^()]{1,16})\)")


def _normalize_control_id(raw: str) -> str:
    """Canonicalize a control ID to dotted, uppercase form.

    ``AC-2(1)(a)`` → ``AC-2.1.A``; ``ac-2.1`` → ``AC-2.1``; ``  cc6.1 `` →
    ``CC6.1``. Preserves hyphens, dots, and alphanumerics; strips
    whitespace. Never raises — unparseable input is returned uppercased.
    """
    s = (raw or "").strip().upper()
    # Convert parenthetical enhancement markers to dots, iteratively so
    # nested groups like ``AC-2(1)(a)`` → ``AC-2.1.A`` land in one pass
    # through the regex (sub() handles all non-overlapping matches).
    return _PAREN_TO_DOT.sub(r".\1", s)


# Crosswalk relationship vocabulary. Kept as a ``Literal`` constant so
# tooling can type-check hand-authored mappings; ``FrameworkMapping.relationship``
# remains a plain ``str`` for backward compatibility with v0.1.x JSON.
RelationshipType = Literal["equivalent", "related", "partial", "superset", "subset", "intersects"]

#: How much control text a catalog carries. Derived from the controls, never
#: declared: ``full`` when every non-withdrawn control has statement text that
#: differs from its title, ``headings`` when none does (the catalog carries
#: control numbering and titles only), ``partial`` otherwise. The redistribution
#: tier says what may be redistributed; this says what is actually there.
TextDepth = Literal["full", "partial", "headings"]


class StatementRow(NamedTuple):
    """The four facts about one catalog entry that decide whether it carries text."""

    title: str
    text: str
    placeholder: bool
    withdrawn: bool


def _collapse(value: str) -> str:
    return " ".join(value.split()).casefold()


def has_statement(row: StatementRow) -> bool:
    """True when the entry carries statement text of its own.

    A placeholder never counts, and neither does text that merely repeats the
    title, which is the shape of a heading-only catalog.
    """
    text = _collapse(row.text)
    return bool(text) and text != _collapse(row.title) and not row.placeholder


def derive_text_depth(rows: Iterable[StatementRow]) -> TextDepth:
    """Classify a catalog's text depth from its entries.

    Withdrawn entries are left out: an upstream source carries no statement
    for a control it has withdrawn, and that absence says nothing about the
    depth of the catalog. An empty catalog is ``headings``.
    """
    eligible = [row for row in rows if not row.withdrawn]
    with_text = sum(1 for row in eligible if has_statement(row))
    if with_text == 0:
        return "headings"
    if with_text == len(eligible):
        return "full"
    return "partial"


class CatalogControl(EvidentiaModel):
    """A single control from a framework catalog."""

    id: str = Field(description="Control ID, e.g. 'AC-2', 'CC6.1'")
    title: str = Field(description="Control title")
    description: str = Field(description="Full control description")
    family: str | None = Field(default=None, description="Control family/group")
    class_: str | None = Field(
        default=None,
        alias="class",
        description="Control class: 'technical', 'operational', 'management'",
    )
    control_class: str | None = Field(
        default=None,
        description="OSCAL `class` attribute (e.g. 'SP800-53'). Distinct from "
        "`class_` which historically carried the control's nature "
        "(technical/operational/management) in Evidentia format.",
    )
    priority: str | None = Field(
        default=None,
        description="Publisher priority label, such as P1 through P4; independent of status and applicability",
    )
    baseline_impact: list[str] = Field(
        default_factory=list,
        description="Baselines this control belongs to: ['low', 'moderate', 'high']",
    )
    enhancements: list[CatalogControl] = Field(
        default_factory=list,
        description="Control enhancements (sub-controls)",
    )
    related_controls: list[str] = Field(
        default_factory=list,
        description="IDs of related controls within the same framework",
    )
    assessment_objectives: list[str] = Field(
        default_factory=list,
        description="Assessment objectives from SP 800-53A",
    )
    objective: str | None = Field(
        default=None,
        description="OSCAL `part.name=objective` prose — concise statement of what the control aims to achieve",
    )
    risk_tier: str | None = Field(
        default=None,
        description=(
            "v0.9.3 P2.1: optional EU-AI-Act-style risk tier annotation "
            "('unacceptable', 'high', 'limited', 'minimal', "
            "'informational'). Used by AI-governance catalogs to "
            "express per-control regulatory weight. Optional for "
            "backward-compat with pre-v0.9.3 catalogs."
        ),
    )
    applies_to_annex_iii: str | None = Field(
        default=None,
        description=(
            "v0.9.3 P2.1: optional EU AI Act Annex III scope marker "
            "('all' = applies to every high-risk domain; a specific "
            "domain string = applies only to that one). Optional."
        ),
    )
    guidance: str | None = Field(
        default=None,
        description="OSCAL `part.name=guidance` prose — implementation guidance "
        "text distinct from the control statement",
    )
    examples: list[str] = Field(
        default_factory=list,
        description="Illustrative examples from the authoritative text",
    )
    parameters: dict[str, str] = Field(
        default_factory=dict,
        description="Organization-defined parameters and their default values",
    )
    ordering: int | None = Field(
        default=None,
        description="Preserves upstream order for CSF subcategories, ISO clause "
        "numbering, etc. Populated during catalog load.",
    )
    tier: str | None = Field(
        default=None,
        description="Redistribution tier: 'A' (public domain), 'B' (free-restricted), "
        "'C' (copyrighted, license required), 'D' (government regulation)",
    )
    license_required: bool = Field(
        default=False,
        description="True if this control's authoritative text is under copyright "
        "and this entry is a stub — users must supply their own licensed copy",
    )
    license_url: str | None = Field(
        default=None,
        description="URL to the authoritative source where licensed control text can be obtained",
    )
    placeholder: bool = Field(
        default=False,
        description="True if the description field is a placeholder rather than "
        "authoritative control text (pairs with license_required for Tier C stubs)",
    )
    withdrawn: bool = Field(
        default=False,
        description="True when the publisher has withdrawn this control (the OSCAL "
        "`status` prop reads `withdrawn`). A withdrawn control carries no statement "
        "upstream, is skipped by gap analysis, and does not count toward text depth.",
    )

    properties: dict[str, str] = Field(
        default_factory=dict,
        description="Independent publisher attributes, such as Existing tags and raw baseline or overlay labels",
    )


CatalogStatus = Literal["current", "superseded", "retired", "historical"]


class CatalogAuditContext(EvidentiaModel):
    """A source-verified audit version for one named authority, not a national default."""

    authority: str = Field(description="Authority that published this audit scope")
    version: str = Field(description="Version used by the named authority for audits")
    source_url: str = Field(description="Primary source for this authority's audit version")
    verified_on: date = Field(description="Date the cited source was checked")
    valid_through: date | None = Field(
        default=None, description="Last date explicitly covered by the source; None means unknown"
    )
    notes: str | None = Field(default=None, description="Scope and limits of the audit-version statement")


class CatalogPublicationNotice(EvidentiaModel):
    """A publication record outside the assessed controls, with no automatic activation."""

    id: str = Field(description="Publisher's designator for the announced revision")
    title: str = Field(description="Short published heading")
    status: Literal["approved-future", "approved-superseded", "pending"] = Field(
        description="Status verified in the source, independent of elapsed calendar dates"
    )
    source_url: str = Field(description="Primary source for the publication status")
    approved_on: date | None = Field(default=None, description="Approval or order issuance date")
    published_on: date | None = Field(default=None, description="Publication date, when verified")
    order_effective_on: date | None = Field(default=None, description="Effective date of the approving legal order")
    effective_on: date | None = Field(default=None, description="Standard's general applicability date")
    inactive_on: date | None = Field(default=None, description="Published last active date, when verified")
    superseded_by: str | None = Field(default=None, description="Successor designator, when verified")
    notes: str | None = Field(default=None, description="Jurisdiction, phased dates and source limitations")


class ControlCatalog(EvidentiaModel):
    """A complete framework catalog containing all controls.

    Loaded from bundled OSCAL JSON files. Provides indexed access
    to controls by ID and family.
    """

    framework_id: str = Field(
        description="Canonical framework ID, e.g. 'nist-800-53-rev5'",
    )
    framework_name: str = Field(
        description="Human-readable name, e.g. 'NIST SP 800-53 Revision 5'",
    )
    version: str = Field(
        description="Framework version, e.g. 'Rev 5', '2022', 'v8'",
    )
    source: str = Field(
        description="Source of the catalog data, e.g. 'usnistgov/oscal-content'",
    )
    controls: list[CatalogControl] = Field(
        description="All controls in this catalog",
    )
    families: list[str] = Field(
        default_factory=list,
        description="List of control families in this catalog",
    )
    family_hierarchy: dict[str, list[str]] | None = Field(
        default=None,
        description="Parent→children map for multi-level OSCAL groups "
        "(e.g. NIST 800-53 groups with sub-groups). None when families are flat.",
    )
    category: Literal["control", "technique", "vulnerability", "obligation"] = Field(
        default="control",
        description="Catalog type — 'control' for compliance frameworks, "
        "'technique' for ATT&CK/CWE/CAPEC, 'vulnerability' for KEV, "
        "'obligation' for privacy laws.",
    )
    tier: str | None = Field(
        default=None,
        description="Redistribution tier: 'A', 'B', 'C', 'D' (see CatalogControl.tier)",
    )
    v0_9_3_note: str | None = Field(
        default=None,
        description=("v0.9.3 P2.1: optional cycle-note documenting catalog enrichment scope. Free-form."),
    )
    annex_iii_risk_categories: list[str] | None = Field(
        default=None,
        description=(
            "v0.9.3 P2.1: optional EU AI Act Annex III high-risk "
            "category list. Set on the eu-ai-act catalog; None "
            "elsewhere."
        ),
    )
    license_required: bool = Field(
        default=False,
        description="True if this catalog is a stub whose authoritative control text "
        "is copyrighted and cannot be bundled",
    )
    license_terms: str | None = Field(
        default=None,
        description="Human-readable description of licensing terms",
    )
    license_url: str | None = Field(
        default=None,
        description="URL to the authoritative source / purchase page",
    )
    placeholder: bool = Field(
        default=False,
        description="True if the catalog as a whole is a stub (all controls have placeholder text)",
    )

    status: CatalogStatus | None = Field(
        default=None, description="Publisher lifecycle in the stated scope; None means unverified"
    )
    notes: str | None = Field(default=None, description="Operator notice about source scope and currency")
    verified_on: date | None = Field(default=None, description="Date the catalog's source and currency were checked")
    superseded_by: str | None = Field(default=None, description="Successor framework ID, without implying equivalence")
    audit_contexts: dict[str, CatalogAuditContext] = Field(
        default_factory=dict,
        description="Audit versions keyed by authority jurisdiction, such as US-TX; absent authorities are unknown",
    )
    publication_notices: list[CatalogPublicationNotice] = Field(
        default_factory=list,
        description="Announced revisions outside the assessed controls; dates never activate them automatically",
    )

    # Private index for fast lookup
    _index: dict[str, CatalogControl] = PrivateAttr(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        """Build recursive control index after initialization.

        v0.2.0: walks the full enhancement tree so 3-level NIST Rev 5
        IDs like ``AC-2(1)(a)`` resolve via ``get_control``.
        v0.2.1: normalizes via ``_normalize_control_id`` so the same
        catalog exposes both NIST-publication-style (``AC-2(1)``) and
        NIST-OSCAL-style (``ac-2.1``) lookups consistently.
        """
        self._index = {}

        def _walk(ctrl: CatalogControl) -> None:
            self._index[_normalize_control_id(ctrl.id)] = ctrl
            for e in ctrl.enhancements:
                _walk(e)

        for control in self.controls:
            _walk(control)

    def get_control(self, control_id: str) -> CatalogControl | None:
        """Look up a control by ID — accepts either NIST-pub (``AC-2(1)``) or
        NIST-OSCAL (``ac-2.1``) style; case-insensitive; whitespace-tolerant.
        """
        return self._index.get(_normalize_control_id(control_id))

    def get_family(self, family: str) -> list[CatalogControl]:
        """Get all controls in a family."""
        return [c for c in self.controls if c.family == family]

    @property
    def control_count(self) -> int:
        """Total number of controls (including enhancements)."""
        return len(self._index)

    def statement_rows(self) -> list[StatementRow]:
        """One :class:`StatementRow` per indexed control, enhancements included."""
        return [
            StatementRow(ctrl.title, ctrl.description, ctrl.placeholder, ctrl.withdrawn)
            for ctrl in self._index.values()
        ]

    @property
    def text_depth(self) -> TextDepth:
        """Derived text depth of this catalog (see :data:`TextDepth`)."""
        return derive_text_depth(self.statement_rows())


class FrameworkMapping(EvidentiaModel):
    """A single mapping entry between two frameworks' controls."""

    source_control_id: str
    source_control_title: str | None = None
    target_control_id: str
    target_control_title: str | None = None
    relationship: str = Field(
        description="Mapping relationship: see RelationshipType constant for "
        "the canonical vocabulary ('equivalent', 'related', 'partial', "
        "'superset', 'subset', 'intersects'). Kept as str for v0.1.x compat.",
    )
    notes: str | None = Field(
        default=None,
        description="Notes about this mapping relationship",
    )
    confidence: str | None = Field(
        default=None,
        description=(
            "v0.9.3 P2.2: per-mapping confidence — 'high', 'medium', "
            "'low'. Surfaces SME-review priority for mappings authored "
            "without domain expertise. Optional for backward-compat with "
            "pre-v0.9.3 crosswalks."
        ),
    )


class CrosswalkDefinition(EvidentiaModel):
    """A complete crosswalk between two frameworks.

    Loaded from bundled JSON files in catalogs/data/mappings/.
    """

    source_framework: str
    target_framework: str
    version: str
    generated_at: str
    source: str = Field(
        description="Authority source for this crosswalk",
    )
    mappings: list[FrameworkMapping]
    v0_9_3_note: str | None = Field(
        default=None,
        description=("v0.9.3 P2.2: optional cycle-note documenting authoring scope + planned refinements. Free-form."),
    )
    confidence_rubric: dict[str, str] | None = Field(
        default=None,
        description=(
            "v0.9.3 P2.2: optional dict explaining the confidence "
            "field's vocabulary (e.g., {'high': '...', 'medium': "
            "'...', 'low': '...'}). Optional for backward-compat."
        ),
    )
    provenance: str | None = Field(
        default=None,
        description=(
            "v0.10.6: optional provenance tag for crosswalks shipped "
            "raw + auto-extracted from upstream sources (e.g., "
            "'upstream-osps-guidelines'). Additive — None for "
            "crosswalks predating v0.10.6."
        ),
    )
    verification: Literal["self-attested-via-upstream", "self-attested", "hand-checked"] | None = Field(
        default=None,
        description=(
            "v0.10.6: verification posture. 'self-attested-via-upstream' "
            "= mappings auto-extracted from upstream guidelines[] "
            "arrays, NOT independently audit-verified. 'self-attested' "
            "(v0.10.10 / FDA 524B pack) = hand-authored by Evidentia, "
            "NOT independently audited — used for illustrative "
            "conceptual crosswalks. 'hand-checked' = SME-reviewed."
        ),
    )
    verification_note: str | None = Field(
        default=None,
        description=(
            "v0.10.6: free-form note explaining the verification "
            "posture's scope + the path to upgrading "
            "'self-attested-via-upstream' → 'hand-checked' if a "
            "consumer requires independent verification."
        ),
    )
    risk_model_note: str | None = Field(
        default=None,
        description=(
            "v0.10.10 (FDA 524B pack): optional free-form note "
            "documenting how the source and target frameworks "
            "characterize risk differently (e.g., the ISO 14971 "
            "safety probability×severity model vs. the AAMI "
            "SW96/TIR57 exploitability×severity security model). "
            "Additive — None for crosswalks that do not span "
            "differing risk models."
        ),
    )

    def get_target_controls(self, source_control_id: str) -> list[FrameworkMapping]:
        """Get all target controls mapped from a source control."""
        return [m for m in self.mappings if m.source_control_id.upper() == source_control_id.strip().upper()]

    def get_source_controls(self, target_control_id: str) -> list[FrameworkMapping]:
        """Get all source controls mapped to a target control (reverse lookup)."""
        return [m for m in self.mappings if m.target_control_id.upper() == target_control_id.strip().upper()]
