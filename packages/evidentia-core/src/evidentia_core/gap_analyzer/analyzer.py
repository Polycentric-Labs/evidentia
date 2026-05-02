"""Core gap analysis engine.

Compares an organization's control inventory against one or more framework
catalogs and produces a prioritized gap report with cross-framework
efficiency opportunities.

Algorithm:
1. Load target framework catalog(s)
2. Build required control set (union of all controls from selected frameworks)
3. Normalize user inventory control IDs to catalog control IDs
4. Identify gaps (required controls not in inventory or partially implemented)
5. Calculate cross-framework value for each gap
6. Compute priority scores
7. Detect efficiency opportunities (controls satisfying 3+ frameworks)
8. Generate prioritized roadmap
"""

from __future__ import annotations

import logging
from collections import defaultdict

from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.gap_analyzer.normalizer import find_best_match
from evidentia_core.models.catalog import CatalogControl, ControlCatalog
from evidentia_core.models.control import (
    ControlImplementation,
    ControlInventory,
    ControlStatus,
)
from evidentia_core.models.gap import (
    ControlGap,
    EfficiencyOpportunity,
    GapAnalysisReport,
    GapSeverity,
    ImplementationEffort,
)

logger = logging.getLogger(__name__)

# ── Scoring weights ────────────────────────────────────────────────────
SEVERITY_WEIGHT: dict[GapSeverity, float] = {
    GapSeverity.CRITICAL: 4.0,
    GapSeverity.HIGH: 3.0,
    GapSeverity.MEDIUM: 2.0,
    GapSeverity.LOW: 1.0,
    GapSeverity.INFORMATIONAL: 0.5,
}

EFFORT_WEIGHT: dict[ImplementationEffort, float] = {
    ImplementationEffort.LOW: 1.0,
    ImplementationEffort.MEDIUM: 2.0,
    ImplementationEffort.HIGH: 4.0,
    ImplementationEffort.VERY_HIGH: 8.0,
}

# Keyword lists backing the hybrid effort estimator (see _estimate_effort).
# These are module-level so tests can import and verify coverage against
# a curated corpus of real NIST/HIPAA/CMMC control descriptions. Keep
# them alphabetized inside each tuple so diffs stay readable.
_HIGH_EFFORT_KEYWORDS: tuple[str, ...] = (
    "architecture",
    "audit log",
    "authentication",
    "continuous monitoring",
    "cryptograph",  # catches 'cryptographic', 'cryptography'
    "encrypt",
    "incident response plan",
    "key management",
    "least privilege",
    "multi-factor",
    "penetration test",
    "public key infrastructure",
    "separation of duties",
    "siem",
    "single sign-on",
    "zero trust",
)

_MEDIUM_EFFORT_KEYWORDS: tuple[str, ...] = (
    "assess",
    "configuration",
    "document",
    "monitor",
    "patch",
    "policy",
    "procedure",
    "review",
    "training",
    "vulnerability scan",
)


def _severity_weight(value: str | GapSeverity) -> float:
    """Look up severity weight by enum or string value (Pydantic uses string values)."""
    if isinstance(value, GapSeverity):
        return SEVERITY_WEIGHT[value]
    for sev, weight in SEVERITY_WEIGHT.items():
        if sev.value == value:
            return weight
    return 1.0


def _effort_weight(value: str | ImplementationEffort) -> float:
    """Look up effort weight by enum or string value."""
    if isinstance(value, ImplementationEffort):
        return EFFORT_WEIGHT[value]
    for eff, weight in EFFORT_WEIGHT.items():
        if eff.value == value:
            return weight
    return 2.0


class GapAnalyzer:
    """The core gap analysis engine.

    Usage:
        analyzer = GapAnalyzer()
        report = analyzer.analyze(
            inventory=my_inventory,
            frameworks=["nist-800-53-mod", "soc2-tsc"],
            show_efficiency=True,
        )
    """

    def __init__(self, registry: FrameworkRegistry | None = None) -> None:
        self.registry = registry or FrameworkRegistry.get_instance()

    def analyze(
        self,
        inventory: ControlInventory,
        frameworks: list[str],
        show_efficiency: bool = True,
        min_efficiency_frameworks: int = 3,
    ) -> GapAnalysisReport:
        """Run gap analysis against specified frameworks."""
        # %r (repr) escapes control characters in user-controlled values
        # — closes CodeQL py/log-injection alerts #78 + #79 (CWE-117)
        # per v0.7.8 P0.5 S2. inventory.organization is user-supplied
        # via CSV/YAML/JSON; frameworks is user-supplied via CLI/API.
        logger.info(
            "Starting gap analysis for %r: %d controls vs %r",
            inventory.organization,
            len(inventory.controls),
            frameworks,
        )

        # Step 1: Load catalogs
        catalogs = {fw: self.registry.get_catalog(fw) for fw in frameworks}

        # v0.2.1: warn on placeholder (Tier-C stub) catalogs. Gap analysis
        # against these produces structurally-valid output but the control
        # text is copyrighted and not bundled — users should import their
        # licensed copy via `evidentia catalog import` to get
        # meaningful description-based effort estimates and remediation
        # guidance. Emits Python's `warnings.warn` (UserWarning) so the
        # signal surfaces in both CLI runs (captured by Rich) and library
        # callers (captured by their own warning filters / test harnesses).
        _placeholders = [
            fw for fw, cat in catalogs.items() if getattr(cat, "placeholder", False)
        ]
        if _placeholders:
            import warnings

            for fw in _placeholders:
                warnings.warn(
                    (
                        f"Framework '{fw}' is a Tier-C placeholder catalog — "
                        f"authoritative control text is copyrighted and not "
                        f"bundled. Gap analysis will run but reports will "
                        f"show placeholder text in control descriptions. "
                        f"Run `evidentia catalog import` to load your "
                        f"licensed copy. See `evidentia catalog "
                        f"license-info {fw}` for source details."
                    ),
                    UserWarning,
                    stacklevel=2,
                )

        # Step 2: Build required control set
        required_controls = self._build_required_set(catalogs)

        # Step 3: Normalize inventory
        inventory_map = self._normalize_inventory(inventory, catalogs)

        # Step 4: Identify gaps
        gaps = self._identify_gaps(required_controls, inventory_map)

        # Step 5: Calculate cross-framework value
        self._calculate_cross_framework_value(gaps)

        # Step 6: Compute priority scores
        for gap in gaps:
            gap.priority_score = self._compute_priority(gap)

        # Sort by priority (descending)
        gaps.sort(key=lambda g: g.priority_score, reverse=True)

        # Step 7: Detect efficiency opportunities
        efficiency: list[EfficiencyOpportunity] = []
        if show_efficiency:
            efficiency = self._detect_efficiency_opportunities(
                gaps, min_frameworks=min_efficiency_frameworks
            )

        # Step 8: Build report
        severity_counts = self._count_severities(gaps)
        total_required = len(required_controls)
        total_gaps = len(gaps)
        coverage = (
            ((total_required - total_gaps) / total_required * 100)
            if total_required > 0
            else 100.0
        )

        report = GapAnalysisReport(
            organization=inventory.organization,
            frameworks_analyzed=frameworks,
            total_controls_required=total_required,
            total_controls_in_inventory=len(inventory.controls),
            total_gaps=total_gaps,
            critical_gaps=severity_counts.get(GapSeverity.CRITICAL.value, 0),
            high_gaps=severity_counts.get(GapSeverity.HIGH.value, 0),
            medium_gaps=severity_counts.get(GapSeverity.MEDIUM.value, 0),
            low_gaps=severity_counts.get(GapSeverity.LOW.value, 0),
            informational_gaps=severity_counts.get(GapSeverity.INFORMATIONAL.value, 0),
            coverage_percentage=round(coverage, 1),
            gaps=gaps,
            efficiency_opportunities=efficiency,
            prioritized_roadmap=[g.id for g in gaps],
            inventory_source=inventory.source_file,
        )

        logger.info(
            "Gap analysis complete: %d gaps found, %.1f%% coverage, %d efficiency opportunities",
            total_gaps,
            coverage,
            len(efficiency),
        )
        return report

    def _build_required_set(
        self, catalogs: dict[str, ControlCatalog]
    ) -> dict[str, list[tuple[str, CatalogControl]]]:
        """Build the set of required controls across all frameworks.

        Returns: {framework:control_id: [(framework_id, CatalogControl), ...]}
        """
        required: dict[str, list[tuple[str, CatalogControl]]] = defaultdict(list)

        for fw_id, catalog in catalogs.items():
            for control in catalog.controls:
                key = f"{fw_id}:{control.id}"
                required[key].append((fw_id, control))
                # Include enhancements as separate requirements
                for enhancement in control.enhancements:
                    enh_key = f"{fw_id}:{enhancement.id}"
                    required[enh_key].append((fw_id, enhancement))

        return required

    def _normalize_inventory(
        self,
        inventory: ControlInventory,
        catalogs: dict[str, ControlCatalog],
    ) -> dict[str, ControlImplementation]:
        """Normalize inventory control IDs and build a lookup map.

        Returns: {framework:control_id: ControlImplementation}
        """
        inv_map: dict[str, ControlImplementation] = {}

        for impl in inventory.controls:
            for fw_id, catalog in catalogs.items():
                matched_id = find_best_match(impl.id, catalog)
                if matched_id:
                    key = f"{fw_id}:{matched_id}"
                    inv_map[key] = impl

        return inv_map

    def _identify_gaps(
        self,
        required: dict[str, list[tuple[str, CatalogControl]]],
        inventory_map: dict[str, ControlImplementation],
    ) -> list[ControlGap]:
        """Identify gaps between required controls and inventory."""
        gaps: list[ControlGap] = []

        for req_key, fw_controls in required.items():
            impl = inventory_map.get(req_key)
            fw_id, catalog_control = fw_controls[0]

            if impl is None:
                # Control is completely missing
                gaps.append(
                    ControlGap(
                        framework=fw_id,
                        control_id=catalog_control.id,
                        control_title=catalog_control.title,
                        control_description=catalog_control.description,
                        control_family=catalog_control.family,
                        gap_severity=GapSeverity.CRITICAL,
                        implementation_status="missing",
                        gap_description=(
                            f"Control {catalog_control.id} ({catalog_control.title}) "
                            f"is required by {fw_id} but is not present in the "
                            f"organization's control inventory."
                        ),
                        remediation_guidance=self._generate_remediation_guidance(
                            catalog_control
                        ),
                        implementation_effort=self._estimate_effort(catalog_control),
                    )
                )
            elif impl.status == ControlStatus.PARTIALLY_IMPLEMENTED.value:
                gaps.append(
                    ControlGap(
                        framework=fw_id,
                        control_id=catalog_control.id,
                        control_title=catalog_control.title,
                        control_description=catalog_control.description,
                        control_family=catalog_control.family,
                        gap_severity=GapSeverity.HIGH,
                        implementation_status="partial",
                        gap_description=(
                            f"Control {catalog_control.id} ({catalog_control.title}) "
                            f"is partially implemented. "
                            f"Notes: {impl.implementation_notes or 'No details provided.'}"
                        ),
                        equivalent_controls_in_inventory=[impl.id],
                        remediation_guidance=self._generate_remediation_guidance(
                            catalog_control, partial=True
                        ),
                        implementation_effort=ImplementationEffort.MEDIUM,
                    )
                )
            elif impl.status == ControlStatus.PLANNED.value:
                gaps.append(
                    ControlGap(
                        framework=fw_id,
                        control_id=catalog_control.id,
                        control_title=catalog_control.title,
                        control_description=catalog_control.description,
                        control_family=catalog_control.family,
                        gap_severity=GapSeverity.MEDIUM,
                        implementation_status="planned",
                        gap_description=(
                            f"Control {catalog_control.id} ({catalog_control.title}) "
                            f"is planned but not yet implemented."
                        ),
                        equivalent_controls_in_inventory=[impl.id],
                        remediation_guidance=(
                            f"Execute the planned implementation for {catalog_control.id}. "
                            f"Ensure implementation addresses all assessment objectives."
                        ),
                        implementation_effort=ImplementationEffort.LOW,
                    )
                )
            elif impl.status == ControlStatus.NOT_IMPLEMENTED.value:
                gaps.append(
                    ControlGap(
                        framework=fw_id,
                        control_id=catalog_control.id,
                        control_title=catalog_control.title,
                        control_description=catalog_control.description,
                        control_family=catalog_control.family,
                        gap_severity=GapSeverity.CRITICAL,
                        implementation_status="missing",
                        gap_description=(
                            f"Control {catalog_control.id} ({catalog_control.title}) "
                            f"is in the inventory but explicitly marked as not implemented."
                        ),
                        equivalent_controls_in_inventory=[impl.id],
                        remediation_guidance=self._generate_remediation_guidance(
                            catalog_control
                        ),
                        implementation_effort=self._estimate_effort(catalog_control),
                    )
                )
            # IMPLEMENTED and NOT_APPLICABLE are not gaps

        return gaps

    def _calculate_cross_framework_value(self, gaps: list[ControlGap]) -> None:
        """For each gap, determine which other frameworks would also benefit."""
        crosswalk = self.registry.crosswalk

        for gap in gaps:
            cross_value = crosswalk.get_cross_framework_value(
                gap.framework, gap.control_id
            )
            gap.cross_framework_value = cross_value

    def _compute_priority(self, gap: ControlGap) -> float:
        """Compute priority score for a gap.

        Formula:
            priority = severity_weight × (1 + 0.2 × cross_framework_count) × (1 / effort_weight)

        Higher score = higher priority (fix first).
        """
        severity_w = _severity_weight(gap.gap_severity)
        cross_fw_bonus = 1 + 0.2 * len(gap.cross_framework_value)
        effort_w = _effort_weight(gap.implementation_effort)

        return round(severity_w * cross_fw_bonus * (1 / effort_w), 3)

    def _detect_efficiency_opportunities(
        self,
        gaps: list[ControlGap],
        min_frameworks: int = 3,
    ) -> list[EfficiencyOpportunity]:
        """Detect controls that satisfy multiple framework requirements."""
        # Group gaps by normalized control concept
        control_groups: dict[str, list[ControlGap]] = defaultdict(list)
        for gap in gaps:
            control_groups[gap.control_id].append(gap)

        opportunities: list[EfficiencyOpportunity] = []

        for control_id, gap_group in control_groups.items():
            all_satisfied: list[str] = []
            for g in gap_group:
                all_satisfied.append(f"{g.framework}:{g.control_id}")
                all_satisfied.extend(g.cross_framework_value)

            unique_frameworks = {s.split(":")[0] for s in all_satisfied}

            if len(unique_frameworks) >= min_frameworks:
                # Pick the effort level from the most severe gap in the group
                most_severe = max(
                    gap_group, key=lambda g: _severity_weight(g.gap_severity)
                )
                effort_value = most_severe.implementation_effort
                effort_w = _effort_weight(effort_value)
                value_score = len(set(all_satisfied)) / effort_w

                opportunities.append(
                    EfficiencyOpportunity(
                        control_id=control_id,
                        control_title=gap_group[0].control_title,
                        frameworks_satisfied=sorted(set(all_satisfied)),
                        framework_count=len(unique_frameworks),
                        total_gaps_closed=len(gap_group),
                        implementation_effort=ImplementationEffort(effort_value)
                        if isinstance(effort_value, str)
                        else effort_value,
                        value_score=round(value_score, 2),
                    )
                )

        # Sort by value score descending
        opportunities.sort(key=lambda o: o.value_score, reverse=True)
        return opportunities

    def _generate_remediation_guidance(
        self,
        control: CatalogControl,
        partial: bool = False,
    ) -> str:
        """Generate remediation guidance for a gap."""
        if partial:
            return (
                f"Complete the implementation of {control.id} ({control.title}). "
                f"Review the control description and assessment objectives to identify "
                f"which aspects are not yet covered. Key requirements:\n"
                f"{control.description[:500]}"
            )
        return (
            f"Implement {control.id} ({control.title}) to meet the following requirement:\n"
            f"{control.description[:500]}\n\n"
            f"Consider: existing tools, processes, or compensating controls that may "
            f"partially address this requirement."
        )

    def _estimate_effort(self, control: CatalogControl) -> ImplementationEffort:
        """Estimate implementation effort for a control — hybrid heuristic.

        v0.2.1: the original implementation used ONLY a structural complexity
        score (``len(enhancements) + len(assessment_objectives)``). That score
        is zero for every bundled catalog currently on disk (OSCAL resolution
        of enhancements is in-scope for the bundled NIST catalog, but other
        catalogs like HIPAA/FedRAMP/CMMC never carry enhancements or
        assessment-objectives metadata). The result: every gap resolved to
        ``LOW``, which collapsed the priority formula to
        ``severity × (1 + 0.2 × cross_fw_count)`` and silently lost the
        effort-weighted "easy wins first" dimension. See
        ``docs/architecture/effort-estimation.md`` for the design rationale
        and keyword list origins.

        The replacement is a three-layer cascade:

        1. **Structural score** (when present) — still the most reliable
           signal because it comes from authoritative catalog structure.
           Thresholds preserved from v0.1.x so NIST OSCAL catalogs estimate
           identically before and after the upgrade.
        2. **Keyword fallback** — when structural score is zero, look for
           domain terms in the control description that indicate
           architectural complexity (cryptography, MFA, continuous
           monitoring) vs. documentation/policy work (procedure, review,
           training). Keyword lists live in module-level constants so
           tests can import them and tune coverage.
        3. **Description-length fallback** — when neither structural nor
           keyword signals fire, long descriptions (>400 chars) indicate
           complex controls and resolve to MEDIUM. Short bare descriptions
           fall through to LOW.

        Returns :class:`ImplementationEffort`. Never raises.
        """
        # Layer 1: structural complexity (works when OSCAL resolution populates
        # enhancements and 800-53A assessment objectives)
        structural_score = len(control.enhancements) + len(
            control.assessment_objectives
        )
        if structural_score >= 10:
            return ImplementationEffort.VERY_HIGH
        if structural_score >= 5:
            return ImplementationEffort.HIGH
        if structural_score >= 2:
            return ImplementationEffort.MEDIUM

        # Layer 2: keyword presence in description. Case-insensitive substring
        # match — deliberately simple so a future fuzzy/embedding upgrade
        # won't need to parse legacy scoring code.
        desc = (control.description or "").lower()

        if any(kw in desc for kw in _HIGH_EFFORT_KEYWORDS):
            return ImplementationEffort.HIGH
        if any(kw in desc for kw in _MEDIUM_EFFORT_KEYWORDS):
            return ImplementationEffort.MEDIUM

        # Layer 3: description length fallback. Controls with long
        # descriptions are almost always meaningfully complex even without
        # explicit keywords; short ones are genuinely low-effort bookkeeping.
        if len(desc) > 400:
            return ImplementationEffort.MEDIUM

        return ImplementationEffort.LOW

    @staticmethod
    def _count_severities(gaps: list[ControlGap]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for gap in gaps:
            key = (
                gap.gap_severity.value
                if isinstance(gap.gap_severity, GapSeverity)
                else gap.gap_severity
            )
            counts[key] = counts.get(key, 0) + 1
        return counts
