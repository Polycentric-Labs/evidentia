"""Gap-diff models — compare two :class:`GapAnalysisReport` snapshots.

v0.3.0 introduced these types to support `evidentia gap diff`, the
PR-level compliance-as-code command. The diff compares two reports (the
"base" and the "head" — names chosen to match `git diff` semantics) and
classifies each `(framework, control_id)` pair as one of five states:

- **closed**: present in base, absent (or status=CLOSED) in head. Good.
- **opened**: absent in base, present in head. Regression.
- **severity_increased**: same gap appears in both, severity went up.
- **severity_decreased**: same gap appears in both, severity went down.
- **unchanged**: same gap, same severity, both reports.

The model is Pydantic-validated and JSON-serializable so CI jobs can
upload diff reports as artifacts without custom serializer code.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel, new_id, utc_now
from evidentia_core.models.gap import GapSeverity

# Ordered enum for severity comparison — critical > high > medium > low > info.
_SEVERITY_ORDER: dict[GapSeverity, int] = {
    GapSeverity.INFORMATIONAL: 0,
    GapSeverity.LOW: 1,
    GapSeverity.MEDIUM: 2,
    GapSeverity.HIGH: 3,
    GapSeverity.CRITICAL: 4,
}


def severity_rank(sev: GapSeverity | str) -> int:
    """Return an integer rank for severity comparison; higher = more severe."""
    if isinstance(sev, GapSeverity):
        return _SEVERITY_ORDER.get(sev, 0)
    for s, rank in _SEVERITY_ORDER.items():
        if s.value == sev:
            return rank
    return 0


DiffStatus = Literal[
    "closed",  # gap fixed (regression-free win)
    "opened",  # new gap (compliance regression)
    "severity_increased",  # same gap, got worse
    "severity_decreased",  # same gap, got better
    "unchanged",  # same gap, no change
]


class GapDiffEntry(EvidentiaModel):
    """A single entry in a gap diff — one per `(framework, control_id)` key.

    For ``opened``/``closed`` entries, ``base_severity`` or ``head_severity``
    is ``None`` respectively. For ``severity_*`` and ``unchanged`` entries,
    both are populated.
    """

    framework: str = Field(description="Framework ID (e.g. 'nist-800-53-rev5-moderate')")
    control_id: str = Field(description="Control ID within the framework")
    control_title: str | None = Field(default=None)
    status: DiffStatus = Field(description="Diff classification")

    base_severity: GapSeverity | None = Field(
        default=None,
        description="Severity in base report (None if gap was absent in base)",
    )
    head_severity: GapSeverity | None = Field(
        default=None,
        description="Severity in head report (None if gap was absent in head)",
    )

    base_priority: float | None = Field(default=None)
    head_priority: float | None = Field(default=None)

    # Optional context fields so markdown/GitHub renderers have everything
    # they need without cross-referencing base/head reports.
    gap_description: str | None = Field(default=None)
    remediation_guidance: str | None = Field(default=None)


class GapDiffSummary(EvidentiaModel):
    """Aggregate counts per diff status — for quick CI decision-making."""

    closed: int = Field(default=0, description="Number of gaps resolved")
    opened: int = Field(default=0, description="Number of new gaps (regressions)")
    severity_increased: int = Field(default=0)
    severity_decreased: int = Field(default=0)
    unchanged: int = Field(default=0)

    @property
    def total_changes(self) -> int:
        """Entries whose status is not 'unchanged'."""
        return self.closed + self.opened + self.severity_increased + self.severity_decreased

    @property
    def is_regression(self) -> bool:
        """``True`` when head has more gaps or worse severities than base."""
        return self.opened > 0 or self.severity_increased > 0


class GapDiff(EvidentiaModel):
    """A full gap-diff document comparing two GapAnalysisReport snapshots."""

    id: str = Field(default_factory=new_id)
    generated_at: str = Field(
        default_factory=lambda: utc_now().isoformat(),
        description="ISO 8601 timestamp when this diff was generated",
    )

    base_organization: str = Field(description="Organization name from base report")
    base_inventory_source: str | None = Field(default=None)
    head_organization: str = Field(description="Organization name from head report")
    head_inventory_source: str | None = Field(default=None)

    frameworks_analyzed: list[str] = Field(
        description="Union of frameworks analyzed in either report",
    )

    summary: GapDiffSummary = Field(
        default_factory=GapDiffSummary,
        description="Per-status aggregate counts",
    )

    entries: list[GapDiffEntry] = Field(
        default_factory=list,
        description="Every gap key present in base or head (or both)",
    )

    @property
    def opened_entries(self) -> list[GapDiffEntry]:
        return [e for e in self.entries if e.status == "opened"]

    @property
    def closed_entries(self) -> list[GapDiffEntry]:
        return [e for e in self.entries if e.status == "closed"]

    @property
    def severity_increased_entries(self) -> list[GapDiffEntry]:
        return [e for e in self.entries if e.status == "severity_increased"]

    @property
    def severity_decreased_entries(self) -> list[GapDiffEntry]:
        return [e for e in self.entries if e.status == "severity_decreased"]
