"""CONMON control health scoring (v0.9.3 P1.3).

Aggregate metrics over a CONMON state file: per-framework counts of
cycles in each attention bucket (current / due_soon / overdue), plus
a roll-up across all frameworks.

Pure-function library; no I/O outside reading the state file via
:func:`evidentia_core.conmon.daemon.load_state_file`. Wired into:

- ``evidentia conmon health`` CLI (v0.9.3 P1.3)
- ``GET /api/conmon/health`` REST endpoint (v0.9.3 P1.3)

Emits :attr:`EventAction.CONMON_HEALTH_REPORT_GENERATED` at the
caller (CLI / REST) layer, not inside this library — matches the
v0.9.0 P3 convention where calendar.py is silent and the CLI fires
the audit event.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

from evidentia_core.conmon.calendar import (
    CycleAttentionState,
    derive_status,
    get_cadence,
    next_due,
)
from evidentia_core.conmon.daemon import load_state_file


@dataclass(frozen=True)
class FrameworkHealth:
    """Per-framework attention-bucket counts.

    Note: there is no ``unknown`` per-framework count by design —
    unknown slugs (cadences in the state file with no registered
    cadence) have no framework attribution, so they roll up to
    :attr:`HealthReport.unknown_slugs` instead (a flat list at the
    report level). v0.9.3 F-V93-Q1 review fix removed a dead-code
    ``per_fw_unknown`` dict that was always empty.
    """

    framework: str
    total: int
    current: int
    due_soon: int
    overdue: int

    @property
    def health_score(self) -> float:
        """Fraction of tracked cycles that aren't currently in trouble.

        Returns 1.0 for "all current", 0.0 for "everything overdue".
        Due-soon is counted as healthy because it's still in the
        operator's window of action; overdue is the auditor-visible
        failure mode.
        """
        denom = self.current + self.due_soon + self.overdue
        if denom == 0:
            return 1.0
        return (self.current + self.due_soon) / denom


@dataclass(frozen=True)
class HealthReport:
    """Roll-up across all tracked frameworks."""

    today: date
    window_days: int
    frameworks: list[FrameworkHealth] = field(default_factory=list)
    unknown_slugs: list[str] = field(default_factory=list)

    @property
    def total_cycles(self) -> int:
        return sum(fh.total for fh in self.frameworks)

    @property
    def total_overdue(self) -> int:
        return sum(fh.overdue for fh in self.frameworks)

    @property
    def total_due_soon(self) -> int:
        return sum(fh.due_soon for fh in self.frameworks)

    @property
    def total_current(self) -> int:
        return sum(fh.current for fh in self.frameworks)

    @property
    def overall_health_score(self) -> float:
        """Aggregate health across all frameworks. Weighted by cycle
        count — frameworks with more cycles contribute more to the
        score."""
        denom = self.total_current + self.total_due_soon + self.total_overdue
        if denom == 0:
            return 1.0
        return (self.total_current + self.total_due_soon) / denom

    def to_dict(self) -> dict[str, object]:
        """JSON-serializable representation. Suitable for REST output."""
        return {
            "today": self.today.isoformat(),
            "window_days": self.window_days,
            "total_cycles": self.total_cycles,
            "total_overdue": self.total_overdue,
            "total_due_soon": self.total_due_soon,
            "total_current": self.total_current,
            "overall_health_score": self.overall_health_score,
            "frameworks": [
                {**asdict(fh), "health_score": fh.health_score}
                for fh in self.frameworks
            ],
            "unknown_slugs": list(self.unknown_slugs),
        }


def compute_health(
    state: dict[str, date],
    today: date,
    window_days: int = 14,
    framework_filter: str | None = None,
) -> HealthReport:
    """Compute attention-bucket counts from a slug -> last_completed
    mapping. Pure function; suitable for both CLI + REST.

    Args:
        state: ``{cadence_slug: last_completed_date}`` mapping;
            typically loaded via
            :func:`evidentia_core.conmon.daemon.load_state_file`.
        today: Reference date for "next-due in window?" calculation.
        window_days: Due-soon window in days. Default 14.
        framework_filter: Optional framework identifier to restrict
            the report to a single framework (e.g.,
            ``"nist-800-53-rev5"``). Other framework cycles are
            excluded from totals.

    Returns:
        A :class:`HealthReport` with one :class:`FrameworkHealth`
        entry per framework present in the input.
    """
    if window_days < 0:
        raise ValueError(f"window_days must be >= 0; got {window_days}")

    per_fw_current: dict[str, int] = {}
    per_fw_due_soon: dict[str, int] = {}
    per_fw_overdue: dict[str, int] = {}
    unknown_slugs: list[str] = []

    for slug, last_completed in state.items():
        cadence = get_cadence(slug)
        if cadence is None:
            unknown_slugs.append(slug)
            continue
        if framework_filter is not None and cadence.framework != framework_filter:
            continue
        due = next_due(slug, last_completed)
        attention = derive_status(due, today, window_days=window_days)
        fw = cadence.framework
        if attention == CycleAttentionState.OVERDUE:
            per_fw_overdue[fw] = per_fw_overdue.get(fw, 0) + 1
        elif attention == CycleAttentionState.DUE_SOON:
            per_fw_due_soon[fw] = per_fw_due_soon.get(fw, 0) + 1
        else:
            per_fw_current[fw] = per_fw_current.get(fw, 0) + 1

    frameworks: list[FrameworkHealth] = []
    all_fws = set(per_fw_current) | set(per_fw_due_soon) | set(per_fw_overdue)
    for fw in sorted(all_fws):
        current = per_fw_current.get(fw, 0)
        due_soon = per_fw_due_soon.get(fw, 0)
        overdue = per_fw_overdue.get(fw, 0)
        frameworks.append(
            FrameworkHealth(
                framework=fw,
                total=current + due_soon + overdue,
                current=current,
                due_soon=due_soon,
                overdue=overdue,
            )
        )

    return HealthReport(
        today=today,
        window_days=window_days,
        frameworks=frameworks,
        unknown_slugs=unknown_slugs,
    )


def health_from_state_file(
    state_file: Path,
    today: date | None = None,
    window_days: int = 14,
    framework_filter: str | None = None,
) -> HealthReport:
    """Convenience: load state file + compute health in one call."""
    state = load_state_file(state_file)
    return compute_health(
        state,
        today if today is not None else date.today(),
        window_days=window_days,
        framework_filter=framework_filter,
    )
