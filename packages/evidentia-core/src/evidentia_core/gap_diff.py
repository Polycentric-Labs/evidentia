"""Core gap-diff computation and rendering.

The comparison key is ``(framework, control_id)`` — a given control is
"the same gap" across reports even if its UUID differs. The diff
classifies entries into five buckets:

- **closed**: in base, absent in head (or head-status is CLOSED)
- **opened**: absent in base, in head
- **severity_increased** / **severity_decreased**: both reports, rank differs
- **unchanged**: both reports, same rank

Usage from CLI::

    from evidentia_core.gap_diff import compute_gap_diff, render_markdown

    diff = compute_gap_diff(base_report, head_report)
    print(render_markdown(diff))
    if diff.summary.is_regression:
        sys.exit(1)
"""

from __future__ import annotations

import logging

from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapStatus,
)
from evidentia_core.models.gap_diff import (
    GapDiff,
    GapDiffEntry,
    GapDiffSummary,
    severity_rank,
)

logger = logging.getLogger(__name__)


def _gap_key(gap: ControlGap) -> tuple[str, str]:
    """Canonical identity key for a gap across reports.

    Framework + control_id is the right level — ``gap.id`` is a UUID
    that changes between reports even when they describe the same gap.
    Using normalized form so ``AC-2(1)`` in base and ``ac-2.1`` in head
    match correctly.
    """
    from evidentia_core.models.catalog import _normalize_control_id

    return (gap.framework, _normalize_control_id(gap.control_id))


def _is_open(gap: ControlGap) -> bool:
    """Treat REMEDIATED / ACCEPTED / NOT_APPLICABLE gaps as 'no longer open'.

    Only ``OPEN`` and ``IN_PROGRESS`` count as genuine gaps for diff
    purposes. An ACCEPTED gap is one where the org formally signed off on
    the residual risk (risk acceptance memo) — showing up "fresh" in the
    head report isn't a regression, it's still accepted.

    v0.3.1: handle both in-memory path (``gap.status`` is a ``GapStatus``
    enum instance) and JSON-roundtrip path (``gap.status`` is the
    enum's string value) — Pydantic's ``use_enum_values=True`` only
    coerces on serialize, not on in-memory construction, so
    ``str(enum)`` naively returns ``"GapStatus.OPEN"`` rather than
    ``"open"``. The CLI goes through a JSON save/load between
    analyze and diff so it accidentally worked; direct library
    usage did not. Normalizing to the enum ``.value`` here covers
    both paths.
    """
    status_value = gap.status.value if isinstance(gap.status, GapStatus) else str(gap.status)
    return status_value in (
        GapStatus.OPEN.value,
        GapStatus.IN_PROGRESS.value,
    )


def compute_gap_diff(
    base: GapAnalysisReport,
    head: GapAnalysisReport,
) -> GapDiff:
    """Compute the structural diff between two gap reports.

    Arguments:
        base: Earlier report (e.g. ``main`` branch state).
        head: Later report (e.g. ``PR`` branch state).

    Returns:
        :class:`GapDiff` with entries sorted: opened first (highest
        priority to surface), severity_increased second, severity_decreased
        third, closed fourth, unchanged last.
    """
    # Index both sides by (framework, control_id) normalized key
    base_by_key: dict[tuple[str, str], ControlGap] = {_gap_key(g): g for g in base.gaps if _is_open(g)}
    head_by_key: dict[tuple[str, str], ControlGap] = {_gap_key(g): g for g in head.gaps if _is_open(g)}

    all_keys = set(base_by_key) | set(head_by_key)
    entries: list[GapDiffEntry] = []

    for key in all_keys:
        base_gap = base_by_key.get(key)
        head_gap = head_by_key.get(key)

        if base_gap is not None and head_gap is None:
            # Gap fixed.
            entries.append(
                GapDiffEntry(
                    framework=base_gap.framework,
                    control_id=base_gap.control_id,
                    control_title=base_gap.control_title,
                    status="closed",
                    base_severity=base_gap.gap_severity,
                    head_severity=None,
                    base_priority=base_gap.priority_score,
                    head_priority=None,
                    gap_description=base_gap.gap_description,
                    remediation_guidance=base_gap.remediation_guidance,
                )
            )
        elif base_gap is None and head_gap is not None:
            # Regression — new gap.
            entries.append(
                GapDiffEntry(
                    framework=head_gap.framework,
                    control_id=head_gap.control_id,
                    control_title=head_gap.control_title,
                    status="opened",
                    base_severity=None,
                    head_severity=head_gap.gap_severity,
                    base_priority=None,
                    head_priority=head_gap.priority_score,
                    gap_description=head_gap.gap_description,
                    remediation_guidance=head_gap.remediation_guidance,
                )
            )
        elif base_gap is not None and head_gap is not None:
            # Both sides — check if severity changed.
            base_rank = severity_rank(base_gap.gap_severity)
            head_rank = severity_rank(head_gap.gap_severity)
            if head_rank > base_rank:
                status = "severity_increased"
            elif head_rank < base_rank:
                status = "severity_decreased"
            else:
                status = "unchanged"
            entries.append(
                GapDiffEntry(
                    framework=head_gap.framework,
                    control_id=head_gap.control_id,
                    control_title=head_gap.control_title,
                    status=status,
                    base_severity=base_gap.gap_severity,
                    head_severity=head_gap.gap_severity,
                    base_priority=base_gap.priority_score,
                    head_priority=head_gap.priority_score,
                    gap_description=head_gap.gap_description,
                    remediation_guidance=head_gap.remediation_guidance,
                )
            )

    # Sort: opened → severity_increased → severity_decreased → closed → unchanged.
    # Within each group, sort by head_priority (highest priority first).
    sort_order = {
        "opened": 0,
        "severity_increased": 1,
        "severity_decreased": 2,
        "closed": 3,
        "unchanged": 4,
    }
    entries.sort(
        key=lambda e: (
            sort_order.get(e.status, 99),
            -(e.head_priority or e.base_priority or 0.0),
        )
    )

    # Summary counts
    summary = GapDiffSummary(
        closed=sum(1 for e in entries if e.status == "closed"),
        opened=sum(1 for e in entries if e.status == "opened"),
        severity_increased=sum(1 for e in entries if e.status == "severity_increased"),
        severity_decreased=sum(1 for e in entries if e.status == "severity_decreased"),
        unchanged=sum(1 for e in entries if e.status == "unchanged"),
    )

    frameworks = sorted(set(base.frameworks_analyzed) | set(head.frameworks_analyzed))

    logger.info(
        "Gap diff: +%d opened, -%d closed, ▲%d sev-up, ▼%d sev-down, %d unchanged",
        summary.opened,
        summary.closed,
        summary.severity_increased,
        summary.severity_decreased,
        summary.unchanged,
    )

    return GapDiff(
        base_organization=base.organization,
        base_inventory_source=base.inventory_source,
        head_organization=head.organization,
        head_inventory_source=head.inventory_source,
        frameworks_analyzed=frameworks,
        summary=summary,
        entries=entries,
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_markdown(diff: GapDiff) -> str:
    """Render a GapDiff as a Markdown document — suitable for PR comments.

    The output is intentionally structured so that the first few lines
    are an at-a-glance summary (scannable in a notification email) and
    the rest drills into specifics.
    """
    s = diff.summary
    verdict = (
        "❌ **Compliance regression detected**"
        if s.is_regression
        else ("✅ **No compliance regression**" if s.total_changes > 0 else "No changes")
    )
    lines: list[str] = [
        "# Evidentia gap diff",
        "",
        verdict,
        "",
        f"**Frameworks analyzed:** {', '.join(diff.frameworks_analyzed)}",
        "",
        "## Summary",
        "",
        "| Status | Count |",
        "|---|---:|",
        f"| 🆕 Opened (regressions) | **{s.opened}** |",
        f"| 📈 Severity increased | **{s.severity_increased}** |",
        f"| 📉 Severity decreased | {s.severity_decreased} |",
        f"| ✅ Closed | {s.closed} |",
        f"| ➖ Unchanged | {s.unchanged} |",
        "",
    ]

    if diff.opened_entries:
        lines.append("## 🆕 Opened gaps (regressions)")
        lines.append("")
        lines.append("| Framework | Control | Severity |")
        lines.append("|---|---|---|")
        for e in diff.opened_entries[:50]:
            lines.append(
                f"| `{e.framework}` | **{e.control_id}** — {e.control_title or ''} | {e.head_severity or '-'} |"
            )
        if len(diff.opened_entries) > 50:
            lines.append(f"| *…and {len(diff.opened_entries) - 50} more* | | |")
        lines.append("")

    if diff.severity_increased_entries:
        lines.append("## 📈 Severity increased")
        lines.append("")
        lines.append("| Framework | Control | Base → Head |")
        lines.append("|---|---|---|")
        for e in diff.severity_increased_entries[:25]:
            lines.append(
                f"| `{e.framework}` | **{e.control_id}** — {e.control_title or ''} | "
                f"{e.base_severity} → **{e.head_severity}** |"
            )
        lines.append("")

    if diff.closed_entries:
        lines.append("## ✅ Closed gaps")
        lines.append("")
        lines.append(f"{len(diff.closed_entries)} gaps resolved since base.")
        if len(diff.closed_entries) <= 10:
            for e in diff.closed_entries:
                lines.append(f"- `{e.framework}`:**{e.control_id}** — {e.control_title or ''}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by `evidentia gap diff`*")
    return "\n".join(lines)


def render_github_annotations(diff: GapDiff) -> str:
    """Render a GapDiff as GitHub Actions workflow-command lines.

    Each opened gap and each severity-increase becomes a ``::error::`` or
    ``::warning::`` line, which GitHub surfaces inline in the Actions tab
    and on the Checks page. Closed gaps emit ``::notice::`` for positive
    acknowledgment.
    """
    lines: list[str] = []
    for e in diff.opened_entries:
        lines.append(
            f"::error title=New gap: {e.control_id}::"
            f"Framework {e.framework}: {e.control_title or e.control_id} "
            f"(severity: {e.head_severity})"
        )
    for e in diff.severity_increased_entries:
        lines.append(
            f"::warning title=Severity increased: {e.control_id}::"
            f"Framework {e.framework}: {e.base_severity} → {e.head_severity}"
        )
    for e in diff.closed_entries[:20]:  # cap to avoid flooding the log
        lines.append(
            f"::notice title=Gap closed: {e.control_id}::Framework {e.framework}: {e.control_title or e.control_id}"
        )
    if not lines:
        lines.append("::notice title=Evidentia::No changes in compliance posture.")
    return "\n".join(lines)
