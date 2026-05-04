"""KRI / KPI / KGI metric primitives (v0.7.11 P1.5 G3).

Three classes of risk-management metrics, distinct by what they
measure + when they signal:

  - **KRI** (Key Risk Indicator) — *leading* metric warning that
    risk is approaching or exceeding its tolerance threshold.
    Example: "Failed-login rate per 1,000 logins crossed 3.0
    last week" warns of credential-stuffing pressure before any
    actual breach.
  - **KPI** (Key Performance Indicator) — *lagging* metric
    measuring how effectively a control or process is being
    executed. Example: "Mean-time-to-patch HIGH CVE = 9.4 days"
    measures the patch-management process, not the risk itself.
  - **KGI** (Key Goal Indicator) — *outcome* metric measuring
    whether the risk-management strategy is achieving its goal.
    Example: "Zero material data breaches in the last 12 months"
    measures the strategic outcome.

Each metric ties back to a documented owner (operator-supplied;
the v0.7.10 governance Owner schema can be cross-referenced via
the optional ``owner_email`` field). Threshold semantics let the
``governance metrics report`` surface flag breaches:

  - ``warning_threshold`` — below this is "comfortable"; at-or-
    above is "watch"
  - ``critical_threshold`` — at-or-above is "breach; act"

Direction matters: for some metrics higher = worse (failed-login
rate); for others higher = better (patch coverage %). The
``direction`` enum disambiguates.

Public surface:

  - :class:`MetricKind` enum (KRI / KPI / KGI)
  - :class:`MetricDirection` enum (HIGHER_IS_WORSE / HIGHER_IS_BETTER)
  - :class:`MetricObservation` — one timestamped value
  - :class:`Metric` — a metric definition + history
  - :func:`evaluate_metric` — compute the current state
    (COMFORTABLE / WATCH / BREACH) from the latest observation
  - :func:`generate_metrics_report` — Markdown dashboard report
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum

from pydantic import Field

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class MetricKind(str, Enum):
    """KRI / KPI / KGI classification."""

    KRI = "kri"
    KPI = "kpi"
    KGI = "kgi"


class MetricDirection(str, Enum):
    """Whether higher values are worse or better.

    For KRIs (risk indicators), higher is typically worse. For
    KPIs measuring coverage / completeness / availability, higher
    is typically better. For KGIs, the direction depends on the
    specific outcome being measured.
    """

    HIGHER_IS_WORSE = "higher_is_worse"
    HIGHER_IS_BETTER = "higher_is_better"


class MetricStatus(str, Enum):
    """Current evaluation status."""

    COMFORTABLE = "comfortable"
    WATCH = "watch"
    BREACH = "breach"
    NO_DATA = "no_data"


class MetricObservation(EvidentiaModel):
    """One timestamped observation of a metric."""

    observed_at: date = Field(
        description="Date the observation was recorded."
    )
    value: float = Field(
        description="Numeric value. Units defined by the parent Metric."
    )
    note: str | None = Field(
        default=None,
        description="Optional contextual note (e.g., 'Q3 backlog spike').",
    )


class Metric(EvidentiaModel):
    """A KRI / KPI / KGI metric definition + observation history.

    Operators define metrics once + add observations over time
    via the ``governance metrics observe`` CLI verb. The current
    state is derived from the latest observation against the
    documented thresholds.
    """

    id: str = Field(default_factory=new_id)
    name: str = Field(
        description="Human-readable metric name (e.g., 'Failed-login rate')."
    )
    description: str = Field(
        description=(
            "What this metric measures + why it's tracked. Should "
            "include the unit (per-day, percentage, count, etc.)."
        )
    )
    kind: MetricKind = Field(
        description="KRI / KPI / KGI classification."
    )
    direction: MetricDirection = Field(
        description="Whether higher values are worse or better."
    )
    unit: str = Field(
        description="Measurement unit (e.g., 'per 1,000 logins', 'days', '%')."
    )
    owner_email: str | None = Field(
        default=None,
        description=(
            "Email of the metric owner. Cross-references the v0.7.10 "
            "governance Owner schema when present."
        ),
    )
    warning_threshold: float | None = Field(
        default=None,
        description=(
            "Threshold above which (HIGHER_IS_WORSE) or below which "
            "(HIGHER_IS_BETTER) the metric is in WATCH state. "
            "None = no threshold (no automatic flagging)."
        ),
    )
    critical_threshold: float | None = Field(
        default=None,
        description=(
            "Threshold above which (HIGHER_IS_WORSE) or below which "
            "(HIGHER_IS_BETTER) the metric is in BREACH state."
        ),
    )
    observations: list[MetricObservation] = Field(
        default_factory=list,
        description="Time-ordered observations. Newest tracked separately.",
    )
    notes: str | None = Field(
        default=None,
        description="Free-text notes about methodology, source data, etc.",
    )

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    evidentia_version: str = Field(default_factory=current_version)


def evaluate_metric(metric: Metric) -> MetricStatus:
    """Return the current MetricStatus from the latest observation.

    Logic:

      - No observations → ``NO_DATA``
      - HIGHER_IS_WORSE: value >= critical → BREACH;
        value >= warning → WATCH; else COMFORTABLE
      - HIGHER_IS_BETTER: value <= critical → BREACH;
        value <= warning → WATCH; else COMFORTABLE
      - Missing thresholds: thresholds default to None which
        means "never trigger". A metric with no critical_threshold
        cannot reach BREACH.
    """
    if not metric.observations:
        return MetricStatus.NO_DATA
    # Latest by observed_at; ties broken by list order.
    latest = max(metric.observations, key=lambda o: o.observed_at)
    value = latest.value

    higher_is_worse = metric.direction == MetricDirection.HIGHER_IS_WORSE.value

    if higher_is_worse:
        if (
            metric.critical_threshold is not None
            and value >= metric.critical_threshold
        ):
            return MetricStatus.BREACH
        if (
            metric.warning_threshold is not None
            and value >= metric.warning_threshold
        ):
            return MetricStatus.WATCH
        return MetricStatus.COMFORTABLE
    # HIGHER_IS_BETTER
    if (
        metric.critical_threshold is not None
        and value <= metric.critical_threshold
    ):
        return MetricStatus.BREACH
    if (
        metric.warning_threshold is not None
        and value <= metric.warning_threshold
    ):
        return MetricStatus.WATCH
    return MetricStatus.COMFORTABLE


def generate_metrics_report(metrics: list[Metric]) -> str:
    """Generate a Markdown dashboard report across a list of metrics.

    Sections:

      1. Executive summary — counts per status (BREACH count first
         so HIGH-priority items lead)
      2. Per-kind breakdown (KRI / KPI / KGI tables; each shows
         name + latest value + status + threshold)
      3. Trend hint (latest vs second-latest observation per metric
         when available)

    Output is deterministic — same input produces the same output
    character-for-character. Empty input renders a minimal report.
    """
    sections: list[str] = []
    if not metrics:
        return (
            "# Governance Metrics Dashboard\n\n"
            "_No metrics defined. Use `evidentia governance metrics "
            "add` to create the first metric._\n"
        )

    # ── §1 Executive summary ─────────────────────────────────────
    status_counts: dict[str, int] = {
        MetricStatus.BREACH.value: 0,
        MetricStatus.WATCH.value: 0,
        MetricStatus.COMFORTABLE.value: 0,
        MetricStatus.NO_DATA.value: 0,
    }
    for m in metrics:
        status_counts[evaluate_metric(m).value] += 1

    breach = status_counts[MetricStatus.BREACH.value]
    watch = status_counts[MetricStatus.WATCH.value]
    comfortable = status_counts[MetricStatus.COMFORTABLE.value]
    no_data = status_counts[MetricStatus.NO_DATA.value]

    summary_callout = ""
    if breach > 0:
        summary_callout = (
            f"> ⚠️ **{breach} metric(s) in BREACH state.** Review "
            "the Per-kind sections below; documented escalation "
            "paths apply.\n\n"
        )

    sections.append(
        "# Governance Metrics Dashboard\n\n"
        f"_Aggregate view across {len(metrics)} metric(s) — "
        "KRI / KPI / KGI classification per IIA + COSO ERM "
        "frameworks._\n\n"
        f"{summary_callout}"
        "| Status | Count |\n"
        "| --- | --- |\n"
        f"| BREACH | {breach} |\n"
        f"| WATCH | {watch} |\n"
        f"| COMFORTABLE | {comfortable} |\n"
        f"| NO_DATA | {no_data} |\n"
        f"| **Total** | **{len(metrics)}** |\n"
    )

    # ── §2 Per-kind breakdown ────────────────────────────────────
    for kind in (MetricKind.KRI, MetricKind.KPI, MetricKind.KGI):
        kind_metrics = sorted(
            (m for m in metrics if m.kind == kind.value),
            key=lambda m: m.name.lower(),
        )
        if not kind_metrics:
            continue
        rows = []
        for m in kind_metrics:
            status = evaluate_metric(m).value
            latest_value = (
                f"{max(m.observations, key=lambda o: o.observed_at).value}"
                if m.observations
                else "_no data_"
            )
            warn = (
                str(m.warning_threshold)
                if m.warning_threshold is not None
                else "—"
            )
            crit = (
                str(m.critical_threshold)
                if m.critical_threshold is not None
                else "—"
            )
            rows.append(
                f"| {m.name} | {latest_value} {m.unit} | {status} | "
                f"{warn} / {crit} | {m.owner_email or '—'} |"
            )
        sections.append(
            f"## {kind.value.upper()} — {_kind_narrative(kind.value)}\n\n"
            "| Name | Latest | Status | Warn / Crit | Owner |\n"
            "| --- | --- | --- | --- | --- |\n"
            + "\n".join(rows)
            + "\n"
        )

    return "\n".join(sections)


def _kind_narrative(kind_value: str) -> str:
    """Map kind enum value to a one-line narrative."""
    return {
        "kri": "Key Risk Indicators (leading metrics)",
        "kpi": "Key Performance Indicators (lagging process metrics)",
        "kgi": "Key Goal Indicators (outcome metrics)",
    }.get(kind_value, "metric")
