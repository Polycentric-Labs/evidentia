"""FAIR Monte Carlo simulation (v0.7.12 P1.5 G4.1).

The v0.7.11 P1.5 G4 (``open_fair.py``) ships deterministic
PERT-mean expected-value quantification — fast, repeatable, but
collapses uncertainty into a single number. This module adds the
canonical Monte Carlo simulation form: draw N samples per FAIR
factor from its Beta-PERT distribution, compute ALE per
iteration, aggregate the distribution + percentiles.

Beta-PERT sampling (per the FAIR-U canonical formulation):

    α = 1 + 4 × (most_likely - low) / (high - low)
    β = 1 + 4 × (high - most_likely) / (high - low)
    sample = low + (high - low) × Beta(α, β)

For scalar inputs, the sample is just the scalar (zero variance).
For PERTRange inputs, each iteration draws an independent sample.

Per-iteration ALE: ``LEF × LM = (TEF × Vulnerability) ×
(PrimaryLoss + SecondaryLoss)``. This is the same formula the
deterministic path uses; only the inputs differ.

The aggregate distribution exposes:

  - P10 / P50 / P90 percentiles (the FAIR canonical reporting set)
  - Mean + std-dev (for parametric framing)
  - Markdown box-and-whisker rendering
  - Optional CSV export of all per-iteration ALE values

Stdlib only — no numpy/scipy dependency. ``random.Random``'s
``betavariate(α, β)`` provides the Beta sampling; ``statistics``
provides quantiles + mean + stdev.

Usage::

    from evidentia_core.risk_quant.monte_carlo import simulate_ale

    result = simulate_ale(scenario, iterations=10000, seed=42)
    print(result.markdown_box_whisker())
    result.to_csv("simulation.csv")
"""

from __future__ import annotations

import csv
import random
import statistics
from datetime import datetime
from pathlib import Path

from pydantic import Field, model_validator

from evidentia_core.models.common import (
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)
from evidentia_core.risk_quant.open_fair import (
    OpenFAIRScenario,
    PERTRange,
    RiskCategory,
    categorize_risk,
)

DEFAULT_ITERATIONS = 10_000


# ── Sampling primitive ─────────────────────────────────────────────


def _sample_pert(value: float | PERTRange, rng: random.Random) -> float:
    """Draw a sample from a scalar-or-PERTRange factor.

    Scalar values return unchanged (zero variance). PERTRange
    values are sampled via the Beta-PERT formulation above.

    Edge case: when ``low == most_likely == high``, the
    distribution is a degenerate point mass; returns the
    point value.
    """
    if isinstance(value, float | int):
        return float(value)
    low = value.low
    most_likely = value.most_likely
    high = value.high
    if high == low:
        # Degenerate; the validator already enforces low <=
        # most_likely <= high, so high == low implies all three
        # are equal.
        return float(low)
    span = high - low
    alpha = 1.0 + 4.0 * (most_likely - low) / span
    beta_param = 1.0 + 4.0 * (high - most_likely) / span
    return low + span * rng.betavariate(alpha, beta_param)


def _sample_ale(scenario: OpenFAIRScenario, rng: random.Random) -> float:
    """One-iteration ALE: (TEF × Vulnerability) × (PL + SL)."""
    tef = _sample_pert(scenario.tef, rng)
    vuln = _sample_pert(scenario.vulnerability, rng)
    pl = _sample_pert(scenario.primary_loss, rng)
    sl = _sample_pert(scenario.secondary_loss, rng)
    return (tef * vuln) * (pl + sl)


# ── Simulation result ──────────────────────────────────────────────


class SimulationResult(EvidentiaModel):
    """The output of a FAIR Monte Carlo simulation.

    Captures the per-iteration ALE samples + canonical aggregate
    statistics. The samples list itself is the source of truth;
    the percentiles + mean + stddev are derived for ergonomic
    access.
    """

    id: str = Field(default_factory=new_id)
    scenario_id: str = Field(description="ID of the OpenFAIRScenario this simulation ran against.")
    scenario_name: str = Field(
        description="Scenario name — duplicated here so reports + CSV exports stay self-contained."
    )
    iterations: int = Field(
        ge=1,
        description="Number of Monte Carlo iterations executed.",
    )
    seed: int | None = Field(
        default=None,
        description=("Random seed used. When set, the simulation is deterministic across runs (golden-file friendly)."),
    )
    samples: list[float] = Field(
        description=(
            "Per-iteration ALE samples ($). The full distribution "
            "is preserved here so callers can compute custom "
            "percentiles or render alternative visualizations."
        ),
    )
    p10: float = Field(description="10th-percentile ALE.")
    p50: float = Field(description="Median (50th-percentile) ALE.")
    p90: float = Field(description="90th-percentile ALE.")
    mean: float = Field(description="Sample mean ALE.")
    stddev: float = Field(description="Sample standard deviation.")
    risk_category_p50: RiskCategory = Field(
        description="FAIR risk band of the median ALE.",
    )

    # Auto-populated metadata
    created_at: datetime = Field(default_factory=utc_now)
    evidentia_version: str = Field(default_factory=current_version)

    @model_validator(mode="after")
    def _enforce_percentile_ordering(self) -> SimulationResult:
        """P10 <= P50 <= P90 invariant. Sanity check on
        construction; would only fail if samples were degenerate."""
        if not (self.p10 <= self.p50 <= self.p90):
            raise ValueError(
                f"SimulationResult percentiles must satisfy "
                f"p10 <= p50 <= p90; got p10={self.p10}, "
                f"p50={self.p50}, p90={self.p90}"
            )
        return self

    def markdown_box_whisker(self) -> str:
        """Deterministic Markdown rendering of the percentile
        distribution. Suitable for embedding in OSCAL AR
        back-matter or CHANGELOG release notes."""
        lines: list[str] = []
        lines.append(f"# FAIR Monte Carlo Simulation — {self.scenario_name}")
        lines.append("")
        lines.append(f"_{self.iterations:,} iterations" + (f", seed={self.seed}_" if self.seed is not None else "_"))
        lines.append("")
        lines.append("| Statistic | ALE ($) |")
        lines.append("|---|---|")
        lines.append(f"| P10  | {_money(self.p10)} |")
        lines.append(f"| P50  | {_money(self.p50)} |")
        lines.append(f"| P90  | {_money(self.p90)} |")
        lines.append(f"| Mean | {_money(self.mean)} |")
        lines.append(f"| Std-dev | {_money(self.stddev)} |")
        lines.append(f"| Risk band (P50) | **{self.risk_category_p50}** |")
        lines.append("")
        # Simple ASCII box-and-whisker
        lines.append("```")
        lines.append(self._render_ascii_box())
        lines.append("```")
        return "\n".join(lines)

    def _render_ascii_box(self, width: int = 60) -> str:
        """80-col-friendly ASCII box-and-whisker for the
        P10/P50/P90 distribution."""
        if self.p90 == self.p10:
            return f"{_money(self.p50)} (degenerate distribution)"
        scale = (self.p90 - self.p10) / float(width)
        if scale == 0:
            return f"{_money(self.p50)} (zero variance)"
        # Position P10 at col 0, P90 at col width
        p50_col = int((self.p50 - self.p10) / scale)
        p50_col = max(0, min(width, p50_col))
        bar = ["─"] * (width + 1)
        bar[0] = "├"
        bar[width] = "┤"
        bar[p50_col] = "┼"
        return (
            f"P10={_money(self.p10):>10}  {''.join(bar)}  "
            f"P90={_money(self.p90)}\n"
            f"{' ' * (15 + p50_col)}P50={_money(self.p50)}"
        )

    def to_csv(self, path: Path | str) -> Path:
        """Write the per-iteration ALE samples to a CSV file.

        Columns: ``iteration``, ``ale``. Header row included.
        Returns the resolved Path of the written file.
        """
        out_path = Path(path).expanduser().resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.writer(fh)
            writer.writerow(["iteration", "ale"])
            for i, ale in enumerate(self.samples, start=1):
                writer.writerow([i, ale])
        return out_path


def _money(amount: float) -> str:
    """Currency formatter consistent with open_fair._format_currency."""
    if amount >= 1_000_000:
        return f"${amount / 1_000_000:.2f}M"
    if amount >= 1_000:
        return f"${amount / 1_000:.1f}k"
    return f"${amount:.2f}"


# ── Public API ─────────────────────────────────────────────────────


def simulate_ale(
    scenario: OpenFAIRScenario,
    iterations: int = DEFAULT_ITERATIONS,
    seed: int | None = None,
) -> SimulationResult:
    """Run a Monte Carlo simulation on an OpenFAIRScenario.

    Args:
        scenario: The scenario to simulate. Each PERTRange factor
            is sampled per iteration; scalar factors contribute
            zero variance.
        iterations: Number of independent Monte Carlo iterations.
            Default 10,000 (the FAIR-U recommended convergence
            point — typical % error in P10/P50/P90 percentiles
            stabilizes well below this count).
        seed: Optional random seed for deterministic runs. When
            None, ``random.SystemRandom()`` is NOT used —
            ``random.Random()`` defaults to a system-time-derived
            seed which gives different results per call. Pass an
            explicit int for golden-file tests + reproducible
            audit-trail outputs.

    Returns:
        :class:`SimulationResult` capturing all per-iteration
        samples + canonical aggregate statistics.

    Raises:
        ValueError: when ``iterations < 1`` or scenario is invalid.
    """
    if iterations < 1:
        raise ValueError(f"iterations must be >= 1; got {iterations}")
    rng = random.Random(seed)
    samples = [_sample_ale(scenario, rng) for _ in range(iterations)]

    p10, p50, p90 = _percentiles(samples, [0.10, 0.50, 0.90])
    mean = statistics.fmean(samples)
    stddev = statistics.stdev(samples) if iterations >= 2 else 0.0
    return SimulationResult.model_validate(
        {
            "scenario_id": scenario.id,
            "scenario_name": scenario.name,
            "iterations": iterations,
            "seed": seed,
            "samples": samples,
            "p10": p10,
            "p50": p50,
            "p90": p90,
            "mean": mean,
            "stddev": stddev,
            "risk_category_p50": categorize_risk(p50),
        }
    )


def _percentiles(samples: list[float], qs: list[float]) -> tuple[float, ...]:
    """Linear-interpolation percentile estimator.

    Mirrors ``numpy.percentile(method='linear')`` for portability.
    """
    if not samples:
        raise ValueError("Cannot compute percentiles of empty samples")
    sorted_samples = sorted(samples)
    n = len(sorted_samples)
    out: list[float] = []
    for q in qs:
        if not 0.0 <= q <= 1.0:
            raise ValueError(f"Percentile must be in [0, 1]; got {q}")
        if n == 1:
            out.append(sorted_samples[0])
            continue
        # Linear interpolation between adjacent samples
        k = (n - 1) * q
        f = int(k)
        c = min(f + 1, n - 1)
        d = k - f
        out.append(sorted_samples[f] * (1 - d) + sorted_samples[c] * d)
    return tuple(out)


def generate_monte_carlo_report(
    scenarios_with_results: list[tuple[OpenFAIRScenario, SimulationResult]],
) -> str:
    """Aggregate Markdown report for multiple simulated scenarios.

    Sorted by P50 ALE descending — biggest exposure first. This
    is the canonical risk-officer reading order (action-priority).

    Args:
        scenarios_with_results: List of ``(scenario, result)``
            tuples. The result must have been computed against
            its paired scenario (no cross-validation here).

    Returns:
        Markdown string suitable for ``docs/`` embedding or
        ``risk quantify --method fair-mc`` console output.
    """
    if not scenarios_with_results:
        return "# FAIR Monte Carlo Risk Quantification Report\n\nNo scenarios.\n"
    sorted_results = sorted(scenarios_with_results, key=lambda pair: -pair[1].p50)
    lines: list[str] = ["# FAIR Monte Carlo Risk Quantification Report", ""]
    lines.append("Sorted by P50 ALE descending.")
    lines.append("")
    lines.append("| # | Scenario | P10 | P50 | P90 | Risk band (P50) |")
    lines.append("|---|---|---|---|---|---|")
    for i, (sc, res) in enumerate(sorted_results, start=1):
        lines.append(
            f"| {i} | {sc.name} | "
            f"{_money(res.p10)} | {_money(res.p50)} | "
            f"{_money(res.p90)} | **{res.risk_category_p50}** |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    for _sc, res in sorted_results:
        lines.append(res.markdown_box_whisker())
        lines.append("")
    return "\n".join(lines)
