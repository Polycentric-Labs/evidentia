"""Risk-generation router — SSE-streamed LLM risk statements.

``POST /api/risk/generate`` runs an asyncio fan-out over the selected
gaps, streaming per-gap progress events to the browser. The generator
reuses :class:`evidentia_ai.RiskStatementGenerator` (which already
exposes an async ``agenerate`` path via ``get_async_instructor_client``),
so offline-mode enforcement works identically to the CLI path.

Stream event shape (JSON-per-message, SSE ``event: message`` default)::

    {"phase": "start",    "total": 10}
    {"phase": "progress", "gap_id": "GAP-0001", "index": 0, "total": 10,
     "status": "generating"}
    {"phase": "progress", "gap_id": "GAP-0001", "index": 0, "total": 10,
     "status": "done", "risk": <RiskStatement>}
    {"phase": "error",    "gap_id": "GAP-0002", "detail": "..."}
    {"phase": "done",     "generated": 9, "failed": 1}
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator
from pathlib import Path

from evidentia_core.gap_store import (
    InvalidReportKeyError,
    load_report_by_key,
)
from evidentia_core.models.gap import ControlGap, GapAnalysisReport
from evidentia_core.risk_quant import OpenFAIRScenario
from evidentia_core.risk_quant.monte_carlo import (
    SimulationResult,
    simulate_ale,
)
from evidentia_core.risk_quant.open_fair import (
    categorize_risk,
    compute_ale,
    compute_lef,
    compute_loss_magnitude,
)
from evidentia_core.security.paths import PathTraversalError
from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sse_starlette.sse import EventSourceResponse

from evidentia_api.errors import api_error, error_responses
from evidentia_api.schemas import RiskGenerateRequest

logger = logging.getLogger(__name__)
router = APIRouter()

# Quantification methods accepted by ``POST /api/risk/quantify`` —
# mirrors the CLI ``risk quantify --method`` allow-list.
_QUANTIFY_METHODS: tuple[str, ...] = ("open-fair", "fair-mc")

# Upper bound on Monte Carlo iterations for the OPEN endpoint. The CLI
# defaults to 10,000 (FAIR-U recommended convergence point) with no
# hard cap, but the API surface is unauthenticated local-compute — a
# bound keeps a single request from monopolizing CPU. 1,000,000 is well
# above any sane convergence need while staying sub-second per scenario.
_MAX_ITERATIONS = 1_000_000


def _load_report(key: str) -> GapAnalysisReport:
    try:
        report = load_report_by_key(key)
    except (InvalidReportKeyError, PathTraversalError) as exc:
        # Both errors reflect client-supplied bad keys; normalize to
        # 400 (the F-V08-DAST-3 status normalization is unchanged)
        # with the structured detail object from
        # :mod:`evidentia_api.errors`.
        raise api_error(400, "invalid_id", str(exc), resource="gap_report") from exc
    if report is None:
        raise api_error(
            404,
            "not_found",
            f"Report {key} not found.",
            resource="gap_report",
            resource_id=key,
        )
    return report


def _pick_gaps(
    report: GapAnalysisReport,
    gap_ids: list[str] | None,
    top_n: int,
) -> list[ControlGap]:
    if gap_ids:
        wanted = set(gap_ids)
        return [g for g in report.gaps if g.id in wanted]
    return sorted(report.gaps, key=lambda g: g.priority_score, reverse=True)[:top_n]


async def _stream_risk_generation(
    report: GapAnalysisReport,
    selected_gaps: list[ControlGap],
    model: str | None,
    context_path: Path | None,
) -> AsyncIterator[str]:
    """Produce SSE-compatible JSON strings for each generation phase."""
    # Deferred import: RiskStatementGenerator pulls in LiteLLM which is
    # expensive to load on cold-start. The import only fires on the first
    # /api/risk/generate call.
    try:
        from evidentia_ai.risk_statements.generator import (
            RiskStatementGenerator,
        )
    except ImportError as e:  # pragma: no cover — evidentia-ai is required
        yield json.dumps({"phase": "error", "detail": f"evidentia-ai not available: {e}"})
        return

    total = len(selected_gaps)
    yield json.dumps({"phase": "start", "total": total})

    if total == 0:
        yield json.dumps({"phase": "done", "generated": 0, "failed": 0})
        return

    generator = RiskStatementGenerator(model=model) if model else RiskStatementGenerator()

    # Load context. RiskStatementGenerator requires a typed SystemContext;
    # there's no raw-dict overload. If no path given or the file can't be
    # parsed, the endpoint fails fast rather than generating risks with
    # empty org context (which produces near-useless statements).
    from evidentia_ai.risk_statements.templates import SystemContext

    if context_path is None or not context_path.is_file():
        yield json.dumps(
            {
                "phase": "error",
                "detail": (
                    "system_context YAML not found. Pass context_path pointing at "
                    "a valid system-context.yaml; see `evidentia init` for a template."
                ),
            }
        )
        return
    try:
        system_context = SystemContext.from_yaml(context_path)
    except Exception as e:
        logger.warning("Malformed system context %s: %s", context_path, e)
        yield json.dumps({"phase": "error", "detail": f"Could not load system_context: {e}"})
        return

    generated = 0
    failed = 0

    # Use asyncio.as_completed for true parallelism. Streaming in arrival
    # order keeps the UI responsive even if one gap is slow.
    tasks: list[asyncio.Task[tuple[int, ControlGap, object | None, str | None]]] = []

    async def _one(index: int, gap: ControlGap) -> tuple[int, ControlGap, object | None, str | None]:
        try:
            # `generate_async` is the async path shipped since v0.3.0.
            risk = await generator.generate_async(gap, system_context)
            return index, gap, risk, None
        except Exception as e:
            logger.exception("Risk generation failed for gap %s", gap.id)
            return index, gap, None, str(e)

    for idx, gap in enumerate(selected_gaps):
        tasks.append(asyncio.create_task(_one(idx, gap)))
        # Emit "generating" status as each task is scheduled so the UI can
        # show a progress row per gap immediately.
        yield json.dumps(
            {
                "phase": "progress",
                "gap_id": gap.id,
                "control_id": gap.control_id,
                "framework": gap.framework,
                "index": idx,
                "total": total,
                "status": "generating",
            }
        )

    for coro in asyncio.as_completed(tasks):
        index, gap, risk, err = await coro
        if risk is not None:
            generated += 1
            risk_payload = risk.model_dump(mode="json") if hasattr(risk, "model_dump") else risk
            yield json.dumps(
                {
                    "phase": "progress",
                    "gap_id": gap.id,
                    "control_id": gap.control_id,
                    "framework": gap.framework,
                    "index": index,
                    "total": total,
                    "status": "done",
                    "risk": risk_payload,
                }
            )
        else:
            failed += 1
            yield json.dumps(
                {
                    "phase": "error",
                    "gap_id": gap.id,
                    "control_id": gap.control_id,
                    "framework": gap.framework,
                    "index": index,
                    "total": total,
                    "detail": err,
                }
            )

    yield json.dumps({"phase": "done", "generated": generated, "failed": failed})


@router.post(
    "/risk/generate",
    responses=error_responses(
        {
            400: ("Malformed ``report_key`` (``error: invalid_id``); raised before the SSE stream starts."),
            404: ("No such stored report (``error: not_found``); raised before the SSE stream starts."),
        }
    ),
)
async def generate(payload: RiskGenerateRequest) -> EventSourceResponse:
    """Generate risk statements for selected gaps, streaming progress via SSE.

    The 400 / 404 documented above are raised by the ``_load_report``
    lookup BEFORE the stream starts; mid-stream failures ride inside
    the event stream as ``phase: error`` messages instead.
    """
    report = _load_report(payload.report_key)
    selected = _pick_gaps(report, payload.gap_ids, payload.top_n)

    async def _event_stream() -> AsyncIterator[dict[str, str]]:
        async for chunk in _stream_risk_generation(
            report=report,
            selected_gaps=selected,
            model=payload.model,
            context_path=payload.context_path,
        ):
            yield {"data": chunk}

    return EventSourceResponse(_event_stream())


# ── Open FAIR risk quantification (v0.10.12) ───────────────────────
#
# HTTP mirror of the ``evidentia risk quantify`` CLI verb. Pure local
# math (Open FAIR / Monte Carlo) — no credentials, no network, no
# state mutation. Left OPEN (no require_role) like the other read-style
# computational endpoints; the app-layer AuthProvider middleware still
# applies when a token file is configured.


class RiskQuantifyRequest(BaseModel):
    """Body of ``POST /api/risk/quantify``.

    Mirrors the CLI ``risk quantify`` options: a ``method`` selector,
    the list of FAIR ``scenarios`` (the core :class:`OpenFAIRScenario`
    schema, reused directly), and the Monte-Carlo-only ``iterations`` /
    ``seed`` knobs. The CLI loads scenarios from a YAML/JSON file; over
    HTTP the caller sends them inline.
    """

    model_config = ConfigDict(extra="forbid")

    method: str = Field(
        default="open-fair",
        description=(
            "Quantification method: 'open-fair' (deterministic PERT-mean "
            "expected value) or 'fair-mc' (Monte Carlo simulation with "
            "P10/P50/P90 percentile bands)."
        ),
    )
    scenarios: list[OpenFAIRScenario] = Field(
        min_length=1,
        max_length=1000,
        description="One or more Open FAIR scenarios to quantify.",
    )
    iterations: int = Field(
        default=10_000,
        ge=1,
        le=_MAX_ITERATIONS,
        description=(
            "Monte Carlo iteration count (only used when method='fair-mc'). "
            "Default 10,000 (FAIR-U recommended convergence point); the API "
            f"caps it at {_MAX_ITERATIONS:,} for bounded compute."
        ),
    )
    seed: int | None = Field(
        default=None,
        description=(
            "Random seed for deterministic Monte Carlo runs (only used when "
            "method='fair-mc'). Pass an explicit int for reproducible bands."
        ),
    )


class OpenFairScenarioResult(BaseModel):
    """Per-scenario deterministic Open FAIR result (method='open-fair')."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(description="The scenario's ID.")
    name: str = Field(description="The scenario's name.")
    lef: float = Field(description="Loss Event Frequency (events/yr).")
    loss_magnitude: float = Field(description="Loss Magnitude per event ($).")
    ale: float = Field(description="Annualized Loss Expectancy ($).")
    risk_category: str = Field(description="FAIR risk band (severe/high/significant/moderate/low).")


class OpenFairQuantifyResponse(BaseModel):
    """Response for method='open-fair' — deterministic per-scenario ALE."""

    model_config = ConfigDict(extra="forbid")

    method: str = Field(default="open-fair")
    scenario_count: int = Field(description="Number of scenarios quantified.")
    total_ale: float = Field(description="Sum of per-scenario ALE ($).")
    scenarios: list[OpenFairScenarioResult]


class FairMcQuantifyResponse(BaseModel):
    """Response for method='fair-mc' — one SimulationResult per scenario."""

    model_config = ConfigDict(extra="forbid")

    method: str = Field(default="fair-mc")
    scenario_count: int = Field(description="Number of scenarios simulated.")
    simulations: list[SimulationResult]


@router.post(
    "/risk/quantify",
    response_model=OpenFairQuantifyResponse | FairMcQuantifyResponse,
    responses=error_responses(
        {
            400: (
                "Unknown ``method`` (``error: unknown_method``; "
                "``detail`` carries ``method`` + ``valid``) or a "
                "degenerate/invalid Monte Carlo run "
                "(``error: invalid_body``)."
            ),
        }
    ),
)
def quantify(
    payload: RiskQuantifyRequest,
) -> OpenFairQuantifyResponse | FairMcQuantifyResponse:
    """Quantify Open FAIR risk scenarios (deterministic or Monte Carlo).

    The HTTP mirror of ``evidentia risk quantify``. ``method='open-fair'``
    returns the deterministic PERT-mean ALE per scenario; ``method='fair-mc'``
    runs a seeded Monte Carlo simulation returning P10/P50/P90 bands. Pure
    local computation — no credentials, no network, no persisted state.
    """
    if payload.method not in _QUANTIFY_METHODS:
        # Runtime body-content error → 400 (not Pydantic's 422 array;
        # the F-V08-DAST-3 status normalization is unchanged) with the
        # structured detail object from evidentia_api.errors.
        raise api_error(
            400,
            "unknown_method",
            (f"method must be one of {', '.join(_QUANTIFY_METHODS)} (got {payload.method!r})."),
            method=payload.method,
            valid=list(_QUANTIFY_METHODS),
        )

    if payload.method == "open-fair":
        results: list[OpenFairScenarioResult] = []
        total_ale = 0.0
        for scenario in payload.scenarios:
            ale = compute_ale(scenario)
            total_ale += ale
            results.append(
                OpenFairScenarioResult(
                    id=scenario.id,
                    name=scenario.name,
                    lef=compute_lef(scenario),
                    loss_magnitude=compute_loss_magnitude(scenario),
                    ale=ale,
                    risk_category=categorize_risk(ale).value,
                )
            )
        return OpenFairQuantifyResponse(
            scenario_count=len(results),
            total_ale=total_ale,
            scenarios=results,
        )

    # method == "fair-mc"
    try:
        simulations = [
            simulate_ale(
                scenario,
                iterations=payload.iterations,
                seed=payload.seed,
            )
            for scenario in payload.scenarios
        ]
    except (ValueError, ValidationError) as exc:
        # simulate_ale raises ValueError on a degenerate / invalid run;
        # normalize to a 400 structured detail like the rest of the
        # surface.
        raise api_error(400, "invalid_body", str(exc)) from exc

    return FairMcQuantifyResponse(
        scenario_count=len(simulations),
        simulations=simulations,
    )
