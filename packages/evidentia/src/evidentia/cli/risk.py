"""`evidentia risk` — AI risk statement generation + Open FAIR quantification."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import typer
import yaml
from evidentia_core.risk_quant import (
    OpenFAIRScenario,
    generate_risk_quantification_report,
)
from pydantic import ValidationError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

app = typer.Typer(help="AI-powered risk statement generation + risk quantification.")
console = Console()


@app.command("generate")
def generate(
    ctx: typer.Context,
    context: Path = typer.Option(
        ...,
        "--context",
        "-c",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to system context YAML file.",
    ),
    gaps: Path | None = typer.Option(
        None,
        "--gaps",
        "-g",
        exists=True,
        file_okay=True,
        readable=True,
        help="Path to a gap report JSON (from `evidentia gap analyze`).",
    ),
    gap_id: str | None = typer.Option(
        None,
        "--gap-id",
        help="Generate a risk statement for a single gap by ID.",
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        "-m",
        help="LLM model name (e.g. 'gpt-4o', 'claude-sonnet-4', 'ollama/llama3.3').",
    ),
    output: Path = typer.Option(
        Path("risks.json"),
        "--output",
        "-o",
        help="Output file path for generated risks.",
    ),
    limit: int | None = typer.Option(
        None,
        "--limit",
        "-n",
        help="Maximum number of gaps to process.",
    ),
    emit_trace: bool = typer.Option(
        False,
        "--emit-trace",
        help=(
            "v0.8.0 P0.2: attach a Policy Reasoning Trace (PRT) "
            "per arXiv 2509.23291 to each generated risk statement. "
            "v0.8.0 ships a single-claim stub trace; v0.8.1 ships "
            "the substantive LLM-driven per-claim decomposition. "
            "Trace data flows through OSCAL emit + Sigstore signing "
            "today regardless of whether it's stub or LLM-driven."
        ),
    ),
) -> None:
    """Generate NIST SP 800-30 risk statements for gaps using an LLM."""
    # Lazy import — avoid loading litellm/instructor unless this command is invoked
    from evidentia_ai.risk_statements import RiskStatementGenerator, SystemContext
    from evidentia_core.models.gap import GapAnalysisReport

    if not gaps and not gap_id:
        console.print(
            "[red]Error: must provide either --gaps or --gap-id.[/red]"
        )
        raise typer.Exit(code=1)

    # v0.2.1: resolve LLM model/temperature via config precedence:
    # CLI flag > env var > evidentia.yaml > RiskStatementGenerator default.
    from evidentia_core.config import EvidentiaConfig, get_default

    cfg_obj = ctx.obj.get("config") if ctx.obj else None
    cfg: EvidentiaConfig = cfg_obj if cfg_obj is not None else EvidentiaConfig()
    resolved_model = get_default(
        cfg, model, "llm.model", env_var="EVIDENTIA_LLM_MODEL"
    )
    # Temperature is harder to precedence via get_default (0.0 is falsy) —
    # do it explicitly. Flag > env > yaml.
    import contextlib

    resolved_temperature: float | None = None
    env_temp = os.environ.get("EVIDENTIA_LLM_TEMPERATURE")
    if env_temp is not None:
        with contextlib.suppress(ValueError):
            resolved_temperature = float(env_temp)
    if resolved_temperature is None and cfg.llm.temperature is not None:
        resolved_temperature = cfg.llm.temperature

    console.print(f"[cyan]Loading system context from[/cyan] [bold]{context}[/bold]...")
    sys_ctx = SystemContext.from_yaml(context)
    console.print(
        f"[green]Loaded:[/green] {sys_ctx.organization} / {sys_ctx.system_name}"
    )

    # v0.2.1: when --gaps is omitted, load the most recent report from
    # the user-dir gap store (populated by every `gap analyze` run).
    # This is the pair to D4 in the v0.2.1 plan.
    if not gaps:
        from evidentia_core.gap_store import load_latest_report

        report = load_latest_report()
        if report is None:
            console.print(
                "[red]No gap reports found in the store.[/red]\n"
                "[dim]Run `evidentia gap analyze ...` first, or pass "
                "`--gaps <path>` to load a report explicitly.[/dim]"
            )
            raise typer.Exit(code=1)
        console.print(
            f"[cyan]Using latest gap report:[/cyan] {report.organization} "
            f"({report.total_gaps} gaps, {len(report.frameworks_analyzed)} frameworks)"
        )
    else:
        report_data = json.loads(gaps.read_text(encoding="utf-8"))
        report = GapAnalysisReport.model_validate(report_data)
    target_gaps = report.gaps

    if gap_id:
        target_gaps = [g for g in target_gaps if g.id == gap_id]
        if not target_gaps:
            console.print(f"[red]No gap found with id={gap_id}[/red]")
            raise typer.Exit(code=1)

    if limit:
        target_gaps = target_gaps[:limit]

    console.print(
        f"[cyan]Generating risk statements for[/cyan] "
        f"[bold]{len(target_gaps)}[/bold] gaps using model "
        f"[bold]{resolved_model or 'default'}[/bold]"
        + (
            f" @ temperature={resolved_temperature}"
            if resolved_temperature is not None
            else ""
        )
        + "..."
    )

    generator = RiskStatementGenerator(
        model=resolved_model, temperature=resolved_temperature
    )

    risks = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Generating...", total=len(target_gaps))
        for gap in target_gaps:
            try:
                risk = generator.generate(
                    gap, sys_ctx, emit_trace=emit_trace
                )
                risks.append(risk)
            except Exception as e:
                console.print(
                    f"[red]Failed for {gap.control_id}: {e}[/red]"
                )
            progress.advance(task)

    # Write output
    output.write_text(
        json.dumps(
            [r.model_dump(mode="json") for r in risks],
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    console.print(
        f"[green]Generated[/green] {len(risks)}/{len(target_gaps)} risk statements"
    )
    console.print(f"[green]Output:[/green] [bold]{output}[/bold]")


# ── Open FAIR risk quantification (v0.7.11 P1.5 G4) ───────────────


def _load_scenarios_or_exit(path: Path) -> list[OpenFAIRScenario]:
    """Load + validate FAIR scenarios from YAML or JSON.

    Expected file shape: a top-level list of scenario records,
    each matching the OpenFAIRScenario schema (see module docs).
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        console.print(f"[red]Error:[/red] could not read {path}: {e}")
        raise typer.Exit(code=1) from e

    suffix = path.suffix.lower()
    try:
        if suffix in {".yaml", ".yml"}:
            raw = yaml.safe_load(text)
        elif suffix == ".json":
            raw = json.loads(text)
        else:
            # Try YAML first (it's a JSON superset for valid JSON)
            raw = yaml.safe_load(text)
    except (yaml.YAMLError, json.JSONDecodeError) as e:
        console.print(
            f"[red]Error:[/red] {path} is not valid YAML/JSON: {e}"
        )
        raise typer.Exit(code=1) from e

    if raw is None:
        return []
    if not isinstance(raw, list):
        console.print(
            f"[red]Error:[/red] {path} must be a list of scenario "
            f"records (got {type(raw).__name__})."
        )
        raise typer.Exit(code=1)

    scenarios: list[OpenFAIRScenario] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            console.print(
                f"[red]Error:[/red] entry {i} in {path} is not a "
                f"mapping; got {type(entry).__name__}."
            )
            raise typer.Exit(code=1)
        try:
            scenarios.append(OpenFAIRScenario.model_validate(entry))
        except ValidationError as e:
            console.print(
                f"[red]Error:[/red] entry {i} in {path} failed "
                f"validation: {e}"
            )
            raise typer.Exit(code=1) from e
    return scenarios


@app.command("quantify")
def quantify(
    method: str = typer.Option(
        "open-fair",
        "--method",
        help=(
            "Quantification method: 'open-fair' (deterministic PERT-mean) "
            "or 'fair-mc' (Monte Carlo simulation, v0.7.12+)."
        ),
    ),
    scenarios: Path = typer.Option(
        ...,
        "--scenarios",
        "-s",
        help="Path to a YAML or JSON file listing FAIR scenarios.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path. If omitted, prints the Markdown report to stdout.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output path if it already exists.",
    ),
    iterations: int = typer.Option(
        10_000,
        "--iterations",
        help=(
            "Monte Carlo iteration count (only with --method fair-mc). "
            "Default 10,000 (FAIR-U recommended convergence point)."
        ),
    ),
    seed: int | None = typer.Option(
        None,
        "--seed",
        help=(
            "Random seed for deterministic Monte Carlo runs (only with "
            "--method fair-mc). Pass an explicit int for golden-file "
            "tests + reproducible audit-trail outputs."
        ),
    ),
    csv_export: Path | None = typer.Option(
        None,
        "--csv",
        help=(
            "Path to write per-iteration ALE samples as CSV (only with "
            "--method fair-mc). Useful for downstream analysis in pandas "
            "or Excel."
        ),
    ),
) -> None:
    """Compute dollarized risk quantification per the chosen method.

    Two methods supported:

    * ``--method open-fair`` (v0.7.11+): deterministic PERT-mean
      expected-value form. Fast, repeatable, collapses uncertainty
      into a single number per scenario.

    * ``--method fair-mc`` (v0.7.12+): Monte Carlo simulation over
      Beta-PERT distributions for each factor. Produces P10/P50/P90
      percentile bands per scenario + optional CSV export of all
      per-iteration ALE samples.

    Scenarios file shape (YAML)::

        - name: Credential stuffing
          description: External attackers reuse leaked credentials
          tef: 365            # daily attempts (scalar)
          vulnerability: 0.001
          primary_loss: 5000
          secondary_loss:     # PERT range
            low: 10000
            most_likely: 50000
            high: 250000
        - name: Ransomware on file server
          ...
    """
    if method not in ("open-fair", "fair-mc"):
        console.print(
            f"[red]Error:[/red] --method must be 'open-fair' or 'fair-mc' "
            f"(got {method!r})."
        )
        raise typer.Exit(code=1)

    scenarios_list = _load_scenarios_or_exit(scenarios)

    if method == "open-fair":
        rendered = generate_risk_quantification_report(scenarios_list)
    else:  # fair-mc
        if iterations < 1:
            console.print(
                f"[red]Error:[/red] --iterations must be >= 1 (got "
                f"{iterations})."
            )
            raise typer.Exit(code=1)
        from evidentia_core.risk_quant.monte_carlo import (
            generate_monte_carlo_report,
            simulate_ale,
        )

        sims: list[tuple[Any, Any]] = []
        for sc in scenarios_list:
            res = simulate_ale(sc, iterations=iterations, seed=seed)
            sims.append((sc, res))
        rendered = generate_monte_carlo_report(sims)
        if csv_export is not None:
            # Concatenate every scenario's samples — one CSV per
            # full simulation set (caller wants a single file).
            csv_path = csv_export.expanduser().resolve()
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            import csv as csv_mod

            with csv_path.open("w", encoding="utf-8", newline="") as fh:
                writer = csv_mod.writer(fh)
                writer.writerow(["scenario_name", "iteration", "ale"])
                for sc, res in sims:
                    for i, ale in enumerate(res.samples, start=1):
                        writer.writerow([sc.name, i, ale])
            console.print(
                f"[green]Wrote[/green] {len(sims)} scenario(s) × "
                f"{iterations} iterations to {csv_path}"
            )

    if output is None:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    if output.exists() and not force:
        console.print(
            f"[red]Error:[/red] {output} already exists; pass --force "
            f"to overwrite."
        )
        raise typer.Exit(code=1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    console.print(
        f"[green]Wrote[/green] FAIR quantification report to "
        f"[bold]{output}[/bold] ({len(scenarios_list)} scenario(s))."
    )
