"""`evidentia governance` — Governance commands (v0.7.10 P1.5).

Foundation for the v0.7.10 P1.5 governance primitives. Currently
ships:

  - ``evidentia governance lines-report --classifications <yaml>``

Future v0.7.10 sub-slices will extend this group with
``effective-challenge`` (P1.5 G2), KRI / KPI / KGI dashboards
(P1.5 G3+), Open FAIR risk quantification (P1.5 G4), and
process-as-code workflows (P1.5 G5).
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import typer
import yaml
from evidentia_core.effective_challenge_store import (
    InvalidChallengeIdError,
    list_challenges,
    load_challenge_by_id,
    save_challenge,
)
from evidentia_core.governance import (
    ChallengeOutcome,
    EffectiveChallenge,
    LineOfDefense,
    Metric,
    MetricDirection,
    MetricKind,
    MetricObservation,
    Owner,
    evaluate_metric,
    generate_lines_report,
    generate_metrics_report,
)
from evidentia_core.metric_store import (
    InvalidMetricIdError,
    delete_metric,
    list_metrics,
    load_metric_by_id,
    save_metric,
)
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Governance commands (3LOD + Effective Challenge + KRI/KPI/KGI).")
challenge_app = typer.Typer(help="Effective Challenge log commands.")
metrics_app = typer.Typer(
    help="KRI / KPI / KGI metric definitions + observations + reports."
)
app.add_typer(challenge_app, name="challenge")
app.add_typer(metrics_app, name="metrics")

console = Console()


def _load_classifications(path: Path) -> list[Owner]:
    """Load a YAML overlay mapping email → line-of-defense classification.

    Expected YAML shape (one entry per owner)::

        - email: alice@example.com
          line_of_defense: first
          team: Loan Origination
          title: Senior Underwriter
        - email: bob@example.com
          line_of_defense: second
          team: MRM
          title: VP, Model Risk

    Returns the parsed list of :class:`Owner` instances. Exits
    cleanly with a clear error on parse failure.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except OSError as e:
        console.print(f"[red]Error:[/red] could not read {path}: {e}")
        raise typer.Exit(code=1) from e
    except yaml.YAMLError as e:
        console.print(
            f"[red]Error:[/red] {path} is not valid YAML: {e}"
        )
        raise typer.Exit(code=1) from e

    if raw is None:
        # Empty file = no owners; let the report generator render
        # the empty-case narrative.
        return []
    if not isinstance(raw, list):
        console.print(
            f"[red]Error:[/red] {path} must be a YAML list of "
            "owner records (got "
            f"{type(raw).__name__})."
        )
        raise typer.Exit(code=1)

    owners: list[Owner] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            console.print(
                f"[red]Error:[/red] entry {i} in {path} is not a mapping; "
                f"got {type(entry).__name__}."
            )
            raise typer.Exit(code=1)
        try:
            owners.append(Owner.model_validate(entry))
        except ValidationError as e:
            console.print(
                f"[red]Error:[/red] entry {i} in {path} failed validation: {e}"
            )
            raise typer.Exit(code=1) from e
    return owners


@app.command("lines-report")
def lines_report(
    classifications: Path = typer.Option(
        ...,
        "--classifications",
        "-c",
        help=(
            "Path to a YAML overlay listing owners + line-of-defense "
            "classifications. See `evidentia governance lines-report "
            "--help` for the expected YAML shape."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path. If omitted, prints to stdout.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output path if it already exists.",
    ),
) -> None:
    """Generate a Three Lines of Defense distribution report.

    Reads classified owners from a YAML overlay file and produces a
    Markdown distribution report covering:

      - Per-line counts + percentages
      - Crossover warning (any owner classified across multiple
        lines is flagged as a regulator-noted anti-pattern)
      - Per-line owner listing
      - Per-team breakdown showing which lines each team
        participates in

    The report is deterministic — same input produces the same
    output. Operators can therefore commit generated reports to git
    + audit-diff them across review cycles.
    """
    owners = _load_classifications(classifications)
    rendered = generate_lines_report(owners)

    if output is None:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    if output.exists() and not force:
        console.print(
            f"[red]Error:[/red] {output} already exists; pass --force to overwrite."
        )
        raise typer.Exit(code=1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    n_first = sum(1 for o in owners if o.line_of_defense == LineOfDefense.FIRST.value)
    n_second = sum(1 for o in owners if o.line_of_defense == LineOfDefense.SECOND.value)
    n_third = sum(1 for o in owners if o.line_of_defense == LineOfDefense.THIRD.value)
    console.print(
        f"[green]Wrote[/green] 3LOD report to [bold]{output}[/bold] "
        f"({len(owners)} owner(s); 1st={n_first} / 2nd={n_second} / 3rd={n_third})."
    )


# ── effective challenge log (v0.7.10 P1.5 G2) ──────────────────────


def _parse_date_or_exit(value: str | None, flag: str) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] {flag} must be ISO-8601 date "
            f"(YYYY-MM-DD); got {value!r}: {e}"
        )
        raise typer.Exit(code=1) from e


@challenge_app.command("add")
def challenge_add(
    subject_model_id: str = typer.Option(
        ..., "--subject-model-id",
        help="ModelInventory.id being challenged.",
    ),
    challenger_email: str = typer.Option(
        ..., "--challenger-email",
        help="Email of the independent challenger.",
    ),
    challenger_role: str = typer.Option(
        ..., "--challenger-role",
        help="Challenger's role label (e.g., 'MRM Director').",
    ),
    challenge_date_str: str = typer.Option(
        ..., "--challenge-date",
        help="ISO-8601 date the challenge event occurred (YYYY-MM-DD).",
    ),
    challenge_topic: str = typer.Option(
        ..., "--challenge-topic",
        help="Short topic label.",
    ),
    challenge_substance: str = typer.Option(
        ..., "--challenge-substance",
        help="Full substantive challenge text.",
    ),
    response: str | None = typer.Option(
        None, "--response",
        help="Model owner's documented response (optional; can be added later via edit).",
    ),
    outcome: str = typer.Option(
        "pending", "--outcome",
        help="Outcome: accepted / rejected / modify / pending.",
    ),
    outcome_rationale: str | None = typer.Option(
        None, "--outcome-rationale",
        help="Rationale for the outcome decision.",
    ),
    resolved_at_str: str | None = typer.Option(
        None, "--resolved-at",
        help="ISO-8601 date the challenge was resolved.",
    ),
) -> None:
    """Add a new effective-challenge log record."""
    challenge_date_val = _parse_date_or_exit(challenge_date_str, "--challenge-date")
    resolved_at_val = _parse_date_or_exit(resolved_at_str, "--resolved-at")
    if challenge_date_val is None:
        # _parse_date_or_exit returns None only when value is None;
        # since challenge_date_str is required, this branch is
        # unreachable but typed for mypy.
        raise typer.Exit(code=1)
    try:
        outcome_enum = ChallengeOutcome(outcome)
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] Unknown outcome {outcome!r}; valid: "
            f"{[o.value for o in ChallengeOutcome]}"
        )
        raise typer.Exit(code=1) from e

    try:
        challenge = EffectiveChallenge(
            subject_model_id=subject_model_id,
            challenger_email=challenger_email,
            challenger_role=challenger_role,
            challenge_date=challenge_date_val,
            challenge_topic=challenge_topic,
            challenge_substance=challenge_substance,
            response=response,
            outcome=outcome_enum,
            outcome_rationale=outcome_rationale,
            resolved_at=resolved_at_val,
        )
    except ValidationError as e:
        console.print(f"[red]Invalid challenge data:[/red] {e}")
        raise typer.Exit(code=1) from e

    save_challenge(challenge)
    console.print(
        f"[green]Logged[/green] challenge "
        f"[bold]{challenge.challenge_topic}[/bold] (id: {challenge.id})"
    )


@challenge_app.command("list")
def challenge_list(
    subject_model_id: str | None = typer.Option(
        None, "--subject-model-id",
        help="Filter by subject ModelInventory.id.",
    ),
    outcome: str | None = typer.Option(
        None, "--outcome",
        help="Filter by outcome: accepted / rejected / modify / pending.",
    ),
    json_out: bool = typer.Option(
        False, "--json",
        help="Emit machine-readable JSON array instead of a table.",
    ),
) -> None:
    """List challenge records sorted newest-first by challenge_date."""
    if outcome and outcome not in {o.value for o in ChallengeOutcome}:
        console.print(
            f"[red]Error:[/red] Unknown outcome {outcome!r}; valid: "
            f"{sorted(o.value for o in ChallengeOutcome)}"
        )
        raise typer.Exit(code=1)

    challenges = list_challenges()
    if subject_model_id:
        challenges = [c for c in challenges if c.subject_model_id == subject_model_id]
    if outcome:
        challenges = [c for c in challenges if c.outcome == outcome]

    if json_out:
        sys.stdout.write(
            json.dumps(
                [c.model_dump(mode="json") for c in challenges], indent=2
            )
        )
        sys.stdout.write("\n")
        return

    if not challenges:
        console.print(
            f"[dim]No challenges in the log "
            f"({len(list_challenges())} total without filter).[/dim]"
        )
        return

    table = Table(title=f"Effective Challenge log ({len(challenges)} matching)")
    table.add_column("ID", style="dim")
    table.add_column("Date")
    table.add_column("Topic", style="bold")
    table.add_column("Challenger")
    table.add_column("Role")
    table.add_column("Outcome", style="cyan")
    for c in challenges:
        table.add_row(
            c.id[:8],
            str(c.challenge_date),
            c.challenge_topic,
            c.challenger_email,
            c.challenger_role,
            c.outcome,
        )
    console.print(table)


@challenge_app.command("show")
def challenge_show(
    challenge_id: str = typer.Argument(..., help="Challenge ID (UUID)."),
    json_out: bool = typer.Option(
        False, "--json",
        help="Emit machine-readable JSON instead of formatted text.",
    ),
) -> None:
    """Show a single challenge record by ID."""
    try:
        challenge = load_challenge_by_id(challenge_id)
    except InvalidChallengeIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if challenge is None:
        console.print(
            f"[red]Error:[/red] No challenge with ID {challenge_id!r} found."
        )
        raise typer.Exit(code=1)

    if json_out:
        sys.stdout.write(challenge.model_dump_json(indent=2))
        sys.stdout.write("\n")
        return

    console.print(f"[bold]{challenge.challenge_topic}[/bold]  [dim]({challenge.id})[/dim]")
    console.print(f"  Subject model:      {challenge.subject_model_id}")
    console.print(
        f"  Challenger:         {challenge.challenger_email} ({challenge.challenger_role})"
    )
    console.print(f"  Challenge date:     {challenge.challenge_date}")
    console.print(f"  Outcome:            [cyan]{challenge.outcome}[/cyan]")
    if challenge.resolved_at:
        console.print(f"  Resolved:           {challenge.resolved_at}")
    console.print(f"  Substance:          {challenge.challenge_substance}")
    if challenge.response:
        console.print(f"  Response:           {challenge.response}")
    if challenge.outcome_rationale:
        console.print(f"  Outcome rationale:  {challenge.outcome_rationale}")
    console.print(
        f"  [dim]Created: {challenge.created_at}  Updated: {challenge.updated_at}  "
        f"evidentia: {challenge.evidentia_version}[/dim]"
    )


# ── KRI / KPI / KGI metrics (v0.7.11 P1.5 G3) ─────────────────────


@metrics_app.command("add")
def metrics_add(
    name: str = typer.Option(..., "--name", "-n", help="Metric name."),
    description: str = typer.Option(
        ..., "--description",
        help="What this metric measures + why it's tracked.",
    ),
    kind: str = typer.Option(
        ..., "--kind",
        help="kri / kpi / kgi.",
    ),
    direction: str = typer.Option(
        ..., "--direction",
        help="higher_is_worse / higher_is_better.",
    ),
    unit: str = typer.Option(
        ..., "--unit",
        help="Measurement unit (e.g., 'per 1000 logins', 'days', '%').",
    ),
    owner_email: str | None = typer.Option(
        None, "--owner-email",
        help="Email of the metric owner (optional).",
    ),
    warning_threshold: float | None = typer.Option(
        None, "--warning-threshold",
        help="Watch threshold; semantics drive direction.",
    ),
    critical_threshold: float | None = typer.Option(
        None, "--critical-threshold",
        help="Breach threshold; semantics drive direction.",
    ),
    notes: str | None = typer.Option(
        None, "--notes",
        help="Optional free-text notes.",
    ),
) -> None:
    """Add a new KRI / KPI / KGI metric."""
    try:
        kind_enum = MetricKind(kind)
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] Unknown kind {kind!r}; valid: "
            f"{[k.value for k in MetricKind]}"
        )
        raise typer.Exit(code=1) from e
    try:
        direction_enum = MetricDirection(direction)
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] Unknown direction {direction!r}; valid: "
            f"{[d.value for d in MetricDirection]}"
        )
        raise typer.Exit(code=1) from e

    try:
        metric = Metric(
            name=name,
            description=description,
            kind=kind_enum,
            direction=direction_enum,
            unit=unit,
            owner_email=owner_email,
            warning_threshold=warning_threshold,
            critical_threshold=critical_threshold,
            notes=notes,
        )
    except ValidationError as e:
        console.print(f"[red]Invalid metric data:[/red] {e}")
        raise typer.Exit(code=1) from e

    save_metric(metric)
    console.print(
        f"[green]Added[/green] metric "
        f"[bold]{metric.name}[/bold] (id: {metric.id})"
    )


@metrics_app.command("observe")
def metrics_observe(
    metric_id: str = typer.Argument(..., help="Metric ID (UUID)."),
    value: float = typer.Option(..., "--value", help="Observation value."),
    observed_at: str = typer.Option(
        ..., "--observed-at",
        help="ISO-8601 date (YYYY-MM-DD) the observation was recorded.",
    ),
    note: str | None = typer.Option(
        None, "--note",
        help="Optional contextual note.",
    ),
) -> None:
    """Record a new observation against an existing metric."""
    try:
        metric = load_metric_by_id(metric_id)
    except InvalidMetricIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if metric is None:
        console.print(
            f"[red]Error:[/red] No metric with ID {metric_id!r} found."
        )
        raise typer.Exit(code=1)
    obs_date = _parse_date_or_exit(observed_at, "--observed-at")
    if obs_date is None:
        raise typer.Exit(code=1)
    new_obs = MetricObservation(
        observed_at=obs_date,
        value=value,
        note=note,
    )
    metric = metric.model_copy(
        update={"observations": [*metric.observations, new_obs]}
    )
    save_metric(metric)
    console.print(
        f"[green]Recorded[/green] observation {value} {metric.unit} on "
        f"{observed_at} for [bold]{metric.name}[/bold]; "
        f"current status: [cyan]{evaluate_metric(metric).value}[/cyan]"
    )


@metrics_app.command("list")
def metrics_list(
    kind: str | None = typer.Option(
        None, "--kind", help="Filter by kri / kpi / kgi."
    ),
    json_out: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON array."
    ),
) -> None:
    """List metrics (filterable by kind)."""
    if kind and kind not in {k.value for k in MetricKind}:
        console.print(
            f"[red]Error:[/red] Unknown kind {kind!r}; valid: "
            f"{sorted(k.value for k in MetricKind)}"
        )
        raise typer.Exit(code=1)
    metrics = list_metrics()
    if kind:
        metrics = [m for m in metrics if m.kind == kind]

    if json_out:
        sys.stdout.write(
            json.dumps(
                [m.model_dump(mode="json") for m in metrics], indent=2
            )
        )
        sys.stdout.write("\n")
        return

    if not metrics:
        console.print("[dim]No metrics defined.[/dim]")
        return

    table = Table(title=f"Metrics inventory ({len(metrics)} total)")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Kind")
    table.add_column("Direction")
    table.add_column("Unit")
    table.add_column("Status", style="cyan")
    table.add_column("Latest")
    for m in metrics:
        latest = (
            f"{max(m.observations, key=lambda o: o.observed_at).value}"
            if m.observations
            else "—"
        )
        table.add_row(
            m.id[:8],
            m.name,
            m.kind,
            m.direction,
            m.unit,
            evaluate_metric(m).value,
            latest,
        )
    console.print(table)


@metrics_app.command("show")
def metrics_show(
    metric_id: str = typer.Argument(..., help="Metric ID (UUID)."),
    json_out: bool = typer.Option(
        False, "--json", help="Emit machine-readable JSON."
    ),
) -> None:
    """Show a single metric with full observation history."""
    try:
        metric = load_metric_by_id(metric_id)
    except InvalidMetricIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if metric is None:
        console.print(
            f"[red]Error:[/red] No metric with ID {metric_id!r} found."
        )
        raise typer.Exit(code=1)

    if json_out:
        sys.stdout.write(metric.model_dump_json(indent=2))
        sys.stdout.write("\n")
        return

    console.print(f"[bold]{metric.name}[/bold]  [dim]({metric.id})[/dim]")
    console.print(f"  Kind:               [cyan]{metric.kind}[/cyan]")
    console.print(f"  Direction:          {metric.direction}")
    console.print(f"  Unit:               {metric.unit}")
    console.print(f"  Owner:              {metric.owner_email or '(none)'}")
    console.print(
        f"  Warning threshold:  {metric.warning_threshold or '(none)'}"
    )
    console.print(
        f"  Critical threshold: {metric.critical_threshold or '(none)'}"
    )
    console.print(f"  Status:             [cyan]{evaluate_metric(metric).value}[/cyan]")
    console.print(f"  Description:        {metric.description}")
    if metric.notes:
        console.print(f"  Notes:              {metric.notes}")
    if metric.observations:
        console.print(f"  Observations ({len(metric.observations)}):")
        for o in sorted(
            metric.observations, key=lambda x: x.observed_at
        ):
            note = f" — {o.note}" if o.note else ""
            console.print(
                f"    - {o.observed_at}: {o.value} {metric.unit}{note}"
            )
    console.print(
        f"  [dim]Created: {metric.created_at}  Updated: {metric.updated_at}[/dim]"
    )


@metrics_app.command("delete")
def metrics_delete(
    metric_id: str = typer.Argument(..., help="Metric ID (UUID)."),
    yes: bool = typer.Option(
        False, "--yes", help="Skip confirmation prompt."
    ),
) -> None:
    """Delete a metric by ID."""
    try:
        metric = load_metric_by_id(metric_id)
    except InvalidMetricIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if metric is None:
        console.print(
            f"[red]Error:[/red] No metric with ID {metric_id!r} found."
        )
        raise typer.Exit(code=1)
    if not yes:
        confirmed = typer.confirm(
            f"Delete metric '{metric.name}' (id: {metric.id})?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)
    deleted = delete_metric(metric_id)
    if deleted:
        console.print(
            f"[green]Deleted[/green] metric [bold]{metric.name}[/bold]."
        )


@metrics_app.command("report")
def metrics_report(
    output: Path | None = typer.Option(
        None, "--output", "-o",
        help="Output path. If omitted, prints to stdout.",
    ),
    force: bool = typer.Option(
        False, "--force",
        help="Overwrite the output path if it exists.",
    ),
) -> None:
    """Generate a Markdown dashboard report across all metrics."""
    metrics = list_metrics()
    rendered = generate_metrics_report(metrics)

    if output is None:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    if output.exists() and not force:
        console.print(
            f"[red]Error:[/red] {output} already exists; pass --force."
        )
        raise typer.Exit(code=1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    console.print(
        f"[green]Wrote[/green] metrics report to [bold]{output}[/bold] "
        f"({len(metrics)} metric(s))."
    )


