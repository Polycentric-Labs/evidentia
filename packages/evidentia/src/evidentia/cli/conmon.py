"""`evidentia conmon` — Continuous Monitoring cycle-calendar commands.

v0.9.0 P3 read-only library + v0.9.3 P1.1 poll-mode daemon.
Operators consult the bundled cadence catalog, compute next-due
dates from a known anchor, and (v0.9.3+) optionally run a long-
lived daemon to poll cycle state on a fixed interval.

Subcommand structure:

    evidentia conmon list [--framework FW] [--json]
        # List all bundled (+ runtime-registered) cadences.

    evidentia conmon next <slug> --last-completed YYYY-MM-DD
        # Compute the next-due date for a specific cadence.

    evidentia conmon check --last-completed-file <path> [--today Y] [--window-days N] [--json]
        # Read a YAML mapping of {cadence_slug: last_completed_date}
        # and report due-soon + overdue cycles via derive_status.
        # Fires CONMON_CYCLE_DUE / CONMON_CYCLE_OVERDUE events for
        # each cycle that surfaces.

    evidentia conmon watch --state-file <path> [--poll-interval N] [--window-days N]
        # v0.9.3 P1.1: long-running poll daemon. Re-reads the state
        # file at each poll interval and fires CONMON_CYCLE_DUE /
        # CONMON_CYCLE_OVERDUE events on state transitions.
        # SIGINT/SIGTERM trigger graceful shutdown.

    evidentia conmon mark-completed <slug> --when YYYY-MM-DD --state-file <path>
        # v0.9.3 P1.1: record a cycle completion in the state file.
        # Emits CONMON_CYCLE_MARKED_COMPLETED with previous + new
        # last_completed values for auditor reconciliation.

The CONMON live-trigger daemon (event-driven, vs the v0.9.3 poll
mode) remains reserved for v1.0.
"""

from __future__ import annotations

import json
import signal
import sys
import threading
from datetime import date
from pathlib import Path

import typer
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.conmon import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    CycleAttentionState,
    DaemonConfig,
    derive_status,
    get_cadence,
    list_cadences,
    mark_completed,
    next_due,
    run_daemon,
)
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Continuous Monitoring cycle calendar (v0.9.0 P3).")
console = Console()
_log = get_logger("evidentia.cli.conmon")


# ── helpers ────────────────────────────────────────────────────────


def _parse_date_or_exit(value: str | None, flag: str) -> date | None:
    """Parse an ISO-8601 date or exit cleanly. Mirrors cli/poam.py."""
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        console.print(
            f"[red]Error:[/red] {flag} must be ISO-8601 date "
            f"(YYYY-MM-DD); got {value!r}: {exc}"
        )
        raise typer.Exit(code=1) from exc


def _load_last_completed_map(
    path: Path,
) -> dict[str, date]:
    """Load a YAML mapping of {cadence_slug: last_completed_date}.

    Schema (YAML):

        nist-800-53-rev5-ca7: 2026-04-01
        fedramp-conmon-poam: 2026-04-15

    Raises :class:`typer.Exit` (code 1) on parse failure or invalid
    schema. Unknown slugs surface a warning at use time, not at
    parse time, so operators can keep entries for cadences they
    haven't yet rolled out.
    """
    import yaml as yaml_mod  # lazy import — keeps the CLI lean

    try:
        raw = yaml_mod.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml_mod.YAMLError as exc:
        console.print(f"[red]Error:[/red] could not parse {path}: {exc}")
        raise typer.Exit(code=1) from exc

    if not isinstance(raw, dict):
        console.print(
            f"[red]Error:[/red] {path} must be a YAML mapping of "
            f"slug → ISO-8601 date; got {type(raw).__name__}"
        )
        raise typer.Exit(code=1)

    out: dict[str, date] = {}
    for slug, value in raw.items():
        if not isinstance(slug, str):
            console.print(
                f"[red]Error:[/red] cadence keys must be strings; "
                f"got {slug!r}"
            )
            raise typer.Exit(code=1)
        if isinstance(value, date):
            out[slug] = value
        elif isinstance(value, str):
            try:
                out[slug] = date.fromisoformat(value)
            except ValueError as exc:
                console.print(
                    f"[red]Error:[/red] {slug!r} → {value!r}: "
                    f"expected ISO-8601 date ({exc})"
                )
                raise typer.Exit(code=1) from exc
        else:
            console.print(
                f"[red]Error:[/red] {slug!r} → {value!r}: expected "
                f"ISO-8601 date string"
            )
            raise typer.Exit(code=1)
    return out


# ── list ───────────────────────────────────────────────────────────


@app.command("list")
def conmon_list(
    framework: str | None = typer.Option(
        None,
        "--framework",
        "-f",
        help=(
            "Filter to cadences for a specific framework "
            "(e.g., nist-800-53-rev5, fedramp-rev5-mod, cmmc-v2)."
        ),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of a rich table.",
    ),
) -> None:
    """List bundled + registered CONMON cadences."""
    cadences = list_cadences(framework=framework)

    if output_json:
        typer.echo(
            json.dumps(
                [json.loads(c.model_dump_json()) for c in cadences],
                indent=2,
            )
        )
        return

    table = Table(title=f"CONMON cadences ({len(cadences)} total)")
    table.add_column("Slug", style="bold")
    table.add_column("Framework")
    table.add_column("Activity")
    table.add_column("Frequency", style="cyan")
    table.add_column("Citation")
    for cadence in cadences:
        table.add_row(
            cadence.slug,
            cadence.framework,
            cadence.activity,
            cadence.frequency,
            cadence.citation or "[dim]—[/dim]",
        )
    console.print(table)


# ── next ───────────────────────────────────────────────────────────


@app.command("next")
def conmon_next(
    slug: str = typer.Argument(..., help="Cadence slug."),
    last_completed: str = typer.Option(
        ...,
        "--last-completed",
        help="ISO-8601 date of the last completed cycle.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON instead of human form.",
    ),
) -> None:
    """Compute the next-due date for a registered cadence."""
    cadence = get_cadence(slug)
    if cadence is None:
        console.print(
            f"[red]Error:[/red] unknown cadence slug {slug!r}. "
            f"Run `evidentia conmon list` to see available."
        )
        raise typer.Exit(code=1)

    anchor = _parse_date_or_exit(last_completed, "--last-completed")
    assert anchor is not None  # required by Typer (...)

    due = next_due(slug, anchor)

    if output_json:
        typer.echo(
            json.dumps(
                {
                    "slug": cadence.slug,
                    "framework": cadence.framework,
                    "activity": cadence.activity,
                    "frequency": cadence.frequency,
                    "last_completed": anchor.isoformat(),
                    "next_due": due.isoformat(),
                },
                indent=2,
            )
        )
        return

    console.print(
        f"[bold]{cadence.slug}[/bold] ({cadence.frequency})"
    )
    console.print(f"  Framework:       {cadence.framework}")
    console.print(f"  Activity:        {cadence.activity}")
    console.print(f"  Last completed:  {anchor.isoformat()}")
    console.print(
        f"  Next due:        [cyan]{due.isoformat()}[/cyan]"
    )
    if cadence.citation:
        console.print(f"  Citation:        [dim]{cadence.citation}[/dim]")


# ── check ──────────────────────────────────────────────────────────


@app.command("check")
def conmon_check(
    last_completed_file: Path = typer.Option(
        ...,
        "--last-completed-file",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "YAML mapping {cadence_slug: ISO-8601-date} of last-"
            "completed dates per cycle. Unknown slugs are warned "
            "(not errored)."
        ),
    ),
    today_override: str | None = typer.Option(
        None,
        "--today",
        help=(
            "Override 'today' for deterministic CLI snapshots "
            "(YYYY-MM-DD). Production operators omit this flag."
        ),
    ),
    window_days: int = typer.Option(
        14,
        "--window-days",
        min=0,
        help=(
            "Due-soon window (days from today). Default: 14 days. "
            "Overdue cycles always surface regardless of this window."
        ),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON instead of human-readable tables.",
    ),
) -> None:
    """Report due-soon + overdue cycles from a tracked-state YAML.

    Fires :attr:`EventAction.CONMON_CYCLE_DUE` per due-soon cycle
    and :attr:`EventAction.CONMON_CYCLE_OVERDUE` per overdue cycle.
    Pure-current cycles (next_due_date > today + window_days) do
    NOT emit audit events — the absence of events is itself an
    auditor signal (no attention needed).
    """
    today_parsed = _parse_date_or_exit(today_override, "--today")
    today: date = today_parsed if today_parsed is not None else date.today()

    last_completed_map = _load_last_completed_map(last_completed_file)

    overdue: list[dict[str, str]] = []
    due_soon: list[dict[str, str]] = []
    unknown: list[str] = []

    for slug, anchor in last_completed_map.items():
        cadence = get_cadence(slug)
        if cadence is None:
            unknown.append(slug)
            continue
        due = next_due(slug, anchor)
        state = derive_status(due, today, window_days=window_days)
        days_until_due = (due - today).days
        row = {
            "slug": slug,
            "framework": cadence.framework,
            "activity": cadence.activity,
            "frequency": cadence.frequency,
            "last_completed": anchor.isoformat(),
            "next_due": due.isoformat(),
            "days_until_due": str(days_until_due),
        }
        if state == CycleAttentionState.OVERDUE:
            overdue.append(row)
            _log.warning(
                action=EventAction.CONMON_CYCLE_OVERDUE,
                outcome=EventOutcome.FAILURE,
                message=(
                    f"CONMON cycle {slug!r} is overdue "
                    f"({days_until_due} days past next-due)"
                ),
                evidentia={
                    "cadence_slug": slug,
                    "framework": cadence.framework,
                    "activity": cadence.activity,
                    "last_completed": anchor.isoformat(),
                    "next_due": due.isoformat(),
                    "days_until_due": days_until_due,
                },
            )
        elif state == CycleAttentionState.DUE_SOON:
            due_soon.append(row)
            _log.info(
                action=EventAction.CONMON_CYCLE_DUE,
                outcome=EventOutcome.SUCCESS,
                message=(
                    f"CONMON cycle {slug!r} due within "
                    f"{window_days} day(s) (next-due {due.isoformat()})"
                ),
                evidentia={
                    "cadence_slug": slug,
                    "framework": cadence.framework,
                    "activity": cadence.activity,
                    "last_completed": anchor.isoformat(),
                    "next_due": due.isoformat(),
                    "days_until_due": days_until_due,
                },
            )

    if output_json:
        typer.echo(
            json.dumps(
                {
                    "today": today.isoformat(),
                    "window_days": window_days,
                    "overdue": overdue,
                    "due_soon": due_soon,
                    "unknown_slugs": unknown,
                },
                indent=2,
            )
        )
        return

    if unknown:
        console.print(
            f"[yellow]Warning:[/yellow] {len(unknown)} unknown "
            f"cadence slug(s) in the file: {', '.join(unknown)}"
        )

    if not overdue and not due_soon:
        console.print(
            f"[green]No CONMON cycles overdue or due within "
            f"{window_days} day(s)[/green] as of {today.isoformat()}."
        )
        return

    if overdue:
        table = Table(
            title=(
                f"OVERDUE cycles ({len(overdue)}) as of {today.isoformat()}"
            ),
            title_style="bold red",
        )
        table.add_column("Slug", style="bold")
        table.add_column("Framework")
        table.add_column("Activity")
        table.add_column("Next due", style="red")
        table.add_column("Days past", justify="right", style="red")
        for row in overdue:
            table.add_row(
                row["slug"],
                row["framework"],
                row["activity"],
                row["next_due"],
                row["days_until_due"],
            )
        console.print(table)

    if due_soon:
        table = Table(
            title=(
                f"Due within {window_days} day(s) ({len(due_soon)}) "
                f"as of {today.isoformat()}"
            ),
            title_style="bold yellow",
        )
        table.add_column("Slug", style="bold")
        table.add_column("Framework")
        table.add_column("Activity")
        table.add_column("Next due", style="yellow")
        table.add_column("Days ahead", justify="right")
        for row in due_soon:
            table.add_row(
                row["slug"],
                row["framework"],
                row["activity"],
                row["next_due"],
                row["days_until_due"],
            )
        console.print(table)


# ── watch (v0.9.3 P1.1 — poll daemon) ─────────────────────────────


@app.command("watch")
def conmon_watch(
    state_file: Path = typer.Option(
        ...,
        "--state-file",
        exists=False,  # daemon tolerates missing file (retries)
        file_okay=True,
        dir_okay=False,
        help=(
            "YAML mapping {cadence_slug: ISO-8601-date} of last-"
            "completed dates. Re-read each poll cycle so operators "
            "can mark cycles completed without daemon restart. "
            "Missing file is tolerated — the daemon logs + retries."
        ),
    ),
    poll_interval_seconds: int = typer.Option(
        DEFAULT_POLL_INTERVAL_SECONDS,
        "--poll-interval",
        min=MIN_POLL_INTERVAL_SECONDS,
        help=(
            f"Seconds between poll cycles. Default: "
            f"{DEFAULT_POLL_INTERVAL_SECONDS}s (1 hour). "
            f"Minimum: {MIN_POLL_INTERVAL_SECONDS}s — sub-minute "
            f"polling adds no signal for daily/weekly/monthly "
            f"CONMON cadences."
        ),
    ),
    window_days: int = typer.Option(
        14,
        "--window-days",
        min=0,
        help=(
            "Due-soon window (days from today). Default: 14 days. "
            "Overdue cycles always surface regardless of this window."
        ),
    ),
) -> None:
    """Long-running poll daemon for CONMON cycle attention-state.

    Reads ``--state-file`` on each poll cycle and emits
    :attr:`EventAction.CONMON_CYCLE_DUE` /
    :attr:`EventAction.CONMON_CYCLE_OVERDUE` audit events when
    cycles enter due-soon or overdue states.

    Lifecycle audit events bracket the run:
    :attr:`EventAction.CONMON_DAEMON_STARTED` at boot,
    :attr:`EventAction.CONMON_DAEMON_STOPPED` at graceful shutdown.

    Graceful shutdown: SIGINT (Ctrl+C) and SIGTERM trigger the
    shutdown event. The daemon finishes the current poll cycle,
    fires CONMON_DAEMON_STOPPED, and exits 0.

    Operator deployment guidance in
    ``docs/conmon-daemon-deployment.md``.
    """
    config = DaemonConfig(
        state_file=state_file,
        poll_interval_seconds=poll_interval_seconds,
        window_days=window_days,
    )

    shutdown = threading.Event()

    def _handle_signal(signum: int, _frame: object) -> None:
        sig_name = signal.Signals(signum).name
        console.print(
            f"\n[yellow]Received {sig_name}; "
            f"finishing current poll cycle...[/yellow]"
        )
        shutdown.set()

    signal.signal(signal.SIGINT, _handle_signal)
    if sys.platform != "win32":
        # SIGTERM is POSIX-only; Windows uses other mechanisms.
        signal.signal(signal.SIGTERM, _handle_signal)

    console.print(
        f"[green]CONMON daemon starting[/green] (poll every "
        f"{poll_interval_seconds}s; window={window_days}d; "
        f"state-file={state_file})"
    )
    console.print("[dim]Press Ctrl+C for graceful shutdown.[/dim]")

    run_daemon(config, shutdown_event=shutdown)

    console.print("[green]CONMON daemon stopped cleanly.[/green]")


# ── mark-completed (v0.9.3 P1.1) ──────────────────────────────────


@app.command("mark-completed")
def conmon_mark_completed(
    slug: str = typer.Argument(
        ...,
        help="Cadence slug (e.g., 'nist-800-53-rev5-ca7').",
    ),
    when: str = typer.Option(
        ...,
        "--when",
        help="ISO-8601 date of cycle completion (YYYY-MM-DD).",
    ),
    state_file: Path = typer.Option(
        ...,
        "--state-file",
        file_okay=True,
        dir_okay=False,
        help=(
            "Path to the YAML state file the daemon polls. Created "
            "if it does not exist."
        ),
    ),
) -> None:
    """Record a CONMON cycle completion in the state file.

    Emits :attr:`EventAction.CONMON_CYCLE_MARKED_COMPLETED` with
    both the previous and new ``last_completed`` values. The audit
    event is the auditor's primary evidence that the cycle was
    actually performed, NOT just scheduled.
    """
    parsed_when = _parse_date_or_exit(when, "--when")
    assert parsed_when is not None

    try:
        previous = mark_completed(state_file, slug, parsed_when)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        console.print(
            "[dim]Run `evidentia conmon list` to see available cadences.[/dim]"
        )
        raise typer.Exit(code=1) from exc

    cadence = get_cadence(slug)
    assert cadence is not None  # validated by mark_completed

    if previous is None:
        console.print(
            f"[green]Marked[/green] [bold]{slug}[/bold] completed on "
            f"{parsed_when.isoformat()} (first recorded completion)"
        )
    else:
        console.print(
            f"[green]Marked[/green] [bold]{slug}[/bold] completed on "
            f"{parsed_when.isoformat()} "
            f"(previous: {previous.isoformat()})"
        )
    if cadence.citation:
        console.print(f"  [dim]Citation: {cadence.citation}[/dim]")
