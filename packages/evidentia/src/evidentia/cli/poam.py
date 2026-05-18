"""`evidentia poam` — Plan-of-Action-and-Milestones commands (v0.9.0 P2).

Provides the user-facing CLI surface on top of the v0.9.0 P1 POA&M
data layer (:mod:`evidentia_core.models.gap` POAMState + Milestone
+ ControlGap.poam_milestones + :mod:`evidentia_core.poam_store`
JSON-file persistence + :mod:`evidentia_core.poam` state/milestone
helpers).

Subcommand structure:

    evidentia poam create --from-gap-report <path>
        # Auto-generate POA&M items from a saved gap-analysis report.
        # By default materializes CRITICAL + HIGH gaps only; --all
        # opts into the full set.

    evidentia poam list [--all] [--severity LEVEL] [--json]
        # List POA&M items in canonical order (severity-rank, has-
        # open-milestones, earliest-open-target-date, control_id).
        # --all forces the listing to include closed (REMEDIATED)
        # POA&Ms; default shows only those with open work.

    evidentia poam show <poam-id> [--json]
        # Render a single POA&M in human-readable form (default) or
        # raw JSON (--json). Shows control gap details + the
        # milestone timeline.

    evidentia poam update <poam-id> --<field>=<value>...
        # Edit a POA&M's top-level fields (status, assigned_to,
        # remediation_guidance, tags, etc.). Backward state
        # transitions are blocked by the state-machine
        # (is_valid_transition); explicit operator override is
        # not supported in v0.9.0 P2.

    evidentia poam milestone add <poam-id> --target-date Y --description D
        # Add a new milestone to an existing POA&M.

    evidentia poam milestone update <poam-id> <milestone-id> --status S
        # Update an existing milestone's status. Backward
        # transitions blocked by is_valid_transition.

    evidentia poam calendar [--window-days N] [--today YYYY-MM-DD]
        # Read-only attention-state surface: lists overdue + due-
        # soon milestones across ALL POA&Ms in the store. Bridge
        # to the v0.9.0 P3 CONMON cycle calendar.

Output format defaults to a rich table; ``--json`` for machine-
readable on list/show/calendar. Mirrors the v0.7.9 TPRM precedent's
"human first, machine on demand" convention.

Audit-trail emit: every persisted mutation (create / update /
milestone state change) fires the corresponding POAM_* EventAction
via :mod:`evidentia_core.audit`. See :mod:`docs/log-schema.md`
``evidentia.poam.*`` section for the field shape.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

import typer
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.models.common import enum_value as _enum_value
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    Milestone,
    POAMState,
)
from evidentia_core.poam.milestone import derive_attention_state
from evidentia_core.poam.state import is_valid_transition
from evidentia_core.poam_store import (
    InvalidPoamIdError,
    delete_poam,
    list_poams,
    load_poam_by_id,
    save_poam,
)
from evidentia_core.security.paths import PathTraversalError
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Plan-of-Action-and-Milestones commands (v0.9.0).")
milestone_app = typer.Typer(help="Milestone sub-commands.")
app.add_typer(milestone_app, name="milestone")

console = Console()
_log = get_logger("evidentia.cli.poam")

# ── helpers ────────────────────────────────────────────────────────


def _parse_date_or_exit(value: str | None, flag: str) -> date | None:
    """Parse an ISO-8601 date or exit cleanly. Mirrors tprm._parse_date_or_exit."""
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


def _load_poam_or_exit(poam_id: str) -> ControlGap:
    """Load a POA&M by ID or exit with a clear error message."""
    try:
        loaded = load_poam_by_id(poam_id)
    except InvalidPoamIdError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if loaded is None:
        console.print(
            f"[red]Error:[/red] No POA&M with ID {poam_id!r} "
            f"found in the store."
        )
        raise typer.Exit(code=1)
    return loaded


def _next_open_milestone(poam: ControlGap) -> Milestone | None:
    """Return the earliest open (PLANNED/IN_PROGRESS/OVERDUE) milestone, if any."""
    open_states = {
        POAMState.PLANNED.value,
        POAMState.IN_PROGRESS.value,
        POAMState.OVERDUE.value,
    }
    open_ms = [m for m in poam.poam_milestones if m.status in open_states]
    if not open_ms:
        return None
    return min(open_ms, key=lambda m: m.target_date)


def _poam_to_row(poam: ControlGap) -> tuple[str, ...]:
    """Project a POA&M into the list-table columns."""
    next_open = _next_open_milestone(poam)
    return (
        poam.id[:8],
        poam.framework,
        poam.control_id,
        poam.gap_severity,
        poam.status,
        next_open.target_date.isoformat() if next_open else "—",
        str(len(poam.poam_milestones)),
        poam.assigned_to or "—",
    )


def _render_poam_table(poams: list[ControlGap]) -> Table:
    """Build a rich Table for ``poam list`` output."""
    table = Table(title=f"POA&M items ({len(poams)} total)")
    table.add_column("ID", style="dim")
    table.add_column("Framework")
    table.add_column("Control")
    table.add_column("Severity")
    table.add_column("Gap status")
    table.add_column("Next due")
    table.add_column("Ms", justify="right")
    table.add_column("Assigned")
    for poam in poams:
        table.add_row(*_poam_to_row(poam))
    return table


def _render_poam_show(poam: ControlGap) -> None:
    """Render a POA&M in human-readable form for ``poam show``."""
    console.print(
        f"[bold]{poam.framework}:{poam.control_id}[/bold]  "
        f"[dim]({poam.id})[/dim]"
    )
    console.print(f"  Control title:      {poam.control_title}")
    console.print(f"  Severity:           [cyan]{poam.gap_severity}[/cyan]")
    console.print(f"  Gap status:         [cyan]{poam.status}[/cyan]")
    console.print(f"  Implementation:     {poam.implementation_status}")
    console.print(f"  Effort:             {poam.implementation_effort}")
    console.print(f"  Priority score:     {poam.priority_score}")
    if poam.assigned_to:
        console.print(f"  Assigned to:        {poam.assigned_to}")
    console.print(f"  Gap description:    {poam.gap_description}")
    console.print(f"  Remediation:        {poam.remediation_guidance}")
    if poam.tags:
        console.print(f"  Tags:               {', '.join(poam.tags)}")
    if poam.poam_milestones:
        console.print(f"  Milestones ({len(poam.poam_milestones)}):")
        for ms in poam.poam_milestones:
            ev_tag = f" [dim](evidence: {ms.evidence_ref})[/dim]" if ms.evidence_ref else ""
            console.print(
                f"    - [{ms.target_date.isoformat()}] "
                f"[cyan]{ms.status}[/cyan] {ms.description}"
                f"{ev_tag}  [dim]({ms.id[:8]})[/dim]"
            )
    else:
        console.print("  Milestones: [dim](none — schedule pending)[/dim]")
    console.print(f"  [dim]Created: {poam.created_at}[/dim]")
    if poam.remediated_at:
        console.print(f"  [dim]Remediated: {poam.remediated_at}[/dim]")


def _gap_passes_severity_filter(
    gap: ControlGap,
    materialize_all: bool,
) -> bool:
    """Return True if the gap should be materialized as a POA&M item.

    Default policy: critical + high severity only. ``--all`` opt-in
    materializes every severity (medium / low / informational too).
    """
    if materialize_all:
        return True
    return gap.gap_severity in {GapSeverity.CRITICAL, GapSeverity.HIGH}


# ── create ─────────────────────────────────────────────────────────


@app.command("create")
def poam_create(
    from_gap_report: Path = typer.Option(
        ...,
        "--from-gap-report",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Path to a JSON-serialized GapAnalysisReport (from "
            "`evidentia gap analyze --output report.json` or the "
            "saved gap_store). Each contained gap becomes one "
            "POA&M item, subject to the severity filter below."
        ),
    ),
    materialize_all: bool = typer.Option(
        False,
        "--all",
        help=(
            "Materialize ALL gaps as POA&M items. Without this flag, "
            "only CRITICAL + HIGH gaps are materialized (the auditor-"
            "expected default per FedRAMP POA&M guidance: open POA&M "
            "items for material findings; document non-material gaps "
            "elsewhere)."
        ),
    ),
    overwrite: bool = typer.Option(
        False,
        "--overwrite",
        help=(
            "Re-materialize POA&M items even if one already exists "
            "with the same ID (gap.id). Without this flag, existing "
            "POA&Ms are skipped to preserve milestone history."
        ),
    ),
) -> None:
    """Auto-generate POA&M items from a gap-analysis report.

    Each gap becomes one POA&M item carrying the gap's metadata
    (framework/control_id/severity/remediation_guidance) plus an
    empty initial milestone list. Operators add milestones via
    ``evidentia poam milestone add`` after creation.

    Default policy materializes only CRITICAL + HIGH severity gaps —
    the auditor-defensible default per FedRAMP POA&M Template
    Completion Guide v3.0 §3.1 (POA&M items track *material*
    findings; lower-severity gaps are documented in the SSP risk
    register without ceremony).
    """
    try:
        report = GapAnalysisReport.model_validate_json(
            from_gap_report.read_text(encoding="utf-8")
        )
    except Exception as exc:
        console.print(
            f"[red]Error:[/red] could not parse gap report "
            f"{from_gap_report}: {exc}"
        )
        raise typer.Exit(code=1) from exc

    materialized = 0
    skipped_existing = 0
    skipped_severity = 0
    skipped_malformed = 0
    for gap in report.gaps:
        if not _gap_passes_severity_filter(gap, materialize_all):
            skipped_severity += 1
            continue
        # Skip gaps whose id field cannot pass the UUID-shape gate
        # rather than crash the whole materialization loop. A
        # malformed gap.id usually indicates a hand-edited or
        # foreign-produced gap report; warn so the operator can
        # spot it without losing the other materializations.
        try:
            existing = load_poam_by_id(gap.id)
        except InvalidPoamIdError as exc:
            console.print(
                f"[yellow]Warning:[/yellow] skipping gap "
                f"{gap.framework}:{gap.control_id} with malformed id "
                f"{gap.id!r}: {exc}"
            )
            skipped_malformed += 1
            continue
        if existing is not None and not overwrite:
            skipped_existing += 1
            continue
        try:
            save_poam(gap)
        except InvalidPoamIdError as exc:
            # Defensive — the load_poam_by_id check above should have
            # surfaced this already, but the save path also validates.
            console.print(
                f"[yellow]Warning:[/yellow] skipping gap "
                f"{gap.framework}:{gap.control_id} with malformed id "
                f"{gap.id!r}: {exc}"
            )
            skipped_malformed += 1
            continue
        materialized += 1
        _log.info(
            action=EventAction.POAM_CREATED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"POA&M item created for {gap.framework}:"
                f"{gap.control_id} (severity={gap.gap_severity})"
            ),
            evidentia={
                "poam_id": gap.id,
                "control_id": f"{gap.framework}:{gap.control_id}",
                "source_report_id": report.id,
            },
        )

    malformed_phrase = (
        f", {skipped_malformed} skipped (malformed gap.id)"
        if skipped_malformed
        else ""
    )
    console.print(
        f"[green]POA&M materialization complete:[/green] "
        f"{materialized} created, {skipped_existing} skipped "
        f"(already exist; pass --overwrite to replace), "
        f"{skipped_severity} skipped (severity filter; pass --all "
        f"to include)"
        f"{malformed_phrase}"
    )


# ── list ───────────────────────────────────────────────────────────


@app.command("list")
def poam_list(
    show_all: bool = typer.Option(
        False,
        "--all",
        help=(
            "Include POA&Ms whose underlying gap is REMEDIATED or "
            "ACCEPTED. Default shows only OPEN / IN_PROGRESS gaps."
        ),
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        help=(
            "Filter by gap severity. Comma-separated; choices: "
            f"{', '.join(s.value for s in GapSeverity)}."
        ),
    ),
    owner: str | None = typer.Option(
        None,
        "--owner",
        help=(
            "v0.9.5 P3.1: filter to POA&M items where at least one "
            "milestone's `owner` matches (exact-equality). Combine "
            "with --severity for owner-scoped triage views."
        ),
    ),
    reviewer: str | None = typer.Option(
        None,
        "--reviewer",
        help=(
            "v0.9.5 P3.1: filter to POA&M items where at least one "
            "milestone's `reviewer` matches (exact-equality)."
        ),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of a rich table.",
    ),
) -> None:
    """List POA&M items in the store."""
    poams = list_poams()

    # Filter on status (default: open work only)
    if not show_all:
        # Use raw values for consistency with the routers/poam.py
        # filter pattern (both EvidentiaModel fields round-trip
        # through use_enum_values=True as strings).
        open_statuses = {GapStatus.OPEN.value, GapStatus.IN_PROGRESS.value}
        poams = [p for p in poams if p.status in open_statuses]

    # Filter on severity
    if severity:
        wanted = {s.strip() for s in severity.split(",") if s.strip()}
        valid = {s.value for s in GapSeverity}
        bad = wanted - valid
        if bad:
            console.print(
                f"[red]Error:[/red] unknown severity {sorted(bad)}; "
                f"valid choices: {sorted(valid)}"
            )
            raise typer.Exit(code=1)
        poams = [p for p in poams if p.gap_severity in wanted]

    # v0.9.5 P3.1: owner / reviewer filtering across milestone collection
    if owner is not None:
        poams = [
            p for p in poams
            if any(m.owner == owner for m in p.poam_milestones)
        ]
    if reviewer is not None:
        poams = [
            p for p in poams
            if any(m.reviewer == reviewer for m in p.poam_milestones)
        ]

    if output_json:
        typer.echo(
            json.dumps(
                [json.loads(p.model_dump_json()) for p in poams],
                indent=2,
            )
        )
        return

    console.print(_render_poam_table(poams))


# ── show ───────────────────────────────────────────────────────────


@app.command("show")
def poam_show(
    poam_id: str = typer.Argument(..., help="POA&M item UUID."),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of human form.",
    ),
) -> None:
    """Show a single POA&M item in detail."""
    poam = _load_poam_or_exit(poam_id)
    if output_json:
        typer.echo(poam.model_dump_json(indent=2))
        return
    _render_poam_show(poam)


# ── update ─────────────────────────────────────────────────────────


@app.command("update")
def poam_update(
    poam_id: str = typer.Argument(..., help="POA&M item UUID."),
    status: str | None = typer.Option(
        None,
        "--status",
        help=(
            "Set the gap-level status (open / in_progress / "
            "remediated / accepted / not_applicable). Forward-only "
            "for some transitions per the gap-store state machine."
        ),
    ),
    assigned_to: str | None = typer.Option(
        None,
        "--assigned-to",
        help="Set or clear the assigned-owner email/LDAP.",
    ),
    remediation_guidance: str | None = typer.Option(
        None,
        "--remediation-guidance",
        help="Replace the remediation_guidance text.",
    ),
    add_tag: str | None = typer.Option(
        None,
        "--add-tag",
        help="Append a tag to the POA&M's tags list (deduplicated).",
    ),
    remove_tag: str | None = typer.Option(
        None,
        "--remove-tag",
        help="Remove a tag from the POA&M's tags list.",
    ),
) -> None:
    """Edit a POA&M item's top-level fields.

    Milestone edits go through ``evidentia poam milestone update``
    (preserves the per-milestone state-machine semantics).
    """
    poam = _load_poam_or_exit(poam_id)
    prior_status = poam.status
    changed: list[str] = []

    if status is not None:
        try:
            new_status = GapStatus(status)
        except ValueError as exc:
            console.print(
                f"[red]Error:[/red] invalid --status {status!r}; "
                f"valid: {[s.value for s in GapStatus]}"
            )
            raise typer.Exit(code=1) from exc
        poam.status = new_status
        if new_status == GapStatus.REMEDIATED:
            poam.remediated_at = datetime.now(tz=poam.created_at.tzinfo)
        changed.append("status")

    if assigned_to is not None:
        poam.assigned_to = assigned_to or None
        changed.append("assigned_to")

    if remediation_guidance is not None:
        poam.remediation_guidance = remediation_guidance
        changed.append("remediation_guidance")

    if add_tag and add_tag not in poam.tags:
        poam.tags.append(add_tag)
        changed.append("tags")

    if remove_tag and remove_tag in poam.tags:
        poam.tags.remove(remove_tag)
        changed.append("tags")

    if not changed:
        console.print(
            "[yellow]No changes specified; nothing to persist.[/yellow]"
        )
        return

    save_poam(poam)
    _log.info(
        action=EventAction.POAM_UPDATED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"POA&M item {poam_id[:8]} updated: "
            f"{', '.join(changed)}"
        ),
        evidentia={
            "poam_id": poam.id,
            "control_id": f"{poam.framework}:{poam.control_id}",
            "prior_state": (
                _enum_value(prior_status) if "status" in changed else None
            ),
            "new_state": (
                _enum_value(poam.status) if "status" in changed else None
            ),
            "fields_changed": changed,
        },
    )
    # If the status transitioned to REMEDIATED, fire the dedicated
    # CLOSED event in addition to the UPDATED record.
    if "status" in changed and poam.status == GapStatus.REMEDIATED:
        _log.info(
            action=EventAction.POAM_CLOSED,
            outcome=EventOutcome.SUCCESS,
            message=f"POA&M {poam_id[:8]} closed (status=remediated)",
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "prior_state": _enum_value(prior_status),
                "new_state": GapStatus.REMEDIATED.value,
            },
        )
    console.print(
        f"[green]Updated[/green] POA&M {poam_id[:8]} "
        f"({', '.join(changed)})"
    )


# ── milestone add ──────────────────────────────────────────────────


@milestone_app.command("add")
def milestone_add(
    poam_id: str = typer.Argument(..., help="POA&M item UUID."),
    target_date: str = typer.Option(
        ...,
        "--target-date",
        help="ISO-8601 target completion date (YYYY-MM-DD).",
    ),
    description: str = typer.Option(
        ...,
        "--description",
        "-d",
        help="Human-readable milestone description.",
    ),
    status: str = typer.Option(
        POAMState.PLANNED.value,
        "--status",
        help=(
            "Initial status. Default: planned. Valid: "
            f"{[s.value for s in POAMState]}."
        ),
    ),
    evidence_ref: str | None = typer.Option(
        None,
        "--evidence-ref",
        help=(
            "Optional reference to the evidence artifact (URL/URI/"
            "Sigstore bundle path/Jira key/etc.)."
        ),
    ),
) -> None:
    """Add a new milestone to an existing POA&M."""
    parsed_date = _parse_date_or_exit(target_date, "--target-date")
    assert parsed_date is not None  # ... required by Typer
    try:
        parsed_status = POAMState(status)
    except ValueError as exc:
        console.print(
            f"[red]Error:[/red] invalid --status {status!r}; "
            f"valid: {[s.value for s in POAMState]}"
        )
        raise typer.Exit(code=1) from exc

    poam = _load_poam_or_exit(poam_id)
    ms = Milestone(
        target_date=parsed_date,
        description=description,
        status=parsed_status,
        evidence_ref=evidence_ref,
    )
    poam.poam_milestones.append(ms)
    save_poam(poam)
    _log.info(
        action=EventAction.POAM_UPDATED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"Milestone added to POA&M {poam_id[:8]}: "
            f"{description!r} ({parsed_status.value} @ {parsed_date})"
        ),
        evidentia={
            "poam_id": poam.id,
            "control_id": f"{poam.framework}:{poam.control_id}",
            "milestone_id": ms.id,
            "new_state": parsed_status.value,
        },
    )
    console.print(
        f"[green]Added milestone[/green] {ms.id[:8]} to POA&M {poam_id[:8]} "
        f"({parsed_status.value} @ {parsed_date})"
    )


# ── milestone update ───────────────────────────────────────────────


@milestone_app.command("update")
def milestone_update(
    poam_id: str = typer.Argument(..., help="POA&M item UUID."),
    milestone_id: str = typer.Argument(..., help="Milestone UUID."),
    status: str | None = typer.Option(
        None,
        "--status",
        help=(
            "Set the milestone status. Backward transitions blocked "
            "by the state machine (auditor-defensible monotonic "
            "progress). Valid: "
            f"{[s.value for s in POAMState]}."
        ),
    ),
    target_date: str | None = typer.Option(
        None,
        "--target-date",
        help="Replace the target completion date (YYYY-MM-DD).",
    ),
    description: str | None = typer.Option(
        None,
        "--description",
        "-d",
        help="Replace the milestone description.",
    ),
    evidence_ref: str | None = typer.Option(
        None,
        "--evidence-ref",
        help="Set or replace the evidence reference.",
    ),
) -> None:
    """Update an existing milestone. Backward state transitions blocked."""
    poam = _load_poam_or_exit(poam_id)
    target_ms: Milestone | None = next(
        (m for m in poam.poam_milestones if m.id == milestone_id),
        None,
    )
    if target_ms is None:
        console.print(
            f"[red]Error:[/red] No milestone {milestone_id!r} on "
            f"POA&M {poam_id!r}."
        )
        raise typer.Exit(code=1)

    prior_state = POAMState(target_ms.status)
    changed: list[str] = []

    if status is not None:
        try:
            new_state = POAMState(status)
        except ValueError as exc:
            console.print(
                f"[red]Error:[/red] invalid --status {status!r}; "
                f"valid: {[s.value for s in POAMState]}"
            )
            raise typer.Exit(code=1) from exc
        if new_state != prior_state and not is_valid_transition(
            prior_state, new_state
        ):
            console.print(
                f"[red]Error:[/red] invalid state transition "
                f"{prior_state.value} → {new_state.value}. "
                f"Backward + invalid transitions are blocked. "
                f"To re-open work, file a NEW milestone with a "
                f"fresh target_date."
            )
            raise typer.Exit(code=1)
        target_ms.status = new_state
        changed.append("status")

    if target_date is not None:
        parsed = _parse_date_or_exit(target_date, "--target-date")
        assert parsed is not None
        target_ms.target_date = parsed
        changed.append("target_date")

    if description is not None:
        target_ms.description = description
        changed.append("description")

    if evidence_ref is not None:
        target_ms.evidence_ref = evidence_ref or None
        changed.append("evidence_ref")

    if not changed:
        console.print(
            "[yellow]No changes specified; nothing to persist.[/yellow]"
        )
        return

    save_poam(poam)

    new_state = POAMState(target_ms.status)

    # Fire the appropriate event(s) for the transition.
    if "status" in changed and new_state == POAMState.COMPLETED:
        _log.info(
            action=EventAction.POAM_MILESTONE_REACHED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} completed"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
                "prior_state": prior_state.value,
                "new_state": new_state.value,
            },
        )
    elif "status" in changed and new_state == POAMState.VERIFIED:
        _log.info(
            action=EventAction.POAM_VERIFIED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} verified"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
                "prior_state": prior_state.value,
                "new_state": new_state.value,
            },
        )
    elif "status" in changed and new_state == POAMState.OVERDUE:
        _log.info(
            action=EventAction.POAM_OVERDUE,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} marked overdue"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
                "prior_state": prior_state.value,
                "new_state": new_state.value,
            },
        )
    else:
        _log.info(
            action=EventAction.POAM_UPDATED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"Milestone {milestone_id[:8]} on POA&M "
                f"{poam_id[:8]} edited: {', '.join(changed)}"
            ),
            evidentia={
                "poam_id": poam.id,
                "control_id": f"{poam.framework}:{poam.control_id}",
                "milestone_id": target_ms.id,
                "fields_changed": changed,
            },
        )

    console.print(
        f"[green]Updated[/green] milestone {milestone_id[:8]} "
        f"on POA&M {poam_id[:8]} ({', '.join(changed)})"
    )


# ── delete ─────────────────────────────────────────────────────────


@app.command("delete")
def poam_delete(
    poam_id: str = typer.Argument(..., help="POA&M item UUID."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the interactive confirmation prompt.",
    ),
) -> None:
    """Remove a POA&M item from the store.

    Auditors generally prefer transitioning a POA&M's gap status
    to REMEDIATED or ACCEPTED (preserving the record) over
    deletion. Use ``poam delete`` only for records that should
    never have existed (e.g., a mis-imported gap or test fixture).
    """
    poam = _load_poam_or_exit(poam_id)
    if not yes:
        confirmation = typer.confirm(
            f"Delete POA&M {poam_id[:8]} ({poam.framework}:"
            f"{poam.control_id})? This cannot be undone."
        )
        if not confirmation:
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(code=0)
    try:
        deleted = delete_poam(poam_id)
    except (InvalidPoamIdError, PathTraversalError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    if not deleted:
        console.print(
            f"[red]Error:[/red] POA&M {poam_id[:8]} could not be deleted "
            f"(no file on disk)."
        )
        raise typer.Exit(code=1)
    console.print(
        f"[green]Deleted[/green] POA&M {poam_id[:8]} "
        f"({poam.framework}:{poam.control_id})"
    )


# ── calendar ───────────────────────────────────────────────────────


@app.command("calendar")
def poam_calendar(
    window_days: int = typer.Option(
        7,
        "--window-days",
        min=0,
        help=(
            "How many days ahead to look for 'due soon' milestones. "
            "Default: 7 days. Overdue milestones are always included "
            "regardless of this window."
        ),
    ),
    today_override: str | None = typer.Option(
        None,
        "--today",
        help=(
            "Override 'today' for deterministic CLI snapshots "
            "(YYYY-MM-DD). Useful for CI assertions; production "
            "operators omit this flag."
        ),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit machine-readable JSON instead of a rich table.",
    ),
) -> None:
    """Show overdue + due-soon milestones across all POA&Ms.

    Read-only attention-state surface. The cycle calendar's full
    cadence-rule library (CONMON) lands in v0.9.0 P3; this command
    consumes the v0.9.0 P1 derive_attention_state helper to give
    operators a forward look right now.
    """
    today = (
        _parse_date_or_exit(today_override, "--today")
        if today_override
        else date.today()
    )
    assert today is not None  # date.today() never returns None

    all_milestones: list[tuple[ControlGap, Milestone]] = []
    for poam in list_poams():
        for ms in poam.poam_milestones:
            all_milestones.append((poam, ms))

    buckets = derive_attention_state(
        [ms for _, ms in all_milestones], today=today
    )
    poam_by_milestone_id = {
        ms.id: poam for poam, ms in all_milestones
    }

    if output_json:
        out: dict[str, Any] = {
            bucket: [
                {
                    "milestone_id": ms.id,
                    "poam_id": poam_by_milestone_id[ms.id].id,
                    "control_id": (
                        f"{poam_by_milestone_id[ms.id].framework}:"
                        f"{poam_by_milestone_id[ms.id].control_id}"
                    ),
                    "target_date": ms.target_date.isoformat(),
                    "status": ms.status,
                    "description": ms.description,
                }
                for ms in milestones
            ]
            for bucket, milestones in buckets.items()
        }
        out["window_days"] = window_days
        out["today"] = today.isoformat()
        typer.echo(json.dumps(out, indent=2))
        return

    overdue_count = len(buckets["overdue"])
    due_soon_count = len(buckets["due_soon"])
    if overdue_count == 0 and due_soon_count == 0:
        console.print(
            f"[green]No overdue or due-soon milestones[/green] "
            f"as of {today.isoformat()}."
        )
        return

    if overdue_count > 0:
        table = Table(
            title=f"OVERDUE milestones ({overdue_count}) as of {today.isoformat()}",
            title_style="bold red",
        )
        table.add_column("Milestone", style="dim")
        table.add_column("POA&M")
        table.add_column("Control")
        table.add_column("Due", style="red")
        table.add_column("Status")
        table.add_column("Description")
        for ms in buckets["overdue"]:
            poam = poam_by_milestone_id[ms.id]
            table.add_row(
                ms.id[:8],
                poam.id[:8],
                f"{poam.framework}:{poam.control_id}",
                ms.target_date.isoformat(),
                ms.status,
                ms.description[:60],
            )
        console.print(table)

    if due_soon_count > 0:
        table = Table(
            title=(
                f"Due within {window_days} day(s) ({due_soon_count}) "
                f"as of {today.isoformat()}"
            ),
            title_style="bold yellow",
        )
        table.add_column("Milestone", style="dim")
        table.add_column("POA&M")
        table.add_column("Control")
        table.add_column("Due", style="yellow")
        table.add_column("Status")
        table.add_column("Description")
        for ms in buckets["due_soon"]:
            poam = poam_by_milestone_id[ms.id]
            table.add_row(
                ms.id[:8],
                poam.id[:8],
                f"{poam.framework}:{poam.control_id}",
                ms.target_date.isoformat(),
                ms.status,
                ms.description[:60],
            )
        console.print(table)
