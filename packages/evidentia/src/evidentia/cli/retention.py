"""`evidentia retention` — audit chain-of-custody CLI (v0.7.11 P0).

Manages per-record retention metadata aligned with US/EU regulator
record-retention regimes (SEC 17a-4 / FINRA 3110 / IRS / SOX / HIPAA
/ GLBA / PCI / SR 11-7 / GDPR).

Subcommand structure:

    evidentia retention set      # add a retention record
    evidentia retention list     # show all tracked records
    evidentia retention show     # show one record's details
    evidentia retention extend   # extend lock-until on a record
    evidentia retention transition  # transition lifecycle stage
    evidentia retention report   # Markdown audit report

WORM backend operations (S3 Object Lock, Azure Immutable Blob,
GCS Bucket Lock) are deferred to v0.7.12; the abstract
:class:`evidentia_core.retention.WORMBackend` ships in v0.7.11
documenting the contract.
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import typer
from evidentia_core.retention import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
    generate_retention_report,
    is_locked,
    transition_lifecycle,
)
from evidentia_core.retention.metadata import (
    RetentionTransitionError,
    default_retention_days,
)
from evidentia_core.retention_metadata_store import (
    InvalidRetentionIdError,
    delete_retention,
    list_retention,
    load_retention_by_id,
    save_retention,
)
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Audit chain-of-custody — retention metadata + WORM.")
console = Console()


def _parse_date_or_exit(value: str | None, flag: str) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {flag} must be ISO-8601 date (YYYY-MM-DD); got {value!r}: {e}")
        raise typer.Exit(code=1) from e


@app.command("set")
def retention_set(
    classification: str = typer.Option(
        ...,
        "--classification",
        help=(
            "Retention classification: sec-17a-4 / finra-3110 / "
            "irs-tax / sox-404 / hipaa / glba / pci-dss / "
            "model-risk / gdpr / generic."
        ),
    ),
    retention_period_days: int | None = typer.Option(
        None,
        "--retention-period-days",
        help=("Retention period in calendar days. Defaults to the regulator-stated minimum for the classification."),
    ),
    record_pointer: str | None = typer.Option(
        None,
        "--record-pointer",
        help="Pointer to the underlying record (file/S3/Azure URL).",
    ),
    legal_hold: bool = typer.Option(
        False,
        "--legal-hold",
        help="Mark this record as under legal hold from the start.",
    ),
    policy_name: str | None = typer.Option(
        None,
        "--policy-name",
        help="Optional cross-reference to a RetentionPolicy.",
    ),
    notes: str | None = typer.Option(
        None,
        "--notes",
        help="Free-text operator notes.",
    ),
) -> None:
    """Add a new retention metadata record."""
    try:
        cls_enum = RetentionClassification(classification)
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] Unknown classification {classification!r}; "
            f"valid: {[c.value for c in RetentionClassification]}"
        )
        raise typer.Exit(code=1) from e

    days = retention_period_days if retention_period_days is not None else default_retention_days(cls_enum)
    try:
        metadata = RetentionMetadata(
            classification=cls_enum,
            retention_period_days=days,
            legal_hold=legal_hold,
            record_pointer=record_pointer,
            policy_name=policy_name,
            notes=notes,
        )
    except ValidationError as e:
        console.print(f"[red]Invalid retention metadata:[/red] {e}")
        raise typer.Exit(code=1) from e

    save_retention(metadata)
    console.print(
        f"[green]Tracked[/green] retention record (id: {metadata.id}); "
        f"classification: [cyan]{cls_enum.value}[/cyan]; "
        f"lock_until: [cyan]{metadata.lock_until}[/cyan]"
    )


@app.command("list")
def retention_list(
    classification: str | None = typer.Option(
        None,
        "--classification",
        help="Filter by classification.",
    ),
    lifecycle: str | None = typer.Option(
        None,
        "--lifecycle",
        help="Filter by lifecycle stage: active / preserved / expired / purged.",
    ),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON array."),
) -> None:
    """List retention records."""
    items = list_retention()
    if classification:
        if classification not in {c.value for c in RetentionClassification}:
            console.print(f"[red]Error:[/red] Unknown classification {classification!r}")
            raise typer.Exit(code=1)
        items = [m for m in items if m.classification == classification]
    if lifecycle:
        if lifecycle not in {s.value for s in RetentionLifecycleStage}:
            console.print(f"[red]Error:[/red] Unknown lifecycle {lifecycle!r}")
            raise typer.Exit(code=1)
        items = [m for m in items if m.lifecycle_stage == lifecycle]

    if json_out:
        sys.stdout.write(json.dumps([m.model_dump(mode="json") for m in items], indent=2))
        sys.stdout.write("\n")
        return

    if not items:
        console.print("[dim]No retention records.[/dim]")
        return

    table = Table(title=f"Retention records ({len(items)} total)")
    table.add_column("ID", style="dim")
    table.add_column("Classification")
    table.add_column("Stage", style="cyan")
    table.add_column("Lock-until")
    table.add_column("Locked?", justify="center")
    table.add_column("Hold?", justify="center")
    table.add_column("Pointer")
    today = date.today()
    for m in items:
        table.add_row(
            m.id[:8],
            m.classification,
            m.lifecycle_stage,
            str(m.lock_until) if m.lock_until else "—",
            "✓" if is_locked(m, today=today) else "—",
            "✓" if m.legal_hold else "—",
            m.record_pointer or "—",
        )
    console.print(table)


@app.command("show")
def retention_show(
    retention_id: str = typer.Argument(..., help="Retention record ID."),
    json_out: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
) -> None:
    """Show a retention record's full details."""
    try:
        metadata = load_retention_by_id(retention_id)
    except InvalidRetentionIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if metadata is None:
        console.print(f"[red]Error:[/red] No retention record with ID {retention_id!r} found.")
        raise typer.Exit(code=1)

    if json_out:
        sys.stdout.write(metadata.model_dump_json(indent=2))
        sys.stdout.write("\n")
        return

    today = date.today()
    console.print(f"[bold]Retention record[/bold]  [dim]({metadata.id})[/dim]")
    console.print(f"  Classification:     [cyan]{metadata.classification}[/cyan]")
    console.print(f"  Lifecycle stage:    [cyan]{metadata.lifecycle_stage}[/cyan]")
    console.print(f"  Retention period:   {metadata.retention_period_days} days")
    console.print(f"  Lock-until:         {metadata.lock_until or '—'}")
    console.print(f"  Currently locked:   {'[red]YES[/red]' if is_locked(metadata, today=today) else 'no'}")
    console.print(f"  Legal hold:         {'[red]YES[/red]' if metadata.legal_hold else 'no'}")
    if metadata.policy_name:
        console.print(f"  Policy:             {metadata.policy_name}")
    if metadata.record_pointer:
        console.print(f"  Record pointer:     {metadata.record_pointer}")
    if metadata.notes:
        console.print(f"  Notes:              {metadata.notes}")
    console.print(f"  [dim]Created: {metadata.created_at}  Updated: {metadata.updated_at}[/dim]")


@app.command("extend")
def retention_extend(
    retention_id: str = typer.Argument(..., help="Retention record ID."),
    new_lock_until: str = typer.Option(
        ...,
        "--new-lock-until",
        help="ISO-8601 date the new lock-until should be (YYYY-MM-DD).",
    ),
) -> None:
    """Extend a record's lock-until date.

    WORM-style retention only allows extending — never shortening.
    """
    try:
        metadata = load_retention_by_id(retention_id)
    except InvalidRetentionIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if metadata is None:
        console.print(f"[red]Error:[/red] No retention record with ID {retention_id!r} found.")
        raise typer.Exit(code=1)
    new_date = _parse_date_or_exit(new_lock_until, "--new-lock-until")
    if new_date is None:
        raise typer.Exit(code=1)
    if metadata.lock_until is not None and new_date < metadata.lock_until:
        console.print(
            f"[red]Error:[/red] WORM forbids shortening retention "
            f"(current lock_until={metadata.lock_until}; "
            f"requested={new_date})."
        )
        raise typer.Exit(code=1)
    from evidentia_core.models.common import utc_now

    new_metadata = metadata.model_copy(update={"lock_until": new_date, "updated_at": utc_now()})
    save_retention(new_metadata)
    console.print(
        f"[green]Extended[/green] retention id={metadata.id[:8]}; "
        f"lock_until: {metadata.lock_until} → [cyan]{new_date}[/cyan]"
    )


@app.command("transition")
def retention_transition(
    retention_id: str = typer.Argument(..., help="Retention record ID."),
    new_stage: str = typer.Option(
        ...,
        "--new-stage",
        help="Target lifecycle stage: active / preserved / expired / purged.",
    ),
) -> None:
    """Transition a record's lifecycle stage."""
    try:
        metadata = load_retention_by_id(retention_id)
    except InvalidRetentionIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if metadata is None:
        console.print(f"[red]Error:[/red] No retention record with ID {retention_id!r} found.")
        raise typer.Exit(code=1)
    try:
        stage_enum = RetentionLifecycleStage(new_stage)
    except ValueError as e:
        console.print(
            f"[red]Error:[/red] Unknown stage {new_stage!r}; valid: {[s.value for s in RetentionLifecycleStage]}"
        )
        raise typer.Exit(code=1) from e
    try:
        new_metadata = transition_lifecycle(metadata, stage_enum)
    except RetentionTransitionError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    save_retention(new_metadata)
    console.print(
        f"[green]Transitioned[/green] retention id={metadata.id[:8]}: "
        f"{metadata.lifecycle_stage} → [cyan]{new_stage}[/cyan]"
    )


@app.command("delete")
def retention_delete(
    retention_id: str = typer.Argument(..., help="Retention record ID."),
    yes: bool = typer.Option(False, "--yes", help="Skip confirmation prompt."),
) -> None:
    """Delete a retention metadata record.

    This deletes only the metadata, not the underlying record.
    Useful for cleaning up tracking entries for records that were
    deleted by other means; for actual evidence purge, transition
    the lifecycle to PURGED first.
    """
    try:
        metadata = load_retention_by_id(retention_id)
    except InvalidRetentionIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if metadata is None:
        console.print(f"[red]Error:[/red] No retention record with ID {retention_id!r} found.")
        raise typer.Exit(code=1)
    if not yes:
        confirmed = typer.confirm(
            f"Delete retention record {metadata.id} ({metadata.classification})?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)
    delete_retention(retention_id)
    console.print(f"[green]Deleted[/green] retention record [bold]{metadata.id[:8]}[/bold].")


@app.command("report")
def retention_report(
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path. If omitted, prints to stdout.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output path if it exists.",
    ),
) -> None:
    """Generate a Markdown retention-posture audit report."""
    items = list_retention()
    rendered = generate_retention_report(items)
    if output is None:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    if output.exists() and not force:
        console.print(f"[red]Error:[/red] {output} already exists; pass --force.")
        raise typer.Exit(code=1)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    console.print(f"[green]Wrote[/green] retention report to [bold]{output}[/bold] ({len(items)} record(s)).")
