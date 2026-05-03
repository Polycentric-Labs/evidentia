"""`evidentia tprm` — Third-Party Risk Management commands (v0.7.9 P0.1.3).

Provides the user-facing CLI surface on top of the v0.7.9 P0.1.1
TPRM Pydantic models + P0.1.2 vendor_store JSON-file persistence.

Subcommand structure (resolved per plan §17.A1):

    evidentia tprm vendor add        # atomic flags + --from-yaml hybrid
    evidentia tprm vendor list       # rich table + --criticality-tier / --type / --json
    evidentia tprm vendor show <id>  # human-readable formatted view + --json
    evidentia tprm vendor edit <id>  # --<field>=<value> flags / --from-yaml / --editor
    evidentia tprm vendor delete <id>  # prompt by default; --yes to bypass

Output format defaults to a rich table (A3); --json for machine-
readable on list/show. Edit + delete operate by vendor ID. The
default-output bias is "human first, machine on demand" — auditors
and risk officers running these commands interactively benefit from
formatted tables; CI/scripts pass --json explicitly.

Future v0.7.9 sub-slices (P0.2 questionnaire generator, P0.3
concentration-risk reporting, P0.4 vendor-risk collectors) will
extend the `tprm` subcommand group with `dd-questionnaire`,
`concentration-report`, etc. The `vendor` sub-group is the atomic
foundation.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

import typer
from evidentia_core.models.tprm import (
    CriticalityTier,
    RegulatoryClassification,
    Vendor,
    VendorType,
)
from evidentia_core.vendor_store import (
    InvalidVendorIdError,
    delete_vendor,
    list_vendors,
    load_vendor_by_id,
    save_vendor,
)
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Third-Party Risk Management commands.")
vendor_app = typer.Typer(help="Vendor inventory commands.")
app.add_typer(vendor_app, name="vendor")

console = Console()


# ── helpers ────────────────────────────────────────────────────────


def _parse_csv_enum(
    value: str | None, enum_cls: type[CriticalityTier | VendorType | RegulatoryClassification]
) -> list[str]:
    """Parse a comma-separated string into a validated list of enum values.

    Returns ``[]`` for ``None`` or empty input. Raises typer.BadParameter
    on any unknown value with the full set of valid choices in the message.
    """
    if not value:
        return []
    raw = [item.strip() for item in value.split(",") if item.strip()]
    valid = {e.value for e in enum_cls}
    bad = [item for item in raw if item not in valid]
    if bad:
        raise typer.BadParameter(
            f"Unknown value(s) {bad!r}; valid choices: {sorted(valid)}"
        )
    return raw


def _parse_date_or_exit(value: str | None, flag: str) -> date | None:
    """Parse an ISO-8601 date string or exit cleanly.

    Typer doesn't accept ``datetime.date`` as a parameter type
    natively (only ``datetime.datetime``), so date flags are
    declared as ``str | None`` and parsed via this helper. Returns
    ``None`` for ``None`` input; raises ``typer.Exit`` with a clear
    message on parse failure.
    """
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


def _vendor_to_table_row(v: Vendor) -> tuple[str, ...]:
    """Project a Vendor into the columns the list table renders."""
    return (
        v.id[:8],  # short-ID for table; use `show` for full
        v.name,
        v.type,
        v.criticality_tier,
        v.relationship_owner,
        str(v.next_review_due) if v.next_review_due else "—",
        str(v.residual_risk_score),
        str(len(v.fourth_parties)),
        str(len(v.evidence_refs)),
    )


def _render_vendor_table(vendors: list[Vendor]) -> Table:
    """Build a rich Table for `vendor list` output (resolved per A3)."""
    table = Table(title=f"Vendor inventory ({len(vendors)} total)")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Type")
    table.add_column("Criticality")
    table.add_column("Owner")
    table.add_column("Next review")
    table.add_column("Risk", justify="right")
    table.add_column("4P", justify="right")
    table.add_column("Ev", justify="right")
    for v in vendors:
        table.add_row(*_vendor_to_table_row(v))
    return table


def _render_vendor_show(v: Vendor) -> None:
    """Render a Vendor in human-readable form for `vendor show` (A8)."""
    console.print(f"[bold]{v.name}[/bold]  [dim]({v.id})[/dim]")
    console.print(f"  Type:               [cyan]{v.type}[/cyan]")
    console.print(f"  Criticality tier:   [cyan]{v.criticality_tier}[/cyan]")
    console.print(f"  Relationship owner: {v.relationship_owner}")
    console.print(f"  Contract start:     {v.contract_start_date}")
    console.print(
        f"  Contract end:       {v.contract_end_date or '[dim](indefinite)[/dim]'}"
    )
    console.print(
        f"  Last DD review:     {v.last_due_diligence_review or '[dim](none)[/dim]'}"
    )
    console.print(
        f"  Next review due:    {v.next_review_due or '[dim](unset; run compute_next_review_due)[/dim]'}"
    )
    console.print(
        f"  Residual risk:      {v.residual_risk_score} / 25"
    )
    if v.regulatory_classification:
        flags = ", ".join(v.regulatory_classification)
        console.print(f"  Regulatory flags:   [yellow]{flags}[/yellow]")
    if v.fourth_parties:
        console.print(f"  4th parties ({len(v.fourth_parties)}):")
        for fp in v.fourth_parties:
            console.print(f"    - {fp.name} ({fp.type}): {fp.relationship}")
    if v.evidence_refs:
        console.print(f"  Evidence refs ({len(v.evidence_refs)}):")
        for ref in v.evidence_refs:
            tag = (
                f"artifact={ref.artifact_id}"
                if ref.artifact_id
                else f"file={ref.file_path}"
            )
            console.print(f"    - {ref.title} [dim]({tag})[/dim]")
    if v.notes:
        console.print(f"  Notes: {v.notes}")
    console.print(
        f"  [dim]Created: {v.created_at}  Updated: {v.updated_at}  "
        f"evidentia: {v.evidentia_version}[/dim]"
    )


def _load_vendor_or_exit(vendor_id: str) -> Vendor:
    """Load a vendor by ID or exit with a clear error.

    Translates :class:`InvalidVendorIdError` (shape) and ``None``
    (well-formed-but-unknown) into typer.Exit(1) with a printed
    message — matches the rest of the CLI's "human-first error
    messaging" convention.
    """
    try:
        loaded = load_vendor_by_id(vendor_id)
    except InvalidVendorIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if loaded is None:
        console.print(
            f"[red]Error:[/red] No vendor with ID {vendor_id!r} found in the store."
        )
        raise typer.Exit(code=1)
    return loaded


# ── add ────────────────────────────────────────────────────────────


@vendor_app.command("add")
def vendor_add(
    name: str | None = typer.Option(
        None, "--name", "-n", help="Vendor legal name."
    ),
    type_: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help=(
            f"Vendor type. One of: {', '.join(t.value for t in VendorType)}."
        ),
    ),
    criticality_tier: str | None = typer.Option(
        None,
        "--criticality-tier",
        "-c",
        help=(
            f"FFIEC criticality tier. One of: "
            f"{', '.join(t.value for t in CriticalityTier)}."
        ),
    ),
    owner: str | None = typer.Option(
        None,
        "--owner",
        "-O",
        help="Internal relationship owner (email or LDAP identifier).",
    ),
    contract_start_date: str | None = typer.Option(
        None,
        "--contract-start-date",
        help="Contract effective date (YYYY-MM-DD).",
    ),
    contract_end_date: str | None = typer.Option(
        None,
        "--contract-end-date",
        help="Contract end date (YYYY-MM-DD); omit for indefinite.",
    ),
    last_due_diligence_review: str | None = typer.Option(
        None,
        "--last-due-diligence-review",
        help="Date of most recent completed DD review (YYYY-MM-DD).",
    ),
    regulatory_classification: str | None = typer.Option(
        None,
        "--regulatory-classification",
        help=(
            "Comma-separated list. Choices: "
            f"{', '.join(c.value for c in RegulatoryClassification)}."
        ),
    ),
    residual_risk_score: int = typer.Option(
        0,
        "--residual-risk-score",
        "-r",
        min=0,
        max=25,
        help="Residual risk score (1-25; 0 = unscored).",
    ),
    notes: str | None = typer.Option(
        None, "--notes", help="Free-text vendor notes."
    ),
    from_yaml: Path | None = typer.Option(
        None,
        "--from-yaml",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Load vendor from a YAML file. Use this for complex adds "
            "with 4th-parties + evidence-refs. Mutually exclusive with "
            "atomic-field flags except where the YAML has a missing field "
            "that a flag overrides."
        ),
    ),
) -> None:
    """Add a new vendor to the inventory.

    Hybrid input model (resolved per plan §17.A5):

      - Atomic flags (--name, --type, --criticality-tier, --owner,
        --contract-start-date) for the common case
      - --from-yaml <path> for complex adds with nested fields
        (4th-parties, evidence-refs)

    Auto-computes ``next_review_due`` when ``--last-due-diligence-review``
    is provided, using the criticality-tier cadence.
    """
    # Pre-parse date flags up front so error messages are unified
    # whether YAML or atomic-flags path runs.
    csd = _parse_date_or_exit(contract_start_date, "--contract-start-date")
    ced = _parse_date_or_exit(contract_end_date, "--contract-end-date")
    lddr = _parse_date_or_exit(
        last_due_diligence_review, "--last-due-diligence-review"
    )

    if from_yaml:
        import yaml as yaml_mod  # lazy import

        data = yaml_mod.safe_load(from_yaml.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            console.print(
                "[red]Error:[/red] --from-yaml file must be a YAML mapping at the top level."
            )
            raise typer.Exit(code=1)
        # Atomic flags override YAML-supplied values when both are set.
        if name:
            data["name"] = name
        if type_:
            data["type"] = type_
        if criticality_tier:
            data["criticality_tier"] = criticality_tier
        if owner:
            data["relationship_owner"] = owner
        if csd:
            data["contract_start_date"] = csd.isoformat()
        if ced:
            data["contract_end_date"] = ced.isoformat()
        if lddr:
            data["last_due_diligence_review"] = lddr.isoformat()
        if regulatory_classification is not None:
            data["regulatory_classification"] = _parse_csv_enum(
                regulatory_classification, RegulatoryClassification
            )
        if residual_risk_score:
            data["residual_risk_score"] = residual_risk_score
        if notes:
            data["notes"] = notes
        try:
            vendor = Vendor.model_validate(data)
        except Exception as e:
            console.print(f"[red]Error:[/red] Invalid vendor data: {e}")
            raise typer.Exit(code=1) from e
    else:
        # Atomic-flag-only path. Required-field validation surfaced
        # via Pydantic.
        missing = [
            arg
            for arg, val in (
                ("--name", name),
                ("--type", type_),
                ("--criticality-tier", criticality_tier),
                ("--owner", owner),
                ("--contract-start-date", csd),
            )
            if not val
        ]
        if missing:
            console.print(
                f"[red]Error:[/red] Missing required field(s): "
                f"{', '.join(missing)}. (Or pass --from-yaml.)"
            )
            raise typer.Exit(code=1)
        # Build via Pydantic validation so each field's enum/range/etc.
        # validators run with proper error messages.
        try:
            vendor = Vendor.model_validate(
                {
                    "name": name,
                    "type": type_,
                    "criticality_tier": criticality_tier,
                    "relationship_owner": owner,
                    "contract_start_date": csd.isoformat() if csd else None,
                    "contract_end_date": ced.isoformat() if ced else None,
                    "last_due_diligence_review": (
                        lddr.isoformat() if lddr else None
                    ),
                    "regulatory_classification": _parse_csv_enum(
                        regulatory_classification, RegulatoryClassification
                    ),
                    "residual_risk_score": residual_risk_score,
                    "notes": notes,
                }
            )
        except Exception as e:
            console.print(f"[red]Error:[/red] Invalid vendor data: {e}")
            raise typer.Exit(code=1) from e

    # Auto-compute next_review_due from the cadence helper.
    if vendor.last_due_diligence_review and vendor.next_review_due is None:
        vendor.next_review_due = vendor.compute_next_review_due()

    save_vendor(vendor)
    console.print(
        f"[green]✓[/green] Added vendor [bold]{vendor.name}[/bold] "
        f"(id: [dim]{vendor.id}[/dim])"
    )


# ── list ───────────────────────────────────────────────────────────


@vendor_app.command("list")
def vendor_list(
    criticality_tier: str | None = typer.Option(
        None,
        "--criticality-tier",
        "-c",
        help="Filter by criticality tier (critical/high/medium/low).",
    ),
    type_: str | None = typer.Option(
        None,
        "--type",
        "-t",
        help="Filter by vendor type.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON array instead of a rich table.",
    ),
) -> None:
    """List vendors in the inventory, sorted by criticality then name."""
    if criticality_tier and criticality_tier not in {
        e.value for e in CriticalityTier
    }:
        console.print(
            f"[red]Error:[/red] Unknown criticality tier {criticality_tier!r}; "
            f"choices: {sorted(e.value for e in CriticalityTier)}"
        )
        raise typer.Exit(code=1)
    if type_ and type_ not in {e.value for e in VendorType}:
        console.print(
            f"[red]Error:[/red] Unknown vendor type {type_!r}; "
            f"choices: {sorted(e.value for e in VendorType)}"
        )
        raise typer.Exit(code=1)

    vendors = list_vendors()
    if criticality_tier:
        vendors = [v for v in vendors if v.criticality_tier == criticality_tier]
    if type_:
        vendors = [v for v in vendors if v.type == type_]

    if json_output:
        # Use mode='json' so dates/datetimes serialize cleanly.
        payload = [v.model_dump(mode="json") for v in vendors]
        console.print_json(json.dumps(payload))
        return

    if not vendors:
        console.print("[dim]No vendors match the filter.[/dim]")
        return
    console.print(_render_vendor_table(vendors))


# ── show ───────────────────────────────────────────────────────────


@vendor_app.command("show")
def vendor_show(
    vendor_id: str = typer.Argument(..., help="Vendor ID (UUID)."),
    json_output: bool = typer.Option(
        False, "--json", help="Emit raw JSON instead of human-readable view."
    ),
) -> None:
    """Show a single vendor's full details."""
    vendor = _load_vendor_or_exit(vendor_id)
    if json_output:
        console.print_json(json.dumps(vendor.model_dump(mode="json")))
        return
    _render_vendor_show(vendor)


# ── edit ───────────────────────────────────────────────────────────


@vendor_app.command("edit")
def vendor_edit(
    vendor_id: str = typer.Argument(..., help="Vendor ID (UUID)."),
    name: str | None = typer.Option(None, "--name"),
    type_: str | None = typer.Option(None, "--type"),
    criticality_tier: str | None = typer.Option(None, "--criticality-tier"),
    owner: str | None = typer.Option(None, "--owner"),
    contract_end_date: str | None = typer.Option(
        None, "--contract-end-date", help="YYYY-MM-DD"
    ),
    last_due_diligence_review: str | None = typer.Option(
        None, "--last-due-diligence-review", help="YYYY-MM-DD"
    ),
    regulatory_classification: str | None = typer.Option(
        None,
        "--regulatory-classification",
        help="Comma-separated; replaces existing list.",
    ),
    residual_risk_score: int | None = typer.Option(
        None, "--residual-risk-score", min=0, max=25
    ),
    notes: str | None = typer.Option(None, "--notes"),
    from_yaml: Path | None = typer.Option(
        None,
        "--from-yaml",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Replace the vendor record from a YAML file (full replace; "
            "preserves the original ID + created_at)."
        ),
    ),
    editor: bool = typer.Option(
        False,
        "--editor",
        help=(
            "Open the current vendor record in $EDITOR as YAML; save the "
            "edited file to persist. Aborts on empty editor output."
        ),
    ),
) -> None:
    """Edit a vendor record.

    Three mutually-exclusive modes (resolved per plan §17.A6):

      - Atomic --<field>=<value> flags for one-off field updates
      - --from-yaml <path> for scripted full-replace
      - --editor to open $EDITOR with the current YAML
    """
    vendor = _load_vendor_or_exit(vendor_id)

    # Detect mode — at most one of (yaml, editor, atomic-flags) per call.
    has_atomic = any(
        v is not None
        for v in (
            name,
            type_,
            criticality_tier,
            owner,
            contract_end_date,
            last_due_diligence_review,
            regulatory_classification,
            residual_risk_score,
            notes,
        )
    )
    modes_chosen = sum([bool(from_yaml), bool(editor), has_atomic])
    if modes_chosen == 0:
        console.print(
            "[red]Error:[/red] No edit input provided. Pass either "
            "--from-yaml, --editor, or one or more --<field> flags."
        )
        raise typer.Exit(code=1)
    if modes_chosen > 1:
        console.print(
            "[red]Error:[/red] Modes are mutually exclusive: pick one of "
            "--from-yaml / --editor / atomic flags."
        )
        raise typer.Exit(code=1)

    if from_yaml:
        import yaml as yaml_mod

        data = yaml_mod.safe_load(from_yaml.read_text(encoding="utf-8")) or {}
        # Preserve identity + creation timestamp.
        data["id"] = vendor.id
        data["created_at"] = vendor.created_at.isoformat()
        try:
            vendor = Vendor.model_validate(data)
        except Exception as e:
            console.print(f"[red]Error:[/red] Invalid vendor data: {e}")
            raise typer.Exit(code=1) from e
    elif editor:
        import yaml as yaml_mod

        editor_cmd = os.environ.get("EDITOR", "vi")
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(
                yaml_mod.safe_dump(
                    vendor.model_dump(mode="json"),
                    default_flow_style=False,
                    sort_keys=False,
                )
            )
            tmp_path = Path(tmp.name)
        try:
            subprocess.run([editor_cmd, str(tmp_path)], check=True)
            edited_text = tmp_path.read_text(encoding="utf-8").strip()
            if not edited_text:
                console.print(
                    "[yellow]Editor returned empty content; aborting edit.[/yellow]"
                )
                raise typer.Exit(code=1)
            data = yaml_mod.safe_load(edited_text)
            if not isinstance(data, dict):
                console.print(
                    "[red]Error:[/red] Edited content must be a YAML mapping."
                )
                raise typer.Exit(code=1)
            data["id"] = vendor.id
            data["created_at"] = vendor.created_at.isoformat()
            vendor = Vendor.model_validate(data)
        finally:
            tmp_path.unlink(missing_ok=True)
    else:
        # Atomic-flag mode — apply each provided field.
        if name is not None:
            vendor.name = name
        if type_ is not None:
            if type_ not in {e.value for e in VendorType}:
                console.print(f"[red]Error:[/red] Unknown type {type_!r}.")
                raise typer.Exit(code=1)
            vendor.type = type_  # type: ignore[assignment]
        if criticality_tier is not None:
            if criticality_tier not in {e.value for e in CriticalityTier}:
                console.print(
                    f"[red]Error:[/red] Unknown criticality_tier {criticality_tier!r}."
                )
                raise typer.Exit(code=1)
            vendor.criticality_tier = criticality_tier  # type: ignore[assignment]
        if owner is not None:
            vendor.relationship_owner = owner
        if contract_end_date is not None:
            vendor.contract_end_date = _parse_date_or_exit(
                contract_end_date, "--contract-end-date"
            )
        if last_due_diligence_review is not None:
            vendor.last_due_diligence_review = _parse_date_or_exit(
                last_due_diligence_review, "--last-due-diligence-review"
            )
        if regulatory_classification is not None:
            vendor.regulatory_classification = _parse_csv_enum(  # type: ignore[assignment]
                regulatory_classification, RegulatoryClassification
            )
        if residual_risk_score is not None:
            vendor.residual_risk_score = residual_risk_score
        if notes is not None:
            vendor.notes = notes

    # Re-compute next_review_due if the anchor changed.
    if vendor.last_due_diligence_review:
        vendor.next_review_due = vendor.compute_next_review_due()

    save_vendor(vendor)
    console.print(
        f"[green]✓[/green] Updated vendor [bold]{vendor.name}[/bold] "
        f"(id: [dim]{vendor.id}[/dim])"
    )


# ── delete ─────────────────────────────────────────────────────────


@vendor_app.command("delete")
def vendor_delete(
    vendor_id: str = typer.Argument(..., help="Vendor ID (UUID)."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt.",
    ),
) -> None:
    """Delete a vendor from the inventory.

    Prompts for confirmation by default (resolved per plan §17.A7).
    """
    vendor = _load_vendor_or_exit(vendor_id)
    if not yes:
        confirm = typer.confirm(
            f"Delete vendor {vendor.name!r} (id: {vendor.id})?",
            default=False,
        )
        if not confirm:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)
    try:
        removed = delete_vendor(vendor.id)
    except InvalidVendorIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if removed:
        console.print(
            f"[green]✓[/green] Deleted vendor [bold]{vendor.name}[/bold]."
        )
    else:
        # Race condition — vendor existed at load time but was removed
        # before delete fired. Surface as a soft warning.
        console.print(
            f"[yellow]Warning:[/yellow] Vendor {vendor.id} was already "
            "removed by another process."
        )
        sys.exit(1)
