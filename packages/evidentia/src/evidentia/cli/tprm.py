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
from evidentia_core.tprm.concentration import (
    SUPPORTED_DIMENSIONS,
    compute_concentration,
    render_csv_report,
    render_html_report,
)
from evidentia_core.tprm.questionnaire import (
    QuestionnaireFormat,
    generate_questionnaire,
    render_csv_questionnaire,
    shipped_formats,
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
dd_app = typer.Typer(help="Due-diligence questionnaire commands.")
app.add_typer(dd_app, name="dd-questionnaire")

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
    next_review_due: str | None = typer.Option(
        None,
        "--next-review-due",
        help=(
            "Override the auto-computed next-review-due date "
            "(YYYY-MM-DD). When omitted, the value is auto-computed "
            "from criticality_tier + last_due_diligence_review."
        ),
    ),
    region: str | None = typer.Option(
        None,
        "--region",
        help=(
            "Free-text geo / cloud-region label (max 128 chars). "
            "Used by `concentration-report --by region`."
        ),
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
    nrd = _parse_date_or_exit(next_review_due, "--next-review-due")

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
        if nrd:
            data["next_review_due"] = nrd.isoformat()
        if region is not None:
            data["region"] = region
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
                    "next_review_due": (
                        nrd.isoformat() if nrd else None
                    ),
                    "region": region,
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
    """List vendors in the inventory, sorted by criticality then name.

    Note: ``--json`` output is a **bare array** of vendor records,
    suitable for ``jq``-style CLI scripting
    (``evidentia tprm vendor list --json | jq '.[].name'``). The
    REST equivalent ``GET /api/tprm/vendors`` returns a
    pagination envelope ``{total, skip, limit, vendors}`` instead;
    the shape divergence is **intentional** — CLI is unpaginated +
    optimized for shell pipes; REST carries pagination metadata
    that consumers need to know exist on the wire. Closes v0.7.9
    P0.1 Continuous-review H-2 by documenting the contract.
    """
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
    next_review_due: str | None = typer.Option(
        None,
        "--next-review-due",
        help=(
            "YYYY-MM-DD. Override the auto-computed next-review-due "
            "date; otherwise auto-recomputed when "
            "--last-due-diligence-review is updated."
        ),
    ),
    region: str | None = typer.Option(
        None,
        "--region",
        help=(
            "Free-text geo / cloud-region label (max 128 chars). "
            "Used by `concentration-report --by region`."
        ),
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
            next_review_due,
            region,
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
        if next_review_due is not None:
            vendor.next_review_due = _parse_date_or_exit(
                next_review_due, "--next-review-due"
            )
        if region is not None:
            vendor.region = region
        if regulatory_classification is not None:
            vendor.regulatory_classification = _parse_csv_enum(  # type: ignore[assignment]
                regulatory_classification, RegulatoryClassification
            )
        if residual_risk_score is not None:
            vendor.residual_risk_score = residual_risk_score
        if notes is not None:
            vendor.notes = notes

    # Re-compute next_review_due if the anchor changed AND the
    # operator didn't explicitly supply --next-review-due. Atomic
    # --next-review-due takes precedence over auto-recompute (the
    # operator is asserting a manual cadence override).
    if (
        vendor.last_due_diligence_review
        and next_review_due is None
    ):
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


# ── concentration-report ───────────────────────────────────────────


@app.command("concentration-report")
def concentration_report(
    by: str = typer.Option(
        "region,cloud-provider",
        "--by",
        help=(
            "Comma-separated dimensions to aggregate by. Choices: "
            f"{', '.join(sorted(SUPPORTED_DIMENSIONS))}."
        ),
    ),
    threshold: float | None = typer.Option(
        None,
        "--threshold",
        min=0.0,
        max=100.0,
        help=(
            "Concentration percentage (0.0-100.0). Per-value rows whose "
            "vendor share meets-or-exceeds this get flagged in the "
            "output. Omit for unflagged distribution view."
        ),
    ),
    format_: str = typer.Option(
        "html",
        "--format",
        "-f",
        help="Output format: html / json / csv.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Write to file path. If omitted: html dumps to stdout (use "
            "shell redirect); json + csv print to stdout."
        ),
    ),
) -> None:
    """Concentration-risk report across the vendor inventory.

    Aggregates the v0.7.9 P0.1 vendor inventory across configurable
    dimensions to surface concentration risk per FFIEC + OCC Bulletin
    2013-29 + FRB SR 13-19 expectations. Example uses:

        # 30% concentration threshold across region + cloud-provider
        evidentia tprm concentration-report --by region,cloud-provider \\
          --threshold 30 --output report.html

        # Service-category distribution as JSON for downstream processing
        evidentia tprm concentration-report --by service-category \\
          --format json --output dist.json

        # 4th-party concentration at 15% threshold (FFIEC critical
        # third-party scrutiny territory)
        evidentia tprm concentration-report --by 4th-party --threshold 15
    """
    if format_ not in {"html", "json", "csv"}:
        console.print(
            f"[red]Error:[/red] --format must be one of html/json/csv; "
            f"got {format_!r}."
        )
        raise typer.Exit(code=1)

    dimensions = [d.strip() for d in by.split(",") if d.strip()]
    if not dimensions:
        console.print(
            "[red]Error:[/red] --by must list at least one dimension."
        )
        raise typer.Exit(code=1)
    bad = [d for d in dimensions if d not in SUPPORTED_DIMENSIONS]
    if bad:
        console.print(
            f"[red]Error:[/red] Unsupported dimension(s) {bad!r}; "
            f"valid: {sorted(SUPPORTED_DIMENSIONS)}"
        )
        raise typer.Exit(code=1)

    vendors = list_vendors()
    report = compute_concentration(
        vendors, dimensions, threshold=threshold
    )

    if format_ == "json":
        rendered = json.dumps(
            report.model_dump(mode="json"), indent=2
        )
    elif format_ == "csv":
        rendered = render_csv_report(report)
    else:
        rendered = render_html_report(report)

    if output:
        output.write_text(rendered, encoding="utf-8")
        console.print(
            f"[green]✓[/green] Wrote {format_.upper()} report to "
            f"[bold]{output}[/bold]  "
            f"([dim]{len(vendors)} vendor(s); "
            f"{len(dimensions)} dimension(s)[/dim])"
        )
    else:
        # JSON + CSV are dumb-pipe friendly via console.print;
        # html through console.print also works (no Rich markup
        # interpretation since we set no_wrap-style behavior via
        # plain print).
        # Use sys.stdout.write to avoid any Rich-markup parsing on
        # the rendered HTML.
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")


# ── dd-questionnaire generate ──────────────────────────────────────


@dd_app.command("generate")
def dd_questionnaire_generate(
    vendor_id: str = typer.Option(
        ...,
        "--vendor-id",
        help="Vendor ID (UUID) to generate the questionnaire for.",
    ),
    format_: str = typer.Option(
        "evidentia-generic",
        "--format",
        help=(
            "Questionnaire framework. Choices: "
            f"{', '.join(f.value for f in shipped_formats())} "
            "(packaged content). Also accepts 'sig' / 'sig-lite' when "
            "supplied with --from-template (BYO XLSX path; v0.7.9 "
            "P0.2 second slice)."
        ),
    ),
    output_format: str = typer.Option(
        "json",
        "--output-format",
        help=(
            "Output format: json / csv / xlsx. xlsx requires the "
            "[xlsx] extra (`pip install 'evidentia-core[xlsx]'`)."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Write to file path. If omitted, writes to stdout — useful "
            "for pipe / shell-redirect patterns. Required for xlsx + "
            "for --from-template (binary outputs)."
        ),
    ),
    from_template: Path | None = typer.Option(
        None,
        "--from-template",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Path to a Shared Assessments licensed SIG / SIG-Lite XLSX "
            "template. Required for --format sig / sig-lite. Evidentia "
            "pre-fills vendor metadata into the standard cells; the "
            "template's question content stays untouched (license "
            "compliance). v0.7.9 P0.2 second slice."
        ),
    ),
) -> None:
    """Generate a due-diligence questionnaire pre-filled with vendor metadata.

    Pre-fills vendor name + type + criticality tier + contract dates +
    region + regulatory classification + 4th-party disclosures so the
    receiving vendor only sees control questions (not blank metadata
    forms). The vendor returns the completed file; load responses back
    into Evidentia via `evidentia tprm dd-questionnaire ingest`.

    Examples:

        # Generic FFIEC-aligned baseline as JSON
        evidentia tprm dd-questionnaire generate \\
          --vendor-id 12345678-1234-... \\
          --format evidentia-generic \\
          --output-format json \\
          --output q.json

        # CAIQ-full as XLSX (multi-sheet workbook)
        evidentia tprm dd-questionnaire generate \\
          --vendor-id 12345678-1234-... \\
          --format caiq-full \\
          --output-format xlsx \\
          --output q.xlsx

        # SIG via licensed BYO template
        evidentia tprm dd-questionnaire generate \\
          --vendor-id 12345678-1234-... \\
          --format sig \\
          --from-template path/to/SIG-2026.xlsx \\
          --output sig-prefilled.xlsx
    """
    if output_format not in {"json", "csv", "xlsx"}:
        console.print(
            f"[red]Error:[/red] --output-format must be one of "
            f"json/csv/xlsx; got {output_format!r}."
        )
        raise typer.Exit(code=1)

    try:
        fmt = QuestionnaireFormat(format_)
    except ValueError:
        console.print(
            f"[red]Error:[/red] Unknown questionnaire format "
            f"{format_!r}. Choices: "
            f"{', '.join(f.value for f in QuestionnaireFormat)}."
        )
        raise typer.Exit(code=1) from None

    vendor = _load_vendor_or_exit(vendor_id)

    # SIG / SIG-Lite BYO-template path: bypass packaged content,
    # write the operator's licensed XLSX with vendor metadata
    # pre-filled directly to the output path.
    if from_template is not None:
        from evidentia_core.tprm.questionnaire import (
            generate_from_byo_template,
        )

        if not output:
            console.print(
                "[red]Error:[/red] --output is required when "
                "--from-template is supplied (binary XLSX output)."
            )
            raise typer.Exit(code=1)
        try:
            xlsx_bytes = generate_from_byo_template(
                vendor, template_path=from_template, fmt=fmt
            )
        except (
            ValueError,
            FileNotFoundError,
            RuntimeError,
            ImportError,
        ) as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=1) from e
        output.write_bytes(xlsx_bytes)
        console.print(
            f"[green]✓[/green] Wrote BYO-template pre-filled XLSX to "
            f"[bold]{output}[/bold]  "
            f"([dim]format={fmt.value}; "
            f"vendor={vendor.name}; template={from_template.name}[/dim])"
        )
        return

    try:
        questionnaire = generate_questionnaire(vendor, fmt)
    except NotImplementedError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e

    if output_format == "json":
        rendered: str | bytes = json.dumps(
            questionnaire.model_dump(mode="json"), indent=2
        )
    elif output_format == "csv":
        rendered = render_csv_questionnaire(questionnaire)
    else:
        # xlsx
        from evidentia_core.tprm.questionnaire import (
            render_xlsx_questionnaire,
        )

        if not output:
            console.print(
                "[red]Error:[/red] --output is required when "
                "--output-format is xlsx (binary output)."
            )
            raise typer.Exit(code=1)
        try:
            rendered = render_xlsx_questionnaire(questionnaire)
        except ImportError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(code=1) from e

    if output:
        if isinstance(rendered, bytes):
            output.write_bytes(rendered)
        else:
            output.write_text(rendered, encoding="utf-8")
        console.print(
            f"[green]✓[/green] Wrote {output_format.upper()} "
            f"questionnaire to [bold]{output}[/bold]  "
            f"([dim]{len(questionnaire.questions)} question(s); "
            f"format={fmt.value}; "
            f"vendor={questionnaire.vendor.vendor_name}[/dim])"
        )
    else:
        if isinstance(rendered, bytes):
            console.print(
                "[red]Error:[/red] xlsx output requires --output "
                "(binary)."
            )
            raise typer.Exit(code=1)
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")


@dd_app.command("ingest")
def dd_questionnaire_ingest(
    questionnaire_path: Path = typer.Option(
        ...,
        "--questionnaire",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Path to the completed questionnaire file. Auto-detects "
            "format from extension: .json / .csv / .xlsx."
        ),
    ),
    vendor_id_override: str | None = typer.Option(
        None,
        "--vendor-id",
        help=(
            "Optional vendor ID override. By default the ingest "
            "auto-correlates via the questionnaire's embedded "
            "vendor_id; pass this when correlation is missing or "
            "the operator wants to record the response against a "
            "different vendor record."
        ),
    ),
    output_format: str = typer.Option(
        "table",
        "--output-format",
        help="Output format: table (default) / json.",
    ),
) -> None:
    """Ingest a completed vendor questionnaire back into Evidentia.

    Auto-detects file format from the extension (.json / .csv / .xlsx).
    Correlates to a vendor inventory record via:

    1. The ``--vendor-id`` flag, if supplied
    2. The questionnaire's embedded ``vendor_id`` (from the prefill)

    Vendor correlation is REQUIRED — without a resolvable vendor, the
    command exits with a clear error. Once the vendor is resolved, the
    parsed CompletedQuestionnaire is printed for operator review (table
    or JSON). v0.7.9 P0.2 second slice ships the parse + correlation
    surface; the persistence-to-vendor.evidence_refs[] phase is queued
    for a follow-up release once the audit-chain-of-custody
    Sigstore-signing wiring lands (P2 in the original v0.7.9 plan).

    Examples:

        # Ingest a completed JSON questionnaire (vendor auto-resolved)
        evidentia tprm dd-questionnaire ingest \\
          --questionnaire completed-q.json

        # Ingest CSV against an explicit vendor (override correlation)
        evidentia tprm dd-questionnaire ingest \\
          --questionnaire completed-q.csv \\
          --vendor-id 12345678-1234-...
    """
    from evidentia_core.tprm.questionnaire import (
        parse_completed_questionnaire,
    )

    if output_format not in {"table", "json"}:
        console.print(
            f"[red]Error:[/red] --output-format must be one of "
            f"table/json; got {output_format!r}."
        )
        raise typer.Exit(code=1)

    try:
        completed = parse_completed_questionnaire(questionnaire_path)
    except (FileNotFoundError, ValueError, ImportError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e

    resolved_vendor_id = vendor_id_override or completed.vendor_id
    if not resolved_vendor_id:
        console.print(
            "[red]Error:[/red] Could not resolve a vendor ID for the "
            "ingested questionnaire. The file's prefill block did not "
            "carry a vendor_id, and --vendor-id was not supplied. "
            "Pass --vendor-id <uuid> to record this response against "
            "a specific vendor."
        )
        raise typer.Exit(code=1)

    vendor = _load_vendor_or_exit(resolved_vendor_id)

    if output_format == "json":
        sys.stdout.write(
            json.dumps(
                {
                    "vendor": {
                        "id": vendor.id,
                        "name": vendor.name,
                    },
                    "questionnaire_id": completed.questionnaire_id,
                    "format": (
                        completed.format.value
                        if completed.format
                        else None
                    ),
                    "responses": completed.responses,
                    "ingested_at": completed.ingested_at.isoformat(),
                    "source_path": completed.source_path,
                },
                indent=2,
            )
        )
        sys.stdout.write("\n")
        return

    # Table output
    from rich.table import Table as _Table

    console.print(
        f"[green]✓[/green] Ingested questionnaire from "
        f"[bold]{questionnaire_path}[/bold]"
    )
    console.print(
        f"[dim]Vendor:[/dim] {vendor.name} ([dim]id={vendor.id}[/dim])  "
        f"[dim]Questionnaire ID:[/dim] "
        f"{completed.questionnaire_id or '(none)'}  "
        f"[dim]Format:[/dim] "
        f"{completed.format.value if completed.format else '(unknown)'}"
    )
    console.print(
        f"[dim]Responses:[/dim] {len(completed.responses)} "
        f"(answered: "
        f"{sum(1 for v in completed.responses.values() if v)})"
    )
    table = _Table(title="Vendor responses (first 25)")
    table.add_column("Question ID")
    table.add_column("Response", overflow="fold")
    for qid, resp in list(completed.responses.items())[:25]:
        table.add_row(qid, resp or "[dim](blank)[/dim]")
    console.print(table)
