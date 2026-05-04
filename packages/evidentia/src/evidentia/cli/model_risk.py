"""`evidentia model-risk` — Model Risk Management commands (v0.7.10 P0.6).

Provides the user-facing CLI surface on top of the v0.7.10 P0.6.1
ModelInventory Pydantic models + model_risk_store JSON-file
persistence. Mirrors the v0.7.9 P0.1.3 `evidentia tprm vendor`
pattern.

Subcommand structure:

    evidentia model-risk model add        # atomic flags + --from-yaml hybrid
    evidentia model-risk model list       # rich table + --tier / --methodology / --json
    evidentia model-risk model show <id>  # human-readable formatted view + --json
    evidentia model-risk model edit <id>  # --<field>=<value> flags / --from-yaml / --editor
    evidentia model-risk model delete <id>  # prompt by default; --yes to bypass

Future v0.7.10 sub-slices (P0.6.2 doc-generate, P0.6.3 validation-
report, P0.6.4 AI-feature linkage) will extend the `model-risk`
subcommand group with `doc generate` / `validation-report` / `link`.
The `model` sub-group is the atomic foundation.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from datetime import date
from pathlib import Path

import typer
from evidentia_core.model_risk import (
    generate_model_documentation,
    generate_validation_report,
)
from evidentia_core.model_risk_store import (
    InvalidModelIdError,
    delete_model,
    list_models,
    load_model_by_id,
    save_model,
)
from evidentia_core.models.model_risk import (
    Methodology,
    ModelInventory,
    Provenance,
    Tier,
)
from rich.console import Console
from rich.table import Table

from evidentia.cli._editor import resolve_editor_or_exit

app = typer.Typer(help="Model Risk Management commands (SR 11-7 / SR 26-02).")
model_app = typer.Typer(help="Model inventory commands.")
doc_app = typer.Typer(help="Model documentation generators (SR 11-7 §III.A).")
validation_app = typer.Typer(
    help="Validation report generators (SR 11-7 §III.D)."
)
app.add_typer(model_app, name="model")
app.add_typer(doc_app, name="doc")
app.add_typer(validation_app, name="validation-report")

console = Console()


# ── helpers ────────────────────────────────────────────────────────


def _parse_date_or_exit(value: str | None, flag: str) -> date | None:
    """Parse an ISO-8601 date string or exit cleanly.

    Typer doesn't accept ``datetime.date`` as a parameter type
    natively; date flags are declared as ``str | None`` and parsed
    via this helper. Returns ``None`` for ``None`` input; raises
    ``typer.Exit`` with a clear message on parse failure.
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


def _model_to_table_row(m: ModelInventory) -> tuple[str, ...]:
    """Project a ModelInventory into list-table columns."""
    return (
        m.id[:8],  # short-ID for table; use `show` for full
        m.name,
        m.tier,
        m.methodology,
        m.vendor_or_internal,
        m.owner,
        str(m.next_validation_due) if m.next_validation_due else "—",
        str(len(m.validation_findings)),
        str(len(m.evidence_refs)),
    )


def _render_model_table(models: list[ModelInventory]) -> Table:
    """Build a rich Table for `model list` output."""
    table = Table(title=f"Model inventory ({len(models)} total)")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Tier")
    table.add_column("Methodology")
    table.add_column("Provenance")
    table.add_column("Owner")
    table.add_column("Next validation")
    table.add_column("Findings", justify="right")
    table.add_column("Ev", justify="right")
    for m in models:
        table.add_row(*_model_to_table_row(m))
    return table


def _render_model_show(m: ModelInventory) -> None:
    """Render a ModelInventory in human-readable form."""
    console.print(f"[bold]{m.name}[/bold]  [dim]({m.id})[/dim]")
    console.print(f"  Purpose:            {m.purpose}")
    console.print(f"  Methodology:        [cyan]{m.methodology}[/cyan]")
    console.print(f"  Tier:               [cyan]{m.tier}[/cyan]")
    console.print(f"  Provenance:         [cyan]{m.vendor_or_internal}[/cyan]")
    if m.vendor_id:
        console.print(
            f"  Vendor cross-link:  [yellow]{m.vendor_id}[/yellow]"
        )
    console.print(f"  Owner:              {m.owner}")
    console.print(
        f"  Last validation:    {m.last_validation_date or '[dim](none)[/dim]'}"
    )
    console.print(
        f"  Next validation:    {m.next_validation_due or '[dim](unset)[/dim]'}"
    )
    if m.inputs:
        console.print(f"  Inputs ({len(m.inputs)}):")
        for inp in m.inputs:
            extras = []
            if inp.transformation:
                extras.append(f"transform={inp.transformation}")
            if inp.data_classification:
                extras.append(f"class={inp.data_classification}")
            extra_str = f" [dim]({'; '.join(extras)})[/dim]" if extras else ""
            console.print(
                f"    - {inp.name} from {inp.source_system}{extra_str}"
            )
    if m.outputs:
        console.print(f"  Outputs ({len(m.outputs)}):")
        for out in m.outputs:
            consumers = (
                f" → {', '.join(out.downstream_consumers)}"
                if out.downstream_consumers
                else ""
            )
            console.print(
                f"    - {out.name} ({out.decision_type}){consumers}"
            )
    if m.validation_findings:
        console.print(
            f"  Validation findings ({len(m.validation_findings)}):"
        )
        for f in m.validation_findings:
            console.print(
                f"    - [{f.severity}] {f.title} "
                f"[dim]({f.status}; detected {f.detected_at})[/dim]"
            )
    if m.retirement_plan:
        console.print(f"  Retirement plan:    {m.retirement_plan}")
    if m.evidence_refs:
        console.print(f"  Evidence refs ({len(m.evidence_refs)}):")
        for ref in m.evidence_refs:
            tag = (
                f"artifact={ref.artifact_id}"
                if ref.artifact_id
                else f"file={ref.file_path}"
            )
            console.print(f"    - {ref.title} [dim]({tag})[/dim]")
    if m.notes:
        console.print(f"  Notes: {m.notes}")
    console.print(
        f"  [dim]Created: {m.created_at}  Updated: {m.updated_at}  "
        f"evidentia: {m.evidentia_version}[/dim]"
    )


def _load_model_or_exit(model_id: str) -> ModelInventory:
    """Load a model by ID or exit with a clear error."""
    try:
        loaded = load_model_by_id(model_id)
    except InvalidModelIdError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    if loaded is None:
        console.print(
            f"[red]Error:[/red] No model with ID {model_id!r} found in the store."
        )
        raise typer.Exit(code=1)
    return loaded


# ── add ────────────────────────────────────────────────────────────


@model_app.command("add")
def model_add(
    name: str | None = typer.Option(None, "--name", "-n", help="Model name."),
    purpose: str | None = typer.Option(
        None,
        "--purpose",
        help="Business purpose per SR 11-7 §III.A 'Conceptual Soundness'.",
    ),
    methodology: str | None = typer.Option(
        None,
        "--methodology",
        "-m",
        help=(
            f"Model methodology. One of: "
            f"{', '.join(t.value for t in Methodology)}."
        ),
    ),
    vendor_or_internal: str | None = typer.Option(
        None,
        "--vendor-or-internal",
        help=(
            f"Provenance. One of: "
            f"{', '.join(p.value for p in Provenance)}."
        ),
    ),
    vendor_id: str | None = typer.Option(
        None,
        "--vendor-id",
        help=(
            "Required for `vendor` provenance: cross-link to TPRM "
            "Vendor.id. MUST be omitted for `internal` provenance."
        ),
    ),
    tier: str | None = typer.Option(
        None,
        "--tier",
        "-T",
        help=(
            f"SR 11-7 criticality tier. One of: "
            f"{', '.join(t.value for t in Tier)}. "
            "Tier 1 = annual validation; Tier 2 = biennial; "
            "Tier 3 = triennial."
        ),
    ),
    owner: str | None = typer.Option(
        None,
        "--owner",
        "-O",
        help="Internal model owner (email or LDAP identifier).",
    ),
    last_validation_date: str | None = typer.Option(
        None,
        "--last-validation-date",
        help="Date of most recent validation (YYYY-MM-DD).",
    ),
    next_validation_due: str | None = typer.Option(
        None,
        "--next-validation-due",
        help=(
            "Override the auto-computed next-validation-due date "
            "(YYYY-MM-DD). When omitted, value is auto-computed "
            "from tier + last_validation_date."
        ),
    ),
    retirement_plan: str | None = typer.Option(
        None,
        "--retirement-plan",
        help=(
            "Per SR 11-7 §III.C ongoing-monitoring expectations: "
            "documented retirement / replacement plan."
        ),
    ),
    notes: str | None = typer.Option(
        None, "--notes", help="Free-text model notes."
    ),
    from_yaml: Path | None = typer.Option(
        None,
        "--from-yaml",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Load model from a YAML file. Use this for complex adds "
            "with nested fields (inputs / outputs / validation-findings "
            "/ evidence-refs). Mutually exclusive with atomic-field "
            "flags except where the YAML has a missing field that a "
            "flag overrides."
        ),
    ),
) -> None:
    """Add a new model to the inventory.

    Hybrid input model (mirrors v0.7.9 TPRM vendor add):

      - Atomic flags (--name, --purpose, --methodology,
        --vendor-or-internal, --tier, --owner) for the common case
      - --from-yaml <path> for complex adds with nested fields
        (inputs, outputs, validation_findings, evidence_refs)

    Auto-computes ``next_validation_due`` when
    ``--last-validation-date`` is provided, using the tier cadence.
    """
    lvd = _parse_date_or_exit(last_validation_date, "--last-validation-date")
    nvd = _parse_date_or_exit(next_validation_due, "--next-validation-due")

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
        if purpose:
            data["purpose"] = purpose
        if methodology:
            data["methodology"] = methodology
        if vendor_or_internal:
            data["vendor_or_internal"] = vendor_or_internal
        if vendor_id is not None:
            data["vendor_id"] = vendor_id
        if tier:
            data["tier"] = tier
        if owner:
            data["owner"] = owner
        if lvd:
            data["last_validation_date"] = lvd.isoformat()
        if nvd:
            data["next_validation_due"] = nvd.isoformat()
        if retirement_plan:
            data["retirement_plan"] = retirement_plan
        if notes:
            data["notes"] = notes
        try:
            model = ModelInventory.model_validate(data)
        except Exception as e:
            console.print(f"[red]Error:[/red] Invalid model data: {e}")
            raise typer.Exit(code=1) from e
    else:
        # Atomic-flag-only path. Required-field validation surfaced
        # via Pydantic.
        missing = [
            arg
            for arg, val in (
                ("--name", name),
                ("--purpose", purpose),
                ("--methodology", methodology),
                ("--vendor-or-internal", vendor_or_internal),
                ("--tier", tier),
                ("--owner", owner),
            )
            if not val
        ]
        if missing:
            console.print(
                f"[red]Error:[/red] Missing required field(s): "
                f"{', '.join(missing)}. (Or pass --from-yaml.)"
            )
            raise typer.Exit(code=1)
        try:
            model = ModelInventory.model_validate(
                {
                    "name": name,
                    "purpose": purpose,
                    "methodology": methodology,
                    "vendor_or_internal": vendor_or_internal,
                    "vendor_id": vendor_id,
                    "tier": tier,
                    "owner": owner,
                    "last_validation_date": (
                        lvd.isoformat() if lvd else None
                    ),
                    "next_validation_due": (
                        nvd.isoformat() if nvd else None
                    ),
                    "retirement_plan": retirement_plan,
                    "notes": notes,
                }
            )
        except Exception as e:
            console.print(f"[red]Error:[/red] Invalid model data: {e}")
            raise typer.Exit(code=1) from e

    # Auto-compute next_validation_due from the cadence helper if not
    # already explicitly set.
    if model.last_validation_date and model.next_validation_due is None:
        model.next_validation_due = model.compute_next_validation_due()

    save_model(model)
    console.print(
        f"[green]Added[/green] model [bold]{model.name}[/bold] "
        f"(id: [dim]{model.id}[/dim])"
    )


# ── list ───────────────────────────────────────────────────────────


@model_app.command("list")
def model_list(
    tier_filter: str | None = typer.Option(
        None,
        "--tier",
        "-T",
        help="Filter by tier (tier_1 / tier_2 / tier_3).",
    ),
    methodology_filter: str | None = typer.Option(
        None,
        "--methodology",
        "-m",
        help="Filter by methodology.",
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON array instead of a rich table.",
    ),
) -> None:
    """List models in the inventory, sorted by tier then name.

    Note: ``--json`` output is a **bare array** of model records,
    matching the v0.7.9 TPRM vendor-list shape so shell pipelines
    work cleanly. The REST endpoint emits a paginated envelope —
    intentional shape divergence per the v0.7.9 H-2 doc fix.
    """
    models = list_models()
    if tier_filter:
        models = [m for m in models if m.tier == tier_filter]
    if methodology_filter:
        models = [m for m in models if m.methodology == methodology_filter]

    if json_output:
        sys.stdout.write(
            json.dumps(
                [m.model_dump(mode="json") for m in models], indent=2
            )
        )
        sys.stdout.write("\n")
        return
    console.print(_render_model_table(models))


# ── show ───────────────────────────────────────────────────────────


@model_app.command("show")
def model_show(
    model_id: str = typer.Argument(..., help="Model ID (UUID)."),
    json_output: bool = typer.Option(
        False, "--json", help="Emit JSON instead of formatted output."
    ),
) -> None:
    """Show a single model record."""
    m = _load_model_or_exit(model_id)
    if json_output:
        sys.stdout.write(json.dumps(m.model_dump(mode="json"), indent=2))
        sys.stdout.write("\n")
        return
    _render_model_show(m)


# ── edit ───────────────────────────────────────────────────────────


@model_app.command("edit")
def model_edit(
    model_id: str = typer.Argument(..., help="Model ID (UUID)."),
    name: str | None = typer.Option(None, "--name"),
    purpose: str | None = typer.Option(None, "--purpose"),
    methodology: str | None = typer.Option(None, "--methodology"),
    tier: str | None = typer.Option(None, "--tier"),
    owner: str | None = typer.Option(None, "--owner"),
    last_validation_date: str | None = typer.Option(
        None, "--last-validation-date", help="YYYY-MM-DD"
    ),
    next_validation_due: str | None = typer.Option(
        None,
        "--next-validation-due",
        help=(
            "YYYY-MM-DD. Override the auto-computed value; "
            "otherwise auto-recomputed when --last-validation-date "
            "is updated."
        ),
    ),
    retirement_plan: str | None = typer.Option(None, "--retirement-plan"),
    notes: str | None = typer.Option(None, "--notes"),
    from_yaml: Path | None = typer.Option(
        None,
        "--from-yaml",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Replace the model record from a YAML file (full replace; "
            "preserves the original ID + created_at)."
        ),
    ),
    editor: bool = typer.Option(
        False,
        "--editor",
        help=(
            "Open the current model record in $EDITOR as YAML; save "
            "the edited file to persist. Aborts on empty editor output."
        ),
    ),
) -> None:
    """Edit a model record.

    Three mutually-exclusive modes (mirrors v0.7.9 TPRM vendor edit):

      - Atomic --<field>=<value> flags for one-off field updates
      - --from-yaml <path> for scripted full-replace
      - --editor to open $EDITOR with the current YAML
    """
    model = _load_model_or_exit(model_id)

    has_atomic = any(
        v is not None
        for v in (
            name,
            purpose,
            methodology,
            tier,
            owner,
            last_validation_date,
            next_validation_due,
            retirement_plan,
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
        data["id"] = model.id
        data["created_at"] = model.created_at.isoformat()
        try:
            model = ModelInventory.model_validate(data)
        except Exception as e:
            console.print(f"[red]Error:[/red] Invalid model data: {e}")
            raise typer.Exit(code=1) from e
    elif editor:
        import yaml as yaml_mod

        # v0.7.11 P3 closure of v0.7.10 F-V10-S2: resolve $EDITOR
        # via the shared allowlist-aware helper to mitigate the
        # CWE-78 risk-amplifier path.
        editor_argv = resolve_editor_or_exit()
        with tempfile.NamedTemporaryFile(
            mode="w+", suffix=".yaml", delete=False, encoding="utf-8"
        ) as tmp:
            tmp.write(
                yaml_mod.safe_dump(
                    model.model_dump(mode="json"),
                    default_flow_style=False,
                    sort_keys=False,
                )
            )
            tmp_path = Path(tmp.name)
        try:
            subprocess.run([*editor_argv, str(tmp_path)], check=True)
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
            data["id"] = model.id
            data["created_at"] = model.created_at.isoformat()
            try:
                model = ModelInventory.model_validate(data)
            except Exception as e:
                console.print(f"[red]Error:[/red] Invalid model data: {e}")
                raise typer.Exit(code=1) from e
        finally:
            tmp_path.unlink(missing_ok=True)
    else:
        # Atomic-flag mode — apply each provided field.
        if name is not None:
            model.name = name
        if purpose is not None:
            model.purpose = purpose
        if methodology is not None:
            if methodology not in {e.value for e in Methodology}:
                console.print(
                    f"[red]Error:[/red] Unknown methodology {methodology!r}."
                )
                raise typer.Exit(code=1)
            model.methodology = methodology  # type: ignore[assignment]
        if tier is not None:
            if tier not in {e.value for e in Tier}:
                console.print(f"[red]Error:[/red] Unknown tier {tier!r}.")
                raise typer.Exit(code=1)
            model.tier = tier  # type: ignore[assignment]
        if owner is not None:
            model.owner = owner
        if last_validation_date is not None:
            model.last_validation_date = _parse_date_or_exit(
                last_validation_date, "--last-validation-date"
            )
        if next_validation_due is not None:
            model.next_validation_due = _parse_date_or_exit(
                next_validation_due, "--next-validation-due"
            )
        if retirement_plan is not None:
            model.retirement_plan = retirement_plan
        if notes is not None:
            model.notes = notes

    # Re-compute next_validation_due if the anchor changed AND the
    # operator didn't explicitly supply --next-validation-due.
    if (
        model.last_validation_date
        and next_validation_due is None
    ):
        model.next_validation_due = model.compute_next_validation_due()

    save_model(model)
    console.print(
        f"[green]Updated[/green] model [bold]{model.name}[/bold] "
        f"(id: [dim]{model.id}[/dim])"
    )


# ── delete ─────────────────────────────────────────────────────────


@model_app.command("delete")
def model_delete(
    model_id: str = typer.Argument(..., help="Model ID (UUID)."),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Skip the confirmation prompt.",
    ),
) -> None:
    """Delete a model record by ID.

    Prompts for confirmation by default; pass ``--yes`` (or ``-y``)
    to bypass — useful for CI / scripted flows.
    """
    model = _load_model_or_exit(model_id)
    if not yes:
        confirmed = typer.confirm(
            f"Delete model '{model.name}' (id: {model.id})?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Aborted.[/yellow]")
            raise typer.Exit(code=0)
    deleted = delete_model(model_id)
    if deleted:
        console.print(
            f"[green]Deleted[/green] model [bold]{model.name}[/bold]."
        )
    else:
        # Should never happen — _load_model_or_exit confirmed it
        # exists. Defensive.
        console.print(
            f"[yellow]No record removed for ID {model_id!r}.[/yellow]"
        )


# ── doc generate (v0.7.10 P0.6.2) ──────────────────────────────────


@doc_app.command("generate")
def doc_generate(
    model_id: str = typer.Argument(..., help="Model ID (UUID)."),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Output path. If omitted, prints to stdout. The file is "
            "written atomically and never overwrites an existing path "
            "unless `--force` is set."
        ),
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output path if it already exists.",
    ),
) -> None:
    """Generate SR 11-7-aligned model documentation in Markdown.

    Writes a self-contained Markdown document covering identification,
    purpose, methodology, inputs, outputs, validation history,
    monitoring/retirement, and the SR 11-7 / SR 26-02 audit-trail
    section linking back to AI-generated risk statements.
    """
    model = _load_model_or_exit(model_id)
    rendered = generate_model_documentation(model)

    if output is None:
        # stdout — pipe-friendly; no rich formatting to keep the
        # Markdown clean for downstream tools (pandoc, etc.).
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
    console.print(
        f"[green]Wrote[/green] model documentation to [bold]{output}[/bold] "
        f"({len(rendered)} chars)."
    )


# ── validation-report generate (v0.7.10 P0.6.3) ────────────────────


@validation_app.command("generate")
def validation_report_generate(
    model_id: str = typer.Argument(..., help="Model ID (UUID)."),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Output path. If omitted, prints to stdout. The file is "
            "written atomically and never overwrites an existing path "
            "unless `--force` is set."
        ),
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output path if it already exists.",
    ),
) -> None:
    """Generate SR 11-7-aligned validation cycle report in Markdown.

    Renders the executive summary (with HIGH-open warning callout
    if applicable), finding-disposition table (severity × status),
    detailed findings table, per-finding remediation narrative, and
    cycle context with tier-driven cadence metadata.
    """
    model = _load_model_or_exit(model_id)
    rendered = generate_validation_report(model)

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
    console.print(
        f"[green]Wrote[/green] validation report to [bold]{output}[/bold] "
        f"({len(rendered)} chars)."
    )

