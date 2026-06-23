"""`evidentia ai-gov` — AI governance commands (v0.9.3 P2.5).

Operator-facing CLI surface for the v0.9.3 P2 AI governance work:

    evidentia ai-gov classify --descriptor <yaml> [--json]
        # One-shot classification (no persistence). Reads operator-
        # supplied descriptor YAML, runs the rule-based classifier,
        # prints the AISystemClassification. Useful for "what would
        # happen if we built this?" planning.

    evidentia ai-gov register --descriptor <yaml>
        # Classify + persist to the AI system registry. Emits
        # AI_SYSTEM_REGISTERED audit event. Returns the system_id.

    evidentia ai-gov list [--tier TIER] [--json]
        # List registered AI systems. Optional tier filter
        # (unacceptable / high / limited / minimal).

    evidentia ai-gov show <system-id> [--json]
        # Show a single registered system in detail.

YAML descriptor schema (matches AISystemDescriptor model):

    name: my-system
    purpose: Plain-English description.
    annex_iii_domain: employment       # optional
    decision_role: advisory             # optional
    affects_natural_persons: false      # optional
    interacts_with_natural_persons: false
    generates_synthetic_content: false
    is_prohibited_practice: false

Audit emit:

- ``classify`` fires :attr:`EventAction.AI_SYSTEM_CLASSIFIED`
- ``register`` fires :attr:`EventAction.AI_SYSTEM_REGISTERED`
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
from evidentia_core.ai_governance import (
    AIRegistryStore,
    AISystemClassification,
    AISystemDescriptor,
    AISystemRegistryEntry,
    DeploymentStatus,
    EUAIActTier,
    classify,
)
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="AI governance (EU AI Act + NIST AI RMF) — v0.9.3 P2.")
console = Console()
_log = get_logger("evidentia.cli.ai_gov")


def _load_descriptor(path: Path) -> AISystemDescriptor:
    """Load + validate an AISystemDescriptor from a YAML file."""
    import yaml as yaml_mod
    from pydantic import ValidationError

    try:
        raw = yaml_mod.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml_mod.YAMLError as exc:
        console.print(f"[red]Error:[/red] could not parse {path}: {exc}")
        raise typer.Exit(code=1) from exc

    if not isinstance(raw, dict):
        console.print(
            f"[red]Error:[/red] {path} must be a YAML mapping; "
            f"got {type(raw).__name__}"
        )
        raise typer.Exit(code=1)

    # v0.9.4 P1.4 F-V93-Q14: narrow except to (ValidationError, ValueError)
    # so genuinely unexpected errors crash to a stack trace instead of
    # being swallowed as "invalid descriptor".
    try:
        return AISystemDescriptor.model_validate(raw)
    except (ValidationError, ValueError) as exc:
        console.print(f"[red]Error:[/red] invalid descriptor: {exc}")
        raise typer.Exit(code=1) from exc


def _render_classification(
    classification: AISystemClassification,
) -> None:
    """Print a bare AISystemClassification."""
    console.print(f"[bold]{classification.descriptor_name}[/bold]")
    _render_classification_body(classification)


def _render_registry_entry(entry: AISystemRegistryEntry) -> None:
    """Print a registry entry (with descriptor + classification + meta)."""
    console.print(f"[bold]{entry.descriptor.name}[/bold]")
    console.print(f"  Provider:           {entry.provider}")
    console.print(f"  Owner:              {entry.owner}")
    console.print(f"  Deployment status:  {entry.deployment_status}")
    console.print(f"  System ID:          {entry.system_id}")
    _render_classification_body(entry.classification)


def _render_classification_body(
    classification: AISystemClassification,
) -> None:
    """Shared body output (tier + RMF + rationale + disclaimer)."""
    tier_style = {
        "unacceptable": "red",
        "high": "yellow",
        "limited": "cyan",
        "minimal": "green",
    }.get(str(classification.eu_ai_act_tier), "white")
    console.print(
        f"  EU AI Act tier:     "
        f"[{tier_style}]{classification.eu_ai_act_tier}[/{tier_style}]"
    )
    console.print(
        f"  NIST AI RMF (top):  "
        f"{classification.applicable_nist_ai_rmf_functions[0]}"
    )
    console.print("  Rationale:")
    for line in classification.rationale:
        console.print(f"    • {line}")
    console.print(
        f"\n[dim italic]{classification.disclaimer}[/dim italic]"
    )


# ── classify ──────────────────────────────────────────────────────


@app.command("classify")
def ai_gov_classify(
    descriptor_file: Path = typer.Option(
        ...,
        "--descriptor",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to AISystemDescriptor YAML.",
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON instead of rich output.",
    ),
) -> None:
    """One-shot classification (no persistence)."""
    descriptor = _load_descriptor(descriptor_file)
    classification = classify(descriptor)

    _log.info(
        action=EventAction.AI_SYSTEM_CLASSIFIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {descriptor.name!r} classified as "
            f"{classification.eu_ai_act_tier}"
        ),
        evidentia={
            "descriptor_name": descriptor.name,
            "eu_ai_act_tier": str(classification.eu_ai_act_tier),
        },
    )

    if output_json:
        typer.echo(classification.model_dump_json(indent=2))
        return
    _render_classification(classification)


# ── register ──────────────────────────────────────────────────────


@app.command("register")
def ai_gov_register(
    descriptor_file: Path = typer.Option(
        ...,
        "--descriptor",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to AISystemDescriptor YAML.",
    ),
    provider: str = typer.Option(
        ...,
        "--provider",
        help="Vendor or in-house team that supplies the AI system.",
    ),
    owner: str = typer.Option(
        ...,
        "--owner",
        help="Responsible person or team within operator org.",
    ),
    deployment_status: str = typer.Option(
        "proposed",
        "--deployment-status",
        help=(
            "Lifecycle status: proposed / in_development / pilot / "
            "production / retired. Default: proposed."
        ),
    ),
) -> None:
    """Classify + persist an AI system to the registry."""
    descriptor = _load_descriptor(descriptor_file)
    classification = classify(descriptor)

    # v0.9.3 F-V93-Q8 review fix: validate --deployment-status upfront
    # with a friendly error matching the --tier pattern in `list`,
    # instead of falling through to a Pydantic ValidationError mid-
    # construction.
    try:
        deployment_status_enum = DeploymentStatus(deployment_status)
    except ValueError:
        console.print(
            f"[red]Error:[/red] unknown deployment-status "
            f"{deployment_status!r}. Valid: "
            f"{', '.join(s.value for s in DeploymentStatus)}"
        )
        raise typer.Exit(code=1) from None

    try:
        entry = AISystemRegistryEntry(
            descriptor=descriptor,
            classification=classification,
            provider=provider,
            owner=owner,
            deployment_status=deployment_status_enum,
        )
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    store = AIRegistryStore()
    store.save(entry)

    _log.info(
        action=EventAction.AI_SYSTEM_REGISTERED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {entry.descriptor.name!r} registered "
            f"(system_id={entry.system_id})"
        ),
        evidentia={
            "system_id": entry.system_id,
            "descriptor_name": entry.descriptor.name,
            "eu_ai_act_tier": str(entry.classification.eu_ai_act_tier),
            "provider": entry.provider,
            "owner": entry.owner,
            "deployment_status": str(entry.deployment_status),
        },
    )

    console.print(
        f"[green]Registered[/green] AI system: "
        f"[bold]{entry.descriptor.name}[/bold]"
    )
    console.print(f"  system_id: {entry.system_id}")
    console.print(
        f"  EU AI Act tier: {entry.classification.eu_ai_act_tier}"
    )


# ── list ──────────────────────────────────────────────────────────


@app.command("list")
def ai_gov_list(
    tier: str | None = typer.Option(
        None,
        "--tier",
        help=(
            "Filter by EU AI Act tier: unacceptable, high, limited, "
            "or minimal."
        ),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON instead of a rich table.",
    ),
) -> None:
    """List registered AI systems."""
    store = AIRegistryStore()
    entries = store.list_all()

    if tier is not None:
        try:
            tier_enum = EUAIActTier(tier)
        except ValueError:
            console.print(
                f"[red]Error:[/red] unknown tier {tier!r}. Valid: "
                f"{', '.join(t.value for t in EUAIActTier)}"
            )
            raise typer.Exit(code=1) from None
        # v0.9.3 F-V93-Q7 review fix: drop redundant str() wrapper.
        entries = [
            e
            for e in entries
            if e.classification.eu_ai_act_tier == tier_enum.value
        ]

    if output_json:
        typer.echo(
            json.dumps(
                [json.loads(e.model_dump_json()) for e in entries],
                indent=2,
            )
        )
        return

    if not entries:
        console.print("[yellow]No registered AI systems.[/yellow]")
        return

    table = Table(title=f"Registered AI systems ({len(entries)} total)")
    table.add_column("System ID", style="dim")
    table.add_column("Name", style="bold")
    table.add_column("Tier", style="cyan")
    table.add_column("Status")
    table.add_column("Provider")
    table.add_column("Owner")
    for e in entries:
        table.add_row(
            str(e.system_id)[:8] + "…",
            e.descriptor.name,
            str(e.classification.eu_ai_act_tier),
            str(e.deployment_status),
            e.provider,
            e.owner,
        )
    console.print(table)


# ── show ──────────────────────────────────────────────────────────


@app.command("show")
def ai_gov_show(
    system_id: str = typer.Argument(..., help="System ID (UUID)."),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit JSON instead of rich output.",
    ),
) -> None:
    """Show one registered AI system in detail."""
    store = AIRegistryStore()
    try:
        entry = store.load(system_id)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if entry is None:
        console.print(
            f"[red]Error:[/red] no registered AI system with ID "
            f"{system_id!r}"
        )
        raise typer.Exit(code=1)

    if output_json:
        typer.echo(entry.model_dump_json(indent=2))
        return
    _render_registry_entry(entry)


# ── update (v0.9.4 P2.3) ──────────────────────────────────────────


@app.command("update")
def ai_gov_update(
    system_id: str = typer.Argument(..., help="System ID (UUID)."),
    owner: str | None = typer.Option(
        None,
        "--owner",
        help="New responsible person or team. Unchanged if omitted.",
    ),
    provider: str | None = typer.Option(
        None,
        "--provider",
        help="New vendor/in-house team. Unchanged if omitted.",
    ),
    deployment_status: str | None = typer.Option(
        None,
        "--deployment-status",
        help=(
            "New lifecycle status: proposed / in_development / pilot "
            "/ production / retired. Unchanged if omitted."
        ),
    ),
    ssp_reference: str | None = typer.Option(
        None,
        "--ssp-reference",
        help=(
            "v0.9.6 P3: URI / handle for the System Security Plan. "
            "Unchanged if omitted."
        ),
    ),
    emit_scr: Path | None = typer.Option(
        None,
        "--emit-scr",
        help=(
            "v0.9.6 P3: write a Significant Change Request form pair "
            "(JSON + Markdown) at <PATH>.json + <PATH>.md after the "
            "update completes. Category auto-detected from the diff "
            "(routine_recurring / adaptive / transformative)."
        ),
    ),
) -> None:
    """Update fields on an existing AI system registry entry.

    v0.9.4 P2.3: wires the ``AI_SYSTEM_UPDATED`` EventAction that
    was reserved in v0.9.3 but never fired from the CLI. Fields not
    passed are left unchanged (partial-update semantics).

    v0.9.6 P3: optional ``--emit-scr`` writes a FedRAMP-compatible
    Significant Change Request form alongside the update.
    """
    from evidentia_core.ai_governance import DeploymentStatus

    store = AIRegistryStore()
    try:
        entry = store.load(system_id)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if entry is None:
        console.print(
            f"[red]Error:[/red] no registered AI system with ID "
            f"{system_id!r}"
        )
        raise typer.Exit(code=1)

    # Validate deployment-status upfront (matches v0.9.3 F-V93-Q8 pattern).
    deployment_status_enum: DeploymentStatus | None = None
    if deployment_status is not None:
        try:
            deployment_status_enum = DeploymentStatus(deployment_status)
        except ValueError:
            console.print(
                f"[red]Error:[/red] unknown deployment-status "
                f"{deployment_status!r}. Valid: "
                f"{', '.join(s.value for s in DeploymentStatus)}"
            )
            raise typer.Exit(code=1) from None

    # Build update payload — only changed fields.
    updates: dict[str, object] = {}
    if owner is not None:
        updates["owner"] = owner
    if provider is not None:
        updates["provider"] = provider
    if deployment_status_enum is not None:
        updates["deployment_status"] = deployment_status_enum
    if ssp_reference is not None:
        updates["ssp_reference"] = ssp_reference

    if not updates:
        console.print(
            "[yellow]No fields to update[/yellow] — pass at least one "
            "of --owner / --provider / --deployment-status / "
            "--ssp-reference"
        )
        raise typer.Exit(code=1)

    # v0.9.5 F-V94-S12 closure: re-validate the merged dict through
    # ``model_validate`` so field validators run on the partial-
    # update path. ``model_copy(update={...})`` bypasses validators
    # — an operator passing an invalid owner string (e.g., empty)
    # would silently land in the registry. Validating via
    # ``model_validate({**entry.model_dump(), **updates})`` runs
    # all field validators on the merged input AND catches type-
    # coercion edge cases (DeploymentStatus enum vs. raw string).
    merged = {**entry.model_dump(mode="python"), **updates}
    updated = type(entry).model_validate(merged)
    store.save(updated)

    # v0.9.6 P3: optional SCR emit on the diff between prior + updated.
    if emit_scr is not None:
        from evidentia_core.ai_governance.scr import emit_scr_form

        scr_form = emit_scr_form(prior=entry, new=updated)
        emit_scr.parent.mkdir(parents=True, exist_ok=True)
        json_path = emit_scr.with_suffix(".json")
        md_path = emit_scr.with_suffix(".md")
        json_path.write_text(
            scr_form.model_dump_json(indent=2), encoding="utf-8"
        )
        md_path.write_text(scr_form.to_markdown(), encoding="utf-8")
        _log.info(
            action=EventAction.AI_SYSTEM_SCR_EMITTED,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"SCR form ({scr_form.category}) emitted for system "
                f"{system_id} → {json_path}, {md_path}"
            ),
            evidentia={
                "system_id": system_id,
                "scr_id": scr_form.scr_id,
                "category": scr_form.category,
                "json_path": str(json_path),
                "md_path": str(md_path),
            },
        )
        console.print(
            f"[green]SCR emitted[/green] "
            f"([bold]{scr_form.category}[/bold]) → "
            f"{json_path}, {md_path}"
        )

    _log.info(
        action=EventAction.AI_SYSTEM_UPDATED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {entry.descriptor.name!r} updated "
            f"(system_id={system_id}; fields={sorted(updates.keys())})"
        ),
        evidentia={
            "system_id": system_id,
            "descriptor_name": entry.descriptor.name,
            "changed_fields": sorted(updates.keys()),
        },
    )

    console.print(
        f"[green]Updated[/green] AI system "
        f"[bold]{entry.descriptor.name}[/bold]"
    )
    _render_registry_entry(updated)


# ── retire (v0.9.4 P2.3) ──────────────────────────────────────────


@app.command("retire")
def ai_gov_retire(
    system_id: str = typer.Argument(..., help="System ID (UUID)."),
) -> None:
    """Retire a registered AI system (sets deployment_status=retired).

    v0.9.4 P2.3: wires the ``AI_SYSTEM_RETIRED`` EventAction from
    the CLI surface (was previously only fired by the REST DELETE
    path). Unlike ``ai-gov delete <id>``, this PRESERVES the entry
    so historical audits can still see the system's classification
    + ownership history.
    """
    from evidentia_core.ai_governance import DeploymentStatus

    store = AIRegistryStore()
    try:
        entry = store.load(system_id)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if entry is None:
        console.print(
            f"[red]Error:[/red] no registered AI system with ID "
            f"{system_id!r}"
        )
        raise typer.Exit(code=1)

    if entry.deployment_status == DeploymentStatus.RETIRED:
        console.print(
            f"[yellow]Already retired[/yellow]: AI system "
            f"[bold]{entry.descriptor.name}[/bold] is already in "
            f"deployment_status=retired"
        )
        return

    retired = entry.model_copy(
        update={"deployment_status": DeploymentStatus.RETIRED}
    )
    store.save(retired)

    _log.info(
        action=EventAction.AI_SYSTEM_RETIRED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {entry.descriptor.name!r} retired "
            f"(system_id={system_id})"
        ),
        evidentia={
            "system_id": system_id,
            "descriptor_name": entry.descriptor.name,
            "previous_status": str(entry.deployment_status),
            "retirement_kind": "lifecycle",
        },
    )

    console.print(
        f"[green]Retired[/green] AI system "
        f"[bold]{entry.descriptor.name}[/bold] (entry preserved for audit)"
    )


# ── categorize-fips (v0.9.6 P3) ───────────────────────────────────


@app.command("categorize-fips")
def ai_gov_categorize_fips(
    system_id: str = typer.Argument(..., help="System ID (UUID)."),
    confidentiality: str = typer.Option(
        ...,
        "--confidentiality",
        "-c",
        help="FIPS 199 confidentiality impact: low / moderate / high.",
    ),
    integrity: str = typer.Option(
        ...,
        "--integrity",
        "-i",
        help="FIPS 199 integrity impact: low / moderate / high.",
    ),
    availability: str = typer.Option(
        ...,
        "--availability",
        "-a",
        help="FIPS 199 availability impact: low / moderate / high.",
    ),
    rationale: str | None = typer.Option(
        None,
        "--rationale",
        help=(
            "Optional free-text justification linking the impact "
            "ratings to underlying information types per NIST SP "
            "800-60."
        ),
    ),
) -> None:
    """Set FIPS 199 categorization on an AI system registry entry (v0.9.6 P3).

    The high-water-mark overall impact is auto-computed from the
    three per-objective ratings per FIPS 199 §3.
    """
    from evidentia_core.ai_governance import (
        FIPS199Categorization,
        FIPS199Impact,
    )

    store = AIRegistryStore()
    try:
        entry = store.load(system_id)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if entry is None:
        console.print(
            f"[red]Error:[/red] no registered AI system with ID "
            f"{system_id!r}"
        )
        raise typer.Exit(code=1)

    try:
        cat = FIPS199Categorization(
            confidentiality_impact=FIPS199Impact(confidentiality.lower()),
            integrity_impact=FIPS199Impact(integrity.lower()),
            availability_impact=FIPS199Impact(availability.lower()),
            rationale=rationale,
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    updated = entry.model_copy(update={"fips_199_categorization": cat})
    store.save(updated)

    _log.info(
        action=EventAction.AI_SYSTEM_FIPS_CATEGORIZED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"FIPS 199 categorized AI system {entry.descriptor.name!r} "
            f"as {cat.overall} (C={cat.confidentiality_impact}, "
            f"I={cat.integrity_impact}, A={cat.availability_impact})"
        ),
        evidentia={
            "system_id": system_id,
            "confidentiality": str(cat.confidentiality_impact),
            "integrity": str(cat.integrity_impact),
            "availability": str(cat.availability_impact),
            "overall": str(cat.overall),
        },
    )

    # Output uses the persisted string values (matches YAML / JSON
    # serialization). Pydantic ``use_enum_values=True`` on
    # EvidentiaModel means cat.overall is already a string after
    # the validator runs, but we coerce defensively for the f-string.
    overall_str = (
        cat.overall.value
        if isinstance(cat.overall, FIPS199Impact)
        else str(cat.overall)
    )
    console.print(
        f"[green]FIPS 199 categorized[/green] [bold]{entry.descriptor.name}[/bold] "
        f"→ overall=[cyan]{overall_str}[/cyan] "
        f"(C={cat.confidentiality_impact}, I={cat.integrity_impact}, "
        f"A={cat.availability_impact})"
    )


# ── set-omb-impact (v0.9.6 P3) ────────────────────────────────────


@app.command("set-omb-impact")
def ai_gov_set_omb_impact(
    system_id: str = typer.Argument(..., help="System ID (UUID)."),
    category: str = typer.Option(
        ...,
        "--category",
        help=(
            "OMB M-24-10 §5(b) category: rights_impacting / "
            "safety_impacting / rights_and_safety_impacting / "
            "neither."
        ),
    ),
) -> None:
    """Set legacy OMB M-24-10 impact category on an AI system (v0.9.6 P3).

    DEPRECATED (v0.10.12): M-24-10 was rescinded 2025-04-03 by M-25-21.
    Use ``ai-gov set-high-impact`` for new work. Retained so existing
    workflows + persisted M-24-10 inventories keep working.
    """
    from evidentia_core.ai_governance import OMBImpactCategory

    store = AIRegistryStore()
    try:
        entry = store.load(system_id)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if entry is None:
        console.print(
            f"[red]Error:[/red] no registered AI system with ID "
            f"{system_id!r}"
        )
        raise typer.Exit(code=1)

    try:
        omb_cat = OMBImpactCategory(category.lower())
    except ValueError:
        console.print(
            f"[red]Error:[/red] unknown OMB category {category!r}. "
            f"Valid: {', '.join(c.value for c in OMBImpactCategory)}"
        )
        raise typer.Exit(code=1) from None

    updated = entry.model_copy(update={"omb_impact": omb_cat})
    store.save(updated)

    _log.info(
        action=EventAction.AI_SYSTEM_OMB_CLASSIFIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"OMB M-24-10 classified AI system "
            f"{entry.descriptor.name!r} as {omb_cat}"
        ),
        evidentia={
            "system_id": system_id,
            "omb_impact": str(omb_cat),
        },
    )

    console.print(
        f"[green]OMB M-24-10[/green] classified [bold]{entry.descriptor.name}[/bold] "
        f"→ [cyan]{omb_cat.value}[/cyan]"
    )
    console.print(
        "[dim italic]Note: OMB M-24-10 was rescinded 2025-04-03 by "
        "M-25-21. Prefer `ai-gov set-high-impact` going forward.[/dim italic]"
    )


# ── set-high-impact (v0.10.12) ────────────────────────────────────


@app.command("set-high-impact")
def ai_gov_set_high_impact(
    system_id: str = typer.Argument(..., help="System ID (UUID)."),
    determination: str = typer.Option(
        ...,
        "--determination",
        help=(
            "OMB M-25-21 high-impact determination: high_impact / "
            "not_high_impact / not_assessed."
        ),
    ),
    basis: list[str] = typer.Option(
        [],
        "--basis",
        help=(
            "Consequence area(s) that make the system high-impact "
            "(repeatable): civil_rights_liberties_privacy / "
            "essential_services_access / critical_government_resources / "
            "health_and_safety / critical_infrastructure / "
            "strategic_assets. Meaningful only for high_impact."
        ),
    ),
    rationale: str | None = typer.Option(
        None,
        "--rationale",
        help="Optional free-text justification for the determination.",
    ),
) -> None:
    """Set the OMB M-25-21 high-impact AI determination on an entry (v0.10.12).

    Supersedes ``set-omb-impact`` after M-24-10's 2025-04-03 rescission.
    A ``high_impact`` determination triggers the M-25-21 minimum
    risk-management practices.
    """
    from evidentia_core.ai_governance import (
        HighImpactBasis,
        HighImpactDetermination,
        OMBHighImpactAssessment,
    )

    store = AIRegistryStore()
    try:
        entry = store.load(system_id)
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if entry is None:
        console.print(
            f"[red]Error:[/red] no registered AI system with ID "
            f"{system_id!r}"
        )
        raise typer.Exit(code=1)

    try:
        determination_enum = HighImpactDetermination(determination.lower())
    except ValueError:
        console.print(
            f"[red]Error:[/red] unknown determination {determination!r}. "
            f"Valid: {', '.join(d.value for d in HighImpactDetermination)}"
        )
        raise typer.Exit(code=1) from None

    basis_enums: list[HighImpactBasis] = []
    for raw in basis:
        try:
            basis_enums.append(HighImpactBasis(raw.lower()))
        except ValueError:
            console.print(
                f"[red]Error:[/red] unknown basis {raw!r}. Valid: "
                f"{', '.join(b.value for b in HighImpactBasis)}"
            )
            raise typer.Exit(code=1) from None

    try:
        assessment = OMBHighImpactAssessment(
            determination=determination_enum,
            bases=basis_enums,
            rationale=rationale,
        )
    except ValueError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    updated = entry.model_copy(update={"omb_high_impact": assessment})
    store.save(updated)

    _log.info(
        action=EventAction.AI_SYSTEM_HIGH_IMPACT_CLASSIFIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"OMB M-25-21 high-impact classified AI system "
            f"{entry.descriptor.name!r} as {determination_enum.value}"
        ),
        evidentia={
            "system_id": system_id,
            "determination": determination_enum.value,
            "bases": [b.value for b in basis_enums],
        },
    )

    basis_str = (
        ", ".join(b.value for b in basis_enums) if basis_enums else "—"
    )
    console.print(
        f"[green]OMB M-25-21[/green] high-impact classified "
        f"[bold]{entry.descriptor.name}[/bold] → "
        f"[cyan]{determination_enum.value}[/cyan] (bases: {basis_str})"
    )
