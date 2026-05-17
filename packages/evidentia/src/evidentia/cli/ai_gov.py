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

    try:
        return AISystemDescriptor.model_validate(raw)
    except Exception as exc:
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
