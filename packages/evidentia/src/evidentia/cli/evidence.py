"""`evidentia evidence` — Evidence artifact CLI (v0.9.6 P2).

Closes the v0.9.5 P3.2 deferral by surfacing the v0.9.6 WORM-
enforced evidence store at the operator-facing CLI layer:

- ``evidence save <yaml>`` — write a new artifact OR a new version
  within an existing lineage chain (the YAML defines which via
  its ``lineage_id`` + ``predecessor_id`` + ``version`` fields).
  WORM enforcement: collisions on ``v<N>.json`` surface as a clear
  error with the canonical recovery suggestion (call
  :meth:`EvidenceArtifact.new_version`).
- ``evidence history <lineage_id>`` — walk the lineage chain,
  rendering every persisted version with its timestamps.
- ``evidence show <lineage_id> --version N`` — render one
  specific version (full content + metadata).

RBAC: ``save`` requires the ``write`` action; ``history`` and
``show`` require ``read``. The CLI mirrors the FastAPI router
contract from v0.9.5 + composes with the v0.9.6 P1
:func:`evidentia.cli._rbac.require_role_cli` decorator.

Audit-trail emit: every persisted save fires
:attr:`EventAction.EVIDENCE_VERSION_PERSISTED`; WORM blocks fire
:attr:`EventAction.EVIDENCE_WORM_VIOLATION_BLOCKED`; reads fire
:attr:`EventAction.EVIDENCE_LINEAGE_QUERIED`. See
:mod:`docs/log-schema.md` ``evidentia.evidence.*`` section for the
field shape.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer
import yaml as yaml_mod
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.evidence_store import (
    EVIDENCE_STORE_ENV_VAR,
    EvidenceWORMViolation,
    InvalidEvidenceIdError,
    list_lineage,
    load_evidence_version,
    save_evidence,
)
from evidentia_core.models.evidence import EvidenceArtifact
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from evidentia.cli._rbac import require_role_cli

app = typer.Typer(help="Evidence-artifact lineage commands (v0.9.6 P2).")
console = Console()
_log = get_logger("evidentia.cli.evidence")


def _load_yaml_artifact_or_exit(path: Path) -> EvidenceArtifact:
    """Parse a YAML / JSON file into an :class:`EvidenceArtifact`.

    Accepts both formats — :func:`yaml.safe_load` reads JSON cleanly
    too, which mirrors the v0.7.x convention across the rest of the
    CLI (one input parser; operators can author either format).
    Exits with code 2 (CLI usage error) on parse / shape failures
    so CI jobs can distinguish "operator gave bad input" from
    "evidentia itself failed" (exit 1).
    """
    if not path.exists():
        console.print(f"[red]Error:[/red] artifact file not found: {path}")
        raise typer.Exit(code=2)
    try:
        raw = yaml_mod.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml_mod.YAMLError as exc:
        console.print(f"[red]Error:[/red] could not parse {path}: {exc}")
        raise typer.Exit(code=2) from exc
    if not isinstance(raw, dict):
        console.print(f"[red]Error:[/red] {path} must contain a mapping at the top level; got {type(raw).__name__}")
        raise typer.Exit(code=2)
    try:
        return EvidenceArtifact.model_validate(raw)
    except ValidationError as exc:
        console.print(f"[red]Error:[/red] {path} does not match the EvidenceArtifact schema:\n{exc}")
        raise typer.Exit(code=2) from exc


# ── save ───────────────────────────────────────────────────────────


@app.command("save")
@require_role_cli("write")
def evidence_save(
    yaml_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Path to a YAML or JSON file describing the evidence "
            "artifact. Must validate against the EvidenceArtifact "
            "schema. For a new lineage, leave ``lineage_id`` and "
            "``predecessor_id`` unset + ``version=1`` (the default). "
            "For a new version in an existing chain, set ``lineage_"
            "id`` to the chain root + ``predecessor_id`` to the "
            "prior version's ``id`` + ``version=N+1``."
        ),
    ),
    store_dir: Path | None = typer.Option(
        None,
        "--store-dir",
        help=(f"Override the evidence-store directory. Defaults to ${EVIDENCE_STORE_ENV_VAR} or platformdirs."),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit a structured JSON summary instead of human text.",
    ),
) -> None:
    """Persist an evidence artifact (new lineage or new version).

    WORM enforcement: collisions on ``v<N>.json`` raise a clear
    error pointing at the canonical recovery (call
    :meth:`EvidenceArtifact.new_version` to construct v<N+1>).
    """
    artifact = _load_yaml_artifact_or_exit(yaml_file)
    try:
        path = save_evidence(artifact, evidence_store_dir=store_dir)
    except EvidenceWORMViolation as exc:
        _log.warning(
            action=EventAction.EVIDENCE_WORM_VIOLATION_BLOCKED,
            outcome=EventOutcome.FAILURE,
            message=str(exc),
            evidentia={
                "lineage_id": exc.lineage_id,
                "attempted_version": exc.attempted_version,
                "next_version": exc.next_version,
                "source_file": str(yaml_file),
            },
        )
        console.print(f"[red]WORM violation:[/red] {exc}")
        raise typer.Exit(code=1) from exc
    except InvalidEvidenceIdError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    _log.info(
        action=EventAction.EVIDENCE_VERSION_PERSISTED,
        outcome=EventOutcome.SUCCESS,
        message=(f"Persisted evidence v{artifact.version} for lineage {artifact.effective_lineage_id}"),
        evidentia={
            "artifact_id": artifact.id,
            "lineage_id": artifact.effective_lineage_id,
            "version": artifact.version,
            "predecessor_id": artifact.predecessor_id,
            "path": str(path),
        },
    )

    if output_json:
        console.print_json(
            json.dumps(
                {
                    "artifact_id": artifact.id,
                    "lineage_id": artifact.effective_lineage_id,
                    "version": artifact.version,
                    "predecessor_id": artifact.predecessor_id,
                    "path": str(path),
                }
            )
        )
    else:
        console.print(
            f"[green]Saved[/green] v{artifact.version} for lineage "
            f"[cyan]{artifact.effective_lineage_id}[/cyan] → {path}"
        )


# ── history ────────────────────────────────────────────────────────


@app.command("history")
@require_role_cli("read")
def evidence_history(
    lineage_id: str = typer.Argument(
        ...,
        help="Lineage UUID. Use the chain root's id (v1.id) or any version's effective_lineage_id.",
    ),
    store_dir: Path | None = typer.Option(
        None,
        "--store-dir",
        help=(f"Override the evidence-store directory. Defaults to ${EVIDENCE_STORE_ENV_VAR} or platformdirs."),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit a structured JSON list instead of human text.",
    ),
) -> None:
    """Walk a lineage chain — list every persisted version with timestamps."""
    try:
        artifacts = list_lineage(lineage_id, evidence_store_dir=store_dir)
    except InvalidEvidenceIdError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    _log.info(
        action=EventAction.EVIDENCE_LINEAGE_QUERIED,
        outcome=EventOutcome.SUCCESS,
        message=f"Queried lineage {lineage_id} ({len(artifacts)} versions)",
        evidentia={
            "lineage_id": lineage_id,
            "version_count": len(artifacts),
        },
    )

    if output_json:
        console.print_json(
            json.dumps(
                [
                    {
                        "artifact_id": a.id,
                        "version": a.version,
                        "predecessor_id": a.predecessor_id,
                        "title": a.title,
                        "collected_at": a.collected_at.isoformat(),
                        "collected_by": a.collected_by,
                    }
                    for a in artifacts
                ]
            )
        )
        return

    if not artifacts:
        console.print(f"[yellow]No versions found for lineage {lineage_id}.[/yellow]")
        return

    table = Table(title=f"Lineage {lineage_id} — {len(artifacts)} version(s)")
    table.add_column("v", justify="right")
    table.add_column("Artifact ID", style="dim")
    table.add_column("Title")
    table.add_column("Collected at")
    table.add_column("Collected by")
    for a in artifacts:
        table.add_row(
            str(a.version),
            a.id[:8],
            a.title,
            a.collected_at.isoformat(),
            a.collected_by,
        )
    console.print(table)


# ── show ───────────────────────────────────────────────────────────


@app.command("show")
@require_role_cli("read")
def evidence_show(
    lineage_id: str = typer.Argument(
        ...,
        help="Lineage UUID.",
    ),
    version: int = typer.Option(
        ...,
        "--version",
        "-V",
        min=1,
        help="Sequence number within the lineage chain (>=1).",
    ),
    store_dir: Path | None = typer.Option(
        None,
        "--store-dir",
        help=(f"Override the evidence-store directory. Defaults to ${EVIDENCE_STORE_ENV_VAR} or platformdirs."),
    ),
    output_json: bool = typer.Option(
        False,
        "--json",
        help="Emit the artifact as JSON (the full model_dump).",
    ),
) -> None:
    """Render one specific version of a lineage chain."""
    try:
        artifact = load_evidence_version(lineage_id, version, evidence_store_dir=store_dir)
    except InvalidEvidenceIdError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if artifact is None:
        console.print(f"[red]Error:[/red] no v{version} found for lineage {lineage_id}.")
        raise typer.Exit(code=1)

    _log.info(
        action=EventAction.EVIDENCE_LINEAGE_QUERIED,
        outcome=EventOutcome.SUCCESS,
        message=(f"Loaded v{version} of lineage {lineage_id} (artifact {artifact.id})"),
        evidentia={
            "lineage_id": lineage_id,
            "version": version,
            "artifact_id": artifact.id,
        },
    )

    if output_json:
        console.print_json(artifact.model_dump_json())
        return

    console.print(f"[bold]{artifact.title}[/bold]  [dim]({artifact.id})[/dim]")
    console.print(f"  Lineage:        [cyan]{artifact.effective_lineage_id}[/cyan]")
    console.print(f"  Version:        {artifact.version}")
    if artifact.predecessor_id:
        console.print(f"  Predecessor:    {artifact.predecessor_id}")
    console.print(f"  Type:           {artifact.evidence_type}")
    console.print(f"  Source system:  {artifact.source_system}")
    console.print(f"  Collected at:   {artifact.collected_at.isoformat()}")
    console.print(f"  Collected by:   {artifact.collected_by}")
    if artifact.description:
        console.print(f"  Description:    {artifact.description}")
    if artifact.content is not None:
        console.print("  [bold]Content:[/bold]")
        console.print_json(json.dumps(artifact.content, default=str))
