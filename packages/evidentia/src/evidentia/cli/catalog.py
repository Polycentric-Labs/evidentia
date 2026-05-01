"""`evidentia catalog` — framework catalog exploration and user-import.

v0.2.0 introduces:
- ``import`` / ``where`` / ``license-info`` / ``remove`` for user-supplied catalogs
- ``list`` filtered by tier and category
- OSCAL profile resolution via ``--profile`` + ``--catalog`` on import
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer
from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.catalogs.user_dir import (
    ensure_user_dir,
    get_user_catalog_dir,
    load_user_manifest,
    resolve_catalog_path,
    save_user_manifest,
)
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(help="Framework catalog exploration and user-import commands.")
console = Console()


# -----------------------------------------------------------------------
# Discovery & rendering
# -----------------------------------------------------------------------


@app.command("list")
def list_frameworks(
    tier: str | None = typer.Option(
        None, "--tier", help="Filter by redistribution tier: A, B, C, or D."
    ),
    category: str | None = typer.Option(
        None,
        "--category",
        help="Filter by catalog type: control, technique, vulnerability, obligation.",
    ),
    bundled_only: bool = typer.Option(
        False, "--bundled-only", help="Show only catalogs shipped with the package."
    ),
    user_only: bool = typer.Option(
        False, "--user-only", help="Show only user-imported catalogs."
    ),
) -> None:
    """List available framework catalogs, with optional filters."""
    registry = FrameworkRegistry.get_instance()
    bundled = registry.manifest
    user = load_user_manifest()

    # Build unified row set: user entries shadow bundled entries
    user_ids = {fw.id for fw in user.frameworks}
    rows: list[tuple[FrameworkManifestEntry, str]] = []

    if not user_only:
        for fw in bundled.frameworks:
            if fw.id in user_ids:
                continue  # shadowed — shown under user
            rows.append((fw, "bundled"))

    if not bundled_only:
        for fw in user.frameworks:
            rows.append((fw, "user"))

    # Apply filters
    if tier:
        rows = [(e, s) for e, s in rows if e.tier == tier.upper()]
    if category:
        rows = [(e, s) for e, s in rows if e.category == category.lower()]

    table = Table(title="Framework Catalogs")
    table.add_column("Framework ID", style="cyan", no_wrap=True)
    table.add_column("Name")
    table.add_column("Tier", justify="center")
    table.add_column("Category", style="dim")
    table.add_column("Controls", justify="right", style="green")
    table.add_column("Source", style="dim")
    table.add_column("Loaded", justify="center")

    from evidentia_core.catalogs.loader import load_any_catalog

    for entry, source in rows:
        try:
            catalog = load_any_catalog(entry.id)
            # Count by category — each catalog type stores its items
            # under a different attribute
            if entry.category == "control":
                count = str(len(catalog.controls))  # type: ignore[attr-defined]
            elif entry.category == "technique":
                count = str(len(catalog.techniques))  # type: ignore[attr-defined]
            elif entry.category == "vulnerability":
                count = str(len(catalog.vulnerabilities))  # type: ignore[attr-defined]
            elif entry.category == "obligation":
                count = str(len(catalog.obligations))  # type: ignore[attr-defined]
            else:
                count = "?"
            loaded = "[green]yes[/green]"
        except Exception:
            count = "-"
            loaded = "[red]no[/red]"
        flag = ""
        if entry.placeholder:
            flag = " [yellow](stub)[/yellow]"
        table.add_row(
            entry.id,
            entry.name + flag,
            entry.tier,
            entry.category,
            count,
            source,
            loaded,
        )

    console.print(table)
    console.print(
        f"[dim]{len(rows)} framework(s) "
        f"{'(filtered)' if tier or category or bundled_only or user_only else ''}[/dim]"
    )


@app.command("show")
def show_catalog(
    framework: str = typer.Argument(..., help="Framework ID, e.g. 'nist-800-53-mod'."),
    control: str | None = typer.Option(
        None, "--control", "-c", help="Show detail for a specific control ID."
    ),
) -> None:
    """Show controls in a framework catalog (or detail for one control)."""
    registry = FrameworkRegistry.get_instance()
    try:
        catalog = registry.get_catalog(framework)
    except Exception as e:
        console.print(f"[red]Error loading catalog '{framework}': {e}[/red]")
        raise typer.Exit(code=1) from e

    if control:
        ctrl = catalog.get_control(control)
        if not ctrl:
            console.print(
                f"[red]Control '{control}' not found in '{framework}'.[/red]"
            )
            raise typer.Exit(code=1)

        # Placeholder rendering — show license URL instead of placeholder prose
        if ctrl.placeholder and ctrl.license_url:
            description_block = (
                f"[yellow]\\[Licensed content — see {ctrl.license_url}][/yellow]"
            )
        else:
            description_block = ctrl.description

        body = (
            f"[bold]ID:[/bold] {ctrl.id}\n"
            f"[bold]Title:[/bold] {ctrl.title}\n"
            f"[bold]Family:[/bold] {ctrl.family or '-'}\n\n"
            f"[bold]Description:[/bold]\n{description_block}\n"
        )
        if ctrl.objective:
            body += f"\n[bold]Objective:[/bold]\n{ctrl.objective}\n"
        if ctrl.guidance:
            body += f"\n[bold]Guidance:[/bold]\n{ctrl.guidance}\n"
        if ctrl.enhancements:
            body += f"\n[bold]Enhancements:[/bold] {len(ctrl.enhancements)}\n"
            for enh in ctrl.enhancements[:10]:
                body += f"  * {enh.id}: {enh.title}\n"
        console.print(Panel(body, title=f"{framework} / {ctrl.id}", border_style="cyan"))
        return

    table = Table(title=f"{catalog.framework_name} ({catalog.framework_id})")
    table.add_column("Control ID", style="cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Family", style="dim")

    for ctrl in catalog.controls:
        table.add_row(ctrl.id, ctrl.title, ctrl.family or "")

    console.print(table)
    console.print(f"[dim]Total: {len(catalog.controls)} controls[/dim]")


@app.command("crosswalk")
def show_crosswalk(
    source: str = typer.Option(..., "--source", "-s", help="Source framework ID."),
    target: str = typer.Option(..., "--target", "-t", help="Target framework ID."),
    control: str = typer.Option(..., "--control", "-c", help="Source control ID."),
) -> None:
    """Show cross-framework mappings for a control."""
    registry = FrameworkRegistry.get_instance()
    crosswalk = registry.crosswalk
    mappings = crosswalk.get_mapped_controls(source, control, target)

    if not mappings:
        console.print(
            f"[yellow]No mappings found from {source}:{control} to {target}.[/yellow]"
        )
        raise typer.Exit(code=0)

    console.print(
        f"[bold cyan]{source}[/bold cyan]:{control} maps to "
        f"[bold cyan]{target}[/bold cyan]:"
    )
    for m in mappings:
        title = m.target_control_title or ""
        rel = f"[dim]\\[{m.relationship}][/dim]"
        console.print(f"  -> [green]{m.target_control_id}[/green] {title} {rel}")
        if m.notes:
            console.print(f"     [dim]{m.notes}[/dim]")


# -----------------------------------------------------------------------
# User-import facility
# -----------------------------------------------------------------------


@app.command("import")
def import_catalog(
    source: Path = typer.Argument(
        None,
        help="Path to a catalog JSON file to import.",
    ),
    framework_id: str | None = typer.Option(
        None,
        "--framework-id",
        help="Override the framework_id in the imported file (default: read from file).",
    ),
    name: str | None = typer.Option(
        None, "--name", help="Override the human-readable framework name."
    ),
    license_terms: str | None = typer.Option(
        None,
        "--license-terms",
        help="Your statement about the content's source and licensing.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite an existing user-imported framework with the same ID.",
    ),
    profile: Path | None = typer.Option(
        None,
        "--profile",
        help="OSCAL profile JSON to resolve. Pair with --catalog.",
    ),
    catalog: Path | None = typer.Option(
        None,
        "--catalog",
        help="OSCAL source catalog JSON (used with --profile).",
    ),
    tier: str = typer.Option(
        "C",
        "--tier",
        help="Redistribution tier of imported content (A/B/C/D). Default C.",
    ),
    catalog_dir: Path | None = typer.Option(
        None,
        "--catalog-dir",
        help="Override user catalog directory (also via EVIDENTIA_CATALOG_DIR).",
    ),
) -> None:
    """Import a user-supplied catalog into the local user catalog directory.

    Three modes:

    \b
    1. Direct JSON:      evidentia catalog import ./my-iso27001.json
    2. OSCAL profile:    evidentia catalog import --profile profile.json --catalog source.json
    3. Replace stub:     evidentia catalog import --framework-id soc2-tsc ./my-tsc.json --force

    Imported catalogs shadow bundled catalogs with the same framework_id,
    so loading a licensed ISO 27001 copy makes it the active catalog for
    all subsequent ``catalog show``, ``gap analyze``, etc. calls.
    """
    user_dir = ensure_user_dir(catalog_dir)

    # Mode 2: OSCAL profile resolution
    if profile is not None:
        from evidentia_core.oscal.profile import resolve_profile

        if not profile.exists():
            console.print(f"[red]Profile not found: {profile}[/red]")
            raise typer.Exit(code=1)
        try:
            resolved = resolve_profile(
                profile,
                override_framework_id=framework_id,
                override_framework_name=name,
            )
        except Exception as exc:
            console.print(f"[red]Profile resolution failed: {exc}[/red]")
            raise typer.Exit(code=1) from exc

        # Write resolved catalog as a standard Evidentia JSON
        payload = resolved.model_dump(mode="json", exclude_none=True, by_alias=True)
        out_path = user_dir / f"{resolved.framework_id}.json"
        if out_path.exists() and not force:
            console.print(
                f"[red]{out_path.name} already exists — use --force to overwrite.[/red]"
            )
            raise typer.Exit(code=1)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        _add_to_user_manifest(
            catalog_dir=catalog_dir,
            framework_id=resolved.framework_id,
            name=resolved.framework_name,
            version=resolved.version,
            tier=tier.upper(),
            path=out_path.name,
            placeholder=False,
            license_terms=license_terms,
        )
        console.print(
            f"[green]Resolved profile and imported as '{resolved.framework_id}' "
            f"({resolved.control_count} controls)[/green]"
        )
        return

    # Mode 1 / 3: direct JSON import
    if source is None:
        console.print(
            "[red]Provide a source path, or use --profile for OSCAL profile "
            "resolution.[/red]"
        )
        raise typer.Exit(code=1)

    if not source.exists():
        console.print(f"[red]File not found: {source}[/red]")
        raise typer.Exit(code=1)

    with open(source, encoding="utf-8") as f:
        data = json.load(f)

    resolved_id = framework_id or data.get("framework_id")
    if not resolved_id:
        console.print(
            "[red]Cannot determine framework_id — either set it in the file or "
            "pass --framework-id.[/red]"
        )
        raise typer.Exit(code=1)

    if framework_id:
        data["framework_id"] = framework_id
    if name:
        data["framework_name"] = name

    resolved_name = data.get("framework_name") or resolved_id
    version = data.get("version", "unknown")
    placeholder = bool(data.get("placeholder", False))

    # Copy/rewrite into user dir
    out_path = user_dir / f"{resolved_id}.json"
    if out_path.exists() and not force:
        console.print(
            f"[red]A user-imported '{resolved_id}' already exists — use --force to "
            f"overwrite.[/red]"
        )
        raise typer.Exit(code=1)

    if framework_id or name:
        # We modified the payload; write the new version
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    else:
        # Byte-for-byte copy
        shutil.copy2(source, out_path)

    _add_to_user_manifest(
        catalog_dir=catalog_dir,
        framework_id=resolved_id,
        name=resolved_name,
        version=version,
        tier=tier.upper(),
        path=out_path.name,
        placeholder=placeholder,
        license_terms=license_terms,
    )

    shadow_note = ""
    if load_manifest().get(resolved_id) is not None:
        shadow_note = " (shadows bundled catalog)"
    console.print(
        f"[green]Imported '{resolved_id}'{shadow_note} → {out_path}[/green]"
    )


@app.command("where")
def where_framework(
    framework_id: str = typer.Argument(..., help="Framework ID to locate."),
    catalog_dir: Path | None = typer.Option(
        None, "--catalog-dir", help="Override user catalog directory."
    ),
) -> None:
    """Show where a framework is resolved from (user, bundled, or not found)."""
    bundled = load_manifest()
    user = load_user_manifest(catalog_dir)
    try:
        path, entry, source = resolve_catalog_path(
            framework_id,
            bundled_manifest=bundled,
            user_manifest=user,
            user_dir_override=catalog_dir,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc

    shadow = ""
    if source == "user" and bundled.get(framework_id):
        shadow = " [yellow](shadows bundled catalog)[/yellow]"
    console.print(
        Panel(
            f"[bold]Framework:[/bold] {entry.name}\n"
            f"[bold]Source:[/bold] {source}{shadow}\n"
            f"[bold]Path:[/bold] {path}\n"
            f"[bold]Tier:[/bold] {entry.tier}  "
            f"[bold]Category:[/bold] {entry.category}\n"
            f"[bold]Placeholder:[/bold] {entry.placeholder}",
            title=framework_id,
            border_style="cyan",
        )
    )


@app.command("license-info")
def license_info(
    framework_id: str = typer.Argument(..., help="Framework ID."),
) -> None:
    """Show licensing information for a framework (tier, terms, source URL)."""
    bundled = load_manifest()
    user = load_user_manifest()
    entry = user.get(framework_id) or bundled.get(framework_id)
    if entry is None:
        console.print(f"[red]Unknown framework '{framework_id}'.[/red]")
        raise typer.Exit(code=1)

    lines = [
        f"[bold]Framework:[/bold] {entry.name}",
        f"[bold]Tier:[/bold] {entry.tier}",
        f"[bold]License required:[/bold] {entry.license_required}",
        f"[bold]Placeholder:[/bold] {entry.placeholder}",
    ]
    if entry.license:
        lines.append(f"[bold]License:[/bold] {entry.license}")
    if entry.license_url:
        lines.append(f"[bold]License URL:[/bold] {entry.license_url}")
    if entry.source_url:
        lines.append(f"[bold]Source URL:[/bold] {entry.source_url}")
    console.print(
        Panel("\n".join(lines), title=f"License: {framework_id}", border_style="cyan")
    )


@app.command("remove")
def remove_framework(
    framework_id: str = typer.Argument(..., help="Framework ID to remove."),
    catalog_dir: Path | None = typer.Option(
        None, "--catalog-dir", help="Override user catalog directory."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Remove a user-imported framework (bundled catalogs are never touched)."""
    user = load_user_manifest(catalog_dir)
    entry = user.get(framework_id)
    if entry is None:
        console.print(
            f"[red]No user-imported framework '{framework_id}'. "
            f"Bundled catalogs cannot be removed.[/red]"
        )
        raise typer.Exit(code=1)

    if not yes:
        confirm = typer.confirm(
            f"Remove user-imported framework '{framework_id}' ({entry.name})?"
        )
        if not confirm:
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(code=0)

    user_dir = get_user_catalog_dir(catalog_dir)
    catalog_path = user_dir / entry.path
    if catalog_path.exists():
        catalog_path.unlink()

    updated = FrameworkManifest(
        version=user.version,
        frameworks=[fw for fw in user.frameworks if fw.id != framework_id],
    )
    save_user_manifest(updated, catalog_dir)
    console.print(f"[green]Removed user-imported '{framework_id}'.[/green]")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _add_to_user_manifest(
    *,
    catalog_dir: Path | None,
    framework_id: str,
    name: str,
    version: str,
    tier: str,
    path: str,
    placeholder: bool,
    license_terms: str | None,
) -> None:
    """Append or replace an entry in the user manifest."""
    user = load_user_manifest(catalog_dir)
    kept = [fw for fw in user.frameworks if fw.id != framework_id]
    new_entry = FrameworkManifestEntry(
        id=framework_id,
        name=name,
        version=version,
        tier=tier,
        category="control",
        path=path,
        license=license_terms,
        placeholder=placeholder,
    )
    updated = FrameworkManifest(version=user.version, frameworks=[*kept, new_entry])
    save_user_manifest(updated, catalog_dir)
