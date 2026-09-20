"""`evidentia catalog` - framework catalog exploration and user-import.

v0.2.0 introduces:
- ``import`` / ``where`` / ``license-info`` / ``remove`` for user-supplied catalogs
- ``list`` filtered by tier and category, with each catalog's derived text depth
- OSCAL profile resolution via ``--profile`` + ``--catalog`` on import
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from tempfile import mkdtemp
from typing import Annotated, NoReturn

import typer
from evidentia_core.catalogs.manifest import (
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.catalogs.user_dir import (
    CatalogManifestTransaction,
    CatalogMutationIntent,
    catalog_entry_sha256,
    load_user_manifest,
    resolve_catalog_path,
)
from evidentia_core.models.catalog import ControlCatalog, TextDepth
from evidentia_core.models.obligation import ObligationCatalog
from evidentia_core.models.open_corpora import ImportResult, NativeSourceError, native_operation
from evidentia_core.models.threat import TechniqueCatalog, VulnerabilityCatalog
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from evidentia.cli._rbac import require_role_cli

app = typer.Typer(help="Framework catalog exploration and user-import commands.")
console = Console()


# -----------------------------------------------------------------------
# Discovery & rendering
# -----------------------------------------------------------------------


def _currency_lines(item: ControlCatalog | FrameworkManifestEntry) -> list[str]:
    """Render source metadata literally so user-supplied brackets cannot hide a notice."""
    lines = []
    for label, value in (
        ("Status", item.status),
        ("Verified on", item.verified_on),
        ("Successor", item.superseded_by),
        ("Notice", item.notes),
    ):
        if value is not None:
            lines.append(f"[bold]{label}:[/bold] {escape(str(value))}")
    return lines


def _show_currency(catalog: ControlCatalog) -> None:
    lines = _currency_lines(catalog)
    if lines:
        console.print(Panel("\n".join(lines), title="Catalog currency", border_style="yellow"))
    for jurisdiction, context in catalog.audit_contexts.items():
        lines = [
            f"Authority: {context.authority}",
            f"Audit version: {context.version}",
            f"Verified on: {context.verified_on}",
            f"Source scope through: {context.valid_through or 'unknown'}",
            f"Source: {context.source_url}",
        ]
        if context.notes:
            lines.append(context.notes)
        console.print(Panel(escape("\n".join(lines)), title=f"Audit context: {escape(jurisdiction)}"))
    if catalog.audit_contexts:
        console.print("Unlisted authorities have no verified audit-version context.", markup=False)
    if catalog.publication_notices:
        console.print("[bold]Published revisions[/bold]")
        console.print(
            "These notices are outside the assessed controls; dates never activate them automatically.", markup=False
        )
        for notice in catalog.publication_notices:
            values = notice.model_dump(mode="json", exclude_none=True)
            lines = [f"{key.replace('_', ' ')}: {value}" for key, value in values.items() if key != "id"]
            console.print(Panel(escape("\n".join(lines)), title=escape(notice.id)))


@app.command("list")
def list_frameworks(
    tier: str | None = typer.Option(None, "--tier", help="Filter by redistribution tier: A, B, C, or D."),
    category: str | None = typer.Option(
        None,
        "--category",
        help="Filter by catalog type: control, technique, vulnerability, obligation.",
    ),
    bundled_only: bool = typer.Option(False, "--bundled-only", help="Show only catalogs shipped with the package."),
    user_only: bool = typer.Option(False, "--user-only", help="Show only user-imported catalogs."),
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
                continue  # shadowed - shown under user
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
    table.add_column("Text", justify="center")
    table.add_column("Source", style="dim")
    table.add_column("Loaded", justify="center")

    from evidentia_core.catalogs.loader import load_any_catalog

    for entry, source in rows:
        try:
            catalog = load_any_catalog(entry.id)
            # Count by category - each catalog type stores its items
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
        if entry.status:
            flag += f" [yellow]({escape(entry.status)})[/yellow]"
        table.add_row(
            entry.id,
            entry.name + flag,
            entry.tier,
            entry.category,
            count,
            entry.text_depth or "-",
            source,
            loaded,
        )

    console.print(table)
    console.print(
        f"[dim]{len(rows)} framework(s) {'(filtered)' if tier or category or bundled_only or user_only else ''}[/dim]"
    )


@app.command("show")
def show_catalog(
    framework: str = typer.Argument(..., help="Framework ID, e.g. 'nist-800-53-mod'."),
    control: str | None = typer.Option(None, "--control", "-c", help="Show detail for a specific control ID."),
    native_source: Annotated[
        bool, typer.Option("--native-source", help="Show the complete bound native source JSON.")
    ] = False,
) -> None:
    """Show controls in a framework catalog (or detail for one control)."""
    registry = FrameworkRegistry.get_instance()
    try:
        catalog = registry.get_catalog(framework)
    except Exception as e:
        console.print(f"[red]Error loading catalog '{framework}': {e}[/red]")
        raise typer.Exit(code=1) from e

    if native_source and not control:
        if catalog.native_source is None:
            console.print("native_source_unavailable", markup=False)
            raise typer.Exit(code=1)
        console.print_json(
            json=json.dumps(catalog.native_source.model_dump(mode="json"), ensure_ascii=True), highlight=False
        )
        return

    if not native_source:
        _show_currency(catalog)

    if control:
        ctrl = catalog.get_control(control)
        if not ctrl:
            console.print(f"[red]Control '{control}' not found in '{framework}'.[/red]")
            raise typer.Exit(code=1)

        if native_source:
            _show_control_source(catalog, ctrl.id)
            return

        # Show the license URL in place of licensed body text.
        if ctrl.placeholder and ctrl.license_url:
            description_block = f"[yellow]\\[Licensed content - see {escape(ctrl.license_url)}][/yellow]"
        else:
            description_block = escape(ctrl.description)

        body = (
            f"[bold]ID:[/bold] {escape(ctrl.id)}\n"
            f"[bold]Title:[/bold] {escape(ctrl.title)}\n"
            f"[bold]Family:[/bold] {escape(ctrl.family or '-')}\n\n"
            f"[bold]Description:[/bold]\n{description_block}\n"
        )
        if ctrl.priority:
            body += f"\n[bold]Priority:[/bold] {escape(ctrl.priority)}\n"
        if ctrl.properties:
            body += "\n[bold]Publisher properties:[/bold]\n"
            body += "\n".join(f"{escape(key)}: {escape(value)}" for key, value in ctrl.properties.items()) + "\n"
        if ctrl.objective:
            body += f"\n[bold]Objective:[/bold]\n{escape(ctrl.objective)}\n"
        if ctrl.guidance:
            body += f"\n[bold]Guidance:[/bold]\n{escape(ctrl.guidance)}\n"
        if ctrl.enhancements:
            body += f"\n[bold]Enhancements:[/bold] {len(ctrl.enhancements)}\n"
            for enh in ctrl.enhancements[:10]:
                body += f"  * {escape(enh.id)}: {escape(enh.title)}\n"
        console.print(Panel(body, title=escape(f"{framework} / {ctrl.id}"), border_style="cyan"))
        if ctrl.native_source_ref is not None:
            _show_control_source(catalog, ctrl.id)
        if ctrl.source_rows:
            console.print("[bold]Source evidence[/bold]")
            console.print_json(
                json=json.dumps([row.model_dump(mode="json") for row in ctrl.source_rows], ensure_ascii=True, indent=2),
                highlight=False,
            )
        return

    table = Table(title=escape(f"{catalog.framework_name} ({catalog.framework_id})"))
    table.add_column("Control ID", style="cyan", no_wrap=True)
    table.add_column("Title")
    table.add_column("Family", style="dim")

    for ctrl in catalog.controls:
        table.add_row(escape(ctrl.id), escape(ctrl.title), escape(ctrl.family or ""))

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
        console.print(f"[yellow]No mappings found from {source}:{control} to {target}.[/yellow]")
        raise typer.Exit(code=0)

    console.print(f"[bold cyan]{source}[/bold cyan]:{control} maps to [bold cyan]{target}[/bold cyan]:")
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
@require_role_cli("write")
def import_catalog(
    source: str | None = typer.Argument(
        None,
        help="Path to a catalog JSON file to import.",
    ),
    framework_id: str | None = typer.Option(
        None,
        "--framework-id",
        help="Override the framework_id in the imported file (default: read from file).",
    ),
    name: str | None = typer.Option(None, "--name", help="Override the human-readable framework name."),
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
    profile: str | None = typer.Option(
        None,
        "--profile",
        help="OSCAL profile JSON to resolve. Pair with --catalog.",
    ),
    catalog: str | None = typer.Option(
        None,
        "--catalog",
        help="Local OSCAL catalog JSON overriding the href of a profile with one import.",
    ),
    tier: str = typer.Option(
        "C",
        "--tier",
        help="Redistribution tier of imported content (A/B/C/D). Default C.",
    ),
    catalog_dir: str | None = typer.Option(
        None,
        "--catalog-dir",
        help="Override user catalog directory (also via EVIDENTIA_CATALOG_DIR).",
    ),
    native_profile: Annotated[
        str | None, typer.Option("--native-profile", help="Pinned native source profile.")
    ] = None,
    source_dir: Annotated[
        str | None, typer.Option("--source-dir", help="Directory containing the exact native source files.")
    ] = None,
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
    # Click keeps these paths lexical so authorization precedes filesystem access.
    directory = Path(catalog_dir) if catalog_dir is not None else None
    if native_profile is not None or source_dir is not None:
        if (
            native_profile != "bsi-grundschutz-plus-plus-367d7750"
            or source_dir is None
            or source is not None
            or profile is not None
            or catalog is not None
            or framework_id is not None
            or name is not None
            or force
            or license_terms is not None
            or tier != "C"
        ):
            console.print(
                "Native import requires --native-profile bsi-grundschutz-plus-plus-367d7750 and --source-dir, "
                "without legacy import overrides.",
                markup=False,
            )
            raise typer.Exit(code=1)
        from evidentia_core.catalogs.open_corpora import read_source_directory

        transaction: CatalogManifestTransaction | None = None
        try:
            with native_operation():
                sources = read_source_directory(native_profile, Path(source_dir))
                transaction = CatalogManifestTransaction(directory)
                result = transaction.commit(CatalogMutationIntent.native(sources))
        except BaseException as exc:
            if transaction is not None:
                _catalog_failure(transaction, exc)
            if isinstance(exc, NativeSourceError):
                console.print(exc.code, markup=False)
                raise typer.Exit(code=1) from exc
            raise
        _catalog_success(transaction, result)
        wire = transaction.result_json
        if not isinstance(result, ImportResult) or wire is None:
            console.print("catalog_publication_indeterminate", markup=False)
            raise typer.Exit(code=1)
        console.print_json(json=wire.decode("utf-8"), highlight=False)
        return

    if profile is not None:
        from evidentia_core.oscal.profile import resolve_profile

        profile_path = Path(profile)
        try:
            resolved = resolve_profile(
                profile_path,
                override_framework_id=framework_id,
                override_framework_name=name,
                source_catalog_path=Path(catalog) if catalog is not None else None,
            )
        except Exception as exc:
            console.print(f"[red]Profile resolution failed: {escape(str(exc))}[/red]")
            raise typer.Exit(code=1) from exc
        payload = json.dumps(resolved.model_dump(mode="json", exclude_none=True, by_alias=True), indent=2).encode()
        entry = _manifest_entry(
            framework_id=resolved.framework_id,
            name=resolved.framework_name,
            version=resolved.version,
            tier=tier.upper(),
            placeholder=False,
            license_terms=license_terms,
            text_depth=resolved.text_depth,
            catalog=resolved,
        )
        _commit_catalog(CatalogMutationIntent.legacy(entry, payload, force=force), directory)
        console.print(
            f"[green]Resolved profile and imported as '{escape(resolved.framework_id)}' "
            f"({resolved.control_count} controls)[/green]"
        )
        return

    if source is None:
        console.print("[red]Provide a source path, or use --profile for OSCAL profile resolution.[/red]")
        raise typer.Exit(code=1)

    from evidentia_core.catalogs.loader import load_any_catalog

    staging_dir: str | None = None
    try:
        with Path(source).open("rb") as source_file:
            raw = source_file.read(16_777_217)
        if len(raw) > 16_777_216:
            raise ValueError("catalog_storage_limit_exceeded")
        data = json.loads(raw)
        if type(data) is not dict:
            raise ValueError("Catalog must be a JSON object")
        resolved_id = framework_id or data.get("framework_id")
        if not isinstance(resolved_id, str) or not resolved_id:
            raise ValueError("Provide framework_id in the file or pass --framework-id")
        if framework_id:
            data["framework_id"] = framework_id
        if name:
            data["framework_name"] = name
        if framework_id or name:
            raw = json.dumps(data, indent=2).encode()
        if len(raw) > 16_777_216:
            raise ValueError("catalog_storage_limit_exceeded")
        staging_dir = mkdtemp(prefix=".catalog-import-")
        staged_path = Path(staging_dir) / "catalog.json"
        staged_path.write_bytes(raw)
        loaded_catalog = load_any_catalog(resolved_id, custom_path=staged_path)
        if not isinstance(loaded_catalog, (ControlCatalog, ObligationCatalog, TechniqueCatalog, VulnerabilityCatalog)):
            raise ValueError("Unsupported catalog type")
        entry = _manifest_entry(
            framework_id=resolved_id,
            name=data.get("framework_name") or resolved_id,
            version=data.get("version", "unknown"),
            tier=tier.upper(),
            placeholder=bool(data.get("placeholder", False)),
            license_terms=license_terms,
            text_depth=loaded_catalog.text_depth,
            catalog=loaded_catalog if isinstance(loaded_catalog, ControlCatalog) else None,
        )
        out_path = _commit_catalog(CatalogMutationIntent.legacy(entry, raw, force=force), directory)
    except (ValueError, OSError, TypeError) as exc:
        console.print("Catalog validation failed.", markup=False)
        raise typer.Exit(code=1) from exc
    finally:
        if staging_dir is not None:
            _cleanup_staging(staging_dir)

    shadow_note = " (shadows bundled catalog)" if load_manifest().get(resolved_id) is not None else ""
    console.print(f"[green]Imported '{escape(resolved_id)}'{shadow_note} -> {escape(str(out_path))}[/green]")


@app.command("where")
def where_framework(
    framework_id: str = typer.Argument(..., help="Framework ID to locate."),
    catalog_dir: Path | None = typer.Option(None, "--catalog-dir", help="Override user catalog directory."),
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
            f"[bold]Placeholder:[/bold] {entry.placeholder}\n"
            f"[bold]Text depth:[/bold] {entry.text_depth or '-'}\n" + "\n".join(_currency_lines(entry)),
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
        f"[bold]Text depth:[/bold] {entry.text_depth or '-'}",
    ]
    lines.extend(_currency_lines(entry))
    if entry.license:
        lines.append(f"[bold]License:[/bold] {escape(entry.license)}")
    if entry.license_url:
        lines.append(f"[bold]License URL:[/bold] {escape(entry.license_url)}")
    if entry.source_url:
        lines.append(f"[bold]Source URL:[/bold] {escape(entry.source_url)}")
    console.print(Panel("\n".join(lines), title=f"License: {framework_id}", border_style="cyan"))


@app.command("remove")
@require_role_cli("admin")
def remove_framework(
    framework_id: str = typer.Argument(..., help="Framework ID to remove."),
    catalog_dir: str | None = typer.Option(None, "--catalog-dir", help="Override user catalog directory."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Remove a user-imported framework (bundled catalogs are never touched)."""
    directory = Path(catalog_dir) if catalog_dir is not None else None
    user = load_user_manifest(directory)
    entry = user.get(framework_id)
    if entry is None:
        console.print(f"[red]No user-imported framework '{framework_id}'. Bundled catalogs cannot be removed.[/red]")
        raise typer.Exit(code=1)

    expected_entry = catalog_entry_sha256(entry)
    if not yes:
        confirm = typer.confirm(f"Remove user-imported framework '{framework_id}' ({entry.name})?")
        if not confirm:
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(code=0)

    _commit_catalog(CatalogMutationIntent.remove(framework_id, expected_entry_sha256=expected_entry), directory)
    console.print(f"[green]Removed user-imported '{escape(framework_id)}'. Catalog files are retained.[/green]")


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------


def _cleanup_staging(staging_dir: str) -> None:
    """Preserve the primary failure when scratch cleanup also fails."""
    primary = sys.exception()
    try:
        shutil.rmtree(staging_dir, ignore_errors=True)
    except BaseException:
        if primary is None:
            raise


def _manifest_entry(
    *,
    framework_id: str,
    name: str,
    version: str,
    tier: str,
    placeholder: bool,
    license_terms: str | None,
    text_depth: TextDepth | None = None,
    catalog: ControlCatalog | None = None,
) -> FrameworkManifestEntry:
    """Capture metadata without publishing or reading a user manifest."""
    return FrameworkManifestEntry(
        id=framework_id,
        name=name,
        version=version,
        tier=tier,
        category="control",
        path="catalog.json",
        license=license_terms if license_terms is not None else catalog.license_terms if catalog else None,
        placeholder=placeholder,
        text_depth=text_depth,
        status=catalog.status if catalog else None,
        notes=catalog.notes if catalog else None,
        verified_on=catalog.verified_on if catalog else None,
        superseded_by=catalog.superseded_by if catalog else None,
        source_url=catalog.source if catalog else None,
        license_url=catalog.license_url if catalog else None,
        license_required=catalog.license_required if catalog else False,
    )


def _catalog_failure(transaction: CatalogManifestTransaction, exc: BaseException) -> NoReturn:
    """Report terminal facts without replacing the primary interruption."""
    # Reporting must not replace the primary exception, including interruption.
    try:
        observation = transaction.observation
        code = observation.error_code if observation is not None else "catalog_storage_failed"
        console.print(code, markup=False)
        if observation is not None:
            console.print_json(json=observation.model_dump_json(), highlight=False)
        if type(exc) is ValueError and exc.args == ("Framework is already registered; use force to replace it",):
            console.print("Use --force to replace an existing user catalog.", markup=False)
    except BaseException:
        pass
    if not isinstance(exc, Exception):
        raise exc
    raise typer.Exit(code=1) from exc


def _catalog_success(transaction: CatalogManifestTransaction, result: Path | ImportResult) -> Path | ImportResult:
    observation = transaction.observation
    if (
        observation is None
        or observation.error_code is not None
        or observation.publication_state not in ("committed", "unchanged")
        or observation.readback_result != "matches_proposed"
    ):
        console.print("catalog_publication_indeterminate", markup=False)
        raise typer.Exit(code=1)
    return result


def _commit_catalog(intent: CatalogMutationIntent, directory: Path | None) -> Path | ImportResult:
    """Publish through the shared transaction and report its terminal facts."""
    transaction = CatalogManifestTransaction(directory)
    try:
        result = transaction.commit(intent)
    except BaseException as exc:
        _catalog_failure(transaction, exc)
    return _catalog_success(transaction, result)


def _show_control_source(catalog: ControlCatalog, control_id: str) -> None:
    """Show the selected occurrence and declared context without copying documents."""
    control = catalog.get_control(control_id)
    bundle = catalog.native_source
    if control is None or control.native_source_ref is None or bundle is None:
        console.print("native_source_unavailable", markup=False)
        raise typer.Exit(code=1)
    reference = control.native_source_ref
    occurrences = bundle.data.occurrences
    selected = occurrences[reference.occurrence_index]
    parents = []
    parent = selected.parent_index
    while parent is not None:
        enclosing = occurrences[parent]
        parents.append(enclosing.model_dump(mode="json"))
        parent = enclosing.parent_index
    console.print_json(
        json=json.dumps(
            {
                "framework_id": catalog.framework_id,
                "control_id": control.id,
                "native_source_ref": reference.model_dump(mode="json"),
                "profile": bundle.data.profile,
                "occurrence": selected.model_dump(mode="json"),
                "enclosing_context": list(reversed(parents)),
                "declared_context": [
                    occurrences[index].model_dump(mode="json") for index in bundle.data.context_indices
                ],
            },
            ensure_ascii=True,
        ),
        highlight=False,
    )
