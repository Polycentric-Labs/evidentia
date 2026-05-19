"""``evidentia mcp`` Typer subcommand group (v0.8.0 P0.3 + v0.8.1 P3.1 + v0.8.2 F-V81-S1).

Wires two CLI verbs:

- ``evidentia mcp serve --transport <stdio|sse|http> [--host ...] [--port ...] [--allow-root <path>]``
  — run the MCP server. v0.8.0 shipped stdio only; v0.8.1 P3.1
  adds HTTP (streamable-http) + SSE (server-sent events)
  transports for non-local MCP clients (browser-based agents,
  remote workers, multi-tenant deployments). v0.8.2 F-V81-S1
  adds ``--allow-root`` to gate file-path tool inputs against
  an operator-configured bound directory.
- ``evidentia mcp doctor`` — health check. Verifies the MCP
  SDK imports cleanly + that the bundled catalog registry
  loads + that the FastMCP server can be constructed without
  errors. Useful for shaking out missing-dep issues post-
  install.

The server lifecycle stays in :mod:`evidentia_mcp.server`;
this module is purely the user-facing CLI shim.

NETWORK-TRANSPORT TRUST MODEL (v0.8.2 F-V81-S1):
HTTP + SSE transports expose the server to non-local MCP
clients. Operators SHOULD pass ``--allow-root <path>`` so
file-path tool inputs (e.g., ``gap_analyze``'s
``inventory_path``) are gated against the bound directory
via ``evidentia_core.security.paths.validate_within``. The
canonical deployment pattern for non-loopback HTTP/SSE
remains: bind to 127.0.0.1 + sidecar reverse-proxy for
cross-network access + AuthProvider middleware (v0.8.1 P3.3)
for token auth + ``--allow-root`` for filesystem authority.
"""

from __future__ import annotations

import sys
from enum import Enum
from pathlib import Path

import typer


class _Transport(str, Enum):
    """v0.8.1 P3.1: explicit transport selection."""

    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"


app = typer.Typer(
    name="mcp",
    help=(
        "Model Context Protocol (MCP) server. Exposes Evidentia "
        "to MCP-aware AI clients (Claude Desktop, Claude Code, "
        "ChatGPT Desktop, custom MCP clients) via stdio (default), "
        "HTTP, or SSE."
    ),
    no_args_is_help=True,
)


@app.command("serve")
def serve(
    transport: _Transport = typer.Option(
        _Transport.STDIO,
        "--transport",
        "-t",
        help=(
            "Transport selection. ``stdio`` (default) is the "
            "canonical MCP transport — used by Claude Desktop, "
            "Claude Code, etc. ``sse`` (server-sent events) "
            "and ``http`` (streamable-http) are the non-local "
            "transports for browser-based agents and remote "
            "MCP clients (v0.8.1 P3.1)."
        ),
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help=(
            "Bind address for HTTP / SSE transports. Default "
            "``127.0.0.1`` (loopback only). Use ``0.0.0.0`` to "
            "bind all interfaces — REQUIRES a reverse-proxy "
            "auth layer; the MCP server doesn't gate file-path "
            "tool inputs against an allow-root in v0.8.1."
        ),
    ),
    port: int = typer.Option(
        8765,
        "--port",
        "-p",
        help=(
            "Bind port for HTTP / SSE transports. Default 8765 "
            "(arbitrary unprivileged port; chosen to avoid "
            "collisions with `evidentia serve`'s default 8000)."
        ),
    ),
    # Backward-compat: accept the v0.8.0 --stdio/--no-stdio shape
    # so existing operators don't break post-upgrade.
    stdio: bool = typer.Option(
        True,
        "--stdio/--no-stdio",
        help=(
            "v0.8.0 backward-compat flag. ``--no-stdio`` errors "
            "out with a hint to use ``--transport`` instead. "
            "Will be removed in v1.0."
        ),
    ),
    # v0.8.2 F-V81-S1: file-path tool input gating.
    allow_root: Path | None = typer.Option(
        None,
        "--allow-root",
        help=(
            "Bound directory for file-path tool inputs (v0.8.2 "
            "F-V81-S1). When set, ``gap_analyze`` + ``gap_diff`` "
            "validate their path inputs against this root via "
            "``evidentia_core.security.paths.validate_within`` — "
            "out-of-root paths surface as ``PathTraversalError`` "
            "(MCP tool error, not server crash). Strongly "
            "RECOMMENDED for non-loopback HTTP / SSE deployments. "
            "When unset, file-path tools accept any path the "
            "server's UID can read (preserves v0.8.1 behavior; "
            "appropriate for stdio + loopback HTTP/SSE)."
        ),
    ),
    cimd_registry_path: Path | None = typer.Option(
        None,
        "--cimd-registry",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "v0.8.5 P4: path to a CIMD (Client ID Metadata "
            "Document) registry JSON file. When set, the server "
            "loads + attaches the registry; per-client scope-"
            "gating logic (v0.8.6 P1) consults it via "
            "``server.evidentia_cimd``. Pair with "
            "``--default-client-id`` for stdio. Optional. See "
            "``evidentia_mcp.cimd`` for the file format."
        ),
    ),
    default_client_id: str | None = typer.Option(
        None,
        "--default-client-id",
        help=(
            "v0.8.6 P1: fallback ``client_id`` when the MCP "
            "request meta does not carry one. On stdio "
            "(canonical case), the wire protocol does NOT pass "
            "a per-request client_id, so this flag IS the "
            "client_id for the entire stdio session — set it "
            "to a slug registered in the CIMD registry to "
            "enable per-tool scope enforcement. On HTTP/SSE, "
            "the flag is a fallback when the MCP client did "
            "not set ``_meta.client_id``. Documented as "
            "INFORMATIONAL (audit-trail granularity), NOT a "
            "security boundary on stdio. See "
            "``evidentia_mcp.scope`` for the threat model."
        ),
    ),
) -> None:
    """Run the MCP server (blocks until the client disconnects)."""
    # Backward-compat: --no-stdio was the v0.8.0 way to surface
    # "I want a non-stdio transport". Surface a helpful error
    # pointing at the new flag.
    if not stdio and transport == _Transport.STDIO:
        typer.echo(
            "The v0.8.0 ``--no-stdio`` flag is replaced by "
            "``--transport sse`` or ``--transport http`` in "
            "v0.8.1. The ``--stdio/--no-stdio`` shape is "
            "retained for back-compat but does nothing on its "
            "own — pass ``--transport`` to select a non-stdio "
            "transport.",
            err=True,
        )
        raise typer.Exit(code=2)

    # Import lazily so `evidentia mcp doctor` works even when the
    # MCP SDK has a transient init issue (the doctor command
    # tells the operator what's wrong).
    from evidentia_mcp.cimd import CIMDRegistry
    from evidentia_mcp.server import (
        build_server,
        run_http,
        run_sse,
        run_stdio,
    )

    # v0.8.5 P4: load CIMD registry if requested.
    cimd_registry: CIMDRegistry | None = None
    if cimd_registry_path is not None:
        try:
            cimd_registry = CIMDRegistry.from_file(cimd_registry_path)
        except (ValueError, FileNotFoundError) as exc:
            typer.echo(
                f"Error loading --cimd-registry at "
                f"{cimd_registry_path}: {exc}",
                err=True,
            )
            raise typer.Exit(code=2) from exc
        typer.echo(
            f"Loaded CIMD registry from {cimd_registry_path}: "
            f"{len(cimd_registry.clients)} client(s) registered.",
            err=True,
        )

    # v0.8.6 P1: --default-client-id validation. Without
    # --cimd-registry the flag is meaningless (no scope to
    # enforce against). Without --default-client-id but with
    # --cimd-registry on stdio, every tool call denies because
    # stdio carries no per-request client_id — surface a warning
    # so operators don't run a server that denies all tool calls.
    if default_client_id is not None and cimd_registry is None:
        typer.echo(
            "WARNING: --default-client-id set without "
            "--cimd-registry. Flag is ignored (no scope to "
            "enforce against).",
            err=True,
        )
    if (
        cimd_registry is not None
        and default_client_id is None
        and transport == _Transport.STDIO
    ):
        typer.echo(
            "WARNING: --cimd-registry set without "
            "--default-client-id on stdio transport. Stdio "
            "carries no per-request client_id, so every tool "
            "call will deny (ambiguous-caller policy). Pair "
            "--cimd-registry with --default-client-id for "
            "stdio deployments.",
            err=True,
        )

    # v0.8.2 F-V81-S1: extra warning when binding non-loopback
    # WITHOUT --allow-root. Pairs with the existing reverse-proxy
    # auth warning to surface BOTH defenses to operators.
    def _warn_non_loopback(transport_name: str) -> None:
        typer.echo(
            f"WARNING: binding {transport_name} to non-loopback "
            f"{host}. Front with a reverse-proxy auth layer or "
            f"use the FastAPI AuthProvider middleware (v0.8.1 "
            f"P3.3).",
            err=True,
        )
        if allow_root is None:
            typer.echo(
                "WARNING: --allow-root not set on a non-loopback "
                "bind. File-path tool inputs (gap_analyze, "
                "gap_diff) will accept any path the server's UID "
                "can read. STRONGLY RECOMMENDED to set "
                "--allow-root <path> for v0.8.2 F-V81-S1 gating.",
                err=True,
            )

    if transport == _Transport.STDIO:
        run_stdio(
            allow_root=allow_root,
            cimd_registry=cimd_registry,
            default_client_id=default_client_id,
        )
    elif transport == _Transport.SSE:
        # SSE transport — the legacy MCP HTTP transport. Some
        # older MCP clients still expect this.
        if host != "127.0.0.1":
            _warn_non_loopback("SSE")
        run_sse(
            host=host,
            port=port,
            allow_root=allow_root,
            cimd_registry=cimd_registry,
            default_client_id=default_client_id,
        )
    elif transport == _Transport.HTTP:
        # Streamable-http transport — the modern MCP HTTP
        # transport supporting bi-directional streaming.
        if host != "127.0.0.1":
            _warn_non_loopback("HTTP")
        run_http(
            host=host,
            port=port,
            allow_root=allow_root,
            cimd_registry=cimd_registry,
            default_client_id=default_client_id,
        )
    else:  # pragma: no cover — exhaustive Enum
        typer.echo(f"Unknown transport: {transport}", err=True)
        raise typer.Exit(code=2)
    # `build_server` import included for symmetry; prevents the
    # lazy-import linter complaining that it's unused.
    _ = build_server


@app.command("doctor")
def doctor() -> None:
    """Validate the MCP server is ready to launch.

    Runs four checks:

    1. The ``mcp`` Python SDK imports cleanly.
    2. The bundled catalog registry loads.
    3. The FastMCP server can be constructed (all tool
       registrations succeed).
    4. The four core tools are registered.

    Exits 0 on success; 1 on any check failure (with a
    human-readable diagnostic on stderr).
    """
    failures: list[str] = []
    # v0.8.1 F-V08-CR-5: initialize report variables at top of
    # function so the report-block is unconditionally safe even
    # if a check fails before the variable would have been
    # populated. Defensive against a future refactor that moves
    # the report-block out of the success-path conditional.
    fws: list[dict[str, str]] = []
    registered: set[str] = set()

    # 1. MCP SDK import
    try:
        import mcp.server.fastmcp  # noqa: F401
    except Exception as exc:
        failures.append(f"MCP SDK import failed: {exc!r}")

    # 2. Catalog registry loads + has frameworks
    try:
        from evidentia_core.catalogs.registry import FrameworkRegistry

        fws = list(FrameworkRegistry().list_frameworks())
        if not fws:
            failures.append("Catalog registry loaded but is empty.")
    except Exception as exc:
        failures.append(f"Catalog registry load failed: {exc!r}")

    # 3. + 4. FastMCP server constructs + has expected tools
    expected_tools = {
        "list_frameworks",
        "get_control",
        "gap_analyze",
        "gap_diff",
    }
    try:
        import asyncio

        from evidentia_mcp.server import build_server

        server = build_server()
        # v0.8.1 F-V08-CR-4: switch from FastMCP private API
        # (_tool_manager._tools) to the public ``list_tools()``
        # async method. Robust against SDK minor-version
        # internal renames.
        tools = asyncio.run(server.list_tools())
        registered = {t.name for t in tools}
        missing = expected_tools - registered
        if missing:
            failures.append(
                f"Expected tools missing from server: "
                f"{sorted(missing)}"
            )
    except Exception as exc:
        failures.append(f"FastMCP server build failed: {exc!r}")

    if failures:
        typer.echo("Evidentia MCP doctor: FAIL", err=True)
        for f in failures:
            typer.echo(f"  • {f}", err=True)
        sys.exit(1)
    typer.echo("Evidentia MCP doctor: PASS")
    typer.echo("  • MCP SDK: importable")
    typer.echo(f"  • Catalog registry: {len(fws)} frameworks loaded")
    typer.echo(f"  • FastMCP server: {len(registered)} tools registered")


#: v0.9.7 P1.2: tools newly added in v0.9.6 that pre-v0.9.6 CIMD
#: registries don't grant by default. Operators running the
#: migrate verb get these added to each client's scope (idempotent
#: — clients already listing them are not modified).
V0_9_6_NEW_TOOLS = (
    "conmon_list_cadences",
    "conmon_next_due",
    "conmon_check_state",
    "conmon_health",
)


@app.command("cimd-migrate")
def cimd_migrate(
    registry_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        writable=True,
        help=(
            "Path to a CIMD registry JSON file. Operators ran this "
            "from `evidentia mcp serve --cimd-registry <path>` in "
            "v0.8.5+; the file is rewritten in place after the "
            "migration."
        ),
    ),
    client_id: str | None = typer.Option(
        None,
        "--client-id",
        help=(
            "When set, apply the migration only to this client. "
            "Default: apply to every client in the registry."
        ),
    ),
    tools: str | None = typer.Option(
        None,
        "--tools",
        help=(
            "Space-separated tool names to add (overrides the "
            "default v0.9.6 tool set). Use to migrate other "
            "future tool additions: "
            "--tools 'tool_a tool_b'."
        ),
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help=(
            "Print the diff without writing. Use to preview the "
            "changes before committing."
        ),
    ),
) -> None:
    """Migrate a CIMD registry to grant the v0.9.6 ``conmon_*`` MCP tools.

    Closes F-V96-conmon-mcp-cimd-migration (v0.9.6 cycle-close
    follow-up). The v0.9.6 CONMON MCP first-mover surface added
    four new tools (``conmon_list_cadences`` / ``conmon_next_due``
    / ``conmon_check_state`` / ``conmon_health``). Operators on
    v0.9.5 CIMD registries see these tools default-rejected at
    dispatch until per-client ``scope`` grants them.

    This verb adds the v0.9.6 tools to each client's ``scope``
    field. Idempotent: a tool already in a client's scope is
    skipped (the diff output flags it as ``no-change``).

    Args:
        registry_file: Path to the CIMD registry JSON. Rewritten
            in place after migration (atomic via .tmp + replace).
            Use ``--dry-run`` to preview without writing.
        client_id: Restrict migration to a single client.
        tools: Override the default v0.9.6 tool set. Use to
            migrate future tool additions.
        dry_run: Preview the diff; do NOT write.

    Exit codes:
        0 — migration succeeded (or dry-run completed)
        1 — registry parse failure or client_id not found
        2 — CLI usage error (invalid combo of options)
    """
    import json
    import os

    from evidentia_mcp.cimd import CIMDRegistry

    new_tools = tuple(tools.split()) if tools else V0_9_6_NEW_TOOLS
    if not new_tools:
        typer.echo(
            "ERROR: --tools resolved to an empty set", err=True
        )
        raise typer.Exit(code=2)

    try:
        registry = CIMDRegistry.from_file(registry_file)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"ERROR: {exc}", err=True)
        raise typer.Exit(code=1) from exc

    target_clients = (
        [client_id] if client_id is not None else list(registry.clients.keys())
    )
    if client_id is not None and client_id not in registry.clients:
        typer.echo(
            f"ERROR: client_id {client_id!r} not in registry "
            f"({len(registry.clients)} clients present)",
            err=True,
        )
        raise typer.Exit(code=1)

    changes: list[tuple[str, list[str], list[str]]] = []
    for cid in target_clients:
        doc = registry.clients[cid]
        existing = set(doc.scope.split()) if doc.scope else set()
        added = [t for t in new_tools if t not in existing]
        if not added:
            changes.append((cid, [], list(existing)))
            continue
        updated_scope = " ".join(sorted(existing | set(added)))
        doc_dict = doc.model_dump()
        doc_dict["scope"] = updated_scope
        registry.clients[cid] = type(doc).model_validate(doc_dict)
        changes.append((cid, added, sorted(existing | set(added))))

    # Print the diff before any write so operators see exactly
    # what landed.
    any_added = any(added for _, added, _ in changes)
    typer.echo(
        f"CIMD migration plan ({'DRY RUN' if dry_run else 'APPLY'}) "
        f"for {registry_file}:"
    )
    for cid, added, final in changes:
        if added:
            typer.echo(
                f"  + {cid}: adding {sorted(added)} "
                f"(final scope: {final})"
            )
        else:
            typer.echo(
                f"  = {cid}: no change "
                f"(already grants {sorted(new_tools)})"
            )
    if not any_added:
        typer.echo("No changes required; registry is already up-to-date.")
        return
    if dry_run:
        typer.echo(
            "Dry run: registry file NOT modified. "
            "Re-run without --dry-run to apply."
        )
        return

    # Atomic write: temp file then os.replace.
    payload = registry.model_dump(mode="json")
    tmp_path = registry_file.with_suffix(
        registry_file.suffix + ".tmp"
    )
    tmp_path.write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )
    os.replace(tmp_path, registry_file)
    typer.echo(
        f"Migration applied: {registry_file} updated atomically."
    )
