"""``evidentia mcp`` Typer subcommand group (v0.8.0 P0.3).

Wires two CLI verbs:

- ``evidentia mcp serve [--stdio]`` — run the MCP server.
  v0.8.0 ships stdio transport only; the ``--stdio`` flag is
  the default and exists as an explicit reminder for operators
  expecting future ``--http`` / ``--sse`` variants.
- ``evidentia mcp doctor`` — health check. Verifies the MCP
  SDK imports cleanly + that the bundled catalog registry
  loads + that the FastMCP server can be constructed without
  errors. Useful for shaking out missing-dep issues post-
  install.

The server lifecycle stays in :mod:`evidentia_mcp.server`;
this module is purely the user-facing CLI shim.
"""

from __future__ import annotations

import sys

import typer

app = typer.Typer(
    name="mcp",
    help=(
        "Model Context Protocol (MCP) server. Exposes Evidentia "
        "to MCP-aware AI clients (Claude Desktop, Claude Code, "
        "ChatGPT Desktop, custom MCP clients) via stdio."
    ),
    no_args_is_help=True,
)


@app.command("serve")
def serve(
    stdio: bool = typer.Option(
        True,
        "--stdio/--no-stdio",
        help=(
            "Run over stdio (the canonical MCP transport). "
            "Currently the only supported transport; HTTP + SSE "
            "land in v0.8.1."
        ),
    ),
) -> None:
    """Run the MCP server (blocks until the client disconnects)."""
    if not stdio:
        typer.echo(
            "Only stdio transport is supported in v0.8.0. "
            "HTTP + SSE land in v0.8.1.",
            err=True,
        )
        raise typer.Exit(code=2)
    # Import lazily so `evidentia mcp doctor` works even when the
    # MCP SDK has a transient init issue (the doctor command
    # tells the operator what's wrong).
    from evidentia_mcp.server import run_stdio

    run_stdio()


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

    # 1. MCP SDK import
    try:
        import mcp.server.fastmcp  # noqa: F401
    except Exception as exc:
        failures.append(f"MCP SDK import failed: {exc!r}")

    # 2. Catalog registry loads + has frameworks
    try:
        from evidentia_core.catalogs.registry import FrameworkRegistry

        fws = FrameworkRegistry().list_frameworks()
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
        from evidentia_mcp.server import build_server

        server = build_server()
        # FastMCP exposes registered tools via _tool_manager._tools
        # (private but stable across the 1.x SDK line).
        registered = set(server._tool_manager._tools.keys())
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
