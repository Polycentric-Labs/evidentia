"""evidentia-mcp — Model Context Protocol server for Evidentia.

Exposes Evidentia's gap analysis, control explanation, gap diff,
risk-statement generation, and OSCAL emit surfaces to MCP-aware
AI clients (Claude Desktop, Claude Code, ChatGPT Desktop, etc.)
via the canonical stdio transport.

Public API:

- :func:`build_server` — construct the FastMCP server with all
  tools registered. Useful for embedding (custom MCP transports,
  tests).
- :func:`run_stdio` — convenience wrapper that builds the server
  and runs it over stdio. Equivalent to ``evidentia mcp serve``.

The CLI entry-points (``evidentia mcp serve``, ``evidentia mcp
doctor``) live in :mod:`evidentia_mcp.cli` and are wired into
the top-level ``evidentia`` Typer app.
"""

from __future__ import annotations

from evidentia_mcp.server import build_server, run_stdio

__all__ = ["build_server", "run_stdio"]
