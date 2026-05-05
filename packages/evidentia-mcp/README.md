# evidentia-mcp

Model Context Protocol (MCP) server for Evidentia.

Exposes Evidentia's gap analysis, risk-statement generation,
control explanation, OSCAL emit, and gap-diff surfaces to
MCP-aware AI clients (Claude Desktop, Claude Code, ChatGPT
Desktop, custom MCP clients).

## Quick start

```bash
pip install evidentia[mcp]

# Run the server over stdio (the canonical MCP transport)
evidentia mcp serve

# Health check (validates SDK availability + reachable
# evidentia-core / evidentia-ai surfaces)
evidentia mcp doctor
```

## Tool surface

| Tool | Maps to | Auth |
|---|---|---|
| `gap_analyze` | `evidentia_core.gap_analyzer` | none (read-only) |
| `risk_generate` | `evidentia_ai.risk_statements` | optional API key (LiteLLM env vars) |
| `explain_control` | `evidentia_ai.explain` | optional API key |
| `oscal_emit` | `evidentia_core.oscal.exporter` | optional Sigstore identity (env-driven) |
| `gap_diff` | `evidentia_core.gap_analyzer.diff` | none |
| `collect_aws` | `evidentia_collectors.aws` | provider creds (env-driven) |
| `collect_github` | `evidentia_collectors.github` | provider creds |
| `collect_jira` | `evidentia_collectors.jira` | provider creds |

All credential handling follows the same env-var-driven
secret-handling protocol Evidentia uses everywhere — the MCP
server NEVER accepts credentials in tool arguments.

## Transport

v0.8.0 ships the **stdio** transport only (the most common +
canonical MCP transport — used by Claude Desktop, Claude Code,
and most other MCP clients). HTTP transport + Client ID
Metadata Document (CIMD) richness defer to v0.8.1.

## License

Apache-2.0. See the workspace root LICENSE file.
