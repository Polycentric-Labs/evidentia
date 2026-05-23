# Evidentia plugin — for `GRCEngClub/claude-grc-engineering`

> Open-source plugin for the [GRC Engineering Club's Claude Code
> marketplace](https://github.com/GRCEngClub/claude-grc-engineering).
> Wraps [Evidentia](https://github.com/Polycentric-Labs/evidentia)'s
> 12 MCP tools so AI clients (Claude Desktop, Claude Code) can drive
> gap analysis, SARIF CI-gate output, OCSF ingestion, TPRM, and
> POA&M end-to-end without leaving the chat.

**Status**: staged in the Evidentia repo as
`marketplace/grc-engineering-suite/plugins/evidentia/` per
[`docs/v0.10.2-marketplace.md`](../../../../docs/v0.10.2-marketplace.md);
upstream PR to `GRCEngClub/claude-grc-engineering` is a separate
step requiring explicit approval.

## What ships

- **Plugin manifest** (`.claude-plugin/plugin.json`) — name +
  version + author + repository + Apache-2.0 license, matching the
  upstream marketplace `plugin.json` schema (cross-checked against
  `grc-auditor`'s manifest).
- **Two OSS commands** (`commands/`) — generalist GRC engineer
  workflows; persona-tied commands (TPRM / federal / model-risk)
  are intentionally reserved for the future Evidentia Pro / Federal
  commercial tier per the v0.10.2 scope decision:
  - `gap-analyze-sarif` — gap analysis + SARIF 2.1.0 for a CI gate.
  - `ingest-ocsf` — Prowler / AWS Security Hub OCSF ingestion +
    optional framework crosswalk.

## Prerequisites

The plugin commands call Evidentia's MCP tools. Operators must have
the MCP server installed and registered in their Claude Code or
Claude Desktop config:

```bash
# Install
pip install 'evidentia[gui]==0.10.2'      # CLI + UI
pip install 'evidentia-mcp==0.10.2'        # MCP server entry point
pip install 'evidentia-collectors[ocsf]==0.10.2'  # for ingest-ocsf

# Register the MCP server. Example Claude Desktop config snippet:
{
  "mcpServers": {
    "evidentia": {
      "command": "evidentia",
      "args": ["mcp", "serve"]
    }
  }
}
```

See the [Evidentia README](https://github.com/Polycentric-Labs/evidentia/blob/main/README.md)
for full install + MCP-registration docs.

## License

Apache-2.0. The Evidentia engine + MCP tools + these commands are
all Apache-2.0 OSS. (The GRC Engineering Club marketplace itself is
MIT; the per-plugin license is what governs the plugin code.)

## Versioning

This plugin tracks the Evidentia release line — v0.10.2 of the
plugin pairs with v0.10.2 of `evidentia-mcp`. The 12 MCP tool names
are frozen per [Evidentia's `api-stability.md` §MCP tool
contract](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/api-stability.md),
so plugin commands stay compatible with future Evidentia minor
releases.
