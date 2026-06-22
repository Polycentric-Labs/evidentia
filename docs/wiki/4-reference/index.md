# 4. Reference

Look up CLI verbs, MCP tools, API symbols, configuration options, and bundled catalog + crosswalk listings.

## Pages in this section

Most pages below are **auto-generated from the live codebase / data** by
`scripts/wiki/sync_reference.py` (the 5 auto-generated reference pages) and
`scripts/wiki/sync_api_docs.py` (the 7 API pages); each carries a "do not edit
directly" banner — edit the underlying code/data and re-run the generator, and a
`--check` mode on both scripts (wired into `sync-wiki.yml`) fails on drift. The
**Inventory + system-context** page below is hand-authored: its field tables are
sourced from the Pydantic models, with example files from `evidentia init`.

- **[CLI](cli.md)** — every CLI command + subcommand + flag, introspected from the live Typer app.

- **API reference (`api/`)** — a concise public-surface index per workspace package (symbols + submodules + a pointer to the live MkDocs API site for full signatures):
  - [`evidentia-core`](api/evidentia-core.md)
  - [`evidentia-ai`](api/evidentia-ai.md)
  - [`evidentia-mcp`](api/evidentia-mcp.md)
  - [`evidentia-collectors`](api/evidentia-collectors.md)
  - [`evidentia-api`](api/evidentia-api.md)
  - [`evidentia-eval`](api/evidentia-eval.md)
  - [`evidentia-integrations`](api/evidentia-integrations.md)

- **[MCP tools](mcp-tools.md)** — the MCP tools + signatures + behavior, parsed from the server's `@server.tool()` functions, with the append-only versioning rule per [`api-stability.md`](../6-project/api-stability.md) (NORMATIVE).

- **[Configuration](configuration.md)** — the `evidentia.yaml` schema + every `EVIDENTIA_*` environment variable + the LLM provider keys.

- **[Catalogs](catalogs.md)** — table of the bundled framework catalogs (the count is computed from the manifest), grouped by family + tier.

- **[Crosswalks](crosswalks.md)** — table of the bundled crosswalks + source/target frameworks + verification posture + mapping-row count (all computed from the mapping files).

- **[Inventory + system-context](inventory-and-system-context.md)** — hand-authored schema reference for the input files `evidentia init` produces and `gap analyze` consumes (`evidentia.yaml`, `system-context.yaml`, `my-controls.yaml`).

## How to use this section

Reference is symbol-level; use full-text search (or the table of contents in each page) to jump to a specific command, flag, env var, or symbol. The catalog + crosswalk tables are sortable + filterable in the rendered MkDocs site.
