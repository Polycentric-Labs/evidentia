# 4. Reference

Look up CLI verbs, MCP tools, API symbols, configuration options, and bundled catalog + crosswalk listings.

## Pages in this section

- **[CLI](cli.md)** — every CLI verb + flag. Auto-generated via mkdocs-click (if Click) or manually maintained (if Typer) per the upstream tool's convention.

- **API reference (`api/`)** — auto-generated per workspace package via mkdocstrings:
  - [`evidentia-core`](api/evidentia-core.md)
  - [`evidentia-ai`](api/evidentia-ai.md)
  - [`evidentia-mcp`](api/evidentia-mcp.md)
  - [`evidentia-collectors`](api/evidentia-collectors.md)
  - [`evidentia-api`](api/evidentia-api.md)
  - [`evidentia-eval`](api/evidentia-eval.md)
  - [`evidentia-integrations`](api/evidentia-integrations.md)

- **[MCP tools](mcp-tools.md)** — the 13 MCP tools + signatures + behavior + append-only versioning rules per [`docs/api-stability.md`](../../api-stability.md) (NORMATIVE).

- **[Configuration](configuration.md)** — all environment variables + `evidentia.yaml` config file format + RBAC token model.

- **[Catalogs](catalogs.md)** — auto-generated table of 92 framework catalogs + family + version + bundled OSCAL availability.

- **[Crosswalks](crosswalks.md)** — auto-generated table of 13 crosswalks + source/target frameworks + verification posture + row count.

## How to use this section

Reference is symbol-level; use full-text search (or the table of contents in each page) to jump to a specific function, flag, or env var. The catalog + crosswalk tables are sortable + filterable in the rendered MkDocs site.

> **Stub status:** as of v0.10.7, the section structure exists but per-page content is stubs. API reference + catalog/crosswalk tables generate at docs-build time once mkdocs + mkdocstrings + the catalog-render script land.
