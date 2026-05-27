# Evidentia wiki

> The canonical reference for using, extending, and operating Evidentia. Six sections; reading-path optimized for first-time users to walk top-to-bottom.

## Sections

1. **[Getting Started](1-getting-started/)** — install + 5-minute quickstart + first collector wire-up.
2. **[Guides](2-guides/)** — task-oriented how-tos (gap analysis, OCSF ingest, SARIF emit, POA&M management, CI integration, OSPS self-assessment, etc.).
3. **[Concepts](3-concepts/)** — explanation + architecture; what's frozen vs evolving; how the catalog/crosswalk/evidence-integrity engines work.
4. **[Reference](4-reference/)** — CLI verbs, MCP tools, API symbols (auto-gen via mkdocstrings), configuration, catalog + crosswalk listings.
5. **[Compliance](5-compliance/)** — the differentiator section: catalog inventory, framework conformance claims, crosswalk index, OSPS Baseline mapping, OCSF mapping, Gemara mapping, financial-sector overlay, contributing a catalog.
6. **[Project](6-project/)** — project meta: roadmap, changelog, API stability, versioning, governance, security, contributing, EOL, verification, FAQ.

## How to navigate

- **First-time user**: start at [Getting Started](1-getting-started/) → [Quickstart](1-getting-started/quickstart.md).
- **Operator running Evidentia in CI**: jump to [Guides → CI integration](2-guides/ci-integration.md) + [Guides → Emit SARIF](2-guides/emit-sarif.md).
- **Compliance engineer adding a framework**: jump to [Compliance → Contributing a catalog](5-compliance/contributing-a-catalog.md) + [Concepts → Catalog engine](3-concepts/catalog-engine.md).
- **Auditor verifying release artifacts**: jump to [Project → Verification](6-project/verification.md) + [Project → Security](6-project/security.md).
- **Looking up a CLI flag or MCP tool signature**: jump to [Reference](4-reference/).

## Source + contributions

Wiki source lives in-repo at `docs/wiki/`. Edits go through normal PR review. The wiki is built with [Material for MkDocs](https://squidfunk.github.io/mkdocs-material/) from the markdown source; see [the canonical mkdocs.yml](../../mkdocs.yml) at repo root for build config.

To contribute: PR to `docs/wiki/<section>/<page>.md`. New pages must include an entry in their section's index.md.
