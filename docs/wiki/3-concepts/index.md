# 3. Concepts

Explanation + the "why" behind Evidentia's design. Read these if you're extending Evidentia or evaluating whether it fits your environment.

## Pages in this section

- **[Architecture](architecture.md)** — 9-package workspace overview + data flow + extension points + design invariants. The foundational page for everything else.

- **[Data model](data-model.md)** — `SecurityFinding`, `ControlGap`, `CollectionContext`, `ComplianceStatus` enum, OCSF mapping; the frozen-surface contract.

- **[Catalog engine](catalog-engine.md)** — how catalog YAMLs are loaded, validated, indexed; the `_load_catalog_data` ext-dispatch pattern; manifest regeneration.

- **[Crosswalk engine](crosswalk-engine.md)** — how crosswalks are loaded; the `CrosswalkDefinition` schema (including v0.10.6 `provenance`/`verification`/`verification_note` additive fields); OSCAL mapping back-matter.

- **[Evidence integrity](evidence-integrity.md)** — CIMD envelope structure; signing keys; verification chain; WORM backend interface.

- **[Frozen surfaces and stability](frozen-surfaces-and-stability.md)** — public-API contract; append-only MCP tool surface; semantic-versioning policy.

- **[RBAC and multi-tenancy](rbac-and-multi-tenancy.md)** — multi-tenant primitives from v0.9.7 (data + decision layer); v0.11+ CLI/REST wiring direction.

## Recommended reading order

`Architecture` → `Data model` → `Catalog engine` → `Crosswalk engine` → `Evidence integrity` → `Frozen surfaces and stability` → `RBAC and multi-tenancy`.

After this section, jump to [Reference](../4-reference/) for symbol-level detail or [Compliance](../5-compliance/) for framework-specific material.

> **Stub status:** as of v0.10.7, `architecture.md` is the only detailed concept page; others are stubs to be filled in over upcoming cycles.
