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

- **[Web console security](web-console-security.md)** — the standing security model for `evidentia serve`: the inherited controls and their default postures, the anonymous-by-default disclosure, what each console exposes, and the hardening checklist for a shared deployment.

## Recommended reading order

`Architecture` → `Data model` → `Catalog engine` → `Crosswalk engine` → `Evidence integrity` → `Frozen surfaces and stability` → `RBAC and multi-tenancy` → `Web console security`.

After this section, jump to [Reference](../4-reference/index.md) for symbol-level detail or [Compliance](../5-compliance/index.md) for framework-specific material.

All eight concept pages above are live.
