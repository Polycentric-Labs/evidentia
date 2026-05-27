# Architecture

Evidentia is a 9-package workspace organized as a layered compliance engine. The diagram below shows the data flow from evidence ingestion to OSCAL emit; the table below summarizes each package's responsibility.

## Data flow (one paragraph)

Evidence collectors pull raw signals from source systems (AWS API, GitHub API, Postgres catalog, etc.). Each signal becomes a `SecurityFinding` populated with full `CollectionContext` provenance. Findings flow through the catalog engine, which loads a framework's controls + bundles them with crosswalks. The gap analyzer compares findings to controls and produces `ControlGap` records. Risk-statement generation (optional, AI-assisted) and POA&M emission run downstream. Output is serialized to OSCAL Assessment Results, SARIF, OCSF Compliance + Detection Findings, or CycloneDX VEX. Throughout, the audit subsystem emits structured ECS 8.11 + NIST AU-3 events; the CIMD subsystem signs evidence with Sigstore keyless OIDC for verifiable downstream consumption.

```
                                                ┌──────────────────────────┐
                                                │ Bundled framework catalog│
                                                │ (92 catalogs incl. NIST  │
                                                │ 800-53 Rev5, FedRAMP,    │
                                                │ OSPS Baseline, etc.)     │
                                                └────────────┬─────────────┘
                                                             │
┌─────────────┐   ┌──────────────────┐   ┌─────────────────┐ │ ┌────────────────────┐   ┌─────────────────┐
│  Source     │   │ Evidence         │   │  Gap analyzer   │ │ │ Risk-statement     │   │ Output emitter  │
│  systems    │──▶│ collectors (14)  │──▶│ (compares       │◀┴▶│ generator (AI;     │──▶│ - OSCAL AR/POA&M│
│  (AWS, GH,  │   │  - github/osps   │   │  evidence to    │   │ optional via       │   │ - SARIF 2.1.0   │
│  PG, ...)   │   │  - aws,...       │   │  controls)      │   │ LiteLLM provider)  │   │ - OCSF Compl. + │
└─────────────┘   └────────┬─────────┘   └─────────────────┘   └────────────────────┘   │   Detection     │
                           │                                                            │ - CycloneDX VEX │
                           ▼                                                            │ - JSON          │
                  ┌─────────────────┐                                                   └─────────────────┘
                  │ Audit subsystem │
                  │ - ECS 8.11      │
                  │ - NIST AU-3     │
                  │ - OTel-friendly │
                  └─────────────────┘
```

## Package responsibilities

| Package | Layer | Responsibility |
|---|---|---|
| `evidentia` | CLI orchestration | Top-level Click CLI; routes verbs to per-domain modules. Entry-point package on PyPI. |
| `evidentia-core` | Foundation | `SecurityFinding` + `ControlGap` + `CrosswalkDefinition` Pydantic models; catalog engine; crosswalk engine; OCSF mapping (`evidentia_core.ocsf`); audit event emitter; CIMD signing; WORM store. The single import other packages depend on. |
| `evidentia-collectors` | Adapters | 14 evidence collectors (AWS, GitHub + GitHub OSPS extension, Postgres, MySQL, Oracle, SQLite, MS-SQL, Snowflake, Databricks, Okta, Vanta, Drata, BitSight, SecurityScorecard). All emit `SecurityFinding` with full `CollectionContext`. The v0.10.0+ `compliance_status` is set explicitly. |
| `evidentia-ai` | LLM features (opt-in) | Risk-statement generator + control explainer via LiteLLM (Claude / OpenAI / Anthropic / Bedrock / etc.). DFAH (Determinism, Faithfulness, And Harness) calibration applies. |
| `evidentia-eval` | Evaluation harness | DFAH calibration corpus + benchmark runner. Extracted to its own package v0.10.5 P9 so the air-gap install posture is preserved (lazy-import contract). |
| `evidentia-api` | REST + frontend | FastAPI REST endpoints + `evidentia-ui` (TS/JS Vite frontend bundled at wheel-assembly time). |
| `evidentia-mcp` | MCP server | 13 MCP tools (append-only per `docs/api-stability.md`). Drives Evidentia from any MCP host (Claude Desktop, Code, Cursor, Copilot CLI). Output envelopes are CIMD-signed. |
| `evidentia-integrations` | Third-party plugins | Bridge to Jira, ServiceNow, etc. for POA&M lifecycle integration. |
| `evidentia-ui` | Frontend | Vite + TypeScript SPA bundled into `evidentia-api`'s wheel. NOT published to PyPI separately. |

## Extension points

- **New framework catalog**: drop a YAML in `packages/evidentia-core/src/evidentia_core/catalogs/data/<region>/`; run `scripts/catalogs/regenerate_manifest.py`. See [contributing-a-catalog.md](../5-compliance/contributing-a-catalog.md).
- **New crosswalk**: drop a JSON in `packages/evidentia-core/src/evidentia_core/catalogs/data/mappings/`. Schema is `CrosswalkDefinition` with optional v0.10.6 `provenance`/`verification`/`verification_note` fields for upstream-attested crosswalks.
- **New collector**: implement the `BaseCollector` interface in `packages/evidentia-collectors/`. Must emit `SecurityFinding` with full `CollectionContext` + (v0.10.0+) explicit `compliance_status`.
- **New MCP tool**: add to `packages/evidentia-mcp/src/evidentia_mcp/server.py` using the append-only contract (never remove or change signatures of existing tools through v1.0).
- **New output format**: implement an emitter in `evidentia_core.gap_analyzer` following the SARIF/OCSF/CycloneDX VEX patterns; expose via `--format`.

## Design invariants

- **Frozen public surfaces** — `SecurityFinding`, `ControlGap`, `CrosswalkDefinition`, `EventAction` enum, MCP tool signatures, and CLI verb names are frozen per `docs/api-stability.md` NORMATIVE. Additions are allowed (optional fields, new enum values, new tools); removals are deprecation-cycle-only.
- **Provenance always set** — every `SecurityFinding` carries a real `CollectionContext` (not the v0.7.0 synthetic-legacy placeholder). The v0.10.5 P10 idempotency hardening makes finding IDs deterministic via UUID v5 + pinned namespace.
- **Deterministic outputs** — same evidence + same catalog version + same code = bit-stable output on identity axis (timestamps still vary). The DFAH harness in `evidentia-eval` verifies this.
- **Cryptographic chain** — evidence → signed CIMD envelope → OSCAL Assessment Results → cosign-signed container → PEP 740-attested wheel → CycloneDX SBOM → SLSA Provenance v1 attestation. Each layer's signing is verifiable independently.

## Threat model

See [`docs/threat-model.md`](../../threat-model.md). High-level: Evidentia trusts its evidence sources (operators are responsible for collector credential scope); does NOT trust input file paths (`evidentia_core.security.paths.validate_within` sanitizer); does NOT trust URLs in `evidentia collect ocsf` URL mode (the v0.10.2 `--block-private-ips` SSRF mitigation).

## Related reading

- [Data model](data-model.md) — every Pydantic schema, frozen + extension fields
- [Catalog engine](catalog-engine.md) — how catalogs load + index + serve
- [Crosswalk engine](crosswalk-engine.md) — how crosswalks load + map + emit OSCAL back-matter
- [Evidence integrity](evidence-integrity.md) — CIMD signing chain in depth
- [Frozen surfaces](frozen-surfaces-and-stability.md) — public API contract
- [`api-stability.md`](../6-project/api-stability.md) — NORMATIVE table of frozen + revision history
