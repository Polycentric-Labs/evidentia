# Frozen surfaces and stability

Evidentia makes an explicit promise about which parts of it you can build on without fear of breakage. That promise is the API-stability contract: some surfaces are *frozen* (changing them is a major-version event with a deprecation cycle), some are *append-only* (you can add, never remove), and some are explicitly *non-frozen* (free to change in any release). This page summarizes that contract and the reasoning behind it. The NORMATIVE source of truth is [`docs/api-stability.md`](../6-project/api-stability.md) (mirrored in the wiki as [`6-project/api-stability.md`](../6-project/api-stability.md)); when this page and that document disagree, that document wins.

## Semantic-versioning policy

Evidentia follows [Semantic Versioning 2.0.0](https://semver.org/) with this interpretation:

| Bump | Meaning | Example |
|---|---|---|
| **Major** (X.0.0) | Breaking change to a frozen surface | Remove a Pydantic field; rename a CLI flag |
| **Minor** (1.X.0) | New functionality; additive-only changes to frozen surfaces | New `EventAction`; new CLI command; new optional model field |
| **Patch** (1.0.X) | Bug fixes, security patches, doc updates, catalog content refreshes | CVE fix; threshold-default adjustment; typo |

The contract has been **NORMATIVE since v0.9.7** — it is already binding, not a post-v1.0 aspiration. Evidentia will not knowingly break a frozen surface in any v0.9.x / v0.10.x release. The v1.0.0 release *ratifies* the contract already in force; it does not add new constraints. (The earlier v0.9.0 – v0.9.6 window was the "stabilization window" where the public surface was identified and documented in DRAFT form; minor bumps there could contain breaking changes.)

## What's frozen

These surfaces carry full semver guarantees. Breaking them requires a major bump with a deprecation cycle.

- **Pydantic model fields** (`evidentia_core.models.*`). All exported model classes have stable field names and types. Adding an optional field (with a default) is a minor change; renaming, removing, or retyping a field is a major trigger. The frozen set spans 48+ classes across 18 modules — `SecurityFinding` / `Finding` / `ComplianceStatus` / `FindingStatus`, `ControlGap` / `Milestone` / `POAMState`, `CrosswalkDefinition` / `FrameworkMapping`, `CatalogControl` / `ControlCatalog`, the AI-governance and RBAC and retention models, and more (see the [data model](data-model.md) page and the api-stability table for the full roster). A serialization guarantee rides along: JSON output of a frozen model at version N must deserialize under version N+1 within the same major (field *ordering* is not guaranteed).
- **The `EventAction` enum** (`evidentia_core.audit.events`) — **append-only**. Existing values are never removed or renamed; new values may be added in any minor. SIEM/alerting integrations can pin to these. (100 members today.)
- **CLI command + flag names and semantics** (`evidentia`). Command names are frozen, flag names are frozen within each command, and flag *semantics* are frozen. Flag *default values* may change in a minor (documented in CHANGELOG); adding new flags or subcommands is non-breaking. A deprecated flag emits a `DeprecationWarning` for at least one minor cycle before removal.
- **Plugin contracts** (`evidentia_core.plugins.*`) — five ABC/Protocol contracts third parties implement: `AuthProvider`, `StorageBackend[T]`, `MarketplaceProvider`, `BaseSaaSCollector`, `ContinuousEvidenceSource`. "Method signatures frozen" means parameter names/types/ordering and return types are stable; adding an optional parameter is non-breaking, but adding a new abstract method to an ABC is a major trigger (it breaks existing implementations).
- **Library entry points** — the documented importable paths (e.g. `from evidentia_core.gap_analyzer import GapAnalyzer`, `from evidentia_core.models import ControlGap`, `from evidentia_core.ocsf import finding_to_ocsf`). These import paths are frozen; a class may move modules internally as long as the original path keeps working via re-export.
- **REST API URIs** (`evidentia_api.routes.*`) — 16 routers under the `/api/<resource>` pattern (`/api/health`, `/api/gaps`, `/api/poam`, `/api/conmon`, …). URI paths, response JSON field names, HTTP methods, and query-parameter names are frozen (additions only); new endpoints are non-breaking. REST deprecation is signaled via the `Deprecation: true` and `Sunset: <date>` response headers (RFC 8594).
- **Env-var public contract** — a set of runtime-configuration env vars (`EVIDENTIA_POAM_STORE_DIR`, `EVIDENTIA_RBAC_POLICY_FILE`, `EVIDENTIA_EVIDENCE_STORE_DIR`, `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM`, and others) whose names and semantics are frozen with the same guarantees as CLI flags.

## The append-only MCP tool surface (13 tools)

MCP tool *names* are part of the contract with AI clients (Claude Desktop, Claude Code, custom MCP clients), so the tool surface is **append-only**: renaming a tool is a major trigger; adding a tool is non-breaking. As of v0.10.4 there are **13 tools**, each registered with a `@server.tool()` decorator in `packages/evidentia-mcp/src/evidentia_mcp/server.py`:

| Tool | Since | Purpose |
|---|---|---|
| `list_frameworks` | v0.8.0 | Enumerate bundled catalogs |
| `get_control` | v0.8.0 | Single-control lookup |
| `gap_analyze` | v0.8.0 | Run gap analysis |
| `gap_diff` | v0.8.0 | Compare two gap reports |
| `conmon_list_cadences` | v0.9.6 | List CONMON cadences |
| `conmon_next_due` | v0.9.6 | Compute next-due date |
| `conmon_check_state` | v0.9.6 | Read a state file into attention buckets |
| `conmon_health` | v0.9.6 | Health-report wrapper |
| `gap_analyze_sarif` | v0.10.2 | Gap analysis + SARIF 2.1.0 output (CI-gate use) |
| `collect_ocsf` | v0.10.2 | OCSF ingestion (file mode only) |
| `tprm_vendor_list` | v0.10.2 | List vendors from the local TPRM store (read-only) |
| `poam_list` | v0.10.2 | List POA&Ms from the local store (read-only) |
| `verify_signed_artifact` | v0.10.4 | Verify an Evidentia signed-artifact bundle |

Two deliberate hardening choices are encoded here: `collect_ocsf` is **file-mode only** — the URL-ingest path was omitted to remove the SSRF surface (finding F-V101-L1); and `verify_signed_artifact` path-gates its input through `validate_within(--allow-root)`. Tool *parameter names* are frozen; tool *descriptions* may be refined for clarity without being a breaking change.

## What's NOT frozen

Equally important is what you should *not* depend on:

- **Anything underscore-prefixed** — `_internal.*`, `_helper` / `_utils` / `_compat` modules, private methods (`def _compute_score`). Private is private.
- **Test fixtures and utilities** — everything under `tests/` (data files, `conftest.py` factories, helpers).
- **Bundled catalog content** — catalogs evolve as authoritative sources publish updates (NIST revisions, ISO amendments, EU enforcement dates). Content changes are patch-level, not API breaks; operators needing a pinned version use `evidentia catalog pin <framework> <version>`.
- **Threshold defaults** — faithfulness, determinism, and health-scoring defaults may be tuned between releases based on calibration; they are documented in CHANGELOG and overridable via CLI flags (`--faithfulness-threshold`, `--faithfulness-threshold-mode`, `--fail-on-determinism-rate-below`, `--health-score-weights`).
- **Scripts** (`scripts/`), **Docker image internals** (only the container's CLI interface is stable, not its file layout or base image), and **MCP tool descriptions/metadata** (the names are frozen; the prose is not).
- **The web UI** (`packages/evidentia-ui/`), CI workflows, and dev tooling are out of scope entirely.

## The deprecation policy

When a frozen surface genuinely must change, the change moves through three steps across at least two minor releases:

1. **Announce** (release N) — add a `DeprecationWarning` (Python) or deprecation header (REST), document under "Deprecated" in CHANGELOG.
2. **Maintain** (through release N+1) — the deprecated surface keeps working unchanged for at least one full minor cycle.
3. **Remove** (earliest release N+2) — document under "Removed"; this is the major bump.

A concrete in-flight example: the `evidentia_ai.eval.*` import path was moved to a dedicated `evidentia_eval` package in v0.10.5, and the old path is preserved as a deprecation shim through v0.11.x (emitting a `DeprecationWarning` at import) with removal scheduled for v0.12.0. The `SecurityFinding` alias follows the same pattern, with `Finding` as the canonical name and the alias retained for at least one minor cycle.

## Why this matters

Compliance tooling is consumed by people whose job is to trust artifacts: FedRAMP 3PAOs running audit queries against the event vocabulary, integrators building on the library entry points, operators pinning catalog versions for a frozen assessment window. A vocabulary that shifts under them breaks audit-trail continuity. Freezing the surfaces — and being equally explicit about what is *not* frozen — is what lets a query written against a v0.7.0 audit log stay meaningful against a v0.10.x one, and what lets an integrator build against `GapAnalyzer` with confidence that it will not move without a deprecation cycle.

## Related reading

- [`6-project/api-stability.md`](../6-project/api-stability.md) — the NORMATIVE contract (full frozen-surface tables + revision history). This page is a summary; that one is authoritative.
- [Data model](data-model.md) — the frozen Pydantic models in depth.
- [Evidence integrity](evidence-integrity.md) — `SignedToolOutput` (a frozen envelope) and the env-var contract.
- [RBAC and multi-tenancy](rbac-and-multi-tenancy.md) — frozen RBAC primitives versus the v0.11+ CLI/REST wiring roadmap.
- [`6-project/deprecation-policy.md`](../6-project/deprecation-policy.md) — the deprecation cadence in project terms.
