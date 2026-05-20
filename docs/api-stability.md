# API stability commitments — NORMATIVE

> **Status**: NORMATIVE as of v0.9.7 (2026-05-19). Promoted from
> DRAFT during the v0.9.7 P2.1 v1.0-prep cycle per the
> `docs/v1.0-transition.md` Candidate B framing. Promoted ahead of
> v1.0 so the v0.9.x → v1.0.0 transition does not require any
> additional API-contract changes — the contract is set and
> tested over the remaining v0.9.x line.
>
> **Scope**: defines which surfaces carry semantic-versioning
> guarantees, and which surfaces remain free to change without
> a major-version bump. Operators MAY rely on the frozen surfaces;
> integrators MAY build against them with confidence that
> Evidentia will not break them without a deprecation cycle.
>
> **Pre-v1.0 vs post-v1.0 semantics**: this NORMATIVE document is
> already binding — Evidentia will not knowingly break a frozen
> surface listed below in any v0.9.x release. The v1.0.0 release
> itself does not add new constraints; it ratifies the contract
> already in force.
>
> **Canonical location**: `docs/api-stability.md`
> **Cross-references**: [v1.0-transition.md](v1.0-transition.md),
> [enterprise-grade.md](enterprise-grade.md),
> [release-checklist.md](release-checklist.md),
> [deprecation-calendar.md](deprecation-calendar.md)

---

## Versioning semantics (post-v1.0)

Evidentia follows [Semantic Versioning 2.0.0](https://semver.org/)
with the following interpretation:

| Bump | Meaning | Example |
|------|---------|---------|
| **Major** (X.0.0) | Breaking change to a frozen surface | Remove a Pydantic field, rename a CLI flag |
| **Minor** (1.X.0) | New functionality, additive-only changes to frozen surfaces | New EventAction, new CLI command, new optional model field |
| **Patch** (1.0.X) | Bug fixes, security patches, doc updates, catalog content refreshes | CVE fix, threshold default adjustment, typo |

**Pre-v1.0 (v0.9.7 onward — this document NORMATIVE)**: the
contract listed in this document is binding. Breaking changes to
frozen surfaces require a deprecation cycle per the policy in §
"Deprecation policy" below. The v1.0.0 release ratifies (does not
expand) the contract already in force.

**Earlier pre-v1.0 (v0.9.0 – v0.9.6)**: minor bumps may have
contained breaking changes to any surface. The v0.9.x line was
the "stabilization window" where the public contract was
identified and documented in DRAFT form.

---

## Frozen surfaces

These surfaces carry full semver guarantees at v1.0+. Breaking
changes require a major-version bump with a deprecation cycle.

### 1. Pydantic model fields

**Package**: `evidentia_core.models.*`

All exported model classes have stable field names and types.
Adding optional fields (with defaults) is a minor-bump change.
Renaming, removing, or changing the type of an existing field
is a major-bump trigger.

Frozen models (45+ classes across 17 modules; v0.9.7-confirmed):

| Module | Key models |
|--------|-----------|
| `common.py` | `FrameworkMetadata`, `ControlMapping`, `EvidentiaModel` |
| `control.py` | `Control`, `ControlFamily`, `ControlImplementation`, `ControlInventory`, `ControlStatus` |
| `evidence.py` | `EvidenceArtifact`, `EvidenceBundle`, `EvidenceType`, `EvidenceSufficiency`. v0.9.5+ adds `EvidenceArtifact.version` / `lineage_id` / `predecessor_id` Optional fields + `new_version()` factory helper; these are now frozen. |
| `gap.py` | `GapFinding`, `GapSeverity`, `GapAnalysisReport`, `ControlGap`, `Milestone`, `POAMState`. v0.9.5 adds `Milestone.owner` / `Milestone.reviewer` Optional fields; these are now frozen. |
| `vendor.py` | `VendorProfile`, `VendorRiskTier` |
| `vendor_finding.py` | `VendorFinding` |
| `vendor_manifest.py` | `VendorManifest` |
| `assessment.py` | `Assessment`, `AssessmentStatus` |
| `claim.py` | `TraceClaim`, `ReasoningTrace` |
| `oscal_profile.py` | `OSCALProfile` |
| `crosswalk.py` | `CrosswalkMapping` |
| `catalog.py` | `CatalogEntry`, `CatalogControl`, `ControlCatalog` |
| `tprm.py` | `TPRMAssessment`, `TPRMFinding` |
| `governance.py` | `AISystem`, `AIRiskClassification`, `GovernanceRecord` |
| `ai_governance/classification.py` (v0.9.3+) | `AISystemDescriptor`, `AISystemClassification`, `EUAIActTier`, `NISTAIRMFFunction`, `AnnexIIIDomain` |
| `ai_governance/registry.py` (v0.9.3+; v0.9.6 federal expansion) | `AISystemRegistryEntry`, `DeploymentStatus`, `ATOReference` (v0.9.6) |
| `ai_governance/fips199.py` (v0.9.6+) | `FIPS199Categorization`, `FIPS199Impact` |
| `ai_governance/omb_m_24_10.py` (v0.9.6+) | `OMBImpactCategory` |
| `ai_governance/scr.py` (v0.9.6+) | `SCRForm`, `SCRCategory` |
| `rbac/policy.py` (v0.9.5+) | `Role`, `RBACPolicy`. `check_permission(identity, action, policy)` + `load_policy_from_file(path)` callables also frozen. |
| `retention/metadata.py` (v0.7.11+) | `RetentionMetadata`, `RetentionClassification`, `RetentionLifecycleStage` |

**Serialization guarantee**: JSON-serialized output of any frozen
model at version N must be deserializable by version N+1 within
the same major. Field ordering in JSON output is not guaranteed.

### 2. EventAction enum

**Package**: `evidentia_core.audit.events`

The `EventAction` enum is an append-only contract. Existing
values are never removed or renamed post-v1.0. New values may
be added in any minor release.

Current namespaces (80+ values as of v0.9.8). Example values below
are real members of `evidentia_core.audit.events.EventAction` — the
enum module is the authoritative source:

| Prefix | Domain | Example values |
|--------|--------|----------------|
| `COLLECT_*` | Evidence collection | `COLLECT_STARTED`, `COLLECT_COMPLETED`, `COLLECT_FAILED` |
| `AUTH_*` | Authentication | `AUTH_CREDENTIAL_RESOLVED`, `AUTH_CREDENTIAL_FAILED` |
| `CONFIG_*` | Configuration | `CONFIG_LOADED`, `CONFIG_RESOLVED`, `CONFIG_INVALID` |
| `SIGN_*` | Cryptographic signing | `SIGN_GPG_SIGNED`, `SIGN_SIGSTORE_SIGNED`, `SIGN_FAILED` |
| `VERIFY_*` | Verification | `VERIFY_DIGEST_PASSED`, `VERIFY_SIGNATURE_PASSED`, `VERIFY_COMPLETED` |
| `MANIFEST_*` | Manifest operations | `MANIFEST_GENERATED`, `MANIFEST_EMPTY_SET_ATTESTED`, `MANIFEST_INCOMPLETE` |
| `AI_*` | AI/LLM operations | `AI_RISK_GENERATED`, `AI_EVAL_FAITHFULNESS_CHECKED` |
| `AI_SYSTEM_*` (v0.9.3+) | AI system inventory | `AI_SYSTEM_CLASSIFIED`, `AI_SYSTEM_REGISTERED`, `AI_SYSTEM_UPDATED`, `AI_SYSTEM_RETIRED`, `AI_SYSTEM_DELETED`, `AI_SYSTEM_FIPS_CATEGORIZED` (v0.9.6), `AI_SYSTEM_OMB_CLASSIFIED` (v0.9.6), `AI_SYSTEM_SCR_EMITTED` (v0.9.6) |
| `AI_MCP_*` | MCP server operations | `AI_MCP_TOOL_AUTHORIZED`, `AI_MCP_TOOL_DENIED` |
| `POAM_*` | POA&M lifecycle | `POAM_CREATED`, `POAM_MILESTONE_REACHED`, `POAM_VERIFIED` |
| `CONMON_*` | Continuous monitoring | `CONMON_DAEMON_STARTED`, `CONMON_ALERT_DISPATCHED`, `CONMON_CYCLE_DUE`, `CONMON_CYCLE_OVERDUE`, `CONMON_CYCLE_MARKED_COMPLETED` |
| `EVIDENCE_*` (v0.9.6+) | Evidence WORM lineage | `EVIDENCE_VERSION_PERSISTED`, `EVIDENCE_WORM_VIOLATION_BLOCKED`, `EVIDENCE_LINEAGE_QUERIED` |
| `RBAC_*` (v0.9.8+) | Multi-tenant RBAC | `RBAC_TENANT_BOUNDARY_CROSSED` |
| `RETENTION_*` | Data retention | `RETENTION_RECORD_PUT`, `RETENTION_RECORD_EXTENDED`, `RETENTION_LEGAL_HOLD_APPLIED`, `RETENTION_LEGAL_HOLD_RELEASED`, `RETENTION_LIFECYCLE_TRANSITIONED`, `RETENTION_RECORD_PURGED`, `RETENTION_GDPR_PURGE` |

Operators building alerting / SIEM integrations on top of the
audit log can depend on these values being stable.

### 3. CLI flag names and semantics

**Package**: `evidentia` (the CLI entry point)

Top-level command groups (18+ as of v0.9.7):

```
evidentia gap          evidentia catalog      evidentia risk
evidentia explain      evidentia integrations evidentia collect
evidentia oscal        evidentia tprm         evidentia model-risk
evidentia governance   evidentia retention    evidentia poam
evidentia conmon       evidentia ai-gov       evidentia eval
evidentia mcp          evidentia serve        evidentia evidence (v0.9.6)
```

**Global flags (frozen across all commands)**:

- `--verbose` / `-v` — DEBUG-level logging
- `--quiet` / `-q` — ERROR-level only
- `--config <path>` — explicit `evidentia.yaml` override
- `--offline` — air-gap guard (v0.4.0)
- `--json-logs` — ECS 8.11 JSON output (v0.7.0)
- `--rbac-identity <id>` — per-invocation RBAC identity override (v0.9.6)

**Stability contract**:

- Command names are frozen (rename = major bump)
- Flag names (`--flag-name`) are frozen within each command
- Flag semantics (what a flag does) are frozen
- Flag default values may change in minor releases (documented
  in CHANGELOG)
- Adding new flags is non-breaking (minor bump)
- Adding new commands or subcommands is non-breaking (minor bump)

**Deprecation for CLI**: a deprecated flag emits a
`DeprecationWarning` for at least 1 minor-release cycle before
removal. The warning includes the replacement flag name.

### 4. Plugin contracts

**Package**: `evidentia_core.plugins.*`

Five ABC/Protocol contracts that third-party code may implement:

| Contract | Location | Stability |
|----------|----------|-----------|
| `AuthProvider` | `plugins.auth._base` | Method signatures frozen |
| `StorageBackend[T]` | `plugins.storage._base` | Generic ABC; method signatures frozen |
| `MarketplaceProvider` | `plugins.marketplace._base` | Method signatures frozen |
| `BaseSaaSCollector` | `plugins.collectors._base` | Method signatures frozen; `_auth_header()` hook stable |
| `ContinuousEvidenceSource` | `plugins.continuous` | Protocol; `poll()` + `health_check()` + attributes frozen |

**What "method signatures frozen" means**:

- Parameter names, types, and ordering are stable
- Return types are stable
- Adding optional parameters (with defaults) is non-breaking
- Adding new abstract methods to an ABC is a major-bump trigger
  (breaks existing implementations)

**Supporting dataclasses** used in plugin signatures are also
frozen: `AuthResult`, `CatalogManifest`, `EvidenceRecord`.

### 5. Library entry points

Public importable paths that operators and integrators use:

```python
# Core analysis + data models
from evidentia_core.gap_analyzer import GapAnalyzer
from evidentia_core.models import ControlGap, GapFinding, ...
from evidentia_core.audit.events import EventAction
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.conmon import derive_status, BUNDLED_CADENCES
from evidentia_core.poam import POAMState, Milestone
from evidentia_core.poam_store import save_poam, load_poam_by_id
from evidentia_core.plugins import AuthProvider, StorageBackend, ...

# v0.9.5+ RBAC + collaboration primitives
from evidentia_core.rbac import (
    Role, RBACPolicy, check_permission, load_policy_from_file,
)

# v0.9.6+ evidence WORM store + cloud mirror
from evidentia_core.evidence_store import (
    save_evidence, list_lineage, load_evidence_version,
    list_lineages, get_evidence_store_dir,
    EvidenceWORMViolation, InvalidEvidenceIdError,
    EVIDENCE_STORE_ENV_VAR,
)
from evidentia_core.evidence_store_worm import (
    mirror_to_worm, fetch_from_worm,
)

# v0.9.6+ AI-gov federal expansion
from evidentia_core.ai_governance import (
    FIPS199Categorization, FIPS199Impact,
    OMBImpactCategory, triggers_minimum_practices,
    ATOReference, AISystemRegistryEntry, DeploymentStatus,
)
from evidentia_core.ai_governance.scr import (
    SCRForm, SCRCategory, emit_scr_form, classify_change,
)

# v0.9.6+ OSCAL schema version constant
from evidentia_core.oscal import OSCAL_SCHEMA_VERSION

# AI features
from evidentia_ai.risk_statements import RiskStatementGenerator
from evidentia_ai.eval import DFAHarness, faithfulness_score

# Collectors + integrations
from evidentia_collectors.vendor_risk import (
    BitSightCollector, SecurityScorecardCollector,
    RiskReconCollector, UpGuardCollector,
)
from evidentia_integrations.alerting import SmtpChannel, WebhookChannel

# API + MCP entry points
from evidentia_api.app import create_app
from evidentia_api.rbac_dependency import require_role
from evidentia_mcp.server import build_server  # v0.8.0+ name
```

**Stability contract**: these import paths are frozen. Moving a
class to a different module internally is allowed as long as the
original import path continues to work (via re-export).

### 6. REST API URIs

**Package**: `evidentia_api.routes.*`

All REST endpoints follow the pattern `/api/<resource>` and are
versioned implicitly (no `/v1/` prefix until a breaking REST
change necessitates it).

Frozen URI prefixes (16 routers):

| Prefix | Router module | Purpose |
|--------|--------------|---------|
| `/api/health` | `health.py` | Liveness + readiness |
| `/api/config` | `config.py` | Configuration state |
| `/api/doctor` | `doctor.py` | Environment diagnostics |
| `/api/explain` | `explain.py` | Control explanations |
| `/api/llm-status` | `llm_status.py` | LLM provider health |
| `/api/frameworks` | `frameworks.py` | Framework catalog |
| `/api/init-wizard` | `init_wizard.py` | First-run wizard |
| `/api/risks` | `risks.py` | Risk statements |
| `/api/gaps` | `gaps.py` | Gap analysis |
| `/api/integrations` | `integrations.py` | Integration status |
| `/api/tprm` | `tprm.py` | Third-party risk |
| `/api/model-risk` | `model_risk.py` | AI model risk |
| `/api/collectors` | `collectors.py` | Collector status |
| `/api/metrics` | `metrics.py` | Prometheus metrics |
| `/api/poam` | `poam.py` | POA&M management |
| `/api/conmon` | `conmon.py` | Continuous monitoring |
| `/api/ai-gov` | `ai_gov.py` | AI governance |

**Stability contract**:

- URI paths are frozen (rename = major bump)
- Response JSON field names are frozen (additions only)
- HTTP methods per endpoint are frozen
- Query parameter names are frozen
- Adding new endpoints is non-breaking (minor bump)
- Adding new optional query parameters is non-breaking

---

## Non-frozen surfaces

These surfaces may change in any release (minor or patch)
without constituting a breaking change. Operators should not
depend on their stability.

### Internal helpers

Any function, class, or module prefixed with underscore (`_`) is
private. This includes:

- `evidentia_core._internal.*`
- Any `_helper`, `_utils`, `_compat` modules
- Private methods on public classes (`def _compute_score(...)`)

### Test fixtures and utilities

Everything under `tests/` is non-frozen:

- Test data files (`tests/data/dfah-calibration/corpus*.jsonl`)
- Fixture factories (`tests/conftest.py`)
- Test helper modules (`tests/helpers/`)

### Bundled catalog content

The compliance catalogs shipped with Evidentia evolve as
authoritative sources publish updates (NIST revisions, ISO
amendments, EU regulation enforcement dates). Catalog content
changes are patch-level — they don't constitute API breaks.

Operators who need pinned catalog versions use:
```bash
evidentia catalog pin <framework> <version>
```

### Threshold defaults

Default values for scoring thresholds (faithfulness, risk
determinism, health scoring) may be tuned between releases
based on empirical calibration results. These changes are
documented in CHANGELOG but are non-breaking because operators
can always override via CLI flags:

- `--faithfulness-threshold`
- `--faithfulness-threshold-mode {framework-aware,fixed}`
- `--fail-on-determinism-rate-below`
- `--health-score-weights`

### Scripts

Everything under `scripts/` is operational tooling, not public
API. Scripts may be added, removed, or refactored freely.

### Docker image internals

The container's internal layout (file paths, installed packages,
base image) is non-frozen. Only the CLI interface exposed by
the container is stable (same guarantees as CLI flags above).

### MCP tool descriptions and metadata

While MCP tool *names* are frozen (they're part of the tool
contract with AI clients), tool *descriptions* and *parameter
descriptions* may be refined for clarity without constituting
a breaking change.

---

## Deprecation policy

When a frozen surface must change:

1. **Announce**: add a `DeprecationWarning` (Python) or
   deprecation notice (REST response header) in minor release N.
   Document in CHANGELOG under "Deprecated".

2. **Maintain**: the deprecated surface continues to work
   unchanged for at least 1 full minor-release cycle (release
   N through N+1).

3. **Remove**: earliest removal is in release N+2. Document
   in CHANGELOG under "Removed". This constitutes a major-
   version bump.

**Example timeline**:

```
v1.2.0 — deprecate --old-flag (warning emitted; --new-flag added)
v1.3.0 — --old-flag still works (warning still emitted)
v2.0.0 — --old-flag removed; major bump
```

For REST endpoints, deprecation is signaled via:
- `Deprecation: true` response header (RFC 8594)
- `Sunset: <date>` header when removal date is known

---

## Compatibility testing

The release pipeline validates API stability via:

1. **Type checking** (mypy strict): catches signature changes
   that would break callers
2. **Test suite** (2747+ tests): exercises public interfaces
   against expected behavior
3. **Import smoke test**: `scripts/check_imports.py` (reserved
   for v1.0) will validate that all documented entry points
   resolve
4. **Schema regression**: Pydantic model `.model_json_schema()`
   output compared between releases (reserved for v1.0)

---

## Scope of this document

This document covers the **library, CLI, REST, and plugin**
surfaces of Evidentia. It does NOT cover:

- **The web UI** (`packages/evidentia-ui/`): frontend component
  APIs are not part of the public contract
- **GitHub Actions workflows**: CI/CD implementation details
- **Development tooling**: ruff config, mypy config, test
  infrastructure
- **Documentation format**: doc structure may reorganize freely

---

## MCP tool contract

**Package**: `evidentia_mcp.server`

MCP tool names are frozen — they are part of the contract with AI
clients (Claude Desktop, Claude Code, custom MCP clients). Renaming
a tool is a major-bump trigger; adding new tools is non-breaking.

Frozen tool surface (as of v0.9.7):

| Tool | Since | Purpose |
|---|---|---|
| `list_frameworks` | v0.8.0 | Enumerate bundled catalogs |
| `get_control` | v0.8.0 | Single-control lookup |
| `gap_analyze` | v0.8.0 | Run gap analysis |
| `gap_diff` | v0.8.0 | Compare two gap reports |
| `conmon_list_cadences` | v0.9.6 | List CONMON cadences |
| `conmon_next_due` | v0.9.6 | Compute next-due date |
| `conmon_check_state` | v0.9.6 | Read state file → attention buckets |
| `conmon_health` | v0.9.6 | Health report wrapper |

Tool *parameter names* are frozen. Tool *descriptions* may be
refined for clarity without constituting a breaking change.

CIMD scope-grant semantics (v0.8.5+) are NOT frozen: operators
adding new tools through CIMD registry updates (via
`evidentia mcp cimd-migrate` in v0.9.7+) is a deployment-time
concern, not an API contract.

---

## Env-var public contract (v0.9.7 NEW)

Operators rely on certain env vars to configure Evidentia at
runtime. The names + semantics of these vars are frozen with the
same guarantees as CLI flags. Removal requires a deprecation
cycle.

| Env var | Since | Purpose |
|---|---|---|
| `EVIDENTIA_POAM_STORE_DIR` | v0.9.0 | POA&M JSON store directory |
| `EVIDENTIA_AI_REGISTRY_DIR` | v0.9.3 | AI-gov registry directory |
| `EVIDENTIA_TRUST_PROXY_HEADERS` | v0.9.5 | `X-Forwarded-For` ingest gate |
| `EVIDENTIA_RBAC_POLICY_FILE` | v0.9.5 (FastAPI), v0.9.6 (CLI) | RBAC policy YAML path |
| `EVIDENTIA_RBAC_IDENTITY` | v0.9.6 | CLI RBAC identity |
| `EVIDENTIA_EVIDENCE_STORE_DIR` | v0.9.6 | Evidence store root directory |
| `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM` | v0.9.7 | Gate auto-mirror to cloud WORM |
| `EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY` | v0.9.7 | Dotted-path factory for auto-mirror backend |

---

## Revision history

| Version | Date | Change |
|---------|------|--------|
| DRAFT | 2026-05-16 | Initial authoring during v0.9.3 P5 |
| DRAFT | 2026-05-18 | v0.9.4 – v0.9.5 surfaces inventoried (no doc edits yet) |
| **NORMATIVE** | **2026-05-19** | **Promoted from DRAFT during v0.9.7 P2.1. v0.9.4 – v0.9.6 surfaces backfilled: evidence WORM store, AI-gov federal fields, FIPS 199 + OMB + SCR models, CONMON MCP tools, OSCAL_SCHEMA_VERSION constant, RBAC primitives, evidence_store env vars. MCP tool contract section + env-var public-contract section added. Pre-v1.0 binding semantics in force.** |
