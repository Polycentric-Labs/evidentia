# API stability commitments — DRAFT

> **Status**: DRAFT — subject to revision until v1.0 cycle-open.
> Authored during v0.9.3 P5 per the v1.0-transition.md Candidate B
> framing. This document will become normative at v1.0.0.
>
> **Scope**: defines which surfaces carry semantic-versioning
> guarantees once v1.0 ships, and which surfaces remain free to
> change without a major-version bump.
>
> **Canonical location**: `docs/api-stability.md`
> **Cross-references**: [v1.0-transition.md](v1.0-transition.md),
> [enterprise-grade.md](enterprise-grade.md),
> [release-checklist.md](release-checklist.md)

---

## Versioning semantics (post-v1.0)

Evidentia follows [Semantic Versioning 2.0.0](https://semver.org/)
with the following interpretation:

| Bump | Meaning | Example |
|------|---------|---------|
| **Major** (X.0.0) | Breaking change to a frozen surface | Remove a Pydantic field, rename a CLI flag |
| **Minor** (1.X.0) | New functionality, additive-only changes to frozen surfaces | New EventAction, new CLI command, new optional model field |
| **Patch** (1.0.X) | Bug fixes, security patches, doc updates, catalog content refreshes | CVE fix, threshold default adjustment, typo |

**Pre-v1.0 (current)**: minor bumps may contain breaking changes
to any surface. The v0.9.x line is the "stabilization window"
where we identify and document the public contract without yet
committing to it.

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

Frozen models (37 classes across 15 modules):

| Module | Key models |
|--------|-----------|
| `common.py` | `FrameworkMetadata` |
| `control.py` | `Control`, `ControlFamily` |
| `evidence.py` | `EvidenceRecord`, `EvidenceStatus` |
| `gap.py` | `GapFinding`, `GapSeverity` |
| `control_gap.py` | `ControlGap` |
| `vendor.py` | `VendorProfile`, `VendorRiskTier` |
| `vendor_finding.py` | `VendorFinding` |
| `vendor_manifest.py` | `VendorManifest` |
| `assessment.py` | `Assessment`, `AssessmentStatus` |
| `claim.py` | `TraceClaim`, `ReasoningTrace` |
| `oscal_profile.py` | `OSCALProfile` |
| `crosswalk.py` | `CrosswalkMapping` |
| `catalog.py` | `CatalogEntry` |
| `tprm.py` | `TPRMAssessment`, `TPRMFinding` |
| `governance.py` | `AISystem`, `AIRiskClassification`, `GovernanceRecord` |

**Serialization guarantee**: JSON-serialized output of any frozen
model at version N must be deserializable by version N+1 within
the same major. Field ordering in JSON output is not guaranteed.

### 2. EventAction enum

**Package**: `evidentia_core.audit.events`

The `EventAction` enum is an append-only contract. Existing
values are never removed or renamed post-v1.0. New values may
be added in any minor release.

Current namespaces (50+ values):

| Prefix | Domain | Example values |
|--------|--------|----------------|
| `COLLECT_*` | Evidence collection | `COLLECT_STARTED`, `COLLECT_COMPLETED` |
| `AUTH_*` | Authentication | `AUTH_SUCCESS`, `AUTH_FAILURE` |
| `CONFIG_*` | Configuration | `CONFIG_LOADED`, `CONFIG_VALIDATED` |
| `SIGN_*` | Cryptographic signing | `SIGN_EVIDENCE`, `SIGN_MANIFEST` |
| `VERIFY_*` | Verification | `VERIFY_EVIDENCE`, `VERIFY_MANIFEST` |
| `MANIFEST_*` | Manifest operations | `MANIFEST_CREATED`, `MANIFEST_ROTATED` |
| `AI_*` | AI/LLM operations | `AI_RISK_GENERATED`, `AI_EVAL_FAITHFULNESS_CHECKED` |
| `MCP_*` | MCP server operations | `AI_MCP_TOOL_AUTHORIZED`, `AI_MCP_TOOL_DENIED` |
| `POAM_*` | POA&M lifecycle | `POAM_CREATED`, `POAM_STATE_TRANSITION` |
| `CONMON_*` | Continuous monitoring | `CONMON_DAEMON_STARTED`, `CONMON_ALERT_DISPATCHED` |
| `RETENTION_*` | Data retention | `RETENTION_POLICY_APPLIED` |

Operators building alerting / SIEM integrations on top of the
audit log can depend on these values being stable.

### 3. CLI flag names and semantics

**Package**: `evidentia` (the CLI entry point)

Top-level command groups (14+):

```
evidentia gap          evidentia catalog      evidentia risk
evidentia explain      evidentia integrations evidentia collect
evidentia oscal        evidentia tprm         evidentia model-risk
evidentia governance   evidentia retention    evidentia poam
evidentia conmon       evidentia ai-gov       evidentia eval
evidentia mcp          evidentia serve
```

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
from evidentia_core.gap_analyzer import GapAnalyzer
from evidentia_core.models import ControlGap, GapFinding, ...
from evidentia_core.audit.events import EventAction
from evidentia_core.catalogs.registry import FRAMEWORK_METADATA
from evidentia_core.conmon import derive_status, BUNDLED_CADENCES
from evidentia_core.poam import POAMState, Milestone
from evidentia_core.plugins import AuthProvider, StorageBackend, ...

from evidentia_ai.risk_statements import RiskStatementGenerator
from evidentia_ai.eval import DFAHarness, faithfulness_score
from evidentia_ai.governance import AIRiskClassifier, AISystemInventory

from evidentia_collectors.vendor_risk import (
    BitSightCollector, SecurityScorecardCollector,
    RiskReconCollector, UpGuardCollector,
)

from evidentia_integrations.alerting import SmtpChannel, WebhookChannel

from evidentia_api.app import create_app
from evidentia_mcp.server import create_mcp_server
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

## Revision history

| Version | Date | Change |
|---------|------|--------|
| DRAFT | 2026-05-16 | Initial authoring during v0.9.3 P5 |
