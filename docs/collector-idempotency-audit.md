# Collector idempotency audit (v0.10.5 Phase 10)

> **Status**: NORMATIVE — establishes the per-collector idempotency
> contract carried into the v1.0 API freeze.
> **Date**: 2026-05-25 (drafted during v0.10.5 Phase 10).
> **Trigger**: principal-engineer architecture audit flagged
> collector idempotency as a load-bearing blind-spot post-v1.0.
> **Canonical location**: `docs/collector-idempotency-audit.md`
> **Cross-references**:
> [api-stability.md](api-stability.md),
> [threat-model.md](threat-model.md) §"Stuck-cursor guards",
> [v0.10.5-plan.md](releases/plans/v0.10.5-plan.md) Phase 10.

---

## 1. Purpose

Idempotency in Evidentia's evidence collectors means: **running the
same collector twice against an unchanged source must produce the
same set of finding identities, distinguishable from each other only
by per-run timestamps (`collected_at`, `first_observed` /
`last_observed`) and the per-run ULID (`collection_context.run_id`).**

This audit records the per-collector cursor-pagination behaviour
plus the finding-identity contract as of v0.10.5, locks in the
deterministic-natural-key guarantee before v1.0, and adds a CI
regression test that asserts the contract.

## 2. The principal-engineer audit and what was actually found

The principal-engineer architecture audit (inference-based; the
analyst hadn't read the code) flagged three suspected issues:

1. *Cursor logic uses naive `updated_at` timestamps at second
   granularity → re-runs within the same second drop or duplicate
   events.*
2. *No deterministic natural keys (e.g. `uuid5(NAMESPACE,
   f"{source}:{event_id}")`) for findings → duplicate inserts on
   retry.*
3. *No idempotency CI test → regressions go undetected.*

A line-by-line read against the actual collectors gives the
following verdict:

| Audit point | Verdict | Evidence |
|---|---|---|
| #1 — second-granularity timestamp cursors | **WRONG** | No collector uses `updated_at >= cursor` style incremental collection. Every `collect()` is a **full enumeration** of the source-system surface (Config rules, repo settings, vendor inventory, etc.). Pagination uses opaque continuation tokens (Vanta / Drata / BitSight / SecurityScorecard), `?page=N&per_page=100` (GitHub / Dependabot), or unconditional LIMIT enumeration (SQL collectors, Snowflake, Databricks). Timestamps never participate in the cursor. |
| #2 — no deterministic natural keys | **PARTIALLY CORRECT** | Every collector DOES emit a deterministic `source_finding_id` (e.g. `f"{rule_name}:{resource_id}"`, `f"{slug}:{branch}:{rule}"`, `str(alert.number)`, `f"user-inventory:{source_system_id}"`). What was **missing**: the `SecurityFinding.id` field — the canonical record identifier — defaulted to `uuid4()` regardless. So the same logical finding got a different `id` on every run, even though `source_finding_id` was stable. v0.10.5 Phase 10 closes this gap: when `source_system + source_finding_id` are present at construction time, `id` now derives deterministically from them via `uuid5`. |
| #3 — no idempotency CI test | **CORRECT** | No existing test ran `collect()` twice and asserted zero new-id delta. v0.10.5 Phase 10 adds `tests/unit/test_collectors/test_idempotency.py`. |
| audit's implied #4 — INSERT ... ON CONFLICT for stores | **WRONG ASSUMPTION** | There is no DB-backed findings store. Findings are streamed: collector → OSCAL Assessment Results / SARIF / OCSF / CSV emit. The "row count delta" the audit referred to has no analogue here. The equivalent guarantee — same logical finding produces same identity — is what the deterministic-id change establishes. |

**Net verdict**: the audit was partially correct in spirit but
wrong on most specifics. The real gap was finding identity, not
cursor logic or store upserts. Phase 10 closes that gap directly.

## 3. Per-collector findings

### Pagination model classes

Three pagination patterns are in play across the collectors:

- **Full enumeration** (no pagination needed). The source returns
  the full surface in one response. Examples: `AwsCollector`'s
  AWS Config / Security Hub (paginator drains everything),
  `OktaCollector`'s `/api/v1/policies`, `GitHubCollector`'s
  `/repos/{owner}/{repo}` (single object), all SQL collectors
  (one query per check, full result set).
- **Cursor-token pagination** (`?cursor=<opaque>` /
  `pageInfo.endCursor`). Used by Vanta + Drata + BitSight +
  SecurityScorecard. Each carries a **stuck-cursor guard** (per
  `docs/threat-model.md` §"Stuck-cursor guards") that breaks the
  loop if the API returns the same `endCursor` twice in a row —
  defends against upstream-bug-driven infinite loops.
- **Page-number pagination** (`?page=N&per_page=K`). Used by
  GitHub + Dependabot. Both carry a 100-page safety cap (10,000
  alerts) before aborting the run with `is_complete=False`.

None of these patterns persists a cursor across runs. Every
`collect()` re-paginates from the beginning. This is intentional:
Evidentia targets **point-in-time evidence** for an OSCAL Assessment
Results document, not a streaming change-feed. Per-run completeness
is attested via `CollectionManifest.is_complete` and
`coverage_counts`, not via cursor durability.

### Per-collector audit table

Every entry below has been verified against the source as of
v0.10.5. The `Cursor` column documents the within-run pagination
model. The `Natural key` column documents the `source_finding_id`
construction. The `Verdict` column summarizes the idempotency
posture **after v0.10.5 Phase 10** lands.

| Collector | Cursor model | Natural key (`source_finding_id`) | Pre-Phase-10 verdict | Post-Phase-10 verdict |
|---|---|---|---|---|
| `AwsCollector` (Config) | Full enumeration via boto3 paginator. No cross-run state. | `f"{rule_name}:{resource_id}"` per non-compliant evaluation. | GAP — `id` random | PASS — `id` derived from (`aws-config`, `rule_name:resource_id`) |
| `AwsCollector` (Security Hub) | Full enumeration via boto3 paginator + `max_findings` cap. | Native AWS finding ARN (`raw["Id"]`). | GAP — `id` random | PASS — `id` derived from (`aws-security-hub`, `<ARN>`) |
| `AccessAnalyzerCollector` | Full enumeration via boto3 paginator. | Native Access Analyzer `finding_id`. | GAP — `id` random | PASS — `id` derived from (`aws-access-analyzer`, `<finding_id>`) |
| `GitHubCollector` (visibility / branch protection / CODEOWNERS) | Single-shot REST calls (no pagination). | `f"{slug}:visibility"`, `f"{slug}:{branch}:{rule}"`, `f"{slug}:codeowners"` — all deterministic from repo coordinates. | GAP — `id` random | PASS — `id` derived from (`github`, `<above>`) |
| `DependabotCollector` | Page-number pagination (`?page=N`) with 100-page safety cap. | Native `alert.number` (string). | GAP — `id` random | PASS — `id` derived from (`github-dependabot`, `<alert.number>`) |
| `OktaCollector` | Link-header pagination (`rel="next"`) on `/api/v1/users`; single-shot elsewhere; capped at `max_users=10_000`. | `f"user-inventory:{source_system_id}"`, `f"inactive-accounts:{source_system_id}"`, `f"admin-accounts:{source_system_id}"`, `f"mfa-enrollment:{source_system_id}"`, etc. — all deterministic from the org URL. | GAP — `id` random | PASS — `id` derived from (`okta`, `<above>`) |
| `GoogleWorkspaceCollector` (v0.13 batch 7) | `nextPageToken` pagination on both the Directory API (`/admin/directory/v1/users`) and the Reports API (login activity); capped at `max_users=10_000` / `max_login_events=10_000`. | `f"user-inventory:{source_system_id}"`, `f"inactive-accounts:{source_system_id}"`, `f"admin-accounts:{source_system_id}"`, `f"admin-2sv:{source_system_id}"`, `f"2sv-enrollment:{source_system_id}"`, `f"login-activity:{source_system_id}"`, all deterministic from the customer id. | N/A, added after Phase 10; ships with deterministic ids from its first release | PASS: `id` derived from (`google-workspace`, `<above>`) |
| `VantaCollector` | Cursor-token pagination + stuck-cursor guard + `max_vendors` cap. | `f"vendor-inventory:{vendor_id}"`, `f"vendor-high-risk:{vendor_id}"`. | GAP — `id` random | PASS — `id` derived from (`vanta-vendors`, `<above>`) |
| `DrataCollector` | Cursor-token pagination + stuck-cursor guard + `max_vendors` cap. | `f"vendor-inventory:{vendor_id}"`, `f"vendor-high-risk:{vendor_id}"`. | GAP — `id` random | PASS — `id` derived from (`drata-vendors`, `<above>`) |
| `BitSightCollector` | Cursor-token pagination + stuck-cursor guard + `max_companies` cap. Refuses scheme-downgrade `next` URLs (per `docs/threat-model.md`). | `f"company-inventory:{guid}"`, `f"company-low-rating:{guid}"`. | GAP — `id` random | PASS — `id` derived from (`bitsight-vendors`, `<above>`) |
| `SecurityScorecardCollector` | Cursor-token pagination + stuck-cursor guard + `max_companies` cap. | `f"company-inventory:{domain}"`, `f"company-low-score:{domain}"`. | GAP — `id` random | PASS — `id` derived from (`securityscorecard-vendors`, `<above>`) |
| `DatabricksCollector` | Full enumeration of the listed resource collections (tokens, clusters, service principals, secret scopes). | `f"databricks-pat:{tok_id}"`, `f"databricks-cluster:{cluster_id}"`, `f"databricks-sp:{sp_id}"`, `f"databricks-secret-scope:{name}"`, etc. | GAP — `id` random | PASS — `id` derived from (`databricks`, `<above>`) |
| `SnowflakeCollector` | Full enumeration via SQL queries against `SNOWFLAKE.ACCOUNT_USAGE.*` views. | `f"user-inventory:{user_name}"`, `f"mfa-disabled:{user_name}"`, etc. — all deterministic from the warehouse coordinates. | GAP — `id` random | PASS — `id` derived from (`snowflake`, `<above>`) |
| `PostgresCollector` / `MySQLCollector` / `MSSQLCollector` / `OracleCollector` / `SQLiteCollector` | Full enumeration via JDBC-style queries against catalog views. | `f"user-inventory:{db}"`, `f"audit-log:{db}"`, `f"crypto-config:{db}"`, `f"connection-limits:{db}"`, etc. — all deterministic from the connected DB name. | GAP — `id` random | PASS — `id` derived from (`postgres` / `mysql` / `mssql` / `oracle` / `sqlite`, `<above>`) |
| `collect_ocsf_file` / `collect_ocsf_url` (OCSF ingest) | Single-shot file read or single-shot HTTPS GET with body cap. | Inherits the source OCSF doc's `finding_info.uid` (set as `SecurityFinding.id` explicitly in the native-mapping path). | PASS — explicit `id` already set from `finding_info.uid` | PASS — unchanged. Round-trip via `unmapped["evidentia"]` continues to honor the embedded `id` field. |

### Summary

- **13 collectors / 1 ingest module audited.**
- **Cursor logic — PASS for all 13.** No collector relied on
  timestamp-cursors. Every cursor pattern is either token-based
  (with stuck-cursor guards) or page-number-based (with safety
  caps), and no cursor is persisted across runs.
- **Source-finding-id natural keys — PASS for all 13.** Every
  collector already produced a deterministic `source_finding_id`
  from natural source coordinates.
- **`SecurityFinding.id` deterministic-derivation — GAP closed at
  v0.10.5 Phase 10 for all 13.** Previously `uuid4()`-random;
  now `uuid5(NAMESPACE_EVIDENTIA_FINDING, f"{source_system}:{source_finding_id}")`
  when both fields are present at construction.
- **OCSF round-trip fidelity preserved.** The OCSF mapper
  serializes `SecurityFinding.id` into
  `unmapped["evidentia"]["id"]`. Deserialization via
  `SecurityFinding.model_validate(unmapped["evidentia"])` honors
  the explicit `id` (the deterministic-derivation validator runs
  only when no `id` is supplied).

## 4. The deterministic-id derivation

Added v0.10.5 Phase 10 in `evidentia_core.models.common`:

```python
# Project-scoped DNS namespace for deterministic SecurityFinding IDs.
# Generated via uuid.uuid5(uuid.NAMESPACE_DNS, "finding.evidentia.dev").
# Fixed forever; rotating would re-key every finding ID in existence
# and break every cached OSCAL Assessment Results document.
NAMESPACE_EVIDENTIA_FINDING = UUID("c2c9c8c8-...")  # see common.py


def deterministic_finding_id(
    source_system: str,
    source_finding_id: str,
) -> str:
    """Return a deterministic UUID5 derived from (source_system, source_finding_id)."""
    payload = f"{source_system}\x00{source_finding_id}"
    return str(uuid5(NAMESPACE_EVIDENTIA_FINDING, payload))
```

A `@model_validator(mode="before")` on `SecurityFinding` runs
the derivation **only when no explicit `id` was provided AND
both `source_system` and `source_finding_id` are present**. The
existing v0.4-era code path that constructs findings without a
source-finding-id (legacy test fixtures, the synthetic-legacy
context placeholder) keeps the `uuid4()` random default.

### Trust boundary preservation

The OCSF Detection Finding ingestion path (third-party input,
default `trust_unmapped=False`) was at risk of identity-forgery
via a malicious `info.uid`. The validator preserves this trust
boundary unchanged: when the ingest path supplies an explicit
`id=info.uid`, the validator does not override it. The existing
`test_from_ocsf_detection_default_does_not_trust_unmapped` test
in `tests/unit/test_ocsf/test_finding_mapping.py` still passes
because that test asserts `finding.id != "ATTACKER-FORGED-ID"`
based on the native-OCSF code path's explicit `id=info.uid`
assignment (a third-party-controlled value), not on default
randomness.

Operators ingesting third-party OCSF MUST NOT treat finding IDs
as authentication or authorization tokens — IDs are dataset-
internal join keys, not security tokens. This was already
documented in `docs/ocsf-mapping.md` and `docs/api-stability.md`.

### Backwards-compatibility

- Pre-v0.10.5 OSCAL AR documents continue to load — every
  `SecurityFinding` in those JSON files carries an explicit
  `id` field set at the time the AR was emitted, and the
  validator's "explicit id wins" branch preserves it.
- Pre-v0.10.5 OCSF Compliance Finding round-trips continue to
  load — the `unmapped["evidentia"]` block carries the explicit
  `id` from the original `SecurityFinding`.
- Pre-v0.10.5 collector test fixtures that constructed findings
  without `id=` and without `source_finding_id=` continue to
  produce random `uuid4()` IDs (no behavior change). This affects
  exactly two construction sites — the synthetic-legacy-context
  helper in `finding.py` and the migration helper in
  `migrations/v0_6_legacy.py`. Neither is on the collector path.

### What is NOT in scope for Phase 10

- **Incremental / change-feed collection**. Adding `since=<run_id>`
  collection mode is a separate v1.1 capability per the v0.10.5
  plan §4 deferred-items.
- **Finding upsert store**. There is no DB-backed findings table
  in evidentia-core. Adding one would be a v1.1 capability and
  is intentionally not undertaken pre-v1.0 (the OSCAL Assessment
  Results document remains the canonical findings sink).
- **OCSF Detection Finding identity remapping**. Third-party
  Detection Findings carry their own `info.uid` per the producer's
  conventions (Prowler, AWS Security Hub). Phase 10 does not
  override these — the explicit-id branch wins.

## 5. The regression test

`tests/unit/test_collectors/test_idempotency.py` runs each
mockable collector twice against a deterministic fixture and
asserts:

1. The set of `(source_system, source_finding_id)` pairs is
   identical across runs (sanity check on the natural keys).
2. The set of `SecurityFinding.id` values is identical across
   runs (the actual idempotency guarantee).
3. The cardinality is preserved (zero net new findings on the
   second run).

Per-collector test methods cover at minimum: AWS Config / AWS
Security Hub / Access Analyzer / GitHub / Dependabot / Okta /
Vanta / Drata / BitSight / SecurityScorecard / Databricks /
Snowflake / SQLite / Postgres-mock / MySQL-mock / MSSQL-mock /
Oracle-mock / OCSF file ingest.

The model-layer derivation is verified by an additional unit
test in `tests/unit/test_models/test_finding_idempotency.py`.

## 6. Open questions for v1.0+

The following remain open after Phase 10 and are tracked in
`docs/v0.10.5-plan.md` §4 and the v1.1 deferred list:

- **Incremental change-feed collection** (v1.1). Would require
  `since=<run_id>` collector kwargs and source-side cursor
  storage (the source system has to support it — most do, but
  GitHub branch protection / repo metadata do not, so this would
  be a per-collector capability flag).
- **Federation-wide cross-run finding diff** (post-v1.0). Even
  with deterministic IDs, computing "new since last run" and
  "resolved since last run" requires a state-store. The OSCAL
  AR document is the natural state-store; a `gap_analyze diff`
  verb is sketched in the v0.11 federal-compliance theme.
- **Hash-based natural keys for collectors without stable source
  IDs** (none in current v0.10.5 surface, but worth tracking).
  If a future collector emits findings whose source has no stable
  identifier, the fallback would be `sha256(canonical(finding))`
  rather than `uuid4()`. Phase 10 does not introduce this; the
  current 13 collectors all carry stable source IDs.

---

> **Audit completed**: 2026-05-25.
> **Maintainer**: review this document at every collector addition
> (new entries should arrive PASS / PASS / PASS by following the
> existing pattern). Update the per-collector table whenever a
> new collector ships and its `source_finding_id` shape becomes
> part of the public contract.
