# Evidentia v0.7.0 — capability matrix

> Step-4 deliverable from the v0.7.0 comprehensive review (2026-04-25).
> Functional + code-review + adversarial smoke testing of every public
> capability surface, ordered by enterprise risk. Findings queued
> through Step 4 and either fixed in-line (CRITICAL) or deferred to
> v0.7.1 (HIGH-priority but design-decision-laden).
>
> Cross-link to: [enterprise-grade.md](enterprise-grade.md) (the quality
> bar), [positioning-and-value.md](positioning-and-value.md) (where this
> sits in the market), [testing-playbook.md](testing-playbook.md) (the
> operational test loop).

---

## Re-validation snapshot — 2026-05-02 (v0.7.7 ship — pre-tag)

v0.7.7 adds the **first substantive new collector surface since v0.5.0**:
five SQL-family adapters (Postgres / MySQL / SQLite / MSSQL / Oracle),
one new Okta evidence collector, and one ServiceNow output
integration. Per the v4 skill rule "patch with new collector surface
recommended to re-walk", this snapshot does a focused re-walk of the
**new surfaces** + a regression check against the **existing 10 tiers**.

### Existing tiers — regression check (no functional change)

| Tier | v0.7.7 status | Evidence |
|---|---|---|
| 1 — AI features | ✅ unchanged | No `evidentia-ai` files touched in v0.7.7 diff |
| 2 — OSCAL signing + verify | ✅ unchanged | No `oscal/signing` or `sigstore` files touched |
| 3 — Air-gap enforcement | ✅ unchanged | `network_guard.py` untouched |
| 4 — Secret scrubber | ✅ unchanged | `audit/logger._scrub` untouched; v0.7.7 adds new env-var-keyed secret paths but each adapter rejects URI-embedded passwords at constructor |
| 5 — Collectors | ✅ extended (see new rows below) | 7 new public surfaces; existing AWS + GitHub + Jira unchanged |
| 6 — OSCAL exporter + output formats | ✅ unchanged | No format/exporter files touched |
| 7 — CLI commands | ✅ extended | `collect sql` adapter dispatch + `collect okta` + `integrations servicenow` subcommands added; existing CLI unchanged |
| 8 — REST API | ✅ extended | 6 new POST endpoints + status-endpoint extension; existing routes unchanged |
| 9 — Web UI | ✅ unchanged | No `evidentia-ui` files touched |
| 10 — Configuration precedence | ✅ unchanged | `EVIDENTIA_*_PASSWORD` + `EVIDENTIA_SQLITE_SAFE_ROOT` follow existing env-var precedence; CLI flags + payloads never accept secrets |

### New surfaces — full v0.7.7 capability walk

Each row covers: functional (tests pass) · adversarial (bad input /
missing dep / network failure / expired credential / malformed config /
DoS bound) · result.

| New surface | Functional | Adversarial | Result |
|---|---|---|---|
| **Postgres adapter** (`sql.postgres`) | ✅ 16 unit + 3 Docker integration tests | ✅ password-in-URI rejected at constructor; psycopg ImportError → typed `PostgresCollectorError`; connection-error wrapper trims to driver class name (F-002 fix); read-only probe via `default_transaction_read_only` + CREATE TEMP rollback | **PASS** |
| **MySQL/MariaDB adapter** (`sql.mysql`) | ✅ 13 unit tests | ✅ same pattern as Postgres; PyMySQL ImportError → typed error; `@@global.read_only` + CREATE TEMPORARY rollback probe | **PASS** |
| **SQLite adapter** (`sql.sqlite`) | ✅ 16 unit tests using `:memory:` | ✅ `safe_root=` containment via `validate_within` (CWE-22 mitigation); `os.access(W_OK)` write-priv probe; `file:?mode=ro` read-only URI; F-003 URI quoting fix; F-004 TOCTOU accepted | **PASS** |
| **MS SQL Server adapter** (`sql.mssql`) | ✅ 20 unit tests | ✅ `Encrypt=yes;TrustServerCertificate=no` connection defaults; pyodbc ImportError → typed error; `IS_SRVROLEMEMBER('sysadmin')` + `IS_ROLEMEMBER('db_owner')` write-priv probe | **PASS** |
| **Oracle adapter** (`sql.oracle`) | ✅ 23 unit tests | ✅ oracledb thin-mode (no Oracle Client install required); password-in-URI rejected; session_roles + session_privs write-priv probe | **PASS** |
| **Okta collector** (`okta`) | ✅ 20 unit tests via `httpx.MockTransport` | ✅ HTTPS-only constructor; explicit 30s timeout; `max_users` cap default 10000 (DoS bound); paginates via Link header rel="next"; user-agent identifies collector for Okta system-log correlation | **PASS** |
| **ServiceNow integration** (`evidentia_integrations.servicenow`) | ✅ 35 unit tests (mapper + client + sync) | ✅ HTTPS-only constructor; `password` field excluded from `model_dump`; explicit 20s timeout; `correlation_id` deterministic for idempotency on re-push (no duplicate records) | **PASS** |

### v0.7.7 findings re-summary

| ID | Bucket | Resolution |
|---|---|---|
| F-001 | HIGH (CWE-22) | **fixed in Step 5.A inline** — REST + CLI honor `EVIDENTIA_SQLITE_SAFE_ROOT`; 3 new tests |
| F-002 | MEDIUM (CWE-209) | **fixed in Step 5.A inline** — 5 SQL adapters connection-error wrappers trimmed to driver class name |
| F-003 | MEDIUM (CWE-20) | **fixed in Step 5.A inline** — SQLite URI now uses `urllib.parse.quote` |
| F-004 | LOW (CWE-367 TOCTOU) | accepted (read-only URI + filesystem ACLs limit blast radius) |
| F-005 | LOW (sample-bound MFA enrollment) | accepted (documented as `EVIDENTIA-OKTA-RATE-LIMIT-PARTIAL` BLIND_SPOT) |

### DAST sub-step (G11)

DAST tools (Schemathesis + Playwright) are not installed in this dev
environment. **Documented skip with rationale**: v0.7.7 adds 6 new
REST endpoints, all of which are exhaustively tested via FastAPI's
`TestClient` in `tests/integration/test_api/test_collectors.py` +
unit-test cursor mocks for the DB call paths. No new UI surface
(unchanged from v0.7.6). DAST install + first-run will land in
v0.7.8 P0 alongside the routine CI integration.

### Step 4 verification gate

| Gate | Result |
|---|---|
| Surface-coverage % ≥ 90% | ✅ 17 / 17 surface rows have ✅/⚠/❌ verdicts (100%) |
| Adversarial probe coverage ≥ 6 of 7 vectors per new surface | ✅ all 7 new surfaces cleared 6+ vectors |
| DAST run completed (or explicit skip) | ⚠ explicit skip with rationale |

---

## Re-validation snapshot — 2026-04-26 (v0.7.1 ship)

This v0.7.0 snapshot below remains representative for v0.7.1 because
**v0.7.1 added no new public capability surfaces** — the AI features
hardening (P0) was an internal refactor of `risk_statements/` and
`explain/` (typed exception hierarchy, `@with_retry`,
`GenerationContext` metadata, ECS structured logging,
`run_id`-correlated audit events). The CLI surface, REST surface,
output formats, and configuration-precedence chain are unchanged.

**Per-row updates for v0.7.1**:

- **Risk-tier 1 — AI features**: `risk_statements/generator.py` and
  `explain/generator.py` rows now PASS (HIGH-bucket H1-H4 all closed).
  All four AI subsystems (`evidentia_ai.client`, `risk_statements/`,
  `explain/`, `explain/cache.py`) now ship with the v0.7.0
  collector-pattern enterprise grade. Detail: see
  [`docs/v0.7.1-plan.md`](v0.7.1-plan.md) §"P0 — AI features
  enterprise-grade hardening".
- **Surface tier 7 — CLI commands**: `evidentia version` would now
  report "Evidentia v0.7.1" (the table below shows the v0.7.0 review
  output as a historical record); `evidentia risk generate` row
  upgrades from "⚠ no test coverage (deferred to v0.7.1)" to "✅
  comprehensive test coverage in `tests/unit/test_ai/test_risk_statements.py`
  (772 lines covering sync + async + batch + retry + air-gap + GenerationContext)".
- **Surface tier 8 — REST API**: `GET /api/health` would now report
  `{"status": "ok", "version": "0.7.1"}`; route count and surface
  unchanged.
- **All other tiers**: unchanged from the v0.7.0 snapshot below.

The next full re-validation pass is scheduled for v0.7.2 ship per the
release-checklist Step 5 + Step 6 acceptance gates and the testing-playbook
operational test loop. The historical v0.7.0 tables below remain the
canonical Step-4 review record per the audit-trail-preservation principle
(don't rewrite the past; layer the present on top).

---

## 1. Risk-first ordering — what was tested, what was found

Surfaces are ordered by **enterprise risk** (higher rows = bugs in
this area would damage the v0.7.0 enterprise-grade story most).

### Risk-tier 1 — AI features (`evidentia-ai`)

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| `evidentia_ai.client` (LiteLLM + Instructor wrapper) | ✅ guarded completion paths verified | ✅ strong: air-gap enforcement via `check_llm_model()`, both sync + async wrapped, lru_cache on instances, mypy-strict cast | ✅ correctly raises `OfflineViolationError` for cloud models in air-gap mode | **PASS** |
| `risk_statements/generator.py` | ⚠ no functional smoke (no API key in test env) | ⚠ **2 BLOCKER B3 violations** (lines 173, 227 — bare `except Exception`); no `@with_retry`; no `CollectionContext`; uses stdlib `logging` not v0.7.0 ECS structured logger; no metadata enrichment from `evidentia_core.audit` | ⚠ **ZERO unit tests** (only `test_explain.py` exists) | **FAIL** — deferred to v0.7.1 |
| `explain/generator.py` | ✅ caching layer tested in `test_explain.py` | ⚠ same enterprise-grade gaps as risk_statements (no @with_retry, no CollectionContext, no ECS structured logs) | ⚠ no adversarial tests for cache-corruption or LLM-validation-failure | **PARTIAL** — defer hardening to v0.7.1 |
| `explain/cache.py` (disk cache) | ✅ tested | ✅ corrupt cache → returns None (graceful); env var override; deterministic cache key | ✅ corrupt cache files handled | **PASS** |

**Why deferred to v0.7.1**: hardening AI features properly requires
4 design decisions (CollectionContext-vs-GenerationContext fit;
@with_retry-vs-Instructor-retry stacking; new EventAction enum
entries; comprehensive `test_risk_statements.py` ~200-300 lines of
careful LLM mocking). Rushing these into v0.7.0 would lock in
suboptimal patterns.

### Risk-tier 2 — OSCAL signing + verify pipeline

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| `oscal/signing.py` (GPG) | ✅ subprocess wrapper validated; `gpg_available()` precondition | ✅ typed exception hierarchy (GPGError → 4 subclasses); --batch --yes for CI; status-fd parsing; distinguishes mismatch (returns `valid=False`) vs infrastructure error (raises) | ✅ existing tests cover sign+verify roundtrip | **PASS** (minor: uses stdlib `logging` not ECS structured — consistency gap with sigstore.py) |
| `oscal/sigstore.py` (Sigstore/Rekor) | ✅ keyless signing via Fulcio + Rekor; air-gap refusal | ✅ typed exception hierarchy; ECS structured logging via `evidentia_core.audit`; `_ensure_online()` air-gap guard; best-effort metadata extraction | ✅ existing tests via `test_sigstore.py` | **PASS** |
| `oscal/verify.py` (orchestrator) | ✅ digest + GPG + Sigstore checks | ✅ tampered/forged/replayed semantics documented; deferred imports; v0.7.0+ extension to Sigstore added in `851f45f` | ✅ 8 new tests added in `851f45f` covering Sigstore detection, custom bundle path, UnsafeNoOp warnings, require_signature satisfied by either GPG or Sigstore | **PASS (after fix)** |
| `evidentia gap analyze --sign-with-sigstore` | ✅ flag exists + wired to `export_report(sign_with_sigstore=...)` after `851f45f` | ✅ companion flags `--sigstore-bundle`, `--sigstore-identity-token` (env: `SIGSTORE_ID_TOKEN`); guard for non-oscal-ar formats | ✅ smoke-tested via `--help` | **PASS (after fix)** |
| `evidentia oscal verify --check-sigstore` | ✅ flag exists after `851f45f` | ✅ companion flags `--sigstore-bundle`, `--expected-identity`, `--expected-issuer`; rich + JSON output updated to surface Sigstore status | ✅ smoke-tested via `--help` | **PASS (after fix)** |
| `.github/actions/gap-analysis/action.yml` Sigstore path | ✅ bash `--sigstore-bundle` flag matches CLI after `851f45f` (was `--bundle`, would have failed at runtime) | ✅ inline doc clear | ⚠ no automated end-to-end smoke test for the action itself (deferred to v0.7.1) | **PASS (after fix)** |

**3 CRITICAL findings caught + fixed in `851f45f`**: Sigstore CLI gap,
Sigstore verify gap, action.yml broken flag reference. The composite
GitHub Action's `emit-sigstore-bundle: true` path is now functional
end-to-end.

### Risk-tier 3 — Air-gap enforcement (`network_guard`)

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| `network_guard.set_offline()` + `is_offline()` | ✅ module-level flag, single-process, well-documented | ✅ strong design; `LOCAL_LLM_PREFIXES` allowlist + `is_loopback_or_private()` for `api_base`; `offline_mode()` context manager for tests | ✅ existing tests cover flag toggling | **PASS** |
| `evidentia_ai.client._guarded_completion` | ✅ calls `check_llm_model()` before any LLM IO | ✅ both sync + async wrapped; correctly resolves `api_base` from kwargs | ✅ raises `OfflineViolationError` for cloud models | **PASS** |
| `oscal/sigstore._ensure_online()` | ✅ refuses Sigstore in air-gap mode | ✅ raises `SigstoreAirGapError` with clear remediation message ("use GPG signing") | ✅ test coverage in `test_sigstore.py` | **PASS** |
| `evidentia doctor --check-air-gap` | ✅ enumerates per-subsystem posture | ✅ checks LLM client + catalog loader + AI telemetry + gap store + Web UI | ✅ table-formatted output | **PASS** |

### Risk-tier 4 — Secret scrubber (`audit/logger._scrub`)

| Sub-surface | Functional | Code review | Adversarial | Result |
|---|---|---|---|---|
| Regex patterns | ✅ scrubs `AKIA*`/`ASIA*` (AWS), `ghp_/gho_/ghu_/ghs_/ghr_` (GitHub), `password=`/`token=`/`api_key=`/`secret=`/`credential=`, JWTs (3 base64url segments) | ✅ narrow patterns minimize false positives; "false positives are annoying but safe; false negatives are a compliance liability" — correct posture | ⚠ **Misses**: Slack tokens (`xoxb-`, `xoxp-`), Stripe keys (`sk_live_`, `sk_test_`), Google API keys (`AIza`), Atlassian tokens, npm tokens | **PASS with v0.7.1 expansion candidate** |
| Application surface | ✅ called on every `message` field before emission | ✅ documented as safety net; collectors are responsible for keeping secrets out of structured field values | n/a | **PASS** |

### Risk-tier 5 — Collectors

Already verified in Step 3 (commit `7e35b2d` — "harden existing AWS +
GitHub collectors"). The collectors got the v0.7.0 enterprise-grade
treatment that the AI features did not:

| Collector | Typed catches | `@with_retry` | `CollectionContext` | ECS structured logs | `BLIND_SPOTS` list |
|---|---|---|---|---|---|
| AWS Config | ✅ | ✅ | ✅ | ✅ | n/a (Config rules are themselves the disclosure) |
| AWS Security Hub | ✅ | ✅ | ✅ | ✅ | n/a |
| AWS IAM Access Analyzer | ✅ | ✅ | ✅ | ✅ | ✅ 5 entries (kms-grants, s3-acls-vs-block-public-access, service-linked-roles, unsupported-resource-types, finding-latency) |
| GitHub branch protection + CODEOWNERS | ✅ | ✅ | ✅ | ✅ | n/a |
| GitHub Dependabot alerts | ✅ | ✅ | ✅ | ✅ | n/a |

`BLIND_SPOTS` correctly threaded through the new
`gap_report_to_oscal_ar(blind_spots=...)` API into AR back-matter
resources (commit `c26d283`).

---

## 2. Surface-tier smoke tests (functional only)

### Surface tier 6 — OSCAL exporter + output formats

| Format | Smoke test | Result |
|---|---|---|
| `json` | ✅ `gap analyze --format json` against Meridian → 77 controls / 64 gaps / 16.9% coverage / report exported | **PASS** |
| `csv` | (covered by `test_export_all_formats[csv-csv]` in `test_end_to_end.py`) | **PASS** (test) |
| `markdown` | (covered by `test_export_all_formats[markdown-md]`) | **PASS** (test) |
| `oscal-ar` | (covered by `test_export_all_formats[oscal-ar-json]` + 3 trestle conformance tests + 8 verify tests + 3 exporter tests) | **PASS** (test) |
| `github` annotations (gap diff only) | ✅ existing test coverage in test_gap_diff | **PASS** (test) |

### Surface tier 7 — CLI commands

| Command | Smoke result |
|---|---|
| `evidentia version` | ✅ "Evidentia v0.7.0" + Python 3.12.13 |
| `evidentia doctor` | ✅ all packages OK; **82 frameworks registered** (validates README claim end-to-end); 9 frameworks mapped (across 6 crosswalks) |
| `evidentia doctor --check-air-gap` | ✅ per-subsystem posture report (covered above in tier 3) |
| `evidentia catalog list --tier A` | ✅ Tier-A frameworks listed correctly |
| `evidentia catalog show <fw> --control <id>` | covered by tests |
| `evidentia catalog crosswalk` | covered by tests |
| `evidentia catalog import` | covered by tests |
| `evidentia gap analyze` | ✅ end-to-end against Meridian sample (above) |
| `evidentia gap diff` | covered by tests + dogfood workflow `evidentia.yml` |
| `evidentia explain control` | covered by `test_explain.py` |
| `evidentia risk generate` | ⚠ no test coverage (deferred to v0.7.1) |
| `evidentia integrations jira *` | covered by tests (mocked) |
| `evidentia collect aws` | covered by tests (moto-mocked) |
| `evidentia collect github` | covered by tests (responses-mocked) |
| `evidentia oscal verify` | ✅ flag surface validated via `--help` after `851f45f`; 18 unit tests pass |
| `evidentia init` | covered by tests |
| `evidentia serve` | not smoke-tested (would require running browser); covered by `test_serve` integration test |

### Surface tier 8 — REST API

| Endpoint sample | Smoke result |
|---|---|
| `GET /api/health` | ✅ 200 OK, `{"status": "ok", "version": "0.7.0"}` |
| `GET /api/frameworks` | ✅ 200 OK, **82 frameworks returned** (validates the doctor count) |
| 26 routes / 12 router modules total | covered by FastAPI TestClient suite + integration tests |

**Note on README discrepancy**: README claims "18 REST endpoints",
actual count is **26 routes across 12 router modules**. Documentation
fix flagged for Step 5.

### Surface tier 9 — Web UI (8 routes)

Not smoke-tested in this Step 4 pass — would require launching
`evidentia serve` and a browser session. Existing coverage:

- 6 Vitest component tests
- 36 FastAPI TestClient tests for the backing API
- WCAG 2.1 AA via Radix primitives (design-time guarantee, not
  per-page audit)

**Recommendation for Step 5**: add a Playwright E2E smoke test that
launches `evidentia serve` and clicks through the 8 pages
(Dashboard → Gap Analysis → Framework Catalog → Control Explorer →
Risk Statements → Integrations Hub → Settings → Project Init).
Already noted as "Planned for v0.4.2 polish" in ROADMAP.

### Surface tier 10 — Configuration precedence

Not exhaustively tested in this Step 4 pass. Existing coverage:

- `test_config.py` covers the precedence chain (CLI flag > env var >
  yaml > built-in default)
- `evidentia.yaml` loaded via `evidentia_core.config.load_config()`
- precedence resolved per-call via `get_default(cfg, cli_value, key, builtin_default=...)`

**No bugs surfaced** in the smoke tests of `gap analyze` (which
uses `--frameworks` precedence chain).

---

## 3. Bugs caught + fix status

### CRITICAL — fixed in commit `851f45f`

| # | Bug | Fix |
|---|---|---|
| C1 | `evidentia gap analyze` had no `--sign-with-sigstore` flag (CLI users couldn't access the library Sigstore feature) | Added `--sign-with-sigstore`, `--sigstore-bundle`, `--sigstore-identity-token` flags; wired through `export_report` |
| C2 | `verify_ar_file` didn't check Sigstore bundles (CLI verify only detected GPG `.asc`) | Extended verify_ar_file with `check_sigstore`, `sigstore_bundle_path`, `expected_sigstore_identity`, `expected_sigstore_issuer` params; updated VerifyReport with `sigstore_*` fields and `warnings` list; `overall_valid` now requires both signatures (when present) to verify |
| C3 | `.github/actions/gap-analysis/action.yml` referenced `--bundle` (non-existent) instead of `--sigstore-bundle` | Renamed to `--sigstore-bundle` to match new CLI |
| Step-3 fix in `25ccca8` | Inter-package version pins stale at `>=0.6.0,<0.7.0` (9 occurrences across 5 pyproject.toml files) | All bumped to `>=0.7.0,<0.8.0` |
| Step-3 fix in `25ccca8` | LiteLLM dep range `>=1.50,<2.0` allowed compromised 1.82.7/1.82.8 | Tightened to `>=1.83.0,<2.0` |

### HIGH — deferred to v0.7.1

| # | Bug | Why deferred |
|---|---|---|
| H1 | `risk_statements/generator.py` lines 173, 227 — bare `except Exception` (BLOCKER B3 violation per docs/enterprise-grade.md) | Fixing properly requires designing the AI-features hardening pattern (typed exception hierarchy mirroring collector pattern); part of broader v0.7.1 AI hardening |
| H2 | `risk_statements/` module has zero unit tests | New `test_risk_statements.py` needs ~200-300 lines of careful LLM mocking; rushing this produces fragile tests |
| H3 | AI features (risk_statements, explain) lack `@with_retry` from `evidentia_core.audit.retry` | Design decision: stack with Instructor's max_retries or replace? LLM-call retry semantics differ from API-call retry semantics |
| H4 | AI features lack `CollectionContext` metadata on outputs | Design decision: repurpose CollectionContext (poor semantic fit) vs new GenerationContext type (cleaner but new abstraction) |
| H5 | AI features use stdlib `logging` not `evidentia_core.audit.logger` (ECS structured) | Need new EventAction enum entries (`evidentia.risk.generated`, `evidentia.explain.generated`); coordinate with EventAction schema |

### MEDIUM — fix in Step 5 docs polish

| # | Issue | Fix |
|---|---|---|
| M1 | README undercounts REST endpoints ("18", actual 26) | Update README §3.4 |
| M2 | README says "the four workspace sub-packages" — actual is five (incl. evidentia-api) | Update README install section |
| M3 | README CLI list missing `evidentia oscal verify` (added v0.7.0) | Update README CLI table |
| M4 | `oscal/signing.py` uses stdlib `logging` not ECS structured logger (consistency gap with sigstore.py) | ~15-line change; consider for v0.7.1 |
| M5 | Sigstore secret-scrubber misses Slack/Stripe/Google API/Atlassian/npm token patterns | ~20-line addition to `_SECRET_PATTERNS`; consider for v0.7.1 |

### LOW — acknowledge, no fix

| # | Issue | Why no fix |
|---|---|---|
| L1 | Composite action `action.yml` uses version pins (`@v5`, `@v4`, `@v2`) not SHA pins | Acceptable for v0.7.0; documented SHA-pin upgrade path in action README; Dependabot can SHA-pin over time |
| L2 | No automated end-to-end smoke test for the composite action itself | Would require dedicated test workflow + a recipient repo to action against; Step-5 deferred candidate |
| L3 | "82 frameworks bundled" claim verified by both file count + `evidentia doctor` | n/a — README is correct |

---

## 4. Test-suite delta from Step 1 to end of Step 4

| Stage | Tests | Notes |
|---|---|---|
| Pre-review baseline (`efa5678`) | 862 passed, 8 skipped | Before any Step 1-4 work |
| After Step 3 fix (`25ccca8`) | 849 passed, 8 skipped | -16 from `test_rename_shims.py` deletion + +3 trestle conformance tests = -13 net |
| After Step 4 critical fix (`851f45f`) | **857 passed**, 8 skipped | +8 new Sigstore verify tests |

mypy: clean (97 source files, no issues)
ruff lint: clean
ruff format: 2 reformatted files (in commit `6f3051d`)

---

## 5. Step 4 unfinished — deferred / not in scope

These were on the original Step 4 plan but not deeply tested
(functional smoke covered the major flows; full adversarial probing
deferred):

- Surface tier 9 — Web UI 8 pages: would require live browser session;
  Vitest + FastAPI TestClient already cover unit + API layer
- Surface tier 10 — Config precedence chain: existing `test_config.py`
  covers; no smoke bugs surfaced in CLI usage
- Collectors deep-dive — already covered by Step 3 review of commit
  `7e35b2d` and the comprehensive moto/responses test suite

---

## 6. Recommendations

### For v0.7.0 final tag (immediate)

✅ **Proceed to Step 5 (refinements)** then Step 6 (release-checklist
+ tag). The Sigstore CLI/verify gap is fixed; the v0.7.0 supply-chain
hardening story is intact end-to-end.

### For v0.7.1 (next minor; ~6-8 weeks out)

Define the v0.7.1 release theme as **"AI features hardening"**:

1. Apply collector-pattern hardening to `risk_statements/` and `explain/`:
   - Typed exception hierarchy (e.g., `RiskStatementError`,
     `ExplanationError`, `LLMUnavailableError`)
   - `@with_retry` integration (after deciding stacking semantics with
     Instructor's `max_retries`)
   - `GenerationContext` (new type — distinct from `CollectionContext`
     because risk statements are generated, not collected) carrying
     model, temperature, prompt_hash, run_id, generated_at
   - ECS structured logging via `evidentia_core.audit.logger` with new
     `EventAction.AI_RISK_GENERATED`, `AI_EXPLAIN_GENERATED`,
     `AI_GENERATION_FAILED`, `AI_GENERATION_RETRY` entries
2. New `test_risk_statements.py` (~200-300 lines): cover sync + async
   batch, validation retries, cache miss/hit patterns, LLM-call
   failures, air-gap refusal
3. Sigstore policy: change `verify_file()` default behavior — emit a
   warning in addition to the `UnsafeNoOp` fallback (Step-4 fix
   already adds the warning to `VerifyReport`; v0.7.1 should emit it
   to logs too)
4. Secret scrubber expansion (Slack, Stripe, Google, Atlassian, npm)
5. Composite action smoke test workflow
6. SHA-pin third-party actions in the composite action.yml

### For v0.8.0 (next minor after that)

Per `docs/positioning-and-value.md` §13.2, the "OSS-native AI moat"
features:

- DFAH-style determinism harness for risk-statement generation
- Policy Reasoning Traces (PRT) integration
- Open risk-statement benchmark dataset on Hugging Face
- Evidence groundedness gate
- MCP server exposing Evidentia's GRC store
- DSE-based screenshot evidence validator
- Standalone `evidentia-catalogs` repo publication

---

*End of capability-matrix.md. Compiled 2026-04-25 as Step 4 deliverable
from the v0.7.0 comprehensive pre-tag review. Will be re-validated
on each future release per the [testing-playbook.md](testing-playbook.md)
operational test loop.*
