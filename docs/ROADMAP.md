# Evidentia roadmap

**Last updated: v0.8.1 (May 2026).**

This roadmap synthesizes community feedback with the architecture plan
at the project root. Versions v0.3.0 through v0.7.16 + v0.8.0 +
v0.8.1 have shipped. **v0.8.0 is the first minor of the v0.8.x
line — "the OSS-native AI moat"** — landing four AI-quality features
(DFAH determinism harness + Policy Reasoning Traces + MCP server +
plugin-contract scaffolding) that distinguish a Vanta-class dashboard
from a compliance-engineering tool. v0.8.1 closes ALL 12 v0.8.0
review-bucketed findings, adds LLM-driven richness (DFAH
risk-determinism CLI + PRT LLM-driven decomposition), MCP HTTP/SSE
transport, and FastAPI AuthProvider middleware (closes the v0.8.0
`/api/metrics` auth gate). v0.8.2 plan opens post-ship to address
the deferred infra primitives. Anything beyond v0.8.x is forward-
looking — the exact shape will depend on real-world usage patterns
and the bigger v0.8+ direction documented in
[`positioning-and-value.md`](positioning-and-value.md) §13.

## v0.3.0 — Compliance-as-code — SHIPPED

- `evidentia gap diff` — compare two gap snapshots, classify every
  gap as opened / closed / severity-changed / unchanged. Supports
  console / json / markdown / github output formats.
  `--fail-on-regression` blocks PRs that make compliance posture worse.
- `evidentia explain <control_id>` — LLM-generated plain-English
  control translation, cached on disk.
- Documentation: `docs/github-action/README.md` + example workflow YAML
  so anyone can drop a `.github/workflows/evidentia.yml` into their
  repo and get PR-level compliance checking without waiting for the
  reusable-action wrapper.

## v0.3.1 — Examples + latent-bug fix — SHIPPED

- Three realistic end-to-end scenarios in `examples/` (Meridian fintech
  v2, Acme Healthtech, Northstar DoD contractor).
- Dogfooded GitHub Action workflow (`.github/workflows/evidentia.yml`).
- Fixed `_is_open` bug on the in-memory gap-diff path.
- 392 passing tests.

## v0.4.0 / v0.4.1 — Accessible GRC — SHIPPED

The audience shift from security engineers (CLI) to compliance officers
and auditors (web UI). Three coordinated deliverables:

### 1. Web UI — `evidentia serve` — SHIPPED (v0.4.1)

FastAPI backend + React/Vite/shadcn/ui frontend, served together from
`127.0.0.1:8000`. Non-technical users install via
`uv tool install "evidentia[gui]"` or
`pip install "evidentia[gui]"`, then run `evidentia serve` and
get a polished localhost-only dashboard.

**Shipped:**
- `evidentia serve` CLI command
- New workspace package `evidentia-api` with 18 REST endpoints
  under `/api/*`
- New workspace directory `evidentia-ui` (Vite + React + shadcn/ui)
- Every user-facing page:
  - **Home** with three-path onboarding wizard (sample data / upload /
    wizard)
  - **Dashboard** — saved-report listing with top-line metrics
  - **Frameworks** (list + detail) — 82-catalog browser with tier /
    category / search filters
  - **Gap Analyze** — interactive form → TanStack Table results
  - **Gap Diff** — two-report picker → summary + per-entry table
  - **Risk Generate** — SSE-streamed per-gap progress
  - **Settings** — editable `evidentia.yaml` + LLM provider /
    air-gap posture
- Hatchling build hook that bundles the SPA into the Python wheel
- 36 FastAPI TestClient + 6 Vitest tests

### Planned for v0.4.2 polish:

- Playwright E2E smoke test against `evidentia serve`
- "Commit to disk" button on the wizard preview (auto-write the three
  YAMLs to the CWD after confirmation)
- Deeper component test coverage (AppLayout, PathChooser, GapTable)
- Auto-generated TypeScript types from FastAPI's OpenAPI schema

**Stack:** React 18 + TypeScript strict + Vite 5 + shadcn/ui (Radix
primitives -> WCAG 2.1 AA) + TanStack Query / Table / Virtual +
React Router 6 + Zustand + React Hook Form + Zod + Recharts.

### 2. Air-gapped mode — `--offline` flag — SHIPPED (v0.4.0)

Global CLI flag plus `evidentia doctor --check-air-gap` validator.
Every LLM / network call consults the `evidentia_core.network_guard`
module; non-loopback / non-RFC-1918 targets raise
`OfflineViolationError` before any network IO fires.

**Positioning:** *"The only open-source GRC tool that runs entirely on
your infrastructure. Use with Ollama for fully air-gapped FedRAMP,
CMMC, and healthcare deployments."*

Shipped: flag, guard module, doctor validator, LLM client integration,
43 unit tests covering the host classifier and guard functions. The UI
Settings page surfaces the posture live. GUI-triggered offline-toggle
is planned for v0.4.2.

### 3. Reusable GitHub Action — SHIPPED (v0.4.1)

`allenfbyrd/evidentia-action` is live at v1.0.0 + floating `v1`
pointer. Consumers replace the 80-line drop-in workflow template with:

```yaml
- uses: allenfbyrd/evidentia-action@v1
  with:
    inventory: my-controls.yaml
    frameworks: nist-800-53-rev5-moderate,soc2-tsc
    fail-on-regression: true
```

Submission to the GitHub Actions Marketplace is a manual UI step in
the repo settings; the listing is pending final screenshots before
publication.

## v0.5.0 — Phase 2 integrations — SHIPPED

First three real integrations. These shipped as empty shells all the
way back to v0.1.0; v0.5.0 wires them up. What landed:

### `evidentia-integrations` (Jira) — SHIPPED

Push gaps as Jira issues + bidirectional status sync. When a Jira
issue transitions to Done, the linked gap's status becomes REMEDIATED
on the next `sync`. Full workflow-name mapping (To Do, In Progress,
Done, Won't Do, + common customizations). Credentials via env vars
only; no secrets ever flow through Evidentia REST responses.

CLI: `evidentia integrations jira {test,push,sync,status-map}`.
REST: `/api/integrations/jira/{status,push/{key},sync/{key},status-map}`.

### `evidentia-collectors[aws]` — SHIPPED

Auto-evidence from AWS Config + Security Hub. Covers NIST 800-53
AC / IA / SC / AU / CM / CP / SI families for cloud-native
deployments. Curated mapping of 25+ Config rules + FSBP / CIS
standards controls; unknown sources fall back to empty `control_ids`
rather than speculative attribution.

Credentials via standard boto3 chain. Unit tests use MagicMock
paginators (Config) + controlled responses (Security Hub);
integration-test-level moto coverage lands in v0.5.1.

CLI: `evidentia collect aws [--region] [--profile]`.
REST: `POST /api/collectors/aws/collect`.

### `evidentia-collectors` (GitHub) — SHIPPED

Branch protection + CODEOWNERS + repo visibility findings mapped to
SA-11 (developer security testing), CM-2/CM-3 (baseline + change
control), AC-3/AC-6 (access enforcement), SI-2 (flaw remediation).
Zero extra deps — uses httpx directly rather than pulling in PyGithub.

CLI: `evidentia collect github --repo owner/repo`.
REST: `POST /api/collectors/github/collect`.

## v0.5.1 — deprecation shims — SHIPPED

The six old PyPI names (`controlbridge`, `controlbridge-core`,
`controlbridge-ai`, `controlbridge-api`, `controlbridge-collectors`,
`controlbridge-integrations`) released at v0.5.1 as transitional shims
that emit a `DeprecationWarning` on import and forward every attribute
and submodule to their `evidentia-*` replacements via `sys.modules`
aliasing. Scheduled for PyPI yank at v0.7.0 (~October 2026).

## v0.6.0 — Project rename (ControlBridge → Evidentia) — SHIPPED

The v0.5.0 name collided with `controlbridge.ai` — a live commercial
SOX 302/404 compliance platform. v0.6.0 renamed the project end-to-end:
PyPI packages (6 names), GitHub repo, CLI entry point, config file
(`controlbridge.yaml` → `evidentia.yaml`), frontend npm scope, and
all docs. No functional changes. See `RENAMED.md` at the repo root for
the full rationale, `CHANGELOG.md § 0.6.0` for the mechanical details,
and the `standing_rule_github_repo_names.md` memory note for the absolute
rule protecting the GitHub URL redirect.

## v0.7.0 — Enterprise-grade release — SHIPPED

The "enterprise-grade" release. Closes all 10 BLOCKER items in
[`docs/enterprise-grade.md`](enterprise-grade.md) and ships the
end-to-end supply-chain hardening narrative:

- **Evidence integrity** — SHA-256 digests on every embedded
  resource in OSCAL Assessment Results back-matter; optional GPG
  signing (air-gap path) or Sigstore/Rekor signing (online path,
  OIDC-keyless via Fulcio).
- **Verification** — `evidentia oscal verify` checks digests + GPG
  `.asc` + Sigstore `.sigstore.json` bundles end-to-end.
  `--require-signature` is satisfied by either GPG or Sigstore.
  `--expected-identity` / `--expected-issuer` enforce signer
  identity for production audit pipelines.
- **CycloneDX SBOM** — generated from `uv.lock` on every release,
  attached to the GitHub Release alongside the wheels.
- **PyPI Trusted Publisher (OIDC)** — long-lived `PYPI_API_TOKEN`
  removed; release publishes are signed via the workflow's ambient
  OIDC identity. Auto-enables PEP 740 attestations on every wheel
  + sdist (Sigstore-signed, Rekor-logged).
- **OSCAL schema conformance** — `compliance-trestle>=4.0` round-trip
  in CI catches unknown-field bugs that NIST's JSON Schema misses.
- **AWS IAM Access Analyzer** + **GitHub Dependabot** collectors
  with explicit `BLIND_SPOTS` disclosure lists threaded into the
  AR back-matter for auditor transparency.
- **ECS-8.11 / NIST AU-3 / OpenTelemetry** structured logs via
  `--json-logs`. Drop-in for Splunk / Elastic / Datadog / Sentinel.
- **Secret scrubber** covers AWS / GitHub / Slack / Stripe / Google
  / npm tokens + JWTs + generic password= patterns.
- **Consolidated GitHub Action** at `.github/actions/gap-analysis/`
  (replaces the archived `allenfbyrd/evidentia-action` repo).
- **6 controlbridge-* deprecation shims removed** from the workspace
  per the public migration contract from v0.6.0.

The release was preceded by a 6-step comprehensive pre-tag review
(see [`docs/positioning-and-value.md`](positioning-and-value.md),
[`docs/capability-matrix.md`](capability-matrix.md),
[`docs/v0.7.1-plan.md`](v0.7.1-plan.md)).

**857 tests passing**; mypy strict clean; ruff lint clean; all 10
BLOCKER items in `docs/enterprise-grade.md` closed.

## v0.7.1 — AI features hardening (P0-only) — SHIPPED

The "AI features hardening" release. Brings `evidentia-ai`
(`risk_statements/` + `explain/`) up to the v0.7.0 collector-pattern
enterprise grade — closing the v0.7.0 BLOCKER B3 carry-over for both
AI subsystems:

- **`GenerationContext`** Pydantic model in `evidentia_core.audit.provenance`,
  sibling of `CollectionContext`. Captures per-output AI provenance:
  `model`, `temperature`, `prompt_hash` (SHA-256), `run_id` (ULID),
  `generated_at`, `attempts`, `instructor_max_retries`,
  `credential_identity` (best-effort operator label per NIST AU-3),
  `evidentia_version`. Optional field on `RiskStatement` and
  `PlainEnglishExplanation` (default `None` for v0.7.x backward compat;
  will tighten to required in v0.8 with deprecation cycle).
- **9 new `EventAction` entries** under the `evidentia.ai.*` namespace
  (`AI_RISK_*` + `AI_EXPLAIN_*` covering generated/failed/retry/cache_hit/batch_completed).
- **Typed exception hierarchy** in `evidentia_ai.exceptions`
  (`EvidentiaAIError`, `LLMUnavailableError`, `LLMValidationError`,
  `RiskStatementError`, `RiskGenerationFailed`, `ExplainError`,
  `ExplainGenerationFailed`) — closes BLOCKER B3 for both AI subsystems.
- **Bounded retry against shared `LLM_TRANSIENT_EXCEPTIONS`** via the
  new `with_retry_async` decorator + `build_retrying`/
  `build_async_retrying` factory functions in
  `evidentia_core.audit.retry`. AI generators pass `AI_RISK_RETRY` /
  `AI_EXPLAIN_RETRY` so SIEM operators can filter retry storms by namespace.
- **Audit-trail correlation** — every `AI_*` event carries `run_id`
  (and inherited `trace.id` from the run_id scope), so SIEM queries
  on `evidentia.run_id` surface failures + successes + retry storms
  attributable to the same batch.
- **Best-effort operator identity** via
  `evidentia_ai.client.get_operator_identity()` (returns
  `$EVIDENTIA_AI_OPERATOR` if set, else `user@hostname`). Closes the
  NIST AU-3 "Identity" gap for AI-derived artifacts.

Shipped as **P0-only** by deliberate scope-narrowing decision at ship
time. P1 (supply-chain polish — SHA-pin composite action, action E2E
smoke test, SLSA L3 build provenance, OpenSSF Scorecard) and P2/P3
(documentation polish + community-driven items) **moved to
[`docs/v0.7.2-plan.md`](v0.7.2-plan.md)** so v0.7.1 could land
focused on the BLOCKER B3 closure without scope creep.

**973 tests collected** (965 passed + 8 environmental skips on local
Windows; 8 skips are GnuPG entropy + Sigstore CI-OIDC-only and pass on
Linux CI per the v0.7.0 baseline); mypy strict clean (98 source files);
ruff lint clean.

## v0.7.2 — Supply-chain polish + documentation refresh — SHIPPED

The "supply-chain polish + documentation refresh" release. What
landed:

- **OpenSSF Scorecard weekly workflow** — `.github/workflows/scorecard.yml`
  publishes to `securityscorecards.dev` on Mondays + push-to-main.
  Surfaces ~20 supply-chain checks (Pinned-Dependencies, Branch-Protection,
  Code-Review, SBOM, Signed-Releases, etc.). v0.7.0 work covers most
  baseline checks; v0.7.3 S1 SHA-pinning will improve Pinned-Dependencies.
- **IDE setup for testing/validation** — version-controlled
  `.vscode/{settings,launch,tasks,extensions}.json` + `.cursorrules`
  + `.editorconfig` + `docs/ide-setup.md` walkthrough. Both Cursor
  and VS Code share the same config; pytest discovery / mypy strict /
  ruff format-on-save / coverage gutters / 7 debug launch configs /
  16 pre-canned tasks. Pre-commit hooks + dev container queued
  for v0.7.3 (DOC6 + DOC7).
- **Catalog-drift false positive fix** — closes daily-noise issues
  #1, #2, #3, #4 opened by `catalog-refresh.yml` between
  2026-04-23 and 2026-04-26. Pinned `yaml.safe_dump(width=200)` for
  byte-stable manifest emit + `--ignore-all-space` belt-and-suspenders
  workflow guard.
- **Pre-release-review refinements** — 4 MEDIUM doc/config polish
  fixes from the v0.7.2 comprehensive pre-tag review (DORA past-tense,
  doc stamp date, Windows venv path removal, regen stderr warning).
- **Scratch-directory convention** — `.gitignore` adds `.local/`
  for per-developer working notes and drafts not ready to share.

Shipped without the originally-scoped P0 supply-chain items
(SHA-pinning, action E2E smoke test, SLSA L3) — those moved to
[`docs/v0.7.3-plan.md`](v0.7.3-plan.md) along with the originally-scoped
docs polish (sigstore-quickstart, v0.8.0-plan, etc.). See the v0.7.2
plan's "Deferred to v0.7.3" section for the full carry-forward
inventory.

**965 tests passing** + 8 environmental skips on local Windows
(GnuPG entropy + Sigstore CI-OIDC; full pass on Linux CI per
v0.7.1 baseline); mypy strict clean (98 source files); ruff lint
clean.

## v0.7.3 — Composite action hardening + docs polish — SHIPPED

See [`docs/v0.7.3-plan.md`](v0.7.3-plan.md) for the full plan. Theme:
finishes the v0.7.1-plan-originated supply-chain items that didn't
make v0.7.2. P0 SHIPPED: SHA-pin every third-party action across the
composite action + every workflow file (28 pinned refs), composite
action E2E smoke test workflow against the Meridian fixture, SLSA L3
build provenance via `actions/attest-build-provenance@v2.4.0`. P1
SHIPPED: release-checklist verifier-note refresh, `docs/v0.8.0-plan.md`
forward release plan, `docs/sigstore-quickstart.md` end-to-end
walkthrough, architecture-plan "Updates since v0.7.0" callout block,
`.pre-commit-config.yaml` + companion `.yamllint` + `.markdownlint.yaml`,
`.devcontainer/devcontainer.json`. DOC5 quarterly positioning re-sync
deferred to v0.7.4+ (Q3 cadence). Audit-cleanup items A6 README
truncation + A10 CITATION.cff + B4 release-checklist refresh + A3
frontend dev-stack CVE bumps (vite + vitest + plugin-react) +
B2 lightweight container image (Dockerfile + non-publishing CI smoke
test) all landed. P2 community items (Okta, ServiceNow, Vanta/Drata,
OSCAL Plugfest, multi-industry sample data) carry forward to v0.7.4+.

## v0.7.4 — Dockerfile invocation hot-fix — SHIPPED

Same-day patch correcting three wrong CLI invocations shipped in
v0.7.3's container-image work + an additional pre-existing latent
same-pattern bug in the composite action's install step (latent
since v0.7.0; never surfaced because the composite action was
never externally consumed in CI before v0.7.3). The Evidentia CLI
registers `version` as a SUBCOMMAND (alongside `init`, `doctor`,
`serve`, `gap`, `catalog`, `risk`, etc.) — not as a `--version`
flag. Similarly the framework-catalog subcommand is `evidentia
catalog` (not `evidentia frameworks`). Adds a "local Docker build"
line to `docs/release-checklist.md` Step 5 so future
Dockerfile-touching releases catch this class of bug pre-tag.
All v0.7.3 PyPI artifacts (wheels, SBOM, attestations) carry
forward unchanged. See `CHANGELOG.md` `[0.7.4]` block.

## v0.7.5 — Container publish + critical security batch + quick-win polish — SHIPPED

See [`docs/v0.7.5-plan.md`](v0.7.5-plan.md). Renumbered from
v0.7.4-plan at v0.7.4 hot-fix ship time; **augmented 2026-04-29
post-v0.7.4** with three new buckets: P0.5 critical-security
batch (S1-S6 closing 14 HIGH `py/path-injection` + 1 HIGH
`py/polynomial-redos` + 3 MEDIUM stack-trace exposure + 4 MEDIUM
missing-workflow-permissions + 5 MEDIUM Pinned-Dependencies +
2 HIGH URL-substring-sanitization review = ~20 of the 37 open
code-scanning alerts), P0.6 Dependabot batch merge (5 currently
open PRs), P0.7 quick-win polish (OpenSSF Best Practices Badge
filing, `/api/health` hardening, `docs/troubleshooting.md`).
Original P0 (container publish + cosign + SLSA) and P1 (R1
quarterly resync, R2 oscal verify UX) carry forward unchanged.
~5-7 week ship target.

## v0.7.6 — UI alpha.2 + benchmark design + quickstart polish — SHIPPED

See [`docs/v0.7.6-plan.md`](v0.7.6-plan.md). Closes the alpha.2
UI completion gap that's been outstanding since v0.4.0 (Gap Analyze
form, Gap Diff picker, Risk Generate streaming page, README
screenshots), runs the deferred quarterly research-resync if Q3
cadence has arrived, lands the performance benchmark design + first
measurement run (`docs/benchmarks.md` v1), publishes
`docs/quickstart.md` (90-second flow), and runs a `/security-review`
deep-pass threat-model walk. ~4-5 week ship target.

## v0.7.7 — SQL family evidence collectors — SHIPPED (+ v0.7.7.1 same-day Dockerfile-pin hot-fix)

See [`docs/v0.7.7-plan.md`](v0.7.7-plan.md). First substantive
new-collector release since v0.5.0. Adds 5 SQL-family adapters as
`evidentia-collectors[sql-{postgres,mysql,sqlite,mssql,oracle}]`
extras — read-only collectors mapping DB-resident compliance
evidence (user privileges, audit-log status, encryption posture,
schema change history) to NIST 800-53 controls AC-2 / AC-3 / AC-6
/ AU-2 / AU-3 / SC-12 / SC-28. Plus the carried-forward Okta
collector + ServiceNow integration + a benchmark re-run. ~6-8 week
ship target.

## v0.7.8 — Cloud data-warehouse collectors + BI integrations — SHIPPED

See [`docs/v0.7.8-plan.md`](v0.7.8-plan.md) for the full plan.
Extended the v0.7.7 relational-DB evidence layer into modern cloud
data warehouses (Databricks, Snowflake) and added the first BI
output integrations (Tableau, Power BI). Each cloud-DW adapter
maps to the same NIST 800-53 control families as the SQL adapters
plus AC-2(11), AC-6(7), AC-7, IA-2(1)/(2), IR-4 for Snowflake.
The Tableau + Power BI integrations push three datasets (gap
inventory, risk register with AI-provenance, collection-run audit
trail) to enterprise BI surfaces, positioning Evidentia as the
OSS evidence-feed beneath dashboards risk officers + audit
committees + boards already consume.

CSV-based Tableau publish (no `.hyper` native binary needed) +
Power BI Push Datasets via Azure AD service-principal OAuth. CLI
+ REST + status-endpoint wiring for all four. Comprehensive
walkthrough docs (`docs/cloud-dw-collectors.md`,
`docs/bi-integrations.md`) + Meridian-with-BI demo scenario
(`examples/meridian-fintech-v2-with-bi/`). Step 5.A pre-tag batch
landed 8 fixes (F-V08-1 unbacked azure/gcp extras removal;
F-V08-2 DFAH/DSE arXiv expansion corrections; F-V08-DAST-1
frameworks 500→404 + regression test; F-V08-DAST-3 17 manual
HTTPException(422) sites converted to 400 to match OpenAPI
schema; F-V08-CR-H1 Snowflake LOGIN_HISTORY LIMIT; F-V08-CR-H2
Snowflake cursor-reuse refactor; F-V08-CR-H3 Power BI clear_table
404 swallow; F-V08-CR-MEDIUM Databricks workspace_url rename +
O(N) coverage + dead-code removal). 1259 tests passing
(+159 new); mypy strict clean across 138 source files. Some
evidence sources DEFERRED to v0.7.9+ (Databricks audit logs +
lineage need SQL Warehouse plumbing; Snowflake ACCESS_HISTORY
needs pagination design; Databricks network policies need
Account API auth path) — all surfaced as explicit BLIND_SPOTS.

## v0.7.9 — TPRM module + 4 vendor-risk-collectors + OSCAL TPRM emit — SHIPPED

See [`docs/v0.7.9-plan.md`](v0.7.9-plan.md) + the v0.7.9 SHIPPED
memory pointer. Tag `v0.7.9` at commit `b643caf` (2026-05-04).
Brings Evidentia into the regulated financial-services compliance
domain via the new `evidentia tprm` top-level capability module —
vendor inventory CRUD, due-diligence questionnaire generation +
ingestion (5 formats incl. SIG BYO + caiq-full), concentration-
risk reporting (6 dimensions), OSCAL TPRM emit (vendor inventory
in metadata.parties[] + back-matter.resources[] with SHA-256
integrity hashes), and 4 vendor-risk SaaS collectors (Vanta +
Drata + BitSight + SecurityScorecard). Plus the v0.7.8 Step 5.A
carry-over batch (4 MEDIUM closed) + `--security-headers`
middleware + PR #18 actions-bump fix. Per the comprehensive plan
§19.1 final-scope-narrowing decision, the model-risk module + 7
new catalogs + governance primitives + audit chain-of-custody
work split out across v0.7.10 + v0.7.11 follow-ons (rather than
the original 8-10 week mega-release scope). 1540 tests / mypy
strict 0/0 across 160 source files / ruff clean. Image digest
`sha256:a378f24efef3ea33062592a767abc82d5c4df9accea61e409a404faec34ac344`.

## v0.7.10 — Federal compliance + Model Risk Management overlay — SHIPPED

See [`docs/v0.7.10-plan.md`](v0.7.10-plan.md). The v0.7.9
follow-on. Shipped: top-level `evidentia model-risk` module per
SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC 2026-13a (model
inventory CRUD + SR-aligned doc generator + validation report
generator + RiskStatement.model_inventory_ref AI-feature linkage),
`evidentia governance` module (G1 Three Lines of Defense
lines-report + G2 Effective Challenge log), 7 new bundled Tier-A
catalogs (FFIEC IT Handbook 5 booklets + FFIEC CAT + OCC 2026-13a /
FRB SR 26-02; total 82 → 89), Codecov + 81.87% statement coverage
closing the last OpenSSF Silver MUST (`test_statement_coverage80`),
and 4 of the 17 v0.7.9-deferred findings (M-1 / M-2 / L-3 / L-7).
Pre-tag review: 0 HIGH / 1 MEDIUM (F-V10-S1 inline-fixed) / 1 LOW
(F-V10-S2 deferred); 0 unfixed at ship.

## v0.7.11 — Audit chain-of-custody + KRI/KPI/KGI + Open FAIR + workflows — SHIPPED

See [`docs/v0.7.11-plan.md`](v0.7.11-plan.md). Shipped: P0 audit
chain-of-custody (RetentionMetadata + lifecycle state machine +
WORMBackend ABC + LocalFilesystemWORM reference impl), P1.5
governance trio (G3 KRI/KPI/KGI metrics + G4 Open FAIR risk
quantification + G5 process-as-code workflows), P3 first-batch
deferral closures (F-V10-S2 + M-1 + M-2 + M-5 + M-6 + L-1 + L-3 +
L-6 + L-7), `validate_within` harmonization across 6 stores, +
P4 docs (audit-chain-of-custody.md + governance-metrics.md +
risk-quantification.md). Concrete S3/Azure/GCS WORM backends +
FAIR Monte Carlo simulation deferred to v0.7.12. Pre-tag review
0 HIGH / 0 MEDIUM / 0 LOW — first PROCEED-CLEAN of the v0.7.x
cycle.

## v0.7.12 — Concrete WORM backends + FAIR Monte Carlo + alert-zero — SHIPPED

See [`docs/v0.7.12-plan.md`](v0.7.12-plan.md). Shipped: 3 cloud-
WORM backend implementations (`S3ObjectLockWORM` /
`AzureImmutableBlobWORM` / `GCSBucketLockWORM` via
`evidentia[worm-s3]` / `[worm-azure]` / `[worm-gcs]` extras),
FAIR Monte Carlo simulation (`risk quantify --method fair-mc`),
GDPR Article 17 purge-flow (`purge_immediately` +
`force_gdpr_purge` operator override), CodeQL custom sanitizer
pack registering `validate_within` as a path-injection sanitizer,
`bump_version.py` inter-package pin tightening, release-checklist
Steps 5.5 + 9.5 doc-consistency + release-notes practices, and
3 cloud-WORM operator runbooks. Second consecutive PROCEED-CLEAN
/security-review (0 HIGH / 0 MEDIUM / 0 LOW). 2075 tests passing
across 188 source files.

## v0.7.13 — Dependency modernization + Codecov fix + P3 closures + release-notes hygiene — SHIPPED

See [`docs/v0.7.13-shipped.md`](v0.7.13-shipped.md). Wrap-up
release for the v0.7.x cycle. PR #18 (13 GH Actions major bumps)
merged post-ship. Codecov source_pkgs fix (Cobertura XML emits
full repo-relative file paths). P3 carry-overs closed (M-9
OSCAL UUID conformance + L-2 Vanta/Drata extended fields + L-4
SIG BYO debug logging + 5 of 9 v0.7.8 LOWs). `release.yml`
auto-populates GitHub Release body from CHANGELOG via new
`extract_changelog_block.py` (closes the v0.7.5→v0.7.12 stub-
body gap structurally). 10 historical release-body backfills
landed retroactively. Third consecutive PROCEED-CLEAN
/security-review (0 unfixed findings; 0 inline-fixes). Step 7
post-tag verification all sub-checks PASS + 2nd consecutive
pin-trap fix validation + 1st validation of G16 release body
substantiveness gate.

## v0.7.14 — Frontend modernization + Codecov P2.1 + final v0.7.x hygiene + v0.8.0 G4 foundation — SHIPPED

See [`docs/v0.7.14-shipped.md`](v0.7.14-shipped.md). 7 of 8 PR
#21 frontend major bumps landed (TypeScript 5→6, ESLint 9→10,
plugin-react-hooks 5→7, plugin-react-refresh 0.4→0.5, jsdom
25→29, postcss + @types/node minors; tailwind 3→4 deferred to
v0.7.15). 3 deferred v0.7.8 LOWs closed (test-coverage gaps,
Tableau Windows tempfile via TemporaryDirectory, Databricks
LTS env-var). **Codecov 0% RESOLVED** via P2.1 attempt 1
(flag_management block removal); dashboard now shows 82.14%
on c0c9a31. container-build Wait extended to poll all 6
packages. Hash-pinned `docker/requirements.txt` preview lands
as v0.8.0 G4 foundation. Fourth consecutive PROCEED-CLEAN
/security-review.

## v0.7.15 — Tailwind 4 + SettingsPage refactor + standing-rule pre-commit — SHIPPED

See [`docs/v0.7.15-shipped.md`](v0.7.15-shipped.md). Tailwind 3→4
migration (CSS-first `@theme` blocks; `@tailwindcss/vite` plugin;
`tw-animate-css` replaces v3-era `tailwindcss-animate`),
SettingsPage refactor (key-based remount; lint rule promoted
warn→error), standing-rule sweep pre-commit hook
(file-content stage). Fifth consecutive PROCEED-CLEAN. Ship-cycle
hardening: post-ship commit `fd36e78` extends release.yml
publish-container Wait step to all 6 packages (matches v0.7.14
P2.2 fix for container-build.yml).

## v0.7.16 — Final v0.7.x: security CVE bump + commit-msg hook + retrospective — SHIPPED

Final v0.7.x release. PR #23 closes 2 Dependabot medium-severity
alerts (python-dotenv CVE — symlink-following in `set_key`;
vulnerable < 1.2.2). Adds the `commit-msg` pre-commit hook
variant that closes the gap left by v0.7.15's file-content-only
hook (catches leaks in commit-message body too). Publishes
`docs/v0.7.15-shipped.md` in-repo retrospective. Validates the
post-v0.7.15 release.yml Wait extension (commit `fd36e78`) on
its first release pipeline run. Refreshes the OpenSSF Silver
answer sheet with v0.7.16 ship state (Codecov 82.14%
`test_statement_coverage80` MET via v0.7.14 P2.1 fix). Sixth
consecutive PROCEED-CLEAN. v0.7.x cycle CLOSED.

## v0.8.0 — The OSS-native AI moat — SHIPPED

See [`docs/security-review-v0.8.0.md`](security-review-v0.8.0.md) for the
full pre-tag review (5th canonical Pre-tag deliverable per the
pre-release-review v4 §G7) + [`docs/v0.8.0-plan.md`](v0.8.0-plan.md)
for the original plan. First minor release after the v0.7.x cycle
close. Lands the four AI-quality features that distinguish a
Vanta-class dashboard from a compliance-engineering tool:

- **DFAH determinism harness (P0.1)** — `evidentia eval stub-smoke`
  CLI verb + `DFAHarness` library API per arXiv 2601.15322. New
  module `evidentia_ai.eval` with harness/metrics/seeds + result
  models. CI-gateable via `--fail-on-determinism-rate-below`. 4
  new EventActions (started + determinism-violation + faithfulness-
  violation reserved + completed).
- **Policy Reasoning Traces (P0.2)** —
  `evidentia risk generate --emit-trace` flag per arXiv 2509.23291.
  New `TraceClaim` + `ReasoningTrace` Pydantic models; optional
  `RiskStatement.reasoning_trace` field (backward-compat). OSCAL
  emit gains `risk_statements_with_traces` kwarg surfacing traces as
  Evidentia-namespaced back-matter resources with canonical JSON +
  SHA-256 (Sigstore-signable). Trestle pydantic.v1 round-trip
  preserves trace data. New EventAction
  `AI_RISK_TRACE_EMITTED`. v0.8.0 ships single-claim stub trace;
  v0.8.1 ships LLM-driven per-claim decomposition.
- **MCP server (P0.3)** — NEW `evidentia-mcp` workspace member
  exposing 4 read-only tools (`list_frameworks`, `get_control`,
  `gap_analyze`, `gap_diff`) over stdio transport. `evidentia mcp
  serve` + `evidentia mcp doctor`. HTTP/SSE + CIMD richness defer
  to v0.8.1. PyPI Pending Publisher feature validated for the new
  `evidentia-mcp` project.
- **Plugin contract scaffolding (P0.4)** — 4 ABCs in
  `evidentia_core.plugins`: `AuthProvider`, `StorageBackend[T]`
  (PEP 695 generic), `MarketplaceProvider`, `BaseSaaSCollector`. 3
  reference implementations + `discover_plugins()` opt-in
  entry-point discovery.
- **M-4 collector base-class refactor** — Vanta, Drata, BitSight,
  SecurityScorecard inherit `BaseSaaSCollector`; per-collector
  scaffolding LOC drops ~60%. BitSight + SecurityScorecard
  override `_auth_header()` for HTTP Basic + custom Token schemes.

P1 architectural primitives:
- **G3 Prometheus `/metrics`** endpoint on `evidentia serve`
  (stdlib-only counter aggregator taps audit-event-firing path).
- **G8 `docs/evidence-integrity.md`** anti-tamper deployment
  guidance (3 deployment patterns + verification commands).
- G1 mutmut + G2 hypothesis + G4 Dockerfile `--require-hashes`
  flip deferred to v0.8.1 per pace constraints.

Image digest `sha256:fa8df8028986bd005469a267db46dc25f834b47bf232566422b63f7e2f6b2c1f`.
PyPI: 7 packages all at 0.8.0 with PEP 740 attestations verified.
SBOM 159 packages / 0 issues (osv-scanner clean). 2227 tests / 12
skipped, mypy strict 0/0 across 210 source files, ruff clean.
First PROCEED-CLEAN of the v0.8.x line. Step 7 post-tag
verification all 7 sub-checks PASS (PEP 740 / cosign / osv-
scanner / docker run / fresh-venv install **6th consecutive
pin-trap validation** / G16 release-body 7615 bytes **5th
consecutive auto-populate-from-CHANGELOG** / Scorecard delta).
Two recurring code-scanning false positives dismissed
(`py/partial-ssrf` on BaseSaaSCollector; `Pinned-Dependencies`
on Dockerfile); 0 open code-scanning alerts at close.

## v0.8.1 — Review-deferral close-out + LLM richness + network surfaces — SHIPPED

Tag `v0.8.1` at commit `3e520a0`. Image digest
`sha256:c9dfcfee90685b6b3232646d11eb43ebf4c6842847f6fe82cec52944b45ca352`.
PyPI: 7 packages all at 0.8.1 with PEP 740 attestations
verified. Release pipeline first-fire PASS (3m56s).
Step 7 post-tag verification all sub-checks PASS: PEP 740 +
cosign + osv-scanner (159 packages / 0 issues) + docker run
smoke (89 frameworks + 9 crosswalks) + fresh-venv install
(7th consecutive pin-trap validation) + G16 release-body
8484 bytes (6th consecutive auto-populate-from-CHANGELOG).
0 open code-scanning alerts at close. **Pre-release-review
v4 Continuous variant PROCEED-CLEAN — 8th consecutive of
the v0.7.x → v0.8.x line.**

See [`docs/security-review-v0.8.1.md`](security-review-v0.8.1.md)
for the full Pre-tag review. Aggressive ~4-week scope (Allen's
v0.8.1 cycle-open lock-in 2026-05-05) executed in a single
focused session.

**ALL 12 v0.8.0-bucketed review findings closed** — 2 HIGH
(logger record_event level filter, MetricsRegistry
encapsulation), 4 MEDIUM (collector `_get` non-dict raise,
FastMCP private API → public, F-V08-S3 `/api/metrics` auth
gate via Phase 3.3 AuthProvider middleware, LocalDirectoryMarketplace
manifest warning), 6 LOW (LocalTokenAuthProvider symlink-
rejection, doctor unbound vars, assert→ValueError under
PYTHONOPTIMIZE, BaseSaaSCollector PEP-695 generic rationale,
discover_plugins of_type kwarg, test defensive None checks).

**LLM-driven richness landed**:

- **DFAH risk-determinism CLI verb** —
  `evidentia eval risk-determinism --context X --gaps Y`
  runs the v0.8.0 DFAHarness against the live
  RiskStatementGenerator. CI-gateable via
  `--fail-on-determinism-rate-below 0.95`.
- **PRT LLM-driven per-claim decomposition** —
  `RISK_STATEMENT_TRACE_PROMPT` augments the system prompt
  when `emit_trace=True`. Instructor extracts 3-7 atomic
  claims with per-claim policy clause citations + self-
  introspected confidence. v0.8.0 stub trace remains as
  defensive fallback. Audit-log `trace_kind=v0.8.1-llm`
  vs `v0.8.0-stub` for auditor filtering.

**Network surfaces**:

- **MCP HTTP/SSE transport** — `evidentia mcp serve
  --transport <stdio|sse|http>` with `--host` + `--port`
  flags. Loopback-default; non-loopback warns at startup.
- **FastAPI AuthProvider middleware** — `create_app(auth_provider=...)`
  + `evidentia serve --auth-token-file <path>` ergonomic
  wiring. Closes v0.8.0 F-V08-S3 MEDIUM finding —
  `/api/metrics` + all data-bearing routes inherit the auth
  requirement. UNAUTHENTICATED_PATHS allowlist for liveness
  probes.

**Deferred to v0.8.2** per §24.6 R6 (infra primitives benefit
from a thoughtful integration plan, not rushed at cycle-end):

- G4 Dockerfile `--require-hashes` flip + reproducible-build
  verification (consumes v0.7.14 P1.5 hash-pinned
  `docker/requirements.txt`).
- G1 mutmut mutation-testing baseline ≥ 65%.
- G2 hypothesis property-based tests on crosswalk + normaliser.
- MCP CIMD richness (best explored against real MCP-client
  deployments).
- 2 NEW v0.8.1 findings: F-V81-S1 MEDIUM (HTTP/SSE file-path
  tool input gating), F-V81-S2 LOW (module-load AuthProvider
  → FastAPI `lifespan`).

**Pre-release-review v4 Continuous variant PROCEED-CLEAN** —
8th consecutive across v0.7.{11,12,13,14,15,16} + v0.8.0 +
v0.8.1. 0 CRITICAL/HIGH unfixed at ship. 2240 tests / 13
skipped, mypy strict 0/0 across 211 source files, ruff clean.

## v0.8.2 — Review-deferral closure + supply-chain hardening + test-quality + DFAH faithfulness — SHIPPED

Tag `v0.8.2` at commit (TBD post-tag). Aggressive ~3-week scope
executed in a single focused session — closes 8 reservations
carried out of v0.8.1 (CIMD richness deferred further to v0.8.3
per §24.6 R6). 9th consecutive PROCEED-CLEAN of the v0.7.x →
v0.8.x line.

See [`docs/security-review-v0.8.2.md`](security-review-v0.8.2.md)
for the full Pre-tag review.

**Closures**:

- **F-V81-S1** — `evidentia mcp serve --allow-root <path>` flag
  gates file-path tool inputs (`gap_analyze`, `gap_diff`) via
  `validate_within`. Out-of-root paths surface as
  `PathTraversalError` (MCP tool error, not server crash). Non-
  loopback HTTP/SSE without `--allow-root` warns at startup.
- **F-V81-S2** — AuthProvider construction moved from import-
  time module-level → FastAPI `lifespan` async context manager.
  Importing `evidentia_api.app` is now side-effect-free; env
  var `EVIDENTIA_API_AUTH_TOKEN_FILE` is read at app startup.
  `AuthProviderMiddleware` is always-attached + reads provider
  from `request.app.state.auth_provider` at dispatch (no-op
  when None preserves v0.8.0 backward-compat).
- **G4 Dockerfile `--require-hashes` (foundation; activation
  deferred to v0.8.3)** — `docker/requirements.txt` regenerated
  against the v0.8.2 dep tree (~140 transitive deps with SHA256
  hashes); `bump_version.py --regenerate-requirements` wires
  regeneration into the version-bump flow. Activation deferred
  per §25.6 R1: release.yml `uv build` is not byte-identical
  across hosts, so pre-tag hashes don't match PyPI. v0.8.3
  closes via reproducible-build verification (SOURCE_DATE_EPOCH)
  OR release-pipeline regeneration step.
- **G1 mutmut baseline** — `[tool.mutmut]` config + weekly
  `.github/workflows/mutmut.yml` targeting `gap_analyzer` +
  `risk_statements`. `docs/mutation-testing.md` operator
  runbook ships.
- **G2 hypothesis property-based tests** — 8 new property tests
  in `tests/property/` covering invariants on the gap-analyzer
  normalizer + the catalogs CrosswalkEngine. Configurable
  `ci` / `dev` profiles via `tests/property/conftest.py`.
- **DFAH faithfulness scoring (P3.1)** — second arXiv 2601.15322
  metric. New `evidentia_ai.eval.faithfulness` module with
  `FaithfulnessResult` model + `faithfulness_score()` function
  using stdlib Jaccard token-overlap (no heavy ML deps). Default
  threshold 0.3. `docs/dfah-faithfulness.md` operator guide.
- **First-class Sigstore signing for `evidentia eval` output
  (P3.2)** — `evidentia_ai.eval.signing` module + CLI flags
  (`--sign / --no-sign`) + new `evidentia eval verify`
  subcommand. Tri-state default auto-detects via
  `GITHUB_ACTIONS` env. New `EventAction.AI_EVAL_OUTPUT_SIGNED`
  audit entry.

**Quality at ship**: 2277 tests / 14 skipped (was 2240 / 13 at
v0.8.1), mypy strict 0/0 across ~215 source files, ruff clean.
0 CRITICAL/HIGH/MEDIUM findings; 3 LOW deferrals to v0.8.3.

## v0.8.3 — Supply-chain G4 activation + AI-quality completion — SHIPPED

Tag `v0.8.3` at commit (TBD post-tag). Aggressive ~3-week scope
executed in a single focused session — closes 6 of 8 v0.8.2
carry-overs; MCP CIMD richness deferred to v0.8.4 (4th
cycle-deferral; per §24.6 R6 gated on empirical operator demand);
DFAHarness `check_faithfulness=True` wiring deferred to v0.8.4
polish. **10th consecutive PROCEED-CLEAN** of the v0.7.x →
v0.8.x line.

See [`docs/security-review-v0.8.3.md`](security-review-v0.8.3.md)
for the full Pre-tag review.

**Closures**:

- **G4 Dockerfile `--require-hashes` ACTIVATED** — Path 1
  (SOURCE_DATE_EPOCH-driven reproducible builds) per §26.D.
  `release.yml` exports `SOURCE_DATE_EPOCH=$(git log -1
  --format=%ct HEAD)` before `uv build` → byte-identical
  wheels across hosts → SHA256 hashes match between local
  pre-tag pip-compile + PyPI uploads. New `release.yml`
  build-twice verification step asserts `sha256sum` matches
  before publish. `bump_version.py --regenerate-requirements`
  wraps `uv build` (with SOURCE_DATE_EPOCH from HEAD) +
  pip-compile against locally-built wheels via
  `--find-links=./dist/`. Closes recurring Scorecard
  PinnedDependencies false-positive cycle (alerts #100 →
  #115 across v0.7.12 → v0.8.2) structurally + permanently.
- **F-V82-S1 LOW**: `bump_version.py --regenerate-requirements`
  auto-detects host platform; on non-Linux hosts auto-invokes
  pip-compile inside the pinned `python:3.14-slim` base image
  so Linux-only transitives (uvloop) resolve correctly.
- **F-V82-S2 LOW**: `evidentia eval verify` CLI replaces broad
  `except Exception` with specific `SigstoreError` subclass
  catches mapped to distinct exit codes (2 = infrastructure
  missing; 1 = cryptographic failure).
- **F-V82-S3 LOW** (transitive): paraphrase precision via P1.1.
- **DFAH faithfulness sentence-transformers path (P1.1)** —
  new `evidentia_ai.eval.faithfulness_semantic` module + opt-in
  `[eval-faithfulness]` extra carrying sentence-transformers.
  Default model `all-MiniLM-L6-v2` (~90 MB); default threshold
  0.7. Catches paraphrases that the v0.8.2 stdlib Jaccard
  baseline misses.
- **LLM atomic-claim extraction (P1.2)** — new
  `evidentia_ai.eval.claim_extraction` module + `extract_claims()`
  function decomposes any AI-generated artifact into atomic
  verifiable claims via LiteLLM-driven LLM call. Defensive
  parsing (strip bullets/numbering; drop empties). Empty input
  returns `[]` cost-aware. New
  `EventAction.AI_EVAL_FAITHFULNESS_CHECKED` reserved for v0.8.4
  DFAHarness wiring.
- **DFAH calibration corpus + threshold-tuning script (P1.3)**
  — 50-entry corpus at
  `tests/data/dfah-calibration/corpus.jsonl` (4 categories;
  verbatim / paraphrase / semi-related / hallucination). New
  `scripts/tune_faithfulness_threshold.py` measures FPR/FNR
  across thresholds + recommends optimum via Youden's J.
  Empirically demonstrates the v0.8.2 Jaccard limitation: the
  bundled corpus's optimal Jaccard threshold is 0.85 (vs default
  0.3) — paraphrase-heavy corpora drag the optimum upward.

**Quality at ship**: 2299 tests / 14 skipped (was 2277 / 14 at
v0.8.2; +22 new tests across P1.1 + P1.2 + reproducible-build
self-tests). mypy strict 0/0 across 220+ source files; ruff
clean. 0 CRITICAL/HIGH/MEDIUM findings; 0 LOW unfixed.

## v0.8.4 — G4 Path 2 + DFAHarness wiring — SHIPPED

Tag `v0.8.4` at commit (TBD post-tag). Aggressive ~2-3 week
focused scope (executed in single session compression matching
v0.8.3 cadence). Closes the v0.8.3 ship-failure root cause via
G4 Path 2 (post-PyPI regeneration in `release.yml` —
sidesteps cross-platform reproducibility entirely) + the
v0.8.3 P1.2 deferred wiring (`check_faithfulness=True`
first-class on `DFAHarness`). MCP CIMD richness deferred 5th
time to v0.8.5; CLI flags + corpus expansion + real-LLM
integration tests deferred to v0.8.5.

See [`docs/security-review-v0.8.4.md`](security-review-v0.8.4.md)
for the v4 Pre-tag-style closeout (PROCEED-CLEAN; 11th
consecutive of v0.7.x → v0.8.x line).

### Closed in v0.8.4

- **G4 Dockerfile `--require-hashes` ACTIVATED via Path 2** —
  closes the recurring Scorecard PinnedDependencies false-
  positive cycle (alerts #100 → #116 across v0.7.12 →
  v0.8.3.1) structurally + permanently. `release.yml`'s
  publish-container job now regenerates `docker/requirements.txt`
  against PyPI's just-published wheels via
  `pip-compile --generate-hashes --no-emit-find-links` BETWEEN
  the existing Wait-for-PyPI step + the docker build step.
  Hashes match because pip-compile downloads from PyPI's bytes
  in the Linux CI runner — same source as the container
  build's pip install. Cross-platform reproducibility no longer
  required. Built-in 3-attempt retry loop with 30s sleeps
  absorbs PyPI propagation lag. The committed
  `docker/requirements.txt` is preview state for operators
  reading the repo; release-time regeneration overwrites it
  ephemerally. Defense-in-depth: hash verification fires at
  pip-compile time + at install time (two distinct points in
  the supply chain).
- **DFAHarness `check_faithfulness=True` wiring** — closes
  the v0.8.3 P1.2 deferral. `EvalSample` schema gains optional
  `source_clauses: list[str] | None = None` field; `EvalResult`
  schema gains `faithfulness_results: list[PromptFaithfulnessResult]`
  list; `DFAHarness.run()` gains 5 new kwargs:
  `check_faithfulness`, `faithfulness_threshold`,
  `faithfulness_method` (jaccard | semantic),
  `claim_extraction_fn` (mock-callable injection point),
  `faithfulness_score_fn` (mock-callable injection point).
  `EventAction.AI_EVAL_FAITHFULNESS_CHECKED` (reserved-but-
  inactive in v0.8.0; ACTIVATED in v0.8.4) +
  `EventAction.AI_EVAL_FAITHFULNESS_VIOLATION` (reserved-but-
  inactive in v0.8.0; ACTIVATED in v0.8.4). Mock-callable
  injection points keep harness tests cost-zero (no LLM /
  sentence-transformers token burn in CI) while exercising
  real production code paths. Default callable resolution
  falls back to v0.8.3-shipped `extract_claims` +
  v0.8.2/v0.8.3-shipped `faithfulness_score` /
  `faithfulness_score_semantic` when callers don't inject
  mocks. 14 new unit tests across 5 test classes. Library +
  harness integration first-class; CLI flags
  (`--check-faithfulness --source-clauses-file <yaml>`)
  deferred to v0.8.5.

### Test count + quality gates

- pytest 100% green: 2313 passed / 14 skipped (was 2299 / 14
  at v0.8.3.1 ship)
- mypy strict 0/0 across 220+ source files
- ruff clean
- Standing-rule keyword sweep clean across both v0.8.4-cycle
  commits

## v0.8.5 — DFAH CLI flags + corpus + real-LLM tests + CIMD — SHIPPED

Tag `v0.8.5` at commit (TBD post-tag). Aggressive ~2-3 week
focused scope (single-session compression matching v0.8.3 +
v0.8.4 cadence). Closes ALL 4 v0.8.4 carry-overs per Allen's
explicit Comprehensive scope + Implement-CIMD-now lock-in
(§28). 12th consecutive PROCEED-CLEAN of v0.7.x → v0.8.x line.

See [`docs/security-review-v0.8.5.md`](security-review-v0.8.5.md)
for the v4 Pre-tag-style closeout (PROCEED-CLEAN; 12th
consecutive of v0.7.x → v0.8.x line).

### Closed in v0.8.5

- **DFAH faithfulness CLI flags** —
  `evidentia eval risk-determinism --check-faithfulness
  --faithfulness-threshold N --faithfulness-method
  {jaccard,semantic} --source-clauses-file <yaml>` operator-
  facing surface. Closes the v0.8.4 P1.2 CLI-surface
  deferral. Pre-condition validation rejects malformed inputs
  BEFORE any LLM call fires.
- **DFAH calibration corpus expansion to 123 entries** +
  per-framework subsets (`corpus_nist.jsonl` /
  `corpus_ffiec.jsonl` / `corpus_iso27001.jsonl`, 24 entries
  each across the 4 categories). `tune_faithfulness_threshold.py
  --corpus-pattern <glob>` for per-framework sweep. Empirical
  per-framework recommended thresholds documented.
- **Real-LLM integration tests** for `extract_claims()` +
  `DFAHarness.run(check_faithfulness=True)` end-to-end at
  `tests/integration/test_eval/test_real_llm_extraction.py`.
  Opt-in via `EVIDENTIA_LLM_INTEGRATION=1` env var.
- **MCP CIMD richness** — implemented after 5 deferral cycles
  per Allen's "implement now" directive. New module
  `evidentia_mcp.cimd` with `CIMDDocument` (per RFC 7591) +
  `CIMDRegistry` (JSON-file-backed, version-tagged).
  `evidentia mcp serve --cimd-registry <path>` flag.
  Server-side attribute `server.evidentia_cimd` exposed for
  tool implementations. v0.8.5 ships the registry-loading +
  attachment infrastructure; per-tool scope enforcement at
  MCP-protocol level deferred to v0.8.6.

### Test count + quality gates

- pytest 100% green: 2338 passed / 17 skipped (was 2313/14
  at v0.8.4 ship; +25 new across P1 + P3 + P4)
- mypy strict 0/0 across 216 source files
- ruff clean
- Standing-rule keyword sweep clean across all 4 v0.8.5-cycle
  commits

## v0.8.6 — CIMD scope enforcement + Cohen's Kappa + per-claim confidence + retrospectives — SHIPPED

Tag `v0.8.6` at commit `eb0f331`. Container digest
`sha256:583d3849b5997edd2557530c48a32f085fa22ebbc2441bbeb2e7fcf7db8799a5`.
Aggressive ~2-3 week comprehensive scope (single-session
compression matching v0.8.3 + v0.8.4 + v0.8.5 cadence).
Closes ALL 3 v0.8.5 carry-overs + 3 cycle-additions per
Allen's explicit Comprehensive scope + CIMD-first sequencing
+ v0.7.x-retrospective / v1.0-transition / audit-trail-layer
additions lock-in (§29). 13th consecutive PROCEED-CLEAN of
v0.7.x → v0.8.x line.

See [`docs/security-review-v0.8.6.md`](security-review-v0.8.6.md)
for the v4 Pre-tag-style closeout (PROCEED-CLEAN; 13th
consecutive).

### Closed in v0.8.6

- **CIMD scope enforcement at MCP-protocol level + per-call
  audit trail** (P1) — closes the v0.8.5 P4 deferral. NEW
  `evidentia_mcp.scope` module monkey-binds `FastMCP.call_tool`
  with idempotency guard; per-call `AI_MCP_TOOL_AUTHORIZED` /
  `AI_MCP_TOOL_DENIED` audit events; `--default-client-id`
  CLI flag; deny paths raise `McpError` code -32602.
  Pass-through preserves v0.8.5 default no-gating behavior.
- **Cohen's Kappa rater agreement script** (P2) — closes the
  v0.8.5 P2 multi-rater methodology reservation. NEW
  `scripts/compute_inter_rater_kappa.py` ships κ formula +
  Landis-Koch interpretation + CI-gateable exit codes;
  rule-based jaccard rater mode probe → best κ = 0.4848
  (moderate) at threshold 0.85 → ships as "single-rater + κ
  probe inconclusive" per §29 R3 mitigation; empirically
  demonstrates v0.8.3 sentence-transformers semantic path's
  necessity. Real LLM-assisted second rater + human second
  rater both reserved for v0.9.0 walk-through.
- **Per-claim bootstrap-resampled confidence + framework-
  aware threshold defaults** (P3) — `FaithfulnessResult.confidence`
  + `framework` fields; `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD`
  map (NIST 0.60 / FFIEC 0.35 / ISO27001 0.30 per v0.8.5 P2
  empirical sweep); `resolve_threshold(framework, method)`
  helper. CLI flag `--faithfulness-threshold-mode {framework-
  aware,fixed}` deferred to v0.8.7.
- **`docs/v0.7.x-retrospective.md`** (P4) — 18-release
  narrative (v0.7.0 → v0.7.16 over ~12 days).
- **`docs/v1.0-transition.md` DRAFT** (P5) — v1.0 theme
  candidates + acceptance gates.

### Test count + quality gates

- pytest 100% green: 2383 passed / 17 skipped (was 2338/17
  at v0.8.5 ship; +45 new across P1 + P2 + P3)
- mypy strict 0/0 across 217 source files
- ruff clean
- Standing-rule keyword sweep clean across all 4 v0.8.6-cycle
  commits

## v0.8.7 — Final v0.8.x wrap-up — SHIPPED

Tag `v0.8.7` at commit (TBD post-tag). Single focused session
per Allen's explicit cycle-open lock-in (§30: Single v0.8.7
wrap-up release + LLM-rater deferred to v0.9.0 + CIMD
signatures deferred to v1.0). 14th consecutive PROCEED-CLEAN
of v0.7.x → v0.8.x line. **FINAL v0.8.x patch** — v0.9.0 opens
with a clean slate.

See [`docs/security-review-v0.8.7.md`](security-review-v0.8.7.md)
for the v4 Pre-tag-style closeout (PROCEED-CLEAN; 14th
consecutive).

### Closed in v0.8.7

- **`--faithfulness-threshold-mode {framework-aware,fixed}`
  CLI flag** (P2) — closes the v0.8.6 P3 CLI-surface
  deferral. Default `framework-aware`; explicit
  `--faithfulness-threshold` value always wins;
  framework-aware mode extracts framework from prompt_id
  (canonical `<framework>:<control_id>` format) +
  `resolve_threshold(framework, method)` lookup; fixed mode
  uses `DEFAULT_FAITHFULNESS_THRESHOLD` (0.30). Default
  `--faithfulness-threshold` changed from `0.3` → `None`
  sentinel; backward-compatible.
- **6 v0.8.6 cycle-close artifacts backfilled** (P1; docs
  only) — `security-review-v0.8.6.md` + `v0.8.6-plan.md` +
  threat-model v0.8.6 delta + capability-matrix v0.8.6
  snapshot + README v0.8.6 entry + ROADMAP v0.8.6 PLANNED →
  SHIPPED transition.

### Test count + quality gates

- pytest 100% green: 2386 passed / 17 skipped (was 2383/17
  at v0.8.6 ship; +3 new from TestFaithfulnessThresholdMode)
- mypy strict 0/0 across 217 source files
- ruff clean
- Standing-rule keyword sweep clean across the v0.8.7-cycle
  commits

## v0.9.0 — Federal compliance — SHIPPED

v0.9.0 SHIPPED 2026-05-15 — first minor of the v0.9.x line.
Opens the federal-compliance theme per the 2026-04-28 §10 Q4
lock-in.

**Phase 1 — POA&M data layer + state model**: `POAMState`
5-state enum (planned / in_progress / overdue / completed /
verified) aligned to FedRAMP POA&M Template Completion Guide
v3.0 + NIST SP 800-53A Rev 5 Appendix F. Forward-only state
transitions; backward transitions programmatically blocked to
preserve auditor-defensible monotonic progress. `Milestone`
Pydantic record + `ControlGap.poam_milestones` optional list
(default-empty for v0.7.x + v0.8.x backward-compat). New
`evidentia_core.poam` sub-package + `evidentia_core.poam_store`
JSON file-store mirroring v0.7.9 vendor_store (atomic-write +
UUID-shape ID gate + `validate_within` path-traversal defense +
`EVIDENTIA_POAM_STORE_DIR` env override). 6 new EventActions.

**Phase 2 — POA&M CLI + REST + OSCAL emit**: `evidentia poam`
Typer subcommand group (7 verbs: create / list / show / update /
milestone add|update / delete / calendar). `/api/poam/*`
FastAPI router (8 endpoints) mirroring v0.7.9 TPRM router shape
+ v0.7.8 F-V08-DAST-3 error-normalization. NEW
`evidentia_core.oscal.poam_exporter.gap_report_to_oscal_poam()`
emits OSCAL 1.1.2 plan-of-action-and-milestones JSON; each
`ControlGap` → one (observation, risk, poam-item) triple with
UUID cross-references; milestones as tracking-entries under
`risks[].remediations[]`; back-matter SHA-256 integrity mirrors
v0.7.0 finding-resource embedding. Default severity-filter is
CRITICAL + HIGH per FedRAMP §3.1 auditor-default.

**Phase 3 — CONMON cycle calendar (read-only)**:
`evidentia_core.conmon` pure-function library with 7 bundled
cadences (NIST 800-53 CA-7 monthly + FedRAMP ConMon × 3 +
CMMC L2 triennial + DoD RMF annual + OCC 2026-13a model-risk
annual). `evidentia conmon` CLI (3 verbs: list / next / check).
2 new EventActions. NO DAEMON — operators poll; the
`evidentia conmon watch` live-trigger daemon is reserved for
v1.0 per §31.1.

**Step 5.A 14-item refinement batch** (commit `ceab880`):
UUID canonicalization in `poam_store` + `vendor_store` prevents
duplicate-records-per-alias + non-conformant OSCAL UUID emit;
`_enum_value` extracted to `evidentia_core.models.common`;
stale-doc refreshes across governance + config + generation_context
references.

15th consecutive PROCEED-CLEAN of v0.7.x → v0.8.x → v0.9.x line.
2583 tests / 17 skipped / 227 source files / mypy strict 0/0 /
ruff clean. Pre-release-review v4 Pre-tag full 7-step
clearance + 3-invocation /security-review (diff-scoped +
per-subsystem + final-gate) all CLEAR.

**Phase 4 — Walk-through-as-validation**: deferred to v0.9.1
per §31.A POA&M-first / walk-through-as-validation posture.
v0.8.6 §29 P2 R3 single-rater κ probe inconclusive carry-
forward acknowledged; domain-expert walk-through becomes the
v0.9.1 reservation. v0.9.0 ships regardless.

## v0.9.1 — Walk-through-driven refinement — PLANNED

After v0.9.0 ships, the v0.9.1 cycle opens with the deferred
Phase 4 walk-through (`docs/v0.9.0-plan.md` §"Phase 4 — Walk-
through-as-validation"). Scope candidates: federal-SI scenario
rows in `capability-matrix.md`; Cohen's Kappa recompute on the
v0.8.5 DFAH calibration corpus with a domain-expert second
rater (closes the v0.8.6 §29 P2 R3 mitigation acceptance); any
walk-through-surfaced POA&M / CONMON shape adjustments; CONMON
REST router parity with the POA&M router pattern if operator
demand surfaces. Plan file lands at v0.9.1 cycle-open.

## v0.7.0+ — Quality signals, more integrations, UI polish

### Risk-statement quality validator

Every AI-generated risk statement gets scored against NIST SP 800-30 /
IR 8286 criteria. Statements that fail validation are automatically
regenerated with corrective instructions. Produces audit-survivable
output that no other open-source tool guarantees.

### Additional collectors + integrations

Same infrastructure as the shipped AWS / GitHub / Jira implementations,
more sources:

- `evidentia-collectors[aws]` — IAM Access Analyzer (AC-3, AC-6, IA-2)
- `evidentia-collectors[github]` — Dependabot alerts (SI-2; requires
  `security-events` scope)
- `evidentia-collectors[okta]` — MFA enforcement, inactive users,
  privileged account counts (AC-2, IA-2, IA-5)
- `evidentia-integrations[servicenow]` — push to `sn_compliance_task`
  via REST with OAuth 2.0
- `evidentia-integrations[vanta]` and `[drata]` — custom test results
  push via their public APIs

### Compliance ROI scoring

Reframes the cross-framework efficiency feature as "close N gaps
across M frameworks with one remediation." CFOs and CISOs respond to
ROI framing in ways they don't respond to "coverage %".

### UI polish

- Auto-generated TypeScript types from FastAPI's OpenAPI schema
  (hand-authored in v0.4.0; auto-gen removes the drift class entirely)
- Tauri desktop packaging option for offline-first users who prefer
  an installable app over `evidentia serve`
- Optional multi-user auth / RBAC for network deployments
  (localhost-only in v0.4.0 — v0.7.0+ adds token auth)

## Deferred / rejected items

- **RSA Archer integration** — deferred indefinitely. Enterprise-only,
  requires an Archer instance to develop against, and the market has
  been moving to REST-native alternatives for years.
- **COSO framework content** — legally non-starter (AICPA copyright,
  same basis as the SOC 2 Tier-C stub treatment).
- **Per-framework crosswalk auto-generation via LLM** — rejected on
  correctness grounds. Crosswalks are audit-critical and need
  human-in-the-loop review. An LLM-authored crosswalk should be
  reviewed and committed, not generated at runtime.

## Release-runbook follow-ups

PyPI Trusted Publisher (OIDC) migration: **DONE in v0.7.0** for the
6 published evidentia-* packages. The legacy `PYPI_API_TOKEN` was
deleted from the `pypi` GitHub environment during v0.7.0 ship-day
housekeeping (verified absent post-v0.7.1 via
`gh secret list --env=pypi --repo polycentric-labs/evidentia` — zero
secrets remain at the repo or env level). The originally-queued
v0.7.1 deletion-verification step is therefore a no-op carried into
v0.7.2 only as a bookkeeping line in `docs/v0.7.2-plan.md`.
