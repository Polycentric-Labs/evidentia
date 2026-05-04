# Evidentia roadmap

**Last updated: v0.7.2 (April 2026).**

This roadmap synthesizes community feedback with the architecture plan
at the project root. Versions v0.3.0 through v0.7.2 have shipped;
v0.7.3 is the next active scope (see
[`v0.7.3-plan.md`](v0.7.3-plan.md)). Anything beyond v0.7.3 is
forward-looking — the exact shape will depend on real-world usage
patterns and the bigger v0.8+ direction documented in
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

## v0.7.11 — Audit chain-of-custody + KRI/KPI/KGI + Open FAIR — NEXT

See [`docs/v0.7.11-plan.md`](v0.7.11-plan.md). Captures the items
originally scoped for the v0.7.9 8-10 week mega-release plus
v0.7.10 carry-forwards:

- P2 retention metadata + WORM backend support (S3 Object Lock /
  Azure Immutable Blob / GCS Bucket Lock)
- Remaining three governance primitives: G3 KRI/KPI/KGI Pydantic
  schemas + metrics dashboard, G4 Open FAIR risk quantification,
  G5 process-as-code governance workflows
- v0.7.10 P3 follow-up: 13 remaining v0.7.9 deferrals (M-3 / M-4 /
  M-5 / M-6 / M-7 / M-8 / M-9 + L-1 / L-2 / L-4 / L-5 / L-6 / L-8)
  + v0.7.10 F-V10-S2 ($EDITOR allowlist) + 9 v0.7.8 LOW × 9 batch
- Harmonize `validate_within` usage across all 3 JSON-file stores
  (Step 4 review forward-look)

~3-4 week ship target.

## v0.7.x — Patches + bridge to v0.8.0 — RESERVED

Reserved patch window for hot-fixes surfacing during v0.7.7-v0.7.11
dogfooding, domain-expert walk-through scheduling for the v0.9.0
federal-compliance theme (CONMON + POA&M), and final polish
before the v0.8.0 AI moat work begins. ~1-2 week reservation.

## v0.8.0 — The OSS-native AI moat — PLANNED

See [`docs/v0.8.0-plan.md`](v0.8.0-plan.md) for the full plan. Theme:
the differentiation features that no commercial GRC vendor offers
today. P0: DFAH determinism harness for risk-statement generation
(`evidentia eval`) + Policy Reasoning Traces mode
(`evidentia risk generate --emit-trace`) + MCP server
(`evidentia mcp serve`) exposing Evidentia's library surface to AI
agents + plugin-contract scaffolding (AuthProvider / StorageBackend
/ MarketplaceProvider) for out-of-tree extension authors. P1:
mutation-testing CI gate, property-based tests, Prometheus
`/metrics`, reproducible build target, `evidentia oscal export
--bundle-for-auditor` workflow, `evidentia trust-center` static-site
generator (preview), `docs/benchmarks.md`, `docs/evidence-integrity.md`.
P2: DSE evidence-validator preview, `evidentia-catalogs` standalone
repo split, Hugging Face benchmark dataset publication. ~3 month
ship target.

## v0.9.0 — Federal compliance — RESERVED

Theme reserved for federal-compliance capability work informed by
domain-expert input on FedRAMP / FISMA / NIST 800-53 (CA-5 / CA-7 /
significant-change request) workflows. Likely scope candidates:
OSCAL POA&M (Plan of Action and Milestones) emit + auto-generation
from gap-analysis findings, manageable POA&M tracking primitives
(state model + milestones + cycle-diff), CONMON (Continuous
Monitoring) cycle calendar — read-only library + CLI listing
upcoming monthly / quarterly / annual control cadence per
framework. Walk-through with the contributing domain expert
scheduled before v0.9.0 scope-lock to confirm which surfaces +
which scenario library to test against. Plan file lands during
the v0.8.0 cycle. ~3 month ship target after v0.8.0 ships.

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
`gh secret list --env=pypi --repo allenfbyrd/evidentia` — zero
secrets remain at the repo or env level). The originally-queued
v0.7.1 deletion-verification step is therefore a no-op carried into
v0.7.2 only as a bookkeeping line in `docs/v0.7.2-plan.md`.
