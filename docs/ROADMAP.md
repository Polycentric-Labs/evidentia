# Evidentia roadmap

**Last updated: v0.10.2 (May 2026).**

This roadmap synthesizes community feedback with the architecture plan
at the project root. Versions v0.3.0 through v0.7.16 + v0.8.0-v0.8.7
+ v0.9.0-v0.9.9 + v0.10.0 + v0.10.1 have shipped; v0.10.2 ships now
(third release of the v0.10.x line in a single calendar day —
2026-05-23: v0.10.0 + v0.10.1 + v0.10.2). **v0.9.0 opened the
v0.9.x "federal compliance" line** with POA&M + CONMON read-only
library; v0.9.1 landed the Polycentric Labs org migration; v0.9.2
added the CONMON REST router + federal corpus + LLM rater + federal
walk-through scenarios; v0.9.3 was the largest minor of the line —
CONMON daemon (Theme A) + AI governance (Theme B); v0.9.4 was the
consolidation pass closing deferred review items + the federal-SI
walk-through opener; v0.9.5 landed walk-through refinement +
collaboration-primitives groundwork; v0.9.6 brought the federal
expansion (WORM evidence store + CLI RBAC + CONMON MCP first-mover);
v0.9.7 was the comprehensive v0.9.x close-out + v1.0 prep
(api-stability NORMATIVE + multi-tenant RBAC + CIMD-signature
groundwork); **v0.9.8 wired those primitives into live CLI, REST,
MCP-dispatch, and storage surfaces**; **v0.9.9 was a supply-chain
hygiene + gate-fidelity patch** (paramiko CVE closure + an
`osv-scanner --sbom` pre-push gate + a full Dependabot-queue clear).
**v0.10.0 opens the v0.10.x research-driven integration line**: the
OCSF-aligned findings schema (the keystone identified by the
2026-05-21 competitive/integration research pass), a bidirectional
OCSF Compliance Finding mapping layer (`evidentia_core.ocsf`, behind
the new `[ocsf]` extra), SARIF 2.1.0 output for `evidentia gap`
(runs gap analysis as a CI gate, surfaced in GitHub code scanning +
GitLab security dashboards), and 3 pilot collectors (AWS, GitHub,
Postgres) populating the new fields. **v0.10.1 consolidates the
integration line** on the same calendar day as v0.10.0: closes both
v0.10.0 pre-release-review findings (F-V100-L1 trust-boundary on
the OCSF `unmapped["evidentia"]` block via a new
`trust_unmapped=False` parameter; F-V100-M1 `bump_version.py`
over-bumping third-party pins via a `[tool.uv.sources]` workspace
allowlist), ships the deferred third-party OCSF *ingestion*
collector with a Detection Finding path for Prowler / AWS Security
Hub, extends `compliance_status` population to the remaining 11
collectors, and introduces the `Finding` class-name alias plus
`evidentia collect convert --format ocsf`. **v0.10.2 brings the
integration line into AI clients**: 4 new MCP tools
(`gap_analyze_sarif`, `collect_ocsf`, `tprm_vendor_list`,
`poam_list`) expand the §MCP tool contract from 8 → 12; a
GRC Engineering Club marketplace plugin is staged in-repo
(`marketplace/grc-engineering-suite/plugins/evidentia/` —
generalist OSS scope per the **first concrete v0.10.x OSS-vs-paid
scope decision**, with persona-tied skills reserved for a future
Pro / Federal commercial tier); and F-V101-L1 (the v0.10.1
SSRF surface on `collect ocsf` URL mode) is closed via a new
default-on `--block-private-ips` flag. Per the v1.0 master-plan
resequencing (2026-05-21), the v0.9.x and v0.10.x lines iterate as
many times as needed toward a solid product — the operator
self-test and demo/pitch recording precede the walk-throughs and
multi-reviewer peer review, which complete before v1.0.0. See
[`v1.0-transition.md`](v1.0-transition.md) for the v1.0
narrative and acceptance gates.

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

## v0.9.1 — Walk-through-driven refinement — SHIPPED

Cycle opened 2026-05-15 after v0.9.0 ship. Plan file:
[`docs/v0.9.1-plan.md`](v0.9.1-plan.md).

- **Phase 1**: CONMON REST router — 4 endpoints under
  `/api/conmon/` (list, get, next, check) matching CLI parity.
  17 integration tests.
- **Phase 2**: LLM-assisted second rater — `scripts/llm_rater.py`
  + `--rule llm` mode in `compute_inter_rater_kappa.py`.
  Temperature-0 deterministic labeling with JSONL sidecar
  persistence.
- **Phase 3**: Federal-compliance calibration corpus —
  `corpus_federal.jsonl` (24 entries; FedRAMP ConMon + POA&M +
  NIST 800-53 CA-7). Total corpus now 147 entries.
- **Phase 4**: Federal-SI walk-through scenarios — 10 scenarios
  (FS-1 through FS-10) in `capability-matrix.md` with persona,
  goal, surfaces exercised, expected outcome.
- **Phase 5 (pending)**: Domain-expert walk-through execution
  (requires federal partner scheduling).
- **Phase 6 (pending)**: Pre-release-review + version bump + ship.

## v0.9.2 — CONMON REST + LLM rater + federal corpus — SHIPPED

(Originally PROPOSED as "AI governance foundation"; the AI
governance theme deferred to v0.9.3 when the org migration consumed
the v0.9.1 cycle.)

- **CONMON REST router** — 4 endpoints under `/api/conmon/` (list,
  get, next, check) matching CLI parity.
- **LLM-assisted second rater** — `scripts/llm_rater.py` +
  `--rule llm` mode in `compute_inter_rater_kappa.py`. Temperature-0
  deterministic labeling with JSONL sidecar persistence.
- **Federal-compliance calibration corpus** — `corpus_federal.jsonl`
  (24 entries; FedRAMP ConMon + POA&M + NIST 800-53 CA-7). Total
  corpus 147 entries.
- **Federal-SI walk-through scenarios** (FS-1 through FS-10) in
  `capability-matrix.md`.

## v0.9.3 — CONMON daemon + AI governance — SHIPPED

The largest minor of the v0.9.x line so far. Combines both
originally-PROPOSED themes (CONMON daemon Theme A + AI governance
Theme B) into a single ship since v0.9.1 (org migration) +
v0.9.2 (CONMON REST + LLM rater) consumed the originally-planned
slots.

**Theme A — CONMON daemon**:

- **`evidentia conmon watch --poll`** — long-running daemon with
  state-file-driven slug→last_completed tracking, configurable poll
  interval, graceful SIGINT/SIGTERM shutdown.
- **Basic alerting** — SMTP (STARTTLS-only with `has_extn` assertion)
  + generic HTTP webhook (HMAC-SHA256 with timestamp-included signed
  material for capture-replay defense). File-backed dedup state +
  per-(slug, state) suppression. Secret-handling protocol enforced
  (file > env > error; CLI value flags rejected).
- **Control health scoring** — `evidentia conmon health` CLI +
  `GET /api/conmon/health` REST endpoint produce per-framework
  attention-bucket counts + cross-framework overall health score.
- **ContinuousEvidenceSource plugin Protocol** + NoopContinuousSource
  reference impl (production refs deferred to v0.9.4).

**Theme B — AI governance**:

- **EU AI Act catalog enrichment** — risk_tier + applies_to_annex_iii
  on every Article 9-15 control; tier promoted D→A.
- **NIST AI RMF crosswalks** — bidirectional mappings to EU AI Act
  (26 entries) + ISO 42001 (23 entries); confidence + rubric fields
  on catalog model.
- **`evidentia_core.ai_governance`** — classification + registry +
  registry_store (UUID validation + path-traversal guard + atomic
  write).
- **`evidentia ai-gov` CLI** (classify/register/list/get/delete) +
  **`/api/ai-gov/*` REST router** (5 endpoints with audit-event
  parity to CLI).

**Carry-overs**:

- LLM-rater κ recompute on 147-entry corpus (framework-agnostic κ =
  0.8820; overall κ = 0.7956; 3 of 5 subsets PASS κ≥0.80).
- Docker/requirements drift CI gate.
- GHCR public-flip release-checklist item.
- API-stability.md DRAFT (v1.0 NORMATIVE commitment scope).

## v0.9.4 — Daemon hardening + operator polish + walk-through — SHIPPED

Consolidation pass after v0.9.3's aggressive single-session
compression. Despite the originally-planned conservative pacing,
shipped via the same aggressive single-session pattern. Closed
the 2 deferred MEDIUMs + 1 HIGH from the v0.9.3 review + the
LOW polish batch + the federal-SI walk-through reserved since
v0.9.0. **19th consecutive PROCEED-CLEAN**.

**Phase 1 — Daemon hardening**:
- P1.1 `evidentia_core.security.FileLock` (POSIX `fcntl.flock` /
  Windows `msvcrt.locking`) + `--state-lock` CLI flag wiring →
  closes F-V93-Q3 HIGH (CWE-362 race-condition).
- P1.2 webhook SSRF mitigation: default-deny `http://` +
  loopback/RFC1918/link-local/reserved IPs; opt-in
  `--webhook-allow-plaintext` + `--webhook-allow-private-network`
  → closes F-V93-S2 MEDIUM (CWE-918).
- P1.3 token-bucket rate-limit middleware on POST /api/ai-gov/
  register + /classify + `X-Idempotency-Key` header support →
  closes F-V93-S10 LOW (CWE-770).
- P1.4 polish batch (F-V93-Q11 User-Agent + Q12 Windows latency
  doc + Q14 narrow except + S9 path-disclosure doc).

**Phase 2 — Operator polish**:
- P2.1 `GET /api/conmon/daemon-status` + sidecar JSON +
  `--status-file` CLI + `CONMON_DAEMON_STATUS_QUERIED` action.
- P2.2 `evidentia conmon dedup-list` CLI verb +
  `AlertDeduper.list_entries()` API.
- P2.3 `evidentia ai-gov update` + `retire` verbs wiring
  `AI_SYSTEM_UPDATED` + `AI_SYSTEM_RETIRED`.

**Phase 3 — Federal-SI walk-through**:
- P3.1 synthetic fixtures + recipe doc + smoke test.
- P3.2 3 walk-through-surfaced refinements (real cadence slugs,
  truncate-tolerant assertions, valid `decision_role` enum).

**Phase 4 — Hygiene** (P4.1 backfill skipped per cycle-open
lock-in; P4.2 Codecov operator-completed; P4.3 DAST deferred
to v0.9.5):
- P4.4 fixed flaky TestJiraStatus (real fix: assertion-scoping,
  NOT fixture leak as initially classified).
- P4.5 added `workflow_dispatch` to `.github/workflows/test.yml`.
- P4.6 token-rotation doc fix in `docs/release-checklist.md`.

**2798 tests / 17 skipped / mypy strict 0 / 219 source files /
ruff clean.**

## v0.9.5 — Walk-through-driven refinement + collaboration primitives — SHIPPED

**Theme**: *Walk-through-driven refinement + collaboration
primitives + carry-over closure.*

**Phase 1 — Carry-over closure** (6 sub-items):
- P1.1: pytest-randomly added to dev deps + random-order test
  sweep clean.
- P1.2: DAST tools (schemathesis + playwright) in dev deps;
  `tests/dast/` scaffold with `test_openapi_fuzz.py` +
  `playwright.config.ts`.
- P1.3: 7 v0.9.3 LOW-bucket residuals closed (F-V93-S4 SSL
  context, S5 trust-boundary doc, S6 SIGINT race doc, S7
  state-file size cap, S8 RFC 5321 recipient validation, Q4
  dedup-state mtime cache, Q13 sleep_fn typing).
- P1.4: 8 v0.9.4 formal-review LOWs + 2 INFOs closed (FileLock
  fd leak / fcntl per-fd doc / rate-limit LRU spray / sleep_fn
  type / rate-limit GIL docstring / IPv6 scope-id sort / cross-
  process FileLock test / model_copy validator skip / Pydantic
  upgrade body-hash doc / replay-after-target-deleted regression).
- P1.5: shared `evidentia_core.security.atomic_write_text`
  helper + 4 v0.9.4 inline call sites refactored.
- P1.6: `EVIDENTIA_TRUST_PROXY_HEADERS=1` auto-wires uvicorn's
  ProxyHeadersMiddleware in `create_app()`.

**Phase 2 — Operator polish**:
- P2.1: AI-persona federal-SI walk-through validation (driven
  by Perplexity + WebSearch + training corpus on FedRAMP 20x,
  RFC-0024, OMB M-24-10, NIST AI RMF). 10 refinement findings
  closed; `docs/walkthrough-validation-v0.9.5.md` captures the
  artifact.
- P2.2: POA&M emit + OSCAL 1.1.2 plan-of-action-and-milestones
  added as Step 8 of the federal-SI walk-through.
- P2.3: daemon-status REST expansion — `GET /api/conmon/
  daemon-history?limit=N` rolling-history endpoint + Prometheus
  `evidentia_conmon_daemon_*` gauges at `/api/metrics`. New
  daemon CLI flags `--history-file` + `--history-max-entries`.

**Phase 3 — Collaboration primitives** (groundwork):
- P3.1: POA&M ownership fields — `Milestone.owner` +
  `Milestone.reviewer` + `evidentia poam list --owner X
  --reviewer Y` CLI + REST `?owner=X&reviewer=Y` filter.
- P3.2: Append-only evidence versioning — `EvidenceArtifact.
  version` + `lineage_id` + `predecessor_id` fields +
  `new_version()` factory helper. Data-model + helper only at
  v0.9.5; WORM store-side enforcement lands v0.9.6.
- P3.3: Basic RBAC primitives — `evidentia_core.rbac` package
  with `Role` enum / `RBACPolicy` / `check_permission` +
  FastAPI `require_role(action)` dependency factory.
  `EVIDENTIA_RBAC_POLICY_FILE` env var loads policy at
  `create_app()`. Default permissive policy preserves v0.9.4
  behavior. CLI-side RBAC enforcement deferred to v0.9.6.

**Phase 4 — Hygiene**: P4.1 backfill deferred (the v0.9.3 +
v0.9.4 docs are the canonical pattern; backfill is portfolio
polish, not blocking). P4.2 Codecov at 84.26% (vs 80% target).
P4.3 uv.lock regenerated atomically at version bump.

**2862 tests / 17 skipped / mypy strict 0 / ~225 source files /
ruff clean / pytest-randomly seed-sweep clean.**

## v0.9.6 — Federal expansion + WORM + CLI RBAC + CONMON MCP first-mover — SHIPPED

Tag `v0.9.6` (2026-05-18). Comprehensive ~3-week scope compressed
into a focused session per the v0.9.5 cycle-close lock-in (Allen's
"Comprehensive ~2-3 weeks" + "Phase 0 verification gate first" +
"CONMON MCP claim now" + "defer walk-through to v0.9.7" choices).
**21st consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x → v0.9.x
line.

**Phase 0 — pre-cycle verification (BLOCKING, all PASSED)**: OSCAL
1.2.1 changelog confirmed schema-compatible with one observation
type rename; OMB M-24-10 field set locked from agency compliance
plans; mypy strict scout reported 0 errors post-cross-package
re-resolution.

**Phase 1 — CLI RBAC + flag normalization**:
- NEW `evidentia.cli._rbac.require_role_cli(action)` Typer decorator
  mirroring `evidentia_api.rbac_dependency.require_role`. Shares
  `evidentia_core.rbac.check_permission` + action taxonomy
  (read / write / admin). Denial exits with code 77 (BSD
  `EX_NOPERM`).
- NEW `evidentia.cli._rbac_lifecycle` — process-lifetime singleton
  loader. Env vars `EVIDENTIA_RBAC_POLICY_FILE` +
  `EVIDENTIA_RBAC_IDENTITY` + new `--rbac-identity` global flag.
- `conmon check --state-file` canonical; `--last-completed-file`
  deprecated (DeprecationWarning; removal target v1.0).

**Phase 2 — WORM evidence store + lineage CLI**:
- NEW `evidentia_core.evidence_store` — append-only enforcement;
  refuses overwrite of `<lineage>/v<N>.json`; raises
  `EvidenceWORMViolation` with canonical recovery (call
  `EvidenceArtifact.new_version()`). UUID canonicalization +
  path-traversal protection.
- NEW `evidentia_core.evidence_store_worm` — optional cloud-WORM
  mirror composing with `WORMBackend` ABC (S3 / Azure / GCS).
- NEW `evidentia evidence` CLI — `save` (write-gated) +
  `history <lineage>` (read) + `show <lineage> --version N` (read).
- 3 new EventActions: `EVIDENCE_VERSION_PERSISTED`,
  `EVIDENCE_WORM_VIOLATION_BLOCKED`, `EVIDENCE_LINEAGE_QUERIED`.

**Phase 3 — AI-gov federal expansion**:
- NEW `evidentia_core.ai_governance.fips199` — `FIPS199Categorization`
  Pydantic model + high-water-mark validator per FIPS PUB 199 §3.
- NEW `evidentia_core.ai_governance.omb_m_24_10` — `OMBImpactCategory`
  enum (rights / safety / both / neither) +
  `triggers_minimum_practices()` helper.
- NEW `evidentia_core.ai_governance.scr` — `SCRForm` matching
  FedRAMP template + `classify_change()` (routine / adaptive /
  transformative) + `emit_scr_form()` diff emitter + JSON / MD
  writers.
- Extended `AISystemRegistryEntry` with 4 Optional fields +
  NEW `ATOReference` submodel.
- NEW CLI verbs: `ai-gov categorize-fips`, `ai-gov set-omb-impact`,
  `ai-gov update --ssp-reference`, `ai-gov update --emit-scr <path>`.
- 3 new EventActions: `AI_SYSTEM_FIPS_CATEGORIZED`,
  `AI_SYSTEM_OMB_CLASSIFIED`, `AI_SYSTEM_SCR_EMITTED`.

**Phase 4 — MCP first-mover + OSCAL upgrade + mypy + positioning**:
- **CONMON MCP first-mover CLAIMED**: 4 new tools on
  `evidentia_mcp.server` (`conmon_list_cadences`,
  `conmon_next_due`, `conmon_check_state`, `conmon_health`)
  wrapping the v0.9.3 daemon. Verified-unclaimed at the v0.9.5
  Q3 2026 quarterly resync; first-mover lock established ahead
  of FedRAMP CR26 mandatory adoption (Jan 1 2027).
- OSCAL 1.1.2 → 1.2.1 via single-source-of-truth
  `OSCAL_SCHEMA_VERSION` constant + observation `types: ["finding"]`
  → `["implementation-issue"]` at one emit site.
- mypy strict gate extended to all 7 evidentia-* packages.
  **256 source files clean** (was 223 of 247 at v0.9.5).
- Positioning: §6.1.A moat trinity + §6.1.B counter-positioning
  vs agentic GRC; README moat-trinity hook.

**Phase 5 — Hygiene + validation + ship**:
- Walk-through deferred to v0.9.7 per scope lock-in.
- `docs/v0.9.6-plan.md` + `docs/v0.9.6-shipped.md` +
  `docs/security-review-v0.9.6.md` all shipped per plan-first
  discipline + v4 G7.

**3018 tests / 17 skipped / mypy strict 256 of 256 source files /
ruff clean / pytest-randomly seed-sweep clean.**

## v0.9.7 — Comprehensive v0.9.x close-out + v1.0 prep — SHIPPED

Tag `v0.9.7` (2026-05-19). Comprehensive ~3-4 week scope
compressed into a focused session per the v0.9.6 cycle-close
lock-in (Allen's "comprehensive + walk-through deferred + api-
stability NORMATIVE + multi-tenant RBAC partial + CIMD signatures
groundwork" choices). **22nd consecutive PROCEED-CLEAN** of the
v0.7.x → v0.8.x → v0.9.x line.

**Phase 0 — pre-cycle verification (all PASSED)**: paramiko
upstream still unpatched (carry-forward); RFC-0007 SCN required-
field set captured; api-stability.md surface enumerated for
NORMATIVE promotion.

**Phase 1 — v0.9.6 carry-overs**:
- **P1.1 WORM auto-mirror** (closes F-V96-worm-app-layer): NEW
  `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM` + `EVIDENTIA_EVIDENCE_
  WORM_BACKEND_FACTORY` env vars. `save_evidence()` calls
  `mirror_to_worm()` after local-store write succeeds. Mirror
  failure non-fatal. 7 new tests.
- **P1.2 CIMD scope-migration CLI verb** (closes F-V96-conmon-
  mcp-cimd-migration): NEW `evidentia mcp cimd-migrate <registry-
  path>` verb. Adds v0.9.6 `conmon_*` MCP tools to each client's
  scope. Idempotent + atomic-write + `--dry-run` + `--client-id`
  filter. 9 new tests.
- **P1.3 Codecov target bump**: 80% → 85%.

**Phase 2 — v1.0 prep (headline)**:
- **P2.1 api-stability.md → NORMATIVE**: status flipped from
  DRAFT. v0.9.4-v0.9.6 surfaces backfilled (45+ models / 60+
  EventActions / 18+ CLI commands / 8 MCP tools / 8 env vars).
  NEW "MCP tool contract" section + "Env-var public contract"
  section. Pre-v1.0 binding semantics now in force.
- **P2.2 Deprecation calendar** (NEW `docs/deprecation-calendar.md`):
  formal catalogue with `conmon check --last-completed-file` as
  anchor entry (target removal v1.0).
- **P2.3 Multi-tenant RBAC primitives**: NEW
  `evidentia_core.rbac.multi_tenant` module — `TenantRBACPolicy`,
  `resolve_tenant_from_identity`, `check_permission_multi_tenant`,
  `load_multi_tenant_policy_from_file`, `from_single_tenant_policy`
  backward-compat. 31 tests. CLI + REST integration deferred to v1.0.
- **P2.4 CIMD signatures groundwork**: NEW `evidentia_mcp.signatures`
  module — `SignedToolOutput` envelope, `sign_tool_output`,
  `verify_tool_output`, env-var-driven signer factory. 19 tests.
  FastMCP dispatch-layer auto-wrap deferred to v1.0.

**Phase 3 — OSCAL SCR notification standard alignment (RFC-0007)**:
- `SCRForm` extended with 8 Optional RFC-0007 fields.
- NEW `SCRForm.to_oscal_scr_notification()` emitter — raises
  `ValueError` listing missing required fields. Per-category extras
  (Adaptive + Transformative pre-impl) auto-emitted.
- 8 new tests.

**Phase 4 — Q3 quarterly resync follow-ups**:
- **P4.1 Academic positioning** sharpened: NEW §11.2.A "OSS-native
  reference implementation for computational compliance" frame
  citing Marino & Lane (arXiv 2601.04474), de la Chica & Martí-
  González (arXiv 2605.14744), FedRAMP CR26 + RFC-0024 readiness.
- **P4.2 HF Hub GRC LLM eval-suite scaffolding** (NEW
  `docs/hf-eval-suite-scaffolding.md`): documented planned dataset
  structure + publication path. Full publish deferred to v0.9.8+.
- **P4.3 Conference outreach** DEFERRED to v0.9.8+ (needs human-
  reviewed talk abstracts).

**Phase 5 — Hygiene + ship**:
- Walk-through deferred indefinitely per scope lock-in.
- `docs/v0.9.7-plan.md` + `docs/security-review-v0.9.7.md` shipped.
- `scripts/bump_version.py --to 0.9.7` + uv.lock regen.
- Backfill v0.9.1 + v0.9.2 security-review docs deferred.

**3092 tests / 17 skipped / mypy strict 258 of 258 source files /
ruff clean.**

## v0.9.8 — v0.9.7 deferral closure + v1.0-prep integration wiring — SHIPPED

Tag `v0.9.8` (2026-05-21). Focused session wiring v0.9.7's
data/decision-only primitives into live surfaces, closing the
CR-V97 review polish, and clearing supply-chain + type-safety gaps
caught during the pre-tag review.

**Phase 1 — v0.9.7 deferral closure**:
- **Multi-tenant RBAC integration** (P1.3-P1.6): NEW `--rbac-tenant`
  CLI flag + tenant-aware policy auto-detection; FastAPI
  `require_role` derives the tenant claim from the authenticated
  principal (closes F-V97-multi-tenant-claim-spoofing); POA&M +
  evidence stores gain per-tenant directory roots; NEW
  `RBAC_TENANT_BOUNDARY_CROSSED` audit event; shared
  `load_rbac_policy_auto`.
- **MCP dispatch-layer signing** (P1.1): `SignedToolOutput` wired
  at the FastMCP tool-dispatch path; the signature rides in
  `CallToolResult._meta` as additive provenance.
- **In-tree Sigstore-keyless MCP signer** (P1.2): NEW
  `evidentia_mcp.sigstore_signer` (closes F-V97-mcp-signer-trust).
- **HF Hub GRC eval suite** (P1.9): FedRAMP Rev 5 High + CMMC L2
  corpus subsets + dataset card + `scripts/publish_hf_eval.py`;
  combined corpus regenerated to 195 entries.

**Phase 2 — CR-V97 review polish**:
- Shared `evidentia_core.factory_resolver` (CR-V97-3 de-duplication
  + CR-V97-1 cached resolution).
- `sign_tool_output()` canonical-JSON encoding via `default=str`
  (CR-V97-4).

**Phase 3 — supply-chain + type-safety**:
- idna 3.11 → 3.15 (CVE-2026-45409).
- Three `SigningContext.production()` runtime breaks fixed
  (sigstore 4.2.0 API migration) + PostgreSQL collector type
  narrowing.
- The CI + release-checklist mypy gates aligned (`--all-extras` in
  CI; `evidentia-mcp` in the checklist command) so extra-gated
  type errors can no longer slip through.

**Deferred**: federal-SI walk-through validation (folded into the
v1.0 self-test phase); paramiko CVE-2026-44405 LOW (a fix now
exists upstream — carried forward to v0.9.9 as its own focused
SSH-library major bump).

**3250 tests / 14 skipped / mypy strict 262 of 262 source files /
ruff clean.**

## v0.9.9 — Supply-chain hygiene + pre-push gate fidelity — SHIPPED

Tag `v0.9.9` (2026-05-21). A focused supply-chain patch — no source
or test code changed; dependency versions, CI workflow, supply-chain
tooling, and docs only.

**Phase 1 — Dependabot queue clearance**:
- Five grouped version-update PRs merged (the `python-dev`,
  `npm-runtime`, `npm-dev`, and `github-actions` groups + the Docker
  base-image digest), all CI-green.
- Three orphaned PRs closed — they targeted only
  `docker/requirements.txt` via a `pip`/`uv-docker` Dependabot
  ecosystem no longer present in `.github/dependabot.yml`; that file
  is regenerated from `uv.lock` at release time (G4 Path 2), so the
  PRs were superseded.
- `.github/dependabot.yml` audited — coverage confirmed complete.

**Phase 2 — `osv-scanner --sbom` pre-push gate**:
- NEW `scripts/run_osv_scan.py` + `osv-scanner.toml` allowlist + an
  `osv-scan` job in `.github/workflows/test.yml` + a Step 5 entry in
  `docs/release-checklist.md`. CI and the documented gate invoke one
  shared script. Closes the v0.9.8 gate-fidelity gap — the 16-row
  pre-push gate's Row 14 read Dependabot alerts, which suppress
  DISPUTED CVEs, so a disputed `pyjwt` advisory surfaced post-tag.

**Phase 3 — paramiko CVE-2026-44405 closed**:
- `compliance-trestle` 4.0.2 → 4.0.3 pulls `paramiko` 4.0.0 → 5.0.0,
  past the `<= 4.0.0` vulnerable range. `paramiko` is a dev-only
  transitive dependency (via `compliance-trestle`, OSCAL round-trip
  tests); no Evidentia code imports it.

**Deferred**: the federal-SI domain-expert walk-through — deferred
indefinitely per the resequencing above; runs before v1.0.0, after
the operator self-test + demo/pitch phase.

**3250 tests / 14 skipped / mypy strict 261 of 261 source files /
ruff clean.**

## v0.10.x — Research-driven integration & AI-governance line — PLANNED

Opened 2026-05-21 following a competitive/integration research pass
(see [`docs/integration-survey.md`](integration-survey.md) and
[`docs/positioning-and-value.md`](positioning-and-value.md) §5.5 /
§5.6.A). The v0.10.x line is the home for the research-driven feature
surface: because it brings meaningful new feature surface, it is a
minor bump from v0.9.9 rather than a continuation of v0.9.x patches.

**Themes** (precise per-release boundaries are set per release plan):

- **OCSF normalized findings schema** — the keystone, and where v0.10.0
  begins. Refactor evidence collectors to emit a canonical,
  framework-neutral finding aligned to the Open Cybersecurity Schema
  Framework, mapping into control gaps downstream. Decouples collector
  count from framework count and unlocks the integrations below.
- **SARIF emit** — `evidentia gap` emits SARIF 2.1.0 so gap analysis is
  a blocking PR check in GitHub / GitLab security dashboards.
- **OCSF-based collectors** — Prowler, AWS Security Hub, Trivy / Checkov
  ingestion, near-free once the normalized schema lands.
- **MCP-as-backend + GRC Engineering Club interop** — deepen the MCP
  tool/resource surface; publish a thin Evidentia MCP plugin into the
  GRC Engineering Club's `grc-engineering-suite` marketplace.
- **Persona modes** (auditor / engineer / TPRM) and **YAML-driven
  catalog / control-tier definitions** to broaden UX and contribution.
- **AI-governance regulatory packs** (EU AI Act Annex IV technical
  documentation, ISO/IEC 42001) and **agentic-governance primitives**
  (agent cards, tool-use permissioning) on the existing MCP / CIMD
  substrate.
- **Map Evidentia onto the OpenSSF Gemara reference model** in
  positioning material.

The full prioritized integration list and sequencing rationale are in
[`docs/integration-survey.md`](integration-survey.md) §7.

### Operator deep-dive & product-validation phase — PLANNED (after the v0.10.x feature surface)

A dedicated phase sequenced after the v0.10.x research-driven feature
surface is built: the maintainer works through the entire product
hands-on to fully understand it end-to-end — exercising every CLI verb,
REST endpoint, evidence collector, MCP tool, and UI surface — builds out
project documentation / a project wiki, and produces demo recordings.
This formalizes and expands the "operator self-test + demo phase"
referenced in the v0.9.9 entry above; it runs before the v1.0
domain-expert walk-through, and any gaps it surfaces feed back into the
backlog.

### v0.10.5 — OSS first-mover artifacts — PLANNED (added 2026-05-24)

Sourced from the Phase B audit re-run + 6-stream Evidentia-integration
research synthesis (`~/.claude/skills/pre-release-review/_audits/evidentia-integration-plan-2026-05-24.md`).
Full plan at [`docs/v0.10.5-plan.md`](v0.10.5-plan.md). Headline:
Evidentia ships **4 first-of-its-kind OSS artifacts**, each currently
absent from the public ecosystem (confirmed via `gh api search/code` +
ecosystem scan):

1. **First public OSCAL serialization of OpenSSF OSPS Baseline**
   (zero prior in `usnistgov/oscal-content` / `oscal-club/awesome-oscal`
   / `IBM/compliance-trestle` / `lula-tool` / OpenSCAP).
2. **First public `OSPS-CONFORMANCE.md` self-attestation**
   (`gh api search/code "OSPS-CONFORMANCE.md"` returns 0).
3. **First Tier-A OSPS-Baseline bundled control catalog set** in any
   GRC tool (3 maturity files matching existing
   `fedramp-rev5-{low,moderate,high}` + `cmmc-2-{l1,l2,l3}` precedent).
4. **First Apache-2.0 machine-readable EU AI Act ↔ ISO/IEC 42001
   crosswalk** (deferred to v0.11 per RF4; v0.10.5 sets up the
   bundled OSPS Baseline crosswalk infrastructure that v0.11 reuses).

v0.10.5 phases: (1) OSPS Baseline 3-maturity catalog set; (2) OSCAL
conversion + upstream PR to `oscal-club/awesome-oscal` (separate
publishing approval); (3) `OSPS-CONFORMANCE.md` + machine-readable
companion + CI gate; (4) `SECURITY.md` + `security.txt` + GitHub
Security Advisories enablement (separate `gh api` approval); (5)
`EOL.md` + `docs/verification.md` consumer-side cosign + PEP 740
recipes; (6) positioning §16 skip-by-reuse note; (9) `evidentia-eval`
workspace package extraction (Kimi audit close-out — DFAH harness
extracted from `evidentia-ai/eval/` to dedicated 8th package so air-
gap installs of the production runtime no longer transitively pull
the dev-time eval stack; `evidentia_ai.eval.*` retained as
deprecation shim through v0.11.x, removal in v0.12.0). ~2 weeks scope.

### v0.10.6 — OSS first-mover artifacts + OSPS crosswalks + GitHub collector extension + hygiene — SHIPPED

Patch on v0.10.5 (released 2026-05-26). 17 cycle commits authored
2026-05-27. Tag `v0.10.6`. **Carried out the v0.10.5
deferred Phases 1-5 OSS first-mover artifacts theme** plus downstream
OSPS crosswalks + GitHub collector extension + post-v0.10.5 hygiene.
Headline shipments: OSPS Baseline 3-catalog bundle + first public
OSCAL Catalog 1.2.1 serialization of the OpenSSF OSPS Baseline (first-
mover claim verified via `gh api search`); `OSPS-CONFORMANCE.md` self-
attestation + `verify-osps-conformance.yml` CI gate that re-validates
every evidence link on push/PR/cron (first public open-source project
to ship this artifact); `SECURITY.md` refresh + `.well-known/security.txt`
+ GHSA private vulnerability reporting (closes OSPS-VM-01/02/03 + CISA
SbD Pledge Goal 5); `EOL.md` + `docs/verification.md` consumer-facing
lifecycle + cosign + PEP 740 + osv-scanner + SLSA Provenance v1
verification recipes; 5 OSPS-Baseline crosswalks (NIST SSDF / NIST CSF
2.0 / EU CRA / PCI DSS 4.0 / NIST 800-161) shipped raw with upstream-
attested provenance disclaimer per the 2026-05-26 brainstorm rigor
decision (hand-verification deferred to v0.10.7); `CrosswalkDefinition`
extended additively with 3 optional `provenance`/`verification`/
`verification_note` fields; `evidentia_collectors.github.osps` module
with 16 `populate_osps_*` helpers covering AC/BR/DO/GV/LE/QA/VM families
+ 4 additive `GitHubClient` methods; workflow-permissions audit
(advisory; v0.10.7 promotes to blocking); Scorecard 6.2 → 6.5+
restoration via `verify-changelog.yml` SHA pinning. Release-checklist
Step 2.A captures the v0.10.5 LL-V105-1 partial-publish prevention
(new-PyPI-project pending-publisher check before tagging). Workspace
ships 8 PyPI packages unchanged from v0.10.5 (no new packages this
cycle, no LL-V105-1 recurrence risk). 3536 tests pass / 14 skipped /
3550 collected across 279 source files (was 268 v0.10.5); mypy strict
0/0; ruff clean. Four §12 corrections-log entries this cycle (see
`docs/v0.10.6-plan.md` §12). OSCAL upstream contribution PR at
https://github.com/oscal-club/awesome-oscal/pull/59.

### v0.10.7 — Polish + hand-verification + automation debt — PLANNED

Carried out of v0.10.6 cycle reviews. Targets:

- **Crosswalk hand-verification** — pass over the 5 OSPS crosswalks shipped raw in v0.10.6 (currently `verification: "self-attested-via-upstream"`); upgrade to `"hand-checked"` where SME confirms accuracy. See `docs/v0.10.6-plan.md` §12.3 maintenance follow-up.
- **OSPS crosswalk regeneration script** — `scripts/catalogs/gen_osps_crosswalks.py` to deterministically rebuild the 5 OSPS JSONs from the pinned upstream YAMLs (reduces manual sweep burden on next OSPS bump). C5 code-quality reviewer Important #1.
- **Hardcoded SHA reduction** in crosswalk JSONs — multi-occurrence SHA references in the 5 OSPS crosswalks (~15 total) create version-sweep burden on upstream bumps. C5 code-quality reviewer Important #2.
- **GitHub OSPS collector DRY pass** — `_unknown_finding()` factory to dedupe ~280 lines of UNKNOWN-branch boilerplate across 12 helpers. C6 code-quality reviewer Important #1.
- **`_file_present_at_any` asymmetric error handling** — 5xx errors currently silently convert to FAIL; should surface UNKNOWN on all-probes-failed. C6 code-quality reviewer Important #2.
- **`scripts/audit_workflow_permissions.py`** promotion to blocking CI gate — currently advisory; v0.10.6 baseline = 8 OK / 3 FAIL (legitimate write scopes for PR/issue comments). Three FAIL workflows need a `JUSTIFIED` status category before promotion: `action-smoke-test.yml`, `catalog-refresh.yml`, `evidentia.yml`. C7 code-quality reviewer bonus finding.
- **`yaml.safe_load` None-handling** in `audit_workflow_permissions.py` — empty workflow files currently `AttributeError`. Add a guard. C7 code-quality reviewer Minor #1.
- **`translate_url()` unit-test extraction** from `verify-osps-conformance.yml` to `scripts/verify_osps_conformance.py` + unit tests. TODO marker already in workflow at lines 135-140.
- **OSPS-LE-01.01 DCO sign-off** — needs GOVERNANCE.md + second-contributor onboarding.
- **OSPS-VM-04.02 VEX emit CLI verb** — `evidentia vex emit` (target v0.11.x).
- **OSPS-VM-05.03 `osv-scanner` CI gate** — `verify-osv-scan.yml` workflow.
- **capability-matrix.md stale absolute-path** cleanup — pre-existing reference from v0.10.4 snapshot (C8 reviewer Minor #2).
- **README v0.10.4 entry style polish** — verify the bold-key-feature pattern matches v0.10.5 + v0.10.2 precedent exactly (low priority).

### v0.11 — Federal-compliance theme + AI governance — PLANNED (post-deep-dive)

Sourced from Phase B audit v3 + integration plan §"Per-release
detailed integration plan" §v0.11. Substantive minor (~6-8 weeks):

- **KSI (Key Security Indicators) emission** as continuous OSCAL
  evidence feeds — wires as third output mode on `evidentia conmon`
  alongside the 7 bundled cadences shipped v0.9.0. Aligns to
  **FedRAMP 20x March 2026 pilot → Q3 2026 public rollout** (NIST +
  GSA expectations harden Q3 2026; this is the v0.10.x integration-
  survey OCSF/MCP positioning advantage made concrete for the
  federal lane). Evidentia's natural slot per Phase B Stream E4: OSS
  engine for the audit-quality middle layer between Trestle (raw
  OSCAL SDK) and RegScale (commercial FedRAMP package generator).
- **`evidentia incident emit --format dora-art-17`** (DoraIncident
  Pydantic record + `classify_dora()` per RTS 2024/1772 Art. 8 +
  Art. 9; auto-POA&M creation for 4h/24h/72h/1-month reporting
  clocks). **First Apache-2.0 OSS DORA Art. 17 reference emitter**
  (closed-source GRC vendors embed this inside paid platforms; no
  public OSS implementation exists). CIR 2025/302 Annex I/II/III/IV
  template alignment.
- **`nist-sp-800-218a-ai-coding` Tier-B bundled catalog** — 11
  controls covering the AI-assisted-code-production subset of NIST
  SP 800-218A (vs the broader AI-model-development scope). Pair
  with `docs/ai-coding-policy.md` template (CLAUDE.md /
  .cursorrules / copilot-instructions.md skeleton ready for clients
  to fork). Strong dogfood narrative: Evidentia uses Claude Code to
  develop itself.
- **AI-governance crosswalk enrichment** 4-phase: (Phase 1) ISO
  27001:2022 Amendment 1:2024 Climate as in-catalog addendum to
  `iso-27001-2022.yaml`; (Phase 2) NIST AI 600-1 GenAI Profile +
  ISO/IEC 23894 as Tier-B catalogs; (Phase 3) **first Apache-2.0
  machine-readable EU AI Act ↔ ISO/IEC 42001 crosswalk** —
  `docs/crosswalks/eu-ai-act-to-iso-42001.yaml` clean-room from EU
  AI Act Annex III + ISO 42001 Clauses 4-10 + Annex A controls
  (zero public OSS equivalent); (Phase 4) Council of Europe AI
  Convention (CETS 225) Tier-C stub.
- **`evidentia vex publish --rekor`** — Sigstore Rekor attestation
  via `cosign attest --type openvex`. Closes OSPS-VM-04 maturity-3
  control + CISA SbD Goal 6 alignment.
- **VSA (Verification Summary Attestation) emit** per SLSA v1.2 —
  `evidentia oscal vsa <ar.json>` → consumer-facing verification
  policy. Closes SLSA Source Track L2 claim path.
- **Auto-generate `docs/security-review-vX.Y.Z.md`** from per-run
  JSON via skill v5.1 Q9 mechanism.
- **DORA-metrics extractor** `scripts/extract_dora_metrics.py` —
  passive collection across 30+ Evidentia releases reading per-run
  JSONs → MTTR / lead-time / change-failure-rate / bypass-rate.
  Enables ESEM 2027 SEIP short-paper submission.
- **arXiv preprint authored**: "Evidentia: OSS Reference
  Implementation of Computational Compliance for Multi-Framework
  Regulatory Assurance" — 6-8pp, cites Marino & Lane (arXiv:2601.04474)
  blueprint, establishes priority before another impl beats Evidentia
  to the generalist-GRC-OSCAL niche.
- **Refresh `docs/integration-survey.md` competitive section**
  post-operator-deep-dive (incorporate AWS OSCAL MCP / Vanta MCP /
  ComplianceCow MCP / Snyk AI Trust Platform shifts).

### v1.1+ — Commercial-tier launch + remaining audit items — RESERVED (added 2026-05-24)

Items deferred from Phase B audit v3 + integration plan §"v1.1+":

- Multi-tenant RBAC full CLI/REST wire (commercial Pro tier per
  v0.10.2 OSS-vs-paid lock-in; primitives shipped v0.9.7).
- PR-time auto-blocking workflow (OSS, NOT Pro carve-out per
  RF3 — closes OSPS-VM-05 + VM-06 maturity-3 controls; per
  Phase B audit, this is a 100-LOC workflow YAML that should
  stay OSS to preserve open-core moat integrity).
- AIReg-Bench adapter (`evidentia_eval/aireg_bench.py`) — scores
  Evidentia against Marino & Lane benchmark; establishes
  computational-compliance reference-implementation priority.
- Auto-redaction script for per-run JSON publication
  (`scripts/redact_for_publication.py`) — strips client-PII;
  enables public dataset release alongside ESEM 2027 paper +
  pairs with MSR 2027 Mining Challenge candidacy.
- ESEM 2027 SEIP short-paper submission (~May 2027 deadline)
  OR ICSE 2027 Demonstrations track (4-6pp tool demo).
- Persona modes full UX (auditor / engineer / TPRM) for Pro tier.
- Hosted federal-cloud variant (Federal tier).
- **OpenSSF Best Practices Badge Gold tier** — unblocked only
  when Polycentric-Labs has ≥2 active core maintainers (tied to
  commercial-tier hiring milestone per `evidentia_commercial_strategy.md`).
- Architectural Tier 3 items from Phase B audit v3 (control-chart
  script ships skill-side; dynamic-install eBPF scan; etc.).

## v1.0 — Federal compliance shipped + API stability — RESERVED

See [`docs/v1.0-transition.md`](v1.0-transition.md) for the full
narrative. v1.0 combines Candidate A (federal-compliance theme
accepted by domain expert) and Candidate B (public API contract
frozen). Acceptance gates include: domain-expert walk-through
completed, 1+ external operator validation, API stability docs
published, deprecation calendar, OpenSSF Gold tier (if achievable),
cryptographic CIMD signatures, and pre-release-review PROCEED-CLEAN.
Commercial packages (evidentia-pro, evidentia-enterprise,
evidentia-federal) launch post-v1.0 as separate PyPI packages with
proprietary licenses.

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
