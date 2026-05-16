# Evidentia

> **Bridge the gap between your controls and your frameworks.**

**Evidentia** is an open-source, Python-first Governance, Risk, and Compliance
(GRC) platform that turns compliance from a spreadsheet problem into a software
problem. It provides composable building blocks for control gap analysis,
AI-generated risk statements, automated evidence collection, and compliance
reporting — all usable from a Python library, a CLI, or a REST API.

[![tests](https://github.com/polycentric-labs/evidentia/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/polycentric-labs/evidentia/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/polycentric-labs/evidentia/branch/main/graph/badge.svg)](https://codecov.io/gh/polycentric-labs/evidentia)
[![PyPI version](https://img.shields.io/pypi/v/evidentia.svg)](https://pypi.org/project/evidentia/)
![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12724/badge?v=silver)](https://www.bestpractices.dev/projects/12724)

---

## Why Evidentia is different

GRC tooling has been waiting for its **Terraform moment**. Vanta and Drata
are the AWS Consoles of compliance — polished SaaS dashboards charging
$30K–$80K/year per framework. Evidentia is the **library-first compliance
infrastructure layer underneath**: composable, embeddable, and built on the
open standards (OSCAL) that the entire federal compliance stack is moving
toward in 2026.

It's the only OSS tool today that combines **all** of the following in one package:

- **OSCAL-native end-to-end** — ingests NIST OSCAL catalogs, emits OSCAL
  Assessment Results. Ready for the **September 2026 federal mandate**
  (OMB M-24-15 + FedRAMP RFC-0024). Vanta, Drata, AuditBoard, OneTrust,
  ServiceNow IRM, MetricStream all ship **zero OSCAL output** today.
- **Cryptographically signed evidence** — Sigstore/Rekor keyless signing
  of every Assessment Results document, PEP 740 attestations on every
  released wheel + sdist, and a CycloneDX SBOM attached to every GitHub
  Release. **No other OSS GRC tool puts cryptographic provenance on the
  evidence itself.**
- **89 framework catalogs bundled** — NIST 800-53 Rev 5 (full 1,196
  controls + Low/Moderate/High/Privacy baselines), CSF 2.0, FedRAMP,
  CMMC 2.0, EU AI Act, DORA, NIS2, GDPR, all 15 comprehensive US state
  privacy laws, the full FFIEC IT Examination Handbook stack (5
  booklets: Information Security / Audit / Management / Operations
  / Outsourcing), FFIEC Cybersecurity Assessment Tool, OCC Bulletin
  2026-13a / FRB SR 26-02 (Model Risk Management), plus 20 Tier-C
  licensed-stub frameworks with `evidentia catalog import` for your
  licensed copies. More than any commercial vendor (Vanta: 35+,
  Drata: 20+, RegScale: 60+).
- **Apache 2.0 license** — embeddable in commercial products without
  AGPL friction. The OSS GRC alternatives (CISO Assistant, Eramba,
  Comp AI) are AGPL with paid commercial tiers.
- **Library-first, CLI-second, API-third** — `pip install evidentia-core;
  from evidentia_core import GapAnalyzer`. The closest peers
  (`compliance-trestle`, RegScale OSCAL Hub) are workflow / CLI tools, not
  embeddable libraries.
- **Air-gap capable** — `--offline` flag refuses network egress; signs
  evidence with GPG when Sigstore can't reach Fulcio. Built for FedRAMP
  High, CMMC Level 2, and EU sovereign-cloud deployments where SaaS GRC
  is a non-starter.
- **AI-optional, not AI-mandatory** — risk-statement generation and
  control explanation use LLMs via LiteLLM (any provider — OpenAI,
  Anthropic, Google, Azure, Bedrock, Ollama, vLLM). Everything else is
  deterministic. No leakage of sensitive evidence to third-party AI APIs
  unless you explicitly opt in.
- **CI-native via composite GitHub Action** — drop in
  `uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0` and every
  PR runs gap analysis, posts a sticky compliance comment, and blocks
  merge on regression. No commercial GRC tool does this at the PR level.

For the full competitive analysis, market tailwinds, intellectual
ancestry, and 12-month direction, see
[`docs/positioning-and-value.md`](docs/positioning-and-value.md) — a
12,000-word synthesis from 7 parallel research streams.

---

## The problem

Modern GRC is stuck in 2005. The typical compliance program runs on:

- **Spreadsheets** that get copy-pasted between auditors, engineers, and exec staff
- **Vendor GRC suites** that cost $50K-500K per year, lock you in, and still require
  weeks of manual work to map one framework to another
- **Point solutions** that handle one piece (a vulnerability scanner, a policy
  tracker, a questionnaire manager) but can't talk to each other
- **Consultants** who re-learn your environment from scratch every audit cycle

Meanwhile, the compliance workload keeps growing. A single fintech or healthcare
SaaS company today might simultaneously be in scope for **SOC 2, PCI DSS 4.0,
HIPAA, GDPR, CCPA, ISO 27001, and NYDFS Part 500** — seven frameworks with
substantial overlap, each demanding its own evidence, gap analysis, and risk
documentation.

The same control (say, "MFA on all privileged accounts") satisfies requirements
in all seven. But because each framework uses different vocabulary, numbering,
and organization, compliance teams end up documenting the same control seven
different ways — and audit season becomes a months-long exercise in cross-referencing.

**This is a software problem.** It should be solved the way software problems
get solved: with composable libraries, structured data, version control, and
automation.

## Why Evidentia exists

Evidentia is built on four principles:

1. **Open standards, not vendor lock-in.** Inputs and outputs use
   [OSCAL](https://pages.nist.gov/OSCAL/) — NIST's open standard for control
   catalogs and assessment results. If you outgrow Evidentia, your data
   travels with you.

2. **Library-first, CLI-second, API-third.** The Python library is the
   canonical interface. The CLI is a thin wrapper. The REST API is a thin
   wrapper. Everything Evidentia can do via the CLI, it can do from a
   Python script — which means you can embed it in CI pipelines, compliance
   portals, or custom integrations.

3. **AI where it helps, not where it hurts.** Evidentia uses LLMs for
   tasks where language understanding is the bottleneck (writing NIST SP 800-30
   risk statements from a gap, validating whether a policy PDF actually
   covers a control). It uses deterministic code for tasks where correctness
   matters (OSCAL parsing, gap arithmetic, cross-framework mapping).

4. **Provider-agnostic LLM access.** All AI features route through
   [LiteLLM](https://docs.litellm.ai/) + [Instructor](https://python.useinstructor.com/),
   giving you structured Pydantic output from any model — OpenAI, Anthropic,
   Google, Azure, Ollama, vLLM, or any OpenAI-compatible endpoint. No vendor
   lock-in on the AI layer either.

## Who it's for

- **Security engineers** at startups and mid-size companies who need to
  hit SOC 2 Type II without hiring a full compliance team
- **GRC consultants** who want to stop rebuilding the same spreadsheets
  for every engagement
- **Platform teams** who want to embed gap analysis into their CI pipelines
  and catch drift before the auditor does
- **CISO offices** that want a real audit trail on risk decisions, backed
  by versioned structured data instead of Slack threads
- **Anyone** who has ever said "I know this NIST control is the same as
  this SOC 2 criterion, but I don't want to re-document it for the fifth time"

---

## Current status: 89 frameworks bundled, full suite passing

### Recent releases

**v0.9.0 (May 2026)** — *Federal compliance — POA&M lifecycle +
CONMON cycle calendar + walk-through-as-validation*. First minor
of the v0.9.x line. Opens the federal-compliance theme reserved
at v0.8.7 cycle-close. Lands operator-facing surfaces auditors
expect in any regulated-industry GRC tool: Plan-of-Action-and-
Milestones tracking + Continuous Monitoring cycle calendar.
**Phase 1** — POA&M data layer: `POAMState` 5-state enum
(planned / in_progress / overdue / completed / verified)
aligned to FedRAMP POA&M Template Completion Guide v3.0 + NIST
SP 800-53A Rev 5 Appendix F; forward-only state transitions;
`Milestone` Pydantic record; `ControlGap.poam_milestones`
optional list (default-empty for v0.7.x + v0.8.x backward-compat);
new `evidentia_core.poam` sub-package (state.py + milestone.py);
new `evidentia_core.poam_store` JSON file-store mirroring
v0.7.9 vendor_store; 6 new EventActions.
**Phase 2** — `evidentia poam` CLI (7 verbs: create from gap
report / list / show / update / milestone add|update / delete /
calendar); `/api/poam/*` FastAPI router (8 endpoints);
`evidentia_core.oscal.poam_exporter.gap_report_to_oscal_poam()`
emitting OSCAL 1.1.2 plan-of-action-and-milestones JSON with
SHA-256 back-matter integrity (mirrors v0.7.0 finding-resource
embedding). Default severity-filter is CRITICAL + HIGH per FedRAMP
§3.1 auditor-default; `--all` opts into the full set.
**Phase 3** — `evidentia_core.conmon` pure-function library
with 7 bundled cadences (NIST 800-53 CA-7 monthly + FedRAMP
ConMon × 3 + CMMC L2 triennial + DoD RMF annual + OCC 2026-13a
model-risk annual); `evidentia conmon` CLI (list / next /
check); 2 new EventActions. No daemon — operators poll.
**Plus** new operator runbooks (`docs/poam-runbook.md` +
`docs/conmon-runbook.md`); 14-item Step 5.A refinement batch
(UUID canonicalization in poam_store + vendor_store via
`str(UUID(id))` preventing duplicate-records-per-alias +
non-conformant OSCAL UUID emit; `_enum_value` extracted to
`evidentia_core.models.common`; stale-doc refreshes across
governance + config + generation_context references).
**15th consecutive PROCEED-CLEAN** of v0.7.x → v0.8.x → v0.9.x
line. **2583 tests passing / 17 skipped across 227 source files;
mypy strict 0/0; ruff clean.** Phase 4 walk-through deferred to
v0.9.1 per §31.A POA&M-first / walk-through-as-validation
posture.

**v0.8.7 (May 2026)** — *Final v0.8.x wrap-up*. Single focused
session closing the v0.8.6 P3 CLI deferral + backfilling
v0.8.6 cycle-close artifacts deferred during single-session
compression. **NEW** `--faithfulness-threshold-mode
{framework-aware,fixed}` flag on `evidentia eval risk-
determinism` (default `framework-aware`) closes the v0.8.6
P3 deferral; `--faithfulness-threshold` default changed from
`0.3` → `None` sentinel for backward-compatible framework-
aware default resolution. Resolution precedence: explicit
value wins → framework-aware mode (extracts framework from
prompt_id; looks up via `resolve_threshold(framework, method)`)
→ fixed mode (0.30 framework-agnostic). 6 v0.8.6 cycle-close
artifacts backfilled (`docs/security-review-v0.8.6.md` +
`docs/v0.8.6-plan.md` + threat-model v0.8.6 delta +
capability-matrix v0.8.6 snapshot + README v0.8.6 entry +
ROADMAP v0.8.6 PLANNED → SHIPPED transition). 14th
consecutive PROCEED-CLEAN of v0.7.x → v0.8.x line. **2386
tests passing across 217 source files; mypy strict 0/0; ruff
clean.** **FINAL v0.8.x patch** — v0.9.0 opens with the
federal-compliance theme per the 2026-04-28 §10 Q4 lock-in.

**v0.8.6 (May 2026)** — *CIMD scope enforcement at MCP-
protocol level + Cohen's Kappa rater agreement + per-claim
confidence + framework-aware threshold defaults + v0.7.x
retrospective + v1.0 transition narrative DRAFT*. Aggressive
~2-3 week comprehensive scope (single-session compression
matching v0.8.3 + v0.8.4 + v0.8.5 cadence). Closes ALL 3
v0.8.5 carry-overs + 3 cycle-additions. **MCP CIMD scope
enforcement at MCP-protocol level**: NEW `evidentia_mcp.scope`
module monkey-binds `FastMCP.call_tool` (mcp Python SDK 1.27
has no public middleware hook); `--default-client-id <slug>`
CLI flag; pass-through preserves v0.8.5 default no-gating
behavior; per-call `AI_MCP_TOOL_AUTHORIZED` /
`AI_MCP_TOOL_DENIED` audit events; deny paths raise
`McpError` code -32602. **Cohen's Kappa rater agreement
script** (`scripts/compute_inter_rater_kappa.py`): two-rater
file mode + rule-based-rater mode; CI-gateable exit codes;
empirical κ = 0.4848 (moderate) at jaccard threshold 0.85
ships as "single-rater + κ probe inconclusive" per the
documented R3 mitigation. **Per-claim bootstrap-resampled
confidence**: `FaithfulnessResult.confidence` field
(default-off cost-aware ~100ms/claim; opt-in via
`compute_confidence=True`); **framework-aware threshold
defaults**: `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD` map
(NIST 0.60 / FFIEC 0.35 / ISO27001 0.30) +
`resolve_threshold(framework, method)` helper +
`FaithfulnessResult.framework` field. **`docs/v0.7.x-
retrospective.md`** publishes the 18-release v0.7.x cycle
narrative; **`docs/v1.0-transition.md` DRAFT** captures v1.0
theme candidates + acceptance gates + open questions for
v0.9.0 cycle-open. Thirteenth consecutive PROCEED-CLEAN of
the v0.7.x → v0.8.x line. **2383 tests passing across 217
source files; mypy strict 0/0; ruff clean.** v0.8.7 wrap-up
release closes the v0.8.6 P3 CLI deferral.

**v0.8.5 (May 2026)** — *DFAH CLI flags + corpus expansion +
real-LLM integration tests + MCP CIMD richness*. Aggressive
~2-3 week comprehensive scope (single-session compression
matching v0.8.3 + v0.8.4 cadence). Closes ALL 4 v0.8.4
carry-overs in one focused session per Allen's explicit
"implement CIMD now" directive — ending the 5-cycle CIMD
deferral pattern. **DFAH faithfulness CLI flags**:
`evidentia eval risk-determinism --check-faithfulness
--faithfulness-threshold N --faithfulness-method
{jaccard,semantic} --source-clauses-file <yaml>`. Closes the
v0.8.4 P1.2 CLI-surface deferral; pre-condition validation
rejects malformed inputs BEFORE any LLM call fires. **DFAH
corpus expansion** to 123 entries with per-framework subsets
(NIST 24 / FFIEC 24 / ISO 27001 24). `tune_faithfulness_threshold.py
--corpus-pattern <glob>` for per-framework sweep; empirical
per-framework recommended thresholds documented. **Real-LLM
integration tests** at `tests/integration/test_eval/` opt-in
via `EVIDENTIA_LLM_INTEGRATION=1`. **MCP CIMD richness**:
new `evidentia_mcp.cimd` module ships `CIMDDocument` (per
RFC 7591 + MCP conventions) + `CIMDRegistry` (JSON-file-
backed, version-tagged). `evidentia mcp serve --cimd-registry
<path>` flag wires it through stdio + SSE + HTTP transports.
Twelfth consecutive PROCEED-CLEAN of v0.7.x → v0.8.x line.
**2338 tests passing across 216 source files; mypy strict
0/0; ruff clean.** v0.8.6 reservations: per-tool scope
enforcement at MCP-protocol level + multi-rater corpus pass
+ per-claim confidence scoring.

**v0.8.4 (May 2026)** — *G4 Path 2 + DFAHarness wiring*.
Aggressive ~2-3 week focused scope (single-session compression
matching v0.8.3 cadence). Closes the v0.8.3 ship-failure root
cause via **G4 Path 2** (post-PyPI regeneration in
`release.yml` — sidesteps cross-platform reproducibility
entirely). New regeneration step BETWEEN Wait-for-PyPI + docker
build runs `pip-compile --generate-hashes --no-emit-find-links`
against PyPI's just-published wheels → ephemeral
`docker/requirements.txt` overwrite → docker build picks it
up. Hashes match because pip-compile downloads from PyPI's
bytes in the Linux CI runner — same source as the container
build's pip install. Built-in 3-attempt retry loop with 30s
sleeps absorbs PyPI propagation lag. **DFAHarness
`check_faithfulness=True` wiring** closes the v0.8.3 P1.2
deferral: `EvalSample.source_clauses` field +
`EvalResult.faithfulness_results` list +
`DFAHarness.run(check_faithfulness=, faithfulness_threshold=,
faithfulness_method=, claim_extraction_fn=,
faithfulness_score_fn=)` kwargs.
`EventAction.AI_EVAL_FAITHFULNESS_CHECKED` +
`AI_EVAL_FAITHFULNESS_VIOLATION` (reserved-but-inactive in
v0.8.0) ACTIVATED. Mock-callable injection points keep harness
tests cost-zero while exercising real production code paths.
14 new unit tests across 5 test classes. Eleventh consecutive
PROCEED-CLEAN of the v0.7.x → v0.8.x line. **2313 tests passing
across 220+ source files; mypy strict 0/0; ruff clean.** MCP
CIMD richness deferred to v0.8.5 (5th cycle-deferral; v0.8.5
re-evaluates with potential formal retirement) + CLI flags +
calibration corpus expansion + real-LLM integration tests
deferred to v0.8.5.

**v0.8.3 + v0.8.3.1 hot-fix (May 2026)** — *Supply-chain G4
attempt + AI-quality completion*. Aggressive ~3-week cycle
executed in a single focused session. Closes 5 of 8 v0.8.2
carry-overs (G4 attempt failed first-fire + reverted in
same-day hot-fix). **G4 Path 1 ATTEMPTED**: Dockerfile flipped
from exact-version pinning to
`pip install --require-hashes -r /tmp/requirements.txt` against
hash-pinned `docker/requirements.txt`; `release.yml` exported
`SOURCE_DATE_EPOCH` for SOURCE_DATE_EPOCH-driven `uv build`
reproducibility. **First-fire revealed `uv build` is NOT
byte-identical between Windows local + Linux CI runner** even
with same SOURCE_DATE_EPOCH (file-ordering / timestamp-precision
drift). PyPI publish succeeded but container build's
`pip install --require-hashes` failed: local-computed hashes ≠
Linux-CI-built wheel hashes. **v0.8.3.1 hot-fix REVERTED** the
Dockerfile to exact-version pinning (same v0.8.2 surface; no
regression); container ship recovered same-day. Recurring
Scorecard PinnedDependencies false-positive cycle continued
(alerts dismissed per the runbook). G4 closure deferred to
v0.8.4 with Path 2 (post-PyPI regeneration; sidesteps cross-
platform reproducibility entirely). **F-V82-S1**:
`bump_version.py --regenerate-requirements` auto-detects host
platform; on non-Linux hosts auto-invokes pip-compile inside
Linux base image. **F-V82-S2**: `evidentia eval verify` CLI
replaces broad `except Exception` with specific `SigstoreError`
subclass catches mapped to distinct exit codes. **DFAH
sentence-transformers path (P1.1)**: opt-in
`[eval-faithfulness]` extra; default model `all-MiniLM-L6-v2`
(~90 MB); catches paraphrases that the v0.8.2 Jaccard baseline
misses. **LLM atomic-claim extraction (P1.2)**: new
`extract_claims()` function decomposes AI-generated artifacts
into atomic verifiable claims for faithfulness scoring.
**Calibration corpus (P1.3)**: 50-entry corpus + threshold-
tuning script empirically guide operators on per-corpus
threshold selection. Tenth consecutive PROCEED-CLEAN of the
v0.7.x → v0.8.x line. **2299 tests passing across 220+ source
files; mypy strict 0/0; ruff clean.** MCP CIMD richness
deferred to v0.8.4 (4th cycle-deferral; gated on empirical
operator demand) + DFAHarness `check_faithfulness=True` wiring
deferred to v0.8.4 polish.

**v0.8.2 (May 2026)** — *Review-deferral closure + supply-chain
hardening + test-quality + DFAH faithfulness*. Aggressive ~3-week
cycle executed in a single focused session. Closes 8 reservations
carried out of v0.8.1. **F-V81-S1**: `evidentia mcp serve
--allow-root <path>` gates file-path tool inputs via
`validate_within`. **F-V81-S2**: AuthProvider construction moved
from import-time module-level → FastAPI `lifespan` event;
imports are side-effect-free. **G4 Dockerfile foundation**:
`docker/requirements.txt` regenerated against the v0.8.2 dep
tree with SHA256 hashes per transitive (activation deferred to
v0.8.3 per §25.6 R1 build-determinism). **G1 mutmut + G2
hypothesis**: mutation-testing baseline + 8 property-based
tests on normalizer + crosswalk. **DFAH faithfulness scoring**:
second arXiv 2601.15322 metric via stdlib Jaccard token-overlap
(threshold 0.3 default). **First-class Sigstore signing for
`evidentia eval`**: `--sign / --no-sign` flag + `evidentia
eval verify` subcommand. Ninth consecutive PROCEED-CLEAN of
the v0.7.x → v0.8.x line. **2277 tests passing across ~215
source files; mypy strict 0/0; ruff clean.** CIMD richness +
sentence-transformers faithfulness + DFAH calibration corpus
deferred to v0.8.3.

**v0.8.1 (May 2026)** — *Review-deferral close-out + LLM richness
+ network surfaces*. Aggressive ~4-week cycle compressed to a
single focused session. Closes ALL 12 v0.8.0-bucketed review
findings (2 HIGH + 4 MEDIUM + 6 LOW polish + 2 INFO). Ships the
LLM-driven richness for the v0.8.0 P0 surfaces:
``evidentia eval risk-determinism --context X --gaps Y`` runs
the DFAHarness against the live RiskStatementGenerator;
PRT LLM-driven per-claim decomposition replaces the v0.8.0
stub (``trace_kind=v0.8.1-llm`` vs ``=v0.8.0-stub`` audit-log
discriminator). Network surfaces: ``evidentia mcp serve
--transport sse|http`` + FastAPI AuthProvider middleware
(``evidentia serve --auth-token-file <path>``). Closes the
v0.8.0 F-V08-S3 ``/api/metrics`` auth gate. Eighth consecutive
PROCEED-CLEAN of the v0.7.x → v0.8.x line. Three Phase 4 infra
primitives (G4 Dockerfile ``--require-hashes``, G1 mutmut, G2
hypothesis) deferred to v0.8.2 per §24.6 R6. **2240 tests
passing across 211 source files; mypy strict 0/0; ruff clean.**

**v0.8.0 (May 2026)** — *The OSS-native AI moat*. First minor
after the v0.7.x cycle close. Lands four AI-quality features
that distinguish a Vanta-class dashboard from a compliance-
engineering tool: **DFAH determinism harness** (`evidentia eval
stub-smoke` — auditor-defensible numerical proof that AI
artifact generation is reproducible per arXiv 2601.15322),
**Policy Reasoning Traces** (`evidentia risk generate
--emit-trace` — decomposes risk statements into ordered claims
with policy clause citations per arXiv 2509.23291), **MCP
server** (`evidentia mcp serve` — exposes Evidentia to MCP-
aware AI clients over stdio with 4 read-only tools), and
**plugin contract scaffolding** (`evidentia_core.plugins` —
4 ABCs + 3 reference implementations + entry-point discovery
for community catalog providers + SI-partner extensions).
M-4 collector base-class refactor consolidates ~60% of the
HTTP scaffolding across the 4 vendor-risk collectors. New
`/api/metrics` Prometheus endpoint + `docs/evidence-integrity.md`
operator deployment guidance. Pre-release-review v4 Pre-tag
PROCEED-CLEAN with 5 inline-fixes from the parallel security
+ code-quality reviews; 12 findings bucketed to v0.8.1 with
documented rationale. **2227 tests passing across 210 source
files; mypy strict 0/0; ruff clean.**

**v0.7.16 (May 2026)** — *Final v0.7.x cycle release.*
Closes the v0.7.x cycle (18 patches + 2 hot-fixes over ~12
days; 6 consecutive PROCEED-CLEAN). python-dotenv CVE bump
+ commit-msg hook variant of standing-rule sweep + post-
ship release.yml hardening validation. v0.8.0 design phase
opens immediately post-ship.

**v0.7.15 (May 2026)** — *Tailwind 4 + SettingsPage refactor +
standing-rule pre-commit hook*. Final v0.7.x cycle release before
v0.8.0 design opens. Tailwind 3→4 migration (full shadcn/ui
preset rewrite to CSS-first `@theme {}`; PostCSS chain replaced
with `@tailwindcss/vite` plugin; `tailwindcss-animate` v3-era →
`tw-animate-css` v4-compatible). SettingsPage.tsx refactored to
key-based remount of `<SettingsForm/>` sub-component; lint rule
`react-hooks/set-state-in-effect` promoted from `warn` to
`error`. New `scripts/standing_rule_sweep.sh` + pre-commit hook
runs the canonical 21-pattern guard at commit-time. Fifth
consecutive PROCEED-CLEAN /security-review. Post-ship hardening
(commit `fd36e78`) extends `release.yml` publish-container Wait
step to all 6 packages — closes the LAST PyPI propagation race
surface. 2120 tests passing across 188 source files.

**v0.7.14 (May 2026)** — *frontend modernization + Codecov
P2.1 RESOLVED + final v0.7.x hygiene + v0.8.0 G4 foundation*.
7 of 8 PR #21 frontend major bumps (TypeScript 5→6, ESLint
9→10 flat-config, plugin-react-hooks 5→7, jsdom + minors;
tailwind 3→4 deferred to v0.7.15). 3 deferred v0.7.8 LOWs
closed (Tableau Windows tempfile via TemporaryDirectory,
Databricks LTS env-var, test-coverage gaps). Codecov dashboard
fixed (was 0% since v0.7.10; now 82.14% via removing the
`flag_management.individual_flags[].paths` glob that filtered
all files out). container-build Wait extended to all 6 packages.
Hash-pinned `docker/requirements.txt` preview lands as v0.8.0
G4 reproducible-build foundation. Fourth consecutive PROCEED-
CLEAN /security-review. 2120 tests passing across 188 source
files.

**v0.7.13 (May 2026)** — *dependency modernization + Codecov fix
+ P3 carry-over closures + release-notes hygiene*. Wrap-up of
the v0.7.x cycle. No new public surfaces. Codecov coverage
upload fixed (switched to `source_pkgs` so Cobertura XML emits
full repo-relative paths). `release.yml` now auto-populates the
GitHub Release body from `CHANGELOG.md` via a new
`extract_changelog_block.py` step + `body_path` arg — closes
the v0.7.5–v0.7.12 stub-body gap structurally; future releases
auto-populate. P3 carry-overs closed: M-9 OSCAL UUID
conformance + L-2 Vanta/Drata high-risk extended fields +
L-4 SIG BYO sparse-row debug logging + 5 of 9 v0.7.8 LOWs.
Third consecutive PROCEED-CLEAN /security-review. Plus 10
historical release-body backfills landed retroactively. 2100
tests passing across 188 source files.

**v0.7.12 (May 2026)** — *concrete cloud-WORM backends + FAIR
Monte Carlo + GDPR purge-flow + alert-zero*. Adds the three cloud
backends to the `WORMBackend` ABC introduced in v0.7.11:
`S3ObjectLockWORM`, `AzureImmutableBlobWORM`, `GCSBucketLockWORM`
(installed via `evidentia[worm-s3]` / `[worm-azure]` /
`[worm-gcs]` extras). Adds FAIR Monte Carlo simulation
(`risk quantify --method fair-mc`) using stdlib-only Beta-PERT
sampling. Adds GDPR Article 17 purge-flow (`purge_immediately` +
`force_gdpr_purge` operator override). Plus 3 cloud-WORM operator
runbooks, alert-zero closure (CodeQL custom sanitizer pack
registers `validate_within` as a path-injection sanitizer),
`bump_version.py` inter-package pin tightening, and
release-checklist Steps 5.5 + 9.5 doc-consistency + release-notes
practices. Second consecutive PROCEED-CLEAN /security-review.
2075 tests passing across 188 source files.

**v0.7.11 (May 2026)** — *audit chain-of-custody + governance trio
+ Open FAIR + 6-store harmony*. Adds the `evidentia retention`
CLI (set / list / show / extend / transition / delete / report)
with 10-regime classification (SEC 17a-4 / FINRA 3110 / IRS / SOX
/ HIPAA / GLBA / PCI / SR 11-7 / GDPR / generic) and a
`WORMBackend` ABC with a `LocalFilesystemWORM` reference impl.
Adds KRI/KPI/KGI metrics overlay (P1.5 G3), Open FAIR risk
quantification (P1.5 G4 deterministic PERT-mean), and
process-as-code governance workflows (P1.5 G5). Closes 9 of 17
v0.7.10 P3 deferrals including F-V10-S2 (`$EDITOR` allowlist).
**First v0.7.x PROCEED-CLEAN** /security-review (0 findings).
1929 tests passing across 184 source files.

**v0.7.9 + v0.7.10 (May 2026)** — *industry overlay (financial
services TPRM + model risk + governance primitives) + federal-
compliance carry-overs*. v0.7.9 ships `evidentia tprm` (vendor
inventory + DD-questionnaire generator with 5 output formats
including SIG BYO + caiq-full + concentration-report) + 4
vendor-risk SaaS collectors (Vanta / Drata / BitSight /
SecurityScorecard) + OSCAL TPRM emit. v0.7.10 adds the model-
risk overlay (SR 11-7 / OCC 2011-12 model inventory + validation
report templates) + 7 new bundled catalogs (5 FFIEC IT Handbook
booklets + OCC 2011-12 / FRB SR 11-7 + FFIEC CAT). Bundled
catalog count: 82 → 89.

**v0.7.8 (May 2026)** — *cloud data-warehouse collectors + BI
integrations*. Adds two read-only evidence collectors for cloud
data warehouses (Databricks workspace API + Snowflake
`account_usage` views; mapped to NIST 800-53 controls AC-2 / AC-3
/ AC-6 / AC-7 / AU-2 / AU-3 / IA-2 / IA-5 / SC-7 / SC-12 / SI-2)
plus the first **output integrations to enterprise BI platforms**
(Tableau Server / Cloud + Power BI). Three published datasets per
BI platform: gap inventory, NIST SP 800-30 risk register with AI-
provenance fields, and CollectionContext audit trail. Ships
walkthrough docs (`docs/cloud-dw-collectors.md`,
`docs/bi-integrations.md`) and an end-to-end Meridian-with-BI
demo.

**v0.7.7 (May 2026)** — *SQL family evidence collectors*. Five
read-only relational-DB adapters (`[sql-postgres]`, `[sql-mysql]`,
`[sql-sqlite]`, `[sql-mssql]`, `[sql-oracle]`) mapping DB-resident
compliance evidence to NIST 800-53 controls. Plus ServiceNow
output integration carry-forward.

See [`CHANGELOG.md`](CHANGELOG.md) for the full version history
(v0.1.0 through v0.7.15). For forward direction, see
[`docs/v0.8.0-plan.md`](docs/v0.8.0-plan.md) (the OSS-native AI
moat — DFAH + PRT + MCP + plugin contracts) and
[`docs/ROADMAP.md`](docs/ROADMAP.md) (everything else).

### What works today

- **Gap analysis against 89 bundled frameworks** across four redistribution
  tiers:

  - **Tier A — US federal (25 frameworks, verbatim public domain):**
    NIST 800-53 Moderate sample, 800-171 Rev 2/Rev 3, 800-172, CSF 2.0,
    AI RMF 1.0, Privacy Framework 1.0, SSDF 800-218; FedRAMP Rev 5
    Low/Moderate/High/LI-SaaS baselines; CMMC 2.0 Levels 1/2/3; HIPAA
    Security/Privacy/Breach Notification Rules; GLBA Safeguards, NY DFS
    500, NERC CIP v7, FDA 21 CFR Part 11, IRS 1075, CMS ARS, FBI CJIS v6,
    CISA Cross-Sector CPGs.

  - **Tier A — International (6 frameworks):** UK NCSC CAF 3.2, UK Cyber
    Essentials, Australian Essential Eight, Australian ISM, Canada
    ITSG-33, New Zealand NZISM.

  - **Tier D — Statutory obligations (21 frameworks, government edicts,
    uncopyrightable):** EU GDPR, EU AI Act, EU NIS2, EU DORA, UK DPA 2018,
    Canada PIPEDA, plus all 15 comprehensive US state privacy laws (CA
    CCPA/CPRA, VA, CO, CT, UT, TX, OR, DE, MT, IA, FL, TN, NH, MD, MN).

  - **Tier C — Licensed stubs (20 frameworks):** ISO/IEC 27001:2022,
    27002:2022, 27017, 27018, 27701, 42001 (AI), 22301 (BC); PCI DSS
    v4.0.1; HITRUST CSF v11; COBIT 2019; SWIFT CSCF 2024; CIS Controls
    v8.1 plus 5 CIS Benchmarks (AWS, Azure, GCP, Kubernetes, RHEL 9);
    Secure Controls Framework 2024; IEC 62443; SOC 2 TSC. Copyrighted
    authoritative text isn't bundled — ships with public clause numbering
    plus a `evidentia catalog import` hook for your licensed copy.

  - **Tier B — Threat and vulnerability catalogs (4 frameworks):** MITRE
    ATT&CK Enterprise (41 techniques), MITRE CWE Top 25 (2024), MITRE
    CAPEC sample, CISA KEV sample (Log4Shell, MOVEit, EternalBlue, etc).

- **Six bundled crosswalks:** NIST CSF 2.0 → 800-53, FedRAMP Moderate →
  CMMC L2, NIST 800-53 → HIPAA Security, ISO 27001 → NIST 800-53, VCDPA →
  CCPA/CPRA, NIST 800-53 → SOC 2 TSC.

- **Multi-format inventory parsing.** Load your controls from YAML, CSV, JSON
  (including OSCAL component-definition), or any format with fuzzy-matched
  column headers. Status normalization handles "implemented", "partial",
  "planned", "in progress", "missing", etc.

- **Cross-framework crosswalk engine.** Bidirectional mapping index: ask
  "what NIST 800-53 controls satisfy my SOC 2 criterion?" or "what CMMC
  Level 2 controls match my FedRAMP Moderate posture?". v0.2.0 ships six
  bundled crosswalks (118 mappings total). Custom crosswalks are
  drop-in JSON files in `catalogs/data/mappings/`.

- **Prioritized gap reports.** Severity by implementation state, effort-weighted
  priority scores, efficiency opportunities (controls that close gaps in 2+
  frameworks simultaneously), and a prioritized remediation roadmap.

- **Four output formats:** JSON (canonical), CSV (flat), Markdown (human
  review), and OSCAL Assessment Results (for audit handoff and tool interop).

- **AI risk statement generator.** NIST SP 800-30 Rev 1 compliant risk
  statements from gaps + system context. Uses Instructor to enforce the
  `RiskStatement` Pydantic schema on LLM output, with automatic retries on
  validation failure. Works with any LiteLLM-supported model.

- **Typer + Rich CLI** with `init`, `catalog list/show/crosswalk/import/
  where/license-info/remove`, `gap analyze`, `gap diff`, `risk generate`,
  `explain control`, `collect aws`, `collect github`, `integrations jira`,
  `oscal verify` (v0.7.0 — verifies SHA-256 digests + GPG `.asc` and/or
  Sigstore `.sigstore.json` signatures), `serve` (web UI), `doctor`,
  and `version` commands. `catalog list` supports `--tier` and `--category`
  filters; `catalog import` accepts direct JSON or an OSCAL profile (via
  `--profile <profile.json> --catalog <source.json>`). Global flags:
  `--offline` (air-gap mode), `--json-logs` (ECS 8.11 structured output
  for SIEM ingestion), `--config <path>`, `--verbose`, `--quiet`.

- **965 tests passing + 8 environmental skips** (Windows-local; full
  suite of 973 passes on Linux CI per the v0.7.0 baseline) covering models, catalog loading (with a
  parametric smoke test per bundled framework), recursive enhancement
  flattener for NIST Rev 5 3-level IDs, tier invariants, OSCAL profile
  resolution, user-import directory precedence, crosswalk bidirectionality,
  multi-format inventory parsing, severity calculation, all four report
  exporters, Jira integration push/sync, AWS Config + Security Hub +
  IAM Access Analyzer + GitHub branch protection + CODEOWNERS +
  Dependabot evidence collection, FastAPI `/api/*` endpoints, air-gap
  mode, OSCAL AR digest + GPG + Sigstore round-trip verification, and
  3 trestle conformance tests against the NIST OSCAL reference impl.

### What's not yet included (as of v0.7.2)

Setting expectations matters. v0.7.0 shipped a substantial enterprise
hardening pass, v0.7.1 closed the AI features carry-over (typed
`EvidentiaAIError` hierarchy, `GenerationContext` metadata, bounded
retry, ECS structured logging across `risk_statements/` + `explain/`),
and v0.7.2 added supply-chain visibility via OpenSSF Scorecard +
contributor-experience IDE config + a catalog-drift detector fix.
See [`CHANGELOG.md`](CHANGELOG.md) for the full v0.7.0 + v0.7.1 +
v0.7.2 deltas. The following are still on the roadmap but not yet
shipped:

- **Composite action hardening** (v0.7.3) — SHA-pin third-party
  actions in `.github/actions/gap-analysis/action.yml`, composite
  action E2E smoke test, SLSA L3 build provenance via
  `actions/attest-build-provenance@v2`. See
  [`docs/v0.7.3-plan.md`](docs/v0.7.3-plan.md) for the full plan;
  2-4 week ship target.
- **LLM-based evidence validation** (Phase 3 / v0.8+) — "is this
  screenshot actually proof of MFA?" scoring, freshness detection,
  multi-modal validation via Document Screenshot Embedding (DSE).
  Currently academic-only; tracked in
  [`docs/positioning-and-value.md`](docs/positioning-and-value.md) §13.
- **Additional collectors / integrations** — Okta (MFA, inactive users,
  privileged-account counts), ServiceNow (`sn_compliance_task` push),
  Vanta + Drata (push test results via their public APIs), Azure + GCP
  evidence collectors. Carried forward to v0.7.3 as
  optional/community-driven items per
  [`docs/v0.7.3-plan.md`](docs/v0.7.3-plan.md) §"P2 — Optional /
  community-driven".
- **Multi-user auth / RBAC** — the web UI is localhost-only today;
  network-deployment token auth is queued for v0.7.x+.
- **Authoritative control text for copyrighted frameworks** (ISO
  27001/27002, SOC 2 TSC, PCI DSS, HITRUST CSF, etc.) — ship as
  **Tier-C stubs** with public clause numbering only. Use
  `evidentia catalog import` to load your own licensed copy.

---

## Quick start

### Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/) 0.4+ (recommended) or pip

### Install from PyPI

```bash
pip install evidentia
```

This installs the `evidentia` and `cb` CLI commands, plus the five workspace
sub-packages as transitive dependencies (`evidentia-core`, `evidentia-ai`,
`evidentia-collectors`, `evidentia-integrations`, `evidentia-api`).

### Install from source (for contributors)

```bash
git clone https://github.com/polycentric-labs/evidentia.git
cd evidentia
uv sync --all-packages
```

This downloads Python 3.12 (if needed), creates a `.venv`, and installs all
five workspace packages in editable mode.

### Run the smoke test

```bash
uv run pytest tests/ -q
# Expected: full suite passes in ~10s on a warm checkout
```

> Hit a snag? See [`docs/troubleshooting.md`](docs/troubleshooting.md)
> for common first-run issues — wrong Python version, missing SPA
> bundle, Sigstore TUF metadata fetch failures, Docker bind-mount
> permissions.
>
> Want the absolute shortest path? See [`docs/quickstart.md`](docs/quickstart.md)
> — five commands from `pip install` to a verified OSCAL Assessment
> Results document.

### Web UI flows (v0.7.6 alpha.2)

`evidentia serve` brings up a FastAPI + React SPA on
`http://127.0.0.1:8000`. Five interactive surfaces ship today,
mirroring the CLI 1:1:

| Page | What it does |
|---|---|
| [Home](docs/gui/screenshots/home.png) | Three-path onboarding (sample data / upload / wizard) |
| [Frameworks](docs/gui/screenshots/frameworks.png) | Browse all 89 bundled catalogs with tier + category filters |
| [Gap Analyze](docs/gui/screenshots/gap-analyze.png) | Form + framework picker → TanStack Table results |
| [Gap Diff](docs/gui/screenshots/gap-diff.png) | Two-report classification + PR-comment markdown export |
| [Risk Generate](docs/gui/screenshots/risk-generate.png) | Streamed AI risk statements per gap |

See [`docs/gui/README.md`](docs/gui/README.md) for a per-page
walkthrough + accessibility notes + troubleshooting.

### End-to-end walkthrough with sample data

Evidentia ships with a realistic fictional fintech scenario in
[`examples/meridian-fintech/`](examples/meridian-fintech/). Walk through it in five steps:

```bash
# 1. Verify installation
uv run evidentia doctor

# 2. Explore available frameworks
uv run evidentia catalog list

# 3. Inspect a specific control
uv run evidentia catalog show nist-800-53-mod --control SI-4

# 4. See how one framework maps to another
uv run evidentia catalog crosswalk \
  --source nist-800-53-mod --target soc2-tsc --control AC-2

# 5. Run gap analysis on the Meridian Financial sample inventory
cd examples/meridian-fintech
uv --project ../.. run evidentia gap analyze \
  --inventory my-controls.yaml \
  --frameworks nist-800-53-mod,soc2-tsc \
  --output report.md --format markdown \
  --min-efficiency-frameworks 2
```

Expected output: a 17-gap report against 28 required controls, 39.3% coverage,
11 critical / 5 high / 1 medium severities, with the top of the priority queue
dominated by monitoring/detection gaps (CC7.1, CC7.2, SI-4, AU-6).

### Use as a GitHub Action

v0.7.0 ships a composite GitHub Action that turns every PR into a
compliance check. It runs `evidentia gap analyze`, diffs against the
main-branch baseline, posts a sticky PR comment with the diff, and gates
merge on regressions.

```yaml
# .github/workflows/compliance.yml
name: Compliance check
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
        with: { fetch-depth: 2 }

      - uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0
        with:
          inventory: inventory.yaml
          frameworks: nist-800-53-rev5-moderate,soc2-tsc
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

See [`.github/actions/gap-analysis/README.md`](.github/actions/gap-analysis/README.md)
for the full input/output surface, OSCAL AR + Sigstore signing options,
SHA-pinned variants for audit pipelines, and the migration guide from
the legacy standalone `allenfbyrd/evidentia-action@v1` (now archived).

### Generate AI risk statements

Requires an LLM API key. Any LiteLLM-supported provider works:

```bash
export OPENAI_API_KEY=sk-...            # or ANTHROPIC_API_KEY, etc.

uv --project ../.. run evidentia risk generate \
  --context system-context.yaml \
  --gaps report.json \
  --model gpt-4o \
  --output risks.json \
  --limit 5
```

This produces five validated `RiskStatement` objects (NIST SP 800-30 structure)
for the five highest-priority gaps.

### Starting your own project

```bash
# From an empty directory
uv run evidentia init

# Creates:
#   evidentia.yaml       — config with defaults
#   my-controls.yaml         — template control inventory
#   system-context.yaml      — template system context
#   .evidentia/          — local storage
```

Edit `my-controls.yaml` with your real inventory and run `evidentia gap analyze`.

---

## Architecture

Evidentia is a **uv workspace monorepo** of six composable Python packages
plus a React/Vite frontend workspace:

| Package                      | Role                                                                        |
| ---------------------------- | --------------------------------------------------------------------------- |
| `evidentia-core`         | Pydantic data models, OSCAL catalog loader, crosswalk engine, gap analyzer  |
| `evidentia-ai`           | LiteLLM + Instructor client, risk statement generator, control explainer  |
| `evidentia-collectors`   | Evidence collection agents — AWS (Config + Security Hub), GitHub (branch protection + CODEOWNERS), Okta (SSO + MFA), Databricks (Unity Catalog + clusters), Snowflake (LOGIN_HISTORY + grants + masking), 5 SQL adapters (Postgres / MySQL / SQLite / MSSQL / Oracle), 4 vendor-risk APIs (Vanta / Drata / BitSight / SecurityScorecard) |
| `evidentia-integrations` | Jira push + bidirectional status sync, ServiceNow ticket sync, Tableau + Power BI publish |
| `evidentia-api`          | FastAPI server (26 REST routes across 12 router modules) that bundles the React SPA for `evidentia serve` |
| `evidentia`              | CLI meta-package: Typer/Rich entry points (`evidentia` + `cb` alias)        |
| `evidentia-ui` *(non-Python)* | Vite + React 18 + shadcn/ui frontend; built bundle is copied into `evidentia-api` at wheel time |

The 6 v0.5.1 `controlbridge-*` deprecation shims published in v0.6.0
were removed at v0.7.0 per the public migration contract. Existing
v0.5.1 installs continue to work; future releases no longer produce
shim wheels.

### Data flow

```
┌─────────────────┐   ┌─────────────────┐   ┌────────────────────┐
│ my-controls.yaml│   │  OSCAL catalogs │   │ framework mappings │
│       .csv      │   │  (77 bundled;   │   │    (crosswalks)    │
│       .json     │   │  manifest-driven) │   └──────────┬───────┘
└────────┬────────┘   └────────┬────────┘              │
         │                     ▼                       ▼
         │           ┌──────────────────────────────────────┐
         └──────────▶│         GapAnalyzer                  │
                     │  normalize → match → score → rank    │
                     └──────────────────┬───────────────────┘
                                        │
                     ┌──────────────────┴───────────────────┐
                     │                                      │
                     ▼                                      ▼
         ┌──────────────────────┐              ┌──────────────────────┐
         │  GapAnalysisReport   │              │   RiskStatementGen   │
         │  (JSON/CSV/MD/OSCAL) │              │   (NIST SP 800-30)   │
         └──────────────────────┘              └──────────┬───────────┘
                                                          │
                                                          ▼
                                              ┌──────────────────────┐
                                              │  LiteLLM+Instructor  │
                                              │  (any LLM provider)  │
                                              └──────────────────────┘
```

### Key design decisions

- **Pydantic v2 everywhere** with `ConfigDict(use_enum_values=True, extra="forbid", str_strip_whitespace=True)`. Structured data, strict validation, JSON-roundtripping for free.
- **OSCAL as the lingua franca.** Inputs parse OSCAL catalogs and component-definitions. Outputs include OSCAL Assessment Results. Your data is portable.
- **Instructor for AI structured output.** LLMs return raw text; Instructor enforces a Pydantic schema and automatically retries on validation failure. No regex parsing of LLM output.
- **Hatchling build backend** with `[tool.hatch.build.targets.wheel] packages = ["src/..."]` and `[dependency-groups] dev = [...]` (the modern uv spec, not the deprecated `[tool.uv] dev-dependencies`).

---

## Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the detailed version-level plan.
Summary below.

### Phase 1 — MVP (v0.1.0 – v0.2.1) — SHIPPED
- [x] Core data models
- [x] OSCAL catalog loader + crosswalk engine
- [x] Multi-format inventory parser
- [x] Gap analyzer with priority scoring
- [x] Report exporters (JSON/CSV/Markdown/OSCAL-AR)
- [x] AI risk statement generator
- [x] CLI (init, catalog, gap, risk, doctor)
- [x] Sample data + end-to-end walkthrough
- [x] **Phase 1.5 (v0.2.0 big-bang):** exhaustive framework expansion
      — full upstream NIST 800-53 Rev 5 OSCAL (~1189 controls + Low/Mod/High/Privacy baselines),
      NIST 800-171 r2/r3, 800-172, CSF 2.0, AI RMF, SSDF, Privacy Framework;
      FedRAMP Rev 5 baselines; CMMC 2.0 L1/L2/L3; CJIS, CISA CPGs, HIPAA,
      GLBA, NY DFS 500, NERC CIP, FDA 21 CFR Pt 11, IRS 1075, CMS ARS;
      EU GDPR/AI Act/NIS2/DORA, UK NCSC CAF, Essential Eight, ACSC ISM,
      Canada ITSG-33/PIPEDA, NZISM; 15 US state privacy laws; Tier-C stubs
      for ISO 27001/27002/27017/27018/27701/42001/22301/9001, SOC 2 TSC,
      PCI DSS 4.0, HITRUST, COBIT, SWIFT CSCF, CIS Controls + Benchmarks,
      SCF, IEC 62443; MITRE ATT&CK, CWE, CAPEC, CISA KEV;
      `evidentia catalog import` for user-licensed Tier-C content;
      GitHub Actions refresh CI for upstream change detection.

### Compliance-as-code (v0.3.x) — SHIPPED
- [x] `evidentia gap diff` — classify gaps opened / closed / severity-changed / unchanged
- [x] `--fail-on-regression` for CI integration
- [x] `evidentia explain <control_id>` — LLM-generated plain-English control translations
- [x] Three realistic example scenarios (Meridian fintech, Acme Healthtech, Northstar DoD)

### Accessible GRC (v0.4.x) — SHIPPED
- [x] FastAPI REST server (`evidentia serve`) — 26 `/api/*` routes across 12 router modules
- [x] React + Vite + shadcn/ui web UI (WCAG 2.1 AA via Radix primitives)
- [x] Air-gapped mode (`--offline` flag + `doctor --check-air-gap` validator)
- [x] Reusable GitHub Action (`allenfbyrd/evidentia-action@v1`)

### Phase 2 — Evidence Collection (v0.5.0) — SHIPPED
- [x] Base collector architecture with `check_connection()`, `collect()`, `get_supported_controls()`
- [x] **AWS collector** — Config rules + Security Hub (FSBP / CIS)
- [x] **GitHub collector** — branch protection, CODEOWNERS, visibility
- [x] **Jira integration** — push gaps as issues + bidirectional status sync

### Rename release (v0.6.0) — SHIPPED
- [x] ControlBridge → Evidentia across code, PyPI, GitHub, docs
- [x] v0.5.1 deprecation shims for the six old PyPI names

### Enterprise-grade release (v0.7.0) — SHIPPED
- [x] SHA-256 digest per evidence item in OSCAL AR exports
- [x] Optional GPG signing of the AR document (air-gap path)
- [x] Sigstore/Rekor signing of the AR (online path, OIDC-based)
- [x] CycloneDX SBOM on every release
- [x] PyPI Trusted Publisher (OIDC) + PEP 740 attestations
- [x] OSCAL conformance via `compliance-trestle` round-trip in CI
- [x] AWS IAM Access Analyzer + GitHub Dependabot collectors
- [x] ECS-8.11 / NIST-AU-3 / OpenTelemetry structured logs
- [x] Consolidated GitHub Action at `.github/actions/gap-analysis/`
- [x] Tamper-evident audit trail for external-auditor review

### AI features hardening (v0.7.1) — SHIPPED
- [x] `GenerationContext` metadata on every AI-generated artifact (sibling of `CollectionContext`)
- [x] 9 new `evidentia.ai.*` `EventAction` entries for ECS-structured AI audit events
- [x] Typed exception hierarchy in `evidentia_ai.exceptions` — closes BLOCKER B3 for `risk_statements/` + `explain/`
- [x] Bounded retry via `with_retry_async` + `build_retrying`/`build_async_retrying` against shared `LLM_TRANSIENT_EXCEPTIONS` set
- [x] `run_id`-correlated audit trails across AI generated/failed/retry/cache_hit/batch_completed events
- [x] Best-effort operator identity via `evidentia_ai.client.get_operator_identity()` — closes NIST AU-3 "Identity" gap for AI artifacts
- [x] 116+ net new tests across `test_ai/`, `test_audit/`, `test_models/`

### Supply-chain polish + documentation refresh (v0.7.2) — SHIPPED
- [x] OpenSSF Scorecard weekly workflow (`.github/workflows/scorecard.yml`) publishing to `securityscorecards.dev`
- [x] Cursor + VS Code workspace config (`.vscode/{4 files}` + `.cursorrules` + `.editorconfig`) for testing/validation inline
- [x] `docs/ide-setup.md` walkthrough — pytest discovery, mypy strict, ruff format-on-save, coverage gutters, 7 debug configs, 16 pre-canned tasks
- [x] Catalog-drift detector fix — pinned `yaml.safe_dump(width=200)` for byte-stable manifest emit + `--ignore-all-space` workflow guard (closes issues #1-#4)
- [x] Pre-release-review refinements — 4 MEDIUM doc/config polish fixes (DORA past-tense, doc stamp date, Windows venv path, regen stderr warning)

### Later — quality signals + more integrations (v0.7.x+)
- [ ] Risk-statement quality validator (NIST SP 800-30 / IR 8286 scoring + auto-regeneration)
- [ ] Additional collectors — IAM Access Analyzer, Dependabot, Okta, Azure, GCP
- [ ] Additional integrations — ServiceNow, Vanta, Drata
- [ ] Compliance ROI scoring ("close N gaps across M frameworks with one remediation")
- [ ] Auto-generated TypeScript types from FastAPI OpenAPI schema
- [ ] Tauri desktop packaging for offline-first users

### Phase 3 — AI Evidence Validation (later)
- [ ] Evidence-to-control relevance scoring (is this screenshot actually proof of MFA?)
- [ ] Freshness / staleness detection per framework (SOC 2 = 90 days, NIST = 365)
- [ ] Multi-modal validation (PDFs, screenshots, log exports, JSON)
- [ ] Coverage heatmaps

### Platform — network deployment (later)
- [ ] Multi-user auth / RBAC for network deployments (localhost-only today)
- [ ] Multi-tenant database backend (PostgreSQL)
- [ ] Cost analytics (LLM spend per control / per framework)

### Phase 5 — Ecosystem
- [ ] Plugin system for custom collectors
- [ ] OSCAL catalog marketplace / community contributions
- [ ] Integration with policy-as-code tools (OPA, Cedar)
- [ ] Terraform provider for compliance-as-code

See [`Evidentia-Architecture-and-Implementation-Plan.md`](Evidentia-Architecture-and-Implementation-Plan.md)
for the full canonical plan (~318 KB) including all code sketches, data
flows, and technology rationales.

---

## Development

### Project layout

```
Evidentia/
├── packages/
│   ├── evidentia-core/         # Pydantic models, catalogs, gap analyzer
│   ├── evidentia-ai/           # LiteLLM client, risk generator, explain
│   ├── evidentia-collectors/   # AWS (Config + Security Hub), GitHub
│   ├── evidentia-integrations/ # Jira (push + sync)
│   ├── evidentia-api/          # FastAPI REST server + bundled SPA
│   ├── evidentia/              # CLI meta-package (Typer entry points)
│   └── evidentia-ui/           # Vite + React + shadcn/ui frontend
├── tests/
│   ├── fixtures/                   # Sample inventories + recorded fixtures
│   ├── unit/                       # Unit tests (per-package subtrees)
│   └── integration/                # CLI + examples smoke tests
├── examples/
│   ├── meridian-fintech/           # Realistic fintech walkthrough
│   ├── acme-healthtech/            # HIPAA-focused scenario
│   └── northstar-systems/          # DoD / CMMC scenario
├── docs/
│   ├── ROADMAP.md                  # Version-level plan
│   ├── air-gapped.md               # `--offline` mode guide
│   ├── architecture/               # Deep-dive docs
│   ├── github-action/              # Reusable action docs
│   └── gui/                        # Web UI guide
├── .github/
│   ├── workflows/test.yml          # CI: pytest matrix + ruff + mypy
│   ├── workflows/release.yml       # Auto-release on main-branch deploys
│   └── ISSUE_TEMPLATE/             # Bug report / feature request
└── pyproject.toml                  # uv workspace root
```

### Run tests

```bash
uv run pytest tests/ -q                       # All tests
uv run pytest tests/unit/ -v                  # Unit tests with verbose output
uv run pytest tests/unit/test_gap_analyzer/   # One subpackage
```

### Add a new framework catalog

1. Drop an OSCAL catalog JSON file in `packages/evidentia-core/src/evidentia_core/catalogs/data/<framework-id>.json`.
2. Register its metadata in `catalogs/registry.py` under `FRAMEWORK_METADATA`.
3. Optionally add crosswalks in `catalogs/data/mappings/`.
4. Run `evidentia catalog list` — your framework should appear.

### Code style

- Python 3.12+ syntax: `str | None`, `list[str]`, `from datetime import UTC`
- `from __future__ import annotations` at the top of every module
- Ruff + mypy (configured in `pyproject.toml`)

---

## Contributing

Phases 1, 1.5, 2 (Jira + AWS + GitHub), and Accessible GRC (v0.4.x web UI
+ air-gap mode) are shipped. High-value contribution areas:

- **Additional crosswalks** — especially ISO 27001 ↔ NIST 800-53 and PCI DSS ↔ SOC 2
- **Queued collectors** — IAM Access Analyzer, Dependabot, Okta, Azure, GCP
- **Queued integrations** — ServiceNow, Vanta, Drata
- **Evidence chain of custody (v0.7.0)** — SHA-256 digests + GPG signing of OSCAL AR exports
- **Risk-statement quality validation** — NIST SP 800-30 / IR 8286 scoring of AI output
- **Production OSCAL catalogs** — drop-in JSON files from upstream sources
- **Test coverage** — edge cases in CSV header matching, OSCAL parsing, and air-gap guard

---

## Security

Please **do not open a public GitHub issue** for security concerns.
See [`SECURITY.md`](SECURITY.md) for the disclosure process —
GitHub Private Vulnerability Reporting is the preferred channel;
email is documented as a backup. The policy also covers the
supported-version table, scope, disclosure timeline, and
supply-chain provenance verification.

Every release ships with cryptographic provenance: PEP 740
attestations on every wheel + sdist (Sigstore + Rekor), CycloneDX
1.6 SBOM attached to each [GitHub
Release](https://github.com/polycentric-labs/evidentia/releases).
Verification command in [`SECURITY.md`](SECURITY.md).

---

## License

[Apache License 2.0](LICENSE)

---

## Acknowledgments

Evidentia stands on the shoulders of excellent open-source projects:

- **[NIST OSCAL](https://pages.nist.gov/OSCAL/)** — the structured data standard that makes framework interop possible
- **[Pydantic](https://docs.pydantic.dev/)** — type-safe data models without the boilerplate
- **[LiteLLM](https://docs.litellm.ai/)** — unified LLM access across every provider
- **[Instructor](https://python.useinstructor.com/)** — structured output extraction from LLMs
- **[Typer](https://typer.tiangolo.com/)** and **[Rich](https://rich.readthedocs.io/)** — the CLI is only as good as the framework
- **[uv](https://docs.astral.sh/uv/)** — Python packaging that finally feels modern

## AI assistance

This project was developed alongside AI platforms.

Models used: Claude Opus 4.6, Claude Opus 4.7, Sonar Deep Research
