# Evidentia

> **Bridge the gap between your controls and your frameworks.**

**Evidentia** is an open-source, Python-first Governance, Risk, and Compliance
(GRC) platform that turns compliance from a spreadsheet problem into a software
problem. It provides composable building blocks for control gap analysis,
AI-generated risk statements, automated evidence collection, and compliance
reporting — all usable from a Python library, a CLI, or a REST API.

[![tests](https://github.com/allenfbyrd/evidentia/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/allenfbyrd/evidentia/actions/workflows/test.yml)
[![PyPI version](https://img.shields.io/pypi/v/evidentia.svg)](https://pypi.org/project/evidentia/)
![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)
![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)
[![Code of Conduct](https://img.shields.io/badge/Contributor%20Covenant-2.1-4baaaa.svg)](CODE_OF_CONDUCT.md)

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
- **82 framework catalogs bundled** — NIST 800-53 Rev 5 (full 1,196
  controls + Low/Moderate/High/Privacy baselines), CSF 2.0, FedRAMP,
  CMMC 2.0, EU AI Act, DORA, NIS2, GDPR, all 15 comprehensive US state
  privacy laws, plus 20 Tier-C licensed-stub frameworks with
  `evidentia catalog import` for your licensed copies. More than any
  commercial vendor (Vanta: 35+, Drata: 20+, RegScale: 60+).
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
  `uses: allenfbyrd/evidentia/.github/actions/gap-analysis@v0` and every
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

## Current status: 82 frameworks bundled, full suite passing

### Recent releases

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
demo. 1256 tests passing (+156 new). Ship summary:
[docs/v0.7.8-plan.md](docs/v0.7.8-plan.md).

**v0.7.7 (May 2026)** — *SQL family evidence collectors*. Five
read-only relational-DB adapters (`[sql-postgres]`, `[sql-mysql]`,
`[sql-sqlite]`, `[sql-mssql]`, `[sql-oracle]`) mapping DB-resident
compliance evidence to NIST 800-53 controls. Plus ServiceNow
output integration carry-forward. Ship summary:
[docs/v0.7.7-plan.md](docs/v0.7.7-plan.md).

**v0.7.5 (May 2026)** — *container publish + critical security
batch + quick-win polish*. Container image publish to
`ghcr.io/allenfbyrd/evidentia` with cosign keyless OIDC signing;
critical security batch (P0.5: 14 HIGH py/path-injection + 1 HIGH
py/polynomial-redos + 3 MEDIUM stack-trace exposure + 4 MEDIUM
workflow permissions + URL-sanitization review); Dependabot
batch merge; OpenSSF Best Practices Badge filing; `/api/health`
hardening; `docs/troubleshooting.md`. Ship summary:
[docs/v0.7.5-plan.md](docs/v0.7.5-plan.md).

See [`CHANGELOG.md`](CHANGELOG.md) for the full version history
(v0.1.0 through v0.7.8). For forward direction, see
[`docs/v0.7.9-plan.md`](docs/v0.7.9-plan.md) (industry overlay —
TPRM + model risk + 7 new catalogs),
[`docs/v0.8.0-plan.md`](docs/v0.8.0-plan.md) (the AI moat — DFAH +
PRT + MCP + plugin contract), and
[`docs/ROADMAP.md`](docs/ROADMAP.md) (everything else).

### What works today

- **Gap analysis against 77 bundled frameworks** across four redistribution
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
git clone https://github.com/allenfbyrd/evidentia.git
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
| [Frameworks](docs/gui/screenshots/frameworks.png) | Browse all 82 bundled catalogs with tier + category filters |
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

      - uses: allenfbyrd/evidentia/.github/actions/gap-analysis@v0
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
| `evidentia-collectors`   | Evidence collection agents — AWS (Config + Security Hub), GitHub (branch protection + CODEOWNERS) |
| `evidentia-integrations` | Jira push + bidirectional status sync; ServiceNow / Vanta / Drata queued    |
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
Release](https://github.com/allenfbyrd/evidentia/releases).
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
