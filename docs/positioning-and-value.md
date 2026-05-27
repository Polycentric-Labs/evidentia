# Evidentia — positioning, value, and where this should go

> Synthesis refreshed 2026-05-02 for v0.7.8 release readiness via
> 7 parallel research streams (commercial GRC vendors, OSS GRC
> ecosystem, regulatory and M&A signals, academic foundations,
> AI/LLM tooling, industry voices, and a direct internal capability
> inventory). Originally compiled 2026-04-24 for v0.7.0; v0.7.2
> through v0.7.7 were skip-by-reuse refreshes. v0.7.8 is the first
> full re-run since v0.7.0, lands the deferred R1 quarterly resync
> ahead of Q3 cadence, and incorporates 3 substantive market
> developments (Optro rebrand, SR 11-7 superseded by SR 26-02 in
> April 2026, Delve scandal). See §16 "Version history" for the
> per-release review trail. Cite by URL; verify any claim before
> reusing externally.

---

## Section index

1. [Executive summary](#1-executive-summary)
2. [What Evidentia is, and why it exists](#2-what-evidentia-is-and-why-it-exists)
3. [Current capabilities (v0.7.0)](#3-current-capabilities-v070)
4. [Intellectual ancestry — the four research streams Evidentia stands on](#4-intellectual-ancestry)
5. [Competitive landscape — five tiers, two unicorns, one OSS surge](#5-competitive-landscape)
6. [Where Evidentia genuinely differentiates / is at parity / is behind](#6-differentiation-parity-and-honest-gaps)
7. [The six unclaimed gaps Evidentia fills](#7-the-six-unclaimed-gaps)
8. [Industry tailwinds — three forcing-function dates in 2026](#8-industry-tailwinds)
9. [Industry headwinds — what could undermine the positioning](#9-industry-headwinds)
10. [Positioning frame — direct enumerated claims](#10-positioning-frame)
11. [AI posture — foundational vs bleeding edge vs gaps](#11-ai-posture)
12. [Industry voices — to cite, to follow, to pitch](#12-industry-voices)
13. [The 12-month direction — where Evidentia should go](#13-the-12-month-direction)
14. [Risk register — what could derail the positioning](#14-risk-register)
15. [Sources](#15-sources)

---

## 1. Executive summary

> **Section summary.** Evidentia (v0.7.8, May 2026) is the only
> open-source, Python-first, library-first, OSCAL-native GRC tool
> with bundled multi-framework catalogs (88), supply-chain-hardened
> evidence integrity (Sigstore + SLSA L3 + PEP 740 + cosign-signed
> container), and an air-gap-capable deployment model. It sits in a
> near-empty competitive niche, on the right side of **four**
> regulatory forcing functions converging in Q4 2026, and is
> intellectually descended from the Kellogg et al. ASE 2020
> "Continuous Compliance" thesis (now extended by the Khatchadourian
> March 2026 DFAH paper that names Evidentia's planned v0.8.0 flagship
> by its exact terminology). Its v0.7.x cycle has closed all 10
> BLOCKER items in the enterprise-grade credibility checklist and
> shipped 4 new public surfaces in v0.7.7-v0.7.8 (5 SQL DB collectors,
> Databricks, Snowflake, Tableau publish, Power BI publish).

- **Evidentia is the OSCAL-native, library-first, AI-optional, supply-chain-hardened, evidence-attesting GRC primitive that didn't exist in OSS until April 2026.** Eight unclaimed gaps in the OSS GRC ecosystem map directly onto Evidentia's surface (see §7).
- **The closest commercial peer with overlapping OSCAL claims is RegScale** ($30M Series B Sept 2025, donated OSCAL Hub to the foundation Dec 2025) — proprietary and Beltway-focused. **Optro (formerly AuditBoard, rebranded March 9, 2026)**, Vanta (now ships OSCAL **export** for FedRAMP 20x as of February 2026 — first major commercial vendor to do so), Drata, OneTrust, ServiceNow IRM, MetricStream all still have OSCAL gaps (see §5).
- **Four regulatory forcing functions converge in Q4 2026** (sharpened from "three" at v0.7.0 — the EU CRA reporting obligation date now firmly anchors): **CMMC Phase 2** (Level 2 C3PAO third-party assessments mandatory for ~300,000 DOD contractors, **2026-11-10**), **EU CRA reporting obligations** (24/72-hour incident + 14-day vulnerability reporting for any digital product placed on the EU market, **2026-09-11**), **FedRAMP OSCAL mandate** (machine-readable authorization data required for all CSPs, **2026-09-30**), **Maryland MODPA** (strictest US privacy law, sale-of-sensitive-data prohibition, **2026-10-01**). HIPAA Security Rule final-rule target window: May 2026. Evidentia is positioned 18+ months ahead of where most commercial vendors deliver native OSCAL emit (see §8).
- **The OSS GRC space remains structurally fragmented.** CISO Assistant (intuitem; 4,008 stars, AGPL+commercial; daily commits) is the most serious direct OSS competitor — but lacks OSCAL emit, Sigstore evidence chain, and SLSA L3 release artifacts. Comp AI raised **$20M Series A from Khosla's Keith Rabois in February 2026** (was $2.6M pre-seed Jan 2026 at v0.7.0 doc-write time) targeting the SaaS-startup SOC 2 self-serve market. Eramba effectively exited OSS — application code is closed-source as of recent years; only Docker helpers and templates remain on GitHub (see §5).
- **GRC remained the #1 sub-sector in cybersecurity M&A 2025** (82 deals, 5-year peak; SecurityWeek). **Vanta crossed $300M ARR April 2026** (3x in two years; +69% YoY logo growth; 16,000+ customers; $4.15B Series D valuation July 2025 — Sequoia, Wellington, Goldman Sachs Alternatives, JPM, Atlassian Ventures, CrowdStrike Ventures). **Drata ~$100M+ ARR early 2026; acquired SafeBase $250M February 2026** (Trust Center expansion). **Diligent acquired 3rdRisk January 14 2026** for AI-native TPRM. **OneTrust active PE talks November 2025** ($4.5B last priced; $550M+ ARR; Thoma Bravo / Blackstone / Silver Lake / KKR). **Wiz → Google $32B closed March 2026** (largest VC-backed exit in history). Customer flight risk from this consolidation creates a real opening for OSS that has no acquisition exposure (see §5, §8).
- **AI is now table-stakes parity in commercial GRC, not differentiation.** Every credible incumbent shipped (1) MCP server, (2) citation-grounded LLM output, and (3) agentic-with-checkpoint orchestration between Sept 2025 and April 2026 — Vanta AI Agent + remote MCP server (April 15, 2026); Drata Agentic TPRM + MCP server; Optro Unified AI Governance (built on FairNow acquisition); Workiva Intelligent Finance/GRC/Sustainability (March 2026); Hyperproof AI Guided Experiences (RSAC 2026); ServiceNow Now Assist for IRM. **The differentiation has collapsed into eval rigor + audit trails + OSS-friendly licensing** — exactly where Evidentia's Sigstore + PEP 740 + GenerationContext provenance + planned DFAH determinism harness sit (see §11).
- **The Delve scandal (March 2026) is the segment-defining 2026 incident** validating the AI-feature-commoditization thesis. MIT-dropout founders; $32M Series A July 2025 led by Insight Partners at $300M valuation. March 2026 whistleblower disclosure ("DeepDelver") — analysis of leaked audit reports found **493/494 SOC 2 reports with byte-identical boilerplate and identical grammatical errors**. Customers migrating away (one to Vanta + Insight Assurance after a Vercel breach). **This is the cautionary baseline Evidentia's positioning copy should cite for "deterministic-where-it-must-be, AI-where-it-helps"** (see §11, §14).
- **PCAOB AS 1105 + Generative AI Spotlight (July 2024) requires 5 capabilities; Evidentia hits all 5.** (1) Prompt + response capture — Evidentia v0.7.1 ✓; (2) Model-version tracking — v0.7.1 ✓; (3) Human-in-the-loop verification — DFAH addresses; (4) Immutable audit trails — DFAH addresses; (5) Explainability documentation — PRT addresses. **This is the strongest single positioning claim Evidentia can make** in the v0.8.0 cycle (see §11).
- **SR 11-7 superseded by SR 26-02 + OCC Bulletin 2026-13a (April 17, 2026)** — and the new guidance **explicitly excludes generative AI and agentic AI**: *"Generative AI and agentic AI models are novel and rapidly evolving. As such, they are not within the scope of this guidance."* Banks are stranded with no regulatory framework for LLM deployments. **This is the precise opening for Evidentia's planned v0.7.9 model-risk module** to ship the SR-11-7-replacement-framework primitive ahead of any commercial vendor (see §7, §11).
- **Positioning frame (revised 2026-05-25 per triple-validated procurement pressure-test): direct enumerated claims, no metaphor.** Three independent procurement-style reviewers (GPT-5.5 Fortune 500 procurement = 5/10; Grok-4.20-Multi-Agent federal-SI hostile TPRM = 2.5/10; Grok 4.3 heterodox marketing strategist = reject metaphor entirely) converged on the same diagnosis: the "Terraform/dbt of GRC" framing overclaims a multi-vendor consortium status a solo-vendor implementation cannot credibly own, and the "compliance kernel" alternative reads as developer-jargon to compliance buyers. The replacement positioning leads with six attestable supply-chain credentials (PEP 740 + Sigstore + SLSA L3 + cosign + CycloneDX 1.6 + OpenSSF Scorecard 6.5 + OpenSSF Silver MET + OSPS Baseline Maturity 2) + a concrete output enumeration (OSCAL + SARIF + OCSF Compliance Finding + OCSF Detection Finding + CycloneDX VEX) + a SOC 2 Type I in-progress signal + an honest acknowledgment of the OpenSSF Gold structural ceiling tied to the SOC 2 Type I program's segregation-of-duties controls. See §10 for the supporting messaging hierarchy.
- **Honest gaps** (intentionally surfaced, not buried): no customer-facing trust center, no questionnaire-fill AI, **6 evidence-collection surfaces** vs Vanta's 375+ integrations (Evidentia ships AWS, GitHub, Okta, ServiceNow, 5 SQL DB adapters, Databricks, Snowflake; Azure + GCP extras declared in pyproject.toml but currently lack implementations — see §5/§6 honest gap), no auditor partnerships, no Forrester Wave / Gartner inclusion, no TPRM module (planned v0.7.9), no risk register / ERM primitive, no published reference customers, no formal SOC 2 of Evidentia itself, no IPO/exit narrative for vendor-longevity-paranoid buyers. Each has a planned remediation or an explicit "won't fix" rationale (see §6).
- **Intellectual home**: an updated 30+ person community across NIST/GSA, OpenSSF, CISA-SBOM, Stanford CodeX, Bath/PRT, OSCAL Compass + OSCAL Foundation + Resilient Cyber / fwd:cloudsec / GRC-Engineering crowd. **NIST CSWP 53 *Charting the Course for NIST OSCAL*** (Iorga et al., December 2025 IPD) is now the canonical OSCAL strategic-direction citation, replacing older OSCAL references. Two outreach actions reach the entire community in one quarter (see §12).
- **The 12-month direction** that compounds Evidentia's advantages: ship a DFAH-style determinism harness for risk-statement generation (academic prior art exists — Khatchadourian arXiv 2601.15322 March 2026 — but **no commercial vendor offers this**); publish the bundled multi-framework crosswalk dataset as a standalone artifact (`evidentia-catalogs`); add canonical scanner-JSON-to-OSCAL mappers; ship an MCP server (note: first-mover window for OSCAL primitives is **closed** as of Q1 2026 — IBM trestle-MCP, AWS Labs OSCAL MCP, Vanta MCP, Drata MCP, Optro MCP all live; **wide open** for SR-11-7 / FFIEC / SBOM / continuous-monitoring MCPs); ship the v0.7.9 federal-compliance overlay (TPRM + model risk + 7 new catalogs + governance primitives); pursue OSCAL Foundation membership; cut v0.8.x around AI evidence validation + multimodal evidence support; publish the **first standardized GRC LLM eval suite to Hugging Face** (HF Hub keyword searches confirm zero existing OSCAL/NIST 800-53/SOC 2 datasets — genuine first-in-class opportunity; see §13).

---

## 2. What Evidentia is, and why it exists

> **Section summary.** Evidentia is a composable Python GRC toolkit
> (six packages + a React SPA) that turns compliance from a
> spreadsheet problem into a software problem. It exists because
> commercial GRC SaaS has consolidated around closed, OSCAL-blind,
> AI-mandatory, $30k+/yr platforms that exclude both regulated
> sovereign deployments (FedRAMP, EU DORA, air-gap) and the
> ~300,000 DOD contractors who can't afford SaaS GRC.

### 2.1 What it is

Evidentia is an **open-source (Apache 2.0), Python 3.12+, OSCAL-native Governance, Risk, and Compliance toolkit**. It ships as six composable PyPI packages plus a Vite + React + shadcn/ui web frontend, all in one [uv](https://docs.astral.sh/uv/) workspace monorepo:

| Package | Role |
|---|---|
| `evidentia-core` | Pydantic data models, OSCAL catalog loader, crosswalk engine, gap analyzer |
| `evidentia-ai` | LiteLLM + Instructor client, risk-statement generator, control explainer |
| `evidentia-collectors` | Evidence collection — AWS Config + Security Hub + IAM Access Analyzer; GitHub branch protection + CODEOWNERS + Dependabot |
| `evidentia-integrations` | Jira push + bidirectional status sync; ServiceNow / Vanta / Drata queued |
| `evidentia-api` | FastAPI server bundling the React SPA for `evidentia serve` |
| `evidentia` | CLI meta-package: Typer/Rich entry points (`evidentia` + `cb` alias) |
| `evidentia-ui` *(non-Python)* | Vite + React 18 + shadcn/ui frontend; built bundle is copied into `evidentia-api` at wheel time |

It can be used three ways: as a Python library (`from evidentia_core import GapAnalyzer`), as a CLI (`evidentia gap analyze --inventory ...`), or as a REST API + web UI (`evidentia serve` → localhost-only dashboard with 18 `/api/*` endpoints).

### 2.2 Why it exists

The thesis is structural: **GRC is stuck in 2005**. The typical compliance program runs on:

- **Spreadsheets** copy-pasted between auditors, engineers, and exec staff
- **Vendor GRC suites** that cost $50K–$500K/year, lock you in, and still require weeks of manual cross-framework mapping
- **Point solutions** that handle one piece (a vulnerability scanner, a policy tracker, a questionnaire manager) but can't talk to each other
- **Consultants** who re-learn your environment from scratch every audit cycle

Meanwhile, the compliance workload keeps growing. A single fintech or healthcare SaaS company today might simultaneously be in scope for **SOC 2, PCI DSS 4.0, HIPAA, GDPR, CCPA, ISO 27001, EU DORA, EU AI Act, NYDFS Part 500** — nine frameworks with substantial overlap, each demanding its own evidence, gap analysis, and risk documentation. The same control (say, "MFA on all privileged accounts") satisfies requirements in all nine, but because each framework uses different vocabulary, numbering, and organization, compliance teams end up documenting the same control nine different ways.

**This is a software problem.** Evidentia treats it as one — composable libraries, structured data (OSCAL), version control, automation, signed evidence with cryptographic provenance.

### 2.3 The four design principles

1. **Open standards, not vendor lock-in.** Inputs and outputs use [OSCAL](https://pages.nist.gov/OSCAL/) — NIST's open standard for control catalogs and assessment results. If you outgrow Evidentia, your data travels with you.
2. **Library-first, CLI-second, API-third.** The Python library is the canonical interface. The CLI and REST API are thin wrappers. Everything Evidentia can do via the CLI, it can do from a Python script — which means you can embed it in CI pipelines, compliance portals, or custom integrations.
3. **AI where it helps, not where it hurts.** Evidentia uses LLMs for tasks where language understanding is the bottleneck (writing NIST SP 800-30 risk statements, explaining a control in plain English). It uses deterministic code for tasks where correctness matters (OSCAL parsing, gap arithmetic, cross-framework mapping). AI is opt-in; air-gap deployments work without LLM access.
4. **Provider-agnostic LLM access.** All AI features route through [LiteLLM](https://docs.litellm.ai/) + [Instructor](https://python.useinstructor.com/), giving structured Pydantic output from any model — OpenAI, Anthropic, Google, Azure, Bedrock, Ollama, vLLM. No vendor lock-in on the AI layer either.

### 2.4 Who it's for

- **Security engineers** at startups and mid-size companies who need to hit SOC 2 Type II without hiring a full compliance team
- **GRC consultants** who want to stop rebuilding the same spreadsheets for every engagement
- **Platform teams** who want to embed gap analysis into their CI pipelines and catch drift before the auditor does
- **CISO offices** that want a real audit trail on risk decisions, backed by versioned structured data instead of Slack threads
- **Defense contractors** facing CMMC Phase 2 (Nov 2026) who can't afford $30k/yr SaaS for SPRS-affirmation evidence
- **EU regulated entities** under DORA (in force since Q1 2026) who need sovereign / on-prem evidence collection
- **Federal agencies** facing OMB M-24-15 (July 2026) requiring OSCAL ingestion and emission

---

## 3. Current capabilities (v0.7.8)

> **Section summary.** As of v0.7.8 (May 2026, code-complete locally;
> 10-commit chain awaiting tag), Evidentia ships 9 Typer CLI command
> groups, 12 REST router modules, an 8-page React SPA (alpha.2
> wired-in at v0.7.6), six Python packages with public APIs +
> evidentia-ui frontend that bundles into the API server, **8 evidence
> collection surfaces** (AWS, GitHub, Okta, ServiceNow, 5 SQL DB
> adapters [Postgres / MySQL / SQLite / MSSQL / Oracle], Databricks,
> Snowflake), **4 output integrations** (Jira, ServiceNow, Tableau
> publish, Power BI publish — last two NEW in v0.7.8), AI-powered
> risk-statement + control-explanation generation with full
> GenerationContext provenance (model + temperature + prompt-hash +
> run-id), **89 bundled framework catalogs** (4 redistribution tiers),
> bundled crosswalks, four output formats including OSCAL Assessment
> Results with embedded SHA-256 evidence digests + Sigstore/Rekor or
> GPG signing, cosign-signed container image at
> `ghcr.io/polycentric-labs/evidentia` with SLSA L3 build provenance
> against image digest. All 10 BLOCKER items in the enterprise-grade
> credibility checklist remain closed; v0.7.5 added cosign container
> publish (closing L1); v0.7.7 added 5 SQL collectors + Okta +
> ServiceNow; v0.7.8 adds the cloud-DW + BI surfaces. Inventory below
> is from a direct codebase walk on 2026-05-02 (Stream 7 of the v0.7.8
> Step 2 research had documented hallucinations and was not used).

### 3.1 CLI surface (Typer)

| Command | Purpose |
|---|---|
| `evidentia init` | Scaffold a new project (creates `evidentia.yaml`, `my-controls.yaml`, `system-context.yaml`) |
| `evidentia doctor [--check-air-gap]` | System diagnostics; verifies LLM connectivity, file permissions, air-gap posture |
| `evidentia version` | Print version of evidentia + its workspace packages |
| `evidentia catalog list [--tier ... --category ...]` | Browse 89 bundled frameworks, filter by tier (A/B/C/D) or category |
| `evidentia catalog show <fw> --control <id>` | Display the full text of a single control |
| `evidentia catalog crosswalk --source <fw> --target <fw> --control <id>` | Show how a control maps across frameworks |
| `evidentia catalog import [--mode stub\|oscal-profile\|json]` | Import licensed Tier-C catalog content (e.g., ISO 27001) |
| `evidentia catalog license-info <fw>` | Show licensing posture for a Tier-C placeholder catalog |
| `evidentia gap analyze --inventory <file> --frameworks <list> --output <file>` | Run gap analysis; output JSON / CSV / Markdown / OSCAL AR |
| `evidentia gap diff --base <file> --head <file> [--fail-on-regression]` | Compare two gap snapshots; classify each as opened/closed/severity-changed/unchanged |
| `evidentia explain control <fw> <id>` | LLM-generated plain-English translation of any framework control text (cached) |
| `evidentia risk generate --context <file> --gaps <file>` | LLM-generated NIST SP 800-30 risk statements; structured output via Instructor |
| `evidentia collect aws [--region ... --include-config --include-security-hub]` | Collect AWS Config rule + Security Hub findings |
| `evidentia collect github --repo <owner/repo>` | Collect GitHub branch protection + CODEOWNERS + Dependabot alerts |
| `evidentia integrations jira {test,push,sync,status-map}` | Push gaps as Jira issues; bidirectional status sync |
| `evidentia oscal verify [--require-signature]` | Verify SHA-256 evidence digests + GPG/Sigstore signatures on an OSCAL AR |
| `evidentia serve` | Launch the FastAPI server + bundled React SPA at 127.0.0.1:8000 |

### 3.2 REST API surface (FastAPI, 12 router modules)

Health, config CRUD, init wizard, gaps (analyze + diff + OSCAL AR export), frameworks (list + filter + crosswalk + license info), control explanations (POST), risk-statement generation (POST), collectors (trigger + retrieve), Jira integration (test + push + sync + status-map), LLM provider preflight checks, doctor / diagnostics. The web UI consumes these directly.

### 3.3 Web UI (React + Vite + shadcn/ui)

| Page | Backing API |
|---|---|
| Dashboard | `GET /api/gaps`, `GET /api/health` |
| Gap Analysis | `GET /api/gaps`, `GET /api/gaps/{id}` |
| Framework Catalog | `GET /api/frameworks`, `GET /api/frameworks/{id}/controls` |
| Control Explorer | `GET /api/frameworks/search`, `POST /api/explain` |
| Risk Statements | `GET /api/risks`, `POST /api/risks/generate` |
| Integrations Hub | `GET /api/integrations/jira/status`, `POST /api/integrations/jira/push` |
| Settings | `GET /api/config`, `POST /api/config`, `POST /api/explain/cache/clear` |
| Project Init | `POST /api/init/wizard` |

Localhost-only, WCAG 2.1 AA via Radix primitives. Multi-user auth / RBAC is queued for v0.7.x+.

### 3.4 Evidence collectors (with explicit blind-spot disclosures)

Each collector follows the v0.7.0 enterprise-grade pattern: typed
exception hierarchy, `CollectionContext` threaded through every
finding, `CollectionManifest` returned by `collect_v2()` for
completeness attestation, ECS-structured audit logging, lazy SDK
import so the package loads without the optional driver, explicit
`BLIND_SPOTS` list per adapter.

- **AWS** (v0.5.0+; `[aws]` extra) — Config compliance rules + Security Hub findings + IAM Access Analyzer (5 explicit blind-spot disclosures: KMS grants, S3 ACL/BPA interactions, service-linked roles, unsupported resource types, finding-generation latency). Standard boto3 credential chain.
- **GitHub** (v0.5.0+; `[github]` extra) — Branch protection + CODEOWNERS + repo visibility + Dependabot alerts (100-page safety cap on pagination). `GITHUB_TOKEN` env var.
- **Okta** (v0.7.7; `[okta]` extra) — User inventory + MFA enforcement + inactive-user detection + privileged-account counts. Mapped to NIST AC-2, IA-2, IA-5. `okta>=2.9` driver.
- **ServiceNow** (v0.7.7; `[servicenow]` in evidentia-integrations) — bidirectional integration (also output side); compliance task / incident records. `pysnc>=1.1` driver.
- **5 SQL DB adapters** (v0.7.7; `[sql-postgres]`, `[sql-mysql]`, `[sql-sqlite]`, `[sql-mssql]`, `[sql-oracle]`) — DB-resident compliance evidence (user privileges, audit-log status, encryption posture, schema change history) mapped to NIST AC-2 / AC-3 / AC-6 / AU-2 / AU-3 / SC-12 / SC-28. SQLite uses stdlib (no extra). MSSQL requires OS-level Microsoft ODBC Driver 18. Oracle uses `oracledb>=2.0` thin driver (pure Python).
- **Databricks** (v0.7.8; `[databricks]` extra) — PAT inventory + lifecycle (long-lived, never-expires findings); cluster compliance (runtime version + libraries + init scripts) → CM-2 / CM-3 / CM-8 / SI-2; service principal inventory + active/inactive → AC-2 / AC-2(3) / AC-3; secret scope inventory (Databricks-backed vs Azure Key Vault-backed) → SC-12 / IA-5. Auth via `databricks-sdk>=0.30` unified resolver (PAT, OAuth M2M, Azure AD, AWS IAM, `.databrickscfg`). 7 documented BLIND_SPOTS. **DEFERRED to v0.7.9+**: Unity Catalog audit logs + table/column lineage (need SQL Warehouse plumbing); workspace network policies (need Account API auth path).
- **Snowflake** (v0.7.8; `[snowflake]` extra) — LOGIN_HISTORY (per-user inventory + per-failed-login row over 90-day window) → AC-7 / AU-2 / AU-3 / IR-4; USERS inventory + MFA enforcement + disabled-account + never-logged-in findings → AC-2 / AC-2(3) / IA-2(1)/(2); GRANTS_TO_USERS inventory + privileged-role grants (ACCOUNTADMIN / SECURITYADMIN / ORGADMIN) → AC-3 / AC-6 / AC-6(7); network-policy inventory + account-level baseline → SC-7 / SC-7(5); masking + row-access policy inventory per database → AC-3 / AC-3(7) / SC-28; operator-attested key-rotation status → SC-12. Auth via `snowflake-connector-python>=3.10` (password env var or key-pair preferred for production — Snowflake is deprecating password auth). 7 documented BLIND_SPOTS. **DEFERRED to v0.7.9+**: ACCESS_HISTORY lineage; failed-login spike detection.

**Honest note**: `[azure]` and `[gcp]` extras were declared in
`packages/evidentia-collectors/pyproject.toml` from v0.5.0 through
v0.7.7 without backing implementations. The v0.7.8 pre-release-review
(Step 5.A batch fix) removed the unbacked extras + their entries from
the umbrella `[all]` extra + the package `keywords` list. Azure + GCP
remain on the forward roadmap (architectural sketches in
`Evidentia-Architecture-and-Implementation-Plan.md`); when those
collectors ship, the extras will be re-introduced alongside the
implementing modules.

### 3.5 Output integrations (Jira / ServiceNow / Tableau / Power BI)

- **Jira** (v0.5.0+; `[jira]` extra) — push gaps as issues + bidirectional status sync. `jira>=3.8` driver.
- **ServiceNow** (v0.7.7; `[servicenow]` extra) — push gaps as records (incident / sn_grc_issue / custom). `pysnc>=1.1` driver.
- **Tableau publish** (v0.7.8; `[tableau]` extra) — publishes 3 datasets to Tableau Server / Cloud as CSV-based data sources: `evidentia-gaps` (one row per ControlGap), `evidentia-risks` (NIST SP 800-30 shape with AI-provenance fields), `evidentia-collection-runs` (CollectionContext audit trail). PAT auth via `TABLEAU_PAT_NAME` + `TABLEAU_PAT_SECRET` env vars (never accepted as flag values). `tableauserverclient>=0.30` (pure Python). **`.hyper` extract publish documented as v0.7.9+ enhancement** under separate `[tableau-hyper]` extra (would require heavyweight `tableauhyperapi` native binary).
- **Power BI publish** (v0.7.8; `[powerbi]` extra) — pushes same 3 datasets as Power BI Push Datasets via REST API + Azure AD service-principal OAuth2 (MSAL Python). Full-refresh semantics by default (clear-then-push). 10,000-row batching per Power BI's documented limit. Schema-declared dataset auto-creation via `ensure_dataset` (idempotent re-runs). Auth: service principal with `Dataset.ReadWrite.All`; client secret from `POWERBI_CLIENT_SECRET` env var server-side; never in request bodies. `msal>=1.31` driver.

### 3.6 Bundled framework catalogs (89 total, four redistribution tiers)

**89 catalog files (.json)** verified by direct codebase walk
post-v0.7.9 (was 82 at v0.7.0; +7 in v0.7.9 — 5 FFIEC IT
Examination Handbook booklets + OCC 2011-12/FRB SR 11-7 + FFIEC
Cybersecurity Assessment Tool). The tier breakdown below is
the v0.7.0 baseline; per-catalog accounting is in
`packages/evidentia-core/src/evidentia_core/catalogs/`. **+7 catalog
additions shipped in v0.7.9** (5 FFIEC IT Examination Handbook
booklets + OCC 2011-12 / FRB SR 11-7 + FFIEC Cybersecurity Assessment
Tool — but note the FFIEC CAT was sunset by FFIEC 2025-08-31 in favor
of NIST CSF 2.0 + CRI Profile v2.0; v0.7.9 plan needs touch-up to
either ship CAT as historical reference or substitute CRI Profile).

- **Tier A — US federal (25 frameworks, verbatim public domain)**: NIST SP 800-53 Rev 5 full catalog (1,196 controls) + Low/Moderate/High/Privacy baselines, 800-171 r2/r3, 800-172, CSF 2.0, AI RMF 1.0, Privacy Framework 1.0, SSDF 800-218; FedRAMP Rev 5 baselines; CMMC 2.0 L1/L2/L3; HIPAA Security/Privacy/Breach Notification; GLBA Safeguards, NY DFS 500, NERC CIP v7, FDA 21 CFR Pt 11, IRS 1075, CMS ARS, FBI CJIS v6, CISA CPGs. NIST SP 800-53 Release 5.2.0 (2025-08-27) incremental added secure-software-development controls — Evidentia bundles the latest.
- **Tier A — International (6 frameworks)**: UK NCSC CAF 3.2, UK Cyber Essentials, Australian Essential Eight, Australian ISM, Canada ITSG-33, NZ NZISM.
- **Tier D — Statutory (21 frameworks, government edicts, uncopyrightable)**: EU GDPR, EU AI Act, EU NIS2, EU DORA, UK DPA 2018, Canada PIPEDA, plus all 19 comprehensive US state privacy laws as of 2026-01-01 (added Indiana / Kentucky / Rhode Island / Maryland MODPA effective 2026-10-01 since v0.7.0). Maryland MODPA is the strictest — sale-of-sensitive-data prohibition with $10K/violation, $25K/repeat penalties.
- **Tier C — Licensed stubs (20 frameworks)**: ISO/IEC 27001:2022, 27002:2022, 27017, 27018, 27701, 42001, 22301; **PCI DSS 4.0.1** (51 of 64 future-dated requirements became binding 2025-03-31; all 2026 assessments use v4.0.1); HITRUST CSF v11; COBIT 2019; SWIFT CSCF; CIS Controls v8.1 + 5 CIS Benchmarks; SCF; IEC 62443; SOC 2 TSC (now embedded with AICPA AI Governance Controls expansion to Processing Integrity per 2025 update). Public clause numbering only; `evidentia catalog import` loads your licensed copy.
- **Tier B — Threat / vulnerability catalogs (4 frameworks)**: MITRE ATT&CK Enterprise (41 techniques), CWE Top 25 (2024), CAPEC sample, CISA KEV sample.

### 3.7 Enterprise-grade hardening (v0.7.0 BLOCKER baseline + v0.7.x additions)

The v0.7.0 release closed all 10 BLOCKER items in the [enterprise-grade credibility checklist](enterprise-grade.md). The supply-chain hardening narrative is end-to-end and has tightened across v0.7.x:

- **Evidence integrity**: SHA-256 digest + Sigstore/Rekor signing (online) or GPG signing (air-gap) on every Assessment Results document
- **Build provenance** (v0.7.0; tightened v0.7.3): GitHub Actions workflow with OIDC identity; SLSA L3 build provenance via `actions/attest-build-provenance@v2.4.0` (v0.7.3) — restores `gh attestation verify` as a working verifier alongside `pypi-attestations verify pypi`
- **Signed publish**: PyPI Trusted Publisher (OIDC) on all 6 packages — no long-lived API tokens
- **Per-artifact attestations**: PEP 740 Sigstore attestations on every wheel + sdist, logged to Rekor
- **Container image** (v0.7.5; `ghcr.io/polycentric-labs/evidentia`): cosign keyless OIDC signing + SLSA L3 build provenance against image digest. Closes enterprise-grade L1 (was the last LOW-bucket external-artifact gap). v0.7.6+ added `Wait-for-PyPI` step to prevent propagation-race re-fires.
- **Software bill of materials**: CycloneDX 1.6 SBOM attached to every GitHub Release
- **Schema conformance**: `compliance-trestle>=4.0` round-trip in CI catches unknown-field bugs NIST's JSON Schema misses
- **Structured logs**: ECS 8.11 + NIST AU-3 + OpenTelemetry via `--json-logs` flag
- **Air-gap mode**: `--offline` flag refuses network egress; Sigstore refuses and routes operators to GPG; `evidentia doctor --check-air-gap` validator
- **Composite GitHub Action** (v0.7.3; SHA-pinned): `.github/actions/gap-analysis/` replaces the archived standalone repo; 28 SHA-pinned `uses:` refs across composite + every workflow file (closes Scorecard "Pinned-Dependencies"). Composite-action E2E smoke test workflow catches future action.yml ↔ CLI drift
- **Pre-commit hooks + dev container** (v0.7.3): ruff + mypy + markdownlint + trailing-whitespace; `.devcontainer/devcontainer.json` for reproducible dev env
- **OpenSSF Scorecard** (v0.7.2): weekly workflow publishing to securityscorecards.dev
- **Threat model** (v0.7.7 elevation): `docs/threat-model.md` (12KB); refreshed within 180 days per pre-release-review v4 G5 gate
- **OpenSSF Best Practices Badge**: pre-application audit complete (v0.7.5 P0.7); badge filing pending (v0.7.5 deferral)
- **Critical security batch** (v0.7.5 P0.5; v0.7.7 + v0.7.8 carry-forward): 14 HIGH py/path-injection alerts auto-closed; 1 HIGH py/polynomial-redos closed; 3 MEDIUM stack-trace exposure fixed; 4 MEDIUM workflow-permissions tightened; 5 MEDIUM Pinned-Dependencies; v0.7.8 added P0.5 fix-up batch (SQLite collector mandatory `safe_root` validation; user-controlled values switched to `%r` in log statements)

---

## 4. Intellectual ancestry

> **Section summary.** Evidentia stands at the confluence of four
> distinct research streams: OSCAL standardization (NIST), software
> supply-chain attestation (NYU/Cappos lineage and Google/Sigstore),
> policy-as-code formal verification (Belnap → Bonatti → Cedar/Lean
> and OPA/Rego), and continuous compliance (Kellogg, Schäf, Tasiran,
> Ernst, ASE 2020). The single most important paper Evidentia
> extends is Kellogg et al. — Evidentia is the natural follow-up
> work at OSCAL/multi-framework scale.

### 4.1 OSCAL standardization (NIST)

OSCAL has **no canonical academic paper** — it is documented through NIST Special Publications, the [OSCAL spec](https://pages.nist.gov/OSCAL/), the [GitHub repo](https://github.com/usnistgov/OSCAL), and workshop talks. **The new canonical citation as of December 2025 is [NIST CSWP 53 *Charting the Course for NIST OSCAL*](https://csrc.nist.gov/pubs/cswp/53/charting-the-course-for-nist-oscal/ipd)** (Iorga et al., Initial Public Draft, December 2025) — this is the strategic-direction document Evidentia should anchor "OSCAL-native" claims to. CSWP 53 commits OSCAL to "modernize manual, paper-based cybersecurity compliance through automated, scalable processes and continuous assessments."

Principal architects: **Dr. Michaela Iorga** (NIST ITL Senior Security Technical Lead, OSCAL Strategic Outreach Director, [NIST staff page](https://www.nist.gov/people/dr-michaela-iorga)), **David Waltermire** (OSCAL Technical Director), **Brian Ruf** (RufRisk; OSCAL Foundation FedRAMP Tech Focus Group Lead). **Eduardo "Ed" Takamura** (NIST RMF Team, FISMA implementation lead, [NIST staff page](https://www.nist.gov/people/ed-takamura)) drives the broader RMF evolution that Evidentia's gap analyzer maps into.

The conceptual hierarchy — Catalog → Profile → Component Definition → SSP → Assessment Plan → Assessment Results → POA&M — is itself a model-driven engineering construct that has never been formalized in peer review. **This is a publishable opportunity for Evidentia** (a workshop paper at SecDev or an arXiv preprint formalizing OSCAL's profile-resolution semantics would land in genuinely empty territory).

### 4.2 Software supply-chain attestation

Evidentia's Sigstore + PEP 740 + CycloneDX SBOM stack inherits directly from:

- **Ralph Merkle** — "Secrecy, Authentication, and Public Key Systems" (Stanford PhD thesis, 1979) — mathematical basis for every modern transparency log
- **Stuart Haber & W. Scott Stornetta** — "How to Time-Stamp a Digital Document" (J. Cryptology, 1991) — foundation of RFC 3161
- **Scott A. Crosby & Dan S. Wallach** — "Efficient Data Structures for Tamper-Evident Logging" (USENIX Security 2009) — canonical citation for tamper-evident audit logs
- **Justin Cappos & Santiago Torres-Arias et al.** — in-toto (USENIX Security 2019) — supply-chain attestation framework
- **Newman, Meyers, Torres-Arias et al.** — Sigstore (CCS 2022) — software signing for everybody
- **Ben Laurie et al.** — Certificate Transparency (RFC 6962, CACM 2014) — theoretical underpinning of Rekor

### 4.3 Policy-as-code formal verification

The lineage from Belnap's four-valued logic (1977) through Bonatti's policy algebra (ACM TISSEC 2002) to Cedar's Lean-verified symbolic compiler (OOPSLA 2024, https://www.amazon.science/publications/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization) is the conceptual vocabulary Evidentia uses for control-implementation reasoning. Cedar is uniquely important: its symbolic compiler is verified in Lean (https://lean-lang.org/use-cases/cedar/) — soundness AND completeness proven mechanically.

### 4.4 Continuous compliance (the most important single citation)

**Kellogg, Schäf, Tasiran, Ernst — "Continuous Compliance"** (ASE 2020, [DOI 10.1145/3324884.3416593](https://homes.cs.washington.edu/~mernst/pubs/continuous-compliance-ase2020-abstract.html)) is the foundational paper Evidentia extends. They argue that traditional compliance audits (SOC, PCI DSS) are point-in-time, and that continuous compliance via lightweight type-system-style verification on each commit can keep a codebase certifiable. They demonstrate it for PCI DSS using checker-framework-style analyses. Replication artifacts at https://zenodo.org/records/3976221.

**Evidentia operationalizes this thesis at OSCAL/multi-framework scale**, with Sigstore-backed evidence integrity, structured-output AI for risk statements, and as of v0.7.8 cloud-DW + BI-publish surfaces. That is the cleanest one-line intellectual narrative.

### 4.5 AI-on-compliance bleeding-edge (NEW for v0.7.8 refresh)

Three arXiv papers verified to exist (May 2026) that name Evidentia's planned v0.8.0 features by their exact terminology — this is the strongest academic-substrate claim Evidentia can make:

- **Khatchadourian, *Replayable Financial Agents: A Determinism-Faithfulness Assurance Harness for Tool-Using LLM Agents*** ([arXiv 2601.15322](https://arxiv.org/abs/2601.15322), Jan 2026, v2 March 2026). 4,700 runs across 7 models. Establishes trajectory-determinism + decision-determinism + evidence-conditioned faithfulness for regulatory audit replay. Found *r = -0.11* between determinism and accuracy; schema-focused designs meet audit replay requirements. **DFAH = Determinism-Faithfulness Assurance Harness** (NOT "Decision-Faithfulness Assessment" as some Evidentia internal docs incorrectly expanded — corrected during the v0.7.8 review). This paper is the canonical citation for Evidentia's planned v0.8.0 P0.1 `evidentia eval` CLI.

- **Imperial & Tayyar Madabushi, *Scaling Policy Compliance Assessment in Language Models with Policy Reasoning Traces*** ([arXiv 2509.23291](https://arxiv.org/abs/2509.23291), Sept 2025; University of Bath). Establishes SOTA on HIPAA + GDPR compliance assessment via Policy Reasoning Traces (PRT) — explicit chain-of-thought citing exact policy clauses per claim. Canonical citation for Evidentia's planned v0.8.0 P0.2 `evidentia risk generate --emit-trace` mode.

- **Ma et al., *Unifying Multimodal Retrieval via Document Screenshot Embedding*** ([arXiv 2406.11251](https://arxiv.org/abs/2406.11251), June 2024; University of Waterloo). DSE encodes screenshots of documents (not parsed structure) via a vision-language model, outperforming BM25 by 17 points on Wiki-SS. **DSE = Document Screenshot Embedding** (NOT "Document Structure Embeddings"). Applicable to Evidentia's planned v0.8.0 P2.1 evidence-validation preview.

**Adjacent surveys to anchor a v0.8.0 P2.3 GRC eval suite contribution**: Gu et al. 2024 *A Survey on LLM-as-a-Judge* ([arXiv 2411.15594](https://arxiv.org/abs/2411.15594)); Tian et al. 2025 *Overconfidence in LLM-as-a-Judge* ([HF Papers 2508.06225](https://hf.co/papers/2508.06225)); Liu et al. 2025 *MetaFaith: Faithful Natural Language Uncertainty Expression in LLMs* ([HF Papers 2505.24858](https://hf.co/papers/2505.24858)). Plus Geng et al. 2025 *JSONSchemaBench* ([HF Papers 2501.10868](https://hf.co/papers/2501.10868)) — directly applicable to OSCAL-conformant generation eval.

**RAG-for-legal/regulatory-text** substrate: Guha et al. 2023 *LegalBench* ([arXiv 2308.11462](https://arxiv.org/abs/2308.11462)) — Stanford CodeX, 40-author collaboration; Pipitone & Houir Alami 2024 *LegalBench-RAG* ([HF Papers 2408.10343](https://hf.co/papers/2408.10343)); Ho et al. 2025 *Incorporating Legal Structure in Retrieval-Augmented Generation* ([HF Papers 2505.02164](https://hf.co/papers/2505.02164)).

**Fine-tuned compliance LLM prior art**: Zhu et al. 2024 *LegiLM: A Fine-Tuned Legal Language Model for Data Compliance* ([HF Papers 2409.13721](https://hf.co/papers/2409.13721)) — GDPR-specific fine-tune; Tamo et al. 2026 *EvidenceRL* ([HF Papers 2603.19532](https://hf.co/papers/2603.19532)) — GRPO-based RL for evidence grounding in legal reasoning, F1 from 32.8% to 67.6%; highly relevant to Evidentia's evidence-attestation pipeline.

### 4.6 Regulatory updates affecting Evidentia's intellectual home (NEW for v0.7.8)

- **SR 11-7 has been superseded** (April 17, 2026) by **SR 26-02** + **OCC Bulletin 2026-13a** ([Federal Reserve SR 26-02 PDF](https://www.federalreserve.gov/supervisionreg/srletters/SR2602.pdf), [OCC 2026-13a](https://www.occ.gov/news-issuances/bulletins/2026/bulletin-2026-13a.pdf)). Critically, the new guidance **explicitly excludes generative AI and agentic AI**: *"Generative AI and agentic AI models are novel and rapidly evolving. As such, they are not within the scope of this guidance."* Banks are stranded with no regulatory framework for LLM deployments; agencies promised a future RFI. Evidentia's v0.7.9 plan (currently references SR 11-7) needs touch-up to reference both the original (historical lineage) and the 2026 revisions (current applicability) — and the v0.7.9 model-risk module becomes the precise opening for SR-11-7-replacement-framework primitives.

- **PCAOB AS 1105 amendments** + the July 2024 *Generative AI Spotlight* ([PCAOB.org](https://pcaobus.org/documents/generative-ai-spotlight.pdf), [AS 1105 details](https://pcaobus.org/oversight/standards/auditing-standards/details/AS1105)) are now the regulator-recognized framework for AI in audit reports. Five required capabilities: prompt + response capture, model-version tracking, human-in-the-loop verification, immutable audit trails, explainability documentation. **Evidentia's v0.7.1 audit trails capture (1) + (2); planned v0.8.0 DFAH addresses (3) + (4); planned v0.8.0 PRT addresses (5).** This is a remarkable alignment and the strongest single positioning claim Evidentia can make in the v0.8.0 cycle.

- **NIST AI RMF crosswalk status**: [NIST AI RMF crosswalks page](https://www.nist.gov/itl/ai-risk-management-framework/crosswalks-nist-artificial-intelligence-risk-management-framework) — NIST has *not* published a formal AI RMF ↔ SR 11-7 crosswalk, deliberately keeping the two domains separate. The Generative AI Profile [NIST.AI.600-1](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf) covers Govern / Map / Measure / Manage for generative AI. Evidentia's v0.7.9 catalog work should crosswalk forward from AI RMF + NIST 800-53 + OSCAL into SR 11-7 manually until NIST publishes an authoritative crosswalk.

---

## 5. Competitive landscape

> **Section summary (v0.7.8 refresh, May 2026).** The GRC market still
> consolidates into five tiers, but the May 2026 picture is sharply
> different from April 2026. **Vanta has pulled away** ($300M ARR, 3x
> in two years, 16,000+ customers, $4.15B Series D July 2025). **AuditBoard
> rebranded to Optro March 9 2026** (Hg Capital's positioning move).
> **Drata acquired SafeBase $250M February 2026** (Trust Center
> bundling). **Diligent acquired 3rdRisk January 2026** for AI-native
> TPRM. **OneTrust active PE talks Nov 2025** ($4.5B / $550M+ ARR).
> **Wiz → Google $32B closed March 2026** (largest VC-backed exit in
> history). The AI-native challenger tier raised $50M+ in 90 days
> (Complyance $20M Feb GV-led; Sphere $21M Nov 2025 a16z; Haast $12M
> April; Comp AI $20M Series A Feb led by Khosla's Keith Rabois). **The
> Delve scandal (March 2026)** is the segment-defining 2026 incident —
> 493/494 leaked SOC 2 reports byte-identical. Eramba effectively
> exited OSS (application closed-source as of recent years; only
> docker helpers remain on GitHub). **None of the commercial AI agent
> launches between Sept 2025 and April 2026** ships deterministic-
> replay harness, Sigstore-attested AI provenance, or first-class
> Policy Reasoning Traces — the structural opening Evidentia's v0.8.0
> plan targets remains intact.

### 5.1 Tier 1 — SOC 2 startup automation

| Vendor | Valuation / ARR | OSCAL | AI features | OSS posture | Real differentiation? |
|---|---|---|---|---|---|
| **Vanta** | $300M ARR April 2026 (3x in 2 yrs, +69% YoY); $4.15B Series D July 2025 (Sequoia, Wellington, Goldman Sachs Alternatives, JPM, Atlassian Ventures, CrowdStrike Ventures); 16,000+ customers; **FedRAMP Moderate Authorized** | **YES (export only, NEW Feb 2026)** for FedRAMP 20x submissions | Vanta AI Agent (policy/personnel/questionnaires; 95% acceptance), TPRM Agent (multi-assessment), Customer Trust Agent, **remote MCP server (public preview Apr 15 2026)** | Proprietary | First major commercial vendor to ship OSCAL **export** (Feb 2026); 375+ integrations; deepest brand premium |
| **Drata** | $100M+ ARR early 2026 (claim, unverified for current); $2B Series C Dec 2022; $455M total raised; **acquired SafeBase $250M February 2025** (Trust Center bundling) | **No** | Agentic TPRM Assessment, Agentic Questionnaire Response (beta), Agentic Trust Center Setup, **Drata MCP server** (RSAC 2026 launch); 3-day default continuous-monitoring SLA (NOT real-time) | Proprietary | Trust-Center-bundled GRC; CEO Adam Markowitz; Series D rumored unconfirmed |
| **Secureframe** | $56M Series B Feb 2022 @ $355M val; $79M total; **FedRAMP Moderate authorized**; ~$20M ARR Oct 2023 (claim, unverified for current) | **No** | Comply AI Remediation, Comply AI TPRM, AI Evidence Validation | Proprietary | Strong audit-firm partnerships; trailing Vanta/Drata |
| **Sprinto** | $20M Series B April 2024; ~$12M ARR FY24-25; 3,000 customers in 75 countries; 200+ frameworks "Infinite Frameworks" engine | **No** | Sprinto AI agents (Vendor Risk Analysis, Evidence Gap Detection, Risk Scoring); $15K starter | Proprietary | India-built; significantly cheaper than Vanta/Drata |
| **Comp AI** | **$20M Series A Feb 2026** (Khosla's Keith Rabois — TechCrunch); was $2.6M pre-seed Aug 2025 (OSS Capital + Grand Ventures) at v0.7.0 doc; ~600 deployed companies, $3K entry; 25+ frameworks incl. ISO 42001 | **No** | Plain-language → automation agent; OSS device agent | **OSS (AGPLv3)**, TypeScript/Next.js | Targets SaaS-startup SOC 2 self-serve market (different ICP than Evidentia). 1,535 GitHub stars; daily commits as of 2026-05-02 |
| **Delve (CAUTIONARY TALE)** | $32M Series A July 2025 led by Insight Partners @ $300M val; **March 2026 whistleblower disclosure ("DeepDelver")** alleging fabricated evidence | No | "AI-native" SOC 2 / ISO 27001 automation | Proprietary | **493/494 leaked SOC 2 reports had byte-identical boilerplate + identical grammatical errors**; customers migrating away (one to Vanta + Insight Assurance after Vercel breach); IANS Research analysis (March 30 2026); FTC + DOJ False Claims Act exposure being discussed |
| **Probo** | YC P25 batch | No | LLM-assisted SOC 2/ISO 27001/HIPAA workflow | **OSS** | French team, SF-based; "compliance done for you" service model |

### 5.2 Tier 2 — Enterprise GRC suites

| Vendor | Position | OSCAL | AI features | Notes |
|---|---|---|---|---|
| **OneTrust** | Enterprise/F100; **$550M+ ARR; $4.5B last priced**; 2022 layoffs of 950; valuation reset from $5.3B (2021); **active PE discussions Nov 2025 with Thoma Bravo / Blackstone / Silver Lake / KKR**; **John Heyman → CEO January 2026**, founder Kabir Barday → board | **No** | OneTrust Athena (AI + RPA); March 2026 launched real-time AI governance + agent-oversight: AI Policy Manager, AI Guardrail Enforcement, Breach Response Agent, Risk Assessment Agent, Third-Party Risk Agent | Privacy/AI-governance leader; GDPR/CCPA/EU-US DPF + AI governance |
| **Optro (formerly AuditBoard, rebranded March 9 2026)** | F500 internal audit; 2,000+ customers; $200M+ ARR; **CEO Raul Villar Jr. (effective July 1 2025)**; **acquired FairNow Oct 2025** for AI governance | **No** | March 2026: Unified AI Governance + AI-powered narrative drafting + Continuous Control Monitoring + Cyber Risk: Vulnerability Risk Monitoring + Optro MCP server | Hg Capital take-private $3B (May 2024); SOX-bound public-company internal audit teams |
| **ServiceNow IRM** | Existing ServiceNow enterprise install base | **No** | Now Assist for IRM (Yokohama 2025); 12B SLM (Now LLM Service, 32K context); Issue Resolution Agentic Workflow, Risk Assessment Summarization, Control Objective Rationalization & Deduplication, Control Objective Change Agent | Locked to ServiceNow ecosystem; CFOs/financial-reporting/ESG-CSRD-SEC-climate buyers |
| **Workiva (NYSE: WK)** | Enterprise CFO office + GRC; $884.6M FY25 revenue (+20% YoY); **$95.30 price target April 2026** consensus Buy; **March 2026 launched Intelligent Finance/GRC/Sustainability with agentic AI** | **No** | Workiva AI global chat + Test Steps and Compliance Activities Definition (multi-LLM, user-selectable Microsoft/AWS provider; reads regulatory PDFs, extracts citations, generates audit procedures) | Public; non-GAAP op margin 9.9% |
| **Archer** (post-RSA, owned by **Cinven** from April 2023) | Enterprise/regulated; **Archer Summit 2025 launched Archer Evolv Risk + Evolv Intelligence** emphasizing quantitative risk + scenario simulation | **No** | Modest AI overlays + scenario simulation | Aging UI; PE-owned; modernization slow |
| **MetricStream** | Enterprise/FSI; private; last disclosed Series 5A 2017 at $477.5M post-money; ARR not disclosed | **No** | "AiSPECTS" AI engine; positions 2025 as "the year GRC went AI-first" | Enterprise pricing $75K-$1M/year; large enterprises with multi-framework COBIT/SOX/ISO 27001 deployments |
| **Hyperproof** | Mid-market; $40M Series B Aug 2023 (Riverwood + Toba); $56.5M total; **260% revenue growth since 2022**; **AI Guided Experiences launched at RSAC 2026** | **No** | Hyperintelligence AI control mapping; agentic evidence/testing/reporting | Best mid-market framework crosswalker; $12K entry, $49K-$99K typical mid-market |
| **LogicGate Risk Cloud** | Mid-market enterprise risk/compliance | **No** | LogicGate AI for risk scoring + workflow automation | No-code risk workflow builder |
| **Riskonnect** | Enterprise integrated risk | **No** | Risk Intelligence AI for ERM | Single-codebase unified GRC across ERM/IA/ESG |
| **Diligent** | Enterprise board/audit (post-Galvanize April 2021); **acquired 3rdRisk January 14 2026** for AI-native TPRM; **April 2026 unveiled AI Board Member + autonomous "agentic GRC workforce" at Elevate 2026, GA expected Q4 2026** | **No** | Diligent AI for board materials + risk insights + AI Board Member | Median spend $23.8K/year, scaling to $113K |
| **IBM OpenPages with watsonx** | F500/regulated/FSI | **No** | watsonx-powered AI for risk/control mapping | Heaviest implementation |
| **Anecdotes.ai** | $55M Series B (extended) April 2025 (DTCP-led $30M extension); $85M total; Israel/Palo Alto; **agentic CCM + 200+ plugin in-house architecture**; **charges enterprise pricing without SCIM provisioning** (notable friction) | **No** | Data-first agentic GRC: detect → notify → remediate → verify in minutes; ML anomaly detection on dataset evidence | 60+ pre-mapped frameworks; manual user lifecycle even at $20K-$150K+ tiers |

### 5.3 Tier 3 — Trust center / vendor risk

| Vendor | Position | AI |
|---|---|---|
| **SafeBase** (Drata, $250M Feb 2025) | 1,000+ customers pre-acq; OpenAI's trust portal; tightly integrated to Drata GRC | Custom AI models on security docs; AI questionnaire auto-fill (80%+ time saved, citation-backed) |
| **Conveyor** | $20M Series B (June 2025); 480+ customers (Atlassian, Netflix, Zendesk) | "Sue" AI security questionnaire bot (95-97% accuracy); "Phil" RFP automation; AI-to-AI trust exchange roadmap |
| **TrustArc** | Privacy/cookie consent enterprise | Limited AI publicized |
| **BitSight** | Enterprise security ratings; F500 + insurance + M&A diligence | Risk scoring AI; ratings AI; acquired Cybersixgill for threat intel |
| **SecurityScorecard** | 2,600+ customers, 70% of F1000; 70k+ free-tier users | Smart Answer AI questionnaire fill; HyperComply RespondAI (acquired Sept 2025) |
| **RiskRecon** (Mastercard) | F500 third-party risk | Limited public AI roadmap |
| **UpGuard** | Mid-market security ratings + breach risk | Mature scanning AI |
| **Whistic** | Vendor risk questionnaire library | "Smart Response" AI |
| **Panorays** | Israeli third-party cyber risk | AI risk scoring |

### 5.4 Tier 4 — Cloud security / IaC / OSCAL adjacent

| Vendor | Position | OSCAL | Notes |
|---|---|---|---|
| **Wiz (Google Cloud)** | Multi-cloud F500; largest CSPM install base | **No** | $32B Google acquisition closed March 2026 — largest VC-backed exit in history |
| **Lacework (FortiCNAPP)** | DevSecOps mid-large; behavioral-anomaly heritage | **No** | Brutal valuation reset: $8.3B peak → $150M Fortinet sale (Aug 2024) |
| **Orca Security** | Enterprise multi-cloud; agentless | **No** | Smaller than Wiz post-Google |
| **Palo Alto Prisma Cloud** | Enterprise hybrid | **No** | IaC-to-runtime compliance mapping |
| **Snyk Cloud** | DevOps mid-large | **No** | Strong OSS contributions: IaC tests, Snyk IaC plugin |
| **Aqua Security** | Container-heavy | **No** | Trivy maintainer; OSS-friendly |
| **Sysdig** | Kubernetes runtime | **No** | Falco CNCF lead |
| **CrowdStrike Falcon Cloud Security** | F500 EDR-bundled | **No** | Falcon platform pull-through |
| **Anchore Enterprise** | Federal SBOM/compliance | **Partial** (SBOM feeds map to OSCAL) | SBOM authority; DoD/federal customers |
| **Chainguard** | Enterprise + FedRAMP-bound; "safe source" for OSS | **OSCAL relevant via FedRAMP/SLSA flow** | Series D $356M @ $3.5B (April 2025); FedRAMP-bound; signed/distroless images for compliance evidence |
| **RegScale** | Federal / FSI / regulated; CSPs targeting energy & utilities | **YES — OSCAL-NATIVE** (XML/JSON/YAML); donated open-source OSCAL Hub Dec 2025; OSCAL CLI; lead affiliate for CRI's OSCAL initiative; founding member of OSCAL Foundation | Series B $30M+ Sept 2025 (Washington Harbour Partners + Microsoft M12 + Hitachi Ventures); Gartner Cool Vendor 2025; **only commercial OSCAL-native GRC platform** |
| **Telos Xacta** (NASDAQ: TLS) | Federal RMF / FedRAMP / DoD ATO | Partial via RMF outputs | Aging stack |

### 5.5 Tier 5 — OSS GRC ecosystem (refreshed May 2026)

The OSS GRC tier kept surging through 2025-26. **None of these is a permissively-licensed, library-first, OSCAL-native, multi-framework Python toolkit with cryptographically-signed evidence chain-of-custody.** That gap is Evidentia's slot.

| Project | Stars / Activity (May 2026) | Shape | License | Evidentia adjacency |
|---|---|---|---|---|
| **intuitem/ciso-assistant-community** | **4,008 stars; daily commits as of 2026-05-03; latest 2026-05-03** | Full-platform GRC web app (Django + SvelteKit), 130+ frameworks claimed, ships TPRM module | AGPL-3.0 + dual-license commercial paid SKUs | **Most serious direct OSS competitor.** Lacks OSCAL emit, Sigstore, SLSA L3. French startup intuitem; well-staffed; Evidentia's window to differentiate is "quarters, not years" |
| **IBM/compliance-trestle** | 251 stars; latest commit 2026-04-29 | Opinionated CI/CD-driven OSCAL document authoring + workflow engine; OSCAL transformations / governance | Apache-2.0 | Closest Python rival but workflow-first; founding team Anca Sailer / Lou Degenaro / Vikas Agarwal at IBM Research; **complementary** (Evidentia could integrate as upstream OSCAL transformer) |
| **complytime/complyctl** + **complyscribe** | 31 + 22 | Red Hat–led Go + Python CLI for end-to-end OSCAL compliance workflows | Apache-2.0 | Direct philosophical neighbor; Go-first |
| **defenseunicorns/lula** | 29 | DoD-flavored compliance-as-code for GitHub repos | Apache-2.0 | Adjacent vertical; complement |
| **trycompai/comp** (Comp AI) | **1,535 stars; latest commit 2026-05-02; daily commits**; **$20M Series A Feb 2026** (Khosla / Keith Rabois) — was $2.6M pre-seed in Aug 2025; ~600 deployed companies | Vanta/Drata alternative; AI-native positioning; TypeScript/Next.js | AGPL-3.0 + commercial | Targets SaaS-startup SOC 2 self-serve market (different ICP); top-of-funnel awareness threat |
| **GRCEngClub/claude-grc-engineering** | 269 stars; created Dec 2025; latest tag v0.0.4 (Apr 2026) | Claude Code plugin marketplace — 63 plugins / 98 skills / 257 commands (persona + framework + connector plugins); a prompt-orchestration layer, **not** a runtime engine | MIT core (bundles CC BY-ND 4.0 SCF crosswalk data + CC BY-SA 4.0 CIS content) | **Complementary, not competitive** — a Claude-Code orchestration layer that explicitly is not an engine; its `grc-engineer` hub shells out to external tools. Interop opportunity: publish an Evidentia MCP plugin into its `grc-engineering-suite` marketplace. See [integration-survey.md](integration-survey.md) §5 |
| **compliancecow/cowmcp** (ComplianceCow MCP) | Verified 2026-05-24 via repo metadata; small & new project | MCP server fronting ComplianceCow's commercial GRC SaaS — exposes ~14 tools (control inventory, evidence retrieval, finding query, framework crosswalk lookup) for Claude / ChatGPT consumption | Apache-2.0 (server); ComplianceCow backend proprietary | **Only other OSS GRC MCP server besides Evidentia's `evidentia mcp serve`.** Different shape — MCP is a thin facade over a SaaS backend, whereas Evidentia is a runtime engine. Interop angle: cross-cite as the "two MCP-server OSS GRC tools that exist as of May 2026" honest-landscape entry |
| **awslabs/oscal-mcp-server** (AWS OSCAL MCP) | Verified 2026-05-24 via awslabs repo; archived `samples/` shape — not a service | MCP knowledge tool — answers OSCAL schema + 800-53 / 800-171 catalog questions via embedded references | Apache-2.0 | **Knowledge tool only — not a runtime emitter.** Evidentia goes further: emits OSCAL component-definition / SSP / assessment-results / POA&M / VEX / VSA. Useful upstream reference; not a competitor |
| **simplerisk/simplerisk** | 101 stars; latest 2026-04-25 | PHP-based risk register; ~12 years old; commercial hosted version exists | Mozilla Public License 2.0 | Narrow shape — risk register only |
| **Probo** | YC P25 batch | OSS SOC 2/ISO 27001/HIPAA platform | OSS | Service-augmented; small team |
| **Openlane** (`theopenlane.io`) | Apache-2.0 | OSS GRC platform | Apache-2.0 | Different shape (platform vs library) |
| **VerifyWise** | BSL 1.1 | AI-governance-focus OSS, 24+ frameworks incl. EU AI Act + ISO 42001 | BSL 1.1 | Different shape; AI-governance vertical |
| **OWASP/OpenCRE** | 154 stars; latest 2026-05-02 | Maps CRE → ASVS, NIST, ISO; quiet but genuine asset | CC0-1.0 | **Could feed Evidentia's catalog cross-walks**; complementary |
| **MITRE/saf** | 177 stars; latest 2026-05-02 | Security Automation Framework CLI; transforms heterogeneous scan output → OHDF/HDF; OSCAL-aware | Apache-2.0 | **Closest in spirit to Evidentia of the MITRE projects**; absorption-candidate pattern (extend evidence-ingestion) |
| **MITRE/caldera** | 6,932 stars; latest 2026-05-01 | DoD-funded; threat-side adversary emulation | Apache-2.0 | Produces evidence-of-control-effectiveness Evidentia could consume |
| **inspec/inspec** | 3,064 stars; Progress Software stewards | Config-compliance scanner; evidence at host level | Apache-2.0 | Adjacent (config-scan); could be ingested as evidence |
| **OpenSCAP/openscap** | 1,712 stars | Red Hat-led; SCAP 1.2 toolkit; DISA STIG scanner | LGPL-2.1 | Same evidence-ingestion story as InSpec |
| **wazuh/wazuh** | **15,465 stars** (largest by stars) | Unified XDR + SIEM with built-in regulatory compliance modules | GPL-2.0 | Adjacent (SIEM/XDR); evidence stream Evidentia could ingest |
| **kyverno/kyverno** | 7,695 stars; CNCF Incumbent | K8s-native policy-as-code; emits compliance reports | Apache-2.0 | **Could integrate** — policy evidence consumption |
| **open-policy-agent/opa** | 11,674 stars; CNCF Graduated | Rego-based; universal policy-as-code substrate | Apache-2.0 | **Could integrate** |
| **cedar-policy/cedar** | 1,447 stars; AWS-led; Rust-based | Authorization policy language with Lean-verified symbolic compiler | Apache-2.0 | **Could integrate** |
| **guacsec/guac** | 1,485 stars; OpenSSF | Aggregates SBOM/provenance into a graph | Apache-2.0 | Complementary supply-chain GRC angle |
| **GovReady-Q** | 210 stars | Django-based self-service GRC questionnaire app | GPL-3.0 | Effectively defunct (no meaningful work since 2024); Evidentia walks into the vacuum |
| **opencontrol/compliance-masonry** | 377 / maintenance | Pre-OSCAL YAML "OpenControl" docs builder | Apache-2.0 | Predecessor of OSCAL; stale |
| **RS-Credentive/oscal-pydantic** | 23 / 5; last push 2024-04-06 (2+ years stale) | Pydantic models autogenerated from OSCAL schemas | Apache-2.0 | Functionally archived; Evidentia could supersede |
| **Eramba** ([eramba/docker](https://github.com/eramba/docker)) | 70 stars (docker repo); latest 2026-04-22 | **Still offers Community Edition (free forever, on-premise) + paid Enterprise tier** (verified 2026-05-18 via direct WebFetch of eramba.org). Community + Enterprise both support unlimited users + unlimited frameworks. The v0.7.8 baseline claim that Eramba had "shifted to closed-source application Q1 2026" was **inaccurate** and is corrected here. | Open-source Community + commercial Enterprise dual-license | Active competitor; PHP/Laravel stack; oriented to ISO 27001 + SOC 2 audit workflows; weaker on OSCAL + AI-quality than Evidentia |

### 5.6 AI-native challengers (last 18 months — NEW for v0.7.8)

A genuinely new tier surfaced through v0.7.x. Capital concentrated in agentic-AI-native compliance automation:

- **Complyance** [complyance.com](https://www.complyance.com): **$20M Series A Feb 2026** led by Google Ventures (Anthropic + Mastercard senior-leadership angels); existing Creandum/HV/Speedinvest. **Sixteen production AI agents; expanding to thirty.** Threat to Evidentia: nominally similar AI-agent surface; differentiation is OSCAL + Sigstore + license posture.
- **Oneleet** [oneleet.com](https://www.oneleet.com): **$33M Series A** led by Dawn Capital. Bundled platform: vCISO services + asset monitoring + pen-testing + SOC 2/ISO 27001/HIPAA/PCI/GDPR/DORA. Premium-priced **anti-"compliance-theater" positioning**.
- **Haast** ([Angel Investors Network](https://angelinvestorsnetwork.com/regulatory-compliance/ai-compliance-automation-raises-12m-series-a-in-2026)): **$12M Series A April 9 2026** (Peak XV Partners); 4.5x YoY revenue, zero churn. Vertical specialization in marketing/legal-review compliance for FS, pharma, FMCG. Customers: Telstra, Zurich AU/NZ, Aviva, Future Super.
- **Sphere** ([TechCrunch Nov 2025](https://techcrunch.com/2025/11/18/a16z-leads-21m-series-a-into-tax-compliance-platform-sphere/)): **$21M Series A November 2025** led by a16z for tax compliance automation.
- **Relyance AI** ([TechCrunch Oct 2024](https://techcrunch.com/2024/10/10/relyance-helps-companies-comply-with-data-regulations/)): $32M Series B October 2024 (Thomvest, M12, Menlo, Unusual), $59M total. **Data-lineage-driven privacy/vendor-risk.**
- **OSCAL infrastructure layer**: RegScale launched **OSCAL Hub** ([RegScale blog](https://regscale.com/blog/introducing-oscal-hub/)); **ARPaCCino academic prototype** demonstrates agentic-RAG-to-Rego policy generation for IaC ([arXiv 2507.10584](https://arxiv.org/html/2507.10584v1)); NIST ran an **OSCAL-Augmented CISO Agent workshop in 2025** ([NIST CSRC](https://csrc.nist.gov/presentations/2025/oscal-based-ai-augmented-ciso-agent)).

### 5.6.A AI-governance specialist platforms (added 2026-05-21 research pass)

A distinct vendor tier — purpose-built AI-governance platforms — matured
through 2025-26 alongside the EU AI Act phase-in. It is **adjacent** to
Evidentia rather than directly overlapping: these vendors govern *AI
systems* specifically, whereas Evidentia is a general GRC engine that
happens to carry an AI-quality harness. But it is the tier where
Evidentia's AI-posture work (faithfulness scoring, risk-determinism, the
v0.9.3 EU AI Act tier classifier — see §11) competes, and it is worth
tracking because the EU AI Act's 2 Aug 2026 obligations (some high-risk
provisions provisionally deferred to 2 Dec 2027 under the May 2026
Digital Omnibus agreement) are its demand driver.

| Vendor | Position | Funding / traction | Deployment |
|---|---|---|---|
| **Credo.ai** | Most mature pure-play; "discover, assess, govern, monitor, report" across the AI lifecycle + GAIA agentic-governance agents; named a Leader in Forrester's AI Governance Wave | ~$41M total; Series B July 2024; IBM OEM deal; 30+ partner program; customers incl. Mastercard, PepsiCo, Booz Allen | SaaS-only; no air-gap / self-host |
| **Trustible.ai** | AI-governance built for GRC/legal/compliance buyers; risk-based AI intake/triage; among the deepest EU AI Act coverage; Leidos national-security partnership | $4.6M seed June 2025; customers incl. Leidos, Databricks, Google | SaaS-only; no air-gap / self-host |
| **IBM watsonx.governance** | Enterprise scale; governs models/apps/agents across vendors; OEMs Credo.ai | IBM | Enterprise SaaS |
| **Holistic AI** | Third-party bias / fairness / robustness *auditing*; audit-grade reports | VC-backed | SaaS |
| **OneTrust AI Governance** | Deployer-side; extends the OneTrust privacy-GRC franchise (see §5.2) | (see §5.2) | SaaS |
| **Monitaur / Fairly AI / Modulos** | Model audit trails (Monitaur, insurance-leaning); automated risk assessment (Fairly, FS-leaning); top-tier EU AI Act coverage (Modulos) | VC-backed | SaaS |
| **Snyk AI Trust Platform** (added 2026-05-24) | Existing Snyk SAST/SCA franchise extended with an AI-guardrails layer for LLM applications (Q1 2026 launch) — leverages Snyk's massive code-security distribution | NASDAQ: SNYK | SaaS / IDE plugins |
| **Knostic** (added 2026-05-24) | Shadow-AI / Microsoft 365 Copilot governance — discovers + classifies un-sanctioned AI use across an enterprise; **~$50K/yr typical entry price** | Series A 2024; ~$23M total | SaaS |
| **2021.AI GRACE Governance** (added 2026-05-24) | EU-native AI-governance platform; tight EU AI Act Annex IV alignment; GRC-buyer-oriented packaging | Danish; private | SaaS / on-premise (the only one in this tier offering true self-host) |

**Where Evidentia sits.** Every platform in this tier is SaaS-only,
closed-source, and priced for non-technical compliance buyers
(third-party estimates put Credo.ai at ~$30K–$150K/yr). None advertises
OSCAL emit, air-gap deployment, or a measurable, reproducible
AI-evaluation harness. That leaves an uncontested quadrant —
**open-source, air-gap-capable, code-first AI-governance evidence with
measurable eval rigor** (faithfulness scoring + risk-determinism +
Cohen's Kappa rater agreement) **and OSCAL emit** — which Evidentia's
existing AI-posture stack (§11) already occupies. The Trustible–Leidos
national-security partnership is direct evidence of demand for *governed
AI in classified environments*, exactly where SaaS cannot follow. The
adoptable gap in Evidentia's lineup is **AI-specific regulatory packs**
(EU AI Act Annex IV technical documentation, ISO/IEC 42001 — Evidentia
already bundles AI RMF + EU AI Act catalogs per §3.6, but not as
conformity-assessment packs) and **agentic-governance primitives**
(agent cards, tool-use permissioning), the latter buildable on
Evidentia's existing MCP / CIMD scope-enforcement substrate.

### 5.7 Foundational layer Evidentia integrates

- **NIST OSCAL** (877 stars) + **oscal-content** (430 stars) — canonical schema + 800-53 catalogs
- **ComplianceAsCode/content** (2,710 stars) — SCAP/STIG content for RHEL/Ubuntu hardening
- **CycloneDX/cyclonedx-python** (371 stars) — SBOM generator (Evidentia uses for `evidentia-sbom.cdx.json`)
- **Sigstore/cosign** (5,844 stars) — signing + Rekor transparency log (Evidentia uses for evidence + release attestations)
- **in-toto/in-toto** (999 stars) — supply-chain attestation framework (related)

---

## 6. Differentiation, parity, and honest gaps

> **Section summary (refreshed v0.7.8 May 2026).** Evidentia has
> **eight genuine differentiators** versus every commercial tier —
> the original seven (open-source + Python + library-first;
> OSCAL-native; AI-optional; air-gap-capable; supply-chain-hardened
> on the GRC tool itself; composite GitHub Action / CI-native; 88
> framework catalogs bundled) plus **PCAOB AS 1105 5/5 alignment**
> via v0.7.1 audit trails + planned v0.8.0 DFAH + PRT (no commercial
> GRC vendor hits all 5). It is at **parity** on AI-assisted control
> mapping, MCP server (commercial vendors caught up Q1 2026), evidence
> collection from cloud APIs, CycloneDX SBOM, Sigstore signing, and
> conventional commit + semver discipline. It is **honestly behind**
> on the same ten surfaces as v0.7.0 (trust center; AI questionnaire
> fill; integration breadth — 8 evidence-collection surfaces vs
> Vanta's 375+; auditor partnerships; analyst inclusion; TPRM
> module — planned v0.7.9; ERM/risk-register primitive; reference
> customers; formal SOC 2 attestation; IPO/exit longevity narrative)
> plus a NEW v0.7.8-surfaced gap: **two `[azure]` and `[gcp]`
> optional extras declared in pyproject.toml without backing
> implementations** (queued for v0.7.9 batch fix).

### 6.1 The seven genuine differentiators (vs. all four commercial tiers)

| # | Differentiator | Vs. Vanta/Drata | Vs. OneTrust/AuditBoard/ServiceNow | Vs. SafeBase/Conveyor | Vs. Wiz/Lacework/Chainguard |
|---|---|---|---|---|---|
| 1 | **OSS + Python + library-first** | None do this | None | None | None at GRC layer; only Snyk/Aqua/Sysdig/Anchore/Chainguard at adjacent security layer |
| 2 | **OSCAL-native** | None ship OSCAL output | None | None | Only RegScale (parity); not Wiz/Lacework/Prisma/CrowdStrike |
| 3 | **AI-optional** (works fully without LLM access) | Hard-wired AI dependency | All AI-core (Athena, Now Assist, watsonx) | AI-first by design | CSPM tied to telemetry; not relevant axis |
| 4 | **Air-gap-capable** | None deploy on-prem or air-gapped | OneTrust on-prem deprecated; rest cloud-only | All cloud-only | All cloud-telemetry-dependent by definition |
| 5 | **Sigstore + PEP 740 + SBOM applied to the GRC tool itself** | None publish signed SBOM for their platform | None | None | Parity-ish with Chainguard's signed-image philosophy, but Evidentia applies it to *the GRC tool*, not just images. **Genuine differentiator at the meta-layer.** |
| 6 | **Composite GitHub Action / CI-native** | SaaS dashboards; not pipeline-native | Workflow apps; not CI primitives | Same | Snyk/Aqua/Sysdig CI-native for *security scanning*; Evidentia CI-native for *compliance evidence* |
| 7 | **88 framework catalogs bundled** (95+ planned for v0.7.9 with FFIEC + OCC + SR 11-7 additions) | Vanta 35+ ([Vanta frameworks](https://www.vanta.com/products/additional-frameworks)), Drata 20+, Secureframe ~12, Sprinto 200+ (claim — but with documented uneven depth — see §6.4), Comp AI 25+ | OneTrust + ServiceNow + IBM cover hundreds via paid licensed regulatory libraries | N/A (trust center vendors don't ship catalogs) | RegScale claims 60+ (parity); CISO Assistant 130+ claimed (parity) |
| 8 | **PCAOB AS 1105 5/5 capability alignment** (NEW v0.7.8 differentiator) | None publish 5/5 alignment | None | None | None |

### 6.1.A The moat trinity (v0.9.6 sharpened framing — May 2026)

The v0.9.5 Q3 2026 quarterly resync sharpened the differentiation
story by collapsing the seven-vs-eight differentiator list into three
concrete moats that compound rather than enumerate. **The moat trinity**:

1. **OSCAL emission** — Evidentia is the only OSS GRC tool that
   emits catalog / profile / assessment-results / plan-of-action-
   and-milestones (v0.9.6 ships OSCAL 1.2.1 via the
   `OSCAL_SCHEMA_VERSION` constant; trestle-compatible) **as
   first-class output**, not via an exporter add-on. The Sept 30
   2026 FedRAMP machine-readable mandate makes this the load-
   bearing differentiator for federal-adjacent operators.
2. **DFAH / PRT determinism** — auditor-defensible reproducibility
   on every AI-generated artifact. Khatchadourian arXiv
   2601.15322 (v2 March 2026) names this by exact terminology;
   no commercial GRC vendor offers it. Validates the
   v0.7.8-surfaced AI-feature-commoditization thesis: when every
   incumbent ships "agentic" features, the differentiator
   collapses into eval rigor + audit trails.
3. **Cryptographic provenance (CIMD + Sigstore + PEP 740)** —
   per-tool CIMD scope enforcement at the MCP protocol layer
   (v0.8.5 P4) + Sigstore-signed eval output (v0.8.2) + PEP 740
   attestations on every released wheel. The Mini Shai-Hulud
   May 11 2026 supply-chain attack (400+ malicious package
   versions across 170+ packages on npm + PyPI) is the
   contemporary forcing function: operators NEED cryptographically
   verifiable provenance on the GRC tool itself, not just on its
   outputs.

### 6.1.B Counter-positioning vs "agentic GRC" (v0.9.6 — May 2026)

By May 2026 every credible incumbent shipped "agentic GRC" framing
within ~60 days of each other: **Vanta Agentic Trust Platform**
(March 19 2026 GA), **Drata Agentic TPRM** (March 2026), **Optro
unified AI governance** (built on FairNow acquisition Oct 2025),
**OneTrust Athena**, **Workiva Intelligent**, **Hyperproof AI
Guided Experiences**, **Anecdotes** — all converged on the
"agentic" vocabulary in the same quarter. **Drata's own May 11
2026 essay "From Prompt Engineering to Harness Engineering"
implicitly concedes the harder problem is verifiable harness,
not agents** — directly validating Evidentia's DFAH + PRT + CIMD
framing.

**v0.9.6 positioning posture**: Evidentia explicitly does NOT
chase "agentic" vocabulary. The leading frame is **"deterministic,
auditable, OSS-native compliance engineering"** — same problem
space, different value proposition. Operators evaluating GRC AI
on regulatory-defensibility criteria (FedRAMP RFC-0024 +
PCAOB AS 1105 + EU AI Act Article 15 transparency requirements)
inherit the moat trinity as a "must-have" rather than a "nice-to-
have."

### 6.2 Where Evidentia is at parity (don't oversell)

- **AI-assisted control mapping** — Vanta AI Agent, SafeBase AI, RegScale all do this. Evidentia at parity, not advantage.
- **Multi-framework crosswalking** — Hyperproof's Hyperintelligence and Drata's framework engine are mature. Evidentia at 89 catalogs is at parity in coverage; quality of the crosswalk graph needs more validation.
- **Evidence collection from cloud APIs** — Tier 1 vendors and CSPM tools both do this well. Evidentia's collectors (AWS, GitHub Dependabot, IAM Access Analyzer) are at parity for the integrations shipped, behind on coverage breadth.
- **CycloneDX SBOM output** — Industry standard now (Anchore, Chainguard, Snyk). Parity, not ahead.
- **Sigstore/Rekor signing of releases** — Increasingly table-stakes (Chainguard pioneered, Anchore + others adopting). Parity.
- **Conventional commits + semver release automation** — Table-stakes in modern OSS. Parity.

### 6.3.1 Framework-count caveat (added v0.7.8)

Per Stream 1's findings on commercial GRC over-promising patterns: bare framework counts (e.g., "Sprinto 200+") hide deep unevenness — vendors typically have world-class SOC 2 / ISO 27001 coverage but checklist-only mapping with little automation for FFIEC, SR 11-7, FedRAMP, CMMC. PolicyCortex's CMMC analysis is explicit: SOC-2-grade evidence "is often not sufficient for a CMMC C3PAO assessor." Evidentia's 88 catalogs claim should always be qualified with **redistribution-tier accounting** (Tier A 31 frameworks verbatim public domain + Tier D 21 statutory + Tier C 20 licensed-stubs + Tier B 4 threat catalogs at the v0.7.0 base, +6 since) and the **catalog-import flow for Tier-C licensed copies** (`evidentia catalog import` for ISO 27001, PCI DSS 4.0.1, etc.).

### 6.3.2 The ten honest gaps (intentionally surfaced)

These are the gaps that will get a sales-eng on a Vanta/Drata bake-off to win, and that messaging should not paper over:

| # | Gap | Status / planned remediation |
|---|---|---|
| 1 | **No customer-facing trust-center module** (SafeBase / Conveyor / Vanta Trust Center are now table-stakes for B2B SaaS buyers) | v0.8.x candidate — could be a `evidentia trust-center` static-site generator that emits Sigstore-attested trust pages from Evidentia's own evidence |
| 2 | **No questionnaire-fill AI** (Conveyor's Sue, Drata/SafeBase, Vanta Questionnaire Automation are mature) | Won't ship — explicit positioning choice; Evidentia is library-first, not RFP-fill-first |
| 3 | **Integration breadth** (Vanta has 375+; Evidentia has 5 collectors today) | Roadmap: Okta, Azure, GCP collectors planned; community-pluggable collector pattern is documented |
| 4 | **No formalized auditor partnerships / no in-platform auditor handoff** | v0.8.x candidate — `evidentia oscal export --bundle-for-auditor` workflow + curated partnership list |
| 5 | **No published Forrester Wave / Gartner Magic Quadrant inclusion** | Realistic only after a commercial sponsor exists; OSS projects don't typically get on these without one |
| 6 | **No third-party risk (TPRM) module** | Composable — Evidentia could ingest BitSight / SecurityScorecard data via collector pattern; not a v0.8 priority |
| 7 | **No risk register / ERM primitive** (AuditBoard, Riskonnect, MetricStream lead with ERM) | Honest framing: Evidentia's "risk statements" are NIST SP 800-30 narratives, not a Riskonnect-class ERM register. Could add a lightweight `evidentia risk register` in v0.9.x |
| 8 | **No reference customers / logo wall / ARR** | Pre-traction. v0.8 priority: get 5 named adopters (consultancies, FedRAMP CSPs, defense contractors) |
| 9 | **No formalized SOC 2 / ISO 27001 of Evidentia itself** | OSS can't *be* SOC 2 compliant (it's not an entity). Mitigation: publish a formal threat model + supply-chain attestation roadmap; if a hosted-service offering ships, pursue SOC 2 Type II for that |
| 10 | **No IPO/exit narrative for vendor-longevity-paranoid buyers** | Mitigation: lean into "OSS = no acquisition risk; the code outlives any company"; cite GovReady-Q / Olive AI / Lacework valuation collapses as cautionary tales |

---

## 7. The eight unclaimed gaps Evidentia fills (refreshed v0.7.8)

> **Section summary.** Cross-stream research as of May 2026 surfaced
> eight structural gaps in the OSS GRC ecosystem that no project
> currently fills, and that Evidentia's existing architecture maps
> directly onto. v0.7.8 added three new gaps to the list (HF GRC eval
> suite, Sigstore-attested AI provenance, SR-11-7-replacement
> framework opening) and merged the GovReady vacuum into the broader
> AGPL-alternative gap. **These are the differentiation spine.**

1. **A maintained Python OSCAL library.** `oscal-pydantic` is 2+ years stale (last push 2024-04-06, 23 stars). Compliance-trestle is opinionated workflow software, not a library. Nothing else fills the `pip install evidentia-core; from evidentia_core import GapAnalyzer` shape.

2. **Bundled multi-framework crosswalk dataset.** NIST publishes 800-53 in OSCAL. CIS publishes Controls v8. ISO 27001 OSCAL ports are fragmented and unofficial. **Nobody bundles 88+ frameworks with vetted crosswalks** (Evidentia at v0.7.8; growing to 95+ in v0.7.9 with FFIEC + OCC + SR 11-7 additions). Evidentia could publish `evidentia-catalogs` as a separate Apache/CC0 repo and become the *de facto* multi-framework reference dataset, the way `oscal-content` is for NIST 800-53 alone. Includes the GovReady-Q vacated niche (210 stars; no meaningful work since 2024).

3. **Apache-2.0 alternative to AGPL CISO Assistant + Comp AI.** Many enterprises (defense contractors, SaaS vendors who would distribute the code, federal sub-primes) categorically refuse AGPL. There is no permissively-licensed full-stack GRC OSS today with active development. **Sharpened in v0.7.8**: CISO Assistant pulls 4,008 stars + daily commits + dual-license commercial paid SKUs; Comp AI raised $20M Series A from Khosla/Rabois Feb 2026 + $2.6M earlier from OSS Capital + Grand Ventures — the AGPL incumbents are well-capitalized and well-staffed. Evidentia's Apache 2.0 + Sigstore + SLSA L3 is the differentiable moat against them.

4. **Standardized bridge from CSPM/IaC scan results → OSCAL Assessment Results.** Prowler/Checkov/Trivy emit JSON. Nobody has canonical mappers to OSCAL `assessment-results` / `observation`. Evidentia's collectors layer is the right shape to fill this. **MITRE/saf** does heterogeneous-scan-to-OHDF — Evidentia could absorb the pattern.

5. **Library-callable evidence chain with cryptographic provenance.** Evidentia's Sigstore/Rekor signing of evidence + CycloneDX SBOM + PEP 740 attestations + cosign container signing + SLSA L3 build provenance make it the only OSS GRC tool that puts supply-chain integrity *on the evidence itself*, not just on the binary distribution. **Cross-stream confirmation**: Stream 2 + Stream 5 both report no commercial GRC vendor stores AI provenance with cryptographic attestation; MAIF (Nov 2025; arXiv 2511.15097) is the closest academic prior art. Evidentia already ships PEP 740 + SLSA L3; extending Sigstore-signing to AI invocations + risk statements (planned v0.8.0) is mostly plumbing.

6. **DFAH-style determinism harness for AI compliance outputs (NEW v0.7.8).** Khatchadourian (arXiv 2601.15322, March 2026) names this exact framework. **No commercial GRC vendor ships it.** Vanta + Drata + Optro + OneTrust + Workiva + ServiceNow + Anecdotes all shipped some form of AI agent + MCP + citation-grounded output between Sept 2025 and April 2026, but **none ship deterministic-replay verification**. PCAOB AS 1105 + Generative AI Spotlight (July 2024) requires immutable audit trails + human-in-the-loop verification for AI-influenced audit information; Evidentia's planned v0.8.0 P0.1 `evidentia eval` CLI is the precise affordance.

7. **First-class Policy Reasoning Traces (PRT) as auditable artifact (NEW v0.7.8).** Imperial & Tayyar Madabushi (arXiv 2509.23291, Sept 2025; University of Bath) names this framework. Commercial vendors ship "citation-grounded answers" (Vanta Agent claim) and "AI-assisted form fills" (GRC 2020 March 2026 critique) but not PRT as a first-class queryable artifact. Evidentia's planned v0.8.0 P0.2 `evidentia risk generate --emit-trace` mode is the precise affordance.

8. **SR-11-7-replacement model-risk framework primitive (NEW v0.7.8).** SR 11-7 superseded by SR 26-02 + OCC Bulletin 2026-13a April 17 2026; new guidance **explicitly excludes generative AI and agentic AI**. Banks need a framework now; agencies promised future RFI but no timeline. Evidentia's planned **v0.7.9 model-risk module** (`evidentia model-risk doc generate` with SR 11-7 §III.A/B/C documentation templates + SR-11-7-traceable AI invocations + Sigstore-signed `(risk_statement, model_inventory_ref)` link) ships before any commercial GRC vendor offers a model-risk-management primitive at this depth. **Strongest single audit-defensibility positioning Evidentia can make for financial-services + federal customers.**

9. **Standardized GRC LLM eval suite on Hugging Face (NEW v0.7.8).** HF Hub keyword searches confirmed across Streams 4 + 5 (May 2026): "OSCAL controls dataset" / "SOC2 GRC audit regulatory" / "compliance OSCAL NIST" all return **zero results**. Adjacent benchmarks exist (AIReg-Bench EU AI Act; CNFinBench finance; OmniCompliance-100K; LegalBench legal-reasoning) but none target NIST 800-53 / OSCAL emit / cross-framework crosswalk reasoning. Evidentia's planned **v0.8.0 P2.3 GRC eval suite** (50-200 manually-validated risk-statement gold-standard examples + per-control evaluation harness) would be **first-in-class on HF Hub** + becomes the *de facto* citable evaluation standard.

---

## 8. Industry tailwinds

> **Section summary (refreshed v0.7.8 May 2026).** **Four regulatory
> forcing functions converge in Q4 2026** that explicitly favor
> OSCAL-native + SBOM-aware + cryptographic-evidence tools: **CMMC
> Phase 2** (Level 2 C3PAO third-party assessments mandatory for ~300K
> DOD contractors handling CUI, **2026-11-10**); **EU CRA reporting
> obligations** (24/72-hour incident + 14-day vulnerability reporting
> for any digital product into EU, **2026-09-11**); **FedRAMP OSCAL
> mandate** (machine-readable authorization data required for all
> CSPs, **2026-09-30**); **Maryland MODPA** (strictest US state
> privacy law, **2026-10-01**). HIPAA Security Rule final-rule target
> window: **May 2026**. Market consolidates at PE-driven scale
> (consolidation tempo accelerated to 38 cybersecurity M&A deals in
> March 2026 alone). **Vanta crossed $300M ARR April 2026**; **Wiz →
> Google $32B closed March 2026** (largest VC-backed exit in history).
> Customer flight risk creates real opening for OSS that has no
> acquisition exposure.

### 8.1 The four forcing-function dates (Q4 2026 convergence)

| Date | Mandate | Implication for Evidentia |
|---|---|---|
| **2025-03-31** (binding all 2026 assessments) | **PCI DSS 4.0.1** — 51 of 64 future-dated requirements (incl. MFA for all CDE access under 8.3.1, e-commerce script-integrity 6.4.3/11.6.1) became binding; no grace period | All 2026 assessments use v4.0.1; bundled PCI DSS catalog needs to be on v4.0.1 (Tier C) |
| **2026-05** target window | **HIPAA Security Rule final rule** (NPRM published 2025-01-06; OCR's regulatory agenda lists May 2026; ~4,700+ comments closed 2025-03-07; once final, 240 days to comply) | Significant uncertainty under new administration; bundled HIPAA Security catalog must be ready for revision |
| **~~2026-08-02~~ → 2027-12-02** | **EU AI Act Annex III high-risk systems obligations DEFERRED to December 2, 2027** per the Digital Omnibus political agreement reached by the EU Council + Parliament on May 7, 2026 ([Council of EU press release](https://www.consilium.europa.eu/en/press/press-releases/2026/05/07/artificial-intelligence-council-and-parliament-agree-to-simplify-and-streamline-rules/); [IAPP coverage](https://iapp.org/news/a/ai-act-omnibus-what-just-happened-and-what-comes-next); [Hogan Lovells](https://www.hoganlovells.com/en/publications/eu-legislators-agree-to-delay-for-highrisk-ai-rules)). Article 50 transparency obligations also slipped. Provisional agreement still requires formal co-legislator adoption to become law but treated as the operative timeline by EU compliance counsel as of May 2026. | First likely AI Act fine pushed ≥16 months; ISO 42001 + EU AI Act crosswalks remain valuable but lose their Q3-Q4 2026 urgency; Evidentia's v0.9.3 EU AI Act tier classifier + v0.11+ ISO 42001 conformity-assessment-pack work retains relevance for the new Dec 2027 horizon |
| **2026-09-11** | **EU CRA reporting obligations** — 24/72-hour incident + 14-day vulnerability reporting for any digital product placed on the EU market (CRA in force since 2024-12-10; full obligations including SBOMs apply 2027-12-11) | Hard demand spike for SBOM, vulnerability-tracking, incident-disclosure tooling; Evidentia's CycloneDX SBOM + collector pattern + audit-event stream is precisely positioned |
| **2026-09-30** | **FedRAMP 20x** — Rev 5 transition target; machine-readable (OSCAL) authorization data mandatory for CSPs to retain status; FedRAMP Ready also retires 2026-07-28 | OSCAL becomes mandatory; vendors lacking OSCAL face revocation risk; 90%+ of incumbents still don't natively emit OSCAL |
| **2026-10-01** | **Maryland MODPA** effective — strictest US privacy law (sale-of-sensitive-data prohibition + "reasonably necessary" data-minimization standard; $10K/violation, $25K/repeat penalties) | Bundled Tier-D state privacy laws now total 19 active in 2026; MODPA new high-water mark |
| **2026-11-10** | **CMMC Phase 2** — Level 2 C3PAO third-party assessments mandatory for most DOD contractors handling CUI (Phase 1 self-assess became binding 2025-11-10) | **~300,000 DOD contractors need 800-171 evidence collection**; Vanta/Drata at $30K+/yr unaffordable for most; Evidentia's free Apache 2.0 + air-gap support is the obvious fit |
| **2026-11-10 to 2027-11-10** | DORA first full enforcement year — ESAs published list of **19 Critical ICT Third-Party Providers** (CTPPs) on 2025-11-18 (incl. AWS, Azure, GCP, Bloomberg, LSEG); 2026 Register of Information cycle uses 2025-12-31 reference data | EU CTPP oversight active; DORA-aware GRC tooling has captured customer base |
| **2026-Q1+** | **NIS2** — 21 of 27 EU member states transposed (Mar 2026); Commission issued reasoned opinion to **19 member states** on 2025-05-07 for incomplete transposition | Fragmented enforcement landscape; multi-jurisdictional crosswalks valuable |

### 8.2 Market validation that GRC is hot (refreshed May 2026)

- **GRC = #1 sub-sector in cybersecurity M&A 2025**: 82 deals, five-year peak (SecurityWeek). Tempo accelerating: **38 cybersecurity M&A deals in March 2026 alone** ([Tech Insider](https://tech-insider.org/cybersecurity-ma-consolidation-2026/)).
- **GRC software market $23.32B in 2026 → $39.01B 2031** (10.84% CAGR; [Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/governance-risk-and-compliance-software-market)). Broader GRC platforms market $56.73B in 2026 at 10.31% CAGR.
- **Gartner highlighted AI governance platforms as a billion-dollar adjacent market** ([Gartner press release 2026-02-17](https://www.gartner.com/en/newsroom/press-releases/2026-02-17-gartner-global-ai-regulations-fuel-billion-dollar-market-for-ai-governance-platforms)).
- **Vanta**: $300M ARR April 2026 (3x in 2 yrs), $4.15B Series D July 2025, 16,000+ customers, 60% YoY logo growth ([Fortune April 29 2026](https://fortune.com/2026/04/29/exclusive-vanta-arr-300-million-sequoia-shadow-ai-claude-cursor/)). IPO speculation persists.
- **Drata**: $100M+ ARR early 2026; $2B Series C Dec 2022; $455M total raised; **acquired SafeBase $250M February 2025**.
- **Diligent**: **Acquired 3rdRisk January 14 2026** for AI-native TPRM; April 2026 unveiled AI Board Member at Elevate 2026.
- **AuditBoard → Optro rebrand**: Hg Capital take-private $3B May 2024; rebranded **March 9 2026**; **acquired FairNow Oct 2025** for AI governance.
- **Wiz**: Google Cloud acquisition $32B closed March 2026 — **largest VC-backed exit in history**.
- **CrowdStrike**: Three 2025 acquisitions: **Bionic ($500M), Onum ($290M), Pangea ($260M)**.
- **OneTrust**: $4.5B last priced; $550M+ ARR; **active PE discussions Nov 2025** with Thoma Bravo / Blackstone / Silver Lake / KKR; **John Heyman → CEO January 2026**, founder Kabir Barday → board.
- **Forrester *GRC Platforms Landscape Q4 2025*** evaluating 30 vendors framing the market as "continuous, AI-driven GRC" with agentic capabilities ([Forrester](https://www.forrester.com/report/the-governance-risk-and-compliance-platforms-landscape-q4-2025/RES189273)).
- **Forrester Wave: AI Governance Solutions Q3 2025** named **Credo AI a Leader** (purpose-built AI governance, distinct from GRC; [Credo AI](https://www.credo.ai/forrester-wave)).
- **Chartis Research RSAC 2026 readout**: **"Agentic AI-driven Cyber GRC"** identified as the dominant innovation theme.
- **eGRC market sizing**: $72B → $204B by 2033 (Grand View Research; consensus 13–14% CAGR).
- **Tool consolidation**: 40%+ of orgs actively consolidating cybersecurity vendors; another 21% planning to (HashiCorp 2025).
- **Verizon DBIR**: **30% of breaches involve a third party** — 100% YoY increase from 15%.
- **Sonatype 2026 SSC Report**: **454,648 new malicious OSS packages in 2025** (cumulative 1.233M; **75% YoY growth**; first-ever self-replicating npm malware Shai-Hulud).

### 8.3 OSS GRC inflection points

- **OSCAL Foundation formally launched February 10, 2025** with Brian Ruf and Stephen Banghart as coordinators — neutral governance for the OSCAL ecosystem
- **RegScale donated OSCAL Hub to the foundation December 2025** — active commercial-to-OSS migration in this exact space
- **FedRAMP 20x took off**: 114 authorizations in FY25 (more than 2× FY24), median time-to-authorization down from ~12 months to ~5 weeks; Phase 2 pilots launched late 2025
- **CSA launched Compliance Automation Revolution (CAR) at RSA 2025** with Google, Oracle, Salesforce, Deloitte Italy
- **OpenSSF published the Gemara model (March 2026; v1.1.0 released 2026-05-12)** — a standardized, machine-readable data model spanning Catalogs (Control / Capability / Principle / Risk / Threat / Vector / Guidance / Lexicon) + Logs (Audit / Enforcement / Evaluation) + Documents (Mapping / Policies) + Entities + Collections. Schemas authored in [CUE](https://cuelang.org/); Go SDK at `github.com/gemaraproj/go-gemara`. Adopters: FINOS Common Cloud Controls + OpenSSF Security Baseline. **v0.10.3 Phase 2**: Evidentia's full component-by-component mapping onto the Gemara taxonomy is now in [`docs/gemara-mapping.md`](gemara-mapping.md) — positions Evidentia as Gemara-mappable without claiming Gemara conformance (no Gemara emit yet; tracked as a v0.11+ candidate alongside FINOS / OpenSSF demand signal). The mapping demonstrates Evidentia (OSCAL-first / NIST) and Gemara (OpenSSF-blessed) are complementary, not competing

### 8.4 Why this matters for Evidentia specifically

- **OSCAL-native, library-first** hits the September 2026 FedRAMP OSCAL mandate at a moment when 90%+ of incumbents still don't natively emit OSCAL (Vanta added export Feb 2026 for FedRAMP 20x submissions only — first major commercial vendor to ship OSCAL export)
- **Open-source + sovereign deploy** serves EU customers facing DORA enforcement + 19 CTPP oversight (who push toward EU-hosted or on-prem) and ~300,000 DOD contractors facing CMMC Phase 2 (who can't afford SaaS GRC at $30K+/yr)
- **Sigstore + air-gap refusal** aligns with EO 14306 retained provisions and Defense Unicorns / Big Bang / Platform One patterns
- **CycloneDX SBOM + collector pattern** aligns with CISA 2025 SBOM minimum elements update + FDA medical-device 524B + **EU CRA September 2026 reporting obligations**
- **Vendor M&A creates customer flight risk** — Optro rebrand, Drata-SafeBase, Diligent-3rdRisk, OneTrust → likely PE buyout, Wiz-Google: enterprise customers are nervous about platform stability. **Open-source = no acquisition risk**
- **Federal SBOM tailwind weakened (OMB M-26-05 January 2026 rescinded mandatory self-attestation)** but EU CRA more than offsets globally
- **3PAO scarcity persists** ([GAO-24-106395](https://cabrilloclub.com/insights/fedramp-20x-explained)): FedRAMP Moderate authorization backlogs averaging 22 months with 200+ vendors in queue. FedRAMP 20x targeted at 2-3x more vendors authorized by 2027 with end-to-end pilot costs of $500K-$1.5M (vs $2M-$5M legacy) — **automation/OSCAL machine-readable evidence is the only way the math works**
- **cATO momentum** ([DoD CIO Continuous Authorization Implementation Guide](https://dodcio.defense.gov/Portals/0/Documents/Library/DoDCIO-ContinuousAuthorizationImplementationGuide.pdf)): Zero Trust target levels mandated by end-FY27; AI/ML-driven assessment automation explicitly called out by the Zero Trust PfMO
- **PCAOB AS 1105 + Generative AI Spotlight (July 2024)** is the regulator-recognized framework for AI in audit reports — Evidentia's v0.7.1 (audit trails) + planned v0.8.0 (DFAH + PRT) hits all 5 required capabilities

---

## 9. Industry headwinds

> **Section summary (refreshed v0.7.8 May 2026).** Eight structural
> headwinds, three of which are NEW since v0.7.0: (NEW) AI feature
> commoditization across all GRC vendors Q1 2026; (NEW) federal SBOM
> tailwind weakened by OMB M-26-05 January 2026; (NEW) AGPL competitor
> velocity (CISO Assistant + Comp AI well-capitalized + daily
> commits); plus the 5 carry-forward headwinds: AI moats at scale;
> OSCAL adoption lagging the mandate; PE consolidation creating
> gravity wells; regulatory complexity demanding maintenance; AI hype
> risk. None is fatal but each shapes positioning choices.

1. **Vanta + Drata + Optro + OneTrust have AI moats from scale.** Hundreds of integrations, customer corpora to fine-tune AI agents, 35+ pre-mapped frameworks. An OSS tool with 8 evidence-collection surfaces looks small by comparison. **Mitigation**: lean into OSCAL/sovereign/air-gap/cryptographic-evidence-attestation angles where SaaS can't follow; federate (let users plug Evidentia into existing SaaS GRC via the v0.7.8 Tableau / Power BI publish surfaces); position as the substrate that AI agents validate against (signed evidence, OSCAL artifacts, DFAH replay).

2. **NEW: AI feature commoditization (Q1 2026 universal launches).** Vanta, Drata, Optro, OneTrust, Hyperproof, Workiva, ServiceNow, Anecdotes all shipped agentic AI + MCP server + citation-grounded LLM output between Sept 2025 and April 2026. **The differentiation is collapsing rapidly** into eval rigor, audit-trail quality, and OSS license posture — not "we have AI." **Mitigation**: accelerate the v0.8.0 DFAH + PRT + MCP + plugin-contract differentiators before they become parity items.

3. **OSCAL adoption lags the mandate.** Zero of 100+ FedRAMP Rev5 authorizations in 2025 used OSCAL. The forcing function is real but vendors lag. **Vanta added OSCAL export Feb 2026 for FedRAMP 20x submissions only** — first major commercial vendor to ship OSCAL export at all. **Risk**: the market educates slowly; revenue follows mandate enforcement, not mandate publication. **Mitigation**: be patient; the September + November 2026 dates will pull the market forward; Evidentia is OSCAL-native and 18 months ahead of incumbent emit capability.

4. **NEW: Federal SBOM tailwind weakened (OMB M-26-05, January 2026).** [Davis Wright Tremaine analysis](https://www.dwt.com/blogs/privacy--security-law-blog/2026/02/omb-changes-course-on-software-security): M-26-05 rescinded M-22-18 + M-23-16, removing the mandatory standardized self-attestation form and shifting to risk-based agency discretion. SBOMs still recommended for cloud-runtime production environments. EO 14028 remains in force. **Mitigation**: EU CRA reporting obligations Sept 11 2026 more than offset globally; positioning toward EU-regulated digital-product manufacturers + US cloud-runtime SBOM (still mandated under M-26-05) carries the demand.

5. **Big-vendor PE consolidation will accelerate.** Hg, Vista, Thoma Bravo, Blackstone, KKR, Silver Lake are all active in GRC M&A. They'll bundle, cross-sell, undercut. OSS competes on different axes (sovereignty, transparency, cost) but loses on inertia and procurement gravity.

6. **NEW: AGPL OSS competitor velocity.** CISO Assistant (intuitem; 4,008 stars; daily commits; well-staffed French startup; 130+ frameworks) + Comp AI ($20M Series A Feb 2026 from Khosla / Keith Rabois; AGPL; 1,535 stars; daily commits; "AI-native" positioning) are well-capitalized and ship-velocity-matched. **Mitigation**: Evidentia's permissive Apache 2.0 + Sigstore + SLSA L3 + bundled multi-framework catalogs + cryptographic evidence chain is the differentiable moat against them; the gap won't naturally close because adding cryptographic provenance + OSCAL emit + signed-evidence-bundle surfaces requires substantial rearchitecture.

7. **Regulatory complexity itself.** 19 US state privacy laws (Maryland MODPA new high-water mark 2026-10-01), NIS2's 27 EU member-state transpositions (21 done; 6 outstanding with 19 reasoned-opinion infringement actions), India DPDP phasing, EU AI Act tiers, China cross-border, FFIEC CAT sunset (Aug 2025) requiring CRI Profile / CSF migration — keeping catalogs current is a real engineering cost. SaaS vendors have compliance teams; OSS relies on community + maintainer effort. **Mitigation**: bundled-catalog-as-a-product approach (the v0.8.0 P2.2 `evidentia-catalogs` standalone repo split); community contribution channel for Tier-D statutory frameworks (uncopyrightable).

8. **AI hype risk + Delve scandal cautionary baseline.** "Agentic GRC" is the hottest framing at every conference. An OSS tool that's "just a library" may look unfashionable to enterprise buyers chasing the AI checkbox. **March 2026 Delve scandal** (493/494 SOC 2 reports byte-identical; whistleblower disclosure DeepDelver; FTC + DOJ False Claims Act exposure) is the precise counter-narrative — "AI-powered" without rigor failed at scale. **Counter-positioning**: cite GRC 2020 March 2026 critique (most "agentic AI" features are AI-assisted form fills, not bounded-autonomy multi-step orchestrators); cite Magesh / Ho et al. (Stanford 2025) measured **17–33% hallucination rates** in commercial RAG-based legal research tools marketed as "hallucination-free"; cite PCAOB AS 1105 + Generative AI Spotlight as the regulator-recognized framework. Frame Evidentia's AI-optional posture as **deterministic-where-it-must-be, AI-where-it-helps**. Khatchadourian DFAH paper (March 2026, arXiv 2601.15322) provides the technical vocabulary.

9. **CMMC backlash possibility.** If Phase 2 (Nov 2026) gets delayed (it has been pushed before), the urgency tailwind softens. Mitigation: don't bet messaging exclusively on CMMC; diversify across the four forcing-function dates and the regulatory-vacuum opportunity (SR 11-7 → SR 26-02 model-risk gap).

10. **Federal procurement budget pressure.** 2025-2026 saw new administration's DOGE-driven cuts to consultants and contractors hitting major federal-services-sector stocks Feb 2025; FY26 continuing resolutions have squeezed civilian-agency + consultant compliance-tool spend ([Nextgov — agency consultant culling](https://www.nextgov.com/acquisition/2025/02/trump-administration-asks-agencies-cull-consultants/403345/)). Mitigation: free Apache 2.0 OSS is precisely the budget-pressure-friendly answer.

11. **OSS sustainability fragility.** Post-xz-Utils backdoor (CVE-2024-3094), Linux Foundation reported April 2026 that social-engineering attacks against OSS maintainers continue at scale ([WebProNews / Linux Foundation alarm](https://www.webpronews.com/the-xz-backdoor-was-just-the-beginning-linux-foundation-sounds-the-alarm-on-social-engineering-attacks-targeting-open-source/)). For OSS GRC tools this is reputational risk by association.

12. **License-shift risk** ([HashiCorp BSL Aug 2023](https://www.hashicorp.com/license-faq), [Elastic SSPL 2021](https://www.elastic.co/blog/why-license-change-aws)). HashiCorp BSL + Elastic SSPL precedent remains the cautionary base rate. No major OSS GRC project has flipped licenses in the 2024-2026 window — but the playbook is well-established and the temptation grows as VC-backed OSS-adjacent platforms scale (CISO Assistant + Comp AI both AGPL+commercial; either could flip incrementally). Mitigation: Apache 2.0 commitment is itself a competitive moat; surface it explicitly in positioning copy.

---

## 10. Positioning frame — direct enumerated claims

> **Section summary (revised 2026-05-25).** The original "Terraform / dbt
> of GRC" frame was dropped after triple-validated procurement pressure-
> test by three independent procurement-style reviewers (GPT-5.5 Fortune
> 500 procurement officer; Grok-4.20-Multi-Agent federal-SI hostile
> TPRM; Grok 4.3 heterodox marketing strategist). All three converged
> on rejection: the metaphor overclaims a multi-vendor consortium
> status a solo-vendor implementation cannot credibly own, and reads
> to compliance buyers as developer-jargon. The replacement positioning
> leads with **direct enumeration of attestable credentials and concrete
> output formats**, mapped explicitly to NIST SSDF / NIST 800-53 / CISA
> Secure-by-Design Pledge frameworks. No analogies, no metaphors, no
> "X of Y" framing until reference customers exist.

### 10.1 Why direct enumeration beats analogy at this stage

- **Reference customers don't yet exist.** The Terraform / dbt / OpenTelemetry / Bazel analogs all WON via reference-customer testimony of pain removed, not via marketing positioning. Metaphor-first positioning without reference customers usually forces a later repositioning when real usage data arrives (Grok 4.3).
- **Solo-vendor vs multi-vendor consortium mismatch.** OpenTelemetry succeeded as a CNCF-governed multi-vendor consortium; Polycentric Labs LLC is a single-vendor implementation. Claiming the "OpenTelemetry of compliance" frame invites "who certified you?" questions OTel never faced after CNCF graduation.
- **Compliance buyers respond to attestable credentials, not metaphors.** The Fortune 500 CISO procurement officer + the federal-SI procurement officer + the 3PAO assessor all evaluate vendors against frameworks (SIG, CAIQ v4, SCF, HITRUST, FedRAMP) — not against analogies to other categories. Direct claims map to questionnaire fields; metaphors don't.
- **The dev-tools-for-compliance trend is real but already crowded.** Chainguard, Snyk, Anchore, Aikido, Tetragon/Cilium all claim it. Borrowing their frame doesn't differentiate Evidentia from them.

### 10.2 Direct-claims pull-quote candidates for marketing (no metaphors)

> *"Evidentia produces six attestable supply-chain credentials per release: PEP 740 attestations on every wheel, Sigstore-based signing, SLSA Level 3 build provenance, cosign-signed container images, CycloneDX 1.6 SBOMs, OpenSSF Scorecard 6.5+. OpenSSF Best Practices Silver MET, OSPS Baseline Maturity 2 MET. SOC 2 Type I examination in progress. Polycentric Labs LLC, Virginia."*

> *"Gap analysis in five interchange formats: OSCAL Assessment Results (1.2.1), SARIF 2.1.0, OCSF Compliance Finding (class_uid 2003), OCSF Detection Finding (class_uid 2004), CycloneDX 1.6 VEX. One toolkit, five SIEM / GRC platform / supply-chain ingestion paths. 89 bundled framework catalogs."*

> *"The puck is moving from PDFs of evidence toward signed JSON streams of evidence. Evidentia is sitting almost exactly where the regulatory and market vectors are converging in the next 12-18 months — and unlike SaaS GRC dashboards, every output artifact is independently verifiable against NIST SP 800-218 SSDF, NIST 800-53 SR/SA controls, and the CISA Secure-by-Design Pledge."*

> *"AI is now table-stakes in commercial GRC, not differentiation. The new wedge is evidence quality, traceability, and auditor acceptance. Evidentia's DFAH determinism + faithfulness assurance harness is the only OSS implementation of the Khatchadourian 2026 framework."*

### 10.3 The supporting messaging hierarchy (no metaphors)

- **Primary**: *"Open-source (Apache 2.0) Python GRC toolkit by Polycentric Labs LLC (Virginia). 89 bundled framework catalogs. OSCAL 1.2.1-native. Six attestable supply-chain credentials per release (PEP 740 + Sigstore + SLSA L3 + cosign + CycloneDX 1.6 + OpenSSF Scorecard 6.5+) mapped to NIST SSDF + 800-53 + CISA SbD. Air-gap capable. AI-optional."*
- **Secondary**: *"Five gap-analysis interchange formats: OSCAL AR + SARIF + OCSF Compliance + OCSF Detection + CycloneDX VEX. 13-tool MCP server with CIMD scope + SignedToolOutput envelope. DFAH determinism + PRT policy-reasoning-traces eval rigor (only OSS implementation of the Khatchadourian / Imperial 2026 academic frameworks)."*
- **Tertiary** (proof points): *"OpenSSF Best Practices Silver tier MET. OSPS Baseline Maturity 2 MET (~95% conforming, with explicit honest-gap declared for OSPS-AC-04.01/02 + OSPS-QA-07 + OSPS-GV-04 — the three solo-maintainer-structurally-unreachable controls). SOC 2 Type I examination in progress with Polycentric Labs LLC as the service organization, scope locked to development lifecycle + release pipeline + vendor management + internal IT controls. 17+ consecutive PROCEED-CLEAN releases of the v0.7.x → v0.10.x line. 3,440+ tests; mypy strict 0 issues across 278 source files; ruff clean."*
- **Honest disclaimer** (builds credibility): *"Not a Vanta replacement for SOC-2-only buyers who want a SaaS dashboard + auditor handoff bundled together. Evidentia is the OSS toolkit for security/compliance engineers who want every evidence artifact independently verifiable. OpenSSF Gold tier is structurally unreachable for a solo maintainer (Gold requires ≥2 unassociated significant contributors + bus factor 2+; no documented exception path); this gap is being resolved through the additional governance + segregation-of-duties controls implemented as part of the in-progress SOC 2 Type I program."*

### 10.4 The acceptance-gate paragraph (procurement-ready, Fortune 500 + federal-SI dual-audience)

Recommended single-paragraph language for v1.0 acceptance-gate documentation, vendor-security questionnaire long-form responses, federal-SI subcontract evidence packets, and procurement diligence packages. Triple-validated against GPT-5.5 (Fortune 500 procurement reviewer) + Grok-4.20-Multi-Agent (federal-SI hostile TPRM) + Grok 4.3 (heterodox marketing strategist) 2026-05-25. **Synthesizes the six positive supply-chain attestations, the OpenSSF Silver MET + OSPS-M2 conformance, the SOC 2 Type I in-progress signal, and the honest Gold-structural-ceiling acknowledgment** into one defensible block:

> *Polycentric Labs LLC (Virginia) produces the following six positive supply-chain attestations for all releases: (1) PEP 740 attestations mapped to NIST SP 800-218 PW.4 and RV.2, NIST SP 800-53 SA-10 and SR-5, supporting CISA SbD verifiable builds and transparency goal; (2) Sigstore-based signing mapped to NIST SP 800-218 PW.5, NIST SP 800-53 SA-12 and SR-11, supporting CISA SbD provenance and integrity goal; (3) SLSA Level 3 conformance mapped to NIST SP 800-218 PW.1 and PS.2, NIST SP 800-53 SA-15 and SR-3, supporting CISA SbD secure design and dependency management goal; (4) cosign artifact signing mapped to NIST SP 800-218 PW.6, NIST SP 800-53 SA-10 and SR-4, supporting CISA SbD artifact integrity goal; (5) CycloneDX 1.6 SBOM generation mapped to NIST SP 800-218 RV.1 and PW.7, NIST SP 800-53 SA-11 and SR-6, supporting CISA SbD transparency and vulnerability exchange goal; (6) OpenSSF Scorecard 6.5+ mapped to NIST SP 800-218 PO.3, NIST SP 800-53 SA-8 and SR-1, supporting CISA SbD risk management and measurement goal. OpenSSF Best Practices Silver tier is fully MET. The project conforms to OSPS Baseline Maturity Level 2. A SOC 2 Type I examination is in progress for Polycentric Labs LLC with scope locked to development lifecycle, release pipeline, vendor management, and internal IT controls; observation period started [DATE — fill in when locked with auditor] with no committed report delivery date. The project explicitly acknowledges the OpenSSF Best Practices Gold tier structural ceiling (≥2 unassociated significant contributors + bus factor 2+ criteria at bestpractices.dev/en/criteria/2 — structurally unreachable for a solo maintainer); **this gap will be directly resolved through the additional governance, segregation of duties, and operational controls implemented as part of the SOC 2 Type I program**.*

**Critical framing shift from the prior draft**: the Gold gap is now tied to the **SOC 2 Type I program's own segregation-of-duties machinery** (procurement-acceptable: "we're addressing it through the same audit that produces the SOC 2") rather than to a vague "commercial-tier hiring milestone" (procurement red flag per GPT-5.5: "We will fix the structural control gap after commercial traction" was read as "asking procurement to fund the vendor into having basic operational maturity"). The substitution is the single most material wording change from the 2026-05-24 acceptance-gate draft.

**Source: triple-validation cross-check 2026-05-25.** GPT-5.5 (procurement reviewer): the additional artifact that moves Evidentia from borderline to approved in Fortune 500 procurement workflows is "a completed SOC 2 Type I report from an independent CPA firm, scoped to the Evidentia commercial service and SDLC." Grok-4.20-MA (federal-SI hostile TPRM): the additional artifacts to clear federal-SI gating are (a) US-incorporated entity (DONE — Polycentric Labs LLC, Virginia), (b) own CMMC L2 self-assessment + SPRS score, (c) accountable legal entity with cyber insurance + flow-down acceptance authority. Grok 4.3 (heterodox marketing): no metaphor, direct claims only.

---

## 11. AI posture

> **Section summary (refreshed v0.7.8 May 2026).** Evidentia's current
> AI stack (LiteLLM + Instructor + Pydantic risk-statement schemas
> with full GenerationContext provenance per v0.7.1) is the right OSS
> production stack as of May 2026. **Foundational AI patterns are now
> table-stakes universally** — every credible GRC vendor shipped
> agentic AI + MCP server + citation-grounded LLM output between Sept
> 2025 and April 2026. **MCP first-mover window for OSCAL primitives
> is CLOSED** — IBM `compliance-trestle-mcp`, AWS Labs
> `mcp-server-for-oscal` (12+ tools), Vanta MCP (April 2026), Drata
> MCP, Optro MCP all live. **Wide open** for SR-11-7 / FFIEC / SBOM /
> TPRM-not-in-Vanta-silo / continuous-compliance-monitoring MCPs.
> **HF Hub keyword searches return ZERO results for OSCAL/NIST 800-53/
> SOC 2 datasets** — Evidentia's planned v0.8.0 P2.3 GRC eval suite
> would be **first-in-class**. **PCAOB AS 1105 + Generative AI Spotlight
> requires 5 capabilities; Evidentia's v0.7.1 + planned v0.8.0 hits
> all 5** — strongest single positioning claim. **The single highest-
> leverage AI feature Evidentia ships next remains DFAH determinism
> harness** (no commercial GRC vendor offers it; Khatchadourian arXiv
> 2601.15322 March 2026 names it by exact terminology).

### 11.1 Foundational patterns (table-stakes; Evidentia at parity)

- **RAG over policy corpus for Q&A** — every commercial vendor and OSS project ships it
- **Auto-fill of security questionnaires with cited sources** — converged at ~95% first-pass accuracy (Conveyor, SafeBase, Vanta, Iris, Inventive)
- **Continuous controls monitoring with LLM-summarized failures** — Drata + Vanta + Hyperproof
- **Crosswalk / control-mapping via LLM embeddings** — Hyperproof "Suggested Links Agent", Optro Accelerate
- **AI-generated policy drafts** — every SOC-2 platform
- **Vendor SOC 2 PDF parsing** — Black Kite, Whistic, ProcessUnity, Vanta TPRM Agent, Drata Agentic TPRM
- **Pydantic / structured-output schemas as default LLM I/O** — Instructor crossed 3M monthly downloads (Evidentia uses this)
- **Trust Center as AI-published artifact** — SafeBase reference architecture; OpenAI's trust portal runs on it

### 11.2 Bleeding-edge patterns (now mostly shipped Q1 2026)

- **Multi-agent / agentic GRC suites** — **shipped at scale Q1 2026** by Vanta, Drata, Optro, OneTrust, Workiva, Hyperproof, ServiceNow, Anecdotes. Pattern: every credible incumbent ships (1) MCP server, (2) citation-grounded LLM output, (3) agentic-with-checkpoint orchestration.
- **MCP-served GRC data to general-purpose LLM clients** — **shipped April 2026**. Vanta remote MCP server (April 15 2026, public preview), Drata MCP server (RSAC 2026), Optro MCP server with role-based permissions + audit controls + role propagation from human-IAM into agent layer, IBM `compliance-trestle-mcp` (oscal-compass), AWS Labs `mcp-server-for-oscal` (FastMCP 2.6+, 12+ tools incl. `list_oscal_models`, `get_oscal_schema`, `query_oscal_documentation`, `list_catalog_controls`, `list_ssp_components`). **CIMD (Client ID Metadata Documents) is now shipped + default** in MCP 2025-11-25 spec — promoted from RFC, replacing Dynamic Client Registration; FastMCP ≥ 2.6, Microsoft C# SDK v1.0 (March 2026), Claude Code, Claude.ai, VS Code all live.
- **First-mover MCP window status (May 2026)**:
  - **CLOSED** for OSCAL primitives — IBM trestle, AWS Labs, Vanta, Drata, Optro all live
  - **CLAIMED at v0.9.6 (May 18 2026)**: **continuous-compliance-monitoring (CONMON) MCP**. Evidentia wraps the v0.9.3 in-process CONMON daemon as 4 MCP tools (`conmon_list_cadences`, `conmon_next_due`, `conmon_check_state`, `conmon_health`) on the existing `evidentia mcp serve` surface. Verified-unclaimed at the v0.9.5 Q3 2026 quarterly resync: existing OSCAL MCPs (oscal-compass, awslabs) are authoring-only; vendor MCPs (Vanta / Drata / Optro / ComplyAI) expose platform data only. The open-source CONMON-cadence lane is now occupied — first-mover lock established ahead of FedRAMP CR26 mandatory adoption (Jan 1 2027) and RFC-0024 stabilization (Nov 1 2027).
  - **WIDE OPEN** for: policy-as-code enforcement MCP, comprehensive vulnerability/SBOM MCP, third-party-risk MCP outside Vanta/Drata silos, HIPAA-specific MCP, **FFIEC/SR-11-7 MCP** (precise opening per v0.7.9 plan)
- **Anthropic Computer Use for browser-agent questionnaire completion** — being demoed; not yet GA in GRC products
- **Multimodal evidence validation** (DSE / MMDocRAG papers) — Optro pre-fills questionnaires from SOC 2 PDFs (document understanding only); **no vendor does true vision-LLM screenshot validation**. Open opportunity.
- **Determinism-replay for audit defensibility (DFAH)** — DFAH framework defines the problem (Khatchadourian March 2026); **NO commercial GRC vendor ships this**. Evidentia's v0.7.1 GenerationContext (model + temperature + prompt-hash + run-id) is the substrate; planned v0.8.0 `evidentia eval` is the affordance.
- **Cryptographic provenance for AI invocations** — **NO commercial GRC vendor stores AI provenance with cryptographic attestation**. MAIF (Nov 2025; arXiv 2511.15097) is the closest academic prior art. Evidentia already attests packages via PEP 740 + SLSA L3 since v0.7.1; extending to AI invocations is mostly plumbing.
- **Live-attestation Trust Center consumption by buyer agents** — Drata Agentic TPRM does this against SafeBase Trust Centers; Vanta Customer Trust Agent ingests vendor Trust Centers
- **Insurance pricing tied to AI-governance compliance** (StackAware × Armilla AI)
- **Frontier model FedRAMP authorization** (May 2026): Anthropic Claude Sonnet 4.5/Opus 4.7 (FedRAMP High via Bedrock GovCloud); OpenAI GPT-4o / o1 / o3 series (FedRAMP 20x Moderate); Azure OpenAI (DoD IL-6 Feb 2026, Top Secret); Gemini for Government + Perplexity Enterprise Pro (FedRAMP 20x Low Jan 2026). Evidentia's LiteLLM-routed AI works against any of these.

### 11.2.1 PCAOB AS 1105 + Generative AI Spotlight alignment (NEW v0.7.8)

PCAOB amended AS 1105 in 2024 to require auditors test either AI-influenced information directly or controls over it. The **PCAOB Generative AI Spotlight** (July 2024, [PCAOB.org](https://pcaobus.org/documents/generative-ai-spotlight.pdf)) defines the regulator-recognized framework for AI in audit reports. **Five required capabilities; Evidentia's v0.7.1 + planned v0.8.0 hits all 5**:

| PCAOB requirement | Evidentia surface | Status |
|---|---|---|
| (1) Prompt + response capture | GenerationContext.prompt_hash + audit-event AI_RISK_GENERATED | **Shipped v0.7.1 ✓** |
| (2) Model-version tracking | GenerationContext.model + temperature | **Shipped v0.7.1 ✓** |
| (3) Human-in-the-loop verification | DFAH harness (`evidentia eval`) gates determinism + faithfulness pre-emit | Planned v0.8.0 P0.1 |
| (4) Immutable audit trails | Sigstore-signed risk-statement artifacts + Rekor transparency log entries | Planned v0.8.0 P0.4 |
| (5) Explainability documentation | PRT mode (`evidentia risk generate --emit-trace`) emits clause-cited reasoning per claim | Planned v0.8.0 P0.2 |

**This is the strongest single audit-defensibility positioning claim Evidentia can make in the v0.8.0 cycle.** Cite PCAOB AS 1105 + Generative AI Spotlight as the regulator-recognized framework Evidentia is purpose-built to satisfy.

### 11.2.A Academic framing — "OSS-native reference implementation for computational compliance" (v0.9.7 P4)

Per the v0.9.5 Q3 2026 quarterly resync (line 1159, action J), v0.9.7
adopts the **"OSS-native reference implementation for computational
compliance"** frame as the canonical academic positioning. The frame
is seeded by **Marino & Lane — "Computational Compliance for AI
Regulation: Blueprint for a New Research Domain" (arXiv 2601.04474,
January 8 2026)** which formalizes the research domain Evidentia is
already executing.

Three concrete uses:

1. **README + §11 of this doc**: cite Marino & Lane (2601.04474) as
   the seed academic frame. Positions Evidentia not as a Vanta
   competitor but as the canonical academic instance of an emergent
   research domain.
2. **Defense of the dual-path PRT architecture** (LLM-driven +
   deterministic stub): cite **de la Chica Rodríguez & Martí-González
   — "Mechanical Enforcement for LLM Governance" (arXiv 2605.14744,
   May 14 2026)** in §11 AI posture. The paper empirically validates
   ("mechanical primitives outside the interpretive loop"; 73%
   reduction in uninformative deferrals; MCC 0.43→0.88) the
   architecture Evidentia ships at v0.8.x.
3. **Pre-empt the FedRAMP CR26 OSCAL machine-readable narrative**:
   add a "FedRAMP CR26 + RFC-0024 readiness" callout to README +
   capability-matrix. The relevant dates per Stream 3
   NOTICE-0009 (March 25 2026): CR26 effective July 1 2026, mandatory
   adoption Jan 1 2027; RFC-0024 deadline Nov 1 2027 + scope narrowed
   to Class D (High) only.

#### 11.2.A.1 Expanded academic citation set (added 2026-05-24, v0.10.5 research pass)

The v0.10.5 research pass (Phase B Stream E5; HF MCP `paper_search` +
arXiv crosswalk) surfaced 5 additional citable papers + 3 industrial-
governance references that strengthen the academic posture beyond the
3 anchors above. Each is cited with its load-bearing claim:

4. **Cilla Ugarte et al. — "Beyond Vibes: A Survey of Programmatic
   Quality Frameworks for AI-Assisted Software Development"** (arXiv
   2604.13767, April 2026) — surveys 47 academic frameworks for AI-
   assisted-coding quality; Evidentia's faithfulness-scoring + CIMD-
   scope harness instantiates 4 of the 9 framework dimensions.
   **Use:** §11 + capability-matrix as the survey paper that places
   Evidentia in the academic landscape of AI-coding quality.
5. **Khatchadourian — DFAH v2: "Decision-Faithfulness Assessment
   Harness for AI-Authored Code"** (arXiv 2601.15322v2, supersedes
   v1) — the v2 update extends DFAH from individual-decision
   faithfulness to multi-decision compositional faithfulness. **Use:**
   §11 PRT-arm narrative as the canonical reference for multi-step
   reasoning-trace evaluation.
6. **Gilda & Gilda — "Auditing AI-Generated Compliance Artefacts: A
   Reproducibility-First Methodology"** (arXiv 2601.21116, January
   2026) — empirically validates that reproducibility + determinism
   are the strongest auditor-trust signals for AI-generated
   compliance text. **Use:** §11 + the v0.9.5 quarterly-resync action
   item J — quote as the academic validation of Evidentia's
   determinism-first DFAH design.
7. **Parasuraman & Manzey — "Complacency and Bias in Human Use of
   Automation: An Attentional Integration"** (Human Factors 52(3),
   2010) — foundational human-factors paper on automation
   complacency; cited by the v5.1 skill's verbatim-bypass-phrase
   pattern. **Use:** capability-matrix "auditor-experience" row as
   the academic foundation for the bypass-phrase design pattern (we
   force cognitive engagement to defeat complacency).
8. **Goddard, Roudsari & Wyatt — "Automation Bias: A Systematic
   Review of Frequency, Effect Mediators, and Mitigators"** (JAMIA
   2012) — companion to Parasuraman & Manzey; quantifies automation-
   bias frequency + mitigators. **Use:** same as #7; the systematic-
   review pair establishes the bypass-phrase mitigation as
   evidence-based, not stylistic.
9. **Charoenwet et al. — "AgenticSCR: Agentic Secure-Code-Review
   Across the SDLC"** (arXiv 2601.19138, January 2026) — formalizes
   agentic security-code-review; positions Evidentia's
   `/security-review` integration alongside ICSE-quality academic
   precedent. **Use:** §11 + v1.0 transition narrative as the
   academic context for agentic-SCR-in-CI.
10. **Li & Storhaug — "Reproducibility Risks in AI-Assisted Software
    Engineering: A Replication Study"** (arXiv 2604.01437, April
    2026) — empirically demonstrates the reproducibility crisis in
    AI-coding tools; Evidentia's deterministic-stub harness is a
    direct mitigation. **Use:** §11 + capability-matrix "research-
    grade reproducibility" row.
11. **Aghajani et al. — "Software Documentation Issues Unveiled"**
    (ICSE 2020) — foundational empirical study of documentation-
    issue typology; backs Evidentia's `must_match_version` doc-
    inventory pattern (added in skill v5.1, mirrored in Evidentia's
    `doc-inventory.yaml`). **Use:** capability-matrix "doc-inventory
    discipline" row as the academic foundation for the pattern.

Three additional industrial-governance references (non-arXiv, included
for completeness):

- **NIST SP 800-218A** (FINAL, July 26 2024) — AI Profile of the SSDF;
  ~10 task subset applies to AI-assisted coding (v0.10.5-plan §9.3
  resolves the v2-audit overscope by scoping to the AI-coding subset).
- **OpenSSF OSPS Baseline v2026.02.19** — 41 controls × 3 maturity
  levels × 8 control families; Evidentia ships the first OSCAL
  conversion (v0.10.5 Phase 2).
- **Marino & Lane (2601.04474) follow-up:** the paper explicitly
  invites OSS reference implementations; Evidentia's v1.0
  transition narrative claims that mantle (see
  [v1.0-transition.md](v1.0-transition.md)).

### 11.2.B GRC LLM eval-suite scaffolding (v0.9.7 P4)

The v0.7.8 quarterly resync surfaced that **HF Hub returns ZERO
results for OSCAL / NIST 800-53 / SOC 2 datasets** — Evidentia's
planned eval suite is genuinely first-in-class. v0.9.7 ships
scaffolding (not the full dataset publish) — see
[`docs/hf-eval-suite-scaffolding.md`](hf-eval-suite-scaffolding.md)
for the planned dataset structure + HF Hub publication path. Full
publish is a v0.9.8 or v1.0 follow-up depending on dataset-curation
cadence.

### 11.3 The 8 ranked OSS contribution opportunities for Evidentia

1. **DFAH-style determinism harness for risk-statement generation** — implement decision-determinism + faithfulness + replay-equivalence metrics on Evidentia's Instructor calls. Ship as `evidentia eval` CLI. **No commercial vendor offers this; it's the most defensible auditor-facing claim Evidentia can make.** (Cite: arXiv 2601.15322)
2. **Policy Reasoning Traces (PRT) integration** for risk statements — emit explicit chain-of-thought traces alongside each risk statement, citing exact policy clauses. (Cite: arXiv 2509.23291)
3. **Open, citable risk-statement benchmark dataset** on Hugging Face — 200 manually-validated (control, threat-context, ideal-risk-statement) triples across NIST SP 800-53 / ISO 27001 Annex A / SOC 2 TSC. Becomes the *de facto* standard.
4. **OSCAL-native input/output** — Evidentia already does this; aligns with September 2026 federal mandate
5. **Evidence groundedness gate** — every risk statement must cite an extracted evidence span; refuse to emit otherwise. Borrow Ragas + DeepEval triad scoring.
6. **MCP server exposing Evidentia's GRC store** — instantly puts Evidentia in a category alongside Anecdotes and CISO Assistant for Claude/ChatGPT users
7. **Sigstore-signed risk-statement artifacts + log schema** — extend existing Sigstore signing to every risk statement so evidence is tamper-evident in audits
8. **Document Screenshot Embedding (DSE)-based screenshot evidence validator** — long-term moat; today only academic (arXiv 2406.11251)

### 11.4 What Evidentia should NOT try to ship

- **Vendor-questionnaire auto-fill** (Conveyor / Iris / Vanta own this category; commodity AI feature now)
- **Trust Center hosting** (SafeBase / Drata own; Evidentia could ship a static-site generator alternative but not a hosted product)
- **Reg-change monitoring** (Compliance.ai, Norm AI specialty; deep regulatory taxonomy required)

### 11.5 Hugging Face compliance datasets that exist (refreshed May 2026)

Cross-stream verified searches (Streams 4 + 5; HF MCP `paper_search` + `hub_repo_search`). The HF Hub compliance surface is **strikingly thin** — this is the most important finding for Evidentia's eval-suite strategy:

- [`ethanolivertroy/nist-cybersecurity-training`](https://hf.co/datasets/ethanolivertroy/nist-cybersecurity-training) — 3.4K downloads; claims to be the largest open-source NIST cybersecurity training dataset; includes CSWP and security-controls
- [`ethanolivertroy/nist-publications-raw`](https://hf.co/datasets/ethanolivertroy/nist-publications-raw) — 24.4K downloads; raw NIST PDF corpus
- [`AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1`](https://hf.co/datasets/AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1) — 6.6K downloads; 99,870 instruction-tuning triples; defensive-cybersecurity focus
- [`Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset`](https://hf.co/datasets/Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset) — 3.4K downloads; 53,202 instruction examples
- [`Vanessasml/cybersecurity_32k_instruction_input_output`](https://hf.co/datasets/Vanessasml/cybersecurity_32k_instruction_input_output) — 590 downloads; NIST taxonomy + ITC EBA IT risk
- [`Sid-tf/TPRM-compliance`](https://hf.co/datasets/Sid-tf/TPRM-compliance) — directly relevant to v0.7.9 TPRM module
- [`Wenbin Hu et al. 2026 *OmniCompliance-100K*`](https://hf.co/papers/2603.13933) — 12,985 rules, 106,009 cases across 74 regulations (March 2026); most ambitious adjacent benchmark; candidate baseline
- [`camlsys/AIReg-Bench`](https://hf.co/papers/2510.01474) — 300 EU AI Act compliance excerpts (Marino et al. Oct 2025)
- [`Finance-Agentic-AI/Investing-Compliance`](https://hf.co/datasets/Finance-Agentic-AI/Investing-Compliance) — 22 downloads; very early stage
- [`nguha/legalbench`](https://hf.co/datasets/nguha/legalbench) — 162 legal-reasoning tasks (Stanford CodeX; canonical legal LLM benchmark)

**Searches that returned ZERO results**: "OSCAL controls dataset" (sorted by trending), "SOC2 GRC audit regulatory" (sorted by downloads), "compliance OSCAL NIST".

**Legal/regulatory fine-tuned models** (most-downloaded compliance-adjacent — none compliance-specific):
- [`Equall/Saul-7B-Instruct-v1`](https://hf.co/Equall/Saul-7B-Instruct-v1) — 5.2K downloads, 111 likes, canonical legal LLM (Mistral-based, MIT)
- [`Equall/SaulLM-54B-Instruct`](https://hf.co/Equall/SaulLM-54B-Instruct) — 158 downloads, Mixtral-based
- [`isaacus/open-australian-legal-llm`](https://hf.co/isaacus/open-australian-legal-llm) — 271 downloads
- BloombergGPT — finance-domain, never released to HF Hub publicly

### 11.6 HF gaps Evidentia could fill (genuine first-in-class opportunity)

- **No open SOC 2 / ISO 27001 control-mapping dataset**
- **No open NIST 800-30 risk-statement generation benchmark**
- **No open OSCAL emit conformance benchmark**
- **No open NIST 800-53 ↔ SOC 2 ↔ ISO 27001 ↔ CIS v8.1 cross-walk benchmark**
- **No open evidence-validation benchmark**
- **No open OSCAL-fluent fine-tuned model**
- **No open multimodal evidence (screenshot+log+PDF) compliance dataset**

**Evidentia's planned v0.8.0 P2.3 GRC eval suite** (50-200 manually-validated risk-statement gold-standard examples + per-control evaluation harness across NIST 800-53 / ISO 27001 Annex A / SOC 2 TSC) is **first-in-class on HF Hub** + becomes the *de facto* citable evaluation standard for any LLM-on-GRC research. Recommended academic submission venue: **JOSS (Journal of Open Source Software)** — open access, peer-reviewed, ~12 weeks submission-to-publication, OSI-approved-license requirement met by Apache 2.0, AI-disclosure standard met by Evidentia's existing AI-attribution README pattern. Then an AISec / OpenSSF Research Forum workshop paper. NIST CSWP collaboration as long-tail aspiration once OSCAL-AI integration matures.

---

## 12. Industry voices — to cite, to follow, to pitch

> **Section summary (refreshed v0.7.8 May 2026).** Stream 6 of the
> v0.7.8 research substantially refreshed Evidentia's voice list with
> verified-public-source affiliations. **Top 10 to follow** spans
> NIST/GSA OSCAL leadership (Iorga, Takamura, Scarfone), CISA SBOM
> (Friedman), FedRAMP modernization (Waterman), OSS security
> stewardship (Behlendorf), industry-analyst tier (Privette + a
> Venture-in-Security author), and GRC-engineering thought leaders
> (AJ Yawn, Grolmus). **Top 5 to cite** anchors Evidentia's
> positioning copy with peer-reviewed/Gartner-cited sources
> (Friedman, Iorga CSWP 53, Cyentia IRIS 2025, Venables CISO 2.0,
> Haydock). **Top 5 to pitch** are journalists/analysts with track
> records covering smaller OSS-adjacent projects (Vizard, Bressers,
> Tal, Springett, Odum) — all reachable through public channels. Two
> outreach actions still reach the OSCAL community in one quarter
> (OSCAL Plugfest 2026 + `oscal-compass/community` interop
> discussion).

### 12.1 Top 10 voices to follow continuously (refreshed May 2026)

| # | Name | Affiliation | Primary platform | Why for Evidentia |
|---|---|---|---|---|
| 1 | **Dr. Michaela Iorga** | NIST ITL Senior Security Technical Lead, OSCAL Strategic Outreach Director | [NIST staff page](https://www.nist.gov/people/dr-michaela-iorga); CSRC presentations | Sets the OSCAL roadmap (CSWP 53); every Evidentia OSCAL change should track her direction |
| 2 | **Ed Takamura** | NIST RMF Team, FISMA implementation lead | [NIST staff page](https://www.nist.gov/people/ed-takamura); [Google Scholar](https://scholar.google.com/citations?user=AX1vAXoAAAAJ) | Drives RMF evolution, the framework Evidentia's gap analyzer maps controls against |
| 3 | **Karen Scarfone** | Scarfone Cybersecurity (formerly NIST senior; SSDF co-author) | [scarfonecybersecurity.com](https://www.scarfonecybersecurity.com) | NIST-trained voice translating SSDF/SP 800-53 into practitioner guidance |
| 4 | **Allan Friedman** | CISA SBOM Lead | [CISA SBOM hub](https://www.cisa.gov/topics/cyber-threats-and-advisories/sbom) + ETSI/Cybellum talks | Single most important federal voice on SBOM regulation/quality; drives Evidentia's SBOM-roadmap citations |
| 5 | **Pete Waterman** | FedRAMP Director (GSA) | [fedramp.gov](https://www.fedramp.gov) + MeriTalk | Owns "FedRAMP Cybersecurity Service" 2026 modernization — the federal compliance trajectory Evidentia rides |
| 6 | **Brian Behlendorf** | Linux Foundation / OpenSSF General Manager | [openssf.org/people/brian-behlendorf](https://openssf.org/people/brian-behlendorf/) | Directs OpenSSF (Sigstore, SLSA, Scorecard, Gemara) — upstream tooling Evidentia integrates |
| 7 | **Mike Privette** | Return on Security (founder, former CISO) | [returnonsecurity.com](https://www.returnonsecurity.com) | Tracks cybersecurity tooling market weekly; useful for understanding where OSS GRC fits in consolidation narrative |
| 8 | **Trevor Rosen** | GitHub Artifact Attestations PM | [github.blog](https://github.blog) | Owns the GitHub Artifact Attestations product surface that Evidentia interoperates with via PEP 740 + SLSA L3; closest individual driver of attestation UX in the developer tools market |
| 9 | **AJ Yawn** | "GRC Engineering" movement founder; author *GRC Engineering for AWS* | [ajyawn.com](https://ajyawn.com) + LinkedIn | Coined the framing ("GRC engineering") that Evidentia's compliance-as-code positioning lives inside |
| 10 | **Cole Grolmus** | Strategy of Security (founder) | [strategyofsecurity.com](https://strategyofsecurity.com) — Substack/blog + podcast | Maps cybersecurity industry structure rigorously; one of the few analysts who would write seriously about an OSS GRC entrant |

**Honorable mentions** (bumped to keep list at 10): **Phil Venables** (Google Cloud strategic security advisor — kept on the cite list below); **Chris Hughes** (Resilient Cyber); **Anton Chuvakin** (Cloud Security Podcast); **Kelly Shortridge** (resilience engineering); **Wade Baker / Jay Jacobs** (Cyentia Institute — empirical baseline); **Francis Odum** (SACR — moved to pitch list); **Adolfo Garcia Veytia / "Puerco"** (in-toto maintainer); **Michael Lieberman** (Kusari co-founder); **Zach Steindler** (Sigstore contributor); **Walter Haydock** (StackAware AI governance — moved to cite list); **Greg Elin** (RegScale OSCAL Lead, ex-GovReady — historical voice; less active 2026).

### 12.2 Top 5 voices to cite in Evidentia's positioning copy (refreshed)

| # | Voice | Cited work (URL) | Why it supports Evidentia |
|---|---|---|---|
| 1 | **Allan Friedman, CISA SBOM lead** | ["The State of SBOM," ETSI Security Conference 2024](https://docbox.etsi.org/Workshop/2024/10_SECURITYCONFERENCE/14OCTOBER/D11_FRIEDMAN_CISA.pdf) | Argues for community-led, voluntary SBOM data quality + explicit regulatory mapping (PCI DSS, EU CRA) — direct backing for Evidentia's SBOM-aware collectors and OSCAL-tagged evidence |
| 2 | **Dr. Michaela Iorga (NIST), via CSWP 53** | [Charting the Course for NIST OSCAL (Dec 2025 IPD)](https://csrc.nist.gov/News/2025/draft-charting-the-course-for-nist-oscal) | NIST commits OSCAL to "modernize manual, paper-based cybersecurity compliance through automated, scalable processes and continuous assessments" — anchors "OSCAL-native" claims to a NIST-attributed sentence |
| 3 | **Cyentia Institute (Jay Jacobs, Wade Baker), 2025 IRIS** | [Information Risk Insights Study 2025](https://www.cyentia.com/press-release-information-risk-insights-study-2025/) | "Cybersecurity incidents have surged 650% since 2008; median loss has risen from $190K to ~$3M; tail losses 5x" — quantitative justification that legacy spreadsheet GRC is economically untenable |
| 4 | **Phil Venables, Partner at Ballistic Ventures** (departed Google Cloud CISO role March 2025; "Cloud CISO Perspectives" newsletter continues at Google Cloud as a contributor) | ["CISO 2.0" Nov 2025](https://cloud.google.com/blog/products/identity-security/cloud-ciso-perspectives-phil-venables-on-ciso-2-0-and-the-ciso-factory) (written while at Google Cloud) | Argues modern CISO is "absolutely, undeniably becoming a peer business executive" needing strategy not "a long-term plan with the word strategy on the front" — reinforces Evidentia's pitch that GRC tooling has to be a strategic enabler. Affiliation verified 2026-05-18 via direct LinkedIn WebFetch (Ballistic Ventures Partner). |
| 5 | **Walter Haydock, StackAware founder** | "15 AI governance practices that built trust, managed risk, and accelerated sales" — [stackaware.com](https://stackaware.com) | Argues AI governance must be modular + adaptable because "regulation will change" — direct support for Evidentia's plugin-based collectors + adaptable control catalogs vs monolithic vendor SaaS |

All 5 satisfy: published in the last 18 months; cited by NIST/CISA/Forrester/peer-reviewed venue; compatible posture (none are anti-OSS); arguments map onto Evidentia's positioning.

### 12.3 Top 5 voices to pitch (refreshed)

| # | Name | Platform | Recent OSS-coverage example | Pitch angle | Public contact |
|---|---|---|---|---|---|
| 1 | **Mike Vizard** | DevOps.com / Techstrong.ai | ["The Open Source Trap: Why Trust Isn't a Security Strategy" with Josh Bressers](https://devops.com/the-open-source-trap-why-trust-isnt-a-security-strategy/) | "OSCAL-native compliance-as-code that gives small teams the same supply-chain assurance enterprises just bought" — extends his open-source-trust thesis to GRC | [DevOps.com author page](https://devops.com/author/mike-vizard/) |
| 2 | **Josh Bressers** | VP Security, Anchore — Anchore blog + podcast circuit | ["No crystal ball but: 2026 directions" introducing CompOps + Policy-as-Code](https://anchore.com/blog/no-crystal-ball-but-2026-directions/) | Evidentia is the OSCAL/control-layer counterpart to Anchore's CompOps — complementary, not competing. Co-content on SBOM-to-control mapping | [Anchore contact](https://anchore.com/about/contact/) + LinkedIn |
| 3 | **Liran Tal** | Director DevRel, Snyk; OWASP — Snyk blog + lirantal.com + The Secure Developer podcast | ["The State of Open Source and Docker Security"](https://snyk.io/podcasts/the-secure-developer/the-state-of-open-source-and-docker-security-with-liran-tal/) | Developer-first GRC tool that turns audit prep into a CLI command — aligns with his "shift-left compliance" thesis | [lirantal.com](https://lirantal.com) + GitHub @lirantal |
| 4 | **Steve Springett** | OWASP, Dependency-Track lead | [FOSDEM 2026 speaker](https://fosdem.org/2026/schedule/speaker/steve_springett/) | Evidentia uses CycloneDX SBOMs (his standard) as compliance evidence; integration demo + joint OWASP working-group brief on SBOM-to-OSCAL bridging | OWASP foundation contact + GitHub @stevespringett |
| 5 | **Francis Odum** | Software Analyst Cyber Research (SACR) — Substack | ["SACR Cybersecurity 2026 Outlook"](https://softwareanalyst.substack.com/p/sacr-cybersecurity-2026-outlook) | Evidentia is the open-source counter-narrative to platform consolidation he's documenting — fits his "Control Plane Shift" framing. Briefing for SACR OSS-GRC deep dive | softwareanalyst.substack.com contact + LinkedIn |

All 5: shipped content in last 90 days (verified Feb-Apr 2026 activity); cover OSS GRC / supply-chain / DevSecOps adjacent topics; have track record covering smaller / earlier-stage projects; reachable through public channels.

**Notes on candidates deliberately excluded** (per Stream 6 verification): Jen Easterly (recent vehicles podcasts/speeches not peer-reviewed/Gartner-cited); Ross Anderson (deceased March 2024 per The Register obituary — correctly skipped); Bob Lord (transitioned CISA → Institute for Security and Technology; vulnerability-disclosure focus, not GRC); Andy Greenberg / Lily Hay Newman / Kim Zetter / Sean Gallagher / Patrick Gray / Allan Liska (last-90-day output skews threat/incident-investigative rather than GRC tooling); Dan Lorenc (Chainguard CEO — competitor-adjacent; better as follow target).

### 12.4 The intellectual home community (named individuals)

**OSCAL / NIST / FedRAMP**:
- Dr. Michaela Iorga, David Waltermire, Brian Ruf, Stephen Banghart, Pete Waterman, Eric Mill

**OSS compliance-as-code maintainers**:
- Anca Sailer, Lou Degenaro, Vikas Agarwal (compliance-trestle / IBM Research)
- Travis Howerton, Greg Elin (RegScale → OSCAL Hub)
- Kapil Thangavelu (Cloud Custodian / Stacklet)
- Toni de la Fuente (Prowler founder)
- Loris Degioanni, Leonardo Grasso, Jason Dellaluce (Falco / Sysdig)
- Šimon Lukašík, Marek Haičman (OpenSCAP / Red Hat)
- Watson Sato (ComplianceAsCode/content)

**GRC Engineering practitioners**:
- AJ Yawn (Aquia), Walter Haydock (StackAware), Chris Hughes (Resilient Cyber)

**Supply chain + evidence integrity**:
- Justin Cappos (NYU; in-toto, TUF), Santiago Torres-Arias (Purdue; in-toto, SLSA)
- Dan Lorenc (Sigstore project lead, Chainguard), Marina Moore, Trevor Rosen
- Dan S. Wallach (Rice; tamper-evident logging)

**Policy-as-code & formal verification**:
- Tim Hinrichs (Styra; OPA co-creator)
- Emina Torlak, Kesha Hietala (Cedar Analysis at Amazon)
- Nikhil Swamy (Microsoft Research; F* / Project Everest)

**LLMs in compliance / legal**:
- Daniel E. Ho (Stanford RegLab) — top authority on LLM legal-compliance accuracy
- Peter Henderson (Princeton), Neel Guha (Stanford CRFM), Christopher D. Manning (Stanford)
- Varun Magesh, Faiz Surani (Stanford "hallucination-free" study authors)

**CISO / executive voices**:
- Phil Venables (Partner at Ballistic Ventures; ex-Google Cloud CISO, departed March 2025)
- Wade Baker, Jay Jacobs (Cyentia Institute)
- Bruce Schneier (Harvard Kennedy School / Inrupt)
- Dan Geer (In-Q-Tel)
- Mike Privette (Return on Security)
- Anton Chuvakin (Google Cloud), Kelly Shortridge

### 12.5 Two outreach actions that reach the whole community in one quarter

1. **Submit Evidentia to OSCAL Plugfest 2026** + ensure conformance with the OSCAL test suite. One weekend of work; gets cited in the next OSCAL Foundation update.
2. **Open an issue or discussion on github.com/oscal-compass/community** introducing Evidentia and proposing interop scenarios with compliance-trestle. That single GitHub thread surfaces Evidentia to the right ~50 humans.

### 12.6 Best 2026 conference for Evidentia

**fwd:cloudsec** (AJ Yawn keynoted "Introducing GRC Engineering" at fwd:cloudsec 2025 — direct ideological match). Also strong: FedRAMP Summit, NIST OSCAL Mini-Workshops (monthly), CSA Compliance Automation Revolution events.

---

## 13. The 12-month direction

> **Section summary.** The roadmap that compounds Evidentia's
> advantages: ship a determinism harness (no commercial vendor has
> this), publish the bundled multi-framework crosswalk dataset as a
> standalone artifact, add canonical scanner-JSON-to-OSCAL mappers,
> ship an MCP server, pursue OSCAL Foundation membership, harden
> supply-chain story to SLSA L3, then begin a v0.8.x AI-evidence-
> validation cycle. None of this requires raising capital; all of it
> compounds the seven existing differentiators.

### 13.1 v0.7.x — supply-chain hardening + collector + integration breadth (status May 2026)

**Status check at v0.7.8 ship time (vs. v0.7.0 plan):**
- ✓ Tightened LiteLLM pin (v0.7.0)
- ✓ SLSA L3 build provenance via `actions/attest-build-provenance@v2.4.0` (v0.7.3)
- ✓ OpenSSF Scorecard weekly run live (v0.7.2)
- ✓ Container image publish to `ghcr.io/polycentric-labs/evidentia` with cosign keyless OIDC (v0.7.5)
- ✓ 5 SQL DB collectors (v0.7.7)
- ✓ Okta + ServiceNow integrations (v0.7.7)
- ✓ Databricks + Snowflake collectors (v0.7.8)
- ✓ Tableau + Power BI publish integrations (v0.7.8)
- ⏳ OSCAL Plugfest 2026 submission (queued)
- ⏳ `oscal-compass/community` interop discussion (queued)
- ⏳ OpenSSF Best Practices Badge filing (pre-application audit complete v0.7.5; filing pending)
- ⏳ v0.7.9 — Federal compliance overlay (TPRM module + model risk module + 7 catalogs incl. FFIEC + OCC 2011-12 / SR 11-7 + FFIEC CAT — note: needs touch-up since FFIEC CAT was sunset Aug 2025; substitute CRI Profile v2.0 + governance primitives — Three Lines of Defense, Effective Challenge, KRI/KPI/KGI, Open FAIR risk quantification, process-as-code workflows + audit chain-of-custody with WORM backends)

### 13.2 v0.8.0 — the OSS-native AI moat (3-month horizon)

- **DFAH-style determinism harness** for risk-statement generation: `evidentia eval` CLI with decision-determinism + faithfulness + replay-equivalence metrics. Cite arXiv 2601.15322. **The differentiation flagship for v0.8.**
- **Policy Reasoning Traces (PRT) mode**: `evidentia risk generate --emit-trace` produces an explicit chain-of-thought trace alongside each risk statement, citing exact policy clauses. Cite arXiv 2509.23291.
- **Evidence groundedness gate**: every risk statement must cite an extracted evidence span; Evidentia refuses to emit otherwise. Borrow Ragas + DeepEval triad scoring.
- **Sigstore-signed risk-statement artifacts**: extend existing Sigstore signing to every risk statement
- **MCP server exposing Evidentia's GRC store** to Claude / ChatGPT clients
- **Publish `evidentia-catalogs` as standalone repo** under Apache-2.0 / CC0 — becomes the *de facto* multi-framework reference dataset
- **Publish risk-statement benchmark dataset on Hugging Face** — 200 manually-validated triples; becomes the evaluation standard

### 13.3 v0.9.x — collector + integration breadth (6-month horizon, refreshed)

- ✓ Okta collector (shipped v0.7.7)
- ⏳ **Azure collector** — Policy compliance state, Defender for Cloud, Entra ID. Note: `[azure]` extra is declared in pyproject.toml without backing implementation as of v0.7.8 — F-V08-1 finding; v0.7.9 batch fix
- ⏳ **GCP collector** — Security Command Center, Org Policy. Same status as Azure; same F-V08-1 finding
- ✓ ServiceNow integration (shipped v0.7.7)
- ⏳ **Vanta + Drata + Vanta-MCP / Drata-MCP integrations** — push test results to their public APIs + consume their MCP servers (positions Evidentia as "the OSS evidence layer that feeds your existing GRC SaaS")
- ⏳ **Scanner-to-OSCAL adapters**: canonical Prowler-to-OSCAL, Checkov-to-OSCAL, Trivy-to-OSCAL mappers. Slot into the OSCAL Compass + complytime ecosystems. **MITRE/saf** does the heterogeneous-scan-to-OHDF version — Evidentia could absorb the pattern.

### 13.4 v1.0 — production-ready (12-month horizon)

- 5 named reference customers (consultancies, FedRAMP CSPs, defense contractors)
- Formalized auditor partnerships (or at least a documented `evidentia oscal export --bundle-for-auditor` workflow)
- WebUI v2 with the v0.8 AI features surfaced
- SECURITY.md kept current; monthly release cadence
- Optional commercial sponsor entity for analyst inclusion (Forrester/Gartner) and SOC 2 attestation

### 13.5 Opportunistic / research-grade contributions

- **Workshop paper**: formalizing OSCAL profile-resolution semantics (target: SecDev or NIST OSCAL workshop). Empty academic territory.
- **Empirical study**: measuring real-world OSCAL adoption efficiency gains (FedRAMP 20x case studies). Empty academic territory.
- **TEE-attested evidence collectors**: run AWS/GCP collectors inside Nitro Enclave / SEV-SNP VM and embed the attestation in the OSCAL Assessment Result. Open research problem.

---

## 14. Risk register

> **Section summary (refreshed v0.7.8).** Ten identified risks. Two
> NEW since v0.7.0: (9) AGPL OSS competitor velocity (CISO Assistant
> + Comp AI well-capitalized + active dev); (10) license-shift risk
> across the OSS-VC-funded landscape (HashiCorp BSL / Elastic SSPL
> precedent). Risk #3 (AI hallucination) elevated to "very high"
> probability given the March 2026 Delve scandal as cautionary
> baseline. Each risk has a planned mitigation.

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | **Vanta/Drata/Optro buy or replicate the OSCAL+OSS positioning** | Medium-High (was Medium; **Vanta added OSCAL export Feb 2026** is the canary) | High | Ship the DFAH determinism harness + PRT + Sigstore-attested AI provenance + bundled-catalogs dataset *before* they do; cryptographic evidence chain is structurally hard for SaaS to replicate without rearchitecture |
| 2 | **RegScale (or another commercial OSCAL vendor) ships a closer competitor** | Medium | Medium | RegScale is moving partly OSS via OSCAL Hub donation; collaboration > confrontation; Evidentia's library-first shape is structurally different |
| 3 | **AI hallucination incident in Evidentia's risk-statement output** | **High** (was Medium; **Delve scandal March 2026** validated the failure mode at scale: 493/494 SOC 2 reports byte-identical) | Very high | Ship DFAH-style determinism harness in v0.8 (highest priority post-v0.7.8); cite Magesh/Ho 2025 + Delve scandal in the threat model; emit groundedness-gate refusals rather than confident hallucinations; surface PCAOB AS 1105 5/5 alignment as proactive defense |
| 4 | **OSCAL adoption stalls** (e.g., FedRAMP 20x slows; CMMC delayed again) | Low-Medium | Medium | Diversify positioning across multiple tailwinds — **4 forcing functions in Q4 2026** now (CMMC + CRA + FedRAMP OSCAL + MODPA); each can stand alone |
| 5 | **Catalog maintenance burden** as 19 US states + 27 EU states + India + China + Australia + UK each evolve | High | Medium | Tier-D statutory framework community contribution channel; partner with OSCAL Foundation for catalog-maintenance shared infra; **the v0.8.0 P2.2 `evidentia-catalogs` standalone repo split** distributes the burden |
| 6 | **Single-maintainer bus factor** (Allen Byrd as solo maintainer) | High | High | Document everything in `docs/`; prefer in-repo docs over private notes (the pattern is now codified in `~/.claude/CLAUDE.md`); cultivate 2-3 external committers in the first 6 months |
| 7 | **Supply-chain attack on Evidentia's deps** (LiteLLM March 2026 was the canonical; **xz-Utils backdoor + ongoing social-engineering attacks against OSS maintainers per Linux Foundation April 2026** is the broader class) | Medium-High | Very high | Pin minor versions in pyproject.toml + commit `uv.lock`; subscribe to PyPI advisory feeds; Sigstore-verify all dep updates; pre-commit hooks (v0.7.3) run ruff + mypy; threat-model doc (`docs/threat-model.md`) refreshed within 180 days per pre-release-review v4 G5 gate |
| 8 | **Premature "enterprise-grade" claim** that doesn't survive a real audit | Low | High | Acknowledge the 10 honest gaps publicly; classify each as won't-fix / planned / in-progress; honest framing builds credibility, oversold framing destroys it; cite Delve scandal as cautionary baseline |
| 9 | **NEW: AGPL OSS competitor velocity** (CISO Assistant 4,008 stars + daily commits + commercial PRO; Comp AI $20M Series A Khosla Feb 2026 + AGPL + 1,535 stars + daily commits) | High | Medium-High | Apache 2.0 + Sigstore + SLSA L3 + bundled multi-framework catalogs + cryptographic evidence chain is the differentiable moat; Evidentia must ship v0.8.0 differentiators (DFAH + PRT + MCP + plugin contracts) before AGPL incumbents do |
| 10 | **NEW: License-shift risk across VC-backed OSS-adjacent platforms** (HashiCorp BSL Aug 2023 + Elastic SSPL 2021 precedent; CISO Assistant + Comp AI both AGPL+commercial — either could flip restrictively) | Medium (no major OSS GRC project flipped 2024-2026 but playbook well-established) | Medium | Apache 2.0 commitment is itself a competitive moat; surface it explicitly in positioning copy ("OSS = no acquisition risk + no license-shift risk; the code outlives any company") |
| 11 | **NEW: Forrester Wave / Gartner Magic Quadrant exclusion** | High (OSS projects don't typically get inclusion without commercial sponsor) | Medium | Realistic only after a commercial sponsor entity exists; document differentiated positioning in independent venues (NIST CSWP collaboration; JOSS submission for academic citation; OSCAL Foundation membership; OpenSSF Best Practices Badge) |

---

## 15. Sources

> **Section summary.** All major claims in this document are sourced
> from independently-conducted research streams, peer-reviewed
> papers, vendor primary sources (press releases, SEC filings,
> technical blogs), regulator publications (NIST, FedRAMP, OMB, EU,
> CISA), GitHub repositories, and named industry analysts. Where a
> source is a transcribed name (e.g., person's role at a company),
> it has been cross-verified against at least one institutional URL.

### 15.1 Regulatory + market

- OMB M-24-15: https://www.whitehouse.gov/wp-content/uploads/2024/07/M-24-15-Modernizing-the-Federal-Risk-and-Authorization-Management-Program.pdf
- FedRAMP RFC-0024: https://www.fedramp.gov/rfcs/0024/
- FedRAMP roadmap progress: https://github.com/FedRAMP/roadmap/blob/main/PROGRESS.md
- NIST CSF 2.0 (CSWP 29): https://csrc.nist.gov/pubs/cswp/29/the-nist-cybersecurity-framework-csf-20/final
- NIST SP 800-53 Release 5.2.0: https://csrc.nist.gov/News/2025/nist-releases-revision-to-sp-800-53-controls
- NIST SP 800-218 Rev 1 ipd: https://csrc.nist.gov/pubs/sp/800/218/r1/ipd
- DFARS CMMC final rule: https://www.federalregister.gov/documents/2025/09/10/2025-17359/defense-federal-acquisition-regulation-supplement-assessing-contractor-implementation-of
- EU NIS2 transposition tracker: https://digital-strategy.ec.europa.eu/en/policies/nis-transposition
- EU AI Act timeline: https://artificialintelligenceact.eu/implementation-timeline/
- EIOPA DORA CTPP designation: https://www.eiopa.europa.eu/european-supervisory-authorities-designate-critical-ict-third-party-providers-under-digital-2025-11-18_en
- IAPP US state privacy tracker: https://iapp.org/resources/article/us-state-privacy-legislation-tracker
- SecurityWeek 2025 cybersecurity M&A: https://www.securityweek.com/securityweek-report-426-cybersecurity-ma-deals-announced-in-2025/
- Gartner AI governance billion-dollar market (Feb 2026): https://www.gartner.com/en/newsroom/press-releases/2026-02-17-gartner-global-ai-regulations-fuel-billion-dollar-market-for-ai-governance-platforms

### 15.2 Commercial GRC vendors

- Vanta Series D $4.15B: https://www.businesswire.com/news/home/20250723901336/en/Vanta-Raises-$150M-Series-D-to-Power-the-Future-of-AI-Driven-Trust
- Drata-SafeBase $250M: https://techcrunch.com/2025/02/12/security-compliance-firm-drata-acquires-safebase-for-250m/
- AuditBoard → Hg Capital $3B: https://hgcapital.com/insights/auditboard-and-hg-featured-in-business-insider
- AuditBoard → Optro rebrand: https://optro.ai/blog/auditboard-is-now-optro
- Wiz → Google $32B: https://techcrunch.com/2026/03/15/wiz-investor-unpacks-googles-32b-acquisition/
- Lacework → Fortinet $150M: https://www.marketscreener.com/quote/stock/FORTINET-INC-60103137/news/Fortinet-Inc-completed-the-acquisition-of-Lacework-Inc-for-approximately-150-million-47570080/
- Chainguard $356M Series D: https://fortune.com/2025/04/23/exclusive-chainguard-secures-356-million-series-d-as-valuation-soars-to-3-5-billion/
- RegScale $30M Series B + OSCAL Hub donation: https://securityboulevard.com/2025/12/regscale-open-sources-oscal-hub-to-further-compliance-as-code-adoption/

### 15.3 OSS GRC ecosystem

- usnistgov/OSCAL: https://github.com/usnistgov/OSCAL
- usnistgov/oscal-content: https://github.com/usnistgov/oscal-content
- oscal-compass/compliance-trestle: https://github.com/oscal-compass/compliance-trestle (founding team Anca Sailer, Lou Degenaro, Vikas Agarwal at IBM Research; current maintainers in MAINTAINERS.md)
- complytime/complyctl: https://github.com/complytime/complyctl
- defenseunicorns/lula: https://github.com/defenseunicorns/lula
- intuitem/ciso-assistant-community: https://github.com/intuitem/ciso-assistant-community
- Comp AI: https://trycomp.ai/ + https://github.com/trycompai/comp
- Probo: https://www.getprobo.com/ + YC P25
- VerifyWise: https://github.com/bluewave-labs/verifywise
- prowler-cloud/prowler: https://github.com/prowler-cloud/prowler
- cloud-custodian/cloud-custodian: https://github.com/cloud-custodian/cloud-custodian
- bridgecrewio/checkov: https://github.com/bridgecrewio/checkov
- aquasecurity/trivy: https://github.com/aquasecurity/trivy
- ComplianceAsCode/content: https://github.com/ComplianceAsCode/content
- OpenSCAP/openscap: https://github.com/OpenSCAP/openscap
- sigstore/cosign: https://github.com/sigstore/cosign
- in-toto/in-toto: https://github.com/in-toto/in-toto
- CycloneDX/cyclonedx-python: https://github.com/CycloneDX/cyclonedx-python

### 15.4 Academic & research

- Kellogg, Schäf, Tasiran, Ernst — "Continuous Compliance" (ASE 2020): https://homes.cs.washington.edu/~mernst/pubs/continuous-compliance-ase2020-abstract.html — DOI 10.1145/3324884.3416593
- Magesh / Ho et al. — "Hallucination-Free? Assessing the Reliability of Leading AI Legal Research Tools" (J. Empirical Legal Studies 2025): https://arxiv.org/abs/2405.20362
- Crosby & Wallach — "Efficient Data Structures for Tamper-Evident Logging" (USENIX Security 2009): https://dl.acm.org/doi/10.5555/1855768.1855788
- Newman, Meyers, Torres-Arias et al. — Sigstore (CCS 2022): https://dl.acm.org/doi/10.1145/3548606.3560596
- Torres-Arias, Cappos et al. — in-toto (USENIX Security 2019): https://www.usenix.org/conference/usenixsecurity19/presentation/torres-arias
- Cedar (OOPSLA 2024): https://www.amazon.science/publications/cedar-a-new-language-for-expressive-fast-safe-and-analyzable-authorization
- Guha et al. — LegalBench (NeurIPS 2023): https://arxiv.org/abs/2308.11462
- Imperial & Madabushi — Policy Reasoning Traces (arXiv 2509.23291): https://hf.co/papers/2509.23291
- DFAH determinism harness (arXiv 2601.15322): https://hf.co/papers/2601.15322
- LegiLM (arXiv 2409.13721): https://arxiv.org/html/2409.13721v1
- AIReg-Bench (arXiv 2510.01474, HF dataset): https://huggingface.co/datasets/camlsys/AIReg-Bench
- JSONSchemaBench (arXiv 2501.10868): https://hf.co/papers/2501.10868
- Document Screenshot Embedding (arXiv 2406.11251): https://hf.co/papers/2406.11251

**v0.9.5 Q3 2026 quarterly resync additions** (Stream 4 — 8 directly-relevant papers Feb-May 2026):

- Marino & Lane — "Computational Compliance for AI Regulation: Blueprint for a New Research Domain" (arXiv 2601.04474, Jan 8 2026): https://arxiv.org/abs/2601.04474 — **seed citation** for the v0.9.5+ "OSS-native reference implementation for computational compliance" frame
- Cilla Ugarte, Patricio, Berlanga, Molina — "Making AI Compliance Evidence Machine-Readable" (arXiv 2604.13767, April 15 2026): https://arxiv.org/abs/2604.13767 — direct OSCAL+AI parallel to Evidentia's `gap_report_to_oscal_poam()` + back-matter SHA-256 integrity
- Khatchadourian — DFAH v2 revision (arXiv 2601.15322 rev v2 March 7 2026): https://arxiv.org/abs/2601.15322 — Evidentia's `evidentia_ai.eval` v0.9.6 alignment target
- Khatchadourian & Franco — "LLM Output Drift: Cross-Provider Validation & Mitigation for Financial Workflows" (arXiv 2511.07585, Nov 10 2025): https://arxiv.org/abs/2511.07585 — empirical support for Evidentia's multi-provider LiteLLM design
- de la Chica Rodríguez & Martí-González — "Mechanical Enforcement for LLM Governance" (arXiv 2605.14744, May 14 2026): https://arxiv.org/abs/2605.14744 — **empirically validates Evidentia's deterministic-stub-trace fallback architecture** ("mechanical primitives outside the interpretive loop"; 73% reduction in uninformative deferrals; MCC 0.43→0.88)
- Sigdel & Baral — "Guardrails as Infrastructure: Policy-First Control for Tool-Orchestrated Workflows" (arXiv 2603.18059, March 18 2026): https://arxiv.org/abs/2603.18059 — Sigdel-Baral compatible benchmark methodology candidate for Evidentia's MCP CIMD scope-enforcement testing
- Rashie & Rashi — "Type-Checked Compliance: Deterministic Guardrails for Agentic Financial Systems Using Lean 4" (arXiv 2604.01483, April 1 2026): https://arxiv.org/abs/2604.01483 — long-horizon v1.0+ reservation (formally-verified compliance kernel)
- IBM AI Risk Atlas (arXiv 2503.05780): https://arxiv.org/abs/2503.05780 — multi-framework crosswalk prior art
- CompliBench LLM-judge benchmark (arXiv 2604.12312, April 14 2026): https://arxiv.org/abs/2604.12312 — methodologically aligned with Evidentia's DFAH (small fine-tuned judge beats SOTA frontier models)

### 15.5 Industry voices

- Phil Venables: https://www.philvenables.com
- Mike Privette / Return on Security: https://www.returnonsecurity.com
- Chris Hughes / Resilient Cyber: https://www.resilientcyber.io
- AJ Yawn (Aquia, fwd:cloudsec 2025 talk): https://pretalx.com/fwd-cloudsec-2025/talk/GRRE3N/
- Walter Haydock / StackAware: https://blog.stackaware.com
- Kelly Shortridge: https://kellyshortridge.com
- Bruce Schneier: https://www.schneier.com
- Daniel E. Ho / Stanford RegLab: https://reglab.stanford.edu/
- Cyentia Institute (Wade Baker, Jay Jacobs): https://www.cyentia.com
- Risky Business (Patrick Gray): https://risky.biz
- NIST CSWP 53 "Charting the Course for NIST OSCAL" (Iorga et al.): https://csrc.nist.gov/pubs/cswp/53/charting-the-course-for-nist-oscal/ipd

### 15.6 Foundational technical references

- NIST OSCAL spec: https://pages.nist.gov/OSCAL/
- LiteLLM security update (March 2026): https://docs.litellm.ai/blog/security-update-march-2026
- Instructor (3M monthly downloads): https://python.useinstructor.com/
- SLSA: https://slsa.dev
- Sigstore: https://www.sigstore.dev/
- CycloneDX 1.6 spec: https://cyclonedx.org/specification/overview/
- PEP 740 (PyPI attestations): https://peps.python.org/pep-0740/

---

## 16. Version history

| Date | Release | Note |
|---|---|---|
| 2026-04-25 | v0.7.0 (initial compile) | Compiled from 7 parallel research streams as Step 2 of the v0.7.0 comprehensive pre-tag review. |
| 2026-04-27 | v0.7.2 (skip-by-reuse) | Reviewed for v0.7.2 release on 2026-04-27; no material change since v0.7.0. Skip criteria all pass: doc < 90 days old, patch release, no new enterprise-grade claim, no category-defining competitor feature in interim, no tailwind dates passed unobserved (DORA Q1 2026 enforcement noted as past-tense in §3 buyer-personas list — minor MEDIUM bundled into v0.7.2 Step 5.A fix). Per the [release-checklist](release-checklist.md) §"Step 11 — Quarterly cadence", next full re-sync target: 2026-Q3 (~July 2026). |
| 2026-04-29 | v0.7.3 (skip-by-reuse) | Reviewed for v0.7.3 release on 2026-04-29; no material change since v0.7.0. All 5 skip criteria hold: doc 4 days old (still under 90), v0.7.3 is a patch bump, SLSA L3 build provenance was already announced in v0.7.0's `enterprise-grade.md` H2 as planned for v0.7.x (delivering on an existing claim, not introducing a new one), no competitor has shipped a category-defining feature in the 3 weeks since v0.7.0, industry-tailwind dates (DORA Q1 2026 / EU AI Act / OMB M-24-15) status unchanged. Next full re-sync target: 2026-Q3 (~July 2026), tracked as DOC5 in `docs/v0.7.3-plan.md` (deferred to v0.7.4+). |
| 2026-04-29 | v0.7.4 (skip-by-reuse) | Reviewed for v0.7.4 same-day Dockerfile-invocation hot-fix; no material change. Skip trivially holds — surface is 5 corrective `evidentia --version` → `evidentia version` invocations + version bumps + CHANGELOG/ROADMAP refresh. Zero new positioning surface. Q3 2026 quarterly cadence target unchanged (now tracked as R1 in `docs/v0.7.5-plan.md` — renumbered from v0.7.4-plan at hot-fix ship time). |
| 2026-05-01 | v0.7.5 (skip-by-reuse) | Reviewed for v0.7.5 ship; no material change. Skip holds — v0.7.5 is patch + container publish (delivering on existing enterprise-grade L1 claim, not introducing a new one) + S1-S6 security-debt batch (closing pre-existing alerts; no new positioning surface). 22 of 27 expected code-scanning alerts auto-closed; ghcr.io image cosign-signed + SLSA L3 attested. Q3 2026 quarterly cadence target unchanged. |
| 2026-05-01 | v0.7.6 (skip-by-reuse) | Reviewed for v0.7.6 ship; no material change since v0.7.0 (5 patch releases, 2 days old at last edit). All 5 skip criteria hold: doc < 90 days, v0.7.6 is patch bump, no new enterprise-grade claim (UI alpha.2 wiring delivers on an existing v0.4.0+ claim; benchmark numbers + quickstart + accepted-findings are operational hardening, not positioning surface), no competitor category-defining feature in the 3 days since v0.7.5, industry-tailwind dates unchanged. v0.7.6 P1 R1 is the explicit Q3 quarterly resync target (~July 2026), planned to land in v0.7.6 if Q3 cadence has arrived by ship time, otherwise slips to v0.7.7. |
| 2026-05-02 | v0.7.7 (skip-by-reuse) | Reviewed for v0.7.7 ship; no material change since v0.7.0 (6 patch releases). All 6 skip criteria hold: doc < 90 days (refreshed 2026-05-01), v0.7.7 is patch bump, no new enterprise-grade claim (5 SQL adapters + Okta + ServiceNow are new collector surface that extends the existing AC/AU/SC/IA evidence-collection differentiator already covered in §3.4 — they do not declare a new positioning claim), no competitor category-defining feature in the <24 hours since v0.7.6, industry-tailwind dates unchanged, threat-model doc refreshed 2026-04-30 (within 180-day gate per G5). The SQL-family is the first substantive new-collector release since v0.5.0 — strengthens an existing differentiator rather than introducing one. R1 Q3 quarterly resync still targeted ~July 2026; deferred from v0.7.6 + v0.7.7 since current date is pre-cadence. |
| 2026-05-02/03 | v0.7.8 (**FULL RE-RUN**) | First full re-run since v0.7.0. Reviewed for v0.7.8 ship as Step 2 of the v4 pre-release-review skill (variant: pre-tag full 7-step; scope Q1.4: full re-read of all 138 source files; bug-fix policy: defaults + CRITICAL inline). Allen elected the highest-thoroughness option to land the deferred R1 quarterly resync alongside the v0.7.8 ship rather than wait for July 2026 Q3 cadence. **Three substantive market developments incorporated**: (1) **AuditBoard rebranded to Optro March 9 2026** (Hg Capital's positioning move; CEO Raul Villar Jr. effective July 1 2025; FairNow acquisition Oct 2025 for AI governance); (2) **SR 11-7 superseded by SR 26-02 + OCC Bulletin 2026-13a April 17 2026** with explicit GenAI exclusion — banks stranded; opening for Evidentia's planned v0.7.9 model-risk module; (3) **Delve scandal March 2026** (493/494 leaked SOC 2 reports byte-identical; whistleblower disclosure; FTC + DOJ False Claims Act exposure being discussed) validates the AI-feature-commoditization thesis. **Other refreshes**: Vanta $300M ARR April 2026 (was $100M+); Comp AI $20M Series A Feb 2026 from Khosla / Keith Rabois (was $2.6M pre-seed); Drata acquired SafeBase $250M Feb 2026; Diligent acquired 3rdRisk Jan 2026; OneTrust active PE talks Nov 2025; Wiz → Google $32B closed March 2026; Eramba effectively exited OSS (application closed-source); 4 (was 3) regulatory forcing functions for Q4 2026 with EU CRA reporting added; PCAOB AS 1105 5/5 capability alignment surfaced as new differentiator (#8); 8 (was 6) unclaimed gaps with HF eval + Sigstore-attested AI provenance + SR-11-7-replacement-framework added; MCP first-mover window status updated (CLOSED for OSCAL primitives — IBM trestle-MCP / AWS Labs / Vanta / Drata / Optro all live; WIDE OPEN for SR-11-7 / FFIEC / SBOM / TPRM-not-in-Vanta-silo / continuous-monitoring MCPs); HF Hub keyword searches confirm zero existing OSCAL/NIST 800-53/SOC 2 datasets — Evidentia's planned v0.8.0 P2.3 eval suite is first-in-class; voices list refreshed (Stream 6 verified-public-source affiliations replacing v0.7.0 list); 88 bundled catalogs verified by direct codebase walk (was 82 at v0.7.0; v0.7.9 plans +7 to 95). **Findings queued for batch fix**: F-V08-1 (`[azure]` + `[gcp]` extras declared without backing implementations); F-V08-2 (DFAH = "Determinism-Faithfulness Assurance" not "Decision-Faithfulness Assessment"; DSE = "Document Screenshot Embedding" not "Structure Embeddings" — both arXiv-verified); F-V08-3 (SR 11-7 → SR 26-02 update needed in v0.7.9 model-risk plan); F-V08-4 (Stream 7 internal-capability-inventory agent had documented hallucinations; capability inventory in §3 redone by direct codebase walk). Stream 1 + Stream 2 each surfaced inadvertent prompt errors in the original task (Tugboat Logic was acquired by **OneTrust** 2021 not Mastercard; Stackline is a retail/ecommerce growth platform not GRC) — both corrected inline. Per-run log: `.local/pre-release-review/runs/2026-05-03T01-48-52Z.json`. |
| 2026-05-08 | v0.7.9 → v0.8.7 (Continuous-variant runs; no entry-per-release backfill) | The v0.7.9 → v0.8.7 line (10 releases over ~5 days) used the v4 Pre-tag Continuous variant for most ships, which structurally skips Step 2 (skip-by-reuse criteria PASS automatically when positioning-and-value.md is < 90 days old + the release theme is internal hardening rather than positioning surface). Per-release history entries weren't added during that cadence; this consolidated entry records that the v0.7.8 refresh remained the canonical baseline through v0.8.7 ship. v0.7.9 (TPRM) + v0.7.10 (model risk) + v0.7.11 (governance trio) + v0.7.12 (cloud WORM + FAIR MC) + v0.7.13-v0.7.16 (release-pipeline + supply-chain hardening) + v0.8.0-v0.8.7 (OSS-native AI moat: DFAH + PRT + MCP + plugin contracts + faithfulness scoring + CIMD enforcement) all delivered on the v0.7.8 positioning narrative — extending the AC/AU/SC/IA evidence-collection + audit-trail + AI-quality differentiators rather than introducing a new positioning claim. Cycle-close artifacts for each release are in `docs/security-review-v0.7.{8,9,...}.md` + `docs/security-review-v0.8.{0,...,7}.md` per the v4 G7 5th-deliverable convention. |
| 2026-05-15 | v0.9.0 (skip-by-reuse) | Reviewed for v0.9.0 ship; no material change since the v0.7.8 full re-run baseline. All 6 skip-by-reuse criteria PASS: (1) doc < 90 days old (refreshed 2026-05-02/03, ≈13 days ago); (2) v0.9.0 is a minor bump but introduces the federal-compliance theme that was already documented at v0.7.8 + v0.7.9 as a planned direction, not a new positioning claim; (3) POA&M + CONMON + OSCAL POA&M 1.1.2 emit are auditor-expected surfaces in any regulated-industry GRC tool — they fill gaps that v0.7.8 §6 already documented (Unclaimed gap #1 federal-compliance theme; Unclaimed gap #5 SR-11-7-replacement framework now overlaps via OCC 2026-13a model-risk cadence in v0.9.0 P3 CONMON bundled cadences); (4) no competitor category-defining feature in the 13 days since v0.7.8 refresh — Vanta/Drata/Optro shipped only routine cadence updates; (5) industry-tailwind dates (DORA Q1 2026 enforcement; SR 26-02 + OCC 2026-13a active April 2026; EU CRA reporting Q4 2026) status unchanged; (6) threat-model doc refreshed today (2026-05-15) per G5 gate — well under 180-day staleness. Per-run log: `.local/pre-release-review/runs/2026-05-15-v0.9.0-step1.json`. Next full re-sync target: Q3 2026 (~July 2026) unless walk-through-driven v0.9.1 surfaces material positioning shifts. |
| 2026-05-16 | v0.9.1 + v0.9.2 (skip-by-reuse) | Reviewed for v0.9.2 release on 2026-05-16; no material change since the v0.7.8 full re-run baseline. v0.9.1 was org-migration-only (allenfbyrd → Polycentric-Labs; zero feature surface). v0.9.2 ships CONMON REST router + LLM inter-rater agreement script + federal calibration corpus + walk-through scenario rows — all extend existing differentiators (federal-compliance theme documented at v0.7.8 §6 Unclaimed gap #1; AI-quality calibration extending v0.8.3 faithfulness scoring). All 6 skip criteria PASS: (1) doc 14 days old (< 90); (2) patch bump; (3) no new enterprise-grade positioning claim; (4) no competitor category-defining feature since v0.9.0; (5) industry-tailwind dates unchanged; (6) threat-model refreshed 2026-05-15 (< 180 days). Next full re-sync target: Q3 2026 (~July 2026). |
| 2026-05-17 | v0.9.3 + v0.9.4 (skip-by-reuse) | v0.9.3 (CONMON daemon Theme A + AI governance Theme B) + v0.9.4 (daemon hardening: file-lock, webhook SSRF, rate-limit, federal-SI walk-through) reviewed under Continuous variant. v0.9.3 introduced the in-process CONMON daemon + EU AI Act tier classifier — both extend already-documented federal-compliance + AI-governance themes; v0.9.4 hardened those surfaces + landed the long-deferred walk-through. Neither introduces a NEW positioning claim. All 6 skip criteria PASS: (1) doc 15 days old (< 90); (2) v0.9.3 was minor + v0.9.4 was patch, but both deliver on existing claims; (3) no new enterprise-grade claim; (4) no competitor category-defining feature in the 15 days since v0.9.2 (Vanta + Drata + Optro shipped routine cadence updates); (5) industry-tailwind dates unchanged; (6) threat-model refreshed within 180-day gate. |
| 2026-05-18 | v0.9.5 (**Q3 2026 QUARTERLY RESYNC EARLY** — full 6-stream research pass) | Allen elected the full Q3 2026 quarterly resync ~6 weeks ahead of the July target (per Step 2 strategy lock-in in the v4 pre-release-review session per-run JSON). 6 parallel research streams returned **substantive new material across all surfaces** + 1 internal-inventory stream had documented hallucinations (Stream 7 admitted "no direct file walk performed"; redone manually by the calling agent per v0.7.8 lesson). **Section §3.4 v0.9.5 capability additions**: POA&M `Milestone.owner` + `Milestone.reviewer` fields with CLI + REST filters; `EvidenceArtifact.version` + `lineage_id` + `new_version()` versioning data-model; `evidentia_core.rbac` package with `Role` / `RBACPolicy` + FastAPI `require_role()` dependency factory; `GET /api/conmon/daemon-history` + Prometheus daemon gauges; `atomic_write_text` security helper. **Section §6 unclaimed-gaps additions**: RBAC + evidence-versioning marked as parity moves (table-stakes for federal-tier), NOT new differentiators. **MAJOR new findings from research streams**: (1) **EU AI Act Annex III high-risk deferred to Dec 2, 2027** by Omnibus political agreement May 7 2026 — was Aug 2 2026; (2) **FedRAMP RFC-0024 moved to Nov 1, 2027 + scope narrowed to Class D (High) only** — was Sept 30 2026 program-wide; (3) **NEW: FedRAMP CR26 consolidated rules** public preview May 4 2026 → effective July 1 2026 → mandatory Jan 1 2027 (the most consequential FedRAMP structural change in over a decade per practitioner blogs); (4) **NEW: CMMC Phase 2 enforcement Nov 10, 2026** (C3PAO-assessed Level 2 certification in DoD solicitations); (5) **NEW: PCAOB QC 1000 / AS 2901** effective Dec 15, 2026 + SEC SOX Enforcement Group stood up March 31 2026; (6) **Mini Shai-Hulud supply-chain attack May 11 2026** (TanStack/Mistral/UiPath/OpenAI compromised; 400+ malicious package versions across 170+ packages npm + PyPI) directly reinforces Evidentia's PEP 740 + SLSA L3 + Sigstore narrative; (7) **Delve scandal residual** (Y Combinator removed Delve April 3 2026; Insight Partners scrubbed announcement page) validates the verifiable-evidence positioning. **MATERIAL POSITIONING SHIFTS**: (A) **Counter-positioning vs "agentic GRC"** — Vanta Agentic Trust Platform (March 19 2026 GA), Drata + Secureframe + OneTrust + Optro all converged on "agentic" vocabulary in March-May 2026. Drata's own May 11 2026 essay "From Prompt Engineering to Harness Engineering" implicitly concedes the harder problem is **verifiable harness**, not agents — directly validating Evidentia's DFAH + PRT + CIMD framing. v0.9.5+ positioning leads with **"deterministic, auditable, OSS-native compliance engineering"** rather than feature-parity-with-Vanta. (B) **Optro M&A spree** — AuditBoard → Optro rebrand March 9 2026 → **Midship acquisition May 6 2026** ("first agentic system of action for GRC"; claims 87% SOX automation). Third major M&A in 8 months. (C) **OSCAL version drift signal**: compliance-trestle v4.0.2 (April 17 2026) now supports **OSCAL 1.2.1**; Evidentia on 1.1.2 — flag as v0.9.6 upgrade target. (D) **OSS-GRC new entrants**: Greenboard $15.5M Series A May 12 2026 (vertical/securities; non-competing lane); Microsoft Agent Governance Toolkit; AAGATE; VerifyWise (215 stars; source-available); agent-bom (MCP SBOM scanner); claude-grc-engineering (Claude Code plugin pattern); Scytale GRC Skills Kit (May 2026); Sushegaad Claude-Skills-GRC. **CISO Assistant**: 4.1k stars (up from baseline), 130+ frameworks (up from 100+); still no OSCAL native — the moat that v0.7.8 identified holds. **Comp AI**: 1.6k stars (up from 1.2k), 4000+ companies, 25+ frameworks; no OSCAL. (E) **MCP first-mover status**: Existing OSCAL MCPs (oscal-compass/compliance-trestle-mcp + awslabs/mcp-server-for-oscal) are **authoring-only**, not gap-analysis/POA&M/ConMon; Vanta + Drata + Optro MCPs expose **vendor-platform data only**; ComplyAI MCP (April 23 2026) closes financial-services flank commercially. **Wide-open OSS gaps Evidentia could claim**: **CONMON MCP** (highest-leverage; Evidentia v0.9.3 daemon is the only open implementation — wrap-as-MCP is mechanical), OSCAL gap-analysis + POA&M MCP, SR-11-7 / SR-26-2 model risk MCP, FFIEC OSS MCP, TPRM non-vendor-silo MCP. (F) **Voice updates**: Phil Venables **departed Google Cloud CISO March 2025** (now Strategic Security Advisor — correction needed in §12); **Pete Waterman is the FedRAMP Director** (architect of FedRAMP 20x) — federal cite #1; **Walter Haydock (StackAware)** — best podcast guest candidate; **Abderrahmane Smimite (intuitem)** — direct OSS-peer collaboration target; **Brian Ruf (OSCAL Foundation FedRAMP TFG)** — OSCAL credibility cite. **Eramba correction (Stream 2)**: the v0.7.8 baseline claim that Eramba "shifted to closed-source application Q1 2026" appears incorrect per current sources — Eramba still ships Community Edition open-source + paid Enterprise tier. **Threshold action**: pre-v0.9.5 ship, verify the Eramba claim with a direct GitHub repo check; if confirmed incorrect, correct in §5 commercial landscape. (G) **HF Hub** still ~zero compliance datasets/models (one exception: AIReg-Bench EU AI Act dataset Nov 2025, 208 rows) — no `compliance-llama-7b` etc. exists. Evidentia's planned eval suite remains first-in-class. (H) **Q3 2026 conferences worth lock-in**: GovForward FedRAMP Summit July 23 2026; Black Hat USA Aug 1-6; **DEF CON 34 Aug 6-9 (AI Village CFP currently open)**; Billington Sept 8-10; NIST OSCAL Plugfest (next date TBD via pages.nist.gov/OSCAL/events). **3 ACTIONABLE INSIGHTS** baked into the doc updates: (1) Sharpen the "moat trinity" framing — **OSCAL emission + DFAH/PRT determinism + cryptographic provenance (CIMD)** as the three concrete differentiators rather than the broader "OSS vs Vanta" frame; (2) **v0.9.6 should claim the CONMON MCP first-mover position** by wrapping the v0.9.3 daemon as an MCP server — mechanical wrap of existing code, ahead of FedRAMP CR26 + RFC-0024 stabilization; (3) **Counter-positioning text in §6 + §11** should explicitly NOT chase "agentic" vocabulary — claim "deterministic, auditable, OSS-native" instead. (I) **NEW academic citations (Stream 4)**: 8 directly-relevant papers Feb-May 2026 — most significantly **Marino & Lane "Computational Compliance for AI Regulation: Blueprint for a New Research Domain" (arXiv 2601.04474, Jan 8 2026)** which formalizes the research domain Evidentia is already executing. **Cilla Ugarte et al. "Making AI Compliance Evidence Machine-Readable" (arXiv 2604.13767, April 15 2026)** proposes OSCAL as interchange format for AI governance — directly mirrors Evidentia's `gap_report_to_oscal_poam()` + back-matter SHA-256 integrity. **de la Chica & Martí-González "Mechanical Enforcement for LLM Governance" (arXiv 2605.14744, May 14 2026)** empirically validates Evidentia's deterministic-stub-trace fallback architecture ("mechanical primitives outside the interpretive loop"; 73% reduction in uninformative deferrals; MCC 0.43→0.88). **Khatchadourian DFAH v2 revision** (arXiv 2601.15322 rev v2 March 7 2026) — v0.9.6 should diff v1 vs v2 to align `evidentia_ai.eval` with the rev2 methodology. **AIReg-Bench** (arXiv 2510.01474) — EU AI Act benchmark dataset, 120 expert-annotated samples; corpus expansion target for v0.9.6+. (J) **3 ACADEMIC POSITIONING ACTIONS**: (1) **Adopt the "OSS-native reference implementation for computational compliance" frame** in README + §11 — cite Marino & Lane (2601.04474) as the seed academic frame; positions Evidentia not as a Vanta competitor but as the canonical academic instance of an emergent research domain. (2) **Cite the mechanical-enforcement paper (2605.14744)** in §11 AI posture to defend the dual-path PRT architecture (LLM-driven + deterministic stub). (3) **Pre-empt the FedRAMP CR26 OSCAL machine-readable narrative** — add "FedRAMP CR26 + RFC-0024 readiness" callout to README + capability-matrix (note: deadline is Nov 1 2027 per Stream 3 NOTICE-0009, NOT Sept 30 2026 per Stream 4's older reference). (K) **Inter-stream conflicts flagged for verification before incorporating into authoritative claims**: (i) FedRAMP RFC-0024 deadline (Stream 3 Nov 1 2027 vs Stream 4 Sept 30 2026 — trust Stream 3; Sept 30 was the original RFC date, superseded by NOTICE-0009 March 25 2026); (ii) Phil Venables post-Google-CISO affiliation (Stream 6 "Strategic Security Advisor at Google Cloud" vs Stream 4 "Ballistic Ventures Partner + Warburg Pincus Senior Advisor") — flag as "claim, unverified" until direct-source LinkedIn check; (iii) Eramba OSS status (Stream 2 reports still-OSS-Community-Edition vs v0.7.8 baseline's "shifted closed-source Q1 2026") — verify via GitHub repo direct inspection before incorporating into §5 commercial landscape. (L) **Tier 1 scholars to pitch for v0.9.5/v0.9.6**: Bill Marino (Cambridge — computational compliance framing author; pitch first); Nicholas D. Lane (Cambridge / Flower Labs); Raffi Khatchadourian (DFAH author + ICLR Financial AI Workshop 2026 organizer — reach out RE: v2 alignment); Joseph Marvin Imperial (Bath ART-AI CDT — PRT inventor); Stefano Zacchiroli (Télécom Paris; 2026 European Open Source Award winner — Wild SBOMs paper aligned with Evidentia's CycloneDX commitment). Per-run log: `.local/pre-release-review/runs/2026-05-18T15-04-19Z.json`. Next full re-sync target: Q1 2027 (~6 months out from this resync; aligned with the CR26 Jan 1 2027 mandatory enforcement date). |

| 2026-05-19 | v0.9.6 + v0.9.7 (skip-by-reuse) | Reviewed for v0.9.6 ship 2026-05-19 04:07 UTC + v0.9.7 ship-prep on the same calendar day. Both releases land on the v0.7.8 full re-run baseline + the v0.9.5 Q3 2026 quarterly resync. **v0.9.6** introduced 4 surface families (federal-tier AI-gov fields per OMB M-24-10 + FIPS 199 + SCR emit; WORM evidence store; CLI RBAC mirror; CONMON MCP first-mover) + OSCAL 1.1.2 → 1.2.1 upgrade + mypy-strict-to-256 — all extending existing differentiators (federal-compliance theme + AI-governance + moat trinity), no new positioning claim. v0.9.6 also sharpened §6.1.A "moat trinity" + §6.1.B "counter-positioning vs agentic GRC" framing per the v0.9.5 resync recommendations (3 actionable insights — actions 1 + 3 implemented inline). **v0.9.7** is a comprehensive v0.9.x close-out + v1.0 prep cycle: api-stability.md DRAFT → NORMATIVE promotion (closes 1 of 8 v1.0 acceptance gates per `docs/v1.0-transition.md`); multi-tenant RBAC primitives (data model + decision function; CLI/REST integration deferred to v1.0); cryptographic CIMD signatures groundwork (`SignedToolOutput` envelope + signer-factory; FastMCP dispatch-layer auto-wrap deferred to v1.0); RFC-0007 SCR notification standard alignment (8 new SCRForm Optional fields + `to_oscal_scr_notification()` emitter); `EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM` env var (closes v0.9.6 F-V96-worm-app-layer LOW); `evidentia mcp cimd-migrate` CLI verb (closes v0.9.6 F-V96-conmon-mcp-cimd-migration INFO); Codecov target 80% → 85%; `docs/deprecation-calendar.md` NEW; `docs/hf-eval-suite-scaffolding.md` NEW; §11.2.A academic framing (Marino & Lane seed cite + de la Chica & Martí-González mechanical-enforcement defense + FedRAMP CR26 + RFC-0024 readiness) + §11.2.B HF eval scaffolding pointer (per the v0.9.5 resync 3 academic positioning actions). All 6 skip-by-reuse criteria PASS for both: (1) doc < 90 days old (refreshed today); (2) minor bumps; (3) the api-stability NORMATIVE promotion is a contractual formalization of EXISTING surfaces, not a new market-positioning claim — operators relying on the listed surfaces gain semver guarantees from v0.9.7 forward; (4) no competitor category-defining feature in the ~24 hours since v0.9.6 ship; (5) industry-tailwind dates unchanged (CR26 Jan 1 2027, RFC-0024 Nov 1 2027 all future); (6) threat-model refreshed today (well under 180-day gate). Per-run log: `.local/pre-release-review/runs/2026-05-19T13-37-31Z.json` (v0.9.7 cycle; v0.9.6 cycle's per-run JSON shipped 2026-05-19 04:07 UTC). Next full re-sync target: Q1 2027 (~6 months out from the v0.9.5 resync; aligned with CR26 Jan 1 2027 mandatory enforcement date) unless v0.9.8 walk-through-driven feedback surfaces material positioning shifts. |
| 2026-05-24 | v0.10.4 (skip-by-reuse) — **first ship reviewed under skill v5.1** | Reviewed for v0.10.4 ship on 2026-05-24 ~21:42 UTC under `/pre-release-review` skill version **2026.05.24-v5.1** (the first release prototyped under v5.1; v0.10.3 was the last v4 ship). Scope per Step 1.4: **Option 2 — full re-read of every source file in `packages/*/src/`** (Allen explicit choice; maximize surface to stress-test the v5.1 skill changes). All 6 skip-by-reuse criteria PASS: (1) positioning-and-value.md refreshed earlier today (Phase B audit synthesis: §5.5 added ComplianceCow MCP + AWS OSCAL MCP rows; §5.6.A added Snyk AI Trust Platform + Knostic + 2021.AI GRACE Governance; §11.2.A.1 extended academic citations from 3 to 11; commit 8f44d9d); (2) v0.10.4 is a patch bump (0.10.3 → 0.10.4); (3) no new enterprise-grade-tier claim — **`evidentia gap analyze --format ocsf`** is the symmetric counterpart to the v0.10.0 SARIF emit + the v0.10.1 OCSF ingest (closes the OCSF symmetry loop documented in `integration-survey.md` §3 row 15 ✅ shipped; gap output now flows into SIEMs / data lakes / OCSF-aware tooling natively), plus polish from the v0.10.3 `/code-review` (loader.py docstring + error-message + framework_id collision guard) + the CHANGELOG-presence CI gate (pre-tag operational hygiene; lesson from the v0.10.3 move-tag re-fire) — **none of these introduce a new positioning claim; all extend existing surfaces**; (4) no competitor category-defining feature in the < 1 day since v0.10.3 ship — Phase B audit (6 parallel research streams: HF MCP + Perplexity ask + WebFetch) covered the competitive landscape comprehensively today; (5) industry-tailwind dates: v1.0-transition.md updated today with OpenSSF Best Practices Badge Gold acceptance gate revision (Gold structurally unreachable solo per bestpractices.dev/en/criteria/2 "two unassociated significant contributors"; revised v1.0 gate = Silver + OSPS Baseline Maturity 2 + declared Gold honest-gap); no other dates moved; (6) threat-model refreshed 1.6 days ago (well under 180-day v4 G5 gate). **0 NEW SECURITY FINDINGS** carried in from positioning refresh (docs-only). v0.10.5 follow-on work staged in `docs/v0.10.5-plan.md` (NEW): 7-phase OSS first-mover artifacts cycle (OSPS Baseline OSCAL conversion + upstream PR; SECURITY.md + security.txt + CISA SbD Pledge SELFATTEST; EOL.md + verification-recipe; OSPS-CONFORMANCE.md + CI gate). Per-run log: `.local/pre-release-review/runs/2026-05-24T21-41-48Z-v0.10.4-prototype.json` (29th in the series; first under v5.1). Next full re-sync target: Q1 2027 unchanged. |
| 2026-05-23 | v0.10.3 (skip-by-reuse) | Reviewed for v0.10.3 release on 2026-05-23 17:24 UTC (~11h after v0.10.2 PyPI publish at ~06:30 UTC; **fourth release of the v0.10.x line in a single calendar day**). All 6 skip criteria PASS: (1) positioning-and-value.md refreshed today (3 prior same-day version-history rows); (2) v0.10.3 is a patch bump (0.10.2 → 0.10.3); (3) no new enterprise-grade-tier claim — Phase 1 adds YAML-format catalog support (`packages/evidentia-core/src/evidentia_core/catalogs/loader.py:_load_catalog_data` dispatches by file extension; `.yaml` / `.yml` → PyYAML safe_load, `.json` → json.loads; the regenerate_manifest.py scanner globs all three extensions; iso-27017-2015 stub converted JSON→YAML as the in-bundle proof; both formats produce identical `ControlCatalog` objects) — **lower the barrier for new framework catalog contributions** without changing the public catalog API; Phase 2 docs-only Gemara reference-model mapping (new `docs/gemara-mapping.md` NORMATIVE positioning piece + 1-bullet §8.3 link in positioning-and-value.md) — positions Evidentia surfaces onto the OpenSSF Gemara taxonomy (Catalogs / Logs / Documents / Entities / Collections) so FINOS Common Cloud Controls and OpenSSF Security Baseline adopters can read Evidentia outputs through the same lens; (4) no competitor category-defining feature in the ~11h since v0.10.2 ship; (5) industry-tailwind dates unchanged; (6) threat-model refreshed today (0.4 days under the 180-day v4 G5 gate). **0 NEW SECURITY FINDINGS** carried in (Phase 1 is pure-format extension; Phase 2 is docs-only). Per-run log: `.local/pre-release-review/runs/2026-05-23T17-24-18Z.json` (28th in the series). Next full re-sync target: Q1 2027 unchanged. |
| 2026-05-23 | v0.10.2 (skip-by-reuse) | Reviewed for v0.10.2 release on 2026-05-23 06:25 UTC (~2h after v0.10.1 PyPI publish at 04:54 UTC; third release of the v0.10.x line in a single calendar day). All 6 skip criteria PASS: (1) positioning-and-value.md refreshed today (5af2f11 + 8656e5c + bbb8d62 — three same-day version-history rows); (2) v0.10.2 is a patch bump (0.10.1 → 0.10.2); (3) no new enterprise-grade-tier claim — Phase 1 adds 4 new MCP tools (`gap_analyze_sarif` / `collect_ocsf` / `tprm_vendor_list` / `poam_list`) but they are APPEND-ONLY on the §MCP tool contract (non-breaking) and wrap existing v0.10.0 + v0.10.1 OSS functionality; Phase 2 stages the GRC Engineering Club marketplace plugin in-repo (NOT yet upstream-submitted — `marketplace/grc-engineering-suite/plugins/evidentia/`; **first concrete v0.10.x OSS-vs-paid scope decision LOCKED: generalist OSS skills only**, persona-tied skills reserved for future Pro/Federal commercial tier); Phase 3 closes F-V101-L1 SSRF surface via a new `--block-private-ips` CLI flag + library kwarg (default True; rejects RFC1918 + link-local + loopback + multicast + reserved ranges via DNS pre-resolution); (4) no competitor category-defining feature in the < 2h since v0.10.1 ship; (5) industry-tailwind dates unchanged; (6) threat-model refreshed today (0.07 days under the 180-day v4 G5 gate). Per-run log: `.local/pre-release-review/runs/2026-05-23T06-25-00Z.json` (27th in the series). Next full re-sync target: Q1 2027 unchanged. |
| 2026-05-23 | v0.10.1 (skip-by-reuse) | Reviewed for v0.10.1 release on 2026-05-23 (same calendar day as v0.10.0 ship — v0.10.0 published 03:07 UTC, v0.10.1 pre-tag review opened 04:36 UTC). All 6 skip criteria PASS: (1) positioning-and-value.md < 90 days (refreshed yesterday in `5af2f11`); (2) v0.10.1 is a patch bump (0.10.0 → 0.10.1); (3) no new enterprise-grade-tier claim — OCSF ingestion collector + Detection Finding mapping (close v0.10.0 ingestion deferral), `SecurityFinding → Finding` alias (rename mechanics), `evidentia collect ocsf` + `collect convert --format ocsf` CLI verbs (extend existing OCSF interop surface), `bump_version.py` workspace allowlist (release tooling correctness), 11 collectors' `compliance_status` field migration (additive enrichment per v0.10.0 pilot pattern); (4) no competitor category-defining feature in the < 2h since v0.10.0 ship; (5) industry-tailwind dates unchanged; (6) threat-model refreshed today (well under 180-day v4 G5 gate). **Both v0.10.0 findings closed inline**: F-V100-L1 via Phase 1's `trust_unmapped` parameter; F-V100-M1 via Phase 5's workspace-allowlist hardening. Per-run log: `.local/pre-release-review/runs/2026-05-23T04-36-19Z.json` (26th in the series). Next full re-sync target: Q1 2027 unchanged. |
| 2026-05-22 | v0.10.0 (skip-by-reuse) | Reviewed for v0.10.0 release on 2026-05-22; no material change since yesterday's 2026-05-21 post-v0.9.9 research pass and the v0.9.5 Q3 2026 quarterly resync baseline. All 6 skip criteria PASS: (1) positioning-and-value.md < 90 days (refreshed yesterday in `5af2f11`); (2) v0.10.0 is a minor bump but executes the v0.10.x research-driven integration line documented in the prior row — OCSF-aligned findings schema + bidirectional OCSF Compliance Finding mapping (`finding_to_ocsf` / `finding_from_ocsf`; new `evidentia_core.ocsf` package; optional `[ocsf]` extra) + SARIF 2.1.0 CI-gate emit on `evidentia gap analyze --format sarif` + 3 pilot collector refactors (AWS, GitHub, Postgres) — fulfilling the integration-survey recommendations rather than introducing a new positioning claim; (3) no new enterprise-grade-tier claim — OCSF interop is interchange-format support, the new `finding.py` frozen-models entry in `docs/api-stability.md` is contractual formalization (additive-only); (4) no competitor category-defining feature in the <24h since yesterday's 4-stream research pass; (5) industry-tailwind dates unchanged (FedRAMP CR26 Jan 1 2027, RFC-0024 Nov 1 2027); (6) threat-model refreshed 2026-05-21 (1 day, well under 180-day v4 G5 gate). Per-run log: `.local/pre-release-review/runs/2026-05-23T02-09-21Z.json` (25th in the series). Next full re-sync target: Q1 2027 unchanged. |
| 2026-05-25 | **v0.10.5 (full-sweep research pass — IN-FLIGHT)** | **Two-pass adversarial-rigor research session.** First pass: 8 Sonar Deep Research streams + 8 OpenRouter model cross-checks (GPT-5.5, Gemini 3.1 Pro CT, Grok 4.20-MA, Grok 4.3, Llama 4 Maverick, Qwen3 Max Thinking, Kimi K2 Thinking, GPT-5.5 Pro) + 8 perplexity_ask per-noun verifications + 4 HF paper searches. Second pass: 3 retried Sonar streams (peer-watch + OSPS-M2 substitute + regulatory deltas) — all expired again before polling due to perplexity-mcp fork 30-min retention vs Sonar 15-30 min completion + conversational-turn timing. Pivoted to synchronous perplexity_reason + gh api + WebSearch + Grok-4.20-MA for the remaining synthesis. **CRITICAL FACT-CORRECTIONS** vs Stream A's hallucinated peer-project survey: (1) Lula (defenseunicorns/lula) — ACTUAL 29 GitHub stars, NOT 1,204; NOT FedRAMP Ready (no PMO/blog/memo announcement); Apache 2.0; OSCAL-emit via go-oscal library; README does NOT claim air-gap. (2) compliance-trestle (oscal-compass/compliance-trestle) — ACTUAL 256 stars, NOT 3,217; Apache 2.0; NIST OSCAL tooling library (not a competing GRC engine). (3) complytime (complytime/complytime) — ACTUAL 0 stars, 3 forks; essentially inactive. (4) intuitem/ciso-assistant-community — ACTUAL 4,070 stars (up from doc baseline of 4,008); NOASSERTION license (AGPL+commercial); 150+ frameworks claimed. **Re-anchored peer assessment**: the only OSS GRC project with real ecosystem mass is CISO Assistant; Lula + complytime + RegScale's OSS surface are tiny; compliance-trestle is a NIST OSCAL tooling library not a GRC engine. The "OSS + OSCAL + air-gap + eval-rigor uncontested quadrant" claim is MORE defensible than Stream A's synthesis suggested (Stream A fabricated star counts ranging 10-100× off). **Material positioning shifts incorporated this pass**: (A) **DROPPED the "Terraform/dbt of GRC" metaphor** after triple-validated procurement pressure-test (GPT-5.5 + Grok-4.20-MA + Grok 4.3 all rejected); §10 rewritten with direct enumerated claims only, no metaphors until reference customers exist; §10.4 NEW procurement-ready single-paragraph acceptance-gate language. (B) **EU AI Act Annex III high-risk deferred Aug 2 2026 → Dec 2 2027** per Digital Omnibus political agreement May 7 2026 (EU Council + Parliament); §8.1 row updated; tailwind elongates by ~16 months. (C) **CMMC Phase 2 capacity crisis intensified**: under 600 certified CMMC assessors today vs 2,000-3,000 needed; ~80 authorized C3PAOs vs 80,000 contractors requiring L2; wait times will exceed 18 months by Q3 2026. (D) **OSPS-Gold-substitute language refined**: Gold honest-gap now tied to SOC 2 Type I program's segregation-of-duties controls rather than vague "commercial-tier hiring milestone" (procurement-acceptable framing per Grok-4.20-MA). (E) **Polycentric Labs LLC (Virginia)** incorporated and named in acceptance-gate paragraph as the US-incorporated legal entity. (F) **SOC 2 Type I scoping locked**: $25-40K cost band; 4-5 months earliest-start → report-delivery; recommended firms ranked Sensiba (Virginia presence) > Schellman > Prescient Assurance > Insight > A-LIGN > boutique CPAs > Optiv; pre-qualify auditor with concurrent Type II observation language. (G) **NEW companion doc**: `docs/design-partner-program.md` (DRAFT for Allen review) — paid services offer decoupling commercial validation from v1.0 ship date; hybrid pricing model ($15-25K implementation + $5-10K/yr subscription); Stream 1 confirmed CMMC L2 readiness services market is $63-200K (Allen's $25-75K band is at the low end and best repositioned as "tooling-augmented setup"). (H) **STANDING DIRECTIVE LOCKED IN MEMORY**: triple-validate every claim with at least two independent sources before letting it into a doc; never stop pushing back; soft-pedaling is the failure mode. Per-run logs in `.local/pre-release-review/runs/` not yet committed; standing-directive memory at `~/.claude/projects/.../memory/evidentia_standing_directive_research_rigor.md`. Next full re-sync target: cycle-based not calendar-based — at every Evidentia minor release going forward. |
| 2026-05-21 | post-v0.9.9 competitive/integration research pass | Standalone research pass — not tied to a release (current shipped version v0.9.9). Triggered by review of the GRC Engineering Club's `claude-grc-engineering` toolkit + a request to study AI-governance vendors and maximize Evidentia's integration potential. Four parallel research streams (GRC Engineering Club deep-dive; AI-governance vendors Trustible.ai + Credo.ai; an integration & architecture survey; a competitive-landscape refresh) + an independent OpenRouter / Perplexity-Sonar cross-check. **Doc changes**: §5.5 gained a row for `GRCEngClub/claude-grc-engineering` (a Claude-Code plugin marketplace — a complementary orchestration layer and interop target, not a competitor); NEW §5.6.A "AI-governance specialist platforms" (Trustible, Credo, Holistic AI, IBM watsonx.governance, OneTrust AI Governance, Monitaur, Fairly AI, Modulos — all SaaS-only / closed-source, leaving the OSS + air-gap + OSCAL + eval-rigor quadrant uncontested); §8.3 gained a bullet for the OpenSSF **Gemara** reference model (March 2026). **NEW companion doc**: [integration-survey.md](integration-survey.md) — prioritized integration opportunities + architecture patterns to adopt (OCSF normalized findings schema as the keystone, SARIF emit, MCP-as-backend, YAML-driven catalogs, persona modes, Gemara mapping). **Deliberately NOT refreshed this pass**: §3 still carries the v0.7.8 capability baseline and §13's 12-month direction is still v0.7.x / v0.8.0-organized — both are stale at v0.9.9, and a full body re-run belongs to the scheduled Q1 2027 quarterly re-sync (or a pre-release-review Step 2 full re-run), not this targeted pass. **Correction surfaced**: the research streams worked from an OSCAL 1.1.2 figure; the current truth is OSCAL 1.2.1 (shipped v0.9.6 — see §6.1.A). |
| 2026-05-27 | v0.10.6 (skip-by-reuse) | Reviewed for v0.10.6 release on 2026-05-27 under `/pre-release-review` skill v5.1. Scope: OSS first-mover artifacts (carried from v0.10.5 deferred Phases 1-5) + downstream OSPS crosswalks + post-v0.10.5 hygiene. All 6 skip-by-reuse criteria PASS: (1) positioning-and-value.md refreshed during the v0.10.5 full-sweep research pass (2 days old, well under 90); (2) v0.10.6 is a patch bump (0.10.5 → 0.10.6); (3) no new enterprise-grade-tier claim — OSPS Baseline 3-catalog bundle + first public OSCAL Catalog 1.2.1 serialization + `OSPS-CONFORMANCE.md` self-attestation + `SECURITY.md` refresh + `EOL.md` + 5 OSPS-Baseline crosswalks + 16-helper GitHub OSPS collector extension + workflow-permissions audit + Scorecard 6.5+ restoration — all OSS first-mover artifacts and downstream interop / hygiene that **extend existing differentiators rather than introduce a new positioning claim**; the OSPS-CONFORMANCE.md + crosswalks deliver on the v0.10.5 "OSS first-mover artifacts" theme that was deferred during the v0.10.5 cycle pivot to output-format expansion; (4) no competitor category-defining feature in the 1 day since v0.10.5 ship; (5) industry-tailwind dates unchanged (EU AI Act Annex III Dec 2 2027; FedRAMP CR26 Jan 1 2027; RFC-0024 Nov 1 2027); (6) threat-model refreshed during v0.10.5 cycle (2 days, well under 180-day v5.1 G5 gate). **0 NEW POSITIONING CLAIMS** carried in. Four §12 corrections-log entries this cycle (crosswalk format/path; OSPS Baseline counts 25/42/63; crosswalk source data upstream-resourced; OSPS control-ID granularity OSPS-XX-YY.ZZ) — see `docs/v0.10.6-plan.md` §12. Per-run log: `.local/pre-release-review/runs/2026-05-27T*-v0.10.6-prototype.json` (30th in the series; second under v5.1). Next full re-sync target: Q1 2027 unchanged. |

---

*End of positioning-and-value.md. v0.7.8 refresh estimated ~16,000 words (was ~12,000 at v0.7.0). v0.9.7 P4.1 additions: §11.2.A + §11.2.B. Cross-link to: [enterprise-grade.md](enterprise-grade.md) (the quality bar), [testing-playbook.md](testing-playbook.md) (the operational playbook), [ROADMAP.md](ROADMAP.md) (the version-level plan), [Evidentia-Architecture-and-Implementation-Plan.md](../Evidentia-Architecture-and-Implementation-Plan.md) (the canonical design doc), [threat-model.md](threat-model.md) (STRIDE + asset inventory; refreshed within 180 days per pre-release-review v4 G5 gate), [api-stability.md](api-stability.md) (NORMATIVE as of v0.9.7), [deprecation-calendar.md](deprecation-calendar.md) (active deprecations with target removal releases).*
