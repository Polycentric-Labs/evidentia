# Evidentia — positioning, value, and where this should go

> Synthesis of ~25,000 words of independent research across 7 parallel
> streams (commercial GRC vendors, OSS GRC ecosystem, regulatory and
> M&A signals, academic foundations, AI/LLM tooling, industry voices,
> and an internal capability inventory). Compiled 2026-04-24 for
> v0.7.0 release readiness. See §16 "Version history" at the bottom
> for the per-release review trail. Cite by URL; verify any claim
> before reusing externally.

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
10. [Positioning frame — "Terraform / dbt of GRC"](#10-positioning-frame)
11. [AI posture — foundational vs bleeding edge vs gaps](#11-ai-posture)
12. [Industry voices — to cite, to follow, to pitch](#12-industry-voices)
13. [The 12-month direction — where Evidentia should go](#13-the-12-month-direction)
14. [Risk register — what could derail the positioning](#14-risk-register)
15. [Sources](#15-sources)

---

## 1. Executive summary

> **Section summary.** Evidentia (v0.7.0, April 2026) is the only
> open-source, Python-first, library-first, OSCAL-native GRC tool
> with bundled multi-framework catalogs, supply-chain-hardened
> evidence integrity, and an air-gap-capable deployment model. It
> sits in a near-empty competitive niche, on the right side of three
> regulatory forcing functions in 2026, and is intellectually descended
> from the Kellogg et al. ASE 2020 "Continuous Compliance" thesis. Its
> v0.7.0 release closes all 10 BLOCKER items in the enterprise-grade
> credibility checklist.

- **Evidentia is the OSCAL-native, library-first, AI-optional, supply-chain-hardened GRC primitive that didn't exist in OSS until April 2026.** Six unclaimed gaps in the OSS GRC ecosystem map directly onto Evidentia's surface (see §7).
- **The closest commercial peer with overlapping OSCAL claims is RegScale** ($30M Series B Sept 2025, donated OSCAL Hub to the foundation Dec 2025) — and they are proprietary and Beltway-focused. Vanta, Drata, AuditBoard (now rebranded Optro), OneTrust, ServiceNow IRM, MetricStream all have **zero published OSCAL support** (see §5).
- **Three regulatory forcing functions hit in the next six months:** OMB M-24-15 (federal agency OSCAL mandate, July 25, 2026), FedRAMP RFC-0024 (machine-readable authorization packages, September 30, 2026), CMMC Phase 2 (Level 2 third-party assessments for ~300,000 DOD contractors, November 10, 2026). Evidentia is positioned 18+ months ahead of where most commercial vendors deliver (see §8).
- **The OSS GRC space is not empty but is structurally fragmented.** CISO Assistant (3,980 stars, AGPL+commercial), compliance-trestle (249 stars, opinionated CI workflow Python software), Comp AI (4,000+ customers, AGPL Vanta-alternative SaaS), and Probo (YC P25, OSS) all exist; **none is a permissively-licensed, library-callable, OSCAL-native, multi-framework Python toolkit**. That is Evidentia's slot (see §5–§7).
- **GRC was the #1 sub-sector in cybersecurity M&A in 2025 (82 deals, five-year peak).** Vanta crossed $4.15B at Series D in July 2025; AuditBoard taken private by Hg Capital for $3B in May 2024; Wiz absorbed by Google for $32B (closed March 2026, largest VC-backed exit in history). Customer flight risk from this consolidation creates a real opening for OSS that has no acquisition exposure (see §5, §8).
- **AI is now table-stakes in commercial GRC, not differentiation.** Every vendor shipped agent suites in Q1 2026. The new wedge is *evidence quality, traceability, and auditor acceptance* — exactly where Evidentia's Sigstore + PEP 740 + structured-output discipline sits (see §11).
- **The positioning frame that wins**: *"Terraform / dbt of GRC"* — a library-first, CI-native primitive that orchestrates evidence and frameworks, rather than a SaaS dashboard you pay $14k/yr/framework for. This sidesteps the Vanta/Drata bake-off Evidentia would lose, and competes inside the dev-tools-for-compliance trend Chainguard, Snyk, and Anchore validated (see §10).
- **Honest gaps** (intentionally surfaced, not buried): no customer-facing trust center, no questionnaire-fill AI, ~5 collectors vs Vanta's 375+ integrations, no auditor partnerships, no Forrester Wave / Gartner inclusion, no TPRM module, no risk register / ERM primitive, no published reference customers, no formal SOC 2 of Evidentia itself, no IPO/exit narrative for vendor-longevity-paranoid buyers. Each has a planned remediation or an explicit "won't fix" rationale (see §6).
- **Intellectual home**: the OSCAL Compass + OSCAL Foundation + Resilient Cyber / fwd:cloudsec / GRC-Engineering crowd — about 30 named individuals across NIST/GSA, IBM Research, RegScale, Stacklet, Aquia. Two outreach actions (OSCAL Plugfest 2026 submission + GitHub issue on `oscal-compass/community` proposing compliance-trestle interop) reach the entire community in one quarter (see §12).
- **The 12-month direction** that compounds Evidentia's advantages: ship a DFAH-style determinism harness for risk-statement generation (no commercial vendor offers this); publish the bundled multi-framework crosswalk dataset as a standalone artifact (`evidentia-catalogs`); add canonical scanner-JSON-to-OSCAL mappers (Prowler, Checkov, Trivy); ship an MCP server exposing Evidentia's GRC store to Claude/ChatGPT clients; pursue OSCAL Foundation membership; cut the v0.8.x cycle around AI evidence validation + multimodal evidence support (see §13).

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

## 3. Current capabilities (v0.7.0)

> **Section summary.** As of v0.7.0, Evidentia ships 12+ CLI commands,
> 12 REST router modules with ~18 endpoints, an 8-page React SPA, six
> Python packages with public APIs, two evidence collectors with five
> explicit blind-spot disclosures, one integration (Jira), AI-powered
> risk-statement and control-explanation generation, 82 bundled
> framework catalogs across four redistribution tiers, six bundled
> crosswalks, and four output formats including OSCAL Assessment
> Results with embedded SHA-256 evidence digests + Sigstore/Rekor or
> GPG signing. All 10 BLOCKER items in the enterprise-grade
> credibility checklist are closed at v0.7.0. (Capability inventory
> drawn from the in-repo Explore agent's Step-2 output; full
> verification matrix to be produced in Step 4.)

### 3.1 CLI surface (Typer)

| Command | Purpose |
|---|---|
| `evidentia init` | Scaffold a new project (creates `evidentia.yaml`, `my-controls.yaml`, `system-context.yaml`) |
| `evidentia doctor [--check-air-gap]` | System diagnostics; verifies LLM connectivity, file permissions, air-gap posture |
| `evidentia version` | Print version of evidentia + its workspace packages |
| `evidentia catalog list [--tier ... --category ...]` | Browse 82 bundled frameworks, filter by tier (A/B/C/D) or category |
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

- **AWS** — Config compliance rules + Security Hub findings + IAM Access Analyzer (with 5 explicit blind-spot disclosures: KMS grants, S3 ACL/BPA interactions, service-linked roles, unsupported resource types, finding-generation latency). Uses standard boto3 credential chain.
- **GitHub** — Branch protection + CODEOWNERS + repo visibility + Dependabot alerts (with 100-page safety cap on pagination). Uses `GITHUB_TOKEN` env var.

### 3.5 Bundled framework catalogs (82 total, four redistribution tiers)

- **Tier A — US federal (25 frameworks, verbatim public domain)**: NIST SP 800-53 Rev 5 full catalog (1,196 controls) + Low/Moderate/High/Privacy baselines, 800-171 r2/r3, 800-172, CSF 2.0, AI RMF 1.0, Privacy Framework 1.0, SSDF 800-218; FedRAMP Rev 5 baselines; CMMC 2.0 L1/L2/L3; HIPAA Security/Privacy/Breach Notification; GLBA Safeguards, NY DFS 500, NERC CIP v7, FDA 21 CFR Pt 11, IRS 1075, CMS ARS, FBI CJIS v6, CISA CPGs.
- **Tier A — International (6 frameworks)**: UK NCSC CAF 3.2, UK Cyber Essentials, Australian Essential Eight, Australian ISM, Canada ITSG-33, NZ NZISM.
- **Tier D — Statutory (21 frameworks, government edicts, uncopyrightable)**: EU GDPR, EU AI Act, EU NIS2, EU DORA, UK DPA 2018, Canada PIPEDA, plus all 15 comprehensive US state privacy laws.
- **Tier C — Licensed stubs (20 frameworks)**: ISO/IEC 27001:2022, 27002:2022, 27017, 27018, 27701, 42001, 22301; PCI DSS v4.0.1; HITRUST CSF v11; COBIT 2019; SWIFT CSCF; CIS Controls v8.1 + 5 CIS Benchmarks; SCF; IEC 62443; SOC 2 TSC. Public clause numbering only; `evidentia catalog import` loads your licensed copy.
- **Tier B — Threat / vulnerability catalogs (4 frameworks)**: MITRE ATT&CK Enterprise (41 techniques), CWE Top 25 (2024), CAPEC sample, CISA KEV sample.

### 3.6 v0.7.0 enterprise-grade additions

The v0.7.0 release closes all 10 BLOCKER items in the [enterprise-grade credibility checklist](enterprise-grade.md). The supply-chain hardening narrative is end-to-end:

- **Evidence integrity**: SHA-256 digest + Sigstore/Rekor signing (online) or GPG signing (air-gap) on every Assessment Results document
- **Build provenance**: GitHub Actions workflow with OIDC identity
- **Signed publish**: PyPI Trusted Publisher (OIDC) — no long-lived API tokens
- **Per-artifact attestations**: PEP 740 Sigstore attestations on every wheel + sdist, logged to Rekor
- **Software bill of materials**: CycloneDX 1.6 SBOM attached to every GitHub Release
- **Schema conformance**: `compliance-trestle>=4.0` round-trip in CI catches unknown-field bugs that NIST's JSON Schema misses
- **Structured logs**: ECS 8.11 + NIST AU-3 + OpenTelemetry via `--json-logs` flag
- **Air-gap mode**: `--offline` flag refuses network egress; Sigstore refuses and routes operators to GPG; `evidentia doctor --check-air-gap` validator
- **Consolidated GitHub Action**: composite action at `.github/actions/gap-analysis/` (replaces archived standalone repo)

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

OSCAL has **no canonical academic paper** — it is documented through NIST Special Publications, the [OSCAL spec](https://pages.nist.gov/OSCAL/), the [GitHub repo](https://github.com/usnistgov/OSCAL), and workshop talks. Principal architects: **Dr. Michaela Iorga** (NIST OSCAL Program Director), **David Waltermire** (OSCAL Technical Director), **Brian Ruf** (RufRisk; OSCAL Foundation FedRAMP Tech Focus Group Lead).

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

**Kellogg, Schäf, Tasiran, Ernst — "Continuous Compliance"** (ASE 2020, [DOI 10.1145/3324884.3416593](https://homes.cs.washington.edu/~mernst/pubs/continuous-compliance-ase2020-abstract.html)) is the single most important paper Evidentia extends. They argue that traditional compliance audits (SOC, PCI DSS) are point-in-time, and that continuous compliance via lightweight type-system-style verification on each commit can keep a codebase certifiable. They demonstrate it for PCI DSS using checker-framework-style analyses. Replication artifacts at https://zenodo.org/records/3976221.

**Evidentia operationalizes this thesis at OSCAL/multi-framework scale**, with Sigstore-backed evidence integrity and structured-output AI for risk statements. That is the cleanest one-line intellectual narrative.

---

## 5. Competitive landscape

> **Section summary.** The GRC market consolidates into five tiers
> (SOC 2 startup automation, enterprise GRC suites, trust center /
> vendor risk, cloud-security-with-compliance, and OSS GRC). Vanta
> ($4.15B) and Drata ($2B) own the SOC 2 startup tier; AuditBoard
> ($3B PE), OneTrust ($10B+ PE talks), and ServiceNow IRM own
> enterprise; SafeBase (now Drata) and Conveyor own trust center;
> Wiz ($32B Google), Lacework ($150M Fortinet), and Chainguard ($3.5B)
> own cloud-security-with-compliance; the OSS tier is a recent surge
> (Comp AI, Probo, Openlane, CISO Assistant, VerifyWise) but **none
> is a permissively-licensed library-first OSCAL-native multi-framework
> Python toolkit** — that is Evidentia's slot. RegScale ($30M Series B)
> is the only commercial OSCAL-native vendor and has gone partly OSS
> by donating its OSCAL Hub to the foundation.

### 5.1 Tier 1 — SOC 2 startup automation

| Vendor | Valuation / ARR | OSCAL | AI features | OSS posture | Real differentiation? |
|---|---|---|---|---|---|
| **Vanta** | $4.15B (Series D, July 2025); $100M+ ARR; 12,000+ customers | **No** | Vanta AI Agent (policy updates, evidence verification), Questionnaire Automation (95% acceptance), 35+ frameworks pre-mapped | Proprietary | Largest install base + 375+ integrations; deep brand premium |
| **Drata** | $2B (Series C, Dec 2022); $100M ARR; 7,000+ customers | **No** | SafeBase AI (post-acq), control monitoring automation, Drata AI policies, Agentic TPRM that consumes vendor SafeBase Trust Centers | Proprietary | 100% YoY growth; SafeBase trust-center bundle |
| **Secureframe** | Series B $56M @ $355M val (2022); no fresh round | **No** | Comply AI policy generator, evidence collection AI | Proprietary | Strong audit-firm partnerships; trailing Vanta/Drata |
| **Sprinto** | Series B $20M (April 2024); 1,000+ customers in 75 countries | **No** | AI for risk/compliance automation; autonomous actions across vendor risk + AI governance | Proprietary | India-built; significantly cheaper than Vanta/Drata |
| **Comp AI** | OSS, ~4,000 customers | **No** | Plain-language → automation agent; OSS device agent (disk encryption, FW, AV, screen lock checks every hour) | **OSS (AGPLv3)** | Direct OSS Vanta alternative; $0 self-hosted vs Vanta $22-80K/yr; rapidly growing |
| **Probo** | YC P25 batch | No | LLM-assisted SOC 2/ISO 27001/HIPAA workflow | **OSS** | French team, SF-based; "compliance done for you" service model |

### 5.2 Tier 2 — Enterprise GRC suites

| Vendor | Position | OSCAL | AI features | Notes |
|---|---|---|---|---|
| **OneTrust** | Enterprise/F100; ~$500M+ ARR | **No** | OneTrust Athena (AI + RPA); Privacy Breach Response Agent on Microsoft Security Copilot | In PE talks at $10B+ (Nov 2025); 2022 layoffs of 950; valuation reset from $5.3B (2021) |
| **AuditBoard → Optro** | F500 internal audit; 2,000+ customers (~50% of F500); $200M+ ARR | **No** | Accelerate suite: Audit Agent, NL workflows, continuous auditing; **acquired FairNow** for AI governance | Hg Capital take-private $3B (May 2024); rebranded to Optro March 2026 |
| **ServiceNow IRM** | Existing ServiceNow enterprise install base | **No** | Now Assist for IRM (Yokohama 2025): GenAI issue summarization, agentic resolution | Locked to ServiceNow ecosystem |
| **Workiva (NYSE: WK)** | Enterprise CFO office + GRC; $884.6M FY25 revenue (+20% YoY) | **No** | Workiva AI assistant for financial reporting + GRC + sustainability | Public; targeting $1B in 2026; non-GAAP op margin 9.9% |
| **Archer** (post-RSA, owned by Cinven from 2023) | Enterprise / regulated | **No** | Modest AI overlays | Aging UI; PE-owned; modernization slow |
| **MetricStream** | Enterprise / financial services | **No** | "AiSPECTS" AI engine | Banking/FSI moat; UX maturity |
| **Hyperproof** | Mid-market enterprise | **No** | Hyperintelligence AI control mapping; AI Guided Experiences (RSA 2026) | Best mid-market framework crosswalker |
| **LogicGate Risk Cloud** | Mid-market enterprise risk/compliance | **No** | LogicGate AI for risk scoring + workflow automation | No-code risk workflow builder |
| **Riskonnect** | Enterprise integrated risk; ranked #1 GRC platform 2026 by their own marketing | **No** | Risk Intelligence AI for ERM | Single-codebase unified GRC across ERM/IA/ESG |
| **Diligent** (formerly Galvanize/HighBond, ZenGRC merger) | Enterprise board/audit | **No** | Diligent AI for board materials + risk insights | Brand confusion post-merger |
| **IBM OpenPages with watsonx** | F500 / regulated / financial services | **No** | watsonx-powered AI for risk/control mapping | Heaviest implementation |

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

### 5.5 Tier 5 — OSS GRC ecosystem

The OSS GRC tier surged in 2025-26. **None of these is a permissively-licensed, library-first, OSCAL-native, multi-framework Python toolkit.** That gap is Evidentia's slot.

| Project | Stars / Activity | Shape | License | Evidentia adjacency |
|---|---|---|---|---|
| **intuitem/ciso-assistant-community** | **3,980 / 698 forks** | Full-platform GRC web app (Django + SvelteKit), 130+ frameworks in DB | AGPL-3.0 community + intuitem Commercial enterprise tier | Different shape (web app vs library), different license |
| **oscal-compass/compliance-trestle** | 249 / 101 | Opinionated CI/CD-driven OSCAL document authoring + workflow engine | Apache-2.0 | Closest Python rival but workflow-first; founding team Anca Sailer / Lou Degenaro / Vikas Agarwal at IBM Research |
| **complytime/complyctl** + **complyscribe** | 31 + 22 | Red Hat–led Go + Python CLI for end-to-end OSCAL compliance workflows | Apache-2.0 | Direct philosophical neighbor; Go-first |
| **defenseunicorns/lula** | 29 | DoD-flavored compliance-as-code for GitHub repos | Apache-2.0 | Adjacent vertical; complement |
| **Comp AI** (`trycomp.ai`) | OSS, ~4,000 customers | Vanta-alternative SaaS with OSS device agent | AGPLv3 (~99%) | Different shape (SaaS app); license incompatible with library embedding |
| **Probo** | YC P25 | OSS SOC 2/ISO 27001/HIPAA platform | OSS | Service-augmented; small team |
| **Openlane** (`theopenlane.io`) | Apache-2.0 | OSS GRC platform | Apache-2.0 | Different shape (platform vs library) |
| **VerifyWise** | BSL 1.1 | AI-governance-focus OSS, 24+ frameworks incl. EU AI Act + ISO 42001 | BSL 1.1 | Different shape; AI-governance vertical |
| **GovReady-Q** | 210 stars | Django-based self-service GRC questionnaire app | GPL-3.0 | Effectively defunct (no meaningful work since 2024); Evidentia walks into the vacuum |
| **GovReady/compliancelib-python** | 63 / abandoned | Python lib for SP 800-53 controls | GPL-3.0 | Predecessor of OSCAL-era; abandoned |
| **opencontrol/compliance-masonry** | 377 / maintenance | Pre-OSCAL YAML "OpenControl" docs builder | Apache-2.0 | Predecessor of OSCAL; stale |
| **RS-Credentive/oscal-pydantic** | **23 / 5; last push 2024-04-06 (2 years stale)** | Pydantic models autogenerated from OSCAL schemas | Apache-2.0 | Functionally archived; Evidentia could supersede |
| **Eramba** | Long enterprise self-hosted footprint | Full-platform PHP GRC | AGPL upstream + Eramba Enterprise | Different language ecosystem |

### 5.6 Foundational layer Evidentia integrates

- **NIST OSCAL** (877 stars) + **oscal-content** (430 stars) — canonical schema + 800-53 catalogs
- **ComplianceAsCode/content** (2,710 stars) — SCAP/STIG content for RHEL/Ubuntu hardening
- **CycloneDX/cyclonedx-python** (371 stars) — SBOM generator (Evidentia uses for `evidentia-sbom.cdx.json`)
- **Sigstore/cosign** (5,844 stars) — signing + Rekor transparency log (Evidentia uses for evidence + release attestations)
- **in-toto/in-toto** (999 stars) — supply-chain attestation framework (related)

---

## 6. Differentiation, parity, and honest gaps

> **Section summary.** Evidentia has **seven genuine differentiators**
> versus every commercial tier — open-source + Python + library-first;
> OSCAL-native; AI-optional; air-gap-capable; supply-chain-hardened
> on the GRC tool itself; composite GitHub Action / CI-native; 82
> framework catalogs bundled. It is at **parity** on AI-assisted
> control mapping, multi-framework crosswalking, evidence collection
> from cloud APIs, CycloneDX SBOM, Sigstore signing, and conventional
> commit + semver discipline. It is **honestly behind** on ten
> specific surfaces: trust center, AI questionnaire fill, integration
> breadth, auditor partnerships, analyst inclusion, TPRM module,
> ERM/risk-register primitive, reference customers, formal SOC 2
> attestation, and IPO/exit longevity narrative. Each gap has a
> planned remediation or an explicit "won't fix" rationale.

### 6.1 The seven genuine differentiators (vs. all four commercial tiers)

| # | Differentiator | Vs. Vanta/Drata | Vs. OneTrust/AuditBoard/ServiceNow | Vs. SafeBase/Conveyor | Vs. Wiz/Lacework/Chainguard |
|---|---|---|---|---|---|
| 1 | **OSS + Python + library-first** | None do this | None | None | None at GRC layer; only Snyk/Aqua/Sysdig/Anchore/Chainguard at adjacent security layer |
| 2 | **OSCAL-native** | None ship OSCAL output | None | None | Only RegScale (parity); not Wiz/Lacework/Prisma/CrowdStrike |
| 3 | **AI-optional** (works fully without LLM access) | Hard-wired AI dependency | All AI-core (Athena, Now Assist, watsonx) | AI-first by design | CSPM tied to telemetry; not relevant axis |
| 4 | **Air-gap-capable** | None deploy on-prem or air-gapped | OneTrust on-prem deprecated; rest cloud-only | All cloud-only | All cloud-telemetry-dependent by definition |
| 5 | **Sigstore + PEP 740 + SBOM applied to the GRC tool itself** | None publish signed SBOM for their platform | None | None | Parity-ish with Chainguard's signed-image philosophy, but Evidentia applies it to *the GRC tool*, not just images. **Genuine differentiator at the meta-layer.** |
| 6 | **Composite GitHub Action / CI-native** | SaaS dashboards; not pipeline-native | Workflow apps; not CI primitives | Same | Snyk/Aqua/Sysdig CI-native for *security scanning*; Evidentia CI-native for *compliance evidence* |
| 7 | **82 framework catalogs bundled** | Vanta 35+, Drata 20+, Secureframe ~12, Sprinto ~10 | OneTrust + ServiceNow + IBM cover hundreds via paid licensed regulatory libraries | N/A (trust center vendors don't ship catalogs) | RegScale claims 60+ (parity) |

### 6.2 Where Evidentia is at parity (don't oversell)

- **AI-assisted control mapping** — Vanta AI Agent, SafeBase AI, RegScale all do this. Evidentia at parity, not advantage.
- **Multi-framework crosswalking** — Hyperproof's Hyperintelligence and Drata's framework engine are mature. Evidentia at 82 catalogs is at parity in coverage; quality of the crosswalk graph needs more validation.
- **Evidence collection from cloud APIs** — Tier 1 vendors and CSPM tools both do this well. Evidentia's collectors (AWS, GitHub Dependabot, IAM Access Analyzer) are at parity for the integrations shipped, behind on coverage breadth.
- **CycloneDX SBOM output** — Industry standard now (Anchore, Chainguard, Snyk). Parity, not ahead.
- **Sigstore/Rekor signing of releases** — Increasingly table-stakes (Chainguard pioneered, Anchore + others adopting). Parity.
- **Conventional commits + semver release automation** — Table-stakes in modern OSS. Parity.

### 6.3 The ten honest gaps (intentionally surfaced)

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

## 7. The six unclaimed gaps Evidentia fills

> **Section summary.** Independent research surfaced six structural
> gaps in the OSS GRC ecosystem that no project currently fills, and
> that Evidentia's existing architecture maps directly onto. These
> are the differentiation spine.

1. **A maintained Python OSCAL library.** `oscal-pydantic` is 2 years stale (last push 2024-04-06, 23 stars). Compliance-trestle is opinionated workflow software, not a library. Nothing else fills the `pip install evidentia-core; from evidentia_core import GapAnalyzer` shape.
2. **Bundled multi-framework crosswalk dataset.** NIST publishes 800-53 in OSCAL. CIS publishes Controls v8. ISO 27001 OSCAL ports are fragmented and unofficial. **Nobody bundles 82+ frameworks with vetted crosswalks.** Evidentia could publish `evidentia-catalogs` as a separate Apache/CC0 repo and become the *de facto* multi-framework reference dataset, the way `oscal-content` is for NIST 800-53 alone.
3. **Apache-2.0 alternative to AGPL CISO Assistant + Eramba + Comp AI.** Many enterprises (defense contractors, SaaS vendors who would distribute the code, federal sub-primes) categorically refuse AGPL. There is no permissively-licensed full-stack GRC OSS today. Real moat.
4. **Standardized bridge from CSPM/IaC scan results → OSCAL Assessment Results.** Prowler/Checkov/Trivy emit JSON. Nobody has canonical mappers to OSCAL `assessment-results` / `observation`. Evidentia's collectors layer is the right shape to fill this.
5. **Library-callable evidence chain with cryptographic provenance.** Evidentia's recent commits — Sigstore/Rekor signing of evidence, CycloneDX SBOM, PEP 740 attestations, air-gap refusal — make it the only OSS GRC tool that puts supply-chain integrity *on the evidence itself*, not just on the binary distribution. Nobody else does this.
6. **GovReady's vacated niche.** GovReady-Q (210 stars) hasn't shipped meaningful work since 2024; the org is functionally dormant. Anyone serious about Python-based GRC for government can simply walk into that vacuum.

---

## 8. Industry tailwinds

> **Section summary.** Three regulatory mandates take effect in the
> next six months that explicitly favor OSCAL-native tools:
> OMB M-24-15 (federal agency OSCAL ingestion/emission, July 25, 2026),
> FedRAMP RFC-0024 (machine-readable authorization packages, September
> 30, 2026), CMMC Phase 2 (Level 2 third-party assessments for ~300,000
> DOD contractors, November 10, 2026). The market is also consolidating
> at PE-driven scale (GRC = #1 cybersecurity M&A sub-sector in 2025
> with 82 deals), creating customer flight risk that OSS uniquely
> mitigates.

### 8.1 The three forcing-function dates

| Date | Mandate | Implication for Evidentia |
|---|---|---|
| **March 31, 2026** | NIST SSDF 800-218 Rev 1 (v1.2) **final** publication | Sets supply-chain compliance baseline through 2030; Evidentia mappings should ship same week |
| **July 25, 2026** | OMB M-24-15 — federal agency GRC tools must produce/ingest OSCAL | Of 100+ FedRAMP Rev5 authorizations in 2025, **zero used OSCAL** — massive supply gap; Evidentia is OSCAL-native and 18 months ahead |
| **August 2, 2026** | EU AI Office full enforcement powers under AI Act | First likely AI Act fine; ISO 42001 + EU AI Act crosswalks become valuable |
| **September 30, 2026** | FedRAMP RFC-0024 — machine-readable authorization packages mandatory | OSCAL becomes mandatory for FedRAMP; vendors lacking OSCAL face revocation risk |
| **November 10, 2026** | CMMC Phase 2 — Level 2 C3PAO third-party assessments mandatory for DOD contractors | **300,000 DOD contractors need 800-171 evidence collection now; only 1% are audit-ready**; Vanta/Drata at $30K/yr unaffordable for most |

### 8.2 Market validation that GRC is hot

- **GRC = #1 sub-sector in cybersecurity M&A 2025**: 82 deals, five-year peak (SecurityWeek)
- **Vanta**: Series D $4.15B (July 2025), $100M+ ARR — likely IPO 2026/2027
- **Drata**: $2B (Series C 2022), $100M ARR; acquired SafeBase $250M (Feb 2025)
- **AuditBoard**: Hg Capital take-private $3B (May 2024); rebranded Optro March 2026
- **Wiz**: Google Cloud acquisition $32B (closed March 2026, **largest VC-backed exit in history**)
- **OneTrust**: In PE talks at $10B+ (Nov 2025)
- **Lacework**: Brutal valuation reset $8.3B → $150M Fortinet sale (Aug 2024)
- **eGRC market sizing**: $72B → $204B by 2033 (Grand View Research; consensus 13–14% CAGR)
- **Tool consolidation**: 40%+ of orgs actively consolidating cybersecurity vendors; another 21% planning to (HashiCorp 2025)

### 8.3 OSS GRC inflection points

- **OSCAL Foundation formally launched February 10, 2025** with Brian Ruf and Stephen Banghart as coordinators — neutral governance for the OSCAL ecosystem
- **RegScale donated OSCAL Hub to the foundation December 2025** — active commercial-to-OSS migration in this exact space
- **FedRAMP 20x took off**: 114 authorizations in FY25 (more than 2× FY24), median time-to-authorization down from ~12 months to ~5 weeks; Phase 2 pilots launched late 2025
- **CSA launched Compliance Automation Revolution (CAR) at RSA 2025** with Google, Oracle, Salesforce, Deloitte Italy

### 8.4 Why this matters for Evidentia specifically

- **OSCAL-native, library-first** hits the September 2026 FedRAMP / July 2026 OMB GRC-tool mandate at a moment when 90%+ of incumbents still don't natively emit OSCAL
- **Open-source + sovereign deploy** serves EU customers facing DORA/NIS2 enforcement (who push toward EU-hosted or on-prem) and ~300,000 DOD contractors facing CMMC Phase 2 (who can't afford SaaS GRC at $30K+/yr)
- **Sigstore + air-gap refusal** aligns with EO 14306 retained provisions and Defense Unicorns / Big Bang / Platform One patterns
- **CycloneDX SBOM + collector pattern** aligns with CISA 2025 SBOM minimum elements update + FDA medical-device 524B
- **Vendor M&A creates customer flight risk** — AuditBoard → Hg, Drata acquiring SafeBase, OneTrust → likely PE buyout: enterprise customers are nervous about platform stability. Open-source = no acquisition risk

---

## 9. Industry headwinds

> **Section summary.** Five structural headwinds: AI moats at scale
> from incumbents; OSCAL adoption lagging the mandate; PE
> consolidation creating gravity wells; regulatory complexity
> demanding maintenance; AI hype risk making "just a library" look
> unfashionable. None is fatal, but each shapes positioning choices.

1. **Vanta + Drata + OneTrust have AI moats from scale.** Hundreds of integrations, customer corpora to fine-tune AI agents, 35+ pre-mapped frameworks. An OSS tool with 5 collectors looks small by comparison. **Mitigation**: lean into the OSCAL/sovereign/air-gap angles where SaaS can't follow; federate (let users plug Evidentia into existing SaaS GRC); position as the substrate that AI agents validate against (signed evidence, OSCAL artifacts).

2. **OSCAL adoption lags the mandate.** Zero of 100+ FedRAMP Rev5 authorizations in 2025 used OSCAL. The forcing function is real but vendors lag. **Risk**: the market educates slowly; revenue follows mandate enforcement, not mandate publication. **Mitigation**: be patient; the September 2026 + November 2026 dates will pull the market forward.

3. **Big-vendor PE consolidation will accelerate.** Hg, Vista, Thoma Bravo, Blackstone, KKR, Silver Lake are all active in GRC M&A. They'll bundle, cross-sell, undercut. OSS competes on different axes (sovereignty, transparency, cost) but loses on inertia and procurement gravity.

4. **Regulatory complexity itself.** 19 US state privacy laws, NIS2's 27 EU member-state transpositions, India DPDP phasing, EU AI Act tiers, China cross-border — keeping catalogs current is a real engineering cost. SaaS vendors have a compliance team; an OSS project relies on community + maintainer effort. **Mitigation**: bundled-catalog-as-a-product approach; community contribution channel for Tier-D statutory frameworks (which are uncopyrightable).

5. **AI hype risk.** "Agentic GRC" is the hottest framing in every conference. An OSS tool that's "just a library" may look unfashionable to enterprise buyers chasing the AI checkbox. **Counter-positioning**: cite Magesh / Ho et al. (Stanford 2025) who measured **17–33% hallucination rates** in commercial RAG-based legal research tools that vendors marketed as "hallucination-free." Frame Evidentia's AI-optional posture as deterministic-where-it-must-be, AI-where-it-helps. The DFAH paper (Mar 2026) provides the technical vocabulary for this distinction.

6. **CMMC backlash possibility.** If Phase 2 (Nov 2026) gets delayed (it has been pushed before), the urgency tailwind softens. Mitigation: don't bet messaging exclusively on CMMC; diversify across the three forcing-function dates.

---

## 10. Positioning frame — "Terraform / dbt of GRC"

> **Section summary.** The positioning frame that wins is **"Terraform
> / dbt of GRC"**: a library-first, CI-native primitive that
> orchestrates evidence and frameworks, rather than a SaaS dashboard
> you pay $14k/yr/framework for. This sidesteps the Vanta/Drata
> bake-off Evidentia would lose, and competes inside the
> dev-tools-for-compliance trend Chainguard, Snyk, and Anchore
> validated.

### 10.1 Why this frame works

- **It moves Evidentia out of a category Vanta/Drata own** (SaaS GRC dashboards) and into a category that has no incumbent (CI-native compliance primitives)
- **It signals to the right buyer** — security engineers and platform teams who already think in "policy as code", "infrastructure as code", "security as code" — that Evidentia speaks their idiom
- **It implies the right deployment model** — `pip install` + `evidentia gap analyze` in CI, not "request a demo" + "schedule a 6-month rollout"
- **It validates the positioning** by analogy: Terraform didn't beat AWS Console; it gave engineers a primitive layer that orchestrates AWS + Azure + GCP. dbt didn't beat Tableau; it gave analysts a primitive layer that orchestrates SQL transformations. Evidentia doesn't beat Vanta; it gives compliance engineers a primitive layer that orchestrates frameworks + evidence + risk

### 10.2 Pull-quote candidates for marketing

> *"The puck is moving from PDFs of evidence toward signed JSON streams of evidence. Evidentia is sitting almost exactly where the regulatory and market vectors are converging in the next 12–18 months."*

> *"AI is now table-stakes in commercial GRC, not differentiation. The new wedge is evidence quality, traceability, and auditor acceptance."*

> *"GRC has been waiting for its Terraform moment. Vanta and Drata are the AWS Consoles of compliance. Evidentia is the IaC layer underneath."*

### 10.3 The supporting messaging hierarchy

- **Primary**: "OSCAL-native, library-first, supply-chain-hardened GRC primitive — the Terraform / dbt of GRC"
- **Secondary**: "Open-source, Python, AI-optional, air-gap-capable. 82 frameworks bundled. Sigstore-signed evidence."
- **Tertiary** (proof points): "All 10 BLOCKER items in the enterprise-grade checklist closed at v0.7.0. PEP 740 attestations on every wheel. CycloneDX SBOM on every release. trestle conformance test in CI."
- **Honest disclaimer** (builds credibility): "Not a Vanta replacement for SOC-2-only buyers — those want the dashboard + auditor handoff. Evidentia is for engineers + platform teams who want compliance as a primitive."

---

## 11. AI posture

> **Section summary.** Evidentia's current AI stack (LiteLLM +
> Instructor + Pydantic risk-statement schemas) is the right OSS
> production stack as of April 2026. Foundational AI patterns in GRC
> (RAG-over-policy, AI questionnaire fill, control-mapping crosswalks)
> are now table-stakes. Bleeding-edge patterns Evidentia could adopt:
> determinism-faithfulness harnesses (DFAH paper, Mar 2026), Policy
> Reasoning Traces (PRT, Sept 2025), MCP server exposure of GRC store,
> Document Screenshot Embedding for evidence validation. AI gaps
> nobody else is filling: open risk-statement quality benchmark,
> open evidence-validation dataset, deterministic-replayable LLM
> evidence reasoning, OSCAL-fluent fine-tuned model. **The single
> highest-leverage AI feature Evidentia could ship next is a
> DFAH-style determinism harness for risk-statement generation.**

### 11.1 Foundational patterns (table-stakes; Evidentia at parity)

- **RAG over policy corpus for Q&A** — every commercial vendor and OSS project ships it
- **Auto-fill of security questionnaires with cited sources** — converged at ~95% first-pass accuracy (Conveyor, SafeBase, Vanta, Iris, Inventive)
- **Continuous controls monitoring with LLM-summarized failures** — Drata + Vanta + Hyperproof
- **Crosswalk / control-mapping via LLM embeddings** — Hyperproof "Suggested Links Agent", Optro Accelerate
- **AI-generated policy drafts** — every SOC-2 platform
- **Vendor SOC 2 PDF parsing** — Black Kite, Whistic, ProcessUnity, Vanta TPRM Agent, Drata Agentic TPRM
- **Pydantic / structured-output schemas as default LLM I/O** — Instructor crossed 3M monthly downloads (Evidentia uses this)
- **Trust Center as AI-published artifact** — SafeBase reference architecture; OpenAI's trust portal runs on it

### 11.2 Bleeding-edge patterns (likely to mature in 2026–2027)

- **Multi-agent / agentic GRC suites** — all majors shipped Q1 2026
- **MCP-served GRC data to general-purpose LLM clients** (Anecdotes, CISO Assistant) — interface paradigm shift
- **Anthropic Computer Use for browser-agent questionnaire completion** — being demoed
- **Multimodal evidence validation** (DSE, MMDocRAG papers) — academic-only today
- **Determinism-replay for audit defensibility** — DFAH framework defines the problem; **no shipping solution yet**
- **Cryptographic provenance for agent actions** (OpenAI Cookbook proposal #2461) — early
- **Live-attestation Trust Center consumption by buyer agents** (Drata Agentic TPRM does this against SafeBase)
- **Insurance pricing tied to AI-governance compliance** (StackAware × Armilla AI)

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

### 11.5 Hugging Face datasets that exist for GRC

- `camlsys/AIReg-Bench` — 300 EU AI Act compliance excerpts (180 downloads)
- `ethanolivertroy/nist-cybersecurity-training` — 530K+ examples from 596 NIST publications (19.6K downloads)
- `ethanolivertroy/nist-publications-raw` — same NIST corpus as raw PDFs (24.4K downloads)
- `nguha/legalbench` — 162 legal-reasoning tasks (canonical legal LLM benchmark)

### 11.6 HF gaps Evidentia could fill (publish to HF for citation/adoption)

- No open SOC 2 / ISO 27001 control-mapping dataset
- No open evidence-validation benchmark
- No open risk-statement quality eval set
- No open OSCAL-fluent fine-tuned model
- No open multimodal evidence (screenshot+log+PDF) compliance dataset

---

## 12. Industry voices — to cite, to follow, to pitch

> **Section summary.** A 30-person community across NIST/GSA, IBM
> Research, RegScale, Stacklet, and Aquia constitutes Evidentia's
> intellectual home (OSCAL Compass + OSCAL Foundation + Resilient
> Cyber / fwd:cloudsec / GRC-Engineering). Two outreach actions
> reach the entire community in one quarter: submit Evidentia to
> OSCAL Plugfest 2026 + open issue on `oscal-compass/community`
> proposing compliance-trestle interop. Top 4 voices to pitch:
> Mike Privette (Return on Security), AJ Yawn (Aquia, GRC
> Engineering), Pete Waterman (FedRAMP) + Brian Ruf (OSCAL
> Foundation), Greg Elin (RegScale, ex-GovReady).

### 12.1 Top 9 voices to follow continuously

1. **Phil Venables** — philvenables.com (strategic CISO frame; "industrialize security" thesis)
2. **Mike Privette** — Return on Security (market signal for OSS GRC)
3. **Chris Hughes** — Resilient Cyber (SBOM + supply chain + GRC — closest editorial fit for Evidentia)
4. **Anton Chuvakin** — Anton on Security + Cloud Security Podcast (cloud threat data)
5. **Kelly Shortridge** — kellyshortridge.com (resilience engineering + sharp DBIR analysis)
6. **AJ Yawn** — fwd:cloudsec talks + LinkedIn (GRC Engineering thought leadership)
7. **Wade Baker / Jay Jacobs** — Cyentia Institute (the empirical baseline for risk data)
8. **Greg Elin** — RegScale OSCAL leader, longest pro-OSS-GRC voice in the field (since 2014)
9. **Dr. Michaela Iorga** — NIST OSCAL Director (the standard itself)

### 12.2 Top 5 voices to cite in Evidentia's positioning copy

| Voice | Cite for | Why |
|---|---|---|
| **Phil Venables** | "Industrialize security" / flywheel framing | Frame Evidentia as the OSS infrastructure for industrialized compliance |
| **Wade Baker (Cyentia IRIS 2025)** | Empirical scale of incident frequency/cost | The "why GRC matters at all" hook |
| **Jack Jones (FAIR) + Doug Hubbard** | Quantitative risk authority | Frame Evidentia's risk-statement engine |
| **Andrew Jaquith** | "Security Metrics" framework | Risk-statement output schema |
| **Dr. Michaela Iorga + NIST CSWP 53** | OSCAL authority | Cite for the standard Evidentia speaks |

### 12.3 Top 4 voices to pitch Evidentia to (most likely amplifiers)

1. **Mike Privette / Return on Security** — single-best newsletter for OSS GRC tool launch coverage
2. **AJ Yawn (Aquia, ByteChek co-founder)** — same intellectual project (GRC Engineering); pitching him as a podcast guest or co-presenter at fwd:cloudsec 2026 is the natural ask
3. **Pete Waterman (FedRAMP) + Brian Ruf (OSCAL Foundation)** — Evidentia is exactly the kind of independent OSS tool that strengthens the FedRAMP 20x ecosystem; submit Evidentia for the FedRAMP 20x conformance pilot stream
4. **Greg Elin (RegScale OSCAL Lead, ex-GovReady)** — has been waiting for more OSS in this space since 2014; will recognize Evidentia as kin

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
- Phil Venables (Google Cloud CISO)
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

### 13.1 v0.7.x — supply-chain hardening polish (next 1–2 months)

- Tighten LiteLLM pin to exclude compromised 1.82.7/1.82.8 versions (`!=1.82.7,!=1.82.8` in pyproject.toml)
- SLSA L3 build provenance via `actions/attest-build-provenance@v2`
- `OpenSSF Scorecard` weekly run with public dashboard
- Submit Evidentia to OSCAL Plugfest 2026; fix any conformance failures
- Open `oscal-compass/community` interop discussion

### 13.2 v0.8.0 — the OSS-native AI moat (3-month horizon)

- **DFAH-style determinism harness** for risk-statement generation: `evidentia eval` CLI with decision-determinism + faithfulness + replay-equivalence metrics. Cite arXiv 2601.15322. **The differentiation flagship for v0.8.**
- **Policy Reasoning Traces (PRT) mode**: `evidentia risk generate --emit-trace` produces an explicit chain-of-thought trace alongside each risk statement, citing exact policy clauses. Cite arXiv 2509.23291.
- **Evidence groundedness gate**: every risk statement must cite an extracted evidence span; Evidentia refuses to emit otherwise. Borrow Ragas + DeepEval triad scoring.
- **Sigstore-signed risk-statement artifacts**: extend existing Sigstore signing to every risk statement
- **MCP server exposing Evidentia's GRC store** to Claude / ChatGPT clients
- **Publish `evidentia-catalogs` as standalone repo** under Apache-2.0 / CC0 — becomes the *de facto* multi-framework reference dataset
- **Publish risk-statement benchmark dataset on Hugging Face** — 200 manually-validated triples; becomes the evaluation standard

### 13.3 v0.9.x — collector + integration breadth (6-month horizon)

- **Okta collector** — MFA enforcement, inactive users, privileged account counts (AC-2, IA-2, IA-5)
- **Azure collector** — Policy compliance state, Defender for Cloud, Entra ID
- **GCP collector** — Security Command Center, Org Policy
- **ServiceNow integration** — push to `sn_compliance_task` via REST with OAuth 2.0
- **Vanta + Drata integrations** — push test results to their public APIs (positions Evidentia as "the OSS evidence layer that feeds your existing GRC SaaS")
- **Scanner-to-OSCAL adapters**: canonical Prowler-to-OSCAL, Checkov-to-OSCAL, Trivy-to-OSCAL mappers. Slot into the OSCAL Compass + complytime ecosystems.

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

> **Section summary.** Eight identified risks: (1) PE-driven Vanta/
> Drata bake-out absorbing the OSS GRC space; (2) commercial OSCAL
> tooling closing the gap; (3) AI hallucination incident discrediting
> Evidentia's risk-statement generation; (4) OSCAL adoption stalling;
> (5) catalog-maintenance burden as regulations multiply; (6) single-
> maintainer bus factor; (7) supply-chain attack on Evidentia's own
> dependencies; (8) reputation hit from premature "enterprise-grade"
> claim. Each has a planned mitigation.

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | **Vanta/Drata buy or replicate the OSCAL+OSS positioning** | Medium | High | Ship the determinism harness + bundled-catalogs dataset *before* they do; the latter is the kind of thing OSS does naturally and SaaS struggles to replicate |
| 2 | **RegScale (or another commercial OSCAL vendor) ships a closer competitor** | Medium | Medium | RegScale is moving partly OSS via OSCAL Hub donation; collaboration > confrontation; Evidentia's library-first shape is structurally different |
| 3 | **AI hallucination incident in Evidentia's risk-statement output** | Medium | Very high | Ship DFAH-style determinism harness in v0.8; cite Magesh/Ho 2025 in the threat model; emit groundedness-gate refusals rather than confident hallucinations |
| 4 | **OSCAL adoption stalls** (e.g., FedRAMP 20x slows; CMMC delayed again) | Low-Medium | Medium | Diversify positioning across multiple tailwinds (EU DORA, EU AI Act, sovereign deploy, GRC-as-CI primitive — each can stand alone) |
| 5 | **Catalog maintenance burden** as 19 US states + 27 EU states + India + China + Australia + UK each evolve their privacy/cybersecurity laws | High | Medium | Tier-D statutory framework community contribution channel; partner with the OSCAL Foundation for catalog-maintenance shared infra |
| 6 | **Single-maintainer bus factor** (Allen Byrd as solo maintainer) | High | High | Document everything in `docs/`; prefer in-repo docs over private notes (the pattern is now codified in `~/.claude/CLAUDE.md`); cultivate 2-3 external committers in the first 6 months |
| 7 | **Supply-chain attack on Evidentia's deps** (LiteLLM March 2026 incident is the canonical example) | Medium | Very high | Pin minor versions in pyproject.toml + commit `uv.lock`; tighten LiteLLM exclusion of 1.82.7/1.82.8; subscribe to PyPI advisory feeds; Sigstore-verify all dep updates |
| 8 | **Premature "enterprise-grade" claim** that doesn't survive a real audit | Low | High | Acknowledge the 10 honest gaps publicly; classify each as won't-fix / planned / in-progress; honest framing builds credibility, oversold framing destroys it |

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

---

*End of positioning-and-value.md. ~12,000 words. Cross-link to: [enterprise-grade.md](enterprise-grade.md) (the quality bar), [testing-playbook.md](testing-playbook.md) (the operational playbook), [ROADMAP.md](ROADMAP.md) (the version-level plan), [Evidentia-Architecture-and-Implementation-Plan.md](../Evidentia-Architecture-and-Implementation-Plan.md) (the canonical design doc).*
