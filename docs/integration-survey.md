# Evidentia — integration & architecture survey

> Compiled 2026-05-21 from a four-stream competitive/market research pass
> (GRC Engineering Club deep-dive, AI-governance vendors, an integration
> survey, and a competitive-landscape refresh). Companion to
> [positioning-and-value.md](positioning-and-value.md) §13 (the 12-month
> direction) and [ROADMAP.md](ROADMAP.md). This document inventories
> where Evidentia can connect to the wider GRC / security ecosystem and
> which architectural patterns from peer projects are worth adopting. It
> is forward-looking analysis, not a release commitment — items land in
> ROADMAP.md when scheduled.

---

## 1. Purpose

Evidentia speaks the **standards layer** of GRC well — OSCAL 1.2.1,
CycloneDX 1.6, Sigstore / PEP 740, the Model Context Protocol. Its
thinner surfaces are two:

1. **The findings-ingestion layer** — getting heterogeneous scanner,
   CSPM, and posture output *into* Evidentia as control evidence.
2. **The GRC-platform interchange layer** — exchanging data with the
   tools operators already run (cloud-native compliance services, other
   OSCAL tooling, SOC 2 platforms, enterprise GRC suites).

This survey maps the highest-leverage moves to close both gaps, plus the
architectural patterns — observed in peer projects and emerging standards
— that make those integrations cheap rather than one-off.

## 2. What Evidentia integrates today (baseline)

| Surface | Detail |
|---|---|
| **OSCAL 1.2.1** | Import + first-class emit: catalog, profile, assessment-results, POA&M, component-definition, CONMON state, SCR notification |
| **Supply chain** | CycloneDX 1.6 SBOM; Sigstore/Rekor + PEP 740 attestations; cosign-signed container; SLSA L3 build provenance |
| **MCP server** | 8 tools (`list_frameworks`, `get_control`, `gap_analyze`, `gap_diff`, `conmon_list_cadences`, `conmon_next_due`, `conmon_check_state`, `conmon_health`); stdio / SSE / HTTP transports; per-tool CIMD scope enforcement; `SignedToolOutput` envelope |
| **REST API** | FastAPI; `/api/poam/*`, `/api/conmon/*`, `/api/gaps`, `/api/metrics`; auth middleware |
| **CI** | Bundled composite GitHub Action (`gap-analysis`) |
| **Evidence collectors** | AWS (Config / Security Hub / IAM Access Analyzer), GitHub, Okta, ServiceNow, 5 SQL databases, Databricks, Snowflake |
| **Output integrations** | Jira, ServiceNow, Tableau, Power BI |

**The structural observation.** Each collector today emits a
framework-shaped finding. That couples collector count to framework
count and is the root cause of the integration-breadth gap that
[positioning-and-value.md](positioning-and-value.md) §6.3.2 honest-gap #3
surfaces (8 evidence collectors vs. Vanta's 375+). §4.1 below is the
structural fix — and every other integration in §3 gets cheaper once it
is in place.

## 3. Integration opportunities (prioritized)

Value and effort are relative to Evidentia's current architecture.
"Effort" assumes the §4.1 normalized-schema work is done first where
noted.

> **SHIPPED column updated 2026-05-23** as v0.10.4 A5 deliverable —
> tracks which integration opportunities have landed in the v0.10.x
> patch line since the survey was compiled.

| # | Integration | What it gives Evidentia | Surface | Value | Effort | Shipped |
|---|---|---|---|---|---|---|
| 1 | **OCSF findings ingestion** | One adapter ingests Prowler, Security Hub, Datadog, RegScale findings → control-gap evidence | OCSF JSON (`compliance` / `detection_finding` classes) | Very high | Med | ✅ **v0.10.1** — `evidentia collect ocsf --input <file-or-url>`; `finding_from_ocsf_detection` for class_uid 2004 (Prowler / Security Hub); 12 collectors populate `compliance_status` |
| 2 | **AWS Security Hub / Audit Manager** | Live cloud posture as evidence; the dominant cloud compliance surface | REST API; native OCSF + ASFF export | Very high | Low–Med (after #1) | ⚠️ **Partial v0.10.1** — Security Hub findings ingestible via the OCSF Detection Finding path; native API collector not yet shipped |
| 3 | **Prowler ingestion** | OSS CSPM, 500+ checks → instant evidence collector; OSS-ethos aligned | CLI emitting `json-ocsf` / SARIF | High | Low | ✅ **v0.10.1** — covered by the OCSF Detection Finding path (Prowler emits class_uid 2004 OCSF natively) |
| 4 | **SARIF emit** | Gap results surface in GitHub code scanning + GitLab MR security dashboards with zero glue | SARIF 2.1.0 JSON | High | Low | ✅ **v0.10.0** — `evidentia gap analyze --format sarif`; CI-gate-ready |
| 5 | **Trivy / Checkov ingestion** | IaC + vuln misconfig findings as control evidence | SARIF 2.1.0 (Trivy also ASFF) | High | Low (after #4) | ❌ — not yet; v0.11+ candidate |
| 6 | **RegScale interchange** | Bidirectional OSCAL exchange with a CONMON-on-OSCAL platform; partner-ecosystem play | REST API; native OSCAL + OCSF | High | Med | ❌ — not yet; partner-engagement-gated |
| 7 | **Lula (Defense Unicorns)** | Co-positioning in the federal/CI compliance-as-code niche; OSCAL artifact exchange | OSCAL artifacts; CLI; GitHub Action | High (federal) | Low–Med | ❌ — not yet; v1.1 federal-tier candidate |
| 8 | **Vanta / Drata API** | Push gap findings / pull evidence from the SOC 2 incumbents; reach the SMB market | REST APIs; OAuth apps; partner programs | Med–High | Med | ⚠️ **Partial v0.10.1** — Vanta + Drata existing collectors gained `compliance_status` field; full bidirectional API exchange deferred to v0.11+ |
| 9 | **ScubaGear / CISA SCuBA** | Ingest M365 baseline results mapped to 800-53 | JSON/CSV; SCuBA→800-53 crosswalk | Med (federal) | Low–Med | ❌ — not yet; v1.1 federal-tier candidate |
| 10 | **Azure Policy / GCP Security Command Center** | Cloud-native posture parity beyond AWS | Azure REST; GCP SCC API (normalize via OCSF) | Med | Med | ❌ — not yet; v0.11+ candidate |
| 11 | **Backstage scorecard plugin** | "Compliance score" tile in internal developer portals | Backstage frontend plugin + catalog JSON | Med | Med | ❌ — not yet |
| 12 | **MLflow / Hugging Face model cards** | AI-governance evidence: model provenance/cards as NIST AI RMF Map/Measure evidence | MLflow registry API; HF model-card YAML | Med (AI moat) | Med | ⚠️ **Partial v0.9.x** — `AISystem` + `AISystemClassification` + Annex IV registry exists; MLflow / HF Hub direct ingest not yet wired |
| 13 | **OPA / Rego policy bundles** | Express control checks as Rego; consume OPA decision logs as evidence | OPA decision API; decision-log JSON | Med | Med | ❌ — not yet; v0.11+ candidate |
| 14 | **ServiceNow IRM / Archer** | Enterprise GRC system-of-record interchange | ServiceNow Table API; Archer REST | Med (enterprise) | High | ❌ — not yet; v1.1 enterprise-tier candidate |
| 15 | **Splunk / Datadog export** | Push compliance posture as events for SIEM dashboards | Splunk HEC; Datadog Events API | Low–Med | Low | ✅ **v0.10.4** — `evidentia gap analyze --format ocsf` emits OCSF Compliance Finding array; SIEM-ready (Splunk/Datadog/Elastic all ingest OCSF) |

**Deliberately not prioritized now:** OneTrust, AuditBoard/Optro,
Hyperproof, Anecdotes — closed partner programs, enterprise-sales-gated
APIs, low OSS-ecosystem overlap. Revisit only on a specific customer
pull.

## 4. Architecture patterns to adopt

Each pattern below was observed in at least one peer project or emerging
standard during the May 2026 research pass. They are ordered by leverage.

### 4.1 Normalized findings schema — align to OCSF (highest priority)

Today every collector emits a framework-specific shape. **Refactor
collectors to emit a canonical, framework-neutral finding, then map
*into* control gaps downstream.** This decouples collector count from
framework count: every tool that already speaks the canonical schema
becomes a near-free collector.

The schema to align to is **OCSF — the Open Cybersecurity Schema
Framework** (`compliance` and `detection_finding` classes). OCSF is the
convergence point already used by AWS Security Hub, Prowler, Datadog,
and RegScale, and it gained ITU support in 2026 — i.e. it is becoming an
international standard, not a vendor schema. Adopting it unlocks
integration opportunities #1, #2, #3, #5, #9, and #10 at once.

Corroborating signal: the GRC Engineering Club's `claude-grc-engineering`
toolkit independently arrived at the same pattern — a bespoke
`finding.schema.json` v1.0.0 with a `resource` + `evaluations[]` shape
and explicit `run_id` / `source_version` reproducibility fields. Two
independent projects converging on "normalize the finding first" is a
strong signal. Evidentia should align to **OCSF** rather than a bespoke
schema, because OCSF carries the larger ecosystem.

This is the keystone item. Everything else in §3 is cheaper after it.

### 4.2 SARIF output for CI-gate-first compliance

Evidentia already ships a GitHub Action. Emitting **SARIF 2.1.0** from
`evidentia gap` makes gap analysis a *blocking PR check* rendered in
GitHub code scanning and GitLab MR security dashboards — no custom UI,
no glue. Small effort, large positioning payoff: it makes "compliance as
a CI gate" literally true and is the natural surface for ingesting
Trivy/Checkov (#5), which already emit SARIF.

### 4.3 MCP-server-as-backend — deepen the differentiator

Evidentia's 8-tool MCP server is a genuine differentiator: it is a
*shipped* server with deterministic, signed output, whereas peer Claude-
ecosystem GRC projects orchestrate prompts and shell out to external
tools. Lean in. Position Evidentia explicitly as **the compliance engine
behind other agents** — audit copilots, IDE assistants, and GRC plugin
suites. Concrete moves: add MCP *resource* endpoints (catalogs,
crosswalks) alongside the tools, and broaden the tool surface toward the
planned `risk_generate` / `oscal_emit` / `collect_*` verbs. See §5 for
the specific GRC Engineering Club channel.

### 4.4 YAML-driven framework & control-tier definitions

Let non-programmers add catalogs and control-tier logic via declarative
YAML rather than Python. Both the GRC Engineering Club toolkit (scaffold
commands, `crosswalk-overrides.yaml`) and Lula ("simple YAML +
spreadsheets") use this to broaden their contributor base. For Evidentia
it lowers the barrier to catalog coverage — the maintenance burden that
[positioning-and-value.md](positioning-and-value.md) §14 risk #5 flags —
without requiring Python review of every new framework.

### 4.5 Persona modes

Auditor / engineer / TPRM views over the same underlying data: auditors
want evidence completeness and assertions; engineers want failing
controls + remediation; TPRM wants vendor-posture summaries. The GRC
Engineering Club ships these as distinct persona plugins; for Evidentia
this is mostly a presentation-layer concern (CLI flags / UI tabs) over
existing models — low cost, real UX gain.

### 4.6 Knowledge-source "live doc" retrieval (opt-in only)

An *optional* online mode that queries authoritative sources (the NIST
OSCAL Hub, regulator pages) at runtime addresses catalog staleness. It
must be gated behind an explicit flag: **air-gap capability and bundled
catalogs remain the default and the canonical path** — that is a core
Evidentia differentiator and must not regress. The MCP server is the
natural host for such a retrieval tool.

### 4.7 Plugin contract — formalize; defer the marketplace

Evidentia already scaffolds `evidentia_core.plugins`. Formalize the
**plugin contract** and document out-of-tree collector authoring. Hold a
*hosted* marketplace until there is real third-party demand — premature
marketplace infrastructure is a maintenance sink. (The GRC Engineering
Club's marketplace works because the artifacts are prompt bundles with
near-zero runtime; Evidentia's plugins are code and carry a higher
review/security bar.)

## 5. The GRC Engineering Club interoperability opportunity

`GRCEngClub/claude-grc-engineering` (MIT core) is a **Claude Code plugin
marketplace** for GRC work — 63 plugins, 98 skills, 257 commands across
persona, framework, and connector plugins. It is a prompt/orchestration
layer with an explicit non-goal of being a runtime engine; its
`grc-engineer` hub shells out to external tools for anything
deterministic.

That makes it **complementary to Evidentia, not competitive** — they are
adjacent layers. The opportunity:

- **Publish a thin Evidentia MCP connector/plugin into the
  `grc-engineering-suite` marketplace.** Evidentia's MCP server (8 tools,
  signed output) is exactly the deterministic backend that toolkit's
  personas lack. This reaches a growing, well-aligned audience through a
  zero-setup distribution channel (`/plugin install`) that Evidentia
  does not otherwise have.
- **Align the §4.1 normalized schema** with the conceptual shape of
  their MIT-licensed `finding.schema.json` where it does not conflict
  with OCSF — interoperability with their connectors is then close to
  free.

Note on licensing: the toolkit's *core code* is MIT (adoptable with
attribution), but it bundles **CC BY-ND 4.0** data (Secure Controls
Framework crosswalks — no derivatives) and **CC BY-SA 4.0** content (CIS
Controls — copyleft). Evidentia should adopt *patterns and ideas*, which
carry no licensing obligation, rather than lifting bundled data into an
Apache-2.0 repository.

## 6. Mapping to the Gemara reference model

In March 2026 the OpenSSF published **Gemara**, a layered reference
model for "GRC engineering" / compliance-as-code. As an emerging
community-blessed architecture, it is worth (a) mapping Evidentia's
components onto Gemara's layers in positioning material, and (b) using
its vocabulary so Evidentia is legible to the practitioners adopting it.
This is a positioning/documentation task, not an engineering one, and it
costs almost nothing.

✅ **SHIPPED v0.10.3** — see [`docs/gemara-mapping.md`](gemara-mapping.md)
(NORMATIVE 13-row component-by-component mapping; Gemara v1.1.0
2026-05-12 cited; adopters FINOS CCC + OpenSSF Security Baseline).

## 7. Suggested sequencing

> **Sequencing status updated 2026-05-23** as v0.10.4 A5 deliverable.

1. **OCSF normalized findings schema** (§4.1) — the keystone.
   ✅ SHIPPED v0.10.0.
2. **SARIF emit** (§4.2) — quick win, unblocks #4/#5 in §3.
   ✅ SHIPPED v0.10.0.
3. **Prowler + AWS Security Hub collectors** (§3 #2, #3) — first payoff
   of the OCSF work. ✅ SHIPPED v0.10.1 (via the OCSF Detection
   Finding ingestion path; native Security Hub API collector
   deferred).
4. **YAML framework definitions** (§4.4) — broadens contribution.
   ✅ SHIPPED v0.10.3.
5. **Persona modes** (§4.5) — presentation-layer UX win.
   🚫 Deferred to commercial-tier (v0.10.2 OSS-vs-paid lock-in:
   generalist OSS skills only; persona-tied skills reserved for
   future Pro/Federal tier).
6. **MCP deepening + GRC Engineering Club plugin** (§4.3, §5).
   ✅ SHIPPED v0.10.2 — MCP surface 8 → 12 tools; marketplace plugin
   staged at `marketplace/grc-engineering-suite/plugins/evidentia/`
   (upstream PR is a separate publishing action awaiting approval).
7. **RegScale / Lula OSCAL interchange** (§3 #6, #7) — federal lane.
   ❌ Deferred to v1.1 federal-tier.
8. **Optional live-doc retrieval** (§4.6) and **plugin-contract
   formalization** (§4.7). ⚠️ §4.7 partially shipped via the v0.9.7
   api-stability.md NORMATIVE promotion; live-doc retrieval still TBD.

**Beyond the original sequence** (added since the May 21 baseline):

- **`evidentia gap analyze --format ocsf`** (the symmetric counterpart
  to the v0.10.0 SARIF emit + the v0.10.1 OCSF ingest) — gap output
  flows into SIEMs / data lakes / OCSF-aware tooling. ✅ SHIPPED v0.10.4.
- **F-V101-L1 SSRF hardening** (`--block-private-ips` on OCSF URL
  mode) — defense-in-depth on the ingest collector. ✅ SHIPPED v0.10.2.
- **YAML-format catalog support** (the §4.4 deliverable) — catalog
  contribution barrier lowered via `_load_catalog_data` extension
  dispatch + `iso-27017-2015.yaml` proof. ✅ SHIPPED v0.10.3.

This sequence front-loads the structural change (OCSF) that makes
everything after it cheap, and defers the items (enterprise GRC
interchange, hosted marketplace) whose value depends on customer pull
that does not yet exist.

## 8. v0.10.5 research-pass additions (2026-05-24)

The Phase B audit research pass (6 parallel streams; HF MCP `paper_search`
+ Perplexity ask + targeted WebFetch) surfaced four high-leverage
integration moves Evidentia can ship as **first-of-its-kind OSS
artifacts**. Each becomes a citable claim in its own right because no
other OSS project has shipped it. Sequenced into v0.10.5 — see
[`v0.10.5-plan.md`](v0.10.5-plan.md).

### 8.1 OpenSSF OSPS Baseline OSCAL conversion (FIRST-MOVER)

The OpenSSF **OSPS Baseline v2026.02.19** ships as Markdown only — 41
controls × 3 maturity levels × 8 control families (AC / BR / DO / GV /
LE / QA / SA / VM). **No OSCAL conversion exists in the OSS ecosystem.**
v0.10.5 Phase 2 ships the conversion as an OSCAL catalog + profile pair
(Apache-2.0) and submits the catalog upstream to
`ossf/security-baseline`. Evidentia becomes the canonical OSCAL surface
for the baseline that defines OSS-project security hygiene — directly
adjacent to where Evidentia sits in the §5.5 OSS GRC tier.

### 8.2 FedRAMP 20x readiness — KSI emission posture

FedRAMP **20x** (the "machine-readable continuous-monitoring" pillar of
the FedRAMP modernization) entered its **Moderate pilot through
2026-03-31** and the **public rollout lands Q3 2026**. The central
artifact is **KSIs — Key Security Indicators** delivered as continuous
OSCAL feeds (a structural extension to assessment-results + POA&M).
Evidentia's existing OSCAL emit + CONMON daemon (v0.9.6 first-mover) +
SCR notification surface (v0.9.7) compose into a near-direct KSI
emitter. v0.11 schedules the KSI binding as a first-mover claim — the
public rollout coincides with Evidentia's federal-compliance theme
window. Sources: GSA FedRAMP 20x announcement; CISA CSAW; RegScale
OSCAL Hub.

### 8.3 OpenVEX 0.2.0 emit (FIRST-MOVER among GRC engines)

**OpenVEX v0.2.0** (CNCF; JSON-LD; status enum
`{not_affected, affected, fixed, under_investigation}`) is the emerging
VEX format for vulnerability-exploitability statements. **Dependency-
Track does NOT consume OpenVEX (only CycloneDX VEX)**; GUAC is the only
mature OSS consumer. Evidentia's planned **`evidentia vex emit`** verb
(v0.11) makes it the first OSS GRC engine to emit OpenVEX statements
alongside its CycloneDX SBOM — the natural bridge between Evidentia's
supply-chain artifacts (§2) and the wider supply-chain-VEX ecosystem.
Coupled with a Grype subprocess wrapper (Grype emits neither `-o vex`
nor `-o ocsf` natively — needs a thin wrapper) this closes the
"vulnerability triage as compliance evidence" loop.

### 8.4 CISA Secure by Design (SbD) Pledge — first OSS signatory

The CISA **Secure by Design Pledge** (~100 signatories as of May 2026,
**all commercial vendors**) has seven goals. **No OSS project has
signed.** Evidentia is uniquely positioned to be the first — every goal
maps onto existing Evidentia work (MFA-by-default, default deny on the
MCP surface, vulnerability disclosure, evidence of patching cadence,
etc.). v0.10.5 Phase 4 ships **SECURITY.md** + a **security.txt** + the
**SbD pledge SELFATTEST** (Markdown form per CISA template) — the first
OSS project to do so. Cross-stream signal: also closes 4 of the 8
templates in skill v5.1's "compliance closure bundle".

### 8.5 SLSA Verification Summary Attestation (VSA) emit

SLSA v1.0 introduces **VSAs** as the auditable third-party verification
artifact (distinct from build provenance). The reference OSS emitter
(`slsa-framework/slsa-verifier --emit-vsa`) exists but is rare in
practice. v0.11 schedules `evidentia vsa emit` so each release ships a
VSA alongside its SLSA Provenance v1 + PEP 740 attestations — the
verification-loop closure for high-trust operators. Cross-cite with
NIST SSDF v1.2 IPD (Dec 17 2025 draft) PS.4 ("Robust and Reliable
Updates") which formalizes update-attestation as a normative
expectation.

### 8.6 Cross-reference table — first-mover claims

| Artifact | First-mover scope | Phase | Ships |
|---|---|---|---|
| OSPS Baseline OSCAL conversion + upstream PR | First OSCAL conversion of the OpenSSF OSPS Baseline | v0.10.5 P2 | OSCAL catalog + profile in `marketplace/oscal/` |
| OSPS-CONFORMANCE.md + CI gate | First OSS project to publish a self-conformance statement against OSPS Baseline | v0.10.5 P3 | `docs/OSPS-CONFORMANCE.md` + `.github/workflows/osps-conformance.yml` |
| CISA SbD Pledge SELFATTEST | First OSS signatory of the CISA Secure by Design Pledge | v0.10.5 P4 | `docs/SECURE-BY-DESIGN-PLEDGE.md` + signal upstream |
| OpenVEX emit | First OSS GRC engine to emit OpenVEX 0.2.0 | v0.11 P3 | `evidentia vex emit` CLI verb |
| FedRAMP 20x KSI emit | First OSS engine to emit Key Security Indicators as continuous OSCAL | v0.11 P5 | `evidentia conmon ksi-emit` CLI verb |
| SLSA VSA emit | First OSS GRC engine to emit SLSA VSAs alongside provenance | v0.11 P4 | `evidentia vsa emit` CLI verb |

### 8.7 AWS OSCAL MCP cross-reference

`awslabs/oscal-mcp-server` (Apache-2.0; `samples/` archived shape — not
a service) is the only other OSCAL-aware MCP server in the OSS
ecosystem as of May 2026. Its scope is **knowledge-tool only** —
answers OSCAL schema + 800-53 / 800-171 catalog questions via embedded
references; does **not** emit OSCAL artifacts. Evidentia's MCP server
(§4.3) goes structurally further: emits component-definition / SSP /
assessment-results / POA&M / VEX / VSA. Worth cross-citing as the only
OSCAL-MCP precedent; not a competitor. See [positioning-and-value.md
§5.5](positioning-and-value.md) for the same cross-reference in the OSS
GRC tier table.

### 8.8 ComplianceCow MCP cross-reference

`compliancecow/cowmcp` (Apache-2.0 server; ComplianceCow backend
proprietary) is the **only other OSS GRC MCP server besides Evidentia's
`evidentia mcp serve`**. The shape difference: ComplianceCow MCP is a
thin facade over a SaaS backend (14 tools, all hitting the
ComplianceCow API), whereas Evidentia is a self-contained runtime
engine. Worth cross-citing as the only other OSS GRC MCP — and as the
honest-landscape entry "two OSS GRC MCP servers exist as of May 2026,
both Apache-2.0".

## 9. Sources

- [OCSF — Open Cybersecurity Schema Framework](https://ocsf.io/)
- [OCSF achieves ITU support (AWS Open Source Blog)](https://aws.amazon.com/blogs/opensource/ocsf-achieves-itu-support-powering-ai-ready-security-operations/)
- [AWS Security Hub and OCSF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ocsf.html)
- [Prowler reporting (OCSF / SARIF / ASFF)](https://docs.prowler.com/user-guide/cli/tutorials/reporting)
- [Trivy SARIF output](https://trivy.dev/docs/latest/configuration/reporting/)
- [SARIF support for GitHub code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support-for-code-scanning)
- [RegScale — continuous monitoring built on OSCAL](https://regscale.com/continuous-monitoring-built-on-oscal/)
- [Lula by Defense Unicorns](https://github.com/defenseunicorns/lula)
- [compliance-trestle (oscal-compass)](https://github.com/oscal-compass/compliance-trestle)
- [CISA ScubaGear](https://github.com/cisagov/ScubaGear)
- [Vanta Developer Hub](https://developer.vanta.com/)
- [Drata API documentation](https://developers.drata.com/api-docs/)
- [Backstage plugins directory](https://backstage.io/plugins/)
- [OpenSSF — introducing the Gemara model](https://openssf.org/blog/2026/03/09/introducing-the-gemara-model/)
- [GRCEngClub/claude-grc-engineering](https://github.com/GRCEngClub/claude-grc-engineering)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)

**Added 2026-05-24 (v0.10.5 research-pass sources):**

- [OpenSSF OSPS Baseline](https://github.com/ossf/security-baseline) (v2026.02.19; Apache-2.0)
- [CISA Secure by Design Pledge](https://www.cisa.gov/securebydesign/pledge) (7 goals; ~100 signatories May 2026; zero OSS)
- [OpenVEX v0.2.0 specification](https://github.com/openvex/spec) (JSON-LD)
- [SLSA v1.0 Verification Summary Attestation (VSA)](https://slsa.dev/spec/v1.0/verification_summary)
- [NIST SSDF v1.2 IPD](https://csrc.nist.gov/pubs/sp/800/218/r1/ipd) (Dec 17 2025 initial public draft; PS.4 + PO.6 + RV.1.2)
- [NIST SP 800-218A — AI Profile](https://csrc.nist.gov/pubs/sp/800/218/a/final) (FINAL July 26 2024)
- [FedRAMP 20x announcement (GSA)](https://www.fedramp.gov/blog/2025-02-27-introducing-fedramp-20x/)
- [awslabs/oscal-mcp-server](https://github.com/awslabs/oscal-mcp-server) (Apache-2.0; knowledge tool)
- [compliancecow/cowmcp](https://github.com/compliancecow/cowmcp) (Apache-2.0 MCP server)
- [Marino & Lane — Computational Compliance for AI Regulation (arXiv 2601.04474)](https://arxiv.org/abs/2601.04474)
- [Khatchadourian — DFAH v2 (arXiv 2601.15322v2)](https://arxiv.org/abs/2601.15322v2)

---

*Cross-link to: [positioning-and-value.md](positioning-and-value.md)
(competitive landscape + 12-month direction), [ROADMAP.md](ROADMAP.md)
(version-level plan), [Evidentia-Architecture-and-Implementation-Plan.md](../Evidentia-Architecture-and-Implementation-Plan.md)
(canonical design doc).*
