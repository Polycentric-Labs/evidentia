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

| # | Integration | What it gives Evidentia | Surface | Value | Effort |
|---|---|---|---|---|---|
| 1 | **OCSF findings ingestion** | One adapter ingests Prowler, Security Hub, Datadog, RegScale findings → control-gap evidence | OCSF JSON (`compliance` / `detection_finding` classes) | Very high | Med |
| 2 | **AWS Security Hub / Audit Manager** | Live cloud posture as evidence; the dominant cloud compliance surface | REST API; native OCSF + ASFF export | Very high | Low–Med (after #1) |
| 3 | **Prowler ingestion** | OSS CSPM, 500+ checks → instant evidence collector; OSS-ethos aligned | CLI emitting `json-ocsf` / SARIF | High | Low |
| 4 | **SARIF emit** | Gap results surface in GitHub code scanning + GitLab MR security dashboards with zero glue | SARIF 2.1.0 JSON | High | Low |
| 5 | **Trivy / Checkov ingestion** | IaC + vuln misconfig findings as control evidence | SARIF 2.1.0 (Trivy also ASFF) | High | Low (after #4) |
| 6 | **RegScale interchange** | Bidirectional OSCAL exchange with a CONMON-on-OSCAL platform; partner-ecosystem play | REST API; native OSCAL + OCSF | High | Med |
| 7 | **Lula (Defense Unicorns)** | Co-positioning in the federal/CI compliance-as-code niche; OSCAL artifact exchange | OSCAL artifacts; CLI; GitHub Action | High (federal) | Low–Med |
| 8 | **Vanta / Drata API** | Push gap findings / pull evidence from the SOC 2 incumbents; reach the SMB market | REST APIs; OAuth apps; partner programs | Med–High | Med |
| 9 | **ScubaGear / CISA SCuBA** | Ingest M365 baseline results mapped to 800-53 | JSON/CSV; SCuBA→800-53 crosswalk | Med (federal) | Low–Med |
| 10 | **Azure Policy / GCP Security Command Center** | Cloud-native posture parity beyond AWS | Azure REST; GCP SCC API (normalize via OCSF) | Med | Med |
| 11 | **Backstage scorecard plugin** | "Compliance score" tile in internal developer portals | Backstage frontend plugin + catalog JSON | Med | Med |
| 12 | **MLflow / Hugging Face model cards** | AI-governance evidence: model provenance/cards as NIST AI RMF Map/Measure evidence | MLflow registry API; HF model-card YAML | Med (AI moat) | Med |
| 13 | **OPA / Rego policy bundles** | Express control checks as Rego; consume OPA decision logs as evidence | OPA decision API; decision-log JSON | Med | Med |
| 14 | **ServiceNow IRM / Archer** | Enterprise GRC system-of-record interchange | ServiceNow Table API; Archer REST | Med (enterprise) | High |
| 15 | **Splunk / Datadog export** | Push compliance posture as events for SIEM dashboards | Splunk HEC; Datadog Events API | Low–Med | Low |

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

## 7. Suggested sequencing

1. **OCSF normalized findings schema** (§4.1) — the keystone.
2. **SARIF emit** (§4.2) — quick win, unblocks #4/#5 in §3.
3. **Prowler + AWS Security Hub collectors** (§3 #2, #3) — first payoff
   of the OCSF work.
4. **YAML framework definitions** (§4.4) — broadens contribution.
5. **Persona modes** (§4.5) — presentation-layer UX win.
6. **MCP deepening + GRC Engineering Club plugin** (§4.3, §5).
7. **RegScale / Lula OSCAL interchange** (§3 #6, #7) — federal lane.
8. **Optional live-doc retrieval** (§4.6) and **plugin-contract
   formalization** (§4.7).

This sequence front-loads the structural change (OCSF) that makes
everything after it cheap, and defers the items (enterprise GRC
interchange, hosted marketplace) whose value depends on customer pull
that does not yet exist.

## 8. Sources

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

---

*Cross-link to: [positioning-and-value.md](positioning-and-value.md)
(competitive landscape + 12-month direction), [ROADMAP.md](ROADMAP.md)
(version-level plan), [Evidentia-Architecture-and-Implementation-Plan.md](../Evidentia-Architecture-and-Implementation-Plan.md)
(canonical design doc).*
