# Evidentia → OpenSSF Gemara reference-model mapping

> **Status**: NORMATIVE positioning material (v0.10.3+).
>
> **Source of truth for Gemara**: [`github.com/ossf/gemara`](https://github.com/ossf/gemara)
> (OpenSSF; current release v1.1.0, 2026-05-12). Schemas authored
> in [CUE](https://cuelang.org/); Go SDK at
> [`github.com/gemaraproj/go-gemara`](https://github.com/gemaraproj/go-gemara).
>
> **Why this doc exists**: per the 2026-05-21 competitive /
> integration research pass and v0.10.3 Phase 2, position Evidentia
> components onto Gemara's data-model taxonomy so OpenSSF-adopting
> peers (FINOS Common Cloud Controls, OpenSSF Security Baseline)
> can read Evidentia outputs through the same lens. This is a
> *mapping*, not a *conformance claim* — Evidentia does not (yet)
> emit Gemara-shape artifacts directly.

---

## 1. What Gemara is

Gemara is OpenSSF's standardized, machine-readable data model
designed to bridge high-level compliance requirements and low-level
technical evidence. It enables automated risk assessment and
consistent reporting across security toolchains.

Where existing standards focus on individual artifacts (NIST OSCAL
for control catalogs and assessment results; OCSF for raw security
findings; SARIF for static-analysis output), **Gemara provides the
taxonomy spanning all of them** — a single reference model in which
the Catalog, the Finding, the Mapping, the Enforcement Log, and the
Entity each have a named place.

Adopters (as of 2026-05-23):

- **FINOS Common Cloud Controls** — cloud-control catalog
  cross-mappings.
- **OpenSSF Security Baseline** — the OpenSSF's own minimum-bar
  project, structured against Gemara.

## 2. Gemara taxonomy (canonical, per v1.1.0)

| Tier | Component family | Components |
|---|---|---|
| **Catalogs** | Static definitions | Control · Capability · Principle · Risk · Threat · Vector · Guidance · Lexicon |
| **Logs** | Dynamic / time-series | Audit · Enforcement · Evaluation |
| **Documents** | Static relations | Mapping documents · Policies |
| **Entities** | Subjects of evaluation | Core entity definitions (org, system, vendor, person) |
| **Collections** | Composites | Related groupings of the above |

## 3. Mapping — Evidentia surfaces onto Gemara

| Gemara component | Evidentia surface | Notes |
|---|---|---|
| **Catalog: Control** | `evidentia_core.models.catalog.ControlCatalog` (89 bundled — NIST 800-53, SOC 2, ISO 27001 stub, CIS, CMMC, PCI DSS, EU GDPR, EU AI Act, …) | Tier-classified (A/B/C/D — see `ATTRIBUTION.md`); JSON or YAML format (v0.10.3+ via `docs/contributing-a-catalog.md`). 1:1 conceptual match. |
| **Catalog: Capability** | partial — `Control.implementation_status` enum (`implemented` / `partial` / `planned` / `missing`) | Evidentia tracks implementation state per control, not as a separate capability registry. Could be promoted to a first-class Capability model if Gemara conformance becomes a goal. |
| **Catalog: Principle** | no direct equivalent | Evidentia treats principles as "tier-D obligations" inside `ObligationCatalog` (statutes, regulatory edicts). Functionally adjacent but not 1:1. |
| **Catalog: Risk** | `evidentia_ai.risk_statements.RiskStatement` (NIST SP 800-30 Rev 1) + `evidentia_core.models.governance.AISystemClassification` (EU AI Act tiers, NIST AI RMF) | Risk catalogs in Evidentia are generated, not pre-defined — the LLM-driven `RiskStatementGenerator` produces statements from gaps + system context. Pre-defined risk catalogs are a v0.11+ candidate. |
| **Catalog: Threat** | `evidentia_core.models.threat.TechniqueCatalog` (MITRE ATT&CK Enterprise — 41 techniques bundled) + `docs/threat-model.md` (STRIDE) | ATT&CK techniques are a 1:1 match for Gemara's Threat catalog. The Evidentia threat model is project-internal STRIDE; Gemara's Threat catalog is broader cross-org. |
| **Catalog: Vector** | `evidentia_core.models.threat.VulnerabilityCatalog` (CWE Top 25 + CISA KEV samples) + CVE references in `SecurityFinding` | CWE / CVE / KEV all map onto Gemara's Vector tier. |
| **Catalog: Guidance** | `docs/*` (operator runbooks, deployment guides, ATTRIBUTION.md, …) + per-finding `SecurityFinding.remediation` (v0.10.0+) + per-gap `ControlGap.remediation_guidance` | Evidentia's guidance is split between human-readable docs and per-finding remediation text. |
| **Catalog: Lexicon** | no direct equivalent | Evidentia uses framework-specific terminology in-place; no separate lexicon registry. Worth considering if multi-framework crosswalks need shared term definitions. |
| **Log: Audit** | `evidentia_core.audit.events.EventAction` (80+ append-only enum values across `COLLECT_*` / `AUTH_*` / `SIGN_*` / `VERIFY_*` / `MANIFEST_*` / `AI_*` / `POAM_*` / `CONMON_*` / `EVIDENCE_*` / `RBAC_*` / `RETENTION_*` namespaces) + ECS 8.11 structured JSON output via `evidentia_core.audit.logger` | Evidentia emits ECS-shaped JSON audit lines. NIST SP 800-53 AU-2 alignment. 1:1 with Gemara's Audit log. |
| **Log: Enforcement** | `evidentia_core.poam` (POA&M state machine — 5 forward-only states per FedRAMP Template v3.0) + `evidentia_core.conmon` (continuous-monitoring cadences + the v0.9.3 daemon) | POA&M state transitions + CONMON daemon events are Evidentia's enforcement timeline. |
| **Log: Evaluation** | `evidentia_ai.eval.DFAHarness` (Determinism-Faithfulness Assurance Harness; v0.8.2+) + faithfulness scoring (Jaccard / sentence-transformers semantic / LLM atomic-claim extraction) | DFAH evaluation results are Gemara-Evaluation-log shaped. |
| **Document: Mapping** | `evidentia_core.models.common.ControlMapping` — OLIR-typed (NIST Open Specification 800-53 to ISO 27001 / CSF / CMMC / etc.) + 6 bundled crosswalks (118 mappings) + per-`SecurityFinding.control_mappings[]` provenance | OLIR relationship + justification on every mapping. 1:1 with Gemara Mapping documents. Evidentia's OLIR layer is more relationship-typed than what Gemara currently specifies. |
| **Document: Policy** | no direct equivalent | Evidentia is policy-*implementation*-side (assess against existing policies); it does not author policy text. Could surface via `RiskStatement` + remediation guidance but that's a stretch. |
| **Entity** | `evidentia_core.models.tprm.Vendor` (TPRM) + `evidentia_core.models.governance.AISystem` (AI inventory) + `SecurityFinding.resource_*` (cloud / GitHub / database resource refs) + `SystemContext` (org + system identity) | Evidentia entities are typed per domain (vendor / AI-system / cloud-resource) rather than unified. A Gemara-shape Entity emit is a v0.11+ candidate. |
| **Collection** | `evidentia_core.models.control.ControlInventory` (operator's controls + status) + `evidentia_core.models.gap.GapAnalysisReport` (assessment output) + `evidentia_core.models.evidence.EvidenceBundle` (curated evidence collections for OSCAL AR back-matter) + the WORM evidence store (v0.9.6+) | Evidentia has multiple Collection-shaped composites; the canonical one for compliance output is the `GapAnalysisReport`. |

## 4. Schema-language interop

Gemara schemas live in [CUE](https://cuelang.org/); Evidentia models
live in Pydantic v2. Both compile to equivalent JSON Schema. The
**`SecurityFinding`** model (Evidentia v0.10.0+) is already
JSON-Schema-validatable via `SecurityFinding.model_json_schema()`;
emitting equivalent CUE constraints alongside would let Gemara
adopters validate Evidentia output through their own CUE pipelines
without translation.

**Future direction (v0.11+ candidate)**:

1. Publish CUE constraints that mirror Evidentia's Pydantic models
   (Catalog → CUE Catalog; SecurityFinding → CUE Findings; etc.).
2. Add an `evidentia collect convert --format gemara` CLI verb (sibling
   of the v0.10.1 `--format ocsf` verb).
3. Map the Gemara Capability tier onto Evidentia's
   `implementation_status` enum as a first-class Capability registry.

None of these are scheduled — they depend on FINOS / OpenSSF
demand signal. See [`integration-survey.md`](integration-survey.md)
for the broader integration backlog.

## 5. Why this mapping matters

- **Auditor-readable cross-toolchain**: organizations adopting
  OpenSSF Security Baseline or FINOS CCC can read Evidentia output
  via the Gemara lens without learning Evidentia-specific
  vocabulary.
- **Positioning signal**: Evidentia is OSCAL-first (NIST). Gemara
  is OpenSSF-blessed (OSS-foundation-led). The mapping demonstrates
  that the two are complementary, not competing.
- **Future integration**: a future Gemara emit (v0.11+) would let
  Evidentia plug into the broader OpenSSF compliance ecosystem
  without re-shaping its core model.

## 6. Cross-references

- Evidentia surfaces named above are documented in
  [`api-stability.md`](api-stability.md) §1 (frozen models),
  §2 (EventAction enum), §5 (library entry points).
- The OSCAL surface that overlaps with Gemara is documented in
  [`ocsf-mapping.md`](ocsf-mapping.md) (the OCSF interchange, which
  is itself one of Gemara's source ecosystems).
- The integration-survey context in
  [`integration-survey.md`](integration-survey.md) ranks the
  Gemara mapping among the v0.10.x integration moves.
