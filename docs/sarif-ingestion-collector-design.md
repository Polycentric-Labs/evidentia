# Design: SARIF-ingestion collector (`evidentia collect sarif`)

> Status: DESIGN (pre-implementation). Target: v0.11. Companion to
> [integration-survey.md](integration-survey.md) §3 #5 + §9 and
> [ROADMAP.md](ROADMAP.md) v0.11. This spec feeds an implementation plan; it is
> not a release commitment.

## 1. Goal

Add a collector that ingests **SARIF 2.1.0** static-analysis output from any emitter
(Trivy, Checkov, Semgrep, CodeQL, and the Clear Capabilities `agentic-security`
scanner) and converts each result into an Evidentia `SecurityFinding`, mirroring the
existing v0.10.1 OCSF ingestion collector. This closes the consume-side counterpart to
the v0.10.0 SARIF *emit* and lets external scanner findings flow into Evidentia's
evidence store → control gaps → POA&M.

## 2. Non-goals

- **No authoritative control attribution invented by the collector.** A finding with no
  derivable control signal lands control-agnostic (empty `control_mappings`), never
  fabricated. (Rationale §4.)
- No code dependency on any ingested scanner (data-layer interop only).
- No hand-authored CWE→800-53 crosswalk (none authoritative exists; §4.4).

## 3. Architecture (mirrors `evidentia_collectors.ocsf`)

```
packages/evidentia-collectors/src/evidentia_collectors/sarif/
  __init__.py     # exports: SARIFIngestError, collect_sarif_file, collect_sarif_url
  collector.py    # parse SARIF log -> iterate runs[].results[] -> list[SecurityFinding]
packages/evidentia-core/src/evidentia_core/sarif/
  finding_mapping.py   # finding_from_sarif(result, *, run, driver, source_system)
```

- **CLI:** new `@app.command("sarif")` in `packages/evidentia/src/evidentia/cli/collect.py`,
  same shape as `collect ocsf`: `--input <file|https-url>`, `--output`, `--url-timeout`,
  `--url-max-bytes`, `--block-private-ips` (default on). **Reuse the OCSF collector's
  HTTPS/SSRF URL guard verbatim** — no new network-egress surface.
- **Parse approach:** hand-rolled minimal SARIF reader (the result/run/driver/taxa subset
  we consume), not a new dependency. The existing `gap_analyzer/sarif.py` is emit-only with
  no reusable parser. Optional `[sarif]` extra reserved only if a schema-validation lib is
  later wanted.
- **Errors:** `SARIFIngestError(RuntimeError)` wrapping JSON-parse / unsupported-version /
  per-result conversion failures, mirroring `OCSFIngestError`.

## 4. Control-mapping strategy (the core decision)

Ingest is **control-agnostic by default**; control signal is emitted as **attestation-gated
candidates** from up to three sources, in descending fidelity. **All three reuse the existing
`ControlMapping` + `OLIRRelationship` models** (additive change only).

### 4.1 Source 1 — SARIF-native taxa/relationships (first cut)

When a producer emits `run.taxonomies[]` / `result.taxa[]` /
`reportingDescriptor.relationships[]`, translate the SARIF relationship `kinds`
(`superset` / `subset` / `equal` / `relevant`) to `OLIRRelationship`
(`SUPERSET_OF` / `SUBSET_OF` / `EQUAL_TO` / `RELATED_TO`) — the vocabularies are isomorphic.
The producer asserted the relationship; we preserve it as a `ControlMapping` with
`status: candidate` + provenance. Ready-made CWE / OWASP-ASVS / WASC taxonomy files exist
upstream (`sarif-standard/taxonomies`); Semgrep/CodeQL carry `metadata.cwe`/`owasp`.

### 4.2 Source 2 — operator/connector YAML map (fast-follow)

Operator/connector supplies a mapping keyed by **(tool, tool-version, ruleId/GUID,
ruleset-version)** — never flat `ruleId`. Each produced `ControlMapping` carries
provenance + `status`. Bundles are schema-validated and version-pinned. Framework-neutral
(`ControlMapping.framework` is already a free `str`). This is the explicit, audit-defensible
path (matching how Lula and the GRC Engineering Club attribute controls).

### 4.3 Source 3 — derived auto-map (future, lowest priority)

Only when neither taxa nor an operator map exists: derive from the best indirect public
source (OWASP OpenCRE, CC0) as **low-confidence `status: candidate`, `RELATED_TO`**, requiring
SME attestation before the mapping is treated as evidence. Never runtime auto-trusted.

### 4.4 Why this shape (evidence)

- **No authoritative CWE/OWASP→800-53 crosswalk exists.** NIST and MITRE publish none; only
  partial/indirect (OpenCRE, control-level-only) or stale/deprecated community CSVs. Verified
  to June 2026.
- **No surveyed tool auto-maps generic third-party SARIF to 800-53 from SARIF content alone.**
  Built-in auto-mappers map only their own check IDs; generic SARIF consumers (DefectDojo,
  grype CLI) stay control-agnostic; control attribution that exists is operator/connector-declared.
- **Audit norm:** automated control mappings are "informative until attested" — a starting
  point needing human/SME attestation. OSCAL Assessment Results + FedRAMP 20x explicitly
  contemplate automated tools authoring findings paired with human attestation, so the
  `candidate|attested` model is forward-compatible (a positioning win).
- **A finding alone attributes no controls today:** `GapAnalyzer` compares an operator
  `ControlInventory` against catalogs and does not consume `SecurityFinding`s. So the mapping
  path (Source 1/2) ships *with* ingest to make the feature compliance-useful — it is not an
  optional later phase.

## 5. Field mapping (SARIF result → `SecurityFinding`)

| SARIF | → `SecurityFinding` |
|---|---|
| `result.level` (error/warning/note/none) + `properties.security-severity` (CVSS-like) + `rank` | `severity` (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL); `security-severity` bands preferred when present |
| `rule.name` / `ruleId` | `title` |
| `result.message.text` | `description` |
| `rule.help` / `result.fixes[]` | `remediation` |
| `driver.name` (+`version`) + `ruleId` | `source_system` + `source_finding_id` |
| `result.fingerprints` / `partialFingerprints` / `guid` / `correlationGuid` | feed `source_finding_id` → existing v0.10.5 **deterministic UUID5** id (idempotent re-ingest) |
| `result.codeFlows[]` (taint traces), full raw result | `raw_data` (provenance preserved, queryable later) |
| `properties` KEV / EPSS | `raw_data`; may inform `severity`/`compliance_status` (decision deferred to plan) |
| `taxa` / `rule.relationships.kinds` | `control_mappings[]` via `OLIRRelationship` (Source 1; `status: candidate`) |
| (default, no signal) | `control_mappings = []`, `compliance_status = UNKNOWN` |

## 6. Model change (additive; frozen-surface care)

`ControlMapping` (`evidentia_core.models.common`) today carries
`{framework, control_id, control_title, relationship (OLIRRelationship), justification}`.
Add **optional** fields: `status: Literal["candidate","attested"] = "candidate"`,
`attested_by: str | None`, `attested_at: datetime | None`, and a source provenance triple
`source_tool / source_tool_version / source_rule_id` (all optional). This mirrors the v0.10.6
crosswalk `verification` / `provenance` precedent. Because `ControlMapping` is embedded in
`SecurityFinding.control_mappings` (a frozen-models / `api-stability.md` surface that
round-trips through OCSF + OSCAL back-matter), the change must be **additive with defaults**,
documented in `api-stability.md`'s revision history, and covered by a round-trip test.

## 7. OSCAL surface

Candidate/attested `ControlMapping`s surface in OSCAL output with a `status` property +
provenance. NIST's purpose-built **OSCAL Control Mapping Model** (OSCAL 1.1.3) is the natural
home for a Source-2 crosswalk *bundle*; Assessment-Results observations remain the home for
*finding instances*. (Bundle emit is out of scope for the first cut; noted for the plan.)

## 8. Testing strategy

- Unit: `tests/unit/test_collectors/test_sarif_collector.py` (+ `finding_from_sarif` unit
  tests in core) with fixtures in `tests/fixtures/sarif/` — include a **real agentic-security
  SARIF report** (rich: codeFlows + KEV/EPSS + taxa) and a **Trivy report** (bare).
- Integration: `tests/integration/test_cli/test_collect_sarif_cli.py` (Typer `CliRunner`),
  mirroring `test_collect_ocsf_cli.py`.
- Idempotency test: ingest the same SARIF twice → identical finding IDs (deterministic UUID5).
- `OLIRRelationship` round-trip test for `kinds`→OLIR translation.
- Add `EventAction.COLLECT_SARIF_EMITTED`.

## 9. Scope

- **First cut (v0.11):** collector + CLI verb + control-agnostic ingest + Source-1 (SARIF-native
  taxa→OLIR candidates) + provenance preservation (codeFlows/KEV/EPSS in `raw_data`) +
  idempotency + the additive `ControlMapping` fields + tests.
- **Fast-follow:** Source-2 operator/connector YAML map + bundle governance.
- **Future:** Source-3 derived auto-map (OpenCRE) + OSCAL Control Mapping Model bundle emit.

## 10. Open questions (resolve in the implementation plan)

1. Do KEV/EPSS / `security-severity` drive `severity`/`compliance_status`, or stay in
   `raw_data` only for the first cut?
2. Do `codeFlows` warrant a typed model field, or is `raw_data` sufficient initially?
3. Exact `source_finding_id` composition when SARIF carries no fingerprints/guid (fallback to
   `tool + ruleId + primary location uri + region` hash?).

## 11. References

- [SARIF 2.1.0 specification (OASIS)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html)
- [SARIF taxonomies & relationships (microsoft/sarif-tutorials)](https://github.com/microsoft/sarif-tutorials/blob/main/docs/3-Beyond-basics.md)
- [sarif-standard/taxonomies (CWE / OWASP ASVS / WASC)](https://github.com/sarif-standard/taxonomies)
- [NIST OLIR program](https://csrc.nist.gov/projects/olir)
- [OWASP OpenCRE](https://www.opencre.org/)
- [OSCAL Control Mapping Model](https://pages.nist.gov/OSCAL/learn/concepts/layer/control/mapping/)
