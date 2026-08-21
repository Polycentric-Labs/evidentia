# FedRAMP CR26 KSI Emission (`evidentia conmon ksi`)

> Status: **v0.11 Wave 2; `fedRampRequirements` block added in v0.12**.
> Emits a FedRAMP CR26 **Security Decision Record (SDR)** as a
> schema-validated JSON document — the `keySecurityIndicators` block
> (v0.11) and the `fedRampRequirements` block (v0.12) — as the third
> `conmon` output mode alongside the rich tables and `--json`.

Under the FedRAMP Consolidated Rules for 2026 (CR26), the Security
Decision Record replaces the traditional System Security Plan, and
providers MUST supply it in both human-readable and JSON forms
(rule `SDR-CSO-FRR`), including per-KSI summaries of measures,
persistence cycles, verification, and validation (`SDR-CSX-KSI`) and
version/date/source metadata (`SDR-CSO-MTD`). This is in force for 20x
certifications since 2026-07-04; a 2026-07-14 rules update extends the
KSI obligation to Rev 5-path Class A certifications (`FRC-CLA-MFR`).
FedRAMP recommends applying ALL Key Security Indicators across the
Minimum Assessment Scope (`FRC-CSX-MAS`, SHOULD).

Evidentia assembles, validates, and reports — the compliance statements
are the operator's own. It never invents prose.

> **v0.12 note on rule-completeness.** `SDR-CSO-FRR` is a MUST: the SDR
> "MUST include at least" an explanation, verification, validation, and
> related statements *for each applicable FedRAMP rule*. Through v0.11.x
> the emitter wrote `fedRampRequirements: []`, which satisfies the
> *schema* (the array is required, its contents are not) but not the
> *rule*. v0.12 adds the `requirements` block below so the SDR can carry
> them, with IDs checked against a new `fedramp-frr-2026` catalog and
> coverage reported. Older status files still load and emit `[]`; the
> coverage line is what tells you the document is not yet complete.

## Quick start

```bash
evidentia conmon ksi \
  --status-file ksi-status.yaml \
  --state-file conmon-state.yaml \
  --out sdr.json
```

Output: a Security Decision Record JSON document, validated offline
against the vendored
`fedramp-security-decision-record-schema-2026-06-24.json` before it is
written (invalid output is a hard failure, never a file), plus two
coverage summaries on the console: KSI (against `fedramp-ksi-2026`,
`FRC-CSX-MAS` SHOULD) and FRR (against `fedramp-frr-2026`,
`SDR-CSO-FRR` MUST).

## The status file

`--status-file` is operator-authored YAML
(`evidentia_core.models.fedramp_ksi.KsiStatusDocument`):

```yaml
certification_package_overview_uri: "https://provider.example/fedramp/cpo.json"
document_version: "1.0.0"          # SDR-CSO-MTD
source: "GRC team"                 # SDR-CSO-MTD
indicators:
  KSI-CED-RAT:
    status: Implemented            # optional; Implemented / Partially Implemented / Not Implemented
    implementation:                # >= 1 required; Markdown allowed
      - "Quarterly all-hands security training; role-specific tracks for engineering."
    validation:
      - "Completion dashboards reviewed monthly."
    assessment:
      - "Independent assessor sampled Q2 completion records."
    tests:
      - "test-training-coverage"
    evidence:
      - evidence_type: Report      # Log / Report / Screenshot / Configuration / Policy / Procedure / Audit Record
        description: "Q2 training completion report"
        location: "https://provider.example/evidence/q2-training.pdf"
        last_updated: 2026-07-01
    persistence_cycles:            # SDR-CSX-KSI persistence-cycle statements
      - cadence_slug: nist-800-53-rev5-ca7
requirements:                      # v0.12 — SDR-CSO-FRR (MUST); optional key, but an SDR
  SDR-CSO-FRR:                     #   without it is schema-valid and rule-incomplete
    status: Implemented            # optional; same vocabulary as KSI status
    implementation:                # >= 1 required; how the rule is followed, OR the
      - "SDR emitted via `evidentia conmon ksi`; human-readable rendering via the console."
    validation:                    #   reason + customer risk for not following it
      - "Schema round-trip on every emit."
    assessment:
      - "3PAO reviewed the emit pipeline 2026-08."
```

- **Indicator IDs** are checked against the bundled `fedramp-ksi-2026`
  catalog (10 families / 46 indicators, generated verbatim from
  FedRAMP's consolidated-rules dataset). Unknown IDs are hard errors
  (exit 2). Indicators you have not addressed yet are reported as
  coverage, not errors.
- **Requirement IDs** (`requirements:` keys) are checked against the
  bundled `fedramp-frr-2026` catalog: the 180 CR26 rules whose upstream
  `affects` names Providers, across 15 families, generated verbatim from
  the same consolidated-rules dataset. Rules addressed to FedRAMP itself,
  assessors, or agencies are deliberately excluded — an SDR is the
  provider's record. Each catalog entry carries the rule's force (MUST /
  SHOULD / MAY) and applicability (all / 20x / rev5) in its guidance, so
  `evidentia catalog show fedramp-frr-2026` is the prioritised to-do list.
  Unknown IDs are hard errors (exit 2); unaddressed rules are reported
  as coverage.
- **`persistence_cycles`** references the same CONMON cadence calendar
  as the rest of `evidentia conmon` (see the
  [CONMON runbook](conmon-runbook.md)). With `--state-file` (the same
  YAML `conmon check` reads), the rendered cycle statements include
  last-completed and next-due dates.
- **`--last-updated`** pins the SDR metadata timestamp for
  deterministic snapshots; it defaults to now (UTC).

## Where the schemas and catalog come from (provenance)

| Artifact | Source | Pin |
|---|---|---|
| SDR + common-definitions schemas | [`FedRAMP/schemas`](https://github.com/FedRAMP/schemas) (CR26, draft) | vendored under `evidentia_core/fedramp/schemas/` |
| `fedramp-ksi-2026` catalog + KSI→800-53 crosswalk | [`FedRAMP/rules`](https://github.com/FedRAMP/rules) `fedramp-consolidated-rules.json` | generated by `scripts/catalogs/gen_fedramp_ksi.py` |
| `fedramp-frr-2026` catalog (provider-facing rules) | same dataset, `FRR` section | generated by `scripts/catalogs/gen_fedramp_frr.py` (reuses the KSI generator's fetch + sha256 check) |

Exact commits, blob SHAs, and sha256 hashes live in
`evidentia_core/fedramp/schemas/UPSTREAM.json`. Both vendored schemas
are byte-identical to upstream (verifiable by `git hash-object` against
the recorded `blob_sha`): the cross-document `$ref` fragment fix that
Evidentia carried as a local delta from 2026-07-18 was merged upstream
on 2026-08-11 (FedRAMP/schemas issue #11 → PR #15) and the v0.12
re-vendor retired the delta. Validation is fully offline — air-gapped
installs validate identically.

Both upstream repos are **2026 Public Preview drafts** that change
frequently. The weekly `fedramp-schema-watch` sentinel
(Wednesdays 09:17 UTC) compares live upstream against the pins: minor
drift opens/updates a tracking issue; a KSI content change, a MAJOR
`$schemaVersion` bump, or a new dated ruleset (CR27) also turns the
sentinel run red until the pins are deliberately re-verified.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Document written, schema-valid |
| 1 | Bad `--last-updated`, or (defensive) emitted document failed schema validation |
| 2 | Invalid status file, unknown KSI ID, or unknown cadence slug |

## Not OSCAL — deliberately

Nothing in the active CR26 stack pins an OSCAL version; KSI submission
is plain JSON per the CR26 schemas. Evidentia's OSCAL surfaces (POA&M,
assessment results, traceability, catalogs) are unaffected and remain
on OSCAL 1.2.1 per the v0.11 Wave 1 verdict
([plan](releases/plans/v0.11-plan.md)).
