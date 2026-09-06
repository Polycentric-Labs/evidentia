# Design: the cadence assertion layer (V13-01) and vulnerability-scan ingest (V13-05)

Status: DRAFT for design review, 2026-09-06. Scope items V13-01 and V13-05 of
[the v0.13 plan](../releases/plans/v0.13-plan.md). Ratified constraints that bind
this design: extension-first (answer 10: fold the layer into existing verbs, at
most one new leaf), 100 percent console parity at the tag (answer 11), a gap-free
dated series is evidence of cadence and nothing more, and completeness of a record
set is a scoping judgement that is never asserted.

## 1. What exists today, and the four gaps

The facts below were read from the tree on 2026-09-06.

- The evidence store (`evidentia_core/evidence_store.py`) is one directory per
  lineage with `v<N>.json` per version, append-only (`EvidenceWORMViolation` on
  any rewrite), no index, and no time-range or per-source query. `EvidenceArtifact`
  carries `collected_at`, `source_system`, `evidence_type`, `expires_at`, `tags`
  and `metadata`; `is_stale` is the only freshness notion and it is operator-set.
- Conmon (`evidentia_core/conmon/calendar.py`, `daemon.py`) knows seven bundled
  cadences, a month-granular `CadenceFrequency` (monthly to triennial), and a
  state file that holds exactly one date per slug: the last completion. There is
  no history and no series.
- Collectors emit `SecurityFinding` records whose only timestamps are
  `collection_context.collected_at`, `first_observed`, `last_observed` and
  `resolved_at`. There is no scan-completion timestamp and no XML parsing anywhere
  in the collectors package.
- The parity gate (`scripts/check_parity.py`, baseline `cli_only: 0`) requires
  every new CLI leaf to land with its API operation, its console wiring and a
  manifest row in the same change.

The four gaps the layer fills: sub-monthly cadences (PCI DSS 11.6.1 every seven
days, NERC CIP-007 R2 every thirty-five calendar days, IRS Pub 1345 weekly),
a dated series instead of a last date, a way to derive that series from evidence
rather than from an operator marking a cycle complete, and a vocabulary for saying
"the series has a gap" without saying "the control failed".

## 2. Design

### 2.1 Cadence vocabulary: day granularity, additive

`CadenceFrequency` gains `WEEKLY` (7 days), `BIWEEKLY` (14 days), `SEMIANNUAL`
(6 months) and `CUSTOM`. `ConmonCadence` gains `interval_days: int | None`, required
for a custom cadence (35 days for CIP-007 R2) and refused otherwise, so a cadence
has one source of truth. `next_due()` adds a day interval directly for weekly,
biweekly and custom cadences and keeps the calendar-aware month arithmetic for the
rest; `derive_status()` is unchanged. Both changes are additive on frozen imports
(`BUNDLED_CADENCES`, `derive_status`) and take a NORMATIVE row in
`docs/api-stability.md`. Bundled cadences added: `pci-dss-11-6-1-weekly`,
`nerc-cip-007-r2-patch-evaluation`, `irs-pub-1345-weekly-asv-scan`,
`glba-314-4-d-semiannual-vulnerability-assessment` and
`glba-314-4-d-annual-penetration-test`. Built in batch 4 as described.

### 2.2 Linking evidence to a cadence

An artifact declares the cadence it satisfies through `metadata["cadence_slug"]`.
This mirrors the one place cadence and a control-like object already meet,
`KsiPersistenceCycle.cadence_slug`, and needs no model change (`EvidenceArtifact`
is `extra="forbid"`, so a new top-level field would be a frozen-model change for
no gain). A helper `evidence_store.iter_artifacts(store_dir, *, since=None,
until=None, source_system=None, metadata=None)` walks `list_lineages()` and reads
versions, filtering on `collected_at`, the source system and equality on every
metadata key given (the series passes `{"cadence_slug": slug}`). It is a linear scan;
for v0.13 store sizes that is acceptable, and an index sidecar is a documented
follow-up rather than part of this item.

### 2.3 The series and its verdict

A new model `CadenceSeries` (`evidentia_core/conmon/series.py`):

| Field | Meaning |
|---|---|
| `slug`, `frequency`, `interval_days` | the cadence being asserted |
| `window_start`, `window_end` | the look-back window (defaults: the cadence's citation, for example twelve months for HITECH 13412) |
| `observations` | `(collected_at, lineage_id, version)` tuples, oldest first |
| `gaps` | `(after, before, days, allowed_days, boundary)` where a spacing exceeds the interval plus tolerance; tolerance defaults to two days for day-based cadences and five for month-based ones (month-end drift alone moves a monthly spacing by up to three days); both window edges are assessed and flagged `boundary` |
| `verdict` | `continuous`, `gapped`, `insufficient` (fewer than two observations), `unknown` (no cadence match) |

`assert_series(slug, artifacts, *, window_start, window_end, tolerance_days=None)` is a pure function
with no I/O, so it is unit-testable with synthetic timestamps. Two wording rules
are enforced by the model itself: the rendered verdict always reads "cadence
evidence" (`CadenceSeries.describe()` never contains the words compliant or
compliance), and counts are reported as observed, never as total, because the
store cannot know what was never collected. `CollectionManifest.is_complete`
and `empty_categories` are consulted when the observations come from a collector
run, so an aborted run is not read as a satisfied interval.

### 2.4 Surface: one new leaf, everything else an extension

Following answer 10, the leaf is the one place the design forces a new verb,
because the semantics differ from `conmon check` (state-file dates marked by an
operator) and folding both into `check` would overload it:

- `evidentia conmon series <slug> --evidence-store <dir> [--since] [--until]
  [--tolerance-days] [--json] [--emit-findings <path>]`: computes and renders the
  series. `--emit-findings` writes `SecurityFinding` records (section 2.5).
- `evidentia conmon check` and `conmon health` gain `--evidence-store`: when set,
  a slug's last observation from the store stands in for a missing state-file
  date, and the tables gain a "series" column with the verdict.
- API: `POST /api/conmon/series` (the leaf) and an optional `evidence_store`
  field on the existing check and health request bodies.
- Console: the existing `/conmon` screen gains a "Cadence evidence" panel; no new
  route. Parity manifest: one new `full` row, existing rows unchanged.
- MCP: `conmon_series` read-only tool, appended to the frozen tool table.

### 2.5 Emitting the result

A `gapped` or `insufficient` verdict can be emitted as a `SecurityFinding` with
`source_system="evidentia-cadence"`, a deterministic id from
`(slug, window_start, window_end)`, `compliance_status=FAIL` for gapped and
`UNKNOWN` for insufficient, and `control_mappings` taken from the cadence's
citation. The title reads "Cadence gap: <N> days between observations against a
<M>-day cadence"; the description repeats the evidence-not-compliance rule. From
there the existing exporters apply unchanged (OCSF compliance finding, SARIF,
gap report embedding). When persisted, the assertion is saved as a new evidence
lineage whose `metadata["source_lineages"]` lists the observations, never as a
new version of the evidence it evaluated.

### 2.6 V13-05: scan ingest as the first consumer

Two file-ingest collectors first, both free and self-hostable, both without
network access in tests:

- `evidentia collect nessus --file scan.nessus [--cadence-slug ...]`: parses the
  Nessus v2 XML export (Nessus Essentials, 16 IPs). One `SecurityFinding` per
  `(host, pluginID)`, id derived from `f"nessus:{scan_name}:{host}:{pluginID}"`,
  severity from the plugin `severity` attribute, `collection_context.collected_at`
  set from `HOST_END` (the scan completion time, which is the cadence timestamp),
  `raw_data` limited to plugin output trimmed to a configurable size.
- `evidentia collect greenbone --file report.xml`: parses the GMP report XML from
  Greenbone Community Edition with the same shape; id from
  `f"greenbone:{report_id}:{host}:{nvt_oid}"`.

Each ingest also writes one `EvidenceArtifact` (`evidence_type` scan report,
`source_system` nessus or greenbone, `metadata["cadence_slug"]` from the flag or
the bundled default `fedramp-conmon-scans`) so the series has something to read.
XML is parsed with `defusedxml` (a new optional extra `scan`) to close XXE and
entity-expansion attacks from untrusted exports; file size is capped like the
OCSF ingest (50 MB). `BLIND_SPOTS` declares what a scan export cannot show:
unauthenticated scans, hosts outside the target list, plugin-feed staleness.

Both leaves register the standard way (collector package, `collect.py` command,
`routers/collectors.py` operation, `/collect` console wiring, parity row). Per
the `check_doc_counts.py` rule, file-import collectors do not raise the README
collector count; API pollers (Tenable.io, Qualys, Rapid7, AWS Inspector) do, and
they follow once the ingest shape is stable.

## 3. Sequencing

1. Batch 4 (V13-01 core): frequency extension and `interval_days`,
   (the `--evidence-store` mode on `conmon check` and `conmon health` landed in
   batch 5 as `use_evidence_store` on the API and a Series column on the CLI),
   `iter_artifacts`, `CadenceSeries` and `assert_series`, the `conmon series`
   leaf with API, console panel, MCP tool and parity row, docs
   (`conmon-runbook.md` section, `api-stability.md` rows). Exit: unit tests on
   synthetic series covering every verdict and the tolerance edge, DAST stateless
   run green on the new operation.
2. Batch 5 (V13-05 first half): Nessus ingest with fixtures under
   `tests/fixtures/scans/`, evidence artifact write, series end-to-end test.
3. Batch 6 (V13-05 second half): Greenbone ingest, `docs/vuln-scan-collectors.md`,
   capability-matrix delta.
4. Later: API pollers, the evidence-store index sidecar, and a persisted
   completion history for conmon if the state file's single date proves limiting.

## 4. Open questions for the review

1. New leaf `conmon series` (this draft) or an `--evidence-store` mode on
   `conmon check` only, with the series rendered as extra columns?
2. `metadata["cadence_slug"]` (this draft) or a `tags` convention such as
   `cadence:<slug>`? Metadata is typed and greppable; tags are already indexed by
   the console.
3. Day-granular enum members plus `interval_days` (this draft) or `interval_days`
   alone with the enum left as is?
4. Should a `gapped` verdict emit `compliance_status=FAIL` (this draft) or always
   `UNKNOWN`, leaving the judgement to the operator? The draft argues that a
   cadence control has a clear pass condition and the wording rule already
   prevents the freshness-equals-compliance reading.
5. Is `defusedxml` acceptable as a new dependency, or should the parsers use the
   standard library with the known entity limits?

## 5. Related documents

[conmon-runbook.md](../conmon-runbook.md), [evidence-integrity.md](../evidence-integrity.md),
[collector-idempotency-audit.md](../collector-idempotency-audit.md),
[ocsf-mapping.md](../ocsf-mapping.md), [api-stability.md](../api-stability.md),
[cli-gui-parity.yaml](../cli-gui-parity.yaml),
[designs/sarif-ingestion-collector-design.md](sarif-ingestion-collector-design.md).
