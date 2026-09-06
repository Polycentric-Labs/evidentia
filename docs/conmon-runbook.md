# CONMON Cycle Calendar Operator Runbook

> Status: **shipped v0.9.0 P3** (read-only cycle-calendar library +
> CLI). Live-trigger daemon (`evidentia conmon watch`) reserved for
> v1.0.

Continuous Monitoring (CONMON) is the federal-compliance discipline
of recurring assessment + reporting cycles per the framework's
prescribed cadence. Evidentia ships a read-only library that knows
the canonical cadences and lets operators query "what's due next?"
+ "what's overdue?" without operating a daemon.

## Quick reference

| Verb | Use case |
|---|---|
| `evidentia conmon list` | Browse bundled + registered cadences |
| `evidentia conmon list --framework <fw>` | Filter to one framework |
| `evidentia conmon next <slug> --last-completed <date>` | Compute the next-due date |
| `evidentia conmon check --last-completed-file state.yaml` | Report due-soon + overdue cycles from tracked state |
| `evidentia conmon series <slug> --evidence-store <dir>` | Assert a cadence evidence series from evidence-store artifacts ([below](#cadence-evidence-series)) |
| `evidentia conmon ksi --status-file ksi.yaml --out sdr.json` | Emit a FedRAMP CR26 SDR with the KSI block ([runbook](fedramp-ksi.md)) |

## Conceptual model

A **ConmonCadence** is a unique combination of:

- **Framework** — `nist-800-53-rev5`, `fedramp-rev5-mod`, `cmmc-v2`,
  `dod-rmf`, `occ-2026-13`, etc.
- **Activity** — `continuous-monitoring`, `poam-update`,
  `security-assessment`, `model-risk-review`, etc.
- **Frequency** — `monthly` / `quarterly` / `annual` / `biennial` /
  `triennial`

Each cadence has a stable slug (`framework-activity` form,
kebab-case) used as the lookup key + audit-trail prop value. Slugs
are append-only across releases; semantic changes get a new slug.

## Bundled cadences

The bundled catalog ships 12 cadences as of v0.13 (run `evidentia conmon
list --json` for the current catalog): the v0.9.0 P3 baseline of 7, plus
5 sub-monthly and semiannual/annual additions that back the [cadence
evidence series](#cadence-evidence-series):

| Slug | Framework | Activity | Frequency |
|---|---|---|---|
| `nist-800-53-rev5-ca7` | nist-800-53-rev5 | continuous-monitoring | monthly |
| `fedramp-conmon-poam` | fedramp-rev5-mod | poam-update | monthly |
| `fedramp-conmon-scans` | fedramp-rev5-mod | vulnerability-scans | monthly |
| `fedramp-conmon-annual` | fedramp-rev5-mod | security-assessment | annual |
| `cmmc-l2-triennial` | cmmc-v2 | reassessment | triennial |
| `dod-rmf-annual` | dod-rmf | control-assessment | annual |
| `occ-2026-13-model-risk` | occ-2026-13 | model-risk-review | annual |
| `pci-dss-11-6-1-weekly` | pci-dss-v4 | change-and-tamper-detection | weekly |
| `nerc-cip-007-r2-patch-evaluation` | nerc-cip | security-patch-evaluation | custom (35 days) |
| `irs-pub-1345-weekly-asv-scan` | irs-pub-1345 | external-vulnerability-scan | weekly |
| `glba-314-4-d-semiannual-vulnerability-assessment` | glba-safeguards | vulnerability-assessment | semiannual |
| `glba-314-4-d-annual-penetration-test` | glba-safeguards | penetration-test | annual |

Each carries a citation to the regulatory or policy authority that
establishes it.

## Workflow 1 — Discover what's available

```
$ evidentia conmon list
                    CONMON cadences (7 total)
┌──────────────────────────────┬─────────────────────┬──────────...
│ Slug                         │ Framework           │ ...
...
```

Or filter to one framework:

```
$ evidentia conmon list --framework fedramp-rev5-mod
```

## Workflow 2 — Compute a single next-due

Given a known anchor (the last-completed cycle's date):

```
$ evidentia conmon next nist-800-53-rev5-ca7 --last-completed 2026-04-15
nist-800-53-rev5-ca7 (monthly)
  Framework:       nist-800-53-rev5
  Activity:        continuous-monitoring
  Last completed:  2026-04-15
  Next due:        2026-05-15
  Citation:        NIST SP 800-53 Rev 5 CA-7 (Continuous Monitoring)
```

Month arithmetic is calendar-aware: `2026-01-31 + 1 month →
2026-02-28` (clamps to last valid day; never produces invalid
dates).

## Workflow 3 — Operator state file

Maintain a YAML file with the last-completed date per cycle you
care about:

```yaml
# state.yaml
nist-800-53-rev5-ca7: 2026-04-01
fedramp-conmon-poam: 2026-04-15
fedramp-conmon-scans: 2026-04-15
fedramp-conmon-annual: 2025-09-30
dod-rmf-annual: 2025-11-15
```

Then run the check verb:

```
$ evidentia conmon check --last-completed-file state.yaml
OVERDUE cycles (2) as of 2026-05-08
...

Due within 14 day(s) (1) as of 2026-05-08
...
```

`--window-days N` adjusts the due-soon lookahead (default 14).
`--today YYYY-MM-DD` overrides the system clock for deterministic
CI assertions.

## Workflow 4 — CI integration

The `--json` flag emits machine-readable output for ingestion by a
dashboard, ticket-system bridge, or paging integration:

```
$ evidentia conmon check \
    --last-completed-file state.yaml \
    --today 2026-05-08 \
    --json > conmon-state.json
```

```json
{
  "today": "2026-05-08",
  "window_days": 14,
  "overdue": [
    {
      "slug": "nist-800-53-rev5-ca7",
      "framework": "nist-800-53-rev5",
      "activity": "continuous-monitoring",
      "frequency": "monthly",
      "last_completed": "2026-04-01",
      "next_due": "2026-05-01",
      "days_until_due": "-7"
    }
  ],
  "due_soon": [...],
  "unknown_slugs": []
}
```

`unknown_slugs[]` lists entries in your state file whose cadence
slug isn't in the registered set — useful for catching typos +
deprecated slugs without errors (the check verb keeps running).

## Workflow 5 — Operator-extensible cadences

Organizations with custom internal cycles can register cadences at
runtime via the Python API:

```python
from evidentia_core.conmon import (
    CadenceFrequency,
    ConmonCadence,
    register_cadence,
)

custom = ConmonCadence(
    slug="acme-internal-policy-review",
    framework="acme-internal",
    activity="policy-review",
    frequency=CadenceFrequency.QUARTERLY,
    description="Acme Corp internal information-security policy review.",
)
register_cadence(custom)
```

Registration is process-local — a new `evidentia` invocation starts
with only the bundled set. Operators who need durable extensions
ship a plugin entry point in the v0.8.0 P0.4 plugin-contract surface
(deferred extensible-cadence wiring to v0.9.1 if walk-through
identifies demand).

## Audit trail

The check verb fires audit events for each due-soon or overdue
cycle it surfaces:

| Action | When emitted |
|---|---|
| `evidentia.conmon.cycle_due` | A cycle is within the configured due-soon window |
| `evidentia.conmon.cycle_overdue` | A cycle's next-due date is in the past |

See [`docs/log-schema.md`](log-schema.md) §`evidentia.conmon.*` for
the full field shape. Both events carry `cadence_slug`,
`framework`, `activity`, `last_completed`, `next_due`, and
`days_until_due`.

**Current cycles (next_due > today + window_days) do NOT emit
events.** The absence of an event is itself an auditor signal —
no attention needed for that cycle this query.

## Relationship to POA&M

The POA&M tracking (v0.9.0 P2) handles **per-gap remediation
schedules** — milestones with target dates per individual control
gap. The CONMON cycle calendar handles **organization-wide
assessment + reporting cadences** — monthly POA&M-update
submissions, annual SARs, triennial CMMC reassessments.

The two surfaces compose naturally: an operator monitors POA&M
calendar (per-milestone attention) AND CONMON calendar (per-cycle
attention), often in the same dashboard view via the shared
attention-state vocabulary (`overdue` / `due_soon` / `current`).

## Cadence evidence series

The workflows above read an operator-maintained state file: one
last-completed date per cadence, set by hand or by `conmon
mark-completed`. v0.13 (V13-01) adds a second way to ask "is this
cadence on track". `evidentia conmon series` reads the append-only
evidence store directly and asserts a dated series against a window,
with no operator-recorded date involved.

**How artifacts link to a cadence.** A saved `EvidenceArtifact` declares
the cadence it satisfies through `metadata.cadence_slug` (the same
convention `KsiPersistenceCycle.cadence_slug` uses for KSI evidence).
`conmon series <slug>` reads every artifact whose `metadata.cadence_slug`
equals `slug` and whose `collected_at` falls inside the window
(`evidentia_core.evidence_store.iter_artifacts`), then asserts the
series (`evidentia_core.conmon.series.assert_series`).

**Verdict vocabulary.** The assertion reports exactly one of:

| Verdict | Meaning |
|---|---|
| `continuous` | Every interval in the window holds an observation, within tolerance. |
| `gapped` | At least one spacing between observations exceeds the cadence's interval plus tolerance. |
| `insufficient` | Fewer than two observations in the window, so there is no spacing to assess. |
| `unknown` | The slug is not a registered cadence. |

A gap-free dated series is evidence of cadence and nothing more: the
counts reported are what the evidence store holds, not what was
performed. Completeness of the record set is a scoping judgement the
operator makes; the tool never asserts it, and the rendered
description repeats this every time.

**Example.** A weekly PCI DSS 11.6.1 series with one missed week:

```
$ evidentia conmon series pci-dss-11-6-1-weekly \
    --evidence-store /var/evidentia/evidence \
    --since 2026-06-01 --until 2026-07-20
pci-dss-11-6-1-weekly  window 2026-06-01 .. 2026-07-20  verdict: gapped
                                       Observations (5)
┌───────────────────────────┬──────────────────────────────────────┬─────────┬───────────────┐
│ Collected at              │ Lineage ID                           │ Version │ Source system │
├───────────────────────────┼──────────────────────────────────────┼─────────┼───────────────┤
│ 2026-06-01T09:00:00+00:00 │ ef2450dd-019e-474c-860a-090266d38d95 │       1 │ nessus        │
│ ...                       │ ...                                   │       1 │ nessus        │
└───────────────────────────┴──────────────────────────────────────┴─────────┴───────────────┘
                                          Gaps (2)
┌───────────────────────────┬──────────────────────────────────┬──────┬─────────┬──────────┐
│ After                     │ Before                           │ Days │ Allowed │ Boundary │
├───────────────────────────┼──────────────────────────────────┼──────┼─────────┼──────────┤
│ 2026-06-15T09:00:00+00:00 │ 2026-06-29T09:00:00+00:00        │   14 │       9 │ no       │
│ 2026-07-06T09:00:00+00:00 │ 2026-07-20T23:59:59.999999+00:00 │   14 │       9 │ yes      │
└───────────────────────────┴──────────────────────────────────┴──────┴─────────┴──────────┘
Cadence evidence for pci-dss-11-6-1-weekly: 5 observations between 2026-06-01 and 2026-07-20.
2 gaps; the widest is 14 days after 2026-06-15 against an allowed 9. Verdict: gapped. A gap-free
dated series is evidence of cadence and nothing more; the counts are what the evidence store
holds, not what was performed.
```

`--json` emits the same series alongside its rendered description:

```json
{
  "series": {
    "slug": "pci-dss-11-6-1-weekly",
    "frequency": "weekly",
    "interval_days": 7,
    "window_start": "2026-06-01T00:00:00Z",
    "window_end": "2026-07-20T23:59:59.999999Z",
    "tolerance_days": 2,
    "observations": [
      {"collected_at": "2026-06-01T09:00:00Z", "lineage_id": "ef2450dd-...", "version": 1, "source_system": "nessus"}
    ],
    "gaps": [
      {"after": "2026-06-15T09:00:00Z", "before": "2026-06-29T09:00:00Z", "days": 14, "allowed_days": 9, "boundary": false}
    ],
    "verdict": "gapped"
  },
  "description": "Cadence evidence for pci-dss-11-6-1-weekly: 5 observations between 2026-06-01 and 2026-07-20. 2 gaps; the widest is 14 days after 2026-06-15 against an allowed 9. Verdict: gapped. A gap-free dated series is evidence of cadence and nothing more; the counts are what the evidence store holds, not what was performed."
}
```

`--evidence-store` defaults to `EVIDENTIA_EVIDENCE_STORE_DIR`, else the
platform user-data directory. `--since`/`--until` default to a
`--lookback-days`-wide window ending today (default 365 days, the
twelve months HITECH §13412 asks for); when only one bound is given,
the other is filled from that same default window. An unknown cadence
slug or a window with `--until` before `--since` both exit 2.
`--emit-findings <path>` writes a JSON array holding the
`SecurityFinding` a `gapped` or `insufficient` verdict produces (an
empty array for `continuous`), ready for the same exporters (OCSF,
SARIF, gap-report embedding) every other Evidentia finding uses.

REST parity: `POST /api/conmon/series` takes the same slug/window/
tolerance fields in its JSON body and returns
`{"series": ..., "description": ...}`; the server resolves its own
evidence store from `EVIDENTIA_EVIDENCE_STORE_DIR` (the request never
carries a filesystem path). MCP parity: the `conmon_series` tool
returns the identical shape.

## Future work

The CONMON live-trigger daemon (`evidentia conmon watch`)
is reserved for v1.0. It will run continuously, monitor the state
file for updates, and emit due/overdue events without operator
polling. v0.9.0 ships the read-only library + polling CLI only.
