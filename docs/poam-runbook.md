# POA&M Operator Runbook

> Status: **shipped v0.9.0 P2** (Plan-of-Action-and-Milestones data
> layer + CLI + REST + OSCAL emit).

Plan-of-Action-and-Milestones (POA&M) is the federal-compliance
mechanism for tracking the remediation of identified gaps. This
runbook walks an operator through the end-to-end Evidentia POA&M
workflow: bootstrap from a gap report → track milestones → emit
OSCAL POA&M 1.2.1 for auditor handoff.

## Quick reference

| Verb | Surface | Use case |
|---|---|---|
| `evidentia poam create --from-gap-report <path>` | CLI | Auto-materialize POA&M items from a saved gap report |
| `evidentia poam list` | CLI | Browse open POA&Ms in canonical order |
| `evidentia poam show <id>` | CLI | View a single POA&M's full detail |
| `evidentia poam update <id> --status <s>` | CLI | Transition the gap-level status |
| `evidentia poam milestone add <id> --target-date <d> --description <d>` | CLI | Add a remediation milestone |
| `evidentia poam milestone update <id> <ms-id> --status <s>` | CLI | Advance a milestone's state |
| `evidentia poam calendar` | CLI | Show overdue + due-soon milestones across all POA&Ms |
| `POST /api/poam/items` | REST | Create a POA&M item programmatically |
| `PATCH /api/poam/items/{id}/milestones/{ms_id}` | REST | Update a milestone via HTTP |

## Conceptual model

A **POA&M item** is a tracked `ControlGap` record from the gap
analyzer, promoted into the POA&M store with an optional milestone
schedule attached. Each item carries:

- **Gap context** — framework, control_id, severity, gap
  description, remediation guidance (inherited from the ControlGap)
- **Milestones** — a time-ordered list of `Milestone` records, each
  with a target date, description, status, and optional evidence
  reference
- **Lifecycle status** — the gap-level `GapStatus` (open /
  in_progress / remediated / accepted / not_applicable)

Milestones use the **POAMState** state machine:

```
PLANNED ──► IN_PROGRESS ──► COMPLETED ──► VERIFIED  (terminal)
   │             │              ▲
   │             │              │
   └─► OVERDUE ──┘──► COMPLETED ┘
```

**Backward transitions are explicitly forbidden** to preserve
auditor-defensible monotonic progress. To re-open work, file a NEW
milestone with a fresh target date.

`OVERDUE` is dual-purpose:
- An operator-set persisted state ("we know we'll miss this date")
- A derived attention signal at query time (`target_date < today`
  AND status ∈ {PLANNED, IN_PROGRESS})

## Workflow 1 — Bootstrap from a gap report

After running `evidentia gap analyze --output report.json`:

```
$ evidentia poam create --from-gap-report report.json
POA&M materialization complete: 12 created, 0 skipped (already exist;
pass --overwrite to replace), 47 skipped (severity filter; pass --all
to include)
```

The **default policy materializes only CRITICAL + HIGH severity
gaps** — the auditor-defensible default per FedRAMP POA&M Template
Completion Guide v3.0 §3.1. Lower-severity findings are documented
in the SSP risk register without creating individual POA&M items.

To materialize everything:

```
$ evidentia poam create --from-gap-report report.json --all
```

To re-materialize after fixing gap-analyzer output (replaces
existing records — milestone history is lost):

```
$ evidentia poam create --from-gap-report report.json --overwrite
```

## Workflow 2 — Track milestones

Add milestones to plan the remediation:

```
$ evidentia poam milestone add abc12345 \
    --target-date 2026-06-30 \
    --description "Deploy Okta SCIM provisioning to staging"

$ evidentia poam milestone add abc12345 \
    --target-date 2026-08-15 \
    --description "Production rollout + 30-day soak"
```

As work progresses, advance the milestone status:

```
$ evidentia poam milestone update abc12345 ms-uuid-1 --status in_progress
$ evidentia poam milestone update abc12345 ms-uuid-1 --status completed \
    --evidence-ref "sigstore:rekor.sigstore.dev/api/v1/log/entries/..."
```

When the auditor signs off on a completed milestone:

```
$ evidentia poam milestone update abc12345 ms-uuid-1 --status verified
```

VERIFIED is terminal. Re-opening requires filing a new milestone.

## Workflow 3 — Surface attention signals

The `calendar` verb is the operator's daily/weekly attention check:

```
$ evidentia poam calendar
OVERDUE milestones (3) as of 2026-05-08
...

Due within 7 day(s) (2) as of 2026-05-08
...
```

`--window-days N` adjusts the due-soon lookahead. `--today
YYYY-MM-DD` overrides the system clock for deterministic CI
snapshots.

For dashboard integration:

```
$ curl http://localhost:8000/api/poam/calendar?today=2026-05-08 | jq
{
  "today": "2026-05-08",
  "overdue": [...],
  "due_soon": [...]
}
```

## Workflow 4 — Close out a POA&M

When all milestones complete + the auditor verifies remediation:

```
$ evidentia poam update abc12345 --status remediated
[green]Updated[/green] POA&M abc12345 (status)
```

Setting status=remediated fires the `evidentia.poam.closed` audit
event in addition to `evidentia.poam.updated`. The record stays in
the store; `evidentia poam list` shows it only when `--all` is
passed.

## Workflow 5 — OSCAL POA&M emit

For auditor handoff, emit OSCAL POA&M 1.2.1 JSON:

```python
from evidentia_core.gap_store import load_latest_report
from evidentia_core.oscal.poam_exporter import gap_report_to_oscal_poam
import json

report = load_latest_report()
poam_doc = gap_report_to_oscal_poam(report)
print(json.dumps(poam_doc, indent=2))
```

The emit includes:

- **`metadata`** — title, organization, oscal-version 1.2.1,
  cross-references to the source gap report
- **`observations[]`** — one per POA&M item (the "what we noticed")
- **`risks[]`** — one per POA&M item with milestones as
  `tracking-entries` under `remediations[]`
- **`poam-items[]`** — one per gap, cross-referencing the matching
  risk + observation by UUID
- **`back-matter`** (default on) — each POA&M record's canonical
  JSON base64-encoded with SHA-256 for tamper-evidence (mirrors the
  v0.7.0 finding-resource integrity pattern)

To skip back-matter (smaller output; no integrity protection):

```python
poam_doc = gap_report_to_oscal_poam(report, embed_back_matter=False)
```

Custom severity filter:

```python
poam_doc = gap_report_to_oscal_poam(
    report,
    severity_filter=lambda gap: True,  # materialize ALL gaps
)
```

## Audit trail

Every persisted POA&M mutation fires an audit event. See
[`docs/log-schema.md`](log-schema.md) §`evidentia.poam.*` for the
full field shape. Quick reference:

| Action | When |
|---|---|
| `evidentia.poam.created` | New POA&M lands in the store |
| `evidentia.poam.updated` | Non-state-transition edit |
| `evidentia.poam.milestone_reached` | A milestone transitions to COMPLETED |
| `evidentia.poam.overdue` | Persisted-status or derived-attention overdue |
| `evidentia.poam.closed` | Last open milestone done OR status=remediated |
| `evidentia.poam.verified` | Auditor sign-off on a closed milestone |

The audit-event stream is the auditor-defensible record. The POA&M
JSON file is the operator-facing record. Both should agree —
divergence indicates either an off-line edit (bypassing
Evidentia) or a clock skew between the operator's machine and the
audit-log sink.

## Storage location

POA&M records live in:

- Windows: `%APPDATA%\Evidentia\poam_store\`
- macOS:   `~/Library/Application Support/evidentia/poam_store/`
- Linux:   `~/.local/share/evidentia/poam_store/`

Override with `EVIDENTIA_POAM_STORE_DIR=<path>` for CI / multi-
environment isolation.

Each POA&M is one JSON file named `<gap.id>.json`. Operators can
edit by hand (and reload via `load_poam_by_id`) but mutations
bypass the audit trail — prefer the CLI/REST surfaces.
