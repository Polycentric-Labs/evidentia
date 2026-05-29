# Manage a Plan of Action and Milestones (POA&M)

A POA&M is the auditor-facing record of *how and when* you will close your gaps.
Evidentia builds POA&M items from a gap-analysis report, lets you attach a
milestone timeline to each, and enforces a forward-only lifecycle so the record
shows genuine progress. This guide walks the full lifecycle with the
`evidentia poam` commands.

## Prerequisites

- A gap-analysis report JSON (see [Run a gap analysis](run-gap-analysis.md)) —
  `evidentia poam create` materializes POA&M items from it.

## The POA&M lifecycle

Each milestone carries a `POAMState`, a five-member lifecycle enum aligned to the
FedRAMP POA&M Template Completion Guide v3.0 and NIST SP 800-53A Rev 5 Appendix F:

```
PLANNED ──> IN_PROGRESS ──> COMPLETED ──> VERIFIED
   │             │              ▲
   └──> OVERDUE <─┘             (auditor sign-off; terminal)
```

- **`planned`** — scheduled, not started.
- **`in_progress`** — actively being worked.
- **`completed`** — operator-claimed done, pending auditor verification.
- **`verified`** — auditor confirmed; **terminal**.
- **`overdue`** — the off-axis attention state: a planned/in-progress milestone
  whose `target_date` is in the past. It is also derived automatically at query
  time against the current date.

Transitions are **forward-only** and enforced by the state machine. You cannot
rewind a `completed` milestone back to `in_progress`, and `verified` is terminal.
To re-open work, you file a *new* milestone with a fresh target date rather than
mutating the verified record — this preserves audit-trail integrity. The
authoritative description lives in
[Concepts → Data model](../3-concepts/data-model.md#poam-milestones).

## Step 1 — Materialize POA&M items from a gap report

```bash
evidentia poam create --from-gap-report=gap-report.json
```

By default this materializes only **critical and high** severity gaps — the
auditor-defensible default per FedRAMP POA&M guidance (POA&M items track material
findings; lower-severity gaps are documented in the SSP risk register). Pass
`--all` to materialize every severity. Existing items are skipped to preserve
milestone history unless you pass `--overwrite`.

```bash
# Materialize every gap, replacing any existing items.
evidentia poam create --from-gap-report=gap-report.json --all --overwrite
```

## Step 2 — List and inspect

```bash
evidentia poam list
```

By default `list` shows only POA&Ms whose underlying gap is `open` or
`in_progress`. Add `--all` to include `remediated` / `accepted` items. Filter
with `--severity` (comma-separated), and — once milestones have owners or
reviewers — with `--owner` / `--reviewer`. Add `--json` for machine-readable
output:

```bash
evidentia poam list --severity=critical,high --json
```

Show one item in full, including its milestone timeline:

```bash
evidentia poam show <poam-id>
```

(`<poam-id>` is the POA&M's UUID, shown in the first column of `poam list`.)

## Step 3 — Add a milestone

```bash
evidentia poam milestone add <poam-id> \
  --target-date=2026-09-30 \
  --description="Enable MFA on all admin accounts"
```

`--target-date` (ISO-8601 `YYYY-MM-DD`) and `--description` (`-d`) are required.
A new milestone starts at `planned` unless you pass `--status`; attach an
evidence pointer with `--evidence-ref` (a URL, Sigstore bundle path, Jira key,
ServiceNow record, etc.):

```bash
evidentia poam milestone add <poam-id> \
  --target-date=2026-10-15 \
  --description="Verify MFA enforcement via Okta export" \
  --status=in_progress \
  --evidence-ref="https://jira.example.com/browse/SEC-1234"
```

## Step 4 — Advance milestones through the lifecycle

```bash
evidentia poam milestone update <poam-id> <milestone-id> --status=completed
```

The state machine blocks invalid or backward transitions and tells you so:

```
Error: invalid state transition completed → in_progress. Backward + invalid
transitions are blocked. To re-open work, file a NEW milestone with a fresh
target_date.
```

You can also revise a milestone's `--target-date`, `--description`, or
`--evidence-ref` in the same command. (`<milestone-id>` is the short UUID shown in
`poam show`.)

## Step 5 — Update the POA&M item itself

Top-level fields (the gap-level status, owner, remediation text, tags) are edited
on the item rather than a milestone:

```bash
evidentia poam update <poam-id> \
  --status=remediated \
  --assigned-to=alice@example.com \
  --add-tag=q3-priority
```

Setting `--status=remediated` stamps a `remediated_at` timestamp and fires the
POA&M-closed audit event. Auditors generally prefer transitioning status over
deleting; `evidentia poam delete <poam-id>` exists for records that should never
have existed (a mis-imported gap or a test fixture) and prompts for confirmation
unless you pass `-y`.

## Step 6 — Watch the calendar

A read-only attention view across *all* POA&Ms surfaces overdue and due-soon
milestones:

```bash
evidentia poam calendar --window-days=14
```

Overdue milestones always appear regardless of the window; `--window-days`
(default 7) controls the "due soon" look-ahead. Use `--today=YYYY-MM-DD` for
deterministic snapshots in CI, and `--json` for machine-readable output. For
recurring assessment and reporting cadences, see the
[CONMON deployment](conmon-deployment.md) guide.

## Emitting an OSCAL POA&M

> **Note (verified against the CLI at this release):** there is no `evidentia
> poam`/`gap` subcommand and no REST endpoint that emits an OSCAL POA&M document.
> The OSCAL POA&M exporter is a **programmatic API**:
> `evidentia_core.oscal.poam_exporter.gap_report_to_oscal_poam(report, *,
> severity_filter=None, embed_back_matter=True)`. It takes a `GapAnalysisReport`
> and returns an OSCAL `plan-of-action-and-milestones` document (defaulting to
> critical+high gaps, with each item's record embedded as a SHA-256-hashed
> back-matter resource for chain-of-custody integrity).

```python
import json
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_core.oscal.poam_exporter import gap_report_to_oscal_poam

report = GapAnalysisReport.model_validate_json(
    open("gap-report.json", encoding="utf-8").read()
)
oscal_poam = gap_report_to_oscal_poam(report)
with open("poam.oscal.json", "w", encoding="utf-8") as fh:
    json.dump(oscal_poam, fh, indent=2, default=str)
```

For an OSCAL *Assessment Results* document (which the CLI does emit directly),
use `evidentia gap analyze --format oscal-ar`
([Run a gap analysis](run-gap-analysis.md)).

## What's next

- **The data model behind POA&M**: [Concepts → Data model](../3-concepts/data-model.md#poam-milestones).
- **Recurring cadences**: [CONMON deployment](conmon-deployment.md).
- **Push gaps to a tracker**: the `evidentia integrations jira` and
  `evidentia integrations servicenow` verbs in the [CLI reference](../4-reference/cli.md).

## Got stuck?

- "No POA&M with ID … found": confirm the UUID with `evidentia poam list` (the
  first column shows a truncated ID; pass the full UUID).
- "invalid state transition": the lifecycle is forward-only — file a new
  milestone instead of rewinding a closed one.
- `poam create` materialized fewer items than expected: by default only
  critical+high gaps become items; add `--all`.
