# Manage audit retention and chain-of-custody

Auditors do not just want your evidence — they want proof that you *kept* it for
as long as the regulator demands, and that nobody quietly shortened that window.
Evidentia's **retention** surface tracks per-record retention metadata: a
regulator-aligned classification, a mandatory-retention `lock_until` date, a
WORM-style extend-only lock, an optional legal hold, and a forward-only lifecycle
that walks a record from `active` through to `purged`. This guide walks the full
lifecycle with the `evidentia retention` commands and shows the equivalent in the
web console.

This surface tracks the *metadata about* a record's retention — it does not move
or delete the underlying evidence. Deleting a retention record removes only the
tracking entry, never the file it points at.

## Prerequisites

- Evidentia installed (`pip install evidentia` or the monorepo dev checkout). No
  extra is required for the CLI retention verbs.
- For the web console: the API server running with the `[gui]` extra. See
  [Serve the local web UI](serve-the-web-ui.md).

## The retention lifecycle

Each record carries a `RetentionLifecycleStage`, a four-member enum, and a
classification that sets the regulator-stated minimum retention period. The
lifecycle is a **forward-and-recoverable** state machine — `active` and
`preserved` can move between each other, but once a record expires it can only be
purged, and `purged` is terminal:

```
active ──> preserved ──> expired ──> purged
  ▲           │                       (terminal)
  └───────────┘
```

- **`active`** — in its retention window; the default for a new record.
- **`preserved`** — held for a specific reason (for example a legal hold or an
  audit in progress).
- **`expired`** — past its retention window; eligible to be purged.
- **`purged`** — securely removed; **terminal**.

The state machine rejects any illegal jump and tells you the legal next stages.
A **legal hold** blocks expiry/purge regardless of stage — it is the brake you
pull when litigation or an investigation freezes a record in place.

## Step 1 — Track a record

```bash
evidentia retention set --classification sec-17a-4 --record-pointer "s3://audit-bucket/2026/trade-blotter.parquet"
```

`--classification` is the only required flag. It selects the regulator regime,
which sets the default retention period: one of `sec-17a-4`, `finra-3110`,
`irs-tax`, `sox-404`, `hipaa`, `glba`, `pci-dss`, `model-risk`, `gdpr`, or
`generic`. The command echoes the new record id and the computed `lock_until`:

```
Tracked retention record (id: e8aa2085-c9c8-4b24-9d6e-4f13f75ec02c);
classification: sec-17a-4; lock_until: 2032-06-20
```

Override the regulator default with `--retention-period-days`, point at the
underlying record with `--record-pointer` (a file path or S3/Azure URL), freeze
the record from the start with `--legal-hold`, cross-reference a written policy
with `--policy-name`, and attach free-text context with `--notes`:

```bash
evidentia retention set --classification finra-3110 --retention-period-days 2555 --record-pointer "/evidence/2026/comms-archive.zip" --legal-hold --policy-name "RR-2026-comms" --notes "Frozen pending FINRA inquiry"
```

## Step 2 — List and inspect

```bash
evidentia retention list
```

`list` prints a table of every tracked record — id, classification, lifecycle
stage, lock-until date, whether it is currently locked, whether a legal hold is
set, and the record pointer:

```
                          Retention records (1 total)
┌──────────┬────────────┬────────┬────────────┬─────────┬───────┬─────────────┐
│ ID       │ Classific… │ Stage  │ Lock-until │ Locked? │ Hold? │ Pointer     │
├──────────┼────────────┼────────┼────────────┼─────────┼───────┼─────────────┤
│ e8aa2085 │ sec-17a-4  │ active │ 2032-06-20 │    ✓    │   —   │ s3://audit… │
└──────────┴────────────┴────────┴────────────┴─────────┴───────┴─────────────┘
```

Narrow the list with `--classification` and `--lifecycle` (one of `active`,
`preserved`, `expired`, `purged`), and add `--json` for machine-readable output:

```bash
evidentia retention list --classification sec-17a-4 --lifecycle active --json
```

Show one record in full — including its created/updated timestamps and notes:

```bash
evidentia retention show e8aa2085-c9c8-4b24-9d6e-4f13f75ec02c
```

```
Retention record  (e8aa2085-c9c8-4b24-9d6e-4f13f75ec02c)
  Classification:     sec-17a-4
  Lifecycle stage:    active
  Retention period:   2190 days
  Lock-until:         2032-06-20
  Currently locked:   YES
  Legal hold:         no
  Record pointer:     s3://audit-bucket/2026/trade-blotter.parquet
```

`show` also accepts `--json`. (`retention show` and the lifecycle verbs accept
either the full UUID or the short 8-character prefix shown in `list`.)

## Step 3 — Extend the lock-until (WORM, extend-only)

Retention is WORM-style: you can push the `lock_until` date **later**, never
earlier. This is what makes the record auditor-defensible — the mandatory window
can grow (for a legal hold or a longer regime) but can never be quietly trimmed.

```bash
evidentia retention extend e8aa2085-c9c8-4b24-9d6e-4f13f75ec02c --new-lock-until 2035-01-01
```

```
Extended retention id=e8aa2085; lock_until: 2032-06-20 → 2035-01-01
```

`--new-lock-until` takes an ISO-8601 `YYYY-MM-DD` date and is required. Asking
for an *earlier* date is rejected:

```
Error: WORM forbids shortening retention (current lock_until=2035-01-01;
requested=2026-01-01).
```

## Step 4 — Transition the lifecycle stage

```bash
evidentia retention transition e8aa2085-c9c8-4b24-9d6e-4f13f75ec02c --new-stage preserved
```

```
Transitioned retention id=e8aa2085: active → preserved
```

`--new-stage` is required and must be a legal next stage. The state machine
blocks any illegal jump and names the valid targets:

```
Error: Illegal transition: preserved → purged. Valid from preserved: ['active',
'expired']
```

To purge a record you must first walk it to `expired`, then transition to
`purged`. A record under legal hold cannot be expired or purged at all.

## Step 5 — Generate a retention-posture report

```bash
evidentia retention report
```

This prints a Markdown audit summary to stdout: a stage-by-stage count, how many
records are locked and under legal hold, and a per-classification distribution.

```
# Retention Posture Report

_As of 2026-06-22, 1 record(s) tracked across the audit chain-of-custody._

| Stage | Count |
| --- | --- |
| ACTIVE | 1 |
...
```

Write it to a file (and overwrite an existing file) instead of printing:

```bash
evidentia retention report --output retention-posture.md --force
```

## Step 6 — Delete a tracking entry (metadata only)

```bash
evidentia retention delete e8aa2085-c9c8-4b24-9d6e-4f13f75ec02c
```

This removes only the **metadata** record, not the underlying evidence. It is for
cleaning up tracking entries for records that were deleted by other means — a
mis-imported entry or a test fixture. For an actual evidence purge, transition
the lifecycle to `purged` first. `delete` prompts for confirmation unless you
pass `--yes`.

## Managing retention in the web console

Everything above also works from the browser. Start the server with
`evidentia serve` and open the **Retention** screen from the sidebar (under
**Govern**; route `/retention`). The screen mirrors the CLI surface and the same
server-side state machine, so it never offers a transition the API would reject.

1. **Add a record.** The **New retention record** form sits at the top. Pick a
   **classification** (the only required field — the server defaults the
   retention period to the regulator-stated minimum when you leave the days
   blank), optionally set the retention period, record pointer, policy name, and
   notes, and tick **Place under legal hold** to freeze it from the start. Click
   **Add record** and it lands in the inventory below. This calls
   `POST /api/retention`.
2. **Generate a report.** The **Retention report** card has a **Generate report**
   button that fetches the same Markdown summary as `retention report` (via
   `GET /api/retention/report`) and renders it inline as preformatted text.
3. **Filter.** Two chip rows narrow the inventory without a page reload — one by
   **classification** and one by **lifecycle stage** — the same two axes the
   `retention list --classification` / `--lifecycle` flags control. Click a chip
   to apply it; click *All …* to clear that axis.
4. **Select.** Click a record card to open its detail panel in place. The panel
   repeats the classification, lifecycle stage, and any legal-hold badge, and
   shows the retention period, lock-until, policy, and timestamps.
5. **Extend the lock-until.** The **Extend lock-until** form takes a date and
   issues the same WORM extend-only change as `retention extend` (via
   `POST /api/retention/{id}/extend`). A shorten attempt is rejected server-side
   and the error surfaces inline.
6. **Transition the stage.** The **Transition stage** controls offer only the
   **legal next stages** for the current stage — `active` offers *Preserved* and
   *Expired*; `expired` offers only *Purged*; a `purged` record offers nothing
   (it is terminal). Clicking issues `POST /api/retention/{id}/transition`.
7. **Delete.** **Delete record** asks for an in-panel confirmation, then issues
   `DELETE /api/retention/{id}` — metadata only, the same as the CLI verb.

## What's next

- **Prove the evidence itself is intact**: [Sign and verify evidence](sign-and-verify-evidence.md)
  and [Concepts → Evidence integrity](../3-concepts/evidence-integrity.md) cover
  the cryptographic chain-of-custody that retention metadata sits alongside.
- **Track remediation work to a deadline**: [Manage a POA&M](manage-poam.md)
  uses the same forward-only-lifecycle discipline for gap closure.
- **Run a recurring compliance cadence**: [CONMON deployment](conmon-deployment.md).

## Got stuck?

- **"Retention record '…' not found"** — confirm the id with
  `evidentia retention list` (it shows the short 8-character prefix; you can pass
  either that prefix or the full UUID).
- **"WORM forbids shortening retention"** — `extend` only moves the lock-until
  *later*. There is no supported way to shorten a retention window; that is the
  WORM guarantee.
- **"Illegal transition: … → …"** — the lifecycle is a state machine. The error
  lists the legal next stages; to purge a record, walk it through `expired`
  first.
- **A record won't expire or purge** — check for a legal hold (`Hold?` column in
  `list`, or the **Legal hold** badge in the console). A held record is frozen
  against expiry and purge by design.
- **The console can't fetch records** — the page shows "Could not fetch retention
  records. Is the backend running?" if the API is down. Start it with
  `evidentia serve`.
