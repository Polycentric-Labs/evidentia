# Manage third-party / vendor risk

Concentration risk, fourth-party exposure, and due-diligence (DD) cadence are
the auditor-facing core of a third-party risk management (TPRM) program.
Evidentia keeps a local vendor inventory, computes concentration-risk reports
across configurable dimensions, and generates / ingests DD questionnaires
(CAIQ, SIG via a licensed template, or a packaged generic baseline). This guide
walks the full operator loop with the `evidentia tprm` command group.

## Prerequisites

- Nothing beyond a working Evidentia install — the vendor inventory is **local
  file-backed persistence** (no third-party credentials, no network calls).
- The store location resolves via, in order: an explicit path, the
  `EVIDENTIA_VENDOR_STORE_DIR` environment variable, then a platform default
  (`platformdirs.user_data_dir`). For a self-contained demo or a CI run, point
  it at a scratch directory so you do not touch your real inventory:

```bash
export EVIDENTIA_VENDOR_STORE_DIR="$(mktemp -d)/vendor_store"
```

> The `xlsx` questionnaire output format requires the optional `[xlsx]` extra
> (`pip install 'evidentia-core[xlsx]'`). The `sig` / `sig-lite` frameworks
> additionally require a Shared Assessments licensed XLSX template you supply
> with `--from-template`. The `json` / `csv` paths below run with no extras.

## Concepts at a glance

| Field | What it drives |
| --- | --- |
| `--type` | Vendor type — one of `saas`, `subservice_org`, `contractor`, `data_processor`, `cloud_provider`, `open_source`. |
| `--criticality-tier` | FFIEC tier — one of `critical`, `high`, `medium`, `low`. Drives the auto-computed DD review cadence. |
| `--regulatory-classification` | Comma-separated flags — `custody`, `clearing`, `model`, `data_processor`, `critical_third_party`. |
| `--residual-risk-score` | Integer `1`–`25` (`0` = unscored). |
| `next_review_due` | Auto-computed from `criticality_tier` + `last_due_diligence_review` unless you override it with `--next-review-due`. |

The concentration-report dimensions (`--by`) are `4th-party`, `cloud-provider`,
`criticality-tier`, `region`, `regulatory-classification`, and
`service-category`, aligned to FFIEC + OCC Bulletin 2013-29 + FRB SR 13-19
expectations.

## Step 1 — Add a vendor

```bash
evidentia tprm vendor add \
  --name "Acme Cloud Inc." \
  --type saas \
  --criticality-tier critical \
  --owner "alice@example.com" \
  --contract-start-date 2026-01-01 \
  --region "us-east-1" \
  --regulatory-classification "data_processor,critical_third_party" \
  --residual-risk-score 16 \
  --last-due-diligence-review 2026-02-15
```

```
✓ Added vendor Acme Cloud Inc. (id: e5dd135b-e489-4a4a-9fa4-f3da59589f71)
```

The command prints the new vendor's **UUID** — capture it; later commands
(`show`, `edit`, `dd-questionnaire generate`) take that ID. Key flags:

- **`--contract-start-date` is required** (`YYYY-MM-DD`). It is easy to miss
  because it sits among the optional date flags, but `vendor add` will not
  create a record without it.
- `--name`, `--type`, `--criticality-tier`, and `--owner` round out the
  minimum atomic add. See the table above for the `--type` and
  `--criticality-tier` enum values.
- Because we passed `--last-due-diligence-review`, Evidentia auto-computes
  `next_review_due` from the criticality-tier cadence (a `critical` vendor
  reviewed `2026-02-15` is next due `2027-02-15`).
- For complex records with fourth-parties and evidence pointers, skip the
  atomic flags and load a YAML file with `--from-yaml <path>` instead.

Add a couple more so later steps have something to aggregate:

```bash
evidentia tprm vendor add --name "Globex Hosting LLC" --type cloud_provider \
  --criticality-tier high --owner "bob@example.com" \
  --contract-start-date 2025-06-01 --region "us-east-1" --residual-risk-score 12

evidentia tprm vendor add --name "Initech Analytics" --type data_processor \
  --criticality-tier medium --owner "carol@example.com" \
  --contract-start-date 2025-09-15 --region "eu-west-1" \
  --regulatory-classification "model" --residual-risk-score 6
```

```
✓ Added vendor Globex Hosting LLC (id: c03d3d9e-c2d0-451c-8a6a-fc3fbf541716)
✓ Added vendor Initech Analytics (id: 6e4d2c8d-7c63-4701-83fd-38aeab4b4e6a)
```

## Step 2 — List and inspect the inventory

```bash
evidentia tprm vendor list
```

```
                          Vendor inventory (3 total)
┌─────────┬─────────┬─────────┬─────────┬──────────┬─────────┬──────┬────┬────┐
│ ID      │ Name    │ Type    │ Critic… │ Owner    │ Next    │ Risk │ 4P │ Ev │
│         │         │         │         │          │ review  │      │    │    │
├─────────┼─────────┼─────────┼─────────┼──────────┼─────────┼──────┼────┼────┤
│ e5dd13… │ Acme    │ saas    │ critic… │ alice@e… │ 2027-0… │   16 │  0 │  0 │
│         │ Cloud   │         │         │          │         │      │    │    │
│ c03d3d… │ Globex  │ cloud_… │ high    │ bob@exa… │ —       │   12 │  0 │  0 │
│         │ Hosting │         │         │          │         │      │    │    │
│ 6e4d2c… │ Initech │ data_p… │ medium  │ carol@e… │ —       │    6 │  0 │  0 │
│         │ Analyt… │         │         │          │         │      │    │    │
└─────────┴─────────┴─────────┴─────────┴──────────┴─────────┴──────┴────┴────┘
```

The table is sorted by criticality then name. The `4P` column counts
fourth-parties and `Ev` counts attached evidence refs. Filter with
`--criticality-tier` / `--type` to narrow a large inventory.

For machine consumption, add `--json` — a **bare array** of vendor records,
ready for `jq`:

```bash
evidentia tprm vendor list --json | jq '.[].name'
```

```json
"Acme Cloud Inc."
"Globex Hosting LLC"
"Initech Analytics"
```

Each record carries the full vendor shape (`id`, `type`, `criticality_tier`,
`relationship_owner`, `region`, the contract / review dates,
`regulatory_classification`, `fourth_parties`, `residual_risk_score`,
`evidence_refs`, `created_at` / `updated_at`, and an `evidentia_version`
stamp). This same JSON is what you feed to gap analysis as a tamper-evident
vendor inventory — see [What's next](#whats-next).

> The CLI `--json` is unpaginated (optimized for shell pipes). The REST
> equivalent `GET /api/tprm/vendors` returns a `{total, skip, limit, vendors}`
> pagination envelope instead; the shape divergence is intentional and
> documented in the [CLI reference](../4-reference/cli.md#evidentia-tprm-vendor-list).

Show one vendor in full, including the resolved review cadence:

```bash
evidentia tprm vendor show e5dd135b-e489-4a4a-9fa4-f3da59589f71
```

```
Acme Cloud Inc.  (e5dd135b-e489-4a4a-9fa4-f3da59589f71)
  Type:               saas
  Criticality tier:   critical
  Relationship owner: alice@example.com
  Contract start:     2026-01-01
  Contract end:       (indefinite)
  Last DD review:     2026-02-15
  Next review due:    2027-02-15
  Residual risk:      16 / 25
  Regulatory flags:   data_processor, critical_third_party
  Created: 2026-05-30 06:44:33+00:00  Updated: 2026-05-30 06:44:33+00:00
```

Add `--json` to `show` for the raw record instead of the human view.

## Step 3 — Edit a vendor record

Atomic `--<field>` flags update one or more fields in place. Record a completed
DD review and bump the residual-risk score for the cloud-provider:

```bash
evidentia tprm vendor edit c03d3d9e-c2d0-451c-8a6a-fc3fbf541716 \
  --residual-risk-score 15 \
  --last-due-diligence-review 2026-03-01
```

```
✓ Updated vendor Globex Hosting LLC (id: c03d3d9e-c2d0-451c-8a6a-fc3fbf541716)
```

Updating `--last-due-diligence-review` re-runs the cadence calculation, so
`next_review_due` moves automatically (a `high` vendor reviewed `2026-03-01` is
next due `2027-03-01`). Confirm with `show`:

```bash
evidentia tprm vendor show c03d3d9e-c2d0-451c-8a6a-fc3fbf541716
```

```
Globex Hosting LLC  (c03d3d9e-c2d0-451c-8a6a-fc3fbf541716)
  Type:               cloud_provider
  Criticality tier:   high
  Relationship owner: bob@example.com
  Contract start:     2025-06-01
  Contract end:       (indefinite)
  Last DD review:     2026-03-01
  Next review due:    2027-03-01
  Residual risk:      15 / 25
  Created: 2026-05-30 06:44:51+00:00  Updated: 2026-05-30 06:45:35+00:00
```

`edit` has two other mutually-exclusive modes: `--from-yaml <path>` for a
scripted full-replace (preserves the original `id` + `created_at`), and
`--editor` to open the current record as YAML in `$EDITOR`. To remove a record
entirely, `evidentia tprm vendor delete <id>` prompts for confirmation unless
you pass `-y` — auditors generally prefer keeping the record and letting the
contract dates lapse over deleting history.

## Step 4 — Run a concentration-risk report

Aggregate the inventory across one or more dimensions to surface where you are
over-concentrated. Pass `--threshold` to flag any value whose vendor share
meets-or-exceeds a percentage; omit it for an unflagged distribution view.

```bash
evidentia tprm concentration-report --by criticality-tier --threshold 30 --format json
```

```json
{
  "generated_at": "2026-05-30T06:45:49.891330Z",
  "total_vendors": 3,
  "threshold": 30.0,
  "dimensions": [
    {
      "dimension": "criticality-tier",
      "total_unique_values": 3,
      "distribution": [
        { "value": "critical", "count": 1, "percentage": 33.3, "exceeds_threshold": true },
        { "value": "high",     "count": 1, "percentage": 33.3, "exceeds_threshold": true },
        { "value": "medium",   "count": 1, "percentage": 33.3, "exceeds_threshold": true }
      ],
      "vendors_with_value": 3
    }
  ]
}
```

> The real JSON also ends with an `"evidentia_version"` field (the build that
> produced the report); it is trimmed here so the doc does not pin a version.

The report dict carries `generated_at`, `total_vendors`, the `threshold` you
passed, and a `dimensions` array — each with a per-value `distribution`
(`count`, `percentage`, and `exceeds_threshold` against your threshold). With
three single-vendor tiers each holding 33.3%, all three exceed a 30% threshold.

`--by` accepts multiple comma-separated dimensions (the default is
`region,cloud-provider`), and `--format` offers `html` / `json` / `csv`. CSV is
the most pipe-friendly for a single dimension:

```bash
evidentia tprm concentration-report --by region --threshold 50 --format csv
```

```
dimension,value,count,percentage,exceeds_threshold
region,us-east-1,2,66.7,true
region,eu-west-1,1,33.3,false
```

Here two of three vendors sit in `us-east-1` (66.7%), which trips the 50%
threshold — exactly the regional-concentration signal an examiner looks for.
The default `--format html` writes a self-contained, sortable HTML report;
redirect it to a file (`--output report.html`) or let it dump to stdout.

## Step 5 — Generate a due-diligence questionnaire

`dd-questionnaire generate` pre-fills a questionnaire with the vendor's metadata
(name, type, criticality, contract dates, region, regulatory classification,
fourth-party disclosures) so the receiving vendor only fills in the control
answers. The default framework is `evidentia-generic` (a packaged FFIEC-aligned
baseline) and the default `--output-format` is `json`:

```bash
evidentia tprm dd-questionnaire generate \
  --vendor-id e5dd135b-e489-4a4a-9fa4-f3da59589f71 \
  --format evidentia-generic \
  --output-format json \
  --output acme-dd.json
```

```
✓ Wrote JSON questionnaire to acme-dd.json  (20 question(s);
  format=evidentia-generic; vendor=Acme Cloud Inc.)
```

The written file carries a `vendor` metadata block (echoing the inventory
record) and a `questions` array. Each question has a stable `id`, a `domain`,
the `question_text`, optional `response_options`, and operator `notes` on
acceptable evidence:

```json
{
  "id": "EVG-GOV-03",
  "domain": "Governance",
  "question_text": "Has your organization undergone an independent third-party security audit (SOC 2 Type II, ISO 27001, FedRAMP, or equivalent) in the last 12 months?",
  "response_options": ["Yes", "No", "Not Applicable"],
  "notes": "If Yes, provide the report or attestation letter and indicate the audit period covered."
}
```

Key flags:

- `--vendor-id` is **required** — the questionnaire is always tied to a record.
- `--format` choices: `caiq-full`, `caiq-lite`, `evidentia-generic` (packaged).
  `sig` / `sig-lite` are also accepted **only** with `--from-template` (see
  below).
- `--output-format` choices: `json`, `csv`, `xlsx`. **`xlsx` requires the
  `[xlsx]` extra** (`pip install 'evidentia-core[xlsx]'`) and a `--output`
  path (binary output can't go to stdout). The `json` / `csv` paths shown here
  need no extra.

> **Requires a licensed template.** SIG / SIG-Lite generation needs a Shared
> Assessments licensed XLSX you supply with `--from-template`; Evidentia
> pre-fills vendor metadata into the standard cells and leaves the question
> content untouched for license compliance. Not shown here (the template is not
> redistributable):
>
> ```bash
> evidentia tprm dd-questionnaire generate \
>   --vendor-id <id> --format sig \
>   --from-template path/to/SIG-2026.xlsx \
>   --output sig-prefilled.xlsx
> ```

## Step 6 — Ingest a completed questionnaire

Once a vendor returns the completed file, `dd-questionnaire ingest` parses it
and correlates it back to the inventory record. Format is auto-detected from the
extension (`.json` / `.csv` / `.xlsx`). Correlation is **required** — it
resolves via `--vendor-id` if you pass it, otherwise via the questionnaire's
embedded `vendor_id` from the prefill.

```bash
evidentia tprm dd-questionnaire ingest --questionnaire acme-completed.json
```

The command parses the file, correlates it back to the vendor inventory record,
and prints a summary for operator review:

```
✓ Ingested questionnaire from completed-q.json
Vendor: Acme Cloud (id=e1ed43f9-…)  Questionnaire ID: ed778a88-…  Format: evidentia-generic
Responses: 20 (answered: 0)
        Vendor responses (first 25)
┌─────────────┬──────────┐
│ Question ID │ Response │
├─────────────┼──────────┤
│ EVG-GOV-01  │ (blank)  │
│ EVG-GOV-02  │ (blank)  │
│ …           │ …        │
└─────────────┴──────────┘
```

Pass `--output-format json` for a machine-readable summary. The `format` field
carries the questionnaire framework (`evidentia-generic`, `caiq-lite`, …); the
`responses` map is keyed by question ID:

```json
{
  "vendor": { "id": "e1ed43f9-…", "name": "Acme Cloud" },
  "questionnaire_id": "ed778a88-…",
  "format": "evidentia-generic",
  "responses": { "EVG-GOV-01": "", "EVG-GOV-02": "", "…": "…" }
}
```

The flags themselves are straightforward: `--questionnaire <path>` is required;
`--vendor-id` overrides correlation when the embedded ID is missing or you want
to file the response against a different record; `--output-format` is `table`
(default) or `json`.

> Note on persistence: this release's
> `ingest` is **parse + correlate + display only**. Writing the response into
> `vendor.evidence_refs[]` is queued for a follow-up release (pending the
> evidence chain-of-custody Sigstore signing — see
> [Sign and verify evidence](sign-and-verify-evidence.md)).

## Managing vendors in the web console

The list-and-add basics also work in the browser. Start the server with
`evidentia serve` and open the **TPRM** screen from the sidebar's *Govern*
group — it reads and writes the same file-backed vendor store the CLI above
manages, so a vendor added in either place shows up in the other. The screen
covers browsing the inventory, filtering it, and the atomic add; the full loop —
concentration-risk reports, due-diligence questionnaires, edits, and deletes —
stays on the CLI.

![The TPRM vendor screen](../images/screen-tprm.png)

1. **Browse.** The inventory renders one card per vendor, each showing the
   vendor **name**, a **criticality-tier** badge (`critical` / `high` /
   `medium` / `low`), a **type** badge (SaaS, Subservice org, Contractor, Data
   processor, Cloud provider, Open source), the **relationship owner**, and the
   **next review due** date (*not scheduled* until a DD review is recorded). The
   header shows a live `N of M vendors` count.
2. **Filter.** Two chip rows narrow the list without a page reload — one by
   **criticality tier** and one by **vendor type** — the same two axes
   `vendor list --criticality-tier` / `--type` filter on. The filters combine;
   click *All tiers* / *All types* to clear an axis.
3. **Add a vendor.** The **New vendor** form takes the same five required fields
   as `vendor add` — **name**, **relationship owner**, **contract start date**
   (a date picker; easy to miss on the CLI, but the form will not submit without
   it), and chip pickers for **type** and **criticality tier**. The **Add
   vendor** button stays disabled until the three text/date fields are filled; a
   validation error from the server surfaces inline beneath the form rather than
   clearing it.

Richer fields — region, regulatory classification, fourth parties, the
residual-risk score, and evidence references — are set through the CLI
(`evidentia tprm vendor edit`, or a `--from-yaml` load) on the same store; the
form leaves residual risk at its `0` (unscored) default.

## What's next

- **Feed the inventory into gap analysis.** `evidentia tprm vendor list --json >
  vendors.json` produces the inventory that `evidentia gap analyze --format
  oscal-ar --vendor-inventory vendors.json` embeds into an OSCAL Assessment
  Results document (each vendor added to `metadata.parties[]` and as a
  SHA-256-hashed back-matter resource). See [Run a gap analysis](run-gap-analysis.md).
- **Track remediation of vendor findings.** Roll material third-party gaps into
  a [POA&M](manage-poam.md) with milestone timelines.
- **Run reviews on a cadence.** Wire the DD-review schedule into a recurring
  assessment loop with [CONMON deployment](conmon-deployment.md).
- **Full flag reference.** Every `tprm` flag, default, and enum is in the
  [CLI reference → `evidentia tprm`](../4-reference/cli.md#evidentia-tprm).
- **The data model.** The base-model conventions behind the vendor record live
  in [Concepts → Data model](../3-concepts/data-model.md).

## Got stuck?

- **`vendor add` exits without creating a record**: confirm you passed
  `--contract-start-date` (`YYYY-MM-DD`). It is required and sits among the
  optional date flags, so it is the most commonly missed argument.
- **`Invalid vendor ID format (expected UUID string)`**: `show` / `edit` /
  `delete` take the full UUID, not the truncated ID shown in the `list` table.
  Run `evidentia tprm vendor list --json | jq '.[].id'` to copy a full ID.
- **`xlsx requires the [xlsx] extra`** (or an import error on `openpyxl`): the
  `xlsx` output format needs `pip install 'evidentia-core[xlsx]'`. Use `json` or
  `csv` if you don't need a workbook.
- **`concentration-report` shows everything at 0%/100% or an empty
  distribution**: the report is computed over whatever is in the store. Confirm
  `EVIDENTIA_VENDOR_STORE_DIR` points at the inventory you populated (a fresh
  `mktemp -d` store starts empty), and that the vendors carry the dimension you
  asked for with `--by` (e.g. `--by region` needs `--region` set on records).

