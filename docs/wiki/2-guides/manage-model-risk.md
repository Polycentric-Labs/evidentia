# Manage a model-risk inventory

A model-risk inventory is the examiner-facing register of *every model the
institution relies on* — what it does, how critical it is, when it was last
validated, and when validation is next due. Evidentia maintains that inventory
as durable JSON records aligned to the Federal Reserve's SR 11-7 and its April
2026 supersession (FRB SR 26-02 / OCC Bulletin 2026-13a), then templates SR 11-7
model documentation and validation-cycle reports straight from each record. This
guide walks the full lifecycle — add, list, show, edit — and the two document
generators, using the `evidentia model-risk` command group. Every record is
local file persistence; no API keys or network access are required.

## Prerequisites

- Before any `evidentia` invocation in a terminal that may render Unicode help
  text, set `PYTHONIOENCODING=utf-8` (Windows `cp1252` consoles otherwise crash
  on a glyph in some `--help` output):

  **Bash / Linux / macOS**

  ```bash
  export PYTHONIOENCODING=utf-8
  ```

  **PowerShell (Windows)**

  ```powershell
  $env:PYTHONIOENCODING = "utf-8"
  ```

- By default the inventory persists to a platform data directory
  (`%APPDATA%\Evidentia\model_store\` on Windows;
  `~/.local/share/evidentia/model_store/` on Linux;
  `~/Library/Application Support/evidentia/model_store/` on macOS). To keep a
  demo or test run isolated, point the `EVIDENTIA_MODEL_STORE_DIR` environment
  variable at a scratch directory — every command below honours it:

  **Bash / Linux / macOS**

  ```bash
  export EVIDENTIA_MODEL_STORE_DIR="$(mktemp -d)/model_store"
  ```

  **PowerShell (Windows)**

  ```powershell
  $env:EVIDENTIA_MODEL_STORE_DIR = Join-Path ([System.IO.Path]::GetTempPath()) "evidentia-demo\model_store"
  ```

## Concepts: criticality tiers and the linkage graph

Each model carries an **SR 11-7 criticality tier** that drives both its
documentation rigour and its independent-validation cadence:

| Tier | Materiality | Validation cadence |
| --- | --- | --- |
| `tier_1` | HIGH — substantial impact on earnings, capital, or strategy | annual |
| `tier_2` | Moderate | biennial |
| `tier_3` | Lower | triennial |

> The `tier_1` / `tier_2` / `tier_3` values are a **regulatory model-criticality
> concept** drawn from SR 11-7 §IV materiality framing. They are not product or
> licensing tiers.

When you record a model's `--last-validation-date`, Evidentia auto-computes
`next_validation_due` by applying the tier cadence — so the inventory always
shows the forward-looking validation deadline an examiner asks for first.

A model record also sits inside a three-node linkage graph that gives every
AI-generated risk statement an SR 11-7 / SR 26-02 audit trace-back:

```
TPRM Vendor  ──Vendor.id──>  ModelInventory  ──ModelInventory.id──>  RiskStatement
(evidentia tprm)            (evidentia model-risk)                 (model_inventory_ref)
```

A model with `--vendor-or-internal vendor` **must** cross-link a TPRM vendor via
`--vendor-id`; an `internal` model **must omit** it (both rules are enforced).
The full composition story lives in
[Financial-services regulatory overlay](../5-compliance/financial-sector-overlay.md).

## Step 1 — Add a model to the inventory

The common case uses atomic flags. Provenance, methodology, and tier are
closed enums — supply exactly one of the listed values.

**Bash / Linux / macOS**

```bash
evidentia model-risk model add \
  --name "Retail Credit PD Scorecard" \
  --purpose "Probability-of-default scoring for the retail unsecured lending book" \
  --methodology ml \
  --vendor-or-internal internal \
  --tier tier_1 \
  --owner "model.risk@example.com" \
  --last-validation-date 2026-02-15
```

**PowerShell (Windows)**

```powershell
evidentia model-risk model add `
  --name "Retail Credit PD Scorecard" `
  --purpose "Probability-of-default scoring for the retail unsecured lending book" `
  --methodology ml `
  --vendor-or-internal internal `
  --tier tier_1 `
  --owner "model.risk@example.com" `
  --last-validation-date 2026-02-15
```

```
Added model Retail Credit PD Scorecard (id:
11b30957-b913-4c13-89ca-bd6b7f850a5f)
```

Note the printed UUID — you pass it to every other `model-risk model` verb and
to both generators. Key flags:

- `--methodology, -m` is one of `statistical`, `ml`, `rules_based`, `llm`,
  `expert_judgment`, `hybrid`.
- `--tier, -T` is one of `tier_1`, `tier_2`, `tier_3` (see the table above).
- `--vendor-or-internal` is `internal` or `vendor`. For `vendor`, add
  `--vendor-id <TPRM Vendor.id>`; for `internal`, omit it.
- `--last-validation-date YYYY-MM-DD` triggers the `next_validation_due`
  auto-computation. Override the computed value with `--next-validation-due` if
  your validation calendar differs from the tier default.
- `--purpose` and `--owner` are required on the atomic-flag path.
- For complex records with nested `inputs` / `outputs` / `validation_findings` /
  `evidence_refs`, use `--from-yaml <path>` instead of the atomic flags.

## Step 2 — List the inventory

`list` renders a rich table sorted by tier then name:

```bash
evidentia model-risk model list
```

```
                           Model inventory (1 total)
┌────────┬────────┬────────┬────────┬────────┬────────┬────────┬─────────┬────┐
│ ID     │ Name   │ Tier   │ Metho… │ Prove… │ Owner  │ Next   │ Findin… │ Ev │
│        │        │        │        │        │        │ valid… │         │    │
├────────┼────────┼────────┼────────┼────────┼────────┼────────┼─────────┼────┤
│ 11b30… │ Retail │ tier_1 │ ml     │ inter… │ model… │ 2027-… │       0 │  0 │
│        │ Credit │        │        │        │        │        │         │    │
│        │ PD     │        │        │        │        │        │         │    │
│        │ Score… │        │        │        │        │        │         │    │
└────────┴────────┴────────┴────────┴────────┴────────┴────────┴─────────┴────┘
```

For scripting, `--json` emits a **bare array** of full model records (this
intentionally differs from the REST endpoint's paginated envelope, so shell
pipelines stay clean). Filter the listing with `--tier` / `--methodology`:

```bash
evidentia model-risk model list --json
```

```json
[
  {
    "id": "11b30957-b913-4c13-89ca-bd6b7f850a5f",
    "name": "Retail Credit PD Scorecard",
    "purpose": "Probability-of-default scoring for the retail unsecured lending book",
    "methodology": "ml",
    "vendor_or_internal": "internal",
    "vendor_id": null,
    "tier": "tier_1",
    "owner": "model.risk@example.com",
    "inputs": [],
    "outputs": [],
    "last_validation_date": "2026-02-15",
    "validation_findings": [],
    "next_validation_due": "2027-02-15",
    "retirement_plan": null,
    "notes": null,
    "evidence_refs": [],
    "created_at": "2026-05-30T06:44:34.756764Z",
    "updated_at": "2026-05-30T06:44:34.757770Z",
    "evidentia_version": "0.10.11"
  }
]
```

Observe `next_validation_due` is `2027-02-15` — exactly one year after the
`tier_1` model's `last_validation_date` of `2026-02-15`.

## Step 3 — Show a single record

```bash
evidentia model-risk model show 11b30957-b913-4c13-89ca-bd6b7f850a5f
```

```
Retail Credit PD Scorecard  (11b30957-b913-4c13-89ca-bd6b7f850a5f)
  Purpose:            Probability-of-default scoring for the retail unsecured
lending book
  Methodology:        ml
  Tier:               tier_1
  Provenance:         internal
  Owner:              model.risk@example.com
  Last validation:    2026-02-15
  Next validation:    2027-02-15
  Created: 2026-05-30 06:44:34.756764+00:00  Updated: 2026-05-30
06:44:34.757770+00:00  evidentia: 0.10.11
```

Add `--json` for the same single record as a JSON object instead of the
formatted block.

## Step 4 — Edit a record

Atomic `--<field>=<value>` flags update one or more fields in place; the record
keeps its original `id` and `created_at` and re-stamps `updated_at`. Updating
`--last-validation-date` re-runs the tier-cadence computation, so
`next_validation_due` moves with it:

**Bash / Linux / macOS**

```bash
evidentia model-risk model edit 11b30957-b913-4c13-89ca-bd6b7f850a5f \
  --owner "quant.validation@example.com" \
  --last-validation-date 2026-05-01
```

**PowerShell (Windows)**

```powershell
evidentia model-risk model edit 11b30957-b913-4c13-89ca-bd6b7f850a5f `
  --owner "quant.validation@example.com" `
  --last-validation-date 2026-05-01
```

```
Updated model Retail Credit PD Scorecard (id:
11b30957-b913-4c13-89ca-bd6b7f850a5f)
```

Re-show to confirm the new owner and the recomputed validation deadline:

```bash
evidentia model-risk model show 11b30957-b913-4c13-89ca-bd6b7f850a5f
```

```
Retail Credit PD Scorecard  (11b30957-b913-4c13-89ca-bd6b7f850a5f)
  Purpose:            Probability-of-default scoring for the retail unsecured
lending book
  Methodology:        ml
  Tier:               tier_1
  Provenance:         internal
  Owner:              quant.validation@example.com
  Last validation:    2026-05-01
  Next validation:    2027-05-01
  Created: 2026-05-30 06:44:34.756764+00:00  Updated: 2026-05-30
06:45:13.492611+00:00  evidentia: 0.10.11
```

`Next validation` moved from `2027-02-15` to `2027-05-01` automatically. Two
other edit modes exist for scripted or interactive workflows: `--from-yaml
<path>` does a full-record replace (preserving `id` + `created_at`), and
`--editor` opens the current record as YAML in `$EDITOR`.

To remove a record entirely, `evidentia model-risk model delete <model-id>`
prompts for confirmation; pass `--yes` / `-y` to skip the prompt in CI.

## Step 5 — Generate SR 11-7 model documentation

`doc generate` writes a self-contained SR 11-7 §III.A model-documentation
Markdown document, templated directly from the inventory record — **no LLM key
or network access is required**. With no `--output`, it prints to stdout:

```bash
evidentia model-risk doc generate 11b30957-b913-4c13-89ca-bd6b7f850a5f
```

```markdown
# Model Documentation — Retail Credit PD Scorecard

_SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC Bulletin 2026-13a aligned model documentation. Generated by Evidentia v0.10.11 from ModelInventory record._

## 1. Identification

| Field | Value |
| --- | --- |
| Model ID | `11b30957-b913-4c13-89ca-bd6b7f850a5f` |
| Name | Retail Credit PD Scorecard |
| Tier | tier_1 |
| Methodology | ml |
| Provenance | internal |
| Owner | quant.validation@example.com |
| Vendor ID | _(internal model)_ |
| Created | 2026-05-30T06:44:34.756764+00:00 |
| Last updated | 2026-05-30T06:45:13.492611+00:00 |
| Last validation | 2026-05-01 |
| Next validation due | 2027-05-01 |

## 2. Purpose and intended use

Probability-of-default scoring for the retail unsecured lending book

## 3. Methodology and design

**Methodology category**: `ml`

**Tier**: `tier_1` — under SR 11-7 §IV materiality framing, this model is HIGH materiality with substantial impact on earnings, capital, or strategic decisions; it requires annual independent validation and the highest level of documentation rigor.

## 4. Inputs

_No inputs recorded. Per SR 11-7 §III.B.2, model documentation must describe the data used by the model. Update the inventory with `evidentia model-risk model edit 11b30957-b913-4c13-89ca-bd6b7f850a5f --from-yaml ...`._

...

## 9. Audit trail

Risk statements generated by AI features that reference this model inventory entry carry `model_inventory_ref='11b30957-b913-4c13-89ca-bd6b7f850a5f'`. The full audit trail is reconstructible by querying the risk-store for risk statements whose `model_inventory_ref` field matches this model's `id`.
```

*(Output trimmed at sections 5–8, which template inputs / outputs / assumptions /
monitoring-and-retirement narrative from the record.)*

To write the document to a file instead, pass `--output, -o`. The file is
written **atomically** and Evidentia refuses to clobber an existing path unless
you add `--force`:

**Bash / Linux / macOS**

```bash
evidentia model-risk doc generate 11b30957-b913-4c13-89ca-bd6b7f850a5f \
  --output reports/model-doc.md
```

**PowerShell (Windows)**

```powershell
evidentia model-risk doc generate 11b30957-b913-4c13-89ca-bd6b7f850a5f `
  --output reports/model-doc.md
```

```
Wrote model documentation to
C:\...\reports\model-doc.md (2177 chars).
```

## Step 6 — Generate a validation-cycle report

`validation-report generate` renders an SR 11-7 §III.D validation report — an
executive summary, a severity-by-status finding-disposition matrix, a detailed
findings table, per-finding remediation narrative, and the tier-driven cadence
context. It is likewise **templated from the record with no LLM dependency**.
For a model with logged `validation_findings`, the executive summary also emits a
HIGH-open warning callout. Our demo model has none recorded yet, so the
disposition matrix is empty:

```bash
evidentia model-risk validation-report generate 11b30957-b913-4c13-89ca-bd6b7f850a5f
```

```markdown
# Validation Report — Retail Credit PD Scorecard

_SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC Bulletin 2026-13a aligned validation report. Generated by Evidentia v0.10.11 from ModelInventory record._

## Executive summary

| Field | Value |
| --- | --- |
| Model ID | `11b30957-b913-4c13-89ca-bd6b7f850a5f` |
| Model name | Retail Credit PD Scorecard |
| Tier | tier_1 |
| Methodology | ml |
| Provenance | internal |
| Owner | quant.validation@example.com |
| Last validation | 2026-05-01 |
| Next validation due | 2027-05-01 |
| Total findings | 0 |

## Finding disposition

| Severity | Open | Remediated | Accepted | Deferred | Total |
| --- | --- | --- | --- | --- | --- |
| (no findings) | 0 | 0 | 0 | 0 | 0 |

## Findings detail

_No validation findings recorded._

## Validation cycle context

**Tier `tier_1` cadence**: annual independent validation per SR 11-7 §III.D.

This report reflects validation activity through 2026-05-01. Subsequent validation cycles will append new findings to the ModelInventory record; re-run `evidentia model-risk validation-report generate 11b30957-b913-4c13-89ca-bd6b7f850a5f` to refresh.
```

Like `doc generate`, this verb accepts `--output, -o` (atomic write) and
`--force` (overwrite an existing path).

## What's next

- **The regulatory composition story** — how the TPRM vendor inventory, this
  model inventory, the governance effective-challenge log, and AI-generated risk
  statements compose into one examiner-defensible toolchain:
  [Financial-services regulatory overlay](../5-compliance/financial-sector-overlay.md).
- **Effective-challenge logging** (SR 11-7 §III.D): the
  `evidentia governance challenge` verbs in the
  [CLI reference](../4-reference/cli.md#evidentia-governance-challenge).
- **Every flag, default, and enum** for this command group:
  [CLI reference → `evidentia model-risk`](../4-reference/cli.md#evidentia-model-risk).

## Got stuck?

- **`Error: Invalid model ID format (expected UUID string): 'not-a-uuid'`** —
  the ID argument must be the model's full UUID. Copy it from the first column
  of `evidentia model-risk model list` (or the `id` field of `list --json`).

- **`Error: No model with ID '…' found in the store.`** — the ID is a valid
  UUID but no record exists under it in the active store. Confirm you are
  pointing at the right inventory: if you set `EVIDENTIA_MODEL_STORE_DIR` for the
  add, the same variable must be set for every subsequent command.

- **`Error: Missing required field(s): --purpose, --owner. (Or pass
  --from-yaml.)`** — the atomic-flag add path requires `--purpose` and `--owner`
  in addition to the other fields. Supply them, or load a complete record from a
  YAML file with `--from-yaml`.

- **`Error: Invalid model data: … vendor-provenance models must set vendor_id
  …`** — a `--vendor-or-internal vendor` model must cross-link a TPRM vendor via
  `--vendor-id`. The inverse also holds: an `internal` model that passes
  `--vendor-id` is rejected with *"internal-provenance models must not set
  `vendor_id`"*.

- **`Error: Invalid model data: … Input should be 'tier_1', 'tier_2' or
  'tier_3'`** (or the analogous methodology message listing `statistical`, `ml`,
  `rules_based`, `llm`, `expert_judgment`, `hybrid`) — `--tier` and
  `--methodology` are closed enums; pass exactly one listed value.

- **`Error: … already exists; pass --force to overwrite.`** — `doc generate` and
  `validation-report generate` never silently overwrite an output file. Add
  `--force` to replace it intentionally.
