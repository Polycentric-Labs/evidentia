# Track governance metrics, Three Lines, and workflows

The `evidentia governance` command group turns the qualitative side of a GRC
program — risk indicators, independent challenge, line-of-defense separation,
and approval processes — into auditable, file-backed records you can diff across
review cycles. This guide walks the whole group end to end: define and observe
KRI / KPI / KGI metrics, log Effective Challenge, produce a Three-Lines-of-Defense
distribution report, and drive a process-as-code approval workflow from a YAML
template.

## Prerequisites

- **No credentials, network, or server.** Every command here is local: records
  persist to JSON files under a platform user-data directory, or wherever you
  point the per-surface store env vars.
- **Set UTF-8 output once per shell.** Evidentia emits Unicode (the ⚠️ crossover
  callout, box-drawing tables). On Windows `cp1252` consoles, export this first
  so a stray character cannot crash a command:

  **Bash / Linux / macOS**

  ```bash
  export PYTHONIOENCODING=utf-8
  ```

  **PowerShell (Windows)**

  ```powershell
  $env:PYTHONIOENCODING = "utf-8"
  ```

- **Optional: redirect the stores into a scratch directory.** Each governance
  surface has its own store-directory override. Point them at a throwaway folder
  to keep a demo (or CI run) isolated from your real records:

  **Bash / Linux / macOS**

  ```bash
  export EVIDENTIA_METRIC_STORE_DIR="$PWD/.gov-demo/metrics"
  export EVIDENTIA_CHALLENGE_STORE_DIR="$PWD/.gov-demo/challenges"
  export EVIDENTIA_WORKFLOW_STORE_DIR="$PWD/.gov-demo/workflows"
  ```

  **PowerShell (Windows)**

  ```powershell
  $env:EVIDENTIA_METRIC_STORE_DIR = "$PWD\.gov-demo\metrics"
  $env:EVIDENTIA_CHALLENGE_STORE_DIR = "$PWD\.gov-demo\challenges"
  $env:EVIDENTIA_WORKFLOW_STORE_DIR = "$PWD\.gov-demo\workflows"
  ```

  The directories are created on first write. If you omit these, Evidentia uses
  a `platformdirs`-backed user-data location. (The Three-Lines report reads only
  a YAML file you supply and has no store of its own.)

## The four governance surfaces

`evidentia governance` has four independent subgroups. Three persist records;
one is a pure function of an input file:

| Subgroup | What it tracks | Persists to | Key concept |
| --- | --- | --- | --- |
| `metrics` | KRI / KPI / KGI definitions + dated observations | `EVIDENTIA_METRIC_STORE_DIR` | A metric's `direction` + thresholds derive a `comfortable` / `watch` / `breach` status from its latest observation. |
| `challenge` | Effective-Challenge log entries (SR 11-7 §III.D) | `EVIDENTIA_CHALLENGE_STORE_DIR` | Each entry names an independent challenger, the model challenged, the substance, and an outcome. |
| `workflow` | Process-as-code approval / review cycles | `EVIDENTIA_WORKFLOW_STORE_DIR` | An ordered list of steps, each transitioning `pending → in_progress → approved / rejected / skipped`, forward-only. |
| `lines-report` | Three-Lines-of-Defense distribution | _(none — reads a YAML overlay)_ | Flags any owner classified across more than one line as a regulator-noted anti-pattern. |

The frozen enums you will see throughout:

- **Metric kind** — `kri` (leading risk indicator), `kpi` (lagging process
  metric), `kgi` (outcome / goal metric).
- **Metric direction** — `higher_is_worse` (e.g. failed-login rate) or
  `higher_is_better` (e.g. patch coverage).
- **Metric status** (derived) — `comfortable`, `watch`, `breach`, `no_data`.
- **Challenge outcome** — `accepted`, `rejected`, `modify`, `pending`.
- **Workflow step status** — `pending`, `in_progress`, `approved`, `rejected`,
  `skipped`.

> The Pydantic field names and enum values for these records are part of
> Evidentia's stable surface, so JSON exports (`--json`) deserialize forward
> within a major version. See
> [Concepts → Frozen surfaces and stability](../3-concepts/frozen-surfaces-and-stability.md).

## Step 1 — Define a metric (KRI)

Create a metric once; you record observations against it over time. `--name`,
`--description`, `--kind`, `--direction`, and `--unit` are required. Thresholds
are optional but unlock automatic status flagging.

**Bash / Linux / macOS**

```bash
evidentia governance metrics add \
  --name "Failed-login rate" \
  --description "Failed authentications per 1,000 logins; a leading indicator of credential-stuffing pressure." \
  --kind kri \
  --direction higher_is_worse \
  --unit "per 1000 logins" \
  --owner-email ciso@bank.example \
  --warning-threshold 3.0 \
  --critical-threshold 5.0
```

**PowerShell (Windows)**

```powershell
evidentia governance metrics add `
  --name "Failed-login rate" `
  --description "Failed authentications per 1,000 logins; a leading indicator of credential-stuffing pressure." `
  --kind kri `
  --direction higher_is_worse `
  --unit "per 1000 logins" `
  --owner-email ciso@bank.example `
  --warning-threshold 3.0 `
  --critical-threshold 5.0
```

```
Added metric Failed-login rate (id: 43b2dd89-82c1-4678-b0de-c04eb452fbde)
```

Key flags:

- `--kind` accepts `kri` / `kpi` / `kgi`; `--direction` accepts
  `higher_is_worse` / `higher_is_better`. An unknown value exits non-zero and
  prints the valid set.
- `--warning-threshold` / `--critical-threshold` are read with direction-aware
  semantics. For a `higher_is_worse` metric, a value **at or above** the
  critical threshold is a `breach`; at or above warning is `watch`. Omit a
  threshold and that band can never trigger.

Copy the printed UUID — every `observe` / `show` / `delete` call takes it.

## Step 2 — Record observations over time

Each observation is a dated value. The command echoes the metric's *current*
status, recomputed from the latest observation against your thresholds:

**Bash / Linux / macOS**

```bash
evidentia governance metrics observe 43b2dd89-82c1-4678-b0de-c04eb452fbde \
  --value 2.1 --observed-at 2026-03-01 --note "Baseline quarter."
evidentia governance metrics observe 43b2dd89-82c1-4678-b0de-c04eb452fbde \
  --value 3.4 --observed-at 2026-04-01 --note "Uptick after partner SSO migration."
evidentia governance metrics observe 43b2dd89-82c1-4678-b0de-c04eb452fbde \
  --value 5.6 --observed-at 2026-05-01 --note "Credential-stuffing campaign detected."
```

**PowerShell (Windows)**

```powershell
evidentia governance metrics observe 43b2dd89-82c1-4678-b0de-c04eb452fbde `
  --value 2.1 --observed-at 2026-03-01 --note "Baseline quarter."
evidentia governance metrics observe 43b2dd89-82c1-4678-b0de-c04eb452fbde `
  --value 3.4 --observed-at 2026-04-01 --note "Uptick after partner SSO migration."
evidentia governance metrics observe 43b2dd89-82c1-4678-b0de-c04eb452fbde `
  --value 5.6 --observed-at 2026-05-01 --note "Credential-stuffing campaign detected."
```

```
Recorded observation 2.1 per 1000 logins on 2026-03-01 for Failed-login rate;
current status: comfortable
Recorded observation 3.4 per 1000 logins on 2026-04-01 for Failed-login rate;
current status: watch
Recorded observation 5.6 per 1000 logins on 2026-05-01 for Failed-login rate;
current status: breach
```

`--value` and `--observed-at` (ISO-8601 `YYYY-MM-DD`) are required. "Latest" is
determined by `observed_at`, not insertion order, so back-dating an older
reading will not change the current status if a newer observation exists.

## Step 3 — Add a second metric and review the list

Add a `kpi` with the opposite direction so the dashboard has more than one kind.
For a `higher_is_better` metric the threshold comparison flips: a value **at or
below** critical is a `breach`.

**Bash / Linux / macOS**

```bash
evidentia governance metrics add \
  --name "Critical-patch coverage" \
  --description "Share of HIGH/CRITICAL CVEs patched within SLA across the fleet." \
  --kind kpi \
  --direction higher_is_better \
  --unit "%" \
  --owner-email patch-mgmt@bank.example \
  --warning-threshold 95.0 \
  --critical-threshold 90.0
evidentia governance metrics observe <kpi-id> \
  --value 97.5 --observed-at 2026-05-01 --note "Within SLA target."
```

**PowerShell (Windows)**

```powershell
evidentia governance metrics add `
  --name "Critical-patch coverage" `
  --description "Share of HIGH/CRITICAL CVEs patched within SLA across the fleet." `
  --kind kpi `
  --direction higher_is_better `
  --unit "%" `
  --owner-email patch-mgmt@bank.example `
  --warning-threshold 95.0 `
  --critical-threshold 90.0
evidentia governance metrics observe <kpi-id> `
  --value 97.5 --observed-at 2026-05-01 --note "Within SLA target."
```

List the inventory. The table shows each metric's derived status and latest
value:

```bash
evidentia governance metrics list
```

```
                          Metrics inventory (2 total)
┌──────────┬─────────────────────────┬──────┬──────────────────┬─────────────────┬─────────────┬────────┐
│ ID       │ Name                    │ Kind │ Direction        │ Unit            │ Status      │ Latest │
├──────────┼─────────────────────────┼──────┼──────────────────┼─────────────────┼─────────────┼────────┤
│ bb2a04b0 │ Critical-patch coverage │ kpi  │ higher_is_better │ %               │ comfortable │ 97.5   │
│ 43b2dd89 │ Failed-login rate       │ kri  │ higher_is_worse  │ per 1000 logins │ breach      │ 5.6    │
└──────────┴─────────────────────────┴──────┴──────────────────┴─────────────────┴─────────────┴────────┘
```

Filter by kind and emit machine-readable JSON for pipelines. The JSON carries
the full observation history:

```bash
evidentia governance metrics list --kind kri --json
```

```jsonc
[
  {
    "id": "43b2dd89-82c1-4678-b0de-c04eb452fbde",
    "name": "Failed-login rate",
    "description": "Failed authentications per 1,000 logins; a leading indicator of credential-stuffing pressure.",
    "kind": "kri",
    "direction": "higher_is_worse",
    "unit": "per 1000 logins",
    "owner_email": "ciso@bank.example",
    "warning_threshold": 3.0,
    "critical_threshold": 5.0,
    "observations": [
      { "observed_at": "2026-03-01", "value": 2.1, "note": "Baseline quarter." },
      { "observed_at": "2026-04-01", "value": 3.4, "note": "Uptick after partner SSO migration." },
      { "observed_at": "2026-05-01", "value": 5.6, "note": "Credential-stuffing campaign detected." }
    ],
    "notes": null
    // created_at / updated_at / evidentia_version metadata elided
  }
]
```

## Step 4 — Inspect one metric in full

`show` prints the definition plus the full chronologically-sorted observation
log:

```bash
evidentia governance metrics show 43b2dd89-82c1-4678-b0de-c04eb452fbde
```

```
Failed-login rate  (43b2dd89-82c1-4678-b0de-c04eb452fbde)
  Kind:               kri
  Direction:          higher_is_worse
  Unit:               per 1000 logins
  Owner:              ciso@bank.example
  Warning threshold:  3.0
  Critical threshold: 5.0
  Status:             breach
  Description:        Failed authentications per 1,000 logins; a leading indicator of credential-stuffing pressure.
  Observations (3):
    - 2026-03-01: 2.1 per 1000 logins — Baseline quarter.
    - 2026-04-01: 3.4 per 1000 logins — Uptick after partner SSO migration.
    - 2026-05-01: 5.6 per 1000 logins — Credential-stuffing campaign detected.
```

Add `--json` for the machine-readable form. (Both forms also carry
created/updated timestamps and the recording Evidentia version, trimmed here.)

## Step 5 — Generate the metrics dashboard

`report` aggregates every metric into a deterministic Markdown dashboard:
a status summary (breach-first), then per-kind KRI / KPI / KGI tables. Same
inputs produce byte-identical output, so you can commit the report and
audit-diff it across cycles.

```bash
evidentia governance metrics report
```

```markdown
# Governance Metrics Dashboard

_Aggregate view across 2 metric(s) — KRI / KPI / KGI classification per IIA + COSO ERM frameworks._

> ⚠️ **1 metric(s) in BREACH state.** Review the Per-kind sections below; documented escalation paths apply.

| Status | Count |
| --- | --- |
| BREACH | 1 |
| WATCH | 0 |
| COMFORTABLE | 1 |
| NO_DATA | 0 |
| **Total** | **2** |

## KRI — Key Risk Indicators (leading metrics)

| Name | Latest | Status | Warn / Crit | Owner |
| --- | --- | --- | --- | --- |
| Failed-login rate | 5.6 per 1000 logins | breach | 3.0 / 5.0 | ciso@bank.example |

## KPI — Key Performance Indicators (lagging process metrics)

| Name | Latest | Status | Warn / Crit | Owner |
| --- | --- | --- | --- | --- |
| Critical-patch coverage | 97.5 % | comfortable | 95.0 / 90.0 | patch-mgmt@bank.example |
```

Pass `-o report.md` (with `--force` to overwrite) to write the report to a file
instead of stdout.

## Step 6 — Log an Effective Challenge

The Effective-Challenge log records independent challenge of a model — the
SR 11-7 §III.D evidence that second-line review actually pushed back. The
`--subject-model-id` is a free-text reference to a `ModelInventory.id` (it is
*not* validated against the model store, so you can log a challenge before, or
independently of, an inventory entry — see
[Manage a model-risk inventory](manage-model-risk.md)).

**Bash / Linux / macOS**

```bash
evidentia governance challenge add \
  --subject-model-id "retail-credit-pd-v3" \
  --challenger-email "mrm-director@bank.example" \
  --challenger-role "MRM Director (2nd line)" \
  --challenge-date 2026-05-12 \
  --challenge-topic "PD calibration drift" \
  --challenge-substance "The probability-of-default calibration was last refit on 2023 data; recent vintages show a 12% under-prediction in the subprime tier. Challenge the owner to re-estimate before the Q3 model-risk committee." \
  --outcome modify \
  --outcome-rationale "Owner agreed to refit on 2024-2025 vintages and re-present." \
  --resolved-at 2026-05-20
```

**PowerShell (Windows)**

```powershell
evidentia governance challenge add `
  --subject-model-id "retail-credit-pd-v3" `
  --challenger-email "mrm-director@bank.example" `
  --challenger-role "MRM Director (2nd line)" `
  --challenge-date 2026-05-12 `
  --challenge-topic "PD calibration drift" `
  --challenge-substance "The probability-of-default calibration was last refit on 2023 data; recent vintages show a 12% under-prediction in the subprime tier. Challenge the owner to re-estimate before the Q3 model-risk committee." `
  --outcome modify `
  --outcome-rationale "Owner agreed to refit on 2024-2025 vintages and re-present." `
  --resolved-at 2026-05-20
```

```
Logged challenge PD calibration drift (id: 7567facc-9880-4e94-98c6-8c695d9b23da)
```

`--subject-model-id`, `--challenger-email`, `--challenger-role`,
`--challenge-date`, `--challenge-topic`, and `--challenge-substance` are
required. `--outcome` defaults to `pending`; the valid set is
`accepted` / `rejected` / `modify` / `pending`. You can omit `--response`,
`--outcome-rationale`, and `--resolved-at` and fill them in on a later entry as
the challenge resolves.

## Step 7 — List and inspect the challenge log

Add a second, still-open challenge so the log has more than one row:

**Bash / Linux / macOS**

```bash
evidentia governance challenge add \
  --subject-model-id "aml-txn-monitoring-v2" \
  --challenger-email "independent-validator@bank.example" \
  --challenger-role "Independent Validator (2nd line)" \
  --challenge-date 2026-05-26 \
  --challenge-topic "Alert-threshold tuning evidence" \
  --challenge-substance "Request the back-testing evidence behind the lowered transaction-monitoring alert threshold; the change log lacks a documented false-negative analysis."
```

**PowerShell (Windows)**

```powershell
evidentia governance challenge add `
  --subject-model-id "aml-txn-monitoring-v2" `
  --challenger-email "independent-validator@bank.example" `
  --challenger-role "Independent Validator (2nd line)" `
  --challenge-date 2026-05-26 `
  --challenge-topic "Alert-threshold tuning evidence" `
  --challenge-substance "Request the back-testing evidence behind the lowered transaction-monitoring alert threshold; the change log lacks a documented false-negative analysis."
```

`list` shows the log newest-first by `challenge_date`:

```bash
evidentia governance challenge list
```

```
                                       Effective Challenge log (2 matching)
┌──────────┬────────────┬──────────────────────────┬───────────────────────────────┬──────────────────────────┬─────────┐
│ ID       │ Date       │ Topic                    │ Challenger                    │ Role                     │ Outcome │
├──────────┼────────────┼──────────────────────────┼───────────────────────────────┼──────────────────────────┼─────────┤
│ 2101df9e │ 2026-05-26 │ Alert-threshold tuning   │ independent-validator@bank.e… │ Independent Validator    │ pending │
│          │            │ evidence                 │                               │ (2nd line)               │         │
│ 7567facc │ 2026-05-12 │ PD calibration drift     │ mrm-director@bank.example     │ MRM Director (2nd line)  │ modify  │
└──────────┴────────────┴──────────────────────────┴───────────────────────────────┴──────────────────────────┴─────────┘
```

Filter with `--subject-model-id` or `--outcome`, and add `--json` for the
machine-readable array. `show` prints one record in full (trim the trailing
metadata line in your own runbooks):

```bash
evidentia governance challenge show 7567facc-9880-4e94-98c6-8c695d9b23da
```

```
PD calibration drift  (7567facc-9880-4e94-98c6-8c695d9b23da)
  Subject model:      retail-credit-pd-v3
  Challenger:         mrm-director@bank.example (MRM Director (2nd line))
  Challenge date:     2026-05-12
  Outcome:            modify
  Resolved:           2026-05-20
  Substance:          The probability-of-default calibration was last refit on 2023 data; recent vintages show a 12% under-prediction in the subprime tier. Challenge the owner to re-estimate before the Q3 model-risk committee.
  Outcome rationale:  Owner agreed to refit on 2024-2025 vintages and re-present.
```

## Step 8 — Produce a Three-Lines-of-Defense report

`lines-report` reads a YAML overlay of owners classified by line of defense and
renders a deterministic distribution report. Its headline value is the
**crossover warning**: any individual classified under more than one line is a
regulator-noted anti-pattern (you cannot run first-line execution *and* provide
second-line oversight on the same activity).

Write the overlay as a YAML **list** of owner records. `email` and
`line_of_defense` (`first` / `second` / `third`) are required per entry; `team`
and `title` are optional. This example deliberately lists `model-owner@bank.example`
under both `first` and `second` to trigger the warning:

```yaml
# owners.yaml
- email: underwriter@bank.example
  line_of_defense: first
  team: Loan Origination
  title: Senior Underwriter
- email: model-owner@bank.example
  line_of_defense: first
  team: Model Development
  title: Lead Quant
- email: mrm-director@bank.example
  line_of_defense: second
  team: MRM
  title: Director, Model Risk
- email: compliance-officer@bank.example
  line_of_defense: second
  team: Compliance
  title: BSA/AML Officer
- email: internal-audit@bank.example
  line_of_defense: third
  team: Internal Audit
  title: VP, Internal Audit
- email: model-owner@bank.example
  line_of_defense: second
  team: MRM
  title: Acting reviewer (rotation)
```

```bash
evidentia governance lines-report --classifications owners.yaml
```

```markdown
# Three Lines of Defense Distribution

_IIA Three Lines Model 2020 distribution across 6 classified owners._

| Line | Count | Share |
| --- | --- | --- |
| first | 2 | 33.3% |
| second | 3 | 50.0% |
| third | 1 | 16.7% |
| **Total** | **6** | 100.0% |

## 3LOD crossover warning

> ⚠️ **1 owner(s) classified across multiple lines of defense.** Per IIA Three Lines Model + regulator expectations (FFIEC + OCC + FRB), an individual cannot simultaneously perform 1st-line execution and 2nd-line oversight, or 2nd-line oversight and 3rd-line audit assurance, on the same activity. Review the table below; if these are intentional (e.g., temporary cross-functional rotation), document the rationale.

| Owner email | Crossover lines |
| --- | --- |
| model-owner@bank.example | first / second |

## First line

| Email | Team | Title |
| --- | --- | --- |
| model-owner@bank.example | Model Development | Lead Quant |
| underwriter@bank.example | Loan Origination | Senior Underwriter |

## Second line

| Email | Team | Title |
| --- | --- | --- |
| compliance-officer@bank.example | Compliance | BSA/AML Officer |
| model-owner@bank.example | MRM | Acting reviewer (rotation) |
| mrm-director@bank.example | MRM | Director, Model Risk |

## Third line

| Email | Team | Title |
| --- | --- | --- |
| internal-audit@bank.example | Internal Audit | VP, Internal Audit |

## Team participation across lines

| Team | Lines participating |
| --- | --- |
| Compliance | second |
| Internal Audit | third |
| Loan Origination | first |
| MRM | second |
| Model Development | first |
```

Pass `-o lines.md --force` to write to a file. A clean separation (no crossover
warning) is the auditor-friendly outcome; the warning section appears only when
an overlap exists.

## Step 9 — Instantiate an approval workflow from a template

`workflow run` reads a YAML **mapping** describing a process and persists a live
workflow instance. The mapping fields map directly to the workflow record:
`name`, `description`, and `initiator` are required; `template` and `subject`
are optional traceability fields; `steps` is an ordered list where each step
needs a `name` and a `required_role` (with optional `description` and an
`sla_days` integer ≥ 1).

```yaml
# change-approval.yaml
name: Credit-model v3 promotion to production
template: change-approval-v1
description: Material change approval for promoting the retail-credit PD model v3 to production.
subject: retail-credit-pd-v3
initiator: model-owner@bank.example
steps:
  - name: Model owner submission
    description: Owner packages performance evidence + change rationale.
    required_role: 1st-line model owner
    sla_days: 5
  - name: MRM 2nd-line review
    description: Independent model-risk review of calibration + back-testing.
    required_role: MRM Director (2nd line)
    sla_days: 14
  - name: Internal audit assurance
    description: 3rd-line check that the change followed the documented SDLC.
    required_role: Internal Audit (3rd line)
    sla_days: 21
  - name: CAB approval
    description: Change Advisory Board final sign-off.
    required_role: CAB chair
    sla_days: 7
```

```bash
evidentia governance workflow run --template change-approval.yaml
```

```
Started workflow Credit-model v3 promotion to production (id: 002dacb9-baed-4dd8-993b-9cd45c171f65); status: in_progress
```

The first step is auto-promoted from `pending` to `in_progress` on instantiation,
so the workflow is active immediately. Confirm with `status` (which prints the
clean enum values):

```bash
evidentia governance workflow status 002dacb9-baed-4dd8-993b-9cd45c171f65
```

```
Credit-model v3 promotion to production  (002dacb9-baed-4dd8-993b-9cd45c171f65)
  Subject:     retail-credit-pd-v3
  Initiator:   model-owner@bank.example
  Status:      in_progress
  Description: Material change approval for promoting the retail-credit PD model v3 to production.
  Steps (4):
    0. Model owner submission  (1st-line model owner) SLA 5d → in_progress (0 event(s))
    1. MRM 2nd-line review  (MRM Director (2nd line)) SLA 14d → pending (0 event(s))
    2. Internal audit assurance  (Internal Audit (3rd line)) SLA 21d → pending (0 event(s))
    3. CAB approval  (CAB chair) SLA 7d → pending (0 event(s))
```

## Step 10 — Advance the workflow through its steps

`advance` transitions one step. `--step` (0-based index), `--new-status`
(`approved` / `rejected` / `skipped` / `in_progress`), and `--actor` are
required; `--note` records the rationale. Approving a step auto-promotes the
next `pending` step to `in_progress`, and approving the last step flips the
whole workflow to `approved`.

**Bash / Linux / macOS**

```bash
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 \
  --step 0 --new-status approved --actor model-owner@bank.example \
  --note "Evidence pack submitted: AUC 0.81, KS 0.42."
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 \
  --step 1 --new-status approved --actor mrm-director@bank.example \
  --note "Calibration acceptable on 2024-2025 vintages."
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 \
  --step 2 --new-status approved --actor internal-audit@bank.example \
  --note "SDLC adherence confirmed."
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 \
  --step 3 --new-status approved --actor cab-chair@bank.example \
  --note "CAB approved for 2026-06-01 release window."
```

**PowerShell (Windows)**

```powershell
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 `
  --step 0 --new-status approved --actor model-owner@bank.example `
  --note "Evidence pack submitted: AUC 0.81, KS 0.42."
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 `
  --step 1 --new-status approved --actor mrm-director@bank.example `
  --note "Calibration acceptable on 2024-2025 vintages."
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 `
  --step 2 --new-status approved --actor internal-audit@bank.example `
  --note "SDLC adherence confirmed."
evidentia governance workflow advance 002dacb9-baed-4dd8-993b-9cd45c171f65 `
  --step 3 --new-status approved --actor cab-chair@bank.example `
  --note "CAB approved for 2026-06-01 release window."
```

```
Advanced step 3 of Credit-model v3 promotion to production to approved; workflow status: approved
```

Steps execute **in order**: you cannot advance a step that is not the active
one, and you cannot rewind a terminal (`approved` / `rejected` / `skipped`)
step. To bypass a step intentionally, advance it with `--new-status skipped`.
The final state:

```bash
evidentia governance workflow status 002dacb9-baed-4dd8-993b-9cd45c171f65
```

```
Credit-model v3 promotion to production  (002dacb9-baed-4dd8-993b-9cd45c171f65)
  Subject:     retail-credit-pd-v3
  Initiator:   model-owner@bank.example
  Status:      approved
  Description: Material change approval for promoting the retail-credit PD model v3 to production.
  Steps (4):
    0. Model owner submission  (1st-line model owner) SLA 5d → approved (1 event(s))
    1. MRM 2nd-line review  (MRM Director (2nd line)) SLA 14d → approved (1 event(s))
    2. Internal audit assurance  (Internal Audit (3rd line)) SLA 21d → approved (1 event(s))
    3. CAB approval  (CAB chair) SLA 7d → approved (1 event(s))
```

`workflow list` shows all instances newest-first (add `--json` for the array):

```bash
evidentia governance workflow list
```

```
                                          Workflows (1 total)
┌──────────┬──────────────────────────────┬─────────────────────┬──────────────────────────┬──────────┬───────┐
│ ID       │ Name                         │ Subject             │ Initiator                │ Status   │ Steps │
├──────────┼──────────────────────────────┼─────────────────────┼──────────────────────────┼──────────┼───────┤
│ 002dacb9 │ Credit-model v3 promotion to │ retail-credit-pd-v3 │ model-owner@bank.example │ approved │ 4     │
│          │ production                   │                     │                          │          │       │
└──────────┴──────────────────────────────┴─────────────────────┴──────────────────────────┴──────────┴───────┘
```

## Step 11 — Emit the workflow audit log

`workflow log` renders a deterministic Markdown audit log: a header, a per-step
status table, and a timestamped, actor-tagged event narrative — the artifact you
hand to an auditor to show *who approved what, when, and why*. (A rejected
workflow gets a prominent REJECTED callout at the top.)

```bash
evidentia governance workflow log 002dacb9-baed-4dd8-993b-9cd45c171f65
```

```markdown
# Workflow Audit Log — Credit-model v3 promotion to production

_Process-as-code governance workflow log per v0.7.11 P1.5 G5._

**ID**: `002dacb9-baed-4dd8-993b-9cd45c171f65`
**Subject**: retail-credit-pd-v3
**Initiator**: model-owner@bank.example
**Status**: `approved`
**Description**: Material change approval for promoting the retail-credit PD model v3 to production.

## Steps

| # | Name | Required role | Status | SLA | Events |
| --- | --- | --- | --- | --- | --- |
| 0 | Model owner submission | 1st-line model owner | approved | 5d | 1 |
| 1 | MRM 2nd-line review | MRM Director (2nd line) | approved | 14d | 1 |
| 2 | Internal audit assurance | Internal Audit (3rd line) | approved | 21d | 1 |
| 3 | CAB approval | CAB chair | approved | 7d | 1 |

## Event narrative

### Step 0 — Model owner submission (`approved`)

**Required role**: 1st-line model owner

**Description**: Owner packages performance evidence + change rationale.

Events:

- `2026-05-30T06:52:52.353750+00:00` **model-owner@bank.example**: in_progress → approved — Evidence pack submitted: AUC 0.81, KS 0.42.

### Step 1 — MRM 2nd-line review (`approved`)

...
```

(The narrative continues with one section per step; the `Created` / `Updated`
header timestamp lines are trimmed above.) Pass `-o workflow-log.md --force` to
write to a file you can commit alongside the change record.

## What's next

- **The CLI reference** for the authoritative flag tables:
  [`evidentia governance`](../4-reference/cli.md#evidentia-governance).
- **Model-risk inventories** — the `--subject-model-id` you challenge in Step 6
  references a record from
  [Manage a model-risk inventory](manage-model-risk.md), which also generates
  SR 11-7 model documentation and validation-cycle reports.
- **Surface stability** — why the metric / challenge / workflow JSON schemas are
  safe to build on:
  [Concepts → Frozen surfaces and stability](../3-concepts/frozen-surfaces-and-stability.md).
- **Recurring assessment cadences** that complement KRI/KPI tracking:
  [CONMON deployment](conmon-deployment.md).

## Got stuck?

- **"No metric with ID … found" / "No workflow with ID … found".** Re-run the
  matching `list` to copy the full UUID. The table's first column is a truncated
  8-character prefix; the commands need the full ID (use `--json` to grab it
  exactly).
- **"Unknown kind … / Unknown direction … / Unknown new-status …".** You passed
  a value outside the enum. The error prints the valid set, e.g.:

  ```
  Error: Unknown new-status 'done'; valid: ['pending', 'in_progress', 'approved', 'rejected', 'skipped']
  ```

- **"Step N is not the active step".** Workflow steps execute in order. You tried
  to advance a step other than the current active one:

  ```
  Error: Step 3 is not the active step (active is index 2); steps must execute in order.
  ```

  Advance the active step first, or `skip` the steps in between with
  `--new-status skipped`.
- **Workflow `run` rejects the template** ("Invalid workflow data" /
  "must be a YAML mapping"). The template is a single YAML *mapping* (not a
  list), `name` / `description` / `initiator` are required at the top level, and
  every step needs `name` + `required_role`. By contrast, the `lines-report`
  `--classifications` file is a YAML *list* of owner records — a common mix-up.
- **A Unicode crash on Windows** (`UnicodeEncodeError` mentioning `cp1252`).
  Export `PYTHONIOENCODING=utf-8` before running — the reports emit the ⚠️
  callout glyph and box-drawing characters.
- **`-o` output "already exists".** The file-writing verbs refuse to clobber by
  default. Re-run with `--force`.
