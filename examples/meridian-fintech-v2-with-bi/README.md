# Meridian fintech v2 — full audit cycle with BI dashboards

**Companion to [`examples/meridian-fintech-v2/`](../meridian-fintech-v2/)**.
This walkthrough shows the v0.7.8 end-to-end pattern: collect
evidence from cloud data warehouses, run gap analysis against the
Meridian baseline, generate AI-driven risk statements, and publish
to **both** Tableau and Power BI for the risk-officer + audit-
committee dashboards.

The base inventory + framework configuration is reused from
`examples/meridian-fintech-v2/` (48 controls × NIST 800-53 Moderate
+ SOC 2 + GDPR). Only the cloud-DW + BI-publish steps are new in
v0.7.8.

> **Read this first**: [`docs/cloud-dw-collectors.md`](../../docs/cloud-dw-collectors.md)
> + [`docs/bi-integrations.md`](../../docs/bi-integrations.md). They
> cover the install + auth setup that this walkthrough assumes is
> already in place.

---

## Scenario

Meridian Financial Inc. is mid-audit prep for FFIEC IT Examination
+ SOC 2 Type II. The compliance team's evidence-collection runbook
already covers AWS + GitHub via the v0.5.x collectors. Two
quarters ago they migrated their analytics platform from on-prem
Oracle to **Snowflake**, and their data-science team uses
**Databricks** for model development. The compliance team needs:

1. Read-only evidence collection from both cloud DWs.
2. Gap analysis against the existing FFIEC + NIST + SOC 2 + GDPR
   inventory (no inventory rewrite required).
3. Risk-officer dashboards in Tableau (the CISO + audit-committee
   tool) AND Power BI (the engineering-leadership tool) — same data,
   two platforms, no manual export.

That's the workflow this demo executes end-to-end.

---

## Prerequisites

```bash
# Install the v0.7.8 collectors + integrations.
pip install "evidentia-collectors[snowflake,databricks]"
pip install "evidentia-integrations[tableau,powerbi]"

# Set the Snowflake audit principal's password env var.
export SNOWFLAKE_PASSWORD='<your snowflake password>'

# Set the Databricks PAT env var.
export DATABRICKS_TOKEN='dapi...'

# Set the Tableau PAT env vars.
export TABLEAU_PAT_NAME='evidentia-audit-pat'
export TABLEAU_PAT_SECRET='<your tableau PAT secret>'

# Set the Power BI service-principal client secret env var.
export POWERBI_CLIENT_SECRET='<your azure ad client secret>'
```

For the principal-setup details (recommended Snowflake role +
Databricks workspace permissions + Tableau + Power BI tenant config),
see the install guides linked above.

---

## Step 1 — Collect cloud-DW evidence

Run both collectors and write the findings to disk. The
`CollectionContext` provenance is preserved per-finding so the
manifests can be embedded in the OSCAL Assessment Results back-
matter later.

```bash
cd examples/meridian-fintech-v2-with-bi

# Snowflake: account_usage views + INFORMATION_SCHEMA policies.
evidentia collect snowflake \
    --account meridian-prod \
    --user EVIDENTIA_AUDIT_RO \
    --warehouse EVIDENTIA_AUDIT_WH \
    --role EVIDENTIA_AUDIT_RO \
    --login-history-window-days 90 \
    --output snowflake-findings.json

# Databricks: workspace API (PAT, clusters, SPs, secret scopes).
evidentia collect databricks \
    --workspace-url https://meridian.cloud.databricks.com \
    --output databricks-findings.json
```

You should see something like:

```
Snowflake findings (meridian-prod): 47 findings written to snowflake-findings.json
Databricks findings (https://meridian.cloud.databricks.com): 23 findings written to databricks-findings.json
```

(Numbers will vary based on your Snowflake user count + Databricks
cluster inventory.)

---

## Step 2 — Run gap analysis

Use the existing Meridian inventory (no changes from
`examples/meridian-fintech-v2/`):

```bash
evidentia gap analyze \
    --inventory ../meridian-fintech-v2/my-controls.yaml \
    --frameworks nist-800-53-rev5-moderate,soc2-tsc \
    --output gap-report.json
```

This produces a `GapAnalysisReport` in `gap-report.json`. The cloud-
DW findings from Step 1 are NOT yet folded in — gap analysis works
off the control inventory, not off the raw evidence stream. (Folding
findings into the inventory state is a v0.8.0+ enhancement.)

---

## Step 3 — Generate AI risk statements (optional)

Convert the highest-priority gaps into NIST SP 800-30 risk
statements:

```bash
evidentia risk generate \
    --gaps gap-report.json \
    --system-context ../meridian-fintech-v2/system-context.yaml \
    --output risks.json \
    --max-risks 10
```

This produces a JSON list of 10 `RiskStatement` objects, each with
full `GenerationContext` provenance (model, temperature,
prompt_hash, run_id) so auditors can trace each statement back to
the exact LLM call.

---

## Step 4 — Publish to Tableau

```bash
evidentia integrations tableau publish \
    --gaps gap-report.json \
    --risks risks.json \
    --server-url https://us-east-1.online.tableau.com \
    --site-id meridian-compliance \
    --project-name "Meridian Audit FY2026"
```

Expected output (Rich table summary):

```
                   Tableau publish result (https://us-east-1.online.tableau.com)
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┓
┃ Dataset                     ┃ Datasource ID                         ┃ Rows ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━┩
│ evidentia-gaps              │ a2b3c4d5-...                          │  142 │
│ evidentia-risks             │ b3c4d5e6-...                          │   10 │
└─────────────────────────────┴───────────────────────────────────────┴──────┘
Skipped: evidentia-collection-runs (collection_runs=None)
```

(The `evidentia-collection-runs` dataset is skipped because we
didn't pass `collection_runs=` — see Step 6 for how to include it.)

---

## Step 5 — Publish to Power BI

```bash
evidentia integrations powerbi publish \
    --gaps gap-report.json \
    --risks risks.json \
    --workspace-id 11111111-1111-1111-1111-111111111111 \
    --tenant-id    22222222-2222-2222-2222-222222222222 \
    --client-id    33333333-3333-3333-3333-333333333333
```

Expected output:

```
Power BI publish result (workspace 11111111-1111-1111-1111-111111111111)
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━┓
┃ Dataset             ┃ Dataset ID                            ┃ Table     ┃ Rows ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━┩
│ evidentia-gaps      │ a2b3c4d5-...                          │ gaps      │  142 │
│ evidentia-risks     │ b3c4d5e6-...                          │ risks     │   10 │
└─────────────────────┴───────────────────────────────────────┴───────────┴──────┘
Skipped: evidentia-collection-runs (collection_runs=None)
```

---

## Step 6 — (Optional) Include collection-run audit trail

To populate the `evidentia-collection-runs` dataset, use the
programmatic API rather than the CLI. The collection-run dataset
is most useful when you're scheduling unattended evidence
collection and want a "did our collection run on time?" dashboard.

```python
import json
from pathlib import Path

from evidentia_collectors.snowflake import SnowflakeCollector
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_integrations.tableau import (
    TableauConfig,
    publish_report,
)

# Run the collector and capture both findings + manifest's context.
with SnowflakeCollector(
    account="meridian-prod",
    user="EVIDENTIA_AUDIT_RO",
    password=os.environ["SNOWFLAKE_PASSWORD"],
) as col:
    findings, manifest = col.collect_v2()

# Extract one CollectionContext per source-system covered.
contexts = [f.collection_context for f in findings]

# Load the gap report from disk.
report = GapAnalysisReport.model_validate_json(Path("gap-report.json").read_text())

# Publish all three datasets.
result = publish_report(
    config=TableauConfig(
        server_url="https://us-east-1.online.tableau.com",
        site_id="meridian-compliance",
        project_name="Meridian Audit FY2026",
    ),
    report=report,
    risks=json.loads(Path("risks.json").read_text()),
    collection_runs=contexts,
)
```

---

## Step 7 — Build the dashboards

In Tableau:

1. Open Tableau Cloud / Server → Site `meridian-compliance` →
   Project `Meridian Audit FY2026`.
2. Create a workbook → connect to the `evidentia-gaps` data
   source.
3. Build a sheet showing gap severity distribution by control
   family. Filter to `status = open` for the executive view.
4. Build a second sheet showing the risk-register narrative
   (`evidentia-risks` data source) — sortable by
   `remediation_priority` ascending.
5. Combine into a dashboard with action filters linking gap rows
   to their associated risk statements.

In Power BI:

1. Open the Power BI workspace by ID.
2. Create a new report → connect to the `evidentia-gaps` Push
   Dataset.
3. Build a similar bar-chart of gap severity by control family.
4. Add a card visual for "Total open gaps" + "Critical gaps"
   counts.
5. Combine into a dashboard.

---

## Refresh cadence — schedule the publish

Both Tableau and Power BI dashboards stay current only as long as
the underlying data sources are refreshed. The recommended cadence
for compliance-evidence dashboards:

- **Weekly**: cloud-DW evidence collection (`evidentia collect`).
- **Weekly**: gap analysis (`evidentia gap analyze`).
- **Monthly**: AI risk-statement regeneration (`evidentia risk
  generate`) — slower-moving than gap inventory.
- **Weekly** (Tableau) / **Daily** (Power BI): `evidentia
  integrations <platform> publish`.

Schedule via cron / GitHub Actions / Azure Automation / etc. The
publishes are idempotent: re-running with the same dataset names
overwrites in place (Tableau) or full-refreshes (Power BI default).

---

## Troubleshooting

- **Snowflake `account_usage` views return empty** — the audit
  principal lacks `MONITOR USAGE` on the account, OR it's been
  fewer than 45 minutes since the data was generated (account_usage
  has up to 45-minute latency for most views, up to 3 hours for
  LOGIN_HISTORY).
- **Databricks PAT-inventory only shows the audit principal's own
  PATs** — the principal lacks `token_management` permission. Either
  grant it (recommended) or accept the partial coverage as a
  documented BLIND_SPOT in the OSCAL Assessment Results.
- **Tableau publish 401** — PAT has expired or been revoked.
  Generate a new PAT in Tableau settings and update the
  `TABLEAU_PAT_SECRET` env var.
- **Power BI 403 on dataset operations** — the service principal
  isn't a Member of the target workspace. Add it via Workspace
  settings → Access → Member.

---

## What's missing (documented gaps)

- **No actual `.tbw` / `.pbit` template** in this demo. Building
  the starter Tableau workbook + Power BI report templates is
  intentional out-of-scope for v0.7.8 — they're operator-built
  on top of the published data sources, and the dashboard design
  is org-specific.
- **No screenshots of the resulting dashboards** in this README
  — adding those requires a live Tableau + Power BI environment
  which isn't available in CI. v0.7.9+ will add screenshots once
  a maintainer-run end-to-end test environment is wired up.
- **No collection-run dataset in the CLI flow** — the CLI doesn't
  yet have a way to thread `collection_runs` through. See Step 6
  for the programmatic workaround. Documented as a v0.7.9+
  enhancement.
