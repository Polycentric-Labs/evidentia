# BI output integrations

> v0.7.8 P1 — Tableau + Power BI publish integrations. Push
> Evidentia's gap inventory + risk register + collection-run audit
> trail to enterprise dashboard surfaces. Companion to
> [cloud-dw-collectors.md](cloud-dw-collectors.md).

This guide covers two output integrations that ship in
`evidentia-integrations` v0.7.8:

- **Tableau** (`evidentia-integrations[tableau]`) — publishes data
  to Tableau Server / Tableau Cloud as CSV-based data sources.
- **Power BI** (`evidentia-integrations[powerbi]`) — pushes data to
  a Power BI workspace as Push Datasets.

Both follow the same pattern: take an Evidentia
`GapAnalysisReport` (and optionally a list of `RiskStatement`
objects), build three datasets (gap inventory, risk register,
collection-run audit trail), and push them to the configured BI
platform.

---

## Why both Tableau AND Power BI?

- **Tableau** dominates the legacy enterprise + financial-services
  market.
- **Power BI** dominates Microsoft-shop deployments and post-2020
  net-new dashboards.
- Most regulated enterprises run both. Same OSS-substrate
  positioning: Evidentia is the evidence feed, the BI tool is the
  dashboard.

Both integrations ship with the same dataset contract so a single
gap-analysis report can be published to both platforms in one
audit cycle.

---

## The three published datasets

Both integrations create / publish three datasets (named
`evidentia-gaps`, `evidentia-risks`, `evidentia-collection-runs`
by default):

### `evidentia-gaps` (one row per `ControlGap`)

| Column | Type | Notes |
|---|---|---|
| `gap_id` | string | Stable Evidentia gap UUID |
| `organization` | string | From `GapAnalysisReport.organization` |
| `analyzed_at` | datetime | When the gap-analysis run produced this report |
| `framework` / `control_id` / `control_title` | string | What the gap references |
| `control_family` | string | NIST control family for grouping |
| `gap_severity` | string | `critical` / `high` / `medium` / `low` / `informational` |
| `implementation_status` | string | `missing` / `partial` / `planned` / `not_applicable` |
| `status` | string | Lifecycle: `open` / `in_progress` / `remediated` / `accepted` / `not_applicable` |
| `priority_score` | float (Tableau) / Double (Power BI) | Sortable priority |
| `implementation_effort` | string | `small` / `medium` / `large` / `xlarge` |
| `equivalent_controls` | string | Semicolon-joined list of partially-satisfying inventory controls |
| `cross_framework_satisfies` | string | Semicolon-joined list of `framework:control_id` pairs this gap also maps to |
| `jira_issue_key` / `servicenow_ticket_id` | string | Outbound ticketing linkage |
| `assigned_to` / `tags` | string | Workflow metadata |
| `created_at` / `remediated_at` | datetime | Lifecycle timestamps |
| `gap_description` / `remediation_guidance` | string | Narrative cells |

### `evidentia-risks` (one row per `RiskStatement`, NIST SP 800-30 shape)

| Column | Notes |
|---|---|
| `risk_id` | Stable UUID |
| `asset` | The system / data / function at risk |
| `threat_source` / `threat_event` / `vulnerability` | NIST SP 800-30 core fields |
| `predisposing_conditions` | Semicolon-joined list |
| `likelihood` / `likelihood_rationale` | Very_Low → Very_High + free-text |
| `impact` / `impact_rationale` | Same shape |
| `risk_level` | Derived overall level |
| `recommended_controls` | Semicolon-joined NIST 800-53 control IDs |
| `remediation_priority` | Int 1-5 |
| `treatment` / `treatment_rationale` | Disposition |
| `model_used` / `temperature` / `prompt_hash` / `run_id` | AI provenance from `GenerationContext` |
| `risk_description` | Full prose statement |

The AI-provenance columns let auditors trace each AI-generated risk
back to the exact LLM call that produced it — useful for SR 11-7
model-risk evidence (the v0.7.9 financial-services overlay).

### `evidentia-collection-runs` (one row per `CollectionContext`)

| Column | Notes |
|---|---|
| `run_id` | Collection-run ULID |
| `collector_id` | e.g. `snowflake-scan`, `databricks-scan`, `sql-postgres-scan` |
| `collector_version` | Semver of `evidentia-collectors` |
| `collected_at` | UTC timestamp |
| `credential_identity` | The principal (NEVER the secret) |
| `source_system_id` | e.g. `snowflake:ACME-PROD` |
| `filter_applied` | JSON-serialized filter dict |
| `evidentia_version` | Version of `evidentia-core` |

Useful for "did our evidence collection run on time?" dashboards.

---

## Tableau

### Install

```bash
pip install "evidentia-integrations[tableau]"
```

This pulls in `tableauserverclient>=0.30`, the official Python
SDK. Pure Python — no native dependencies.

> **CSV vs `.hyper`**: v0.7.8 ships **CSV-datasource** publish
> because it works on every modern Tableau Server / Cloud version
> without requiring the heavyweight `tableauhyperapi` native
> binary (~100 MB). `.hyper` extract publish is documented as a
> v0.7.9+ enhancement under a separate `[tableau-hyper]` extra.

### Auth

Personal Access Token (PAT) only — username/password auth is being
deprecated by Tableau Cloud and is not exposed by this integration.

1. In Tableau Server / Cloud, go to your user settings → Personal
   Access Tokens → Create.
2. Note the **token name** (the human-readable label) AND the
   **token secret** (the long random string).
3. Set both as env vars:

   ```bash
   export TABLEAU_PAT_NAME='evidentia-audit-pat'
   export TABLEAU_PAT_SECRET='<the long random string>'
   ```

The token name + secret env var names are configurable via
`--pat-name-env` / `--pat-secret-env` flags. The values themselves
are NEVER passed as flag values — only the env-var names.

### CLI

```bash
evidentia integrations tableau publish \
    --gaps gap-report.json \
    --server-url https://us-east-1.online.tableau.com \
    --site-id compliance-team \
    --project-name "Compliance Dashboards" \
    [--risks risks.json] \
    [--no-overwrite]
```

The `--risks` flag is optional. When provided, the file should be a
JSON array of `RiskStatement` objects (the format `evidentia risk
generate` emits).

`--no-overwrite` makes the publish use Tableau's "CreateNew" mode
— fail if the dataset already exists. Default is "Overwrite" mode
(re-running the publish updates the existing data sources in place).

### REST

```bash
# First, save a gap report via /api/gap/analyze (returns a key).
REPORT_KEY=$(curl -X POST http://localhost:8000/api/gap/analyze \
    -H "Content-Type: application/json" \
    -d '{"frameworks": ["nist-800-53-rev5-moderate"], ...}' \
    | jq -r '.report_key')

# Then publish to Tableau:
curl -X POST "http://localhost:8000/api/integrations/tableau/publish/$REPORT_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "server_url": "https://us-east-1.online.tableau.com",
        "site_id": "compliance-team",
        "project_name": "Compliance Dashboards"
    }'
```

The PAT name + secret values NEVER flow through the request body —
the API server reads them server-side from the env vars named in
the body (`pat_name_env` / `pat_secret_env`, defaulting to
`TABLEAU_PAT_NAME` / `TABLEAU_PAT_SECRET`).

### Programmatic use

```python
from evidentia_integrations.tableau import (
    TableauConfig,
    publish_report,
)
from evidentia_core.models.gap import GapAnalysisReport

report = GapAnalysisReport.model_validate_json(open("gap-report.json").read())

config = TableauConfig(
    server_url="https://us-east-1.online.tableau.com",
    site_id="compliance-team",
    project_name="Compliance Dashboards",
)

result = publish_report(config=config, report=report)

for ds in result.datasets:
    print(f"Published {ds.name} ({ds.rows} rows) → {ds.datasource_id}")
```

---

## Power BI

### Install

```bash
pip install "evidentia-integrations[powerbi]"
```

This pulls in `msal>=1.31` (Microsoft Authentication Library for
Python). HTTP calls go through `httpx` (already a base dependency).

### Auth — Azure AD service principal

Power BI Push Datasets require an Azure AD service principal with
`Dataset.ReadWrite.All` permission on the target workspace.

**One-time setup**:

1. Create an Azure AD App Registration in the Azure Portal.
2. Generate a client secret (note: it's only shown once).
3. Grant the App Registration the `Dataset.ReadWrite.All` Power BI
   service application permission, and have an Azure AD admin grant
   admin consent.
4. In your Power BI admin portal, allow service principals to use
   Power BI APIs (this is a tenant-level toggle).
5. Add the service principal as a Member of the target workspace
   (Workspace settings → Access → Member).

Note the three identifiers:

- **Tenant ID** (UUID) — your Azure AD directory ID
- **Client ID** (UUID) — the App Registration's Application (client) ID
- **Workspace ID** (UUID) — the Power BI workspace's ID
- **Client Secret** — the password from step 2

Set the client secret as an env var:

```bash
export POWERBI_CLIENT_SECRET='<your client secret>'
```

### CLI

```bash
evidentia integrations powerbi publish \
    --gaps gap-report.json \
    --workspace-id 11111111-1111-1111-1111-111111111111 \
    --tenant-id 22222222-2222-2222-2222-222222222222 \
    --client-id 33333333-3333-3333-3333-333333333333 \
    [--client-secret-env POWERBI_CLIENT_SECRET] \
    [--risks risks.json] \
    [--no-clear]
```

`--no-clear` makes the publish APPEND rows rather than full-refresh
(default is clear-then-push, which implements full-refresh
semantics — the typical compliance-dashboard expectation).

### REST

```bash
curl -X POST "http://localhost:8000/api/integrations/powerbi/publish/$REPORT_KEY" \
    -H "Content-Type: application/json" \
    -d '{
        "workspace_id": "11111111-1111-1111-1111-111111111111",
        "tenant_id":    "22222222-2222-2222-2222-222222222222",
        "client_id":    "33333333-3333-3333-3333-333333333333"
    }'
```

The client secret value NEVER flows through the request body — the
API server reads it server-side from the env var named in the body
(`client_secret_env`, defaulting to `POWERBI_CLIENT_SECRET`).

### Programmatic use

```python
from evidentia_integrations.powerbi import (
    PowerBIConfig,
    publish_report,
)
from evidentia_core.models.gap import GapAnalysisReport

report = GapAnalysisReport.model_validate_json(open("gap-report.json").read())

config = PowerBIConfig(
    workspace_id="11111111-1111-1111-1111-111111111111",
    tenant_id="22222222-2222-2222-2222-222222222222",
    client_id="33333333-3333-3333-3333-333333333333",
)

result = publish_report(config=config, report=report)

for ds in result.datasets:
    print(
        f"Published {ds.name} ({ds.rows} rows) → "
        f"workspace/{config.workspace_id}/dataset/{ds.dataset_id}/"
        f"table/{ds.table_name}"
    )
```

### Push Datasets — limits + caveats

The Power BI Push Datasets API has documented limits:

- **10,000 rows per push call** — the integration auto-batches at
  this limit.
- **75 columns per dataset** — the Evidentia datasets are well under
  this.
- **5 million rows total per dataset** (FIFO eviction beyond) —
  enough for years of compliance evidence.
- **No PowerQuery / DAX in the source** — Push Datasets are
  schema-fixed; transformations happen on the consumer side
  (the Power BI report).

For very large compliance estates, Power BI Premium / Fabric
capacity may be a better fit (full Tabular Model storage rather
than Push Datasets). That's not in v0.7.8's scope but is documented
as a future enhancement.

---

## Both integrations — full audit-cycle workflow

```bash
# 1. Collect evidence from cloud DWs.
evidentia collect snowflake \
    --account acme-prod --user EVIDENTIA_AUDIT_RO \
    --output snowflake-findings.json

evidentia collect databricks \
    --workspace-url https://acme.cloud.databricks.com \
    --output databricks-findings.json

# 2. (Optional) Generate AI-driven risk statements from gap output.
evidentia risk generate \
    --gaps gap-report.json \
    --output risks.json

# 3. Run gap analysis against your control inventory.
evidentia gap analyze \
    --inventory my-controls.yaml \
    --frameworks nist-800-53-rev5-moderate \
    --output gap-report.json

# 4. Publish to BOTH BI platforms.
evidentia integrations tableau publish \
    --gaps gap-report.json \
    --risks risks.json \
    --server-url https://acme.online.tableau.com \
    --site-id compliance-team

evidentia integrations powerbi publish \
    --gaps gap-report.json \
    --risks risks.json \
    --workspace-id <uuid> \
    --tenant-id <uuid> \
    --client-id <uuid>
```

The same `gap-report.json` + `risks.json` ship to both BI platforms,
so the dashboards are guaranteed to be consistent across teams that
prefer different tools.

---

## Tableau-side dashboard tips

- **Refresh schedule**: Tableau Server / Cloud lets you schedule
  data-source refreshes. Pair the Evidentia publish with a
  scheduled refresh so dashboards stay current.
- **Live connections vs extracts**: CSV data sources are
  extracts by definition. The integration is intended to run
  on a periodic schedule (daily / weekly / per-audit-cycle).
- **Joins**: in Tableau, join `evidentia-gaps` with
  `evidentia-collection-runs` on `framework` (or by
  `gap_severity` × `collector_id` for "evidence-coverage by
  control family" dashboards).

## Power BI-side dashboard tips

- **DirectQuery vs Import**: Push Datasets are import-only by
  design. For DirectQuery, Power BI Premium / Fabric is required.
- **Refresh model**: with `clear_before_push=True` (default), each
  publish replaces the dataset content. Power BI auto-detects the
  change and refreshes downstream reports.
- **Composite models**: Power BI lets you combine the three
  Evidentia datasets in a single composite model — useful for
  building a single executive-summary report on top.

---

## End-to-end demo

See [`examples/meridian-fintech-v2-with-bi/`](../examples/meridian-fintech-v2-with-bi/)
for an end-to-end walkthrough using the Meridian fintech v2
inventory: collect from Snowflake, run gap analysis, generate AI
risk statements, publish to Tableau + Power BI, screenshots of the
resulting dashboards.

---

## Troubleshooting

### Tableau

- **`TableauAuthError: Tableau sign-in failed`** — usually a wrong
  PAT name (the human-readable label) vs. PAT secret pairing.
  Double-check the env vars.
- **`TableauPublishError: Project '...' not found`** — the project
  name doesn't exist on the site. Either create it in Tableau's
  UI or pass `--project-name default`.
- **API version mismatch** — the integration pins to API version
  3.21 by default. Older Tableau Server installations may need
  `TableauConfig.api_version` to be set explicitly to a lower
  version.

### Power BI

- **`PowerBIAuthError: access token not granted`** — the service
  principal lacks `Dataset.ReadWrite.All` admin consent, or the
  tenant's Power BI admin portal hasn't allowed service principals
  to use Power BI APIs. Verify both.
- **403 on dataset operations** — the service principal isn't a
  Member of the target workspace. Add it via Workspace settings →
  Access.
- **Dataset push silently truncates rows** — Power BI Push
  Datasets have a 200,000-row-per-hour throughput limit. The
  integration warns at 100k+ rows in a single batch.
