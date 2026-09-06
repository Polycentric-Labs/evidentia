# Cloud data warehouse collectors

> v0.7.8 P0 — Databricks + Snowflake adapters. Read-only collectors
> mapping cloud-DW-resident compliance evidence to NIST 800-53
> Rev 5 controls. Companion to v0.7.7's relational-database
> evidence layer.

This guide covers two cloud data-warehouse evidence collectors that
ship in `evidentia-collectors` v0.7.8:

- **Databricks** (`evidentia-collectors[databricks]`) — surfaces
  PAT inventory, cluster compliance, service-principal usage, and
  secret-scope inventory from a Databricks workspace.
- **Snowflake** (`evidentia-collectors[snowflake]`) — surfaces
  login history, user + grant inventory, MFA enforcement, network
  policies, masking + row-access policy inventory, and key-rotation
  status from a Snowflake account.

Both are designed to slot into the existing v0.7.0+ collector
contract: typed exception hierarchy, `CollectionContext` threaded
through every emitted finding, `CollectionManifest` with completeness
attestation, ECS-structured audit logging, explicit `BLIND_SPOTS`
list.

---

## Why both Databricks AND Snowflake?

The two platforms have non-overlapping strengths in regulated
environments:

- **Databricks** dominates ML / AI workloads and ships with built-
  in model lineage as first-class data — useful for NIST SR 11-7
  model-risk evidence (the v0.7.9 financial-services overlay).
- **Snowflake** dominates traditional data-warehouse / SOX-
  compliant data controls — useful for SOX 302/404 IT-general-
  controls evidence.

Most regulated enterprises run both. v0.7.8 ships both adapters
with the same surface contract so a single Evidentia run can
collect from both into one OSCAL Assessment Results document.

---

## Databricks

### Install

```bash
pip install "evidentia-collectors[databricks]"
```

This pulls in `databricks-sdk>=0.30`, the official unified-auth
SDK that wraps the Databricks workspace + account REST APIs.

### Auth modes

The collector forwards to the SDK's unified-auth resolver — no
auth code lives in the collector itself. Operators configure auth
in the environment, never in code:

| Mode | Env vars | Recommended for |
|---|---|---|
| Personal Access Token (PAT) | `DATABRICKS_TOKEN` | dev / CI / one-shot collection |
| OAuth machine-to-machine | `DATABRICKS_CLIENT_ID` + `DATABRICKS_CLIENT_SECRET` | **production** |
| Azure AD service principal | (Azure CLI / Managed Identity) | Azure Databricks production |
| AWS IAM | (boto3 default chain) | AWS Databricks production |
| `.databrickscfg` profile | `DATABRICKS_CONFIG_PROFILE` | local development |

### Required principal privileges

The collector is read-only. The audit principal needs:

- **Workspace API**:
  - `can_use` on the workspace (any user has this)
  - `token_management` permission (or workspace admin) for
    full PAT-inventory coverage; falls back to "current user
    only" if missing
- **Account API** (only if collecting cross-workspace evidence):
  - `account admin` role — required only for cluster-policy
    + network-config evidence at account scope; deferred to a
    future release per the BLIND_SPOT below

### Evidence sources (v0.7.8 P0.1)

| Source | NIST controls | Status |
|---|---|---|
| Personal Access Token inventory | AC-2, AC-2(11), IA-5, IA-5(1), AC-3 | DONE |
| Cluster compliance (runtime version, libraries, init scripts) | CM-2, CM-3, CM-8, SI-2 | DONE |
| Service principal inventory + active/inactive | AC-2, AC-2(3), AC-3 | DONE |
| Secret scope inventory (Databricks-backed vs Key-Vault-backed) | SC-12, IA-5 | DONE |
| Workspace audit logs (Unity Catalog `system.access.audit`) | AU-2, AU-3 | DEFERRED — needs SQL Warehouse plumbing |
| Table + column lineage (`system.access.column_lineage`) | SI-7, SR 11-7 | DEFERRED — needs SQL Warehouse plumbing |
| Workspace network policies (Account API) | SC-7 | DEFERRED — different auth scope |

### CLI

```bash
export DATABRICKS_TOKEN='dapi...'  # or configure OAuth M2M

evidentia collect databricks \
    --workspace-url https://my-workspace.cloud.databricks.com \
    --output databricks-findings.json
```

### REST

```bash
curl -X POST http://localhost:8000/api/collectors/databricks/collect \
    -H "Content-Type: application/json" \
    -d '{"workspace_url": "https://my-workspace.cloud.databricks.com"}'
```

The response is a JSON array of `SecurityFinding` objects, identical
to other Evidentia collectors.

### Programmatic use

```python
from evidentia_collectors.databricks import DatabricksCollector

# DATABRICKS_TOKEN env var is read by the SDK's unified-auth resolver.
with DatabricksCollector(
    host="https://my-workspace.cloud.databricks.com",
) as collector:
    findings, manifest = collector.collect_v2()

print(f"Collected {len(findings)} findings; manifest is_complete={manifest.is_complete}")
```

### BLIND_SPOTS

The collector ships an explicit `BLIND_SPOTS` list documenting
known coverage gaps (operators MUST surface these in the OSCAL
Assessment Results back-matter):

| ID | Title |
|---|---|
| `EVIDENTIA-DATABRICKS-ACCOUNT-VS-WORKSPACE` | Account-API evidence requires separate auth path |
| `EVIDENTIA-DATABRICKS-UC-SYSTEM-TABLES` | Unity Catalog `system.access.*` requires SQL Warehouse |
| `EVIDENTIA-DATABRICKS-PAT-MGMT-PERMISSION` | PAT inventory falls back to "current user" without `token_management` |
| `EVIDENTIA-DATABRICKS-CLUSTER-INIT-SCRIPT-CONTENT` | Init script *path* inventoried; content is not collected |
| `EVIDENTIA-DATABRICKS-NOTEBOOK-CONTENT` | Notebook content is not collected |
| `EVIDENTIA-DATABRICKS-DLT-INTERNALS` | Delta Live Tables internals not surfaced |
| `EVIDENTIA-DATABRICKS-CLOUD-IAM` | Cloud-provider IAM is out of scope |

Read each in full via `python -c
"from evidentia_collectors.databricks import BLIND_SPOTS;
import json; print(json.dumps(BLIND_SPOTS, indent=2))"`.

---

## Snowflake

### Install

```bash
pip install "evidentia-collectors[snowflake]"
```

This pulls in `snowflake-connector-python>=3.10`, the official
driver. Pure Python — no native dependencies.

### Auth modes

Snowflake auth is more involved than Databricks because Snowflake is
deprecating password authentication. The collector supports:

| Mode | How | Recommended |
|---|---|---|
| Password (env var) | `SNOWFLAKE_PASSWORD` env var; pass `--password-env` to override | dev / interim |
| Key-pair | PEM-encoded RSA private key on disk; pass `--private-key-path`. Public key registered via `ALTER USER ... SET RSA_PUBLIC_KEY = '...'` | **production** |
| OAuth | `token=` kwarg on the constructor (programmatic only) | when you have an external IdP issuing OAuth tokens |
| SSO (`externalbrowser`) | not supported by the CLI — interactive only | n/a |

### Required principal privileges

Recommended hardened audit-principal setup (run once as
`ACCOUNTADMIN`):

```sql
USE ROLE ACCOUNTADMIN;

CREATE ROLE EVIDENTIA_AUDIT_RO;
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE
    TO ROLE EVIDENTIA_AUDIT_RO;
GRANT MONITOR USAGE ON ACCOUNT TO ROLE EVIDENTIA_AUDIT_RO;

CREATE WAREHOUSE EVIDENTIA_AUDIT_WH
    WAREHOUSE_SIZE = 'X-SMALL'
    AUTO_SUSPEND = 60
    AUTO_RESUME = TRUE
    INITIALLY_SUSPENDED = TRUE;

GRANT USAGE ON WAREHOUSE EVIDENTIA_AUDIT_WH
    TO ROLE EVIDENTIA_AUDIT_RO;

CREATE USER EVIDENTIA_AUDIT_RO
    PASSWORD = '<env-supplied>'
    DEFAULT_ROLE = EVIDENTIA_AUDIT_RO
    DEFAULT_WAREHOUSE = EVIDENTIA_AUDIT_WH
    MUST_CHANGE_PASSWORD = FALSE;

GRANT ROLE EVIDENTIA_AUDIT_RO TO USER EVIDENTIA_AUDIT_RO;
```

For per-database masking + row-access policy inventory, also grant
`USAGE` on each database whose policies should be inventoried:

```sql
GRANT USAGE ON DATABASE <db_name> TO ROLE EVIDENTIA_AUDIT_RO;
```

### Evidence sources (v0.7.8 P0.2)

| Source | NIST controls | Status |
|---|---|---|
| LOGIN_HISTORY (per-user inventory + per-failed-login row) | AC-7, AU-2, AU-3, IR-4 | DONE |
| USERS inventory + MFA enforcement | AC-2, AC-2(3), IA-2(1), IA-2(2) | DONE |
| GRANTS_TO_USERS inventory + privileged-role grants | AC-3, AC-6, AC-6(7) | DONE |
| Network policies (account-level + per-policy inventory) | SC-7, SC-7(5) | DONE |
| Masking + row-access policies (per database) | AC-3, AC-3(7), SC-28 | DONE |
| Operator-attested key-rotation status | SC-12 | DONE |
| ACCESS_HISTORY (data lineage) | SI-7, SR 11-7 | DEFERRED — large rowcount; pagination + sampling design needed |
| Failed-login spike detection (24h sliding window) | AC-7, IR-4 | DEFERRED — alert-rule heuristic, separate from inventory |

### CLI

```bash
# Password auth (interim; Snowflake is deprecating this).
export SNOWFLAKE_PASSWORD='your-snowflake-password'

evidentia collect snowflake \
    --account acme-prod \
    --user EVIDENTIA_AUDIT_RO \
    --password-env SNOWFLAKE_PASSWORD \
    --warehouse EVIDENTIA_AUDIT_WH \
    --role EVIDENTIA_AUDIT_RO \
    --login-history-window-days 90 \
    --output snowflake-findings.json
```

Or with key-pair auth (preferred for production):

```bash
evidentia collect snowflake \
    --account acme-prod \
    --user EVIDENTIA_AUDIT_RO \
    --private-key-path /etc/evidentia/snowflake_audit_rsa_key.p8 \
    --warehouse EVIDENTIA_AUDIT_WH \
    --output snowflake-findings.json
```

When `--private-key-path` is set, `--password-env` is ignored.

### REST

```bash
curl -X POST http://localhost:8000/api/collectors/snowflake/collect \
    -H "Content-Type: application/json" \
    -d '{
        "account": "acme-prod",
        "user": "EVIDENTIA_AUDIT_RO",
        "password_env": "SNOWFLAKE_PASSWORD",
        "warehouse": "EVIDENTIA_AUDIT_WH",
        "login_history_window_days": 90
    }'
```

The password VALUE never flows through the request body — only the
env-var name. The API server reads the password server-side from the
named env var.

### Programmatic use

```python
import os
from evidentia_collectors.snowflake import SnowflakeCollector

with SnowflakeCollector(
    account="acme-prod",
    user="EVIDENTIA_AUDIT_RO",
    password=os.environ["SNOWFLAKE_PASSWORD"],
    warehouse="EVIDENTIA_AUDIT_WH",
    role="EVIDENTIA_AUDIT_RO",
    login_history_window_days=90,
) as collector:
    findings, manifest = collector.collect_v2()
```

### BLIND_SPOTS

| ID | Title |
|---|---|
| `EVIDENTIA-SNOWFLAKE-ACCOUNT-USAGE-LATENCY` | `account_usage` views have up to 3-hour latency |
| `EVIDENTIA-SNOWFLAKE-PRIVATE-PREVIEW-FEATURES` | Private-preview features not surfaced |
| `EVIDENTIA-SNOWFLAKE-CROSS-ACCOUNT-REPLICATION` | Cross-account replication targets not enumerated |
| `EVIDENTIA-SNOWFLAKE-INFORMATION-SCHEMA-PER-DB` | INFORMATION_SCHEMA views are per-database; missing principal grants silently exclude data |
| `EVIDENTIA-SNOWFLAKE-PASSWORD-AUTH-DEPRECATION` | Password authentication is being deprecated |
| `EVIDENTIA-SNOWFLAKE-ENCRYPTION-PLATFORM-MANAGED` | Account-level encryption keys are platform-managed; cadence is operator-attested |
| `EVIDENTIA-SNOWFLAKE-LEGACY-ACCOUNT-LOGIN-HISTORY` | LOGIN_HISTORY scope window depends on edition |

---

## End-to-end pattern: cloud-DW evidence → gap analysis → BI dashboard

The intended workflow connecting v0.7.8's two halves:

1. **Collect**: run `evidentia collect databricks` and/or
   `evidentia collect snowflake` to gather raw findings.
2. **Map to controls**: feed the findings into the Evidentia gap
   analyzer alongside your control inventory:

   ```bash
   evidentia gap analyze \
       --inventory my-controls.yaml \
       --frameworks nist-800-53-rev5-moderate \
       --output gap-report.json
   ```

3. **Publish to BI**: push the gap report (and optionally a risk
   register) to Tableau or Power BI:

   ```bash
   evidentia integrations tableau publish \
       --gaps gap-report.json \
       --server-url https://your-tableau-cloud.online.tableau.com \
       --site-id compliance-team

   evidentia integrations powerbi publish \
       --gaps gap-report.json \
       --workspace-id <uuid> \
       --tenant-id <uuid> \
       --client-id <uuid>
   ```

4. **Dashboard**: open the published data sources in Tableau or
   Power BI and build refreshable compliance dashboards.

See [bi-integrations.md](bi-integrations.md) for the BI side of the
workflow.

---

## Operator notes — running both adapters in one collection run

Both collectors emit findings tagged with `source_system="databricks"`
or `source_system="snowflake"` plus full `CollectionContext`
provenance. To run both in a single audit cycle and produce a
combined OSCAL Assessment Results document:

```python
import os
from evidentia_collectors.databricks import DatabricksCollector
from evidentia_collectors.snowflake import SnowflakeCollector

all_findings = []
all_manifests = []

with DatabricksCollector(
    host=os.environ["DATABRICKS_WORKSPACE_URL"],
) as dbx:
    f, m = dbx.collect_v2()
    all_findings.extend(f)
    all_manifests.append(m)

with SnowflakeCollector(
    account=os.environ["SNOWFLAKE_ACCOUNT"],
    user=os.environ["SNOWFLAKE_USER"],
    password=os.environ["SNOWFLAKE_PASSWORD"],
) as sf:
    f, m = sf.collect_v2()
    all_findings.extend(f)
    all_manifests.append(m)

# Both manifests can be embedded in the OSCAL AR back-matter so
# auditors can verify per-platform completeness independently.
```

---

## Future work (v0.7.9+)

- **Databricks**: SQL-Warehouse plumbing for Unity Catalog system
  tables (audit logs, lineage). Account-API auth path for network
  policies. Notebook content collection (operator-driven).
- **Snowflake**: ACCESS_HISTORY lineage with pagination + sampling.
  Failed-login spike heuristic (24h sliding window). External
  table + sharing inventory.

Both will be additive — they slot into the existing collector
classes without breaking the v0.7.8 surface contract.
