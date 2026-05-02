# SQL evidence collectors

> *Status: ships in v0.7.7 — first substantive new-collector release since v0.5.0.*

Five read-only collectors that surface compliance-relevant evidence
from running SQL databases and emit `SecurityFinding` objects mapped
to NIST 800-53 Rev 5 controls. Each adapter is a separate optional
extra so you only install what you need.

| Adapter | Extra | Driver | DB versions tested |
|---|---|---|---|
| PostgreSQL | `[sql-postgres]` | `psycopg[binary]>=3.1` | 14, 15, 16 |
| MySQL / MariaDB | `[sql-mysql]` | `PyMySQL>=1.1` | MySQL 8.0+, MariaDB 10.x+ |
| SQLite | `[sql-sqlite]` (empty) | stdlib `sqlite3` | 3.x (stdlib) |
| MS SQL Server | `[sql-mssql]` | `pyodbc>=5.0` + ODBC Driver 18 | 2017, 2019, 2022, Azure SQL |
| Oracle | `[sql-oracle]` | `oracledb>=2.0` (thin) | 19c, 21c, 23c, Database Free |

Or pull all five at once with the umbrella `[sql]` extra.

## Common design

All five collectors follow the v0.7.0 enterprise-grade collector
pattern:

- Typed exception hierarchy (`<Adapter>CollectorError` /
  `<Adapter>ConnectionError` / `<Adapter>QueryError`)
- `CollectionContext` threaded through every emitted finding
- `CollectionManifest` returned by `collect_v2()` for completeness
  attestation
- ECS-structured audit logging via
  `evidentia_core.audit.get_logger()`
- Read-only principal verification probe on first connect
- Explicit `BLIND_SPOTS` list documenting coverage gaps
- Lazy driver imports — adapters load cleanly without their driver
  installed; the actual connection pulls the driver in

### Read-only principal verification

Every adapter (except SQLite, which has no DB principal) probes for
write capability on first connect and emits an
`EVIDENTIA-WRITE-PRIV-DETECTED` finding mapped to **NIST AC-6 Least
Privilege** when the principal exceeds read-only:

| Adapter | Probe | Triggers |
|---|---|---|
| Postgres | `default_transaction_read_only` + `CREATE TEMP TABLE` rollback | superuser / non-rolreadonly principal |
| MySQL | `@@global.read_only` + `@@session.transaction_read_only` + `CREATE TEMPORARY TABLE` rollback | non-read-only principal |
| SQLite | `os.access(W_OK)` against the database file | filesystem permits write (collector still uses `file:?mode=ro` URI) |
| MSSQL | `IS_SRVROLEMEMBER('sysadmin')` + `IS_ROLEMEMBER('db_owner')` + `IS_ROLEMEMBER('db_datawriter')` | sysadmin / db_owner / db_datawriter membership |
| Oracle | `session_roles` for `DBA` + `session_privs` for `SYSDBA` + ANY-table grants | DBA role / SYSDBA / ANY-table grants |

A detected write privilege does **not** abort collection — the
adapter still emits the read-only evidence findings and lets the
operator decide whether the violation blocks acceptance.

### Secret handling

**Connection passwords MUST NOT pass through CLI flags or request
bodies.** Each adapter sources its password from a per-adapter
environment variable on the server / CLI host:

| Adapter | Env var |
|---|---|
| Postgres | `EVIDENTIA_POSTGRES_PASSWORD` |
| MySQL | `EVIDENTIA_MYSQL_PASSWORD` |
| SQLite | (no password — file ACL is the auth boundary) |
| MSSQL | `EVIDENTIA_MSSQL_PASSWORD` |
| Oracle | `EVIDENTIA_ORACLE_PASSWORD` |

The adapter constructors refuse to start if the connection URI's
userinfo contains a password (`user:secret@host`). Override the env
var name via `--password-env` / `password_env` if your deployment
uses different naming.

### CLI surface

```sh
# Postgres
EVIDENTIA_POSTGRES_PASSWORD=$pg_pwd \
  evidentia collect sql --adapter postgres \
  --connection-uri "postgres://reader@db.example.com/app?sslmode=require"

# MySQL
EVIDENTIA_MYSQL_PASSWORD=$my_pwd \
  evidentia collect sql --adapter mysql \
  --connection-uri "mysql://reader@db.example.com:3306/app"

# SQLite — pass the file path as the connection URI
evidentia collect sql --adapter sqlite \
  --connection-uri /var/lib/app/data.db

# MSSQL — also requires Microsoft ODBC Driver 18 at OS level
EVIDENTIA_MSSQL_PASSWORD=$ms_pwd \
  evidentia collect sql --adapter mssql \
  --connection-uri "mssql://reader@db.example.com:1433/app"

# Oracle — uses oracledb thin mode (no Oracle Client install needed)
EVIDENTIA_ORACLE_PASSWORD=$or_pwd \
  evidentia collect sql --adapter oracle \
  --connection-uri "oracle://reader@db.example.com:1521/orcl"
```

### REST surface

Each adapter has a corresponding POST endpoint:

```
POST /api/collectors/sql/postgres/collect
POST /api/collectors/sql/mysql/collect
POST /api/collectors/sql/sqlite/collect
POST /api/collectors/sql/mssql/collect
POST /api/collectors/sql/oracle/collect
```

Status of installed adapters + configured env vars (no secrets):

```
GET /api/collectors/status
```

## NIST 800-53 mapping summary

| Control | Postgres | MySQL | SQLite | MSSQL | Oracle |
|---|---|---|---|---|---|
| **AC-2** Account Management | `pg_roles` / `pg_authid` | `mysql.user` | — | `sys.server_principals` | `dba_users` |
| **AC-3** Access Enforcement | `INFORMATION_SCHEMA` privileges + `max_connections` | `INFORMATION_SCHEMA.USER_PRIVILEGES` + `max_connections` | file ACLs (BLIND_SPOT for distributed FS) | `sys.server_permissions` + user-conn limit | `dba_sys_privs` + sessions/processes |
| **AC-6** Least Privilege | privilege grants + write-priv probe | privilege grants + write-priv probe | write-priv probe via `os.access(W_OK)` | sysadmin/db_owner/db_datawriter probe + `sys.server_role_members` | DBA role + SYSDBA + ANY-table probe |
| **AU-2** Event Logging | `pg_settings.log_*` + pgaudit | `general_log` + `audit_log_*` plugin | — (BLIND_SPOT EVIDENTIA-SQLITE-NO-AUDIT-LOG) | `sys.server_audits` | `AUDIT_UNIFIED_ENABLED_POLICIES` (12c+) or `audit_trail` |
| **AU-3** Content of Audit Records | `log_line_prefix` | `audit_log_format` | — | server-audit specifications | unified-audit policy definitions |
| **IA-5** Authenticator Management | — (covered via SC-12) | — | — | — | `dba_profiles` PASSWORD resources |
| **SC-12** Cryptographic Key Establishment | `password_encryption` (must be `scram-sha-256`) + TLS settings | `default_authentication_plugin` + `ssl_*` | — | `CONNECTIONPROPERTY('encrypt_option')` | `sqlnet.encryption_server` |
| **SC-28** Protection of Information at Rest | TLS posture + filesystem-level (BLIND_SPOT) | `innodb_*_encryption` + keyring plugin | encryption-extension probe (SEE / SQLCipher / WxSQLite3) | `sys.dm_database_encryption_keys` (TDE) | `v$encryption_wallet` + `dba_tablespaces.encrypted` (Advanced Security Option) |
| **SI-7** Software/Firmware/Information Integrity | — | — | `PRAGMA integrity_check` + `PRAGMA foreign_key_check` | — | — |

Each emitted finding carries the relevant `control_ids` plus an
explicit `ControlMapping` with `framework=nist-800-53-rev5`,
relationship (`SUBSET_OF` / `INTERSECTS_WITH` / `RELATED_TO`), and a
per-rule justification string (the rationale for *why* this evidence
maps to this control).

## Adapter-specific notes

### PostgreSQL

- Required principal privileges: `GRANT pg_read_all_settings TO
  evidentia_reader; GRANT pg_read_all_stats TO evidentia_reader;`
  plus connect privilege on the target database.
- Collected evidence: user + role inventory (`pg_roles`,
  `pg_authid`, `pg_auth_members`), privilege grants
  (`INFORMATION_SCHEMA.TABLE_PRIVILEGES` + `pg_class.relacl`), audit
  log status (`pg_settings.log_*`, pgaudit if loaded), encryption
  posture (`pg_settings.ssl_*` for TLS-on-the-wire), crypto
  config (`password_encryption`).
- BLIND_SPOTS: SC-28 in-rest encryption is filesystem-level
  (LUKS / dm-crypt / RDS storage encryption) and not directly
  queryable; cloud-managed Postgres restricts visibility on a
  subset of `pg_settings`.

### MySQL / MariaDB

- Required privileges: `GRANT SELECT ON mysql.user TO 'reader'@'%';`
  + `GRANT SELECT ON information_schema.* TO 'reader'@'%';` plus
  `GRANT PROCESS ON *.* TO 'reader'@'%';` for `SHOW VARIABLES`.
- BLIND_SPOTS:
  - `EVIDENTIA-MYSQL-AUDIT-PLUGIN-COMMUNITY` — Community Edition has
    no built-in audit-log plugin; operators needing AU-2/AU-3
    coverage should run Percona Server / MariaDB / MySQL Enterprise.
  - `EVIDENTIA-MYSQL-MYSQL-CONFIG-FILE-ACCESS` — many security
    settings (`default_authentication_plugin`, ssl_cert paths,
    `plugin_load_add`) are read at server startup from `my.cnf`
    and not exposed via `SHOW VARIABLES`.
  - `EVIDENTIA-MYSQL-CLOUD-MANAGED` — RDS / Aurora / Cloud SQL
    restrict access to certain `SHOW VARIABLES` outputs.

### SQLite

Smallest surface — SQLite has no built-in user system, so the
collector focuses on file + extension-level evidence:

- File ACL probe (UNIX mode bits + uid/gid) — AC-3 evidence
- Read-only enforcement at the SQLite level via `file:?mode=ro` URI
- `os.access(W_OK)` probe for AC-6 write-privilege detection
- `PRAGMA journal_mode` + `synchronous` — durability evidence (SC-28)
- `PRAGMA integrity_check(1)` + `PRAGMA foreign_key_check` — SI-7
- Encryption-extension probe (`PRAGMA cipher_version` /
  `cipher` / `see_version`) — best-effort detection of SEE /
  SQLCipher / WxSQLite3 (SC-28)
- BLIND_SPOTS:
  - `EVIDENTIA-SQLITE-FILE-ACL-MULTI-HOST` — file ACLs are
    meaningful only on single-host deployments; distributed
    filesystems (CephFS, GlusterFS, NFS) require operator-supplied
    out-of-band evidence
  - `EVIDENTIA-SQLITE-NO-AUDIT-LOG` — no audit-log subsystem
  - `EVIDENTIA-SQLITE-ENCRYPTION-EXTENSION-DETECTION` — negative
    cipher-probe results are INCONCLUSIVE; operators with
    non-standard encryption extensions should provide out-of-band
    evidence

### MS SQL Server

- Driver: `pyodbc` + Microsoft ODBC Driver 18 (OS-level install
  required). On Linux:
  ```sh
  curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
  sudo apt-get install -y msodbcsql18
  ```
  On Windows the driver ships with SQL Server tooling or as a
  standalone download from Microsoft.
- Required privileges: `GRANT VIEW SERVER STATE TO evidentia_reader;`
  + `GRANT VIEW ANY DEFINITION TO evidentia_reader;` plus
  `db_datareader` membership on each database in scope.
- Collected evidence: `sys.server_principals` + `sys.database_principals`
  for AC-2 inventory, `sys.server_role_members` for sysadmin
  count, `sys.server_audits` + `is_state_enabled` for AU-2,
  `sys.dm_database_encryption_keys.encryption_state` for TDE
  (state=3 means encrypted), `CONNECTIONPROPERTY` for connection
  encryption posture.
- BLIND_SPOTS:
  - `EVIDENTIA-MSSQL-EXTENDED-EVENTS` — XE sessions used for
    audit are not enumerated; out-of-band collection required
  - `EVIDENTIA-MSSQL-AZURE-SQL-FEATURE-MATRIX` — Azure SQL Database
    / Managed Instance have reduced T-SQL surface
  - `EVIDENTIA-MSSQL-ALWAYS-ENCRYPTED-COLUMN-VISIBILITY` — column-
    master-key presence reported; per-column protection requires
    out-of-band review

### Oracle Database

- Driver: `oracledb>=2.0` thin mode (pure Python — no Oracle
  Client install required).
- Required privileges: `GRANT SELECT_CATALOG_ROLE TO
  evidentia_reader; GRANT CREATE SESSION TO evidentia_reader;`
- Collected evidence: `dba_users` (AC-2), `dba_role_privs` for DBA
  membership (AC-6), `dba_profiles` PASSWORD resources (IA-5),
  `AUDIT_UNIFIED_ENABLED_POLICIES` (12c+) or `audit_trail`
  parameter for AU-2, `v$encryption_wallet` +
  `dba_tablespaces.encrypted` for TDE (SC-28), `sqlnet.encryption_server`
  for in-transit (SC-12).
- BLIND_SPOTS:
  - `EVIDENTIA-ORACLE-LICENSE-FEATURE` — TDE / Database Vault /
    Audit Vault require separately-licensed components; absence
    may indicate "unlicensed" rather than "misconfigured"
  - `EVIDENTIA-ORACLE-AUDIT-MIXED-MODE` — Unified + Traditional
    audit coexistence requires out-of-band reconciliation
  - `EVIDENTIA-ORACLE-CDB-PDB-CONTEXT` — Multitenant deployments
    need per-PDB collection runs
  - `EVIDENTIA-ORACLE-NETWORK-ENCRYPTION-CLIENT` — `sqlnet.ora` is
    OS-level configuration not always queryable via `V$PARAMETER`

## Troubleshooting

### `<Adapter>CollectorError: <Adapter> driver is not installed`

Install the corresponding extra:

```sh
pip install "evidentia-collectors[sql-postgres]"
pip install "evidentia-collectors[sql-mysql]"
pip install "evidentia-collectors[sql-mssql]"   # also: sudo apt-get install msodbcsql18
pip install "evidentia-collectors[sql-oracle]"
```

SQLite uses stdlib `sqlite3` — the `[sql-sqlite]` extra is empty
and exists only so you can declare adapter intent consistently.

### `connection_uri must NOT embed a password`

Strip the password from the URI; place it in the corresponding
env var instead. The adapter will refuse to connect with the URI
form `user:secret@host:port/db`.

### `Environment variable 'EVIDENTIA_<ADAPTER>_PASSWORD' not set`

Set the env var on the host or in your CI/CD secret store and
relaunch. Override the variable name with `--password-env <NAME>`
(CLI) or `password_env` (REST request body) if your deployment
uses a different naming convention.

### Postgres: `FATAL: SSL connection is required`

Append `?sslmode=require` to the connection URI.

### MySQL: cloud-managed missing variables

Some `SHOW VARIABLES` outputs are restricted on RDS / Aurora /
Cloud SQL. The collector handles missing values gracefully — they're
recorded as INDETERMINATE rather than treated as misconfigurations.

### MSSQL: `[Microsoft][ODBC Driver Manager] Data source name not found`

Microsoft ODBC Driver 18 is not installed at OS level. Install per
the link above. Also confirm the driver version with `odbcinst -j`.

### Oracle: `DPY-3001: Native network encryption disabled`

The Oracle thin driver does not yet support Native Network
Encryption — for environments that mandate NNE, use thick mode
(set `oracledb.init_oracle_client(...)` before instantiating the
collector). Document the deviation in your control evidence.

## See also

- [docs/threat-model.md](threat-model.md) — public threat model
  covering the v0.7.7 collector surface
- [docs/enterprise-grade-accepted-findings.md](enterprise-grade-accepted-findings.md) —
  accepted-findings rationale + Open Questions deferred to v0.8.0+
- [docs/release-checklist.md](release-checklist.md) — per-release runbook
- [docs/positioning-and-value.md](positioning-and-value.md) — why
  Evidentia + how the SQL collectors fit the broader narrative
