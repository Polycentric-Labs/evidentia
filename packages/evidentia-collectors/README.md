# evidentia-collectors

Evidence collectors for [Evidentia](https://github.com/Polycentric-Labs/evidentia), the open-source compliance-as-code engine. Collectors read source configuration and findings without changing the source system. Results include `SecurityFinding` records and a collection manifest; available control mappings and coverage depend on the collector. Configuration observations alone do not establish compliance.

## Collectors

| Collector | CLI leaf | Evidence | Extra |
|---|---|---|---|
| AWS | `collect aws` | Config rules, Security Hub findings, IAM Access Analyzer | `[aws]` |
| GitHub | `collect github` | Repository visibility, branch protection, CODEOWNERS, Dependabot alerts, OSPS Baseline helpers | `[github]` |
| Okta | `collect okta` | User inventory, inactive accounts, admin assignments, MFA enrollment, password and sign-on policies | none (`[okta]` adds the official SDK for your own code) |
| Google Workspace | `collect google-workspace` | Directory users, inactive accounts, admin accounts, 2-Step Verification enrollment, Reports login activity | none |
| Entra ID / Microsoft 365 | `collect entra-m365` | Conditional Access, authentication registration, sign-ins, activated roles, Intune devices, retention labels, supplied DLP configuration, Defender alerts and incidents | none |
| Storage retention | `collect retention` | Selected S3 Object Lock/versioning, Azure Blob policy/hold configuration with account/service context, and GCS bucket retention/versioning | `[retention]` for S3; none for Azure/GCS |
| PostgreSQL, MySQL, SQLite, MS SQL, Oracle | `collect sql` | User privileges, audit configuration, encryption posture | `[sql-postgres]`, `[sql-mysql]`, `[sql-sqlite]`, `[sql-mssql]`, `[sql-oracle]`, or `[sql]` for the whole family |
| Databricks | `collect databricks` | Token lifecycle, cluster configuration, service principals, secret scopes | `[databricks]` |
| Snowflake | `collect snowflake` | Login history, users and MFA, grants, network and masking policies | `[snowflake]` |
| Vanta, Drata, BitSight, SecurityScorecard | `collect vanta`, `collect drata`, `collect bitsight`, `collect securityscorecard` | Vendor inventory and security ratings | none |

Three importers read exports or feeds instead of calling a credentialed API: `collect ocsf` for OCSF Compliance and Detection Findings (`[ocsf]`), and `collect nessus` and `collect greenbone` for vulnerability-scan exports (`[scan]`).

## Install

```bash
pip install evidentia-collectors            # the httpx-based collectors and importers
pip install 'evidentia-collectors[aws]'     # add one provider's driver
pip install 'evidentia-collectors[all]'     # every optional driver
```

Credentials come from environment variables named in each leaf's `--help`; no collector accepts a secret as a flag or in a request body. Outbound hosts pass an SSRF guard by default.

Entra/M365 returns a full result envelope with nine capability states, counts, source provenance and a manifest. Prefer `EntraM365Collector.collect_v2(request)` in Python; `collect(request)` returns findings only. Graph access uses pre-minted tokens from `ENTRA_M365_ACCESS_TOKEN` and a separate delegated `ENTRA_M365_RETENTION_ACCESS_TOKEN`. `ENTRA_M365_AUTH_MODE` declares the primary token mode. DLP-only ingestion needs no token. Partial or unavailable evidence is explicit and never proves tenant-wide compliance. Tests use labeled synthetic Graph responses and a selected recorded CISA DLP export; live-tenant acceptance remains unverified.

Operator guide: [Run evidence collectors](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/wiki/2-guides/run-collectors.md).

Storage retention accepts a bounded JSON request selecting one provider and 1 through 20 resources. `StorageRetentionCollector.collect_v2(request)` and the CLI, API and console retain every resource and component, including partial and unavailable evidence. Native days, years, quoted seconds and source timestamp text remain distinct. Results describe configuration, with unknown compliance and no object-enforcement or recordset-completeness claim. Credentials use fixed server-side references, without SDK discovery or refresh. Tests use 24 labeled synthetic provider-response fixtures; live cloud acceptance is unverified. See the [storage design](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/designs/storage-retention-collector-design.md).

License: Apache 2.0
