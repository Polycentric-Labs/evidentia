# evidentia-collectors

Evidence collectors for [Evidentia](https://github.com/Polycentric-Labs/evidentia), the open-source compliance-as-code engine. Each collector makes read-only, authenticated calls to a source system and returns `SecurityFinding` records mapped to framework controls, together with a collection manifest that records what was scanned and where coverage stopped.

## Collectors

| Collector | CLI leaf | Evidence | Extra |
|---|---|---|---|
| AWS | `collect aws` | Config rules, Security Hub findings, IAM Access Analyzer | `[aws]` |
| GitHub | `collect github` | Repository visibility, branch protection, CODEOWNERS, Dependabot alerts, OSPS Baseline helpers | `[github]` |
| Okta | `collect okta` | User inventory, inactive accounts, admin assignments, MFA enrollment, password and sign-on policies | none (`[okta]` adds the official SDK for your own code) |
| Google Workspace | `collect google-workspace` | Directory users, inactive accounts, admin accounts, 2-Step Verification enrollment, Reports login activity | none |
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

Operator guide: [Run evidence collectors](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/wiki/2-guides/run-collectors.md).

License: Apache 2.0
