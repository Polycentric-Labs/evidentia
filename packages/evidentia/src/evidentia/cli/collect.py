"""`evidentia collect` — evidence-collection CLI commands.

v0.5.0 ships two collectors:

- ``collect aws`` — AWS Config + Security Hub findings
- ``collect github --repo owner/repo`` — branch protection + CODEOWNERS

Each command writes a list of :class:`SecurityFinding` objects as JSON
to ``--output`` (default: stdout) and prints a summary table.

Credentials:

- **AWS**: standard boto3 chain — env vars, ``~/.aws/credentials``,
  or instance profile.
- **GitHub**: ``GITHUB_TOKEN`` env var (personal access token or
  workflow token). Public repos also work unauthenticated, rate-limited.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from pathlib import Path

import typer
from evidentia_core.models.finding import SecurityFinding
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    no_args_is_help=True,
    help="Evidence collectors — AWS, GitHub, etc.",
)

console = Console()


@app.command("aws")
def collect_aws(
    region: str | None = typer.Option(
        None,
        "--region",
        "-r",
        help="AWS region. Defaults to the SDK's resolved region.",
    ),
    profile: str | None = typer.Option(
        None,
        "--profile",
        "-p",
        help="Optional AWS profile from ~/.aws/credentials.",
    ),
    include_config: bool = typer.Option(
        True,
        "--include-config/--no-config",
        help="Pull AWS Config non-compliant rule evaluations.",
    ),
    include_security_hub: bool = typer.Option(
        True,
        "--include-security-hub/--no-security-hub",
        help="Pull Security Hub active findings.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect evidence from AWS Config + Security Hub."""
    try:
        from evidentia_collectors.aws import AwsCollector, AwsCollectorError
    except ImportError as e:
        console.print(
            "[red]Error:[/red] AWS collector is not installed. "
            "Run [cyan]pip install 'evidentia-collectors[aws]'[/cyan]."
        )
        raise typer.Exit(code=1) from e

    try:
        collector = AwsCollector(region=region, profile=profile)
        identity = collector.test_connection()
    except AwsCollectorError as e:
        console.print(f"[red]AWS connection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    console.print(
        f"[dim]Collecting from account [bold]{identity['account']}[/bold] "
        f"in region [bold]{collector.region}[/bold]...[/dim]"
    )
    findings = collector.collect_all(
        include_config=include_config,
        include_security_hub=include_security_hub,
    )
    _write_findings(findings, output, title=f"AWS findings ({collector.region})")


@app.command("github")
def collect_github(
    repo: str = typer.Option(
        ...,
        "--repo",
        "-r",
        help="GitHub repository in 'owner/repo' format.",
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help=(
            "GitHub personal access token. Defaults to $GITHUB_TOKEN. "
            "Required for private repos and higher rate limits."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect evidence from a GitHub repository."""
    try:
        from evidentia_collectors.github import (
            GitHubApiError,
            GitHubCollector,
            GitHubCollectorError,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] GitHub collector failed to import: " + str(e)
        )
        raise typer.Exit(code=1) from e

    if "/" not in repo:
        console.print(
            "[red]Error:[/red] --repo must be 'owner/repo' format."
        )
        raise typer.Exit(code=1)
    owner, repo_name = repo.split("/", 1)

    resolved_token = token or os.environ.get("GITHUB_TOKEN")

    try:
        with GitHubCollector(
            owner=owner, repo=repo_name, token=resolved_token
        ) as collector:
            findings = collector.collect()
    except (GitHubCollectorError, GitHubApiError) as e:
        console.print(f"[red]GitHub collection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    _write_findings(findings, output, title=f"GitHub findings ({repo})")


@app.command("okta")
def collect_okta(
    org_url: str = typer.Option(
        ...,
        "--org-url",
        "-u",
        help="Okta org URL (e.g., https://your-org.okta.com).",
    ),
    inactive_threshold_days: int = typer.Option(
        90,
        "--inactive-threshold-days",
        help=(
            "Days since last login that mark an ACTIVE user as "
            "inactive. Default: 90 (per AC-2(3))."
        ),
    ),
    max_users: int = typer.Option(
        10_000,
        "--max-users",
        help=(
            "Hard cap on user enumeration. Default: 10000. "
            "Increase only if your org is genuinely larger."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect evidence from an Okta org (read-only).

    The API token is sourced from the OKTA_API_TOKEN env var per
    the secret-handling protocol — refused via CLI flag.
    """
    try:
        from evidentia_collectors.okta import (
            OktaCollector,
            OktaCollectorError,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] Okta collector failed to import: " + str(e)
        )
        raise typer.Exit(code=1) from e

    api_token = os.environ.get("OKTA_API_TOKEN")
    if api_token is None:
        console.print(
            "[red]Error:[/red] OKTA_API_TOKEN env var not set. "
            "Set it to a read-only Okta API token."
        )
        raise typer.Exit(code=1)

    try:
        with OktaCollector(
            org_url=org_url,
            api_token=api_token,
            inactive_threshold_days=inactive_threshold_days,
            max_users=max_users,
        ) as collector:
            findings = collector.collect()
    except OktaCollectorError as e:
        console.print(f"[red]Okta collection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    _write_findings(findings, output, title=f"Okta findings ({org_url})")


@app.command("sql")
def collect_sql(
    adapter: str = typer.Option(
        ...,
        "--adapter",
        "-a",
        help="SQL adapter: postgres, mysql, sqlite, mssql, oracle.",
    ),
    connection_uri: str = typer.Option(
        ...,
        "--connection-uri",
        "-u",
        help=(
            "Database connection URI WITHOUT embedded password. "
            "Example: postgres://reader@db.example.com/app?sslmode=require. "
            "Pass the password via the --password-env env var."
        ),
    ),
    password_env: str = typer.Option(
        "EVIDENTIA_POSTGRES_PASSWORD",
        "--password-env",
        help=(
            "Environment variable containing the DB password. "
            "Default: EVIDENTIA_POSTGRES_PASSWORD. The collector "
            "refuses to read the password from a CLI flag per the "
            "secret-handling protocol."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect compliance evidence from a SQL database (read-only).

    v0.7.7 ships --adapter postgres / mysql / sqlite (P0.1+P0.2+P0.3).
    P0.4 (mssql) / P0.5 (oracle) follow in subsequent commits.

    Each adapter is read-only by design and runs a write-privilege
    verification probe on first connect. Detected write privilege
    emits an EVIDENTIA-WRITE-PRIV-DETECTED finding mapped to NIST
    AC-6 (least privilege violation).

    SQLite is special: no auth, no password env var. Pass the database
    file path via --connection-uri (e.g., --connection-uri /var/lib/app/data.db).
    """
    if adapter == "postgres":
        try:
            from evidentia_collectors.sql.postgres import (
                PostgresCollector,
                PostgresCollectorError,
            )
        except ImportError as e:
            console.print(
                "[red]Error:[/red] PostgreSQL collector is not installed. "
                "Run [cyan]pip install 'evidentia-collectors[sql-postgres]'[/cyan]."
            )
            raise typer.Exit(code=1) from e

        # Default env-var name follows per-adapter convention; override
        # via --password-env for non-default placements.
        if password_env == "EVIDENTIA_POSTGRES_PASSWORD":
            password = os.environ.get(password_env)
        else:
            password = os.environ.get(password_env)
        if password is None:
            console.print(
                f"[red]Error:[/red] {password_env} env var not set. "
                "Set it to the DB password before running this command."
            )
            raise typer.Exit(code=1)

        try:
            with PostgresCollector(
                connection_uri=connection_uri, password=password
            ) as collector:
                findings = collector.collect()
        except PostgresCollectorError as e:
            console.print(f"[red]Postgres collection failed:[/red] {e}")
            raise typer.Exit(code=1) from e

        _write_findings(findings, output, title=f"Postgres findings ({connection_uri})")
        return

    if adapter == "mysql":
        try:
            from evidentia_collectors.sql.mysql import (
                MySQLCollector,
                MySQLCollectorError,
            )
        except ImportError as e:
            console.print(
                "[red]Error:[/red] MySQL collector is not installed. "
                "Run [cyan]pip install 'evidentia-collectors[sql-mysql]'[/cyan]."
            )
            raise typer.Exit(code=1) from e

        # MySQL defaults to a different env-var name unless overridden
        effective_env = (
            "EVIDENTIA_MYSQL_PASSWORD"
            if password_env == "EVIDENTIA_POSTGRES_PASSWORD"
            else password_env
        )
        password = os.environ.get(effective_env)
        if password is None:
            console.print(
                f"[red]Error:[/red] {effective_env} env var not set. "
                "Set it to the DB password before running this command."
            )
            raise typer.Exit(code=1)

        try:
            with MySQLCollector(
                connection_uri=connection_uri, password=password
            ) as collector:
                findings = collector.collect()
        except MySQLCollectorError as e:
            console.print(f"[red]MySQL collection failed:[/red] {e}")
            raise typer.Exit(code=1) from e

        _write_findings(findings, output, title=f"MySQL findings ({connection_uri})")
        return

    if adapter == "sqlite":
        try:
            from evidentia_collectors.sql.sqlite import (
                SQLiteCollector,
                SQLiteCollectorError,
            )
        except ImportError as e:
            console.print(
                "[red]Error:[/red] SQLite collector failed to import: " + str(e)
            )
            raise typer.Exit(code=1) from e

        # SQLite has no auth — the connection_uri is treated as the
        # database file path. No password env var is required or read.
        # Honor EVIDENTIA_SQLITE_SAFE_ROOT for path-traversal containment
        # in multi-tenant deployments (CWE-22; see docs/sql-collectors.md).
        safe_root = os.environ.get("EVIDENTIA_SQLITE_SAFE_ROOT") or None
        try:
            with SQLiteCollector(
                database_path=connection_uri,
                safe_root=safe_root,
            ) as collector:
                findings = collector.collect()
        except SQLiteCollectorError as e:
            console.print(f"[red]SQLite collection failed:[/red] {e}")
            raise typer.Exit(code=1) from e

        _write_findings(findings, output, title=f"SQLite findings ({connection_uri})")
        return

    if adapter == "mssql":
        try:
            from evidentia_collectors.sql.mssql import (
                MSSQLCollector,
                MSSQLCollectorError,
            )
        except ImportError as e:
            console.print(
                "[red]Error:[/red] MSSQL collector is not installed. "
                "Run [cyan]pip install 'evidentia-collectors[sql-mssql]'[/cyan] "
                "and ensure Microsoft ODBC Driver 18 is installed."
            )
            raise typer.Exit(code=1) from e

        effective_env = (
            "EVIDENTIA_MSSQL_PASSWORD"
            if password_env == "EVIDENTIA_POSTGRES_PASSWORD"
            else password_env
        )
        password = os.environ.get(effective_env)
        if password is None:
            console.print(
                f"[red]Error:[/red] {effective_env} env var not set. "
                "Set it to the DB password before running this command."
            )
            raise typer.Exit(code=1)

        try:
            with MSSQLCollector(
                connection_uri=connection_uri, password=password
            ) as collector:
                findings = collector.collect()
        except MSSQLCollectorError as e:
            console.print(f"[red]MSSQL collection failed:[/red] {e}")
            raise typer.Exit(code=1) from e

        _write_findings(findings, output, title=f"MSSQL findings ({connection_uri})")
        return

    if adapter == "oracle":
        try:
            from evidentia_collectors.sql.oracle import (
                OracleCollector,
                OracleCollectorError,
            )
        except ImportError as e:
            console.print(
                "[red]Error:[/red] Oracle collector is not installed. "
                "Run [cyan]pip install 'evidentia-collectors[sql-oracle]'[/cyan]."
            )
            raise typer.Exit(code=1) from e

        effective_env = (
            "EVIDENTIA_ORACLE_PASSWORD"
            if password_env == "EVIDENTIA_POSTGRES_PASSWORD"
            else password_env
        )
        password = os.environ.get(effective_env)
        if password is None:
            console.print(
                f"[red]Error:[/red] {effective_env} env var not set. "
                "Set it to the DB password before running this command."
            )
            raise typer.Exit(code=1)

        try:
            with OracleCollector(
                connection_uri=connection_uri, password=password
            ) as collector:
                findings = collector.collect()
        except OracleCollectorError as e:
            console.print(f"[red]Oracle collection failed:[/red] {e}")
            raise typer.Exit(code=1) from e

        _write_findings(findings, output, title=f"Oracle findings ({connection_uri})")
        return

    console.print(
        f"[red]Error:[/red] Unknown adapter {adapter!r}. "
        "Supported: postgres, mysql, sqlite, mssql, oracle "
        "(v0.7.7 P0.1+P0.2+P0.3+P0.4+P0.5)."
    )
    raise typer.Exit(code=1)


@app.command("databricks")
def collect_databricks(
    workspace_url: str = typer.Option(
        ...,
        "--workspace-url",
        "-w",
        help=(
            "Databricks workspace URL. "
            "Example: https://my-workspace.cloud.databricks.com. "
            "Auth is delegated to the Databricks SDK's unified-auth "
            "resolver — set DATABRICKS_TOKEN env var (PAT) OR "
            "configure Azure AD / AWS IAM / OAuth M2M / "
            ".databrickscfg. The collector NEVER accepts a token "
            "via CLI flag per the secret-handling protocol."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect compliance evidence from a Databricks workspace (read-only).

    v0.7.8 P0.1 ships 4 evidence sources:

    - PAT inventory (AC-2 / IA-5) + long-lived + never-expires checks
    - Cluster compliance (CM-2 / CM-8 / SI-2) + outdated-runtime
    - Service principal inventory (AC-2 / AC-3) + inactive-SP
    - Secret scope inventory (SC-12 / IA-5) + Key-Vault-vs-Databricks-
      backed advisories

    Auth modes (via SDK unified-auth):

    - PAT (DATABRICKS_TOKEN env var) — simplest for CI/dev
    - OAuth M2M (DATABRICKS_CLIENT_ID + DATABRICKS_CLIENT_SECRET)
      — recommended for production
    - Azure AD service principal (when on Azure Databricks)
    - AWS IAM (when on AWS Databricks)
    - .databrickscfg profile

    See `evidentia_collectors.databricks.__init__` for full docs.

    Deferred to subsequent v0.7.8 commits:

    - Workspace audit logs + table/column lineage (need SQL Warehouse)
    - Workspace network policies (need Account API auth path)
    """
    try:
        from evidentia_collectors.databricks import (
            DatabricksCollector,
            DatabricksCollectorError,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] Databricks collector is not installed. "
            "Run [cyan]pip install 'evidentia-collectors[databricks]'[/cyan]."
        )
        raise typer.Exit(code=1) from e

    try:
        with DatabricksCollector(host=workspace_url) as collector:
            findings = collector.collect()
    except DatabricksCollectorError as e:
        console.print(f"[red]Databricks collection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    _write_findings(
        findings,
        output,
        title=f"Databricks findings ({workspace_url})",
    )


@app.command("snowflake")
def collect_snowflake(
    account: str = typer.Option(
        ...,
        "--account",
        "-a",
        help=(
            "Snowflake account locator. "
            "Example: 'acme-prod' or 'acme-prod.us-east-1'. "
            "The driver appends '.snowflakecomputing.com' "
            "automatically."
        ),
    ),
    user: str = typer.Option(
        ...,
        "--user",
        "-u",
        help=(
            "Snowflake user for the audit principal. "
            "Recommended: dedicated EVIDENTIA_AUDIT_RO user with "
            "MONITOR USAGE on account + IMPORTED PRIVILEGES on "
            "the SNOWFLAKE shared database."
        ),
    ),
    password_env: str = typer.Option(
        "SNOWFLAKE_PASSWORD",
        "--password-env",
        help=(
            "Name of the env var holding the password. The CLI "
            "reads from this env var rather than accepting the "
            "password as a flag (per secret-handling protocol). "
            "Defaults to SNOWFLAKE_PASSWORD."
        ),
    ),
    private_key_path: Path | None = typer.Option(
        None,
        "--private-key-path",
        help=(
            "Path to a PEM-encoded RSA private key for key-pair "
            "authentication. Preferred over password for "
            "production deployments. When set, --password-env is "
            "ignored."
        ),
    ),
    warehouse: str | None = typer.Option(
        None,
        "--warehouse",
        "-w",
        help=(
            "Optional warehouse name. Audit principals SHOULD "
            "use a dedicated low-cost warehouse "
            "(e.g. EVIDENTIA_AUDIT_WH XS auto-suspend 60s)."
        ),
    ),
    role: str | None = typer.Option(
        None,
        "--role",
        "-r",
        help=(
            "Optional role name. Defaults to the user's "
            "default role."
        ),
    ),
    login_history_window_days: int = typer.Option(
        90,
        "--login-history-window-days",
        help=(
            "How many days back to scan in LOGIN_HISTORY. "
            "Defaults to 90 (industry-standard window)."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect compliance evidence from a Snowflake account (read-only).

    v0.7.8 P0.2 ships 6 evidence sources:

    - LOGIN_HISTORY (AC-7 / AU-2) — per-user inventory + per-failed-
      login row over the configured window
    - USERS (AC-2 / AC-2(3) / IA-2(1)/IA-2(2)) — inventory + MFA-
      disabled + disabled-account + never-logged-in findings
    - GRANTS_TO_USERS (AC-3 / AC-6 / AC-6(7)) — inventory +
      privileged-role grant findings (ACCOUNTADMIN /
      SECURITYADMIN / ORGADMIN)
    - Network policies (SC-7 / SC-7(5)) — inventory + finding when
      no account-level policy is set
    - Masking + row-access policies (AC-3 / AC-3(7) / SC-28) — per-
      database inventory across every database the principal can see
    - Operator-attested encryption-key rotation (SC-12) — single
      resolved finding documenting the platform-managed default

    Auth modes:

    - Password (--password-env $VAR; default SNOWFLAKE_PASSWORD)
    - Key-pair (--private-key-path /path/to/rsa.pem) — preferred
      for production; Snowflake is deprecating password auth
    - OAuth (programmatic only — not supported via CLI)

    Required principal privileges:

    - IMPORTED PRIVILEGES on the SNOWFLAKE shared database
    - MONITOR USAGE on the account
    - USAGE on each database whose policies should be inventoried

    See `evidentia_collectors.snowflake.__init__` for the
    recommended setup script.

    Deferred to subsequent v0.7.8 commits:

    - ACCESS_HISTORY (data lineage; large rowcount — pagination +
      sampling design needed)
    - Failed-login spike detection (sliding-window heuristic;
      separate from inventory)
    """
    try:
        from evidentia_collectors.snowflake import (
            SnowflakeCollector,
            SnowflakeCollectorError,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] Snowflake collector is not installed. "
            "Run [cyan]pip install 'evidentia-collectors[snowflake]'[/cyan]."
        )
        raise typer.Exit(code=1) from e

    # Source the password from env (never accept as a flag value).
    # Skip when private_key_path is set — key-pair auth bypasses the
    # password requirement.
    password: str | None = None
    if private_key_path is None:
        password = os.environ.get(password_env)
        if not password:
            console.print(
                f"[red]Error:[/red] env var [cyan]{password_env}"
                f"[/cyan] is not set or is empty. Either set it "
                f"to the Snowflake password OR pass "
                f"[cyan]--private-key-path[/cyan] for key-pair auth."
            )
            raise typer.Exit(code=1)

    try:
        with SnowflakeCollector(
            account=account,
            user=user,
            password=password,
            private_key_path=(
                str(private_key_path) if private_key_path else None
            ),
            warehouse=warehouse,
            role=role,
            login_history_window_days=login_history_window_days,
        ) as collector:
            findings = collector.collect()
    except SnowflakeCollectorError as e:
        console.print(f"[red]Snowflake collection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    _write_findings(
        findings,
        output,
        title=f"Snowflake findings ({account})",
    )


@app.command("vanta")
def collect_vanta(
    token_env: str = typer.Option(
        "VANTA_API_TOKEN",
        "--token-env",
        help=(
            "Name of the env var holding the Vanta API token. The "
            "CLI reads from this env var rather than accepting the "
            "token as a flag (per secret-handling protocol). "
            "Defaults to VANTA_API_TOKEN. The token can be either a "
            "Personal Access Token (developer / scripting use) or "
            "a pre-acquired OAuth 2.0 access token; both pass "
            "Authorization: Bearer <token>."
        ),
    ),
    base_url: str = typer.Option(
        "https://api.vanta.com",
        "--base-url",
        help=(
            "Vanta Public API base URL. Override for staging / "
            "dev tenants."
        ),
    ),
    max_vendors: int = typer.Option(
        2000,
        "--max-vendors",
        min=1,
        max=100_000,
        help=(
            "Hard cap on vendor enumeration. Default 2000 — covers "
            "typical orgs without unbounded pagination."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect compliance evidence from a Vanta TPRM workspace (read-only).

    v0.7.9 P0.4 first slice ships ONE evidence source:

    - **Vanta vendor inventory** (NIST 800-53 SR-2 / SR-3 / SR-6 +
      OCC 2013-29 §III.A + FRB SR 13-19 §II + FFIEC IT Handbook
      Outsourcing booklet §II) — every vendor in the operator's
      Vanta workspace gets an INFORMATIONAL inventory finding;
      Vanta-flagged HIGH or CRITICAL risk-tier vendors additionally
      get a MEDIUM ACTIVE finding with OCC §III.A.4 ongoing-
      monitoring mappings calling for operator review.

    Auth: pass the API token via env var (default
    ``VANTA_API_TOKEN``). Vanta supports both Personal Access
    Tokens (developer / scripting use) and OAuth 2.0 access
    tokens (pre-acquired via client-credentials grant). Both pass
    ``Authorization: Bearer <token>``. Recommended scope:
    ``vendors:read`` only — no broader scopes needed for this
    first-slice surface.

    Deferred to subsequent v0.7.9 P0.4 slices:

    - Vanta control test results (/v1/controls + /v1/control-tests)
    - Ongoing-monitoring posture changes (state-diff)
    - OAuth 2.0 client-credentials grant (token exchange + refresh)
    - Webhook event ingestion (push model)

    See `evidentia_collectors.vanta.__init__` for the public-
    surface walkthrough.
    """
    try:
        from evidentia_collectors.vanta import (
            VantaCollector,
            VantaCollectorError,
        )
    except ImportError as e:
        # Should never fire today (httpx is a base dep) but kept
        # for parity with the per-collector extras pattern in case
        # a future evidentia-collectors[vanta] extra brings in
        # extra deps.
        console.print(
            "[red]Error:[/red] Vanta collector module not importable. "
            "Run [cyan]pip install evidentia-collectors[/cyan]."
        )
        raise typer.Exit(code=1) from e

    api_token = os.environ.get(token_env)
    if not api_token:
        console.print(
            f"[red]Error:[/red] env var [cyan]{token_env}[/cyan] "
            "is not set or is empty. Set it to your Vanta API "
            "token (Personal Access Token or OAuth access token)."
        )
        raise typer.Exit(code=1)

    try:
        with VantaCollector(
            api_token=api_token,
            base_url=base_url,
            max_vendors=max_vendors,
        ) as collector:
            findings = collector.collect()
    except VantaCollectorError as e:
        console.print(f"[red]Vanta collection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    _write_findings(
        findings,
        output,
        title=f"Vanta findings ({base_url})",
    )


@app.command("drata")
def collect_drata(
    token_env: str = typer.Option(
        "DRATA_API_TOKEN",
        "--token-env",
        help=(
            "Name of the env var holding the Drata API token. The "
            "CLI reads from this env var rather than accepting the "
            "token as a flag (per secret-handling protocol). "
            "Defaults to DRATA_API_TOKEN."
        ),
    ),
    base_url: str = typer.Option(
        "https://public-api.drata.com",
        "--base-url",
        help=(
            "Drata Public API base URL. Override for staging / "
            "dev tenants."
        ),
    ),
    max_vendors: int = typer.Option(
        2000,
        "--max-vendors",
        min=1,
        max=100_000,
        help=(
            "Hard cap on vendor enumeration. Default 2000 — covers "
            "typical orgs without unbounded pagination."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect compliance evidence from a Drata workspace (read-only).

    v0.7.9 P0.4 second slice ships ONE evidence source:

    - **Drata vendor inventory** (NIST 800-53 SR-2 / SR-3 / SR-6 +
      OCC 2013-29 §III.A + FRB SR 13-19 §II + FFIEC IT Handbook
      Outsourcing booklet §II) — every vendor in the operator's
      Drata workspace gets an INFORMATIONAL inventory finding;
      Drata-flagged HIGH or CRITICAL risk-level vendors additionally
      get a MEDIUM ACTIVE finding with OCC §III.A.4 ongoing-
      monitoring mappings calling for operator review.

    Auth: pass the API token via env var (default
    ``DRATA_API_TOKEN``). Drata uses Personal API tokens that pass
    ``Authorization: Bearer <token>`` headers. Recommended scope:
    read-only access to the vendor inventory surface.

    Deferred to subsequent v0.7.9 P0.4 slices:

    - Drata control test results
    - Ongoing-monitoring posture changes (state-diff)
    - OAuth 2.0 client-credentials grant
    - Webhook event ingestion (push model)
    """
    try:
        from evidentia_collectors.drata import (
            DrataCollector,
            DrataCollectorError,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] Drata collector module not importable. "
            "Run [cyan]pip install evidentia-collectors[/cyan]."
        )
        raise typer.Exit(code=1) from e

    api_token = os.environ.get(token_env)
    if not api_token:
        console.print(
            f"[red]Error:[/red] env var [cyan]{token_env}[/cyan] "
            "is not set or is empty. Set it to your Drata API token."
        )
        raise typer.Exit(code=1)

    try:
        with DrataCollector(
            api_token=api_token,
            base_url=base_url,
            max_vendors=max_vendors,
        ) as collector:
            findings = collector.collect()
    except DrataCollectorError as e:
        console.print(f"[red]Drata collection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    _write_findings(
        findings,
        output,
        title=f"Drata findings ({base_url})",
    )


@app.command("bitsight")
def collect_bitsight(
    token_env: str = typer.Option(
        "BITSIGHT_API_TOKEN",
        "--token-env",
        help=(
            "Name of the env var holding the BitSight API token. "
            "Defaults to BITSIGHT_API_TOKEN. The collector wraps "
            "the token in HTTP Basic auth (token:empty-password) "
            "internally; the token never appears in URLs."
        ),
    ),
    base_url: str = typer.Option(
        "https://api.bitsighttech.com",
        "--base-url",
        help="BitSight API base URL.",
    ),
    max_companies: int = typer.Option(
        2000,
        "--max-companies",
        min=1,
        max=100_000,
        help=(
            "Hard cap on portfolio enumeration. Default 2000 — "
            "covers typical portfolios."
        ),
    ),
    rating_threshold: int = typer.Option(
        700,
        "--rating-threshold",
        min=250,
        max=900,
        help=(
            "BitSight rating below which to emit a low-rating "
            "finding. Default 700 (BitSight's 'Basic' boundary "
            "between B and C grades). Range 250-900."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect compliance evidence from a BitSight portfolio (read-only).

    v0.7.9 P0.4 third slice ships portfolio inventory + per-company
    low-rating flag detection.

    BitSight is a continuous-rating provider; ratings are on a
    250-900 scale (A: 740-900, B: 670-739, C: 600-669, D: 530-599,
    F: <530). The collector emits an INFORMATIONAL finding per
    portfolio company (NIST SR-2 / SR-3 / SR-6 + OCC 2013-29 §III.A
    + FRB SR 13-19 §II + FFIEC IT Handbook Outsourcing booklet §II)
    plus a MEDIUM ACTIVE finding when the rating falls below the
    operator-configured threshold (default 700; RA-3 + CA-7 + OCC
    §III.A.4 + SR 13-19 §II.D).

    Auth: pass the API token via env var (default
    ``BITSIGHT_API_TOKEN``). BitSight uses HTTP Basic with token
    as username and empty password — the collector handles this
    internally.

    Deferred to subsequent v0.7.9 P0.4 slices:

    - Per-company factor scores (Botnet Infections, Spam,
      Patching Cadence, etc.)
    - Historical rating trends (90-day window)
    """
    try:
        from evidentia_collectors.bitsight import (
            BitSightCollector,
            BitSightCollectorError,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] BitSight collector module not "
            "importable. Run [cyan]pip install evidentia-collectors[/cyan]."
        )
        raise typer.Exit(code=1) from e

    api_token = os.environ.get(token_env)
    if not api_token:
        console.print(
            f"[red]Error:[/red] env var [cyan]{token_env}[/cyan] "
            "is not set or is empty. Set it to your BitSight API token."
        )
        raise typer.Exit(code=1)

    try:
        with BitSightCollector(
            api_token=api_token,
            base_url=base_url,
            max_companies=max_companies,
            low_rating_threshold=rating_threshold,
        ) as collector:
            findings = collector.collect()
    except BitSightCollectorError as e:
        console.print(f"[red]BitSight collection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    _write_findings(
        findings,
        output,
        title=f"BitSight findings ({base_url})",
    )


@app.command("securityscorecard")
def collect_securityscorecard(
    portfolio_id: str | None = typer.Option(
        None,
        "--portfolio-id",
        help=(
            "SSC portfolio identifier. If omitted, the collector "
            "lists portfolios first and pulls from the first "
            "available one."
        ),
    ),
    token_env: str = typer.Option(
        "SECURITYSCORECARD_API_TOKEN",
        "--token-env",
        help=(
            "Name of the env var holding the SSC API token. "
            "Defaults to SECURITYSCORECARD_API_TOKEN. The collector "
            "passes Authorization: Token <value> headers."
        ),
    ),
    base_url: str = typer.Option(
        "https://api.securityscorecard.io",
        "--base-url",
        help="SecurityScorecard API base URL.",
    ),
    max_companies: int = typer.Option(
        2000,
        "--max-companies",
        min=1,
        max=100_000,
        help=(
            "Hard cap on portfolio enumeration. Default 2000 — "
            "covers typical portfolios."
        ),
    ),
    score_threshold: int = typer.Option(
        70,
        "--score-threshold",
        min=0,
        max=100,
        help=(
            "SSC score below which to emit a low-score finding. "
            "Default 70 (boundary between C and D grades). "
            "Range 0-100."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the findings JSON. Default: stdout.",
    ),
) -> None:
    """Collect compliance evidence from a SecurityScorecard
    portfolio (read-only).

    v0.7.9 P0.4 fourth slice ships portfolio inventory + per-company
    low-score flag detection. Sister collector to BitSight.

    SSC scores 0-100 with grades A (90+), B (80-89), C (70-79),
    D (60-69), F (<60). The collector emits an INFORMATIONAL
    finding per portfolio company plus a MEDIUM ACTIVE finding
    when the score falls below the operator-configured threshold
    (default 70).

    Auth: pass the API token via env var (default
    ``SECURITYSCORECARD_API_TOKEN``). SSC uses
    ``Authorization: Token <value>`` headers (distinct from
    BitSight's HTTP Basic).

    Deferred to subsequent v0.7.9 P0.4 slices:

    - Per-company factor scores (Application Security, DNS Health,
      Endpoint Security, Hacker Chatter, IP Reputation, Network
      Security, Patching Cadence, Social Engineering, etc.)
    - Historical grade trends
    """
    try:
        from evidentia_collectors.securityscorecard import (
            SecurityScorecardCollector,
            SecurityScorecardCollectorError,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] SecurityScorecard collector module "
            "not importable. Run "
            "[cyan]pip install evidentia-collectors[/cyan]."
        )
        raise typer.Exit(code=1) from e

    api_token = os.environ.get(token_env)
    if not api_token:
        console.print(
            f"[red]Error:[/red] env var [cyan]{token_env}[/cyan] "
            "is not set or is empty. Set it to your "
            "SecurityScorecard API token."
        )
        raise typer.Exit(code=1)

    try:
        with SecurityScorecardCollector(
            api_token=api_token,
            portfolio_id=portfolio_id,
            base_url=base_url,
            max_companies=max_companies,
            low_score_threshold=score_threshold,
        ) as collector:
            findings = collector.collect()
    except SecurityScorecardCollectorError as e:
        console.print(
            f"[red]SecurityScorecard collection failed:[/red] {e}"
        )
        raise typer.Exit(code=1) from e

    _write_findings(
        findings,
        output,
        title=f"SecurityScorecard findings ({base_url})",
    )


# ── rendering ────────────────────────────────────────────────────────────


def _write_findings(
    findings: Iterable[SecurityFinding],
    output: Path | None,
    *,
    title: str,
) -> None:
    findings_list = list(findings)
    payload = [f.model_dump(mode="json") for f in findings_list]

    if output is not None:
        output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        console.print(f"[green]Wrote {len(findings_list)} findings to[/green] {output}")
    elif not findings_list:
        console.print("[yellow]No findings.[/yellow]")

    _render_summary(findings_list, title=title)


def _render_summary(findings: list[SecurityFinding], *, title: str) -> None:
    total = len(findings)
    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_source[f.source_system] = by_source.get(f.source_system, 0) + 1

    table = Table(title=f"{title} — {total} total")
    table.add_column("Severity", style="cyan")
    table.add_column("Count")
    for sev in ("critical", "high", "medium", "low", "informational"):
        if sev in by_severity:
            table.add_row(sev, str(by_severity[sev]))
    console.print(table)

    if by_source:
        src_table = Table(title="By source", show_header=True)
        src_table.add_column("Source")
        src_table.add_column("Count")
        for src, n in sorted(by_source.items()):
            src_table.add_row(src, str(n))
        console.print(src_table)
