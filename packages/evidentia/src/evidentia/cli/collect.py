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
