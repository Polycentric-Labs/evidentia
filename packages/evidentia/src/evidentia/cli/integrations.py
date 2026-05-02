"""`evidentia integrations` — CLI wiring for output integrations.

v0.5.0 ships Jira only. ServiceNow / Vanta / Drata land in v0.5.1+.

Three subcommands under ``integrations jira``:

- ``test`` — validate creds + project access.
- ``push`` — push open gaps from a report as Jira issues.
- ``sync`` — pull status from Jira for every linked gap in a report.

All commands read credentials from environment variables (see
``docs/integrations/jira.md`` for the full list). ``--organization``,
``--project-key``, and friends are available as overrides for
scripting workflows.
"""

from __future__ import annotations

from pathlib import Path

import typer
from evidentia_core.models.gap import GapAnalysisReport
from evidentia_integrations.jira import (
    JiraApiError,
    JiraClient,
    JiraConfig,
    JiraSyncResult,
    push_open_gaps,
    sync_report,
)
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    no_args_is_help=True,
    help="Output integrations (Jira, ServiceNow, etc).",
)

jira_app = typer.Typer(
    no_args_is_help=True,
    help="Jira Cloud integration — push gaps as issues + status sync.",
)
app.add_typer(jira_app, name="jira")

servicenow_app = typer.Typer(
    no_args_is_help=True,
    help="ServiceNow integration — push gaps as records (incident / sn_grc_issue / custom).",
)
app.add_typer(servicenow_app, name="servicenow")

tableau_app = typer.Typer(
    no_args_is_help=True,
    help=(
        "Tableau integration — publish gap inventory + risk register "
        "+ collection-run audit trail to Tableau Server / Cloud."
    ),
)
app.add_typer(tableau_app, name="tableau")

powerbi_app = typer.Typer(
    no_args_is_help=True,
    help=(
        "Power BI integration — push gap inventory + risk register "
        "+ collection-run audit trail to a Power BI workspace."
    ),
)
app.add_typer(powerbi_app, name="powerbi")

console = Console()


def _load_report(gaps_path: Path) -> GapAnalysisReport:
    """Load a GapAnalysisReport from JSON on disk."""
    if not gaps_path.is_file():
        console.print(
            f"[red]Error:[/red] report not found: {gaps_path}. Run "
            "[cyan]evidentia gap analyze[/cyan] first."
        )
        raise typer.Exit(code=1)
    return GapAnalysisReport.model_validate_json(
        gaps_path.read_text(encoding="utf-8")
    )


def _save_report(report: GapAnalysisReport, gaps_path: Path) -> None:
    """Persist an updated GapAnalysisReport back to the same path."""
    gaps_path.write_text(
        report.model_dump_json(indent=2),
        encoding="utf-8",
    )


def _build_client() -> JiraClient:
    try:
        cfg = JiraConfig.from_env()
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e
    return JiraClient(cfg)


@jira_app.command("test")
def jira_test() -> None:
    """Verify Jira credentials + project access.

    Exits 0 on success, 1 on any credential / API failure.
    """
    client = _build_client()
    try:
        info = client.test_connection()
    except JiraApiError as e:
        console.print(f"[red]Jira connection failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    table = Table(title="Jira connection OK", show_lines=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for k in ("base_url", "user", "project_key", "project_name"):
        table.add_row(k, info.get(k, ""))
    console.print(table)


@jira_app.command("push")
def jira_push(
    gaps: Path = typer.Option(
        ...,
        "--gaps",
        "-g",
        help="Path to a GapAnalysisReport JSON (from `gap analyze --output`).",
    ),
    severity: str | None = typer.Option(
        None,
        "--severity",
        "-s",
        help=(
            "Comma-separated severities to push. E.g. 'critical,high'. "
            "Default: all severities."
        ),
    ),
    max_issues: int | None = typer.Option(
        None,
        "--max",
        help="Safety rail: cap total creates. Good for first-time runs.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help=(
            "Where to write the updated report. Default: overwrite the input. "
            "Pass '-' to skip the write (dry-run)."
        ),
    ),
) -> None:
    """Push open gaps from a report as Jira issues.

    Any gap whose ``jira_issue_key`` is already set is skipped. Severity
    filter restricts to only the severities listed. Exits 0 when all
    pushes succeed, 1 when any errored.
    """
    report = _load_report(gaps)

    severity_filter: set[str] | None = None
    if severity:
        severity_filter = {
            s.strip().lower() for s in severity.split(",") if s.strip()
        }

    with _build_client() as client:
        result = push_open_gaps(
            report,
            client,
            severity_filter=severity_filter,
            max_issues=max_issues,
        )

    _render_result(result, title="Jira push")

    if output is None:
        _save_report(report, gaps)
    elif str(output) != "-":
        _save_report(report, output)

    if result.errored > 0:
        raise typer.Exit(code=1)


@jira_app.command("sync")
def jira_sync(
    gaps: Path = typer.Option(
        ...,
        "--gaps",
        "-g",
        help="Path to a GapAnalysisReport JSON to sync.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Where to write the updated report. Default: overwrite the input.",
    ),
) -> None:
    """Pull status from Jira for every linked gap in the report."""
    report = _load_report(gaps)

    with _build_client() as client:
        result = sync_report(report, client)

    _render_result(result, title="Jira sync")

    if output is None:
        _save_report(report, gaps)
    elif str(output) != "-":
        _save_report(report, output)

    if result.errored > 0:
        raise typer.Exit(code=1)


def _render_result(result: JiraSyncResult, *, title: str) -> None:
    """Pretty-print a :class:`JiraSyncResult` as a Rich table."""
    table = Table(title=title, show_lines=False)
    table.add_column("Gap", style="cyan")
    table.add_column("Action")
    table.add_column("Issue")
    table.add_column("Detail")

    for o in result.outcomes:
        action_color = {
            "created": "green",
            "updated": "green",
            "skipped": "yellow",
            "errored": "red",
        }.get(o.action.value, "white")
        table.add_row(
            f"{o.framework}:{o.control_id}",
            f"[{action_color}]{o.action.value}[/{action_color}]",
            o.issue_key or "-",
            o.detail,
        )

    console.print(table)
    console.print(
        f"[bold]Summary:[/bold] created={result.created} "
        f"updated={result.updated} skipped={result.skipped} errored={result.errored}"
    )


@servicenow_app.command("test")
def servicenow_test() -> None:
    """Verify ServiceNow credentials + table read access."""
    try:
        from evidentia_integrations.servicenow import (
            ServiceNowApiError,
            ServiceNowClient,
            ServiceNowConfig,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] ServiceNow integration failed to import: "
            + str(e)
        )
        raise typer.Exit(code=1) from e

    try:
        cfg = ServiceNowConfig.from_env()
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e

    with ServiceNowClient(cfg) as client:
        try:
            info = client.test_connection()
        except ServiceNowApiError as e:
            console.print(f"[red]ServiceNow connection failed:[/red] {e}")
            raise typer.Exit(code=1) from e

    table = Table(title="ServiceNow connection OK", show_lines=False)
    table.add_column("Field", style="cyan")
    table.add_column("Value")
    for k in ("instance_url", "user", "table_name", "result_count"):
        table.add_row(k, info.get(k, ""))
    console.print(table)


@servicenow_app.command("push")
def servicenow_push(
    gaps: Path = typer.Option(
        ...,
        "--gaps",
        "-g",
        help="Path to a GapAnalysisReport JSON.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help=(
            "Create new records even if a matching correlation_id "
            "already exists. Rarely needed; mostly for testing."
        ),
    ),
) -> None:
    """Push open gaps from a report as ServiceNow records.

    Idempotent — re-running this command on the same report
    detects existing records via correlation_id and reports them
    as EXISTING rather than creating duplicates.
    """
    try:
        from evidentia_integrations.servicenow import (
            ServiceNowClient,
            ServiceNowConfig,
        )
        from evidentia_integrations.servicenow import (
            push_open_gaps as sn_push_open_gaps,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] ServiceNow integration failed to import: "
            + str(e)
        )
        raise typer.Exit(code=1) from e

    try:
        cfg = ServiceNowConfig.from_env()
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(code=1) from e

    report = _load_report(gaps)

    with ServiceNowClient(cfg) as client:
        result = sn_push_open_gaps(report, client, force=force)

    table = Table(title="ServiceNow push", show_lines=False)
    table.add_column("Gap", style="cyan")
    table.add_column("Action")
    table.add_column("Record")
    table.add_column("Detail")
    for o in result.outcomes:
        action_color = {
            "created": "green",
            "existing": "yellow",
            "skipped": "yellow",
            "errored": "red",
        }.get(o.action.value, "white")
        table.add_row(
            f"{o.framework}:{o.control_id}",
            f"[{action_color}]{o.action.value}[/{action_color}]",
            o.record_number or "-",
            o.detail,
        )
    console.print(table)
    console.print(
        f"[bold]Summary:[/bold] created={result.created} "
        f"existing={result.existing} skipped={result.skipped} "
        f"errored={result.errored}"
    )

    if result.errored > 0:
        raise typer.Exit(code=1)


@jira_app.command("status-map")
def jira_status_map(
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: 'table' or 'json'."
    ),
) -> None:
    """Print the Jira-status <-> GapStatus mapping currently in use."""
    from evidentia_integrations.jira import (
        GAP_STATUS_TO_JIRA_STATUS,
        JIRA_STATUS_TO_GAP_STATUS,
    )

    if output_format == "json":
        console.print_json(
            data={
                "gap_status_to_jira": {
                    k.value: v for k, v in GAP_STATUS_TO_JIRA_STATUS.items()
                },
                "jira_status_to_gap": {
                    k: v.value for k, v in JIRA_STATUS_TO_GAP_STATUS.items()
                },
            }
        )
        return

    table = Table(title="GapStatus -> Jira (push)")
    table.add_column("GapStatus", style="cyan")
    table.add_column("Jira status name")
    for gs, jira_name in GAP_STATUS_TO_JIRA_STATUS.items():
        table.add_row(gs.value, jira_name)
    console.print(table)

    table2 = Table(title="Jira status -> GapStatus (sync)")
    table2.add_column("Jira status (case-insensitive)", style="cyan")
    table2.add_column("GapStatus")
    for jira_name, gs in JIRA_STATUS_TO_GAP_STATUS.items():
        table2.add_row(jira_name, gs.value)
    console.print(table2)


# ── Tableau commands (v0.7.8 P1.1) ────────────────────────────────


def _load_risks_optional(risks_path: Path | None) -> object | None:
    """Load a JSON file containing a list of RiskStatement objects.

    Returns the parsed list, or None if no path was provided.
    Imports are inline so the function is free of evidentia-ai
    coupling when not needed.
    """
    if risks_path is None:
        return None
    if not risks_path.is_file():
        console.print(
            f"[red]Error:[/red] risks file not found: {risks_path}."
        )
        raise typer.Exit(code=1)
    import json as _json

    from evidentia_core.models.risk import RiskStatement

    payload = _json.loads(risks_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        console.print(
            "[red]Error:[/red] risks file must contain a JSON list."
        )
        raise typer.Exit(code=1)
    return [RiskStatement.model_validate(item) for item in payload]


@tableau_app.command("publish")
def tableau_publish(
    gaps: Path = typer.Option(
        ...,
        "--gaps",
        help=(
            "Path to a gap-analysis report JSON file (the output "
            "of 'evidentia gap analyze --output ...')."
        ),
    ),
    server_url: str = typer.Option(
        ...,
        "--server-url",
        help=(
            "Tableau Server / Cloud base URL. Example: "
            "'https://us-east-1.online.tableau.com' or "
            "'https://tableau.acme.example.com'. NO trailing slash."
        ),
    ),
    site_id: str = typer.Option(
        "",
        "--site-id",
        help=(
            "Tableau site ID slug. For Tableau Cloud, this is the "
            "site you signed up for; for Tableau Server's default "
            "site, leave empty (default empty string)."
        ),
    ),
    project_name: str = typer.Option(
        "default",
        "--project-name",
        help=(
            "Project name on the Tableau site to publish into. "
            "Defaults to 'default' (auto-created on every site)."
        ),
    ),
    pat_name_env: str = typer.Option(
        "TABLEAU_PAT_NAME",
        "--pat-name-env",
        help=(
            "Name of the env var holding the PAT name. The CLI "
            "reads from this env var (never accepts the PAT name "
            "or secret as a flag value)."
        ),
    ),
    pat_secret_env: str = typer.Option(
        "TABLEAU_PAT_SECRET",
        "--pat-secret-env",
        help="Name of the env var holding the PAT secret.",
    ),
    risks: Path | None = typer.Option(
        None,
        "--risks",
        help=(
            "Optional path to a JSON list of RiskStatement objects "
            "to publish as the 'evidentia-risks' dataset."
        ),
    ),
    no_overwrite: bool = typer.Option(
        False,
        "--no-overwrite",
        help=(
            "If set, publish in CreateNew mode and fail if the "
            "datasets already exist. Default is Overwrite (re-"
            "running the publish updates the existing data sources)."
        ),
    ),
) -> None:
    """Publish gap inventory + risk register to Tableau as data sources."""
    try:
        from evidentia_integrations.tableau import (
            TableauApiError,
            TableauConfig,
            publish_report,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] Tableau integration is not "
            "installed. Run "
            "[cyan]pip install 'evidentia-integrations[tableau]'[/cyan]."
        )
        raise typer.Exit(code=1) from e

    report = _load_report(gaps)
    risk_list = _load_risks_optional(risks)
    cfg = TableauConfig(
        server_url=server_url,
        site_id=site_id,
        project_name=project_name,
        pat_name_env=pat_name_env,
        pat_secret_env=pat_secret_env,
    )
    try:
        result = publish_report(
            config=cfg,
            report=report,
            risks=risk_list,  # type: ignore[arg-type]
            overwrite=not no_overwrite,
        )
    except TableauApiError as e:
        console.print(
            f"[red]Tableau publish failed:[/red] {e}"
        )
        raise typer.Exit(code=1) from e

    table = Table(title=f"Tableau publish result ({server_url})")
    table.add_column("Dataset", style="cyan")
    table.add_column("Datasource ID")
    table.add_column("Rows")
    for ds in result.datasets:
        table.add_row(ds.name, ds.datasource_id, str(ds.rows))
    console.print(table)
    if result.skipped:
        console.print(
            "[yellow]Skipped:[/yellow] " + "; ".join(result.skipped)
        )


# ── Power BI commands (v0.7.8 P1.2) ───────────────────────────────


@powerbi_app.command("publish")
def powerbi_publish(
    gaps: Path = typer.Option(
        ...,
        "--gaps",
        help="Path to a gap-analysis report JSON file.",
    ),
    workspace_id: str = typer.Option(
        ...,
        "--workspace-id",
        help="Power BI workspace ID (UUID).",
    ),
    tenant_id: str = typer.Option(
        ...,
        "--tenant-id",
        help="Azure AD tenant ID (UUID).",
    ),
    client_id: str = typer.Option(
        ...,
        "--client-id",
        help=(
            "Azure AD service-principal application (client) ID. "
            "Must have Dataset.ReadWrite.All on the target "
            "workspace."
        ),
    ),
    client_secret_env: str = typer.Option(
        "POWERBI_CLIENT_SECRET",
        "--client-secret-env",
        help=(
            "Name of the env var holding the service-principal "
            "client secret. The CLI reads from this env var "
            "(never accepts the secret as a flag value)."
        ),
    ),
    risks: Path | None = typer.Option(
        None,
        "--risks",
        help="Optional path to a JSON list of RiskStatement objects.",
    ),
    no_clear: bool = typer.Option(
        False,
        "--no-clear",
        help=(
            "If set, append rows to existing datasets rather than "
            "clearing them first (default behavior is full-refresh "
            "via clear-then-push)."
        ),
    ),
) -> None:
    """Push gap inventory + risk register to Power BI as Push Datasets."""
    try:
        from evidentia_integrations.powerbi import (
            PowerBIApiError,
            PowerBIConfig,
            publish_report,
        )
    except ImportError as e:
        console.print(
            "[red]Error:[/red] Power BI integration is not "
            "installed. Run "
            "[cyan]pip install 'evidentia-integrations[powerbi]'[/cyan]."
        )
        raise typer.Exit(code=1) from e

    report = _load_report(gaps)
    risk_list = _load_risks_optional(risks)
    cfg = PowerBIConfig(
        workspace_id=workspace_id,
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret_env=client_secret_env,
    )
    try:
        result = publish_report(
            config=cfg,
            report=report,
            risks=risk_list,  # type: ignore[arg-type]
            clear_before_push=not no_clear,
        )
    except PowerBIApiError as e:
        console.print(f"[red]Power BI publish failed:[/red] {e}")
        raise typer.Exit(code=1) from e

    table = Table(
        title=f"Power BI publish result (workspace {workspace_id})"
    )
    table.add_column("Dataset", style="cyan")
    table.add_column("Dataset ID")
    table.add_column("Table")
    table.add_column("Rows")
    for ds in result.datasets:
        table.add_row(
            ds.name, ds.dataset_id, ds.table_name, str(ds.rows)
        )
    console.print(table)
    if result.skipped:
        console.print(
            "[yellow]Skipped:[/yellow] " + "; ".join(result.skipped)
        )
