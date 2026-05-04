"""Evidentia CLI entry point.

The CLI is a thin Typer wrapper around the evidentia_core, evidentia_ai,
evidentia_collectors, and evidentia_integrations libraries.
"""

from __future__ import annotations

import logging
import sys

import typer
from rich.console import Console
from rich.table import Table

from evidentia.cli import catalog as catalog_cmd
from evidentia.cli import collect as collect_cmd
from evidentia.cli import explain as explain_cmd
from evidentia.cli import gap as gap_cmd
from evidentia.cli import governance as governance_cmd
from evidentia.cli import init as init_cmd
from evidentia.cli import integrations as integrations_cmd
from evidentia.cli import model_risk as model_risk_cmd
from evidentia.cli import oscal as oscal_cmd
from evidentia.cli import risk as risk_cmd
from evidentia.cli import tprm as tprm_cmd

app = typer.Typer(
    name="evidentia",
    help=(
        "Evidentia: open-source GRC tool for gap analysis, risk statements, "
        "and compliance automation."
    ),
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# Sub-applications
app.add_typer(gap_cmd.app, name="gap", help="Gap analysis commands.")
app.add_typer(catalog_cmd.app, name="catalog", help="Framework catalog commands.")
app.add_typer(risk_cmd.app, name="risk", help="AI risk statement commands.")
app.add_typer(
    explain_cmd.app,
    name="explain",
    help="Plain-English LLM-generated control explanations.",
)
app.add_typer(
    integrations_cmd.app,
    name="integrations",
    help="Output integrations — Jira, ServiceNow, etc.",
)
app.add_typer(
    collect_cmd.app,
    name="collect",
    help="Evidence collectors — AWS, GitHub, etc.",
)
app.add_typer(
    oscal_cmd.app,
    name="oscal",
    help="OSCAL integrity + signature tooling (v0.7.0).",
)
app.add_typer(
    tprm_cmd.app,
    name="tprm",
    help="Third-Party Risk Management — vendor inventory + DD (v0.7.9 P0.1).",
)
app.add_typer(
    model_risk_cmd.app,
    name="model-risk",
    help="Model Risk Management — SR 11-7 / SR 26-02 model inventory (v0.7.10 P0.6).",
)
app.add_typer(
    governance_cmd.app,
    name="governance",
    help="Governance — Three Lines of Defense + Effective Challenge (v0.7.10 P1.5).",
)
app.command(name="init", help="Initialize a new Evidentia project.")(init_cmd.init)

console = Console()


@app.callback()
def _global_options(
    ctx: typer.Context,
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable verbose (DEBUG) logging."
    ),
    quiet: bool = typer.Option(
        False, "--quiet", "-q", help="Suppress non-error output."
    ),
    config: typer.FileText | None = typer.Option(
        None,
        "--config",
        help=(
            "Path to a evidentia.yaml config file. Defaults to walking "
            "CWD -> parents for the first `evidentia.yaml` found."
        ),
    ),
    offline: bool = typer.Option(
        False,
        "--offline",
        help=(
            "Air-gapped mode: refuse all outbound network calls. LLM "
            "features require an Ollama/vLLM/local endpoint. Use with "
            "`evidentia doctor --check-air-gap` to validate posture."
        ),
    ),
    json_logs: bool = typer.Option(
        False,
        "--json-logs",
        help=(
            "v0.7.0: emit logs as ECS 8.11-compliant JSON (one record "
            "per line) instead of human-readable Rich console output. "
            "Drop-in ingestable by Splunk / Elastic / Datadog / Sumo "
            "Logic / Microsoft Sentinel. Use in SIEM-ingest pipelines "
            "and CI systems that parse structured logs."
        ),
    ),
) -> None:
    """Global options applied to all commands."""
    level = logging.DEBUG if verbose else (logging.ERROR if quiet else logging.INFO)

    if json_logs:
        # v0.7.0: switch the ``evidentia`` logger hierarchy to ECS JSON
        # output BEFORE basicConfig so the caller's JSON-consumer pipeline
        # sees structured events from the first log line onward.
        from evidentia_core.audit import enable_json_logs as _enable_json_logs

        _enable_json_logs()
        logging.getLogger("evidentia").setLevel(level)
    else:
        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        )

    # v0.4.0: flip the process-wide air-gap guard. Every LLM call and
    # every URL-based catalog import consults the module-level flag.
    if offline:
        from evidentia_core.network_guard import set_offline

        set_offline(True)
        logging.getLogger("evidentia.cli").info(
            "Air-gapped mode enabled (--offline) — outbound network calls "
            "to non-loopback hosts will raise OfflineViolationError."
        )

    # v0.2.1: load evidentia.yaml once and make it available to every
    # subcommand via ctx.obj. Subcommands consult it through
    # `evidentia_core.config.get_default()` with the precedence rule
    # CLI flag > env var > yaml > built-in default.
    from pathlib import Path

    from evidentia_core.config import load_config

    explicit_path = Path(config.name) if config is not None else None
    cfg = load_config(explicit_path)
    ctx.obj = {"config": cfg, "offline": offline, "json_logs": json_logs}
    if cfg.source_path is not None:
        logging.getLogger("evidentia.config").debug(
            "Loaded config from %s", cfg.source_path
        )


@app.command()
def version() -> None:
    """Show Evidentia version and Python environment information."""
    from evidentia import __version__ as cb_version

    py = ".".join(str(v) for v in sys.version_info[:3])
    console.print(f"[bold cyan]Evidentia[/bold cyan] v{cb_version}")
    console.print(f"Python {py}")


@app.command()
def doctor(
    check_air_gap: bool = typer.Option(
        False,
        "--check-air-gap",
        help=(
            "Run the air-gap validator: enumerate every subsystem that "
            "issues network calls and report each one's offline posture "
            "(Ollama-ready, custom api_base on loopback, or cloud-only)."
        ),
    ),
) -> None:
    """Run a diagnostic check of the Evidentia installation."""
    from evidentia_core.catalogs.registry import FrameworkRegistry

    table = Table(title="Evidentia Diagnostics")
    table.add_column("Check", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Detail")

    py = ".".join(str(v) for v in sys.version_info[:3])
    table.add_row("Python", "OK", py)

    # Core packages
    for pkg in [
        "evidentia_core",
        "evidentia_ai",
        "evidentia_collectors",
        "evidentia_integrations",
    ]:
        try:
            __import__(pkg)
            table.add_row(pkg, "OK", "installed")
        except ImportError as e:
            table.add_row(pkg, "MISSING", str(e))

    # evidentia-api (optional extra) — show only if installed
    try:
        __import__("evidentia_api")
        table.add_row("evidentia_api", "OK", "installed (web UI available)")
    except ImportError:
        table.add_row(
            "evidentia_api",
            "OPTIONAL",
            "not installed — `pip install 'evidentia[gui]'` for web UI",
        )

    # Catalogs and crosswalks
    try:
        FrameworkRegistry.reset_instance()
        registry = FrameworkRegistry.get_instance()
        frameworks = registry.list_frameworks()
        table.add_row(
            "OSCAL catalogs",
            "OK",
            f"{len(frameworks)} frameworks registered",
        )

        crosswalk = registry.crosswalk
        table.add_row(
            "Crosswalks",
            "OK",
            f"{len(crosswalk.available_frameworks)} frameworks mapped",
        )
    except Exception as e:
        table.add_row("OSCAL catalogs", "FAIL", str(e))

    # LLM API key detection
    import os

    llm_keys = {
        "OPENAI_API_KEY": "OpenAI",
        "ANTHROPIC_API_KEY": "Anthropic",
        "GOOGLE_API_KEY": "Google",
        "AZURE_OPENAI_API_KEY": "Azure OpenAI",
    }
    detected = [name for env, name in llm_keys.items() if os.environ.get(env)]
    if detected:
        table.add_row("LLM provider", "OK", ", ".join(detected))
    else:
        table.add_row(
            "LLM provider",
            "WARN",
            "No API key detected (set OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.)",
        )

    console.print(table)

    if check_air_gap:
        console.print()
        _render_air_gap_report()


def _render_air_gap_report() -> None:
    """Print a per-subsystem air-gap posture table.

    Each check answers: if ``--offline`` were on right now, would this
    subsystem's configured target be refused? Not a live network probe —
    pure configuration audit.
    """
    import os

    from evidentia_core.config import load_config
    from evidentia_core.network_guard import (
        LOCAL_LLM_PREFIXES,
        is_loopback_or_private,
    )

    cfg = load_config()

    table = Table(title="Air-gap Posture Report")
    table.add_column("Subsystem", style="cyan")
    table.add_column("Posture", style="green")
    table.add_column("Detail")

    # 1. LLM client — inspect configured model + EVIDENTIA_LLM_API_BASE env
    model = (
        os.environ.get("EVIDENTIA_LLM_MODEL")
        or (cfg.llm.model if cfg.llm else None)
        or "gpt-4o"
    )
    api_base = os.environ.get("EVIDENTIA_LLM_API_BASE") or os.environ.get(
        "OPENAI_API_BASE"
    )
    if any(model.lower().startswith(p) for p in LOCAL_LLM_PREFIXES):
        table.add_row(
            "LLM client",
            "AIR-GAP READY",
            f"model={model} (local prefix)",
        )
    elif api_base:
        from urllib.parse import urlparse

        host = urlparse(api_base).hostname or ""
        if is_loopback_or_private(host):
            table.add_row(
                "LLM client",
                "AIR-GAP READY",
                f"api_base={api_base} on loopback/RFC-1918",
            )
        else:
            table.add_row(
                "LLM client",
                "WOULD LEAK",
                f"api_base={api_base} (non-loopback host)",
            )
    else:
        table.add_row(
            "LLM client",
            "WOULD LEAK",
            f"model={model} is a cloud model; no local api_base set. "
            "Set EVIDENTIA_LLM_MODEL=ollama/llama3 or similar.",
        )

    # 2. Catalog loader — v0.4.0 only loads from bundled + user data dirs,
    # no URL-based imports yet. Reserved for v0.5.0 when --from-url lands.
    table.add_row(
        "Catalog loader",
        "AIR-GAP READY",
        "v0.4.0 loads only from bundled + user-dir catalogs (no URL fetch)",
    )

    # 3. AI telemetry — LiteLLM's Anthropic/OpenAI clients do not phone
    # home; Instructor doesn't either. No additional guards needed.
    table.add_row(
        "AI telemetry",
        "AIR-GAP READY",
        "LiteLLM + Instructor do not emit telemetry",
    )

    # 4. Gap store — on-disk in platformdirs, no network.
    table.add_row(
        "Gap store",
        "AIR-GAP READY",
        "platformdirs user-data (local filesystem only)",
    )

    # 5. FastAPI server (if installed) — localhost bind recommended.
    try:
        import evidentia_api  # noqa: F401

        table.add_row(
            "Web UI",
            "AIR-GAP READY",
            "`evidentia serve` binds to 127.0.0.1 by default",
        )
    except ImportError:
        pass

    console.print(table)
    console.print(
        "\n[dim]Pass [bold cyan]--offline[/bold cyan] on any command to enforce; "
        "this report audits the configuration, not live traffic.[/dim]"
    )


@app.command()
def serve(
    ctx: typer.Context,
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help=(
            "Host to bind the web UI to. Default 127.0.0.1 (localhost-only). "
            "Binding to 0.0.0.0 exposes the UI on your network; Evidentia "
            "has no auth in v0.4.0, so only do this if you know what you're doing."
        ),
    ),
    port: int = typer.Option(
        8000,
        "--port",
        "-p",
        help="Port to serve on (default: 8000).",
    ),
    dev: bool = typer.Option(
        False,
        "--dev",
        help=(
            "Dev mode: permissive CORS for the Vite dev server at :5173. "
            "Use with `npm run dev` in packages/evidentia-ui/."
        ),
    ),
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Don't auto-open a browser on startup.",
    ),
    reload: bool = typer.Option(
        False,
        "--reload",
        help="Enable uvicorn --reload for backend development.",
    ),
    security_headers: bool | None = typer.Option(
        None,
        "--security-headers/--no-security-headers",
        help=(
            "Inject defense-in-depth response headers (CSP, X-Frame-Options, "
            "X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security, "
            "Permissions-Policy) on every response. Default: auto — enabled "
            "when --host is non-loopback (operator opted into network "
            "exposure); disabled for localhost-bound dev binds. Pass "
            "--security-headers to force ON; --no-security-headers to force "
            "OFF (e.g., when a TLS-terminating reverse proxy already injects "
            "these headers and you don't want duplicates)."
        ),
    ),
) -> None:
    """Start the Evidentia web UI (REST API + React SPA).

    Requires the `[gui]` optional extra:

        pip install "evidentia[gui]"   # or `uv tool install ...`

    The server serves the React SPA at / and the REST API at /api/*.
    Press Ctrl+C to stop.
    """
    try:
        from evidentia_api.cli import serve as serve_impl
    except ImportError:
        console.print(
            "[bold red]Error:[/bold red] evidentia-api is not installed.\n\n"
            "Install the web UI extra:\n"
            "  [cyan]pip install 'evidentia[gui]'[/cyan]\n"
            "  [cyan]uv tool install 'evidentia[gui]'[/cyan]\n"
        )
        raise typer.Exit(code=1) from None

    # Propagate the global --offline flag into the serve subprocess env.
    offline = bool(ctx.obj.get("offline", False)) if ctx.obj else False

    exit_code = serve_impl(
        host=host,
        port=port,
        offline=offline,
        dev=dev,
        open_browser=not no_browser,
        reload=reload,
        security_headers=security_headers,
    )
    if exit_code != 0:
        raise typer.Exit(code=exit_code)


if __name__ == "__main__":
    app()
