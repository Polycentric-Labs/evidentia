"""`evidentia explain` — plain-English control explanations via LLM.

v0.3.0: one of the locked-in differentiator features. Translates any
bundled control's authoritative text into engineer-and-executive-
friendly language. Answers are cached on disk per
``(framework, control, model, temperature)`` so you only pay the LLM
cost once.

Usage::

    evidentia explain AC-2 --framework nist-800-53-rev5
    evidentia explain CC6.1 --framework soc2-tsc --model claude-opus-4
    evidentia explain AC-2 --framework nist-800-53-rev5 --refresh
"""

from __future__ import annotations

import os
from pathlib import Path

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

app = typer.Typer(help="Plain-English control explanation commands.")
console = Console()


@app.command("control")
def explain_control(
    ctx: typer.Context,
    control_id: str = typer.Argument(
        ...,
        help="Control ID to explain, e.g. 'AC-2' or 'AC-2(1)' or 'ac-2.1'.",
    ),
    framework: str | None = typer.Option(
        None,
        "--framework",
        "-f",
        help=(
            "Framework ID the control belongs to (e.g. 'nist-800-53-rev5'). "
            "Reads from `evidentia.yaml` when --framework is omitted and "
            "exactly one framework is configured."
        ),
    ),
    model: str | None = typer.Option(
        None,
        "--model",
        "-m",
        help=("LLM model. Defaults to $EVIDENTIA_LLM_MODEL, then evidentia.yaml llm.model, then 'gpt-4o'."),
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        help="Force re-generation even if a cached explanation exists.",
    ),
    format: str = typer.Option(
        "panel",
        "--format",
        help="Output format: panel (Rich box, default), markdown, json.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write to this file instead of stdout.",
    ),
) -> None:
    """Translate a compliance control into plain English.

    The first call for a given (framework, control, model, temperature)
    tuple hits the LLM and caches the result. Subsequent calls return
    the cached explanation instantly.
    """
    from evidentia_core.catalogs.registry import FrameworkRegistry
    from evidentia_core.config import EvidentiaConfig, get_default

    cfg_obj = ctx.obj.get("config") if ctx.obj else None
    cfg: EvidentiaConfig = cfg_obj if cfg_obj is not None else EvidentiaConfig()

    # Resolve framework: --framework > only entry in cfg.frameworks > error
    resolved_fw = framework
    if not resolved_fw:
        fws = cfg.frameworks
        if len(fws) == 1:
            resolved_fw = fws[0]
        elif len(fws) > 1:
            console.print(
                f"[red]Multiple frameworks in evidentia.yaml ({len(fws)}); specify --framework to pick one.[/red]"
            )
            raise typer.Exit(code=1)
        else:
            console.print("[red]--framework is required (or set a single framework in evidentia.yaml).[/red]")
            raise typer.Exit(code=1)

    # Resolve LLM model
    resolved_model = get_default(cfg, model, "llm.model", env_var="EVIDENTIA_LLM_MODEL")
    # Fall back to the AI client's default (reads env + hardcoded default)
    if not resolved_model:
        from evidentia_ai.client import get_default_model

        resolved_model = get_default_model()

    # Temperature (same precedence pattern as `risk generate`)
    import contextlib

    resolved_temperature: float | None = None
    env_temp = os.environ.get("EVIDENTIA_LLM_TEMPERATURE")
    if env_temp is not None:
        with contextlib.suppress(ValueError):
            resolved_temperature = float(env_temp)
    if resolved_temperature is None and cfg.llm.temperature is not None:
        resolved_temperature = cfg.llm.temperature

    # Look up the control
    registry = FrameworkRegistry.get_instance()
    try:
        control = registry.get_control(resolved_fw, control_id)
    except Exception as exc:
        console.print(f"[red]Could not load framework '{resolved_fw}': {exc}[/red]")
        raise typer.Exit(code=1) from exc

    if control is None:
        console.print(
            f"[red]Control '{control_id}' not found in framework "
            f"'{resolved_fw}'.[/red]\n"
            f"[dim]Run `evidentia catalog show {resolved_fw}` to see "
            f"available control IDs.[/dim]"
        )
        raise typer.Exit(code=1)

    # Pre-flight: is an LLM API key available? If not, give a clear message
    # instead of a cryptic LiteLLM auth error 10 seconds in.
    _preflight_llm_auth(resolved_model)

    # Run the generator (cached)
    from evidentia_ai.explain import ExplanationGenerator

    gen = ExplanationGenerator(
        model=resolved_model,
        temperature=resolved_temperature,
    )
    console.print(
        f"[cyan]Generating explanation for[/cyan] "
        f"[bold]{resolved_fw}:{control.id}[/bold] "
        f"using [bold]{resolved_model}[/bold]..."
    )
    try:
        explanation = gen.generate(control, framework_id=resolved_fw, refresh=refresh)
    except Exception as exc:
        console.print(f"[red]LLM call failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc

    # Render. Non-panel branches populate `text` (str); panel renders
    # directly via Rich and short-circuits.
    if format == "panel":
        _render_panel(explanation)
        return
    if format == "json":
        text = explanation.model_dump_json(indent=2)
    elif format == "markdown":
        text = _render_markdown(explanation)
    else:
        console.print(f"[red]Unknown --format: {format!r}[/red]")
        raise typer.Exit(code=1)

    if output is not None:
        output.write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote:[/green] {output}")
    else:
        import sys

        sys.stdout.write(text)
        sys.stdout.write("\n")


def _preflight_llm_auth(model: str) -> None:
    """Warn (non-fatally) if no API key looks configured for the picked model.

    Matches model-prefix → env var so the hint is model-appropriate rather
    than a generic "set some API key somewhere".
    """
    hints = {
        "gpt": "OPENAI_API_KEY",
        "openai": "OPENAI_API_KEY",
        "claude": "ANTHROPIC_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "gemini": "GOOGLE_API_KEY",
        "google": "GOOGLE_API_KEY",
    }
    for prefix, env_var in hints.items():
        if prefix in model.lower() and not os.environ.get(env_var):
            console.print(
                f"[yellow]Note: ${env_var} is not set. The '{model}' call "
                f"will likely fail unless you're using an OpenAI-compatible "
                f"endpoint or LiteLLM fallback.[/yellow]"
            )
            return


def _render_markdown(exp) -> str:  # type: ignore[no-untyped-def]
    lines = [
        f"# {exp.control_id} — {exp.control_title}",
        f"*Framework: {exp.framework_id}*",
        "",
        "## Plain English",
        exp.plain_english,
        "",
        "## Why it matters",
        exp.why_it_matters,
        "",
        "## What to do",
    ]
    for step in exp.what_to_do:
        lines.append(f"- {step}")
    lines.extend(["", "## Effort estimate", exp.effort_estimate])
    if exp.common_misconceptions:
        lines.extend(["", "## Common misconceptions", exp.common_misconceptions])
    return "\n".join(lines)


def _render_panel(exp) -> None:  # type: ignore[no-untyped-def]
    body_md = _render_markdown(exp)
    console.print(
        Panel(
            Markdown(body_md),
            title=f"{exp.framework_id} / {exp.control_id}",
            border_style="cyan",
        )
    )


# ---------------------------------------------------------------------------
# Cache management commands (scoped under `evidentia explain cache ...`)
# ---------------------------------------------------------------------------

cache_app = typer.Typer(help="Manage the explanation cache.")
app.add_typer(cache_app, name="cache")


@cache_app.command("clear")
def clear(
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
) -> None:
    """Remove all cached explanations."""
    from evidentia_ai.explain.cache import clear_cache, get_cache_dir

    path = get_cache_dir()
    if not yes:
        confirm = typer.confirm(f"Delete all cached explanations in {path}?")
        if not confirm:
            console.print("[yellow]Cancelled.[/yellow]")
            raise typer.Exit(code=0)
    n = clear_cache()
    console.print(f"[green]Cleared {n} cached explanation(s).[/green]")


@cache_app.command("where")
def where() -> None:
    """Show the cache directory location."""
    from evidentia_ai.explain.cache import get_cache_dir

    path = get_cache_dir()
    console.print(str(path))
    console.print("[dim]Override via $EVIDENTIA_EXPLAIN_CACHE_DIR[/dim]")
