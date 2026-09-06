"""`evidentia init` \u2014 bootstrap a new Evidentia project.

v0.4.0 moved the starter-file templates and framework-recommendation rules
into :mod:`evidentia_core.init_wizard` so the GUI's onboarding wizard
(``POST /api/init/wizard``) can produce identical files without touching
this Typer command.
"""

from __future__ import annotations

from pathlib import Path

import typer
from evidentia_core.init_wizard import (
    generate_evidentia_yaml,
    generate_my_controls_yaml,
    generate_system_context_yaml,
)
from rich.console import Console

console = Console()


def init(
    directory: Path = typer.Option(
        Path("."),
        "--directory",
        "-d",
        help="Target directory for the new project (default: current directory).",
    ),
    frameworks: str = typer.Option(
        "nist-800-53-rev5-moderate,soc2-tsc",
        "--frameworks",
        "-f",
        help="Comma-separated default framework IDs.",
    ),
    organization: str = typer.Option(
        "Acme Corporation",
        "--organization",
        "-o",
        help="Organization name used in the generated evidentia.yaml.",
    ),
    preset: str = typer.Option(
        "nist-moderate-starter",
        "--preset",
        help=(
            "Starter control set for my-controls.yaml. One of: "
            "soc2-starter, nist-moderate-starter, hipaa-starter, "
            "cmmc-starter, empty."
        ),
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite existing files.",
    ),
) -> None:
    """Initialize a new Evidentia project in the target directory."""
    directory.mkdir(parents=True, exist_ok=True)

    framework_list = [f.strip() for f in frameworks.split(",") if f.strip()]

    # v0.4.0: delegate to evidentia_core.init_wizard \u2014 same code path
    # the GUI's /api/init/wizard endpoint uses.
    try:
        files = {
            "evidentia.yaml": generate_evidentia_yaml(
                organization=organization,
                frameworks=framework_list,
            ),
            "my-controls.yaml": generate_my_controls_yaml(
                preset=preset,  # type: ignore[arg-type]
                organization=organization,
            ),
            "system-context.yaml": generate_system_context_yaml(
                organization=organization,
                system_name=f"{organization} Platform",
                regulatory_requirements=framework_list,
            ),
        }
    except ValueError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1) from None

    created: list[str] = []
    skipped: list[str] = []

    for filename, content in files.items():
        target = directory / filename
        if target.exists() and not force:
            skipped.append(filename)
            continue
        target.write_text(content, encoding="utf-8")
        created.append(filename)

    storage = directory / ".evidentia"
    storage.mkdir(exist_ok=True)

    console.print(f"[bold cyan]Evidentia project initialized in[/bold cyan] {directory}")
    for f in created:
        console.print(f"  [green]created[/green]  {f}")
    for f in skipped:
        console.print(f"  [yellow]skipped[/yellow]  {f} (already exists; pass --force to overwrite)")
    console.print("  [green]created[/green]  .evidentia/")
    console.print()
    console.print("[bold]Next steps:[/bold]")
    console.print("  1. Edit [cyan]my-controls.yaml[/cyan] with your real control inventory.")
    console.print(
        "  2. Run: [cyan]evidentia gap analyze --inventory my-controls.yaml "
        f"--frameworks {frameworks} --output report.json[/cyan]"
    )
    console.print(
        "  3. (Optional) Edit [cyan]system-context.yaml[/cyan] and run [cyan]evidentia risk generate ...[/cyan]"
    )
    console.print(
        "  4. Launch the web UI: [cyan]evidentia serve[/cyan] "
        r"(requires the \[gui] extra: [cyan]pip install 'evidentia[gui]'[/cyan])"
    )
