"""`evidentia governance` — Governance commands (v0.7.10 P1.5).

Foundation for the v0.7.10 P1.5 governance primitives. Currently
ships:

  - ``evidentia governance lines-report --classifications <yaml>``

Future v0.7.10 sub-slices will extend this group with
``effective-challenge`` (P1.5 G2), KRI / KPI / KGI dashboards
(P1.5 G3+), Open FAIR risk quantification (P1.5 G4), and
process-as-code workflows (P1.5 G5).
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
import yaml
from evidentia_core.governance import (
    LineOfDefense,
    Owner,
    generate_lines_report,
)
from pydantic import ValidationError
from rich.console import Console

app = typer.Typer(help="Governance commands (3LOD + Effective Challenge).")
console = Console()


def _load_classifications(path: Path) -> list[Owner]:
    """Load a YAML overlay mapping email → line-of-defense classification.

    Expected YAML shape (one entry per owner)::

        - email: alice@example.com
          line_of_defense: first
          team: Loan Origination
          title: Senior Underwriter
        - email: bob@example.com
          line_of_defense: second
          team: MRM
          title: VP, Model Risk

    Returns the parsed list of :class:`Owner` instances. Exits
    cleanly with a clear error on parse failure.
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except OSError as e:
        console.print(f"[red]Error:[/red] could not read {path}: {e}")
        raise typer.Exit(code=1) from e
    except yaml.YAMLError as e:
        console.print(
            f"[red]Error:[/red] {path} is not valid YAML: {e}"
        )
        raise typer.Exit(code=1) from e

    if raw is None:
        # Empty file = no owners; let the report generator render
        # the empty-case narrative.
        return []
    if not isinstance(raw, list):
        console.print(
            f"[red]Error:[/red] {path} must be a YAML list of "
            "owner records (got "
            f"{type(raw).__name__})."
        )
        raise typer.Exit(code=1)

    owners: list[Owner] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            console.print(
                f"[red]Error:[/red] entry {i} in {path} is not a mapping; "
                f"got {type(entry).__name__}."
            )
            raise typer.Exit(code=1)
        try:
            owners.append(Owner.model_validate(entry))
        except ValidationError as e:
            console.print(
                f"[red]Error:[/red] entry {i} in {path} failed validation: {e}"
            )
            raise typer.Exit(code=1) from e
    return owners


@app.command("lines-report")
def lines_report(
    classifications: Path = typer.Option(
        ...,
        "--classifications",
        "-c",
        help=(
            "Path to a YAML overlay listing owners + line-of-defense "
            "classifications. See `evidentia governance lines-report "
            "--help` for the expected YAML shape."
        ),
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path. If omitted, prints to stdout.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Overwrite the output path if it already exists.",
    ),
) -> None:
    """Generate a Three Lines of Defense distribution report.

    Reads classified owners from a YAML overlay file and produces a
    Markdown distribution report covering:

      - Per-line counts + percentages
      - Crossover warning (any owner classified across multiple
        lines is flagged as a regulator-noted anti-pattern)
      - Per-line owner listing
      - Per-team breakdown showing which lines each team
        participates in

    The report is deterministic — same input produces the same
    output. Operators can therefore commit generated reports to git
    + audit-diff them across review cycles.
    """
    owners = _load_classifications(classifications)
    rendered = generate_lines_report(owners)

    if output is None:
        sys.stdout.write(rendered)
        if not rendered.endswith("\n"):
            sys.stdout.write("\n")
        return

    if output.exists() and not force:
        console.print(
            f"[red]Error:[/red] {output} already exists; pass --force to overwrite."
        )
        raise typer.Exit(code=1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8")
    n_first = sum(1 for o in owners if o.line_of_defense == LineOfDefense.FIRST.value)
    n_second = sum(1 for o in owners if o.line_of_defense == LineOfDefense.SECOND.value)
    n_third = sum(1 for o in owners if o.line_of_defense == LineOfDefense.THIRD.value)
    console.print(
        f"[green]Wrote[/green] 3LOD report to [bold]{output}[/bold] "
        f"({len(owners)} owner(s); 1st={n_first} / 2nd={n_second} / 3rd={n_third})."
    )
