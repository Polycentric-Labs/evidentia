"""Three Lines of Defense primitives (v0.7.10 P1.5 G1).

The Three Lines Model (IIA 2020 revision; superseded the legacy
"Three Lines of Defense" terminology but the regulator-facing
acronym 3LOD is still standard) classifies risk-management roles
into three independent oversight lines:

  - **First line** — business operations: model owners, vendor
    managers, control owners, system administrators. The people
    running the activity that creates the risk.
  - **Second line** — risk + compliance functions: chief risk
    officer, model-risk-management group, compliance, IT-risk.
    Independent of the first line; sets policy + monitors
    adherence.
  - **Third line** — internal audit: independent assurance
    function reporting to the board / audit committee. Independent
    of both first + second line.

This module ships the foundation primitives:

  - :class:`LineOfDefense` enum
  - :class:`Owner` Pydantic model linking an email identity to a
    line-of-defense classification (plus optional team + title)
  - :func:`generate_lines_report` — Markdown distribution report
    summarizing how owners are spread across the three lines, with
    an explicit warning callout when 1st / 2nd / 3rd line
    overlap is detected (a regulator anti-pattern: 1st-line owners
    cannot also be 2nd-line oversight)

Audit utility — a 3LOD distribution report is a standard early
finding artifact in MRM exam reviews. Producing it deterministically
from the vendor + model-risk inventories shifts the conversation
from "do you have one?" to "here it is; let's discuss findings."
"""

from __future__ import annotations

from collections import Counter, defaultdict
from enum import Enum

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel


class LineOfDefense(str, Enum):
    """3LOD classification per IIA Three Lines Model 2020 revision."""

    FIRST = "first"
    SECOND = "second"
    THIRD = "third"


class Owner(EvidentiaModel):
    """An owner identity with 3LOD classification.

    The minimum primitive for governance reporting. Each Owner ties
    an email identity to a line-of-defense classification so the
    aggregate distribution can be measured + presented.

    Optional ``team`` and ``title`` fields support richer reporting
    (e.g., "MRM team has 3 owners, 2 in 2nd line + 1 in 3rd line —
    governance crossover requires explanation").
    """

    email: str = Field(
        description=(
            "Owner's primary email address (acts as the identity key). "
            "Free-form str to match the existing inventory-model "
            "convention; light validation is up to the caller."
        )
    )
    line_of_defense: LineOfDefense = Field(
        description=(
            "3LOD classification per IIA Three Lines Model 2020. "
            "First line = business operations; second line = risk/"
            "compliance oversight; third line = internal audit."
        )
    )
    team: str | None = Field(
        default=None,
        description="Optional team / department label (e.g., 'MRM', 'Audit').",
    )
    title: str | None = Field(
        default=None,
        description="Optional job-title label (e.g., 'Director, Model Risk').",
    )


def generate_lines_report(owners: list[Owner]) -> str:
    """Aggregate a list of classified owners into a Markdown report.

    Output structure:

      1. Executive summary — counts + percentages per line + total
      2. Crossover warning callout (if any email appears under > 1
         line; regulators flag this as a 3LOD violation)
      3. Per-line listing (alphabetical by email)
      4. Per-team breakdown (if any owner has a team) showing
         which lines that team participates in

    Output is deterministic. Empty `owners` list still produces a
    valid (minimal) report.

    Parameters
    ----------
    owners
        List of classified Owner records. Caller assembles the list
        from vendor inventory, model-risk inventory, or external
        YAML overlay — see ``evidentia governance lines-report``
        CLI docs for the canonical assembly path.
    """
    sections: list[str] = []

    # ── §1 Executive summary ─────────────────────────────────────
    total = len(owners)
    counts = Counter(o.line_of_defense for o in owners)
    if total == 0:
        sections.append(
            "# Three Lines of Defense Distribution\n\n"
            "_No owners classified. Provide a YAML overlay or populate "
            "the vendor + model-risk inventories with classified "
            "owners and re-run._\n"
        )
        return "\n".join(sections)

    line_rows = []
    for line in (LineOfDefense.FIRST, LineOfDefense.SECOND, LineOfDefense.THIRD):
        n = counts.get(line.value, 0)
        pct = (n / total * 100.0) if total else 0.0
        line_rows.append(
            f"| {line.value} | {n} | {pct:.1f}% |"
        )
    sections.append(
        "# Three Lines of Defense Distribution\n\n"
        f"_IIA Three Lines Model 2020 distribution across "
        f"{total} classified owners._\n\n"
        "| Line | Count | Share |\n"
        "| --- | --- | --- |\n"
        + "\n".join(line_rows)
        + f"\n| **Total** | **{total}** | 100.0% |\n"
    )

    # ── §2 Crossover warning ─────────────────────────────────────
    by_email: defaultdict[str, set[str]] = defaultdict(set)
    for o in owners:
        by_email[str(o.email)].add(str(o.line_of_defense))
    crossover = sorted(
        (email, sorted(lines))
        for email, lines in by_email.items()
        if len(lines) > 1
    )
    if crossover:
        crossover_rows = "\n".join(
            f"| {email} | {' / '.join(lines)} |"
            for email, lines in crossover
        )
        sections.append(
            "## 3LOD crossover warning\n\n"
            f"> ⚠️ **{len(crossover)} owner(s) classified across "
            "multiple lines of defense.** Per IIA Three Lines Model "
            "+ regulator expectations (FFIEC + OCC + FRB), an "
            "individual cannot simultaneously perform 1st-line "
            "execution and 2nd-line oversight, or 2nd-line "
            "oversight and 3rd-line audit assurance, on the same "
            "activity. Review the table below; if these are intentional "
            "(e.g., temporary cross-functional rotation), document "
            "the rationale.\n\n"
            "| Owner email | Crossover lines |\n"
            "| --- | --- |\n"
            f"{crossover_rows}\n"
        )

    # ── §3 Per-line listing ──────────────────────────────────────
    for line in (LineOfDefense.FIRST, LineOfDefense.SECOND, LineOfDefense.THIRD):
        line_owners = sorted(
            (o for o in owners if o.line_of_defense == line.value),
            key=lambda o: str(o.email),
        )
        if not line_owners:
            sections.append(
                f"## {line.value.capitalize()} line\n\n"
                "_No owners classified to this line._\n"
            )
            continue
        rows = []
        for o in line_owners:
            rows.append(
                f"| {o.email} | "
                f"{o.team if o.team else '_—_'} | "
                f"{o.title if o.title else '_—_'} |"
            )
        sections.append(
            f"## {line.value.capitalize()} line\n\n"
            "| Email | Team | Title |\n"
            "| --- | --- | --- |\n"
            + "\n".join(rows)
            + "\n"
        )

    # ── §4 Per-team breakdown ────────────────────────────────────
    team_lines: defaultdict[str, set[str]] = defaultdict(set)
    for o in owners:
        if o.team:
            team_lines[o.team].add(str(o.line_of_defense))
    if team_lines:
        team_rows = []
        for team in sorted(team_lines):
            lines_str = " / ".join(sorted(team_lines[team]))
            team_rows.append(f"| {team} | {lines_str} |")
        sections.append(
            "## Team participation across lines\n\n"
            "| Team | Lines participating |\n"
            "| --- | --- |\n"
            + "\n".join(team_rows)
            + "\n"
        )

    return "\n".join(sections)
