"""Unit tests for evidentia_core.governance.lines_of_defense (v0.7.10 P1.5 G1)."""

from __future__ import annotations

import pytest
from evidentia_core.governance import (
    LineOfDefense,
    Owner,
    generate_lines_report,
)
from pydantic import ValidationError

# ── enum + Owner construction ──────────────────────────────────────


class TestLineOfDefenseEnum:
    def test_three_values(self) -> None:
        values = {line.value for line in LineOfDefense}
        assert values == {"first", "second", "third"}


class TestOwner:
    def test_minimal_construction(self) -> None:
        o = Owner(email="alice@example.com", line_of_defense=LineOfDefense.FIRST)
        assert o.email == "alice@example.com"
        assert o.line_of_defense == LineOfDefense.FIRST.value
        assert o.team is None
        assert o.title is None

    def test_full_construction(self) -> None:
        o = Owner(
            email="bob@example.com",
            line_of_defense=LineOfDefense.SECOND,
            team="MRM",
            title="Director, Model Risk",
        )
        assert o.team == "MRM"
        assert o.title == "Director, Model Risk"

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Owner(  # type: ignore[call-arg]
                email="x@y.com",
                line_of_defense=LineOfDefense.FIRST,
                bogus="should-fail",
            )

    def test_invalid_line_of_defense_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Owner.model_validate(
                {"email": "x@y.com", "line_of_defense": "fourth"}
            )


# ── generate_lines_report ──────────────────────────────────────────


class TestGenerateLinesReport:
    def test_empty_owners_renders_minimal_message(self) -> None:
        out = generate_lines_report([])
        assert "Three Lines of Defense Distribution" in out
        assert "No owners classified" in out

    def test_distribution_counts_and_percentages(self) -> None:
        owners = [
            Owner(email=f"first-{i}@x.com", line_of_defense=LineOfDefense.FIRST)
            for i in range(6)
        ] + [
            Owner(email=f"second-{i}@x.com", line_of_defense=LineOfDefense.SECOND)
            for i in range(3)
        ] + [
            Owner(email="third@x.com", line_of_defense=LineOfDefense.THIRD),
        ]
        out = generate_lines_report(owners)
        # 6/3/1 = 60.0% / 30.0% / 10.0% of 10
        assert "| first | 6 | 60.0% |" in out
        assert "| second | 3 | 30.0% |" in out
        assert "| third | 1 | 10.0% |" in out
        assert "**Total** | **10**" in out

    def test_crossover_warning_fires_when_email_in_two_lines(self) -> None:
        owners = [
            Owner(email="alice@x.com", line_of_defense=LineOfDefense.FIRST),
            Owner(email="alice@x.com", line_of_defense=LineOfDefense.SECOND),
            Owner(email="bob@x.com", line_of_defense=LineOfDefense.SECOND),
        ]
        out = generate_lines_report(owners)
        assert "3LOD crossover warning" in out
        assert "alice@x.com" in out
        # Bob (single line) should NOT appear in the crossover table
        crossover_section = out.split("3LOD crossover warning")[1].split("##")[0]
        assert "bob@x.com" not in crossover_section

    def test_no_crossover_warning_when_all_single_line(self) -> None:
        owners = [
            Owner(email="alice@x.com", line_of_defense=LineOfDefense.FIRST),
            Owner(email="bob@x.com", line_of_defense=LineOfDefense.SECOND),
        ]
        out = generate_lines_report(owners)
        assert "3LOD crossover warning" not in out

    def test_per_line_listing_renders_team_and_title(self) -> None:
        owners = [
            Owner(
                email="alice@x.com",
                line_of_defense=LineOfDefense.FIRST,
                team="Loan Origination",
                title="Senior Underwriter",
            ),
        ]
        out = generate_lines_report(owners)
        assert "## First line" in out
        assert "alice@x.com | Loan Origination | Senior Underwriter" in out

    def test_per_line_listing_handles_no_team_or_title(self) -> None:
        owners = [
            Owner(email="bare@x.com", line_of_defense=LineOfDefense.SECOND),
        ]
        out = generate_lines_report(owners)
        assert "bare@x.com | _—_ | _—_" in out

    def test_team_breakdown_when_teams_present(self) -> None:
        owners = [
            Owner(
                email="a@x.com",
                line_of_defense=LineOfDefense.FIRST,
                team="MRM",
            ),
            Owner(
                email="b@x.com",
                line_of_defense=LineOfDefense.SECOND,
                team="MRM",
            ),
        ]
        out = generate_lines_report(owners)
        assert "## Team participation across lines" in out
        # MRM appears in both first + second
        assert "| MRM | first / second |" in out

    def test_team_breakdown_omitted_when_no_teams(self) -> None:
        owners = [
            Owner(email="a@x.com", line_of_defense=LineOfDefense.FIRST),
        ]
        out = generate_lines_report(owners)
        assert "## Team participation across lines" not in out

    def test_render_is_deterministic_for_same_input(self) -> None:
        owners = [
            Owner(email="a@x.com", line_of_defense=LineOfDefense.FIRST),
            Owner(email="b@x.com", line_of_defense=LineOfDefense.SECOND),
        ]
        a = generate_lines_report(owners)
        b = generate_lines_report(owners)
        assert a == b

    def test_empty_line_renders_placeholder(self) -> None:
        owners = [
            Owner(email="only-first@x.com", line_of_defense=LineOfDefense.FIRST),
        ]
        out = generate_lines_report(owners)
        # second + third lines are empty
        assert "_No owners classified to this line._" in out
