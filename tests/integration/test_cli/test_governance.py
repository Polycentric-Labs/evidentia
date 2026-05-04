"""Integration tests for `evidentia governance` CLI (v0.7.10 P1.5 G1)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _write_classifications(path: Path, content: str) -> None:
    path.write_text(dedent(content).lstrip(), encoding="utf-8")


class TestLinesReport:
    def test_happy_path_to_stdout(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: alice@example.com
              line_of_defense: first
              team: Loan Origination
              title: Senior Underwriter
            - email: bob@example.com
              line_of_defense: second
              team: MRM
              title: Director, Model Risk
            - email: carol@example.com
              line_of_defense: third
              team: Internal Audit
            """,
        )
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Three Lines of Defense Distribution" in result.output
        # 1 owner per line; 33.3% each
        assert "| first | 1 | 33.3% |" in result.output

    def test_to_file(self, runner: CliRunner, tmp_path: Path) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: a@x.com
              line_of_defense: first
            """,
        )
        out = tmp_path / "lines.md"
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
                "--output", str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        body = out.read_text(encoding="utf-8")
        assert "Three Lines of Defense Distribution" in body

    def test_refuses_to_overwrite_without_force(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: a@x.com
              line_of_defense: first
            """,
        )
        out = tmp_path / "lines.md"
        out.write_text("existing", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
                "--output", str(out),
            ],
        )
        assert result.exit_code == 1
        assert "--force" in result.output
        assert out.read_text(encoding="utf-8") == "existing"

    def test_invalid_yaml_errors_clearly(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        cls = tmp_path / "broken.yaml"
        # Unbalanced brace + tab — guaranteed YAML parse failure
        cls.write_text("{key: [value\n\t}", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
            ],
        )
        assert result.exit_code == 1
        assert "not valid YAML" in result.output

    def test_invalid_line_of_defense_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        cls = tmp_path / "bad.yaml"
        _write_classifications(
            cls,
            """
            - email: a@x.com
              line_of_defense: fourth
            """,
        )
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
            ],
        )
        assert result.exit_code == 1
        assert "validation" in result.output.lower()

    def test_top_level_must_be_list(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        cls = tmp_path / "scalar.yaml"
        cls.write_text("not_a_list: true", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
            ],
        )
        assert result.exit_code == 1
        assert "must be a YAML list" in result.output

    def test_empty_yaml_renders_empty_report(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        cls = tmp_path / "empty.yaml"
        cls.write_text("", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
            ],
        )
        assert result.exit_code == 0
        assert "No owners classified" in result.output

    def test_crossover_warning_in_output(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        cls = tmp_path / "owners.yaml"
        _write_classifications(
            cls,
            """
            - email: alice@x.com
              line_of_defense: first
            - email: alice@x.com
              line_of_defense: second
            """,
        )
        result = runner.invoke(
            app,
            [
                "governance", "lines-report",
                "--classifications", str(cls),
            ],
        )
        assert result.exit_code == 0
        assert "3LOD crossover warning" in result.output
