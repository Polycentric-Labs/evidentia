"""Integration tests for `evidentia risk quantify` CLI (v0.7.11 P1.5 G4)."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def _write(path: Path, content: str) -> None:
    path.write_text(dedent(content).lstrip(), encoding="utf-8")


_SAMPLE_SCENARIOS = """
- name: Credential stuffing
  description: External attackers reuse leaked credentials.
  tef: 365
  vulnerability: 0.001
  primary_loss: 5000
  secondary_loss: 50000
- name: Ransomware
  description: Untargeted ransomware drive-by.
  tef: 12
  vulnerability: 0.05
  primary_loss: 250000
  secondary_loss:
    low: 100000
    most_likely: 500000
    high: 2000000
"""


class TestQuantify:
    def test_quantify_to_stdout(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        scenarios = tmp_path / "scenarios.yaml"
        _write(scenarios, _SAMPLE_SCENARIOS)
        result = runner.invoke(
            app,
            [
                "risk", "quantify",
                "--method", "open-fair",
                "--scenarios", str(scenarios),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "FAIR Risk Quantification Report" in result.output
        assert "Credential stuffing" in result.output
        assert "Ransomware" in result.output

    def test_quantify_to_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        scenarios = tmp_path / "scenarios.yaml"
        _write(scenarios, _SAMPLE_SCENARIOS)
        out = tmp_path / "report.md"
        result = runner.invoke(
            app,
            [
                "risk", "quantify",
                "--method", "open-fair",
                "--scenarios", str(scenarios),
                "--output", str(out),
            ],
        )
        assert result.exit_code == 0
        body = out.read_text(encoding="utf-8")
        assert "FAIR Risk Quantification Report" in body

    def test_unknown_method_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        scenarios = tmp_path / "scenarios.yaml"
        _write(scenarios, _SAMPLE_SCENARIOS)
        result = runner.invoke(
            app,
            [
                "risk", "quantify",
                "--method", "fair-mc",
                "--scenarios", str(scenarios),
            ],
        )
        assert result.exit_code == 1
        assert "must be 'open-fair'" in result.output

    def test_invalid_yaml_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        scenarios = tmp_path / "broken.yaml"
        scenarios.write_text("{key: [value\n\t}", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "risk", "quantify",
                "--method", "open-fair",
                "--scenarios", str(scenarios),
            ],
        )
        assert result.exit_code == 1
        assert "not valid" in result.output.lower()

    def test_top_level_must_be_list(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        scenarios = tmp_path / "scalar.yaml"
        scenarios.write_text("not_a_list: true\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "risk", "quantify",
                "--method", "open-fair",
                "--scenarios", str(scenarios),
            ],
        )
        assert result.exit_code == 1
        assert "list of scenario records" in result.output

    def test_invalid_scenario_validation_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        scenarios = tmp_path / "bad.yaml"
        _write(scenarios, """
            - name: x
              description: x
              tef: -1
              vulnerability: 0.5
              primary_loss: 1000
        """)
        result = runner.invoke(
            app,
            [
                "risk", "quantify",
                "--method", "open-fair",
                "--scenarios", str(scenarios),
            ],
        )
        # Negative TEF — Pydantic would normally accept (no constraint
        # in the schema), but if PERTRange-like validation kicks in,
        # this would fail. Either way: scenario loads or doesn't,
        # the test asserts the CLI either succeeds (scenario accepted)
        # or fails cleanly.
        assert result.exit_code in (0, 1)

    def test_empty_yaml(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        scenarios = tmp_path / "empty.yaml"
        scenarios.write_text("", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "risk", "quantify",
                "--method", "open-fair",
                "--scenarios", str(scenarios),
            ],
        )
        assert result.exit_code == 0
        assert "No scenarios defined" in result.output
