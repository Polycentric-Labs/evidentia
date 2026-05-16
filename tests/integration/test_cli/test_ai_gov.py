"""Integration tests for `evidentia ai-gov` (v0.9.3 P2.5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def isolated_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    registry_dir = tmp_path / "ai_registry"
    monkeypatch.setenv("EVIDENTIA_AI_REGISTRY_DIR", str(registry_dir))
    return registry_dir


@pytest.fixture()
def descriptor_yaml(tmp_path: Path) -> Path:
    path = tmp_path / "descriptor.yaml"
    path.write_text(
        "name: resume-screener\n"
        "purpose: Score job applicants for HR review\n"
        "annex_iii_domain: employment\n",
        encoding="utf-8",
    )
    return path


class TestClassify:
    def test_classify_emits_json(
        self, runner: CliRunner, descriptor_yaml: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "classify",
                "--descriptor",
                str(descriptor_yaml),
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["descriptor_name"] == "resume-screener"
        assert body["eu_ai_act_tier"] == "high"

    def test_classify_rich_output(
        self, runner: CliRunner, descriptor_yaml: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "classify",
                "--descriptor",
                str(descriptor_yaml),
            ],
        )
        assert result.exit_code == 0
        assert "resume-screener" in result.output
        assert "high" in result.output.lower()

    def test_invalid_descriptor_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        bad = tmp_path / "bad.yaml"
        bad.write_text("not: a valid descriptor\n", encoding="utf-8")
        result = runner.invoke(
            app, ["ai-gov", "classify", "--descriptor", str(bad)]
        )
        assert result.exit_code != 0


class TestRegisterListShow:
    def test_register_then_list_then_show(
        self,
        runner: CliRunner,
        descriptor_yaml: Path,
        isolated_registry: Path,
    ) -> None:
        register = runner.invoke(
            app,
            [
                "ai-gov",
                "register",
                "--descriptor",
                str(descriptor_yaml),
                "--provider",
                "acme-ai",
                "--owner",
                "hr-team",
            ],
        )
        assert register.exit_code == 0
        # Extract system_id from the output
        assert "system_id:" in register.output

        listed = runner.invoke(app, ["ai-gov", "list", "--json"])
        assert listed.exit_code == 0
        entries = json.loads(listed.output)
        assert len(entries) == 1
        system_id = entries[0]["system_id"]

        shown = runner.invoke(
            app, ["ai-gov", "show", system_id, "--json"]
        )
        assert shown.exit_code == 0
        body = json.loads(shown.output)
        assert body["descriptor"]["name"] == "resume-screener"

    def test_list_with_tier_filter(
        self,
        runner: CliRunner,
        descriptor_yaml: Path,
        isolated_registry: Path,
    ) -> None:
        runner.invoke(
            app,
            [
                "ai-gov",
                "register",
                "--descriptor",
                str(descriptor_yaml),
                "--provider",
                "acme-ai",
                "--owner",
                "hr-team",
            ],
        )
        result = runner.invoke(
            app,
            ["ai-gov", "list", "--tier", "high", "--json"],
        )
        assert result.exit_code == 0
        assert len(json.loads(result.output)) == 1

        # Filter to a tier with no matches
        empty = runner.invoke(
            app,
            ["ai-gov", "list", "--tier", "minimal", "--json"],
        )
        assert empty.exit_code == 0
        assert json.loads(empty.output) == []

    def test_show_unknown_id_errors(
        self,
        runner: CliRunner,
        isolated_registry: Path,
    ) -> None:
        # Well-formed UUID that doesn't exist
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "show",
                "11111111-1111-4111-8111-111111111111",
            ],
        )
        assert result.exit_code == 1
        assert "no registered" in result.output.lower()
