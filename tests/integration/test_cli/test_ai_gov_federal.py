"""Integration tests for v0.9.6 P3 ai-gov federal verbs.

Covers:

- ``ai-gov categorize-fips`` happy path + validation errors.
- ``ai-gov set-omb-impact`` happy path + validation errors.
- ``ai-gov update --emit-scr`` writes JSON + Markdown SCR form pair.
- ``ai-gov update --ssp-reference`` updates the new field.
"""

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
    """Isolated AI registry per test."""
    registry_dir = tmp_path / "ai_registry"
    monkeypatch.setenv("EVIDENTIA_AI_REGISTRY_DIR", str(registry_dir))
    return registry_dir


@pytest.fixture()
def descriptor_yaml(tmp_path: Path) -> Path:
    """Minimal descriptor for registration."""
    path = tmp_path / "descriptor.yaml"
    path.write_text(
        "name: fed-ai-system\n"
        "purpose: Federal AI use case for testing.\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture()
def registered_system_id(
    runner: CliRunner,
    descriptor_yaml: Path,
    isolated_registry: Path,
) -> str:
    """Register a system and return its UUID by parsing CLI output."""
    import re

    result = runner.invoke(
        app,
        [
            "ai-gov",
            "register",
            "--descriptor",
            str(descriptor_yaml),
            "--provider",
            "self-built",
            "--owner",
            "team-fed",
        ],
    )
    assert result.exit_code == 0, result.output
    match = re.search(
        r"system_id:\s*([0-9a-f-]{36})",
        result.output,
    )
    assert match, f"could not parse system_id from output: {result.output!r}"
    return match.group(1)


# ── categorize-fips ────────────────────────────────────────────────


class TestCategorizeFips:
    def test_happy_path(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "categorize-fips",
                registered_system_id,
                "-c",
                "moderate",
                "-i",
                "high",
                "-a",
                "low",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "high" in result.output.lower()

    def test_with_rationale(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "categorize-fips",
                registered_system_id,
                "-c",
                "low",
                "-i",
                "low",
                "-a",
                "low",
                "--rationale",
                "Internal-only HR tool; SP 800-60 §6.1.2.",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_unknown_system_errors(
        self,
        runner: CliRunner,
        isolated_registry: Path,
    ) -> None:
        from uuid import uuid4

        result = runner.invoke(
            app,
            [
                "ai-gov",
                "categorize-fips",
                str(uuid4()),
                "-c",
                "low",
                "-i",
                "low",
                "-a",
                "low",
            ],
        )
        assert result.exit_code == 1

    def test_invalid_impact_errors(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "categorize-fips",
                registered_system_id,
                "-c",
                "extreme",  # not a valid FIPS199Impact value
                "-i",
                "low",
                "-a",
                "low",
            ],
        )
        assert result.exit_code == 1

    def test_persists_through_show(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        cat_result = runner.invoke(
            app,
            [
                "ai-gov",
                "categorize-fips",
                registered_system_id,
                "-c",
                "moderate",
                "-i",
                "high",
                "-a",
                "moderate",
            ],
        )
        assert cat_result.exit_code == 0
        show_result = runner.invoke(
            app,
            ["ai-gov", "show", registered_system_id, "--json"],
        )
        assert show_result.exit_code == 0
        body = json.loads(show_result.output)
        fips = body.get("fips_199_categorization")
        assert fips is not None
        assert fips["overall"] == "high"


# ── set-omb-impact ─────────────────────────────────────────────────


class TestSetOMBImpact:
    def test_happy_path_rights(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-omb-impact",
                registered_system_id,
                "--category",
                "rights_impacting",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "rights_impacting" in result.output

    def test_happy_path_neither(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-omb-impact",
                registered_system_id,
                "--category",
                "neither",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_happy_path_both(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-omb-impact",
                registered_system_id,
                "--category",
                "rights_and_safety_impacting",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_unknown_category_errors(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-omb-impact",
                registered_system_id,
                "--category",
                "highly_impacting",  # not a valid category
            ],
        )
        assert result.exit_code == 1

    def test_unknown_system_errors(
        self,
        runner: CliRunner,
        isolated_registry: Path,
    ) -> None:
        from uuid import uuid4

        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-omb-impact",
                str(uuid4()),
                "--category",
                "neither",
            ],
        )
        assert result.exit_code == 1


# ── set-high-impact (v0.10.12; OMB M-25-21) ─────────────────────────


class TestSetHighImpact:
    def test_happy_path_high_impact_with_bases(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                registered_system_id,
                "--determination",
                "high_impact",
                "--basis",
                "civil_rights_liberties_privacy",
                "--basis",
                "essential_services_access",
                "--rationale",
                "Affects access to an essential service.",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "high_impact" in result.output
        assert "civil_rights_liberties_privacy" in result.output

    def test_happy_path_not_high_impact(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                registered_system_id,
                "--determination",
                "not_high_impact",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_happy_path_not_assessed(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                registered_system_id,
                "--determination",
                "not_assessed",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_unknown_determination_errors(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                registered_system_id,
                "--determination",
                "very_high",  # not valid
            ],
        )
        assert result.exit_code == 1

    def test_unknown_basis_errors(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                registered_system_id,
                "--determination",
                "high_impact",
                "--basis",
                "national_pride",  # not a valid basis
            ],
        )
        assert result.exit_code == 1

    def test_unknown_system_errors(
        self,
        runner: CliRunner,
        isolated_registry: Path,
    ) -> None:
        from uuid import uuid4

        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                str(uuid4()),
                "--determination",
                "high_impact",
            ],
        )
        assert result.exit_code == 1


# ── update --emit-scr ──────────────────────────────────────────────


class TestUpdateEmitSCR:
    def test_emit_scr_produces_json_and_md(
        self,
        runner: CliRunner,
        registered_system_id: str,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "scr-output"
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "update",
                registered_system_id,
                "--owner",
                "new-team",
                "--emit-scr",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out.with_suffix(".json").exists()
        assert out.with_suffix(".md").exists()

    def test_scr_json_is_valid(
        self,
        runner: CliRunner,
        registered_system_id: str,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "scr"
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "update",
                registered_system_id,
                "--provider",
                "new-vendor",
                "--emit-scr",
                str(out),
            ],
        )
        assert result.exit_code == 0
        scr_data = json.loads(
            out.with_suffix(".json").read_text(encoding="utf-8")
        )
        assert scr_data["category"] == "adaptive"
        assert scr_data["system_id"] == registered_system_id

    def test_scr_md_has_expected_sections(
        self,
        runner: CliRunner,
        registered_system_id: str,
        tmp_path: Path,
    ) -> None:
        out = tmp_path / "scr"
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "update",
                registered_system_id,
                "--owner",
                "new-owner",
                "--emit-scr",
                str(out),
            ],
        )
        assert result.exit_code == 0
        md = out.with_suffix(".md").read_text(encoding="utf-8")
        assert "# Significant Change Request" in md
        assert "## Summary" in md
        assert "## Customer impact" in md
        assert "## Plan and timeline" in md

    def test_pilot_to_production_emits_transformative(
        self,
        runner: CliRunner,
        registered_system_id: str,
        tmp_path: Path,
    ) -> None:
        # Move to PILOT first.
        pilot = runner.invoke(
            app,
            [
                "ai-gov",
                "update",
                registered_system_id,
                "--deployment-status",
                "pilot",
            ],
        )
        assert pilot.exit_code == 0

        out = tmp_path / "scr"
        promote = runner.invoke(
            app,
            [
                "ai-gov",
                "update",
                registered_system_id,
                "--deployment-status",
                "production",
                "--emit-scr",
                str(out),
            ],
        )
        assert promote.exit_code == 0
        scr_data = json.loads(
            out.with_suffix(".json").read_text(encoding="utf-8")
        )
        assert scr_data["category"] == "transformative"


# ── update --ssp-reference ─────────────────────────────────────────


class TestUpdateSSPReference:
    def test_ssp_reference_persists(
        self,
        runner: CliRunner,
        registered_system_id: str,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "update",
                registered_system_id,
                "--ssp-reference",
                "emass://12345",
            ],
        )
        assert result.exit_code == 0, result.output
        show = runner.invoke(
            app, ["ai-gov", "show", registered_system_id, "--json"]
        )
        assert show.exit_code == 0
        body = json.loads(show.output)
        assert body["ssp_reference"] == "emass://12345"
