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


# ── v0.11 Wave 2: ai-gov set-practice ──────────────────────────────


class TestSetPractice:
    def _set_high_impact(
        self, runner: CliRunner, system_id: str
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                system_id,
                "--determination",
                "high_impact",
                "--basis",
                "health_and_safety",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_set_practice_happy_path(
        self,
        runner: CliRunner,
        registered_system_id: str,
        isolated_registry: Path,
    ) -> None:
        self._set_high_impact(runner, registered_system_id)
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-practice",
                registered_system_id,
                "--practice",
                "pre_deployment_testing",
                "--status",
                "implemented",
                "--notes",
                "Red-team + regression suite before each deploy.",
                "--last-reviewed",
                "2026-07-01",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "pre_deployment_testing" in result.output
        assert "1/7 recorded" in result.output.replace("\n", "")

    def test_set_practice_waived_with_waiver_flags(
        self,
        runner: CliRunner,
        registered_system_id: str,
        isolated_registry: Path,
    ) -> None:
        self._set_high_impact(runner, registered_system_id)
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-practice",
                registered_system_id,
                "--practice",
                "public_feedback",
                "--status",
                "waived",
                "--waiver-issued-on",
                "2026-06-01",
                "--waiver-issued-by",
                "Agency CAIO",
                "--waiver-justification",
                "Unacceptable impediment to critical agency operations.",
                "--waiver-reported-on",
                "2026-06-15",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "waived" in result.output

    def test_waived_without_waiver_flags_exits_1(
        self,
        runner: CliRunner,
        registered_system_id: str,
        isolated_registry: Path,
    ) -> None:
        self._set_high_impact(runner, registered_system_id)
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-practice",
                registered_system_id,
                "--practice",
                "public_feedback",
                "--status",
                "waived",
            ],
        )
        assert result.exit_code == 1
        # No waiver flags at all -> the domain model's validator fires
        # (the CLI pre-check covers the partial-flags case separately).
        assert "requires a waiver" in result.output

    def test_set_practice_without_assessment_exits_1(
        self,
        runner: CliRunner,
        registered_system_id: str,
        isolated_registry: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-practice",
                registered_system_id,
                "--practice",
                "impact_assessment",
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 1
        assert "set-high-impact" in result.output

    def test_unknown_practice_exits_1(
        self,
        runner: CliRunner,
        registered_system_id: str,
        isolated_registry: Path,
    ) -> None:
        self._set_high_impact(runner, registered_system_id)
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "set-practice",
                registered_system_id,
                "--practice",
                "vibes_check",
                "--status",
                "implemented",
            ],
        )
        assert result.exit_code == 1
        assert "unknown practice" in result.output

    def test_practices_persist_on_the_entry(
        self,
        runner: CliRunner,
        registered_system_id: str,
        isolated_registry: Path,
    ) -> None:
        self._set_high_impact(runner, registered_system_id)
        for practice, status in (
            ("pre_deployment_testing", "implemented"),
            ("ongoing_monitoring", "in_progress"),
        ):
            result = runner.invoke(
                app,
                [
                    "ai-gov",
                    "set-practice",
                    registered_system_id,
                    "--practice",
                    practice,
                    "--status",
                    status,
                ],
            )
            assert result.exit_code == 0, result.output
        assert "2/7 recorded" in result.output.replace("\n", "")

        from evidentia_core.ai_governance import AIRegistryStore

        entry = AIRegistryStore().load(registered_system_id)
        assert entry is not None
        assert entry.omb_high_impact is not None
        practices = entry.omb_high_impact.practices
        assert len(practices) == 2

    def test_re_determination_preserves_recorded_practices(
        self,
        runner: CliRunner,
        registered_system_id: str,
        isolated_registry: Path,
    ) -> None:
        """A later set-high-impact must NOT wipe recorded practices.

        Regression: set-high-impact is the only verb that amends
        bases/rationale on an already-classified system; rebuilding the
        assessment without carrying ``practices`` forward silently
        destroyed the recorded status + CAIO waiver provenance.
        """
        self._set_high_impact(runner, registered_system_id)
        waive = runner.invoke(
            app,
            [
                "ai-gov",
                "set-practice",
                registered_system_id,
                "--practice",
                "human_oversight",
                "--status",
                "waived",
                "--waiver-issued-on",
                "2026-06-01",
                "--waiver-issued-by",
                "Agency CAIO",
                "--waiver-justification",
                "Interim operational necessity per §4(a)(ii).",
                "--waiver-reported-on",
                "2026-06-15",
            ],
        )
        assert waive.exit_code == 0, waive.output

        # Re-run set-high-impact to amend the bases (unrelated edit).
        amend = runner.invoke(
            app,
            [
                "ai-gov",
                "set-high-impact",
                registered_system_id,
                "--determination",
                "high_impact",
                "--basis",
                "health_and_safety",
                "--basis",
                "civil_rights_liberties_privacy",
            ],
        )
        assert amend.exit_code == 0, amend.output

        from evidentia_core.ai_governance import AIRegistryStore
        from evidentia_core.ai_governance.omb_m_25_21 import MinimumPractice

        entry = AIRegistryStore().load(registered_system_id)
        assert entry is not None and entry.omb_high_impact is not None
        practices = entry.omb_high_impact.practices
        assert MinimumPractice.HUMAN_OVERSIGHT in practices, (
            "the re-determination destroyed the recorded practice"
        )
        assert (
            practices[MinimumPractice.HUMAN_OVERSIGHT].waiver is not None
        ), "the CAIO waiver provenance was lost on re-determination"


# ── v0.11 Wave 2: ai-gov acquisition (OMB M-25-22) ─────────────────


def _normalize(output: str) -> str:
    """Strip ANSI escapes + collapse whitespace (rich wraps at ~80 cols
    on CI runners; mirrors tests/integration/test_cli/test_conmon.py)."""
    import re as _re

    return " ".join(_re.sub(r"\[[0-9;]*m", "", output).split())


@pytest.fixture()
def isolated_acquisitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Isolated M-25-22 acquisition store per test."""
    store_dir = tmp_path / "ai_acquisitions"
    monkeypatch.setenv("EVIDENTIA_AI_ACQUISITION_DIR", str(store_dir))
    return store_dir


class TestAcquisition:
    def _register(self, runner: CliRunner) -> str:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "acquisition",
                "register",
                "Case-triage LLM service",
                "--solicitation-ref",
                "RFP-26-0141",
                "--likely-high-impact",
                "high_impact",
            ],
        )
        assert result.exit_code == 0, result.output
        import re

        match = re.search(r"ID:\s+([0-9a-f-]{36})", result.output)
        assert match, result.output
        return match.group(1)

    def test_register_and_show(
        self, runner: CliRunner, isolated_acquisitions: Path
    ) -> None:
        acquisition_id = self._register(runner)
        result = runner.invoke(
            app, ["ai-gov", "acquisition", "show", acquisition_id]
        )
        assert result.exit_code == 0, result.output
        normalized = _normalize(result.output)
        assert "Case-triage LLM service" in normalized
        assert "high_impact" in normalized
        assert "not recorded" in normalized

    def test_set_phase_and_progress(
        self, runner: CliRunner, isolated_acquisitions: Path
    ) -> None:
        acquisition_id = self._register(runner)
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "acquisition",
                "set-phase",
                acquisition_id,
                "--phase",
                "identification_of_requirements",
                "--status",
                "complete",
                "--last-reviewed",
                "2026-07-10",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "1/6 recorded" in _normalize(result.output)

    def test_unknown_phase_exits_1(
        self, runner: CliRunner, isolated_acquisitions: Path
    ) -> None:
        acquisition_id = self._register(runner)
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "acquisition",
                "set-phase",
                acquisition_id,
                "--phase",
                "vibes_alignment",
                "--status",
                "complete",
            ],
        )
        assert result.exit_code == 1
        assert "unknown phase" in _normalize(result.output)

    def test_unknown_id_exits_1(
        self, runner: CliRunner, isolated_acquisitions: Path
    ) -> None:
        result = runner.invoke(
            app,
            [
                "ai-gov",
                "acquisition",
                "show",
                "11111111-1111-4111-8111-111111111111",
            ],
        )
        assert result.exit_code == 1

    def test_list_json(
        self, runner: CliRunner, isolated_acquisitions: Path
    ) -> None:
        self._register(runner)
        result = runner.invoke(app, ["ai-gov", "acquisition", "list", "--json"])
        assert result.exit_code == 0, result.output
        records = json.loads(result.output)
        assert len(records) == 1
        assert records[0]["name"] == "Case-triage LLM service"
