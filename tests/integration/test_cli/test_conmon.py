"""Integration tests for `evidentia conmon` subcommands (v0.9.0 P3)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# ── list ───────────────────────────────────────────────────────────


class TestConmonList:
    def test_default_lists_all(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["conmon", "list"])
        assert result.exit_code == 0
        assert "CONMON cadences" in result.output

    def test_json_output(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["conmon", "list", "--json"])
        assert result.exit_code == 0
        cadences = json.loads(result.output)
        assert len(cadences) >= 7
        slugs = {c["slug"] for c in cadences}
        assert "nist-800-53-rev5-ca7" in slugs
        assert "fedramp-conmon-annual" in slugs

    def test_framework_filter(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["conmon", "list", "--framework", "fedramp-rev5-mod", "--json"],
        )
        assert result.exit_code == 0
        cadences = json.loads(result.output)
        assert all(c["framework"] == "fedramp-rev5-mod" for c in cadences)
        assert len(cadences) >= 3

    def test_unknown_framework_returns_empty_json(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            app, ["conmon", "list", "--framework", "totally-not-real", "--json"]
        )
        assert result.exit_code == 0
        cadences = json.loads(result.output)
        assert cadences == []


# ── next ───────────────────────────────────────────────────────────


class TestConmonNext:
    def test_monthly_next_due(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "next",
                "nist-800-53-rev5-ca7",
                "--last-completed",
                "2026-04-15",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["next_due"] == "2026-05-15"
        assert body["frequency"] == "monthly"

    def test_annual_next_due(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "next",
                "fedramp-conmon-annual",
                "--last-completed",
                "2026-04-15",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["next_due"] == "2027-04-15"

    def test_unknown_slug_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "next",
                "not-a-real-slug",
                "--last-completed",
                "2026-04-15",
            ],
        )
        assert result.exit_code == 1
        assert "unknown cadence slug" in result.output

    def test_invalid_date_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "next",
                "nist-800-53-rev5-ca7",
                "--last-completed",
                "not-a-date",
            ],
        )
        assert result.exit_code == 1
        assert "ISO-8601" in result.output

    def test_human_output(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "next",
                "nist-800-53-rev5-ca7",
                "--last-completed",
                "2026-04-15",
            ],
        )
        assert result.exit_code == 0
        assert "nist-800-53-rev5-ca7" in result.output
        assert "2026-05-15" in result.output


# ── check ──────────────────────────────────────────────────────────


class TestConmonCheck:
    def test_overdue_cycle_surfaces(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        # Anchor 2026-01-01 + monthly → next-due 2026-02-01; way overdue
        state_file.write_text(
            "nist-800-53-rev5-ca7: 2026-01-01\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--last-completed-file",
                str(state_file),
                "--today",
                "2026-05-08",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert len(body["overdue"]) == 1
        assert body["overdue"][0]["slug"] == "nist-800-53-rev5-ca7"
        assert int(body["overdue"][0]["days_until_due"]) < 0

    def test_due_soon_cycle_surfaces(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        # Anchor 2026-04-25 + monthly → next-due 2026-05-25; 17 days
        # from 2026-05-08 → within 30-day window
        state_file.write_text(
            "nist-800-53-rev5-ca7: 2026-04-25\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--last-completed-file",
                str(state_file),
                "--today",
                "2026-05-08",
                "--window-days",
                "30",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert len(body["due_soon"]) == 1

    def test_current_cycle_does_not_emit_event(
        self,
        runner: CliRunner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        state_file = tmp_path / "state.yaml"
        # Anchor 2026-05-01 + annual → next-due 2027-05-01; far future
        state_file.write_text(
            "fedramp-conmon-annual: 2026-05-01\n",
            encoding="utf-8",
        )
        # caplog with the audit logger name so per-cycle DUE/OVERDUE
        # emits would surface. The absence-of-events invariant the
        # log-schema doc promises requires this stricter assertion —
        # JSON output buckets being empty does NOT prove zero audit
        # records fired (v0.9.0 P5 F-V90-5 strengthening).
        with caplog.at_level("INFO", logger="evidentia.cli.conmon"):
            result = runner.invoke(
                app,
                [
                    "conmon",
                    "check",
                    "--last-completed-file",
                    str(state_file),
                    "--today",
                    "2026-05-08",
                    "--json",
                ],
            )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["overdue"] == []
        assert body["due_soon"] == []
        # No CONMON_CYCLE_DUE or CONMON_CYCLE_OVERDUE events fired.
        captured_actions = [
            getattr(r, "ecs_record", {}).get("event", {}).get("action")
            for r in caplog.records
            if r.name == "evidentia.cli.conmon"
        ]
        assert "evidentia.conmon.cycle_due" not in captured_actions
        assert "evidentia.conmon.cycle_overdue" not in captured_actions

    def test_unknown_slug_warned_not_errored(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "totally-not-a-real-slug: 2026-04-01\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--last-completed-file",
                str(state_file),
                "--today",
                "2026-05-08",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert "totally-not-a-real-slug" in body["unknown_slugs"]

    def test_invalid_yaml_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "nist-800-53-rev5-ca7: not-a-date\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--last-completed-file",
                str(state_file),
                "--today",
                "2026-05-08",
            ],
        )
        assert result.exit_code == 1
        assert "ISO-8601" in result.output

    def test_yaml_root_not_dict_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "- this is a list, not a dict\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--last-completed-file",
                str(state_file),
                "--today",
                "2026-05-08",
            ],
        )
        assert result.exit_code == 1
        assert "must be a YAML mapping" in result.output

    def test_human_output_renders_overdue_table(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "nist-800-53-rev5-ca7: 2026-01-01\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--last-completed-file",
                str(state_file),
                "--today",
                "2026-05-08",
            ],
        )
        assert result.exit_code == 0
        assert "OVERDUE" in result.output

    def test_clean_state_message(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "fedramp-conmon-annual: 2026-05-01\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--last-completed-file",
                str(state_file),
                "--today",
                "2026-05-08",
            ],
        )
        assert result.exit_code == 0
        assert "No CONMON cycles overdue" in result.output


# ── mark-completed (v0.9.3 P1.1) ──────────────────────────────────


class TestConmonMarkCompleted:
    """`evidentia conmon mark-completed` CLI verb."""

    def test_first_mark_creates_state_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        result = runner.invoke(
            app,
            [
                "conmon",
                "mark-completed",
                "nist-800-53-rev5-ca7",
                "--when",
                "2026-05-01",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 0
        assert "first recorded completion" in result.output
        assert state_file.is_file()

    def test_second_mark_surfaces_previous(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        # First mark
        runner.invoke(
            app,
            [
                "conmon",
                "mark-completed",
                "nist-800-53-rev5-ca7",
                "--when",
                "2026-04-01",
                "--state-file",
                str(state_file),
            ],
        )
        # Second mark
        result = runner.invoke(
            app,
            [
                "conmon",
                "mark-completed",
                "nist-800-53-rev5-ca7",
                "--when",
                "2026-05-01",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 0
        assert "previous: 2026-04-01" in result.output

    def test_unknown_slug_errors_with_helpful_message(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        result = runner.invoke(
            app,
            [
                "conmon",
                "mark-completed",
                "no-such-cadence",
                "--when",
                "2026-05-01",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 1
        assert "unknown cadence slug" in result.output
        assert "evidentia conmon list" in result.output

    def test_invalid_date_errors_cleanly(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        result = runner.invoke(
            app,
            [
                "conmon",
                "mark-completed",
                "nist-800-53-rev5-ca7",
                "--when",
                "not-a-date",
                "--state-file",
                str(state_file),
            ],
        )
        assert result.exit_code == 1
        assert "--when" in result.output
