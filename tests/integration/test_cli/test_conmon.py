"""Integration tests for `evidentia conmon` subcommands (v0.9.0 P3)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _save_artifact(
    store: Path,
    collected: datetime,
    slug: str = "pci-dss-11-6-1-weekly",
    source: str = "nessus",
) -> None:
    """Save one evidence artifact linked to ``slug`` at ``collected``."""
    from evidentia_core.evidence_store import save_evidence
    from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

    artifact = EvidenceArtifact.model_validate(
        {
            "title": f"scan {collected.date().isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": source,
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": {"cadence_slug": slug},
        }
    )
    save_evidence(artifact, evidence_store_dir=store)


def _normalize(output: str) -> str:
    """Strip ANSI escapes + collapse whitespace.

    Rich-rendered Typer error panels wrap content based on the
    detected terminal width. CI runners default to ~80 cols which
    can wrap long option-name tokens (e.g., ``--smtp-sender``)
    across panel rows; local terminals are typically wider and
    render on one line. Tests that assert on option-name substrings
    in panel-rendered errors must normalize first to be portable
    across the local/CI environment boundary (v0.9.3 CI fix).
    """
    return " ".join(_ANSI_RE.sub("", output).split())


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

    def test_unknown_framework_returns_empty_json(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["conmon", "list", "--framework", "totally-not-real", "--json"])
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
    def test_overdue_cycle_surfaces(self, runner: CliRunner, tmp_path: Path) -> None:
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
                "--state-file",
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

    def test_due_soon_cycle_surfaces(self, runner: CliRunner, tmp_path: Path) -> None:
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
                "--state-file",
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
                    "--state-file",
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

    def test_unknown_slug_warned_not_errored(self, runner: CliRunner, tmp_path: Path) -> None:
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
                "--state-file",
                str(state_file),
                "--today",
                "2026-05-08",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert "totally-not-a-real-slug" in body["unknown_slugs"]

    def test_invalid_yaml_errors(self, runner: CliRunner, tmp_path: Path) -> None:
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
                "--state-file",
                str(state_file),
                "--today",
                "2026-05-08",
            ],
        )
        assert result.exit_code == 1
        assert "ISO-8601" in result.output

    def test_yaml_root_not_dict_errors(self, runner: CliRunner, tmp_path: Path) -> None:
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
                "--state-file",
                str(state_file),
                "--today",
                "2026-05-08",
            ],
        )
        assert result.exit_code == 1
        assert "must be a YAML mapping" in result.output

    def test_human_output_renders_overdue_table(self, runner: CliRunner, tmp_path: Path) -> None:
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
                "--state-file",
                str(state_file),
                "--today",
                "2026-05-08",
            ],
        )
        assert result.exit_code == 0
        assert "OVERDUE" in result.output

    def test_clean_state_message(self, runner: CliRunner, tmp_path: Path) -> None:
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
                "--state-file",
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

    def test_first_mark_creates_state_file(self, runner: CliRunner, tmp_path: Path) -> None:
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

    def test_second_mark_surfaces_previous(self, runner: CliRunner, tmp_path: Path) -> None:
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

    def test_unknown_slug_errors_with_helpful_message(self, runner: CliRunner, tmp_path: Path) -> None:
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

    def test_invalid_date_errors_cleanly(self, runner: CliRunner, tmp_path: Path) -> None:
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


# ── watch alerting flag validation (v0.9.3 P1.2) ──────────────────


class TestConmonWatchAlertingFlags:
    """Validate the watch command's alerting flag pre-checks.

    We test the eager validation that happens BEFORE the poll loop
    starts — these tests don't require running the daemon. Full
    daemon-loop alerting integration is covered by the unit tests
    in test_alerting.py.
    """

    def test_smtp_host_without_sender_errors(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_SMTP_PASSWORD", "p")
        state_file = tmp_path / "state.yaml"
        dedup_file = tmp_path / "dedup.json"
        result = runner.invoke(
            app,
            [
                "conmon",
                "watch",
                "--state-file",
                str(state_file),
                "--alert-dedup-file",
                str(dedup_file),
                "--smtp-host",
                "smtp.example.com",
                # Missing --smtp-sender and --smtp-recipient
            ],
        )
        assert result.exit_code != 0
        assert "--smtp-sender" in _normalize(result.output)

    def test_smtp_host_without_password_errors(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Explicitly clear the env var to test the error path.
        monkeypatch.delenv("EVIDENTIA_SMTP_PASSWORD", raising=False)
        state_file = tmp_path / "state.yaml"
        dedup_file = tmp_path / "dedup.json"
        result = runner.invoke(
            app,
            [
                "conmon",
                "watch",
                "--state-file",
                str(state_file),
                "--alert-dedup-file",
                str(dedup_file),
                "--smtp-host",
                "smtp.example.com",
                "--smtp-sender",
                "from@example.com",
                "--smtp-recipient",
                "to@example.com",
            ],
        )
        assert result.exit_code != 0
        assert "SMTP password" in _normalize(result.output)

    def test_webhook_without_secret_errors(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("EVIDENTIA_WEBHOOK_SECRET", raising=False)
        state_file = tmp_path / "state.yaml"
        dedup_file = tmp_path / "dedup.json"
        result = runner.invoke(
            app,
            [
                "conmon",
                "watch",
                "--state-file",
                str(state_file),
                "--alert-dedup-file",
                str(dedup_file),
                "--webhook-url",
                "https://1.1.1.1/in",
            ],
        )
        assert result.exit_code != 0
        assert "webhook" in _normalize(result.output).lower()

    def test_alerting_without_dedup_file_errors(
        self,
        runner: CliRunner,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_WEBHOOK_SECRET", "s")
        state_file = tmp_path / "state.yaml"
        result = runner.invoke(
            app,
            [
                "conmon",
                "watch",
                "--state-file",
                str(state_file),
                "--webhook-url",
                "https://1.1.1.1/in",
                # Missing --alert-dedup-file
            ],
        )
        assert result.exit_code != 0
        assert "--alert-dedup-file" in _normalize(result.output)

    def test_no_password_value_flag(self, runner: CliRunner) -> None:
        # Defense in depth — verify that --smtp-password / --webhook-
        # secret value flags are NOT registered. Rich truncates long
        # flag names in --help output so we test by trying to use the
        # flags directly (should error with "no such option").
        for forbidden in ("--smtp-password", "--webhook-secret"):
            result = runner.invoke(
                app,
                [
                    "conmon",
                    "watch",
                    "--state-file",
                    "/tmp/state.yaml",
                    forbidden,
                    "anything",
                ],
            )
            assert result.exit_code != 0
            assert (
                "no such option" in result.output.lower()
                or "unexpected" in result.output.lower()
                or "got unexpected" in result.output.lower()
            )


# ── health (v0.9.3 P1.3) ──────────────────────────────────────────


class TestConmonHealth:
    """`evidentia conmon health` CLI verb."""

    def test_basic_table_output(self, runner: CliRunner, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "nist-800-53-rev5-ca7: 2025-01-01\nfedramp-conmon-poam: 2026-05-10\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "health",
                "--state-file",
                str(state_file),
                "--today",
                "2026-05-15",
            ],
        )
        assert result.exit_code == 0
        assert "CONMON health" in result.output
        assert "nist-800-53-rev5" in result.output
        assert "fedramp-rev5-mod" in result.output

    def test_json_output(self, runner: CliRunner, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text("nist-800-53-rev5-ca7: 2026-05-10\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "health",
                "--state-file",
                str(state_file),
                "--today",
                "2026-05-15",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["total_cycles"] == 1
        assert body["overall_health_score"] == 1.0

    def test_emits_audit_event(
        self,
        runner: CliRunner,
        tmp_path: Path,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text("nist-800-53-rev5-ca7: 2026-05-10\n", encoding="utf-8")
        with caplog.at_level("INFO", logger="evidentia.cli.conmon"):
            result = runner.invoke(
                app,
                [
                    "conmon",
                    "health",
                    "--state-file",
                    str(state_file),
                    "--today",
                    "2026-05-15",
                ],
            )
        assert result.exit_code == 0
        actions = [getattr(r, "ecs_record", {}).get("event", {}).get("action") for r in caplog.records]
        assert "evidentia.conmon.health_report_generated" in actions

    def test_framework_filter(self, runner: CliRunner, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "nist-800-53-rev5-ca7: 2026-05-10\nfedramp-conmon-poam: 2026-05-10\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "health",
                "--state-file",
                str(state_file),
                "--today",
                "2026-05-15",
                "--framework",
                "nist-800-53-rev5",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert len(body["frameworks"]) == 1
        assert body["frameworks"][0]["framework"] == "nist-800-53-rev5"


# ── series (v0.13, V13-01: cadence evidence series) ──────────────


class TestConmonSeries:
    """`evidentia conmon series`: the cadence evidence series leaf."""

    def test_json_output_shape_continuous(self, runner: CliRunner, tmp_path: Path) -> None:
        store = tmp_path / "evidence"
        start = datetime(2026, 6, 1, 9, tzinfo=UTC)
        for i in range(3):
            _save_artifact(store, start + timedelta(days=7 * i))

        result = runner.invoke(
            app,
            [
                "conmon",
                "series",
                "pci-dss-11-6-1-weekly",
                "--evidence-store",
                str(store),
                "--since",
                "2026-06-01",
                "--until",
                "2026-06-15",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert set(body.keys()) == {"series", "description"}
        assert body["series"]["slug"] == "pci-dss-11-6-1-weekly"
        assert body["series"]["verdict"] == "continuous"
        assert body["series"]["gaps"] == []
        assert len(body["series"]["observations"]) == 3
        assert "evidence of cadence" in body["description"]

    def test_human_output_renders_verdict_and_tables(self, runner: CliRunner, tmp_path: Path) -> None:
        store = tmp_path / "evidence"
        start = datetime(2026, 6, 1, 9, tzinfo=UTC)
        for offset in (0, 7, 21):  # day 14 missing -> one gap
            _save_artifact(store, start + timedelta(days=offset))

        result = runner.invoke(
            app,
            [
                "conmon",
                "series",
                "pci-dss-11-6-1-weekly",
                "--evidence-store",
                str(store),
                "--since",
                "2026-06-01",
                "--until",
                "2026-06-22",
            ],
        )
        assert result.exit_code == 0, result.output
        out = _normalize(result.output)
        assert "verdict: gapped" in out
        assert "Observations" in out
        assert "Gaps" in out
        assert "evidence of cadence" in out

    def test_emit_findings_writes_one_finding_for_gapped_series(self, runner: CliRunner, tmp_path: Path) -> None:
        store = tmp_path / "evidence"
        start = datetime(2026, 6, 1, 9, tzinfo=UTC)
        for offset in (0, 7, 21):  # day 14 missing -> one gap
            _save_artifact(store, start + timedelta(days=offset))
        findings_path = tmp_path / "findings.json"

        result = runner.invoke(
            app,
            [
                "conmon",
                "series",
                "pci-dss-11-6-1-weekly",
                "--evidence-store",
                str(store),
                "--since",
                "2026-06-01",
                "--until",
                "2026-06-22",
                "--emit-findings",
                str(findings_path),
            ],
        )
        assert result.exit_code == 0, result.output
        findings = json.loads(findings_path.read_text(encoding="utf-8"))
        assert len(findings) == 1
        assert findings[0]["source_system"] == "evidentia-cadence"
        assert findings[0]["compliance_status"] == "fail"

    def test_emit_findings_writes_empty_array_for_continuous_series(self, runner: CliRunner, tmp_path: Path) -> None:
        store = tmp_path / "evidence"
        start = datetime(2026, 6, 1, 9, tzinfo=UTC)
        for i in range(3):
            _save_artifact(store, start + timedelta(days=7 * i))
        findings_path = tmp_path / "findings.json"

        result = runner.invoke(
            app,
            [
                "conmon",
                "series",
                "pci-dss-11-6-1-weekly",
                "--evidence-store",
                str(store),
                "--since",
                "2026-06-01",
                "--until",
                "2026-06-15",
                "--emit-findings",
                str(findings_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(findings_path.read_text(encoding="utf-8")) == []

    def test_unknown_slug_exits_2(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "series",
                "not-a-real-slug",
                "--evidence-store",
                str(tmp_path / "evidence"),
            ],
        )
        assert result.exit_code == 1
        assert "unknown cadence slug" in result.output

    def test_bad_window_exits_2(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "series",
                "nist-800-53-rev5-ca7",
                "--evidence-store",
                str(tmp_path / "evidence"),
                "--since",
                "2026-06-15",
                "--until",
                "2026-06-01",
            ],
        )
        assert result.exit_code == 2
        assert "is before" in result.output

    def test_only_since_given_fills_until_from_default_window(self, runner: CliRunner, tmp_path: Path) -> None:
        """--until is unset -> filled from default_window's end (~today).

        The only assertion pinned here is on --since (fully
        deterministic); --until necessarily depends on the real clock
        when omitted, so this does not assert its exact value; it
        only checks the window is well-formed (start <= end), which
        holds for any real run date.
        """
        result = runner.invoke(
            app,
            [
                "conmon",
                "series",
                "nist-800-53-rev5-ca7",
                "--evidence-store",
                str(tmp_path / "evidence"),
                "--since",
                "2026-06-01",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        body = json.loads(result.output)
        assert body["series"]["window_start"].startswith("2026-06-01")
        assert body["series"]["window_end"] >= body["series"]["window_start"]


# ── v0.9.4 P2.2: conmon dedup-list ─────────────────────────────────


class TestConmonDedupList:
    """``evidentia conmon dedup-list`` — operator-facing read of the
    alert-dedup state file."""

    def test_missing_file_returns_empty(self, runner: CliRunner, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "conmon",
                "dedup-list",
                "--alert-dedup-file",
                str(tmp_path / "missing.json"),
            ],
        )
        assert result.exit_code == 0
        assert "No dedup entries" in result.output

    def test_lists_entries_table_output(self, runner: CliRunner, tmp_path: Path) -> None:
        import json as _json

        dedup_file = tmp_path / "dedup.json"
        dedup_file.write_text(
            _json.dumps(
                {
                    "nist-800-53-rev5-ca7|overdue": "2026-05-17T12:00:00+00:00",
                    "fedramp-conmon-poam|due_soon": "2026-05-17T13:00:00+00:00",
                }
            )
        )

        result = runner.invoke(
            app,
            [
                "conmon",
                "dedup-list",
                "--alert-dedup-file",
                str(dedup_file),
            ],
        )
        assert result.exit_code == 0
        # Use _normalize since rich truncates long slugs in narrow
        # terminals on CI runners (same fragility class as v0.9.3
        # TestConmonWatchAlertingFlags). Check for a shorter
        # substring that won't be truncated.
        out = _normalize(result.output)
        assert "nist-800-53-rev5-c" in out  # may truncate trailing "a7"
        assert "fedramp-conmon-poam" in out
        assert "overdue" in out
        assert "due_soon" in out

    def test_slug_filter(self, runner: CliRunner, tmp_path: Path) -> None:
        import json as _json

        dedup_file = tmp_path / "dedup.json"
        dedup_file.write_text(
            _json.dumps(
                {
                    "nist-800-53-rev5-ca7|overdue": "2026-05-17T12:00:00+00:00",
                    "fedramp-conmon-poam|due_soon": "2026-05-17T13:00:00+00:00",
                }
            )
        )

        result = runner.invoke(
            app,
            [
                "conmon",
                "dedup-list",
                "--alert-dedup-file",
                str(dedup_file),
                "--slug",
                "fedramp-conmon-poam",
                "--json",
            ],
        )
        assert result.exit_code == 0
        rows = json.loads(result.output)
        assert len(rows) == 1
        assert rows[0]["cadence_slug"] == "fedramp-conmon-poam"

    def test_json_output_shape(self, runner: CliRunner, tmp_path: Path) -> None:
        import json as _json

        dedup_file = tmp_path / "dedup.json"
        dedup_file.write_text(
            _json.dumps(
                {
                    "nist-800-53-rev5-ca7|overdue": "2026-05-17T12:00:00+00:00",
                }
            )
        )

        result = runner.invoke(
            app,
            [
                "conmon",
                "dedup-list",
                "--alert-dedup-file",
                str(dedup_file),
                "--json",
            ],
        )
        assert result.exit_code == 0
        rows = json.loads(result.output)
        assert len(rows) == 1
        assert rows[0]["cadence_slug"] == "nist-800-53-rev5-ca7"
        assert rows[0]["state"] == "overdue"
        assert "last_dispatched_at" in rows[0]
        assert "suppression_remaining_minutes" in rows[0]


# ── ksi (v0.11 Wave 2 — FedRAMP CR26 SDR emit) ────────────────────


VALID_KSI_STATUS = """\
certification_package_overview_uri: "https://provider.example/fedramp/cpo.json"
document_version: "1.0.0"
source: "CLI integration tests"
indicators:
  KSI-CED-RAT:
    status: Implemented
    implementation:
      - "Quarterly all-hands security training."
    tests:
      - "test-training-coverage"
    evidence:
      - evidence_type: Report
        description: "Q2 training completion report"
        last_updated: 2026-07-01
    persistence_cycles:
      - cadence_slug: nist-800-53-rev5-ca7
"""


class TestConmonKsi:
    def test_emits_schema_valid_sdr(self, runner: CliRunner, tmp_path: Path) -> None:
        status_file = tmp_path / "ksi-status.yaml"
        status_file.write_text(VALID_KSI_STATUS, encoding="utf-8")
        state_file = tmp_path / "state.yaml"
        state_file.write_text("nist-800-53-rev5-ca7: 2026-07-01\n", encoding="utf-8")
        out = tmp_path / "sdr.json"

        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--state-file",
                str(state_file),
                "--last-updated",
                "2026-07-14T12:00:00+00:00",
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "schema-valid" in _normalize(result.output)
        assert "1/46" in _normalize(result.output)

        document = json.loads(out.read_text(encoding="utf-8"))
        assert document["certificationPackageOverviewUri"] == ("https://provider.example/fedramp/cpo.json")
        assert document["fedRampRequirements"] == []
        entry = document["keySecurityIndicators"][0]
        assert entry["ksiId"] == "KSI-CED-RAT"
        assert entry["ksiImplementationStatus"] == "Implemented"
        # The state file drove a dated persistence-cycle statement.
        assert any("last completed 2026-07-01" in s for s in entry["ksiImplementation"])
        assert document["metadata"]["lastUpdated"] == "2026-07-14T12:00:00+00:00"
        # Round-trip through the vendored schema, independent of the CLI.
        from evidentia_core.fedramp import validate_sdr_document

        assert validate_sdr_document(document) == []

    def test_invalid_status_file_exits_2(self, runner: CliRunner, tmp_path: Path) -> None:
        status_file = tmp_path / "bad.yaml"
        status_file.write_text("certification_package_overview_uri: x\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--out",
                str(tmp_path / "sdr.json"),
            ],
        )
        assert result.exit_code == 2
        assert "not a valid KSI status file" in _normalize(result.output)

    def test_unknown_indicator_id_exits_2(self, runner: CliRunner, tmp_path: Path) -> None:
        status_file = tmp_path / "unknown.yaml"
        status_file.write_text(
            VALID_KSI_STATUS.replace("KSI-CED-RAT", "KSI-FAKE-XXX"),
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--out",
                str(tmp_path / "sdr.json"),
            ],
        )
        assert result.exit_code == 2
        assert "unknown KSI indicator ID" in _normalize(result.output)

    def test_bad_last_updated_exits_1(self, runner: CliRunner, tmp_path: Path) -> None:
        status_file = tmp_path / "ksi-status.yaml"
        status_file.write_text(VALID_KSI_STATUS, encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--last-updated",
                "not-a-datetime",
                "--out",
                str(tmp_path / "sdr.json"),
            ],
        )
        assert result.exit_code == 1
        assert "--last-updated" in _normalize(result.output)

    def test_duplicate_indicator_key_rejected(self, runner: CliRunner, tmp_path: Path) -> None:
        """A duplicate KSI ID must not be silently last-wins merged.

        Regression: the stock YAML loader drops the earlier block from
        the emitted federal SDR; a submission artifact must not lose data
        to a copy-paste slip.
        """
        dup = VALID_KSI_STATUS + (
            '  KSI-CED-RAT:\n    status: Not Implemented\n    implementation:\n      - "Duplicate block."\n'
        )
        status_file = tmp_path / "dup.yaml"
        status_file.write_text(dup, encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--out",
                str(tmp_path / "sdr.json"),
            ],
        )
        assert result.exit_code == 2
        assert "duplicate key" in _normalize(result.output)

    def test_yaml_merge_keys_still_accepted(self, runner: CliRunner, tmp_path: Path) -> None:
        """The duplicate-key guard must not reject legal `<<` merge keys.

        Regression: a naive no-dup loader that skips flatten_mapping breaks
        merge-key DRY sharing that the stock loader accepted.
        """
        # Anchor the shared block on the first KSI and merge it into the
        # second (the model forbids extra top-level keys, so DRY sharing
        # rides real indicator anchors — the realistic merge-key use).
        merged = """\
certification_package_overview_uri: "https://provider.example/fedramp/cpo.json"
document_version: "1.0.0"
source: "merge-key test"
indicators:
  KSI-CED-RAT: &shared
    status: Implemented
    tests: ["shared-test"]
    evidence:
      - evidence_type: Report
        description: "shared evidence"
    implementation:
      - "Quarterly all-hands security training."
  KSI-CMT-LMC:
    <<: *shared
    implementation:
      - "Least-managed-change control in effect."
"""
        status_file = tmp_path / "merged.yaml"
        status_file.write_text(merged, encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--out",
                str(tmp_path / "sdr.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "schema-valid" in _normalize(result.output)

    def test_unknown_state_file_slug_warns(self, runner: CliRunner, tmp_path: Path) -> None:
        """A state-file anchor for a non-existent cadence slug warns.

        Its dates would otherwise be silently absent from the SDR.
        """
        status_file = tmp_path / "ksi-status.yaml"
        status_file.write_text(VALID_KSI_STATUS, encoding="utf-8")
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "nist-800-53-rev5-ca7: 2026-07-01\ntypo-not-a-real-slug: 2026-07-02\n",
            encoding="utf-8",
        )
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--state-file",
                str(state_file),
                "--out",
                str(tmp_path / "sdr.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        norm = _normalize(result.output)
        assert "unknown cadence slug" in norm
        assert "typo-not-a-real-slug" in norm

    def test_unwritable_out_path_exits_1(self, runner: CliRunner, tmp_path: Path) -> None:
        """A missing --out parent dir yields a clean exit 1, not a stack
        trace."""
        status_file = tmp_path / "ksi-status.yaml"
        status_file.write_text(VALID_KSI_STATUS, encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--out",
                str(tmp_path / "no-such-dir" / "sdr.json"),
            ],
        )
        assert result.exit_code == 1
        assert "could not write" in _normalize(result.output)


# ── conmon ksi: fedRampRequirements block (v0.12, SDR-CSO-FRR) ──────

STATUS_WITH_REQUIREMENTS = (
    VALID_KSI_STATUS
    + """\
requirements:
  SDR-CSO-FRR:
    status: Implemented
    implementation:
      - "SDR emitted by `evidentia conmon ksi` in JSON; human-readable rendering via the web console."
    validation:
      - "Schema round-trip on every emit."
"""
)


class TestConmonKsiRequirements:
    def _emit(self, runner: CliRunner, tmp_path: Path, status_yaml: str) -> tuple[int, str, dict]:
        status_file = tmp_path / "ksi-status.yaml"
        status_file.write_text(status_yaml, encoding="utf-8")
        out = tmp_path / "sdr.json"
        result = runner.invoke(
            app,
            [
                "conmon",
                "ksi",
                "--status-file",
                str(status_file),
                "--out",
                str(out),
                "--last-updated",
                "2026-08-21T12:00:00+00:00",
            ],
        )
        doc = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        return result.exit_code, result.output, doc

    def test_requirements_emit_into_the_sdr(self, runner: CliRunner, tmp_path: Path) -> None:
        code, output, doc = self._emit(runner, tmp_path, STATUS_WITH_REQUIREMENTS)
        assert code == 0, output
        [item] = doc["fedRampRequirements"]
        assert item["frrID"] == "SDR-CSO-FRR"
        assert item["frrImplementationStatus"] == "Implemented"

    def test_reports_frr_coverage_separately_from_ksi(self, runner: CliRunner, tmp_path: Path) -> None:
        """The operator needs to see the rule-completeness gap, not just KSIs."""
        code, output, _ = self._emit(runner, tmp_path, STATUS_WITH_REQUIREMENTS)
        assert code == 0, output
        assert "1 KSI entry" in output
        assert "1 FRR entry" in output
        assert "requirements addressed" in output
        assert "SDR-CSO-FRR" in output  # the MUST is cited

    def test_v011_status_file_without_requirements_still_emits(self, runner: CliRunner, tmp_path: Path) -> None:
        """Back-compat: an older file loads, emits [], and is told why that matters."""
        code, output, doc = self._emit(runner, tmp_path, VALID_KSI_STATUS)
        assert code == 0, output
        assert doc["fedRampRequirements"] == []
        assert "0 FRR entries" in output
        assert "SDR-CSO-FRR" in output

    def test_unknown_requirement_id_exits_2(self, runner: CliRunner, tmp_path: Path) -> None:
        bad = (
            VALID_KSI_STATUS
            + """\
requirements:
  AFC-FRP-VRE:
    implementation: ["not a provider rule"]
"""
        )
        code, output, _ = self._emit(runner, tmp_path, bad)
        assert code == 2
        assert "unknown FRR" in output
