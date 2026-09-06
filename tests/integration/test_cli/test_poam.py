"""Integration tests for `evidentia poam` subcommands (v0.9.0 P2).

Uses Typer's CliRunner against the real `evidentia.cli.main:app`.
Each test scopes both the POA&M store AND the gap store to
``tmp_path`` so no state leaks into the real user profile.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.models.gap import (
    ControlGap,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
    Milestone,
    POAMState,
)
from evidentia_core.poam_store import save_poam
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_stores(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate poam_store + gap_store for each test."""
    poam_dir = tmp_path / "poam-store"
    monkeypatch.setenv("EVIDENTIA_POAM_STORE_DIR", str(poam_dir))
    gap_dir = tmp_path / "gap-store"
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(gap_dir))
    return tmp_path


def _make_gap(
    control_id: str = "AC-2",
    severity: GapSeverity = GapSeverity.CRITICAL,
) -> ControlGap:
    return ControlGap(
        framework="nist-800-53-rev5",
        control_id=control_id,
        control_title="Account Management",
        control_description="Manage system accounts.",
        gap_severity=severity,
        implementation_status="missing",
        gap_description="No automated lifecycle process.",
        remediation_guidance="Implement Okta lifecycle.",
        implementation_effort=ImplementationEffort.MEDIUM,
    )


def _make_report(gaps: list[ControlGap]) -> GapAnalysisReport:
    return GapAnalysisReport(
        organization="Acme Corp",
        frameworks_analyzed=["nist-800-53-rev5"],
        total_controls_required=100,
        total_controls_in_inventory=80,
        total_gaps=len(gaps),
        critical_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.CRITICAL),
        high_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.HIGH),
        medium_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.MEDIUM),
        low_gaps=sum(1 for g in gaps if g.gap_severity == GapSeverity.LOW),
        coverage_percentage=80.0,
        gaps=gaps,
    )


# ── create ─────────────────────────────────────────────────────────


class TestPoamCreate:
    def test_create_from_report_materializes_critical_high_only(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        gaps = [
            _make_gap("AC-1", GapSeverity.LOW),
            _make_gap("AC-2", GapSeverity.CRITICAL),
            _make_gap("AC-3", GapSeverity.HIGH),
            _make_gap("AC-4", GapSeverity.MEDIUM),
        ]
        report = _make_report(gaps)
        report_path = tmp_path / "report.json"
        report_path.write_text(report.model_dump_json(), encoding="utf-8")

        result = runner.invoke(
            app,
            ["poam", "create", "--from-gap-report", str(report_path)],
        )
        assert result.exit_code == 0, result.output
        assert "2 created" in result.output
        assert "2 skipped (severity filter" in result.output

        # Verify the store
        list_result = runner.invoke(app, ["poam", "list", "--json"])
        assert list_result.exit_code == 0
        items = json.loads(list_result.output)
        assert len(items) == 2
        ctrl_ids = {item["control_id"] for item in items}
        assert ctrl_ids == {"AC-2", "AC-3"}

    def test_create_all_flag_includes_lower_severity(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        gaps = [
            _make_gap("AC-1", GapSeverity.LOW),
            _make_gap("AC-2", GapSeverity.CRITICAL),
        ]
        report = _make_report(gaps)
        report_path = tmp_path / "report.json"
        report_path.write_text(report.model_dump_json(), encoding="utf-8")

        result = runner.invoke(
            app,
            [
                "poam",
                "create",
                "--from-gap-report",
                str(report_path),
                "--all",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "2 created" in result.output

    def test_create_skips_existing_without_overwrite(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        gap = _make_gap("AC-2", GapSeverity.CRITICAL)
        report = _make_report([gap])
        report_path = tmp_path / "report.json"
        report_path.write_text(report.model_dump_json(), encoding="utf-8")

        # First run
        runner.invoke(
            app,
            ["poam", "create", "--from-gap-report", str(report_path)],
        )
        # Second run (no overwrite)
        result = runner.invoke(
            app,
            ["poam", "create", "--from-gap-report", str(report_path)],
        )
        assert result.exit_code == 0
        assert "0 created" in result.output
        assert "1 skipped (already exist" in result.output

    def test_create_with_invalid_report_path_errors(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ) -> None:
        result = runner.invoke(
            app,
            [
                "poam",
                "create",
                "--from-gap-report",
                str(tmp_path / "missing.json"),
            ],
        )
        # Typer rejects with non-zero exit on missing-file constraint
        assert result.exit_code != 0


# ── list ───────────────────────────────────────────────────────────


class TestPoamList:
    def test_empty_store_lists_zero(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["poam", "list"])
        assert result.exit_code == 0
        assert "0 total" in result.output

    def test_list_json_returns_array(self, runner: CliRunner) -> None:
        save_poam(_make_gap("AC-2", GapSeverity.HIGH))
        result = runner.invoke(app, ["poam", "list", "--json"])
        assert result.exit_code == 0
        items = json.loads(result.output)
        assert len(items) == 1
        assert items[0]["control_id"] == "AC-2"

    def test_severity_filter(self, runner: CliRunner) -> None:
        save_poam(_make_gap("AC-1", GapSeverity.LOW))
        save_poam(_make_gap("AC-2", GapSeverity.CRITICAL))
        # default lists only open (both are open) but with severity filter
        result = runner.invoke(app, ["poam", "list", "--severity", "critical", "--json"])
        items = json.loads(result.output)
        assert len(items) == 1
        assert items[0]["gap_severity"] == "critical"

    def test_severity_filter_invalid_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["poam", "list", "--severity", "not-a-real-severity"])
        assert result.exit_code == 1
        assert "unknown severity" in result.output

    def test_default_excludes_remediated(self, runner: CliRunner) -> None:
        closed = _make_gap("AC-1", GapSeverity.CRITICAL)
        closed.status = GapStatus.REMEDIATED
        save_poam(closed)
        save_poam(_make_gap("AC-2", GapSeverity.CRITICAL))
        # Default: open-only
        result = runner.invoke(app, ["poam", "list", "--json"])
        items = json.loads(result.output)
        assert len(items) == 1
        # --all includes the remediated one
        all_result = runner.invoke(app, ["poam", "list", "--all", "--json"])
        all_items = json.loads(all_result.output)
        assert len(all_items) == 2


# ── show ───────────────────────────────────────────────────────────


class TestPoamShow:
    def test_show_renders_human_form(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(app, ["poam", "show", gap.id])
        assert result.exit_code == 0
        assert "nist-800-53-rev5:AC-2" in result.output
        assert "high" in result.output

    def test_show_json_emits_full_record(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["id"] == gap.id

    def test_show_unknown_id_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["poam", "show", "00000000-0000-0000-0000-000000000000"])
        assert result.exit_code == 1
        assert "No POA&M" in result.output

    def test_show_invalid_id_shape_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["poam", "show", "../bad"])
        assert result.exit_code == 1


# ── update ─────────────────────────────────────────────────────────


class TestPoamUpdate:
    def test_update_status_to_remediated_fires_closed_event(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(app, ["poam", "update", gap.id, "--status", "remediated"])
        assert result.exit_code == 0, result.output
        # Re-fetch to verify
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        assert body["status"] == "remediated"
        assert body["remediated_at"] is not None

    def test_update_assigned_to(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(
            app,
            [
                "poam",
                "update",
                gap.id,
                "--assigned-to",
                "ops@example.com",
            ],
        )
        assert result.exit_code == 0
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        assert body["assigned_to"] == "ops@example.com"

    def test_update_no_changes_warns(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(app, ["poam", "update", gap.id])
        assert result.exit_code == 0
        assert "No changes" in result.output

    def test_update_invalid_status_errors(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(app, ["poam", "update", gap.id, "--status", "not-valid"])
        assert result.exit_code == 1


# ── milestone add ──────────────────────────────────────────────────


class TestMilestoneAdd:
    def test_add_milestone_to_poam(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "add",
                gap.id,
                "--target-date",
                "2026-06-30",
                "--description",
                "Deliver Okta integration",
            ],
        )
        assert result.exit_code == 0, result.output
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        assert len(body["poam_milestones"]) == 1
        assert body["poam_milestones"][0]["description"] == "Deliver Okta integration"
        assert body["poam_milestones"][0]["status"] == "planned"

    def test_add_milestone_invalid_date_errors(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "add",
                gap.id,
                "--target-date",
                "not-a-date",
                "--description",
                "x",
            ],
        )
        assert result.exit_code == 1
        assert "ISO-8601" in result.output


# ── milestone update ───────────────────────────────────────────────


class TestMilestoneUpdate:
    def test_update_milestone_status_forward(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 6, 30),
                description="phase 1",
            )
        )
        save_poam(gap)
        ms_id = gap.poam_milestones[0].id
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                ms_id,
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 0, result.output
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        assert body["poam_milestones"][0]["status"] == "in_progress"

    def test_invalid_backward_transition_blocked(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 6, 30),
                description="phase 1",
                status=POAMState.COMPLETED,
            )
        )
        save_poam(gap)
        ms_id = gap.poam_milestones[0].id
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                ms_id,
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 1
        assert "invalid state transition" in result.output

    def test_unknown_milestone_id_errors(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                "00000000-0000-0000-0000-000000000000",
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 1

    def test_update_accepts_full_uuid(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(Milestone(target_date=date(2026, 6, 30), description="phase 1"))
        save_poam(gap)
        ms_id = gap.poam_milestones[0].id
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                ms_id,  # full UUID
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 0, result.output
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        assert body["poam_milestones"][0]["status"] == "in_progress"

    def test_update_accepts_displayed_eight_char_prefix(self, runner: CliRunner) -> None:
        """The 8-char prefix the CLI shows the operator must work."""
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(Milestone(target_date=date(2026, 6, 30), description="phase 1"))
        save_poam(gap)
        ms_prefix = gap.poam_milestones[0].id[:8]
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                ms_prefix,  # what the CLI displayed in `(<prefix>)`
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 0, result.output
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        assert body["poam_milestones"][0]["status"] == "in_progress"

    def test_prefix_updates_the_right_milestone(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(Milestone(target_date=date(2026, 6, 30), description="phase 1"))
        gap.poam_milestones.append(Milestone(target_date=date(2026, 7, 31), description="phase 2"))
        save_poam(gap)
        target = gap.poam_milestones[1]  # phase 2
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                target.id[:8],
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 0, result.output
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        statuses = {m["description"]: m["status"] for m in body["poam_milestones"]}
        assert statuses["phase 2"] == "in_progress"
        assert statuses["phase 1"] == "planned"

    def test_ambiguous_prefix_errors_clearly(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        # Two milestones sharing the same 8-char prefix.
        gap.poam_milestones.append(
            Milestone(
                id="3f70eae3-0000-4000-8000-000000000001",
                target_date=date(2026, 6, 30),
                description="phase 1",
            )
        )
        gap.poam_milestones.append(
            Milestone(
                id="3f70eae3-1111-4000-8000-000000000002",
                target_date=date(2026, 7, 31),
                description="phase 2",
            )
        )
        save_poam(gap)
        result = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                "3f70eae3",
                "--status",
                "in_progress",
            ],
        )
        assert result.exit_code == 1
        # Rich soft-wraps console output at the terminal width, so
        # collapse whitespace before substring-matching the message.
        flat = " ".join(result.output.split())
        assert "ambiguous milestone id '3f70eae3' matches 2 milestones" in flat
        assert "use more characters" in flat

    def test_add_then_update_displayed_prefix_round_trip(self, runner: CliRunner) -> None:
        """End-to-end: add a milestone, scrape the prefix the CLI
        printed, feed it back to `milestone update`."""
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        add = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "add",
                gap.id,
                "--target-date",
                "2026-06-30",
                "--description",
                "Deliver Okta integration",
            ],
        )
        assert add.exit_code == 0, add.output
        # `Added milestone <8-char> to POA&M ...` — pull the prefix the
        # operator would actually copy off the screen. Collapse Rich's
        # soft-wrap whitespace first so the scrape is width-independent.
        import re

        flat_add = " ".join(add.output.split())
        match = re.search(r"Added milestone (\S+) to POA&M", flat_add)
        assert match is not None, add.output
        displayed_prefix = match.group(1)
        assert len(displayed_prefix) == 8

        upd = runner.invoke(
            app,
            [
                "poam",
                "milestone",
                "update",
                gap.id,
                displayed_prefix,
                "--status",
                "in_progress",
            ],
        )
        assert upd.exit_code == 0, upd.output
        show = runner.invoke(app, ["poam", "show", gap.id, "--json"])
        body = json.loads(show.output)
        assert body["poam_milestones"][0]["status"] == "in_progress"


# ── delete ─────────────────────────────────────────────────────────


class TestPoamDelete:
    def test_delete_with_yes_flag_skips_prompt(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(app, ["poam", "delete", gap.id, "--yes"])
        assert result.exit_code == 0
        # Verify gone
        show = runner.invoke(app, ["poam", "show", gap.id])
        assert show.exit_code == 1

    def test_delete_prompt_cancel(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        save_poam(gap)
        result = runner.invoke(app, ["poam", "delete", gap.id], input="n\n")
        assert result.exit_code == 0
        assert "Cancelled" in result.output


# ── calendar ───────────────────────────────────────────────────────


class TestPoamCalendar:
    def test_empty_calendar_shows_clean_message(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["poam", "calendar", "--today", "2026-05-08"])
        assert result.exit_code == 0
        assert "No overdue or due-soon" in result.output

    def test_overdue_milestone_surfaces(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 1, 1),
                description="overdue work",
                status=POAMState.PLANNED,
            )
        )
        save_poam(gap)
        result = runner.invoke(app, ["poam", "calendar", "--today", "2026-05-08"])
        assert result.exit_code == 0
        assert "OVERDUE milestones" in result.output

    def test_due_soon_milestone_surfaces(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 5, 12),
                description="upcoming",
                status=POAMState.IN_PROGRESS,
            )
        )
        save_poam(gap)
        result = runner.invoke(
            app,
            ["poam", "calendar", "--today", "2026-05-08", "--window-days", "7"],
        )
        assert result.exit_code == 0
        assert "Due within 7 day" in result.output

    def test_calendar_json_output(self, runner: CliRunner) -> None:
        gap = _make_gap("AC-2", GapSeverity.HIGH)
        gap.poam_milestones.append(
            Milestone(
                target_date=date(2026, 1, 1),
                description="overdue",
                status=POAMState.PLANNED,
            )
        )
        save_poam(gap)
        result = runner.invoke(
            app,
            [
                "poam",
                "calendar",
                "--today",
                "2026-05-08",
                "--json",
            ],
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["today"] == "2026-05-08"
        assert len(body["overdue"]) == 1
        assert len(body["due_soon"]) == 0
