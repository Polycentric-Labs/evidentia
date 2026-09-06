"""Integration tests for `evidentia governance workflow` CLI (v0.7.11 P1.5 G5)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from textwrap import dedent

import pytest
from evidentia.cli.main import app
from evidentia_core.workflow_store import WORKFLOW_STORE_ENV_VAR
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def isolated_workflow_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "workflow-store"
    monkeypatch.setenv(WORKFLOW_STORE_ENV_VAR, str(store))
    return store


def _write_template(path: Path, content: str) -> None:
    path.write_text(dedent(content).lstrip(), encoding="utf-8")


_THREE_STEP_TEMPLATE = """
name: Test approval flow
description: Three-step test workflow.
subject: Model X
initiator: alice@example.com
steps:
  - name: Step 1
    description: First step
    required_role: 1LOD owner
  - name: Step 2
    required_role: 2LOD reviewer
    sla_days: 14
  - name: Step 3
    required_role: 3LOD audit
"""


def _run_workflow(runner: CliRunner, tmp_path: Path) -> str:
    template = tmp_path / "wf.yaml"
    _write_template(template, _THREE_STEP_TEMPLATE)
    result = runner.invoke(
        app,
        ["governance", "workflow", "run", "--template", str(template)],
    )
    assert result.exit_code == 0, result.output
    match = re.search(r"id:\s+([0-9a-f-]{36})", result.output)
    assert match
    return match.group(1)


# ── run ────────────────────────────────────────────────────────────


class TestWorkflowRun:
    def test_run_from_template(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        assert wid

    def test_run_status_renders_clean_value(self, runner: CliRunner, tmp_path: Path) -> None:
        """The confirmation line shows the clean status value, not the
        ``WorkflowStatus.IN_PROGRESS`` enum repr."""
        template = tmp_path / "wf.yaml"
        _write_template(template, _THREE_STEP_TEMPLATE)
        result = runner.invoke(
            app,
            ["governance", "workflow", "run", "--template", str(template)],
        )
        assert result.exit_code == 0, result.output
        assert "WorkflowStatus." not in result.output
        assert "in_progress" in result.output

    def test_run_invalid_yaml(self, runner: CliRunner, tmp_path: Path) -> None:
        template = tmp_path / "broken.yaml"
        template.write_text("{key: [value\n\t}", encoding="utf-8")
        result = runner.invoke(
            app,
            ["governance", "workflow", "run", "--template", str(template)],
        )
        assert result.exit_code == 1

    def test_run_yaml_must_be_mapping(self, runner: CliRunner, tmp_path: Path) -> None:
        template = tmp_path / "list.yaml"
        template.write_text("- item\n", encoding="utf-8")
        result = runner.invoke(
            app,
            ["governance", "workflow", "run", "--template", str(template)],
        )
        assert result.exit_code == 1


# ── advance ────────────────────────────────────────────────────────


class TestWorkflowAdvance:
    def test_advance_step(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(
            app,
            [
                "governance",
                "workflow",
                "advance",
                wid,
                "--step",
                "0",
                "--new-status",
                "approved",
                "--actor",
                "alice@example.com",
                "--note",
                "Looks good",
            ],
        )
        assert result.exit_code == 0
        assert "Advanced" in result.output

    def test_advance_status_renders_clean_value(self, runner: CliRunner, tmp_path: Path) -> None:
        """The advance confirmation shows the clean workflow-status value,
        not the ``WorkflowStatus.<NAME>`` enum repr."""
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(
            app,
            [
                "governance",
                "workflow",
                "advance",
                wid,
                "--step",
                "0",
                "--new-status",
                "approved",
                "--actor",
                "alice@example.com",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "WorkflowStatus." not in result.output

    def test_advance_invalid_status(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(
            app,
            [
                "governance",
                "workflow",
                "advance",
                wid,
                "--step",
                "0",
                "--new-status",
                "invalid-status",
                "--actor",
                "alice@example.com",
            ],
        )
        assert result.exit_code == 1

    def test_advance_unknown_workflow(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "governance",
                "workflow",
                "advance",
                "00000000-0000-0000-0000-000000000000",
                "--step",
                "0",
                "--new-status",
                "approved",
                "--actor",
                "x@y.com",
            ],
        )
        assert result.exit_code == 1

    def test_cannot_skip_ahead(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(
            app,
            [
                "governance",
                "workflow",
                "advance",
                wid,
                "--step",
                "2",
                "--new-status",
                "approved",
                "--actor",
                "x@y.com",
            ],
        )
        assert result.exit_code == 1


# ── status / list ──────────────────────────────────────────────────


class TestWorkflowStatusAndList:
    def test_status(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(app, ["governance", "workflow", "status", wid])
        assert result.exit_code == 0
        assert "Test approval flow" in result.output

    def test_status_json(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(app, ["governance", "workflow", "status", wid, "--json"])
        data = json.loads(result.output)
        assert data["id"] == wid

    def test_list_empty(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["governance", "workflow", "list"])
        assert result.exit_code == 0
        assert "No workflows defined" in result.output

    def test_list_json(self, runner: CliRunner, tmp_path: Path) -> None:
        _run_workflow(runner, tmp_path)
        result = runner.invoke(app, ["governance", "workflow", "list", "--json"])
        data = json.loads(result.output)
        assert len(data) == 1


# ── log ────────────────────────────────────────────────────────────


class TestWorkflowLog:
    def test_log_to_stdout(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(app, ["governance", "workflow", "log", wid])
        assert result.exit_code == 0
        assert "Workflow Audit Log" in result.output

    def test_log_to_file(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        out = tmp_path / "log.md"
        result = runner.invoke(
            app,
            [
                "governance",
                "workflow",
                "log",
                wid,
                "--output",
                str(out),
            ],
        )
        assert result.exit_code == 0
        body = out.read_text(encoding="utf-8")
        assert "Test approval flow" in body


# ── delete ─────────────────────────────────────────────────────────


class TestWorkflowDelete:
    def test_delete_with_yes(self, runner: CliRunner, tmp_path: Path) -> None:
        wid = _run_workflow(runner, tmp_path)
        result = runner.invoke(app, ["governance", "workflow", "delete", wid, "--yes"])
        assert result.exit_code == 0
        assert "Deleted" in result.output
