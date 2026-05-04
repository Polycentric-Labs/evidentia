"""Integration tests for `evidentia governance metrics` CLI (v0.7.11 P1.5 G3)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.metric_store import METRIC_STORE_ENV_VAR
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def isolated_metric_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    store = tmp_path / "metric-store"
    monkeypatch.setenv(METRIC_STORE_ENV_VAR, str(store))
    return store


def _add_minimal_metric(
    runner: CliRunner,
    *,
    name: str = "Failed-login rate",
    kind: str = "kri",
    direction: str = "higher_is_worse",
) -> str:
    result = runner.invoke(
        app,
        [
            "governance", "metrics", "add",
            "--name", name,
            "--description", "Test description",
            "--kind", kind,
            "--direction", direction,
            "--unit", "per 1k",
            "--warning-threshold", "2.0",
            "--critical-threshold", "4.0",
        ],
    )
    assert result.exit_code == 0, result.output
    match = re.search(r"id:\s+([0-9a-f-]{36})", result.output)
    assert match, f"failed to parse id from: {result.output!r}"
    return match.group(1)


# ── add ────────────────────────────────────────────────────────────


class TestMetricsAdd:
    def test_minimal_add(self, runner: CliRunner) -> None:
        mid = _add_minimal_metric(runner)
        assert mid

    def test_invalid_kind_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "governance", "metrics", "add",
                "--name", "x", "--description", "x",
                "--kind", "not-a-kind",
                "--direction", "higher_is_worse",
                "--unit", "x",
            ],
        )
        assert result.exit_code == 1
        assert "Unknown kind" in result.output

    def test_invalid_direction_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "governance", "metrics", "add",
                "--name", "x", "--description", "x",
                "--kind", "kri",
                "--direction", "weird-direction",
                "--unit", "x",
            ],
        )
        assert result.exit_code == 1
        assert "Unknown direction" in result.output


# ── observe ────────────────────────────────────────────────────────


class TestMetricsObserve:
    def test_record_observation(self, runner: CliRunner) -> None:
        mid = _add_minimal_metric(runner)
        result = runner.invoke(
            app,
            [
                "governance", "metrics", "observe", mid,
                "--value", "1.5",
                "--observed-at", "2026-01-15",
            ],
        )
        assert result.exit_code == 0
        assert "Recorded" in result.output
        assert "comfortable" in result.output  # 1.5 < warning 2.0

    def test_observe_unknown_metric_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "governance", "metrics", "observe",
                "00000000-0000-0000-0000-000000000000",
                "--value", "1.0",
                "--observed-at", "2026-01-15",
            ],
        )
        assert result.exit_code == 1


# ── list ───────────────────────────────────────────────────────────


class TestMetricsList:
    def test_empty_message(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["governance", "metrics", "list"])
        assert result.exit_code == 0
        assert "No metrics defined" in result.output

    def test_json_output(self, runner: CliRunner) -> None:
        _add_minimal_metric(runner, name="A", kind="kri")
        _add_minimal_metric(runner, name="B", kind="kpi", direction="higher_is_better")
        result = runner.invoke(
            app, ["governance", "metrics", "list", "--json"]
        )
        data = json.loads(result.output)
        assert len(data) == 2
        names = {m["name"] for m in data}
        assert names == {"A", "B"}

    def test_filter_by_kind(self, runner: CliRunner) -> None:
        _add_minimal_metric(runner, name="K1", kind="kri")
        _add_minimal_metric(runner, name="K2", kind="kpi", direction="higher_is_better")
        result = runner.invoke(
            app, ["governance", "metrics", "list", "--kind", "kri", "--json"]
        )
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["name"] == "K1"


# ── show ───────────────────────────────────────────────────────────


class TestMetricsShow:
    def test_show_existing(self, runner: CliRunner) -> None:
        mid = _add_minimal_metric(runner)
        result = runner.invoke(
            app, ["governance", "metrics", "show", mid]
        )
        assert result.exit_code == 0
        assert "Failed-login rate" in result.output

    def test_show_unknown_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "governance", "metrics", "show",
                "00000000-0000-0000-0000-000000000000",
            ],
        )
        assert result.exit_code == 1


# ── delete ─────────────────────────────────────────────────────────


class TestMetricsDelete:
    def test_delete_with_yes(self, runner: CliRunner) -> None:
        mid = _add_minimal_metric(runner)
        result = runner.invoke(
            app, ["governance", "metrics", "delete", mid, "--yes"]
        )
        assert result.exit_code == 0
        assert "Deleted" in result.output


# ── report ─────────────────────────────────────────────────────────


class TestMetricsReport:
    def test_empty_report(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["governance", "metrics", "report"])
        assert result.exit_code == 0
        assert "No metrics defined" in result.output

    def test_report_with_metrics(self, runner: CliRunner) -> None:
        _add_minimal_metric(runner)
        result = runner.invoke(app, ["governance", "metrics", "report"])
        assert result.exit_code == 0
        assert "## KRI" in result.output

    def test_report_to_file(self, runner: CliRunner, tmp_path: Path) -> None:
        _add_minimal_metric(runner)
        out = tmp_path / "report.md"
        result = runner.invoke(
            app,
            ["governance", "metrics", "report", "--output", str(out)],
        )
        assert result.exit_code == 0
        body = out.read_text(encoding="utf-8")
        assert "Governance Metrics Dashboard" in body
