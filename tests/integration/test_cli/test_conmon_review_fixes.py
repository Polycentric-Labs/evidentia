"""CONMON CLI hardening from the v0.13.0 review (state loaders, paths, bounds, markup)."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_yaml_timestamp_in_state_file_is_accepted(runner: CliRunner, tmp_path: Path) -> None:
    """A YAML timestamp loads as datetime; day-based cadences used to raise TypeError."""
    state_file = tmp_path / "state.yaml"
    state_file.write_text("pci-dss-11-6-1-weekly: 2026-10-01 09:00:00\n", encoding="utf-8")
    result = runner.invoke(app, ["conmon", "check", "--state-file", str(state_file), "--today", "2026-10-02", "--json"])
    assert result.exit_code in (0, 1), result.output
    assert "Traceback" not in result.output
    assert "pci-dss-11-6-1-weekly" in result.output


def test_missing_evidence_store_is_a_usage_error(runner: CliRunner, tmp_path: Path) -> None:
    """A typo in --evidence-store used to read as an all-clear (probe and sweep findings)."""
    result = runner.invoke(
        app,
        ["conmon", "check", "--evidence-store", str(tmp_path / "does-not-exist"), "--today", "2026-10-02"],
    )
    assert result.exit_code == 2, result.output
    assert "does-not-exist" in result.output


def test_mark_completed_rejects_future_dates(runner: CliRunner, tmp_path: Path) -> None:
    state_file = tmp_path / "state.yaml"
    future = (date.today() + timedelta(days=30)).isoformat()
    result = runner.invoke(
        app,
        ["conmon", "mark-completed", "pci-dss-11-6-1-weekly", "--when", future, "--state-file", str(state_file)],
    )
    assert result.exit_code == 2, result.output
    assert "in the future" in result.output
    assert not state_file.exists()


def test_series_unknown_slug_with_markup_is_safe(runner: CliRunner, tmp_path: Path) -> None:
    store = tmp_path / "evidence"
    store.mkdir()
    result = runner.invoke(app, ["conmon", "series", "[/x]not-a-slug", "--evidence-store", str(store)])
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
    assert "unknown cadence slug" in result.output


def test_series_lookback_is_bounded(runner: CliRunner, tmp_path: Path) -> None:
    store = tmp_path / "evidence"
    store.mkdir()
    result = runner.invoke(
        app,
        ["conmon", "series", "pci-dss-11-6-1-weekly", "--evidence-store", str(store), "--lookback-days", "99999999"],
    )
    assert result.exit_code == 2, result.output
    assert "Traceback" not in result.output
