"""Integration tests for `evidentia retention` CLI (v0.7.11 P0)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.retention_metadata_store import RETENTION_STORE_ENV_VAR
from typer.testing import CliRunner


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def isolated_retention_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "retention-store"
    monkeypatch.setenv(RETENTION_STORE_ENV_VAR, str(store))
    return store


def _add_record(
    runner: CliRunner,
    *,
    classification: str = "sox-404",
    legal_hold: bool = False,
) -> str:
    args = [
        "retention",
        "set",
        "--classification",
        classification,
    ]
    if legal_hold:
        args.append("--legal-hold")
    result = runner.invoke(app, args)
    assert result.exit_code == 0, result.output
    match = re.search(r"id:\s+([0-9a-f-]{36})", result.output)
    assert match, f"failed to parse id from {result.output!r}"
    return match.group(1)


# ── set ────────────────────────────────────────────────────────────


class TestRetentionSet:
    def test_minimal(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        assert rid

    def test_unknown_classification(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            ["retention", "set", "--classification", "weird-class"],
        )
        assert result.exit_code == 1
        assert "Unknown classification" in result.output

    def test_with_legal_hold(self, runner: CliRunner) -> None:
        rid = _add_record(runner, legal_hold=True)
        result = runner.invoke(app, ["retention", "show", rid, "--json"])
        data = json.loads(result.output)
        assert data["legal_hold"] is True


# ── list ───────────────────────────────────────────────────────────


class TestRetentionList:
    def test_empty(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["retention", "list"])
        assert result.exit_code == 0
        assert "No retention" in result.output

    def test_json(self, runner: CliRunner) -> None:
        _add_record(runner, classification="sox-404")
        _add_record(runner, classification="pci-dss")
        result = runner.invoke(app, ["retention", "list", "--json"])
        data = json.loads(result.output)
        assert len(data) == 2

    def test_filter_by_classification(self, runner: CliRunner) -> None:
        _add_record(runner, classification="sox-404")
        _add_record(runner, classification="pci-dss")
        result = runner.invoke(
            app,
            ["retention", "list", "--classification", "sox-404", "--json"],
        )
        data = json.loads(result.output)
        assert len(data) == 1
        assert data[0]["classification"] == "sox-404"


# ── show ───────────────────────────────────────────────────────────


class TestRetentionShow:
    def test_show(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        result = runner.invoke(app, ["retention", "show", rid])
        assert result.exit_code == 0
        assert "Classification" in result.output

    def test_show_unknown(self, runner: CliRunner) -> None:
        result = runner.invoke(
            app,
            [
                "retention",
                "show",
                "00000000-0000-0000-0000-000000000000",
            ],
        )
        assert result.exit_code == 1


# ── extend ─────────────────────────────────────────────────────────


class TestRetentionExtend:
    def test_extend_succeeds(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        result = runner.invoke(
            app,
            [
                "retention",
                "extend",
                rid,
                "--new-lock-until",
                "2099-12-31",
            ],
        )
        assert result.exit_code == 0
        assert "Extended" in result.output

    def test_extend_shortening_rejected(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        result = runner.invoke(
            app,
            [
                "retention",
                "extend",
                rid,
                "--new-lock-until",
                "2020-01-01",  # very past
            ],
        )
        assert result.exit_code == 1
        assert "shortening" in result.output.lower() or "forbid" in result.output.lower()


# ── transition ─────────────────────────────────────────────────────


class TestRetentionTransition:
    def test_active_to_preserved(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        result = runner.invoke(
            app,
            [
                "retention",
                "transition",
                rid,
                "--new-stage",
                "preserved",
            ],
        )
        assert result.exit_code == 0
        assert "Transitioned" in result.output

    def test_unknown_stage(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        result = runner.invoke(
            app,
            [
                "retention",
                "transition",
                rid,
                "--new-stage",
                "weird-stage",
            ],
        )
        assert result.exit_code == 1
        assert "Unknown stage" in result.output

    def test_active_to_expired_rejected_inside_window(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        result = runner.invoke(
            app,
            [
                "retention",
                "transition",
                rid,
                "--new-stage",
                "expired",
            ],
        )
        # Inside window → rejected with clear error
        assert result.exit_code == 1


# ── delete ─────────────────────────────────────────────────────────


class TestRetentionDelete:
    def test_delete_with_yes(self, runner: CliRunner) -> None:
        rid = _add_record(runner)
        result = runner.invoke(app, ["retention", "delete", rid, "--yes"])
        assert result.exit_code == 0


# ── report ─────────────────────────────────────────────────────────


class TestRetentionReport:
    def test_empty_report(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["retention", "report"])
        assert result.exit_code == 0
        assert "No records" in result.output

    def test_populated_report(self, runner: CliRunner) -> None:
        _add_record(runner)
        result = runner.invoke(app, ["retention", "report"])
        assert result.exit_code == 0
        assert "Retention Posture Report" in result.output

    def test_to_file(self, runner: CliRunner, tmp_path: Path) -> None:
        _add_record(runner)
        out = tmp_path / "report.md"
        result = runner.invoke(
            app,
            ["retention", "report", "--output", str(out)],
        )
        assert result.exit_code == 0
        body = out.read_text(encoding="utf-8")
        assert "Retention Posture Report" in body
