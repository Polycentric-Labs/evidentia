"""`evidentia conmon check/health --evidence-store` (v0.13, batch 5).

The evidence store stands in for a missing state-file date and adds a series
verdict column; the state file always wins where it has a date.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.conmon import CADENCE_SLUG_METADATA_KEY
from evidentia_core.evidence_store import save_evidence
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType
from typer.testing import CliRunner

WEEKLY = "pci-dss-11-6-1-weekly"
MONTHLY = "nist-800-53-rev5-ca7"
START = datetime(2026, 6, 1, 12, tzinfo=UTC)


def _save(store: Path, collected: datetime, slug: str = WEEKLY) -> None:
    artifact = EvidenceArtifact.model_validate(
        {
            "title": f"scan {collected.date().isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": "nessus",
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": {CADENCE_SLUG_METADATA_KEY: slug},
        }
    )
    save_evidence(artifact, evidence_store_dir=store)


@pytest.fixture()
def weekly_store(tmp_path: Path) -> Path:
    store = tmp_path / "store"
    for offset in range(8):
        _save(store, START + timedelta(days=7 * offset))
    return store


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


class TestCheck:
    def test_evidence_store_alone_supplies_the_anchor_and_the_series(
        self, runner: CliRunner, weekly_store: Path
    ) -> None:
        result = runner.invoke(
            app,
            ["conmon", "check", "--evidence-store", str(weekly_store), "--today", "2026-07-25", "--json"],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        rows = payload["overdue"] + payload["due_soon"]
        row = next(r for r in rows if r["slug"] == WEEKLY)
        assert row["last_completed"] == "2026-07-20"
        assert row["next_due"] == "2026-07-27"
        # The default window reaches back a year; the silence before June is a gap.
        assert row["series"] == "gapped"

    def test_state_file_wins_and_missing_slugs_come_from_evidence(
        self, runner: CliRunner, weekly_store: Path, tmp_path: Path
    ) -> None:
        state = tmp_path / "state.yaml"
        state.write_text(f"{WEEKLY}: 2026-05-01\n{MONTHLY}: 2026-07-01\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "check",
                "--state-file",
                str(state),
                "--evidence-store",
                str(weekly_store),
                "--today",
                "2026-07-25",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        payload = json.loads(result.output)
        rows = {r["slug"]: r for r in payload["overdue"] + payload["due_soon"]}
        assert rows[WEEKLY]["last_completed"] == "2026-05-01"
        assert rows[MONTHLY]["last_completed"] == "2026-07-01"
        assert rows[MONTHLY]["series"] == "insufficient"

    def test_series_column_is_rendered(self, runner: CliRunner, weekly_store: Path) -> None:
        result = runner.invoke(
            app,
            ["conmon", "check", "--evidence-store", str(weekly_store), "--today", "2026-07-25"],
        )
        assert result.exit_code == 0, result.output
        assert "Series" in result.output
        assert "gapped" in result.output

    def test_without_state_file_the_column_is_absent(self, runner: CliRunner, tmp_path: Path) -> None:
        state = tmp_path / "state.yaml"
        state.write_text(f"{WEEKLY}: 2026-07-20\n", encoding="utf-8")
        result = runner.invoke(app, ["conmon", "check", "--state-file", str(state), "--today", "2026-07-25", "--json"])
        assert result.exit_code == 0, result.output
        rows = json.loads(result.output)["due_soon"]
        assert rows and "series" not in rows[0]

    def test_neither_source_is_an_error(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["conmon", "check", "--today", "2026-07-25"])
        assert result.exit_code == 2
        assert "--evidence-store" in result.output


class TestHealth:
    def test_evidence_store_alone(self, runner: CliRunner, weekly_store: Path) -> None:
        result = runner.invoke(
            app,
            ["conmon", "health", "--evidence-store", str(weekly_store), "--today", "2026-07-25", "--json"],
        )
        assert result.exit_code == 0, result.output
        report = json.loads(result.output)
        assert report["total_cycles"] == 1
        assert [f["framework"] for f in report["frameworks"]] == ["pci-dss-v4"]

    def test_state_file_merged_with_evidence(self, runner: CliRunner, weekly_store: Path, tmp_path: Path) -> None:
        state = tmp_path / "state.yaml"
        state.write_text(f"{MONTHLY}: 2026-07-01\n", encoding="utf-8")
        result = runner.invoke(
            app,
            [
                "conmon",
                "health",
                "--state-file",
                str(state),
                "--evidence-store",
                str(weekly_store),
                "--today",
                "2026-07-25",
                "--json",
            ],
        )
        assert result.exit_code == 0, result.output
        assert json.loads(result.output)["total_cycles"] == 2

    def test_neither_source_is_an_error(self, runner: CliRunner) -> None:
        result = runner.invoke(app, ["conmon", "health", "--today", "2026-07-25"])
        assert result.exit_code == 2
