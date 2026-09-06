"""Integration test for `evidentia collect nessus` (v0.13 V13-05)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from evidentia.cli.main import app
from typer.testing import CliRunner

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "scans"


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


def test_collect_nessus_writes_findings_and_saves_evidence(runner: CliRunner, tmp_path: Path) -> None:
    """`collect nessus --file <fixture>` writes findings JSON + saves one
    evidence artifact into the `--evidence-store` override, tagged with
    the default `fedramp-conmon-scans` cadence slug."""
    pytest.importorskip("defusedxml")
    out = tmp_path / "findings.json"
    store = tmp_path / "evidence"
    result = runner.invoke(
        app,
        [
            "collect",
            "nessus",
            "--file",
            str(FIXTURES / "nessus-sample.nessus"),
            "--output",
            str(out),
            "--evidence-store",
            str(store),
        ],
    )
    assert result.exit_code == 0, result.output
    findings = json.loads(out.read_text(encoding="utf-8"))
    assert len(findings) == 5
    assert {f["severity"] for f in findings} == {
        "informational",
        "low",
        "medium",
        "high",
        "critical",
    }

    from evidentia_core.evidence_store import list_lineage, list_lineages

    lineages = list_lineages(store)
    assert len(lineages) == 1
    versions = list_lineage(lineages[0], store)
    assert len(versions) == 1
    assert versions[0].metadata["cadence_slug"] == "fedramp-conmon-scans"
    assert versions[0].source_system == "nessus"
    assert "Saved evidence" in result.output
    # The manifest is incomplete (one fixture host has no HOST_END) — the
    # printed line surfaces that rather than silently claiming completeness.
    assert "incomplete" in result.output


def test_collect_nessus_custom_cadence_slug(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    store = tmp_path / "evidence"
    result = runner.invoke(
        app,
        [
            "collect",
            "nessus",
            "--file",
            str(FIXTURES / "nessus-sample.nessus"),
            "--output",
            str(tmp_path / "out.json"),
            "--evidence-store",
            str(store),
            "--cadence-slug",
            "nist-800-53-rev5-ca7",
        ],
    )
    assert result.exit_code == 0, result.output

    from evidentia_core.evidence_store import list_lineage, list_lineages

    lineages = list_lineages(store)
    versions = list_lineage(lineages[0], store)
    assert versions[0].metadata["cadence_slug"] == "nist-800-53-rev5-ca7"


def test_collect_nessus_no_save_evidence_saves_nothing(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    store = tmp_path / "evidence"
    result = runner.invoke(
        app,
        [
            "collect",
            "nessus",
            "--file",
            str(FIXTURES / "nessus-sample.nessus"),
            "--output",
            str(tmp_path / "out.json"),
            "--evidence-store",
            str(store),
            "--no-save-evidence",
        ],
    )
    assert result.exit_code == 0, result.output
    assert not store.exists() or not any(store.iterdir())
    assert "not saved" in result.output.lower()


def test_collect_nessus_unknown_cadence_slug_exits_1(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    result = runner.invoke(
        app,
        [
            "collect",
            "nessus",
            "--file",
            str(FIXTURES / "nessus-sample.nessus"),
            "--cadence-slug",
            "not-a-real-cadence",
        ],
    )
    assert result.exit_code == 1
    assert "unknown cadence slug" in result.output


def test_collect_nessus_hostile_fixture_exits_1(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    result = runner.invoke(
        app,
        [
            "collect",
            "nessus",
            "--file",
            str(FIXTURES / "nessus-hostile-entity.nessus"),
        ],
    )
    assert result.exit_code == 1
    assert "Nessus ingestion failed" in result.output


def test_two_ingests_produce_two_conmon_series_observations(runner: CliRunner, tmp_path: Path) -> None:
    """End-to-end: ingesting the fixture twice, with two different HOST_END
    timestamps, saves two separate evidence-artifact lineages (each
    ``collect nessus`` call mints a fresh EvidenceArtifact.id); `conmon
    series` — driven through the same Typer runner — then reports two
    observations against the cadence they share."""
    pytest.importorskip("defusedxml")
    base_text = (FIXTURES / "nessus-sample.nessus").read_text(encoding="utf-8")
    assert "Tue Sep  1 10:22:31 2026" in base_text

    copy1 = tmp_path / "scan-1.nessus"
    copy1.write_text(
        base_text.replace("Tue Sep  1 10:22:31 2026", "Mon Jun  1 10:00:00 2026"),
        encoding="utf-8",
    )
    copy2 = tmp_path / "scan-2.nessus"
    copy2.write_text(
        base_text.replace("Tue Sep  1 10:22:31 2026", "Wed Jul  1 10:00:00 2026"),
        encoding="utf-8",
    )

    store = tmp_path / "evidence"
    for copy in (copy1, copy2):
        result = runner.invoke(
            app,
            [
                "collect",
                "nessus",
                "--file",
                str(copy),
                "--output",
                str(tmp_path / f"{copy.stem}-findings.json"),
                "--evidence-store",
                str(store),
                "--cadence-slug",
                "fedramp-conmon-scans",
            ],
        )
        assert result.exit_code == 0, result.output

    from evidentia_core.evidence_store import list_lineages

    assert len(list_lineages(store)) == 2

    series_result = runner.invoke(
        app,
        [
            "conmon",
            "series",
            "fedramp-conmon-scans",
            "--evidence-store",
            str(store),
            "--since",
            "2026-01-01",
            "--until",
            "2026-12-31",
            "--json",
        ],
    )
    assert series_result.exit_code == 0, series_result.output
    body = json.loads(series_result.output)
    assert len(body["series"]["observations"]) == 2


def test_collect_nessus_missing_extra_exits_1(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``sys.modules[name] = None`` makes a subsequent ``import name`` raise
    ImportError — the hermetic way to simulate the [scan] extra being
    absent (mirrors tests/unit/test_collectors/test_collector_ssrf_guard.py's
    driver-absent simulation)."""
    monkeypatch.setitem(sys.modules, "evidentia_collectors.nessus", None)
    result = runner.invoke(
        app,
        [
            "collect",
            "nessus",
            "--file",
            str(FIXTURES / "nessus-sample.nessus"),
        ],
    )
    assert result.exit_code == 1
    assert "scan extra" in result.output.lower()
