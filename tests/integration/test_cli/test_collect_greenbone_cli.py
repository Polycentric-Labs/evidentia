"""Integration test for `evidentia collect greenbone` (v0.13 V13-05)."""

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


def test_collect_greenbone_writes_findings_and_saves_evidence(runner: CliRunner, tmp_path: Path) -> None:
    """`collect greenbone --file <fixture>` writes findings JSON + saves one
    evidence artifact into the `--evidence-store` override, tagged with
    the default `fedramp-conmon-scans` cadence slug."""
    pytest.importorskip("defusedxml")
    out = tmp_path / "findings.json"
    store = tmp_path / "evidence"
    result = runner.invoke(
        app,
        [
            "collect",
            "greenbone",
            "--file",
            str(FIXTURES / "greenbone-sample.xml"),
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
    assert versions[0].source_system == "greenbone"
    assert "Saved evidence" in result.output
    # The fixture's inner report carries a <scan_end>; the manifest is
    # complete and the printed line says so.
    assert "(complete scan)" in result.output


def test_collect_greenbone_custom_cadence_slug(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    store = tmp_path / "evidence"
    result = runner.invoke(
        app,
        [
            "collect",
            "greenbone",
            "--file",
            str(FIXTURES / "greenbone-sample.xml"),
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


def test_collect_greenbone_no_save_evidence_saves_nothing(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    store = tmp_path / "evidence"
    result = runner.invoke(
        app,
        [
            "collect",
            "greenbone",
            "--file",
            str(FIXTURES / "greenbone-sample.xml"),
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


def test_collect_greenbone_unknown_cadence_slug_exits_1(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    result = runner.invoke(
        app,
        [
            "collect",
            "greenbone",
            "--file",
            str(FIXTURES / "greenbone-sample.xml"),
            "--cadence-slug",
            "not-a-real-cadence",
        ],
    )
    assert result.exit_code == 1
    assert "unknown cadence slug" in result.output


def test_collect_greenbone_hostile_fixture_exits_1(runner: CliRunner, tmp_path: Path) -> None:
    pytest.importorskip("defusedxml")
    result = runner.invoke(
        app,
        [
            "collect",
            "greenbone",
            "--file",
            str(FIXTURES / "greenbone-hostile-entity.xml"),
        ],
    )
    assert result.exit_code == 1
    assert "Greenbone ingestion failed" in result.output


def test_nessus_and_greenbone_ingests_produce_two_conmon_series_observations(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """End-to-end: ingesting a Nessus export and a Greenbone report a week
    apart, against the same cadence slug, saves two separate evidence-
    artifact lineages; `conmon series` (driven through the same Typer
    runner) then reports two observations against the cadence they share."""
    pytest.importorskip("defusedxml")
    nessus_text = (FIXTURES / "nessus-sample.nessus").read_text(encoding="utf-8")
    nessus_copy = tmp_path / "scan.nessus"
    nessus_copy.write_text(
        nessus_text.replace("Tue Sep  1 10:22:31 2026", "Mon Jun  1 10:00:00 2026"),
        encoding="utf-8",
    )

    greenbone_text = (FIXTURES / "greenbone-sample.xml").read_text(encoding="utf-8")
    assert "2026-06-01T09:45:12Z" in greenbone_text
    greenbone_copy = tmp_path / "report.xml"
    greenbone_copy.write_text(
        greenbone_text.replace("2026-06-01T09:45:12Z", "2026-06-08T09:45:12Z"),
        encoding="utf-8",
    )

    store = tmp_path / "evidence"
    for verb, path in (("nessus", nessus_copy), ("greenbone", greenbone_copy)):
        result = runner.invoke(
            app,
            [
                "collect",
                verb,
                "--file",
                str(path),
                "--output",
                str(tmp_path / f"{path.stem}-findings.json"),
                "--evidence-store",
                str(store),
                "--cadence-slug",
                "fedramp-conmon-scans",
            ],
        )
        assert result.exit_code == 0, result.output

    from evidentia_core.evidence_store import list_lineages

    lineages = list_lineages(store)
    assert len(lineages) == 2

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
    assert {o["source_system"] for o in body["series"]["observations"]} == {
        "nessus",
        "greenbone",
    }


def test_collect_greenbone_missing_extra_exits_1(
    runner: CliRunner,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``sys.modules[name] = None`` makes a subsequent ``import name`` raise
    ImportError: the hermetic way to simulate the [scan] extra being
    absent (mirrors tests/unit/test_collectors/test_collector_ssrf_guard.py's
    driver-absent simulation)."""
    monkeypatch.setitem(sys.modules, "evidentia_collectors.greenbone", None)
    result = runner.invoke(
        app,
        [
            "collect",
            "greenbone",
            "--file",
            str(FIXTURES / "greenbone-sample.xml"),
        ],
    )
    assert result.exit_code == 1
    assert "scan extra" in result.output.lower()
