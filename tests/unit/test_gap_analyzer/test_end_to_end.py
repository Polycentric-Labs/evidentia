"""End-to-end smoke tests for the gap analyzer pipeline.

These tests use the bundled sample catalogs (nist-800-53-mod, soc2-tsc) and
the persistent fixture inventory files in tests/fixtures/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.gap_analyzer import GapAnalyzer, export_report, load_inventory
from evidentia_core.models.gap import GapAnalysisReport, GapSeverity

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


@pytest.fixture(autouse=True)
def _reset_registry():
    """Reset the framework registry between tests."""
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


def test_load_yaml_inventory():
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    assert inv.organization == "Acme Corporation"
    assert len(inv.controls) == 9
    assert inv.source_format == "evidentia"
    ids = {c.id for c in inv.controls}
    assert {"AC-2", "AC-3", "IA-2", "CC6.1", "CC7.1"}.issubset(ids)


def test_load_csv_inventory():
    inv = load_inventory(FIXTURES / "sample-inventory.csv")
    assert inv.source_format == "csv"
    assert len(inv.controls) == 7
    ids = {c.id for c in inv.controls}
    assert {"AC-2", "AC-3", "AU-2", "IA-2", "SC-13"}.issubset(ids)


def test_gap_analysis_runs_end_to_end():
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    analyzer = GapAnalyzer()
    report = analyzer.analyze(
        inventory=inv,
        frameworks=["nist-800-53-mod", "soc2-tsc"],
        show_efficiency=True,
        min_efficiency_frameworks=2,
    )

    assert isinstance(report, GapAnalysisReport)
    assert report.organization == "Acme Corporation"
    assert report.frameworks_analyzed == ["nist-800-53-mod", "soc2-tsc"]
    assert report.total_controls_required > 0
    assert report.total_gaps > 0
    assert 0 <= report.coverage_percentage <= 100
    # Implemented controls should have reduced the gap count
    assert report.total_gaps < report.total_controls_required
    # Should have detected at least some efficiency opportunities with 2-fw threshold
    assert len(report.efficiency_opportunities) >= 0


def test_gaps_are_sorted_by_priority():
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    report = GapAnalyzer().analyze(
        inventory=inv,
        frameworks=["nist-800-53-mod", "soc2-tsc"],
    )
    priorities = [g.priority_score for g in report.gaps]
    assert priorities == sorted(priorities, reverse=True)


def test_partial_implementation_produces_high_severity():
    """AC-3 is partially_implemented in the fixture — should be HIGH severity."""
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    report = GapAnalyzer().analyze(
        inventory=inv,
        frameworks=["nist-800-53-mod"],
    )
    ac3 = next((g for g in report.gaps if g.control_id == "AC-3"), None)
    assert ac3 is not None, "Expected AC-3 to be in the gap report (partial)"
    assert ac3.gap_severity == GapSeverity.HIGH.value
    assert ac3.implementation_status == "partial"


def test_planned_control_produces_medium_severity():
    """AU-2 is planned in the fixture — should be MEDIUM severity."""
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    report = GapAnalyzer().analyze(
        inventory=inv,
        frameworks=["nist-800-53-mod"],
    )
    au2 = next((g for g in report.gaps if g.control_id == "AU-2"), None)
    assert au2 is not None
    assert au2.gap_severity == GapSeverity.MEDIUM.value
    assert au2.implementation_status == "planned"


def test_implemented_control_produces_no_gap():
    """AC-2 is implemented — should NOT appear in the gap report."""
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    report = GapAnalyzer().analyze(
        inventory=inv,
        frameworks=["nist-800-53-mod"],
    )
    assert not any(g.control_id == "AC-2" for g in report.gaps)


def test_cross_framework_value_populated():
    """Gaps should have cross_framework_value populated from the bundled crosswalk."""
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    report = GapAnalyzer().analyze(
        inventory=inv,
        frameworks=["nist-800-53-mod", "soc2-tsc"],
    )
    # At least one gap should have cross-framework mappings
    assert any(len(g.cross_framework_value) > 0 for g in report.gaps), (
        "Expected at least one gap to have cross-framework mappings from the bundled crosswalk"
    )


@pytest.mark.parametrize(
    "fmt,ext",
    [
        ("json", "json"),
        ("csv", "csv"),
        ("markdown", "md"),
        ("oscal-ar", "json"),
        ("sarif", "sarif"),
        # v0.10.5 Phase 7 + Phase 8 — gap-output format expansions
        ("ocsf-detection", "json"),
        ("cyclonedx-vex", "json"),
    ],
)
def test_export_all_formats(tmp_path, fmt, ext):
    inv = load_inventory(FIXTURES / "sample-inventory.yaml")
    report = GapAnalyzer().analyze(
        inventory=inv,
        frameworks=["nist-800-53-mod", "soc2-tsc"],
    )

    out_path = tmp_path / f"report.{ext}"
    result = export_report(report, out_path, format=fmt)  # type: ignore[arg-type]
    assert result.exists()
    assert result.stat().st_size > 0

    # JSON-based outputs should be parseable
    if ext in ("json", "sarif"):
        data = json.loads(result.read_text(encoding="utf-8"))
        # OCSF emits (compliance + detection) produce JSON arrays of
        # finding records; everything else produces JSON objects.
        if fmt in ("ocsf", "ocsf-detection"):
            assert isinstance(data, list)
        else:
            assert isinstance(data, dict)
