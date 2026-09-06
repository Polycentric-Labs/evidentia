"""Tests for the example data bundled inside the ``evidentia`` package.

Phase D6.A (v0.10.7): ``evidentia/examples/sample-inventory.yaml`` ships
in the wheel so a fresh ``pip install evidentia`` user can run the
quickstart with zero setup. These tests guard three properties:

1. The file is resolvable via ``importlib.resources`` from the installed
   package (not just the repo checkout) — the access path documented in
   the quickstart.
2. It parses with the real ``load_inventory`` loader as the Evidentia
   inventory format, with the expected schema and control IDs.
3. An end-to-end ``gap analyze`` against the bundled
   ``nist-800-53-rev5-moderate`` catalog produces a valid report without
   error — i.e. the template is genuinely runnable, not just parseable.

A fourth test drives the actual ``evidentia gap analyze`` CLI against the
bundled file via Typer's ``CliRunner`` to prove the quickstart command
works against the resource as a user would invoke it.
"""

from __future__ import annotations

from importlib.resources import as_file, files
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.gap_analyzer import GapAnalyzer, load_inventory
from evidentia_core.models.control import ControlInventory, ControlStatus
from evidentia_core.models.gap import GapAnalysisReport
from typer.testing import CliRunner

BUNDLED_INVENTORY = "sample-inventory.yaml"
# The catalog the bundled inventory is designed to produce a meaningful
# report against (non-placeholder, no license required).
QUICKSTART_FRAMEWORK = "nist-800-53-rev5-moderate"


@pytest.fixture(autouse=True)
def _reset_registry():
    """Isolate the singleton framework registry between tests."""
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_gap_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Keep the `gap analyze` gap-store snapshot out of the real profile."""
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gap-store"))


def test_bundled_inventory_resolvable_via_importlib_resources() -> None:
    """The documented `importlib.resources` access path returns a real file."""
    resource = files("evidentia.examples") / BUNDLED_INVENTORY
    assert resource.is_file(), (
        f"{BUNDLED_INVENTORY} must ship inside the evidentia.examples package "
        "so `pip install evidentia` users can run the quickstart."
    )
    # The text is non-trivial and self-documenting (header comment present).
    text = resource.read_text(encoding="utf-8")
    assert "controls:" in text
    assert "Evidentia sample control inventory" in text


def test_bundled_inventory_parses_as_evidentia_format() -> None:
    """The bundled YAML parses via the real loader with the expected schema."""
    resource = files("evidentia.examples") / BUNDLED_INVENTORY
    with as_file(resource) as path:
        assert path.suffix == ".yaml"  # loader dispatches on extension
        inv = load_inventory(path)

    assert isinstance(inv, ControlInventory)
    assert inv.source_format == "evidentia"
    assert inv.organization == "Example Organization"
    # Realistic size for a starting template.
    assert len(inv.controls) >= 10

    ids = {c.id for c in inv.controls}
    assert {"AC-2", "AU-2", "IA-2", "SC-13", "SI-4"}.issubset(ids)

    # The template intentionally mixes statuses so the report has signal.
    statuses = {c.status for c in inv.controls}
    assert ControlStatus.IMPLEMENTED in statuses
    assert ControlStatus.NOT_IMPLEMENTED in statuses


def test_bundled_inventory_control_ids_exist_in_quickstart_catalog() -> None:
    """Every bundled control ID resolves in the quickstart framework catalog.

    Guards against a future catalog edit silently making the shipped
    template analyze against controls that no longer exist (which would
    make the quickstart produce a confusing all-gaps report).
    """
    resource = files("evidentia.examples") / BUNDLED_INVENTORY
    with as_file(resource) as path:
        inv = load_inventory(path)

    catalog = FrameworkRegistry.get_instance().get_catalog(QUICKSTART_FRAMEWORK)
    catalog_ids = {c.id for c in catalog.controls}
    bundled_ids = {c.id for c in inv.controls}
    missing = bundled_ids - catalog_ids
    assert not missing, (
        f"Bundled inventory references control IDs absent from {QUICKSTART_FRAMEWORK}: {sorted(missing)}"
    )


def test_bundled_inventory_runs_gap_analysis_end_to_end() -> None:
    """`GapAnalyzer.analyze` against the bundled inventory yields a report."""
    resource = files("evidentia.examples") / BUNDLED_INVENTORY
    with as_file(resource) as path:
        inv = load_inventory(path)

    report = GapAnalyzer().analyze(
        inventory=inv,
        frameworks=[QUICKSTART_FRAMEWORK],
    )

    assert isinstance(report, GapAnalysisReport)
    assert report.frameworks_analyzed == [QUICKSTART_FRAMEWORK]
    # 16 implemented/partial controls vs 177 in rev5-moderate -> real gaps,
    # but the inventory must also satisfy some controls (not a 100%-gap run).
    assert report.total_controls_required > len(inv.controls)
    assert report.total_gaps > 0
    assert report.total_gaps < report.total_controls_required
    assert 0.0 < report.coverage_percentage < 100.0


def test_bundled_inventory_runs_via_gap_analyze_cli(runner: CliRunner, tmp_path: Path) -> None:
    """The documented quickstart CLI works against the bundled file.

    Mirrors exactly how a `pip install evidentia` user runs the
    quickstart: `evidentia gap analyze --inventory <bundled> --frameworks
    nist-800-53-rev5-moderate --output report.json`.
    """
    out = tmp_path / "gap-report.json"
    resource = files("evidentia.examples") / BUNDLED_INVENTORY
    with as_file(resource) as path:
        result = runner.invoke(
            app,
            [
                "gap",
                "analyze",
                "--inventory",
                str(path),
                "--frameworks",
                QUICKSTART_FRAMEWORK,
                "--output",
                str(out),
            ],
        )

    assert result.exit_code == 0, result.output
    assert out.exists()
    report = GapAnalysisReport.model_validate_json(out.read_text(encoding="utf-8"))
    assert report.frameworks_analyzed == [QUICKSTART_FRAMEWORK]
    assert report.total_gaps > 0
