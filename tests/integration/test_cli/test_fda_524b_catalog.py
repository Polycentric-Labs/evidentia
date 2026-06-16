"""Integration tests for the FDA Section 524B premarket-cybersecurity catalog.

The ``fda-524b-appendix1`` catalog (added in the FDA 524B pack) enumerates
the eight security control categories from Section V.B.1 of the FDA final
guidance "Cybersecurity in Medical Devices: Quality Management System
Considerations and Content of Premarket Submissions" (Feb 3, 2026 edition).

These tests drive the CLI end-to-end via Typer's CliRunner against the
persistent fixture inventory, asserting:

(a) the framework appears in ``evidentia catalog list``, and
(b) ``evidentia gap analyze --frameworks fda-524b-appendix1`` runs against
    the bundled sample inventory and returns a report (the sample inventory
    does not address 524B controls, so high gaps are expected — the test
    only confirms the run succeeds and a report is produced).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.main import app
from evidentia_core.catalogs.loader import load_any_catalog
from evidentia_core.catalogs.registry import FrameworkRegistry
from typer.testing import CliRunner

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"

FRAMEWORK_ID = "fda-524b-appendix1"

# The eight §V.B.1 security control categories, verbatim, in order.
EXPECTED_CONTROLS = [
    ("524b-scc-1-authentication", "Authentication"),
    ("524b-scc-2-authorization", "Authorization"),
    ("524b-scc-3-cryptography", "Cryptography"),
    ("524b-scc-4-code-data-execution-integrity", "Code, Data, and Execution Integrity"),
    ("524b-scc-5-confidentiality", "Confidentiality"),
    ("524b-scc-6-event-detection-logging", "Event Detection and Logging"),
    ("524b-scc-7-resiliency-recovery", "Resiliency and Recovery"),
    ("524b-scc-8-updatability-patchability", "Updatability and Patchability"),
]


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Keep the gap-store snapshot side effect out of the real profile."""
    monkeypatch.setenv("EVIDENTIA_GAP_STORE_DIR", str(tmp_path / "gap-store"))
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


def test_fda_524b_in_catalog_list(runner: CliRunner) -> None:
    """`catalog list` includes the FDA 524B framework."""
    result = runner.invoke(app, ["catalog", "list"])
    assert result.exit_code == 0, result.output
    assert FRAMEWORK_ID in result.output


def test_fda_524b_loads_with_eight_categories() -> None:
    """The catalog loads as a Tier-A control catalog with the 8 §V.B.1 categories."""
    catalog = load_any_catalog(FRAMEWORK_ID)
    assert catalog is not None
    assert catalog.framework_id == FRAMEWORK_ID
    assert catalog.tier == "A"
    assert catalog.placeholder is False
    assert len(catalog.controls) == 8

    actual = [(c.id, c.title) for c in catalog.controls]
    assert actual == EXPECTED_CONTROLS

    # Control #8 must surface the Appendix-1 name variant in its prose.
    updatability = catalog.get_control("524b-scc-8-updatability-patchability")
    assert updatability is not None
    assert "Firmware and Software Updates" in updatability.description


def test_fda_524b_gap_analyze_runs(runner: CliRunner, tmp_path: Path) -> None:
    """`gap analyze --frameworks fda-524b-appendix1` runs and writes a report.

    The bundled sample inventory does not address the 524B controls, so the
    analysis is expected to surface gaps. This test only confirms the command
    succeeds end-to-end and produces a parseable report artifact.
    """
    out = tmp_path / "fda-524b-gap.json"
    result = runner.invoke(
        app,
        [
            "gap",
            "analyze",
            "--inventory",
            str(FIXTURES / "sample-inventory.yaml"),
            "--frameworks",
            FRAMEWORK_ID,
            "--output",
            str(out),
        ],
    )

    assert result.exit_code == 0, result.output
    assert out.exists()

    report = json.loads(out.read_text(encoding="utf-8"))
    assert report, "expected a non-empty gap report"
