"""Withdrawn catalog controls are not requirements.

NIST SP 800-53 Rev 5 keeps 182 withdrawn entries in its OSCAL catalog (24
controls and 158 enhancements) so that references keep resolving. Through
v0.12 every one of them surfaced as a CRITICAL "missing" gap in an analysis
against the full catalog.
"""

from __future__ import annotations

import pytest
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.gap_analyzer import GapAnalyzer
from evidentia_core.models.catalog import CatalogControl, ControlCatalog
from evidentia_core.models.control import ControlImplementation, ControlInventory, ControlStatus


@pytest.fixture(autouse=True)
def _reset_registry():  # type: ignore[no-untyped-def]
    FrameworkRegistry.reset_instance()
    yield
    FrameworkRegistry.reset_instance()


def _catalog() -> ControlCatalog:
    return ControlCatalog(
        framework_id="demo",
        framework_name="Demo",
        version="1",
        source="test",
        controls=[
            CatalogControl(
                id="AC-2",
                title="Account Management",
                description="Manage accounts.",
                enhancements=[
                    CatalogControl(id="AC-2(1)", title="Automated", description="Automate it."),
                    CatalogControl(id="AC-2(10)", title="Shared credentials", description="", withdrawn=True),
                ],
            ),
            CatalogControl(id="AC-13", title="Supervision and Review", description="", withdrawn=True),
        ],
    )


def test_required_set_skips_withdrawn_controls_and_enhancements() -> None:
    required = GapAnalyzer()._build_required_set({"demo": _catalog()})
    assert set(required) == {"demo:AC-2", "demo:AC-2(1)"}


def test_bundled_full_catalog_reports_no_withdrawn_gaps() -> None:
    inventory = ControlInventory(
        organization="Test",
        controls=[ControlImplementation(id="AC-1", title="Policy", status=ControlStatus.IMPLEMENTED)],
    )
    report = GapAnalyzer().analyze(inventory, ["nist-800-53-rev5"])
    ids = {gap.control_id for gap in report.gaps}
    assert "AC-13" not in ids
    assert "AC-2.10" not in ids and "AC-2(10)" not in ids
    assert "AC-2" in ids
