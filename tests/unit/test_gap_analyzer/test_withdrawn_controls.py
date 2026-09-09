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


def _deep_catalog(*, top_withdrawn: bool = False, middle_withdrawn: bool = False) -> ControlCatalog:
    return ControlCatalog(
        framework_id="deep",
        framework_name="Deep",
        version="1",
        source="test",
        controls=[
            CatalogControl(
                id="AC-1",
                title="Top",
                description="Top statement.",
                withdrawn=top_withdrawn,
                enhancements=[
                    CatalogControl(
                        id="AC-1(1)",
                        title="Middle",
                        description="Middle statement.",
                        withdrawn=middle_withdrawn,
                        enhancements=[CatalogControl(id="AC-1(1)(a)", title="Leaf", description="Leaf statement.")],
                    ),
                    CatalogControl(id="AC-1(2)", title="Sibling", description="Sibling statement."),
                ],
            ),
            CatalogControl(id="AC-2", title="Last", description="Last statement."),
        ],
    )


@pytest.mark.parametrize(
    ("top_withdrawn", "middle_withdrawn", "expected"),
    [
        (False, False, ["deep:AC-1", "deep:AC-1(1)", "deep:AC-1(1)(a)", "deep:AC-1(2)", "deep:AC-2"]),
        (True, False, ["deep:AC-2"]),
        (False, True, ["deep:AC-1", "deep:AC-1(2)", "deep:AC-2"]),
    ],
)
def test_required_set_visits_all_active_depths_and_excludes_withdrawn_subtrees(
    top_withdrawn: bool, middle_withdrawn: bool, expected: list[str]
) -> None:
    catalog = _deep_catalog(top_withdrawn=top_withdrawn, middle_withdrawn=middle_withdrawn)
    required = GapAnalyzer()._build_required_set({"deep": catalog})
    assert list(required) == expected
    assert [item[0][1].id for item in required.values()] == [key.removeprefix("deep:") for key in expected]


@pytest.mark.parametrize("depth", [1, 2])
@pytest.mark.parametrize("inventory_id", ["CC-3", "CC-03", "Escalation Journey Review"])
def test_implemented_descendants_match_by_id_fuzzy_id_and_title(
    monkeypatch: pytest.MonkeyPatch, depth: int, inventory_id: str
) -> None:
    leaf = CatalogControl(id="CC-3", title="Escalation Journey Review", description="Review escalations.")
    middle = CatalogControl(
        id="BB-2",
        title="Resource Inventory",
        description="Maintain resources.",
        enhancements=[leaf] if depth == 2 else [],
    )
    top = CatalogControl(
        id="AA-1",
        title="Policy Foundation",
        description="Maintain policy.",
        enhancements=[middle] if depth == 2 else [middle, leaf],
    )
    catalog = ControlCatalog(framework_id="deep", framework_name="Deep", version="1", source="test", controls=[top])
    analyzer = GapAnalyzer()
    monkeypatch.setattr(analyzer.registry, "get_catalog", lambda framework_id: catalog)
    inventory = ControlInventory(
        organization="Test",
        controls=[
            ControlImplementation(id=value, status=ControlStatus.IMPLEMENTED)
            for value in ("AA-1", "BB-2", inventory_id)
        ],
    )
    report = analyzer.analyze(inventory, ["deep"], show_efficiency=False)
    assert report.total_controls_required == 3
    assert report.total_gaps == 0
    assert report.gaps == []
    assert report.coverage_percentage == 100.0
