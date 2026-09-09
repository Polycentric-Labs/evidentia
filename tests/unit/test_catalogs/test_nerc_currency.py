"""NERC publication dates must not create additional assessed standards."""

import importlib.util
import json
from datetime import date
from pathlib import Path

from evidentia_core.catalogs.loader import load_catalog
from evidentia_core.gap_analyzer import GapAnalyzer

CURRENT = {
    "CIP-002-5.1a",
    "CIP-003-9",
    "CIP-004-7",
    "CIP-005-7",
    "CIP-006-6",
    "CIP-007-6",
    "CIP-008-6",
    "CIP-009-6",
    "CIP-010-4",
    "CIP-011-3",
    "CIP-012-2",
    "CIP-013-2",
    "CIP-014-3",
}
FUTURE = {
    "CIP-002-7",
    "CIP-002-8",
    "CIP-003-10",
    "CIP-003-11",
    "CIP-004-8",
    "CIP-005-8",
    "CIP-006-7.1",
    "CIP-007-7.1",
    "CIP-008-7.1",
    "CIP-009-7.1",
    "CIP-010-5",
    "CIP-011-4.1",
    "CIP-013-3",
    "CIP-015-1",
    "CIP-015-2",
}


def test_current_us_set_and_license_boundary() -> None:
    catalog = load_catalog("nerc-cip-v7")
    assert {c.id for c in catalog.controls} == CURRENT
    assert catalog.control_count == 13
    assert catalog.get_control("CIP-014-3").title == "Physical Security"
    assert catalog.verified_on == date(2026, 9, 9)
    assert catalog.tier == "C"
    assert catalog.placeholder and catalog.license_required
    assert catalog.text_depth == "headings"
    assert all(c.placeholder and c.license_required and c.description == "" for c in catalog.controls)
    assert all(c.properties["jurisdiction"] == "US" for c in catalog.controls)
    assert catalog.get_control("CIP-012-2").properties["effective_on"] == "2026-07-01"


def test_approval_publication_and_applicability_dates_are_separate() -> None:
    catalog = load_catalog("nerc-cip-v7")
    notices = {n.id: n for n in catalog.publication_notices}
    assert {key for key, n in notices.items() if n.status != "pending"} == FUTURE
    assert notices["CIP-014-4"].status == "pending"
    assert notices["CIP-014-4"].approved_on is None
    o919 = notices["CIP-006-7.1"]
    assert o919.approved_on == date(2026, 3, 19)
    assert o919.published_on == date(2026, 3, 24)
    assert o919.order_effective_on == date(2026, 5, 26)
    assert o919.effective_on == date(2028, 7, 1)
    assert notices["CIP-002-7"].superseded_by == "CIP-002-8"
    assert notices["CIP-003-10"].inactive_on == date(2029, 6, 30)
    assert notices["CIP-015-1"].effective_on == date(2028, 10, 1)
    assert notices["CIP-015-1"].inactive_on == date(2029, 9, 30)
    assert notices["CIP-015-2"].approved_on == date(2026, 8, 10)
    assert notices["CIP-015-2"].published_on is None
    assert notices["CIP-015-2"].effective_on == date(2029, 10, 1)
    assert "2030-10-01" in notices["CIP-015-2"].notes
    assert "2031-10-01" in notices["CIP-015-2"].notes
    required = GapAnalyzer()._build_required_set({catalog.framework_id: catalog})
    assert set(required) == {f"nerc-cip-v7:{c}" for c in CURRENT}


def test_nerc_generator_matches_the_bundled_catalog(tmp_path, monkeypatch) -> None:
    root = Path(__file__).resolve().parents[3]
    folder = root / "scripts/catalogs"
    monkeypatch.syspath_prepend(str(folder))
    import _generators

    monkeypatch.setattr(_generators, "DATA_ROOT", tmp_path)
    spec = importlib.util.spec_from_file_location("nerc_currency_generator", folder / "gen_nerc_currency.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = module.main()
    original = root / "packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal/nerc-cip-v7.json"
    assert json.loads(output.read_text(encoding="utf-8")) == json.loads(original.read_text(encoding="utf-8"))
    assert len(list(tmp_path.rglob("*.json"))) == 1
