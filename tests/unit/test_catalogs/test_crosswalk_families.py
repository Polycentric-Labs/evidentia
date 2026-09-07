"""Crosswalk families and crosswalk resolution.

A baseline or maturity level is a view of a larger catalog; a crosswalk keyed
on the larger catalog (the family) must apply to every member, or a gap found
against the member receives no cross-framework value. ``resolve_crosswalk``
measures whether a crosswalk's ids exist in the catalogs it names.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia_core.catalogs.crosswalk import CrosswalkEngine, resolve_crosswalk
from evidentia_core.catalogs.registry import FrameworkRegistry
from evidentia_core.models.catalog import CrosswalkDefinition, FrameworkMapping


def _crosswalk(source: str, target: str, rows: list[tuple[str, str]]) -> CrosswalkDefinition:
    return CrosswalkDefinition(
        source_framework=source,
        target_framework=target,
        version="test",
        generated_at="2026-01-01",
        source="test",
        mappings=[FrameworkMapping(source_control_id=s, target_control_id=t, relationship="related") for s, t in rows],
    )


@pytest.fixture
def engine(tmp_path: Path) -> CrosswalkEngine:
    payload = _crosswalk("parent", "other", [("AC-2", "X-1"), ("AC-3", "X-2")]).model_dump()
    (tmp_path / "parent_to_other.json").write_text(json.dumps(payload), encoding="utf-8")
    member_only = _crosswalk("child-a", "third", [("AC-2", "T-9")]).model_dump()
    (tmp_path / "child-a_to_third.json").write_text(json.dumps(member_only), encoding="utf-8")
    eng = CrosswalkEngine(mappings_dir=tmp_path, families={"child-a": "parent", "child-b": "parent"})
    eng.load_all()
    return eng


class TestLookupKeys:
    def test_member_consults_itself_then_its_family(self, engine: CrosswalkEngine) -> None:
        assert engine.lookup_keys("child-a") == ("child-a", "parent")

    def test_family_and_unrelated_ids_stand_alone(self, engine: CrosswalkEngine) -> None:
        assert engine.lookup_keys("parent") == ("parent",)
        assert engine.lookup_keys("nobody") == ("nobody",)

    def test_a_family_pointing_at_itself_is_not_duplicated(self, tmp_path: Path) -> None:
        eng = CrosswalkEngine(mappings_dir=tmp_path, families={"x": "x"})
        assert eng.lookup_keys("x") == ("x",)

    def test_families_is_read_only(self, engine: CrosswalkEngine) -> None:
        with pytest.raises(TypeError):
            engine.families["new"] = "parent"  # type: ignore[index]


class TestFamilyLookups:
    def test_member_inherits_the_family_crosswalk(self, engine: CrosswalkEngine) -> None:
        mapped = engine.get_mapped_controls("child-a", "AC-2", "other")
        assert [m.target_control_id for m in mapped] == ["X-1"]

    def test_reverse_lookup_toward_a_member(self, engine: CrosswalkEngine) -> None:
        mapped = engine.get_mapped_controls("other", "X-2", "child-b")
        assert [m.target_control_id for m in mapped] == ["AC-3"]

    def test_cross_framework_value_includes_family_and_member_crosswalks(self, engine: CrosswalkEngine) -> None:
        value = engine.get_cross_framework_value("child-a", "AC-2")
        assert sorted(value) == ["other:X-1", "third:T-9"]

    def test_member_specific_crosswalk_does_not_leak_to_siblings(self, engine: CrosswalkEngine) -> None:
        assert engine.get_cross_framework_value("child-b", "AC-2") == ["other:X-1"]

    def test_family_itself_does_not_inherit_member_crosswalks(self, engine: CrosswalkEngine) -> None:
        assert engine.get_cross_framework_value("parent", "AC-2") == ["other:X-1"]

    def test_available_frameworks_lists_declared_ids_only(self, engine: CrosswalkEngine) -> None:
        assert engine.available_frameworks == {"parent", "other", "child-a", "third"}


class TestResolveCrosswalk:
    def test_counts_rows_and_lists_unresolved_ids(self) -> None:
        cw = _crosswalk("s", "t", [("AC-2", "X-1"), ("ac-2(1)", "X-9"), ("ZZ-1", "X-1")])
        res = resolve_crosswalk(cw, source_ids={"AC-2", "AC-2.1"}, target_ids={"X-1"}, file="s_to_t.json")
        assert res.rows == 3
        assert res.source_resolved == 2 and res.unresolved_source_ids == ("ZZ-1",)
        assert res.target_resolved == 2 and res.unresolved_target_ids == ("X-9",)
        assert res.source_ratio == pytest.approx(2 / 3)
        assert res.file == "s_to_t.json"

    def test_unknown_side_has_no_ratio(self) -> None:
        cw = _crosswalk("s", "external", [("AC-2", "1.2d")])
        res = resolve_crosswalk(cw, source_ids={"AC-2"}, target_ids=None)
        assert res.target_ids_known is False
        assert res.target_ratio is None
        assert res.source_ratio == 1.0

    def test_empty_crosswalk_resolves_fully(self) -> None:
        res = resolve_crosswalk(_crosswalk("s", "t", []), source_ids=set(), target_ids=set())
        assert res.source_ratio == 1.0 and res.target_ratio == 1.0


class TestBundledFamilies:
    @pytest.fixture(autouse=True)
    def _reset(self):  # type: ignore[no-untyped-def]
        FrameworkRegistry.reset_instance()
        yield
        FrameworkRegistry.reset_instance()

    def test_manifest_families_reach_the_engine(self) -> None:
        registry = FrameworkRegistry()
        families = registry.crosswalk.families
        assert families["fedramp-rev5-moderate"] == "nist-800-53-rev5"
        assert families["nist-800-53-mod"] == "nist-800-53-rev5"
        assert families["osps-baseline-m1"] == "osps-baseline"
        assert set(registry.family_members("nist-800-53-rev5")) >= {
            "nist-800-53-rev5-low",
            "nist-800-53-rev5-moderate",
            "nist-800-53-rev5-high",
            "nist-800-53-rev5-privacy",
            "fedramp-rev5-low",
            "fedramp-rev5-moderate",
            "fedramp-rev5-high",
            "fedramp-rev5-li-saas",
        }

    def test_a_baseline_gap_receives_cross_framework_value(self) -> None:
        """The README quickstart path: every moderate-baseline gap had zero value through v0.12."""
        value = FrameworkRegistry().crosswalk.get_cross_framework_value("fedramp-rev5-moderate", "AC-2")
        assert "soc2-tsc:CC6.1" in value
        assert any(v.startswith("fedramp-ksi-2026:") for v in value)

    def test_the_legacy_sample_resolves_through_the_family(self) -> None:
        mapped = FrameworkRegistry().crosswalk.get_mapped_controls("nist-csf-2.0", "GV.OC-01", "nist-800-53-mod")
        assert "AC-1" in {m.target_control_id for m in mapped}

    def test_control_ids_for_bundled_family_and_unknown(self) -> None:
        registry = FrameworkRegistry()
        assert "AC-2.1" in (registry.control_ids_for("nist-800-53-rev5") or set())
        family_ids = registry.control_ids_for("osps-baseline")
        assert family_ids is not None and "OSPS-AC-01.01" in family_ids
        assert registry.control_ids_for("eu-cra") is None
        obligations = registry.control_ids_for("us-va-vcdpa")
        assert obligations is not None and "VCDPA.ACCESS" in obligations

    def test_re_keyed_legacy_crosswalks_resolve_completely(self) -> None:
        registry = FrameworkRegistry()
        engine = registry.crosswalk
        full = registry.control_ids_for("nist-800-53-rev5")
        for name in (
            "iso-27001-2022_to_nist-800-53-rev5.json",
            "nist-800-53-rev5_to_hipaa-security.json",
            "nist-800-53-rev5_to_soc2-tsc.json",
            "nist-csf-2.0_to_nist-800-53-rev5.json",
        ):
            path = Path(engine._dir) / name
            cw = CrosswalkDefinition.model_validate(json.loads(path.read_text(encoding="utf-8")))
            side = "source" if cw.source_framework == "nist-800-53-rev5" else "target"
            res = resolve_crosswalk(
                cw,
                source_ids=full if side == "source" else registry.control_ids_for(cw.source_framework),
                target_ids=full if side == "target" else registry.control_ids_for(cw.target_framework),
                file=name,
            )
            assert res.source_ratio == 1.0, (name, res.unresolved_source_ids)
            assert res.target_ratio == 1.0, (name, res.unresolved_target_ids)
