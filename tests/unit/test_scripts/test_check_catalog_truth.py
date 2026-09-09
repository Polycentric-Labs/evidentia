"""Unit tests for ``scripts/check_catalog_truth.py`` (v0.13 catalog truth gate).

The catalog and crosswalk claims the docs and the manifest make (text
depth per catalog, crosswalk families, crosswalk framework ids, crosswalk
id resolution, the Tier C stub invariant, and the inventory summary table)
had no mechanical check before this gate. These tests pin the gate's own
parsing, rendering, and comparison rules against synthetic inputs, so they
neither depend on nor freeze the real repo's current catalog content.

The end-to-end assertion lives in ``TestEndToEnd`` at the bottom and
requires the real repository to pass every check.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from evidentia_core.catalogs.crosswalk import CrosswalkResolution
from evidentia_core.catalogs.loader import load_any_catalog
from evidentia_core.catalogs.manifest import FrameworkManifestEntry, load_manifest
from evidentia_core.models.catalog import CatalogControl, ControlCatalog, CrosswalkDefinition
from pydantic import ValidationError

REPO_ROOT = Path(__file__).resolve().parents[3]
CHECK_PATH = REPO_ROOT / "scripts" / "check_catalog_truth.py"


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Registering the module before exec is required here (unlike the
    # simpler pattern in test_check_public_surface.py): the module under
    # test declares a module-level ``@dataclass`` under
    # ``from __future__ import annotations``, and CPython's dataclass
    # machinery resolves string field annotations via
    # ``sys.modules[cls.__module__]`` at class-creation time. Skipping this
    # line makes that lookup return ``None`` and crash with an
    # AttributeError before a single test runs.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def check() -> Any:
    return _load_module("check_catalog_truth_under_test", CHECK_PATH)


def _entry(
    id: str,  # mirrors the manifest field name for readability
    *,
    tier: str = "A",
    text_depth: str | None = "full",
    crosswalk_family: str | None = None,
    placeholder: bool = False,
    license_required: bool = False,
) -> FrameworkManifestEntry:
    """A minimal, valid manifest entry for the fields these checks read."""
    return FrameworkManifestEntry(
        id=id,
        name=id,
        version="1.0",
        tier=tier,
        path=f"{id}.json",
        text_depth=text_depth,
        crosswalk_family=crosswalk_family,
        placeholder=placeholder,
        license_required=license_required,
    )


def _crosswalk(source: str, target: str) -> CrosswalkDefinition:
    """A minimal, valid crosswalk with no rows (rows are irrelevant to check 3)."""
    return CrosswalkDefinition(
        source_framework=source,
        target_framework=target,
        version="1.0",
        generated_at="2026-01-01",
        source="test fixture",
        mappings=[],
    )


def _resolution(
    *,
    file: str = "a_to_b.json",
    source_framework: str = "a",
    target_framework: str = "b",
    rows: int = 4,
    source_ids_known: bool = True,
    target_ids_known: bool = True,
    source_resolved: int = 4,
    target_resolved: int = 4,
    unresolved_source_ids: tuple[str, ...] = (),
    unresolved_target_ids: tuple[str, ...] = (),
) -> CrosswalkResolution:
    return CrosswalkResolution(
        file=file,
        source_framework=source_framework,
        target_framework=target_framework,
        rows=rows,
        source_ids_known=source_ids_known,
        target_ids_known=target_ids_known,
        source_resolved=source_resolved,
        target_resolved=target_resolved,
        unresolved_source_ids=unresolved_source_ids,
        unresolved_target_ids=unresolved_target_ids,
    )


def _shadow_user_catalogs(user_dir: Path, monkeypatch: pytest.MonkeyPatch, framework_ids: tuple[str, ...]) -> None:
    """Create real user imports with different text and ids from the bundle."""
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(user_dir))
    entries = []
    for framework_id in framework_ids:
        bundled_entry = load_manifest().get(framework_id)
        assert bundled_entry is not None
        entry = bundled_entry.model_copy(
            update={
                "path": f"{framework_id}.json",
                "text_depth": "full",
                "placeholder": False,
                "license_required": False,
            }
        )
        entries.append(entry.model_dump(mode="json"))
        catalog = ControlCatalog(
            framework_id=framework_id,
            framework_name=entry.name,
            version=entry.version,
            source="User import fixture",
            controls=[
                CatalogControl(
                    id="USER-ONLY",
                    title="User control",
                    description="User-supplied text that differs from the bundled catalog.",
                )
            ],
        )
        (user_dir / entry.path).write_text(catalog.model_dump_json(), encoding="utf-8", newline="\n")
    (user_dir / "frameworks.yaml").write_text(
        json.dumps({"version": 1, "frameworks": entries}), encoding="utf-8", newline="\n"
    )


class TestBundledCatalogIsolation:
    def test_user_import_cannot_change_bundled_depth(
        self, check: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _shadow_user_catalogs(tmp_path, monkeypatch, ("soc2-tsc",))
        assert load_any_catalog("soc2-tsc").text_depth == "full"

        inputs = check.gather_inputs()

        assert inputs.derived_depths["soc2-tsc"] == "headings"

    def test_user_import_cannot_change_bundled_crosswalk_resolution(
        self, check: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _shadow_user_catalogs(tmp_path, monkeypatch, ("soc2-tsc",))

        inputs = check.gather_inputs()
        resolution = next(res for res in inputs.resolutions if res.file == "nist-800-53-rev5_to_soc2-tsc.json")

        assert resolution.target_ratio == 1.0

    def test_user_imports_cannot_change_family_crosswalk_resolution(
        self, check: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _shadow_user_catalogs(tmp_path, monkeypatch, ("osps-baseline-m1", "osps-baseline-m2", "osps-baseline-m3"))

        inputs = check.gather_inputs()
        resolutions = [res for res in inputs.resolutions if res.source_framework == "osps-baseline"]

        assert resolutions
        assert all(res.source_ratio == 1.0 for res in resolutions)


# ── check 1: manifest depth ─────────────────────────────────────────


class TestManifestDepth:
    def test_depth_mismatch_fails(self, check: Any) -> None:
        entries = [_entry("a", text_depth="full")]
        failures = check.compare_manifest_depth(entries, {"a": "headings"})
        assert len(failures) == 1
        assert "'full'" in failures[0]
        assert "'headings'" in failures[0]

    def test_none_depth_fails(self, check: Any) -> None:
        """An entry that predates the derivation (text_depth None) is a mismatch."""
        entries = [_entry("a", text_depth=None)]
        failures = check.compare_manifest_depth(entries, {"a": "full"})
        assert len(failures) == 1
        assert "None" in failures[0]
        assert "'full'" in failures[0]

    def test_matching_depth_passes(self, check: Any) -> None:
        entries = [_entry("a", text_depth="partial")]
        assert check.compare_manifest_depth(entries, {"a": "partial"}) == []


# ── check 2: crosswalk families ─────────────────────────────────────


class TestFamilies:
    def test_family_with_one_member_fails(self, check: Any) -> None:
        entries = [_entry("m1", crosswalk_family="fam"), _entry("other")]
        failures = check.compare_families(entries)
        assert any("fam" in f and "1 member" in f for f in failures)

    def test_member_that_is_also_a_family_fails(self, check: Any) -> None:
        entries = [
            _entry("parent", crosswalk_family="grandparent"),
            _entry("child1", crosswalk_family="parent"),
            _entry("child2", crosswalk_family="parent"),
        ]
        failures = check.compare_families(entries)
        assert any("'parent'" in f and "nested" in f for f in failures)

    def test_family_that_is_a_bundled_catalog_id_passes_with_one_member(self, check: Any) -> None:
        entries = [_entry("full-catalog"), _entry("baseline", crosswalk_family="full-catalog")]
        assert check.compare_families(entries) == []

    def test_family_with_two_members_and_no_bundled_id_passes(self, check: Any) -> None:
        entries = [_entry("m1", crosswalk_family="fam"), _entry("m2", crosswalk_family="fam")]
        assert check.compare_families(entries) == []


# ── check 3: crosswalk framework ids ────────────────────────────────


class TestCrosswalkFrameworkIds:
    def test_unknown_source_framework_fails(self, check: Any) -> None:
        crosswalks = [("a_to_b.json", _crosswalk("not-real", "b"))]
        failures = check.compare_crosswalk_framework_ids(
            crosswalks, bundled_ids=frozenset({"b"}), family_ids=frozenset()
        )
        assert len(failures) == 1
        assert "not-real" in failures[0]

    def test_external_target_is_not_a_failure(self, check: Any) -> None:
        crosswalks = [("a_to_eucra.json", _crosswalk("a", "eu-cra"))]
        failures = check.compare_crosswalk_framework_ids(
            crosswalks,
            bundled_ids=frozenset({"a"}),
            family_ids=frozenset(),
            external_targets=frozenset({"eu-cra"}),
        )
        assert failures == []

    def test_unknown_non_external_target_fails(self, check: Any) -> None:
        crosswalks = [("a_to_nowhere.json", _crosswalk("a", "nowhere"))]
        failures = check.compare_crosswalk_framework_ids(
            crosswalks,
            bundled_ids=frozenset({"a"}),
            family_ids=frozenset(),
            external_targets=frozenset({"eu-cra"}),
        )
        assert len(failures) == 1
        assert "nowhere" in failures[0]

    def test_a_family_id_on_either_side_passes(self, check: Any) -> None:
        crosswalks = [("fam_to_b.json", _crosswalk("fam", "b"))]
        failures = check.compare_crosswalk_framework_ids(
            crosswalks, bundled_ids=frozenset({"b"}), family_ids=frozenset({"fam"})
        )
        assert failures == []


# ── check 4: crosswalk resolution ───────────────────────────────────


class TestResolution:
    def test_source_below_100_percent_fails_with_unresolved_ids_listed(self, check: Any) -> None:
        res = _resolution(source_resolved=2, unresolved_source_ids=("A-1", "A-2"))
        failures = check.compare_resolutions([res])
        assert len(failures) == 1
        assert "A-1" in failures[0]
        assert "A-2" in failures[0]

    def test_target_below_100_percent_fails_on_a_bundled_target(self, check: Any) -> None:
        res = _resolution(target_resolved=1, unresolved_target_ids=("B-1", "B-2", "B-3"))
        failures = check.compare_resolutions([res])
        assert len(failures) == 1
        assert "B-1" in failures[0]

    def test_external_target_with_low_resolution_is_reported_not_failed(self, check: Any) -> None:
        res = _resolution(
            file="a_to_eu-cra.json",
            target_framework="eu-cra",
            target_ids_known=False,
            target_resolved=0,
        )
        assert check.compare_resolutions([res], external_targets=frozenset({"eu-cra"})) == []

    def test_formerly_external_target_is_checked_once_bundled(self, check: Any) -> None:
        res = _resolution(target_framework="eu-cra", target_resolved=0, unresolved_target_ids=("BAD-ID",))

        failures = check.compare_resolutions([res])

        assert len(failures) == 1
        assert "BAD-ID" in failures[0]

    def test_unknown_source_is_left_to_the_framework_id_check(self, check: Any) -> None:
        """No bundled catalog for the source means nothing to resolve against here;
        compare_crosswalk_framework_ids is the check that reports the bad id."""
        res = _resolution(source_ids_known=False, source_resolved=0)
        assert check.compare_resolutions([res]) == []

    def test_full_resolution_on_both_sides_passes(self, check: Any) -> None:
        res = _resolution()
        assert check.compare_resolutions([res]) == []

    def test_unresolved_ids_are_capped_at_20_with_a_count(self, check: Any) -> None:
        unresolved = tuple(f"X-{i}" for i in range(25))
        res = _resolution(rows=25, source_resolved=0, target_resolved=25, unresolved_source_ids=unresolved)
        failures = check.compare_resolutions([res])
        assert len(failures) == 1
        message = failures[0]
        assert "25 unresolved" in message
        assert "X-19" in message
        assert "X-20" not in message
        assert "and 5 more" in message


# ── check 5: Tier C invariant ────────────────────────────────────────


class TestTierCInvariant:
    def test_missing_placeholder_fails(self, check: Any) -> None:
        entries = [_entry("a", tier="C", placeholder=False, license_required=True, text_depth="headings")]
        failures = check.compare_tier_c_invariant(entries)
        assert len(failures) == 1
        assert "placeholder is False" in failures[0]

    def test_missing_license_required_fails(self, check: Any) -> None:
        entries = [_entry("a", tier="C", placeholder=True, license_required=False, text_depth="headings")]
        failures = check.compare_tier_c_invariant(entries)
        assert "license_required is False" in failures[0]

    def test_wrong_text_depth_fails(self, check: Any) -> None:
        entries = [_entry("a", tier="C", placeholder=True, license_required=True, text_depth="full")]
        failures = check.compare_tier_c_invariant(entries)
        assert "text_depth" in failures[0]

    def test_conformant_tier_c_entry_passes(self, check: Any) -> None:
        entries = [_entry("a", tier="C", placeholder=True, license_required=True, text_depth="headings")]
        assert check.compare_tier_c_invariant(entries) == []

    def test_non_tier_c_entries_are_ignored(self, check: Any) -> None:
        entries = [_entry("a", tier="A", placeholder=False, license_required=False, text_depth="full")]
        assert check.compare_tier_c_invariant(entries) == []


# ── check 6: the inventory summary block ────────────────────────────

GOLDEN_BLOCK = (
    "The current distribution across all 8 catalogs, derived from the manifest and the\n"
    "catalog files themselves (the text depth is computed, never declared):\n"
    "\n"
    "| Tier | Catalogs | Full text | Partial text | Headings only |\n"
    "|---|---|---|---|---|\n"
    "| A | 3 | 2 | 1 | 0 |\n"
    "| B | 1 | 0 | 0 | 1 |\n"
    "| C | 3 | 0 | 0 | 3 |\n"
    "| D | 1 | 1 | 0 | 0 |"
)

GOLDEN_COUNTS = {
    "A": {"full": 2, "partial": 1, "headings": 0},
    "B": {"full": 0, "partial": 0, "headings": 1},
    "C": {"full": 0, "partial": 0, "headings": 3},
    "D": {"full": 1, "partial": 0, "headings": 0},
}


class TestRenderInventoryBlock:
    def test_matches_the_golden_shape_for_synthetic_counts(self, check: Any) -> None:
        assert check.render_inventory_block(GOLDEN_COUNTS, 8) == GOLDEN_BLOCK

    def test_wrap_adds_the_begin_and_end_markers(self, check: Any) -> None:
        wrapped = check.wrap_marked_block(GOLDEN_BLOCK)
        assert wrapped.startswith(check.BEGIN_MARKER + "\n")
        assert wrapped.endswith("\n" + check.END_MARKER)
        assert GOLDEN_BLOCK in wrapped


class TestCompareInventoryBlock:
    def test_reports_a_missing_marker_block(self, check: Any) -> None:
        failures = check.compare_inventory_block("no markers on this page", GOLDEN_BLOCK)
        assert len(failures) == 1
        assert "--write-inventory" in failures[0]

    def test_reports_a_stale_block(self, check: Any) -> None:
        page = "before\n\n" + check.wrap_marked_block("stale content") + "\n\nafter\n"
        failures = check.compare_inventory_block(page, GOLDEN_BLOCK)
        assert len(failures) == 1
        assert "does not match" in failures[0]

    def test_passes_when_the_block_is_current(self, check: Any) -> None:
        page = "before\n\n" + check.wrap_marked_block(GOLDEN_BLOCK) + "\n\nafter\n"
        assert check.compare_inventory_block(page, GOLDEN_BLOCK) == []

    def test_tolerates_crlf_in_the_page(self, check: Any) -> None:
        lf_page = "before\n\n" + check.wrap_marked_block(GOLDEN_BLOCK) + "\n\nafter\n"
        crlf_page = lf_page.replace("\n", "\r\n")
        assert check.compare_inventory_block(crlf_page, GOLDEN_BLOCK) == []


class TestMarkerHelpers:
    def test_find_marked_block_returns_none_when_absent(self, check: Any) -> None:
        assert check.find_marked_block("nothing here") is None

    def test_find_marked_block_raises_on_an_unterminated_marker(self, check: Any) -> None:
        with pytest.raises(check.CatalogTruthError):
            check.find_marked_block(check.BEGIN_MARKER + "\nno end marker follows")

    def test_find_legacy_block_returns_none_when_absent(self, check: Any) -> None:
        assert check.find_legacy_block("nothing here") is None

    def test_find_legacy_block_raises_without_a_tier_d_row(self, check: Any) -> None:
        with pytest.raises(check.CatalogTruthError):
            check.find_legacy_block("The current distribution across all 3 catalogs:\nno table here")


class TestWriteInventoryPage:
    def test_bootstraps_the_legacy_block_and_preserves_crlf(self, check: Any, tmp_path: Path) -> None:
        legacy = (
            "# Catalog inventory\n\n"
            "Some intro.\n\n"
            "The current distribution across all 96 catalogs:\n\n"
            "| Tier | Count |\n|---|---|\n| A | 1 |\n| D | 1 |\n\n"
            "**Trailing prose.**\n"
        ).replace("\n", "\r\n")
        page = tmp_path / "catalog-inventory.md"
        page.write_bytes(legacy.encode("utf-8"))

        check.write_inventory_page(page, GOLDEN_BLOCK)

        raw = page.read_bytes()
        assert raw.count(b"\n") == raw.count(b"\r\n"), "every newline should still be part of a CRLF pair"
        text = raw.decode("utf-8")
        assert check.BEGIN_MARKER in text
        assert check.END_MARKER in text
        assert "Trailing prose" in text
        assert "96 catalogs" not in text

    def test_updates_an_existing_marker_block_in_place(self, check: Any, tmp_path: Path) -> None:
        page_text = "before\n\n" + check.wrap_marked_block("stale content") + "\n\nafter\n"
        page = tmp_path / "catalog-inventory.md"
        page.write_text(page_text, encoding="utf-8", newline="\n")

        check.write_inventory_page(page, GOLDEN_BLOCK)

        updated = page.read_text(encoding="utf-8")
        assert "stale content" not in updated
        assert GOLDEN_BLOCK in updated
        assert "before" in updated
        assert "after" in updated

    def test_neither_marker_nor_legacy_pattern_raises(self, check: Any, tmp_path: Path) -> None:
        page = tmp_path / "catalog-inventory.md"
        page.write_text("nothing this gate recognizes\n", encoding="utf-8", newline="\n")
        with pytest.raises(check.CatalogTruthError):
            check.write_inventory_page(page, GOLDEN_BLOCK)


# ── crosswalk file loading ───────────────────────────────────────────


class TestLoadCrosswalkFiles:
    def test_loads_every_json_file_in_name_order(self, check: Any, tmp_path: Path) -> None:
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        for name, source, target in (("b_to_c.json", "b", "c"), ("a_to_b.json", "a", "b")):
            (mappings_dir / name).write_text(
                json.dumps(
                    {
                        "source_framework": source,
                        "target_framework": target,
                        "version": "1.0",
                        "generated_at": "2026-01-01",
                        "source": "test fixture",
                        "mappings": [],
                    }
                ),
                encoding="utf-8",
            )
        loaded = check.load_crosswalk_files(mappings_dir)
        assert [name for name, _ in loaded] == ["a_to_b.json", "b_to_c.json"]
        assert loaded[0][1].source_framework == "a"

    def test_missing_directory_raises(self, check: Any, tmp_path: Path) -> None:
        with pytest.raises(check.CatalogTruthError):
            check.load_crosswalk_files(tmp_path / "does-not-exist")

    def test_a_malformed_crosswalk_file_raises_loudly(self, check: Any, tmp_path: Path) -> None:
        """A schema break must surface as a crash, not a swallowed failure line."""
        mappings_dir = tmp_path / "mappings"
        mappings_dir.mkdir()
        (mappings_dir / "broken.json").write_text(json.dumps({"source_framework": "a"}), encoding="utf-8")
        with pytest.raises(ValidationError):
            check.load_crosswalk_files(mappings_dir)


# ── end-to-end ─────────────────────────────────────────────────────


class TestEndToEnd:
    def test_report_prints_a_line_for_every_manifest_entry(
        self, check: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        check.main(["--report"])
        captured = capsys.readouterr().out
        for entry in load_manifest().frameworks:
            assert entry.id in captured

    def test_gate_passes_on_the_real_repo(self, check: Any) -> None:
        assert check.main([]) == 0
