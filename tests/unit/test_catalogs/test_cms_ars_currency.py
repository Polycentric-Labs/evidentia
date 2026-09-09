"""CMS workbook cells and grouping stay independent of assessment scope."""

from __future__ import annotations

import copy
import hashlib
import json
import runpy
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from evidentia_core.catalogs.loader import load_evidentia_catalog
from evidentia_core.gap_analyzer import GapAnalyzer
from evidentia_core.models.catalog import ControlCatalog

ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "scripts/catalogs/gen_cms_ars.py"
SOURCE = SCRIPT.parent / "sources/cms-ars-5.2-source.json"
DATA = ROOT / "packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal"
OUTPUT = DATA / "cms-ars-5.2.json"
SOURCE_SHA = "6d7881b1c186aa1df10b3e91dd7c7287b030f7aa8e61390ca83d08117987a444"
SOURCE_TEXT_SHA = "8e7b4638193a7fe42e232fe5981d398ccf9f744ac75b07dbd0a967b8035ddf76"
SOURCE_CONTENT_SHA = "3de2ba8b263cd5a1d00fa6c4f16368275afdc000937ed12bb774d86fb770aa8c"
RAW_ROWS_SHA = "68cd13dfc045fa55c1108529fff73d7a255309f11cc90725fb886b6b8f9ec7a5"
CELL_METADATA_SHA = "51f49c4acdf2bc4660aa006ef29e7e26d38c59f2b019cdc9368888dba61c09b0"
GROUPING_SHA = "fc23c6a92eb81a6f42762645eea22d1a22f6f5b533aa6c3d75a7053977737d71"
ANNOTATIONS_SHA = "95e0ed0d8ffac8b7eb2441a354202cdbe6ea85f363688a83669d6460e28abc27"
LEGACY_CONTROLS_SHA = "dcd4160bba7c4bfece53711b01f41b409fa28c9171f67194508d05aca72de34c"
HEADERS = [
    "Control Family",
    "Control Number",
    "Control Name",
    "Control Statement",
    "Control Review Frequency",
    "Assessment Frequency",
    "CMS Baseline",
    "MAC ARS",
    "HVA Overlay",
    "FTI Overlay",
    "CMS Discussion\n",
    "Priority",
    "Related Controls",
    "Reference Policy",
]
REPAIRS = {823: ("MA04(04)a", "MA-04(04)a"), 824: ("MA04(04)b", "MA-04(04)b"), 1654: ("SR04(04)", "SR-04(04)")}


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _digest(value: object) -> str:
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def _lf(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


@pytest.fixture(scope="module")
def generator() -> dict[str, Any]:
    return runpy.run_path(str(SCRIPT), run_name="cms_generator_test")


@pytest.fixture
def source() -> dict[str, Any]:
    return _read(SOURCE)


@pytest.fixture(scope="module")
def catalog(generator: dict[str, Any]) -> dict[str, Any]:
    value = generator["build_catalog"](_read(SOURCE))
    assert isinstance(value, dict)
    return value


def _all_rows(catalog: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(
        (row for control in catalog["controls"] for row in control["source_rows"]), key=lambda row: row["row"]
    )


def test_projection_matches_independent_workbook_cell_and_metadata_fingerprints(source: dict[str, Any]) -> None:
    assert hashlib.sha256(_lf(SOURCE)).hexdigest() == SOURCE_TEXT_SHA
    assert _digest(source) == SOURCE_CONTENT_SHA
    assert source["source"]["sha256"] == SOURCE_SHA
    assert source["source"]["bytes"] == 432804
    assert source["headers"] == HEADERS
    assert len(source["rows"]) == 1681
    assert [row["row"] for row in source["rows"]] == list(range(2, 1683))
    assert _digest([[row["row"], row["values"]] for row in source["rows"]]) == RAW_ROWS_SHA
    assert (
        _digest([[row["row"], row["data_types"], row["number_formats"], row["style_ids"]] for row in source["rows"]])
        == CELL_METADATA_SHA
    )
    assert _digest(source["cell_annotations"]) == ANNOTATIONS_SHA
    assert len(source["cell_annotations"]) == 7
    assert Counter(type(value).__name__ for row in source["rows"] for value in row["values"]) == {
        "str": 17122,
        "NoneType": 6412,
    }
    assert Counter(fmt for row in source["rows"] for fmt in row["number_formats"]) == {"General": 23133, "@": 401}


def test_all_raw_rows_and_cell_types_survive_without_assessment_inflation(
    catalog: dict[str, Any], source: dict[str, Any]
) -> None:
    controls = catalog["controls"]
    assert len(controls) == 605
    rows = _all_rows(catalog)
    assert len(rows) == len({row["row"] for row in rows}) == 1681
    assert Counter(row["kind"] for row in rows) == {"aggregate": 605, "clause": 1076}
    assert _digest([[row["row"], [row["values"][header] for header in HEADERS]] for row in rows]) == RAW_ROWS_SHA
    for actual, expected in zip(rows, source["rows"], strict=True):
        assert actual["source_sha256"] == SOURCE_SHA
        assert actual["sheet"] == "ARS 5.2"
        assert actual["source_id"] == expected["values"][1]
        assert actual["source_id_format"] == expected["number_formats"][1]
        assert actual["resolved_values"] == {}
        assert list(actual["values"]) == HEADERS
        for value, expected_value in zip(actual["values"].values(), expected["values"], strict=True):
            assert value == expected_value and type(value) is type(expected_value)
    by_number = {row["row"]: row for row in rows}
    expected_annotations = {
        f"{annotation['cell']}.{kind}.{key}": value
        for annotation in source["cell_annotations"]
        for kind in ("hyperlink", "comment")
        for key, value in (annotation[kind] or {}).items()
        if value is not None
    }
    actual_annotations = {
        key: value
        for row in rows
        for key, value in row["provenance"].items()
        if ".hyperlink." in key or ".comment." in key
    }
    assert actual_annotations == expected_annotations
    for annotation in source["cell_annotations"]:
        owner = by_number[int(annotation["cell"][1:])]
        for kind in ("hyperlink", "comment"):
            for key, value in (annotation[kind] or {}).items():
                if value is not None:
                    assert owner["provenance"][f"{annotation['cell']}.{kind}.{key}"] == value
    grouping = [
        [
            control["id"],
            control["source_rows"][0]["row"],
            control["properties"]["source_record_kind"],
            control["properties"].get("source_parent_id"),
            [row["row"] for row in control["source_rows"][1:]],
        ]
        for control in controls
    ]
    assert _digest(grouping) == GROUPING_SHA
    assert Counter(control["properties"]["source_record_kind"] for control in controls) == {
        "base": 243,
        "enhancement": 362,
    }
    assert len(catalog["families"]) == 20
    assert catalog["families"] == list(dict.fromkeys(control["family"] for control in controls))


def test_aggregate_projections_use_only_their_own_publisher_cells(catalog: dict[str, Any]) -> None:
    for control in catalog["controls"]:
        source_row = control["source_rows"][0]
        cells = source_row["values"]
        assert source_row["kind"] == "aggregate"
        assert control["title"] == cells["Control Name"]
        assert control["description"] == cells["Control Statement"]
        assert control["guidance"] == cells["CMS Discussion\n"]
        assert control["priority"] == cells["Priority"]
        assert control["family"] == cells["Control Family"]
        assert control.get("baseline_impact", []) == []
        assert control.get("related_controls", []) == []
        assert control.get("assessment_objectives", []) == []
        assert control.get("enhancements", []) == []
        for clause in control["source_rows"][1:]:
            assert clause["kind"] == "clause"
            assert clause["provenance"]["aggregate_id"] == control["id"]


def test_only_three_reviewed_identifier_interpretations_are_applied(catalog: dict[str, Any]) -> None:
    changed = {
        row["row"]: (row["source_id"], row["interpreted_id"])
        for row in _all_rows(catalog)
        if row["interpreted_id"] is not None
    }
    assert changed == REPAIRS
    controls = {control["id"]: control for control in catalog["controls"]}
    assert controls["SR-04(04)"]["source_rows"][0]["source_id"] == "SR04(04)"
    assert [row["source_id"] for row in controls["MA-04(04)"]["source_rows"]] == ["MA-04(04)", "MA04(04)a", "MA04(04)b"]
    orphans = {
        control["id"]
        for control in catalog["controls"]
        if control["properties"].get("source_parent_present") == "false"
    }
    assert orphans == {"AU-13(03)", "SC-37(01)"}
    assert "AU-13" not in controls and "SC-37" not in controls
    assert "AC-02(01)" in controls and "AC-2(1)" not in controls


def test_clause_specific_values_blank_cells_and_priority_anomalies_survive(catalog: dict[str, Any]) -> None:
    rows = _all_rows(catalog)
    by_id = {row["source_id"]: row for row in rows}
    assert {row["source_id"] for row in rows if row["values"]["CMS Baseline"] is None} == {
        "CM-11(03)a",
        "CP-02i",
        "CP-03b",
        "SR-06b",
        "SR-06c",
    }
    assert by_id["CP-02i"]["values"]["HVA Overlay"]
    assert by_id["CM-02(06)a"]["values"]["CMS Baseline"] != by_id["CM-02(06)"]["values"]["CMS Baseline"]
    assert by_id["PE-13a"]["values"]["CMS Baseline"] != by_id["PE-13"]["values"]["CMS Baseline"]
    assert sum(value == "\u00a0" for row in rows for value in row["values"].values()) == 11
    assert sum(row["values"]["CMS Baseline"] == "HIgh\n" for row in rows) == 2
    priority = Counter(row["values"]["Priority"] for row in rows)
    assert priority["1 year"] == 8 and priority["6 months"] == 2 and priority["Current"] == 13
    assert priority["P3\n6 months "] == priority["Current \n1 year"] == priority["\n6 months"] == 1
    differences: Counter[str] = Counter()
    non_substrings = 0
    for control in catalog["controls"]:
        aggregate = control["source_rows"][0]["values"]
        for clause in control["source_rows"][1:]:
            for key in ("CMS Baseline", "MAC ARS", "HVA Overlay", "FTI Overlay"):
                differences[key] += clause["values"][key] != aggregate[key]
            non_substrings += clause["values"]["Control Statement"] not in aggregate["Control Statement"]
    assert differences == {"CMS Baseline": 7, "MAC ARS": 5, "HVA Overlay": 194, "FTI Overlay": 630}
    assert non_substrings == 161


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_native_load_keeps_all_source_rows_and_605_reference_units(
    catalog: dict[str, Any], tmp_path: Path, fmt: str
) -> None:
    content = (
        json.dumps(catalog, ensure_ascii=True)
        if fmt == "json"
        else yaml.safe_dump(catalog, allow_unicode=False, sort_keys=False)
    )
    path = tmp_path / f"cms.{fmt}"
    path.write_text(content, encoding="utf-8", newline="\n")
    loaded = load_evidentia_catalog(path)
    assert loaded.control_count == len(loaded.controls) == len(loaded.statement_rows()) == 605
    assert loaded.text_depth == "full"
    assert loaded.status == "current" and loaded.verified_on == date(2026, 9, 9)
    assert not loaded.placeholder and not loaded.license_required
    for row in _all_rows(catalog):
        if row["kind"] == "clause":
            assert loaded.get_control(row["source_id"]) is None
    assert loaded.get_control("AC-02.01") is not None
    assert loaded.get_control("AC-2(1)") is None
    required = GapAnalyzer()._build_required_set({"cms-ars-5.2": loaded})
    without_rows = ControlCatalog.model_validate(
        {
            **catalog,
            "controls": [
                {key: value for key, value in control.items() if key != "source_rows"}
                for control in catalog["controls"]
            ],
        }
    )
    assert list(required) == list(GapAnalyzer()._build_required_set({"cms-ars-5.2": without_rows}))
    assert len(required) == 605
    actual = loaded.model_dump(mode="json")
    assert [control["source_rows"] for control in actual["controls"]] == [
        control["source_rows"] for control in catalog["controls"]
    ]


def test_bundled_catalog_matches_pure_generation(catalog: dict[str, Any]) -> None:
    assert _read(OUTPUT) == catalog
    assert _lf(OUTPUT).isascii()


@pytest.mark.parametrize(
    "mutation, message",
    [
        ("schema", "schema version"),
        ("hash", "source identity"),
        ("edition", "source identity"),
        ("sheet", "source identity"),
        ("header", "headers"),
        ("duplicate-header", "headers"),
        ("missing-row", "1681"),
        ("row-bool", "row sequence"),
        ("row-order", "row sequence"),
        ("missing-cell", "14 cells"),
        ("formula", "cell data types"),
        ("invalid-scalar", "cell values"),
        ("duplicate-id", "duplicate"),
        ("malformed-id", "Unsupported source ID"),
        ("missing-parent", "Missing aggregate"),
        ("repair-literal", "repair precondition"),
        ("repair-row", "repair precondition"),
        ("statement", "projection checksum"),
        ("cell-format", "projection checksum"),
        ("annotation", "projection checksum"),
    ],
)
def test_unreviewed_source_changes_fail_closed(
    generator: dict[str, Any], source: dict[str, Any], mutation: str, message: str
) -> None:
    if mutation == "schema":
        source["schema_version"] = "future"
    elif mutation == "hash":
        source["source"]["sha256"] = "0" * 64
    elif mutation == "edition":
        source["source"]["edition"] = "5.3"
    elif mutation == "sheet":
        source["source"]["sheet"] = "Other"
    elif mutation == "header":
        source["headers"][10] = "CMS Discussion"
    elif mutation == "duplicate-header":
        source["headers"][1] = source["headers"][0]
    elif mutation == "missing-row":
        source["rows"].pop()
    elif mutation == "row-bool":
        source["rows"][0]["row"] = True
    elif mutation == "row-order":
        source["rows"][0], source["rows"][1] = source["rows"][1], source["rows"][0]
    elif mutation == "missing-cell":
        source["rows"][0]["values"].pop()
    elif mutation == "formula":
        source["rows"][0]["data_types"][0] = "f"
    elif mutation == "invalid-scalar":
        source["rows"][0]["values"][0] = {"nested": "value"}
    elif mutation == "duplicate-id":
        source["rows"][3]["values"][1] = source["rows"][0]["values"][1]
    elif mutation == "malformed-id":
        source["rows"][3]["values"][1] = "not-a-control"
    elif mutation == "missing-parent":
        source["rows"][1]["values"][1] = "ZZ-99a"
    elif mutation == "repair-literal":
        source["rows"][821]["values"][1] = "MA-04(04)a"
    elif mutation == "repair-row":
        source["rows"][800]["values"][1] = "MA04(04)a"
    elif mutation == "statement":
        source["rows"][0]["values"][3] += " changed"
    elif mutation == "cell-format":
        source["rows"][0]["number_formats"][0] = "@"
    elif mutation == "annotation":
        source["cell_annotations"][0]["hyperlink"]["target"] = "https://example.org/changed"
    with pytest.raises(ValueError, match=message):
        generator["build_catalog"](source)


def test_generator_is_pure_isolated_deterministic_and_check_only(
    generator: dict[str, Any], source: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_before = _lf(SOURCE)
    legacy_before = _lf(DATA / "cms-ars-5.1.json")
    expected = generator["build_catalog"](source)
    snapshot = copy.deepcopy(expected)
    source["rows"][0]["values"][3] = "Changed later"
    assert expected == snapshot
    monkeypatch.chdir(tmp_path)
    runpy.run_path(str(SCRIPT), run_name="cms_import_only")
    assert list(tmp_path.iterdir()) == []
    destination = tmp_path / "isolated/catalog.json"
    args = ["--source", str(SOURCE), "--output", str(destination)]
    assert generator["main"](args) == 0
    first = destination.read_bytes()
    assert b"\r\n" not in first and first.isascii()
    assert json.loads(first) == expected
    assert generator["main"](args) == 0
    assert destination.read_bytes() == first
    assert generator["main"]([*args, "--check"]) == 0
    destination.write_text("changed\n", encoding="utf-8", newline="\n")
    assert generator["main"]([*args, "--check"]) == 1
    assert destination.read_bytes() == b"changed\n"
    absent = tmp_path / "absent/catalog.json"
    assert generator["main"](["--source", str(SOURCE), "--output", str(absent), "--check"]) == 1
    assert not absent.parent.exists()
    assert _lf(SOURCE) == source_before and _lf(DATA / "cms-ars-5.1.json") == legacy_before


def test_historical_assessment_controls_remain_unchanged() -> None:
    legacy = _read(DATA / "cms-ars-5.1.json")
    assert len(legacy["controls"]) == 19
    assert _digest(legacy["controls"]) == LEGACY_CONTROLS_SHA


def test_generator_rejects_hard_link_output_without_altering_source(generator: dict[str, Any], tmp_path: Path) -> None:
    isolated_source = tmp_path / "source.json"
    isolated_source.write_bytes(SOURCE.read_bytes())
    aliased_output = tmp_path / "output.json"
    aliased_output.hardlink_to(isolated_source)
    assert isolated_source.resolve() != aliased_output.resolve()
    assert isolated_source.samefile(aliased_output)
    original = isolated_source.read_bytes()
    with pytest.raises(ValueError, match="input and output paths must differ"):
        generator["generate"](source_path=isolated_source, output_path=aliased_output)
    assert isolated_source.read_bytes() == aliased_output.read_bytes() == original
