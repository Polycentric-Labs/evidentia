"""Source evidence preserves parsed cells without changing assessment units."""

from __future__ import annotations

import copy
import json
import math
import operator
from collections import UserDict
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
import yaml
from evidentia_core.catalogs.loader import load_evidentia_catalog
from evidentia_core.gap_analyzer import GapAnalyzer
from evidentia_core.models.catalog import CatalogControl, ControlCatalog
from evidentia_core.models.control import ControlInventory
from pydantic import BaseModel, TypeAdapter, ValidationError, create_model
from pydantic_core import PydanticSerializationError


def _payload() -> dict[str, Any]:
    return {
        "source_sha256": "a" * 64,
        "sheet": " source sheet ",
        "row": 1461,
        "source_id": 5.2,
        "source_id_format": "0.00",
        "interpreted_id": "5.20",
        "kind": "fragment",
        "values": {
            " raw key\n": " \u00a0 ",
            "null": None,
            "empty": "",
            "integer": 5,
            "float": 5.0,
            "bool": True,
            "text": "005",
            "flag_text": "yes",
            "minus_zero": -0.0,
            "U": None,
        },
        "resolved_values": {"U": "Existing"},
        "provenance": {"U:anchor": "U1460", "U:merged_range": "U1460:U1461"},
    }


def _row(**updates: Any) -> Any:
    return CatalogControl(
        id="AC-1", title="Policy", description="Maintain a policy.", source_rows=[{**_payload(), **updates}]
    ).source_rows[0]


def _catalog(with_rows: bool = True) -> ControlCatalog:
    leaf = {"id": "AC-1(1)(a)", "title": "Leaf", "description": "Implement the leaf."}
    if with_rows:
        leaf["source_rows"] = [_payload()]
    return ControlCatalog.model_validate(
        {
            "framework_id": "source-test",
            "framework_name": "Source test",
            "version": "1",
            "source": "test",
            "controls": [
                {
                    "id": "AC-1",
                    "title": "Policy",
                    "description": "Maintain a policy.",
                    **({"source_rows": [_payload()]} if with_rows else {}),
                    "enhancements": [
                        {
                            "id": "AC-1(1)",
                            "title": "Child",
                            "description": "Implement the child.",
                            "enhancements": [leaf],
                        }
                    ],
                }
            ],
        }
    )


def test_shared_row_retains_exact_scalars_whitespace_and_interpretation() -> None:
    row = _row()
    assert row.model_dump() == _payload()
    assert row.source_id == 5.2 and type(row.source_id) is float
    assert row.source_id_format == "0.00" and row.interpreted_id == "5.20"
    for key, expected in _payload()["values"].items():
        assert row.values[key] == expected
        assert type(row.values[key]) is type(expected)
    assert math.copysign(1, row.values["minus_zero"]) == -1
    assert row.values["U"] is None and row.resolved_values["U"] == "Existing"
    assert type(row).model_validate_json(row.model_dump_json()).model_dump() == _payload()


@pytest.mark.parametrize("kind", ["aggregate", "clause", "fragment"])
def test_closed_source_row_kinds(kind: str) -> None:
    assert _row(kind=kind).kind == kind


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_native_load_and_shared_responses_preserve_nested_rows(tmp_path: Path, fmt: str) -> None:
    catalog = _catalog()
    data = catalog.model_dump(mode="json")
    content = json.dumps(data) if fmt == "json" else yaml.safe_dump(data, sort_keys=False)
    path = tmp_path / f"catalog.{fmt}"
    path.write_text(content, encoding="utf-8")
    loaded = load_evidentia_catalog(path)
    assert loaded.controls[0].source_rows[0].model_dump() == _payload()
    leaf = loaded.get_control("AC-1.1.A")
    assert leaf is not None
    assert leaf.source_rows[0].model_dump() == _payload()
    full = TypeAdapter(ControlCatalog).dump_python(loaded, mode="json")
    single = TypeAdapter(CatalogControl).dump_python(leaf, mode="json")
    assert full["controls"][0]["enhancements"][0]["enhancements"][0]["source_rows"] == [_payload()]
    assert single["source_rows"] == [_payload()]
    assert copy.deepcopy(loaded).model_dump() == data
    assert loaded.model_copy(deep=True).model_dump() == data


@pytest.mark.parametrize("fmt", ["json", "yaml"])
def test_native_date_cells_match_json_staging(tmp_path: Path, fmt: str) -> None:
    data = _catalog(False).model_dump(mode="json")
    dated = date(2026, 7, 23)
    source_row = {**_payload(), "source_id": dated, "values": {"date": dated}, "resolved_values": {"date": dated}}
    data["controls"][0]["source_rows"] = [source_row]
    content = json.dumps(data, default=lambda value: value.isoformat()) if fmt == "json" else yaml.safe_dump(data)
    path = tmp_path / f"dates.{fmt}"
    path.write_text(content, encoding="utf-8")
    row = load_evidentia_catalog(path).controls[0].source_rows[0]
    assert row.source_id == "2026-07-23"
    assert row.values == row.resolved_values == {"date": "2026-07-23"}


@pytest.mark.parametrize("mapping", [dict, MappingProxyType, UserDict])
@pytest.mark.parametrize("cell", [date(2026, 7, 23), datetime(2026, 7, 23, 12, 34, 56, 123, tzinfo=UTC)])
def test_dates_normalize_in_every_scalar_entry_point(mapping: Any, cell: date) -> None:
    row = _row(source_id=cell, values=mapping({"date": cell}), resolved_values=mapping({"date": cell}))
    assert row.source_id == cell.isoformat()
    assert row.values == {"date": cell.isoformat()}
    assert row.resolved_values == {"date": cell.isoformat()}
    assert type(row).model_validate_json(row.model_dump_json()).model_dump() == row.model_dump()


def test_rows_detach_input_and_freeze_maps_including_defaults() -> None:
    payload = _payload()
    row = _row(**payload)
    payload["values"]["integer"] = 99
    payload["resolved_values"]["U"] = "Changed"
    payload["provenance"]["U:anchor"] = "wrong"
    assert row.model_dump() == _payload()
    defaults = type(row).model_validate(
        {key: value for key, value in _payload().items() if key not in {"provenance", "resolved_values"}}
    )
    assert defaults.provenance == defaults.resolved_values == {}
    for mapping in (row.values, row.resolved_values, row.provenance, defaults.provenance, defaults.resolved_values):
        with pytest.raises(TypeError):
            operator.setitem(mapping, "untrusted", "new")
    with pytest.raises(ValidationError):
        row.sheet = "changed"
    for copier in (
        copy.copy,
        copy.deepcopy,
        lambda value: value.model_copy(),
        lambda value: value.model_copy(deep=True),
    ):
        assert copier(row).model_dump() == _payload()
    replacement = {"text": " exact "}
    changed = row.model_copy(update={"values": replacement}, deep=True)
    replacement["text"] = "later"
    assert changed.values == {"text": " exact "}
    assert row.values == _payload()["values"]
    assert row.model_copy().model_fields_set == row.model_fields_set
    assert defaults.model_dump(exclude_unset=True) == {
        key: value for key, value in _payload().items() if key not in {"provenance", "resolved_values"}
    }


@pytest.mark.parametrize("field", ["source_id", "values", "resolved_values"])
@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf, Decimal("1.2"), b"bytes", {"nested": "value"}, [1]])
def test_invalid_scalar_values_reject_on_validation_and_copy(field: str, bad: Any) -> None:
    row = _row()
    update = {field: bad if field == "source_id" else {"bad": bad}}
    with pytest.raises(ValidationError):
        type(row).model_validate({**_payload(), **update})
    with pytest.raises(ValidationError):
        row.model_copy(update=update)


@pytest.mark.parametrize(
    "update",
    [
        {"row": True},
        {"row": 0},
        {"row": -1},
        {"row": "1"},
        {"source_sha256": "z" * 64},
        {"source_sha256": "a" * 63},
        {"sheet": ""},
        {"sheet": " "},
        {"sheet": "\t\n"},
        {"sheet": "\u00a0"},
        {"kind": "control"},
        {"kind": "enhancement"},
        {"extra": "field"},
        {"values": {1: "value"}},
        {"provenance": {"anchor": 1}},
        {"source_id_format": 1},
        {"interpreted_id": 5.2},
    ],
)
def test_source_metadata_rejects_invalid_or_coerced_values(update: dict[str, Any]) -> None:
    row = _row()
    with pytest.raises(ValidationError):
        type(row).model_validate({**_payload(), **update})
    with pytest.raises(ValidationError):
        row.model_copy(update=update)


@pytest.mark.parametrize("field", ["source_id", "values", "resolved_values"])
@pytest.mark.parametrize("trusted_path", ["construct", "base_copy"])
def test_trusted_invalid_evidence_rejects_before_persistence(field: str, trusted_path: str) -> None:
    row = _row()
    update = {field: math.nan if field == "source_id" else {"bad": math.nan}}
    invalid = (
        type(row).model_construct(**{**_payload(), **update})
        if trusted_path == "construct"
        else BaseModel.model_copy(row, update=update)
    )
    with pytest.raises(ValidationError):
        type(row).model_validate(invalid)
    with pytest.raises(ValidationError):
        CatalogControl(id="AC-1", title="Policy", description="Statement", source_rows=[invalid])
    unchecked_parent = CatalogControl.model_construct(
        id="AC-1", title="Policy", description="Statement", source_rows=[invalid]
    )
    for dump in (
        invalid.model_dump,
        invalid.model_dump_json,
        lambda: TypeAdapter(CatalogControl).dump_json(unchecked_parent),
    ):
        with pytest.raises(PydanticSerializationError):
            dump()


def test_source_schema_describes_actual_shared_response_fields() -> None:
    row_type = type(_row())
    validation = row_type.model_json_schema(mode="validation")
    serialization = row_type.model_json_schema(mode="serialization")
    assert serialization["properties"] == validation["properties"]
    assert serialization["required"] == validation["required"]
    assert serialization["additionalProperties"] is False
    shared_schema = TypeAdapter(ControlCatalog).json_schema(mode="serialization")
    assert shared_schema["$defs"]["CatalogSourceRow"]["properties"] == validation["properties"]
    assert shared_schema["$defs"]["CatalogSourceRow"]["properties"]["values"]["type"] == "object"
    extended = create_model("ExtendedRow", __base__=row_type, unrelated_private_field=(str, "private"))
    value = extended.model_validate(_payload())
    assert "unrelated_private_field" not in TypeAdapter(row_type).dump_python(value, mode="json")


def test_source_rows_do_not_change_catalog_or_gap_denominators(monkeypatch: pytest.MonkeyPatch) -> None:
    baseline, evidence = _catalog(False), _catalog(True)
    analyzer = GapAnalyzer()
    assert baseline.control_count == evidence.control_count == 3
    assert baseline.statement_rows() == evidence.statement_rows()
    assert baseline.text_depth == evidence.text_depth == "full"
    for catalog in (baseline, evidence):
        assert catalog.get_control("5.20") is None
        assert catalog.get_control("5.2") is None
    base_required = analyzer._build_required_set({"source-test": baseline})
    evidence_required = analyzer._build_required_set({"source-test": evidence})
    assert list(base_required) == list(evidence_required)
    summaries = []
    for catalog in (baseline, evidence):
        monkeypatch.setattr(analyzer.registry, "get_catalog", lambda framework_id, current=catalog: current)
        report = analyzer.analyze(
            ControlInventory(organization="Test", controls=[]), ["source-test"], show_efficiency=False
        )
        summaries.append(
            (
                report.total_controls_required,
                report.total_gaps,
                report.coverage_percentage,
                [gap.control_id for gap in report.gaps],
            )
        )
    assert summaries[0] == summaries[1]
    assert summaries[0][:3] == (3, 3, 0.0)


def test_existing_controls_have_independent_empty_row_defaults() -> None:
    first = CatalogControl(id="A", title="A", description="First statement.")
    second = CatalogControl(id="B", title="B", description="Second statement.")
    assert first.source_rows == second.source_rows == []
    first.source_rows.append(_row())
    assert second.source_rows == []


@pytest.mark.parametrize("fmt", ["json", "yaml"])
@pytest.mark.parametrize("source_id", [None, "", "005", 0, 2**80, 5.0, 5.2, -0.0, True, False])
def test_scalar_types_and_sign_survive_native_and_shared_round_trips(tmp_path: Path, fmt: str, source_id: Any) -> None:
    cells = {
        "null": None,
        "empty": "",
        "text": "005",
        "bool": True,
        "int": 5,
        "large": 2**80,
        "float": 5.0,
        "zero": -0.0,
    }
    row = _row(source_id=source_id, values=cells, resolved_values=cells)
    catalog = _catalog(False)
    catalog.controls[0].source_rows = [row]
    serialized = catalog.model_dump(mode="json")
    content = json.dumps(serialized) if fmt == "json" else yaml.safe_dump(serialized)
    path = tmp_path / f"scalar-types.{fmt}"
    path.write_text(content, encoding="utf-8")
    loaded = load_evidentia_catalog(path)
    loaded_row = loaded.controls[0].source_rows[0]
    outputs = [
        json.loads(row.model_dump_json()),
        loaded_row.model_dump(mode="json"),
        TypeAdapter(ControlCatalog).dump_python(loaded, mode="json")["controls"][0]["source_rows"][0],
        TypeAdapter(CatalogControl).dump_python(loaded.controls[0], mode="json")["source_rows"][0],
    ]
    for output in outputs:
        assert output["source_id"] == source_id
        assert type(output["source_id"]) is type(source_id)
        if isinstance(source_id, float) and source_id == 0:
            assert math.copysign(1, output["source_id"]) == math.copysign(1, source_id)
        for name in ("values", "resolved_values"):
            for key, expected in cells.items():
                assert output[name][key] == expected
                assert type(output[name][key]) is type(expected)
                if isinstance(expected, float) and expected == 0:
                    assert math.copysign(1, output[name][key]) == math.copysign(1, expected)
