"""Check reviewed FCC facts without inferring category applicability."""

from __future__ import annotations

import copy
import gzip
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.registries import refresh_fcc as refresh

ROOT = Path(__file__).parents[3]
FIXTURES = ROOT / "tests" / "fixtures" / "registries"


def full_input(registry: str) -> tuple[dict[str, Any], dict[str, Any]]:
    index = json.loads(
        (ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries/data/source-index.json").read_bytes()
    )
    entry = index["snapshot_index"][registry]
    raw = (ROOT / entry["tuple_path"]).read_bytes()
    if "tuple_storage" in entry:
        raw = gzip.decompress(raw)
    return json.loads(raw), entry["tuple_input"]


def test_all_fact_families_are_regenerated_separately() -> None:
    document, binding = full_input("fcc-covered-list")
    output = refresh.regenerate(document, binding)
    assert output["fact_counts"] == {
        "named_entries": 12,
        "category_rows": 4,
        "footnotes": 9,
        "conditional_approvals": 40,
        "definition_context": 3,
        "source_context": 11,
    }
    assert all(row["publisher_row_identifier_presence"] == "absent" for row in output["facts"]["named_entries"])
    assert output["source_manifest"]["as_of"]["date"] == "2026-09-09"


def test_proposal_and_fact_schema_drift_are_rejected() -> None:
    for name in ("source-proposal.json", "source-fact-schema-drift.json"):
        with pytest.raises(ValueError):
            refresh.regenerate(json.loads((FIXTURES / "fcc" / name).read_bytes()), {})


def test_duplicate_normalized_alias_is_rejected() -> None:
    document, binding = full_input("fcc-covered-list")
    document = copy.deepcopy(document)
    document["named_entries"][1]["names_source_literal"] = ["  HUAWEI  Technologies Company  "]
    with pytest.raises(ValueError):
        refresh.regenerate(document, binding)


@pytest.mark.parametrize(
    "filename,family",
    [
        ("source-covered-entries.json", "named_entries"),
        ("source-conditional-approvals.json", "conditional_approvals"),
        ("source-category-only.json", "category_rows"),
    ],
)
def test_minimal_fact_fixtures_preserve_scope_and_occurrences(filename: str, family: str) -> None:
    from evidentia_collectors.registries import fcc

    fixture = json.loads((FIXTURES / "fcc" / filename).read_bytes())
    selected = fcc.project_fact(family, fixture[family][0])
    assert selected == fixture[family][0]
    assert selected["publisher_row_identifier_presence"] == "absent"
    assert selected["source_occurrences"]
    if family == "conditional_approvals":
        assert selected["approval_groups"][0]["termination_component"] == {"presence": "empty", "source_literal": ""}
        assert "names_source_literal" not in selected
    if family == "category_rows":
        assert fixture["named_entries"] == []
        assert "names_source_literal" not in selected


@pytest.mark.parametrize(
    "mutation",
    ["bool_position", "missing_occurrence", "reordered_header", "duplicate_footnote", "date_number", "unsupported_key"],
)
def test_reviewed_fact_format_drift_is_rejected(mutation: str) -> None:
    document, binding = full_input("fcc-covered-list")
    document = copy.deepcopy(document)
    row = document["named_entries"][0]
    if mutation == "bool_position":
        row["source_occurrences"][0]["inclusion_date_cell"]["pdf_page"] = True
    elif mutation == "missing_occurrence":
        row["source_occurrences"] = []
    elif mutation == "reordered_header":
        document["appendix_a_column_headers_source_literal"].reverse()
    elif mutation == "duplicate_footnote":
        document["footnotes"].append(copy.deepcopy(document["footnotes"][0]))
    elif mutation == "date_number":
        row["inclusion_date_source_literal"] = 20260909
    else:
        row["implicit_affiliate_assessment"] = True
    with pytest.raises(ValueError):
        refresh.regenerate(document, binding)


def test_complete_regeneration_no_write_check_is_byte_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.registries import refresh_fedramp as boundary

    index_path = ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries/data/source-index.json"
    index = json.loads(index_path.read_bytes())
    entry = index["snapshot_index"]["fcc-covered-list"]
    expected = (
        ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries" / entry.get("storage", entry)["path"]
    )
    output = tmp_path / "snapshot"
    output.write_bytes(expected.read_bytes())
    before = (output.stat().st_mtime_ns, output.read_bytes(), sorted(path.name for path in tmp_path.iterdir()))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "refresh_fcc",
            "--input",
            str(ROOT / entry["tuple_path"]),
            "--receipt",
            str(index_path),
            "--output",
            str(output),
            "--check",
        ],
    )
    monkeypatch.setattr(tempfile, "NamedTemporaryFile", lambda **kwargs: pytest.fail("--check attempted a write"))
    assert boundary.main("fcc-covered-list", refresh.regenerate) == 0
    assert (output.stat().st_mtime_ns, output.read_bytes(), sorted(path.name for path in tmp_path.iterdir())) == before
