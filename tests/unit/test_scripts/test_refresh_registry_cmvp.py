"""Check finite CMVP HTML selection and independent complete coalescing."""

from __future__ import annotations

import copy
import gzip
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.registries import refresh_cmvp as refresh

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


def test_all_table_occurrences_and_detail_are_regenerated() -> None:
    document, binding = full_input("cmvp")
    output = refresh.regenerate(document, binding)
    rows = output["facts"]["certificates"]
    assert output["fact_counts"] == {"certificates": 5510}
    assert sum(len(row["occurrences"]) for row in rows) == 5532
    assert [row["certificate_number"] for row in rows if "detail" in row] == ["5517"]
    assert sum(row["status"]["value"] == "Revoked" for row in rows) == 25


def test_active_table_preserves_entities_and_br_order() -> None:
    rows = refresh.extract_source((FIXTURES / "cmvp/source-active.html").read_bytes(), "active")
    assert rows == [
        {
            "source_index": 0,
            "fields": {
                "Certificate Number": "5517",
                "Vendor Name": "Synthetic & vendor",
                "Module Name": "Synthetic module",
                "Module Type": "Software",
                "Validation Date": "01/02/2026\n12/01/2025",
            },
        }
    ]


def test_historical_query_does_not_overwrite_revoked_literal() -> None:
    rows = refresh.extract_source((FIXTURES / "cmvp/source-historical-revoked.html").read_bytes(), "historical")
    assert rows[0]["fields"]["Status"] == "Revoked"
    assert rows[0]["fields"]["Validation Date"] == "01/01/2020\n"


def test_detail_uses_exact_labels_and_only_selected_values() -> None:
    rows = refresh.extract_source((FIXTURES / "cmvp/source-certificate.html").read_bytes(), "certificate_5517_detail")
    assert rows[0]["fields"]["Caveat"] == "Synthetic caveat\nSecond line"
    assert set(rows[0]["fields"]) == {"Module Name", "Standard", "Status", "Sunset Date", "Caveat", "Module Type"}


def test_layout_and_duplicate_disagreement_are_rejected() -> None:
    with pytest.raises(ValueError):
        refresh.extract_source((FIXTURES / "cmvp/source-layout-drift.html").read_bytes(), "active")
    document, binding = full_input("cmvp")
    document = copy.deepcopy(document)
    historical_ids = {row["fields"]["Certificate Number"] for row in document["tables"][1]["rows"]}
    revoked = next(
        row["fields"] for row in document["tables"][2]["rows"] if row["fields"]["Certificate Number"] in historical_ids
    )
    historical = next(
        row["fields"]
        for row in document["tables"][1]["rows"]
        if row["fields"]["Certificate Number"] == revoked["Certificate Number"]
    )
    historical["Module Name"] += " changed"
    with pytest.raises(ValueError):
        refresh.regenerate(document, binding)


@pytest.mark.parametrize("table", ["active", "historical", "revoked"])
def test_column_count_identity_and_duplicate_selected_id_fail_closed(table: str) -> None:
    fixture = "source-active.html" if table == "active" else "source-historical-revoked.html"
    raw = (FIXTURES / "cmvp" / fixture).read_bytes()
    with pytest.raises(ValueError):
        refresh.extract_source(raw.replace(b"</tr></tbody>", b"<td>extra</td></tr></tbody>"), table)
    with pytest.raises(ValueError):
        refresh.extract_source(raw.replace(b'id="searchResultsTable"', b'id="searchResultsTable" id="changed"'), table)
    with pytest.raises(ValueError):
        refresh.extract_source(
            raw.replace(b">5517</a>", b">not-a-number</a>").replace(b">42</a>", b">not-a-number</a>"), table
        )


def test_detail_heading_label_and_empty_value_semantics() -> None:
    raw = (FIXTURES / "cmvp/source-certificate.html").read_bytes()
    for altered in (
        raw.replace(b"Certificate #5517", b"Certificate #5518"),
        raw.replace(b">Caveat<", b">Caveat changed<"),
        raw.replace(b'id="module-name"', b'id="changed-name"'),
    ):
        with pytest.raises(ValueError):
            refresh.extract_source(altered, "certificate_5517_detail")
    selected = refresh.extract_source(raw.replace(b"Synthetic caveat<br/>Second line", b""), "certificate_5517_detail")
    assert selected[0]["fields"]["Caveat"] == ""


def test_compressed_hash_checks_precede_decoder_and_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.registries import refresh_fedramp as boundary

    index = json.loads(
        (ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries/data/source-index.json").read_bytes()
    )
    entry = index["snapshot_index"]["cmvp"]
    raw = (ROOT / entry["tuple_path"]).read_bytes()
    monkeypatch.setattr(
        boundary, "_decode_gzip", lambda *args, **kwargs: pytest.fail("decoder ran before stored hash check")
    )
    with pytest.raises(ValueError):
        boundary.convert(raw[:-1] + bytes([raw[-1] ^ 1]), index, "cmvp", refresh.regenerate)
    monkeypatch.setattr(boundary, "_decode_gzip", lambda *args, **kwargs: b"{}")
    monkeypatch.setattr(boundary, "parse_source", lambda *args: pytest.fail("parser ran before decoded hash check"))
    with pytest.raises(ValueError):
        boundary.convert(raw, index, "cmvp", refresh.regenerate)


def test_complete_regeneration_no_write_check_is_byte_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.registries import refresh_fedramp as boundary

    index_path = ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries/data/source-index.json"
    index = json.loads(index_path.read_bytes())
    entry = index["snapshot_index"]["cmvp"]
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
            "refresh_cmvp",
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
    assert boundary.main("cmvp", refresh.regenerate) == 0
    assert (output.stat().st_mtime_ns, output.read_bytes(), sorted(path.name for path in tmp_path.iterdir())) == before
