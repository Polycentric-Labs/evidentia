"""Check independent FedRAMP source joins and complete regeneration."""

from __future__ import annotations

import copy
import gzip
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from scripts.registries import refresh_fedramp as refresh

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


def test_all_selected_occurrences_are_regenerated() -> None:
    document, binding = full_input("fedramp")
    output = refresh.regenerate(document, binding)
    assert output["fact_counts"] == {"products": 666, "unmatched_history": 334, "unjoined_packages": 62}
    products = output["facts"]["products"]
    assert sum(len(row["history"]) for row in products) == 1786
    assert sum(len(row["package_rows"]) for row in products) == 7
    assert sum(len(row["history"]) for row in products) + len(output["facts"]["unmatched_history"]) == 2120


def test_raw_product_selection_excludes_contacts_and_preserves_order() -> None:
    rows = refresh.extract_source((FIXTURES / "fedramp/source-products.json").read_bytes(), "products")
    assert rows[0]["fields"]["id"] == "F-SYNTHETIC"
    assert rows[0]["fields"]["service_model"] == ["SaaS", "SaaS"]
    assert "contact" not in rows[0]["fields"]


def test_conflicting_statuses_keep_source_order_and_distinct_dates() -> None:
    rows = refresh.extract_source((FIXTURES / "fedramp/source-status-conflict.json").read_bytes(), "history")
    assert [row["fields"]["to_status"] for row in rows] == ["Authorized", "Revoked"]
    assert rows[0]["fields"]["transition_date"] == "2026-02-01"
    assert rows[1]["fields"]["recorded_date"] == "2026-09-10T00:00:00Z"


def test_native_field_shape_drift_is_rejected() -> None:
    with pytest.raises(ValueError):
        refresh.extract_source((FIXTURES / "fedramp/source-shape-drift.json").read_bytes(), "products")


def test_duplicate_source_identity_is_not_coalesced() -> None:
    document, binding = full_input("fedramp")
    document = copy.deepcopy(document)
    document["tables"][0]["rows"][1]["fields"]["id"] = document["tables"][0]["rows"][0]["fields"]["id"]
    with pytest.raises(ValueError):
        refresh.regenerate(document, binding)


@pytest.mark.parametrize(
    "raw",
    [
        b"\xef\xbb\xbf{}",
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1e9999}',
        b'{"a":1e-9999}',
        b'{"a":9007199254740993.0}',
        b'{"a":"\\ud800"}',
        b'{"a":' + b"1" * 129 + b"}",
        b"[]",
    ],
)
def test_strict_source_parser_rejects_loss_or_ambiguous_native_values(raw: bytes) -> None:
    with pytest.raises(ValueError):
        refresh.parse_source(raw)


def test_source_byte_and_depth_boundaries_are_inclusive() -> None:
    exact = b"{}" + b" " * (refresh.MAX_BYTES - 2)
    assert refresh.parse_source(exact) == {}
    with pytest.raises(ValueError):
        refresh.parse_source(exact + b" ")
    assert refresh.parse_source(b'{"a":' * 16 + b"0" + b"}" * 16)
    with pytest.raises(ValueError):
        refresh.parse_source(b'{"a":' * 17 + b"0" + b"}" * 17)


def test_native_callbacks_and_cycles_are_never_evaluated() -> None:
    class Meta(type):
        def __hash__(cls) -> int:
            pytest.fail("metaclass hash callback executed")

        def __eq__(cls, other: object) -> bool:
            pytest.fail("metaclass comparison callback executed")

    class Hostile(metaclass=Meta):
        pass

    with pytest.raises(ValueError):
        refresh.native(Hostile())
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError):
        refresh.native(cyclic)


def test_agreeing_join_is_exact_and_false_flag_never_attaches() -> None:
    document, binding = full_input("fedramp")
    document = copy.deepcopy(document)
    output = refresh.regenerate(document, binding)
    for product in output["facts"]["products"]:
        for package in product["package_rows"]:
            fields = package["fields"]
            assert fields["id_matches_expected"] is True
            assert (
                fields["serviceIdentification"]["fedRampPackageId"]
                == fields["ZD_frid_retro"]
                == product["fields"]["id"]
            )
    packages = document["tables"][2]["rows"]
    identifiers = {row["fields"]["id"] for row in document["tables"][0]["rows"]}
    agreeing = next(
        row
        for row in packages
        if row["fields"]["id_matches_expected"] is True
        and row["fields"]["ZD_frid_retro"] in identifiers
        and row["fields"]["serviceIdentification"]["fedRampPackageId"] == row["fields"]["ZD_frid_retro"]
    )
    other = next(row for row in packages if row is not agreeing)
    other["fields"] = copy.deepcopy(agreeing["fields"])
    with pytest.raises(ValueError):
        refresh.regenerate(document, binding)


def test_hash_gate_precedes_tuple_parser_and_preserves_existing_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index_path = ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries/data/source-index.json"
    index = json.loads(index_path.read_bytes())
    entry = index["snapshot_index"]["fedramp"]
    raw = (ROOT / entry["tuple_path"]).read_bytes()
    monkeypatch.setattr(refresh, "parse_source", lambda _: pytest.fail("tuple parser ran before raw hash validation"))
    with pytest.raises(ValueError):
        refresh.convert(raw[:-1] + b"x", index, "fedramp", refresh.regenerate)


def test_actual_no_write_check_and_alias_protection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source, receipt, output = (tmp_path / name for name in ("source.json", "receipt.json", "snapshot.json"))
    source.write_bytes(b"{}")
    receipt.write_bytes(b"{}")
    output.write_bytes(b"prior snapshot")
    prior = (output.stat().st_mtime_ns, output.read_bytes())
    monkeypatch.setattr(refresh, "convert", lambda *args: b"prior snapshot")
    monkeypatch.setattr(
        tempfile, "NamedTemporaryFile", lambda **kwargs: pytest.fail("--check attempted to create a temporary file")
    )
    refresh.refresh_files(source, receipt, output, check=True, registry="fedramp", regenerator=refresh.regenerate)
    assert (output.stat().st_mtime_ns, output.read_bytes()) == prior
    for alias in (source, receipt):
        with pytest.raises(ValueError):
            refresh.refresh_files(
                source, receipt, alias, check=False, registry="fedramp", regenerator=refresh.regenerate
            )
    hardlink = tmp_path / "alias.json"
    hardlink.hardlink_to(source)
    with pytest.raises(ValueError):
        refresh.refresh_files(
            source, receipt, hardlink, check=False, registry="fedramp", regenerator=refresh.regenerate
        )
    assert source.read_bytes() == b"{}"


def test_failed_conversion_and_check_mismatch_preserve_prior_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, receipt, output = (tmp_path / name for name in ("source.json", "receipt.json", "snapshot.json"))
    source.write_bytes(b"{}")
    receipt.write_bytes(b"{}")
    output.write_bytes(b"prior snapshot")
    prior = (output.stat().st_mtime_ns, output.read_bytes(), sorted(path.name for path in tmp_path.iterdir()))
    with pytest.raises(ValueError):
        refresh.refresh_files(source, receipt, output, check=False, registry="fedramp", regenerator=refresh.regenerate)
    monkeypatch.setattr(refresh, "convert", lambda *args: b"different")
    with pytest.raises(ValueError):
        refresh.refresh_files(source, receipt, output, check=True, registry="fedramp", regenerator=refresh.regenerate)
    assert (output.stat().st_mtime_ns, output.read_bytes(), sorted(path.name for path in tmp_path.iterdir())) == prior


def test_minimal_saved_source_pipeline_keeps_false_join_unattached() -> None:
    document, _ = full_input("fedramp")
    document = copy.deepcopy(document)
    names = (
        ("products", "source-products.json"),
        ("history", "source-status-conflict.json"),
        ("packages", "source-packages.json"),
    )
    for index, (table, filename) in enumerate(names):
        raw = (FIXTURES / "fedramp" / filename).read_bytes()
        source = json.loads(raw)
        document["tables"][index]["rows"] = refresh.extract_source(raw, table)
        document["tables"][index]["source_envelope"] = (
            {"meta": source["meta"]} if table == "products" else {"metadata": source["metadata"]}
        )
        document["selected_occurrence_counts"][table] = len(document["tables"][index]["rows"])
        document["sources"][index]["raw_bytes"] = len(raw)
        document["sources"][index]["raw_sha256"] = refresh.digest(raw)
        document["sources"][index]["url"] = "https://example.org/synthetic/" + filename
        document["sources"][index]["commit"] = "0" * 40
        document["sources"][index]["source_cutoff"]["value"] = "2026-09-10T00:00:00Z"
    encoded = refresh.encode(document)
    output = refresh.regenerate(
        document, {"source_kind": "reviewed-native-tuples", "bytes": len(encoded), "sha256": refresh.digest(encoded)}
    )
    assert output["fact_counts"] == {"products": 1, "unmatched_history": 0, "unjoined_packages": 2}
    product = output["facts"]["products"][0]
    assert product["fields"]["status"] == "Historical"
    assert [row["fields"]["to_status"] for row in product["history"]] == ["Authorized", "Revoked"]
    assert len(product["package_rows"]) == 1
    assert "ueiNumber" not in product["package_rows"][0]["fields"]["serviceIdentification"]
    assert output["facts"]["unjoined_packages"][0]["join_not_established"] == [
        "source_ids_disagree",
        "source_agreement_flag_not_true",
    ]
    assert output["facts"]["unjoined_packages"][1]["join_not_established"] == [
        "administrative_id_not_in_product_snapshot"
    ]
    one = refresh.extract_source((FIXTURES / "fedramp/source-statuses.json").read_bytes(), "history")
    assert len(one) == 1 and one[0]["fields"]["recorded_date"] == "2026-09-10T00:00:00Z"


@pytest.mark.parametrize(
    "mutation", ["bool_index", "index_gap", "null_field", "native_flag", "row_count", "column_path"]
)
def test_tuple_layout_and_native_kinds_fail_closed(mutation: str) -> None:
    document, binding = full_input("fedramp")
    document = copy.deepcopy(document)
    if mutation == "bool_index":
        document["tables"][0]["rows"][0]["source_index"] = False
    elif mutation == "index_gap":
        document["tables"][1]["rows"][1]["source_index"] = 8
    elif mutation == "null_field":
        document["tables"][0]["rows"][0]["fields"]["status"] = None
    elif mutation == "native_flag":
        document["tables"][2]["rows"][0]["fields"]["id_matches_expected"] = 1
    elif mutation == "row_count":
        document["selected_occurrence_counts"]["history"] -= 1
    else:
        document["tables"][0]["columns"][0]["source_pointer"] = "/data/Products/*/wrong"
    with pytest.raises(ValueError):
        refresh.regenerate(document, binding)


def test_complete_regeneration_no_write_check_is_byte_exact(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from scripts.registries import refresh_fedramp as boundary

    index_path = ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries/data/source-index.json"
    index = json.loads(index_path.read_bytes())
    entry = index["snapshot_index"]["fedramp"]
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
            "refresh_fedramp",
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
    assert boundary.main("fedramp", refresh.regenerate) == 0
    assert (output.stat().st_mtime_ns, output.read_bytes(), sorted(path.name for path in tmp_path.iterdir())) == before


def _publisher_cutoff_document(values: tuple[str, str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Alter only in-memory publisher metadata for counterfactual cutoff checks."""
    document, _ = full_input("fedramp")
    for index, literal in enumerate(values):
        document["sources"][index]["source_cutoff"]["value"] = literal
        envelope = document["tables"][index]["source_envelope"]
        if index == 0:
            envelope["meta"]["last_change"] = literal
        else:
            envelope["metadata"]["export_timestamp"] = literal
    raw = refresh.encode(document)
    return document, {"source_kind": "reviewed-native-tuples", "bytes": len(raw), "sha256": refresh.digest(raw)}


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize(
    "unsupported",
    [
        "2026-09-10T00:00:00.0000009Z",
        "2026-09-10T00:00:00.0000001Z",
        "2026-09-10T00:00:00.0000005Z",
        "2026-09-10T00:00:00-00:00",
    ],
)
def test_unsupported_publisher_cutoff_refused_before_fact_projection(
    position: int, unsupported: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    cutoffs = ["2026-09-10T00:00:00Z"] * 3
    cutoffs[position] = unsupported
    document, binding = _publisher_cutoff_document((cutoffs[0], cutoffs[1], cutoffs[2]))
    before = copy.deepcopy(document)
    monkeypatch.setattr(
        refresh, "_validate_fields", lambda *args, **kwargs: pytest.fail("unsupported cutoff reached projection")
    )
    with pytest.raises(refresh.RefreshError, match=r"^invalid_offline_registry_input$"):
        refresh.regenerate(document, binding)
    assert document == before


@pytest.mark.parametrize(
    "cutoffs",
    [
        (
            "2026-09-10T00:00:00.000009Z",
            "2026-09-10T00:00:00.000001Z",
            "2026-09-10T00:00:00.000005Z",
        ),
        (
            "2026-09-10T00:00:00.000009Z",
            "2026-09-10T01:00:00.000001+01:00",
            "2026-09-09T20:00:00.000005-04:00",
        ),
        (
            "2026-09-10T00:00:00.000009000Z",
            "2026-09-10T00:00:00.000001000Z",
            "2026-09-10T00:00:00.000005000Z",
        ),
        (
            "2026-09-10t00:00:00.000009z",
            "2026-09-10t00:00:00.000001z",
            "2026-09-10t00:00:00.000005z",
        ),
    ],
)
def test_supported_publisher_cutoff_orders_exactly_and_preserves_literal(cutoffs: tuple[str, str, str]) -> None:
    document, binding = _publisher_cutoff_document(cutoffs)
    before = copy.deepcopy(document)
    output = refresh.regenerate(document, binding)
    manifest = output["source_manifest"]
    assert manifest["as_of"]["literal"] == cutoffs[1]
    assert manifest["as_of"]["representation"] == "rfc3339"
    assert [source["publisher_cutoff"]["literal"] for source in manifest["sources"]] == list(cutoffs)
    assert document == before


@pytest.mark.parametrize("unsupported", ["2026-09-10T00:00:00.0000001Z", "2026-09-10T00:00:00-00:00"])
@pytest.mark.parametrize("check", [False, True])
def test_unsupported_publisher_cutoff_never_opens_output(
    unsupported: str, check: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    document, binding = _publisher_cutoff_document((unsupported, "2026-09-11T00:00:00Z", "2026-09-12T00:00:00Z"))
    index = json.loads(
        (ROOT / "packages/evidentia-collectors/src/evidentia_collectors/registries/data/source-index.json").read_bytes()
    )
    # Bind the counterfactual input correctly so cutoff validation, not a hash mismatch, refuses it.
    index["snapshot_index"]["fedramp"]["tuple_input"] = binding
    source, receipt, output = (tmp_path / name for name in ("source.json", "receipt.json", "snapshot.json"))
    source.write_bytes(refresh.encode(document))
    receipt.write_bytes(refresh.encode(index))
    output.write_bytes(b"existing synthetic output")
    before = (output.read_bytes(), output.stat().st_mtime_ns, sorted(path.name for path in tmp_path.iterdir()))
    original_read = refresh._read

    def guarded_read(path: Path) -> bytes:
        if path == output:
            pytest.fail("unsupported cutoff opened existing output")
        return original_read(path)

    monkeypatch.setattr(refresh, "_read", guarded_read)
    monkeypatch.setattr(
        refresh, "_validate_fields", lambda *args, **kwargs: pytest.fail("unsupported cutoff reached projection")
    )
    monkeypatch.setattr(
        tempfile, "NamedTemporaryFile", lambda **kwargs: pytest.fail("unsupported cutoff created output")
    )
    with pytest.raises(refresh.RefreshError, match=r"^invalid_offline_registry_input$"):
        refresh.refresh_files(source, receipt, output, check=check, registry="fedramp", regenerator=refresh.regenerate)
    assert (output.read_bytes(), output.stat().st_mtime_ns, sorted(path.name for path in tmp_path.iterdir())) == before
