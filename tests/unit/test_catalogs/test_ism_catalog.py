"""Source-derived ISM correspondence; expected values never come from the converter."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from evidentia_core.catalogs.loader import load_catalog

DATA = Path(__file__).resolve().parents[3] / "packages/evidentia-core/src/evidentia_core/catalogs/data"
ISM_DIRECTORY = DATA / "sources/au-ism/2026.09.4"
ISM_RAW_SHA = "237ea09362b8449ed5c5ee85de4725a0468ee73d13af7cf61c26d4e6ac47f12d"
ISM_PARTS = (
    (1711308, "717617f753da6f1a9f498a3b5429d08297cf5519109790608968a9133678483c", 0, 1572849),
    (1186531, "1ac6adfa444cd624f5bed6c87dcf668d7a9863f674df966e529a39946c356426", 1572849, 1104899),
)


def source_bytes():
    pieces = []
    for index, (size, digest, start, count) in enumerate(ISM_PARTS):
        stored = (ISM_DIRECTORY / f"ISM_catalog.part-{index:03d}.json").read_bytes()
        assert len(stored) == size
        assert hashlib.sha256(stored).hexdigest() == digest
        assert stored.endswith(b"\n")
        envelope = json.loads(stored)
        assert envelope["index"] == index
        assert envelope["byte_start"] == start
        raw = envelope["raw_utf8"].encode("utf-8")
        assert len(raw) == envelope["byte_length"] == count
        assert hashlib.sha256(raw).hexdigest() == envelope["sha256"]
        pieces.append(raw)
    raw = b"".join(pieces)
    assert len(raw) == 2677748
    assert hashlib.sha256(raw).hexdigest() == ISM_RAW_SHA
    assert not raw.endswith(b"\n")
    return raw


def source_occurrences(raw, *, ism):
    """Traverse native JSON member order independently of the production token graph."""
    catalog = json.loads(raw)["catalog"]
    rows = [("catalog", None, catalog), ("metadata", 0, catalog["metadata"])]

    def descend(owner, parent):
        for member, items in owner.items():
            if member not in {"groups", "controls"}:
                continue
            for item in items:
                kind = "group" if member == "groups" else "control"
                if ism and item.get("class") == "ISM-principle":
                    kind = "principle"
                index = len(rows)
                rows.append((kind, parent, item))
                descend(item, index)

    descend(catalog, 0)
    return rows


def decoded_ref(raw, ref):
    assert ref["document_index"] == 0
    assert type(ref["byte_start"]) is int and type(ref["byte_end"]) is int
    value = raw[ref["byte_start"] : ref["byte_end"]]
    assert hashlib.sha256(value).hexdigest() == ref["sha256"]
    return json.loads(value)


def assert_oscal_correspondence(raw, native, *, ism):
    """Check complete source owners, direct fields, order and whole parameter references."""
    expected = source_occurrences(raw, ism=ism)
    observed = [row for row in native["occurrences"] if row["source"]["document_index"] == 0]
    assert len(observed) == len(expected)
    ordinals = Counter()
    for index, ((kind, parent, owner), occurrence) in enumerate(zip(expected, observed, strict=True)):
        assert occurrence["index"] == index
        assert occurrence["kind"] == kind
        assert occurrence["parent_index"] == parent
        assert occurrence["sibling_ordinal"] == ordinals[parent]
        ordinals[parent] += 1
        assert decoded_ref(raw, occurrence["source"]) == owner
        assert [field["name"] for field in occurrence["fields"]] == list(owner)
        previous = -1
        for field, (key, value) in zip(occurrence["fields"], owner.items(), strict=True):
            assert field["key"]["byte_start"] > previous
            previous = field["key"]["byte_start"]
            assert decoded_ref(raw, field["key"]) == key
            assert decoded_ref(raw, field["value"]) == value
        selected = {row["role"]: row["value"] for row in occurrence["selections"]}
        if kind in {"group", "control", "principle"}:
            if "params" not in owner:
                assert selected["parameter"] == {"state": "absent"}
            else:
                field = next(field for field in occurrence["fields"] if field["name"] == "params")
                assert selected["parameter"] == {
                    "state": "native_null" if owner["params"] is None else "present",
                    "refs": [field["value"]],
                }
            for role, prop_name in (
                ("applicability", "applicability"),
                ("essential_eight_applicability", "essential-eight-applicability"),
            ):
                props = [p for p in owner.get("props", []) if p["name"] == prop_name]
                actual = [decoded_ref(raw, ref) for ref in selected[role].get("refs", [])]
                assert actual == props
    return expected


@pytest.fixture(scope="module")
def ism_result():
    raw = source_bytes()
    catalog = load_catalog("au-ism", custom_path=DATA / "international/au-ism.json")
    result = catalog.model_dump(by_alias=True, mode="json")
    return raw, catalog, result


def test_complete_pinned_ism_source_graph_and_assessed_denominator(ism_result):
    raw, catalog, result = ism_result
    native = result["native_source"]["data"]
    assert native["documents"][0]["raw_utf8"].encode("utf-8") == raw
    rows = assert_oscal_correspondence(raw, native, ism=True)
    assert Counter(kind for kind, _, _ in rows) == {
        "catalog": 1,
        "metadata": 1,
        "group": 582,
        "control": 1143,
        "principle": 49,
    }
    assessed = [owner["id"] for kind, _, owner in rows if kind == "control"]
    principles = {owner["id"] for kind, _, owner in rows if kind == "principle"}
    assert [row["control_id"] for row in native["control_bindings"]] == assessed
    assert catalog.control_count == 1143
    assert all(catalog.get_control(identity) is not None for identity in assessed)
    assert all(catalog.get_control(identity) is None for identity in principles)
    props = Counter(p["name"] for _, _, owner in rows for p in owner.get("props", []))
    assert props["applicability"] == 5511
    assert props["essential-eight-applicability"] == 256


def test_ism_context_identity_and_bundle_digest_are_source_bound(ism_result):
    _, _, result = ism_result
    bundle = result["native_source"]
    native = bundle["data"]
    compact = json.dumps(native, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")
    assert hashlib.sha256(b"evidentia.catalog-native.v1\x00" + compact).hexdigest() == bundle["bundle_sha256"]
    assert set(native["context_indices"]) == {
        r["index"] for r in native["occurrences"] if r["kind"] not in {"control", "policy"}
    }
    for binding, control in zip(native["control_bindings"], result["controls"], strict=True):
        assert control["native_source_ref"] == {
            "bundle_sha256": bundle["bundle_sha256"],
            "occurrence_index": binding["occurrence_index"],
        }
    migration = json.loads((ISM_DIRECTORY / "legacy-ids.json").read_bytes())
    assert len(migration["rows"]) == 24
    assert {row["status"] for row in migration["rows"]} == {"retired_heading"}
    assert all(row["replacement_ids"] == [] for row in migration["rows"])
    assert {r["code"] for r in native["diagnostics"]} == {"legacy_ids_retired"}
