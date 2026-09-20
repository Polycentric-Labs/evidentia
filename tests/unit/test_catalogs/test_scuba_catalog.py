"""Independent native SCuBA counts and selected text correspondence."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

import pytest
from evidentia_core.catalogs.loader import load_catalog

DATA = Path(__file__).resolve().parents[3] / "packages/evidentia-core/src/evidentia_core/catalogs/data"
DIRECTORY = DATA / "sources/cisa-scuba-m365/7ef9501d7de9804ddb9d6013af6b665cccfb39d9"
# Exact source review order and raw digests; these are independent source inputs.
SOURCES = (
    ("aad.md", 85909, "ea0fe8dec93fa85ce580280b326b955c11aeb5fa24a18e840186bff05f58c415"),
    ("defender.md", 58801, "5718b800e9c99ac73f0196a2665ba563e36bfe0236aaf6a54a0eccbcf97f402e"),
    ("exo.md", 35917, "de6fd5151958383ecaae4f8a0d1092d5bb6d6d885d21afc8f13221dd775d80c1"),
    ("powerbi.md", 41593, "f9d22c204fdd11d53800d1da9afece03edcb05dac11878417f5042f73ea66b1f"),
    ("powerplatform.md", 29143, "e87a2d553aa0390dcce5d9e7d4a69e1cd898080cd5cf1c519e8e72e2a1cc98e5"),
    ("securitysuite.md", 76745, "55623da97cb70fbee74c0405639d14150c118e7f1446b10c4477b2b3efaf9bbf"),
    ("sharepoint.md", 18780, "7ea2f414156f2d367924f8a8d5b2267cfd39a679ae65bbfbc2327cafaac2cb10"),
    ("teams.md", 46804, "0b7d56dfea2f579face7fa94371f88a038c5e4cc7d795d6c3195c5a46dab2d6a"),
    ("ScubaBaselines.json", 880055, "25c5c6aa260a1dfa911cf18f91a715241a70fd60721d117129207630cb8349bf"),
    ("LICENSE.txt", 7048, "a2010f343487d3f7618affe54f789f5487602331c0a8d03f49e9a7c547cf0499"),
    ("scubabaselineschema.md", 9221, "341cc7f3a1ee0c7d64e8b2ebdc805ebae0dcc2778936a5c4ee486ba9268d801d"),
)


@pytest.fixture(scope="module")
def scuba_result():
    raw = []
    for name, size, digest in SOURCES:
        body = (DIRECTORY / name).read_bytes()
        assert len(body) == size and hashlib.sha256(body).hexdigest() == digest
        raw.append(body)
    catalog = load_catalog("cisa-scuba", custom_path=DATA / "cisa/scuba.json")
    result = catalog.model_dump(by_alias=True, mode="json")
    return raw, catalog, result


def ref_bytes(raw, ref):
    value = raw[ref["document_index"]][ref["byte_start"] : ref["byte_end"]]
    assert hashlib.sha256(value).hexdigest() == ref["sha256"]
    return value


def test_eight_documents_and_all_128_source_policy_identities(scuba_result):
    raw, catalog, result = scuba_result
    native = result["native_source"]["data"]
    assert [doc["raw_utf8"].encode("utf8") for doc in native["documents"]] == raw
    identities = []
    for body in raw[:8]:
        identities.extend(
            m[1].decode("ascii") for m in re.finditer(rb"(?m)^#### (MS\.[A-Z]+\.\d+(?:\.\d+)*v\d+)\r?$", body)
        )
    assert len(identities) == len(set(identities)) == 128
    assert [c["id"] for c in result["controls"]] == identities
    assert [b["control_id"] for b in native["control_bindings"]] == identities
    assert catalog.control_count == 128
    assert Counter(row["kind"] for row in native["occurrences"])["section"] == 51
    assert sum(len(re.findall(rb"(?m)^## \d+\. ", body)) for body in raw[:8]) == 51
    for row in native["occurrences"]:
        ref_bytes(raw, row["source"])
        for field in row["fields"]:
            ref_bytes(raw, field["key"])
            ref_bytes(raw, field["value"])
        for selection in row["selections"]:
            for ref in selection["value"].get("refs", []):
                ref_bytes(raw, ref)


def test_all_reference_records_preserve_original_resource_shapes_and_omissions(scuba_result):
    raw, _, result = scuba_result
    source = json.loads(raw[8])
    expected = [policy for policies in source["baselines"].values() for policy in policies]
    assert len(expected) == 127
    native = result["native_source"]["data"]
    records = [row for row in native["occurrences"] if row["kind"] == "reference_policy"]
    assert len(records) == len(expected)
    observed = [json.loads(ref_bytes(raw, row["source"])) for row in records]
    assert observed == expected
    assert Counter(type(row["resources"]).__name__ for row in expected) == {"dict": 23, "list": 104}
    assert sum("mitreMapping" not in row for row in expected) == 15
    for row, expected_record in zip(records, expected, strict=True):
        assert [field["name"] for field in row["fields"]] == list(expected_record)
        for field, (key, value) in zip(row["fields"], expected_record.items(), strict=True):
            assert json.loads(ref_bytes(raw, field["key"])) == key
            assert json.loads(ref_bytes(raw, field["value"])) == value
    by_id = {row["id"]: row for row in expected}
    for binding in native["control_bindings"]:
        policy = native["occurrences"][binding["occurrence_index"]]
        selected = policy["selections"][-1]
        assert selected["role"] == "reference_record"
        identity = binding["control_id"]
        if identity == "MS.AAD.9.1v1":
            assert identity not in by_id
            assert selected["value"] == {"state": "absent"}
            assert any(
                d["code"] == "missing_reference_record" and d["occurrence_index"] == policy["index"]
                for d in native["diagnostics"]
            )
        else:
            assert selected["value"]["state"] == "present"
            assert len(selected["value"]["refs"]) == 1
            assert json.loads(ref_bytes(raw, selected["value"]["refs"][0])) == by_id[identity]


def test_criticality_conflict_and_every_policy_note_remain_explicit(scuba_result):
    raw, _, result = scuba_result
    native = result["native_source"]["data"]
    notes = 0
    policies_with_notes = 0
    for binding in native["control_bindings"]:
        policy = native["occurrences"][binding["occurrence_index"]]
        selections = {s["role"]: s["value"] for s in policy["selections"]}
        note_refs = selections["note"].get("refs", [])
        notes += len(note_refs)
        policies_with_notes += bool(note_refs)
        source = ref_bytes(raw, policy["source"])
        assert len(re.findall(rb"(?m)^(?:[-*][ \t]+(?:_Note:_|_Note_:|Note:)|>[ \t]*Note:)", source)) == len(note_refs)
        statement = (
            ref_bytes(raw, selections["statement"]["refs"][0]).decode("utf8").replace("\r\n", "\n").strip(" \t\r\n")
        )
        control = next(c for c in result["controls"] if c["id"] == binding["control_id"])
        expected_description = "Statement:\n" + statement
        for ref in note_refs:
            expected_description += "\n\nNote:\n" + ref_bytes(raw, ref).decode("utf8").replace("\r\n", "\n").strip(
                " \t\r\n"
            )
        assert control["description"] == expected_description
        if binding["control_id"] == "MS.SECURITYSUITE.7.2v1":
            assert binding["admitted_criticality"] is None
            assert ref_bytes(raw, selections["criticality_identity"]["refs"][0]) == b"MS.SECURITYSUITE.15.2v1"
            assert ref_bytes(raw, selections["criticality"]["refs"][0]) == b"SHOULD"
            assert any(
                d["code"] == "source_identity_conflict" and d["occurrence_index"] == policy["index"]
                for d in native["diagnostics"]
            )
    assert (notes, policies_with_notes) == (54, 52)


def test_complete_native_serialization_keeps_capture_after_same_length_model_mutation(scuba_result, monkeypatch):
    from evidentia_core.catalogs import open_corpora as source

    _, catalog, expected = scuba_result
    original = source.validate_catalog_mapping
    title = catalog.framework_name

    def mutate_after_verification(data):
        wire = original(data)
        object.__getattribute__(catalog, "__dict__")["framework_name"] = "X" + title[1:]
        return wire

    monkeypatch.setattr(source, "validate_catalog_mapping", mutate_after_verification)
    try:
        assert catalog.model_dump(by_alias=True, mode="json") == expected
    finally:
        object.__getattribute__(catalog, "__dict__")["framework_name"] = title


def test_complete_native_wire_requires_explicit_mode_and_retains_source(scuba_result, tmp_path, monkeypatch):
    from evidentia_core.catalogs import loader

    raw, _, result = scuba_result
    wire = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    source = tmp_path / "native.json"
    source.write_bytes(wire)
    # The expected source documents and 128 policy identities are independently
    # checked above. This case exercises the new file-admission boundary.
    with monkeypatch.context() as context:
        context.setattr(Path, "read_text", lambda *a, **k: pytest.fail("legacy read reached"))
        loaded = loader.load_native_wire_catalog(source)
    assert loaded.control_count == 128
    assert [doc.raw_utf8.encode("utf8") for doc in loaded.native_source.data.documents] == raw
    duplicate = wire[:-1] + b',"framework_name":' + json.dumps(result["framework_name"]).encode("ascii") + b"}"
    source.write_bytes(duplicate)
    for invoke in (
        lambda: loader.load_native_wire_catalog(source),
        lambda: loader.load_evidentia_catalog(source),
        lambda: loader.load_catalog("cisa-scuba", custom_path=source),
        lambda: loader.load_any_catalog("cisa-scuba", custom_path=source),
    ):
        with pytest.raises(ValueError, match="native_source_invalid"):
            invoke()


@pytest.mark.parametrize("change", ["parent", "ordinal", "span-kind", "span-hash", "projection", "cross-control"])
def test_complete_native_catalog_refuses_rehashed_authority_tampering(scuba_result, change):
    import copy

    from evidentia_core.models.catalog import _NativeControlCatalog

    _, _, original = scuba_result
    data = copy.deepcopy(original)
    bundle = data["native_source"]
    native = bundle["data"]
    original_compact = json.dumps(native, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    assert hashlib.sha256(b"evidentia.catalog-native.v1\0" + original_compact).hexdigest() == bundle["bundle_sha256"]
    row = native["occurrences"][native["control_bindings"][0]["occurrence_index"]]
    if change == "parent":
        row["parent_index"] = None
    elif change == "ordinal":
        row["sibling_ordinal"] += 1
    elif change == "span-kind":
        row["source"]["kind"] = "json_string"
    elif change == "span-hash":
        row["source"]["sha256"] = "0" * 64
    elif change == "projection":
        data["controls"][0]["description"] += "changed"
    else:
        data["controls"][0]["native_source_ref"] = copy.deepcopy(data["controls"][1]["native_source_ref"])
    # Recompute the documented digest independently so these cases require
    # source/projection authority, not merely a stale digest rejection.
    compact = json.dumps(native, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    bundle["bundle_sha256"] = hashlib.sha256(b"evidentia.catalog-native.v1\0" + compact).hexdigest()
    with pytest.raises(ValueError, match="native_source_invalid"):
        _NativeControlCatalog.model_validate(data)
