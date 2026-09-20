"""Independent bounded native parser controls; legacy dispatch remains separate."""

from __future__ import annotations

import hashlib
import json

import pytest
from evidentia_core.catalogs.loader import _load_catalog_data


def _entrypoint_ref() -> dict[str, object]:
    return {"document_index": 0, "byte_start": 0, "byte_end": 1, "kind": "json_string", "sha256": "0" * 64}


@pytest.mark.parametrize("adapter", [False, True])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("extra", ["forbid", "ignore", "allow"])
@pytest.mark.parametrize("change", ["extra", "missing"])
def test_native_model_entrypoint_keys_remain_closed(adapter, nested, extra, change):
    from evidentia_core.models.open_corpora import FieldRef, ValueRef
    from pydantic import TypeAdapter

    value = _entrypoint_ref()
    if change == "extra":
        value["unexpected"] = 1
    else:
        del value["document_index"]
    subject = FieldRef if nested else ValueRef
    data = {"name": "x", "key": _entrypoint_ref(), "value": value} if nested else value
    validate = TypeAdapter(subject).validate_python if adapter else subject.model_validate
    with pytest.raises(ValueError, match="native_source_invalid"):
        validate(data, extra=extra, strict=False)


@pytest.mark.parametrize("adapter", [False, True])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("value", [True, "0", 0.0])
def test_native_model_entrypoint_scalar_types_ignore_coercion_options(adapter, nested, value):
    from evidentia_core.models.open_corpora import FieldRef, ValueRef
    from pydantic import TypeAdapter

    ref = {**_entrypoint_ref(), "document_index": value}
    subject = FieldRef if nested else ValueRef
    data = {"name": "x", "key": _entrypoint_ref(), "value": ref} if nested else ref
    validate = TypeAdapter(subject).validate_python if adapter else subject.model_validate
    with pytest.raises(ValueError, match="native_source_invalid"):
        validate(data, extra="ignore", strict=False)


@pytest.mark.parametrize("adapter", [False, True])
@pytest.mark.parametrize("spelling", ["ordinary", "duplicate", "escaped_duplicate"])
def test_native_model_entrypoint_refuses_lossy_json_mode(adapter, spelling):
    from evidentia_core.models.open_corpora import ValueRef
    from pydantic import TypeAdapter

    wire = json.dumps(_entrypoint_ref(), separators=(",", ":")).encode()
    if spelling == "duplicate":
        wire = wire.replace(b'"document_index":0', b'"document_index":false,"document_index":0')
    elif spelling == "escaped_duplicate":
        wire = wire.replace(b'"document_index":0', b'"document_index":false,"document_\\u0069ndex":0')
    validate = TypeAdapter(ValueRef).validate_json if adapter else ValueRef.model_validate_json
    with pytest.raises(ValueError, match="native_source_invalid"):
        validate(wire, strict=False, extra="ignore")
    if spelling != "ordinary":
        with pytest.raises(ValueError, match="native_source_invalid"):
            _load_catalog_data(None, raw_bytes=wire, mode="wire_json")


def test_native_model_entrypoint_checks_the_owned_mapping_capture(monkeypatch):
    from evidentia_core.models import open_corpora as models

    data = _entrypoint_ref()
    original_rules = models._NATIVE_FIELD_RULES[id(models.ValueRef)]

    class InterveningChange(dict):
        def get(self, name, default=None):
            rule = super().get(name, default)
            if name == "document_index":
                data["document_index"] = "7"
            return rule

    monkeypatch.setitem(models._NATIVE_FIELD_RULES, id(models.ValueRef), InterveningChange(original_rules))
    value = models.ValueRef.model_validate(data, strict=False)
    assert value.document_index == 0
    assert data["document_index"] == "7"


@pytest.mark.parametrize("item", [True, "0", 0.0])
def test_native_model_entrypoint_integer_array_is_checked_before_correspondence(monkeypatch, item):
    from evidentia_core.models import open_corpora as models

    def correspondence_must_not_run(_value):
        raise AssertionError("invalid native field reached source correspondence")

    monkeypatch.setattr(models.NativeData, "_source_correspondence", correspondence_must_not_run)
    data = {
        "schema_version": "catalog-native-v1",
        "profile": "au-ism-2026.09.4",
        "catalog_id": "au-ism",
        "converter_id": "evidentia-open-corpora-v1",
        "converter_sha256": "0" * 64,
        "documents": [],
        "occurrences": [],
        "control_bindings": [],
        "context_indices": [item],
        "diagnostics": [],
    }
    with pytest.raises(ValueError, match="native_source_invalid"):
        models.NativeData.model_validate(data, strict=False)


def _publication_observation(cleanup_errors: list[str]) -> dict[str, object]:
    return {
        "schema_version": "catalog-publication-observation-v1",
        "operation": "native_import",
        "publication_state": "not_attempted",
        "prior_manifest_state": "unread",
        "prior_sha256": None,
        "proposed_sha256": None,
        "replace_outcome": "not_called",
        "observed_manifest_state": "not_observed",
        "observed_sha256": None,
        "readback_result": "not_attempted",
        "cleanup_state": "failed" if cleanup_errors else "complete",
        "cleanup_errors": cleanup_errors,
        "failure_phase": "cleanup" if cleanup_errors else "admission",
        "primary_kind": "exception",
        "error_code": "catalog_cleanup_failed" if cleanup_errors else "catalog_storage_failed",
    }


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize(
    "codes",
    [
        [],
        ["temporary_cleanup_failed"],
        ["lock_release_failed", "temporary_cleanup_failed", "handle_close_failed"],
    ],
)
def test_native_model_entrypoint_preserves_distinct_cleanup_order(nested, codes):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation, CatalogStorageErrorEnvelope

    publication = _publication_observation(codes)
    subject = CatalogStorageErrorEnvelope if nested else CatalogPublicationObservation
    data = {"code": publication["error_code"], "publication": publication} if nested else publication
    value = subject.model_validate(data, strict=False, extra="ignore")
    assert value.model_dump(mode="json") == data
    assert value.model_copy().model_dump(mode="json") == data


@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("code", ["temporary_cleanup_failed", "handle_close_failed", "lock_release_failed"])
def test_native_model_entrypoint_refuses_duplicate_cleanup_codes(nested, code):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation, CatalogStorageErrorEnvelope

    publication = _publication_observation([code, code])
    subject = CatalogStorageErrorEnvelope if nested else CatalogPublicationObservation
    data = {"code": publication["error_code"], "publication": publication} if nested else publication
    with pytest.raises(ValueError, match="native_source_invalid"):
        subject.model_validate(data, strict=False, extra="allow")


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_native_model_entrypoint_cleanup_uniqueness_schema(mode):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation, CatalogStorageErrorEnvelope

    direct = CatalogPublicationObservation.model_json_schema(mode=mode)
    envelope = CatalogStorageErrorEnvelope.model_json_schema(mode=mode)
    definition = envelope["$defs"][envelope["properties"]["publication"]["$ref"].rsplit("/", 1)[1]]
    for schema in (direct, definition):
        rules = schema["properties"]["cleanup_errors"]
        assert rules["uniqueItems"] is True
        assert rules["maxItems"] == 3
        assert rules["items"]["enum"] == ["temporary_cleanup_failed", "handle_close_failed", "lock_release_failed"]


def test_native_source_keeps_exact_utf8_tokens_and_lexical_numbers() -> None:
    raw = '{"é":"a\\u0062","n":123456789012345678901234567890,"null":null}'.encode()
    parsed = _load_catalog_data(None, raw_bytes=raw, mode="source_json")
    assert parsed.raw == raw
    assert parsed.data["é"] == "ab"
    assert parsed.data["n"].lexeme == "123456789012345678901234567890"
    assert parsed.data["null"] is None
    assert raw[parsed.root.members[0][0].start : parsed.root.members[0][0].end] == '"é"'.encode()
    assert raw[parsed.root.members[0][1].start : parsed.root.members[0][1].end] == b'"a\\u0062"'


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"\\u0061":2}',
        b'{"a":{"x":1,"x":2}}',
        b'{"a":NaN}',
        b'{"a":01}',
        b'{"a":"\\ud800"}',
        b'{"a":true}false',
        b"[]",
    ],
)
def test_native_source_rejects_ambiguous_or_invalid_json(raw: bytes) -> None:
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=raw, mode="source_json")


def test_native_source_exact_scalar_limit_and_one_over() -> None:
    accepted = b'{"x":"' + b"a" * 262144 + b'"}'
    parsed = _load_catalog_data(None, raw_bytes=accepted, mode="source_json")
    assert len(parsed.data["x"].encode()) == 262144
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=b'{"x":"' + b"a" * 262145 + b'"}', mode="source_json")


def test_native_source_object_member_limit() -> None:
    accepted = ("{" + ",".join(f'"k{i}":null' for i in range(64)) + "}").encode()
    assert len(_load_catalog_data(None, raw_bytes=accepted, mode="source_json").data) == 64
    refused = ("{" + ",".join(f'"k{i}":null' for i in range(65)) + "}").encode()
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=refused, mode="source_json")


def test_native_source_rejects_non_native_bytes_without_callbacks() -> None:
    class Hostile(bytes):
        def decode(self, *args, **kwargs):
            raise AssertionError("caller callback")

    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=Hostile(b"{}"), mode="source_json")


def test_source_reference_requires_a_nonempty_forward_span():
    from evidentia_core.models.open_corpora import ValueRef

    value = dict(document_index=0, byte_start=3, byte_end=3, kind="utf8_text", sha256="0" * 64)
    with pytest.raises(ValueError, match="native_source_invalid"):
        ValueRef.model_validate(value)


@pytest.mark.parametrize("state,kind", [("native_null", "json_string"), ("present", "json_null")])
def test_selection_state_matches_native_token(state, kind):
    from evidentia_core.models.open_corpora import FieldSelection
    from pydantic import TypeAdapter

    value = dict(document_index=0, byte_start=0, byte_end=4, kind=kind, sha256="0" * 64)
    with pytest.raises(ValueError):
        TypeAdapter(FieldSelection).validate_python({"state": state, "refs": [value]})


def test_source_document_checks_exact_raw_length_and_hash():
    from evidentia_core.models.open_corpora import SourceDocument

    binding = dict(
        source_key="synthetic",
        role="publication_context",
        media_type="text/plain",
        repository="synthetic/local",
        commit="0" * 40,
        upstream_path="sample.txt",
        raw_bytes=1,
        raw_sha256=hashlib.sha256(b"x").hexdigest(),
    )
    with pytest.raises(ValueError, match="native_source_invalid"):
        SourceDocument.model_validate({"binding": binding, "raw_utf8": "y"})


def test_native_refs_reject_aliases_callbacks_and_construct_bypass():
    from evidentia_core.models.open_corpora import FieldRef, ValueRef

    ref = dict(document_index=0, byte_start=0, byte_end=1, kind="utf8_text", sha256="0" * 64)
    with pytest.raises(ValueError, match="native_source_invalid"):
        FieldRef.model_validate({"name": "x", "key": ref, "value": ref})
    broken = ValueRef.model_construct(**{**ref, "byte_end": 0})
    with pytest.raises((ValueError, TypeError), match="native_source_invalid"):
        broken.model_dump_json()


def test_native_model_preserves_spaces_and_detaches_updates():
    from evidentia_core.models.open_corpora import SourceDocument, native_value

    raw = b" \tlocal\n "
    binding = dict(
        source_key="synthetic",
        role="publication_context",
        media_type="text/plain",
        repository="synthetic/local",
        commit="0" * 40,
        upstream_path="sample.txt",
        raw_bytes=len(raw),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )
    value = SourceDocument.model_validate({"binding": binding, "raw_utf8": raw.decode()})
    binding["raw_bytes"] = 0
    assert value.raw_utf8.encode() == raw
    assert native_value(value)["binding"]["raw_bytes"] == len(raw)
    with pytest.raises(ValueError):
        value.model_copy(update={"raw_utf8": "changed"})


def test_hand_derived_oscal_parts_keep_every_paragraph_in_order():
    from evidentia_core.catalogs.open_corpora import _members, _part_prose, _parts

    raw = b'{"parts":[{"name":"statement","prose":" first ","parts":[{"name":"item","prose":"second"}]},{"name":"guidance","prose":"guide"},{"name":"statement","prose":"third"}]}'
    root = _load_catalog_data(None, raw_bytes=raw, mode="source_json").root
    parts = _members(root)["parts"].items
    assert [text for part in _parts(parts, "statement") for text in _part_prose(part)] == [" first ", "second", "third"]
    assert [_part_prose(part) for part in _parts(parts, "guidance")] == [["guide"]]


def test_markdown_heading_scanner_keeps_fences_and_pre_inert():
    from evidentia_core.catalogs.open_corpora import _headings
    from evidentia_core.models.open_corpora import NativeBudget

    raw = (
        b"# Synthetic\n## 1. Section\n"
        + bytes((96,)) * 3
        + b"text\n#### MS.AAD.1.1v1\n"
        + bytes((96,)) * 3
        + b"\n<pre>\n#### MS.AAD.2.1v1\n</pre>\n#### MS.AAD.3.1v1\nBody\n"
    )
    headings = _headings(raw, NativeBudget())
    assert [h.title for h in headings] == ["Synthetic", "1. Section", "MS.AAD.3.1v1"]
    assert raw[headings[-1].title_start : headings[-1].title_end] == b"MS.AAD.3.1v1"


def test_native_profile_rejects_unrecognized_hash_before_parser(monkeypatch):
    from evidentia_core.catalogs import open_corpora as module

    calls = []
    monkeypatch.setattr(module, "_load_catalog_data", lambda *a, **k: calls.append(True))
    with pytest.raises(ValueError, match="native_source_invalid"):
        module.derive_native_catalog("au-ism-2026.09.4", {"ISM_catalog.json": b"{}", "README.md": b"x"})
    assert calls == []


def test_wire_node_domain_excludes_objects_and_keys():
    from evidentia_core.catalogs.loader import _NativeCatalogParser
    from evidentia_core.models.open_corpora import NativeBudget

    parser = _NativeCatalogParser(b'{"a":{"b":[{},null]}}', "wire_json", NativeBudget())
    parser.node_limit = 2
    assert parser.parse().data == {"a": {"b": [{}, None]}}
    assert parser.nodes == 2
    source = _NativeCatalogParser(b'{"a":{"b":[{},null]}}', "source_json", NativeBudget())
    source.node_limit = 2
    with pytest.raises(ValueError, match="native_source_invalid"):
        source.parse()


def test_wire_primitive_array_exact_limit_and_one_over():
    raw = b'{"a":[' + b"null," * 262142 + b"null]}"
    parsed = _load_catalog_data(None, raw_bytes=raw, mode="wire_json")
    assert len(parsed.data["a"]) == 262143
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=raw[:-2] + b",null]}", mode="wire_json")


@pytest.mark.parametrize("case", ["reparse", "changed"])
def test_native_file_refuses_reparse_or_read_drift(tmp_path, monkeypatch, case):
    import os
    from pathlib import Path
    from types import SimpleNamespace

    from evidentia_core.catalogs import loader
    from evidentia_core.models.open_corpora import NativeBudget

    target = tmp_path / "source.json"
    target.write_bytes(b'{"x":1}')
    if case == "reparse":
        original = type(target).lstat

        def changed_stat(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if Path(path) == target:
                return SimpleNamespace(st_mode=result.st_mode, st_file_attributes=1024)
            return result

        monkeypatch.setattr(type(target), "lstat", changed_stat)
    else:
        original_read = os.read
        initial = target.stat()
        changed = False

        def change_read(fd, count):
            nonlocal changed
            result = original_read(fd, count)
            if not changed:
                changed = True
                target.write_bytes(b'{"x":2}')
                # Force visible metadata drift independently of clock granularity.
                os.utime(target, ns=(initial.st_atime_ns, initial.st_mtime_ns + 2_000_000_000))
                assert target.stat().st_mtime_ns != initial.st_mtime_ns
            return result

        monkeypatch.setattr(os, "read", change_read)
    with pytest.raises(ValueError, match="native_source_invalid"):
        loader._read_native_catalog(target, 32, NativeBudget())


def test_native_file_preserves_primary_base_exception_on_close(tmp_path, monkeypatch):
    import os

    from evidentia_core.catalogs import loader
    from evidentia_core.models.open_corpora import NativeBudget

    target = tmp_path / "source.json"
    target.write_bytes(b"{}")
    primary = KeyboardInterrupt("synthetic primary")
    secondary = SystemExit("synthetic cleanup")

    def failed_read(fd, count):
        raise primary

    original_close = os.close

    def failed_close(fd):
        original_close(fd)
        raise secondary

    monkeypatch.setattr(os, "read", failed_read)
    monkeypatch.setattr(os, "close", failed_close)
    with pytest.raises(KeyboardInterrupt) as captured:
        loader._read_native_catalog(target, 32, NativeBudget())
    assert captured.value is primary
    assert captured.value.__cause__ is secondary


def test_native_file_exact_ceiling_and_one_over(tmp_path):
    from evidentia_core.catalogs import loader
    from evidentia_core.models.open_corpora import NativeBudget

    target = tmp_path / "source.json"
    target.write_bytes(b"x" * 32)
    assert loader._read_native_catalog(target, 32, NativeBudget()) == b"x" * 32
    target.write_bytes(b"x" * 33)
    with pytest.raises(ValueError, match="native_source_invalid"):
        loader._read_native_catalog(target, 32, NativeBudget())


@pytest.mark.parametrize(
    "member,state,kind",
    [
        (b"", "absent", None),
        (b',"params":null', "native_null", "json_null"),
        (b',"params":[]', "present", "json_array"),
        (b',"params":{}', "present", "json_object"),
        (b',"params":false', "present", "json_boolean"),
        (b',"params":0', "present", "json_number"),
        (b',"params":""', "present", "json_string"),
    ],
)
def test_parameter_role_selects_the_complete_direct_native_field(member, state, kind):
    from evidentia_core.catalogs.open_corpora import _Graph, _oscal
    from evidentia_core.models.open_corpora import NativeBudget

    raw = (
        b'{"catalog":{"metadata":{"title":"Synthetic","version":"1"},"controls":['
        b'{"id":"synthetic-1","title":"Synthetic"' + member + b"}]}}"
    )
    graph = _Graph((raw,), NativeBudget())
    try:
        # A single independently authored control does not claim the frozen
        # complete publisher count; inspect the emitted field before that refusal.
        with pytest.raises(ValueError, match="native_source_invalid"):
            _oscal(graph, "bsi-grundschutz-plus-plus-367d7750")
        occurrence = graph.occurrences[2]
        selected = next(row["value"] for row in occurrence["selections"] if row["role"] == "parameter")
        assert selected["state"] == state
        if kind is None:
            assert selected == {"state": "absent"}
        else:
            field = next(row for row in occurrence["fields"] if row["name"] == "params")
            assert selected["refs"] == [field["value"]]
            assert selected["refs"][0]["kind"] == kind
            assert raw[field["value"]["byte_start"] : field["value"]["byte_end"]] == member.split(b":", 1)[1]
    finally:
        graph.clear()


@pytest.mark.parametrize("note_label", [b"- _Note:_", b"- _Note_:", b"- Note:", b"> Note:"])
def test_markdown_policy_fields_keep_original_badge_and_repeated_label_order(note_label):
    from evidentia_core.catalogs.open_corpora import _Graph, _headings, _markdown_policy
    from evidentia_core.models.open_corpora import NativeBudget

    raw = (
        b"## 1. Synthetic\n### Policies\n#### MS.AAD.1.1v1\nStatement.\n"
        b"[![Badge](inert-image)](inert-link)\n<!--Policy: MS.AAD.1.1v1; Criticality: SHALL -->\n"
        b"- _Rationale:_ First.\n- _Note:_ One.\n- _Note:_ Two.\n"
        b"### Resources\nResources.\n### License Requirements\nNone.\n"
        b"### Implementation\nIntro.\n#### MS.AAD.1.1v1 Instructions\nInstructions.\n"
    )
    raw = raw.replace(b"- _Note:_", note_label)
    budget = NativeBudget()
    graph = _Graph((raw,), budget)
    headings = _headings(raw, budget)
    section, _, policy = headings[:3]
    graph.add(0, "section", None, graph.ref(0, 0, len(raw), "markdown_block"), [], [])
    try:
        ordinary, _ = _markdown_policy(graph, 0, policy, section, 0, headings)
        fields = graph.occurrences[1]["fields"]
        assert [field["name"] for field in fields] == ["MS.AAD.1.1v1", "Badge", "Rationale", "Note", "Note"]
        assert [field["key"]["byte_start"] for field in fields] == sorted(
            field["key"]["byte_start"] for field in fields
        )
        assert ordinary["description"] == "Statement:\nStatement.\n\nNote:\nOne.\n\nNote:\nTwo."
        assert (
            ordinary["guidance"]
            == "Rationale:\nFirst.\n\nShared implementation:\nIntro.\n\nInstructions:\nInstructions.\n\nLicense Requirements:\nNone.\n\nResources:\nResources."
        )
    finally:
        graph.clear()


def test_snapshot_catalog_has_one_outer_budget_for_wire_and_model(monkeypatch):
    from evidentia_core.catalogs import open_corpora as source_module
    from evidentia_core.catalogs.open_corpora import NativeCatalogSnapshot
    from evidentia_core.models.catalog import _NativeControlCatalog
    from evidentia_core.models.open_corpora import _ACTIVE_BUDGET

    observed = []
    marker = object()

    def data(raw):
        observed.append(_ACTIVE_BUDGET.get())
        return {"native_source": {}}

    def validate(value):
        observed.append(_ACTIVE_BUDGET.get())
        return marker

    monkeypatch.setattr(source_module, "_decode", data)
    monkeypatch.setattr(_NativeControlCatalog, "model_validate", validate)
    assert NativeCatalogSnapshot(b"{}", "0" * 64, "0" * 64).catalog() is marker
    assert observed[0] is not None
    assert observed[0] is observed[1]


def test_final_verification_reserve_keeps_original_deadline(monkeypatch):
    from evidentia_core.models import open_corpora as model

    now = [0.0]
    monkeypatch.setattr(model.time, "monotonic", lambda: now[0])
    with model.native_operation() as budget:
        original = budget._deadline
        now[0] = 49.0
        with budget.publication():
            now[0] = 55.0
            with model.native_operation() as nested:
                assert nested is budget
                assert nested._deadline == original == 60.0
                nested.check()
            now[0] = 60.0
            with pytest.raises(ValueError, match="processing_deadline_exceeded"):
                budget.check()
            now[0] = 59.0
        with pytest.raises(ValueError, match="processing_deadline_exceeded"):
            budget.check()
        assert budget._deadline == original


@pytest.mark.parametrize("text", ["", "plain", '"\\\b\f\n\r\t\x00', "é", "\U0001f600", " \r\n "])
def test_canonical_string_size_matches_independent_stdlib(text):
    import json

    from evidentia_core.models.open_corpora import _json_string_bytes

    assert _json_string_bytes(text) == len(json.dumps(text, ensure_ascii=True).encode("ascii"))


def test_canonical_size_refuses_escape_expansion_before_encoding():
    from evidentia_core.models.open_corpora import _preflight

    with pytest.raises(ValueError, match="native_source_invalid"):
        _preflight({"raw_utf8": "\x00" * 3_000_000})


@pytest.mark.parametrize("failure_point", ["open", "iterate", "close"])
def test_closed_directory_enumeration_never_accepts_partial_or_unreadable_listing(tmp_path, monkeypatch, failure_point):
    import os
    from types import SimpleNamespace

    from evidentia_core.catalogs.open_corpora import _directory_names
    from evidentia_core.models.open_corpora import NativeBudget

    refusal = PermissionError("synthetic inaccessible entry")

    class Entries:
        def __iter__(self):
            yield SimpleNamespace(name="visible.json")
            if failure_point == "iterate":
                raise refusal

        def close(self):
            if failure_point == "close":
                raise refusal

    def scan(path):
        if failure_point == "open":
            raise refusal
        return Entries()

    monkeypatch.setattr(os, "scandir", scan)
    with pytest.raises(PermissionError) as caught:
        _directory_names(tmp_path, 2, NativeBudget())
    assert caught.value is refusal


def test_closed_directory_preserves_primary_interruption_during_cleanup(tmp_path, monkeypatch):
    import os
    from types import SimpleNamespace

    from evidentia_core.catalogs.open_corpora import _directory_names
    from evidentia_core.models.open_corpora import NativeBudget

    primary = KeyboardInterrupt("synthetic enumeration cancellation")
    cleanup = OSError("synthetic close failure")

    class Entries:
        def __iter__(self):
            yield SimpleNamespace(name="visible.json")
            raise primary

        def close(self):
            raise cleanup

    monkeypatch.setattr(os, "scandir", lambda path: Entries())
    with pytest.raises(KeyboardInterrupt) as caught:
        _directory_names(tmp_path, 2, NativeBudget())
    assert caught.value is primary
    assert caught.value.__cause__ is cleanup


def test_native_catalog_serializer_returns_capture_without_later_live_read(monkeypatch):
    import json

    from evidentia_core.catalogs import open_corpora as source
    from evidentia_core.models.catalog import ControlCatalog

    model = ControlCatalog.model_construct(
        framework_id="synthetic", framework_name="Before", version="1", controls=[], native_source={}
    )
    captured = {"framework_name": "Before", "native_source": {}}
    monkeypatch.setattr(source, "catalog_model_data", lambda value: dict(captured))

    def verified(mapping):
        wire = json.dumps(mapping, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode()
        object.__getattribute__(model, "__dict__")["framework_name"] = "After!"
        return wire

    monkeypatch.setattr(source, "validate_catalog_mapping", verified)
    calls = []

    def forbidden_live_handler(value):
        calls.append(value)
        return {"framework_name": value.framework_name}

    assert model.validate_native_catalog_output(forbidden_live_handler) == captured
    assert calls == []


def test_native_compact_clears_owned_mapping_on_encoder_interruption(monkeypatch):
    from evidentia_core.models import open_corpora as model

    value = model.ValueRef.model_validate(
        {"document_index": 0, "byte_start": 0, "byte_end": 1, "kind": "utf8_text", "sha256": "0" * 64}
    )
    captured = []
    primary = KeyboardInterrupt("synthetic encoder interruption")

    def encode(data, **kwargs):
        captured.append(data)
        raise primary

    monkeypatch.setattr(model.json, "dumps", encode)
    with pytest.raises(KeyboardInterrupt) as caught:
        model.native_compact(value)
    assert caught.value is primary
    assert captured == [{}]


@pytest.mark.parametrize("codepoint", [0x00A0, 0x202F, 0x00AD])
def test_native_source_keeps_protected_publisher_characters_exact(codepoint):
    import json

    from evidentia_core.models.open_corpora import SourceDocument, native_value

    text = "left" + chr(codepoint) + "right"
    raw = json.dumps({"prose": text}, ensure_ascii=False).encode("utf8")
    parsed = _load_catalog_data(None, raw_bytes=raw, mode="source_json")
    assert parsed.data["prose"] == text
    binding = dict(
        source_key="synthetic",
        role="publication_context",
        media_type="text/plain",
        repository="synthetic/local",
        commit="0" * 40,
        upstream_path="sample.txt",
        raw_bytes=len(raw),
        raw_sha256=hashlib.sha256(raw).hexdigest(),
    )
    document = SourceDocument.model_validate({"binding": binding, "raw_utf8": raw.decode("utf8")})
    assert native_value(document)["raw_utf8"].encode("utf8") == raw


def test_source_parser_exact_raw_ceiling_and_one_over():
    # A valid minimal JSON document padded to the source read limit; no catalog claim.
    raw = b"{}" + b" " * (8388608 - 2)
    assert _load_catalog_data(None, raw_bytes=raw, mode="source_json").data == {}
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=raw + b" ", mode="source_json")


@pytest.mark.parametrize("mode,depth", [("source_json", 32), ("wire_json", 64)])
def test_parser_exact_depth_and_one_over(mode, depth):
    raw = b'{"v":' + b"[" * (depth - 1) + b"null" + b"]" * (depth - 1) + b"}"
    _load_catalog_data(None, raw_bytes=raw, mode=mode)
    refused = b'{"v":' + b"[" * depth + b"null" + b"]" * depth + b"}"
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=refused, mode=mode)


def test_source_parser_exact_array_and_total_value_node_counts():
    # root + one outer array + 25 inner arrays + 99,973 nulls = 100,000 values.
    arrays = [b"[" + b",".join([b"null"] * 4096) + b"]" for _ in range(24)]
    arrays.append(b"[" + b",".join([b"null"] * 1669) + b"]")
    raw = b'{"v":[' + b",".join(arrays) + b"]}"
    parsed = _load_catalog_data(None, raw_bytes=raw, mode="source_json")
    assert len(parsed.data["v"]) == 25
    assert sum(len(items) for items in parsed.data["v"]) == 99973
    arrays[-1] = arrays[-1][:-1] + b",null]"
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=b'{"v":[' + b",".join(arrays) + b"]}", mode="source_json")
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=b'{"v":[' + b",".join([b"null"] * 4097) + b"]}", mode="source_json")


@pytest.mark.parametrize("kind,limit", [("key", 1024), ("number", 128)])
def test_source_parser_exact_key_and_numeric_lexeme_limits(kind, limit):
    if kind == "key":
        accepted = b'{"' + b"k" * limit + b'":null}'
        refused = b'{"' + b"k" * (limit + 1) + b'":null}'
    else:
        accepted = b'{"v":' + b"9" * limit + b"}"
        refused = b'{"v":' + b"9" * (limit + 1) + b"}"
    _load_catalog_data(None, raw_bytes=accepted, mode="source_json")
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=refused, mode="source_json")


@pytest.mark.parametrize(
    "component,limit",
    [("documents", 7340032), ("occurrences", 6291456), ("ordinary_controls", 2097152), ("remaining_envelope", 524288)],
)
def test_disjoint_resource_counter_exact_and_one_over(component, limit):
    # Isolate the byte counter with actual canonical JSON. These are not valid
    # source-derived catalog models; complete pinned profiles are tested separately.
    import json

    from evidentia_core.catalogs.open_corpora import _measure
    from evidentia_core.models.open_corpora import NativeBudget

    def compact(value):
        return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")

    data = {"documents": [], "occurrences": []}
    bundle = {"data": data}
    projection = {"controls": [], "native_source": bundle, "remainder": ""}
    if component == "remaining_envelope":
        base = len(compact(projection)) - 6
        projection["remainder"] = "x" * (limit - base)
    else:
        owner = projection if component == "ordinary_controls" else data
        key = "controls" if component == "ordinary_controls" else component
        owner[key] = ["x" * (limit - 4)]
        assert len(compact(owner[key])) == limit
    wire = compact(projection)
    _measure(projection, bundle, wire, NativeBudget())
    if component == "remaining_envelope":
        projection["remainder"] += "x"
    else:
        owner[key][0] += "x"
    with pytest.raises(ValueError, match="native_source_invalid"):
        _measure(projection, bundle, compact(projection), NativeBudget())
    # The disjoint maximum is 15.5 MiB, leaving 0.5 MiB below the whole-wire cap.
    assert 7340032 + 6291456 + 2097152 + 524288 == 16252928
    assert 16777216 - 16252928 == 524288


def test_wire_parser_and_preflight_exact_whole_byte_limit():
    import json

    from evidentia_core.models.open_corpora import _preflight

    # Only declared raw_utf8 owner slots can carry these large strings.
    data = {"a": {"raw_utf8": ""}, "b": {"raw_utf8": ""}}
    overhead = len(json.dumps(data, separators=(",", ":")).encode("ascii"))
    remaining = 16777216 - overhead
    data["a"]["raw_utf8"] = "x" * (remaining // 2)
    data["b"]["raw_utf8"] = "x" * (remaining - remaining // 2)
    raw = json.dumps(data, separators=(",", ":")).encode("ascii")
    assert len(raw) == 16777216
    _preflight(data)
    assert _load_catalog_data(None, raw_bytes=raw, mode="wire_json").raw == raw
    data["b"]["raw_utf8"] += "x"
    with pytest.raises(ValueError, match="native_source_invalid"):
        _preflight(data)
    with pytest.raises(ValueError, match="native_source_invalid"):
        _load_catalog_data(None, raw_bytes=raw + b" ", mode="wire_json")


def test_native_bundle_counter_exact_and_one_over():
    # The actual closed model encoder and bundle guard are exercised here.
    # Deliberately constructed NativeData bypasses pinned-source correspondence,
    # so this is a byte-boundary proof, not an admitted complete catalog.
    import json

    from evidentia_core.models.open_corpora import NativeBundle, NativeData, SourceDocument

    def compact(value):
        return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")

    binding = dict(
        source_key="synthetic",
        role="authoritative",
        media_type="text/plain",
        repository="synthetic/local",
        commit="0" * 40,
        upstream_path="sample.txt",
        raw_bytes=4000000,
        raw_sha256="0" * 64,
    )
    data = dict(
        schema_version="catalog-native-v1",
        profile="au-ism-2026.09.4",
        catalog_id="au-ism",
        converter_id="evidentia-open-corpora-v1",
        converter_sha256="0" * 64,
        documents=[dict(binding=binding, raw_utf8="")],
        occurrences=[],
        control_bindings=[],
        context_indices=[],
        diagnostics=[],
    )
    available = 12058624 - 92 - len(compact(data))
    source = chr(0x00E9) * (available // 6) + "x" * (available % 6)

    def model_for(text):
        raw = text.encode("utf8")
        binding["raw_bytes"] = len(raw)
        binding["raw_sha256"] = hashlib.sha256(raw).hexdigest()
        assert len(str(binding["raw_bytes"])) == 7
        data["documents"][0]["raw_utf8"] = text
        document = SourceDocument.model_validate({"binding": dict(binding), "raw_utf8": text})
        native = NativeData.model_construct(
            **{
                **data,
                "documents": (document,),
                "occurrences": (),
                "control_bindings": (),
                "context_indices": (),
                "diagnostics": (),
            }
        )
        digest = hashlib.sha256(b"evidentia.catalog-native.v1\x00" + compact(data)).hexdigest()
        return NativeBundle.model_construct(data=native, bundle_sha256=digest)

    model = model_for(source)
    assert len(compact({"bundle_sha256": model.bundle_sha256, "data": data})) == 12058624
    assert model._bundle_digest() is model
    refused = model_for(source + "x")
    with pytest.raises(ValueError, match="native_source_invalid"):
        refused._bundle_digest()


@pytest.mark.parametrize("marker", ["native_source", "native_source_package"])
@pytest.mark.parametrize("value", [None, False, {}])
@pytest.mark.parametrize("entry", ["central", "evidentia", "catalog", "any", "oscal", "non_control"])
def test_legacy_entry_points_refuse_presence_of_native_markers(tmp_path, marker, value, entry):
    import json

    from evidentia_core.catalogs import loader

    source = tmp_path / "legacy.json"
    source.write_text(
        json.dumps({"framework_id": "synthetic", "framework_name": "Synthetic", "controls": [], marker: value}),
        encoding="utf8",
    )
    entries = {
        "central": lambda: loader._load_catalog_data(source),
        "evidentia": lambda: loader.load_evidentia_catalog(source),
        "catalog": lambda: loader.load_catalog("synthetic", custom_path=source),
        "any": lambda: loader.load_any_catalog("synthetic", custom_path=source),
        "oscal": lambda: loader.load_oscal_catalog(source),
        "non_control": lambda: loader.load_non_control_catalog(source),
    }
    with pytest.raises(ValueError, match="native_source_invalid"):
        entries[entry]()


@pytest.mark.parametrize(
    "raw",
    [
        b'{"native_source":null,"native_source":null}',
        b'{"native_source":{"x":1,"x":1}}',
        b'{"native_source":"\xff"}',
        b'{"a":' + b"[" * 64 + b"null" + b"]" * 64 + b"}",
        b'{"a":[' + b"null," * 262143 + b"null]}",
        b" " * 16777217,
    ],
    ids=["duplicate-root", "duplicate-nested", "invalid-utf8", "excess-depth", "excess-nodes", "excess-bytes"],
)
def test_explicit_native_file_checks_before_model_or_legacy_parser(tmp_path, monkeypatch, raw):
    from pathlib import Path

    from evidentia_core.catalogs import loader
    from evidentia_core.models.catalog import _NativeControlCatalog

    source = tmp_path / "native.json"
    source.write_bytes(raw)
    calls = []

    def unexpected(*args, **kwargs):
        calls.append(True)
        raise AssertionError("legacy read or model reached before native admission")

    monkeypatch.setattr(Path, "read_text", unexpected)
    monkeypatch.setattr(_NativeControlCatalog, "model_validate", unexpected)
    with pytest.raises(ValueError, match="native_source_invalid"):
        loader.load_native_wire_catalog(source)
    assert calls == []


@pytest.mark.parametrize(
    "suffix,raw",
    [
        (
            ".json",
            b'{"framework_id":"synthetic","framework_name":" Synthetic ","controls":[{"id":"X","title":" One ","description":" unchanged "}]}',
        ),
        (
            ".yaml",
            b'framework_id: synthetic\nframework_name: " Synthetic "\ncontrols:\n  - id: X\n    title: " One "\n    description: " unchanged "\n',
        ),
    ],
)
def test_non_native_legacy_json_and_yaml_keep_existing_projection(tmp_path, suffix, raw):
    from evidentia_core.catalogs.loader import load_any_catalog, load_evidentia_catalog

    source = tmp_path / ("legacy" + suffix)
    source.write_bytes(raw)
    for result in (load_evidentia_catalog(source), load_any_catalog("synthetic", custom_path=source)):
        assert result.framework_id == "synthetic"
        assert result.framework_name == "Synthetic"
        assert result.native_source is None
        assert result.controls[0].title == "One"
        assert result.controls[0].description == "unchanged"


def test_explicit_native_file_uses_one_original_budget(tmp_path, monkeypatch):
    from evidentia_core.catalogs import loader
    from evidentia_core.models import open_corpora as models

    source = tmp_path / "native.json"
    source.write_bytes(b'{"native_source":null}')
    created = []
    observed = []
    original = models.NativeBudget.__init__
    read = loader._read_native_catalog

    def initialized(self):
        original(self)
        created.append(self)

    def captured(path, limit, budget):
        observed.append(budget)
        return read(path, limit, budget)

    monkeypatch.setattr(models.NativeBudget, "__init__", initialized)
    monkeypatch.setattr(loader, "_read_native_catalog", captured)
    with pytest.raises(ValueError, match="native_source_invalid"):
        loader.load_native_wire_catalog(source)
    assert len(created) == len(observed) == 1
    assert created[0] is observed[0]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":{"x":1,"\\u0078":2}}',
        b'{"a":1} ',
        b'{ "a":1}',
        b'{"a":"\\u0061"}',
        b'{"a":-0}',
        b'{"a":1.0}',
        b'{"a":1e0}',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b'{"a":"\\ud800"}',
        b'{"a":"\xff"}',
        b"[]",
        b"null",
        b'{"a":true}false',
    ],
    ids=[
        "duplicate",
        "nested-escaped-duplicate",
        "trailing-space",
        "internal-space",
        "alternate-escape",
        "negative-zero",
        "decimal",
        "exponent",
        "nan",
        "infinity",
        "surrogate",
        "utf8",
        "array-root",
        "null-root",
        "trailing-value",
    ],
)
def test_captured_wire_refuses_ambiguous_noncanonical_or_non_native_json(raw):
    from evidentia_core.catalogs.loader import _restore_catalog_capture

    with pytest.raises(ValueError, match="native_source_invalid"):
        _restore_catalog_capture(raw)


def test_captured_wire_is_detached_and_rejects_byte_subclass_callbacks():
    from evidentia_core.catalogs.loader import _restore_catalog_capture

    calls = []

    class Hostile(bytes):
        def __len__(self):
            calls.append("len")
            raise AssertionError("caller callback")

        def decode(self, *args, **kwargs):
            calls.append("decode")
            raise AssertionError("caller callback")

    raw = b'{"values":[null,true,123,"literal"]}'
    first = _restore_catalog_capture(raw)
    first["values"].clear()
    assert _restore_catalog_capture(raw) == {"values": [None, True, 123, "literal"]}
    with pytest.raises(ValueError, match="native_source_invalid"):
        _restore_catalog_capture(Hostile(raw))
    assert calls == []


@pytest.mark.parametrize("dimension", ["key", "integer", "text", "raw-text", "members", "depth", "nodes", "elements"])
def test_captured_wire_exact_structural_bounds_and_one_over(dimension):
    import json

    from evidentia_core.catalogs.loader import _restore_catalog_capture

    if dimension == "key":
        accepted = {"k" * 1024: None}
        refused = {"k" * 1025: None}
    elif dimension == "integer":
        accepted = {"n": int("9" * 128)}
        refused = {"n": int("9" * 129)}
    elif dimension == "text":
        accepted = {"text": "x" * 262144}
        refused = {"text": "x" * 262145}
    elif dimension == "raw-text":
        accepted = {"raw_utf8": "x" * 8388608}
        refused = {"raw_utf8": "x" * 8388609}
    elif dimension == "members":
        accepted = {str(index): None for index in range(64)}
        refused = {str(index): None for index in range(65)}
    elif dimension == "depth":
        accepted = refused = None
        for _ in range(63):
            accepted = [accepted]
        refused = {"v": [accepted]}
        accepted = {"v": accepted}
    elif dimension == "nodes":
        accepted = {"v": [None] * 262143}
        refused = {"v": [None] * 262144}
    else:
        # Empty objects do not consume primitive/array nodes. All array
        # entries still contribute to the independent element bound.
        accepted = {"a": [{} for _ in range(131072)], "b": [{} for _ in range(131072)]}
        refused = {"a": accepted["a"], "b": [*accepted["b"], {}]}

    def encode(value):
        return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf8")

    assert _restore_catalog_capture(encode(accepted)) == accepted
    with pytest.raises(ValueError, match="native_source_invalid"):
        _restore_catalog_capture(encode(refused))


def test_captured_wire_keeps_first_deadline_and_releases_failure_buffers(monkeypatch):
    from evidentia_core.catalogs import loader
    from evidentia_core.models import open_corpora as models

    clock = [100.0]
    monkeypatch.setattr(models.time, "monotonic", lambda: clock[0])
    original = loader.json.loads
    with models.native_operation() as budget:

        def consume_original_budget(*args, **kwargs):
            assert models._ACTIVE_BUDGET.get() is budget
            data = original(*args, **kwargs)
            clock[0] = 150.0
            return data

        monkeypatch.setattr(loader.json, "loads", consume_original_budget)
        with pytest.raises(models.NativeSourceError, match="processing_deadline_exceeded") as caught:
            loader._restore_catalog_capture(b'{"x":"captured"}')
    traceback = caught.value.__traceback__
    while traceback and traceback.tb_frame.f_code.co_name != "_restore_catalog_capture":
        traceback = traceback.tb_next
    assert traceback is not None
    values = traceback.tb_frame.f_locals
    assert values["data"] == {}
    assert values["pending"] == []
    assert values["decoded"] is None
    assert values["text"] == ""
    assert values["encoded"] == b""
    assert values["raw"] == b""


def test_captured_wire_preserves_cancellation_identity_and_clears_owned_data(monkeypatch):
    from evidentia_core.catalogs import loader

    class Cancel(BaseException):
        pass

    primary = Cancel()

    def interrupted(*args, **kwargs):
        raise primary

    monkeypatch.setattr(loader.json, "dumps", interrupted)
    with pytest.raises(Cancel) as caught:
        loader._restore_catalog_capture(b'{"x":["captured"]}')
    assert caught.value is primary
    traceback = primary.__traceback__
    while traceback and traceback.tb_frame.f_code.co_name != "_restore_catalog_capture":
        traceback = traceback.tb_next
    assert traceback is not None
    values = traceback.tb_frame.f_locals
    assert values["data"] == {}
    assert values["pending"] == []
    assert values["decoded"] is None
    assert values["value"] is None
    assert values["text"] == ""
    assert values["encoded"] == b""


def test_shared_catalog_serialization_schema_preserves_declared_response_fields():
    from evidentia_core.models.catalog import CatalogSourceRow, ControlCatalog
    from pydantic import TypeAdapter, create_model

    for model in (ControlCatalog, create_model("CatalogEnvelope", catalog=(ControlCatalog, ...))):
        validation = TypeAdapter(model).json_schema(mode="validation")
        serialization = TypeAdapter(model).json_schema(mode="serialization")
        assert (
            serialization["$defs"]["CatalogSourceRow"]["properties"]
            == CatalogSourceRow.model_json_schema()["properties"]
        )
        assert (
            serialization["$defs"]["CatalogControl"]["properties"]["source_rows"]
            == validation["$defs"]["CatalogControl"]["properties"]["source_rows"]
        )
        assert (
            serialization["additionalProperties"] is False
            if model is ControlCatalog
            else "catalog" in serialization["properties"]
        )


def test_native_serialization_schema_resolves_every_local_reference():
    from evidentia_core.models.catalog import ControlCatalog
    from evidentia_core.models.open_corpora import ControlSourceRef, NativeBundle, NativeData
    from pydantic import TypeAdapter, create_model

    for model in (
        NativeData,
        NativeBundle,
        ControlSourceRef,
        ControlCatalog,
        create_model("NativeEnvelope", catalog=(ControlCatalog, ...)),
    ):
        validation = TypeAdapter(model).json_schema(mode="validation")
        serialization = TypeAdapter(model).json_schema(mode="serialization")
        assert serialization["properties"] == validation["properties"]
        assert serialization.get("required") == validation.get("required")
        for schema in (validation, serialization):
            pending = [schema]
            while pending:
                value = pending.pop()
                if type(value) is dict:
                    if "$ref" in value:
                        assert value["$ref"].startswith("#/")
                        target = schema
                        for token in value["$ref"][2:].split("/"):
                            target = target[token.replace("~1", "/").replace("~0", "~")]
                        assert type(target) is dict
                    pending.extend(value.values())
                elif type(value) is list:
                    pending.extend(value)


def test_captured_wire_whole_byte_bound_precedes_decode(monkeypatch):
    import json

    from evidentia_core.catalogs import loader

    data = {"a": {"raw_utf8": ""}, "b": {"raw_utf8": ""}}
    overhead = len(json.dumps(data, separators=(",", ":")).encode("ascii"))
    remaining = 16777216 - overhead
    data["a"]["raw_utf8"] = "x" * (remaining // 2)
    data["b"]["raw_utf8"] = "x" * (remaining - remaining // 2)
    raw = json.dumps(data, separators=(",", ":")).encode("ascii")
    assert len(raw) == 16777216
    assert loader._restore_catalog_capture(raw) == data
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("decode before byte admission")

    monkeypatch.setattr(loader.json, "loads", forbidden)
    with pytest.raises(ValueError, match="native_source_invalid"):
        loader._restore_catalog_capture(raw + b" ")
    assert calls == []


def _f3_publication() -> dict[str, object]:
    return {
        "schema_version": "catalog-publication-observation-v1",
        "operation": "native_import",
        "publication_state": "committed",
        "prior_manifest_state": "absent",
        "prior_sha256": None,
        "proposed_sha256": "1" * 64,
        "replace_outcome": "returned",
        "observed_manifest_state": "present",
        "observed_sha256": "1" * 64,
        "readback_result": "matches_proposed",
        "cleanup_state": "complete",
        "cleanup_errors": [],
        "failure_phase": None,
        "primary_kind": "none",
        "error_code": None,
    }


def _f3_uploads() -> dict[str, object]:
    return {
        "profile": "bsi-grundschutz-plus-plus-367d7750",
        "documents": [{"source_key": key, "raw_utf8": ""} for key in ("bsi-catalog", "bsi-license", "bsi-readme")],
    }


def test_f3_upload_keys_are_complete_before_storage():
    from evidentia_core.models.open_corpora import ExternalImportRequest

    value = _f3_uploads()
    value["documents"][2]["source_key"] = "bsi-license"
    with pytest.raises(ValueError, match="native_source_invalid"):
        ExternalImportRequest.model_validate(value)


@pytest.mark.parametrize("excess", [False, True])
def test_f3_source_utf8_aggregate_exact_and_one_over(excess):
    from evidentia_core.models.open_corpora import ExternalImportRequest

    value = _f3_uploads()
    value["documents"][0]["raw_utf8"] = "a" * 4194304
    value["documents"][1]["raw_utf8"] = "b" * 4194304
    value["documents"][2]["raw_utf8"] = "c" if excess else ""
    if excess:
        with pytest.raises(ValueError, match="native_source_invalid"):
            ExternalImportRequest.model_validate(value)
    else:
        admitted = ExternalImportRequest.model_validate(value)
        assert sum(len(document.raw_utf8.encode("utf8")) for document in admitted.documents) == 8388608


@pytest.mark.parametrize(
    "change",
    [
        {"prior_manifest_state": "present"},
        {"prior_sha256": "0" * 64},
        {"observed_manifest_state": "absent"},
        {"observed_sha256": None},
        {"proposed_sha256": None},
        {"publication_state": "not_committed"},
        {"publication_state": "not_attempted"},
        {"publication_state": "indeterminate"},
        {"readback_result": "matches_prior"},
        {"readback_result": "unavailable"},
        {"observed_sha256": "2" * 64},
        {"cleanup_state": "failed"},
        {"cleanup_errors": ["handle_close_failed"]},
        {"primary_kind": "exception"},
        {"failure_phase": "cleanup"},
        {"primary_kind": "base_exception", "error_code": "catalog_storage_failed", "failure_phase": "cleanup"},
    ],
)
def test_f3_publication_rejects_inconsistent_closed_states(change):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogPublicationObservation.model_validate({**_f3_publication(), **change})


def test_f3_ordinary_error_code_matches_its_publication():
    from evidentia_core.models.open_corpora import CatalogStorageErrorEnvelope

    publication = {
        **_f3_publication(),
        "primary_kind": "exception",
        "failure_phase": "cleanup",
        "error_code": "processing_deadline_exceeded",
    }
    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogStorageErrorEnvelope.model_validate({"code": "catalog_storage_failed", "publication": publication})
    admitted = CatalogStorageErrorEnvelope.model_validate(
        {"code": "processing_deadline_exceeded", "publication": publication}
    )
    assert admitted.code == admitted.publication.error_code


@pytest.mark.parametrize("state", ["not_attempted", "unchanged", "not_committed", "committed", "indeterminate"])
def test_f3_publication_accepts_independently_authored_terminal_states(state):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = _f3_publication()
    if state == "not_attempted":
        value.update(
            publication_state=state,
            prior_manifest_state="unread",
            proposed_sha256=None,
            replace_outcome="not_called",
            observed_manifest_state="not_observed",
            observed_sha256=None,
            readback_result="not_attempted",
            primary_kind="exception",
            failure_phase="lock",
            error_code="catalog_transaction_conflict",
        )
    elif state == "unchanged":
        value.update(
            publication_state=state, prior_manifest_state="present", prior_sha256="1" * 64, replace_outcome="not_called"
        )
    elif state == "not_committed":
        value.update(
            publication_state=state,
            replace_outcome="raised",
            observed_manifest_state="absent",
            observed_sha256=None,
            readback_result="matches_prior",
            primary_kind="exception",
            failure_phase="replace",
            error_code="catalog_publication_failed",
        )
    elif state == "indeterminate":
        value.update(
            publication_state=state,
            replace_outcome="raised",
            observed_manifest_state="not_observed",
            observed_sha256=None,
            readback_result="unavailable",
            primary_kind="exception",
            failure_phase="replace",
            error_code="catalog_publication_indeterminate",
        )
    assert CatalogPublicationObservation.model_validate(value).publication_state == state


@pytest.mark.parametrize("code", ["catalog_storage_failed", "processing_deadline_exceeded", "catalog_cleanup_failed"])
def test_f3_returned_other_readback_requires_generation_conflict(code):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = {
        **_f3_publication(),
        "observed_sha256": "2" * 64,
        "readback_result": "other",
        "primary_kind": "exception",
        "failure_phase": "readback",
        "error_code": code,
    }
    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogPublicationObservation.model_validate(value)


@pytest.mark.parametrize(
    "change",
    [
        {"failure_phase": "readback"},
        {"cleanup_state": "complete", "cleanup_errors": []},
        {"replace_outcome": "raised"},
    ],
)
def test_f3_cleanup_code_requires_cleanup_as_the_first_failure(change):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = {
        **_f3_publication(),
        "primary_kind": "exception",
        "failure_phase": "cleanup",
        "error_code": "catalog_cleanup_failed",
        "cleanup_state": "failed",
        "cleanup_errors": ["handle_close_failed"],
        **change,
    }
    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogPublicationObservation.model_validate(value)


@pytest.mark.parametrize(
    "primary_kind,code", [("exception", "catalog_generation_conflict"), ("base_exception", "catalog_interrupted")]
)
def test_f3_readback_conflict_and_primary_interruption_remain_distinct(primary_kind, code):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = {
        **_f3_publication(),
        "observed_sha256": "2" * 64,
        "readback_result": "other",
        "primary_kind": primary_kind,
        "failure_phase": "readback",
        "error_code": code,
        "cleanup_state": "failed",
        "cleanup_errors": ["handle_close_failed"],
    }
    admitted = CatalogPublicationObservation.model_validate(value)
    assert admitted.publication_state == "committed"
    assert admitted.error_code == code


def test_f3_cleanup_first_ordinary_failure_is_admitted():
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = {
        **_f3_publication(),
        "primary_kind": "exception",
        "failure_phase": "cleanup",
        "error_code": "catalog_cleanup_failed",
        "cleanup_state": "failed",
        "cleanup_errors": ["handle_close_failed"],
    }
    assert CatalogPublicationObservation.model_validate(value).error_code == "catalog_cleanup_failed"


# T2, T3 and T4 use fixed failure codes even when replacement is observed committed.
def _f3_raised_publication(state: str) -> dict[str, object]:
    value = {
        **_f3_publication(),
        "publication_state": state,
        "prior_manifest_state": "present",
        "prior_sha256": "1" * 64,
        "replace_outcome": "raised",
        "primary_kind": "exception",
        "failure_phase": "replace",
        "error_code": "catalog_publication_failed",
    }
    if state == "not_committed":
        value.update(prior_sha256="2" * 64, observed_sha256="2" * 64, readback_result="matches_prior")
    elif state == "indeterminate":
        value.update(
            observed_manifest_state="not_observed",
            observed_sha256=None,
            readback_result="unavailable",
            error_code="catalog_publication_indeterminate",
        )
    return value


@pytest.mark.parametrize("state", ["committed", "not_committed", "indeterminate"])
def test_f3_raised_publication_requires_a_primary_failure(state):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = {**_f3_raised_publication(state), "primary_kind": "none", "failure_phase": None, "error_code": None}
    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogPublicationObservation.model_validate(value)


@pytest.mark.parametrize("state", ["committed", "not_committed", "indeterminate"])
@pytest.mark.parametrize("wrong_kind", ["generic_storage", "other_publication_state"])
def test_f3_raised_publication_refuses_wrong_fixed_codes(state, wrong_kind):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = _f3_raised_publication(state)
    value["error_code"] = (
        "catalog_storage_failed"
        if wrong_kind == "generic_storage"
        else "catalog_publication_failed"
        if state == "indeterminate"
        else "catalog_publication_indeterminate"
    )
    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogPublicationObservation.model_validate(value)


@pytest.mark.parametrize("state", ["committed", "not_committed", "indeterminate"])
def test_f3_raised_publication_retains_fixed_ordinary_failure(state):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = _f3_raised_publication(state)
    assert CatalogPublicationObservation.model_validate(value).model_dump() == value


@pytest.mark.parametrize("state", ["committed", "not_committed", "indeterminate"])
def test_f3_raised_publication_preserves_interruption_precedence(state):
    from evidentia_core.models.open_corpora import CatalogPublicationObservation

    value = {**_f3_raised_publication(state), "primary_kind": "base_exception", "error_code": "catalog_interrupted"}
    assert CatalogPublicationObservation.model_validate(value).model_dump() == value
    value["error_code"] = "catalog_publication_failed"
    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogPublicationObservation.model_validate(value)


@pytest.mark.parametrize("state", ["committed", "not_committed", "indeterminate"])
def test_f3_raised_storage_envelope_enforces_the_publication_table(state):
    from evidentia_core.models.open_corpora import CatalogStorageErrorEnvelope

    publication = _f3_raised_publication(state)
    value = {"code": publication["error_code"], "publication": publication}
    assert CatalogStorageErrorEnvelope.model_validate(value).model_dump() == value
    publication["error_code"] = "catalog_storage_failed"
    with pytest.raises(ValueError, match="native_source_invalid"):
        CatalogStorageErrorEnvelope.model_validate({"code": "catalog_storage_failed", "publication": publication})
