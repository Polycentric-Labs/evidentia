"""Closed model ingress and exact optional-source serialization."""

import json

import pytest
from evidentia_core.release_cadence._contracts import (
    PollRequest,
    ReleaseError,
    SelectedReleaseFacts,
    SourcePublicationTime,
)
from evidentia_core.release_cadence._limits import ReleaseFailure
from pydantic import TypeAdapter, ValidationError

REQUEST = {
    "schema_version": "release-poll-request-v1",
    "source_profile": "github-public-releases-2026-03-10",
    "owner": "Example",
    "repository": "Synthetic",
    "channel": "full_releases",
    "persist": False,
}
SELECTED = {
    "id": 101,
    "node_id": "synthetic",
    "url": "",
    "html_url": "",
    "tag_name": "",
    "target_commitish": "",
    "name": None,
    "draft": False,
    "prerelease": False,
    "created_at": "",
    "published_at": None,
}


@pytest.mark.parametrize("options", [{}, {"strict": False}, {"extra": "ignore"}])
@pytest.mark.parametrize(
    "mutation",
    [
        {"persist": 0},
        {"persist": "false"},
        {"owner": 1},
        {"owner": "a/"},
        {"repository": "x.git"},
        {"schema_version": "other"},
        {"extra": 1},
    ],
)
def test_request_refuses_invalid_native_values(mutation, options):
    with pytest.raises((ReleaseFailure, ValidationError)):
        PollRequest.model_validate({**REQUEST, **mutation}, **options)


def test_missing_keys_models_and_subclasses_are_not_authority():
    for key in REQUEST:
        value = dict(REQUEST)
        del value[key]
        with pytest.raises((ReleaseFailure, ValidationError)):
            PollRequest.model_validate(value)
    model = PollRequest.model_validate(dict(REQUEST))
    with pytest.raises((ReleaseFailure, ValidationError)):
        PollRequest.model_validate(model)

    class Forged(dict):
        def items(self):
            raise AssertionError("callback")

    with pytest.raises((ReleaseFailure, ValidationError)):
        PollRequest.model_validate(Forged(REQUEST))


def test_only_strict_json_entrypoint_performs_duplicate_preflight():
    raw = json.dumps(REQUEST).encode()
    assert PollRequest.model_validate_json(raw).owner == "Example"
    duplicate = raw[:-1] + b',"persist":false}'
    with pytest.raises((ReleaseFailure, ValidationError)):
        PollRequest.model_validate_json(duplicate)
    with pytest.raises((ReleaseFailure, ValidationError)):
        TypeAdapter(PollRequest).validate_json(duplicate)


def test_optional_presence_survives_both_serializers():
    model = SelectedReleaseFacts.model_validate(dict(SELECTED))
    assert model.model_dump() == SELECTED
    assert json.loads(model.model_dump_json()) == SELECTED
    explicit = {**SELECTED, "immutable": False, "updated_at": None}
    assert SelectedReleaseFacts.model_validate(explicit).model_dump() == explicit
    with pytest.raises((ReleaseFailure, ValidationError)):
        SelectedReleaseFacts.model_validate({**SELECTED, "immutable": None})
    schema = SelectedReleaseFacts.model_json_schema()
    assert set(schema["required"]) == set(SELECTED)
    assert "default" not in schema["properties"]["immutable"]


def test_source_classification_is_recomputed():
    value = {
        "source_literal": "2000-01-01T00:00:00Z",
        "classification": "normalized",
        "normalized_utc": "2000-01-01T00:00:00.000000Z",
    }
    assert SourcePublicationTime.model_validate(value).classification == "normalized"
    for change in (
        {"classification": "absent"},
        {"normalized_utc": None},
        {"normalized_utc": "2000-01-02T00:00:00.000000Z"},
    ):
        with pytest.raises((ReleaseFailure, ValidationError)):
            SourcePublicationTime.model_validate({**value, **change})


def test_fixed_error_rows_are_not_an_enum_cross_product():
    value = {
        "schema_version": "release-error-v1",
        "code": "invalid_request",
        "message": "The release request is invalid.",
    }
    assert ReleaseError.model_validate(value).code == "invalid_request"
    with pytest.raises((ReleaseFailure, ValidationError)):
        ReleaseError.model_validate({**value, "code": "operation_failed"})


def test_raw_model_storage_is_bounded_before_copy():
    from evidentia_core.release_cadence._contracts import PollRequest, native_model

    value = PollRequest.model_validate(
        {
            "schema_version": "release-poll-request-v1",
            "source_profile": "github-public-releases-2026-03-10",
            "owner": "Example",
            "repository": "Synthetic",
            "channel": "all_published",
            "persist": False,
        }
    )
    object.__getattribute__(value, "__dict__")["owner"] = "a" * 4097
    with pytest.raises(ValueError):
        native_model(value)


def test_raw_model_key_type_is_checked_before_key_comparison():
    from evidentia_core.release_cadence._contracts import PollRequest, native_model

    calls = []

    class Key(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            calls.append("eq")
            raise AssertionError("Foreign key equality called")

    value = PollRequest.model_validate(
        {
            "schema_version": "release-poll-request-v1",
            "source_profile": "github-public-releases-2026-03-10",
            "owner": "Example",
            "repository": "Synthetic",
            "channel": "all_published",
            "persist": False,
        }
    )
    values = dict(object.__getattribute__(value, "__dict__"))
    del values["owner"]
    values[Key("owner")] = "Example"
    object.__setattr__(value, "__dict__", values)
    with pytest.raises(ValueError):
        native_model(value)
    assert calls == []


def test_fresh_core_imports_do_not_need_collectors_or_perform_io():
    import json
    import subprocess
    import sys
    from pathlib import Path

    source = Path(__file__).parents[3] / "packages/evidentia-core/src"
    script = r"""
import importlib
import importlib.abc
import json
from pathlib import Path
import socket
import subprocess
import sys
sys.path.insert(0, sys.argv[1])
import evidentia_core.evidence_store as store
class NoCollectors(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "evidentia_collectors" or fullname.startswith("evidentia_collectors."):
            raise AssertionError("Optional Collectors were imported")
def forbidden(*args, **kwargs):
    raise AssertionError("Pure import attempted external work")
sys.meta_path.insert(0, NoCollectors())
socket.getaddrinfo = socket.socket = forbidden
subprocess.run = subprocess.Popen = forbidden
for name in ("get_evidence_store_dir", "save_evidence", "save_evidence_version_one", "iter_artifacts", "list_lineage"):
    setattr(store, name, forbidden)
origins = {}
for name in ("_limits", "_json", "_source", "_time", "_contracts", "_identity", "_store", "_series"):
    module = importlib.import_module("evidentia_core.release_cadence." + name)
    origins[name] = str(Path(module.__file__).resolve())
assert not any(name.startswith("evidentia_collectors") for name in sys.modules)
print(json.dumps(origins))
"""
    completed = subprocess.run(
        [sys.executable, "-I", "-B", "-c", script, str(source)], capture_output=True, check=False
    )
    assert completed.returncode == 0, completed.stderr.decode("utf-8", "replace")
    origins = json.loads(completed.stdout)
    assert len(origins) == 8
    assert all(Path(value).is_relative_to(source) for value in origins.values())


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_schema_preserves_scalar_array_and_optional_source_bounds(mode):
    from evidentia_core.release_cadence._contracts import (
        EventKey,
        PageLedger,
        PollResult,
        RowMetadata,
        RunClocks,
    )

    request = PollRequest.model_json_schema(mode=mode)
    for name, maximum in (("owner", 39), ("repository", 100)):
        value = request["properties"][name]
        assert value["type"] == "string"
        assert value["minLength"] == 0
        assert value["maxLength"] == maximum
        assert value["pattern"] == "^[\\x00-\\x7f]*$"
    event = EventKey.model_json_schema(mode=mode)["properties"]
    assert event["release_id"]["minimum"] == 1
    assert event["release_id"]["maximum"] == 9_007_199_254_740_991
    assert not {"ge", "le"} & event["release_id"].keys()
    assert event["canonical_owner"]["pattern"] == "^[a-z0-9._-]{1,256}$"
    clocks = RunClocks.model_json_schema(mode=mode)["properties"]
    assert clocks["poll_id"]["minLength"] == clocks["poll_id"]["maxLength"] == 36
    assert clocks["poll_id"]["pattern"] == ("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
    assert clocks["started_at"]["minLength"] == clocks["started_at"]["maxLength"] == 27
    row = RowMetadata.model_json_schema(mode=mode)["properties"]
    assert row["eligibility_reasons"]["maxItems"] == 5
    page = PageLedger.model_json_schema(mode=mode)["properties"]
    choices = page["http_status"]["anyOf"]
    assert {"type": "null"} in choices
    number = next(item for item in choices if item.get("type") == "integer")
    assert number["minimum"] == 100 and number["maximum"] == 599
    assert not {"ge", "le"} & number.keys()
    result = PollResult.model_json_schema(mode=mode)
    assert result["properties"]["rows"]["maxItems"] == 1000
    selected = result["$defs"]["SelectedReleaseFacts"]
    assert selected["type"] == "object"
    assert selected["additionalProperties"] is False
    assert set(selected["properties"]) == set(SELECTED) | {"immutable", "updated_at"}
    assert set(selected["required"]) == set(SELECTED)
    assert selected["properties"]["immutable"]["type"] == "boolean"
    assert "anyOf" not in selected["properties"]["immutable"]
    for name in ("immutable", "updated_at"):
        assert "default" not in selected["properties"][name]
    nullable = selected["properties"]["updated_at"]["anyOf"]
    assert {"type": "null"} in nullable
    assert next(item for item in nullable if item.get("type") == "string")["maxLength"] == 128


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_selected_schema_is_closed_at_its_own_export(mode):
    schema = SelectedReleaseFacts.model_json_schema(mode=mode)
    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == set(SELECTED) | {"immutable", "updated_at"}
    assert set(schema["required"]) == set(SELECTED)
    assert schema["properties"]["id"]["minimum"] == 1
    assert schema["properties"]["id"]["maximum"] == 9_007_199_254_740_991


@pytest.mark.parametrize("mode", ["validation", "serialization"])
@pytest.mark.parametrize(
    ("model_name", "field_name", "valid", "invalid"),
    [
        ("ReleaseSeriesRequest", "owner", "Example-Org", ["-example", "example_", "a/", "a" * 40]),
        ("ReleaseSeriesRequest", "repository", "Example.Repo-1", ["a/", "a b", "a" * 101]),
        ("SeriesScope", "canonical_owner", "example-org", ["Example", "a/", "a" * 257]),
        ("SeriesScope", "canonical_repository", "example.repo-1", ["Example", "a b", "a" * 257]),
    ],
)
def test_series_schema_rejects_blank_and_invalid_repository_tokens(mode, model_name, field_name, valid, invalid):
    from evidentia_core.release_cadence import _contracts
    from jsonschema import Draft202012Validator

    model = getattr(_contracts, model_name)
    schema = model.model_json_schema(mode=mode)["properties"][field_name]
    validator = Draft202012Validator(schema)
    assert validator.is_valid(valid)
    for value in ["", " ", "\t\n", "\u0085", "\u00a0", "\u3000", valid + "\n", valid + "\r\n", *invalid]:
        assert not validator.is_valid(value), repr(value)
