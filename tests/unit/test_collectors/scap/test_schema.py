"""Verify independently derived fixture artifacts through the complete public schema."""

import hashlib
import json
from pathlib import Path

import pytest
from evidentia_collectors.scap._contracts import ScapCollectionResult, ScapError
from evidentia_collectors.scap.collector import _begin_import, collect_scap_bytes
from jsonschema import Draft202012Validator
from pydantic import ValidationError

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "scap"
_INDEX = json.loads((_FIXTURES / "source-index.json").read_text(encoding="utf-8"))


def _fixture_bytes(name):
    # Only checked-in synthetic fixture bytes have a fixed LF convention.
    return (_FIXTURES / name).read_bytes().replace(b"\r\n", b"\n")


@pytest.mark.parametrize("row", _INDEX["fixtures"], ids=lambda row: row["source_profile"])
def test_full_native_result_matches_the_independent_fixture_ledger(row):
    raw = _fixture_bytes(row["file"])
    expected_bytes = _fixture_bytes(row["expected_file"])
    assert len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"]
    assert len(expected_bytes) == row["expected_bytes"]
    assert hashlib.sha256(expected_bytes).hexdigest() == row["expected_sha256"]
    expected = json.loads(expected_bytes)
    result = collect_scap_bytes(raw, source_profile=row["source_profile"], assessment_index=0)
    output = result.model_dump()
    assert output["native_document"] == expected["native_document"]
    assert output["assessment"] == expected["assessment"]
    assert output["source"]["sha256"] == expected["source_sha256"]
    schema = ScapCollectionResult.model_json_schema()
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(output)
    if row["source_profile"].startswith("oval-"):
        assert output["evidence_artifact"] is None
        del output["evidence_artifact"]
        assert list(Draft202012Validator(schema).iter_errors(output))
        with pytest.raises(ValidationError):
            ScapCollectionResult.model_validate(output)


@pytest.mark.parametrize("name", ["xccdf-1.2", "oval-5.8"])
def test_all_stable_artifact_fields_and_identities_match_reviewed_expectations(name):
    expected = json.loads(_fixture_bytes(name + "-native.expected.json"))
    raw = _fixture_bytes(name + "-native.xml")
    assert len(expected["artifact_cases"]) == 2
    for case in expected["artifact_cases"]:
        operation = _begin_import(**case["request"], actor=case["actor"])
        accepted = operation.consume(raw)
        assert accepted.result.evidence_artifact is not None
        artifact = accepted.result.evidence_artifact.model_dump()
        assert artifact == case["evidence_artifact"]
        assert artifact["id"] == case["identity"]["artifact_id"]
        assert artifact["content_hash"] == case["identity"]["content_sha256"]
        assert accepted.result.findings[0].id == case["finding_identity"]["finding_id"]
        assert json.loads(accepted.output_bytes("artifact")) == artifact
        Draft202012Validator(ScapCollectionResult.model_json_schema()).validate(json.loads(accepted.wire))


def test_error_schema_has_no_extra_or_missing_fields():
    schema = ScapError.model_json_schema()
    Draft202012Validator.check_schema(schema)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"schema_version", "code", "message"}
