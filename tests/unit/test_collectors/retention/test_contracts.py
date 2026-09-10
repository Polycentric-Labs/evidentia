"""Strict selected-storage request and evidence factory regressions."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import warnings
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from evidentia_collectors.retention import _contracts as c
from evidentia_collectors.retention._parsing import JsonObject
from evidentia_core.models.common import NON_BLANK_PATTERN, deterministic_finding_id
from pydantic import BaseModel, TypeAdapter, ValidationError

START = datetime(2024, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
END = START + timedelta(seconds=2)


def request(provider: str = "s3", count: int = 1) -> c.StorageRetentionCollectRequest:
    targets: list[dict[str, Any]]
    if provider == "s3":
        targets = [{"bucket": f"bucket-{n}", "region": "us-east-1"} for n in range(count)]
    elif provider == "azure":
        targets = [
            {
                "subscription_id": "12345678-ABCD-1234-ABCD-123456789ABC",
                "resource_group": "Example_Group",
                "account": "store123",
                "container": f"container-{n}",
            }
            for n in range(count)
        ]
    else:
        targets = [{"bucket": f"bucket_{n}"} for n in range(count)]
    return c.validated_request({"provider": provider, "scope_label": "Scope_1", "targets": targets})


def projection() -> c.ProjectedComponent:
    return c.ProjectedComponent(
        api_version="v1",
        native_scope="bucket",
        fields={"missing_is_omitted": None, "retentionPeriod": "00086400", "nested": {"enabled": False}},
    )


def component(
    target: c.StorageTarget, name: c.ComponentId, state: str = "complete"
) -> c.StorageRetentionComponentResult:
    return c.make_component_result(
        name,
        target,
        attempts=1 if state != "unavailable" else 0,
        raw_bytes=123 if state != "unavailable" else 0,
        decoded_bytes=123 if state != "unavailable" else 0,
        started_at=START if state != "unavailable" else None,
        finished_at=END if state != "unavailable" else None,
        http_status=200 if state != "unavailable" else None,
        projection=projection() if state != "unavailable" else None,
        diagnostics=(c.StorageRetentionDiagnostic(code="missing_source_detail"),)
        if state == "partial"
        else (c.StorageRetentionDiagnostic(code="configuration_missing"),)
        if state == "unavailable"
        else (),
    )


def result(provider: str = "s3", states: tuple[str, ...] | None = None) -> c.StorageRetentionCollectResult:
    req = request(provider)
    target = req.root.targets[0]
    ids = c.component_ids(req.root.provider)
    states = states or tuple("complete" for _ in ids)
    parts = [component(target, name, state) for name, state in zip(ids, states, strict=True)]
    return c.make_result(
        req,
        run_id="synthetic-run",
        started_at=START,
        finished_at=END,
        components={c.target_identity(target): parts},
        diagnostics=(),
    )


@pytest.mark.parametrize("provider", ["s3", "azure", "gcs"])
def test_request_native_json_schema_and_target_order(provider: str) -> None:
    req = request(provider, 2)
    raw = req.model_dump_json()
    assert "root" not in json.loads(raw)
    assert c.parse_request(raw.encode()) == req
    assert c.validated_request(req) == req
    assert req.root.targets[0] != req.root.targets[1]
    schema = req.model_json_schema()
    branch = schema["$defs"][type(req.root).__name__]
    label = branch["properties"]["scope_label"]
    assert label["pattern"] == NON_BLANK_PATTERN
    assert label["allOf"] == [{"pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?![\s\S])"}]
    assert schema["discriminator"]["propertyName"] == "provider"


@pytest.mark.parametrize(
    "label", ["", " ", "x\n", "\u0085", "\u3000", ".x", "_x", "-x", "\u00e9", "x" * 65, False, 0, [], {}]
)
def test_invalid_scope_alias_is_closed(label: object) -> None:
    body = request().model_dump()
    body["scope_label"] = label
    with pytest.raises(c.StorageRetentionInputError) as error:
        c.validated_request(body)
    assert str(error.value) == "invalid_request"
    assert error.value.code == "invalid_request"


@pytest.mark.parametrize(
    "raw",
    [b"[]", b"{}", b'{"provider":"s3","provider":"gcs"}', b'{"x":NaN}', b'{"x":"\\ud800"}', b"\xff", b" " * 65537],
    ids=["wrong-root", "empty", "duplicate", "nonfinite", "surrogate", "invalid-utf8", "too-large"],
)
def test_request_parser_refuses_invalid_full_bodies(raw: bytes) -> None:
    with pytest.raises(c.StorageRetentionInputError):
        c.parse_request(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"bucket": "https://other.example"},
        {"bucket": "a..b"},
        {"bucket": "192.168.001.1"},
        {"bucket": "999.888.777.666"},
        {"bucket": "xn--bucket"},
        {"bucket": "thing--x-s3"},
        {"bucket": "thing-s3alias"},
        {"bucket": "Uppercase"},
        {"bucket": "abc%2fdef"},
        {"region": "aws-global"},
        {"region": "cn-north-1"},
        {"region": True},
        {"expected_owner": "1"},
        {"expected_owner": 123456789012},
        {"bucket": "abc\n"},
    ],
)
def test_s3_target_refusals(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        c.S3Target.model_validate({"bucket": "example.bucket", "region": "us-east-1", **changes})


def test_exact_s3_urls_regions_and_owner_expectation() -> None:
    assert isinstance(c.S3_REGIONS, frozenset)
    assert len(c.S3_REGIONS) == 34
    for region in sorted(c.S3_REGIONS):
        target = c.S3Target(bucket="example.bucket-an", region=region, expected_owner="001234567890")
        assert (
            c.build_component_url("s3-object-lock", target)
            == f"https://s3.{region}.amazonaws.com/example.bucket-an?object-lock"
        )
        assert (
            c.build_component_url("s3-versioning", target)
            == f"https://s3.{region}.amazonaws.com/example.bucket-an?versioning"
        )
        assert c.target_identity(target) == f"s3:{region}:example.bucket-an"
        assert c.target_provider(target) == "s3"


def test_azure_identity_preserves_display_and_encodes_once() -> None:
    target = c.AzureTarget(
        subscription_id="12345678-ABCD-1234-ABCD-123456789ABC",
        resource_group="Group_(A)",
        account="store123",
        container="records",
    )
    assert target.subscription_id == "12345678-abcd-1234-abcd-123456789abc"
    assert target.resource_group == "Group_(A)"
    base = (
        "/subscriptions/12345678-abcd-1234-abcd-123456789abc/resourceGroups/Group_%28A%29"
        "/providers/Microsoft.Storage/storageAccounts/store123"
    )
    assert (
        c.build_component_url("azure-account", target)
        == "https://management.azure.com" + base + "?api-version=2026-04-01"
    )
    assert c.build_component_url("azure-blob-service", target).endswith("/blobServices/default?api-version=2026-04-01")
    assert c.build_component_url("azure-container", target).endswith(
        "/blobServices/default/containers/records?api-version=2026-04-01"
    )
    assert c.target_identity(target).endswith(
        "/resourcegroups/group_(a)/providers/microsoft.storage/storageaccounts/store123/blobservices/default/containers/records"
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("subscription_id", "12345678abcd1234abcd123456789abc"),
        ("resource_group", "ends."),
        ("resource_group", "a/b"),
        ("resource_group", "\u00e9"),
        ("account", "Abc"),
        ("container", "a--b"),
        ("container", "a_b"),
        ("account", False),
    ],
)
def test_azure_subset(field: str, value: object) -> None:
    raw = request("azure").root.targets[0].model_dump()
    raw[field] = value
    with pytest.raises(ValidationError):
        c.AzureTarget.model_validate(raw)


@pytest.mark.parametrize(
    "bucket", ["a" * 64, "a..b", "a." + "b" * 64, "1.2.3.4", "abc/def", "abc%2fdef", "Uppercase", "a_b\n"]
)
def test_gcs_subset(bucket: str) -> None:
    with pytest.raises(ValidationError):
        c.GcsTarget(bucket=bucket)


def test_gcs_exact_url_and_dotted_long_name() -> None:
    bucket = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 30])
    target = c.GcsTarget(bucket=bucket)
    assert (
        c.build_component_url("gcs-bucket", target)
        == f"https://storage.googleapis.com/storage/v1/b/{bucket}?projection=noAcl"
    )


@pytest.mark.parametrize("provider", ["s3", "azure", "gcs"])
def test_duplicates_and_conflicting_target_expectations_reject(provider: str) -> None:
    req = request(provider).model_dump()
    duplicate = copy.deepcopy(req["targets"][0])
    if provider == "s3":
        duplicate["expected_owner"] = "123456789012"
    if provider == "azure":
        duplicate["resource_group"] = duplicate["resource_group"].lower()
    req["targets"].append(duplicate)
    with pytest.raises(c.StorageRetentionInputError):
        c.validated_request(req)


def test_defaults_copies_constructed_targets_and_provider_mismatch() -> None:
    req = request()
    with pytest.raises(ValidationError):
        req.model_copy(update={"root": req.root.model_copy(update={"targets": []})})
    invalid = c.S3Target.model_construct(bucket="bad/target", region="us-east-1", expected_owner=None)
    with pytest.raises(c.StorageRetentionInputError):
        c.build_component_url("s3-object-lock", invalid)
    with pytest.raises(c.StorageRetentionInputError):
        c.build_component_url("azure-account", req.root.targets[0])
    assert isinstance(req.root, c.S3RetentionRequest)
    req.root.targets.append(req.root.targets[0])
    with pytest.raises(c.StorageRetentionInputError):
        c.validated_request(req)


def test_projection_snapshot_is_detached_and_deepcopy_safe() -> None:
    fields: dict[str, Any] = {"nested": {"name": "  literal  ", "value": None}, "number": 5.2, "text": "5.20"}
    obj = c.ProjectedComponent(api_version="v1", native_scope="bucket", fields=fields)
    fields["nested"]["value"] = "changed"
    view = obj.fields
    nested = view["nested"]
    assert isinstance(nested, dict)
    nested["value"] = "changed again"
    assert obj.fields == {"nested": {"name": "  literal  ", "value": None}, "number": 5.2, "text": "5.20"}
    assert copy.deepcopy(obj).fields == obj.fields
    with pytest.raises((AttributeError, TypeError)):
        untyped: Any = obj
        untyped.api_version = "tampered"


@pytest.mark.parametrize(
    "fields",
    [
        {"n": float("nan")},
        {"n": float("inf")},
        {"bad": "\ud800"},
        {"n": START},
        {"long": "x" * 16384},
        [1],
        {1: "bad"},
    ],
)
def test_projection_invalid_tree_or_size(fields: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        c.ProjectedComponent(api_version="v1", native_scope="bucket", fields=cast(JsonObject, fields))


@pytest.mark.parametrize("provider", ["s3", "azure", "gcs"])
def test_full_result_finding_manifest_exact_roundtrip(provider: c.ProviderName) -> None:
    obj = result(provider)
    assert obj.status == "complete"
    assert obj.object_enforcement_assessed is False
    assert obj.recordset_completeness_assessed is False
    assert obj.authenticated_identity_verified is False
    assert len(obj.findings) == 1
    finding = obj.findings[0]
    assert finding.compliance_status == "unknown"
    assert finding.resolved_at is None
    assert finding.control_mappings == []
    assert finding.collection_context.pagination_context is None
    assert finding.collection_context.filter_applied
    assert finding.collection_context.credential_identity == "operator-configured:identity-unverified"
    assert finding.source_finding_id is not None
    assert finding.id == deterministic_finding_id(c.SOURCE_SYSTEM, finding.source_finding_id)
    assert obj.manifest.is_complete is True
    assert obj.manifest.total_findings == 1
    assert obj.manifest.coverage_counts[1].scanned == len(c.component_ids(provider))
    assert obj.manifest.coverage_counts[1].collected == len(c.component_ids(provider))
    wire = obj.model_dump_json(warnings="error")
    assert "2024-01-02T03:04:05.123456Z" in wire
    assert c.StorageRetentionCollectResult.model_validate_json(wire) == obj
    projection_value = json.loads(wire)["resources"][0]["components"][0]["projection"]
    digest = projection_value.pop("canonical_projection_sha256")
    assert (
        digest
        == hashlib.sha256(
            json.dumps(
                projection_value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode()
        ).hexdigest()
    )


@pytest.mark.parametrize("states", list(itertools.product(("complete", "partial", "unavailable"), repeat=3)))
def test_every_azure_component_state_combination(states: tuple[str, ...]) -> None:
    obj = result("azure", states)
    expected = (
        "complete"
        if all(s == "complete" for s in states)
        else "unavailable"
        if all(s == "unavailable" for s in states)
        else "partial"
    )
    assert obj.status == expected
    assert obj.resources[0].status == expected
    assert len(obj.findings) == (0 if expected == "unavailable" else 1)
    assert obj.manifest.is_complete is (expected == "complete")


@pytest.mark.parametrize(
    "field,value",
    [
        ("object_enforcement_assessed", 0),
        ("authenticated_identity_verified", 0),
        ("recordset_completeness_assessed", 0),
        ("status", "unavailable"),
        ("scope_label", "other"),
        ("findings", []),
    ],
)
def test_result_tampering_rejects_before_persistence(field: str, value: object) -> None:
    obj = result()
    with pytest.raises(ValidationError):
        obj.model_copy(update={field: value})
    poisoned = c.StorageRetentionCollectResult.model_construct(**{**obj.__dict__, field: value})
    with warnings.catch_warnings(record=True) as caught, pytest.raises(ValueError):
        poisoned.model_dump_json(warnings="error")
    assert caught == []


def test_cross_target_component_swap_and_missing_extra_component_reject() -> None:
    req = request("s3", 2)
    first, second = req.root.targets
    parts = [component(first, name) for name in c.component_ids("s3")]
    for bad in ([parts[0]], [*parts, parts[0]], list(reversed(parts))):
        with pytest.raises(c.StorageRetentionInputError):
            c.make_result(
                req,
                run_id="run",
                started_at=START,
                finished_at=END,
                components={c.target_identity(first): bad, c.target_identity(second): parts},
                diagnostics=(),
            )
    with pytest.raises(c.StorageRetentionInputError):
        c.make_result(
            req,
            run_id="run",
            started_at=START,
            finished_at=END,
            components={c.target_identity(first): parts, c.target_identity(second): parts},
            diagnostics=(),
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"attempts": True},
        {"attempts": 4},
        {"raw_bytes": True},
        {"decoded_bytes": -1},
        {"http_status": True},
        {"started_at": START.replace(tzinfo=None)},
        {"finished_at": START - timedelta(seconds=1)},
        {"attempts": 0},
        {"raw_bytes": 2**53},
    ],
)
def test_component_strict_counters_clocks(changes: dict[str, Any]) -> None:
    obj = result().resources[0].components[0]
    with pytest.raises(ValidationError):
        obj.model_copy(update=changes)


def test_measured_overshoot_retained_and_cleanup_makes_run_partial() -> None:
    req = request("gcs")
    target = req.root.targets[0]
    failed = c.make_component_result(
        "gcs-bucket",
        target,
        attempts=1,
        raw_bytes=16 * 1024 * 1024 + 1,
        decoded_bytes=0,
        started_at=START,
        finished_at=END,
        http_status=200,
        projection=None,
        diagnostics=(c.StorageRetentionDiagnostic(code="response_limit"),),
    )
    obj = c.make_result(
        req,
        run_id="run",
        started_at=START,
        finished_at=END,
        components={c.target_identity(target): [failed]},
        diagnostics=(),
    )
    assert obj.status == "unavailable"
    complete = component(target, "gcs-bucket")
    obj = c.make_result(
        req,
        run_id="run",
        started_at=START,
        finished_at=END,
        components={c.target_identity(target): [complete]},
        diagnostics=(c.StorageRetentionDiagnostic(code="cleanup_failed"),),
    )
    assert obj.status == "partial"
    assert len(obj.findings) == 1
    assert obj.manifest.is_complete is False


def test_mutable_nested_result_and_strict_core_manifest_are_revalidated() -> None:
    obj = result()
    selected = obj.resources[0].components[0].projection
    assert selected is not None
    selected.fields["bad"] = float("nan")
    with pytest.raises(ValueError):
        obj.model_dump_json(warnings="error")
    obj = result()
    obj.manifest.coverage_counts[0].scanned = True
    with pytest.raises(ValueError):
        obj.model_dump_json(warnings="error")
    obj = result()
    obj.findings[0].collection_context.filter_applied.clear()
    with pytest.raises(ValueError):
        obj.model_dump_json(warnings="error")


@pytest.mark.parametrize("value", [0, 0.0, float("nan"), float("inf")])
def test_finding_raw_scalar_tampering_is_never_erased_by_json(value: object) -> None:
    obj = result()
    obj.findings[0].raw_data["object_enforcement_assessed"] = cast(Any, value)
    with warnings.catch_warnings(record=True) as caught, pytest.raises(ValueError):
        obj.model_dump_json(warnings="error")
    assert caught == []


def test_serialization_schema_retains_full_declared_shapes() -> None:
    request_schema = c.StorageRetentionCollectRequest.model_json_schema(mode="serialization")
    assert request_schema["discriminator"]["propertyName"] == "provider"
    result_schema = c.StorageRetentionCollectResult.model_json_schema(mode="serialization")
    assert set(c.StorageRetentionCollectResult.model_fields) == set(result_schema["properties"])
    assert "resources" in result_schema["required"]
    assert "findings" in result_schema["required"]
    assert result_schema["properties"]["scope_label"]["pattern"] == NON_BLANK_PATTERN


@pytest.mark.parametrize("provider", ["s3", "azure", "gcs"])
def test_extra_fields_wrong_container_and_target_limits(provider: c.ProviderName) -> None:
    body = request(provider).model_dump()
    for key, value in (("token", "synthetic"), ("base_url", "https://example.org"), ("provider", "wrong")):
        with pytest.raises(c.StorageRetentionInputError):
            c.validated_request({**body, key: value})
    invalid_targets: tuple[object, ...] = (
        [],
        tuple(body["targets"]),
        {"target": body["targets"][0]},
        body["targets"] * 21,
    )
    for targets in invalid_targets:
        with pytest.raises(c.StorageRetentionInputError):
            c.validated_request({**body, "targets": targets})
    req = request(provider, 20)
    assert len(c.parse_request(req.model_dump_json().encode()).root.targets) == 20


def test_projection_size_includes_metadata_and_exact_digest_boundary() -> None:
    value = projection()
    obj = value._wire().model_dump(mode="json")
    obj.pop("canonical_projection_sha256")
    expected = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert c.projection_size(value) == len(expected)
    assert c.projection_size(value) > len(json.dumps(value.fields).encode())
    wire = value._wire()
    with pytest.raises(ValidationError):
        wire.model_copy(update={"canonical_projection_sha256": "0" * 64})
    minimum = c.ProjectedComponent(api_version="v1", native_scope="bucket", fields={"text": ""})
    exact = c.ProjectedComponent(
        api_version="v1", native_scope="bucket", fields={"text": "x" * (16384 - c.projection_size(minimum))}
    )
    assert c.projection_size(exact) == 16384
    with pytest.raises(c.StorageRetentionInputError):
        c.ProjectedComponent(
            api_version="v1", native_scope="bucket", fields={"text": "x" * (16385 - c.projection_size(minimum))}
        )


@pytest.mark.parametrize("status", [201, 202, 204, 206, 301, 403, 404, 500])
def test_gcs_admission_never_accepts_wrong_http_status(status: int) -> None:
    obj = result("gcs").resources[0].components[0]
    with pytest.raises(ValidationError):
        obj.model_copy(update={"http_status": status})


def test_exact_absent_lock_and_projection_diagnostic_merge() -> None:
    target = request().root.targets[0]
    value = c.ProjectedComponent(
        api_version="2006-03-01",
        native_scope="bucket",
        fields={"absence": True},
        diagnostics=(c.StorageRetentionDiagnostic(code="missing_source_detail"),),
    )
    part = c.make_component_result(
        "s3-object-lock",
        target,
        attempts=1,
        raw_bytes=4,
        decoded_bytes=4,
        started_at=START,
        finished_at=END,
        http_status=404,
        projection=value,
        diagnostics=(),
    )
    assert part.status == "partial"
    assert [d.code for d in part.diagnostics] == ["missing_source_detail"]
    with pytest.raises(ValidationError):
        part.model_copy(update={"diagnostics": [c.StorageRetentionDiagnostic(code="forbidden")]})


def test_result_copy_deep_detaches_nested_fields() -> None:
    obj = result()
    cloned = obj.model_copy(deep=True)
    assert cloned == obj
    clone_projection = cloned.resources[0].components[0].projection
    original_projection = obj.resources[0].components[0].projection
    assert clone_projection is not None and original_projection is not None
    clone_projection.fields["retentionPeriod"] = "7"
    assert original_projection.fields["retentionPeriod"] == "00086400"
    assert c.StorageRetentionCollectResult.model_validate_json(obj.model_dump_json()) == obj


def test_full_result_preserves_twenty_maximal_azure_resource_projections() -> None:
    req = request("azure", 20)
    observed = c.ProjectedComponent(api_version="2026-04-01", native_scope="container", fields={"text": "x" * 15_900})
    components: dict[str, list[c.StorageRetentionComponentResult]] = {}
    for target in req.root.targets:
        components[c.target_identity(target)] = [
            c.make_component_result(
                name,
                target,
                attempts=1,
                raw_bytes=16_000,
                decoded_bytes=16_000,
                started_at=START,
                finished_at=END,
                http_status=200,
                projection=observed,
                diagnostics=(),
            )
            for name in c.component_ids("azure")
        ]
    obj = c.make_result(
        req, run_id="maximal-synthetic", started_at=START, finished_at=END, components=components, diagnostics=()
    )
    assert len(obj.resources) == len(obj.findings) == 20
    assert obj.completed_components == 60
    assert obj.status == "complete"
    assert sum(item.raw_bytes for row in obj.resources for item in row.components) == 960_000
    assert sum(item.decoded_bytes for row in obj.resources for item in row.components) == 960_000
    assert 1_900_000 < len(obj.model_dump_json().encode()) <= c.RESULT_BYTE_LIMIT


class _ResponseWrapper(BaseModel):
    request: c.StorageRetentionCollectRequest
    result: c.StorageRetentionCollectResult


def test_shared_response_nested_schema_and_validation_boundary() -> None:
    obj = _ResponseWrapper(request=request(), result=result())
    schema = TypeAdapter(_ResponseWrapper).json_schema(mode="serialization")
    assert schema["$defs"]["StorageRetentionCollectRequest"]["discriminator"]["propertyName"] == "provider"
    assert "resources" in schema["$defs"]["StorageRetentionCollectResult"]["properties"]
    obj.result.resources[0].components[0].__dict__["raw_bytes"] = True
    with warnings.catch_warnings(record=True) as caught, pytest.raises(ValueError):
        TypeAdapter(_ResponseWrapper).dump_json(obj, warnings="error")
    assert caught == []


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_raw_null_cannot_hide_nonfinite_mutation(bad: float) -> None:
    obj = result()
    raw: Any = obj.findings[0].raw_data
    raw["resource"]["components"][0]["projection"]["fields"]["missing_is_omitted"] = bad
    with warnings.catch_warnings(record=True) as caught, pytest.raises(ValueError):
        obj.model_dump_json(warnings="error")
    assert caught == []


@pytest.mark.parametrize(
    "label",
    ["A", "a.b-C_2", "A" * 64, "A\n", " A", "A ", "A\r\n", *[chr(n) for n in range(0x3001) if chr(n).isspace()]],
)
def test_alias_runtime_and_published_patterns_agree(label: str) -> None:
    import re

    branch = c.S3RetentionRequest.model_json_schema()["properties"]["scope_label"]
    patterns = [branch["pattern"], *[entry["pattern"] for entry in branch["allOf"]]]
    schema_accepts = 1 <= len(label) <= 64 and all(re.search(pattern, label) for pattern in patterns)
    body = request().model_dump()
    body["scope_label"] = label
    try:
        parsed = c.validated_request(body)
    except c.StorageRetentionInputError:
        assert not schema_accepts
    else:
        assert schema_accepts
        assert parsed.root.scope_label == label


def test_collection_clock_normalizes_offset_without_losing_microseconds() -> None:
    req = request("gcs")
    target = req.root.targets[0]
    from datetime import timezone

    offset = timezone(timedelta(hours=5, minutes=30))
    begin = START.astimezone(offset)
    finish = END.astimezone(offset)
    part = c.make_component_result(
        "gcs-bucket",
        target,
        attempts=1,
        raw_bytes=0,
        decoded_bytes=0,
        started_at=begin,
        finished_at=finish,
        http_status=200,
        projection=projection(),
        diagnostics=(),
    )
    assert part.started_at == START
    assert part.started_at is not None and part.started_at.tzinfo is UTC
    assert "2024-01-02T03:04:05.123456Z" in part.model_dump_json()


def test_manifest_types_advertise_the_safe_integer_ceiling() -> None:
    for mode in ("validation", "serialization"):
        schema = c.StorageRetentionCollectResult.model_json_schema(mode=mode)
        manifest = schema["$defs"]["_StrictManifest"]
        count_ref = manifest["properties"]["coverage_counts"]["items"]["$ref"].rsplit("/", 1)[1]
        assert schema["$defs"][count_ref]["properties"]["scanned"]["maximum"] == 2**53 - 1


def _budget_component(
    target: c.StorageTarget,
    *,
    attempts: int = 1,
    raw_bytes: int = c.RESPONSE_BYTE_LIMIT,
    decoded_bytes: int = c.RESPONSE_BYTE_LIMIT,
    state: str = "complete",
) -> c.StorageRetentionComponentResult:
    return c.make_component_result(
        "gcs-bucket",
        target,
        attempts=attempts,
        raw_bytes=raw_bytes,
        decoded_bytes=decoded_bytes,
        started_at=START,
        finished_at=END,
        http_status=200,
        projection=None if state == "unavailable" else projection(),
        diagnostics=(c.StorageRetentionDiagnostic(code="response_limit"),)
        if state == "unavailable"
        else (c.StorageRetentionDiagnostic(code="missing_source_detail"),)
        if state == "partial"
        else (),
    )


@pytest.mark.parametrize("attempts", [1, 2, 3])
@pytest.mark.parametrize("field", ["raw_bytes", "decoded_bytes"])
@pytest.mark.parametrize("state", ["complete", "partial"])
def test_admitted_component_budget_rejects_impossible_bytes(attempts: int, field: str, state: str) -> None:
    counters = {"raw_bytes": 1, "decoded_bytes": 1, field: attempts * c.RESPONSE_BYTE_LIMIT + 1}
    with pytest.raises(c.StorageRetentionInputError, match=r"^invalid_result$"):
        _budget_component(request("gcs").root.targets[0], attempts=attempts, state=state, **counters)


@pytest.mark.parametrize("attempts", [1, 2, 3])
@pytest.mark.parametrize("state", ["complete", "partial"])
def test_admitted_component_budget_preserves_exact_retry_ceiling(attempts: int, state: str) -> None:
    measured = attempts * c.RESPONSE_BYTE_LIMIT
    obj = _budget_component(
        request("gcs").root.targets[0], attempts=attempts, raw_bytes=measured, decoded_bytes=measured, state=state
    )
    restored = c.StorageRetentionComponentResult.model_validate_json(obj.model_dump_json(warnings="error"))
    assert restored.raw_bytes == restored.decoded_bytes == measured
    assert restored.status == state
    assert restored.projection is not None


@pytest.mark.parametrize("field", ["raw_bytes", "decoded_bytes"])
@pytest.mark.parametrize("boundary", ["copy", "json", "serialize", "adapter"])
def test_admitted_component_budget_rejects_persistence_bypass(field: str, boundary: str) -> None:
    obj = _budget_component(request("gcs").root.targets[0], attempts=3)
    measured = 3 * c.RESPONSE_BYTE_LIMIT + 1
    wire = obj.model_dump(mode="json")
    wire[field] = measured
    with warnings.catch_warnings(record=True) as caught, pytest.raises(ValueError, match="invalid_admitted_byte_count"):
        if boundary == "copy":
            obj.model_copy(update={field: measured})
        elif boundary == "json":
            c.StorageRetentionComponentResult.model_validate_json(json.dumps(wire))
        else:
            forged = c.StorageRetentionComponentResult.model_construct(**obj.__dict__)
            forged.__dict__[field] = measured
            if boundary == "serialize":
                forged.model_dump_json(warnings="error")
            else:
                TypeAdapter(c.StorageRetentionComponentResult).dump_json(forged, warnings="error")
    assert caught == []


def _complete_budget_result(*, extra_field: str | None = None) -> c.StorageRetentionCollectResult:
    req = request("gcs", 16)
    components: dict[str, list[c.StorageRetentionComponentResult]] = {}
    for index, target in enumerate(cast(c.GcsRetentionRequest, req.root).targets):
        counters = {"raw_bytes": c.RESPONSE_BYTE_LIMIT, "decoded_bytes": c.RESPONSE_BYTE_LIMIT}
        if index == 0 and extra_field is not None:
            counters[extra_field] += 1
        components[c.target_identity(target)] = [
            _budget_component(
                target,
                attempts=2 if index == 0 else 1,
                raw_bytes=counters["raw_bytes"],
                decoded_bytes=counters["decoded_bytes"],
            )
        ]
    return c.make_result(
        req, run_id="budget-synthetic", started_at=START, finished_at=END, components=components, diagnostics=()
    )


def test_complete_run_budget_accepts_both_exact_ceilings() -> None:
    obj = _complete_budget_result()
    restored = c.StorageRetentionCollectResult.model_validate_json(obj.model_dump_json(warnings="error"))
    parts = [item for resource in restored.resources for item in resource.components]
    assert sum(item.raw_bytes for item in parts) == c.RUN_BYTE_LIMIT
    assert sum(item.decoded_bytes for item in parts) == c.RUN_BYTE_LIMIT
    assert restored.status == "complete"
    assert restored.manifest.is_complete is True
    assert restored.completed_components == 16
    assert len(restored.findings) == 16


@pytest.mark.parametrize("field", ["raw_bytes", "decoded_bytes"])
def test_complete_run_budget_rejects_one_byte_over(field: str) -> None:
    with pytest.raises(c.StorageRetentionInputError, match=r"^invalid_result$"):
        _complete_budget_result(extra_field=field)


@pytest.mark.parametrize("field", ["raw_bytes", "decoded_bytes"])
@pytest.mark.parametrize("boundary", ["copy", "json", "serialize", "adapter"])
def test_complete_run_budget_rejects_consistent_persistence_bypass(field: str, boundary: str) -> None:
    obj = _complete_budget_result()
    wire = obj.model_dump(mode="json")
    wire["resources"][0]["components"][0][field] += 1
    wire["findings"][0]["raw_data"]["resource"]["components"][0][field] += 1
    part = obj.resources[0].components[0]
    part.__dict__[field] += 1
    raw_data: Any = obj.findings[0].raw_data
    raw_data["resource"]["components"][0][field] += 1
    with warnings.catch_warnings(record=True) as caught, pytest.raises(ValueError, match="invalid_complete_byte_count"):
        if boundary == "copy":
            obj.model_copy(deep=True)
        elif boundary == "json":
            c.StorageRetentionCollectResult.model_validate_json(json.dumps(wire))
        elif boundary == "serialize":
            obj.model_dump_json(warnings="error")
        else:
            TypeAdapter(c.StorageRetentionCollectResult).dump_json(obj, warnings="error")
    assert caught == []


@pytest.mark.parametrize("field", ["raw_bytes", "decoded_bytes"])
@pytest.mark.parametrize("admitted", [False, True])
def test_refused_response_budget_overshoot_survives_full_result(field: str, admitted: bool) -> None:
    req = request("gcs", 2 if admitted else 1)
    target = req.root.targets[-1]
    measured = c.RUN_BYTE_LIMIT + 65_536
    counters = {"raw_bytes": 0, "decoded_bytes": 0, field: measured}
    refused = _budget_component(target, state="unavailable", **counters)
    components = {c.target_identity(req.root.targets[0]): [_budget_component(req.root.targets[0])]} if admitted else {}
    components[c.target_identity(target)] = [refused]
    obj = c.make_result(
        req, run_id="refused-synthetic", started_at=START, finished_at=END, components=components, diagnostics=()
    )
    restored = c.StorageRetentionCollectResult.model_validate_json(obj.model_dump_json(warnings="error"))
    assert getattr(restored.resources[-1].components[0], field) == measured
    assert restored.resources[-1].components[0].projection is None
    assert restored.status == ("partial" if admitted else "unavailable")
    assert restored.manifest.is_complete is False
    assert len(restored.findings) == int(admitted)
    if admitted:
        assert restored.resources[0].components[0].projection is not None
        assert restored.resources[0].status == "complete"
