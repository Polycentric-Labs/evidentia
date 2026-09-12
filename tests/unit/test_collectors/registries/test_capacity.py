"""Exercise derived result truth, publication fidelity and evidence bounds."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest
from evidentia_collectors.registries._contracts import (
    HostnameTarget,
    RegistryLookupRequest,
    RegistryLookupResult,
    SourceRead,
    SourceTime,
    diagnostic,
    make_observation,
    make_result,
    normalized_source_time,
    read_identifier,
    result_bytes,
)
from pydantic import BaseModel, TypeAdapter

NOW = datetime(2026, 9, 11, 12, 0, 0, tzinfo=UTC)
RUN = "01K4Z5S9P0123456789ABCDEFG"


def request() -> RegistryLookupRequest:
    return RegistryLookupRequest.model_validate({"registry": "rdap", "target": {"domain": "example.org"}})


def read(*, count: int = 1, status: str = "complete") -> SourceRead:
    selected = request()
    return SourceRead.model_validate(
        {
            "read_id": read_identifier(selected),
            "registry": "rdap",
            "ordinal": 0,
            "method": "GET",
            "template": "rdap_selected_domain",
            "query_scope": selected,
            "transport_kind": "https",
            "status": status,
            "freshness": "current_observation",
            "http_status": 200,
            "network_attempts": 1,
            "attempted_pages": 1,
            "accepted_pages": 1,
            "source_records": count,
            "admitted_records": count,
            "raw_bytes": 100,
            "decoded_bytes": 100,
            "body_complete": True,
            "source_digest": "1" * 64,
            "retrieved_at": NOW,
            "publisher_date": None,
            "publisher_version": None,
            "snapshot_source": None,
            "cache_state": "not_applicable",
            "transport_verified": True,
            "source_signature": "not_applicable",
        }
    )


def result(
    *, count: int = 1, status: str = "complete", identity: str = "example.org", fields: dict[str, Any] | None = None
) -> RegistryLookupResult:
    source = read(count=count, status=status)
    observations = [
        make_observation(
            "rdap",
            source.read_id,
            source_identity={"ldhName": f"example{index}.org"},
            matched_identity=identity,
            fields={"ldhName": "example.org"} if fields is None else fields,
            field_coverage={"ldhName": "present"},
        )
        for index in range(count)
    ]
    return make_result(
        request(),
        reads=[source],
        observations=observations,
        diagnostics=[] if status == "complete" else [diagnostic("traversal_incomplete", source.read_id)],
        started_at=NOW,
        finished_at=NOW,
        run_id=RUN,
    )


def test_complete_result_uses_core_compatibility_with_unknown_compliance() -> None:
    from evidentia_core.audit.provenance import CollectionContext, CollectionManifest, CoverageCount
    from evidentia_core.models.finding import ComplianceStatus

    value = result()
    assert value.lookup_outcome == "found"
    assert value.collection_status == "complete"
    assert value.observation_scope == "selected_registry_query"
    assert isinstance(value.manifest, CollectionManifest)
    assert isinstance(value.manifest.coverage_counts[0], CoverageCount)
    finding = value.findings[0]
    assert isinstance(finding.collection_context, CollectionContext)
    assert finding.collection_context.credential_identity == "not-established"
    assert finding.compliance_status == ComplianceStatus.UNKNOWN
    assert finding.control_mappings == []
    assert finding.raw_data.observation == value.observations[0]
    assert RegistryLookupResult.model_validate_json(result_bytes(value)) == value


@pytest.mark.parametrize(
    "count,status,outcome,complete",
    [
        (0, "complete", "not_found", True),
        (0, "partial", "unavailable", False),
        (2, "complete", "found", True),
        (1, "partial", "found", False),
    ],
)
def test_selected_query_status_is_derived(count: int, status: str, outcome: str, complete: bool) -> None:
    value = result(count=count, status=status)
    assert value.lookup_outcome == outcome
    assert value.manifest.is_complete is complete
    assert value.manifest.empty_categories == (["selected_registry_query"] if outcome == "not_found" else [])
    assert value.manifest.total_findings == count


def test_different_candidate_identities_are_ambiguous() -> None:
    source = read(count=2)
    observations = [
        make_observation(
            "rdap",
            source.read_id,
            source_identity={"id": name},
            matched_identity=name,
            fields={"ldhName": name},
            field_coverage={"ldhName": "present"},
        )
        for name in ("first.example.org", "second.example.org")
    ]
    value = make_result(
        request(), reads=[source], observations=observations, diagnostics=[], started_at=NOW, finished_at=NOW
    )
    assert value.lookup_outcome == "ambiguous"
    assert value.manifest.is_complete


@pytest.mark.parametrize(
    "path,replacement",
    [
        (("lookup_outcome",), "not_found"),
        (("collection_status",), "partial"),
        (("freshness",), "dated_snapshot"),
        (("registry",), "tls"),
        (("manifest", "total_findings"), 0),
        (("manifest", "is_complete"), False),
        (("manifest", "empty_categories"), ["selected_registry_query"]),
        (("manifest", "filters_applied"), {}),
        (("manifest", "coverage_counts", 0, "scanned"), True),
        (("findings", 0, "compliance_status"), "pass"),
        (("findings", 0, "collection_context", "credential_identity"), "authenticated"),
        (("findings", 0, "raw_data", "observation", "fields"), {}),
        (("source_reads", 0, "admitted_records"), 0),
        (("source_reads", 0, "source_digest"), "2" * 63),
    ],
)
def test_contradictory_native_and_json_results_are_refused(path: tuple[str | int, ...], replacement: Any) -> None:
    body = json.loads(result_bytes(result()))
    parent = body
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = replacement
    with pytest.raises(ValueError):
        RegistryLookupResult.model_validate(body)
    with pytest.raises(ValueError):
        RegistryLookupResult.model_validate_json(json.dumps(body))


def test_frozen_evidence_and_forced_mutation_revalidation() -> None:
    value = result()
    with pytest.raises(TypeError):
        value.observations.append(value.observations[0])
    with pytest.raises(TypeError):
        value.observations[0].fields["ldhName"] = "changed.example.org"
    with pytest.raises(TypeError):
        value.manifest.filters_applied.clear()
    copied = value.model_copy(deep=True)
    assert copied == value and copied is not value
    assert copied.observations[0].fields is not value.observations[0].fields
    dict.__setitem__(value.observations[0].fields, "ldhName", "changed.example.org")
    with pytest.raises(ValueError):
        result_bytes(value)


@pytest.mark.parametrize(
    "literal,expected",
    [
        ("2026-09-11T12:00:00Z", "2026-09-11T12:00:00.000000Z"),
        ("2026-09-11t08:00:00.123456000-04:00", "2026-09-11T12:00:00.123456Z"),
        ("2026-09-11T12:00:00.1234561Z", None),
        ("2026-09-11", None),
        ("2026-09-11T12:00:60Z", None),
        ("2026-09-11T12:00:00-00:00", None),
        ("2026-09-11T12:00:00+00:99", None),
        ("2026-09-11T25:00:00Z", None),
        ("01/31/11", None),
    ],
)
def test_source_times_preserve_literals_without_rounding(literal: str, expected: str | None) -> None:
    value = SourceTime.model_validate(
        {"path": "/events/0/eventDate", "literal": literal, "representation": "rfc3339", "normalized_utc": expected}
    )
    assert value.literal == literal
    assert normalized_source_time(literal) == expected
    assert value.model_dump(mode="json")["literal"] == literal


def test_numeric_timestamp_is_not_stringified_or_rounded() -> None:
    assert normalized_source_time(1, "unix_milliseconds") == "1970-01-01T00:00:00.001000Z"
    assert normalized_source_time(0.1, "unix_milliseconds") is None
    with pytest.raises(ValueError):
        SourceTime.model_validate(
            {
                "path": "/expiry",
                "literal": "2026-09-11T12:00:00.0000001Z",
                "representation": "rfc3339",
                "normalized_utc": "2026-09-11T12:00:00.000000Z",
            }
        )


def test_incomplete_body_cannot_claim_complete_digest() -> None:
    with pytest.raises(ValueError):
        read().model_copy(update={"body_complete": False})
    changed = read().model_copy(update={"body_complete": False, "source_digest": None, "status": "partial"})
    assert changed.source_digest is None


@pytest.mark.parametrize(
    "native",
    [
        {"registry": "tls", "target": {"hostname": "example.org", "base_url": "ignored"}},
        {"registry": "tls", "target": {"hostname": "example.org"}, "extra": True},
    ],
)
def test_nested_extra_override_cannot_bypass_request_shape(native: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        TypeAdapter(RegistryLookupRequest).validate_python(native, extra="ignore")


@pytest.mark.parametrize(
    "raw",
    [
        b'{"registry":"tls","registry":"tls","target":{"hostname":"example.org"}}',
        b" " * 65_536 + b'{"registry":"tls","target":{"hostname":"example.org"}}',
        b'{"registry":"tls","target":{"hostname":"example.org"}}',
    ],
    ids=["duplicate-key", "raw-byte-limit", "explicit-raw-json-entry-point"],
)
def test_nested_raw_json_requires_the_public_preflight(raw: bytes) -> None:
    with pytest.raises(ValueError):
        TypeAdapter(RegistryLookupRequest).validate_json(raw)

    class Envelope(BaseModel):
        request: RegistryLookupRequest

    with pytest.raises(ValueError):
        Envelope.model_validate_json(b'{"request":' + raw + b"}")


def test_wire_copy_refuses_callbacks_before_touching_native_state() -> None:
    calls: list[str] = []

    class Trap(dict[str, Any]):
        def keys(self) -> Any:
            calls.append("keys")
            return super().keys()

        def __getitem__(self, key: str) -> Any:
            calls.append("get")
            return super().__getitem__(key)

    target = HostnameTarget(hostname="example.org")
    object.__setattr__(target, "__dict__", Trap(hostname="example.org"))
    with pytest.raises(ValueError):
        target.model_copy()
    assert calls == []


def test_root_copy_refuses_custom_key_equality() -> None:
    calls: list[str] = []

    class Key(str):
        def __eq__(self, other: object) -> bool:
            calls.append("eq")
            return super().__eq__(other)

        __hash__ = str.__hash__

    update: dict[str, Any] = {Key("root"): {"registry": "tls", "target": {"hostname": "example.org"}}}
    calls.clear()
    with pytest.raises(ValueError):
        request().model_copy(update=update)
    assert calls == []


def test_target_construction_refuses_native_string_subclasses() -> None:
    class Text(str):
        pass

    with pytest.raises(ValueError):
        HostnameTarget(hostname=Text("example.org"))


def sized_observation(index: int, size: int) -> Any:
    from evidentia_collectors.registries._parsing import canonical_json

    source = read()

    def construct(padding: str) -> Any:
        return make_observation(
            "rdap",
            source.read_id,
            source_identity={"id": str(index)},
            matched_identity="example.org",
            fields={"notices": [{"description": [padding]}]},
            field_coverage={"notices": "present"},
        )

    base = construct("")
    overhead = len(canonical_json(base.model_dump(mode="json")))
    return construct("x" * (size - overhead))


def test_complete_observation_byte_boundary_and_plus_one() -> None:
    from evidentia_collectors.registries._parsing import canonical_json

    value = sized_observation(0, 65_536)
    assert len(canonical_json(value.model_dump(mode="json"))) == 65_536
    with pytest.raises(ValueError):
        sized_observation(0, 65_537)


def test_duplicated_evidence_exceeds_export_before_observation_budget() -> None:
    from evidentia_collectors.registries._contracts import CapacityPlan
    from evidentia_collectors.registries._parsing import canonical_json

    values = [sized_observation(index, 65_536) for index in range(32)]
    assert sum(len(canonical_json(value.model_dump(mode="json"))) for value in values) == 2_097_152
    plan = CapacityPlan(request())
    assert plan.reserved_bytes(values) > 4_194_304
    assert plan.refusal(values) == "result_limit"
    with pytest.raises(ValueError):
        make_result(
            request(),
            reads=[read(count=32)],
            observations=values,
            diagnostics=[],
            started_at=NOW,
            finished_at=NOW,
            run_id=RUN,
        )


def test_capacity_uses_exact_encoded_skeleton_boundary() -> None:
    from evidentia_collectors.registries._contracts import CapacityPlan, _CapacityLimits

    values = list(result().observations)
    size = CapacityPlan(request()).reserved_bytes(values)
    assert size > len(result_bytes(result()))
    assert CapacityPlan(request(), _limits=_CapacityLimits(result_bytes=size)).refusal(values) is None
    assert CapacityPlan(request(), _limits=_CapacityLimits(result_bytes=size - 1)).refusal(values) == "result_limit"


def test_capacity_preserves_the_previous_page_on_atomic_refusal() -> None:
    from evidentia_collectors.registries._contracts import CapacityPlan, _CapacityLimits

    accepted = list(result().observations)
    next_page = [sized_observation(99, 800)]
    before = [item.model_dump(mode="json") for item in accepted]
    plan = CapacityPlan(request(), _limits=_CapacityLimits(records=1))
    assert plan.refusal(accepted) is None
    assert plan.refusal(accepted + next_page) == "record_limit"
    assert [item.model_dump(mode="json") for item in accepted] == before


def test_capacity_reduced_observation_ceiling_exercises_size_refusal() -> None:
    from evidentia_collectors.registries._contracts import CapacityPlan, _CapacityLimits

    value = sized_observation(3, 900)
    assert CapacityPlan(request(), _limits=_CapacityLimits(observation_bytes=900)).refusal([value]) is None
    assert (
        CapacityPlan(request(), _limits=_CapacityLimits(observation_bytes=899)).refusal([value]) == "observation_limit"
    )
    assert (
        CapacityPlan(request(), _limits=_CapacityLimits(observations_bytes=899)).refusal([value]) == "observation_limit"
    )
    with pytest.raises(ValueError):
        _CapacityLimits(result_bytes=4_194_305)
    with pytest.raises(ValueError):
        _CapacityLimits(records=True)


def test_skeleton_binds_all_concrete_model_fields_and_metadata_copies() -> None:
    from evidentia_collectors.registries._contracts import (
        RegistryDiagnostic,
        RegistryFinding,
        RegistryManifest,
        _terminal_skeleton,
    )

    value = result()
    body = _terminal_skeleton(request(), list(value.observations))
    assert set(body) == set(RegistryLookupResult.model_fields)
    assert set(body["manifest"]) == set(RegistryManifest.model_fields)
    assert len(body["source_reads"]) == 24
    assert all(set(item) == set(SourceRead.model_fields) for item in body["source_reads"])
    assert len(body["diagnostics"]) == 64
    assert all(set(item) == set(RegistryDiagnostic.model_fields) for item in body["diagnostics"])
    assert set(body["findings"][0]) == set(RegistryFinding.model_fields)
    assert body["observations"][0] == body["findings"][0]["raw_data"]["observation"]


def test_result_factory_rejects_custom_collections_without_iteration() -> None:
    calls: list[str] = []

    class Trap(list[Any]):
        def __iter__(self) -> Any:
            calls.append("iter")
            return super().__iter__()

    with pytest.raises(ValueError):
        make_result(request(), reads=Trap(), observations=[], diagnostics=[], started_at=NOW, finished_at=NOW)
    assert calls == []


@pytest.mark.parametrize("path", [(), ("source_reads", 0), ("manifest",), ("findings", 0), ("observations", 0)])
def test_lax_extra_override_cannot_discard_result_evidence(path: tuple[str | int, ...]) -> None:
    body = json.loads(result_bytes(result()))
    node = body
    for part in path:
        node = node[part]
    node["unexpected_field"] = "discard-me"
    with pytest.raises(ValueError):
        TypeAdapter(RegistryLookupResult).validate_python(body, extra="ignore")


@pytest.mark.parametrize("replacement", ["1", 1.0, True])
def test_lax_validation_cannot_coerce_ledger_counts(replacement: Any) -> None:
    body = json.loads(result_bytes(result()))
    body["source_reads"][0]["network_attempts"] = replacement
    with pytest.raises(ValueError):
        TypeAdapter(RegistryLookupResult).validate_python(body, strict=False)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"path":"/x","path":"/x","literal":null,"representation":"source_text","normalized_utc":null}',
        b'{"path":"/x","literal":1e-400,"representation":"source_text","normalized_utc":null}',
        b'{"path":"/x","literal":9007199254740993.0,"representation":"source_text","normalized_utc":null}',
        b" " * 4_194_304 + b'{"path":"/x","literal":null,"representation":"source_text","normalized_utc":null}',
    ],
    ids=["duplicate-key", "underflow", "precision-loss", "raw-byte-limit"],
)
def test_auxiliary_models_refuse_unpreflighted_json(raw: bytes) -> None:
    with pytest.raises(ValueError):
        TypeAdapter(SourceTime).validate_json(raw)


@pytest.mark.parametrize("location", ["root", "metadata", "literal"])
def test_unknown_metaclasses_never_run_equality_at_native_admission(location: str) -> None:
    calls: list[str] = []

    class Meta(type):
        def __eq__(cls, other: object) -> bool:
            calls.append("equal")
            return False

        __hash__ = type.__hash__

    class Unknown(metaclass=Meta):
        pass

    value: Any = Unknown()
    if location == "metadata":
        value = {"path": value, "literal": None, "representation": "source_text", "normalized_utc": None}
    elif location == "literal":
        value = {"path": "/x", "literal": value, "representation": "source_text", "normalized_utc": None}
    with pytest.raises(ValueError):
        SourceTime.model_validate(value)
    assert calls == []
