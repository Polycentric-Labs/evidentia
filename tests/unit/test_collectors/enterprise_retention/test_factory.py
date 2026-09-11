"""Evidence-ledger boundaries independent of provider transport."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from evidentia_collectors.enterprise_retention import _contracts as contracts
from evidentia_collectors.enterprise_retention._parsing import result_json_bytes
from evidentia_core.models.finding import SecurityFinding
from pydantic import JsonValue, ValidationError

CLOCK = datetime(2026, 1, 1, tzinfo=UTC)


def sample(kind: contracts.ReadKind) -> tuple[contracts.ReadKey, dict[str, Any]]:
    sources: dict[contracts.ReadKind, tuple[str, dict[str, Any]]] = {
        "vault-matter": ("matter-1", {"matterId": "matter-1", "state": "OPEN"}),
        "vault-holds": ("matter-1", {"holdId": "hold-1", "corpus": "MAIL"}),
        "splunk-index": ("events", {"name": "events", "content": {"datatype": "event", "disabled": False}}),
        "elastic-explain": ("events", {"index": "events", "managed": False}),
        "elastic-policy": ("retention-1", {"version": 1, "policy": {"phases": {}}}),
        "elastic-status": ("service", {"operation_mode": "RUNNING"}),
    }
    source_id, source = sources[kind]
    return contracts.ReadKey(kind=kind, source_id=source_id), source


def observation(kind: contracts.ReadKind) -> contracts.EnterpriseRetentionObservation:
    key, source = sample(kind)
    expected = contracts.expected_fields(kind, source)
    identity = "hold-1" if kind == "vault-holds" else key.source_id
    return contracts.make_observation(
        key, profile_alias="selected", source_identity=identity, fields=expected.fields, coverage=expected.coverage
    )


def admitted_read(kind: contracts.ReadKind) -> contracts.EnterpriseRetentionReadResult:
    key, _ = sample(kind)
    item = observation(kind)
    return contracts.empty_read(key, profile_alias="selected").model_copy(
        update={
            "status": "complete",
            "attempts": 1,
            "responses_received": 1,
            "pages_received": 1,
            "pages_admitted": 1,
            "records_received": 1,
            "records_admitted": 1,
            "raw_bytes": 200,
            "decoded_bytes": 200,
            "started_at": CLOCK,
            "finished_at": CLOCK,
            "safe_http_status": 200,
            "observations": [item],
        }
    )


@pytest.mark.parametrize("kind", list(contracts._METHODS))
def test_read_roundtrip_preserves_projection_and_clock(kind: contracts.ReadKind) -> None:
    value = admitted_read(kind)
    wire = value.model_dump_json()
    restored = contracts.EnterpriseRetentionReadResult.model_validate_json(wire)
    assert restored.model_dump(mode="python") == value.model_dump(mode="python")
    assert json.loads(wire)["started_at"] == "2026-01-01T00:00:00.000000Z"
    assert restored.observations[0].canonical_projection_sha256 == value.observations[0].canonical_projection_sha256


@pytest.mark.parametrize(
    "updates",
    [
        {"records_admitted": True},
        {"records_admitted": 0},
        {"responses_received": 2},
        {"pages_admitted": 0},
        {"safe_http_status": None},
        {"method_id": "vault.matters.get"},
        {"status": "unavailable"},
        {"conflicts_quarantined": 1},
        {"started_at": None},
        {"finished_at": datetime(2025, 1, 1, tzinfo=UTC)},
        {"terminal_reason": "http_denied"},
    ],
)
def test_admitted_ledger_refuses_inconsistent_native_state(updates: dict[str, Any]) -> None:
    with pytest.raises((ValueError, ValidationError)):
        admitted_read("splunk-index").model_copy(update=updates)


def test_empty_vault_enumeration_is_complete_evidence() -> None:
    key, _ = sample("vault-holds")
    value = contracts.empty_read(key, profile_alias="selected").model_copy(
        update={
            "status": "complete",
            "attempts": 1,
            "responses_received": 1,
            "pages_received": 1,
            "pages_admitted": 1,
            "raw_bytes": 12,
            "decoded_bytes": 12,
            "started_at": CLOCK,
            "finished_at": CLOCK,
            "safe_http_status": 200,
        }
    )
    assert value.records_admitted == 0
    assert value.status == "complete"
    assert value.observations == []


def test_later_failed_page_keeps_earlier_evidence() -> None:
    value = admitted_read("vault-holds")
    earlier = value.observations[0].canonical_projection_sha256
    failure = contracts.EnterpriseRetentionDiagnostic(code="http_denied", read_id=value.read_id, safe_http_status=403)
    value = value.model_copy(
        update={
            "status": "partial",
            "attempts": 2,
            "responses_received": 2,
            "safe_http_status": None,
            "terminal_reason": "http_denied",
            "diagnostics": [failure],
        }
    )
    restored = contracts.EnterpriseRetentionReadResult.model_validate_json(value.model_dump_json())
    assert restored.observations[0].canonical_projection_sha256 == earlier
    assert restored.pages_admitted == 1
    with pytest.raises(ValueError):
        value.model_copy(update={"status": "complete"})


def test_selected_fields_are_detached_and_tampering_invalidates_digest() -> None:
    key, source = sample("elastic-explain")
    expected = contracts.expected_fields(key.kind, source)
    value = contracts.make_observation(
        key, profile_alias="selected", source_identity=key.source_id, fields=expected.fields, coverage=expected.coverage
    )
    expected.fields["managed"] = True
    assert value.fields["managed"] is False
    value.fields["managed"] = True
    with pytest.raises((ValueError, ValidationError)):
        contracts.EnterpriseRetentionObservation.model_validate(value)
    with pytest.raises(ValueError):
        value.model_dump_json()


def test_constructed_projection_cannot_bypass_nested_admission() -> None:
    value = admitted_read("elastic-explain")
    forged = contracts.EnterpriseRetentionObservation.model_construct(**value.observations[0].model_dump())
    forged.fields["managed"] = 1
    with pytest.raises((ValueError, ValidationError)):
        value.model_copy(update={"observations": [forged]})


def test_archive_derivation_does_not_attest_discarded_path() -> None:
    key, _ = sample("splunk-index")

    def project(path: str) -> contracts.EnterpriseRetentionObservation:
        expected = contracts.expected_fields(key.kind, {"name": "events", "content": {"coldToFrozenDir": path}})
        return contracts.make_observation(
            key,
            profile_alias="selected",
            source_identity=key.source_id,
            fields=expected.fields,
            coverage=expected.coverage,
        )

    first, second = project("first discarded value"), project("second discarded value")
    assert first.canonical_projection_sha256 == second.canonical_projection_sha256
    assert "discarded" not in first.model_dump_json()


@pytest.mark.parametrize(
    "wire_clock",
    [
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.000000+00:00",
        "2026-01-01T00:00:00.0000000Z",
        "2026-01-01T00:00:00.000000Z\n",
    ],
)
def test_collection_wire_clock_has_one_exact_format(wire_clock: str) -> None:
    body = json.loads(admitted_read("elastic-status").model_dump_json())
    body["started_at"] = wire_clock
    with pytest.raises(ValueError):
        contracts.EnterpriseRetentionReadResult.model_validate_json(json.dumps(body))


def test_http_status_ambiguity_cannot_revert_to_a_later_status() -> None:
    statuses = contracts.HttpStatusAccumulator()
    for value in (None, 503, 200, 200, None):
        statuses.add(value)
    assert statuses.value is None


def test_whole_observation_limit_counts_metadata_and_preserves_prior_value() -> None:
    key, source = sample("vault-holds")
    small = observation(key.kind)
    before = small.model_dump_json()
    source["name"] = "x" * contracts.PROJECTION_BYTE_LIMIT
    expected = contracts.expected_fields(key.kind, source)
    with pytest.raises(ValueError, match="projection_limit"):
        contracts.make_observation(
            key, profile_alias="selected", source_identity="hold-1", fields=expected.fields, coverage=expected.coverage
        )
    assert small.model_dump_json() == before


def test_diagnostic_cannot_cross_read_kinds_under_matching_owner_text() -> None:
    matter = contracts.read_identifier(
        "google-vault", "selected", contracts.ReadKey(kind="vault-matter", source_id="matter-1")
    )
    diagnostic = contracts.EnterpriseRetentionDiagnostic(
        code="duplicate_conflict", read_id=matter, safe_http_status=200
    )
    with pytest.raises(ValueError):
        contracts.checked_diagnostics(
            [diagnostic], scope="read", provider="google-vault", kind="vault-holds", owner_read_id=matter
        )


@pytest.mark.parametrize(
    "context",
    [
        {"scope": "future", "provider": "google-vault"},
        {"scope": "run", "provider": "future"},
        {"scope": "run", "provider": "google-vault", "kind": "elastic-explain"},
        {"scope": "read", "provider": "google-vault"},
    ],
)
def test_empty_diagnostics_still_validate_the_context(context: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        contracts.checked_diagnostics([], **context)


def test_diagnostic_context_rejects_objects_before_equality_callbacks() -> None:
    calls: list[object] = []

    class Spoof:
        def __eq__(self, other: object) -> bool:
            calls.append(other)
            return True

    with pytest.raises(ValueError):
        contracts.diagnostic_rule("credential_missing", cast(contracts.DiagnosticScope, Spoof()), "google-vault")
    with pytest.raises(ValueError):
        contracts.diagnostic_rule("credential_missing", "run", cast(contracts.ProviderName, Spoof()))
    assert calls == []


RUN_ID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"


def request_for(provider: contracts.ProviderName) -> contracts.EnterpriseRetentionCollectRequest:
    target = {"matter_id": "matter-1"} if provider == "google-vault" else {"index": "events"}
    return contracts.EnterpriseRetentionCollectRequest.model_validate(
        {
            "provider": provider,
            "profile_alias": "selected",
            "scope_label": "selected",
            "targets": [target],
        }
    )


def result_for(
    provider: contracts.ProviderName, *, complete: bool = True
) -> contracts.EnterpriseRetentionCollectResult:
    request = request_for(provider)
    reads = [
        admitted_read(key.kind) if complete else contracts.empty_read(key, profile_alias="selected")
        for key in contracts.initial_read_keys(request)
    ]
    return contracts.make_result(
        request,
        reads=reads,
        run_id=RUN_ID,
        started_at=CLOCK,
        finished_at=CLOCK,
        diagnostics=[],
        collector_version="0.13.0",
        evidentia_version="0.13.0",
    )


@pytest.mark.parametrize("provider", ["google-vault", "splunk-enterprise", "elastic-ilm"])
@pytest.mark.parametrize("complete", [True, False])
def test_full_factory_roundtrip_and_exact_unique_manifest(provider: contracts.ProviderName, complete: bool) -> None:
    value = result_for(provider, complete=complete)
    wire = value.publication_bytes()
    restored = contracts.EnterpriseRetentionCollectResult.model_validate_json(wire)
    assert restored.publication_bytes() == wire
    assert value.root.status == ("complete" if complete else "unavailable")
    assert value.root.manifest.resources_requested == 1
    assert value.root.manifest.resources_attempted == int(complete)
    assert value.root.manifest.attempts == (len(value.root.source_reads) if complete else 0)
    assert len(value.root.findings) == int(complete)
    if complete:
        assert value.root.findings[0].control_mappings == []
        assert value.root.findings[0].collection_context.run_id == RUN_ID
        assert isinstance(value.root.findings[0], SecurityFinding)


def test_shared_service_alone_preserves_read_without_index_claim() -> None:
    request = request_for("elastic-ilm")
    reads = [
        admitted_read("elastic-status"),
        contracts.empty_read(sample("elastic-explain")[0], profile_alias="selected"),
    ]
    value = contracts.make_result(
        request,
        reads=reads,
        run_id=RUN_ID,
        started_at=CLOCK,
        finished_at=CLOCK,
        diagnostics=[],
        collector_version="0.13.0",
        evidentia_version="0.13.0",
    )
    assert value.root.status == "unavailable"
    assert value.root.resources[0].status == "partial"
    assert value.root.manifest.resources_attempted == 0
    assert value.root.manifest.attempts == 1
    assert value.root.findings == []
    assert value.root.source_reads[0].observations


@pytest.mark.parametrize(
    "path,value",
    [
        (("manifest", "attempts"), 10),
        (("manifest", "resources_attempted"), 0),
        (("authenticated_identity_verified",), 0),
        (("object_enforcement_assessed",), True),
        (("findings", 0, "control_mappings"), [{"framework": "invented", "control_id": "invented"}]),
        (("findings", 0, "collection_context", "credential_identity"), "invented"),
        (("findings", 0, "first_observed"), "2026-01-01T00:00:00Z"),
        (("findings", 0, "raw_data", "reads", 0, "observations"), 9),
        (("resources", 0, "status"), "unavailable"),
    ],
)
def test_full_wire_rejects_forged_totals_scope_and_findings(path: tuple[Any, ...], value: Any) -> None:
    body = json.loads(result_for("splunk-enterprise").publication_bytes())
    parent = body
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    with pytest.raises(contracts.EnterpriseRetentionInputError, match="invalid_result"):
        contracts.EnterpriseRetentionCollectResult.model_validate_json(json.dumps(body))


def test_full_result_schema_keeps_the_provider_branches_in_both_modes() -> None:
    for mode in ("validation", "serialization"):
        schema = contracts.EnterpriseRetentionCollectResult.model_json_schema(mode=mode)
        assert set(schema["discriminator"]["mapping"]) == {"google-vault", "splunk-enterprise", "elastic-ilm"}
        assert len(schema["oneOf"]) == 3


def maximum_request(provider: contracts.ProviderName) -> contracts.EnterpriseRetentionCollectRequest:
    limit = 128 if provider == "google-vault" else 80 if provider == "splunk-enterprise" else 255
    identities = [f"i{index:02d}" + "x" * (limit - 3) for index in range(20)]
    key = "matter_id" if provider == "google-vault" else "index"
    return contracts.EnterpriseRetentionCollectRequest.model_validate(
        {
            "provider": provider,
            "profile_alias": "a" * 64,
            "scope_label": "s" * 64,
            "targets": [{key: identity} for identity in identities],
        }
    )


def read_from_source(
    key: contracts.ReadKey, source: dict[str, Any], alias: str
) -> contracts.EnterpriseRetentionReadResult:
    fields = contracts.expected_fields(key.kind, source)
    identity = source["holdId"] if key.kind == "vault-holds" else key.source_id
    item = contracts.make_observation(
        key, profile_alias=alias, source_identity=identity, fields=fields.fields, coverage=fields.coverage
    )
    return contracts.empty_read(key, profile_alias=alias).model_copy(
        update={
            "status": "complete",
            "attempts": 1,
            "responses_received": 1,
            "pages_received": 1,
            "pages_admitted": 1,
            "records_received": 1,
            "records_admitted": 1,
            "raw_bytes": 1000,
            "decoded_bytes": 1000,
            "started_at": CLOCK,
            "finished_at": CLOCK,
            "safe_http_status": 200,
            "observations": [item],
        }
    )


@pytest.mark.parametrize("provider", ["google-vault", "splunk-enterprise", "elastic-ilm"])
def test_maximum_metadata_plus_observation_limit_is_below_publication_limit(provider: contracts.ProviderName) -> None:
    request = maximum_request(provider)
    plan = contracts.CapacityPlan(request)
    assert plan.maximum_result_bound_bytes < contracts.RESULT_BYTE_LIMIT
    assert plan.maximum_result_bound_bytes > contracts.RUN_PROJECTION_BYTE_LIMIT
    assert plan.metadata_bound_bytes == len(result_json_bytes(contracts._terminal_skeleton(request)))
    print(f"capacity {provider}: metadata={plan.metadata_bound_bytes} combined={plan.maximum_result_bound_bytes}")
    with pytest.raises(AttributeError, match="immutable_capacity_plan"):
        plan._limit = 1


def test_real_maximum_elastic_result_has_41_reads_20_findings_and_bound_parity() -> None:
    request = maximum_request("elastic-ilm")
    keys = contracts.initial_read_keys(request)
    policies = [f"p{index:02d}" + "x" * 252 for index in range(20)]
    reads = [read_from_source(keys[0], {"operation_mode": "RUNNING"}, request.root.profile_alias)]
    for key, policy in zip(keys[1:], policies, strict=True):
        reads.append(
            read_from_source(
                key, {"index": key.source_id, "managed": True, "policy": policy}, request.root.profile_alias
            )
        )
    for policy in policies:
        reads.append(
            read_from_source(
                contracts.ReadKey(kind="elastic-policy", source_id=policy),
                {"version": 1, "policy": {"phases": {}}},
                request.root.profile_alias,
            )
        )
    value = contracts.make_result(
        request,
        reads=reads,
        run_id=RUN_ID,
        started_at=CLOCK,
        finished_at=CLOCK,
        diagnostics=[],
        collector_version="v" * 64,
        evidentia_version="v" * 64,
    )
    plan = contracts.CapacityPlan(request)
    plan.validate_result(value)
    assert value.root.manifest.reads_planned == 41
    assert value.root.manifest.attempts == 41
    assert value.root.manifest.findings == 20
    assert len(value.root.resources) == 20
    assert len(value.root.findings[0].id) == 36
    assert len(value.root.manifest.run_id) == 26
    assert len(value.root.started_at.isoformat(timespec="microseconds").replace("+00:00", "Z")) == 27
    assert len(value.publication_bytes()) <= plan.admission_bound(value.root.source_reads)
    assert (
        value.publication_bytes()
        == contracts.EnterpriseRetentionCollectResult.model_validate_json(value.publication_bytes()).publication_bytes()
    )


def test_internal_capacity_exact_boundary_and_one_byte_refusal() -> None:
    request = request_for("splunk-enterprise")
    value = result_for("splunk-enterprise")
    baseline = contracts.CapacityPlan(request)
    bound = baseline.admission_bound(value.root.source_reads)
    exact = contracts.CapacityPlan(request, _result_byte_limit=bound)
    exact.validate_result(value)
    plus_one = contracts.CapacityPlan(request, _result_byte_limit=bound - 1)
    with pytest.raises(contracts.CapacityExceeded, match="result_limit"):
        plus_one.admission_bound(value.root.source_reads)
    assert contracts.RESULT_BYTE_LIMIT == 4_194_304
    assert contracts.RUN_PROJECTION_BYTE_LIMIT == 2_097_152


def test_capacity_refusal_keeps_prior_result_and_late_terminal_diagnostics() -> None:
    request = request_for("google-vault")
    first = admitted_read("vault-matter")
    holds = contracts.empty_read(sample("vault-holds")[0], profile_alias="selected")
    plan = contracts.CapacityPlan(request)
    before = plan.admission_bound([first, holds])
    limited = contracts.CapacityPlan(request, _result_byte_limit=before)
    with pytest.raises(contracts.CapacityExceeded, match="result_limit"):
        limited.admission_bound([first, admitted_read("vault-holds")])
    diagnostics = [
        contracts.EnterpriseRetentionDiagnostic(code=code, read_id=first.read_id, safe_http_status=None)
        for code in ("deadline_exceeded", "result_limit", "cleanup_failed")
    ]
    result = contracts.make_result(
        request,
        reads=[first, holds],
        run_id=RUN_ID,
        started_at=CLOCK,
        finished_at=CLOCK,
        diagnostics=diagnostics,
        collector_version="0.13.0",
        evidentia_version="0.13.0",
    )
    limited.validate_result(result)
    assert result.root.status == "partial"
    assert (
        result.root.source_reads[0].observations[0].canonical_projection_sha256
        == first.observations[0].canonical_projection_sha256
    )
    assert result.root.source_reads[1].attempts == 0
    assert [item.code for item in result.root.diagnostics] == ["deadline_exceeded", "result_limit", "cleanup_failed"]


def test_empty_terminal_skeleton_must_fit_before_source_work() -> None:
    request = request_for("elastic-ilm")
    plan = contracts.CapacityPlan(request)
    with pytest.raises(ValueError, match="terminal_metadata_limit"):
        contracts.CapacityPlan(request, _result_byte_limit=plan.metadata_bound_bytes - 1)


def json_object_at(value: JsonValue, *path: str | int) -> dict[str, JsonValue]:
    """Narrow existing fixture containers without copying or converting values."""
    for key in path:
        if isinstance(key, str):
            assert isinstance(value, dict)
            value = value[key]
        else:
            assert isinstance(value, list)
            value = value[key]
    assert isinstance(value, dict)
    return value


def test_capacity_schema_drift_requires_an_explicit_bound() -> None:
    request = request_for("splunk-enterprise")
    skeleton = contracts._terminal_skeleton(request)
    del json_object_at(skeleton, "manifest")["attempts"]
    with pytest.raises(ValueError, match="capacity_schema_changed"):
        contracts._capacity_field_coverage(skeleton, "splunk-enterprise")


@pytest.mark.parametrize("status", [100, 201, 302, 401, 403, 404, 429, 503, 599])
def test_admitted_success_requires_200_in_the_observed_status_set(status: int) -> None:
    value = admitted_read("splunk-index")
    with pytest.raises(ValueError, match="invalid_successful_response_status"):
        value.model_copy(update={"safe_http_status": status})


@pytest.mark.parametrize("kind", ["vault-holds", "splunk-index"])
@pytest.mark.parametrize(
    "changes",
    [
        {"attempts": 2, "responses_received": 2, "pages_received": 2},
        {"records_received": 2},
    ],
)
def test_complete_requires_accounting_for_every_received_source_page_and_record(
    kind: contracts.ReadKind, changes: dict[str, Any]
) -> None:
    with pytest.raises(ValueError, match="incomplete_source_accounting"):
        admitted_read(kind).model_copy(update=changes)


def test_complete_holds_can_account_for_exact_coalesced_duplicates() -> None:
    value = admitted_read("vault-holds").model_copy(update={"records_received": 2, "duplicates_coalesced": 1})
    assert value.status == "complete"
    assert len(value.observations) == 1
    assert value.records_received == value.records_admitted + value.duplicates_coalesced


def test_empty_policy_relationship_is_missing_and_cannot_create_followup() -> None:
    request = request_for("elastic-ilm")
    key, _ = sample("elastic-explain")
    reads = [
        admitted_read("elastic-status"),
        read_from_source(key, {"index": "events", "managed": True, "policy": ""}, "selected"),
    ]
    value = contracts.make_result(
        request,
        reads=reads,
        run_id=RUN_ID,
        started_at=CLOCK,
        finished_at=CLOCK,
        diagnostics=[],
        collector_version="0.13.0",
        evidentia_version="0.13.0",
    )
    assert value.root.status == "partial"
    assert value.root.resources[0].policy_resolution == "unresolved"
    assert [item.code for item in value.root.resources[0].diagnostics] == ["policy_reference_missing"]
    assert len(value.root.source_reads) == 2


@pytest.mark.parametrize(
    "wrong",
    [
        ("vault-matter", "matter-1", "selected"),
        ("splunk-index", "events", "other-alias"),
        ("splunk-index", "other-index", "selected"),
    ],
)
def test_capacity_binds_every_candidate_read_to_its_request(wrong: tuple[contracts.ReadKind, str, str]) -> None:
    kind, identity, alias = wrong
    plan = contracts.CapacityPlan(request_for("splunk-enterprise"))
    with pytest.raises(ValueError, match="invalid_capacity_state"):
        plan.admission_bound(
            [contracts.empty_read(contracts.ReadKey(kind=kind, source_id=identity), profile_alias=alias)]
        )


def test_capacity_refuses_duplicate_and_unplanned_slots() -> None:
    plan = contracts.CapacityPlan(request_for("splunk-enterprise"))
    selected = contracts.empty_read(sample("splunk-index")[0], profile_alias="selected")
    for reads in ([selected, selected], [selected] * 41, []):
        with pytest.raises(ValueError, match="invalid_capacity_state"):
            plan.admission_bound(reads)


@pytest.mark.parametrize("provider", ["google-vault", "splunk-enterprise", "elastic-ilm"])
def test_capacity_schema_check_covers_all_target_locations(provider: contracts.ProviderName) -> None:
    request = request_for(provider)
    for where in ("resource", "filter", "finding"):
        skeleton = contracts._terminal_skeleton(request)
        if where == "resource":
            target = json_object_at(skeleton, "resources", 0, "target")
        elif where == "filter":
            target = json_object_at(skeleton, "findings", 0, "collection_context", "filter_applied", "target")
        else:
            target = json_object_at(skeleton, "findings", 0, "raw_data", "target")
        target["future_metadata"] = "unbounded"
        with pytest.raises(ValueError, match="capacity_schema_changed"):
            contracts._capacity_field_coverage(skeleton, provider)
