"""Independent Elastic field expectations and synthetic shared-session reads."""

from __future__ import annotations

import json
import socket
import ssl
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from itertools import product
from pathlib import Path
from typing import cast

import httpx
import pytest
from evidentia_collectors.enterprise_retention import elastic
from evidentia_collectors.enterprise_retention._client import (
    AuthorityError,
    EnterpriseReadSession,
    ParsedResponse,
    ProjectedPage,
    ReadSubject,
)
from evidentia_collectors.enterprise_retention._contracts import (
    CoverageState,
    ElasticIndexTarget,
    EnterpriseRetentionCollectResult,
    ReadKind,
    validated_request,
)
from evidentia_collectors.enterprise_retention._credentials import CredentialMaterial
from evidentia_collectors.enterprise_retention._parsing import JsonObject, parse_strict_json
from evidentia_collectors.enterprise_retention._profiles import AddressPolicy, AuthorizedProfile, FrozenProfile
from evidentia_core import network_guard
from pydantic import JsonValue

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "enterprise_retention" / "elastic"
INDEX = "synthetic-index"
POLICY = "synthetic-retention"
STRINGS = ("policy", "phase", "action", "step", "failed_step")
TIMES = (
    "index_creation_date_millis",
    "lifecycle_date_millis",
    "phase_time_millis",
    "action_time_millis",
    "step_time_millis",
)
EXPLAIN_ROOTS = ("index", "managed", *STRINGS, *TIMES, "phase_execution")
Project = Callable[[ParsedResponse, ReadSubject], ProjectedPage]


def fixture(name: str) -> JsonObject:
    value = parse_strict_json((FIXTURES / name).read_bytes())
    assert isinstance(value, dict)
    return value


def explain_source(value: JsonObject) -> JsonObject:
    indices = value["indices"]
    assert isinstance(indices, dict)
    source = indices[INDEX]
    assert isinstance(source, dict)
    return source


def project(kind: ReadKind, source: JsonObject) -> ProjectedPage:
    functions: dict[ReadKind, Project] = {
        "elastic-status": elastic.project_status,
        "elastic-explain": elastic.project_explain,
        "elastic-policy": elastic.project_policy,
    }
    identity = {"elastic-status": "service", "elastic-explain": INDEX, "elastic-policy": POLICY}[kind]
    return functions[kind](ParsedResponse(source, 200), ReadSubject(kind, identity))


def test_managed_projection_selects_exact_native_fields() -> None:
    record = project("elastic-explain", fixture("explain-managed.json")).records[0]
    assert record.fields == {
        "index": INDEX,
        "managed": True,
        "policy": POLICY,
        "phase": "hot",
        "action": "rollover",
        "step": "ERROR",
        "failed_step": "check-rollover-ready",
        "index_creation_date_millis": 0,
        "lifecycle_date_millis": 9007199254740993,
        "phase_time_millis": 1700000000000,
        "action_time_millis": 1700000000001,
        "step_time_millis": 1700000000002,
        "phase_execution": {
            "policy": "synthetic-cached-policy",
            "version": 3,
            "modified_date_in_millis": 1690000000000,
            "phase_definition": {"min_age": "30d", "actions": {"delete": {"delete_searchable_snapshot": False}}},
        },
    }
    assert record.source_identity == INDEX and record.source_ordinal == 0 and record.native_scope == "index"
    assert type(record.fields["lifecycle_date_millis"]) is int
    assert record.field_coverage == dict.fromkeys(EXPLAIN_ROOTS, "known")
    assert record.diagnostics == ()


def test_policy_projection_preserves_current_extensions_and_nullable_phases() -> None:
    record = project("elastic-policy", fixture("policy-current.json")).records[0]
    assert record.source_identity == POLICY and record.native_scope == "policy"
    assert record.fields == {
        "version": 8,
        "modified_date": "2026-01-02T03:04:05.123456789+02:30",
        "policy": {
            "phases": {
                "hot": {"min_age": "0ms", "actions": {"rollover": {"max_primary_shard_size": "50gb"}}},
                "warm": None,
                "synthetic_future_phase": {
                    "min_age": "90d",
                    "actions": {},
                    "synthetic_extension": {
                        "_meta": {"retained": "literal-phase-configuration"},
                        "sequence": [None, False, 1, 1.0],
                    },
                },
            }
        },
    }
    assert record.field_coverage == {"version": "known", "modified_date": "known", "policy": "unknown"}
    assert record.diagnostics == ("unsupported_source_value", "missing_source_detail")


@pytest.mark.parametrize(
    "value,state",
    [
        ("RUNNING", "known"),
        ("STOPPING", "known"),
        ("STOPPED", "known"),
        ("FUTURE", "unknown"),
        ("", "unknown"),
        (None, "null"),
    ],
)
def test_status_literal_coverage(value: JsonValue, state: CoverageState) -> None:
    record = project("elastic-status", {"operation_mode": value, "ignored": "synthetic"}).records[0]
    assert record.fields == {"operation_mode": value}
    assert record.field_coverage == {"operation_mode": state}
    expected = (
        ("missing_source_detail",) if value is None else (() if state == "known" else ("unsupported_source_value",))
    )
    assert record.diagnostics == expected


def test_missing_status_is_distinct_from_null() -> None:
    record = project("elastic-status", {}).records[0]
    assert record.fields == {} and record.field_coverage == {"operation_mode": "absent"}
    assert record.diagnostics == ("missing_source_detail",)


def object_value(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def source_for(kind: ReadKind) -> tuple[JsonObject, JsonObject]:
    if kind == "elastic-explain":
        raw = fixture("explain-managed.json")
        return raw, explain_source(raw)
    if kind == "elastic-policy":
        source: JsonObject = {
            "version": 1,
            "modified_date": 0,
            "policy": {"phases": {"hot": {"min_age": "0d", "actions": {}}}},
        }
        return {POLICY: source}, source
    raw = {"operation_mode": "RUNNING"}
    return raw, raw


def parent_for(source: JsonObject, path: tuple[str, ...]) -> JsonObject:
    for name in path[:-1]:
        source = object_value(source[name])
    return source


@dataclass(frozen=True)
class FieldCase:
    kind: ReadKind
    path: tuple[str, ...]
    allowed: tuple[type[object], ...]
    nonnegative: bool = False


FIELD_CASES = (
    *(FieldCase("elastic-explain", (name,), (str,)) for name in STRINGS),
    *(FieldCase("elastic-explain", (name,), (int,), True) for name in TIMES),
    FieldCase("elastic-explain", ("phase_execution",), (dict,)),
    FieldCase("elastic-explain", ("phase_execution", "policy"), (str,)),
    FieldCase("elastic-explain", ("phase_execution", "version"), (int,), True),
    FieldCase("elastic-explain", ("phase_execution", "modified_date_in_millis"), (int,), True),
    FieldCase("elastic-explain", ("phase_execution", "phase_definition"), (dict,)),
    FieldCase("elastic-explain", ("phase_execution", "phase_definition", "min_age"), (str,)),
    FieldCase("elastic-explain", ("phase_execution", "phase_definition", "actions"), (dict,)),
    FieldCase("elastic-policy", ("version",), (int,), True),
    FieldCase("elastic-policy", ("modified_date",), (str, int)),
    FieldCase("elastic-policy", ("policy",), (dict,)),
    FieldCase("elastic-policy", ("policy", "phases"), (dict,)),
    FieldCase("elastic-policy", ("policy", "phases", "hot"), (dict,)),
    FieldCase("elastic-policy", ("policy", "phases", "hot", "min_age"), (str,)),
    FieldCase("elastic-policy", ("policy", "phases", "hot", "actions"), (dict,)),
    FieldCase("elastic-status", ("operation_mode",), (str,)),
)
WRONG_NATIVE: tuple[JsonValue, ...] = (True, False, 0, 1.0, "synthetic", [], {})


@pytest.mark.parametrize("case", FIELD_CASES, ids=lambda c: c.kind + ":" + ".".join(c.path))
@pytest.mark.parametrize("presence", ["absent", "null"])
def test_every_optional_field_preserves_absence_and_null(case: FieldCase, presence: str) -> None:
    raw, source = source_for(case.kind)
    parent = parent_for(source, case.path)
    if presence == "absent":
        del parent[case.path[-1]]
    else:
        parent[case.path[-1]] = None
    record = project(case.kind, raw).records[0]
    selected = parent_for(record.fields, case.path)
    if presence == "absent":
        assert case.path[-1] not in selected
    else:
        assert selected[case.path[-1]] is None
    if case.path == ("policy", "phases", "hot") and presence == "absent":
        assert record.diagnostics == ()
    else:
        assert "missing_source_detail" in record.diagnostics
    if len(case.path) == 1:
        assert record.field_coverage[case.path[0]] == presence


@pytest.mark.parametrize(
    "case,value",
    [(case, value) for case in FIELD_CASES for value in WRONG_NATIVE if type(value) not in case.allowed]
    + [(case, -1) for case in FIELD_CASES if case.nonnegative],
)
def test_every_declared_field_rejects_wrong_native_type(case: FieldCase, value: JsonValue) -> None:
    raw, source = source_for(case.kind)
    parent_for(source, case.path)[case.path[-1]] = value
    with pytest.raises(AuthorityError, match=r"^invalid_response$"):
        project(case.kind, raw)


@pytest.mark.parametrize("name", TIMES)
@pytest.mark.parametrize("value", [0, 9007199254740993, 10**127])
def test_native_millisecond_integers_remain_exact(name: str, value: int) -> None:
    raw, source = source_for("elastic-explain")
    source[name] = value
    record = project("elastic-explain", raw).records[0]
    assert type(record.fields[name]) is int and record.fields[name] == value
    assert record.field_coverage[name] == "known"


@pytest.mark.parametrize(
    "value,state",
    [
        (-1, "known"),
        (0, "known"),
        (9007199254740993, "known"),
        ("2024-02-29T23:59:59.000000000123-23:59", "known"),
        ("2026-01-02t03:04:05z", "known"),
        ("2026-02-29T00:00:00Z", "unknown"),
        ("2026-01-02T23:59:60Z", "unknown"),
        ("2026-01-02T00:00:00+24:00", "unknown"),
        ("2026-01-02T00:00:00+00:60", "unknown"),
        ("2026-01-02", "unknown"),
        ("", "unknown"),
        ("synthetic future time", "unknown"),
    ],
)
def test_current_modified_date_native_and_literal_interpretation(value: JsonValue, state: CoverageState) -> None:
    raw, source = source_for("elastic-policy")
    source["modified_date"] = value
    record = project("elastic-policy", raw).records[0]
    assert record.fields["modified_date"] == value and type(record.fields["modified_date"]) is type(value)
    assert record.field_coverage["modified_date"] == state


@pytest.mark.parametrize(
    "value,state",
    [
        ("synthetic-retention", "known"),
        (".synthetic-policy", "known"),
        ("-", "known"),
        ("a" * 255, "known"),
        ("a" * 256, "unknown"),
        ("", "unknown"),
        (".", "unknown"),
        ("..", "unknown"),
        ("_ALL", "unknown"),
        ("synthetic/name", "unknown"),
        ("synthetic%2fname", "unknown"),
        ("synthetic*", "unknown"),
        ("synthetic,name", "unknown"),
        ("synthetic policy", "unknown"),
    ],
)
def test_policy_reference_interpretation_is_literal(value: str, state: CoverageState) -> None:
    raw, source = source_for("elastic-explain")
    source["policy"] = value
    record = project("elastic-explain", raw).records[0]
    assert record.fields["policy"] == value and record.field_coverage["policy"] == state


@pytest.mark.parametrize("name", ["phase", "action", "step", "failed_step"])
@pytest.mark.parametrize("value", ["ERROR", "FUTURE_SYNTHETIC_STATE", ""])
def test_step_action_phase_labels_are_literal_state(name: str, value: str) -> None:
    raw, source = source_for("elastic-explain")
    source[name] = value
    record = project("elastic-explain", raw).records[0]
    assert record.fields[name] == value and record.field_coverage[name] == "known"


def test_open_phase_and_action_extensions_are_not_recursively_redacted() -> None:
    raw, source = source_for("elastic-policy")
    phase = object_value(object_value(object_value(source["policy"])["phases"])["hot"])
    phase["_meta"] = {"literal": "synthetic selected phase"}
    phase["actions"] = {
        "synthetic_future": {
            "error": "literal config",
            "email": "synthetic@example.invalid",
            "values": [None, False, -0.0, 1.0, 10**127],
        }
    }
    record = project("elastic-policy", raw).records[0]
    selected_phase = object_value(object_value(object_value(record.fields["policy"])["phases"])["hot"])
    assert selected_phase == phase
    assert record.field_coverage["policy"] == "unknown"
    assert record.diagnostics == ("unsupported_source_value",)
    values = object_value(object_value(selected_phase["actions"])["synthetic_future"])["values"]
    assert isinstance(values, list) and type(values[2]) is float and type(values[3]) is float
    assert json.dumps(values).endswith(str(10**127) + "]")


def test_detached_input_and_output_cannot_change_projection() -> None:
    raw = fixture("explain-managed.json")
    record = project("elastic-explain", raw).records[0]
    before = record.fields
    explain_source(raw)["policy"] = "synthetic-mutated"
    view = record.fields
    object_value(view["phase_execution"])["version"] = 999
    record.field_coverage.clear()
    assert record.fields == before and record.field_coverage["index"] == "known"


def field_corpus() -> list[JsonObject]:
    data = parse_strict_json((FIXTURES.parent / "source-field-cases.json").read_bytes())
    rows = object_value(data)["cases"]
    assert isinstance(rows, list)
    selected = []
    for value in rows:
        row = object_value(value)
        kind = row["read_kind"]
        assert isinstance(kind, str)
        if kind.startswith("elastic-"):
            selected.append(row)
    return selected


@pytest.mark.parametrize("case", field_corpus(), ids=lambda c: c["id"])
def test_reviewed_source_corpus_uses_independent_literal_expectations(case: JsonObject) -> None:
    kind = case["read_kind"]
    assert isinstance(kind, str) and kind in ("elastic-explain", "elastic-policy", "elastic-status")
    identity = object_value(case["subject"])["source_id"]
    assert isinstance(identity, str)
    projector = {
        "elastic-explain": elastic.project_explain,
        "elastic-policy": elastic.project_policy,
        "elastic-status": elastic.project_status,
    }[kind]
    records = projector(
        ParsedResponse(object_value(case["raw_response"]), 200), ReadSubject(cast(ReadKind, kind), identity)
    ).records
    expected = case["expected_records"]
    assert isinstance(expected, list) and len(records) == len(expected)
    for record, row_value in zip(records, expected, strict=True):
        row = object_value(row_value)
        assert record.source_ordinal == row["source_ordinal"]
        assert record.source_identity == row["source_identity"]
        assert record.fields == row["fields"]
        assert record.field_coverage == row["field_coverage"]
        required = case["required_interpretation_codes"]
        assert isinstance(required, list)
        assert all(code in record.diagnostics for code in required)


@dataclass(frozen=True)
class Reply:
    data: JsonObject
    status: int = 200


class Body(httpx.SyncByteStream):
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.closes = 0
        self.delivered = 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in (self.content[:11], self.content[11:]):
            self.delivered += len(chunk)
            yield chunk

    def close(self) -> None:
        self.closes += 1


class Wire:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, indexes: tuple[str, ...] = (INDEX,)) -> None:
        self.request = validated_request(
            {
                "provider": "elastic-ilm",
                "profile_alias": "synthetic",
                "scope_label": "synthetic-selected-configuration",
                "targets": [{"index": index} for index in indexes],
            }
        )
        self.requests: list[httpx.Request] = []
        self.bodies: list[Body] = []
        self.replies: list[Reply] = []
        self.resolutions = 0
        self.dns = 0
        self.elapsed = 0.0
        self.profile = FrozenProfile(
            alias="synthetic",
            provider="elastic-ilm",
            origin="https://elastic.example.invalid:9243",
            credential_ref="ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
            address_policy=AddressPolicy("public"),
        )
        monkeypatch.setattr(socket, "getaddrinfo", self.resolve_dns)
        monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", self.resolve_dns)
        monkeypatch.setattr(network_guard._pin_state, "hosts", {}, raising=False)
        monkeypatch.setattr(network_guard, "_offline_enabled", False)

    def resolve_dns(
        self, host: object, port: object, *args: object, **kwargs: object
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host in ("elastic.example.invalid", b"elastic.example.invalid") and type(port) is int
        self.dns += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def resolve(self, profile: FrozenProfile) -> CredentialMaterial:
        assert profile.provider == "elastic-ilm" and profile.alias == "synthetic"
        self.resolutions += 1
        return CredentialMaterial("elastic-ilm", "synthetic-value", None)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert self.replies, "Unexpected additional request"
        reply = self.replies.pop(0)
        body = Body(json.dumps(reply.data, ensure_ascii=True, allow_nan=False).encode("utf-8"))
        self.bodies.append(body)
        return httpx.Response(reply.status, stream=body)

    def factory(self, context: ssl.SSLContext) -> httpx.BaseTransport:
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        return httpx.MockTransport(self.handle)

    def sleep(self, delay: float) -> None:
        self.elapsed += delay

    def collect(self) -> EnterpriseRetentionCollectResult:
        with EnterpriseReadSession(
            self.request,
            profile=AuthorizedProfile(self.profile, self),
            transport_factory=self.factory,
            utc_clock=lambda: datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=self.elapsed),
            monotonic_clock=lambda: self.elapsed,
            sleep=self.sleep,
            run_id_factory=lambda: "01K00000000000000000000000",
        ) as session:
            resources = []
            for target in self.request.root.targets:
                assert isinstance(target, ElasticIndexTarget)
                resources.append(elastic.read_elastic(target, session))
            return session.finish(tuple(resources))


def test_real_session_fixed_requests_cached_and_current_phase_are_separate(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = Wire(monkeypatch)
    wire.replies = [
        Reply(fixture("status-stopped.json")),
        Reply(fixture("explain-managed.json")),
        Reply(fixture("policy-current.json")),
    ]
    result = wire.collect()
    assert result.root.status == "complete"
    assert [request.url.raw_path for request in wire.requests] == [
        b"/_ilm/status",
        b"/synthetic-index/_ilm/explain?only_managed=false&only_errors=false",
        b"/_ilm/policy/synthetic-retention",
    ]
    assert all(request.method == "GET" and request.content == b"" for request in wire.requests)
    assert wire.resolutions == 1 and all(body.closes == 1 for body in wire.bodies)
    assert result.root.resources[0].policy_resolution == "resolved"
    status, explain, policy = result.root.source_reads
    assert status.observations[0].fields == {"operation_mode": "STOPPED"}
    assert explain.observations[0].fields["step"] == "ERROR"
    cached = object_value(explain.observations[0].fields["phase_execution"])
    assert cached["version"] == 3 and policy.observations[0].fields["version"] == 8
    assert result.root.unassessed_surfaces == (
        "document_coverage",
        "lifecycle_execution_guarantees",
        "templates_and_unselected_indices",
        "atomic_provider_snapshot",
    )
    assert result.root.observation_scope == "configuration" and result.root.coverage_scope == "selected_resources"
    assert (
        not result.root.object_enforcement_assessed
        and not result.root.recordset_completeness_assessed
        and not result.root.authenticated_identity_verified
    )
    assert (
        EnterpriseRetentionCollectResult.model_validate_json(result.publication_bytes()).publication_bytes()
        == result.publication_bytes()
    )


@pytest.mark.parametrize(
    "name,expected_status,resolution",
    [
        ("explain-unmanaged.json", "complete", "not_applicable"),
        ("explain-unknown-null.json", "partial", "unresolved"),
        ("explain-invalid-identity.json", "unavailable", "unresolved"),
    ],
)
def test_real_session_no_unapproved_policy_read(
    monkeypatch: pytest.MonkeyPatch, name: str, expected_status: str, resolution: str
) -> None:
    wire = Wire(monkeypatch)
    wire.replies = [Reply(fixture("status-running.json")), Reply(fixture(name))]
    result = wire.collect()
    assert result.root.status == expected_status
    assert result.root.resources[0].policy_resolution == resolution
    assert len(wire.requests) == 2 and len(result.root.source_reads) == 2
    assert all(body.closes == 1 for body in wire.bodies)
    if name == "explain-invalid-identity.json":
        assert result.root.source_reads[1].terminal_reason == "identity_mismatch"
        assert not result.root.findings


@pytest.mark.parametrize("managed", [True, False])
@pytest.mark.parametrize(
    "policy", [None, "", ".", "..", "_ALL", "synthetic/name", "synthetic*", "synthetic%2fname", "x" * 256]
)
def test_unresolved_references_never_authorize_requests(
    monkeypatch: pytest.MonkeyPatch, managed: bool, policy: JsonValue
) -> None:
    wire = Wire(monkeypatch)
    raw = fixture("explain-managed.json")
    source = explain_source(raw)
    source["managed"] = managed
    source["policy"] = policy
    wire.replies = [Reply({}), Reply(raw)]
    result = wire.collect()
    assert len(wire.requests) == 2 and len(result.root.source_reads) == 2
    assert result.root.source_reads[1].status == "complete"
    assert result.root.resources[0].policy_resolution == ("unresolved" if managed else "not_applicable")
    assert result.root.status == ("partial" if managed else "complete")
    assert result.root.source_reads[1].observations[0].fields["policy"] == policy


@pytest.mark.parametrize("managed", [True, False])
def test_absent_policy_is_not_filled_from_cached_phase(monkeypatch: pytest.MonkeyPatch, managed: bool) -> None:
    wire = Wire(monkeypatch)
    raw = fixture("explain-managed.json")
    source = explain_source(raw)
    del source["policy"]
    source["managed"] = managed
    wire.replies = [Reply({}), Reply(raw)]
    result = wire.collect()
    assert len(wire.requests) == 2
    assert result.root.resources[0].policy_resolution == ("unresolved" if managed else "not_applicable")
    assert "policy" not in result.root.source_reads[1].observations[0].fields


@pytest.mark.parametrize("policy", [True, 0, 1.0, [], {}])
def test_wrong_policy_scalar_invalidates_explain_before_followup(
    monkeypatch: pytest.MonkeyPatch, policy: JsonValue
) -> None:
    wire = Wire(monkeypatch)
    raw = fixture("explain-managed.json")
    explain_source(raw)["policy"] = policy
    wire.replies = [Reply({}), Reply(raw)]
    result = wire.collect()
    assert len(wire.requests) == 2
    read = result.root.source_reads[1]
    assert read.status == "unavailable" and read.terminal_reason == "invalid_response" and not read.observations
    assert not result.root.findings


@pytest.mark.parametrize("status_ok,explain_ok,policy_ok", list(product((False, True), repeat=3)))
def test_every_required_read_failure_combination_retains_admitted_evidence(
    monkeypatch: pytest.MonkeyPatch, status_ok: bool, explain_ok: bool, policy_ok: bool
) -> None:
    wire = Wire(monkeypatch)
    wire.replies = [
        Reply({"operation_mode": "STOPPED"}, 200 if status_ok else 403),
        Reply(fixture("explain-managed.json"), 200 if explain_ok else 403),
    ]
    if explain_ok:
        wire.replies.append(Reply(fixture("policy-current.json"), 200 if policy_ok else 403))
    result = wire.collect()
    expected = "complete" if status_ok and explain_ok and policy_ok else ("partial" if explain_ok else "unavailable")
    assert result.root.status == expected
    assert len(wire.requests) == (3 if explain_ok else 2)
    assert bool(result.root.source_reads[0].observations) is status_ok
    assert bool(result.root.source_reads[1].observations) is explain_ok
    assert len(result.root.findings) == int(explain_ok)
    assert all(body.closes == 1 for body in wire.bodies)
    assert result.root.manifest.attempts == len(wire.requests)
    assert result.root.manifest.raw_bytes == sum(body.delivered for body in wire.bodies)
    assert (
        EnterpriseRetentionCollectResult.model_validate_json(result.publication_bytes()).publication_bytes()
        == result.publication_bytes()
    )


@pytest.mark.parametrize("policy_status", [200, 403, 404, 503])
def test_shared_policy_success_and_failure_are_cached_once(monkeypatch: pytest.MonkeyPatch, policy_status: int) -> None:
    wire = Wire(monkeypatch, (INDEX, "synthetic-second-index"))
    second = fixture("explain-managed.json")
    member = explain_source(second)
    member["index"] = "synthetic-second-index"
    second["indices"] = {"synthetic-second-index": member}
    wire.replies = [Reply({"operation_mode": "RUNNING"}), Reply(fixture("explain-managed.json"))]
    attempts = 3 if policy_status == 503 else 1
    wire.replies.extend(Reply(fixture("policy-current.json"), policy_status) for _ in range(attempts))
    wire.replies.append(Reply(second))
    result = wire.collect()
    assert sum(request.url.path == "/_ilm/status" for request in wire.requests) == 1
    assert sum(request.url.path == "/_ilm/policy/" + POLICY for request in wire.requests) == attempts
    assert len(result.root.source_reads) == 4 and result.root.manifest.reads_planned == 4
    assert result.root.manifest.resources_attempted == 2 and len(result.root.findings) == 2
    first, second_resource = result.root.resources
    assert first.policy_resolution == second_resource.policy_resolution == "resolved"
    assert first.read_ids[1:] == second_resource.read_ids[1:]
    policy = result.root.source_reads[-1]
    assert policy.attempts == attempts and policy.status == ("complete" if policy_status == 200 else "unavailable")
    assert result.root.manifest.attempts == 3 + attempts
    assert result.root.status == ("complete" if policy_status == 200 else "partial")


@pytest.mark.parametrize("stage", ["status", "explain", "policy"])
def test_primary_401_stops_later_provider_reads(monkeypatch: pytest.MonkeyPatch, stage: str) -> None:
    wire = Wire(monkeypatch, (INDEX, "synthetic-second-index"))
    wire.replies = [
        Reply({} if stage == "status" else {"operation_mode": "RUNNING"}, 401 if stage == "status" else 200)
    ]
    if stage != "status":
        wire.replies.append(Reply(fixture("explain-managed.json"), 401 if stage == "explain" else 200))
    if stage == "policy":
        wire.replies.append(Reply({}, 401))
    result = wire.collect()
    assert len(wire.requests) == {"status": 1, "explain": 2, "policy": 3}[stage]
    assert wire.resolutions == 1 and all(body.closes == 1 for body in wire.bodies)
    assert result.root.resources[1].status != "complete"
    assert result.root.source_reads[2].attempts == 0
    assert any(d.code == "credential_rejected" for d in result.root.diagnostics)


@pytest.mark.parametrize("extra", [False, True])
def test_policy_response_identity_cannot_expand_the_authorized_selection(
    monkeypatch: pytest.MonkeyPatch, extra: bool
) -> None:
    wire = Wire(monkeypatch)
    body = fixture("policy-current.json")
    value = body[POLICY]
    if extra:
        body["synthetic-other-policy"] = value
    else:
        body = {"synthetic-other-policy": value}
    wire.replies = [Reply({}), Reply(fixture("explain-managed.json")), Reply(body)]
    result = wire.collect()
    policy = result.root.source_reads[-1]
    assert policy.status == "unavailable" and policy.terminal_reason == "identity_mismatch"
    assert len(wire.requests) == 3 and result.root.source_reads[1].observations
    assert result.root.status == "partial"


@pytest.mark.parametrize("extra", [False, True])
def test_explain_response_identity_cannot_expand_alias_or_data_stream(
    monkeypatch: pytest.MonkeyPatch, extra: bool
) -> None:
    wire = Wire(monkeypatch)
    body = fixture("explain-managed.json")
    member = explain_source(body)
    indices = object_value(body["indices"])
    if extra:
        indices["synthetic-expanded-index"] = member
    else:
        body["indices"] = {"synthetic-expanded-index": member}
    wire.replies = [Reply({}), Reply(body)]
    result = wire.collect()
    assert len(wire.requests) == 2
    assert result.root.source_reads[1].terminal_reason == "identity_mismatch"
    assert not result.root.findings


def negative_corpus() -> list[tuple[JsonObject, JsonObject]]:
    positives: dict[str, JsonObject] = {}
    for case in field_corpus():
        identity = case["id"]
        assert isinstance(identity, str)
        positives[identity] = case
    data = parse_strict_json((FIXTURES.parent / "source-field-negative-cases.json").read_bytes())
    rows = object_value(data)["cases"]
    assert isinstance(rows, list)
    selected = []
    for item in rows:
        row = object_value(item)
        name = row["base_case"]
        assert isinstance(name, str)
        if name in positives and object_value(row["mutation"])["target"] == "raw_response":
            selected.append((positives[name], row))
    return selected


@pytest.mark.parametrize("base,negative", negative_corpus(), ids=[str(row["id"]) for _, row in negative_corpus()])
def test_reviewed_raw_negative_recipes_refuse(base: JsonObject, negative: JsonObject) -> None:
    raw = ParsedResponse(object_value(base["raw_response"]), 200).data
    mutation = object_value(negative["mutation"])
    path = mutation["path"]
    assert isinstance(path, list) and all(isinstance(name, str) for name in path)
    names = cast(list[str], path)
    value_json = mutation["value_json"]
    assert isinstance(value_json, str) and mutation["operation"] == "replace"
    parent_for(raw, tuple(names))[names[-1]] = parse_strict_json(value_json.encode("utf-8"))
    kind = base["read_kind"]
    assert isinstance(kind, str)
    identity = object_value(base["subject"])["source_id"]
    assert isinstance(identity, str)
    projector = {
        "elastic-explain": elastic.project_explain,
        "elastic-policy": elastic.project_policy,
        "elastic-status": elastic.project_status,
    }[kind]
    with pytest.raises(AuthorityError, match=r"^invalid_response$"):
        projector(ParsedResponse(raw, 200), ReadSubject(cast(ReadKind, kind), identity))


@pytest.mark.parametrize("value", [None, 0, 1, 0.0, "true", [], {}])
def test_managed_requires_a_native_boolean(value: JsonValue) -> None:
    raw, source = source_for("elastic-explain")
    source["managed"] = value
    with pytest.raises(AuthorityError, match=r"^invalid_response$"):
        project("elastic-explain", raw)


@pytest.mark.parametrize("field", ["index", "managed"])
def test_required_identity_and_state_cannot_be_omitted(field: str) -> None:
    raw, source = source_for("elastic-explain")
    del source[field]
    with pytest.raises(AuthorityError, match=r"^(identity_mismatch|invalid_response)$"):
        project("elastic-explain", raw)


@pytest.mark.parametrize("kind", ["elastic-status", "elastic-explain", "elastic-policy"])
def test_projector_rejects_wrong_read_kind(kind: ReadKind) -> None:
    raw, _ = source_for(kind)
    projector = {
        "elastic-explain": elastic.project_explain,
        "elastic-policy": elastic.project_policy,
        "elastic-status": elastic.project_status,
    }[kind]
    with pytest.raises(AuthorityError, match=r"^invalid_response$"):
        projector(ParsedResponse(raw, 200), ReadSubject("splunk-index", INDEX))


def test_large_selected_phase_refuses_admission_without_policy_followup(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = Wire(monkeypatch)
    raw = fixture("explain-managed.json")
    execution = object_value(explain_source(raw)["phase_execution"])
    definition = object_value(execution["phase_definition"])
    definition["actions"] = {"synthetic_action": {"value": "x" * 70000}}
    wire.replies = [Reply({"operation_mode": "RUNNING"}), Reply(raw)]
    result = wire.collect()
    assert len(wire.requests) == 2 and len(result.root.source_reads) == 2
    assert result.root.source_reads[0].observations
    explain = result.root.source_reads[1]
    assert not explain.observations and explain.terminal_reason == "projection_limit"
    assert explain.pages_received == 1 and explain.pages_admitted == 0
    assert result.root.manifest.raw_bytes == sum(body.delivered for body in wire.bodies)
    assert all(body.closes == 1 for body in wire.bodies)


@pytest.mark.parametrize("policy", [".synthetic-policy", "a" * 255])
def test_supported_policy_name_is_requested_exactly(monkeypatch: pytest.MonkeyPatch, policy: str) -> None:
    wire = Wire(monkeypatch)
    raw = fixture("explain-managed.json")
    explain_source(raw)["policy"] = policy
    wire.replies = [Reply({}), Reply(raw), Reply({policy: {"policy": {"phases": {}}}})]
    result = wire.collect()
    assert wire.requests[-1].url.raw_path == ("/_ilm/policy/" + policy).encode("ascii")
    assert result.root.resources[0].policy_resolution == "resolved" and result.root.status == "complete"
    assert result.root.source_reads[-1].source_id == policy


def test_distinct_policy_reads_append_in_selected_index_order(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = Wire(monkeypatch, (INDEX, "synthetic-second-index"))
    second = fixture("explain-managed.json")
    member = explain_source(second)
    member["index"] = "synthetic-second-index"
    member["policy"] = "synthetic-second-policy"
    second["indices"] = {"synthetic-second-index": member}
    wire.replies = [
        Reply({"operation_mode": "RUNNING"}),
        Reply(fixture("explain-managed.json")),
        Reply({POLICY: {"policy": {"phases": {}}}}),
        Reply(second),
        Reply({"synthetic-second-policy": {"policy": {"phases": {}}}}),
    ]
    result = wire.collect()
    assert result.root.status == "complete"
    assert [read.source_id for read in result.root.source_reads] == [
        "service",
        INDEX,
        "synthetic-second-index",
        POLICY,
        "synthetic-second-policy",
    ]
    assert [request.url.path for request in wire.requests] == [
        "/_ilm/status",
        "/synthetic-index/_ilm/explain",
        "/_ilm/policy/synthetic-retention",
        "/synthetic-second-index/_ilm/explain",
        "/_ilm/policy/synthetic-second-policy",
    ]
    assert result.root.resources[0].read_ids[-1] == result.root.resources[1].read_ids[-1]
    assert result.root.manifest.reads_planned == result.root.manifest.reads_attempted == 5
