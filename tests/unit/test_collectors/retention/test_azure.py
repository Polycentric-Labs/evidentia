"""Synthetic Azure ARM field selection and common-session integration."""

from __future__ import annotations

import copy
import gzip
import itertools
import json
import socket
from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from evidentia_collectors.retention import azure
from evidentia_collectors.retention._client import (
    ClientFault,
    ComponentProjector,
    ComponentResponse,
    StorageReadSession,
)
from evidentia_collectors.retention._contracts import (
    AzureTarget,
    ComponentId,
    ProjectedComponent,
    ProviderName,
    StorageRetentionCollectResult,
    build_component_url,
    make_result,
    target_identity,
    validated_request,
)
from evidentia_collectors.retention._credentials import BearerCredentials, CredentialResolution
from evidentia_collectors.retention._parsing import JsonObject
from evidentia_core import network_guard

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "retention" / "azure"
NOW = datetime(2024, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)
COMPONENTS: tuple[ComponentId, ...] = ("azure-account", "azure-blob-service", "azure-container")
FILES = (
    "account-enabled.synthetic.json",
    "service-versioning-disabled.synthetic.json",
    "container-locked-held.synthetic.json",
)
PROJECTORS: tuple[ComponentProjector, ...] = (azure._project_account, azure._project_service, azure._project_container)


def target() -> AzureTarget:
    return AzureTarget(
        subscription_id="11111111-2222-4333-8444-555555555555",
        resource_group="Synthetic_Group",
        account="syntheticstore",
        container="synthetic-container",
    )


def fixture(name: str) -> dict[str, Any]:
    body = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    assert isinstance(body, dict)
    return body


def bodies() -> list[dict[str, Any]]:
    return [fixture(name) for name in FILES]


def project(index: int, body: object) -> ProjectedComponent:
    return PROJECTORS[index](
        ComponentResponse(COMPONENTS[index], 200, cast(JsonObject, body), '"transport-etag"'), target()
    )


def nested(body: dict[str, Any], path: tuple[str, ...]) -> dict[str, Any]:
    for key in path:
        body = body[key]
    return body


def codes(projected: ProjectedComponent) -> set[str]:
    return {item.code for item in projected.diagnostics}


class SyntheticCredentials:
    def __init__(self) -> None:
        self.calls: list[ProviderName] = []

    def resolve(self, provider: ProviderName) -> CredentialResolution:
        self.calls.append(provider)
        return CredentialResolution(BearerCredentials("SYNTHETIC_AZURE_TOKEN"), None)


class SyntheticStream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield self.body[:7]
        yield self.body[7:]

    def close(self) -> None:
        self.closed = True


class SyntheticTransport(httpx.MockTransport):
    def __init__(self, replies: list[tuple[int, bytes]], *, compressed: bool = False) -> None:
        self.replies = list(replies)
        self.requests: list[httpx.Request] = []
        self.streams: list[SyntheticStream] = []
        self.closed = False
        self.compressed = compressed
        super().__init__(self.reply)

    def reply(self, request: httpx.Request) -> httpx.Response:
        assert self.replies, "Unexpected fourth Azure request"
        assert request.method == "GET" and request.content == b""
        assert request.url.host == "management.azure.com"
        assert request.headers["authorization"] == "Bearer SYNTHETIC_AZURE_TOKEN"
        assert {row[4][0] for row in socket.getaddrinfo(request.url.host, 443)} == {"8.8.8.8"}
        self.requests.append(request)
        status, body = self.replies.pop(0)
        if self.compressed:
            body = gzip.compress(body, mtime=0)
        stream = SyntheticStream(body)
        self.streams.append(stream)
        return httpx.Response(
            status,
            headers={"etag": '"synthetic-transport"', "content-encoding": "gzip" if self.compressed else "identity"},
            stream=stream,
        )

    def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def no_live_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refused(*args: object, **kwargs: object) -> Any:
        raise AssertionError("Synthetic Azure tests cannot use DNS or sockets")

    monkeypatch.setattr(socket, "getaddrinfo", refused)
    monkeypatch.setattr(socket, "create_connection", refused)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(network_guard, "_offline_enabled", False)


def collect(
    monkeypatch: pytest.MonkeyPatch,
    payloads: Sequence[object],
    *,
    statuses: list[int] | None = None,
    compressed: bool = False,
) -> tuple[StorageRetentionCollectResult, SyntheticTransport, SyntheticCredentials, list[str]]:
    selected = target()
    request = validated_request({"provider": "azure", "scope_label": "synthetic", "targets": [selected]})
    credential = SyntheticCredentials()
    replies = [
        (status, body if isinstance(body, bytes) else json.dumps(body).encode())
        for status, body in zip(statuses or [200] * len(payloads), payloads, strict=True)
    ]
    transport = SyntheticTransport(replies, compressed=compressed)
    guarded: list[str] = []

    def public(url: str, *, subsystem: str, block_private: bool = True) -> list[str]:
        assert subsystem == "storage-retention" and block_private
        guarded.append(url)
        return ["8.8.8.8"]

    monkeypatch.setattr(network_guard, "enforce_public_host", public)
    session = StorageReadSession(
        request,
        credentials=credential,
        transport_factory=lambda: transport,
        utc_clock=lambda: NOW,
        monotonic_clock=lambda: 0.0,
        sleep=lambda delay: None,
        run_id_factory=lambda: "synthetic-azure-run",
    )
    try:
        parts = azure.read_azure(selected, session)
    finally:
        session.close()
    result = make_result(
        request,
        run_id=session.context.run_id,
        started_at=NOW,
        finished_at=NOW,
        components={target_identity(selected): parts},
        diagnostics=(),
    )
    return result, transport, credential, guarded


def test_synthetic_projection_fields_and_exclusions() -> None:
    account, service, container = [project(index, body) for index, body in enumerate(bodies())]
    assert all(item.diagnostics == () for item in (account, service, container))
    assert account.fields == {
        "id": bodies()[0]["id"],
        "properties": {
            "isHnsEnabled": False,
            "immutableStorageWithVersioning": bodies()[0]["properties"]["immutableStorageWithVersioning"],
        },
    }
    assert service.fields == {"id": bodies()[1]["id"], "properties": {"isVersioningEnabled": False}}
    selected = container.fields["properties"]
    assert isinstance(selected, dict)
    expected = copy.deepcopy(bodies()[2]["properties"])
    del expected["immutabilityPolicy"]["updateHistory"]
    expected["legalHold"]["tags"] = [{"tag": "case1"}]
    del expected["legalHold"]["protectedAppendWritesHistory"]["timestamp"]
    assert selected == expected
    assert container.source_etag == '"transport-etag"'
    assert container.api_version == "2026-04-01"
    assert [item.native_scope for item in (account, service, container)] == [
        "Microsoft.Storage/storageAccounts",
        "Microsoft.Storage/storageAccounts/blobServices",
        "Microsoft.Storage/storageAccounts/blobServices/containers",
    ]
    assert "EXCLUDED_" not in json.dumps([item.fields for item in (account, service, container)])


@pytest.mark.parametrize("compressed", [False, True])
def test_actual_session_keeps_three_routes_and_configuration_scope(
    monkeypatch: pytest.MonkeyPatch, compressed: bool
) -> None:
    result, transport, credentials, guarded = collect(monkeypatch, bodies(), compressed=compressed)
    assert result.status == "complete"
    assert result.completed_components == 3 and len(result.findings) == 1
    assert credentials.calls == ["azure"]
    expected = [build_component_url(name, target()) for name in COMPONENTS]
    assert [str(request.url) for request in transport.requests] == expected == guarded
    assert transport.closed and all(stream.closed for stream in transport.streams)
    assert result.object_enforcement_assessed is False
    assert result.recordset_completeness_assessed is False
    assert result.authenticated_identity_verified is False
    assert result.findings[0].control_mappings == []
    assert result.findings[0].resolved_at is None
    assert result.findings[0].compliance_status.value == "unknown"
    assert "EXCLUDED_" not in result.model_dump_json(warnings="error")
    assert StorageRetentionCollectResult.model_validate_json(result.model_dump_json(warnings="error")) == result
    parts = result.resources[0].components
    assert [part.component_id for part in parts] == list(COMPONENTS)
    for part, stream in zip(parts, transport.streams, strict=True):
        assert part.raw_bytes == len(stream.body)
        expected_decoded = gzip.decompress(stream.body) if compressed else stream.body
        assert part.decoded_bytes == len(expected_decoded)


@pytest.mark.parametrize("states", list(itertools.product(("complete", "partial", "unavailable"), repeat=3)))
def test_every_component_state_combination_keeps_prior_evidence(
    monkeypatch: pytest.MonkeyPatch, states: tuple[str, ...]
) -> None:
    payloads = bodies()
    for index, state in enumerate(states):
        if state == "partial":
            payloads[index]["properties"] = {}
        elif state == "unavailable":
            payloads[index]["id"] += "-wrong"
    result, transport, credentials, _ = collect(monkeypatch, payloads)
    assert [item.status for item in result.resources[0].components] == list(states)
    expected = (
        "complete"
        if all(state == "complete" for state in states)
        else "unavailable"
        if all(state == "unavailable" for state in states)
        else "partial"
    )
    assert result.status == expected
    assert len(result.findings) == int(expected != "unavailable")
    assert result.completed_components == states.count("complete")
    assert len(transport.requests) == 3 and credentials.calls == ["azure"]
    for state, item in zip(states, result.resources[0].components, strict=True):
        assert (item.projection is not None) is (state != "unavailable")
        if state == "unavailable":
            assert {detail.code for detail in item.diagnostics} == {"source_identity_mismatch"}


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("status", [401, 403, 404])
def test_common_authorization_failure_and_no_fallback(monkeypatch: pytest.MonkeyPatch, index: int, status: int) -> None:
    statuses = [200, 200, 200]
    statuses[index] = status
    result, transport, _, _ = collect(monkeypatch, bodies(), statuses=statuses)
    parts = result.resources[0].components
    assert parts[index].projection is None
    assert (
        parts[index].diagnostics[0].code
        == {401: "credential_rejected", 403: "forbidden", 404: "resource_not_found"}[status]
    )
    assert len(transport.requests) == (index + 1 if status == 401 else 3)
    for offset in range(index):
        assert parts[offset].status == "complete"
    for offset in range(index + 1, 3):
        assert parts[offset].status == ("unavailable" if status == 401 else "complete")
        assert parts[offset].attempts == (0 if status == 401 else 1)


BOOL_FIELDS = (
    (0, "properties.isHnsEnabled"),
    (0, "properties.immutableStorageWithVersioning.enabled"),
    (0, "properties.immutableStorageWithVersioning.immutabilityPolicy.allowProtectedAppendWrites"),
    (1, "properties.isVersioningEnabled"),
    (2, "properties.hasImmutabilityPolicy"),
    (2, "properties.hasLegalHold"),
    (2, "properties.immutabilityPolicy.properties.allowProtectedAppendWrites"),
    (2, "properties.immutabilityPolicy.properties.allowProtectedAppendWritesAll"),
    (2, "properties.immutableStorageWithVersioning.enabled"),
    (2, "properties.legalHold.hasLegalHold"),
    (2, "properties.legalHold.protectedAppendWritesHistory.allowProtectedAppendWritesAll"),
)
OBJECT_FIELDS = (
    (0, "properties.immutableStorageWithVersioning"),
    (0, "properties.immutableStorageWithVersioning.immutabilityPolicy"),
    (2, "properties.immutabilityPolicy"),
    (2, "properties.immutabilityPolicy.properties"),
    (2, "properties.immutableStorageWithVersioning"),
    (2, "properties.legalHold"),
    (2, "properties.legalHold.protectedAppendWritesHistory"),
)
STRING_FIELDS = (
    (0, "properties.immutableStorageWithVersioning.immutabilityPolicy.state"),
    (2, "properties.immutabilityPolicy.properties.state"),
    (2, "properties.immutableStorageWithVersioning.migrationState"),
    (2, "properties.immutableStorageWithVersioning.timeStamp"),
    (2, "properties.immutabilityPolicy.etag"),
)
DAY_FIELDS = (
    (0, "properties.immutableStorageWithVersioning.immutabilityPolicy.immutabilityPeriodSinceCreationInDays"),
    (2, "properties.immutabilityPolicy.properties.immutabilityPeriodSinceCreationInDays"),
)


def change(body: dict[str, Any], path: str, value: object, *, omit: bool = False) -> None:
    keys = path.split(".")
    parent = nested(body, tuple(keys[:-1]))
    if omit:
        del parent[keys[-1]]
    else:
        parent[keys[-1]] = value


@pytest.mark.parametrize(("index", "path"), BOOL_FIELDS)
@pytest.mark.parametrize("value", [0, 1, "true", [], {}])
def test_boolean_fields_never_coerce(index: int, path: str, value: object) -> None:
    body = bodies()[index]
    change(body, path, value)
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(index, body)


@pytest.mark.parametrize(("index", "path"), OBJECT_FIELDS)
@pytest.mark.parametrize("value", [False, 0, "object", []])
def test_selected_object_shapes_are_strict(index: int, path: str, value: object) -> None:
    body = bodies()[index]
    change(body, path, value)
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(index, body)


@pytest.mark.parametrize(("index", "path"), STRING_FIELDS)
@pytest.mark.parametrize("value", [False, 1, [], {}])
def test_source_string_fields_never_coerce(index: int, path: str, value: object) -> None:
    body = bodies()[index]
    change(body, path, value)
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(index, body)


@pytest.mark.parametrize(("index", "path"), DAY_FIELDS)
@pytest.mark.parametrize("value", [True, 1.0, "365", -1, 0, 2**31])
def test_native_retention_days_are_positive_int32(index: int, path: str, value: object) -> None:
    body = bodies()[index]
    change(body, path, value)
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(index, body)


def test_account_days_honor_published_ceiling() -> None:
    body = bodies()[0]
    change(body, DAY_FIELDS[0][1], 146000)
    assert codes(project(0, body)) == set()
    change(body, DAY_FIELDS[0][1], 146001)
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(0, body)


@pytest.mark.parametrize(("index", "path"), (*BOOL_FIELDS, *OBJECT_FIELDS, *STRING_FIELDS, *DAY_FIELDS))
def test_explicit_null_selected_fields_remain_partial_and_literal(index: int, path: str) -> None:
    body = bodies()[index]
    change(body, path, None)
    value = project(index, body)
    keys = path.split(".")
    assert nested(cast(dict[str, Any], value.fields), tuple(keys[:-1]))[keys[-1]] is None
    assert "missing_source_detail" in codes(value)


@pytest.mark.parametrize(("index", "path"), (*BOOL_FIELDS, *OBJECT_FIELDS, *STRING_FIELDS, *DAY_FIELDS))
def test_omitted_selected_fields_are_not_recreated(index: int, path: str) -> None:
    body = bodies()[index]
    change(body, path, None, omit=True)
    value = project(index, body)
    keys = path.split(".")
    assert keys[-1] not in nested(cast(dict[str, Any], value.fields), tuple(keys[:-1]))


@pytest.mark.parametrize(("index", "path"), STRING_FIELDS[:3])
def test_unknown_enum_is_preserved_without_normalization(index: int, path: str) -> None:
    body = bodies()[index]
    change(body, path, " future-State ")
    value = project(index, body)
    keys = path.split(".")
    assert nested(cast(dict[str, Any], value.fields), tuple(keys[:-1]))[keys[-1]] == " future-State "
    assert "unsupported_source_value" in codes(value)


@pytest.mark.parametrize("state", ["Disabled", "Unlocked", "Locked"])
def test_account_policy_known_states_and_disabled_without_days(state: str) -> None:
    body = bodies()[0]
    policy = body["properties"]["immutableStorageWithVersioning"]["immutabilityPolicy"]
    policy["state"] = state
    if state == "Disabled":
        del policy["immutabilityPeriodSinceCreationInDays"]
    assert codes(project(0, body)) == set()


@pytest.mark.parametrize("state", ["Unlocked", "Locked"])
def test_container_policy_known_states_keep_days(state: str) -> None:
    body = bodies()[2]
    body["properties"]["immutabilityPolicy"]["properties"]["state"] = state
    assert codes(project(2, body)) == set()


@pytest.mark.parametrize("state", ["InProgress", "Completed"])
def test_known_migration_state_is_an_observation(state: str) -> None:
    body = bodies()[2]
    body["properties"]["immutableStorageWithVersioning"]["migrationState"] = state
    assert codes(project(2, body)) == set()


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize(
    "body", [None, [], "payload", True, {}, {"id": "missing-properties"}, {"error": {"message": "EXCLUDED_ERROR"}}]
)
def test_wrong_response_envelopes_are_refused(index: int, body: object) -> None:
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(index, body)


@pytest.mark.parametrize("index", [0, 1, 2])
@pytest.mark.parametrize("suffix", ["/", "?x=1", "#fragment", "-other", " ", "\n"])
def test_returned_identity_must_be_exact_canonical_path(index: int, suffix: str) -> None:
    body = bodies()[index]
    body["id"] += suffix
    with pytest.raises(ClientFault, match=r"^source_identity_mismatch$"):
        project(index, body)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_arm_ascii_case_is_accepted_but_original_id_retained(index: int) -> None:
    body = bodies()[index]
    body["id"] = body["id"].upper()
    assert project(index, body).fields["id"] == body["id"]
    body["id"] = body["id"].replace("/", "%2F")
    with pytest.raises(ClientFault, match=r"^source_identity_mismatch$"):
        project(index, body)


@pytest.mark.parametrize("value", [None, 1, [], {}])
def test_identity_wrong_scalar_is_not_partial(value: object) -> None:
    body = bodies()[0]
    body["id"] = value
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(0, body)


@pytest.mark.parametrize("flags", list(itertools.product((False, True), repeat=3)))
def test_hold_flags_and_nonempty_tags_must_agree(flags: tuple[bool, ...]) -> None:
    top, embedded, present = flags
    body = bodies()[2]
    body["properties"]["hasLegalHold"] = top
    body["properties"]["legalHold"]["hasLegalHold"] = embedded
    body["properties"]["legalHold"]["tags"] = [{"tag": "case1"}] if present else []
    value = project(2, body)
    assert ("unsupported_source_value" in codes(value)) is not (top == embedded == present)


@pytest.mark.parametrize("tags", [["case1"], [None], [True], {"tag": "case1"}, "case1", [{"tag": 1}], [{"tag": []}]])
def test_legal_hold_tag_structures_reject_coercion(tags: object) -> None:
    body = bodies()[2]
    body["properties"]["legalHold"]["tags"] = tags
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(2, body)


@pytest.mark.parametrize("tags", [None, [{}], [{"tag": None}]])
def test_missing_hold_tag_detail_is_literal_partial(tags: object) -> None:
    body = bodies()[2]
    body["properties"]["legalHold"]["tags"] = tags
    value = project(2, body)
    assert nested(cast(dict[str, Any], value.fields), ("properties", "legalHold"))["tags"] == tags
    assert "missing_source_detail" in codes(value)


def test_hold_text_timestamp_and_detached_source_are_literal() -> None:
    body = bodies()[2]
    tag = " <script>synthetic</script> "
    body["properties"]["legalHold"]["tags"][0]["tag"] = tag
    value = project(2, body)
    body["properties"]["legalHold"]["tags"][0]["tag"] = "changed"
    fields = cast(dict[str, Any], value.fields)
    assert fields["properties"]["legalHold"]["tags"] == [{"tag": tag}]
    assert fields["properties"]["immutableStorageWithVersioning"]["timeStamp"] == "2024-01-02T03:04:05.1234567Z"
    fields["properties"]["legalHold"]["tags"].clear()
    assert nested(cast(dict[str, Any], value.fields), ("properties", "legalHold"))["tags"] == [{"tag": tag}]


def test_mutually_exclusive_policy_append_flags_are_partial() -> None:
    body = bodies()[2]
    body["properties"]["immutabilityPolicy"]["properties"]["allowProtectedAppendWrites"] = True
    assert "unsupported_source_value" in codes(project(2, body))


def test_policy_presence_and_flag_cannot_disagree() -> None:
    body = bodies()[2]
    body["properties"]["hasImmutabilityPolicy"] = False
    assert "unsupported_source_value" in codes(project(2, body))
    body = bodies()[2]
    del body["properties"]["immutabilityPolicy"]
    assert "missing_source_detail" in codes(project(2, body))


def test_explicit_disabled_and_absent_configuration_is_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = [fixture("account-disabled.synthetic.json"), bodies()[1], fixture("container-absent.synthetic.json")]
    result, _, _, _ = collect(monkeypatch, payloads)
    assert result.status == "complete"
    assert "immutabilityPolicy" not in cast(Any, result.resources[0].components[2].projection).fields["properties"]


@pytest.mark.parametrize(
    ("name", "index", "expected"),
    [
        ("container-wrong-id.synthetic.json", 2, "unavailable"),
        ("service-wrong-boolean.synthetic.json", 1, "unavailable"),
        ("container-hold-conflict.synthetic.json", 2, "partial"),
    ],
)
def test_named_negative_fixtures(monkeypatch: pytest.MonkeyPatch, name: str, index: int, expected: str) -> None:
    payloads = bodies()
    payloads[index] = fixture(name)
    result, _, _, _ = collect(monkeypatch, payloads)
    assert result.resources[0].components[index].status == expected


def test_duplicate_raw_json_keys_refuse_only_the_component(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads: list[object] = list(bodies())
    payloads[1] = (
        '{"id":'
        + json.dumps(bodies()[1]["id"])
        + ',"properties":{"isVersioningEnabled":false,"isVersioningEnabled":true}}'
    ).encode()
    result, transport, _, _ = collect(monkeypatch, payloads)
    assert [item.status for item in result.resources[0].components] == ["complete", "unavailable", "complete"]
    assert result.resources[0].components[1].diagnostics[0].code == "invalid_response"
    assert len(transport.requests) == 3


def test_oversized_selected_projection_is_atomic(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = bodies()
    payloads[2]["properties"]["legalHold"]["tags"] = [{"tag": "x" * 60} for _ in range(300)]
    result, _, _, _ = collect(monkeypatch, payloads)
    last = result.resources[0].components[2]
    assert last.status == "unavailable" and last.projection is None
    assert last.diagnostics[0].code == "projection_limit"
    assert result.status == "partial" and len(result.findings) == 1


def test_hns_and_versioning_context_do_not_erase_container_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    payloads = bodies()
    payloads[0] = fixture("account-disabled.synthetic.json")
    result, _, _, _ = collect(monkeypatch, payloads)
    assert result.status == "complete"
    last = result.resources[0].components[-1]
    assert last.projection is not None
    properties = cast(dict[str, Any], last.projection.fields["properties"])
    assert properties["immutabilityPolicy"]["properties"]["state"] == "Locked"
    assert properties["hasLegalHold"] is True
    assert result.object_enforcement_assessed is False


@pytest.mark.parametrize(("index", "path"), STRING_FIELDS)
def test_source_strings_have_bounded_retention(index: int, path: str) -> None:
    body = bodies()[index]
    maximum = 1024 if path.endswith("etag") else 128
    change(body, path, "x" * (maximum + 1))
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(index, body)


def test_hold_tag_text_bound_is_exact() -> None:
    body = bodies()[2]
    body["properties"]["legalHold"]["tags"][0]["tag"] = "x" * 1024
    selected = project(2, body)
    assert len(cast(Any, selected.fields)["properties"]["legalHold"]["tags"][0]["tag"]) == 1024
    body["properties"]["legalHold"]["tags"][0]["tag"] += "x"
    with pytest.raises(ClientFault, match=r"^invalid_response$"):
        project(2, body)


def test_missing_primary_observations_cannot_claim_complete() -> None:
    for index, body in enumerate(bodies()):
        body["properties"] = {}
        selected = project(index, body)
        assert selected.fields["properties"] == {}
        assert codes(selected) == {"missing_source_detail"}


def test_source_error_text_does_not_escape_component_or_logs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    payloads = bodies()
    payloads[1] = {"error": {"code": "EXCLUDED_ERROR_CODE", "message": "EXCLUDED_ERROR_DETAIL"}}
    result, _, _, _ = collect(monkeypatch, payloads)
    assert result.resources[0].components[1].diagnostics[0].code == "invalid_response"
    assert "EXCLUDED_" not in result.model_dump_json(warnings="error")
    assert "EXCLUDED_" not in caplog.text
    assert "SYNTHETIC_AZURE_TOKEN" not in caplog.text


def test_invalid_constructed_target_is_rejected_before_credentials() -> None:
    selected = target()
    credential = SyntheticCredentials()
    request = validated_request({"provider": "azure", "scope_label": "synthetic", "targets": [selected]})
    session = StorageReadSession(request, credentials=credential, utc_clock=lambda: NOW, monotonic_clock=lambda: 0.0)
    forged = AzureTarget.model_construct(**{**selected.__dict__, "account": "not/a/path"})
    try:
        with pytest.raises(ClientFault, match=r"^endpoint_mismatch$"):
            azure.read_azure(forged, session)
    finally:
        session.close()
    assert credential.calls == []
