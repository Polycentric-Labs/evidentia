"""Session source authority, atomic admission, caching, handles, and deadline controls."""

from __future__ import annotations

import copy
import json
import socket
import ssl
from collections.abc import Callable, Iterator
from dataclasses import FrozenInstanceError, dataclass, field
from datetime import UTC, datetime
from typing import cast

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _client, _credentials
from evidentia_collectors.enterprise_retention._contracts import (
    ElasticIndexTarget,
    EnterpriseRetentionCollectRequest,
    EnterpriseRetentionCollectResult,
    EnterpriseRetentionReadResult,
    ProviderName,
    ReadKind,
    VaultMatterTarget,
    expected_fields,
)
from evidentia_collectors.enterprise_retention._credentials import CredentialMaterial
from evidentia_collectors.enterprise_retention._parsing import JsonObject, canonical_json
from evidentia_collectors.enterprise_retention._profiles import AddressPolicy, AuthorizedProfile, FrozenProfile
from evidentia_core import network_guard
from pydantic import JsonValue

NOW = datetime(2026, 9, 10, 12, 0, 0, 123456, tzinfo=UTC)


RUN_ID = "01K4RZP8V00000000000000000"


SCOPE: dict[ReadKind, _client.NativeScope] = {
    "vault-matter": "matter",
    "vault-holds": "hold",
    "splunk-index": "index",
    "elastic-explain": "index",
    "elastic-policy": "policy",
    "elastic-status": "service",
}


@dataclass(frozen=True)
class Reply:
    path: str
    body: JsonObject
    status: int = 200
    query: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Call:
    method: str
    host: str
    path: str
    query: tuple[tuple[str, str], ...]


class Stream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body
        self.closed = False

    def __iter__(self) -> Iterator[bytes]:
        midpoint = max(1, len(self.body) // 2)
        yield self.body[:midpoint]
        yield self.body[midpoint:]

    def close(self) -> None:
        self.closed = True


@dataclass
class Router:
    replies: list[Reply]
    expected_host: str
    violations: list[Call] = field(default_factory=list)
    calls: list[Call] = field(default_factory=list)
    streams: list[Stream] = field(default_factory=list)
    transports: list[httpx.MockTransport] = field(default_factory=list)

    def handle(self, request: httpx.Request) -> httpx.Response:
        call = Call(request.method, request.url.host, request.url.path, tuple(request.url.params.multi_items()))
        self.calls.append(call)
        if not self.replies:
            self.violations.append(call)
            raise AssertionError("an unplanned outbound request was attempted")
        reply = self.replies.pop(0)
        if (
            call.method != "GET"
            or call.host != self.expected_host
            or call.path != reply.path
            or sorted(call.query) != sorted(reply.query)
            or len(call.query) != len({key for key, _ in call.query})
        ):
            self.violations.append(call)
            raise AssertionError("a request differs from the fixed synthetic route")
        body = json.dumps(reply.body, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        stream = Stream(body)
        self.streams.append(stream)
        return httpx.Response(reply.status, headers={"Content-Type": "application/json"}, stream=stream)

    def factory(self, context: ssl.SSLContext) -> httpx.MockTransport:
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
        transport = httpx.MockTransport(self.handle)
        self.transports.append(transport)
        return transport

    def assert_consumed(self) -> None:
        assert not self.violations
        assert not self.replies
        assert all(stream.closed for stream in self.streams)


@dataclass
class Resolver:
    providers: list[ProviderName] = field(default_factory=list)

    def resolve(self, profile: FrozenProfile) -> CredentialMaterial:
        self.providers.append(profile.provider)
        return CredentialMaterial(profile.provider, "synthetic-session-token")


@dataclass
class Rig:
    request: EnterpriseRetentionCollectRequest
    profile: AuthorizedProfile
    router: Router
    resolver: Resolver

    def session(self) -> _client.EnterpriseReadSession:
        def no_retry(delay: float) -> None:
            raise AssertionError("these admission cases must not retry")

        return _client.EnterpriseReadSession(
            self.request,
            profile=self.profile,
            transport_factory=self.router.factory,
            utc_clock=lambda: NOW,
            monotonic_clock=lambda: 0.0,
            sleep=no_retry,
            run_id_factory=lambda: RUN_ID,
        )

    @property
    def vault(self) -> VaultMatterTarget:
        target = self.request.root.targets[0]
        assert isinstance(target, VaultMatterTarget)
        return target

    @property
    def elastic(self) -> tuple[ElasticIndexTarget, ...]:
        targets = self.request.root.targets
        assert all(isinstance(target, ElasticIndexTarget) for target in targets)
        return tuple(target for target in targets if isinstance(target, ElasticIndexTarget))


def rig(provider: ProviderName, replies: list[Reply], identities: tuple[str, ...] = ("selected",)) -> Rig:
    target_name = "matter_id" if provider == "google-vault" else "index"
    request = EnterpriseRetentionCollectRequest.model_validate(
        {
            "provider": provider,
            "profile_alias": "review",
            "scope_label": "synthetic-selected",
            "targets": [{target_name: identity} for identity in identities],
        }
    )
    origin = (
        "https://vault.googleapis.com:443" if provider == "google-vault" else "https://elastic.example.invalid:9200"
    )
    profile = FrozenProfile("review", provider, origin, "ENTERPRISE_RETENTION_REVIEW_TOKEN", AddressPolicy("public"))
    resolver = Resolver()
    return Rig(request, AuthorizedProfile(profile, resolver), Router(list(replies), profile.host), resolver)


@pytest.fixture(autouse=True)
def isolated_destination(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    def synthetic_dns(
        host: str | bytes, port: int, family: int = 0, type: int = 0, proto: int = 0, flags: int = 0
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        assert host in (
            "vault.googleapis.com",
            b"vault.googleapis.com",
            "elastic.example.invalid",
            b"elastic.example.invalid",
        )
        assert port in (443, 9200)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]

    def forbidden_environment(name: str) -> str | None:
        raise AssertionError("no environment credential reference may be read")

    monkeypatch.setattr(socket, "getaddrinfo", synthetic_dns)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", network_guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(_client, "ssl_context", lambda profile: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    monkeypatch.setattr(_credentials, "_environment_value", forbidden_environment)
    with network_guard.offline_mode(False):
        yield


def sources(subject: _client.ReadSubject, data: JsonObject) -> list[JsonObject]:
    if subject.kind == "vault-holds":
        return cast(list[JsonObject], data.get("holds", []))
    if subject.kind == "elastic-explain":
        return [cast(dict[str, JsonObject], data["indices"])[subject.source_id]]
    if subject.kind == "elastic-policy":
        return [cast(JsonObject, data[subject.source_id])]
    return [data]


def project_data(data: JsonObject, subject: _client.ReadSubject) -> _client.ProjectedPage:
    records = []
    for ordinal, source in enumerate(sources(subject, data)):
        selected = expected_fields(subject.kind, source)
        identity = cast(str, source["holdId"]) if subject.kind == "vault-holds" else subject.source_id
        records.append(
            _client.ProjectedRecord(
                ordinal, identity, SCOPE[subject.kind], selected.fields, selected.coverage, selected.diagnostics
            )
        )
    return _client.ProjectedPage(tuple(records))


def project(response: _client.ParsedResponse, subject: _client.ReadSubject) -> _client.ProjectedPage:
    assert response.status == 200
    return project_data(response.data, subject)


def matter(identity: str = "selected", status: int = 200) -> Reply:
    return Reply(f"/v1/matters/{identity}", {"matterId": identity, "state": "OPEN"}, status, (("view", "BASIC"),))


def holds(body: JsonObject, token: str | None = None) -> Reply:
    query: tuple[tuple[str, str], ...] = (("view", "FULL_HOLD"), ("pageSize", "100"))
    if token is not None:
        query += (("pageToken", token),)
    return Reply("/v1/matters/selected/holds", body, query=query)


def hold(identity: str, name: str | None = None) -> JsonObject:
    return {"holdId": identity, "name": identity if name is None else name, "corpus": "MAIL"}


def status(code: int = 200) -> Reply:
    return Reply("/_ilm/status", {"operation_mode": "RUNNING"}, code)


def explain(identity: str, fields: JsonObject) -> Reply:
    return Reply(
        f"/{identity}/_ilm/explain",
        {"indices": {identity: {"index": identity, **fields}}},
        query=(("only_managed", "false"), ("only_errors", "false")),
    )


def policy(identity: str = "shared-policy", code: int = 200) -> Reply:
    return Reply(f"/_ilm/policy/{identity}", {identity: {"version": 1, "policy": {"phases": {}}}}, code)


def complete_vault(rig: Rig, projector: _client.Projector = project) -> EnterpriseRetentionCollectResult:
    with rig.session() as session:
        target = rig.vault
        first = session.read_vault_matter(target, project)
        second = session.read_vault_holds(target, projector)
        resource = session.finish_resource(target, reads=(first, second))
        result = session.finish((resource,))
    rig.router.assert_consumed()
    return validate_result(result)


def complete_elastic(rig: Rig, projector: _client.Projector = project) -> EnterpriseRetentionCollectResult:
    with rig.session() as session:
        shared_status = session.read_elastic_status(project)
        resources = []
        for target in rig.elastic:
            explanation = session.read_elastic_explain(target, projector)
            linked_policy = session.read_elastic_policy(target, explanation, project)
            handles = (
                (explanation, shared_status) if linked_policy is None else (explanation, linked_policy, shared_status)
            )
            resources.append(session.finish_resource(target, reads=handles))
        result = session.finish(tuple(resources))
    rig.router.assert_consumed()
    return validate_result(result)


def validate_result(result: EnterpriseRetentionCollectResult) -> EnterpriseRetentionCollectResult:
    encoded = result.model_dump_json(warnings="error")
    checked = EnterpriseRetentionCollectResult.model_validate_json(encoded)
    assert checked.model_dump(mode="json", warnings="error") == result.model_dump(mode="json", warnings="error")
    manifest = checked.root.manifest
    assert manifest.attempts == sum(read.attempts for read in checked.root.source_reads)
    assert manifest.records_received == sum(read.records_received for read in checked.root.source_reads)
    assert manifest.records_admitted == sum(read.records_admitted for read in checked.root.source_reads)
    return checked


def read(
    result: EnterpriseRetentionCollectResult, kind: ReadKind, identity: str | None = None
) -> EnterpriseRetentionReadResult:
    matches = [
        entry
        for entry in result.root.source_reads
        if entry.kind == kind and (identity is None or entry.source_id == identity)
    ]
    assert len(matches) == 1
    return matches[0]


def ids(entry: EnterpriseRetentionReadResult) -> list[str]:
    return [observation.source_identity for observation in entry.observations]


def replace_record(
    record: _client.ProjectedRecord, *, ordinal: int | None = None, fields: JsonObject | None = None
) -> _client.ProjectedRecord:
    return _client.ProjectedRecord(
        record.source_ordinal if ordinal is None else ordinal,
        record.source_identity,
        record.native_scope,
        record.fields if fields is None else fields,
        record.field_coverage,
        record.diagnostics,
    )


def mutate_view(change: Callable[[JsonObject], None]) -> _client.Projector:
    def modified(response: _client.ParsedResponse, subject: _client.ReadSubject) -> _client.ProjectedPage:
        data = response.data
        change(data)
        return project_data(data, subject)

    return modified


def list_json(values: list[JsonObject]) -> list[JsonValue]:
    return cast(list[JsonValue], values)


def test_vault_follows_only_exact_opaque_source_token() -> None:
    token = "?next=https://untrusted.invalid/x&view=FULL_HOLD#%+ token"
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"holds": [hold("first")], "nextPageToken": token}),
            holds({"holds": [hold("second")], "nextPageToken": ""}, token),
        ],
    )
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert ids(entry) == ["first", "second"]
    assert (entry.pages_received, entry.pages_admitted, entry.records_received, entry.records_admitted) == (2, 2, 2, 2)
    assert entry.status == "complete"
    assert result.root.status == "complete"
    assert len(source.router.calls) == 3
    assert {call.host for call in source.router.calls} == {"vault.googleapis.com"}
    assert source.router.calls[-1].query[-1] == ("pageToken", token)


@pytest.mark.parametrize("body", [{}, {"holds": []}, {"holds": [], "nextPageToken": ""}])
def test_empty_terminal_vault_page_is_complete(body: JsonObject) -> None:
    source = rig("google-vault", [matter(), holds(body)])
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert entry.status == "complete" and ids(entry) == []
    assert (entry.pages_received, entry.pages_admitted, entry.records_received, entry.records_admitted) == (1, 1, 0, 0)
    assert len(result.root.findings) == 1


def test_empty_intermediate_page_does_not_end_source_continuation() -> None:
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"nextPageToken": "next"}),
            holds({"holds": [hold("later")]}, "next"),
        ],
    )
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert entry.status == "complete" and ids(entry) == ["later"]
    assert (entry.pages_received, entry.pages_admitted, entry.records_received) == (2, 2, 1)


@pytest.mark.parametrize("tamper", ["drop", "repeat", "reverse", "ordinal", "field"])
def test_whole_page_callback_refusal_preserves_previous_page(tamper: str) -> None:
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"holds": [hold("earlier")], "nextPageToken": "next"}),
            holds({"holds": [hold("current-a"), hold("current-b")], "nextPageToken": "never-follow"}, "next"),
        ],
    )
    earlier: list[bytes] = []

    def adversarial(response: _client.ParsedResponse, subject: _client.ReadSubject) -> _client.ProjectedPage:
        page = project(response, subject)
        if page.records[0].source_identity == "earlier":
            earlier.append(page.records[0]._fields)
            return page
        records = page.records
        if tamper == "drop":
            records = records[:1]
        elif tamper == "repeat":
            records = (records[0], records[0])
        elif tamper == "reverse":
            records = tuple(reversed(records))
        elif tamper == "ordinal":
            records = (records[0], replace_record(records[1], ordinal=0))
        else:
            fields = records[1].fields
            fields["name"] = "changed"
            records = (records[0], replace_record(records[1], fields=fields))
        return _client.ProjectedPage(records)

    result = complete_vault(source, adversarial)
    entry = read(result, "vault-holds")
    assert entry.status == "partial" and ids(entry) == ["earlier"]
    assert entry.observations[0].fields["name"] == "earlier"
    assert earlier == [b'{"corpus":"MAIL","holdId":"earlier","name":"earlier"}']
    assert (entry.pages_received, entry.pages_admitted, entry.records_received, entry.records_admitted) == (2, 1, 3, 1)
    assert entry.duplicates_coalesced == entry.conflicts_quarantined == 0
    assert len(source.router.calls) == 3


@pytest.mark.parametrize("bad", [None, {}, {"holdId": 7}, {"holdId": "bad", "corpus": []}])
def test_raw_list_counts_invalid_member_without_admitting_any_current_record(bad: JsonValue) -> None:
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"holds": [hold("earlier")], "nextPageToken": "next"}),
            holds({"holds": [hold("current"), bad], "nextPageToken": "never-follow"}, "next"),
        ],
    )
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert ids(entry) == ["earlier"] and entry.status == "partial"
    assert (entry.pages_received, entry.pages_admitted, entry.records_received) == (2, 1, 3)
    assert len(source.router.calls) == 3


def test_wrong_raw_list_counts_zero_records_and_refuses_page() -> None:
    source = rig("google-vault", [matter(), holds({"holds": None})])
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert entry.status == "unavailable" and ids(entry) == []
    assert (entry.pages_received, entry.pages_admitted, entry.records_received) == (1, 0, 0)


@pytest.mark.parametrize("token", [None, 1])
def test_invalid_source_token_cannot_be_repaired_by_callback(token: JsonValue) -> None:
    called = []
    source = rig("google-vault", [matter(), holds({"holds": [hold("unadmitted")], "nextPageToken": token})])

    def repair(response: _client.ParsedResponse, subject: _client.ReadSubject) -> _client.ProjectedPage:
        called.append(subject.kind)
        data = response.data
        data.pop("nextPageToken", None)
        return project_data(data, subject)

    result = complete_vault(source, repair)
    entry = read(result, "vault-holds")
    assert (entry.pages_received, entry.pages_admitted, entry.records_received) == (1, 0, 1)
    assert entry.status == "unavailable" and called == []
    assert len(source.router.calls) == 2


def test_repeated_source_token_refuses_candidate_before_state_commit() -> None:
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"holds": [hold("earlier")], "nextPageToken": "repeat"}),
            holds({"holds": [hold("unadmitted")], "nextPageToken": "repeat"}, "repeat"),
        ],
    )
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert entry.status == "partial" and ids(entry) == ["earlier"]
    assert (entry.pages_received, entry.pages_admitted, entry.records_received, entry.records_admitted) == (2, 1, 2, 1)
    assert len(source.router.calls) == 3
    assert "token_repeated" in {diagnostic.code for diagnostic in entry.diagnostics}


@pytest.mark.parametrize("across_pages", [False, True])
def test_identical_duplicates_coalesce_by_selected_projection(across_pages: bool) -> None:
    first, second = hold("same"), hold("same")
    first["excluded_metadata"] = {"value": "first"}
    second["excluded_metadata"] = {"value": "second"}
    pages = (
        [holds({"holds": [first], "nextPageToken": "next"}), holds({"holds": [second]}, "next")]
        if across_pages
        else [holds({"holds": [first, second]})]
    )
    result = complete_vault(rig("google-vault", [matter(), *pages]))
    entry = read(result, "vault-holds")
    assert entry.status == "complete" and ids(entry) == ["same"]
    assert (
        entry.records_received,
        entry.records_admitted,
        entry.duplicates_coalesced,
        entry.conflicts_quarantined,
    ) == (2, 1, 1, 0)
    assert "excluded_metadata" not in entry.observations[0].fields


@pytest.mark.parametrize("across_pages", [False, True])
def test_conflicting_identity_is_quarantined_with_unrelated_evidence_retained(across_pages: bool) -> None:
    initial = [hold("conflict", "old"), hold("stable")]
    incoming = [hold("conflict", "new"), hold("later")]
    pages = (
        [holds({"holds": list_json(initial), "nextPageToken": "next"}), holds({"holds": list_json(incoming)}, "next")]
        if across_pages
        else [holds({"holds": list_json(initial + incoming)})]
    )
    result = complete_vault(rig("google-vault", [matter(), *pages]))
    entry = read(result, "vault-holds")
    assert entry.status == "partial" and ids(entry) == ["stable", "later"]
    assert (
        entry.records_received,
        entry.records_admitted,
        entry.duplicates_coalesced,
        entry.conflicts_quarantined,
    ) == (4, 2, 0, 1)
    assert entry.pages_admitted == (2 if across_pages else 1)


def test_invalid_page_does_not_commit_a_conflict_from_its_valid_prefix() -> None:
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"holds": [hold("stable", "original")], "nextPageToken": "next"}),
            holds({"holds": [hold("stable", "changed"), None]}, "next"),
        ],
    )
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert ids(entry) == ["stable"] and entry.observations[0].fields["name"] == "original"
    assert entry.conflicts_quarantined == 0
    assert (entry.pages_admitted, entry.records_received) == (1, 3)


@pytest.mark.parametrize("replacement", [None, "callback-forged"])
def test_callback_token_view_cannot_replace_or_delete_raw_continuation(replacement: str | None) -> None:
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"holds": [hold("first")], "nextPageToken": "raw-next"}),
            holds({"holds": [hold("second")]}, "raw-next"),
        ],
    )

    def mutate(data: JsonObject) -> None:
        if replacement is None:
            data.pop("nextPageToken", None)
        else:
            data["nextPageToken"] = replacement

    result = complete_vault(source, mutate_view(mutate))
    assert ids(read(result, "vault-holds")) == ["first", "second"]
    assert result.root.status == "complete"
    assert source.router.calls[-1].query[-1] == ("pageToken", "raw-next")


def test_unavailable_matter_cannot_authorize_holds_read() -> None:
    source = rig("google-vault", [matter(status=403)])
    result = complete_vault(source)
    entry = read(result, "vault-holds")
    assert entry.status == "unavailable" and entry.attempts == 0
    assert entry.records_received == 0 and entry.started_at is None
    assert result.root.status == "unavailable" and len(result.root.resources) == 1
    assert len(source.router.calls) == 1


@pytest.mark.parametrize("code", [200, 403])
def test_elastic_shared_status_is_cached_on_success_or_failure(code: int) -> None:
    source = rig(
        "elastic-ilm",
        [status(code), explain("first", {"managed": False}), explain("second", {"managed": False})],
        ("first", "second"),
    )
    with source.session() as session:
        resources = []
        status_ids = []
        for target in source.elastic:
            shared = session.read_elastic_status(project)
            status_ids.append(shared.read_id)
            own = session.read_elastic_explain(target, project)
            assert session.read_elastic_policy(target, own, project) is None
            resources.append(session.finish_resource(target, reads=(own, shared)))
        result = validate_result(session.finish(tuple(resources)))
    source.router.assert_consumed()
    assert status_ids[0] == status_ids[1]
    assert [entry.kind for entry in result.root.source_reads] == [
        "elastic-status",
        "elastic-explain",
        "elastic-explain",
    ]
    assert result.root.manifest.attempts == 3
    assert read(result, "elastic-status").status == ("complete" if code == 200 else "unavailable")
    assert all(resource.status == ("complete" if code == 200 else "partial") for resource in result.root.resources)


@pytest.mark.parametrize("code", [200, 403])
def test_elastic_shared_policy_has_one_admitted_relationship_and_one_wire_read(code: int) -> None:
    source = rig(
        "elastic-ilm",
        [
            status(),
            explain("first", {"managed": True, "policy": "shared-policy"}),
            policy(code=code),
            explain("second", {"managed": True, "policy": "shared-policy"}),
        ],
        ("first", "second"),
    )
    result = complete_elastic(source)
    assert [entry.kind for entry in result.root.source_reads] == [
        "elastic-status",
        "elastic-explain",
        "elastic-explain",
        "elastic-policy",
    ]
    shared = read(result, "elastic-policy")
    assert shared.source_id == "shared-policy" and shared.attempts == 1
    assert result.root.manifest.attempts == 4
    assert all(resource.policy_resolution == "resolved" for resource in result.root.resources)
    assert all(resource.read_ids[1] == shared.read_id for resource in result.root.resources)
    assert all(resource.status == ("complete" if code == 200 else "partial") for resource in result.root.resources)


@pytest.mark.parametrize(
    "fields",
    [
        {"managed": False, "policy": "looks-supported"},
        {"managed": True},
        {"managed": True, "policy": None},
        {"managed": True, "policy": ""},
        {"managed": True, "policy": "unsupported/path"},
    ],
)
def test_raw_relation_without_supported_managed_policy_never_creates_a_policy_request(fields: JsonObject) -> None:
    source = rig("elastic-ilm", [status(), explain("selected", fields)])
    result = complete_elastic(source)
    assert len(source.router.calls) == 2
    assert all(entry.kind != "elastic-policy" for entry in result.root.source_reads)
    observation = read(result, "elastic-explain").observations[0]
    if "policy" in fields:
        assert "policy" in observation.fields and observation.fields["policy"] == fields["policy"]
    else:
        assert "policy" not in observation.fields
    assert result.root.resources[0].policy_resolution == (
        "not_applicable" if fields["managed"] is False else "unresolved"
    )


@pytest.mark.parametrize(
    "raw,changes",
    [
        ({"managed": False, "policy": "raw-policy"}, {"managed": True}),
        ({"managed": True, "policy": "raw-policy"}, {"managed": False}),
        ({"managed": True, "policy": "raw-policy"}, {"managed": 1}),
        ({"managed": True, "policy": "raw-policy"}, {"policy": "forged-policy"}),
        ({"managed": True}, {"policy": "forged-policy"}),
        ({"managed": True, "policy": None}, {"policy": ""}),
    ],
)
def test_callback_cannot_change_raw_policy_authority(raw: JsonObject, changes: JsonObject) -> None:
    source = rig("elastic-ilm", [status(), explain("selected", raw)])

    def mutate(data: JsonObject) -> None:
        native = cast(dict[str, JsonObject], data["indices"])["selected"]
        native.update(changes)

    result = complete_elastic(source, mutate_view(mutate))
    own = read(result, "elastic-explain")
    assert own.status == "unavailable" and own.pages_admitted == 0
    assert (own.pages_received, own.records_received, own.records_admitted) == (1, 1, 0)
    assert all(entry.kind != "elastic-policy" for entry in result.root.source_reads)
    assert result.root.resources[0].policy_resolution == "unresolved"
    assert len(source.router.calls) == 2


def test_returned_callback_view_mutation_cannot_relabel_admitted_policy() -> None:
    source = rig(
        "elastic-ilm", [status(), explain("selected", {"managed": True, "policy": "raw-policy"}), policy("raw-policy")]
    )
    retained: list[_client.ProjectedPage] = []

    def retain(response: _client.ParsedResponse, subject: _client.ReadSubject) -> _client.ProjectedPage:
        page = project(response, subject)
        retained.append(page)
        return page

    with source.session() as session:
        shared = session.read_elastic_status(project)
        target = source.elastic[0]
        own = session.read_elastic_explain(target, retain)
        detached_view = retained[0].records[0].fields
        detached_view["policy"] = "forged-policy"
        object.__setattr__(retained[0].records[0], "_fields", canonical_json(detached_view))
        linked = session.read_elastic_policy(target, own, project)
        assert linked is not None
        resource = session.finish_resource(target, reads=(own, linked, shared))
        result = validate_result(session.finish((resource,)))
    source.router.assert_consumed()
    assert read(result, "elastic-explain").observations[0].fields["policy"] == "raw-policy"
    assert read(result, "elastic-policy").source_id == "raw-policy"


def test_foreign_session_handle_does_not_authorize_policy_or_resource() -> None:
    first = rig("elastic-ilm", [status(), explain("selected", {"managed": True, "policy": "raw-policy"})])
    second = rig("elastic-ilm", [])
    with first.session() as source, second.session() as destination:
        source.read_elastic_status(project)
        foreign = source.read_elastic_explain(first.elastic[0], project)
        with pytest.raises(ValueError):
            destination.read_elastic_policy(second.elastic[0], foreign, project)
        with pytest.raises(ValueError):
            destination.finish_resource(second.elastic[0], reads=(foreign,))
    first.router.assert_consumed()
    second.router.assert_consumed()
    assert second.resolver.providers == [] and second.router.calls == []


def test_valid_handle_for_different_target_cannot_authorize_policy() -> None:
    source = rig(
        "elastic-ilm", [status(), explain("first", {"managed": True, "policy": "raw-policy"})], ("first", "second")
    )
    with source.session() as session:
        first, second = source.elastic
        session.read_elastic_status(project)
        own = session.read_elastic_explain(first, project)
        with pytest.raises(ValueError):
            session.read_elastic_policy(second, own, project)
    source.router.assert_consumed()
    assert len(source.router.calls) == 2


@pytest.mark.parametrize("clone", ["copy", "forged"])
def test_copied_or_forged_handle_cannot_authorize_policy(clone: str) -> None:
    source = rig("elastic-ilm", [status(), explain("selected", {"managed": True, "policy": "raw-policy"})])
    with source.session() as session:
        target = source.elastic[0]
        session.read_elastic_status(project)
        own = session.read_elastic_explain(target, project)
        if clone == "copy":
            try:
                counterfeit = copy.copy(own)
            except (TypeError, ValueError):
                counterfeit = None
            if counterfeit is own:
                counterfeit = None
        else:
            counterfeit = object.__new__(type(own))
            for cls in type(own).__mro__:
                slots = getattr(cls, "__slots__", ())
                for name in (slots,) if isinstance(slots, str) else slots:
                    if name not in ("__dict__", "__weakref__") and hasattr(own, name):
                        object.__setattr__(counterfeit, name, getattr(own, name))
        if counterfeit is not None:
            with pytest.raises(ValueError):
                session.read_elastic_policy(target, counterfeit, project)
    source.router.assert_consumed()
    assert len(source.router.calls) == 2


def test_handle_read_id_is_readonly_and_not_a_general_followup_key() -> None:
    source = rig("elastic-ilm", [status(), explain("selected", {"managed": True, "policy": "raw-policy"})])
    with source.session() as session:
        target = source.elastic[0]
        session.read_elastic_status(project)
        own = session.read_elastic_explain(target, project)
        assert own.read_id == "enterprise-retention/elastic-ilm/review/elastic-explain/selected"
        with pytest.raises((AttributeError, FrozenInstanceError, TypeError)):
            attribute = "read_id"
            setattr(own, attribute, "enterprise-retention/elastic-ilm/review/elastic-policy/forged")
        with pytest.raises(ValueError):
            session.read_elastic_policy(target, cast(_client.ReadHandle, own.read_id), project)
    source.router.assert_consumed()


@dataclass
class Clock:
    current: float = 0.0
    armed: bool = False
    trips: int = 0

    def utc(self) -> datetime:
        if self.armed:
            self.armed = False
            self.current = 121.0
            self.trips += 1
        return NOW

    def monotonic(self) -> float:
        return self.current


def make_session(source: Rig, clock: Clock) -> _client.EnterpriseReadSession:
    def no_wait(delay: float) -> None:
        raise AssertionError("no retry expected")

    return _client.EnterpriseReadSession(
        source.request,
        profile=source.profile,
        transport_factory=source.router.factory,
        utc_clock=clock.utc,
        monotonic_clock=clock.monotonic,
        sleep=no_wait,
        run_id_factory=lambda: RUN_ID,
    )


def test_factory_clock_crossing_deadline_refuses_current_page_with_prior_facts() -> None:
    clock = Clock()
    source = rig(
        "google-vault",
        [
            matter(),
            holds({"holds": [hold("earlier")], "nextPageToken": "next"}),
            holds({"holds": [hold("late")]}, "next"),
        ],
    )

    def arm_after_projection(response: _client.ParsedResponse, subject: _client.ReadSubject) -> _client.ProjectedPage:
        page = project(response, subject)
        if page.records[0].source_identity == "late":
            clock.armed = True
        return page

    with make_session(source, clock) as session:
        first = session.read_vault_matter(source.vault, project)
        second = session.read_vault_holds(source.vault, arm_after_projection)
        resource = session.finish_resource(source.vault, reads=(first, second))
        result = validate_result(session.finish((resource,)))
    source.router.assert_consumed()
    entry = read(result, "vault-holds")
    assert clock.trips == 1 and len(source.router.calls) == 3
    assert ids(entry) == ["earlier"]
    assert (entry.pages_received, entry.pages_admitted, entry.records_received, entry.records_admitted) == (2, 1, 2, 1)
    assert result.root.status == "partial"
    assert "deadline_exceeded" in {diagnostic.code for diagnostic in result.root.diagnostics}


def test_final_factory_clock_crossing_deadline_does_not_publish_complete() -> None:
    clock = Clock()
    source = rig("google-vault", [matter(), holds({"holds": [hold("earlier")]})])
    with make_session(source, clock) as session:
        first = session.read_vault_matter(source.vault, project)
        second = session.read_vault_holds(source.vault, project)
        resource = session.finish_resource(source.vault, reads=(first, second))
        clock.armed = True
        result = validate_result(session.finish((resource,)))
    source.router.assert_consumed()
    entry = read(result, "vault-holds")
    assert clock.trips == 1 and len(source.router.calls) == 2
    assert ids(entry) == ["earlier"] and entry.pages_admitted == 1
    assert result.root.status == "partial"
    assert "deadline_exceeded" in {diagnostic.code for diagnostic in result.root.diagnostics}
