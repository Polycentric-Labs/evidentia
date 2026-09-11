"""Detached source authority and owned synchronous enterprise HTTP attempts."""

from __future__ import annotations

import copy
import http.cookiejar
import ipaddress
import math
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import ExitStack
from dataclasses import dataclass, field
from dataclasses import replace as dataclass_replace
from datetime import UTC, datetime, timedelta
from functools import partial
from types import MappingProxyType, TracebackType
from typing import Any, Literal, Never, cast
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request as CookieRequest

import httpx
from evidentia_core import __version__ as EVIDENTIA_VERSION
from evidentia_core import network_guard
from evidentia_core.audit.provenance import new_run_id
from pydantic import ValidationError

from evidentia_collectors import __version__ as COLLECTOR_VERSION
from evidentia_collectors.retention import _client as frozen
from evidentia_collectors.retention._client import quiet_transport_logs

from ._contracts import (
    DIAGNOSTIC_ORDER,
    CapacityExceeded,
    CapacityPlan,
    CorrespondenceError,
    CoverageState,
    DiagnosticCode,
    DiagnosticScope,
    ElasticIndexTarget,
    EnterpriseRetentionCollectRequest,
    EnterpriseRetentionCollectResult,
    EnterpriseRetentionDiagnostic,
    EnterpriseRetentionObservation,
    EnterpriseRetentionReadResult,
    EnterpriseRetentionResourceResult,
    EnterpriseTarget,
    HttpStatusAccumulator,
    InterpretationCode,
    ProviderName,
    ReadKey,
    ReadKind,
    SplunkIndexTarget,
    VaultMatterTarget,
    diagnostic_rule,
    empty_read,
    expected_fields,
    initial_read_keys,
    make_observation,
    make_result,
    parse_request,
    supported_policy,
    target_identity,
    validate_correspondence,
    validated_request,
)
from ._credentials import CredentialError, CredentialMaterial, validated_material
from ._parsing import MAX_NODES, JsonObject, ParsingError, canonical_json, checked_json, parse_strict_json
from ._profiles import (
    AddressPolicyError,
    AuthorizedProfile,
    FrozenProfile,
    classify_answers,
    ssl_context,
    validated_profile,
)

ErrorCode = Literal["invalid_json", "invalid_response", "identity_mismatch", "token_invalid", "upstream_error"]
ReadWarning = Literal["upstream_warning", "unsupported_source_value"]
Presence = Literal["absent", "null", "empty", "value"]
NativeScope = Literal["matter", "hold", "index", "policy", "service"]
KINDS: tuple[ReadKind, ...] = (
    "vault-matter",
    "vault-holds",
    "splunk-index",
    "elastic-explain",
    "elastic-policy",
    "elastic-status",
)
SCOPES = MappingProxyType(
    {
        "vault-matter": "matter",
        "vault-holds": "hold",
        "splunk-index": "index",
        "elastic-explain": "index",
        "elastic-policy": "policy",
        "elastic-status": "service",
    }
)
COUNTER_MAX = (1 << 128) - 1


class AuthorityError(ValueError):
    """A closed failure code without source values, paths or provider text."""

    def __init__(self, code: ErrorCode = "invalid_response") -> None:
        self.code = code
        super().__init__(code)


def _kind(value: object) -> ReadKind:
    if type(value) is not str or value not in KINDS:
        raise AuthorityError()
    return value


def _integer(value: object, *, positive: bool = False) -> int:
    if type(value) is not int or not int(positive) <= value <= COUNTER_MAX:
        raise AuthorityError()
    return value


def _text(value: object, *, max_bytes: int = 1024, nonblank: bool = True) -> str:
    if type(value) is not str:
        raise AuthorityError()
    text = value
    try:
        size = len(text.encode("utf-8", errors="strict"))
    except UnicodeError:
        raise AuthorityError() from None
    if size > max_bytes or (nonblank and not text.strip()):
        raise AuthorityError()
    return text


def _source_id(kind: ReadKind, value: object) -> str:
    text = _text(value)
    try:
        return ReadKey(kind=kind, source_id=text).source_id
    except ValueError:
        raise AuthorityError() from None


def _object(value: object) -> JsonObject:
    try:
        selected = checked_json(value)
    except ParsingError:
        raise AuthorityError() from None
    if type(selected) is not dict:
        raise AuthorityError()
    return selected


def _bytes_object(value: object) -> JsonObject:
    if type(value) is not bytes:
        raise AuthorityError()
    try:
        selected = parse_strict_json(value)
    except ParsingError:
        raise AuthorityError("invalid_json") from None
    if type(selected) is not dict:
        raise AuthorityError()
    return selected


def _canonical(value: object) -> bytes:
    try:
        return canonical_json(checked_json(value))
    except ParsingError:
        raise AuthorityError() from None


def _codes(value: object, allowed: tuple[str, ...]) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise AuthorityError()
    selected = cast(tuple[object, ...], value)
    if len(selected) > len(allowed) or any(type(item) is not str or item not in allowed for item in selected):
        raise AuthorityError()
    result = cast(tuple[str, ...], selected)
    if tuple(code for code in allowed if code in result) != result:
        raise AuthorityError()
    return result


def _copy_key(value: object) -> ReadKey:
    if type(value) is not ReadKey:
        raise AuthorityError()
    key = value
    return ReadKey(kind=_kind(key.kind), source_id=_source_id(key.kind, key.source_id))


@dataclass(frozen=True, slots=True)
class ReadSubject:
    kind: ReadKind
    source_id: str = field(repr=False)

    def __post_init__(self) -> None:
        _source_id(_kind(self.kind), self.source_id)


@dataclass(frozen=True, slots=True)
class SourceOptionalText:
    presence: Presence
    value: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if type(self.presence) is not str or self.presence not in ("absent", "null", "empty", "value"):
            raise AuthorityError()
        if self.presence in ("absent", "null"):
            if self.value is not None:
                raise AuthorityError()
        elif self.presence == "empty":
            if type(self.value) is not str or self.value != "":
                raise AuthorityError()
        elif not _text(self.value, max_bytes=1_048_576, nonblank=False):
            raise AuthorityError()


def _copy_optional(value: object) -> SourceOptionalText:
    if type(value) is not SourceOptionalText:
        raise AuthorityError()
    optional = value
    return SourceOptionalText(optional.presence, optional.value)


def _optional(source: JsonObject, name: str, *, token: bool = False) -> SourceOptionalText:
    if name not in source:
        return SourceOptionalText("absent")
    value = source[name]
    if value is None and not token:
        return SourceOptionalText("null")
    if type(value) is not str:
        raise AuthorityError("token_invalid" if token else "invalid_response")
    if token and len(value.encode("utf-8")) > 4096:
        raise AuthorityError("token_invalid")
    return SourceOptionalText("value" if value else "empty", value)


@dataclass(frozen=True, slots=True)
class RawExplainRelation:
    index: str = field(repr=False)
    managed: bool
    policy: SourceOptionalText = field(repr=False)

    def __post_init__(self) -> None:
        _source_id("elastic-explain", self.index)
        if type(self.managed) is not bool:
            raise AuthorityError()
        object.__setattr__(self, "policy", _copy_optional(self.policy))


@dataclass(frozen=True, slots=True)
class SourceOccurrence:
    ordinal: int
    source_identity: str = field(repr=False)
    protected_fields: bytes = field(repr=False)

    def __post_init__(self) -> None:
        _integer(self.ordinal)
        _text(self.source_identity)
        parsed = _bytes_object(self.protected_fields)
        if _canonical(parsed) != self.protected_fields:
            raise AuthorityError()


@dataclass(frozen=True, slots=True)
class RawEnvelopeAuthority:
    read_key: ReadKey = field(repr=False)
    page_sequence: int
    occurrences: tuple[SourceOccurrence, ...] = field(repr=False)
    continuation: SourceOptionalText = field(repr=False)
    explain_relation: RawExplainRelation | None = field(repr=False)
    diagnostics: tuple[ReadWarning, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "read_key", _copy_key(self.read_key))
        _integer(self.page_sequence, positive=True)
        if type(self.occurrences) is not tuple or len(self.occurrences) > MAX_NODES:
            raise AuthorityError()
        detached = []
        for item in self.occurrences:
            if type(item) is not SourceOccurrence:
                raise AuthorityError()
            detached.append(SourceOccurrence(item.ordinal, item.source_identity, item.protected_fields))
        object.__setattr__(self, "occurrences", tuple(detached))
        object.__setattr__(self, "continuation", _copy_optional(self.continuation))
        if self.explain_relation is not None:
            if type(self.explain_relation) is not RawExplainRelation:
                raise AuthorityError()
            relation = self.explain_relation
            object.__setattr__(
                self, "explain_relation", RawExplainRelation(relation.index, relation.managed, relation.policy)
            )
        _codes(self.diagnostics, ("upstream_warning", "unsupported_source_value"))


@dataclass(frozen=True, slots=True, init=False)
class ParsedResponse:
    _data: bytes = field(repr=False)
    status: int

    def __init__(self, data: JsonObject, status: int) -> None:
        if type(status) is not int or status != 200:
            raise AuthorityError()
        object.__setattr__(self, "_data", _canonical(_object(data)))
        object.__setattr__(self, "status", status)

    @property
    def data(self) -> JsonObject:
        return _bytes_object(self._data)


@dataclass(frozen=True, slots=True, init=False)
class ProjectedRecord:
    source_ordinal: int
    source_identity: str = field(repr=False)
    native_scope: NativeScope
    _fields: bytes = field(repr=False)
    _field_coverage: bytes = field(repr=False)
    diagnostics: tuple[InterpretationCode, ...]

    def __init__(
        self,
        source_ordinal: int,
        source_identity: str,
        native_scope: NativeScope,
        fields: JsonObject,
        field_coverage: dict[str, CoverageState],
        diagnostics: tuple[InterpretationCode, ...] = (),
    ) -> None:
        _integer(source_ordinal)
        _text(source_identity)
        if type(native_scope) is not str or native_scope not in ("matter", "hold", "index", "policy", "service"):
            raise AuthorityError()
        selected_coverage = _object(field_coverage)
        if any(
            type(v) is not str or v not in ("absent", "null", "known", "unknown") for v in selected_coverage.values()
        ):
            raise AuthorityError()
        _codes(diagnostics, ("unsupported_source_value", "missing_source_detail"))
        object.__setattr__(self, "source_ordinal", source_ordinal)
        object.__setattr__(self, "source_identity", source_identity)
        object.__setattr__(self, "native_scope", native_scope)
        object.__setattr__(self, "_fields", _canonical(_object(fields)))
        object.__setattr__(self, "_field_coverage", _canonical(selected_coverage))
        object.__setattr__(self, "diagnostics", diagnostics)

    @property
    def fields(self) -> JsonObject:
        return _bytes_object(self._fields)

    @property
    def field_coverage(self) -> dict[str, CoverageState]:
        return cast(dict[str, CoverageState], _bytes_object(self._field_coverage))


def _copy_record(value: object) -> ProjectedRecord:
    if type(value) is not ProjectedRecord:
        raise AuthorityError()
    item = value
    return ProjectedRecord(
        item.source_ordinal, item.source_identity, item.native_scope, item.fields, item.field_coverage, item.diagnostics
    )


@dataclass(frozen=True, slots=True)
class ProjectedPage:
    records: tuple[ProjectedRecord, ...] = field(repr=False)
    diagnostics: tuple[ReadWarning, ...] = ()

    def __post_init__(self) -> None:
        if type(self.records) is not tuple or len(self.records) > MAX_NODES:
            raise AuthorityError()
        object.__setattr__(self, "records", tuple(_copy_record(item) for item in self.records))
        _codes(self.diagnostics, ("upstream_warning", "unsupported_source_value"))


Projector = Callable[[ParsedResponse, ReadSubject], ProjectedPage]


def received_record_count(kind: object, data: object) -> int:
    """Count physical source occurrences before envelope/member identity refusal."""
    selected_kind = _kind(kind)
    try:
        raw = checked_json(data)
    except ParsingError:
        raise AuthorityError("invalid_json") from None
    if type(raw) is not dict:
        return 0
    if selected_kind in ("vault-matter", "elastic-status"):
        return 1
    if selected_kind in ("vault-holds", "splunk-index"):
        members = raw.get("holds" if selected_kind == "vault-holds" else "entry")
        return len(members) if type(members) is list else 0
    envelope = raw.get("indices") if selected_kind == "elastic-explain" else raw
    if type(envelope) is not dict or len(envelope) != 1:
        return 0
    return int(type(next(iter(envelope.values()))) is dict)


def _exact_identity(value: object, expected: str) -> str:
    if type(value) is not str or value != expected:
        raise AuthorityError("identity_mismatch")
    return expected


def _messages(raw: JsonObject) -> tuple[ReadWarning, ...]:
    if "messages" not in raw:
        return ()
    messages = raw["messages"]
    if type(messages) is not list:
        raise AuthorityError()
    kinds: set[str] = set()
    for item in messages:
        if type(item) is not dict or type(item.get("type")) is not str:
            raise AuthorityError()
        kinds.add(cast(str, item["type"]))
    if "ERROR" in kinds:
        raise AuthorityError("upstream_error")
    warnings: list[ReadWarning] = []
    if "WARN" in kinds:
        warnings.append("upstream_warning")
    if kinds - {"ERROR", "WARN", "INFO", "DEBUG"}:
        warnings.append("unsupported_source_value")
    return tuple(warnings)


def _inspect(
    key: ReadKey, raw: JsonObject
) -> tuple[list[JsonObject], list[str], SourceOptionalText, RawExplainRelation | None, tuple[ReadWarning, ...]]:
    continuation = SourceOptionalText("absent")
    relation = None
    warnings: tuple[ReadWarning, ...] = ()
    if key.kind == "vault-matter":
        identity = _exact_identity(raw.get("matterId"), key.source_id)
        return [raw], [identity], continuation, relation, warnings
    if key.kind == "vault-holds":
        continuation = _optional(raw, "nextPageToken", token=True)
        members = raw.get("holds", [])
        if type(members) is not list:
            raise AuthorityError()
        sources: list[JsonObject] = []
        identities: list[str] = []
        for member in members:
            if type(member) is not dict:
                raise AuthorityError()
            identity = _text(member.get("holdId"))
            sources.append(member)
            identities.append(identity)
        return sources, identities, continuation, relation, warnings
    if key.kind == "splunk-index":
        warnings = _messages(raw)
        entries = raw.get("entry")
        if type(entries) is not list or len(entries) != 1 or type(entries[0]) is not dict:
            raise AuthorityError()
        source = entries[0]
        identity = _exact_identity(source.get("name"), key.source_id)
        if type(source.get("content")) is not dict:
            raise AuthorityError()
        return [source], [identity], continuation, relation, warnings
    if key.kind == "elastic-explain":
        indices = raw.get("indices")
        if type(indices) is not dict or len(indices) != 1 or key.source_id not in indices:
            raise AuthorityError("identity_mismatch")
        explained = indices[key.source_id]
        if type(explained) is not dict:
            raise AuthorityError()
        identity = _exact_identity(explained.get("index"), key.source_id)
        managed = explained.get("managed")
        if type(managed) is not bool:
            raise AuthorityError()
        relation = RawExplainRelation(identity, managed, _optional(explained, "policy"))
        return [explained], [identity], continuation, relation, warnings
    if key.kind == "elastic-policy":
        if len(raw) != 1 or key.source_id not in raw:
            raise AuthorityError("identity_mismatch")
        policy = raw[key.source_id]
        if type(policy) is not dict:
            raise AuthorityError()
        return [policy], [key.source_id], continuation, relation, warnings
    return [raw], ["service"], continuation, relation, warnings


def _protected(kind: ReadKind, source: JsonObject, identity: str) -> bytes:
    if kind == "vault-matter":
        selected: JsonObject = {"matterId": identity}
    elif kind == "vault-holds":
        selected = {"holdId": identity}
    elif kind == "splunk-index":
        selected = {"name": identity}
    elif kind == "elastic-explain":
        selected = {"index": identity, "managed": source["managed"]}
        if "policy" in source:
            selected["policy"] = source["policy"]
    elif kind == "elastic-policy":
        selected = {"envelope_key": identity}
    else:
        selected = {}
    return _canonical(selected)


def extract_authority(key: ReadKey, page_sequence: int, data: JsonObject) -> RawEnvelopeAuthority:
    """Derive authority before a callback sees any detached source view."""
    selected_key = _copy_key(key)
    _integer(page_sequence, positive=True)
    raw = _object(data)
    sources, identities, token, relation, warnings = _inspect(selected_key, raw)
    occurrences = tuple(
        SourceOccurrence(ordinal, identity, _protected(selected_key.kind, source, identity))
        for ordinal, (source, identity) in enumerate(zip(sources, identities, strict=True))
    )
    return RawEnvelopeAuthority(selected_key, page_sequence, occurrences, token, relation, warnings)


def validate_projected_page(
    authority: RawEnvelopeAuthority,
    immutable_source: bytes,
    projected: ProjectedPage,
) -> ProjectedPage:
    """Return an owned snapshot only after complete native source correspondence."""
    if type(authority) is not RawEnvelopeAuthority or type(projected) is not ProjectedPage:
        raise AuthorityError()
    selected = RawEnvelopeAuthority(
        authority.read_key,
        authority.page_sequence,
        authority.occurrences,
        authority.continuation,
        authority.explain_relation,
        authority.diagnostics,
    )
    raw = _bytes_object(immutable_source)
    expected = extract_authority(selected.read_key, selected.page_sequence, raw)
    if selected != expected:
        raise AuthorityError()
    page = ProjectedPage(projected.records, projected.diagnostics)
    if len(page.records) != len(selected.occurrences) or any(
        code not in selected.diagnostics for code in page.diagnostics
    ):
        raise AuthorityError()
    sources, _, _, _, _ = _inspect(selected.read_key, raw)
    for ordinal, (record, occurrence, source) in enumerate(
        zip(page.records, selected.occurrences, sources, strict=True)
    ):
        if record.source_ordinal != ordinal or record.source_identity != occurrence.source_identity:
            raise AuthorityError()
        if record.native_scope != SCOPES[selected.read_key.kind]:
            raise AuthorityError()
        try:
            validate_correspondence(selected.read_key.kind, source, record.fields, record.field_coverage)
            wanted = expected_fields(selected.read_key.kind, source)
        except CorrespondenceError:
            raise AuthorityError() from None
        if record.diagnostics != wanted.diagnostics:
            raise AuthorityError()
    return page


AdapterCode = Literal[
    "destination_refused",
    "dns_failed",
    "offline_refused",
    "redirect_refused",
    "credential_rejected",
    "credential_invalid",
    "internal_error",
]
TransportFactory = Callable[[ssl.SSLContext], httpx.BaseTransport]


class AdapterError(ValueError):
    """Carry a fixed diagnostic, never a destination or header value."""

    def __init__(self, code: AdapterCode) -> None:
        if type(code) is not str or code not in (
            "destination_refused",
            "dns_failed",
            "offline_refused",
            "redirect_refused",
            "credential_rejected",
            "credential_invalid",
            "internal_error",
        ):
            code = "internal_error"
        self.code = code
        super().__init__(code)


class RejectCookies(http.cookiejar.DefaultCookiePolicy):
    """Refuse response storage and outbound cookie selection."""

    def set_ok(self, cookie: http.cookiejar.Cookie, request: CookieRequest) -> bool:
        return False

    def return_ok(self, cookie: http.cookiejar.Cookie, request: CookieRequest) -> bool:
        return False


def _destination(profile: FrozenProfile, value: object) -> httpx.URL:
    if type(value) is not str or not value or any(char < "!" or char > "~" for char in value):
        raise AdapterError("destination_refused")
    if "\\" in value or "#" in value:
        raise AdapterError("destination_refused")
    try:
        parts = urlsplit(value)
        expected = urlsplit(profile.origin)
        if parts.scheme != "https" or parts.netloc != expected.netloc or not parts.path.startswith("/"):
            raise AdapterError("destination_refused")
        parsed = httpx.URL(value)
        if (
            parsed.scheme != "https"
            or parsed.host != profile.host
            or (parsed.port or 443) != profile.port
            or parsed.userinfo
            or parsed.fragment
        ):
            raise AdapterError("destination_refused")
        return parsed
    except (ValueError, httpx.InvalidURL):
        raise AdapterError("destination_refused") from None


def _socket_int(value: object, enum: type[socket.AddressFamily] | type[socket.SocketKind]) -> bool:
    return type(value) is int or type(value) is enum


def _raw_answers(value: object, port: int) -> tuple[str, ...]:
    """Validate every native row before normalizing or deduplicating addresses."""
    if type(value) is not list or not value:
        raise AdapterError("dns_failed")
    result: list[str] = []
    for item in value:
        if type(item) is not tuple or len(item) != 5:
            raise AdapterError("dns_failed")
        family, kind, protocol, canonical_name, address = item
        if (
            not _socket_int(family, socket.AddressFamily)
            or family not in (socket.AF_INET, socket.AF_INET6)
            or not _socket_int(kind, socket.SocketKind)
            or kind != socket.SOCK_STREAM
            or type(protocol) is not int
            or protocol != socket.IPPROTO_TCP
            or type(canonical_name) is not str
            or type(address) is not tuple
            or len(address) != (2 if family == socket.AF_INET else 4)
        ):
            raise AdapterError("dns_failed")
        raw, returned_port = address[:2]
        if (
            type(raw) is not str
            or not 1 <= len(raw) <= 45
            or not raw.isascii()
            or "%" in raw
            or type(returned_port) is not int
            or returned_port != port
        ):
            raise AdapterError("dns_failed")
        if family == socket.AF_INET6 and (
            type(address[2]) is not int
            or not 0 <= address[2] <= 0xFFFFF
            or type(address[3]) is not int
            or address[3] != 0
        ):
            raise AdapterError("dns_failed")
        try:
            parsed = ipaddress.ip_address(raw)
        except ValueError:
            raise AdapterError("dns_failed") from None
        if parsed.version != (4 if family == socket.AF_INET else 6):
            raise AdapterError("dns_failed")
        result.append(raw)
    return tuple(result)


def _timeouts(value: object) -> dict[str, float]:
    if type(value) is not httpx.Timeout:
        raise AdapterError("internal_error")
    result: dict[str, float] = {}
    for name, bound in (("connect", 5), ("pool", 5), ("read", 20), ("write", 20)):
        item = getattr(value, name)
        if type(item) not in (float, int) or not 0 < item <= bound or not math.isfinite(item):
            raise AdapterError("internal_error")
        result[name] = float(item)
    return result


def _authorization(value: object, provider: str) -> str:
    prefix = "ApiKey " if provider == "elastic-ilm" else "Bearer "
    if type(value) is not str or not value.startswith(prefix):
        raise AdapterError("credential_invalid")
    material = value[len(prefix) :]
    if not 1 <= len(material) <= 16_384 or any(char < "!" or char > "~" for char in material):
        raise AdapterError("credential_invalid")
    return value


def owned_transport(context: ssl.SSLContext) -> httpx.BaseTransport:
    """Put the verified context on the actual owned synchronous transport."""
    return httpx.HTTPTransport(
        verify=context,
        trust_env=False,
        http1=True,
        http2=False,
        retries=0,
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
    )


class OwnedHttpAttempt:
    """Approve one destination, then permit one request in the same worker."""

    __slots__ = (
        "_client",
        "_factory",
        "_on_status",
        "_profile",
        "_response",
        "_stack",
        "_state",
        "_thread_id",
        "_transport",
        "_url",
        "cleanup_failed",
    )

    def __init__(
        self,
        profile: FrozenProfile,
        url: str,
        *,
        on_status: Callable[[int], None],
        transport_factory: TransportFactory | None = None,
    ) -> None:
        self._profile = validated_profile(profile)
        self._url = _destination(self._profile, url)
        self._on_status = on_status
        self._factory = transport_factory or owned_transport
        self._stack = ExitStack()
        self._transport: httpx.BaseTransport | None = None
        self._client: httpx.Client | None = None
        self._response: httpx.Response | None = None
        self._state: Literal["new", "entered", "sent", "closed"] = "new"
        self.cleanup_failed = False
        self._thread_id: int | None = None

    def __repr__(self) -> str:
        return "OwnedHttpAttempt(<redacted>)"

    def __enter__(self) -> OwnedHttpAttempt:
        if self._state != "new":
            raise AdapterError("internal_error")
        self._thread_id = threading.get_ident()
        try:
            self._stack.enter_context(quiet_transport_logs())
            try:
                network_guard.check_url(str(self._url), subsystem="enterprise_retention")
            except network_guard.OfflineViolationError:
                raise AdapterError("offline_refused") from None
            try:
                # The frozen pin wrapper matches str only. Bytes obtain a fresh
                # delegate answer even when an outer same-host pin is active.
                raw = socket.getaddrinfo(
                    self._profile.host.encode("ascii"),
                    self._profile.port,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM,
                    socket.IPPROTO_TCP,
                )
            except OSError:
                raise AdapterError("dns_failed") from None
            answers = _raw_answers(raw, self._profile.port)
            try:
                accepted = classify_answers(self._profile.address_policy, answers)
            except AddressPolicyError:
                raise AdapterError("destination_refused") from None
            self._stack.enter_context(network_guard.pin_resolved_host(self._profile.host, list(accepted)))
            if self._profile.address_policy.mode == "public":
                try:
                    guarded = network_guard.enforce_public_host(
                        str(self._url), block_private=True, subsystem="enterprise_retention"
                    )
                    if type(guarded) is not list:
                        raise AdapterError("destination_refused")
                    approved = classify_answers(self._profile.address_policy, tuple(guarded))
                    if set(approved) != set(accepted):
                        raise AdapterError("destination_refused")
                except (network_guard.SSRFBlockedError, AddressPolicyError):
                    raise AdapterError("destination_refused") from None
            self._transport = self._factory(ssl_context(self._profile))
            self._client = httpx.Client(
                transport=self._transport,
                trust_env=False,
                http1=True,
                http2=False,
                follow_redirects=False,
                auth=None,
                cookies=http.cookiejar.CookieJar(policy=RejectCookies()),
                event_hooks={"response": [self._status]},
            )
            self._state = "entered"
            return self
        except BaseException:
            self._cleanup(primary=True)
            raise

    def _close_response(self) -> BaseException | None:
        if self._response is not None:
            try:
                self._response.close()
            except BaseException as error:
                self.cleanup_failed = True
                return error
        return None

    def _status(self, response: httpx.Response) -> None:
        self._response = response
        try:
            status = response.status_code
            if type(status) is not int or not 100 <= status <= 599:
                raise AdapterError("internal_error")
            self._on_status(status)
            if 300 <= status <= 399:
                raise AdapterError("redirect_refused")
            if status == 401:
                raise AdapterError("credential_rejected")
        except BaseException:
            self._close_response()
            raise

    def send(
        self,
        *,
        authorization: str,
        timeout: httpx.Timeout,
        before_send: Callable[[], httpx.Timeout | None],
    ) -> httpx.Response:
        if self._state != "entered" or self._client is None or self._thread_id != threading.get_ident():
            raise AdapterError("internal_error")
        self._state = "sent"
        request = httpx.Request(
            "GET",
            self._url,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "gzip, identity",
                "Authorization": _authorization(authorization, self._profile.provider),
            },
            content=b"",
            extensions={"timeout": _timeouts(timeout)},
        )
        refreshed_timeout = before_send()
        if refreshed_timeout is not None:
            request.extensions["timeout"] = _timeouts(refreshed_timeout)
        response = self._client.send(request, stream=True, auth=None, follow_redirects=False)
        self._response = response
        return response

    def _cleanup(self, *, primary: bool = False) -> None:
        failures: list[BaseException] = []
        error = self._close_response()
        if error is not None:
            failures.append(error)
        if self._client is not None:
            try:
                self._client.close()
            except BaseException as error:
                failures.append(error)
                if self._transport is not None:
                    try:
                        self._transport.close()
                    except BaseException as fallback_error:
                        failures.append(fallback_error)
        elif self._transport is not None:
            try:
                self._transport.close()
            except BaseException as error:
                failures.append(error)
        try:
            self._stack.close()
        except BaseException as error:
            failures.append(error)
        self._state = "closed"
        self._response = None
        self._client = None
        self._transport = None
        self.cleanup_failed = self.cleanup_failed or bool(failures)
        if not primary:
            for failure in failures:
                if not isinstance(failure, Exception):
                    raise failure

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        if self._thread_id != threading.get_ident():
            raise AdapterError("internal_error")
        self._cleanup(primary=exc_type is not None)
        return False


class _ObservedEnterpriseClose(httpx.SyncByteStream):
    """Keep EOF cleanup failure separate from successfully delivered source bytes."""

    def __init__(self, stream: httpx.SyncByteStream, failed: Callable[[], None]) -> None:
        self._stream = stream
        self._failed = failed
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        yield from self._stream

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._stream.close()
        except Exception:
            self._failed()
        except BaseException:
            self._failed()
            raise


class EnterpriseRetentionOperationalError(ValueError):
    """Refuse an invalid runtime state without returning fabricated evidence."""

    def __init__(self) -> None:
        super().__init__("enterprise_retention_internal_error")


class _SessionFault(ValueError):
    def __init__(self, code: DiagnosticCode, *, run: bool = False) -> None:
        self.code = code
        self.run = run
        super().__init__(code)


class _DiagnosticBag:
    def __init__(self) -> None:
        self._values: dict[DiagnosticCode, tuple[str | None, HttpStatusAccumulator]] = {}

    def add(self, code: DiagnosticCode, read_id: str | None, status: int | None) -> None:
        if code not in self._values:
            self._values[code] = (read_id, HttpStatusAccumulator())
        previous, statuses = self._values[code]
        statuses.add(status)
        self._values[code] = (previous if previous == read_id else None, statuses)

    def items(self) -> list[EnterpriseRetentionDiagnostic]:
        return [
            EnterpriseRetentionDiagnostic(
                code=code, read_id=self._values[code][0], safe_http_status=self._values[code][1].value
            )
            for code in DIAGNOSTIC_ORDER
            if code in self._values
        ]

    def clone(self) -> _DiagnosticBag:
        return copy.deepcopy(self)


def _now_utc() -> datetime:
    return datetime.now(UTC)


class EnterpriseRunContext:
    """Keep the selected request, bounded physical counters and checked clocks."""

    def __init__(
        self,
        request: object,
        *,
        utc_clock: Callable[[], datetime] = _now_utc,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        run_id_factory: Callable[[], str] = new_run_id,
    ) -> None:
        selected = validated_request(request)
        self._request_bytes = selected.model_dump_json(warnings="error").encode("utf-8")
        self.capacity = CapacityPlan(selected)
        if not all(callable(value) for value in (utc_clock, monotonic_clock, sleep, run_id_factory)):
            raise EnterpriseRetentionOperationalError()
        self._utc_clock = utc_clock
        self._monotonic_clock = monotonic_clock
        self._sleep = sleep
        self._last_tick: float | None = None
        self._last_utc: datetime | None = None
        self.started_at = self.utc_now()
        self._start_tick = self.tick()
        try:
            run_id = run_id_factory()
            if type(run_id) is not str or re.fullmatch(r"[0-7][0-9A-HJKMNP-TV-Z]{25}", run_id) is None:
                raise ValueError
        except Exception:
            raise EnterpriseRetentionOperationalError() from None
        self.run_id = run_id
        self.raw_bytes = 0
        self.decoded_bytes = 0
        self.attempts = 0
        self.holds_pages = 0
        self.holds_records = 0
        self.diagnostics = _DiagnosticBag()
        self.stop_reason: DiagnosticCode | None = None

    @property
    def request(self) -> EnterpriseRetentionCollectRequest:
        return parse_request(self._request_bytes)

    def utc_now(self) -> datetime:
        try:
            value = self._utc_clock()
            if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
                raise ValueError
            result = value.astimezone(UTC)
            if self._last_utc is not None and result < self._last_utc:
                raise ValueError
            self._last_utc = result
            return result
        except Exception:
            raise EnterpriseRetentionOperationalError() from None

    def tick(self) -> float:
        try:
            value = self._monotonic_clock()
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError
            result = float(value)
            if self._last_tick is not None and result < self._last_tick:
                raise ValueError
            self._last_tick = result
            return result
        except Exception:
            raise EnterpriseRetentionOperationalError() from None

    def remaining(self) -> float:
        value = 120.0 - (self.tick() - self._start_tick)
        if value <= 0:
            raise _SessionFault("deadline_exceeded", run=True)
        return value

    def wait(self, delay: float) -> None:
        if type(delay) not in (int, float) or not math.isfinite(delay) or delay < 0 or delay > 10:
            raise EnterpriseRetentionOperationalError()
        if delay > self.remaining():
            raise _SessionFault("deadline_exceeded", run=True)
        try:
            self._sleep(delay)
        except Exception:
            raise EnterpriseRetentionOperationalError() from None
        self.remaining()


def _counter_add(value: int, increment: int) -> int:
    if type(value) is not int or type(increment) is not int or min(value, increment) < 0:
        raise EnterpriseRetentionOperationalError()
    result = value + increment
    if result > (1 << 128) - 1:
        raise EnterpriseRetentionOperationalError()
    return result


@dataclass(slots=True)
class _ReadState:
    key: ReadKey
    data: dict[str, Any]
    diagnostics: _DiagnosticBag = field(default_factory=_DiagnosticBag)
    statuses: HttpStatusAccumulator = field(default_factory=HttpStatusAccumulator)
    tokens: set[str] = field(default_factory=set, repr=False)
    quarantined: set[str] = field(default_factory=set, repr=False)
    relation: RawExplainRelation | None = field(default=None, repr=False)
    current_status: int | None = None
    terminal: DiagnosticCode | None = None
    complete: bool = False
    done: bool = False

    def snapshot(self) -> EnterpriseRetentionReadResult:
        values = dict(self.data)
        values["safe_http_status"] = self.statuses.value
        values["diagnostics"] = self.diagnostics.items()
        values["terminal_reason"] = self.terminal
        values["records_admitted"] = len(values["observations"])
        values["conflicts_quarantined"] = len(self.quarantined)
        values["status"] = (
            "complete"
            if self.complete and self.terminal is None and not self.quarantined
            else "partial"
            if values["pages_admitted"]
            else "unavailable"
        )
        return EnterpriseRetentionReadResult.model_validate(values)

    def candidate(self) -> _ReadState:
        return dataclass_replace(
            self,
            data=dict(self.data),
            diagnostics=self.diagnostics.clone(),
            tokens=set(self.tokens),
            quarantined=set(self.quarantined),
        )


class ReadHandle:
    """Identify one issued read without granting authority to another source."""

    __slots__ = ("_owner", "_read_id")
    _owner: object
    _read_id: str

    def __init__(self, owner: object, read_id: str) -> None:
        object.__setattr__(self, "_owner", owner)
        object.__setattr__(self, "_read_id", read_id)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("immutable_read_handle")

    @property
    def read_id(self) -> str:
        return self._read_id

    def __repr__(self) -> str:
        return "ReadHandle(<redacted>)"

    def __reduce__(self) -> Never:
        raise TypeError("runtime_only_read_handle")


_RETRY_STATUSES = frozenset({408, 429, 500, 502, 503, 504})
_RETRY_EXCEPTIONS = (httpx.ConnectTimeout, httpx.ReadTimeout, httpx.ConnectError, httpx.ReadError)
_RUN_CODES = frozenset(
    {
        "credential_missing",
        "credential_invalid",
        "credential_expired",
        "credential_resolution_failed",
        "credential_rejected",
        "deadline_exceeded",
        "attempt_limit",
        "run_byte_limit",
        "page_limit",
        "record_limit",
        "result_limit",
        "cleanup_failed",
        "internal_error",
        "dependency_unavailable",
    }
)
_NO_STATUS_CODES = frozenset(
    {
        "credential_missing",
        "credential_invalid",
        "credential_expired",
        "credential_resolution_failed",
        "offline_refused",
        "destination_refused",
        "dns_failed",
        "attempt_limit",
        "internal_error",
        "dependency_unavailable",
    }
)


class EnterpriseReadSession:
    """Execute a finite configuration plan and commit only fully checked pages."""

    def __init__(
        self,
        request: object,
        *,
        profile: AuthorizedProfile,
        transport_factory: TransportFactory | None = None,
        utc_clock: Callable[[], datetime] = _now_utc,
        monotonic_clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        run_id_factory: Callable[[], str] = new_run_id,
    ) -> None:
        selected = validated_request(request)
        if type(profile) is not AuthorizedProfile:
            raise EnterpriseRetentionOperationalError()
        try:
            capability = AuthorizedProfile(profile.profile, profile.resolver)
        except Exception:
            raise EnterpriseRetentionOperationalError() from None
        if (
            capability.profile.provider != selected.root.provider
            or capability.profile.alias != selected.root.profile_alias
            or (transport_factory is not None and not callable(transport_factory))
        ):
            raise EnterpriseRetentionOperationalError()
        self.context = EnterpriseRunContext(
            selected, utc_clock=utc_clock, monotonic_clock=monotonic_clock, sleep=sleep, run_id_factory=run_id_factory
        )
        self._profile = capability.profile
        self._resolver = capability.resolver
        self._factory = transport_factory
        self._owner = object()
        self._states: dict[tuple[ReadKind, str], _ReadState] = {}
        self._handles: dict[tuple[ReadKind, str], ReadHandle] = {}
        self._resolved = False
        self._credential: CredentialMaterial | None = None
        self._rejected = False
        self._active = False
        self._closed = False
        self._broken = False
        self._thread_id = threading.get_ident()
        self._selected_next = 0
        self._finished: EnterpriseRetentionCollectResult | None = None
        for key in initial_read_keys(selected):
            self._install(self._empty_state(key))

    def __repr__(self) -> str:
        return "EnterpriseReadSession(<redacted>)"

    def _empty_state(self, key: ReadKey) -> _ReadState:
        return _ReadState(key, empty_read(key, profile_alias=self._profile.alias).model_dump(mode="python"))

    def _install(self, state: _ReadState) -> None:
        key = (state.key.kind, state.key.source_id)
        self._states[key] = state
        if key not in self._handles:
            self._handles[key] = ReadHandle(self._owner, state.data["read_id"])

    def _guard(self) -> None:
        if (
            self._active
            or self._closed
            or self._broken
            or self._finished is not None
            or threading.get_ident() != self._thread_id
        ):
            raise EnterpriseRetentionOperationalError()

    def __enter__(self) -> EnterpriseReadSession:
        self._guard()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc_value: BaseException | None, traceback: TracebackType | None
    ) -> Literal[False]:
        self._closed = True
        self._credential = None
        return False

    def _target(self, target: EnterpriseTarget, kind: ReadKind) -> tuple[ReadKind, str]:
        self._guard()
        target_types: dict[ReadKind, type[VaultMatterTarget] | type[SplunkIndexTarget] | type[ElasticIndexTarget]] = {
            "vault-matter": VaultMatterTarget,
            "vault-holds": VaultMatterTarget,
            "splunk-index": SplunkIndexTarget,
            "elastic-explain": ElasticIndexTarget,
        }
        expected_type = target_types.get(kind)
        if expected_type is None or type(target) is not expected_type:
            raise EnterpriseRetentionOperationalError()
        try:
            checked = expected_type.model_validate(target)
            identity = target_identity(checked)
        except Exception:
            raise EnterpriseRetentionOperationalError() from None
        key = (kind, identity)
        if key not in self._states:
            raise EnterpriseRetentionOperationalError()
        return key

    def _issued(self, value: ReadHandle) -> tuple[ReadKind, str]:
        if type(value) is not ReadHandle or value._owner is not self._owner:
            raise EnterpriseRetentionOperationalError()
        for key, handle in self._handles.items():
            if value is handle and value.read_id == self._states[key].data["read_id"]:
                return key
        raise EnterpriseRetentionOperationalError()

    def _selected(self, target: EnterpriseTarget, kind: ReadKind, projector: Projector) -> ReadHandle:
        key = self._target(target, kind)
        state = self._states[key]
        if not state.done:
            targets = self.context.request.root.targets
            if self._selected_next >= len(targets) or target_identity(targets[self._selected_next]) != key[1]:
                raise EnterpriseRetentionOperationalError()
            if kind == "elastic-explain" and not self._states[("elastic-status", "service")].done:
                raise EnterpriseRetentionOperationalError()
            self._run_read(key, projector)
            self._selected_next += 1
        return self._handles[key]

    def read_vault_matter(self, target: VaultMatterTarget, projector: Projector) -> ReadHandle:
        return self._selected(target, "vault-matter", projector)

    def read_splunk_index(self, target: SplunkIndexTarget, projector: Projector) -> ReadHandle:
        return self._selected(target, "splunk-index", projector)

    def read_elastic_explain(self, target: ElasticIndexTarget, projector: Projector) -> ReadHandle:
        return self._selected(target, "elastic-explain", projector)

    def read_vault_holds(self, target: VaultMatterTarget, projector: Projector) -> ReadHandle:
        key = self._target(target, "vault-holds")
        matter = self._states[("vault-matter", key[1])]
        if not matter.done:
            raise EnterpriseRetentionOperationalError()
        if not matter.data["pages_admitted"]:
            self._states[key].done = True
        elif not self._states[key].done:
            self._run_read(key, projector)
        return self._handles[key]

    def read_elastic_status(self, projector: Projector) -> ReadHandle:
        self._guard()
        key: tuple[ReadKind, str] = ("elastic-status", "service")
        if key not in self._states:
            raise EnterpriseRetentionOperationalError()
        if not self._states[key].done:
            self._run_read(key, projector)
        return self._handles[key]

    def read_elastic_policy(
        self, target: ElasticIndexTarget, explain: ReadHandle, projector: Projector
    ) -> ReadHandle | None:
        key = self._target(target, "elastic-explain")
        if self._issued(explain) != key:
            raise EnterpriseRetentionOperationalError()
        state = self._states[key]
        if not state.done:
            raise EnterpriseRetentionOperationalError()
        relation = state.relation
        if relation is None or relation.managed is False or not supported_policy(relation.policy.value):
            return None
        policy = relation.policy.value
        if type(policy) is not str:
            raise EnterpriseRetentionOperationalError()
        policy_key: tuple[ReadKind, str] = ("elastic-policy", policy)
        if policy_key not in self._states:
            raise EnterpriseRetentionOperationalError()
        if not self._states[policy_key].done:
            self._run_read(policy_key, projector)
        return self._handles[policy_key]

    def _fault(self, state: _ReadState, fault: _SessionFault, *, terminal: bool = True) -> None:
        code = fault.code
        run = fault.run or code in _RUN_CODES
        scope: DiagnosticScope = "run" if run else "read"
        try:
            diagnostic_rule(code, scope, self._profile.provider, None if run else state.key.kind)
        except ValueError:
            raise EnterpriseRetentionOperationalError() from None
        status = None if code in _NO_STATUS_CODES else state.current_status
        bag = self.context.diagnostics if run else state.diagnostics
        bag.add(code, state.data["read_id"], status)
        if terminal and state.terminal is None:
            state.terminal = code
        if run and self.context.stop_reason is None:
            self.context.stop_reason = code

    def _resolve_material(self) -> CredentialMaterial:
        if self._rejected:
            raise _SessionFault("credential_rejected", run=True)
        if not self._resolved:
            self._resolved = True
            try:
                material = self._resolver.resolve(validated_profile(self._profile))
            except CredentialError as error:
                raise _SessionFault(error.code, run=True) from None
            except Exception:
                raise _SessionFault("credential_resolution_failed", run=True) from None
            try:
                self._credential = validated_material(
                    material, provider=self._profile.provider, now=self.context.utc_now()
                )
            except CredentialError as error:
                raise _SessionFault(error.code, run=True) from None
        if self._credential is None:
            raise EnterpriseRetentionOperationalError()
        try:
            return validated_material(self._credential, provider=self._profile.provider, now=self.context.utc_now())
        except CredentialError as error:
            raise _SessionFault(error.code, run=True) from None

    def _before_send(self) -> httpx.Timeout:
        material = self._resolve_material()
        before = self.context.tick()
        current = self.context.utc_now()
        after = self.context.tick()
        remaining = 120.0 - (after - self.context._start_tick)
        if remaining <= 0:
            raise _SessionFault("deadline_exceeded", run=True)
        # Account conservatively for time spent obtaining the final UTC sample.
        # No injected callback runs after the final expiry and timeout decision.
        try:
            latest = current + timedelta(seconds=after - before)
            validated_material(material, provider=self._profile.provider, now=latest)
        except CredentialError as error:
            raise _SessionFault(error.code, run=True) from None
        except (ValueError, OverflowError):
            raise EnterpriseRetentionOperationalError() from None
        return httpx.Timeout(
            connect=min(5.0, remaining),
            pool=min(5.0, remaining),
            read=min(20.0, remaining),
            write=min(20.0, remaining),
        )

    def _consume(self, state: _ReadState, raw: int, decoded: int) -> None:
        state.data["raw_bytes"] = _counter_add(state.data["raw_bytes"], raw)
        state.data["decoded_bytes"] = _counter_add(state.data["decoded_bytes"], decoded)
        self.context.raw_bytes = _counter_add(self.context.raw_bytes, raw)
        self.context.decoded_bytes = _counter_add(self.context.decoded_bytes, decoded)
        if self.context.raw_bytes > 16_777_216 or self.context.decoded_bytes > 16_777_216:
            raise _SessionFault("run_byte_limit", run=True)
        self.context.remaining()

    def _status(self, state: _ReadState, status: int) -> None:
        state.current_status = status
        state.statuses.add(status)
        state.data["responses_received"] = _counter_add(state.data["responses_received"], 1)
        if status == 401:
            self._rejected = True
            self._fault(state, _SessionFault("credential_rejected", run=True))

    def _fetch(self, state: _ReadState, token: str | None) -> bytes:
        for ordinal in (1, 2, 3):
            self.context.remaining()
            if self.context.attempts >= 100:
                raise _SessionFault("attempt_limit", run=True)
            state.current_status = None
            state.data["attempts"] = _counter_add(state.data["attempts"], 1)
            self.context.attempts += 1
            now = self.context.utc_now()
            if state.data["started_at"] is None:
                state.data["started_at"] = now
            state.data["finished_at"] = now
            adapter: OwnedHttpAttempt | None = None
            response: httpx.Response | None = None
            delay: float | None = None
            retry_failure: DiagnosticCode | None = None
            cancelled = False
            try:
                url = build_read_url(validated_profile(self._profile), state.key, continuation=token)
                adapter = OwnedHttpAttempt(
                    self._profile,
                    url,
                    on_status=lambda value: self._status(state, value),
                    transport_factory=self._factory,
                )
                with adapter:
                    self.context.remaining()
                    material = self._resolve_material()
                    scheme = "ApiKey" if self._profile.provider == "elastic-ilm" else "Bearer"
                    response = adapter.send(
                        authorization=scheme + " " + material.value,
                        timeout=httpx.Timeout(5.0),
                        before_send=self._before_send,
                    )
                    if not isinstance(response.stream, httpx.SyncByteStream):
                        raise EnterpriseRetentionOperationalError()
                    response.stream = _ObservedEnterpriseClose(
                        response.stream, partial(setattr, adapter, "cleanup_failed", True)
                    )
                    status = response.status_code
                    if status not in _RETRY_STATUSES and status != 200:
                        code: DiagnosticCode = (
                            "http_denied" if status == 403 else "http_not_found" if status == 404 else "http_error"
                        )
                        raise _SessionFault(code)
                    content = read_enterprise_body(
                        response, consume=lambda raw, decoded: self._consume(state, raw, decoded)
                    )
                    if status == 200:
                        return content
                    retry_failure = "http_error"
                    if ordinal == 3:
                        raise _SessionFault("http_error")
                    delay = enterprise_retry_delay(
                        response, attempt=ordinal, now=self.context.utc_now(), remaining=self.context.remaining()
                    )
            except (EndpointError, AdapterError, BodyRetryError) as error:
                if error.code == "internal_error":
                    raise EnterpriseRetentionOperationalError() from None
                raise _SessionFault(cast(DiagnosticCode, error.code)) from None
            except httpx.TransportError as error:
                if type(error) not in _RETRY_EXCEPTIONS or ordinal == 3:
                    raise _SessionFault(
                        "timeout" if isinstance(error, httpx.TimeoutException) else "transport_failed"
                    ) from None
                retry_failure = "timeout" if isinstance(error, httpx.TimeoutException) else "transport_failed"
                delay = float(ordinal)
            except BaseException as error:
                cancelled = not isinstance(error, Exception)
                raise
            finally:
                try:
                    state.data["finished_at"] = self.context.utc_now()
                    if adapter is not None and adapter.cleanup_failed:
                        self._fault(state, _SessionFault("cleanup_failed", run=True), terminal=False)
                except BaseException:
                    if not cancelled:
                        raise
            if self.context.stop_reason is not None:
                if retry_failure is not None:
                    raise _SessionFault(retry_failure)
                raise _SessionFault(self.context.stop_reason, run=True)
            if delay is None:
                raise EnterpriseRetentionOperationalError()
            self.context.wait(delay)
        raise EnterpriseRetentionOperationalError()

    def _models(
        self, replacement: _ReadState | None = None, extra: _ReadState | None = None
    ) -> list[EnterpriseRetentionReadResult]:
        return [
            (replacement if replacement is not None and state.key == replacement.key else state).snapshot()
            for state in self._states.values()
        ] + ([] if extra is None else [extra.snapshot()])

    def _result(
        self, reads: list[EnterpriseRetentionReadResult], *, finished_at: datetime | None = None
    ) -> EnterpriseRetentionCollectResult:
        return make_result(
            self.context.request,
            reads=reads,
            run_id=self.context.run_id,
            started_at=self.context.started_at,
            finished_at=self.context.utc_now() if finished_at is None else finished_at,
            diagnostics=self.context.diagnostics.items(),
            collector_version=COLLECTOR_VERSION,
            evidentia_version=EVIDENTIA_VERSION,
        )

    def _admit(
        self, state: _ReadState, authority: RawEnvelopeAuthority, body: bytes, projected: ProjectedPage
    ) -> str | None:
        checked = validate_projected_page(authority, body, projected)
        self.context.remaining()
        token = authority.continuation.value if authority.continuation.presence == "value" else None
        if token is not None and token in state.tokens:
            raise _SessionFault("token_repeated")
        if token is not None and self.context.holds_pages >= 20:
            raise _SessionFault("page_limit", run=True)
        candidate = state.candidate()
        observed = {
            item.source_identity: item
            for item in cast(list[EnterpriseRetentionObservation], state.data["observations"])
        }
        for record in checked.records:
            try:
                observation = make_observation(
                    state.key,
                    profile_alias=self._profile.alias,
                    source_identity=record.source_identity,
                    fields=record.fields,
                    coverage=record.field_coverage,
                )
            except ParsingError:
                raise _SessionFault("projection_limit") from None
            except ValidationError as error:
                errors = error.errors(include_input=False, include_url=False)
                if all(item.get("ctx", {}).get("error", ValueError()).args == ("projection_limit",) for item in errors):
                    raise _SessionFault("projection_limit") from None
                raise EnterpriseRetentionOperationalError() from None
            identity = observation.source_identity
            if identity in candidate.quarantined:
                continue
            previous = observed.get(identity)
            if previous is None:
                observed[identity] = observation
            elif previous.canonical_projection_sha256 == observation.canonical_projection_sha256:
                candidate.data["duplicates_coalesced"] = _counter_add(candidate.data["duplicates_coalesced"], 1)
            else:
                candidate.quarantined.add(identity)
                del observed[identity]
        for code in authority.diagnostics:
            candidate.diagnostics.add(code, candidate.data["read_id"], 200)
        if candidate.quarantined:
            candidate.diagnostics.add("duplicate_conflict", candidate.data["read_id"], 200)
        candidate.data["observations"] = list(observed.values())
        candidate.data["pages_admitted"] = _counter_add(candidate.data["pages_admitted"], 1)
        candidate.complete = token is None
        if token is not None:
            candidate.tokens.add(token)
        candidate.relation = authority.explain_relation
        extra: _ReadState | None = None
        if candidate.relation is not None and candidate.relation.managed is True:
            policy = candidate.relation.policy.value
            if supported_policy(policy):
                policy_key = ReadKey(kind="elastic-policy", source_id=cast(str, policy))
                if (policy_key.kind, policy_key.source_id) not in self._states:
                    extra = self._empty_state(policy_key)
        models = self._models(candidate, extra)
        try:
            self.context.capacity.admission_bound(models)
            result = self._result(models)
            self.context.capacity.validate_result(result)
        except CapacityExceeded as error:
            raise _SessionFault(cast(DiagnosticCode, error.code), run=True) from None
        self.context.remaining()
        self._install(candidate)
        if extra is not None:
            self._install(extra)
        return token

    def _run_read(self, key: tuple[ReadKind, str], projector: Projector) -> None:
        if not callable(projector):
            raise EnterpriseRetentionOperationalError()
        state = self._states[key]
        if self.context.stop_reason is not None:
            state.done = True
            return
        self._active = True
        token: str | None = None
        try:
            while True:
                state = self._states[key]
                if state.key.kind == "vault-holds" and self.context.holds_pages >= 20:
                    raise _SessionFault("page_limit", run=True)
                body = self._fetch(state, token)
                raw = parse_strict_json(body)
                state.data["pages_received"] = _counter_add(state.data["pages_received"], 1)
                records = received_record_count(state.key.kind, raw)
                state.data["records_received"] = _counter_add(state.data["records_received"], records)
                if state.key.kind == "vault-holds":
                    self.context.holds_pages += 1
                    self.context.holds_records = _counter_add(self.context.holds_records, records)
                    if self.context.holds_records > 2000:
                        raise _SessionFault("record_limit", run=True)
                if type(raw) is not dict:
                    raise _SessionFault("invalid_response")
                authority = extract_authority(state.key, state.data["pages_received"], raw)
                projected = projector(ParsedResponse(raw, 200), ReadSubject(state.key.kind, state.key.source_id))
                token = self._admit(state, authority, body, projected)
                state = self._states[key]
                if token is None:
                    break
                if self.context.stop_reason is not None:
                    raise _SessionFault(self.context.stop_reason, run=True)
        except _SessionFault as fault:
            self._fault(state, fault)
        except (AuthorityError, ParsingError, CorrespondenceError) as error:
            code = (
                error.code
                if isinstance(error, AuthorityError)
                else "invalid_json"
                if isinstance(error, ParsingError)
                else "invalid_response"
            )
            self._fault(state, _SessionFault(cast(DiagnosticCode, code)))
        except Exception:
            self._broken = True
            raise EnterpriseRetentionOperationalError() from None
        except BaseException:
            self._broken = True
            raise
        finally:
            self._active = False
            self._states[key].done = True

    def finish_resource(
        self, target: EnterpriseTarget, *, reads: tuple[ReadHandle, ...]
    ) -> EnterpriseRetentionResourceResult[Any]:
        self._guard()
        if type(reads) is not tuple:
            raise EnterpriseRetentionOperationalError()
        try:
            identity = target_identity(target)
            result = self._result(self._models())
            resource = next(value for value in result.root.resources if target_identity(value.target) == identity)
            if type(resource.target) is not type(target) or resource.target.model_dump(
                mode="python"
            ) != target.model_dump(mode="python"):
                raise ValueError
            for handle in reads:
                self._issued(handle)
            if [handle.read_id for handle in reads] != resource.read_ids:
                raise ValueError
            return resource.model_copy(deep=True)
        except Exception:
            raise EnterpriseRetentionOperationalError() from None

    def finish(self, resources: tuple[EnterpriseRetentionResourceResult[Any], ...]) -> EnterpriseRetentionCollectResult:
        self._guard()
        if type(resources) is not tuple:
            raise EnterpriseRetentionOperationalError()
        try:
            try:
                self.context.remaining()
            except _SessionFault as fault:
                self.context.diagnostics.add(fault.code, None, None)
                if self.context.stop_reason is None:
                    self.context.stop_reason = fault.code
            result = self._result(self._models())
            if len(resources) != len(result.root.resources):
                raise ValueError
            for actual, expected in zip(resources, result.root.resources, strict=True):
                if type(actual) is not type(expected) or actual.model_dump_json(
                    warnings="error"
                ) != expected.model_dump_json(warnings="error"):
                    raise ValueError
            self.context.capacity.validate_result(result)
            published = EnterpriseRetentionCollectResult.model_validate_json(result.publication_bytes())
            try:
                self.context.remaining()
            except _SessionFault as fault:
                self.context.diagnostics.add(fault.code, None, None)
                if self.context.stop_reason is None:
                    self.context.stop_reason = fault.code
                result = self._result(self._models(), finished_at=published.root.finished_at)
                self.context.capacity.validate_result(result)
                published = EnterpriseRetentionCollectResult.model_validate_json(result.publication_bytes())
            self._finished = published
            self._credential = None
            return published
        except Exception:
            self._broken = True
            raise EnterpriseRetentionOperationalError() from None


EndpointCode = Literal["destination_refused", "token_invalid"]
_PROVIDERS: dict[ReadKind, ProviderName] = {
    "vault-matter": "google-vault",
    "vault-holds": "google-vault",
    "splunk-index": "splunk-enterprise",
    "elastic-explain": "elastic-ilm",
    "elastic-policy": "elastic-ilm",
    "elastic-status": "elastic-ilm",
}


class EndpointError(ValueError):
    """Expose a closed endpoint diagnostic without source values."""

    def __init__(self, code: EndpointCode = "destination_refused") -> None:
        if type(code) is not str or code not in ("destination_refused", "token_invalid"):
            code = "destination_refused"
        self.code = code
        super().__init__(code)


def _checked_key(value: ReadKey) -> ReadKey:
    """Detach the finite native payload before shared semantic validation."""
    if type(value) is not ReadKey:
        raise EndpointError()
    raw = value.__dict__
    if type(raw) is not dict or len(raw) != 2 or value.__pydantic_extra__ is not None:
        raise EndpointError()
    fields: dict[str, str] = {}
    for name, item in raw.items():
        if type(name) is not str or name not in ("kind", "source_id") or type(item) is not str:
            raise EndpointError()
        fields[name] = item
    return ReadKey.model_validate(fields)


def _token(value: str) -> str:
    """Bound opaque UTF-8 before allocating its encoded query representation."""
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise EndpointError("token_invalid")
    try:
        if len(value.encode("utf-8", errors="strict")) > 4096:
            raise EndpointError("token_invalid")
    except UnicodeError:
        raise EndpointError("token_invalid") from None
    return value


def _template(key: ReadKey, continuation: str | None) -> tuple[str, str]:
    segment = quote(key.source_id, safe="", encoding="ascii", errors="strict")
    parameters: list[tuple[str, str]] = []
    if continuation is not None and key.kind != "vault-holds":
        raise EndpointError()
    if key.kind == "vault-matter":
        path = f"/v1/matters/{segment}"
        parameters = [("view", "BASIC")]
    elif key.kind == "vault-holds":
        path = f"/v1/matters/{segment}/holds"
        parameters = [("view", "FULL_HOLD"), ("pageSize", "100")]
        if continuation is not None:
            parameters.append(("pageToken", _token(continuation)))
    elif key.kind == "splunk-index":
        path = f"/services/data/indexes/{segment}"
        parameters = [("output_mode", "json"), ("summarize", "false")]
    elif key.kind == "elastic-explain":
        path = f"/{segment}/_ilm/explain"
        parameters = [("only_managed", "false"), ("only_errors", "false")]
    elif key.kind == "elastic-policy":
        path = f"/_ilm/policy/{segment}"
    else:
        path = "/_ilm/status"
    return path, urlencode(parameters, quote_via=quote, safe="", encoding="utf-8", errors="strict")


def build_read_url(profile: FrozenProfile, key: ReadKey, *, continuation: str | None = None) -> str:
    """Build one fixed route from detached, validated session-selected inputs.

    This helper grants no profile, policy or pagination authority. The session
    supplies its authorized profile/key and admitted opaque continuation. The
    exact profile origin, including its explicit port, is retained for the
    transport adapter's raw-authority check. HTTPX's interpreted authority and
    encoded path/query must also match before the URL is returned.
    """
    try:
        selected = validated_profile(profile)
        selected_key = _checked_key(key)
        if selected.provider != _PROVIDERS[selected_key.kind]:
            raise EndpointError()
        path, query = _template(selected_key, continuation)
        suffix = path + ("?" + query if query else "")
        value = selected.origin + suffix
        authority = httpx.URL(selected.origin)
        parsed = httpx.URL(value)
        if (
            parsed.scheme != "https"
            or parsed.host != selected.host
            or parsed.raw_host != authority.raw_host
            or parsed.netloc != authority.netloc
            or (parsed.port or 443) != selected.port
            or parsed.userinfo
            or parsed.fragment
            or parsed.raw_path != suffix.encode("ascii")
            or parsed.query != query.encode("ascii")
        ):
            raise EndpointError()
        return value
    except EndpointError as exc:
        raise EndpointError(exc.code) from None
    except (AttributeError, TypeError, ValueError, RuntimeError, httpx.InvalidURL):
        raise EndpointError() from None


RESPONSE_MAX_BYTES = 1_048_576
RETRY_AFTER_MAX_BYTES = 128
RETRY_MAX_SECONDS = 10.0
BodyRetryCode = Literal[
    "invalid_encoding", "response_limit", "retry_after_invalid", "deadline_exceeded", "internal_error"
]


class BodyRetryError(ValueError):
    """Carry only a fixed public diagnostic."""

    def __init__(self, code: BodyRetryCode) -> None:
        if type(code) is not str or code not in (
            "invalid_encoding",
            "response_limit",
            "retry_after_invalid",
            "deadline_exceeded",
            "internal_error",
        ):
            code = "internal_error"
        self.code = code
        super().__init__(code)


def _response(value: object) -> httpx.Response:
    if type(value) is not httpx.Response:
        raise BodyRetryError("internal_error")
    return value


def _body_fault_origin(error: frozen.ClientFault) -> bool:
    """Translate only a direct fault from this unchanged helper invocation."""
    trace = error.__traceback__
    if trace is None or trace.tb_frame.f_code is not read_enterprise_body.__code__:
        return False
    origin = trace.tb_next
    return origin is not None and origin.tb_frame.f_code is frozen.read_bounded_body.__code__ and origin.tb_next is None


def read_enterprise_body(response: httpx.Response, *, consume: Callable[[int, int], None]) -> bytes:
    """Preserve delivered-byte accounting and caller-owned response cleanup."""
    selected = _response(response)
    values = selected.headers.get_list("content-encoding")
    if len(values) > 1 or (values and values[0].strip(" \t").lower() not in ("identity", "gzip")):
        raise BodyRetryError("invalid_encoding")
    consumer_error: BaseException | None = None

    def tracked(raw: int, decoded: int) -> None:
        nonlocal consumer_error
        try:
            consume(raw, decoded)
        except BaseException as error:
            consumer_error = error
            raise

    try:
        return frozen.read_bounded_body(selected, consume=tracked, max_bytes=RESPONSE_MAX_BYTES)
    except frozen.ClientFault as error:
        if error is consumer_error or not _body_fault_origin(error):
            raise
        if error.code == "invalid_response":
            raise BodyRetryError("invalid_encoding") from None
        if error.code == "response_limit":
            raise BodyRetryError("response_limit") from None
        raise BodyRetryError("internal_error") from None


def _retry_inputs(attempt: object, now: object, remaining: object) -> datetime:
    if type(attempt) is not int or attempt not in (1, 2) or type(now) is not datetime:
        raise BodyRetryError("internal_error")
    if not isinstance(remaining, (int, float)) or type(remaining) not in (int, float):
        raise BodyRetryError("internal_error")
    try:
        if not math.isfinite(remaining) or now.tzinfo is None or now.utcoffset() is None:
            raise BodyRetryError("internal_error")
        return now.astimezone(UTC)
    except Exception:
        raise BodyRetryError("internal_error") from None


def enterprise_retry_delay(response: httpx.Response, *, attempt: int, now: datetime, remaining: float) -> float:
    """Validate one server header before comparing its delay with live budget."""
    selected = _response(response)
    current = _retry_inputs(attempt, now, remaining)
    values = selected.headers.get_list("retry-after")
    if len(values) > 1:
        raise BodyRetryError("retry_after_invalid")
    header = values[0] if values else None
    if header is not None and (not header.isascii() or len(header) > RETRY_AFTER_MAX_BYTES):
        raise BodyRetryError("retry_after_invalid")
    try:
        # Keep the frozen helper's 30-second policy unchanged. Enterprise applies
        # its stricter server-delay cap before testing the caller's live budget.
        delay = frozen.retry_delay(header, attempt=attempt, now=current, remaining=30.0)
    except frozen.ClientFault as error:
        if error.code in ("retry_after_invalid", "run_budget_exhausted"):
            raise BodyRetryError("retry_after_invalid") from None
        raise BodyRetryError("internal_error") from None
    if delay > RETRY_MAX_SECONDS:
        raise BodyRetryError("retry_after_invalid")
    if remaining <= 0 or delay > remaining:
        raise BodyRetryError("deadline_exceeded")
    return delay
