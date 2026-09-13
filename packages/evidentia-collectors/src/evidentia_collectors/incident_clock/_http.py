"""Read approved incident endpoints with owned TLS sockets and bounded framing."""

from __future__ import annotations

import hashlib
import math
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol, cast
from urllib.parse import quote, urlencode

import certifi
from evidentia_core import network_guard

from ._contracts import DiagnosticCode, EndpointTemplate, PagerDutyRequest, ServiceNowMapping
from ._credentials import CredentialError, CredentialMaterial, authorization_header
from ._dns import DNSError, pinned_public_host, resolve_public
from ._profiles import AuthorizedSelection, ProfileUnavailable, _selection

BODY_BYTES = 1048576
TOTAL_BODY_BYTES = 8388608
WIRE_BYTES = 1179648
TOTAL_WIRE_BYTES = 10485760
LINE_BYTES = 8192
HEADER_BYTES = 65536
HEADER_FIELDS = 100
FRAMING_BYTES = 65536
CONNECT_SECONDS = 5.0
TLS_SECONDS = 5.0
IDLE_SECONDS = 10.0
_TOKEN = rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_FIELD_NAME = re.compile(_TOKEN)
_CHUNK_SIZE = re.compile(
    rb"[0-9A-Fa-f]+(?:;" + _TOKEN + rb"(?:=(?:" + _TOKEN + rb'|"(?:[\t !#-\[\]-~]|\\[\t -~])*"))?)*'
)
_FORBIDDEN_TRAILERS = frozenset(
    (b"content-length", b"transfer-encoding", b"content-encoding", b"host", b"authorization", b"connection", b"trailer")
)


class _Failure(ValueError):
    def __init__(self, code: DiagnosticCode) -> None:
        self.code = code
        super().__init__(code)


@dataclass(slots=True)
class TransferBudget:
    """Count observed entity and decrypted response bytes across one session."""

    body_bytes: int = 0
    wire_bytes: int = 0

    def check(self) -> None:
        if type(self) is not TransferBudget or type(self.body_bytes) is not int or type(self.wire_bytes) is not int:
            raise _Failure("response_budget")
        if not 0 <= self.body_bytes <= TOTAL_BODY_BYTES or not 0 <= self.wire_bytes <= TOTAL_WIRE_BYTES:
            raise _Failure("response_budget")


@dataclass(frozen=True, slots=True)
class HTTPReceipt:
    """Retain a complete identity body only when its framing and budgets pass."""

    http_status: int | None
    retrieved_at: datetime
    body: bytes | None
    body_bytes: int
    wire_bytes: int
    diagnostic: DiagnosticCode | None

    @property
    def body_complete(self) -> bool:
        return self.body is not None

    @property
    def body_sha256(self) -> str | None:
        return None if self.body is None else hashlib.sha256(self.body).hexdigest()


class _Stream(Protocol):
    def recv(self, size: int) -> bytes: ...
    def settimeout(self, timeout: float) -> None: ...


def _valid_deadline(value: object) -> bool:
    if type(value) is not float and type(value) is not int:
        return False
    if type(value) is int and value.bit_length() > 1023:
        return False
    return math.isfinite(value)


def _remaining(deadline: float, cap: float = IDLE_SECONDS) -> float:
    if not _valid_deadline(deadline):
        raise _Failure("deadline_exceeded")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _Failure("deadline_exceeded")
    return min(remaining, cap)


class _Reader:
    def __init__(self, stream: _Stream, deadline: float, budget: TransferBudget) -> None:
        budget.check()
        self.stream = stream
        self.deadline = deadline
        self.budget = budget
        self.wire_bytes = 0
        self.body_bytes = 0
        self.header_bytes = 0
        self.framing_bytes = 0
        self.fields = 0
        self.status: int | None = None
        self.body = bytearray()
        self.complete = False

    def _recv(self, maximum: int, *, entity: bool = False, header: bool = False, framing: bool = False) -> bytes:
        limits = [maximum, WIRE_BYTES + 1 - self.wire_bytes, TOTAL_WIRE_BYTES + 1 - self.budget.wire_bytes]
        if entity:
            limits.extend((BODY_BYTES + 1 - self.body_bytes, TOTAL_BODY_BYTES + 1 - self.budget.body_bytes))
        if header:
            limits.append(HEADER_BYTES + 1 - self.header_bytes)
        if framing:
            limits.append(FRAMING_BYTES + 1 - self.framing_bytes)
        size = min(limits)
        if size <= 0:
            raise _Failure("wire_budget")
        self.stream.settimeout(_remaining(self.deadline))
        try:
            data = self.stream.recv(size)
        except TimeoutError:
            _remaining(self.deadline)
            raise _Failure("read_timeout") from None
        except OSError:
            raise _Failure("framing_invalid") from None
        if type(data) is not bytes or len(data) > size:
            raise _Failure("framing_invalid")
        observed = len(data)
        self.wire_bytes += observed
        self.budget.wire_bytes += observed
        if entity:
            self.body_bytes += observed
            self.budget.body_bytes += observed
            self.body.extend(data)
        if header:
            self.header_bytes += observed
        if framing:
            self.framing_bytes += observed
        if self.wire_bytes > WIRE_BYTES or self.budget.wire_bytes > TOTAL_WIRE_BYTES:
            raise _Failure("wire_budget")
        if self.body_bytes > BODY_BYTES:
            raise _Failure("body_limit")
        if self.budget.body_bytes > TOTAL_BODY_BYTES:
            raise _Failure("response_budget")
        if self.header_bytes > HEADER_BYTES:
            raise _Failure("header_limit")
        if self.framing_bytes > FRAMING_BYTES:
            raise _Failure("framing_limit")
        if not data:
            raise _Failure("framing_invalid")
        return data

    def _line(self, *, header: bool = False, framing: bool = False) -> bytes:
        line = bytearray()
        while True:
            line.extend(self._recv(1, header=header, framing=framing))
            if len(line) > LINE_BYTES:
                raise _Failure("header_limit" if header else "framing_limit")
            if line[-1] == 10:
                if len(line) < 2 or line[-2] != 13:
                    raise _Failure("framing_invalid")
                return bytes(line[:-2])
            if len(line) > 1 and line[-2] == 13:
                raise _Failure("framing_invalid")

    def _field(self, line: bytes) -> tuple[bytes, bytes]:
        self.fields += 1
        if self.fields > HEADER_FIELDS:
            raise _Failure("header_limit")
        name, separator, value = line.partition(b":")
        if not separator or _FIELD_NAME.fullmatch(name) is None:
            raise _Failure("framing_invalid")
        if any((byte < 32 and byte != 9) or byte == 127 for byte in value):
            raise _Failure("framing_invalid")
        return name.lower(), value.strip(b" \t")

    def _headers(self) -> tuple[bytes, dict[bytes, bytes]]:
        status = self._line(header=True)
        match = re.fullmatch(rb"(HTTP/1\.[01]) ([1-5][0-9]{2}) [\t -~\x80-\xff]*", status)
        if match is None:
            raise _Failure("framing_invalid")
        self.status = int(match[2])
        if self.status != 200:
            if 100 <= self.status < 200:
                code: DiagnosticCode = "framing_invalid"
            elif 300 <= self.status < 400:
                code = "redirect_refused"
            else:
                status_codes: dict[int, DiagnosticCode] = {
                    401: "http_unauthorized",
                    403: "http_forbidden",
                    404: "http_not_found",
                }
                code = status_codes.get(self.status, "http_status_refused")
            raise _Failure(code)
        fields: dict[bytes, bytes] = {}
        while line := self._line(header=True):
            name, value = self._field(line)
            if name in (b"content-length", b"transfer-encoding", b"content-encoding"):
                if name in fields:
                    raise _Failure("unsupported_encoding" if name == b"content-encoding" else "framing_invalid")
                fields[name] = value
        if b"content-encoding" in fields and fields[b"content-encoding"].lower() != b"identity":
            raise _Failure("unsupported_encoding")
        return match[1], fields

    def _exact(self, count: int, *, entity: bool = False, framing: bool = False) -> bytes:
        result = bytearray()
        while len(result) < count:
            result.extend(self._recv(min(65536, count - len(result)), entity=entity, framing=framing))
        return bytes(result)

    def read(self) -> bytes:
        version, fields = self._headers()
        length, transfer = fields.get(b"content-length"), fields.get(b"transfer-encoding")
        if (length is None) == (transfer is None):
            raise _Failure("framing_invalid")
        if length is not None:
            if re.fullmatch(rb"[0-9]+", length) is None:
                raise _Failure("framing_invalid")
            significant = length.lstrip(b"0") or b"0"
            if len(significant) > 7 or int(significant) > BODY_BYTES:
                raise _Failure("body_limit")
            count = int(significant)
            if count > TOTAL_BODY_BYTES - self.budget.body_bytes:
                raise _Failure("response_budget")
            self._exact(count, entity=True)
        else:
            if version != b"HTTP/1.1" or transfer is None or transfer.lower() != b"chunked":
                raise _Failure("framing_invalid")
            self._chunks()
        self.complete = True
        _remaining(self.deadline)
        return bytes(self.body)

    def _chunks(self) -> None:
        while True:
            line = self._line(framing=True)
            if _CHUNK_SIZE.fullmatch(line) is None:
                raise _Failure("framing_invalid")
            digits = line.partition(b";")[0].lstrip(b"0") or b"0"
            if len(digits) > 6 or int(digits, 16) > BODY_BYTES - self.body_bytes:
                raise _Failure("body_limit")
            size = int(digits, 16)
            if size > TOTAL_BODY_BYTES - self.budget.body_bytes:
                raise _Failure("response_budget")
            if size == 0:
                while trailer := self._line(header=True, framing=True):
                    name, _ = self._field(trailer)
                    if name in _FORBIDDEN_TRAILERS:
                        raise _Failure("framing_invalid")
                return
            self._exact(size, entity=True)
            if self._exact(2, framing=True) != b"\r\n":
                raise _Failure("framing_invalid")


def tls_context() -> ssl.SSLContext:
    """Use the installed certifi bundle without ambient TLS or proxy settings."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.load_verify_locations(cafile=certifi.where())
    if (
        context.minimum_version != ssl.TLSVersion.TLSv1_2
        or context.verify_mode != ssl.CERT_REQUIRED
        or context.check_hostname is not True
        or context.keylog_filename is not None
    ):
        raise _Failure("tls_failure")
    return context


def request_target(selection: AuthorizedSelection, template: EndpointTemplate, start: int | None) -> tuple[str, str]:
    """Build only a selected record, site grant or contiguous history GET target."""
    _selection(selection)
    request = selection.request
    origin = selection.origin
    if type(template) is not str or (start is not None and (type(start) is not int or not 0 <= start <= 10000)):
        raise _Failure("source_shape")
    history = template in ("jira_changelog", "pagerduty_log_entries")
    if history != (start is not None):
        raise _Failure("source_shape")
    query: dict[str, str] = {}
    if request.provider == "servicenow" and template == "servicenow_record":
        definition = selection.definition
        first = cast(ServiceNowMapping, definition.start).field
        last = cast(ServiceNowMapping, definition.end).field
        target = "/api/now/v2/table/sn_si_incident/" + request.record_id
        query = {
            "sysparm_display_value": "false",
            "sysparm_exclude_reference_link": "true",
            "sysparm_fields": ",".join(("sys_id", first, last)),
        }
    elif request.provider == "jira" and template in ("jira_accessible_resources", "jira_issue", "jira_changelog"):
        if template == "jira_accessible_resources":
            target = "/oauth/token/accessible-resources"
        else:
            target = "/ex/jira/" + cast(str, selection.cloud_id) + "/rest/api/3/issue/" + request.record_id
            if template == "jira_issue":
                query = {"fields": "created", "fieldsByKeys": "false", "updateHistory": "false", "failFast": "true"}
            else:
                target += "/changelog"
                query = {"startAt": str(start), "maxResults": "100"}
    elif request.provider == "pagerduty" and template in ("pagerduty_incident", "pagerduty_log_entries"):
        target = "/incidents/" + request.record_id
        if template == "pagerduty_log_entries":
            selected = cast(PagerDutyRequest, request)
            target += "/log_entries"
            query = {
                "offset": str(start),
                "limit": "100",
                "total": "true",
                "time_zone": "UTC",
                "since": selected.since,
                "until": selected.until,
                "is_overview": "false",
            }
    else:
        raise _Failure("source_shape")
    if query:
        target += "?" + urlencode(query, quote_via=quote, safe="")
    if len(target) > 8192 or not target.isascii():
        raise _Failure("source_shape")
    return origin.removeprefix("https://"), target


def _socket_close(tls: ssl.SSLSocket | None, raw: socket.socket | None) -> tuple[bool, BaseException | None]:
    failed = False
    cancellation: BaseException | None = None
    for owned in (tls, raw):
        if owned is None:
            continue
        for _ in range(2):
            try:
                owned.close()
                break
            except BaseException as error:
                if isinstance(error, Exception):
                    failed = True
                    break
                if cancellation is None:
                    cancellation = error
        else:
            failed = True
    return failed, cancellation


def get_identity(
    selection: AuthorizedSelection,
    material: CredentialMaterial,
    template: EndpointTemplate,
    start: int | None,
    deadline: float,
    budget: TransferBudget,
) -> HTTPReceipt:
    """Issue one approved GET without retries, redirects, cookies or decompression."""
    raw: socket.socket | None = None
    tls: ssl.SSLSocket | None = None
    reader: _Reader | None = None
    body: bytes | None = None
    diagnostic: DiagnosticCode | None = None
    cancelled: BaseException | None = None
    stage: DiagnosticCode = "source_shape"
    try:
        if type(budget) is not TransferBudget:
            raise _Failure("response_budget")
        budget.check()
        host, target = request_target(selection, template, start)
        _remaining(deadline)
        if network_guard.is_offline():
            raise _Failure("offline_refused")
        stage = "tls_failure"
        context = tls_context()
        stage = "dns_failure"
        addresses = resolve_public(host, deadline)
        with pinned_public_host(host, addresses) as admitted:
            _remaining(deadline)
            address = admitted[0]
            stage = "connect_failure"
            raw = socket.socket(
                socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP
            )
            raw.settimeout(_remaining(deadline, CONNECT_SECONDS))
            raw.connect((address, 443, 0, 0) if ":" in address else (address, 443))
            _remaining(deadline)
            stage = "tls_failure"
            tls_cutoff = min(deadline, time.monotonic() + TLS_SECONDS)
            raw.settimeout(_remaining(tls_cutoff, TLS_SECONDS))
            tls = context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
            tls.settimeout(_remaining(tls_cutoff, TLS_SECONDS))
            tls.do_handshake()
            _remaining(tls_cutoff)
            # Resolve the header again after DNS, connect and TLS have consumed time.
            header = authorization_header(material, selection, datetime.now(UTC))
            accept = (
                "application/vnd.pagerduty+json;version=2" if selection.provider == "pagerduty" else "application/json"
            )
            request_bytes = (
                "GET "
                + target
                + " HTTP/1.1\r\nHost: "
                + host
                + "\r\nAccept: "
                + accept
                + "\r\nAccept-Encoding: identity\r\nAuthorization: "
                + header
                + "\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            del header
            stage = "read_timeout"
            tls.settimeout(_remaining(deadline))
            tls.sendall(request_bytes)
            del request_bytes
            _remaining(deadline)
            reader = _Reader(tls, deadline, budget)
            body = reader.read()
    except BaseException as error:
        if not isinstance(error, Exception):
            cancelled = error
        elif isinstance(error, (_Failure, DNSError, CredentialError)):
            diagnostic = error.code
        elif isinstance(error, ProfileUnavailable):
            diagnostic = "profile_refused"
        else:
            diagnostic = "deadline_exceeded" if _valid_deadline(deadline) and time.monotonic() >= deadline else stage
    if reader is not None and reader.complete:
        body = bytes(reader.body)
    cleanup_failed, cleanup_cancellation = _socket_close(tls, raw)
    if cancelled is None:
        cancelled = cleanup_cancellation
    if cleanup_failed:
        diagnostic = "cleanup_failure"
    if cancelled is not None:
        raise cancelled from None
    return HTTPReceipt(
        http_status=None if reader is None else reader.status,
        retrieved_at=datetime.now(UTC),
        body=body,
        body_bytes=0 if reader is None else reader.body_bytes,
        wire_bytes=0 if reader is None else reader.wire_bytes,
        diagnostic=diagnostic,
    )
