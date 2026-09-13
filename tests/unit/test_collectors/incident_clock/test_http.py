"""Exercise response framing and socket ownership with synthetic local streams."""

from __future__ import annotations

import hashlib
import secrets
import socket
import ssl
import time
from contextlib import contextmanager
from datetime import UTC
from typing import Any

import pytest
from evidentia_collectors.incident_clock import _http as http
from evidentia_collectors.incident_clock._contracts import validated_request
from evidentia_collectors.incident_clock._credentials import CredentialError
from evidentia_collectors.incident_clock._profiles import ProfileStore, authorize_cli_selection


class BytesStream:
    def __init__(self, content: bytes, fragment: int = 65536) -> None:
        self.content = content
        self.position = 0
        self.fragment = fragment
        self.timeouts: list[float] = []
        self.failure: BaseException | None = None
        self.failure_at = len(content) + 1
        self.after_recv: Any = None

    def recv(self, size: int) -> bytes:
        if self.position >= self.failure_at and self.failure is not None:
            raise self.failure
        end = min(len(self.content), self.position + min(size, self.fragment))
        data = self.content[self.position : end]
        self.position = end
        if self.after_recv is not None:
            self.after_recv()
        return data

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)


def response(body: bytes = b"{}", extra: bytes = b"", version: bytes = b"HTTP/1.1") -> bytes:
    return version + b" 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\n" + extra + b"\r\n" + body


def reader_for(content: bytes, *, budget: http.TransferBudget | None = None, fragment: int = 65536) -> http._Reader:
    return http._Reader(
        BytesStream(content, fragment), time.monotonic() + 60, http.TransferBudget() if budget is None else budget
    )


@pytest.mark.parametrize("version", [b"HTTP/1.0", b"HTTP/1.1"])
@pytest.mark.parametrize("fragment", [1, 7, 65536])
@pytest.mark.parametrize("body", [b"", b"{}", bytes(range(256))], ids=["empty", "object", "binary-identity"])
def test_explicit_length_keeps_exact_entity_and_observed_wire(version: bytes, fragment: int, body: bytes) -> None:
    wire = response(body, b"Content-Encoding: \tIdEnTiTy \t\r\n", version)
    reader = reader_for(wire, fragment=fragment)
    assert reader.read() == body
    assert reader.body_bytes == len(body) and reader.wire_bytes == len(wire)
    assert reader.budget.body_bytes == len(body) and reader.budget.wire_bytes == len(wire)
    assert all(0 < timeout <= 10 for timeout in reader.stream.timeouts)


@pytest.mark.parametrize(
    "fields,code",
    [
        (b"", "framing_invalid"),
        (b"Content-Length: 1\r\nContent-Length: 1\r\n", "framing_invalid"),
        (b"Content-Length: 1, 1\r\n", "framing_invalid"),
        (b"Content-Length: +1\r\n", "framing_invalid"),
        (b"Content-Length: -1\r\n", "framing_invalid"),
        (b"Content-Length: 1.0\r\n", "framing_invalid"),
        (b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n", "framing_invalid"),
        (b"Transfer-Encoding: gzip, chunked\r\n", "framing_invalid"),
        (b"Transfer-Encoding: identity\r\n", "framing_invalid"),
        (b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n", "framing_invalid"),
        (b"Content-Length: 1\r\nContent-Encoding: gzip\r\n", "unsupported_encoding"),
        (b"Content-Length: 1\r\nContent-Encoding: identity, identity\r\n", "unsupported_encoding"),
        (b"Content-Length: 1\r\nContent-Encoding: identity\r\nContent-Encoding: identity\r\n", "unsupported_encoding"),
        (b"Content-Length: 1\r\nContent-Encoding: \r\n", "unsupported_encoding"),
        (b"Content-Length : 1\r\n", "framing_invalid"),
        (b" Content-Length: 1\r\n", "framing_invalid"),
        (b"Content-Length: 1\r\nX-Test: a\x00b\r\n", "framing_invalid"),
        (b"Content-Length: 1\r\nX-Test: a\x7fb\r\n", "framing_invalid"),
        (b"Content-Length: 1\n", "framing_invalid"),
        (b"Content-Length: 1048577\r\n", "body_limit"),
        (b"Content-Length: " + b"9" * 128 + b"\r\n", "body_limit"),
    ],
    ids=[
        "eof-only",
        "duplicate-length",
        "length-list",
        "positive-sign",
        "negative",
        "decimal",
        "transfer-and-length",
        "transfer-chain",
        "transfer-identity",
        "duplicate-transfer",
        "gzip",
        "encoding-list",
        "duplicate-encoding",
        "empty-encoding",
        "name-space",
        "folded",
        "nul",
        "del",
        "bare-lf",
        "body-limit",
        "large-count",
    ],
)
def test_refused_headers_never_read_an_error_body(fields: bytes, code: str) -> None:
    header = b"HTTP/1.1 200 OK\r\n" + fields + b"\r\n"
    reader = reader_for(header + b"body-must-not-be-read")
    with pytest.raises(http._Failure, match=r"^" + code + "$"):
        reader.read()
    assert reader.body_bytes == 0 and reader.wire_bytes <= len(header)


@pytest.mark.parametrize(
    "status,code",
    [
        (100, "framing_invalid"),
        (101, "framing_invalid"),
        (204, "http_status_refused"),
        (301, "redirect_refused"),
        (401, "http_unauthorized"),
        (403, "http_forbidden"),
        (404, "http_not_found"),
        (429, "http_status_refused"),
        (500, "http_status_refused"),
    ],
)
def test_refused_numeric_status_stops_at_status_line(status: int, code: str) -> None:
    line = f"HTTP/1.1 {status} Response\r\n".encode()
    reader = reader_for(line + b"Content-Length: 100\r\n\r\n" + b"x" * 100)
    with pytest.raises(http._Failure, match=r"^" + code + "$"):
        reader.read()
    assert reader.status == status and reader.wire_bytes == len(line) and reader.body_bytes == 0


@pytest.mark.parametrize(
    "line",
    [
        b"HTTP/2 200 OK\r\n",
        b"HTTP/1.1 0200 OK\r\n",
        b"HTTP/1.1 600 Unknown\r\n",
        b"HTTP/1.1 200 OK\n",
        b"HTTP/1.1 200 bad\x00reason\r\n",
    ],
)
def test_unadmitted_status_has_no_invented_numeric_status(line: bytes) -> None:
    reader = reader_for(line)
    with pytest.raises(http._Failure, match=r"^framing_invalid$"):
        reader.read()
    assert reader.status is None


@pytest.mark.parametrize("fragment", [1, 3, 65536])
def test_chunked_identity_extensions_and_trailers(fragment: int) -> None:
    body = b'3;source=synthetic\r\nabc\r\n2;quoted="x y"\r\nde\r\n0\r\nX-Source: synthetic\r\n\r\n'
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: ChUnKeD\r\n\r\n" + body
    reader = reader_for(wire, fragment=fragment)
    assert reader.read() == b"abcde"
    assert reader.body_bytes == 5 and reader.wire_bytes == len(wire)
    assert reader.framing_bytes == len(body) - 5 and reader.fields == 2


@pytest.mark.parametrize(
    "tail,code",
    [
        (b"+1\r\nx\r\n0\r\n\r\n", "framing_invalid"),
        (b"0x1\r\nx\r\n0\r\n\r\n", "framing_invalid"),
        (b"1 \r\nx\r\n0\r\n\r\n", "framing_invalid"),
        (b'1;bad="unterminated\r\nx\r\n0\r\n\r\n', "framing_invalid"),
        (b"1\r\nx??0\r\n\r\n", "framing_invalid"),
        (b"2\r\nx", "framing_invalid"),
        (b"0\r\nContent-Length: 0\r\n\r\n", "framing_invalid"),
        (b"0\r\nContent-Encoding: gzip\r\n\r\n", "framing_invalid"),
        (b"0\r\nTransfer-Encoding: chunked\r\n\r\n", "framing_invalid"),
        (b"0\r\n folded\r\n\r\n", "framing_invalid"),
        (b"100001\r\n", "body_limit"),
    ],
    ids=[
        "plus",
        "hex-prefix",
        "space",
        "extension",
        "delimiter",
        "truncated",
        "length-trailer",
        "encoding-trailer",
        "transfer-trailer",
        "folded-trailer",
        "chunk-limit",
    ],
)
def test_chunk_refusals_keep_observed_counters(tail: bytes, code: str) -> None:
    wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + tail
    reader = reader_for(wire)
    with pytest.raises(http._Failure, match=r"^" + code + "$"):
        reader.read()
    assert reader.wire_bytes == reader.stream.position <= len(wire)
    assert reader.body_bytes == len(reader.body)


def test_http10_chunked_and_incomplete_explicit_body_are_refused() -> None:
    for wire in [
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nx",
    ]:
        reader = reader_for(wire)
        with pytest.raises(http._Failure, match=r"^framing_invalid$"):
            reader.read()
        assert reader.wire_bytes == reader.stream.position


def test_maximum_body_and_cumulative_entity_budget() -> None:
    body = b"x" * http.BODY_BYTES
    wire = response(body)
    budget = http.TransferBudget(body_bytes=http.TOTAL_BODY_BYTES - len(body))
    reader = reader_for(wire, budget=budget)
    assert hashlib.sha256(reader.read()).digest() == hashlib.sha256(body).digest()
    assert budget.body_bytes == http.TOTAL_BODY_BYTES
    rejected = reader_for(response(b"x"), budget=budget)
    with pytest.raises(http._Failure, match=r"^response_budget$"):
        rejected.read()
    assert rejected.body_bytes == 0 and budget.body_bytes == http.TOTAL_BODY_BYTES


def headers_of_size(size: int) -> bytes:
    prefix = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n"
    parts = [prefix]
    remaining = size - len(prefix) - 2
    while remaining > http.LINE_BYTES:
        parts.append(b"X: " + b"a" * (http.LINE_BYTES - 5) + b"\r\n")
        remaining -= http.LINE_BYTES
    parts.append(b"Y: " + b"a" * (remaining - 5) + b"\r\n")
    return b"".join(parts) + b"\r\n"


def test_header_total_exact_limit_and_single_observed_overflow_byte() -> None:
    wire = headers_of_size(http.HEADER_BYTES)
    reader = reader_for(wire)
    assert len(wire) == http.HEADER_BYTES and reader.read() == b""
    reader = reader_for(headers_of_size(http.HEADER_BYTES + 1))
    with pytest.raises(http._Failure, match=r"^header_limit$"):
        reader.read()
    assert reader.wire_bytes == http.HEADER_BYTES + 1 and reader.header_bytes == http.HEADER_BYTES + 1


def test_line_and_field_count_limits_include_received_rejection() -> None:
    for excess in (0, 1):
        line = b"X: " + b"a" * (http.LINE_BYTES - 5 + excess) + b"\r\n"
        reader = reader_for(response(b"", line))
        if excess:
            with pytest.raises(http._Failure, match=r"^header_limit$"):
                reader.read()
        else:
            assert reader.read() == b""
    for extra in (0, 1):
        reader = reader_for(response(b"", b"X: a\r\n" * (99 + extra)))
        if extra:
            with pytest.raises(http._Failure, match=r"^header_limit$"):
                reader.read()
        else:
            assert reader.read() == b"" and reader.fields == 100


def test_chunk_framing_exact_limit_and_one_byte_overflow() -> None:
    prefix = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    tail = b"01\r\nx\r\n" + b"1\r\nx\r\n" * 13105 + b"0\r\n\r\n"
    reader = reader_for(prefix + tail)
    assert reader.read() == b"x" * 13106 and reader.framing_bytes == http.FRAMING_BYTES
    reader = reader_for(prefix + b"0" + tail)
    with pytest.raises(http._Failure, match=r"^framing_limit$"):
        reader.read()
    assert reader.framing_bytes == http.FRAMING_BYTES + 1 and reader.body_bytes == 13106


def test_wire_caps_count_the_one_consumed_overflow_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    budget = http.TransferBudget(wire_bytes=http.TOTAL_WIRE_BYTES - 5)
    reader = reader_for(response(), budget=budget)
    with pytest.raises(http._Failure, match=r"^wire_budget$"):
        reader.read()
    assert budget.wire_bytes == http.TOTAL_WIRE_BYTES + 1 and reader.wire_bytes == 6
    monkeypatch.setattr(http, "WIRE_BYTES", 45)
    reader = reader_for(response(b"x" * 100))
    with pytest.raises(http._Failure, match=r"^wire_budget$"):
        reader.read()
    assert reader.wire_bytes == 46 and reader.body_bytes == 46 - len(response(b"x" * 100)) + 100


def test_idle_timeout_and_elapsed_deadline_keep_consumed_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    wire = response(b"abc")
    stream = BytesStream(wire)
    stream.failure_at = len(wire) - 3
    stream.failure = TimeoutError()
    reader = http._Reader(stream, time.monotonic() + 60, http.TransferBudget())
    with pytest.raises(http._Failure, match=r"^read_timeout$"):
        reader.read()
    assert reader.body_bytes == 0 and reader.wire_bytes == len(wire) - 3
    now = [0.0]
    monkeypatch.setattr(http.time, "monotonic", lambda: now[0])
    stream = BytesStream(wire)

    def expire_after_body() -> None:
        if stream.position == len(wire):
            now[0] = 6.0

    stream.after_recv = expire_after_body
    reader = http._Reader(stream, 5.0, http.TransferBudget())
    with pytest.raises(http._Failure, match=r"^deadline_exceeded$"):
        reader.read()
    assert reader.body_bytes == 3 and reader.wire_bytes == len(wire)


def selection(provider: str = "pagerduty") -> Any:
    request: dict[str, Any] = {
        "provider": provider,
        "profile_alias": "synthetic",
        "clock_alias": "workflow",
        "record_id": "P1",
    }
    first: dict[str, Any] = {"label": "Start", "meaning": "Configured recorded start"}
    last: dict[str, Any] = {"label": "End", "meaning": "Configured recorded end"}
    profile: dict[str, Any] = {
        "alias": "synthetic",
        "provider": provider,
        "allow_local_cli": True,
        "credential_ref": "INCIDENT_CLOCK_TEST_TOKEN",
        "record_ids": [],
        "clocks": [],
    }
    if provider == "servicenow":
        request["record_id"] = "1" * 32
        profile["origin"] = "https://instance.example.org"
        first["field"], last["field"] = "u_start", "u_end"
    elif provider == "jira":
        request["record_id"] = "10001"
        profile["cloud_id"] = "11111111-1111-1111-1111-111111111111"
        first.update(
            field_id="status", **{"from": {"state": "null", "value": None}, "to": {"state": "value", "value": "100"}}
        )
        last.update(
            field_id="status", **{"from": {"state": "value", "value": "100"}, "to": {"state": "value", "value": "200"}}
        )
    else:
        request.update(since="2024-01-01T00:00:00Z", until="2024-01-02T00:00:00Z")
        first["event_type"], last["event_type"] = "acknowledge_log_entry", "resolve_log_entry"
    profile["record_ids"] = [request["record_id"]]
    profile["clocks"] = [
        {
            "clock_alias": "workflow",
            "label": "Selected workflow",
            "mapping_reference": "Test runbook",
            "declared_workflow_meaning": "Configured source event pair",
            "start": first,
            "end": last,
        }
    ]
    return authorize_cli_selection(
        ProfileStore({"schema_version": "1", "profiles": [profile]}), validated_request(request)
    )


@pytest.mark.parametrize(
    "provider,template,start,path",
    [
        ("servicenow", "servicenow_record", None, "/api/now/v2/table/sn_si_incident/"),
        ("jira", "jira_accessible_resources", None, "/oauth/token/accessible-resources"),
        ("jira", "jira_issue", None, "/ex/jira/11111111-1111-1111-1111-111111111111/rest/api/3/issue/10001?"),
        (
            "jira",
            "jira_changelog",
            7,
            "/ex/jira/11111111-1111-1111-1111-111111111111/rest/api/3/issue/10001/changelog?",
        ),
        ("pagerduty", "pagerduty_incident", None, "/incidents/P1"),
        ("pagerduty", "pagerduty_log_entries", 7, "/incidents/P1/log_entries?"),
    ],
)
def test_only_approved_selected_targets(provider: str, template: Any, start: int | None, path: str) -> None:
    host, target = http.request_target(selection(provider), template, start)
    assert target.startswith(path)
    if provider == "jira":
        assert host == "api.atlassian.com"
        if start is not None:
            assert "startAt=7&maxResults=100" in target
    elif provider == "pagerduty":
        assert host == "api.pagerduty.com"
        if start is not None:
            assert "offset=7&limit=100&total=true&time_zone=UTC&since=" in target and "is_overview=false" in target
    else:
        assert (
            "sysparm_display_value=false&sysparm_exclude_reference_link=true&sysparm_fields=sys_id%2Cu_start%2Cu_end"
            in target
        )
    for invalid in (True, -1, 10001, "0"):
        with pytest.raises(http._Failure):
            http.request_target(selection(provider), template, invalid)


def test_tls_context_uses_native_required_policy_without_ambient_paths(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    keylog = tmp_path / "must-not-exist.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "untrusted-ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path / "untrusted-directory"))

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("ambient_tls_defaults")

    monkeypatch.setattr(http.ssl, "create_default_context", forbidden)
    context = http.tls_context()
    assert type(context) is ssl.SSLContext and context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.check_hostname is True and context.verify_mode == ssl.CERT_REQUIRED
    assert context.keylog_filename is None and context.cert_store_stats()["x509_ca"] > 0
    assert not keylog.exists()


def fake_transport(monkeypatch: pytest.MonkeyPatch, content: bytes, failure: str = "") -> dict[str, Any]:
    observed: dict[str, Any] = {"raw": [], "tls": [], "pins": [], "sent": False, "header_calls": 0}
    native_socket = socket.socket
    token = secrets.token_urlsafe(32)

    class Raw:
        def __init__(self, family: int, kind: int, protocol: int) -> None:
            self.native = native_socket(family, kind, protocol)
            observed["raw"].append(self)

        def connect(self, address: Any) -> None:
            observed["address"] = address
            if failure == "connect":
                raise OSError("synthetic")

        def settimeout(self, timeout: float) -> None:
            assert 0 < timeout <= 5

        def close(self) -> None:
            self.native.close()
            if failure == "cleanup":
                raise OSError("synthetic")

    class TLS(BytesStream):
        def __init__(self) -> None:
            super().__init__(content)
            self.closed = False
            if failure == "cancel":
                self.failure_at, self.failure = 0, KeyboardInterrupt()
            observed["tls"].append(self)

        def do_handshake(self) -> None:
            if failure == "tls":
                raise ssl.SSLError("synthetic")

        def sendall(self, request: bytes) -> None:
            observed["sent"] = True
            observed["request_valid"] = (
                request.startswith(b"GET /incidents/P1 HTTP/1.1\r\n")
                and b"Host: api.pagerduty.com\r\n" in request
                and b"Accept-Encoding: identity\r\n" in request
                and ("Authorization: Token token=" + token + "\r\n").encode() in request
            )

        def close(self) -> None:
            self.closed = True

    class Context:
        def wrap_socket(self, raw: Any, **options: Any) -> TLS:
            observed["tls_options"] = options
            return TLS()

    @contextmanager
    def pin(host: str, addresses: tuple[str, ...]) -> Any:
        observed["pins"].append((host, addresses))
        yield addresses

    def header(*args: Any) -> str:
        observed["header_calls"] += 1
        assert observed["tls"]
        if failure == "expired":
            raise CredentialError("credential_expired")
        return "Token token=" + token

    monkeypatch.setattr(http.network_guard, "is_offline", lambda: False)
    monkeypatch.setattr(http, "resolve_public", lambda host, deadline: ("8.8.8.8", "1.1.1.1"))
    monkeypatch.setattr(http, "pinned_public_host", pin)
    monkeypatch.setattr(http.socket, "socket", Raw)
    monkeypatch.setattr(http, "tls_context", Context)
    monkeypatch.setattr(http, "authorization_header", header)
    return observed


@pytest.mark.parametrize(
    "failure,expected",
    [
        ("", None),
        ("connect", "connect_failure"),
        ("tls", "tls_failure"),
        ("expired", "credential_expired"),
        ("cleanup", "cleanup_failure"),
        ("cancel", None),
    ],
)
def test_get_owns_native_socket_and_closes_every_failure(
    failure: str, expected: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = fake_transport(monkeypatch, response(), failure)
    selected = selection()
    if failure == "cancel":
        with pytest.raises(KeyboardInterrupt):
            http.get_identity(
                selected, object(), "pagerduty_incident", None, time.monotonic() + 60, http.TransferBudget()
            )
    else:
        result = http.get_identity(
            selected, object(), "pagerduty_incident", None, time.monotonic() + 60, http.TransferBudget()
        )
        assert result.diagnostic == expected
        if not failure:
            assert result.body == b"{}" and result.body_sha256 == hashlib.sha256(b"{}").hexdigest()
            assert result.body_complete and result.http_status == 200 and result.retrieved_at.tzinfo is UTC
            assert observed["request_valid"] and observed["header_calls"] == 1
            assert observed["address"] == ("8.8.8.8", 443)
            assert observed["tls_options"] == {"server_hostname": "api.pagerduty.com", "do_handshake_on_connect": False}
        elif failure == "cleanup":
            assert result.body == b"{}" and result.body_complete
            assert result.body_sha256 == hashlib.sha256(b"{}").hexdigest()
        else:
            assert result.body is None and result.body_sha256 is None and not result.body_complete
    assert all(raw.native.fileno() == -1 for raw in observed["raw"])
    assert all(tls.closed for tls in observed["tls"])
    if failure in ("expired", "connect", "tls"):
        assert not observed["sent"]


def test_offline_and_expired_deadline_refuse_before_dns_or_sockets(monkeypatch: pytest.MonkeyPatch) -> None:
    observed = fake_transport(monkeypatch, response())
    selected = selection()
    monkeypatch.setattr(http.network_guard, "is_offline", lambda: True)
    result = http.get_identity(
        selected, object(), "pagerduty_incident", None, time.monotonic() + 60, http.TransferBudget()
    )
    assert result.diagnostic == "offline_refused" and not observed["pins"] and not observed["raw"]
    monkeypatch.setattr(http.network_guard, "is_offline", lambda: False)
    result = http.get_identity(
        selected, object(), "pagerduty_incident", None, time.monotonic() - 1, http.TransferBudget()
    )
    assert result.diagnostic == "deadline_exceeded" and not observed["pins"] and not observed["raw"]


@pytest.mark.parametrize("phase", ["tls", "raw"])
def test_http_cleanup_cancellation_preserves_native_socket_release(phase: str, monkeypatch: pytest.MonkeyPatch) -> None:
    observed = fake_transport(monkeypatch, response())
    selected = selection()
    original_close = http._socket_close
    injected: list[str] = []

    def close_with_cancellation(tls: Any, raw: Any) -> Any:
        owned = tls if phase == "tls" else raw
        original = owned.close

        def interrupted() -> None:
            if not injected:
                injected.append(phase)
                raise KeyboardInterrupt()
            original()

        monkeypatch.setattr(owned, "close", interrupted)
        return original_close(tls, raw)

    monkeypatch.setattr(http, "_socket_close", close_with_cancellation)
    with pytest.raises(KeyboardInterrupt):
        http.get_identity(selected, object(), "pagerduty_incident", None, time.monotonic() + 60, http.TransferBudget())
    assert injected == [phase]
    assert all(raw.native.fileno() == -1 for raw in observed["raw"])
    assert all(tls.closed for tls in observed["tls"])


@pytest.mark.parametrize(
    "deadline",
    [10**1000, -(10**1000), float("nan"), float("inf"), True],
    ids=["huge-positive", "huge-negative", "nan", "infinite", "bool"],
)
def test_invalid_deadline_never_escapes_or_starts_network(deadline: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    observed = fake_transport(monkeypatch, response())
    result = http.get_identity(selection(), object(), "pagerduty_incident", None, deadline, http.TransferBudget())
    assert result.diagnostic == "deadline_exceeded" and not observed["pins"] and not observed["raw"]


def test_mismatched_template_and_page_kind_are_refused_before_network(monkeypatch: pytest.MonkeyPatch) -> None:
    observed = fake_transport(monkeypatch, response())
    for template, start in [("jira_issue", None), ("pagerduty_incident", 0), ("pagerduty_log_entries", None)]:
        result = http.get_identity(selection(), object(), template, start, time.monotonic() + 60, http.TransferBudget())
        assert result.diagnostic == "source_shape" and result.http_status is None
    assert not observed["pins"] and not observed["raw"]


@pytest.mark.parametrize("chunked", [False, True], ids=["length", "chunked"])
def test_completed_body_evidence_survives_final_deadline_refusal(
    chunked: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    wire = (
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n" if chunked else response(b"abc")
    )
    observed = fake_transport(monkeypatch, wire)
    readers: list[http._Reader] = []
    native_reader, original_remaining = http._Reader, http._remaining

    def capture(*args: Any) -> http._Reader:
        reader = native_reader(*args)
        readers.append(reader)
        return reader

    def final_refusal(deadline: float, cap: float = 10.0) -> float:
        if readers and readers[0].complete:
            raise http._Failure("deadline_exceeded")
        return original_remaining(deadline, cap)

    monkeypatch.setattr(http, "_Reader", capture)
    monkeypatch.setattr(http, "_remaining", final_refusal)
    result = http.get_identity(
        selection(), object(), "pagerduty_incident", None, time.monotonic() + 60, http.TransferBudget()
    )
    assert result.diagnostic == "deadline_exceeded" and result.http_status == 200
    assert result.body_complete and result.body == b"abc" and result.body_sha256 == hashlib.sha256(b"abc").hexdigest()
    assert result.body_bytes == 3 and result.wire_bytes == len(wire)
    assert all(raw.native.fileno() == -1 for raw in observed["raw"])
    assert all(tls.closed for tls in observed["tls"])
