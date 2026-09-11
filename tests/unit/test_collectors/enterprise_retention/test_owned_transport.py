"""Synthetic owned-socket controls; no connection reaches the operating system."""

from __future__ import annotations

import socket
import ssl
from collections.abc import Generator, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from evidentia_collectors.enterprise_retention import _client as a
from evidentia_collectors.enterprise_retention import _profiles as profiles
from evidentia_core import network_guard as guard

CA_PEM = """-----BEGIN CERTIFICATE-----
MIIC8zCCAdugAwIBAgIBATANBgkqhkiG9w0BAQsFADAxMS8wLQYDVQQDDCZTeW50
aGV0aWMgZW50ZXJwcmlzZSByZXRlbnRpb24gdGVzdCBDQTAeFw0yMDAxMDEwMDAw
MDBaFw00MDAxMDEwMDAwMDBaMDExLzAtBgNVBAMMJlN5bnRoZXRpYyBlbnRlcnBy
aXNlIHJldGVudGlvbiB0ZXN0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAkZGoJHyq1fQRP8YESGQQLc43CubPRNeTjcFXV8Feh2U41PoiKktKHpzT
y5H+QE3ucyv4ub5IWPY2N8/rRjrRGxqZfHnjyUGg89bLG+xlauUMHnNmPnCZ+KcU
o6r7tLYcK3sGo0QnpjapcCF4GHY9UxYFCyxWy4zfKE0PeoWtvphsqz9JN9UkDBV7
0+GUFp+FnihH5RjSbtvIZA1z8N45z5YRIYePFOHDs3HARbGfg2xydaRDxhzhCN/H
CI0qIf5sm8ym/Vd2MwQvgpoUtfFG8axDShSLCV5nyFPXWO6Ddb/l9xH6HDgbjh1O
00rmDMvQ3Alzrgj4IWUMd6nXFq9qcQIDAQABoxYwFDASBgNVHRMBAf8ECDAGAQH/
AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQAqAbmeqJAcJTtxWWTUVtph0SxvaUAZ0y/G
DRrvrAcKLjZXpAwIXgwXe5VPRIh3BrBPcykUG7PWN8ZDXoMy3vLAVj3DJV3dnH65
cG16cak+5yfhmQynUbKicq4K/LMzOeyBqXOFFsZQwkkhPPwmTb2sbtlogNaqL7DD
bYdAXN9WHJq60/HVDhLP9y6Cysyd2I850PuuaVLzaEbjsK+L1SReBqkS47zLULqZ
vrfO+wJy7nagkqZWVU57PaTp5w08uKYcVS5AbeHtYpP6th5Tb2y4TOvxLFFXPvk+
12VdBQqF0WyRlg5Rk6Kbd2UXfGUgH0CDnT5Qur9FOHr/ctpPq35F
-----END CERTIFICATE-----
"""
HOST = "splunk.example.invalid"
URL = f"https://{HOST}:8089/services/data/indexes/selected?output_mode=json&summarize=false"
TOKEN = "Bearer synthetic-test-value"


def profile(**changes: Any) -> profiles.FrozenProfile:
    fields: dict[str, Any] = {
        "alias": "selected",
        "provider": "splunk-enterprise",
        "origin": f"https://{HOST}:8089",
        "credential_ref": "ENTERPRISE_RETENTION_SYNTHETIC_TOKEN",
        "address_policy": profiles.AddressPolicy("public"),
        "ca_bytes": CA_PEM.encode("ascii"),
    }
    return profiles.FrozenProfile(**fields | changes)


def row(ip: str = "8.8.8.8", port: int = 8089) -> tuple[Any, ...]:
    if ":" in ip:
        return (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port, 0, 0))
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))


class Wire:
    """Keep native sockets but intercept connect and all subsequent TLS I/O."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.answers: object = [row()]
        self.resolve_calls: list[tuple[Any, ...]] = []
        self.connected: list[tuple[Any, ...]] = []
        self.sockets: list[socket.socket] = []
        self.tls_sockets: list[FakeTLS] = []
        self.contexts: list[ssl.SSLContext] = []
        self.server_names: list[str | None] = []
        self.writes: list[bytes] = []
        self.response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: unwanted=synthetic\r\n\r\n{}"
        self.connect_error: OSError | None = None
        self.tls_error: OSError | None = None
        self.read_error: OSError | None = None
        self.close_error: OSError | None = None
        monkeypatch.setattr(socket, "getaddrinfo", self.resolve)
        monkeypatch.setattr(guard, "_GETADDRINFO_DELEGATE", self.resolve)
        monkeypatch.setattr(guard._pin_state, "hosts", {}, raising=False)
        monkeypatch.setattr(socket.socket, "connect", lambda sock, address: self.connect(sock, address))
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", lambda context, sock, **kw: self.wrap(context, sock, **kw))

    def resolve(self, *args: Any, **kwargs: Any) -> Any:
        self.resolve_calls.append(args)
        if isinstance(self.answers, BaseException):
            raise self.answers
        return self.answers

    def connect(self, sock: socket.socket, address: tuple[Any, ...]) -> None:
        self.connected.append(address)
        self.sockets.append(sock)
        if self.connect_error is not None:
            raise self.connect_error

    def wrap(self, context: ssl.SSLContext, sock: socket.socket, *, server_hostname: str | None = None) -> FakeTLS:
        self.contexts.append(context)
        self.server_names.append(server_hostname)
        if self.tls_error is not None:
            raise self.tls_error
        wrapped = FakeTLS(self, sock)
        self.tls_sockets.append(wrapped)
        return wrapped


class FakeTLS:
    def __init__(self, wire: Wire, sock: socket.socket) -> None:
        self.wire = wire
        self.sock = sock
        self.pending = wire.response
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        self.sock.settimeout(timeout)

    def send(self, data: bytes) -> int:
        self.wire.writes.append(bytes(data))
        return len(data)

    def recv(self, limit: int) -> bytes:
        if self.wire.read_error is not None:
            raise self.wire.read_error
        data, self.pending = (self.pending[:limit], self.pending[limit:])
        return data

    def close(self) -> None:
        self.closed = True
        self.sock.close()
        if self.wire.close_error is not None:
            raise self.wire.close_error

    def fileno(self) -> int:
        return self.sock.fileno()


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> Iterator[Wire]:
    selected = Wire(monkeypatch)
    yield selected
    for sock in selected.sockets:
        sock.close()


def timeout() -> httpx.Timeout:
    return httpx.Timeout(connect=5.0, pool=5.0, read=20.0, write=20.0)


def test_actual_owned_socket_path_pins_first_answer(wire: Wire) -> None:
    statuses: list[int] = []
    with a.OwnedHttpAttempt(profile(), URL, on_status=statuses.append) as attempt:
        wire.answers = [row("10.0.0.1")]
        response = attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
        assert response.read() == b"{}"
    assert wire.connected == [("8.8.8.8", 8089)]
    assert len(wire.resolve_calls) == 1
    assert statuses == [200]
    assert wire.server_names == [HOST]
    assert wire.contexts[0].verify_mode == ssl.CERT_REQUIRED
    assert wire.contexts[0].check_hostname
    assert all(sock.fileno() == -1 for sock in wire.sockets)
    assert all(sock.closed for sock in wire.tls_sockets)
    assert not attempt.cleanup_failed
    assert not getattr(guard._pin_state, "hosts", {})


def test_first_private_answer_refuses_before_send_callback(wire: Wire) -> None:
    wire.answers = [row("10.0.0.1")]
    callbacks: list[str] = []
    with (
        pytest.raises(a.AdapterError, match=r"^destination_refused$"),
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: callbacks.append("status")) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: callbacks.append("before"))
    assert callbacks == []
    assert wire.connected == []
    assert not getattr(guard._pin_state, "hosts", {})


def test_early_status_hook_refuses_malformed_redirect(wire: Wire) -> None:
    wire.response = b"HTTP/1.1 302 Found\r\nLocation: https://[broken\r\nContent-Length: 0\r\n\r\n"
    statuses: list[int] = []
    with (
        pytest.raises(a.AdapterError, match=r"^redirect_refused$"),
        a.OwnedHttpAttempt(profile(), URL, on_status=statuses.append) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
    assert statuses == [302]
    assert len(wire.connected) == 1
    assert all(sock.closed for sock in wire.tls_sockets)
    assert not attempt.cleanup_failed


@pytest.mark.parametrize(
    "answers",
    [
        None,
        (),
        [],
        [None],
        [list(row())],
        [row()[:-1]],
        [(99999, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8089))],
        [(True, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8089))],
        [(socket.AF_INET, socket.SOCK_DGRAM, 6, "", ("8.8.8.8", 8089))],
        [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 8089))],
        [(socket.AF_INET, socket.SOCK_STREAM, True, "", ("8.8.8.8", 8089))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, None, ("8.8.8.8", 8089))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ["8.8.8.8", 8089])],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (8, 8089))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("invalid", 8089))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", True))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8089, 0, 0))],
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 8089))],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 8089, 0, 0))],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 8089, 0, 2))],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 8089, 0, False))],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 8089, -1, 0))],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 8089, True, 0))],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111", 8089, 1048576, 0))],
        [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700::1111%eth0", 8089, 0, 0))],
        [row(), ("bad",)],
    ],
)
def test_every_raw_dns_row_must_be_valid_before_any_socket(wire: Wire, answers: Any) -> None:
    wire.answers = answers
    with (
        pytest.raises(a.AdapterError, match=r"^dns_failed$"),
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None),
    ):
        pytest.fail("malformed answer reached approved context")
    assert wire.connected == []
    assert not getattr(guard._pin_state, "hosts", {})


@pytest.mark.parametrize(
    "answers", [[row(), row("10.0.0.1")], [row("10.0.0.1"), row()], [row("::ffff:8.8.8.8")], [row("169.254.169.254")]]
)
def test_complete_forbidden_answer_set_is_refused(wire: Wire, answers: list[tuple[Any, ...]]) -> None:
    wire.answers = answers
    with (
        pytest.raises(a.AdapterError, match=r"^destination_refused$"),
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None),
    ):
        pytest.fail("mixed or denied set must never admit credentials")
    assert wire.connected == []


def test_unpinned_negative_control_would_use_second_private_lookup(wire: Wire) -> None:
    assert socket.getaddrinfo(HOST, 8089, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP) == [row()]
    wire.answers = [row("10.0.0.1")]
    sock = socket.create_connection((HOST, 8089), timeout=1)
    sock.close()
    assert len(wire.resolve_calls) == 2
    assert wire.connected == [("10.0.0.1", 8089)]


def test_native_connect_failure_closes_socket_and_never_uses_second_dns(wire: Wire) -> None:
    wire.connect_error = OSError("synthetic-connect")
    with (
        pytest.raises(httpx.ConnectError),
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt,
    ):
        wire.answers = [row("10.0.0.1")]
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
    assert wire.connected == [("8.8.8.8", 8089)]
    assert len(wire.resolve_calls) == 1
    assert all(sock.fileno() == -1 for sock in wire.sockets)
    assert not getattr(guard._pin_state, "hosts", {})


def test_actual_ipv6_socket_path_keeps_exact_port(wire: Wire) -> None:
    wire.answers = [row("2606:4700::1111"), row("2606:4700:0:0:0:0:0:1111")]
    with a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt:
        response = attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
        assert response.read() == b"{}"
    assert wire.connected == [("2606:4700::1111", 8089, 0, 0)]
    assert len(wire.resolve_calls) == 1


@pytest.mark.parametrize("address", ["10.1.2.3", "fd00:1234::8"])
def test_explicit_private_literal_is_allowed_offline_under_exact_private_policy(wire: Wire, address: str) -> None:
    host = f"[{address}]" if ":" in address else address
    origin = f"https://{host}:8089"
    selected = profile(origin=origin, address_policy=profiles.AddressPolicy("private", ("10.0.0.0/8", "fc00::/7")))
    wire.answers = [row(address)]
    with (
        guard.offline_mode(),
        a.OwnedHttpAttempt(
            selected, origin + "/services/data/indexes/selected", on_status=lambda status: None
        ) as attempt,
    ):
        assert attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None).read() == b"{}"
    assert wire.connected[0][0] == address
    assert len(wire.resolve_calls) == 1


@pytest.mark.parametrize("mode,cidrs", [("public", ()), ("private", ("10.0.0.0/8",))])
def test_offline_hostname_refuses_before_any_dns(wire: Wire, mode: Any, cidrs: tuple[str, ...]) -> None:
    selected = profile(address_policy=profiles.AddressPolicy(mode, cidrs))
    with (
        guard.offline_mode(),
        pytest.raises(a.AdapterError, match=r"^offline_refused$"),
        a.OwnedHttpAttempt(selected, URL, on_status=lambda status: None),
    ):
        pytest.fail("offline hostname reached destination approval")
    assert wire.resolve_calls == []


@pytest.mark.parametrize(
    "url",
    [
        URL.replace("https:", "http:"),
        URL.replace(HOST, "other.example.invalid"),
        URL.replace(":8089", ":443"),
        URL.replace(HOST, "user@" + HOST),
        URL + "#fragment",
        URL + "#",
        URL.replace(HOST, HOST + "."),
        URL.replace(HOST, "SPLUNK.example.invalid"),
        URL + "\\other",
        URL + "\n",
        URL + " ",
    ],
)
def test_wrong_authority_or_ambiguous_url_is_refused_before_dns(wire: Wire, url: str) -> None:
    with pytest.raises(a.AdapterError, match=r"^destination_refused$"):
        a.OwnedHttpAttempt(profile(), url, on_status=lambda status: None)
    assert wire.resolve_calls == []


@pytest.mark.parametrize("guarded", [[], ["8.8.4.4"], ["8.8.8.8", "8.8.4.4"], ["10.0.0.1"], None])
def test_public_guard_must_confirm_the_same_approved_set(
    wire: Wire, monkeypatch: pytest.MonkeyPatch, guarded: Any
) -> None:

    def changed(*args: Any, **kwargs: Any) -> Any:
        assert kwargs["block_private"] is True
        assert getattr(guard._pin_state, "hosts", {}).get(HOST) == ["8.8.8.8"]
        return guarded

    monkeypatch.setattr(guard, "enforce_public_host", changed)
    with (
        pytest.raises(a.AdapterError, match=r"^destination_refused$"),
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None),
    ):
        pytest.fail("guard disagreement reached credentials")
    assert wire.connected == []
    assert not getattr(guard._pin_state, "hosts", {})


@pytest.mark.parametrize(
    "status,code",
    [(301, "redirect_refused"), (304, "redirect_refused"), (399, "redirect_refused"), (401, "credential_rejected")],
)
def test_status_is_recorded_before_refusal_and_response_is_closed(wire: Wire, status: int, code: str) -> None:
    wire.response = f"HTTP/1.1 {status} Synthetic\r\nContent-Length: 100\r\n\r\n".encode()
    statuses: list[int] = []
    with (
        pytest.raises(a.AdapterError, match=r"^" + code + "$"),
        a.OwnedHttpAttempt(profile(), URL, on_status=statuses.append) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
    assert statuses == [status]
    assert all(sock.closed for sock in wire.tls_sockets)
    assert not attempt.cleanup_failed


@pytest.mark.parametrize("status", [200, 204, 403, 404, 408, 429, 500, 502, 503, 504])
def test_other_statuses_return_untouched_for_root_session_policy(wire: Wire, status: int) -> None:
    wire.response = f"HTTP/1.1 {status} Synthetic\r\nContent-Length: 0\r\n\r\n".encode()
    statuses: list[int] = []
    with a.OwnedHttpAttempt(profile(), URL, on_status=statuses.append) as attempt:
        result = attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
        assert result.status_code == status
        assert not result.is_stream_consumed
    assert statuses == [status]
    assert result.is_closed


def test_cookie_defaults_and_client_auth_do_not_enter_fresh_request(wire: Wire) -> None:
    calls: list[str] = []

    class DisallowedAuth(httpx.Auth):
        def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
            calls.append("auth")
            yield request

    with a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt:
        assert attempt._client is not None
        attempt._client.headers["X-Unrelated"] = "should-not-merge"
        attempt._client.params = {"unrelated": "should-not-merge"}
        attempt._client.auth = DisallowedAuth()
        response = attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
        assert len(attempt._client.cookies) == 0
        assert response.read() == b"{}"
    sent = b"".join(wire.writes)
    assert sent.startswith(b"GET /services/data/indexes/selected?output_mode=json&summarize=false HTTP/1.1\r\n")
    headers, body = sent.split(b"\r\n\r\n", 1)
    assert body == b""
    names = [line.split(b":", 1)[0].lower() for line in headers.split(b"\r\n")[1:]]
    assert set(names) == {b"host", b"accept", b"accept-encoding", b"authorization"}
    assert len(names) == 4
    assert b"Host: splunk.example.invalid:8089" in headers
    assert b"Accept-Encoding: gzip, identity" in headers
    assert calls == []


def test_before_send_observes_constructed_request_and_can_stop_without_socket(
    wire: Wire, monkeypatch: pytest.MonkeyPatch
) -> None:
    built: list[httpx.Request] = []
    original = httpx.Request

    def construct(*args: Any, **kwargs: Any) -> httpx.Request:
        request = original(*args, **kwargs)
        built.append(request)
        return request

    monkeypatch.setattr(httpx, "Request", construct)
    expected = RuntimeError("synthetic-expiry-check")

    def before() -> None:
        assert len(built) == 1
        assert built[0].headers["Authorization"] == TOKEN
        assert built[0].extensions["timeout"] == {"connect": 5.0, "pool": 5.0, "read": 20.0, "write": 20.0}
        raise expected

    with (
        pytest.raises(RuntimeError) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=before)
    assert result.value is expected
    assert wire.connected == []
    assert not attempt.cleanup_failed
    assert not getattr(guard._pin_state, "hosts", {})


def test_same_thread_is_required_before_any_second_dns_or_send(wire: Wire) -> None:
    from concurrent.futures import ThreadPoolExecutor

    with a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt:
        wire.answers = [row("10.0.0.1")]
        with ThreadPoolExecutor(max_workers=1) as workers:
            future = workers.submit(attempt.send, authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
            with pytest.raises(a.AdapterError, match=r"^internal_error$"):
                future.result()
    assert len(wire.resolve_calls) == 1
    assert wire.connected == []


def test_one_attempt_cannot_send_twice_or_reenter(wire: Wire) -> None:
    attempt = a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None)
    with attempt:
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None).read()
        with pytest.raises(a.AdapterError, match=r"^internal_error$"):
            attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
        with pytest.raises(a.AdapterError, match=r"^internal_error$"):
            attempt.__enter__()
    with pytest.raises(a.AdapterError, match=r"^internal_error$"):
        attempt.__enter__()
    with pytest.raises(a.AdapterError, match=r"^internal_error$"):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
    assert len(wire.connected) == 1


@pytest.mark.parametrize("phase", ["connect", "tls", "read"])
def test_native_failures_propagate_with_scopes_and_owned_socket_closed(wire: Wire, phase: str) -> None:
    error = OSError("synthetic-native-marker")
    if phase == "connect":
        wire.connect_error = error
    elif phase == "tls":
        wire.tls_error = error
    else:
        wire.read_error = error
    with (
        pytest.raises(httpx.TransportError),
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
    assert all(sock.fileno() == -1 for sock in wire.sockets)
    assert not getattr(guard._pin_state, "hosts", {})


@pytest.mark.parametrize("status", [302, 401])
def test_close_error_does_not_replace_primary_early_status(wire: Wire, status: int) -> None:
    wire.response = f"HTTP/1.1 {status} Synthetic\r\nContent-Length: 100\r\n\r\n".encode()
    wire.close_error = OSError("synthetic-close-marker")
    with (
        pytest.raises(a.AdapterError) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
    assert result.value.code == ("redirect_refused" if status == 302 else "credential_rejected")
    assert attempt.cleanup_failed
    assert all(sock.fileno() == -1 for sock in wire.sockets)
    assert not getattr(guard._pin_state, "hosts", {})


def test_late_cleanup_error_signals_separately_from_primary(wire: Wire, monkeypatch: pytest.MonkeyPatch) -> None:
    primary = RuntimeError("synthetic-first-error")
    with (
        pytest.raises(RuntimeError) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt,
    ):
        original = attempt._stack.close

        def close() -> None:
            original()
            raise OSError("synthetic-late-cleanup")

        monkeypatch.setattr(attempt._stack, "close", close)
        raise primary
    assert result.value is primary
    assert attempt.cleanup_failed
    assert not getattr(guard._pin_state, "hosts", {})


def test_no_primary_cleanup_error_is_a_separate_fixed_signal(wire: Wire, monkeypatch: pytest.MonkeyPatch) -> None:
    with a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt:
        assert attempt._client is not None
        original = attempt._client.close

        def close() -> None:
            original()
            raise OSError("synthetic-close-marker")

        monkeypatch.setattr(attempt._client, "close", close)
    assert attempt.cleanup_failed
    assert not getattr(guard._pin_state, "hosts", {})


@pytest.mark.parametrize("callback_kind", ["before", "status"])
def test_operational_callback_exception_identity_is_preserved(wire: Wire, callback_kind: str) -> None:
    primary = LookupError("synthetic-callback-marker")

    def fail() -> None:
        raise primary

    def status(code: int) -> None:
        fail()

    with (
        pytest.raises(LookupError) as result,
        a.OwnedHttpAttempt(
            profile(), URL, on_status=status if callback_kind == "status" else lambda code: None
        ) as attempt,
    ):
        attempt.send(
            authorization=TOKEN, timeout=timeout(), before_send=fail if callback_kind == "before" else lambda: None
        )
    assert result.value is primary
    assert all(sock.fileno() == -1 for sock in wire.sockets)
    assert not getattr(guard._pin_state, "hosts", {})


@pytest.mark.parametrize(
    "field,value",
    [
        ("connect", 0),
        ("connect", 5.00001),
        ("pool", None),
        ("pool", False),
        ("read", float("nan")),
        ("read", float("inf")),
        ("write", 20.0001),
        ("write", -1),
        ("connect", "1"),
    ],
)
def test_unsafe_timeout_rejected_before_callback_or_socket(wire: Wire, field: str, value: Any) -> None:
    selected = timeout()
    setattr(selected, field, value)
    calls: list[str] = []
    with (
        pytest.raises(a.AdapterError, match=r"^internal_error$"),
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=selected, before_send=lambda: calls.append("called"))
    assert calls == []
    assert wire.connected == []


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Bearer ",
        "Bearer a b",
        "Bearer synthetic\r\nX-Test: injected",
        "Bearer synthetic\x00",
        "Bearer synthetic\xe9",
        "ApiKey synthetic",
        "Bearer " + "x" * 16385,
    ],
)
def test_invalid_header_material_never_reaches_request_or_error(wire: Wire, value: str) -> None:
    with (
        pytest.raises(a.AdapterError, match=r"^credential_invalid$") as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt,
    ):
        attempt.send(authorization=value, timeout=timeout(), before_send=lambda: None)
    assert result.value.args == ("credential_invalid",)
    assert wire.connected == []
    assert TOKEN not in repr(attempt)


def test_new_transport_has_explicit_http1_and_no_retry_keepalive_proxy_policy(wire: Wire) -> None:
    with a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt:
        assert type(attempt._transport) is httpx.HTTPTransport
        assert attempt._client is not None
        assert not attempt._client.trust_env
        assert not attempt._client.follow_redirects
        assert attempt._client._mounts == {}
        pool = attempt._transport._pool
        assert pool._http1 is True and pool._http2 is False
        assert pool._max_connections == 1 and pool._max_keepalive_connections == 0
        assert pool._retries == 0
        assert pool._ssl_context is not None
        assert pool._ssl_context.verify_mode == ssl.CERT_REQUIRED
        assert pool._ssl_context.check_hostname is True
        assert pool._ssl_context.keylog_filename is None
        assert isinstance(attempt._client.cookies.jar._policy, a.RejectCookies)
    assert not attempt.cleanup_failed


def test_transport_constructor_failure_restores_approved_pin(wire: Wire) -> None:
    primary = RuntimeError("synthetic-constructor")

    def factory(context: ssl.SSLContext) -> httpx.BaseTransport:
        assert context.verify_mode == ssl.CERT_REQUIRED
        raise primary

    with (
        pytest.raises(RuntimeError) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None, transport_factory=factory),
    ):
        pytest.fail("constructor failure reached context body")
    assert result.value is primary
    assert wire.connected == []
    assert not getattr(guard._pin_state, "hosts", {})


def test_log_suppression_is_local_and_restored(wire: Wire, caplog: pytest.LogCaptureFixture) -> None:
    import logging

    logger = logging.getLogger("httpx")
    with caplog.at_level(logging.DEBUG, logger="httpx"):
        with a.OwnedHttpAttempt(profile(), URL, on_status=lambda status: None) as attempt:
            logger.warning("synthetic-inside-marker")
            attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None).read()
        logger.warning("synthetic-after-marker")
    messages = [record.getMessage() for record in caplog.records]
    assert messages == ["synthetic-after-marker"]


def test_client_construction_failure_closes_constructed_transport(wire: Wire, monkeypatch: pytest.MonkeyPatch) -> None:
    transports: list[httpx.BaseTransport] = []
    closed: list[bool] = []

    class ObservedTransport(httpx.HTTPTransport):
        def close(self) -> None:
            closed.append(True)
            super().close()

    def factory(context: ssl.SSLContext) -> httpx.BaseTransport:
        transport = ObservedTransport(verify=context, trust_env=False, http2=False, retries=0)
        transports.append(transport)
        return transport

    primary = RuntimeError("synthetic-client-constructor")

    def fail(*args: Any, **kwargs: Any) -> None:
        raise primary

    monkeypatch.setattr(httpx, "Client", fail)
    with (
        pytest.raises(RuntimeError) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None, transport_factory=factory),
    ):
        pytest.fail("client construction failure entered context")
    assert result.value is primary
    assert len(transports) == len(closed) == 1
    assert not getattr(guard._pin_state, "hosts", {})


def test_body_consumer_exception_preserves_primary_and_closes_unread_body(wire: Wire) -> None:
    wire.response = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n"
    primary = RuntimeError("synthetic-body-admission")
    with (
        pytest.raises(RuntimeError) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt,
    ):
        response = attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
        assert not response.is_stream_consumed
        raise primary
    assert result.value is primary
    assert response.is_closed
    assert all(sock.fileno() == -1 for sock in wire.sockets)


@pytest.mark.parametrize("has_primary", [True, False])
def test_cleanup_cancellation_restores_scope_without_replacing_earlier_error(
    wire: Wire, monkeypatch: pytest.MonkeyPatch, has_primary: bool
) -> None:
    primary = RuntimeError("synthetic-first")
    interrupted = KeyboardInterrupt("synthetic-cleanup-interruption")
    expected = primary if has_primary else interrupted
    with (
        pytest.raises(type(expected)) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt,
    ):
        assert attempt._client is not None
        original = attempt._client.close

        def close() -> None:
            original()
            raise interrupted

        monkeypatch.setattr(attempt._client, "close", close)
        if has_primary:
            raise primary
    assert result.value is expected
    assert attempt.cleanup_failed
    assert not getattr(guard._pin_state, "hosts", {})


def test_callback_cancellation_before_send_closes_resources(wire: Wire) -> None:
    interrupted = KeyboardInterrupt("synthetic-before-interruption")

    def before() -> None:
        raise interrupted

    with (
        pytest.raises(KeyboardInterrupt) as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt,
    ):
        attempt.send(authorization=TOKEN, timeout=timeout(), before_send=before)
    assert result.value is interrupted
    assert not attempt.cleanup_failed
    assert wire.connected == []
    assert not getattr(guard._pin_state, "hosts", {})


def test_nested_existing_pin_is_restored_after_attempt(wire: Wire) -> None:
    with guard.pin_resolved_host(HOST, ["8.8.4.4"]):
        with a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt:
            response = attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
            assert response.read() == b"{}"
        assert getattr(guard._pin_state, "hosts", {})[HOST] == ["8.8.4.4"]
    assert not getattr(guard._pin_state, "hosts", {})
    assert wire.connected == [("8.8.8.8", 8089)]
    assert len(wire.resolve_calls) == 1
    assert wire.resolve_calls[0][0] == HOST.encode("ascii")


def test_attempts_have_separate_owned_clients_and_cookie_jars(wire: Wire) -> None:
    clients: list[httpx.Client] = []
    transports: list[httpx.BaseTransport] = []
    for _unused in range(2):
        with a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt:
            assert attempt._client is not None and attempt._transport is not None
            clients.append(attempt._client)
            transports.append(attempt._transport)
            attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None).read()
            assert len(attempt._client.cookies) == 0
    assert clients[0] is not clients[1]
    assert transports[0] is not transports[1]
    assert len(wire.resolve_calls) == len(wire.connected) == 2
    assert all(client.is_closed for client in clients)


def test_proxy_and_netrc_environment_does_not_change_owned_request(
    wire: Wire, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    netrc = tmp_path / "synthetic-netrc"
    netrc.write_text(f"machine {HOST} login synthetic password synthetic\n", encoding="ascii")
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://proxy.example.invalid:8888")
    monkeypatch.setenv("NETRC", str(netrc))
    with a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None) as attempt:
        assert attempt._client is not None
        assert attempt._client._mounts == {}
        response = attempt.send(authorization=TOKEN, timeout=timeout(), before_send=lambda: None)
        assert response.read() == b"{}"
    assert wire.connected == [("8.8.8.8", 8089)]
    assert b"Authorization: " + TOKEN.encode() + b"\r\n" in b"".join(wire.writes)
    assert b"Proxy-" not in b"".join(wire.writes)


def test_dns_os_error_is_fixed_and_precedes_factory(wire: Wire) -> None:
    wire.answers = socket.gaierror("synthetic-dns-detail")
    calls: list[str] = []

    def factory(context: ssl.SSLContext) -> httpx.BaseTransport:
        calls.append("factory")
        return httpx.MockTransport(lambda request: httpx.Response(200))

    with (
        pytest.raises(a.AdapterError, match=r"^dns_failed$") as result,
        a.OwnedHttpAttempt(profile(), URL, on_status=lambda code: None, transport_factory=factory),
    ):
        pytest.fail("failed DNS reached approved context")
    assert result.value.__suppress_context__
    assert calls == []


def test_maximum_header_material_and_elastic_scheme_remain_exact(wire: Wire) -> None:
    selected = profile(provider="elastic-ilm")
    value = "ApiKey " + "x" * 16384
    with a.OwnedHttpAttempt(selected, URL, on_status=lambda code: None) as attempt:
        result = attempt.send(authorization=value, timeout=timeout(), before_send=lambda: None)
        assert result.read() == b"{}"
        assert value not in repr(attempt)
    assert b"Authorization: " + value.encode() + b"\r\n" in b"".join(wire.writes)
