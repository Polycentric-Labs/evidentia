"""Exercise SAM's owned stdlib response path with synthetic credentials only."""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import threading
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from evidentia_collectors.registries import _sam_http
from evidentia_collectors.registries._contracts import validated_request
from evidentia_collectors.registries._credentials import SamCredential, SamCredentialCache
from evidentia_core import network_guard

MARKER = "synthetic-sam-" + "query-material"
NOW = datetime(2026, 9, 11, tzinfo=UTC)


def request(registry: str = "sam-entity", **target: str) -> Any:
    return validated_request({"registry": registry, "target": target or {"uei": "ABC123DEF456"}})


class Wire:
    def __init__(self, response: bytes) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.client.settimeout(3)
                self.client.connect(listener.getsockname())
                self.server, _ = listener.accept()
            except BaseException:
                self.client.close()
                raise
        self.response = response
        self.request = b""
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        self.server.settimeout(3)
        try:
            while b"\r\n\r\n" not in self.request:
                part = self.server.recv(8192)
                if not part:
                    return
                self.request += part
            self.server.sendall(self.response)
        except (OSError, TimeoutError):
            pass
        finally:
            self.server.close()

    def close(self) -> None:
        self.client.close()
        self.server.close()
        self.thread.join(timeout=4)
        assert not self.thread.is_alive()


@pytest.fixture
def wire(monkeypatch: pytest.MonkeyPatch) -> Any:
    wires: list[Wire] = []
    events: list[Any] = []
    original_socket = socket.getaddrinfo
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", original_socket)

    def resolve(*args: Any, **kwargs: Any) -> list[Any]:
        events.append(("dns", args[0]))
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)

    def configure(body: bytes) -> tuple[Wire, list[Any]]:
        current = Wire(body)
        wires.append(current)

        def connect(address: Any, timeout: Any, source_address: Any = None) -> socket.socket:
            events.append(("connect", address, timeout))
            assert address == ("api.sam.gov", 443)
            assert socket.getaddrinfo(address[0], 443)[0][4][0] == "93.184.216.34"
            return current.client

        class Context:
            def wrap_socket(self, sock: socket.socket, *, server_hostname: str) -> socket.socket:
                events.append(("handshake", server_hostname))
                assert server_hostname == "api.sam.gov"
                return sock

        monkeypatch.setattr(socket, "create_connection", connect)
        monkeypatch.setattr(_sam_http, "tls_context", Context)
        return current, events

    with network_guard.offline_mode(False):
        yield configure
    for current in wires:
        current.close()


def collect(wire: Any, body: bytes, **kwargs: Any) -> tuple[Any, Wire, list[Any]]:
    current, events = wire(body)

    def resolve(reference: str) -> SamCredential:
        events.append(("credential", reference))
        return SamCredential(MARKER)

    attempt = _sam_http.SamAttempt()
    result = attempt.fetch(
        request(),
        page=0,
        credentials=SamCredentialCache(resolve),
        remaining=lambda: 60.0,
        utc_now=lambda: NOW,
        consume=kwargs.pop("consume", lambda raw, decoded: None),
        **kwargs,
    )
    return result, current, events


def test_owned_response_bridge_has_no_secret_request_or_httpx_client(
    wire: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("SAM invoked an HTTPX network client")

    monkeypatch.setattr(httpx, "Client", refused)
    monkeypatch.setattr(httpx, "HTTPTransport", refused)
    monkeypatch.setattr(http.client.HTTPConnection, "debuglevel", 9)
    charged: list[tuple[int, int]] = []
    result, current, events = collect(
        wire,
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
        consume=lambda raw, decoded: charged.append((raw, decoded)),
    )
    assert result == b"{}" and sum(raw for raw, _ in charged) == 2
    assert [item[0] for item in events] == ["dns", "connect", "handshake", "credential"]
    target = current.request.split(b" ", 2)[1].decode("ascii")
    query = parse_qs(urlsplit(target).query)
    assert query == {
        "sensitivity": ["public"],
        "samRegistered": ["Yes"],
        "includeSections": ["entityRegistration"],
        "size": ["10"],
        "ueiSAM": ["ABC123DEF456"],
        "api_key": [MARKER],
    }
    assert b"Cookie:" not in current.request and b"Authorization:" not in current.request


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 {m}\r\nContent-Length: 2\r\nX-Reflected: {m}\r\nSet-Cookie: {m}\r\n\r\n{}",
        b"{m} invalid status\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{m}\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n{m}" + b"x" * 65536 + b"\r\n\r\n",
        b"HTTP/1.1 302 {m}\r\nLocation: https://{m}.example.org/\r\nContent-Length: 0\r\n\r\n",
    ],
    ids=["reflection", "status", "chunk", "trailer", "redirect"],
)
def test_no_secret_at_log_record_creation_or_outputs(
    response: bytes, wire: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    records: list[str] = []
    factory = logging.getLogRecordFactory()

    def observed(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = factory(*args, **kwargs)
        records.append(repr((record.msg, record.args, record.exc_info)))
        return record

    monkeypatch.setattr(http.client.HTTPConnection, "debuglevel", 9)
    monkeypatch.setattr(http.client.HTTPResponse, "debuglevel", 9, raising=False)
    logging.setLogRecordFactory(observed)
    try:
        logging.getLogger("registry-test-observer").warning("positive-observer-control")
        try:
            collect(wire, response.replace(b"{m}", MARKER.encode("ascii")))
        except _sam_http.SamTransportError as error:
            assert error.__context__ is None and MARKER not in repr(error)
    finally:
        logging.setLogRecordFactory(factory)
    output = capsys.readouterr()
    assert any("positive-observer-control" in item for item in records)
    assert all(MARKER not in item for item in records)
    assert MARKER not in output.out + output.err


def test_callback_cancellation_identity_and_socket_cleanup(wire: Any) -> None:
    cancellation = KeyboardInterrupt("synthetic cancellation")
    current, _ = wire(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    attempt = _sam_http.SamAttempt()

    def consume(raw: int, decoded: int) -> None:
        if raw:
            raise cancellation

    with pytest.raises(KeyboardInterrupt) as raised:
        attempt.fetch(
            request(),
            page=0,
            credentials=SamCredentialCache(lambda _: SamCredential(MARKER)),
            remaining=lambda: 60.0,
            utc_now=lambda: NOW,
            consume=consume,
        )
    assert raised.value is cancellation and current.client.fileno() == -1
    assert attempt.status_code == 200


def test_truncated_content_length_is_not_a_complete_body(wire: Any) -> None:
    current, _ = wire(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}")
    attempt = _sam_http.SamAttempt()
    charged: list[int] = []
    with pytest.raises(_sam_http.SamTransportError, match=r"^invalid_response$"):
        attempt.fetch(
            request(),
            page=0,
            credentials=SamCredentialCache(lambda _: SamCredential(MARKER)),
            remaining=lambda: 60.0,
            utc_now=lambda: NOW,
            consume=lambda raw, decoded: charged.append(raw),
        )
    assert sum(charged) == 2 and attempt.status_code == 200 and current.client.fileno() == -1


def test_no_dns_or_credentials_for_invalid_selector_or_page(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: calls.append(args))
    for selected, page in [(request("tls", hostname="example.org"), 0), (request(), 1), (request(), True)]:
        with pytest.raises(ValueError):
            _sam_http.SamAttempt().fetch(
                selected,
                page=page,
                credentials=SamCredentialCache(lambda ref: calls.append(ref)),
                remaining=lambda: 60.0,
                utc_now=lambda: NOW,
                consume=lambda *_: None,
            )
    assert calls == []


@pytest.mark.parametrize("body", [b"-1\r\n{}", b"+2\r\n{}", b"2\r\n{}xx0\r\n\r\n", b"0\r\n", b"0\r\nno-colon\r\n\r\n"])
def test_malformed_chunk_framing_is_refused(body: bytes, wire: Any) -> None:
    with pytest.raises(_sam_http.SamTransportError, match=r"^invalid_response$"):
        collect(wire, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body)


@pytest.mark.parametrize(
    "headers",
    [
        b"Content-Length: 2\r\nContent-Length: 2\r\n",
        b"Content-Length: 2\r\nTransfer-Encoding: chunked\r\n",
        b"Content-Length: -1\r\n",
        b"Transfer-Encoding: gzip\r\n",
        b"Content-Encoding: gzip\r\nContent-Encoding: identity\r\n",
    ],
)
def test_ambiguous_or_unsupported_framing_headers_are_refused(headers: bytes, wire: Any) -> None:
    with pytest.raises(_sam_http.SamTransportError, match=r"^invalid_response$"):
        collect(wire, b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n{}")


def test_whole_observed_body_is_charged_before_callback_failure(wire: Any) -> None:
    failure = ValueError("fixed synthetic callback failure")
    charged: list[int] = []
    current, _ = wire(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")

    def consume(raw: int, decoded: int) -> None:
        charged.append(raw)
        if raw:
            raise failure

    with pytest.raises(ValueError) as raised:
        _sam_http.SamAttempt().fetch(
            request(),
            page=0,
            credentials=SamCredentialCache(lambda _: SamCredential(MARKER)),
            remaining=lambda: 60.0,
            utc_now=lambda: NOW,
            consume=consume,
        )
    assert raised.value is failure and sum(charged) == 2 and current.client.fileno() == -1


def test_deadline_checked_during_interim_headers(wire: Any) -> None:
    current, _ = wire(
        (b"HTTP/1.1 100 Continue\r\nX: value\r\n\r\n" * 1000) + b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"
    )
    calls = 0
    deadline = ValueError("deadline_exceeded")

    def remaining() -> float:
        nonlocal calls
        calls += 1
        if calls >= 25:
            raise deadline
        return 1.0

    with pytest.raises(ValueError) as raised:
        _sam_http.SamAttempt().fetch(
            request(),
            page=0,
            credentials=SamCredentialCache(lambda _: SamCredential(MARKER)),
            remaining=remaining,
            utc_now=lambda: NOW,
            consume=lambda *_: None,
        )
    assert raised.value is deadline and calls == 25 and current.client.fileno() == -1


def test_credential_expiry_is_rechecked_after_final_clock_callback(wire: Any) -> None:
    from datetime import timedelta

    from evidentia_collectors.registries._credentials import CredentialError

    current, _ = wire(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return NOW if calls < 3 else NOW + timedelta(seconds=2)

    with pytest.raises(CredentialError):
        _sam_http.SamAttempt().fetch(
            request(),
            page=0,
            credentials=SamCredentialCache(lambda _: SamCredential(MARKER, expires_at=NOW + timedelta(seconds=1))),
            remaining=lambda: 60.0,
            utc_now=clock,
            consume=lambda *_: None,
        )
    assert current.request == b"" and current.client.fileno() == -1


@pytest.mark.parametrize("primary", [False, True])
def test_close_failure_is_fixed_and_does_not_replace_primary(
    primary: bool, wire: Any, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    original = http.client.HTTPSConnection.close

    def bad_close(self: Any) -> None:
        original(self)
        raise OSError(MARKER)

    monkeypatch.setattr(http.client.HTTPSConnection, "close", bad_close)
    current, _ = wire(b"HTTP/1.1 " + (b"302 redirect" if primary else b"200 OK") + b"\r\nContent-Length: 2\r\n\r\n{}")
    attempt = _sam_http.SamAttempt()
    with pytest.raises(_sam_http.SamTransportError) as raised:
        attempt.fetch(
            request(),
            page=0,
            credentials=SamCredentialCache(lambda _: SamCredential(MARKER)),
            remaining=lambda: 60.0,
            utc_now=lambda: NOW,
            consume=lambda *_: None,
        )
    assert str(raised.value) == ("redirect_refused" if primary else "cleanup_failure")
    assert raised.value.__context__ is None and attempt.cleanup_failed and current.client.fileno() == -1
    output = capsys.readouterr()
    assert MARKER not in output.out + output.err


@pytest.mark.parametrize("trust", ["verified", "untrusted", "wrong-host"])
def test_real_owned_https_verifies_certificate_and_hostname(
    trust: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    from datetime import timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic registry test")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("different.example.org" if trust == "wrong-host" else "api.sam.gov")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / "synthetic-cert.pem", tmp_path / "synthetic-key.pem"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert_path), str(key_path))
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if trust != "untrusted":
        client_context.load_verify_locations(cadata=cert_pem.decode("ascii"))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    observed: list[bytes] = []

    def serve() -> None:
        try:
            raw, _ = listener.accept()
            with raw, server_context.wrap_socket(raw, server_side=True) as secure:
                value = b""
                while b"\r\n\r\n" not in value:
                    value += secure.recv(8192)
                observed.append(value)
                secure.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
        except (OSError, TimeoutError):
            pass
        finally:
            listener.close()

    server_thread = threading.Thread(target=serve, daemon=True)
    server_thread.start()
    original_create = socket.create_connection
    original_resolve = socket.getaddrinfo
    local_port = listener.getsockname()[1]
    actual_connects: list[Any] = []

    def resolve(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host == b"api.sam.gov":
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]
        return original_resolve(host, *args, **kwargs)

    def connect(address: Any, timeout: float, source_address: Any = None) -> socket.socket:
        actual_connects.append((address, socket.getaddrinfo(address[0], 443)[0][4][0]))
        return original_create(("127.0.0.1", local_port), timeout)

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", original_resolve)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "create_connection", connect)
    monkeypatch.setattr(_sam_http, "tls_context", lambda: client_context)
    for name in ("HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    keylog = tmp_path / "keylog.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    credentials: list[str] = []

    def credential(reference: str) -> SamCredential:
        credentials.append(reference)
        return SamCredential(MARKER)

    try:
        with network_guard.offline_mode(False), network_guard.pin_resolved_host("api.sam.gov", ["1.1.1.1"]):
            attempt = _sam_http.SamAttempt()
            if trust == "verified":
                assert (
                    attempt.fetch(
                        request(),
                        page=0,
                        credentials=SamCredentialCache(credential),
                        remaining=lambda: 3.0,
                        utc_now=lambda: NOW,
                        consume=lambda *_: None,
                    )
                    == b"{}"
                )
            else:
                with pytest.raises(_sam_http.SamTransportError, match=r"^tls_failure$"):
                    attempt.fetch(
                        request(),
                        page=0,
                        credentials=SamCredentialCache(credential),
                        remaining=lambda: 3.0,
                        utc_now=lambda: NOW,
                        consume=lambda *_: None,
                    )
            assert socket.getaddrinfo("api.sam.gov", 443)[0][4][0] == "1.1.1.1"
        assert actual_connects == [(("api.sam.gov", 443), "93.184.216.34")]
        assert len(credentials) == (1 if trust == "verified" else 0)
        assert bool(observed) == (trust == "verified") and not keylog.exists()
    finally:
        listener.close()
        server_thread.join(timeout=4)
        assert not server_thread.is_alive()


@pytest.mark.parametrize("framing", [b"2\r\n{}\r\n0\r\n\r\n", b'2;name="a;b";flag\r\n{}\r\n0\r\nX-End: value\r\n\r\n'])
def test_valid_chunked_body_and_extensions_complete(framing: bytes, wire: Any) -> None:
    result, current, _ = collect(wire, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + framing)
    assert result == b"{}" and current.client.fileno() == -1


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 +200 OK\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nmissing-colon\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nBad Name: value\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;name=" + bytes([0]) + b"\r\n{}\r\n0\r\n\r\n",
    ],
)
def test_native_status_header_and_extension_preflight(response: bytes, wire: Any) -> None:
    with pytest.raises(_sam_http.SamTransportError, match=r"^invalid_response$"):
        collect(wire, response)


def test_native_response_cleanup_cancellation_remains_original(wire: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    cancellation = KeyboardInterrupt("synthetic cleanup cancellation")
    original_close = _sam_http._GuardedFile.close

    def cancel_close(self: Any) -> None:
        original_close(self)
        raise cancellation

    monkeypatch.setattr(_sam_http._GuardedFile, "close", cancel_close)
    with pytest.raises(KeyboardInterrupt) as raised:
        collect(wire, b"HTTP/1.1 +200 OK\r\nContent-Length: 2\r\n\r\n{}")
    assert raised.value is cancellation


def test_expired_sam_attempt_refuses_before_dns_or_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: calls.append(args))

    def resolve(reference: str) -> SamCredential:
        calls.append(reference)
        return SamCredential(MARKER)

    with network_guard.offline_mode(False), pytest.raises(_sam_http.SamTransportError, match=r"^timeout$"):
        _sam_http.SamAttempt().fetch(
            request(),
            page=0,
            credentials=SamCredentialCache(resolve),
            remaining=lambda: 0.0,
            utc_now=lambda: NOW,
            consume=lambda *_: None,
        )
    assert calls == []
