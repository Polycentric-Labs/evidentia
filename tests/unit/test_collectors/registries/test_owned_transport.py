"""Exercise owned non-SAM clients, early refusal and original cancellation."""

from __future__ import annotations

import socket
from typing import Any

import httpx
import pytest
from evidentia_collectors.registries import _client
from evidentia_collectors.registries._tls import tls_context
from evidentia_core import network_guard


@pytest.fixture
def destination(monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", socket.getaddrinfo)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))],
    )
    with network_guard.offline_mode(False), network_guard.pin_resolved_host("example.org", ["1.1.1.1"]):
        yield
        assert socket.getaddrinfo("example.org", 443)[0][4][0] == "1.1.1.1"


class Body(httpx.SyncByteStream):
    def __init__(self, *, failure: BaseException | None = None) -> None:
        self.closed = False
        self.failure = failure

    def __iter__(self) -> Any:
        yield b"{}"

    def close(self) -> None:
        self.closed = True
        if self.failure is not None:
            raise self.failure


def test_fixed_fresh_unauthenticated_request_and_owned_close(destination: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    body = Body()
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert socket.getaddrinfo("example.org", 443)[0][4][0] == "93.184.216.34"
        return httpx.Response(200, stream=body, headers={"Set-Cookie": "synthetic=value"})

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(_client, "_http_transport", lambda context, approved, owned: transport)
    charged: list[tuple[int, int]] = []
    attempt = _client.HttpAttempt()
    assert (
        attempt.fetch(
            "https://example.org/source",
            remaining=lambda: 60.0,
            consume=lambda raw, decoded: charged.append((raw, decoded)),
        )
        == b"{}"
    )
    assert len(calls) == 1 and body.closed and attempt.status_code == 200
    assert calls[0].headers.get("Authorization") is None and calls[0].headers.get("Cookie") is None
    assert calls[0].extensions["timeout"] == {"connect": 5.0, "pool": 5.0, "read": 10.0, "write": 10.0}
    assert sum(raw for raw, _ in charged) == 2 and sum(decoded for _, decoded in charged) == 2


@pytest.mark.parametrize("status", [301, 302, 307, 308, 401, 403, 429, 500])
def test_status_precedes_location_parsing_and_close_preserves_refusal(
    status: int, destination: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    body = Body(failure=OSError("synthetic cleanup failure"))
    monkeypatch.setattr(
        _client,
        "_http_transport",
        lambda context, approved, owned: httpx.MockTransport(
            lambda request: httpx.Response(
                status, stream=body, headers={"Location": "https://[invalid", "Retry-After": "1"}
            )
        ),
    )
    attempt = _client.HttpAttempt()
    with pytest.raises(_client.HttpFault) as raised:
        attempt.fetch("https://example.org/source", remaining=lambda: 60.0, consume=lambda *_: None)
    assert str(raised.value) == ("redirect_refused" if 300 <= status < 400 else "http_error")
    assert raised.value.__context__ is None and attempt.status_code == status and attempt.cleanup_failed and body.closed


def test_original_callback_cancellation_survives_close_failure(
    destination: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    cancellation = KeyboardInterrupt("synthetic cancellation")
    body = Body(failure=OSError("synthetic close failure"))
    monkeypatch.setattr(
        _client,
        "_http_transport",
        lambda context, approved, owned: httpx.MockTransport(lambda request: httpx.Response(200, stream=body)),
    )

    def consume(raw: int, decoded: int) -> None:
        if raw:
            raise cancellation

    attempt = _client.HttpAttempt()
    with pytest.raises(KeyboardInterrupt) as raised:
        attempt.fetch("https://example.org/source", remaining=lambda: 60.0, consume=consume)
    assert raised.value is cancellation and attempt.cleanup_failed and body.closed


def test_sam_origin_is_excluded_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: calls.append(args))
    with pytest.raises(_client.HttpFault, match=r"^destination_refused$"):
        _client.HttpAttempt().fetch(
            "https://api.sam.gov/entity-information/v4/entities", remaining=lambda: 60.0, consume=lambda *_: None
        )
    assert calls == []


@pytest.mark.parametrize("trust", ["verified", "untrusted", "wrong-host", "ambient"])
def test_real_httpx_tls_and_environment_isolation(trust: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    import ssl
    import threading
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic HTTP registry test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("wrong.example.org" if trust == "wrong-host" else "example.org")]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_bytes = certificate.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(cert_bytes)
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(str(cert_path), str(key_path))
    key_path.unlink()
    if trust == "ambient":
        monkeypatch.setenv("SSL_CERT_FILE", str(cert_path))
        monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    client_context = tls_context()
    if trust in {"verified", "wrong-host"}:
        client_context.load_verify_locations(cadata=cert_bytes.decode("ascii"))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    local_address = listener.getsockname()
    listener.listen(1)
    listener.settimeout(3)
    received: list[bytes] = []

    def serve() -> None:
        try:
            raw, _ = listener.accept()
            with raw, server_context.wrap_socket(raw, server_side=True) as secured:
                value = b""
                while b"\r\n\r\n" not in value:
                    part = secured.recv(8192)
                    if not part:
                        return
                    value += part
                received.append(value)
                secured.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nSet-Cookie: synthetic=value\r\n\r\n{}")
        except OSError:
            pass
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    original_resolve = socket.getaddrinfo
    connections: list[Any] = []

    def resolve(host: Any, *args: Any, **kwargs: Any) -> Any:
        if host == b"example.org":
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))]
        return original_resolve(host, *args, **kwargs)

    class MappedSocket(socket.socket):
        def connect(self, address: Any) -> None:
            connections.append((address, socket.getaddrinfo("example.org", 443)[0][4][0]))
            assert address == ("93.184.216.34", 443)
            super().connect(local_address)

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", original_resolve)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(socket, "socket", MappedSocket)
    monkeypatch.setattr(_client, "tls_context", lambda: client_context)
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(variable, "http://127.0.0.1:1")
    netrc = tmp_path / "synthetic-netrc"
    netrc.write_text("machine example.org login synthetic password synthetic-only\n", encoding="ascii")
    monkeypatch.setenv("NETRC", str(netrc))
    keylog = tmp_path / "keylog.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    try:
        with network_guard.offline_mode(False), network_guard.pin_resolved_host("example.org", ["1.1.1.1"]):
            attempt = _client.HttpAttempt()
            if trust == "verified":
                assert (
                    attempt.fetch("https://example.org/source", remaining=lambda: 3.0, consume=lambda *_: None) == b"{}"
                )
            else:
                with pytest.raises(_client.HttpFault, match=r"^tls_failure$"):
                    attempt.fetch("https://example.org/source", remaining=lambda: 3.0, consume=lambda *_: None)
            assert socket.getaddrinfo("example.org", 443)[0][4][0] == "1.1.1.1"
        assert connections == [(("93.184.216.34", 443), "93.184.216.34")]
        assert bool(received) == (trust == "verified")
        assert all(b"Authorization:" not in value and b"Cookie:" not in value for value in received)
        assert not keylog.exists() and client_context.keylog_filename is None
    finally:
        listener.close()
        thread.join(timeout=4)
        assert not thread.is_alive()


def test_expired_attempt_refuses_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: calls.append(args))
    with network_guard.offline_mode(False), pytest.raises(_client.HttpFault, match=r"^timeout$"):
        _client.HttpAttempt().fetch("https://example.org/source", remaining=lambda: 0.0, consume=lambda *_: None)
    assert calls == []


def test_late_cleanup_cancellation_survives_http_refusal(destination: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    cancellation = KeyboardInterrupt("synthetic late cleanup cancellation")
    body = Body(failure=cancellation)
    monkeypatch.setattr(
        _client,
        "_http_transport",
        lambda context, approved, owned: httpx.MockTransport(lambda request: httpx.Response(401, stream=body)),
    )
    attempt = _client.HttpAttempt()
    with pytest.raises(KeyboardInterrupt) as raised:
        attempt.fetch("https://example.org/source", remaining=lambda: 60.0, consume=lambda *_: None)
    assert raised.value is cancellation and attempt.cleanup_failed and body.closed
