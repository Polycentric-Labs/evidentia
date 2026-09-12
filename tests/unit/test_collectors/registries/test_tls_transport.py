"""Exercise the actual worker-local pin and verified context with synthetic DNS."""

from __future__ import annotations

import socket
import ssl
from typing import Any

import pytest
from evidentia_collectors.registries import _tls
from evidentia_collectors.registries._tls import (
    TransportError,
    approved_destination,
    public_url,
    resolver_addresses,
    tls_context,
)
from evidentia_core import network_guard


def answer(address: str, family: int = socket.AF_INET) -> tuple[Any, ...]:
    return (
        family,
        socket.SOCK_STREAM,
        socket.IPPROTO_TCP,
        "",
        (address, 443) if family == socket.AF_INET else (address, 443, 0, 0),
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org/",
        "https://user@example.org/",
        "https://example.org:444/",
        "https://127.0.0.1/",
        "https://0x7f000001/",
        "https://example.org/#fragment",
        "https://example.org/white space",
        "https://example.org/" + chr(10),
        "https://example.org\\evil/path",
    ],
)
def test_unsafe_destination_syntax_is_refused(url: str) -> None:
    with pytest.raises(TransportError):
        public_url(url)


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [answer("93.184.216.34"), answer("127.0.0.1")],
        [answer("bad")],
        [answer("10.0.0.1")],
        [answer("224.0.0.1")],
        [answer("::1", socket.AF_INET6)],
        [answer("93.184.216.34", socket.AF_INET6)],
        [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", True))],
        [(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2606:4700:4700::1111", 443, 0, 1))],
    ],
    ids=["empty", "mixed", "invalid", "private", "multicast", "loopback-v6", "wrong-family", "bool-port", "zone"],
)
def test_complete_native_resolver_set_must_be_admissible(rows: Any) -> None:
    with pytest.raises(TransportError):
        resolver_addresses(rows)


def test_offline_guard_runs_before_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: calls.append(args))
    with (
        network_guard.offline_mode(),
        pytest.raises(TransportError, match=r"^offline_refused$"),
        approved_destination("https://example.org/"),
    ):
        raise AssertionError("destination unexpectedly admitted")
    assert calls == []


def test_complete_answer_pin_defeats_rebinding_and_restores_outer_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []

    def resolve(*args: Any) -> list[tuple[Any, ...]]:
        calls.append(args)
        return [answer("93.184.216.34"), answer("2606:4700:4700::1111", socket.AF_INET6)]

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", socket.getaddrinfo)
    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with network_guard.offline_mode(False), network_guard.pin_resolved_host("example.org", ["1.1.1.1"]):
        with approved_destination("https://example.org/") as approved:
            actual = socket.getaddrinfo("example.org", 443, socket.AF_UNSPEC, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            assert resolver_addresses(actual) == approved.addresses == ("93.184.216.34", "2606:4700:4700::1111")
        assert socket.getaddrinfo("example.org", 443)[0][4][0] == "1.1.1.1"
    assert len(calls) == 1 and calls[0][0] == b"example.org"


def test_pin_restores_on_original_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", socket.getaddrinfo)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: [answer("93.184.216.34")])
    cancellation = KeyboardInterrupt()
    with network_guard.offline_mode(False), network_guard.pin_resolved_host("example.org", ["1.1.1.1"]):
        with pytest.raises(KeyboardInterrupt) as raised, approved_destination("https://example.org/"):
            raise cancellation
        assert raised.value is cancellation
        assert socket.getaddrinfo("example.org", 443)[0][4][0] == "1.1.1.1"


def test_tls_context_ignores_keylog_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    keylog = tmp_path / "synthetic-keylog.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    context = tls_context()
    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.keylog_filename is None and not keylog.exists()


@pytest.mark.parametrize("trust", ["verified", "untrusted", "wrong-host"])
def test_selector_actual_single_tls_handshake(trust: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    import hashlib
    import threading
    from datetime import UTC, datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic TLS selector")])
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
    pem = certificate.public_bytes(serialization.Encoding.PEM)
    cert_path, key_path = tmp_path / "certificate.pem", tmp_path / "key.pem"
    cert_path.write_bytes(pem)
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        server_context.load_cert_chain(str(cert_path), str(key_path))
    finally:
        key_path.unlink()
    observed_sni: list[str | None] = []
    server_context.set_servername_callback(lambda sock, name, context: observed_sni.append(name))
    keylog = tmp_path / "keylog.txt"
    monkeypatch.setenv("SSLKEYLOGFILE", str(keylog))
    client_context = tls_context()
    if trust != "untrusted":
        client_context.load_verify_locations(cadata=pem.decode("ascii"))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    local_address = listener.getsockname()
    listener.listen(1)
    listener.settimeout(3)

    def serve() -> None:
        try:
            accepted, _ = listener.accept()
            with accepted, server_context.wrap_socket(accepted, server_side=True):
                pass
        except OSError:
            pass
        finally:
            listener.close()

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    original_connect, original_resolve = socket.socket.connect, socket.getaddrinfo
    connections: list[Any] = []
    lookups: list[Any] = []

    def resolve(*args: Any) -> Any:
        lookups.append(args[0])
        assert args[0] == b"example.org"
        return [answer("93.184.216.34"), answer("1.1.1.1")]

    def connect(sock: socket.socket, address: Any) -> None:
        connections.append(address)
        assert address == ("93.184.216.34", 443)
        original_connect(sock, local_address)

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", original_resolve)
    monkeypatch.setattr(socket.socket, "connect", connect)
    monkeypatch.setattr(_tls, "tls_context", lambda: client_context)
    try:
        with network_guard.offline_mode(False), network_guard.pin_resolved_host("example.org", ["9.9.9.9"]):
            attempt = _tls.TLSAttempt()
            if trust == "verified":
                result = attempt.fetch("Example.org.", remaining=lambda: 3.0)
                assert (
                    result["der_sha256"]
                    == hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()
                )
                assert result["protocol"] in {"TLSv1.2", "TLSv1.3"}
                assert result["peer_address"] == "127.0.0.1"
                assert result["certificate"]["subjectAltName"] == [["DNS", "example.org"]]
                assert "notBefore" in result["certificate"] and "notAfter" in result["certificate"]
            else:
                with pytest.raises(TransportError, match=r"^tls_failure$"):
                    attempt.fetch("example.org", remaining=lambda: 3.0)
            assert socket.getaddrinfo("example.org", 443)[0][4][0] == "9.9.9.9"
        assert connections == [("93.184.216.34", 443)] and lookups == [b"example.org"]
        assert observed_sni == ["example.org"] and not attempt.cleanup_failed
        assert not keylog.exists() and client_context.keylog_filename is None
    finally:
        listener.close()
        worker.join(timeout=4)
        assert not worker.is_alive() and not key_path.exists()


@pytest.mark.parametrize("value", [0.0, -1.0, True, float("nan"), float("inf")])
def test_selector_invalid_deadline_precedes_dns(value: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[Any] = []
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: calls.append(args))
    with network_guard.offline_mode(False), pytest.raises(TransportError, match=r"^timeout$"):
        _tls.TLSAttempt().fetch("example.org", remaining=lambda: value)
    assert calls == []


@pytest.fixture
def selector_socket(monkeypatch: pytest.MonkeyPatch) -> Any:
    from contextlib import contextmanager
    from threading import get_ident

    events: list[Any] = []

    class Socket:
        der: bytes = b"synthetic DER"
        handshake_error: BaseException | None = None
        close_error: BaseException | None = None

        def settimeout(self, timeout: float) -> None:
            events.append(("timeout", timeout))

        def connect(self, address: Any) -> None:
            events.append(("connect", address))

        def do_handshake(self) -> None:
            events.append("handshake")
            if self.handshake_error is not None:
                raise self.handshake_error

        def getpeercert(self, *, binary_form: bool = False) -> Any:
            events.append(("certificate", binary_form))
            return self.der if binary_form else {"subject": ((("commonName", "example.org"),),)}

        def cipher(self) -> None:
            return None

        def version(self) -> None:
            return None

        def getpeername(self) -> tuple[str, int]:
            return "93.184.216.34", 443

        def close(self) -> None:
            events.append("close")
            if self.close_error is not None:
                raise self.close_error

    current = Socket()

    class Context:
        def wrap_socket(self, sock: Any, **kwargs: Any) -> Any:
            assert kwargs == {"server_hostname": "example.org", "do_handshake_on_connect": False}
            return sock

    @contextmanager
    def approved(url: str) -> Any:
        yield _tls.ApprovedHost(url, "example.org", ("93.184.216.34", "1.1.1.1"), get_ident())

    monkeypatch.setattr(_tls, "approved_destination", approved)
    monkeypatch.setattr(_tls, "tls_context", Context)
    monkeypatch.setattr(_tls, "_first_socket", lambda approved: (current, (approved.addresses[0], 443)))
    return current, events


@pytest.mark.parametrize("length", [65_536, 65_537])
def test_selector_leaf_limit_precedes_metadata_projection(length: int, selector_socket: Any) -> None:
    current, events = selector_socket
    current.der = b"x" * length
    attempt = _tls.TLSAttempt()
    if length == 65_536:
        assert attempt.fetch("example.org", remaining=lambda: 2.0)["cipher"] is None
        assert ("certificate", False) in events
    else:
        with pytest.raises(TransportError, match=r"^invalid_response$"):
            attempt.fetch("example.org", remaining=lambda: 2.0)
        assert ("certificate", False) not in events
    assert events.count("handshake") == 1 and events.count("close") == 2


def test_selector_preserves_primary_and_late_cleanup_cancellation(selector_socket: Any) -> None:
    current, events = selector_socket
    primary, cleanup = KeyboardInterrupt("synthetic primary"), SystemExit("synthetic cleanup")
    current.handshake_error, current.close_error = primary, cleanup
    with pytest.raises(KeyboardInterrupt) as raised:
        _tls.TLSAttempt().fetch("example.org", remaining=lambda: 2.0)
    assert raised.value is primary and events.count("close") == 2
    current.handshake_error = ssl.SSLError("synthetic TLS failure")
    with pytest.raises(SystemExit) as raised_cleanup:
        _tls.TLSAttempt().fetch("example.org", remaining=lambda: 2.0)
    assert raised_cleanup.value is cleanup
