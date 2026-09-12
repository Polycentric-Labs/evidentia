"""Retain native resources and distinguish retryable HTTP operation failures."""

from __future__ import annotations

import socket
from datetime import UTC, datetime
from typing import Any, cast

import httpcore
import httpx
import pytest
from evidentia_collectors.registries import _client, _http_backend
from evidentia_collectors.registries._contracts import LEITarget
from evidentia_collectors.registries._tls import ApprovedHost, TransportError, tls_context
from evidentia_core import network_guard


@pytest.mark.parametrize("slot", ["available", "requested"])
def test_timeout_type_guard_refuses_foreign_values_without_callbacks(slot: str) -> None:
    calls: list[str] = []

    class Meta(type):
        def __eq__(cls, other: object) -> bool:
            calls.append("equality")
            return False

    class Value(metaclass=Meta):
        pass

    value = cast(float, Value())
    state = _http_backend.OwnedState(lambda: value if slot == "available" else 20.0)
    with pytest.raises(TransportError, match="timeout" if slot == "available" else "invalid_response"):
        state.timeout(5.0, value if slot == "requested" else 2.0)
    assert not calls


@pytest.mark.parametrize("cleanup_cancel", [False, True])
def test_native_connect_cancellation_keeps_primary_and_closes_descriptor(
    monkeypatch: pytest.MonkeyPatch, cleanup_cancel: bool
) -> None:
    primary = KeyboardInterrupt("synthetic connect cancellation")
    secondary: BaseException = (
        SystemExit("synthetic cleanup cancellation") if cleanup_cancel else OSError("synthetic cleanup")
    )
    sockets: list[socket.socket] = []

    class CancelledSocket(socket.socket):
        def connect(self, address: Any) -> None:
            raise primary

        def close(self) -> None:
            super().close()
            raise secondary

    def first(approved: ApprovedHost) -> tuple[socket.socket, tuple[Any, ...]]:
        raw = CancelledSocket()
        sockets.append(raw)
        return raw, ("93.184.216.34", 443)

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", socket.getaddrinfo)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr(_http_backend, "_first_socket", first)
    attempt = _client.HttpAttempt()
    with network_guard.offline_mode(False), pytest.raises(KeyboardInterrupt) as raised:
        attempt.fetch("https://example.org/source", remaining=lambda: 30.0, consume=lambda *_: None)
    assert raised.value is primary and attempt.cleanup_failed
    assert len(sockets) == 1 and sockets[0].fileno() == -1


@pytest.mark.parametrize("operation", ["read", "write"])
def test_native_operation_timeouts_keep_their_retry_class(operation: str) -> None:
    class TimedOutSocket(socket.socket):
        def recv(self, buffersize: int, flags: int = 0) -> bytes:
            raise TimeoutError("synthetic read timeout")

        def send(self, data: Any, flags: int = 0) -> int:
            raise TimeoutError("synthetic write timeout")

    raw = TimedOutSocket()
    state = _http_backend.OwnedState(lambda: 30.0)
    stream = _http_backend.OwnedStream(raw, cast(ApprovedHost, None), tls_context(), state)
    try:
        if operation == "read":
            with pytest.raises(httpcore.ReadTimeout, match="timeout"):
                stream.read(64)
        else:
            with pytest.raises(httpcore.WriteTimeout, match="connection_failure"):
                stream.write(b"GET / HTTP/1.1\r\n\r\n")
    finally:
        state.close_all()
    assert raw.fileno() == -1


@pytest.mark.parametrize("failure", [httpx.WriteTimeout, httpx.PoolTimeout])
def test_session_does_not_retry_write_or_pool_timeout(
    monkeypatch: pytest.MonkeyPatch, failure: type[httpx.TimeoutException]
) -> None:
    sent: list[httpx.Request] = []

    def send(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        raise failure("synthetic operation timeout")

    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", socket.getaddrinfo)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args: [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443))],
    )
    monkeypatch.setattr(_client, "_http_transport", lambda context, approved, owned: httpx.MockTransport(send))
    target = LEITarget(lei="A" * 20)
    current = _client.RegistryReadSession(
        {"registry": "gleif", "target": target},
        _utc=lambda: datetime(2026, 9, 11, 12, tzinfo=UTC),
        _monotonic=lambda: 0.0,
        _sleep=lambda delay: pytest.fail("non-retryable timeout scheduled another attempt"),
    )
    with network_guard.offline_mode(False):
        result = current.read_gleif(target, lambda value: pytest.fail("timeout projected a record"))
    assert len(sent) == result.source_reads[0].network_attempts == 1
    assert result.diagnostics[0].code == "connection_failure" and not result.observations
