"""Owned Graph HTTP transport uses the real DNS guard and pin before sockets."""

from __future__ import annotations

import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest
from evidentia_collectors.entra_m365 import _client as client
from evidentia_collectors.entra_m365 import _contracts as contracts
from evidentia_core import network_guard

HOST = "graph.microsoft.com"
PUBLIC_IP = "93.184.216.34"
PRIVATE_IP = "169.254.169.254"
NOW = datetime(2026, 9, 10, tzinfo=UTC)


class _ConnectCaptured(RuntimeError):
    """A synthetic stop after capturing the target, before connection."""


@dataclass
class _Probe:
    first_ip: str = PUBLIC_IP
    resolutions: list[tuple[object, object]] = field(default_factory=list)
    addresses: list[tuple[Any, ...]] = field(default_factory=list)
    sockets: list[socket.socket] = field(default_factory=list)
    requests: list[tuple[str, str, str]] = field(default_factory=list)
    transport_options: list[dict[str, Any]] = field(default_factory=list)
    closed_transports: list[httpx.HTTPTransport] = field(default_factory=list)

    def resolve(self, host: object, port: object, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        assert host == HOST, "Unexpected host must not reach a resolver"
        self.resolutions.append((host, port))
        address = self.first_ip if len(self.resolutions) == 1 else PRIVATE_IP
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (address, port))]


@pytest.fixture
def wire_probe(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Probe]:
    """Restore resolver, delegate and pin registry using one function-scoped patch."""
    probe = _Probe()
    original_init = httpx.HTTPTransport.__init__
    original_handle = httpx.HTTPTransport.handle_request
    original_close = httpx.HTTPTransport.close

    def capture_connect(sock: socket.socket, address: tuple[Any, ...]) -> None:
        probe.addresses.append(address)
        probe.sockets.append(sock)
        sock.close()
        raise _ConnectCaptured("synthetic connection intercepted")

    def refuse_connect_ex(sock: socket.socket, address: tuple[Any, ...]) -> int:
        sock.close()
        raise AssertionError("Unexpected connect_ex path was refused")

    def record_init(transport: httpx.HTTPTransport, *args: Any, **kwargs: Any) -> None:
        probe.transport_options.append(dict(kwargs))
        original_init(transport, *args, **kwargs)

    def record_handle(transport: httpx.HTTPTransport, request: httpx.Request) -> httpx.Response:
        probe.requests.append((request.method, request.url.host, request.url.path))
        return original_handle(transport, request)

    def record_close(transport: httpx.HTTPTransport) -> None:
        probe.closed_transports.append(transport)
        original_close(transport)

    monkeypatch.setattr(socket, "getaddrinfo", probe.resolve)
    monkeypatch.setattr(socket.socket, "connect", capture_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse_connect_ex)
    monkeypatch.setattr(network_guard, "_GETADDRINFO_DELEGATE", probe.resolve)
    monkeypatch.setattr(network_guard, "_pin_state", threading.local())
    monkeypatch.setattr(network_guard, "_offline_enabled", False)
    monkeypatch.setattr(httpx.HTTPTransport, "__init__", record_init)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", record_handle)
    monkeypatch.setattr(httpx.HTTPTransport, "close", record_close)
    yield probe


@dataclass
class _Credentials:
    calls: list[client.CredentialGroup] = field(default_factory=list)

    def resolve(self, group: client.CredentialGroup) -> client._CredentialResolution:
        self.calls.append(group)
        return client._CredentialResolution(token="SYNTHETIC_OWNED_READER", declared_auth_mode="application")


def _context() -> tuple[contracts.EntraM365CollectRequest, contracts.EntraM365RunContext]:
    request = contracts.EntraM365CollectRequest(tenant_label="synthetic-owned", capabilities=["conditional-access"])
    context = contracts.EntraM365RunContext.start(
        request,
        utc_clock=lambda: NOW,
        monotonic_clock=lambda: 0.0,
        sleep=lambda _seconds: None,
        run_id_factory=lambda: "synthetic-owned-transport-run",
    )
    return request, context


def test_owned_graph_http_transport_pins_validated_public_address(wire_probe: _Probe) -> None:
    credentials = _Credentials()
    request, context = _context()
    reader = client.EntraM365GraphReader(credentials=credentials, client=None)
    assert reader._client is None and reader._owned is True
    try:
        source = reader.read_collection("conditional-access", request, context)
        assert wire_probe.requests == [("GET", HOST, "/v1.0/identity/conditionalAccess/policies")]
        assert wire_probe.addresses == [(PUBLIC_IP, 443)]
        assert len(wire_probe.resolutions) == 1
        assert credentials.calls == ["primary"]
        assert source.capability.state == "unavailable"
        assert source.capability.requests_attempted == 1 and source.capability.pages_completed == 0
        assert [diagnostic.code for diagnostic in source.capability.diagnostics] == ["internal_error"]
        assert all(sock.fileno() == -1 for sock in wire_probe.sockets)
        assert getattr(network_guard._pin_state, "hosts", {}) == {}
        # The next unpinned lookup really would return the private address.
        assert socket.getaddrinfo(HOST, 443)[0][4][0] == PRIVATE_IP
        assert len(wire_probe.resolutions) == 2
        assert reader._client is not None and not reader._client.is_closed
        assert isinstance(reader._client._transport, httpx.HTTPTransport)
        assert reader._client.trust_env is False
        assert reader._client.follow_redirects is False
        assert not any(reader._client._mounts.values())
        assert wire_probe.transport_options == [{"trust_env": False, "http2": False, "retries": 0}]
        assert len(reader._states) == 1
    finally:
        reader.close()
    assert reader._client is not None and reader._client.is_closed
    assert len(wire_probe.closed_transports) == 1
    assert len(reader._states) == 0
    reader.close()
    assert len(wire_probe.closed_transports) == 1
    with pytest.raises(ValueError, match="invalid_collection_request"):
        reader.read_collection("conditional-access", request, context)
    assert credentials.calls == ["primary"] and len(wire_probe.resolutions) == 2


def test_private_first_resolution_refuses_before_credentials_or_transport(wire_probe: _Probe) -> None:
    wire_probe.first_ip = PRIVATE_IP
    credentials = _Credentials()
    request, context = _context()
    reader = client.EntraM365GraphReader(credentials=credentials, client=None)
    try:
        source = reader.read_collection("conditional-access", request, context)
        assert source.capability.state == "unavailable"
        assert source.capability.declared_auth_mode is None
        assert source.capability.requests_attempted == source.capability.pages_completed == 0
        assert [diagnostic.code for diagnostic in source.capability.diagnostics] == ["unsafe_destination"]
        assert credentials.calls == []
        assert len(wire_probe.resolutions) == 1
        assert wire_probe.requests == []
        assert wire_probe.addresses == []
        assert wire_probe.transport_options == []
        assert reader._client is None
    finally:
        reader.close()
    assert wire_probe.closed_transports == [] and len(reader._states) == 0


def test_rebinding_fixture_detects_unpinned_second_lookup(wire_probe: _Probe) -> None:
    assert network_guard.enforce_public_host("https://" + HOST, subsystem="entra-m365") == [PUBLIC_IP]
    unpinned = httpx.Client(trust_env=False, http2=False)
    try:
        with pytest.raises(_ConnectCaptured):
            unpinned.get("https://" + HOST + "/v1.0/identity/conditionalAccess/policies")
    finally:
        unpinned.close()
    assert wire_probe.addresses == [(PRIVATE_IP, 443)]
    assert len(wire_probe.resolutions) == 2
    assert all(sock.fileno() == -1 for sock in wire_probe.sockets)
    assert unpinned.is_closed and len(wire_probe.closed_transports) == 1


def test_closing_unused_owned_reader_allocates_no_transport(wire_probe: _Probe) -> None:
    credentials = _Credentials()
    reader = client.EntraM365GraphReader(credentials=credentials, client=None)
    reader.close()
    reader.close()
    assert reader._client is None
    assert credentials.calls == []
    assert wire_probe.resolutions == []
    assert wire_probe.addresses == []
    assert wire_probe.transport_options == []
    assert wire_probe.closed_transports == []
