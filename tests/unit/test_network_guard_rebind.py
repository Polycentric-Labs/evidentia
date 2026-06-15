"""DNS-rebinding (TOCTOU) regression tests for the SSRF guard's pin.

Finding F-V1010-S1: ``enforce_public_host`` validated the host, then every
connecting library (httpx, urllib, the SQL drivers, the SDKs) re-resolved the
SAME hostname independently when it opened its socket. A low-TTL attacker DNS
record could pass validation as public and then re-resolve to
``169.254.169.254`` (cloud-metadata) or an internal host at connection time —
the validated IP was NOT pinned to the connection.

These tests drive a resolver that returns a PUBLIC address on the FIRST
(validation) call and a PRIVATE address (169.254.169.254) on the SECOND
(connection) call, then assert the connection is forced to the PUBLIC
validated address — i.e. the rebind is defeated.

They are hermetic: ``socket.getaddrinfo`` is the only resolution seam and is
driven by an in-test stub. No real DNS / sockets.
"""

from __future__ import annotations

import socket
import threading
from typing import Any

import pytest
from evidentia_core import network_guard
from evidentia_core.network_guard import (
    enforce_public_host,
    pin_resolved_host,
)

PUBLIC_IP = "93.184.216.34"
REBOUND_PRIVATE_IP = "169.254.169.254"  # AWS IMDS — the classic SSRF target
REBIND_HOST = "rebind.evil.example"

# The pristine OS resolver, captured before any test can wrap it. The
# isolation fixture restores socket.getaddrinfo to this between tests so the
# process-level pin wrapper installed by one test cannot bleed into another.
_PRISTINE_GETADDRINFO = socket.getaddrinfo


class _RebindingResolver:
    """A getaddrinfo stub that flips PUBLIC -> PRIVATE after the first call.

    Models a low-TTL attacker record: the validation lookup sees the public
    address; the connection lookup sees the rebound private address.
    """

    def __init__(self, host: str, first_ip: str, later_ip: str) -> None:
        self._host = host
        self._first_ip = first_ip
        self._later_ip = later_ip
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(
        self, host: str, port: Any, *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
        if host != self._host:
            # Unrelated host — resolve to a stable public address so any
            # incidental lookup in the block doesn't blow up the test.
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))
            ]
        with self._lock:
            self.calls += 1
            ip = self._first_ip if self.calls == 1 else self._later_ip
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port))]


@pytest.fixture(autouse=True)
def _restore_getaddrinfo() -> Any:
    """Force a clean resolver + empty pin registry around every test.

    ``pin_resolved_host`` installs a process-level wrapper that re-binds
    ``socket.getaddrinfo`` to the module's pinning shim and records the
    function it replaced as the delegate. Left in place, that wrapper (and
    a stale delegate) would bleed into the next test. We pin the resolver
    back to the pristine OS resolver, reset the module's delegate, and
    clear any thread-local pin state — before AND after each test.
    """
    socket.getaddrinfo = _PRISTINE_GETADDRINFO  # type: ignore[assignment]
    network_guard._GETADDRINFO_DELEGATE = _PRISTINE_GETADDRINFO
    if hasattr(network_guard._pin_state, "hosts"):
        network_guard._pin_state.hosts.clear()
    yield
    socket.getaddrinfo = _PRISTINE_GETADDRINFO  # type: ignore[assignment]
    network_guard._GETADDRINFO_DELEGATE = _PRISTINE_GETADDRINFO
    if hasattr(network_guard._pin_state, "hosts"):
        network_guard._pin_state.hosts.clear()


def test_enforce_public_host_returns_validated_public_ips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard returns the validated public IPs so callers can pin them."""

    def _fake(host: str, port: Any, *a: Any, **k: Any) -> Any:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port)),
            # Duplicate to prove de-duplication.
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _fake)
    validated = enforce_public_host(
        f"https://{REBIND_HOST}/v1", subsystem="test"
    )
    assert validated == [PUBLIC_IP]


def test_enforce_public_host_opt_out_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """block_private=False validates nothing, so there is nothing to pin."""

    def _boom(*_a: Any, **_k: Any) -> Any:  # pragma: no cover - must not run
        raise AssertionError("opt-out must not resolve")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    assert (
        enforce_public_host(
            f"https://{REBIND_HOST}/v1",
            subsystem="test",
            block_private=False,
        )
        == []
    )


def test_pin_forces_connection_to_validated_public_ip(
    monkeypatch: pytest.MonkeyPatch, _restore_getaddrinfo: Any
) -> None:
    """THE rebind defeat: validate sees PUBLIC, connect would see PRIVATE,
    but the pin forces the connection lookup back to the PUBLIC address."""
    resolver = _RebindingResolver(
        REBIND_HOST, first_ip=PUBLIC_IP, later_ip=REBOUND_PRIVATE_IP
    )
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    validated = enforce_public_host(
        f"https://{REBIND_HOST}/v1", subsystem="test"
    )
    assert validated == [PUBLIC_IP]
    assert resolver.calls == 1  # validation lookup

    with pin_resolved_host(REBIND_HOST, validated):
        # This is the lookup the connecting library would do. Without the
        # pin it returns the rebound private IP; with the pin it returns
        # the validated public IP.
        infos = socket.getaddrinfo(REBIND_HOST, 443)
        dialed = {info[4][0] for info in infos}

    assert dialed == {PUBLIC_IP}
    assert REBOUND_PRIVATE_IP not in dialed


def test_pin_synthesizes_requested_port(
    monkeypatch: pytest.MonkeyPatch, _restore_getaddrinfo: Any
) -> None:
    """The pin returns addrinfo for the PORT the connection asks for, not
    the port-less validation lookup."""
    resolver = _RebindingResolver(
        REBIND_HOST, first_ip=PUBLIC_IP, later_ip=REBOUND_PRIVATE_IP
    )
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    validated = enforce_public_host(REBIND_HOST, subsystem="test")

    with pin_resolved_host(REBIND_HOST, validated):
        infos = socket.getaddrinfo(REBIND_HOST, 5432, 0, socket.SOCK_STREAM)
    ports = {info[4][1] for info in infos}
    assert ports == {5432}


def test_pin_only_affects_registered_host(
    monkeypatch: pytest.MonkeyPatch, _restore_getaddrinfo: Any
) -> None:
    """An un-pinned host inside the block still delegates to the real
    resolver (the wrapper is a transparent pass-through)."""
    resolver = _RebindingResolver(
        REBIND_HOST, first_ip=PUBLIC_IP, later_ip=REBOUND_PRIVATE_IP
    )
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    validated = enforce_public_host(REBIND_HOST, subsystem="test")

    with pin_resolved_host(REBIND_HOST, validated):
        other = socket.getaddrinfo("other.example", 443)
    # other.example is not pinned -> real resolver answered (public stub).
    assert {info[4][0] for info in other} == {PUBLIC_IP}


def test_pin_is_thread_local(
    monkeypatch: pytest.MonkeyPatch, _restore_getaddrinfo: Any
) -> None:
    """A pin set on one thread must NOT leak resolution onto another."""
    resolver = _RebindingResolver(
        REBIND_HOST, first_ip=PUBLIC_IP, later_ip=REBOUND_PRIVATE_IP
    )
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    validated = enforce_public_host(REBIND_HOST, subsystem="test")

    other_thread_result: dict[str, set[str]] = {}
    started = threading.Event()
    release = threading.Event()

    def _worker() -> None:
        started.set()
        release.wait(timeout=5)
        # No pin on THIS thread -> the wrapper delegates to the rebinding
        # resolver, which (now past its first call) returns the private IP.
        infos = socket.getaddrinfo(REBIND_HOST, 443)
        other_thread_result["ips"] = {info[4][0] for info in infos}

    t = threading.Thread(target=_worker)
    with pin_resolved_host(REBIND_HOST, validated):
        t.start()
        started.wait(timeout=5)
        release.set()
        t.join(timeout=5)
        # On the pinning thread the lookup is forced public.
        mine = {info[4][0] for info in socket.getaddrinfo(REBIND_HOST, 443)}

    assert mine == {PUBLIC_IP}
    # The other thread saw the (rebound) resolver result, NOT the pin.
    assert other_thread_result["ips"] == {REBOUND_PRIVATE_IP}


def test_unresolvable_host_pin_is_noop_when_empty(
    monkeypatch: pytest.MonkeyPatch, _restore_getaddrinfo: Any
) -> None:
    """An empty pin list is a no-op: the wrapper isn't consulted and the
    real resolver answers (covers the opt-out passthrough)."""

    def _fake(host: str, port: Any, *a: Any, **k: Any) -> Any:
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake)
    with pin_resolved_host(REBIND_HOST, []):
        infos = socket.getaddrinfo(REBIND_HOST, 443)
    assert {info[4][0] for info in infos} == {PUBLIC_IP}


def test_rebind_without_pin_would_succeed_control(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control case proving the resolver actually rebinds: validate sees
    PUBLIC (passes), a second bare resolution sees PRIVATE — exactly the
    bypass the pin closes."""
    resolver = _RebindingResolver(
        REBIND_HOST, first_ip=PUBLIC_IP, later_ip=REBOUND_PRIVATE_IP
    )
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    # First call: validation passes (public).
    enforce_public_host(REBIND_HOST, subsystem="test")
    # Second call (no pin): the rebind has flipped to the private IP.
    second = socket.getaddrinfo(REBIND_HOST, 443)
    assert {info[4][0] for info in second} == {REBOUND_PRIVATE_IP}


def test_exported_symbol() -> None:
    assert "pin_resolved_host" in network_guard.__all__
