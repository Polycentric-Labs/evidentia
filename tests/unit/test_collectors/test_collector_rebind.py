"""Per-transport-class DNS-rebinding regression tests (F-V1010-S1).

The v0.10.10 SSRF guard validated the host, then each connecting library
RE-RESOLVED the hostname independently when it opened its socket — so a
low-TTL attacker record could pass validation as public and then rebind to
``169.254.169.254`` / an internal host at connection time. The guard now pins
the validated resolution through the connection (``pin_resolved_host``), so a
re-resolution is forced back to the validated public address.

Each test below drives a resolver that returns a PUBLIC address on the FIRST
(validation) call and a PRIVATE address on the SECOND (connection) call, then
asserts the address the library actually dials is the PUBLIC validated one —
i.e. the rebind is defeated. The socket ``connect`` is stubbed to capture the
dialed address without opening a real socket.

Covered transport classes:
- httpx           via ``BaseSaaSCollector`` (the Vanta subclass; every other
                    BaseSaaSCollector subclass, including the v0.13 batch 7
                    Google Workspace collector, shares the same chokepoint)
- urllib          — via the OCSF URL collector
- psycopg (SQL)   — via the Postgres collector (also asserts the libpq
                    ``hostaddr`` pin)
"""

from __future__ import annotations

import socket
import threading
from typing import Any

import pytest
from evidentia_core import network_guard

PUBLIC_IP = "93.184.216.34"
REBOUND_PRIVATE_IP = "169.254.169.254"  # AWS IMDS — the classic SSRF target

_PRISTINE_GETADDRINFO = socket.getaddrinfo


@pytest.fixture(autouse=True)
def _isolate_pin() -> Any:
    """Reset the process-level pin wrapper + thread-local registry per test."""
    socket.getaddrinfo = _PRISTINE_GETADDRINFO  # type: ignore[assignment]
    network_guard._GETADDRINFO_DELEGATE = _PRISTINE_GETADDRINFO
    if hasattr(network_guard._pin_state, "hosts"):
        network_guard._pin_state.hosts.clear()
    yield
    socket.getaddrinfo = _PRISTINE_GETADDRINFO  # type: ignore[assignment]
    network_guard._GETADDRINFO_DELEGATE = _PRISTINE_GETADDRINFO
    if hasattr(network_guard._pin_state, "hosts"):
        network_guard._pin_state.hosts.clear()


class _RebindingResolver:
    """getaddrinfo stub: PUBLIC on the first call, PRIVATE thereafter."""

    def __init__(self, host: str) -> None:
        self._host = host
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(
        self, host: str, port: Any, *args: Any, **kwargs: Any
    ) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
        if host != self._host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))]
        with self._lock:
            self.calls += 1
            ip = PUBLIC_IP if self.calls == 1 else REBOUND_PRIVATE_IP
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (ip, port))]


class _ConnectReached(Exception):
    """Carries the address the library tried to dial, then aborts the
    connection so no real socket opens."""

    def __init__(self, address: Any) -> None:
        self.address = address
        super().__init__(f"connect to {address!r}")


def _install_connect_capture(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make socket.socket.connect raise _ConnectReached(address).

    httpcore's sync backend + urllib both call ``socket.create_connection``,
    which calls ``getaddrinfo`` (now pinned) then ``sock.connect(sa)``. By
    capturing the connect target we observe exactly which IP the library was
    steered to — the public validated one if the pin held.
    """

    def _fake_connect(self: Any, address: Any) -> None:
        raise _ConnectReached(address)

    monkeypatch.setattr(socket.socket, "connect", _fake_connect)


# ── httpx transport (BaseSaaSCollector via Vanta) ──────────────────────────


def test_httpx_base_collector_rebind_defeated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The validation lookup sees PUBLIC; httpx's connection lookup would see
    PRIVATE, but the pin steers the socket to the PUBLIC validated IP."""
    from evidentia_collectors.vanta import VantaCollector

    host = "rebind-vanta.example"
    resolver = _RebindingResolver(host)
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    _install_connect_capture(monkeypatch)

    collector = VantaCollector(api_token="t", base_url=f"https://{host}")
    # Validation happens in _ensure_client (call 1 -> PUBLIC, passes).
    collector._ensure_client()
    assert collector._pinned_ips == [PUBLIC_IP]

    # The request triggers httpx's connection-time re-resolution. With the
    # pin, the socket is steered to the PUBLIC IP (connect capture fires
    # before any real IO).
    with pytest.raises(Exception) as exc:
        collector._get("/v1/vendors")
    reached = _find_connect_reached(exc.value)
    assert reached is not None, f"no connect captured: {exc.value!r}"
    assert reached.address[0] == PUBLIC_IP
    assert reached.address[0] != REBOUND_PRIVATE_IP
    collector.__exit__(None, None, None)


# ── urllib transport (OCSF URL collector) ──────────────────────────────────


def test_urllib_ocsf_rebind_defeated(monkeypatch: pytest.MonkeyPatch) -> None:
    """OCSF URL ingest: validation sees PUBLIC, urllib's connection lookup
    would see PRIVATE, but the pin steers the socket to the PUBLIC IP."""
    from evidentia_collectors.ocsf.collector import collect_ocsf_url

    host = "rebind-ocsf.example"
    resolver = _RebindingResolver(host)
    monkeypatch.setattr(socket, "getaddrinfo", resolver)
    _install_connect_capture(monkeypatch)

    with pytest.raises(Exception) as exc:
        collect_ocsf_url(f"https://{host}/findings.json")
    reached = _find_connect_reached(exc.value)
    assert reached is not None, f"no connect captured: {exc.value!r}"
    assert reached.address[0] == PUBLIC_IP
    assert reached.address[0] != REBOUND_PRIVATE_IP


def test_urllib_ocsf_single_resolution_is_not_the_only_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: a host that resolves private on the FIRST lookup is still
    refused outright (the single-resolution guard), distinct from the
    rebind case above."""
    from evidentia_collectors.ocsf.collector import (
        OCSFIngestError,
        collect_ocsf_url,
    )

    def _always_private(host: str, port: Any, *a: Any, **k: Any) -> Any:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                (REBOUND_PRIVATE_IP, port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _always_private)
    with pytest.raises(OCSFIngestError) as exc:
        collect_ocsf_url("https://metadata.example/findings.json")
    assert "SSRF policy" in str(exc.value)


# ── psycopg transport (Postgres collector) ─────────────────────────────────


def test_postgres_psycopg_rebind_defeated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Postgres: validation sees PUBLIC; the libpq hostaddr pin forces the
    connection to the PUBLIC validated IP. We assert the hostaddr kwarg is
    set to the validated public IP AND that no rebound private IP leaks in
    via a re-resolution (the getaddrinfo pin backs it up)."""
    import psycopg
    from evidentia_collectors.sql.postgres import (
        PostgresCollector,
        PostgresConnectionError,
    )

    host = "rebind-pg.example"
    resolver = _RebindingResolver(host)
    monkeypatch.setattr(socket, "getaddrinfo", resolver)

    captured: dict[str, Any] = {}

    def _fake_connect(conninfo: str, **kwargs: Any) -> Any:
        captured["conninfo"] = conninfo
        captured["kwargs"] = kwargs
        # Prove what a re-resolution inside the driver would now return:
        # under the pin it must be the PUBLIC IP, not the rebound private.
        infos = socket.getaddrinfo(host, 5432)
        captured["redial_ips"] = {info[4][0] for info in infos}
        raise _ConnectReached((kwargs.get("hostaddr"), 5432))

    monkeypatch.setattr(psycopg, "connect", _fake_connect)

    collector = PostgresCollector(connection_uri=f"postgresql://reader@{host}:5432/app", password="pw")
    with pytest.raises(PostgresConnectionError):
        collector._ensure_connected()

    # libpq hostaddr pin: dial the validated public IP directly.
    assert captured["kwargs"].get("hostaddr") == PUBLIC_IP
    # getaddrinfo resolution pin: a re-resolution under the pin is forced
    # back to the public IP (the rebind is defeated even for the driver's
    # own lookups).
    assert captured["redial_ips"] == {PUBLIC_IP}
    assert REBOUND_PRIVATE_IP not in captured["redial_ips"]


def test_postgres_multi_ip_rebind_defeated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Postgres multi-IP: a host resolving to MULTIPLE public A records is
    still pinned via the libpq ``hostaddr`` param. psycopg's binary libpq
    resolves in C and bypasses the Python getaddrinfo pin, so the prior
    ``len == 1`` hostaddr guard left a multi-A host re-resolving in libpq —
    the residual the v0.10.10 adversarial review caught. hostaddr must be a
    VALIDATED PUBLIC IP, never the rebound private one."""
    import psycopg
    from evidentia_collectors.sql.postgres import (
        PostgresCollector,
        PostgresConnectionError,
    )

    host = "rebind-pg-multi.example"
    public_ip_2 = "93.184.216.35"
    calls = {"n": 0}

    def _multi_then_private(h: str, port: Any, *a: Any, **k: Any) -> list[tuple[int, int, int, str, tuple[Any, ...]]]:
        if h != host:
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port))]
        calls["n"] += 1
        if calls["n"] == 1:
            # validation lookup: two public A records
            return [
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (PUBLIC_IP, port)),
                (socket.AF_INET, socket.SOCK_STREAM, 0, "", (public_ip_2, port)),
            ]
        # any re-resolution rebinds to the private metadata IP
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (REBOUND_PRIVATE_IP, port))]

    monkeypatch.setattr(socket, "getaddrinfo", _multi_then_private)

    captured: dict[str, Any] = {}

    def _fake_connect(conninfo: str, **kwargs: Any) -> Any:
        captured["kwargs"] = kwargs
        raise _ConnectReached((kwargs.get("hostaddr"), 5432))

    monkeypatch.setattr(psycopg, "connect", _fake_connect)

    collector = PostgresCollector(connection_uri=f"postgresql://reader@{host}:5432/app", password="pw")
    with pytest.raises(PostgresConnectionError):
        collector._ensure_connected()

    # hostaddr is pinned to a VALIDATED PUBLIC IP for the multi-IP case too,
    # never the rebound private metadata address.
    assert captured["kwargs"].get("hostaddr") in {PUBLIC_IP, public_ip_2}
    assert captured["kwargs"].get("hostaddr") != REBOUND_PRIVATE_IP


def test_postgres_single_resolution_still_refuses_private(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Control: a Postgres host that resolves private on the first lookup is
    refused (the single-resolution guard remains intact)."""
    from evidentia_collectors.sql.postgres import (
        PostgresCollector,
        PostgresConnectionError,
    )

    def _always_private(host: str, port: Any, *a: Any, **k: Any) -> Any:
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                0,
                "",
                (REBOUND_PRIVATE_IP, port),
            )
        ]

    monkeypatch.setattr(socket, "getaddrinfo", _always_private)
    collector = PostgresCollector(
        connection_uri="postgresql://reader@metadata.example:5432/app",
        password="pw",
    )
    with pytest.raises(PostgresConnectionError) as exc:
        collector._ensure_connected()
    assert "SSRF policy" in str(exc.value)


# ── helpers ─────────────────────────────────────────────────────────────


def _find_connect_reached(exc: BaseException) -> _ConnectReached | None:
    """Walk an exception's __cause__/__context__ chain for _ConnectReached."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, _ConnectReached):
            return cur
        cur = cur.__cause__ or cur.__context__
    return None
