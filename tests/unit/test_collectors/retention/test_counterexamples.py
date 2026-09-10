"""Independent synthetic counterexamples for the bounded storage client."""

from __future__ import annotations

import gzip
import importlib
import socket
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

client = importlib.import_module("evidentia_collectors.retention._client")
contracts = importlib.import_module("evidentia_collectors.retention._contracts")
materials = importlib.import_module("evidentia_collectors.retention._credentials")


class Clock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def tick(self) -> float:
        return self.value

    def utc(self) -> datetime:
        return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=self.value)

    def sleep(self, duration: float) -> None:
        self.sleeps.append(duration)
        self.value += duration


class Provider:
    def __init__(self, clock: Clock, expires: float | None = None) -> None:
        expiry = None if expires is None else clock.utc() + timedelta(seconds=expires)
        self.material = materials.BearerCredentials("SYNTHETIC_BEARER", expiry)
        self.calls = 0
        self.callback: Callable[[], None] = lambda: None

    def resolve(self, provider: str) -> Any:
        assert provider == "gcs"
        self.calls += 1
        self.callback()
        return materials.CredentialResolution(self.material, None)


class Stream(httpx.SyncByteStream):
    def __init__(self, chunks: list[bytes], callback: Callable[[], None] | None = None) -> None:
        self.chunks = chunks
        self.callback = callback
        self.closed = 0

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self.chunks:
            if self.callback is not None:
                self.callback()
            yield chunk

    def close(self) -> None:
        self.closed += 1


class Wire(httpx.BaseTransport):
    def __init__(self, clock: Clock) -> None:
        self.clock = clock
        self.requests: list[httpx.Request] = []
        self.send_times: list[float] = []
        self.streams: list[Stream] = []
        self.statuses = [200]
        self.bodies = [b"{}"]
        self.response_headers: dict[str, str] = {}
        self.callback: Callable[[int], None] = lambda index: None
        self.chunk_callback: Callable[[], None] | None = None
        self.closed = 0
        self.addresses: list[list[str]] = []

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        self.send_times.append(self.clock.value)
        self.addresses.append([str(row[4][0]) for row in socket.getaddrinfo(request.url.host, 443)])
        index = len(self.requests) - 1
        self.callback(index)
        status = self.statuses[min(index, len(self.statuses) - 1)]
        body = self.bodies[min(index, len(self.bodies) - 1)]
        stream = Stream([body], self.chunk_callback)
        self.streams.append(stream)
        return httpx.Response(status, headers=self.response_headers, stream=stream)

    def close(self) -> None:
        self.closed += 1


@pytest.fixture
def setup(monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable[..., tuple[Any, Wire, Provider, Clock]]]:
    sessions = []
    guard = client.network_guard
    monkeypatch.setattr(guard, "_GETADDRINFO_DELEGATE", guard._GETADDRINFO_DELEGATE)
    monkeypatch.setattr(guard, "_offline_enabled", False)
    monkeypatch.setattr(guard, "enforce_public_host", lambda *args, **kwargs: ["8.8.8.8"])

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("External DNS or socket use is forbidden in this test")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)

    def make(*, factory_seconds: float = 0, expires: float | None = None) -> tuple[Any, Wire, Provider, Clock]:
        clock = Clock()
        provider = Provider(clock, expires)
        wire = Wire(clock)

        def factory() -> httpx.BaseTransport:
            clock.value += factory_seconds
            return wire

        value = client.StorageReadSession(
            {
                "provider": "gcs",
                "scope_label": "synthetic",
                "targets": [{"bucket": "original-example"}, {"bucket": "second-example"}],
            },
            credentials=provider,
            transport_factory=factory,
            utc_clock=clock.utc,
            monotonic_clock=clock.tick,
            sleep=clock.sleep,
            run_id_factory=lambda: "SYNTHETIC_RUN",
        )
        sessions.append(value)
        return value, wire, provider, clock

    yield make
    for value in sessions:
        value.close()


def project(response: Any, target: Any) -> Any:
    return contracts.ProjectedComponent("synthetic-v1", "configuration", {"observed": True})


def read(value: Any, target: Any = None) -> Any:
    if target is None:
        target = value.context.request.root.targets[0]
    return value.read_component("gcs-bucket", target, project)


def code_list(result: Any) -> list[str]:
    return [diagnostic.code for diagnostic in result.diagnostics]


def test_target_mutation_during_retry_cannot_change_selected_resource(setup: Callable[..., Any]) -> None:
    value, wire, _, _ = setup()
    target = value.context.request.root.targets[0]
    wire.statuses = [500, 200]

    def mutate(index: int) -> None:
        if index == 0:
            target.bucket = "outside-example"

    wire.callback = mutate
    result = read(value, target)
    assert result.status == "complete"
    assert len(wire.requests) == 2
    assert all(request.url.path.endswith("/original-example") for request in wire.requests), (
        "A retry must use the selected detached target"
    )


def test_timeout_recomputed_after_slow_transport_factory(setup: Callable[..., Any]) -> None:
    value, wire, _, _ = setup(factory_seconds=119)
    result = read(value)
    assert result.status == "complete"
    assert len(wire.requests) == 1
    remaining_at_send = 120 - wire.send_times[0]
    assert max(wire.requests[0].extensions["timeout"].values()) <= remaining_at_send, (
        "Timeouts must fit the remaining budget at send"
    )


def test_known_expiry_rechecked_after_slow_transport_factory(setup: Callable[..., Any]) -> None:
    value, wire, _, _ = setup(factory_seconds=2, expires=1)
    result = read(value)
    assert wire.requests == [], "Known expired credentials must not be sent"
    assert result.status == "unavailable"


def test_exact_deadline_during_factory_prevents_send_and_closes(setup: Callable[..., Any]) -> None:
    value, wire, _, _ = setup(factory_seconds=120)
    result = read(value)
    assert wire.requests == []
    assert code_list(result) == ["run_budget_exhausted"]
    value.close()
    assert wire.closed == 1


def test_actual_send_holds_pin_against_rebinding(setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch) -> None:
    value, wire, _, _ = setup()
    delegated = []

    def rebound(host: str, port: Any, *args: Any, **kwargs: Any) -> Any:
        delegated.append(host)
        return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", rebound)
    result = read(value)
    assert result.status == "complete"
    assert wire.addresses == [["8.8.8.8"]]
    assert delegated == []
    assert socket.getaddrinfo("storage.googleapis.com", 443)[0][4][0] == "169.254.169.254"
    assert delegated == ["storage.googleapis.com"]


@pytest.mark.parametrize("cut", [1, 7, 31])
def test_fragmented_gzip_run_overshoot_counts_delivered_chunks(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, cut: int
) -> None:
    value, wire, _, _ = setup()
    payload = b'{"value":"' + b"x" * 200 + b'"}'
    raw = gzip.compress(payload, mtime=0)
    wire.bodies = [raw]
    wire.response_headers = {"Content-Encoding": "gzip"}
    monkeypatch.setattr(client, "RUN_MAX_BYTES", len(payload) - cut)
    result = read(value)
    assert result.projection is None
    assert result.status == "unavailable"
    assert "run_budget_exhausted" in code_list(result)
    assert result.raw_bytes == len(raw)
    assert result.decoded_bytes == len(payload)
    assert value.context.decoded_bytes == len(payload)
    assert wire.streams[0].closed == 1


def test_response_read_deadline_refuses_projection_and_closes(setup: Callable[..., Any]) -> None:
    value, wire, _, clock = setup()
    wire.chunk_callback = lambda: setattr(clock, "value", 120)
    result = read(value)
    assert code_list(result) == ["run_budget_exhausted"]
    assert result.raw_bytes == result.decoded_bytes == 2
    assert result.projection is None
    assert wire.streams[0].closed == 1


def test_credential_snapshot_is_detached_between_components(setup: Callable[..., Any]) -> None:
    value, wire, provider, _ = setup()
    first = read(value)
    object.__setattr__(provider.material, "token", "DIFFERENT_SYNTHETIC_BEARER")
    second = read(value, value.context.request.root.targets[1])
    assert first.status == second.status == "complete"
    assert provider.calls == 1
    assert wire.requests[0].headers["authorization"] == wire.requests[1].headers["authorization"]


def test_invalid_retry_metadata_never_sends_again(setup: Callable[..., Any]) -> None:
    value, wire, _, clock = setup()
    wire.statuses = [503, 200]
    wire.response_headers = {"Retry-After": "31"}
    result = read(value)
    assert result.status == "unavailable" and result.projection is None
    assert len(wire.requests) == 1 and clock.sleeps == []
    assert wire.streams[0].closed == 1
