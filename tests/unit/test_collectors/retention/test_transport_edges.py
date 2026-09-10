"""Additional transport ownership and malformed redirect controls."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest

from .test_counterexamples import code_list, contracts, project, read
from .test_counterexamples import setup as setup


@pytest.mark.parametrize("location", ["http://[", "http://example.com:wrong", "\x00"])
def test_malformed_redirect_stays_redirect_refused(setup: Callable[..., Any], location: str) -> None:
    value, wire, _, clock = setup()
    wire.statuses = [307]
    wire.response_headers = {"Location": location}
    result = read(value)
    assert code_list(result) == ["redirect_refused"], "Every 3xx remains an explicit redirect refusal"
    assert len(wire.requests) == 1 and clock.sleeps == []
    assert wire.streams[0].closed == 1


class InterruptStream(httpx.SyncByteStream):
    def __init__(self, exception: BaseException) -> None:
        self.exception = exception
        self.closed = 0

    def __iter__(self) -> Iterator[bytes]:
        yield b"ab"
        raise self.exception

    def close(self) -> None:
        self.closed += 1


def test_partial_read_timeout_charges_failed_prefix_and_retries(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    value, wire, provider, clock = setup()
    interrupted = InterruptStream(httpx.ReadTimeout("synthetic read timeout"))
    original = wire.handle_request

    def send(request: httpx.Request) -> httpx.Response:
        response = original(request)
        if len(wire.requests) == 1:
            response.stream = interrupted
        return response

    monkeypatch.setattr(wire, "handle_request", send)
    result = read(value)
    assert result.status == "complete" and result.attempts == 2
    assert result.raw_bytes == result.decoded_bytes == 4
    assert interrupted.closed == 1
    assert provider.calls == 1 and clock.sleeps == [1.0]


def test_cancellation_keeps_response_and_owned_client_closable(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    value, wire, _, _ = setup()
    interrupted = InterruptStream(KeyboardInterrupt())
    original = wire.handle_request

    def send(request: httpx.Request) -> httpx.Response:
        response = original(request)
        response.stream = interrupted
        return response

    monkeypatch.setattr(wire, "handle_request", send)
    with pytest.raises(KeyboardInterrupt):
        read(value)
    assert interrupted.closed == 1
    assert value.context.raw_bytes == value.context.decoded_bytes == 2
    value.close()
    assert wire.closed == 1


def test_projection_failure_does_not_charge_aggregate_bytes(setup: Callable[..., Any]) -> None:
    value, wire, _, _ = setup()
    invalid = object.__new__(contracts.ProjectedComponent)
    result = value.read_component(
        "gcs-bucket",
        value.context.request.root.targets[0],
        lambda response, target: invalid,
    )
    assert result.status == "unavailable" and result.projection is None
    assert value.context.projection_bytes == 0
    assert wire.streams[0].closed == 1


def test_closed_session_cannot_resolve_or_send_again(setup: Callable[..., Any]) -> None:
    value, wire, provider, _ = setup()
    value.close()
    with pytest.raises(ValueError):
        value.read_component("gcs-bucket", value.context.request.root.targets[0], project)
    assert provider.calls == 0 and wire.requests == []
