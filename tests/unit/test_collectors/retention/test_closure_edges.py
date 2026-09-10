"""Review controls for the corrected response hook and final send boundary."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import httpx
import pytest

from .test_counterexamples import code_list, read
from .test_counterexamples import setup as setup
from .test_transport_edges import InterruptStream


@pytest.mark.parametrize(
    "variant",
    ["success", "redirect", "unauthorized", "invalid_body", "read_timeout", "cancellation", "close_failure"],
)
def test_response_hook_is_cleared_on_every_exit(
    setup: Callable[..., Any], monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    value, wire, _, _ = setup()
    interrupted: InterruptStream | None = None
    if variant == "redirect":
        wire.statuses = [307]
        wire.response_headers = {"Location": "http://example.com:wrong"}
    elif variant == "unauthorized":
        wire.statuses = [401]
    elif variant == "invalid_body":
        wire.bodies = [b"{"]
    elif variant == "read_timeout":

        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("synthetic read timeout")

        monkeypatch.setattr(wire, "handle_request", timeout)
    elif variant in {"cancellation", "close_failure"}:
        original = wire.handle_request
        if variant == "cancellation":
            interrupted = InterruptStream(KeyboardInterrupt())

        def receive(request: httpx.Request) -> httpx.Response:
            response = original(request)
            if variant == "cancellation":
                assert interrupted is not None
                response.stream = interrupted
            else:
                raw_stream = wire.streams[-1]

                def failed_close() -> None:
                    raw_stream.closed += 1
                    raise RuntimeError("synthetic close failure")

                monkeypatch.setattr(raw_stream, "close", failed_close)
            return response

        monkeypatch.setattr(wire, "handle_request", receive)
    if variant == "cancellation":
        with pytest.raises(KeyboardInterrupt):
            read(value)
        assert interrupted is not None and interrupted.closed == 1
    else:
        result = read(value)
        if variant == "success":
            assert result.status == "complete"
        elif variant == "close_failure":
            assert result.status == "partial" and code_list(result) == ["cleanup_failed"]
        else:
            assert result.status == "unavailable"
    assert value._client is not None
    assert value._client.event_hooks == {"request": [], "response": []}
    value.close()
    assert wire.closed == 1


def test_slow_final_utc_clock_cannot_send_after_deadline(setup: Callable[..., Any]) -> None:
    value, wire, _, clock = setup()

    def slow_clock() -> Any:
        clock.value = 120
        return clock.utc()

    value.context._utc_clock = slow_clock
    result = read(value)
    assert wire.requests == [], "The final clock read must precede the last deadline check"
    assert result.status == "unavailable"
    assert code_list(result) == ["run_budget_exhausted"]


def test_slow_final_utc_clock_cannot_send_expired_material(setup: Callable[..., Any]) -> None:
    value, wire, _, clock = setup(expires=1)
    calls = 0

    def slow_clock() -> Any:
        nonlocal calls
        calls += 1
        if calls == 4:
            clock.value = 2
        return clock.utc()

    value.context._utc_clock = slow_clock
    result = read(value)
    assert wire.requests == [], "The final clock read must precede the last expiry check"
    assert result.status == "unavailable"
