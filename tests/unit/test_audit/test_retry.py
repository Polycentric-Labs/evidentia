"""Tests for :mod:`evidentia_core.audit.retry` (v0.7.0+)."""

from __future__ import annotations

import pytest
from evidentia_core.audit.events import EventAction
from evidentia_core.audit.retry import (
    DEFAULT_MAX_ATTEMPTS,
    TEST_MODE_ENV,
    build_async_retrying,
    build_retrying,
    is_test_mode,
    with_retry,
    with_retry_async,
)


@pytest.fixture(autouse=True)
def test_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TEST_MODE_ENV, "1")


def test_is_test_mode_true_when_env_set() -> None:
    assert is_test_mode() is True


def test_is_test_mode_false_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TEST_MODE_ENV, raising=False)
    assert is_test_mode() is False


@pytest.mark.parametrize("falsy", ["", "0", "false", "False", "no"])
def test_is_test_mode_false_for_falsy_values(
    monkeypatch: pytest.MonkeyPatch, falsy: str
) -> None:
    monkeypatch.setenv(TEST_MODE_ENV, falsy)
    assert is_test_mode() is False


def test_success_on_first_attempt_calls_once() -> None:
    calls = {"n": 0}

    @with_retry()
    def fn() -> str:
        calls["n"] += 1
        return "ok"

    assert fn() == "ok"
    assert calls["n"] == 1


def test_retries_on_retry_exception_until_success() -> None:
    attempts = {"n": 0}

    @with_retry(max_attempts=5, retry_on=(ConnectionError,))
    def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError(f"fail {attempts['n']}")
        return "ok"

    assert flaky() == "ok"
    assert attempts["n"] == 3


def test_raises_after_max_attempts() -> None:
    attempts = {"n": 0}

    @with_retry(max_attempts=3, retry_on=(ConnectionError,))
    def always_fails() -> str:
        attempts["n"] += 1
        raise ConnectionError(f"attempt {attempts['n']}")

    with pytest.raises(ConnectionError, match="attempt 3"):
        always_fails()
    assert attempts["n"] == 3


def test_non_retry_exception_raises_immediately() -> None:
    attempts = {"n": 0}

    @with_retry(max_attempts=5, retry_on=(ConnectionError,))
    def value_error_fn() -> str:
        attempts["n"] += 1
        raise ValueError("programmer error")

    with pytest.raises(ValueError):
        value_error_fn()
    assert attempts["n"] == 1


def test_function_signature_preserved() -> None:
    @with_retry()
    def documented(x: int, y: int = 5) -> int:
        """Sum two ints."""
        return x + y

    assert documented.__name__ == "documented"
    assert documented.__doc__ == "Sum two ints."
    assert documented(1, 2) == 3
    assert documented(1) == 6


def test_default_retries_on_connection_and_timeout_errors() -> None:
    attempts = {"n": 0}

    @with_retry(max_attempts=3)
    def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 2:
            raise TimeoutError("slow")
        return "ok"

    assert flaky() == "ok"
    assert attempts["n"] == 2


def test_default_max_attempts_constant() -> None:
    assert DEFAULT_MAX_ATTEMPTS == 5


def test_retry_emits_log_events(caplog: pytest.LogCaptureFixture) -> None:
    attempts = {"n": 0}

    @with_retry(max_attempts=3, retry_on=(ConnectionError,))
    def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError(f"fail {attempts['n']}")
        return "ok"

    with caplog.at_level("WARNING", logger="evidentia.audit.retry"):
        flaky()

    retry_messages = [
        r.message
        for r in caplog.records
        if "failed with ConnectionError" in r.message
    ]
    assert len(retry_messages) == 2
    assert "attempt 1/3 failed" in retry_messages[0]
    assert "attempt 2/3 failed" in retry_messages[1]


# -----------------------------------------------------------------------------
# v0.7.1 — event_action override + with_retry_async + build_* factories
# -----------------------------------------------------------------------------


def test_with_retry_default_event_action_is_collect_retry(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Backward-compat: existing collector callers get COLLECT_RETRY without
    passing the new parameter."""

    @with_retry(max_attempts=2, retry_on=(ConnectionError,))
    def flaky() -> str:
        raise ConnectionError("nope")

    with caplog.at_level("WARNING", logger="evidentia.audit.retry"), pytest.raises(ConnectionError):
        flaky()

    actions = [
        r.ecs_record["event"]["action"]
        for r in caplog.records
        if hasattr(r, "ecs_record")
    ]
    assert actions == [EventAction.COLLECT_RETRY.value]


def test_with_retry_event_action_override_emitted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When the caller passes event_action=AI_RISK_RETRY, retry events
    fire under that namespace instead of COLLECT_RETRY."""

    @with_retry(
        max_attempts=2,
        retry_on=(ConnectionError,),
        event_action=EventAction.AI_RISK_RETRY,
    )
    def flaky() -> str:
        raise ConnectionError("transient")

    with caplog.at_level("WARNING", logger="evidentia.audit.retry"), pytest.raises(ConnectionError):
        flaky()

    actions = [
        r.ecs_record["event"]["action"]
        for r in caplog.records
        if hasattr(r, "ecs_record")
    ]
    assert actions == [EventAction.AI_RISK_RETRY.value]


def test_build_retrying_returns_iterable_with_attempt_state() -> None:
    """build_retrying exposes the underlying tenacity Retrying so callers
    (notably the v0.7.1 AI generators) can read attempt_number for
    GenerationContext.attempts."""
    retrying = build_retrying(
        function_name="test_fn",
        max_attempts=3,
        retry_on=(ConnectionError,),
    )
    attempts = 0
    last_attempt_number = 0
    for attempt in retrying:
        attempts += 1
        with attempt:
            last_attempt_number = attempt.retry_state.attempt_number
            if attempts < 2:
                raise ConnectionError("flaky")
            # second attempt succeeds (no exception)
    assert attempts == 2
    assert last_attempt_number == 2


# -----------------------------------------------------------------------------
# v0.13 batch 7: retry_predicate (state-based retry, not just exception type)
# -----------------------------------------------------------------------------


def test_retry_predicate_overrides_type_based_retry_on() -> None:
    """A predicate that accepts only a marker exception retries that one
    and re-raises any other exception immediately (attempt count 1).

    This module's own ``test_mode`` fixture (above) is ``autouse`` and
    already sets ``EVIDENTIA_TEST_MODE=1`` for every test in this file, so
    no extra ``monkeypatch.setenv`` call is needed here.
    """

    class _MarkerError(Exception):
        """A stand-in for a status-code-bearing collector error."""

    def only_marker(exc: BaseException) -> bool:
        return isinstance(exc, _MarkerError)

    marker_attempts = {"n": 0}

    @with_retry(max_attempts=3, retry_predicate=only_marker)
    def flaky_marker() -> str:
        marker_attempts["n"] += 1
        if marker_attempts["n"] < 2:
            raise _MarkerError("retry me")
        return "ok"

    assert flaky_marker() == "ok"
    assert marker_attempts["n"] == 2

    other_attempts = {"n": 0}

    @with_retry(max_attempts=3, retry_predicate=only_marker)
    def always_other() -> str:
        other_attempts["n"] += 1
        raise ValueError("not retried by the predicate")

    with pytest.raises(ValueError):
        always_other()
    assert other_attempts["n"] == 1


@pytest.mark.asyncio
async def test_with_retry_async_succeeds_after_retries() -> None:
    attempts = {"n": 0}

    @with_retry_async(max_attempts=5, retry_on=(ConnectionError,))
    async def flaky() -> str:
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise ConnectionError(f"fail {attempts['n']}")
        return "ok"

    assert await flaky() == "ok"
    assert attempts["n"] == 3


@pytest.mark.asyncio
async def test_with_retry_async_exhausts_then_raises() -> None:
    attempts = {"n": 0}

    @with_retry_async(max_attempts=3, retry_on=(ConnectionError,))
    async def always_fails() -> str:
        attempts["n"] += 1
        raise ConnectionError(f"attempt {attempts['n']}")

    with pytest.raises(ConnectionError, match="attempt 3"):
        await always_fails()
    assert attempts["n"] == 3


@pytest.mark.asyncio
async def test_with_retry_async_event_action_override(
    caplog: pytest.LogCaptureFixture,
) -> None:
    @with_retry_async(
        max_attempts=2,
        retry_on=(ConnectionError,),
        event_action=EventAction.AI_EXPLAIN_RETRY,
    )
    async def flaky() -> str:
        raise ConnectionError("transient")

    with caplog.at_level("WARNING", logger="evidentia.audit.retry"), pytest.raises(ConnectionError):
        await flaky()

    actions = [
        r.ecs_record["event"]["action"]
        for r in caplog.records
        if hasattr(r, "ecs_record")
    ]
    assert actions == [EventAction.AI_EXPLAIN_RETRY.value]


@pytest.mark.asyncio
async def test_build_async_retrying_exposes_attempt_state() -> None:
    retrying = build_async_retrying(
        function_name="test_async_fn",
        max_attempts=3,
        retry_on=(ConnectionError,),
    )
    attempts = 0
    last_attempt_number = 0
    async for attempt in retrying:
        attempts += 1
        with attempt:
            last_attempt_number = attempt.retry_state.attempt_number
            if attempts < 2:
                raise ConnectionError("flaky")
    assert attempts == 2
    assert last_attempt_number == 2
