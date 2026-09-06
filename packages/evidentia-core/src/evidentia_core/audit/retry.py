"""Bounded retry with exponential backoff + jitter (v0.7.0+).

Implements checklist item B10: every API call made by a collector must
be wrapped in bounded retry logic so transient source-system failures
don't produce silent evidence gaps.

Design principles:

- **Bounded by attempts, not time.** Unbounded retry loops are a
  denial-of-service vector against source systems. Default cap is 5.
- **Exponential backoff with full jitter.** tenacity's
  ``wait_exponential_jitter`` applies full jitter per the AWS
  Architecture Blog guidance.
- **Structured logging on every retry.** Every retry emits a
  configurable :class:`~evidentia_core.audit.events.EventAction` event.
  Defaults to
  :attr:`~evidentia_core.audit.events.EventAction.COLLECT_RETRY` to
  preserve the v0.7.0 collector behaviour; AI generators (v0.7.1+)
  override with :attr:`~evidentia_core.audit.events.EventAction.AI_RISK_RETRY`
  or :attr:`~evidentia_core.audit.events.EventAction.AI_EXPLAIN_RETRY` so
  SIEM operators can filter by namespace.
- **Test-mode short-circuit.** When ``EVIDENTIA_TEST_MODE=1`` is set,
  backoff is zeroed so retry-heavy tests don't burn wall-clock time.

Public surface:

- :func:`with_retry` — sync decorator. The collector-friendly wrapper.
- :func:`with_retry_async` — async sibling decorator (v0.7.1).
- :func:`build_retrying` / :func:`build_async_retrying` — factory
  functions returning configured tenacity ``Retrying`` /
  ``AsyncRetrying`` instances. Used by the AI generators directly so
  they can read ``retry_state.attempt_number`` for the
  ``GenerationContext.attempts`` provenance field.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from functools import wraps
from typing import ParamSpec, TypeVar

from tenacity import (
    AsyncRetrying,
    RetryCallState,
    Retrying,
    retry_if_exception,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from evidentia_core.audit.events import EventAction, EventOutcome
from evidentia_core.audit.logger import get_logger

P = ParamSpec("P")
R = TypeVar("R")

DEFAULT_MAX_ATTEMPTS = 5
DEFAULT_INITIAL_BACKOFF_SECONDS = 1.0
DEFAULT_MAX_BACKOFF_SECONDS = 60.0
TEST_MODE_ENV = "EVIDENTIA_TEST_MODE"

_log = get_logger("evidentia.audit.retry")


def _effective_backoff(initial_backoff: float, max_backoff: float) -> tuple[float, float]:
    """Apply the test-mode short-circuit: zero out backoff under EVIDENTIA_TEST_MODE."""
    if os.environ.get(TEST_MODE_ENV):
        return (0.0, 0.0)
    return (initial_backoff, max_backoff)


def build_retrying(
    *,
    function_name: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    initial_backoff: float = DEFAULT_INITIAL_BACKOFF_SECONDS,
    max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
    retry_on: tuple[type[BaseException], ...] = (
        ConnectionError,
        TimeoutError,
    ),
    retry_predicate: Callable[[BaseException], bool] | None = None,
    event_action: EventAction = EventAction.COLLECT_RETRY,
) -> Retrying:
    """Return a configured :class:`tenacity.Retrying` instance.

    Public so callers (notably the v0.7.1 AI generators) can drive the
    retry loop manually and read ``retry_state.attempt_number`` for
    structured provenance, instead of using the :func:`with_retry`
    decorator which hides that state.

    When ``retry_predicate`` is given, it replaces the type-based
    ``retry_on`` check with ``tenacity.retry_if_exception(retry_predicate)``,
    so a caller can decide whether to retry from runtime state carried on
    the exception (for example an HTTP status code) rather than from the
    exception's type alone.
    """
    initial, mx = _effective_backoff(initial_backoff, max_backoff)
    retry_condition = (
        retry_if_exception(retry_predicate) if retry_predicate is not None else retry_if_exception_type(retry_on)
    )
    return Retrying(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential_jitter(initial=initial, max=mx),
        retry=retry_condition,
        before_sleep=_log_retry_event(function_name, max_attempts, event_action),
        reraise=True,
    )


def build_async_retrying(
    *,
    function_name: str,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    initial_backoff: float = DEFAULT_INITIAL_BACKOFF_SECONDS,
    max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
    retry_on: tuple[type[BaseException], ...] = (
        ConnectionError,
        TimeoutError,
    ),
    event_action: EventAction = EventAction.COLLECT_RETRY,
) -> AsyncRetrying:
    """Async sibling of :func:`build_retrying` returning :class:`tenacity.AsyncRetrying`."""
    initial, mx = _effective_backoff(initial_backoff, max_backoff)
    return AsyncRetrying(
        stop=stop_after_attempt(max_attempts),
        wait=wait_exponential_jitter(initial=initial, max=mx),
        retry=retry_if_exception_type(retry_on),
        before_sleep=_log_retry_event(function_name, max_attempts, event_action),
        reraise=True,
    )


def with_retry(
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    initial_backoff: float = DEFAULT_INITIAL_BACKOFF_SECONDS,
    max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
    retry_on: tuple[type[BaseException], ...] = (
        ConnectionError,
        TimeoutError,
    ),
    retry_predicate: Callable[[BaseException], bool] | None = None,
    event_action: EventAction = EventAction.COLLECT_RETRY,
) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Decorator adding bounded exponential-backoff retry to a sync function.

    The wrapped function's signature is preserved. On the final failed
    attempt, the last exception is re-raised.

    ``event_action`` determines the structured-log event that fires on
    each retry. Defaults to
    :attr:`~evidentia_core.audit.events.EventAction.COLLECT_RETRY` so
    pre-v0.7.1 collectors keep their existing behaviour; AI generators
    pass an ``AI_*_RETRY`` action so SIEM filters can distinguish the
    namespaces. ``retry_predicate`` is passed through to
    :func:`build_retrying` unchanged.
    """

    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        @wraps(fn)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            retrying = build_retrying(
                function_name=fn.__name__,
                max_attempts=max_attempts,
                initial_backoff=initial_backoff,
                max_backoff=max_backoff,
                retry_on=retry_on,
                retry_predicate=retry_predicate,
                event_action=event_action,
            )
            for attempt in retrying:
                with attempt:
                    return fn(*args, **kwargs)
            raise RuntimeError("unreachable")

        return wrapper

    return decorator


def with_retry_async(
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    initial_backoff: float = DEFAULT_INITIAL_BACKOFF_SECONDS,
    max_backoff: float = DEFAULT_MAX_BACKOFF_SECONDS,
    retry_on: tuple[type[BaseException], ...] = (
        ConnectionError,
        TimeoutError,
    ),
    event_action: EventAction = EventAction.COLLECT_RETRY,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Async sibling of :func:`with_retry` for ``async def`` functions.

    Mirrors :func:`with_retry` exactly — same parameters, same defaults,
    same retry/backoff semantics — but uses tenacity's
    :class:`~tenacity.AsyncRetrying` so the awaitable is awaited
    correctly between retries. Added in v0.7.1 to support
    ``evidentia-ai``'s async generators.
    """

    def decorator(fn: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @wraps(fn)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            retrying = build_async_retrying(
                function_name=fn.__name__,
                max_attempts=max_attempts,
                initial_backoff=initial_backoff,
                max_backoff=max_backoff,
                retry_on=retry_on,
                event_action=event_action,
            )
            async for attempt in retrying:
                with attempt:
                    return await fn(*args, **kwargs)
            raise RuntimeError("unreachable")

        return wrapper

    return decorator


def _log_retry_event(
    function_name: str,
    max_attempts: int,
    event_action: EventAction = EventAction.COLLECT_RETRY,
) -> Callable[[RetryCallState], None]:
    """Build a tenacity ``before_sleep`` callback emitting retry events."""

    def _callback(retry_state: RetryCallState) -> None:
        attempt_number = retry_state.attempt_number
        exc: BaseException | None = None
        if retry_state.outcome is not None:
            exc = retry_state.outcome.exception()

        _log.warning(
            action=event_action,
            outcome=EventOutcome.FAILURE,
            message=(
                # Tenacity invokes ``before_sleep`` AFTER an attempt
                # fails and BEFORE the next attempt starts, so
                # ``attempt_number`` is the one that just failed.
                f"{function_name} attempt {attempt_number}/{max_attempts} "
                f"failed with {type(exc).__name__ if exc else 'unknown'}; "
                f"retrying"
            ),
            error=(
                {
                    "type": type(exc).__name__,
                    "message": str(exc),
                }
                if exc
                else None
            ),
            evidentia={
                "function": function_name,
                "attempt": attempt_number,
                "max_attempts": max_attempts,
            },
        )

    return _callback


def is_test_mode() -> bool:
    """Return True iff :envvar:`EVIDENTIA_TEST_MODE` is set to a truthy value."""
    value = os.environ.get(TEST_MODE_ENV, "")
    return value.lower() not in ("", "0", "false", "no")


__all__ = [
    "DEFAULT_INITIAL_BACKOFF_SECONDS",
    "DEFAULT_MAX_ATTEMPTS",
    "DEFAULT_MAX_BACKOFF_SECONDS",
    "TEST_MODE_ENV",
    "build_async_retrying",
    "build_retrying",
    "is_test_mode",
    "with_retry",
    "with_retry_async",
]
