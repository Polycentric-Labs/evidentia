"""Structured JSON logger for Evidentia (v0.7.0).

Emits logs in Elastic Common Schema (ECS) 8.11 format with NIST
SP 800-53 Rev 5 AU-3 (Content of Audit Records) content requirements
satisfied per-event:

- **What**: :attr:`~evidentia_core.audit.events.EventAction` + ``event.category``
- **When**: ``@timestamp`` (+ optional ``event.start`` / ``event.end``)
- **Where**: ``host.*`` + ``cloud.*`` + ``service.environment``
- **Source**: ``service.name`` + ``log.logger``
- **Outcome**: ``event.outcome`` (success / failure / unknown)
- **Identity**: ``user.id`` + ``user.domain``

OpenTelemetry ``trace.id`` / ``span.id`` correlate events across a
single collection run — an auditor querying
``trace.id:<run-ulid>`` retrieves every log line for that run in
order, across all collectors and retries.

Two output modes:

- **Rich console** (default): human-readable, colorized.
- **ECS JSON** (opt-in via ``--json-logs`` or :func:`enable_json_logs`):
  single-line JSON per event, SIEM-ready. Splunk / Elastic / Datadog /
  Sumo Logic / Microsoft Sentinel all ingest ECS natively.

Both modes emit the same events; only the encoding differs.

Secret-scrubbing: ``message`` strings pass through a narrow regex
filter before emission (AWS access keys, GitHub token prefixes, simple
``password=`` patterns). Collectors are responsible for keeping secrets
out of structured field values — the scrubber is a safety net, not
the primary defence.
"""

from __future__ import annotations

import contextvars
import json
import logging
import re
import socket
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from typing import Any

import ulid

from evidentia_core.audit.events import (
    EventAction,
    EventCategory,
    EventOutcome,
    EventType,
)

ECS_VERSION = "8.11"
"""ECS specification version that this logger conforms to."""

SERVICE_NAME = "evidentia"
"""Value of ECS ``service.name`` on every emitted record."""

# ContextVar default=None avoids the ruff B039 warning about mutable
# default arguments — every reader goes through _get_scope() which
# substitutes an empty dict for the None sentinel.
_scope_context: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "evidentia_audit_scope", default=None
)
_json_mode: bool = False


def _get_scope() -> dict[str, Any]:
    """Return the active scope dict, substituting {} for the None default."""
    value = _scope_context.get()
    return value if value is not None else {}


# ── secret scrubber ─────────────────────────────────────────────────────
#
# Narrow patterns — anything with high confidence of being a credential.
# False positives here are annoying but safe (redacted message); false
# negatives are a compliance liability. Err on the side of over-scrubbing.
#
# v0.7.0 Step-5 review: expanded from the initial AWS+GitHub+JWT set to
# also cover Slack, Stripe, Google API, and npm tokens — the most
# common credential shapes seen in real-world incident logs (per OWASP
# Cheat Sheet on credential leakage and the GitHub token-scan corpus
# at github.com/leondz/garak/blob/main/garak/probes/leakreplay.py).
_SECRET_PATTERNS = [
    # AWS access key IDs (AKIA prefix, 20 chars total, base32).
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),  # temporary credentials
    # GitHub personal access tokens (ghp_, gho_, ghu_, ghs_, ghr_ + 36 chars).
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    # Slack tokens (xoxb_, xoxp_, xoxa_, xoxr_, xoxs_ + variable length).
    # Doc: https://api.slack.com/authentication/token-types
    re.compile(r"\bxox[abprs]-[0-9]+-[0-9]+-[0-9]+-[A-Fa-f0-9]+\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{20,}\b"),  # newer formats
    # Stripe API keys (sk_live_, sk_test_, pk_live_, pk_test_,
    # rk_live_, rk_test_ + 24+ chars). Doc: stripe.com/docs/keys
    re.compile(r"\b(sk|pk|rk)_(live|test)_[A-Za-z0-9]{24,}\b"),
    # Google API keys (AIza prefix, 39 chars total).
    # Doc: cloud.google.com/docs/authentication/api-keys
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    # npm tokens (npm_ prefix, 36 chars total — introduced 2021).
    # Doc: docs.npmjs.com/about-access-tokens
    re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    # Generic "password=xxx" / "token=xxx" / "api_key=xxx" shapes, length ≥8.
    re.compile(
        r"\b(password|token|api[_-]?key|secret|credential)\s*[=:]\s*[\'\"]?"
        r"[A-Za-z0-9_\-\.]{8,}[\'\"]?",
        re.IGNORECASE,
    ),
    # JWTs — three base64url segments separated by dots.
    re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
]


def _scrub(message: str) -> str:
    """Replace well-known secret patterns in free-text with ``[REDACTED]``.

    Operates on message strings only. Structured field values are the
    collector's responsibility — the scrubber is a safety net for
    exception stringification and ad-hoc log lines that might inline a
    credential accidentally.
    """
    for pattern in _SECRET_PATTERNS:
        message = pattern.sub("[REDACTED]", message)
    return message


def _build_ecs_record(
    *,
    level: str,
    logger_name: str,
    message: str,
    action: EventAction | str,
    outcome: EventOutcome | str = EventOutcome.SUCCESS,
    category: list[EventCategory | str] | None = None,
    types: list[EventType | str] | None = None,
    event_start: datetime | None = None,
    event_end: datetime | None = None,
    duration_ms: float | None = None,
    user: dict[str, Any] | None = None,
    cloud: dict[str, Any] | None = None,
    error: dict[str, Any] | None = None,
    evidentia: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct a single ECS 8.11 log record as a dict."""
    scope = scope or {}
    now = datetime.now().astimezone()

    record: dict[str, Any] = {
        "@timestamp": now.isoformat(timespec="microseconds"),
        "ecs": {"version": ECS_VERSION},
        "log": {
            "level": level,
            "logger": logger_name,
        },
        "message": _scrub(message),
        "event": {
            "kind": "event",
            "action": action.value if isinstance(action, EventAction) else action,
            "outcome": (
                outcome.value
                if isinstance(outcome, EventOutcome)
                else outcome
            ),
            "id": str(ulid.ULID()),
            "dataset": f"{SERVICE_NAME}.audit",
        },
        "service": {
            "name": SERVICE_NAME,
            "version": _resolve_service_version(),
            "type": "grc",
        },
        "host": {
            "hostname": socket.gethostname(),
        },
    }

    if category is not None:
        record["event"]["category"] = [
            c.value if isinstance(c, EventCategory) else c for c in category
        ]
    if types is not None:
        record["event"]["type"] = [
            t.value if isinstance(t, EventType) else t for t in types
        ]

    if event_start is not None:
        record["event"]["start"] = event_start.astimezone().isoformat(
            timespec="microseconds"
        )
    if event_end is not None:
        record["event"]["end"] = event_end.astimezone().isoformat(
            timespec="microseconds"
        )
    if duration_ms is not None:
        # ECS spec is nanoseconds, integer. Convert from milliseconds.
        record["event"]["duration"] = int(duration_ms * 1_000_000)

    if "trace_id" in scope:
        record["trace"] = {"id": scope["trace_id"]}
    if "span_id" in scope:
        record["span"] = {"id": scope["span_id"]}

    if user is not None:
        record["user"] = user
    elif "user" in scope:
        record["user"] = scope["user"]

    if cloud is not None:
        record["cloud"] = cloud
    elif "cloud" in scope:
        record["cloud"] = scope["cloud"]

    if error is not None:
        record["error"] = error

    evidentia_payload: dict[str, Any] = {}
    if "evidentia" in scope:
        evidentia_payload.update(scope["evidentia"])
    if evidentia is not None:
        evidentia_payload.update(evidentia)
    if evidentia_payload:
        record["evidentia"] = evidentia_payload

    return record


def _resolve_service_version() -> str:
    """Return the installed evidentia-core version string."""
    from evidentia_core import __version__

    return __version__


class ECSFormatter(logging.Formatter):
    """Formatter that emits single-line ECS JSON."""

    def format(self, record: logging.LogRecord) -> str:
        ecs_record: dict[str, Any] | None = getattr(record, "ecs_record", None)
        if ecs_record is None:
            ecs_record = {
                "@timestamp": datetime.fromtimestamp(
                    record.created
                ).astimezone().isoformat(timespec="microseconds"),
                "ecs": {"version": ECS_VERSION},
                "log": {
                    "level": record.levelname.lower(),
                    "logger": record.name,
                },
                "message": _scrub(record.getMessage()),
                "event": {
                    "kind": "event",
                    "dataset": "evidentia.library",
                },
                "service": {
                    "name": SERVICE_NAME,
                    "type": "grc",
                },
            }
        return json.dumps(ecs_record, ensure_ascii=False, default=str)


class EvidentiaLogger:
    """Typed wrapper around :class:`logging.Logger` with ECS-aware emit."""

    def __init__(self, name: str) -> None:
        self._stdlib = logging.getLogger(name)
        self.name = name

    @contextmanager
    def scope(self, **kwargs: Any) -> Iterator[None]:
        """Context manager adding fields to every event emitted within."""
        parent = _get_scope()
        merged: dict[str, Any] = dict(parent)
        for key, value in kwargs.items():
            if (
                key == "evidentia"
                and isinstance(value, dict)
                and isinstance(parent.get("evidentia"), dict)
            ):
                merged["evidentia"] = {**parent["evidentia"], **value}
            else:
                merged[key] = value
        token = _scope_context.set(merged)
        try:
            yield
        finally:
            _scope_context.reset(token)

    def info(self, **kwargs: Any) -> None:
        self._emit(logging.INFO, **kwargs)

    def warning(self, **kwargs: Any) -> None:
        self._emit(logging.WARNING, **kwargs)

    def error(self, **kwargs: Any) -> None:
        self._emit(logging.ERROR, **kwargs)

    def debug(self, **kwargs: Any) -> None:
        self._emit(logging.DEBUG, **kwargs)

    def critical(self, **kwargs: Any) -> None:
        self._emit(logging.CRITICAL, **kwargs)

    def _emit(
        self,
        stdlib_level: int,
        *,
        action: EventAction | str,
        message: str,
        outcome: EventOutcome | str = EventOutcome.SUCCESS,
        category: list[EventCategory | str] | None = None,
        types: list[EventType | str] | None = None,
        event_start: datetime | None = None,
        event_end: datetime | None = None,
        duration_ms: float | None = None,
        user: dict[str, Any] | None = None,
        cloud: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
        evidentia: dict[str, Any] | None = None,
    ) -> None:
        level_name = logging.getLevelName(stdlib_level).lower()
        ecs_record = _build_ecs_record(
            level=level_name,
            logger_name=self.name,
            message=message,
            action=action,
            outcome=outcome,
            category=category,
            types=types,
            event_start=event_start,
            event_end=event_end,
            duration_ms=duration_ms,
            user=user,
            cloud=cloud,
            error=error,
            evidentia=evidentia,
            scope=_get_scope(),
        )
        self._stdlib.log(
            stdlib_level,
            _scrub(message),
            extra={"ecs_record": ecs_record},
        )
        # v0.8.0 P1 G3: tap event into the in-process Prometheus
        # counter aggregator. Lazy-import keeps logger.py free of
        # the metrics module's threading.Lock at import time.
        from evidentia_core.audit.metrics import record_event

        action_str = action.value if hasattr(action, "value") else str(action)
        outcome_str = outcome.value if hasattr(outcome, "value") else str(outcome)
        record_event(action=action_str, outcome=outcome_str)


def get_logger(name: str) -> EvidentiaLogger:
    """Return an EvidentiaLogger for the given module-path name."""
    return EvidentiaLogger(name)


def enable_json_logs(stream: Any = None) -> None:
    """Switch the root Evidentia logger to ECS-JSON output."""
    global _json_mode
    _json_mode = True

    root = logging.getLogger(SERVICE_NAME)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    stream_handler = logging.StreamHandler(stream or sys.stderr)
    stream_handler.setFormatter(ECSFormatter())
    root.addHandler(stream_handler)
    root.propagate = False

    if root.level == logging.NOTSET:
        root.setLevel(logging.INFO)


def is_json_mode() -> bool:
    """Return True iff :func:`enable_json_logs` has been called."""
    return _json_mode


def _reset_for_tests() -> None:
    """Test helper: revert module-level state between test cases."""
    global _json_mode
    _json_mode = False
    root = logging.getLogger(SERVICE_NAME)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.propagate = True
    _scope_context.set(None)
