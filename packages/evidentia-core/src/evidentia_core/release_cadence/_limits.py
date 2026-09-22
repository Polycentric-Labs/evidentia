"""Finite release profile bounds and one cooperative invocation deadline."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

PAGE_BYTES = 4_194_304
TOTAL_BYTES = 16_777_216
RESULT_BYTES = 16_777_216
SELECTED_BYTES = 16_384
SELECTED_TOTAL_BYTES = 8_388_608
REQUEST_BYTES = 4_096
ARTIFACT_BYTES = 65_536
STORED_BYTES = 131_072
STORE_TOTAL_BYTES = 67_108_864
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_PAGES = 10
MAX_ROWS = 1_000
JSON_DEPTH = 64
JSON_VALUES = 131_072
JSON_KEY_BYTES = 256
JSON_NUMBER_BYTES = 128
RAW_CHUNK_BYTES = 65_536
OPERATION_SECONDS = 60
POLL_RESERVE_SECONDS = 15
SERIES_RESERVE_SECONDS = 5
SOURCE_PROFILE = "github-public-releases-2026-03-10"
SOURCE_HOST = "api.github.com"

ERRORS: dict[str, tuple[int, str]] = {
    "invalid_request": (422, "The release request is invalid."),
    "request_limit_exceeded": (413, "The release request exceeds its limit."),
    "result_limit_exceeded": (413, "The release result exceeds its limit."),
    "unsupported_media": (415, "The release request media type is unsupported."),
    "support_unavailable": (503, "Release support is unavailable."),
    "support_broken": (500, "Release support failed."),
    "authority_unavailable": (503, "Release authority is unavailable."),
    "operation_failed": (500, "The release operation failed."),
    "persistence_outcome_unavailable": (
        500,
        "The release deadline expired after a save was attempted. "
        "Persistence may have occurred. Inspect local records before retrying.",
    ),
}


class ReleaseFailure(ValueError):
    """A fixed outward error and a bounded internal reason, without source values."""

    def __init__(self, reason: str = "invalid_request", *, code: str | None = None) -> None:
        if type(reason) is not str or (type(code) is not str and code is not None):
            raise ValueError("Invalid release error classification.")
        chosen = code if code is not None else reason if reason in ERRORS else "operation_failed"
        if chosen not in ERRORS:
            raise ValueError("Invalid release error classification.")
        self.reason = reason
        self.code = chosen
        self.status, self.message = ERRORS[chosen]
        super().__init__(self.message)


def text_value(value: object, maximum: int, *, minimum: int = 0) -> str:
    """Check native scalar bytes before using its contents."""
    if type(value) is not str:
        raise ReleaseFailure()
    text = cast(str, value)
    if len(text) > maximum:
        raise ReleaseFailure("json_scalar")
    try:
        length = len(text.encode("utf-8"))
    except UnicodeError:
        raise ReleaseFailure("json_scalar") from None
    if not minimum <= length <= maximum:
        raise ReleaseFailure("json_scalar")
    return text


def integer(value: object, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= cast(int, value) <= maximum:
        raise ReleaseFailure()
    return cast(int, value)


@dataclass(frozen=True, slots=True)
class Budget:
    """A reader of one deadline; lifecycle closures retain their own authority."""

    deadline: float

    def remaining(self) -> float:
        if type(self) is not Budget or type(self.deadline) is not float or not math.isfinite(self.deadline):
            raise ReleaseFailure("clock_invalid")
        now = time.monotonic()
        if type(now) is not float or not math.isfinite(now):
            raise ReleaseFailure("clock_invalid")
        return self.deadline - now

    def check(self, reserve: int = 0) -> None:
        remaining = self.remaining()
        if remaining <= 0 or (reserve and remaining < reserve):
            raise ReleaseFailure("deadline_exceeded")


def start_budget() -> Budget:
    now = time.monotonic()
    if type(now) is not float or not math.isfinite(now) or now < 0:
        raise ReleaseFailure("clock_invalid")
    return Budget(now + OPERATION_SECONDS)


def check_budget(budget: Budget | None) -> None:
    if budget is not None:
        if type(budget) is not Budget:
            raise ReleaseFailure("clock_invalid")
        budget.check()


class _PersistenceExpiry(ReleaseFailure):
    """An owned failure with previously captured observations, never a new result."""

    def __init__(
        self,
        original_failure: Exception,
        captured_outcomes: tuple[bytes, ...],
        save_observations: tuple[tuple[int, str], ...],
        save_failures: tuple[Exception, ...],
    ) -> None:
        super().__init__("deadline_exceeded", code="persistence_outcome_unavailable")
        self.original_failure = original_failure
        self.captured_outcomes = captured_outcomes
        self.save_observations = save_observations
        self.save_failures = save_failures


@dataclass(frozen=True, slots=True)
class _PersistenceAuthority:
    """Private capabilities retained by the invocation, outside all result models."""

    prepare: Callable[[tuple[bytes, ...]], None]
    record: Callable[[int, bytes], None]
    save: Callable[[int, Any, Path], Any]
    failure: Callable[[Exception], _PersistenceExpiry | None]
    wire: Callable[[_PersistenceExpiry], bytes]


def _persistence_authority(budget: Budget, check: Callable[[int], None]) -> _PersistenceAuthority:
    prepared = False
    fixed_wire: bytes | None = None
    outcomes: tuple[bytes, ...] = ()
    observations: tuple[tuple[int, str], ...] = ()
    failures: tuple[Exception, ...] = ()
    owned_failure: _PersistenceExpiry | None = None

    def prepare(values: tuple[bytes, ...]) -> None:
        nonlocal prepared, fixed_wire, outcomes
        from ._contracts import ReleaseError
        from ._json import canonical_bytes

        check(0)
        if prepared or type(values) is not tuple or len(values) > MAX_ROWS * 2:
            raise ReleaseFailure("operation_failed")
        if any(type(value) is not bytes or not 0 < len(value) <= 2048 for value in values):
            raise ReleaseFailure("operation_failed")
        error = {
            "schema_version": "release-error-v1",
            "code": "persistence_outcome_unavailable",
            "message": ERRORS["persistence_outcome_unavailable"][1],
        }
        ReleaseError.model_validate(error)
        encoded = canonical_bytes(error, 511, budget=budget)
        check(0)
        outcomes, fixed_wire, prepared = values, encoded, True

    def record(slot: int, value: bytes) -> None:
        nonlocal outcomes
        check(0)
        if (
            not prepared
            or type(slot) is not int
            or not 0 <= slot < len(outcomes)
            or type(value) is not bytes
            or not 0 < len(value) <= 2048
        ):
            raise ReleaseFailure("operation_failed")
        outcomes = (*outcomes[:slot], value, *outcomes[slot + 1 :])

    def save(slot: int, artifact: Any, root: Path) -> Any:
        nonlocal observations, failures
        from evidentia_core import evidence_store

        check(0 if observations else 15)
        if not prepared or type(slot) is not int or not 0 <= slot < len(outcomes):
            raise ReleaseFailure("operation_failed")
        if any(index == slot for index, _ in observations):
            raise ReleaseFailure("operation_failed")
        invoke = evidence_store.save_evidence_version_one
        expected_path = root / artifact.id / "v1.json"
        observations = (*observations, (slot, "entered"))
        try:
            returned = invoke(artifact, evidence_store_dir=root)
            if (
                type(returned) is not evidence_store.EvidenceVersionOneSaveResult
                or type(returned.state) is not str
                or returned.state not in {"created", "collided"}
                or type(returned.path) is not type(Path())
                or returned.path != expected_path
            ):
                raise ReleaseFailure("save_failed")
        except Exception as error:
            observations = (*observations[:-1], (slot, "raised"))
            failures = (*failures, error)
            raise
        observations = (*observations[:-1], (slot, "returned_" + returned.state))
        return returned

    def failure(error: Exception) -> _PersistenceExpiry | None:
        nonlocal owned_failure
        if not observations or fixed_wire is None:
            return None
        if error is owned_failure:
            return owned_failure
        try:
            check(0)
        except ReleaseFailure as clock_error:
            if clock_error.reason != "deadline_exceeded":
                return None
        else:
            return None
        if owned_failure is None:
            owned_failure = _PersistenceExpiry(error, outcomes, observations, failures)
        return owned_failure

    def wire(error: _PersistenceExpiry) -> bytes:
        if owned_failure is None or error is not owned_failure or fixed_wire is None:
            raise ReleaseFailure("operation_failed")
        return fixed_wire

    return _PersistenceAuthority(prepare, record, save, failure, wire)


@dataclass(frozen=True, slots=True)
class _Invocation:
    """Private single-use entry clock shared with the actual API body reader."""

    budget: Budget
    _take: Callable[[], tuple[Budget, datetime, Callable[[int], None]]]
    _guard: Callable[[int], None]
    persistence: _PersistenceAuthority

    def take(self) -> tuple[Budget, datetime, Callable[[int], None]]:
        if type(self) is not _Invocation:
            raise ReleaseFailure("clock_invalid")
        return self._take()

    def check(self, reserve: int = 0) -> None:
        self._guard(reserve)


def _capture_invocation(original: Budget, started: datetime) -> _Invocation:
    """Capture trusted entry clocks; callers never expose these as wire options."""
    if type(original) is not Budget or type(started) is not datetime or started.tzinfo is not UTC:
        raise ReleaseFailure("clock_invalid")
    original.check()
    deadline = original.deadline
    reader = Budget(deadline)
    lock = threading.Lock()

    def check(reserve: int = 0) -> None:
        if (
            type(original.deadline) is not float
            or original.deadline != deadline
            or type(reader.deadline) is not float
            or reader.deadline != deadline
        ):
            raise ReleaseFailure("clock_invalid")
        Budget(deadline).check(reserve)

    def take() -> tuple[Budget, datetime, Callable[[int], None]]:
        if not lock.acquire(blocking=False):
            raise ReleaseFailure("invalid_request")
        check()
        return original, started, check

    return _Invocation(reader, take, check, _persistence_authority(original, check))


def _start_invocation() -> _Invocation:
    return _capture_invocation(start_budget(), datetime.now(UTC))
