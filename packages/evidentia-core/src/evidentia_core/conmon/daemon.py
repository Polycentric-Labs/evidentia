"""CONMON poll-mode daemon (v0.9.3 P1.1).

Long-running poll loop that reads a state file (slug -> last_completed
mapping), polls :func:`evidentia_core.conmon.calendar.derive_status`
at a configurable interval, and invokes operator-supplied callbacks
for due-soon and overdue cycles. The CLI surface ``evidentia conmon
watch --poll`` wires this loop into the operator workflow.

Design constraints (per v0.9.3 plan P1.1):

- **Single-process, no fork** — the poll loop runs in the caller's
  process. Operators wanting daemonization use systemd / launchd /
  Windows Service Manager (see ``docs/conmon-daemon-deployment.md``).
- **No durable queue** — state transitions emit audit events
  synchronously; no message broker; no async result handling.
- **Callback hooks** — alerting (P1.2) plugs in via the
  ``on_due_soon`` / ``on_overdue`` parameters; this module knows
  nothing about email/webhooks/etc.
- **Graceful shutdown** — operators signal via :class:`threading.Event`;
  the loop finishes the current poll cycle, fires
  ``CONMON_DAEMON_STOPPED``, and returns. Signal handler installation
  is the CLI layer's responsibility — this module is signal-agnostic
  so it remains testable.

State file format (YAML, matching the existing v0.9.0 P3
``evidentia conmon check --last-completed-file`` schema):

    nist-800-53-rev5-ca7: 2026-04-01
    fedramp-conmon-poam: 2026-04-15
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Protocol

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.conmon.calendar import (
    ConmonCadence,
    CycleAttentionState,
    derive_status,
    get_cadence,
    next_due,
)
from evidentia_core.security.atomic_write import atomic_write_text

_log = get_logger("evidentia_core.conmon.daemon")

MIN_POLL_INTERVAL_SECONDS = 60
"""Hard floor on poll interval. Daemons polling more aggressively
than once-per-minute risk audit-event spam without operator value;
CONMON cycles are daily/weekly/monthly at finest, so sub-minute
polling adds no signal."""

DEFAULT_POLL_INTERVAL_SECONDS = 3600
"""1-hour default. Matches the practical floor at which operators
can react to overdue/due-soon signals during business hours."""


@dataclass(frozen=True)
class CycleObservation:
    """One cadence's state at poll time. Passed to operator callbacks."""

    cadence: ConmonCadence
    last_completed: date
    next_due: date
    state: CycleAttentionState
    days_until_due: int


class CycleHandler(Protocol):
    """Callback signature for alerting integration (P1.2 hook point).

    Implementations receive one observation per poll cycle and
    decide whether to dispatch an alert (with their own
    deduplication logic). The daemon does not retry or batch
    callback invocations; exceptions are caught + logged but do
    not stop the poll loop (one bad alert shouldn't kill the
    daemon).
    """

    def __call__(self, obs: CycleObservation) -> None: ...


@dataclass(frozen=True)
class DaemonConfig:
    """Operator-supplied daemon configuration.

    Constructed once at CLI parse time; never mutated. Auditors
    inspect the ``CONMON_DAEMON_STARTED`` event payload to verify
    these values match policy.
    """

    state_file: Path
    poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS
    window_days: int = 14
    status_file: Path | None = None
    """v0.9.4 P2.1: optional sidecar JSON path the daemon writes
    after every poll cycle. Pairs with ``GET /api/conmon/daemon-
    status`` REST endpoint for operator health-check visibility.
    None disables status-file emission (backward-compat default)."""
    history_file: Path | None = None
    """v0.9.5 P2.3: optional JSONL history path the daemon appends
    to after every poll cycle. Pairs with ``GET /api/conmon/daemon-
    history`` REST endpoint so operators can detect flapping
    daemons (rapid success → failure → success oscillation that the
    point-in-time status sidecar can't reveal). Trimmed to the
    last :data:`DAEMON_HISTORY_MAX_ENTRIES` entries on each append
    so the file size is bounded. None disables history-file
    emission (backward-compat default; pair with status_file when
    enabling)."""
    history_max_entries: int = 100
    """v0.9.5 P2.3: rolling cap on history file length. 100 entries
    × 1-hour poll interval = ~4 days of flapping-detection
    visibility. Operators with shorter poll intervals or wanting
    more history can raise this."""

    def __post_init__(self) -> None:
        if self.poll_interval_seconds < MIN_POLL_INTERVAL_SECONDS:
            raise ValueError(
                f"poll_interval_seconds must be >= "
                f"{MIN_POLL_INTERVAL_SECONDS}; got "
                f"{self.poll_interval_seconds}"
            )
        if self.window_days < 0:
            raise ValueError(
                f"window_days must be >= 0; got {self.window_days}"
            )


def write_daemon_status(
    status_file: Path,
    *,
    started_at: datetime,
    last_poll_at: datetime,
    last_poll_outcome: str,  # "success" | "failed"
    last_poll_error: str | None,
    recognized_cadence_count: int,
    unknown_cadence_count: int = 0,
    poll_interval_seconds: int,
    state_file: Path,
    window_days: int,
) -> None:
    """Atomically write a daemon-status JSON sidecar (v0.9.4 P2.1).

    Same atomic-write pattern as the state-file (write-to-temp +
    replace). Operators reading via ``GET /api/conmon/daemon-status``
    never see a half-written status.

    v0.9.4 Step 5.A F-V94-Q4 closure: renamed ``tracked_cadence_count``
    → ``recognized_cadence_count`` to accurately reflect the count
    semantic (excludes state-file slugs with no registered cadence).
    Operators inspecting the sidecar see both ``recognized_cadence_
    count`` + ``unknown_cadence_count`` so the totals reconcile with
    the raw state-file slug count.
    """
    payload: dict[str, Any] = {
        "started_at": started_at.isoformat(),
        "last_poll_at": last_poll_at.isoformat(),
        "last_poll_outcome": last_poll_outcome,
        "last_poll_error": last_poll_error,
        "recognized_cadence_count": recognized_cadence_count,
        "unknown_cadence_count": unknown_cadence_count,
        "poll_interval_seconds": poll_interval_seconds,
        "state_file": str(state_file),
        "window_days": window_days,
        "daemon_uptime_seconds": int(
            (last_poll_at - started_at).total_seconds()
        ),
    }
    # v0.9.5 P1.5: delegates atomic-write + .tmp cleanup to the
    # shared helper. Behavior is identical to the v0.9.4 inline
    # pattern (write-tmp → os.replace → cleanup-on-OSError); the
    # helper centralizes maintenance so future atomic-write sites
    # inherit the cleanup behavior for free.
    atomic_write_text(
        status_file,
        json.dumps(payload, indent=2, sort_keys=True),
    )


def append_daemon_history(
    history_file: Path,
    snapshot: dict[str, Any],
    *,
    max_entries: int = 100,
) -> None:
    """Append one snapshot to a JSONL rolling history file (v0.9.5 P2.3).

    Read-truncate-append-write pattern: the file is read in full,
    the new snapshot appended, the result trimmed to the last
    ``max_entries`` lines, then atomically written back. This is
    the simplest implementation that bounds the file size; for
    high-frequency poll intervals (< 5 min), operators should
    consider an external log rotator or downstream metrics
    pipeline instead.

    Args:
        history_file: JSONL output path. Created if missing.
        snapshot: Same payload shape as :func:`write_daemon_status`.
            One JSON object per line; one line per poll cycle.
        max_entries: Cap on retained entries. Defaults to 100,
            matching :attr:`DaemonConfig.history_max_entries`.

    Failure mode: on OSError the existing history file is
    untouched + the exception propagates. The atomic-write helper
    (:func:`atomic_write_text`) handles `.tmp` cleanup.
    """
    existing: list[str] = []
    if history_file.is_file():
        try:
            existing = history_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            # Treat read failure as "history corrupted; start fresh"
            # rather than crashing the daemon poll loop.
            existing = []
    existing.append(json.dumps(snapshot, sort_keys=True))
    if len(existing) > max_entries:
        existing = existing[-max_entries:]
    atomic_write_text(history_file, "\n".join(existing) + "\n")


def read_daemon_history(
    history_file: Path, *, limit: int | None = None
) -> list[dict[str, Any]]:
    """Read recent daemon-status snapshots from the history file.

    Args:
        history_file: JSONL path the daemon has been appending to.
        limit: Optional cap on returned entries; default ``None``
            returns every entry. Always returns the MOST RECENT
            entries (file tail) first sorted by file order (oldest
            at index 0, newest at index -1).

    Returns:
        List of parsed JSON payloads. Empty list if the file
        doesn't exist OR cannot be read. Individual lines that
        fail to parse are SKIPPED (the file may be mid-write or
        partially corrupted; remaining valid lines are still
        useful for flap detection).
    """
    if not history_file.is_file():
        return []
    try:
        lines = history_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    if limit is not None and limit > 0 and len(lines) > limit:
        lines = lines[-limit:]
    out: list[dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            out.append(parsed)
    return out


def read_daemon_status(status_file: Path) -> dict[str, Any] | None:
    """Read a daemon-status JSON sidecar (v0.9.4 P2.1).

    Returns the parsed payload or ``None`` if the file doesn't
    exist (daemon hasn't started, or operator hasn't configured
    ``--status-file``). Returns ``None`` also on parse failure
    (file is mid-write or corrupted) so the REST endpoint surfaces
    a graceful "no status available" instead of a 500.
    """
    if not status_file.is_file():
        return None
    try:
        raw = json.loads(status_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(raw, dict):
        return None
    return raw


@dataclass
class PollResult:
    """Aggregate observation from one poll cycle. Useful for tests."""

    today: date
    overdue: list[CycleObservation] = field(default_factory=list)
    due_soon: list[CycleObservation] = field(default_factory=list)
    current: list[CycleObservation] = field(default_factory=list)
    unknown_slugs: list[str] = field(default_factory=list)


#: Maximum permitted on-disk size for a conmon state file (v0.9.5
#: F-V93-S7 closure). A YAML mapping of slug → ISO-8601 date is
#: small by construction; even with a maximal 200-cadence registry
#: + 30-char slugs + ISO dates, the serialized file is well under
#: 16 KiB. The 1 MiB cap accommodates a 100× safety factor while
#: refusing to load operator-misconfigured or attacker-crafted
#: huge files that would consume excess memory in yaml.safe_load.
#: Operators with legitimate need can override via the
#: ``state_file_max_bytes`` parameter on :func:`load_state_file`.
DEFAULT_STATE_FILE_MAX_BYTES = 1 * 1024 * 1024  # 1 MiB


def load_state_file(
    path: Path,
    *,
    state_file_max_bytes: int = DEFAULT_STATE_FILE_MAX_BYTES,
) -> dict[str, date]:
    """Load a slug -> last_completed YAML state file.

    Schema matches :func:`evidentia.cli.conmon._load_last_completed_map`;
    duplicated here so the daemon library has no CLI-layer dependency.
    Raises :class:`ValueError` (not ``typer.Exit``) on parse failure
    so callers can decide their own error-handling posture.

    v0.9.5 F-V93-S7 closure: enforces a configurable size cap
    BEFORE invoking yaml.safe_load. Files exceeding
    ``state_file_max_bytes`` raise :class:`ValueError` without
    being parsed. Defends against a DoS where an attacker (or
    operator misconfiguration) replaces the state file with a
    multi-GB blob the daemon then tries to load into memory.
    """
    import yaml as yaml_mod

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError(f"could not stat {path}: {exc}") from exc
    if size > state_file_max_bytes:
        raise ValueError(
            f"{path} size {size} bytes exceeds the "
            f"{state_file_max_bytes} byte cap; refusing to load. "
            f"Override with state_file_max_bytes= if the legitimate "
            f"state file is genuinely larger (an operator with "
            f"hundreds of cadences may need to raise this)."
        )

    try:
        raw = yaml_mod.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml_mod.YAMLError as exc:
        raise ValueError(f"could not parse {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(
            f"{path} must be a YAML mapping of slug -> ISO-8601 date; "
            f"got {type(raw).__name__}"
        )

    out: dict[str, date] = {}
    for slug, value in raw.items():
        if not isinstance(slug, str):
            raise ValueError(
                f"cadence keys must be strings; got {slug!r}"
            )
        if isinstance(value, date):
            out[slug] = value
        elif isinstance(value, str):
            try:
                out[slug] = date.fromisoformat(value)
            except ValueError as exc:
                raise ValueError(
                    f"{slug!r} -> {value!r}: expected ISO-8601 date "
                    f"({exc})"
                ) from exc
        else:
            raise ValueError(
                f"{slug!r} -> {value!r}: expected ISO-8601 date string"
            )
    return out


def save_state_file(path: Path, state: dict[str, date]) -> None:
    """Atomically write a slug -> last_completed YAML state file.

    Atomicity via write-to-temp + rename, matching the v0.7.9
    vendor_store + v0.9.0 poam_store pattern. Operators can read the
    file concurrently without seeing a half-written state.
    """
    import yaml as yaml_mod

    serializable = {slug: when.isoformat() for slug, when in state.items()}
    # v0.9.5 P1.5: delegates atomic-write + .tmp cleanup to the
    # shared helper (see write_daemon_status for the same migration).
    atomic_write_text(
        path,
        yaml_mod.safe_dump(serializable, sort_keys=True),
    )


def mark_completed(
    state_file: Path,
    slug: str,
    when: date,
    use_lock: bool = False,
    lock_timeout_seconds: float = 5.0,
) -> date | None:
    """Record a cycle completion in the state file. Returns the
    previous ``last_completed`` value (or ``None`` if first mark).

    Emits :attr:`EventAction.CONMON_CYCLE_MARKED_COMPLETED` with
    the previous + new values so auditors can reconcile cycle-by-
    cycle progress.

    Raises :class:`ValueError` if the slug is not a registered
    cadence (operators should only mark cadences that exist).

    Concurrency (v0.9.4 P1.1 closes F-V93-Q3 HIGH):

    By default (``use_lock=False``) this function does a non-atomic
    read-modify-write on the state file (``load_state_file`` →
    mutate dict → ``save_state_file``). The ``os.replace`` in
    ``save_state_file`` is atomic, but the read-modify cycle is
    not. Concurrent ``mark_completed`` calls — e.g., two CI jobs
    marking different slugs, or a human + automation racing — may
    clobber each other's entries (last-writer-wins). The expected
    single-writer deployment model matches the precedent set by
    ``poam_store`` (v0.9.0) and ``vendor_store`` (v0.7.9).

    Pass ``use_lock=True`` to wrap the read-modify-write in a
    :class:`evidentia_core.security.FileLock` on a sidecar
    ``<state_file>.lock`` file. The lock serializes concurrent
    writers via ``fcntl.flock`` (POSIX) or ``msvcrt.locking``
    (Windows). Default off preserves v0.9.3 backward-compat perf
    path (no lock-file I/O); opt-in surfaces via the CLI
    ``--state-lock`` flag.

    Args:
        state_file: Path to the YAML state file.
        slug: Cadence slug to mark completed.
        when: ISO-8601 completion date.
        use_lock: Enable cross-process locking on the read-modify-
            write critical section. Default ``False``.
        lock_timeout_seconds: Maximum wait when ``use_lock=True``.
            Raises :class:`FileLockTimeout` if the lock isn't
            acquired within this window.

    Raises:
        ValueError: unknown cadence slug.
        FileLockTimeout: ``use_lock=True`` and lock unavailable.
    """
    cadence = get_cadence(slug)
    if cadence is None:
        raise ValueError(
            f"unknown cadence slug {slug!r}; cannot mark completed"
        )

    def _do_mark() -> date | None:
        state = load_state_file(state_file) if state_file.is_file() else {}
        previous = state.get(slug)
        state[slug] = when
        save_state_file(state_file, state)
        return previous

    if use_lock:
        from evidentia_core.security import FileLock

        lock_path = state_file.with_suffix(state_file.suffix + ".lock")
        with FileLock(lock_path, timeout_seconds=lock_timeout_seconds):
            previous = _do_mark()
    else:
        previous = _do_mark()

    _log.info(
        action=EventAction.CONMON_CYCLE_MARKED_COMPLETED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"CONMON cycle {slug!r} marked completed on "
            f"{when.isoformat()}"
        ),
        evidentia={
            "cadence_slug": slug,
            "framework": cadence.framework,
            "activity": cadence.activity,
            "previous_last_completed": (
                previous.isoformat() if previous is not None else None
            ),
            "new_last_completed": when.isoformat(),
            "used_lock": use_lock,
        },
    )
    return previous


def _classify_state(
    state: dict[str, date],
    today: date,
    window_days: int,
) -> PollResult:
    """Pure classification: bucket each tracked cadence by state."""
    result = PollResult(today=today)
    for slug, last_completed in state.items():
        cadence = get_cadence(slug)
        if cadence is None:
            result.unknown_slugs.append(slug)
            continue
        due = next_due(slug, last_completed)
        attention = derive_status(due, today, window_days=window_days)
        obs = CycleObservation(
            cadence=cadence,
            last_completed=last_completed,
            next_due=due,
            state=attention,
            days_until_due=(due - today).days,
        )
        if attention == CycleAttentionState.OVERDUE:
            result.overdue.append(obs)
        elif attention == CycleAttentionState.DUE_SOON:
            result.due_soon.append(obs)
        else:
            result.current.append(obs)
    return result


def poll_once(
    config: DaemonConfig,
    today: date | None = None,
) -> PollResult:
    """Execute one poll cycle. Returns the bucketed observations.

    Does NOT emit audit events or invoke callbacks — used by tests
    for the pure classification path. The full loop wires emit +
    callbacks via :func:`run_daemon`.
    """
    state = load_state_file(config.state_file)
    return _classify_state(
        state,
        today if today is not None else date.today(),
        config.window_days,
    )


def _emit_and_dispatch(
    result: PollResult,
    on_due_soon: CycleHandler | None,
    on_overdue: CycleHandler | None,
) -> None:
    """Emit audit events + invoke callbacks for one poll's result.

    Callback exceptions are caught + logged but do not propagate;
    one bad alert dispatcher shouldn't crash the daemon.
    """
    for obs in result.overdue:
        _log.warning(
            action=EventAction.CONMON_CYCLE_OVERDUE,
            outcome=EventOutcome.FAILURE,
            message=(
                f"CONMON cycle {obs.cadence.slug!r} is overdue "
                f"({obs.days_until_due} days past next-due)"
            ),
            evidentia={
                "cadence_slug": obs.cadence.slug,
                "framework": obs.cadence.framework,
                "activity": obs.cadence.activity,
                "last_completed": obs.last_completed.isoformat(),
                "next_due": obs.next_due.isoformat(),
                "days_until_due": obs.days_until_due,
            },
        )
        if on_overdue is not None:
            try:
                on_overdue(obs)
            except Exception as exc:
                _log.warning(
                    action=EventAction.CONMON_CYCLE_OVERDUE,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"on_overdue callback raised for "
                        f"{obs.cadence.slug!r}: {exc}"
                    ),
                )

    for obs in result.due_soon:
        _log.info(
            action=EventAction.CONMON_CYCLE_DUE,
            outcome=EventOutcome.SUCCESS,
            message=(
                f"CONMON cycle {obs.cadence.slug!r} due in "
                f"{obs.days_until_due} day(s)"
            ),
            evidentia={
                "cadence_slug": obs.cadence.slug,
                "framework": obs.cadence.framework,
                "activity": obs.cadence.activity,
                "last_completed": obs.last_completed.isoformat(),
                "next_due": obs.next_due.isoformat(),
                "days_until_due": obs.days_until_due,
            },
        )
        if on_due_soon is not None:
            try:
                on_due_soon(obs)
            except Exception as exc:
                _log.warning(
                    action=EventAction.CONMON_CYCLE_DUE,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"on_due_soon callback raised for "
                        f"{obs.cadence.slug!r}: {exc}"
                    ),
                )


def run_daemon(
    config: DaemonConfig,
    *,
    on_due_soon: CycleHandler | None = None,
    on_overdue: CycleHandler | None = None,
    shutdown_event: threading.Event | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> None:
    """Run the poll loop until ``shutdown_event`` is set.

    Emits :attr:`EventAction.CONMON_DAEMON_STARTED` at boot and
    :attr:`EventAction.CONMON_DAEMON_STOPPED` at graceful shutdown.
    Per-cycle audit events + callbacks are dispatched by
    :func:`_emit_and_dispatch`.

    The ``sleep_fn`` parameter is the test injection point —
    tests pass a synchronous mock that decrements a counter so the
    loop terminates after N polls without actually sleeping.

    Args:
        config: Operator-supplied daemon configuration. Read once
            at boot; the state file is re-loaded each poll cycle so
            operators can mark cycles completed without daemon
            restart.
        on_due_soon: Optional callback invoked per due-soon cycle.
            Plug point for P1.2 alerting.
        on_overdue: Optional callback invoked per overdue cycle.
            Plug point for P1.2 alerting.
        shutdown_event: Optional threading.Event for graceful
            shutdown. If None, the daemon polls forever (caller
            must use a process-level signal).
        sleep_fn: Injected sleep implementation. Defaults to
            ``time.sleep``; tests inject a no-op or counter.
    """
    if shutdown_event is None:
        shutdown_event = threading.Event()

    started_at = datetime.now(tz=UTC)

    _log.info(
        action=EventAction.CONMON_DAEMON_STARTED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"CONMON daemon started (poll_interval="
            f"{config.poll_interval_seconds}s, "
            f"window_days={config.window_days}, "
            f"state_file={config.state_file})"
        ),
        evidentia={
            "poll_interval_seconds": config.poll_interval_seconds,
            "state_file": str(config.state_file),
            "window_days": config.window_days,
            "status_file": (
                str(config.status_file)
                if config.status_file is not None
                else None
            ),
        },
    )

    try:
        while not shutdown_event.is_set():
            poll_at = datetime.now(tz=UTC)
            recognized_count = 0
            unknown_count = 0
            outcome = "success"
            error_msg: str | None = None
            try:
                result = poll_once(config)
                _emit_and_dispatch(result, on_due_soon, on_overdue)
                recognized_count = (
                    len(result.overdue)
                    + len(result.due_soon)
                    + len(result.current)
                )
                unknown_count = len(result.unknown_slugs)
            except (ValueError, OSError) as exc:
                # State file errors are operator-actionable: we log
                # but keep polling so a transient FS issue doesn't
                # kill the daemon (e.g., file briefly absent during
                # operator edit). Use the dedicated POLL_FAILED
                # action so SIEM filters separate daemon-health
                # problems from genuine CYCLE_OVERDUE signals
                # (v0.9.3 F-V93-Q5 review fix).
                outcome = "failed"
                error_msg = f"{exc.__class__.__name__}: {exc}"
                _log.warning(
                    action=EventAction.CONMON_DAEMON_POLL_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"poll cycle skipped: {exc}; will retry at "
                        f"next interval"
                    ),
                )

            # v0.9.4 P2.1: write status sidecar after each poll
            # (success or failure) so the REST endpoint can serve
            # operator health-check queries. Best-effort: a status-
            # file write failure is logged but does not crash the
            # daemon (status visibility is auxiliary, not critical).
            #
            # v0.9.5 P2.3: in addition to the point-in-time status
            # sidecar, append the same payload to a rolling history
            # JSONL file (capped at config.history_max_entries) so
            # the GET /api/conmon/daemon-history endpoint can detect
            # flapping daemons that the status sidecar's point-in-
            # time view can't reveal.
            if config.status_file is not None:
                snapshot: dict[str, Any] = {
                    "started_at": started_at.isoformat(),
                    "last_poll_at": poll_at.isoformat(),
                    "last_poll_outcome": outcome,
                    "last_poll_error": error_msg,
                    "recognized_cadence_count": recognized_count,
                    "unknown_cadence_count": unknown_count,
                    "poll_interval_seconds": config.poll_interval_seconds,
                    "state_file": str(config.state_file),
                    "window_days": config.window_days,
                    "daemon_uptime_seconds": int(
                        (poll_at - started_at).total_seconds()
                    ),
                }
                with contextlib.suppress(OSError):
                    write_daemon_status(
                        config.status_file,
                        started_at=started_at,
                        last_poll_at=poll_at,
                        last_poll_outcome=outcome,
                        last_poll_error=error_msg,
                        recognized_cadence_count=recognized_count,
                        unknown_cadence_count=unknown_count,
                        poll_interval_seconds=config.poll_interval_seconds,
                        state_file=config.state_file,
                        window_days=config.window_days,
                    )
                if config.history_file is not None:
                    with contextlib.suppress(OSError):
                        append_daemon_history(
                            config.history_file,
                            snapshot,
                            max_entries=config.history_max_entries,
                        )

            # shutdown_event.wait() respects sleep interruption —
            # operators get sub-poll-interval shutdown latency.
            # When sleep_fn is overridden (test path), fall back to
            # the injected fn so tests can drive the loop count.
            if sleep_fn is time.sleep:
                shutdown_event.wait(timeout=config.poll_interval_seconds)
            else:
                # Test injection: call the mock + check shutdown.
                # v0.9.5 F-V94-Q8 closure: sleep_fn is now typed as
                # Callable[[float], None] so the type: ignore is
                # no longer required.
                sleep_fn(config.poll_interval_seconds)
    finally:
        _log.info(
            action=EventAction.CONMON_DAEMON_STOPPED,
            outcome=EventOutcome.SUCCESS,
            message="CONMON daemon stopped (graceful shutdown)",
            evidentia={
                "state_file": str(config.state_file),
            },
        )
