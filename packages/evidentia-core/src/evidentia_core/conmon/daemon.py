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

import threading
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Protocol

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.conmon.calendar import (
    ConmonCadence,
    CycleAttentionState,
    derive_status,
    get_cadence,
    next_due,
)

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


@dataclass
class PollResult:
    """Aggregate observation from one poll cycle. Useful for tests."""

    today: date
    overdue: list[CycleObservation] = field(default_factory=list)
    due_soon: list[CycleObservation] = field(default_factory=list)
    current: list[CycleObservation] = field(default_factory=list)
    unknown_slugs: list[str] = field(default_factory=list)


def load_state_file(path: Path) -> dict[str, date]:
    """Load a slug -> last_completed YAML state file.

    Schema matches :func:`evidentia.cli.conmon._load_last_completed_map`;
    duplicated here so the daemon library has no CLI-layer dependency.
    Raises :class:`ValueError` (not ``typer.Exit``) on parse failure
    so callers can decide their own error-handling posture.
    """
    import yaml as yaml_mod

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
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        yaml_mod.safe_dump(serializable, sort_keys=True),
        encoding="utf-8",
    )
    tmp.replace(path)


def mark_completed(
    state_file: Path,
    slug: str,
    when: date,
) -> date | None:
    """Record a cycle completion in the state file. Returns the
    previous ``last_completed`` value (or ``None`` if first mark).

    Emits :attr:`EventAction.CONMON_CYCLE_MARKED_COMPLETED` with
    the previous + new values so auditors can reconcile cycle-by-
    cycle progress.

    Raises :class:`ValueError` if the slug is not a registered
    cadence (operators should only mark cadences that exist).

    Single-writer contract (v0.9.3 F-V93-Q3 review note): this
    function does a non-atomic read-modify-write on the state file
    (``load_state_file`` → mutate dict → ``save_state_file``). The
    ``os.replace`` in ``save_state_file`` is atomic, but the read-
    modify cycle is not. Concurrent ``mark_completed`` calls — e.g.,
    two CI jobs marking different slugs, or a human + automation
    racing — may clobber each other's entries (last-writer-wins).
    The expected deployment model is one writer per state file,
    matching the precedent set by ``poam_store`` (v0.9.0) and
    ``vendor_store`` (v0.7.9). Operators needing multi-writer
    semantics should wire a higher-level lock (or partition by
    slug-prefix into separate state files).
    """
    cadence = get_cadence(slug)
    if cadence is None:
        raise ValueError(
            f"unknown cadence slug {slug!r}; cannot mark completed"
        )

    state = load_state_file(state_file) if state_file.is_file() else {}

    previous = state.get(slug)
    state[slug] = when
    save_state_file(state_file, state)

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
    sleep_fn: object = time.sleep,
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
        },
    )

    try:
        while not shutdown_event.is_set():
            try:
                result = poll_once(config)
                _emit_and_dispatch(result, on_due_soon, on_overdue)
            except (ValueError, OSError) as exc:
                # State file errors are operator-actionable: we log
                # but keep polling so a transient FS issue doesn't
                # kill the daemon (e.g., file briefly absent during
                # operator edit). Use the dedicated POLL_FAILED
                # action so SIEM filters separate daemon-health
                # problems from genuine CYCLE_OVERDUE signals
                # (v0.9.3 F-V93-Q5 review fix).
                _log.warning(
                    action=EventAction.CONMON_DAEMON_POLL_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"poll cycle skipped: {exc}; will retry at "
                        f"next interval"
                    ),
                )

            # shutdown_event.wait() respects sleep interruption —
            # operators get sub-poll-interval shutdown latency.
            # When sleep_fn is overridden (test path), fall back to
            # the injected fn so tests can drive the loop count.
            if sleep_fn is time.sleep:
                shutdown_event.wait(timeout=config.poll_interval_seconds)
            else:
                # Test injection: call the mock + check shutdown.
                sleep_fn(config.poll_interval_seconds)  # type: ignore[operator]
    finally:
        _log.info(
            action=EventAction.CONMON_DAEMON_STOPPED,
            outcome=EventOutcome.SUCCESS,
            message="CONMON daemon stopped (graceful shutdown)",
            evidentia={
                "state_file": str(config.state_file),
            },
        )
