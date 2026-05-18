"""CONMON daemon alerting (v0.9.3 P1.2).

Plug-point for the v0.9.3 P1.1 daemon's ``on_due_soon`` /
``on_overdue`` callback hooks. Defines:

- :class:`AlertChannel` Protocol — what a sender (SMTP, webhook,
  custom) must implement.
- :class:`AlertDeduper` — file-backed dedup state so the same
  (cadence_slug, state) doesn't spam operators on every poll.
- :func:`make_alert_handler` — wires a list of channels + a
  deduper into a single :class:`CycleHandler` suitable for
  :func:`evidentia_core.conmon.daemon.run_daemon`.

- :func:`resolve_secret` — secret-handling helper enforcing the
  file > env > error precedence per the v0.9.3 cycle-open sign-off.
  Never accepts secrets as positional arguments; callers MUST go
  through this resolver.

Reference implementations of :class:`AlertChannel` for SMTP and
generic HTTP webhook live in ``evidentia_integrations.alerting.*``.
Operators implementing their own channel just need a callable
matching the Protocol signature.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.conmon.daemon import CycleHandler, CycleObservation
from evidentia_core.security.atomic_write import atomic_write_text

_log = get_logger("evidentia_core.conmon.alerting")

DEFAULT_SUPPRESSION_HOURS = 24
"""Per-(slug, state) suppression window. Within this window, repeat
detections of the same cycle in the same state will be suppressed.
24 hours matches the cadence at which an operator workday
naturally surfaces missed alerts — finer windows risk spam, longer
windows risk silent transitions."""


# ── secret resolution ─────────────────────────────────────────────


def resolve_secret(
    file_arg: Path | None,
    env_var: str,
    purpose: str,
) -> str:
    """Resolve a secret per the file > env > error precedence.

    Per Allen's global secret-handling protocol + the v0.9.3 cycle-
    open sign-off question-4: secrets MUST come from a file or env
    var, never a CLI positional/option value. This helper enforces
    the contract centrally so every channel uses the same path.

    Resolution precedence:

    1. ``file_arg`` (if provided): read + strip; the file's
       permissions are the operator's responsibility (typically
       chmod 600 + ACL on the deploy host).
    2. ``env_var`` (if set + non-empty): used directly.
    3. Raises :class:`ValueError` with a clear message naming
       both options.

    Args:
        file_arg: Optional path passed via ``--*-file`` CLI flag.
        env_var: Environment variable name to fall back to.
        purpose: Human-readable description for error messages
            (e.g., ``"SMTP password"`` or ``"webhook HMAC secret"``).

    Returns:
        The secret value (whitespace-stripped).

    Raises:
        ValueError: If neither source resolves to a non-empty value.
        OSError: If the file path is provided but unreadable.
    """
    if file_arg is not None:
        # File path operator-controlled; trust it.
        value = file_arg.read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError(
                f"{purpose}: file {file_arg} is empty"
            )
        return value

    env_value = os.environ.get(env_var, "").strip()
    if env_value:
        return env_value

    raise ValueError(
        f"{purpose}: provide via --*-file flag or {env_var} env "
        f"var; CLI value flags are not accepted for secrets"
    )


# ── alert channel protocol ────────────────────────────────────────


class AlertChannel(Protocol):
    """Concrete sender interface. SMTP + webhook implementations
    live in evidentia_integrations.alerting.*."""

    name: str
    """Channel identifier for audit events ('smtp', 'webhook',
    operator-custom)."""

    def dispatch(self, obs: CycleObservation) -> None:
        """Send one alert. Implementations may raise on transient
        failures; the daemon's callback-exception handler will log
        + continue without retry (operators wire retry/queue in
        their own infrastructure)."""
        ...


# ── deduplication ─────────────────────────────────────────────────


@dataclass
class AlertDeduper:
    """File-backed per-(slug, state) suppression window.

    State file format (JSON, atomic-write via temp + rename):

        {
          "nist-800-53-rev5-ca7|overdue": "2026-05-16T03:00:00+00:00",
          ...
        }

    Operators can inspect the state file directly; the daemon
    re-reads it each call so external edits propagate.

    Concurrency (v0.9.4 P1.1 closes F-V93-Q3 HIGH): by default
    (``use_lock=False``) ``mark_dispatched`` does a non-atomic
    read-modify-write on the state file. Pass ``use_lock=True`` to
    serialize concurrent dispatchers via
    :class:`evidentia_core.security.FileLock` on a sidecar
    ``<state_file>.lock`` file. ``should_suppress`` is a read-only
    check and remains unlocked (eventual consistency is acceptable
    for "should I bother dispatching?" decisions).
    """

    state_file: Path
    suppression: timedelta
    # v0.9.4 Step 5.A F-V94-Q7 closure: mark concurrency-control
    # fields kw_only=True so legacy positional callers
    # (state_file, suppression) can never accidentally bind values
    # to use_lock / lock_timeout_seconds. Python 3.10+ dataclass
    # kw_only field support.
    use_lock: bool = field(default=False, kw_only=True)
    lock_timeout_seconds: float = field(default=5.0, kw_only=True)
    # v0.9.5 F-V93-Q4 closure: cache the parsed state dict + the
    # underlying file's mtime_ns. On the hot path
    # (should_suppress + mark_dispatched fire ~once per cycle, per
    # cadence, per channel; a 7-cadence/3-channel daemon = 21
    # _load_state calls per poll), re-reading + re-parsing the
    # JSON every call is wasteful. The cache returns the prior
    # dict iff the file's mtime hasn't changed. The cache is
    # invalidated on file-not-found OR on mtime advance. NOT
    # frozen at first load — a subprocess editing the state file
    # advances mtime + we re-read.
    _cache_mtime_ns: int | None = field(default=None, init=False, repr=False)
    _cache_state: dict[str, datetime] | None = field(
        default=None, init=False, repr=False
    )

    @classmethod
    def from_hours(
        cls,
        state_file: Path,
        hours: float,
        *,
        use_lock: bool = False,
        lock_timeout_seconds: float = 5.0,
    ) -> AlertDeduper:
        if hours < 0:
            raise ValueError(f"suppression hours must be >= 0; got {hours}")
        return cls(
            state_file=state_file,
            suppression=timedelta(hours=hours),
            use_lock=use_lock,
            lock_timeout_seconds=lock_timeout_seconds,
        )

    def _load_state(self) -> dict[str, datetime]:
        if not self.state_file.is_file():
            # File missing: invalidate any cached state + return empty.
            self._cache_mtime_ns = None
            self._cache_state = None
            return {}
        # v0.9.5 F-V93-Q4: cache hit when mtime unchanged.
        try:
            mtime_ns = self.state_file.stat().st_mtime_ns
        except OSError:
            mtime_ns = None
        if (
            mtime_ns is not None
            and self._cache_mtime_ns == mtime_ns
            and self._cache_state is not None
        ):
            # Cache valid: return a copy so callers mutating the dict
            # don't corrupt the cache.
            return dict(self._cache_state)
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # v0.9.3 F-V93-Q10 closure: corrupted dedup state
            # shouldn't block alerting (fail-open). v0.9.4 Step 5.A
            # F-V94-Q5 closure: gate the backup-rename + audit-event
            # on whether the backup file already exists, so concurrent
            # dispatchers racing past a transient corruption don't
            # both fire conflicting audit events (the second racer
            # quietly observes the first racer's backup).
            backup_ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
            backup_path = self.state_file.with_suffix(
                f"{self.state_file.suffix}.corrupt-{backup_ts}"
            )
            # Best-effort rename; if a concurrent dispatcher already
            # backed up this corruption window, our rename will fail
            # (file gone) and we skip the audit event.
            renamed = False
            try:
                self.state_file.rename(backup_path)
                renamed = True
            except OSError:
                # Either backup_path exists (race lost) or the source
                # was already moved by a concurrent caller. Either
                # way: corruption already observed + handled.
                pass
            if renamed:
                _log.warning(
                    action=EventAction.CONMON_ALERT_SUPPRESSED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"alert dedup state {self.state_file} corrupted "
                        f"({exc.__class__.__name__}); reset (backup: "
                        f"{backup_path.name}). Suppression history "
                        f"lost; next poll may re-alert on already-"
                        f"handled cycles."
                    ),
                )
            return {}
        out: dict[str, datetime] = {}
        for key, ts_str in raw.items():
            if not isinstance(key, str) or not isinstance(ts_str, str):
                continue
            try:
                out[key] = datetime.fromisoformat(ts_str)
            except ValueError:
                continue
        # v0.9.5 F-V93-Q4: prime the cache. Subsequent calls return
        # this dict as long as the mtime is unchanged.
        if mtime_ns is not None:
            self._cache_mtime_ns = mtime_ns
            self._cache_state = dict(out)
        return out

    def _save_state(self, state: dict[str, datetime]) -> None:
        # v0.9.5 P1.5: delegates atomic-write + .tmp cleanup to the
        # shared helper (see daemon.write_daemon_status for the same
        # migration). Functionally identical to the v0.9.4 inline
        # pattern.
        serializable = {k: v.isoformat() for k, v in state.items()}
        atomic_write_text(
            self.state_file,
            json.dumps(serializable, indent=2, sort_keys=True),
        )
        # v0.9.5 F-V93-Q4: refresh cache from the just-written state.
        # We could let the next _load_state re-stat + re-parse, but
        # priming directly avoids a redundant disk read after every
        # mark_dispatched.
        try:
            self._cache_mtime_ns = self.state_file.stat().st_mtime_ns
            self._cache_state = dict(state)
        except OSError:
            # If we can't stat the file we just wrote, drop the cache
            # to force a fresh read next time.
            self._cache_mtime_ns = None
            self._cache_state = None

    @staticmethod
    def _key(obs: CycleObservation) -> str:
        return f"{obs.cadence.slug}|{obs.state.value}"

    def list_entries(
        self, slug_filter: str | None = None
    ) -> list[tuple[str, str, datetime]]:
        """Return all dedup entries as ``(slug, state, last_dispatched)``
        tuples, sorted by ``last_dispatched`` descending (newest first).

        v0.9.4 P2.2: read-only helper for the ``evidentia conmon
        dedup-list`` CLI verb. Pure read; does NOT mutate state.

        Args:
            slug_filter: Optional cadence-slug filter. Returns only
                entries whose slug matches exactly. None returns all.

        Returns:
            List of (slug, state, last_dispatched_utc) tuples. Empty
            list if the dedup file doesn't exist or has no entries.
        """
        state = self._load_state()
        entries: list[tuple[str, str, datetime]] = []
        for key, ts in state.items():
            # Keys are "<slug>|<state>" per ``_key()``. Handle malformed
            # keys defensively — they can't be observation-derived.
            parts = key.split("|", 1)
            if len(parts) != 2:
                continue
            slug, state_name = parts
            if slug_filter is not None and slug != slug_filter:
                continue
            # Tolerate naive datetimes in stored state (legacy).
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=UTC)
            entries.append((slug, state_name, ts))
        entries.sort(key=lambda e: e[2], reverse=True)
        return entries

    def should_suppress(
        self, obs: CycleObservation, now: datetime | None = None
    ) -> bool:
        """Return True if an alert for this (slug, state) was fired
        within the suppression window. Pure read; does NOT mark.
        """
        state = self._load_state()
        last = state.get(self._key(obs))
        if last is None:
            return False
        check_now = now if now is not None else datetime.now(tz=UTC)
        # Tolerate naive datetimes in stored state (legacy format).
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        return (check_now - last) < self.suppression

    def mark_dispatched(
        self, obs: CycleObservation, now: datetime | None = None
    ) -> None:
        """Record that an alert was dispatched for this (slug, state).
        Caller invokes this AFTER a successful channel.dispatch().

        Concurrency (v0.9.4 P1.1 closes F-V93-Q3 HIGH):

        By default (``use_lock=False`` on the AlertDeduper instance)
        this method does a non-atomic read-modify-write on the dedup
        state file. Concurrent dispatchers may clobber each other's
        mark entries (last-writer-wins). The expected deployment
        model is one daemon process per state file — matches the
        precedent set by ``poam_store`` (v0.9.0) and ``vendor_store``
        (v0.7.9).

        When the operator constructs ``AlertDeduper(..., use_lock=
        True)`` (typically via the CLI ``--state-lock`` flag), the
        read-modify-write is wrapped in a
        :class:`evidentia_core.security.FileLock` on a sidecar
        ``<state_file>.lock`` file. Concurrent dispatchers serialize
        cleanly.
        """

        def _do_mark() -> None:
            state = self._load_state()
            state[self._key(obs)] = (
                now if now is not None else datetime.now(tz=UTC)
            )
            self._save_state(state)

        if self.use_lock:
            from evidentia_core.security import FileLock

            lock_path = self.state_file.with_suffix(
                self.state_file.suffix + ".lock"
            )
            with FileLock(
                lock_path, timeout_seconds=self.lock_timeout_seconds
            ):
                _do_mark()
        else:
            _do_mark()


# ── handler factory ───────────────────────────────────────────────


def make_alert_handler(
    channels: list[AlertChannel],
    deduper: AlertDeduper | None = None,
) -> CycleHandler:
    """Build a :class:`CycleHandler` that dispatches to each channel
    after the dedup check.

    The returned callable matches the signature expected by
    :func:`evidentia_core.conmon.daemon.run_daemon`'s ``on_due_soon``
    + ``on_overdue`` parameters. Per-channel failures are logged but
    do not stop sibling dispatches — one broken webhook shouldn't
    silence the SMTP channel.

    Args:
        channels: Ordered list of alert channels. Empty list returns
            a no-op handler (useful for testing the daemon without
            wiring alerting).
        deduper: Optional dedup state. ``None`` disables dedup
            (every cycle observation dispatches every poll — only
            sensible for testing).

    Returns:
        A callable suitable for ``on_due_soon`` / ``on_overdue``.
    """

    def _handler(obs: CycleObservation) -> None:
        if deduper is not None and deduper.should_suppress(obs):
            _log.info(
                action=EventAction.CONMON_ALERT_SUPPRESSED,
                outcome=EventOutcome.SUCCESS,
                message=(
                    f"alert for {obs.cadence.slug!r} state="
                    f"{obs.state.value!r} suppressed within "
                    f"{deduper.suppression.total_seconds() / 3600:.1f}h "
                    f"window"
                ),
                evidentia={
                    "cadence_slug": obs.cadence.slug,
                    "state": obs.state.value,
                    "suppression_window_hours": (
                        deduper.suppression.total_seconds() / 3600
                    ),
                },
            )
            return

        any_succeeded = False
        for channel in channels:
            try:
                channel.dispatch(obs)
            except Exception as exc:
                _log.warning(
                    action=EventAction.CONMON_ALERT_DISPATCHED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"alert dispatch failed on channel "
                        f"{channel.name!r} for {obs.cadence.slug!r}: "
                        f"{exc}"
                    ),
                    evidentia={
                        "cadence_slug": obs.cadence.slug,
                        "state": obs.state.value,
                        "channel": channel.name,
                    },
                )
                continue
            any_succeeded = True
            _log.info(
                action=EventAction.CONMON_ALERT_DISPATCHED,
                outcome=EventOutcome.SUCCESS,
                message=(
                    f"alert dispatched on channel {channel.name!r} "
                    f"for {obs.cadence.slug!r} state="
                    f"{obs.state.value!r}"
                ),
                evidentia={
                    "cadence_slug": obs.cadence.slug,
                    "state": obs.state.value,
                    "channel": channel.name,
                },
            )

        # Only mark dedup when at least one channel succeeded;
        # otherwise next poll retries. Operators relying on dedup
        # for noise reduction get noise back as a feature signal
        # that their alerting infrastructure is broken.
        if any_succeeded and deduper is not None:
            deduper.mark_dispatched(obs)

    return _handler
