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

import contextlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.conmon.daemon import CycleHandler, CycleObservation

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
    """

    state_file: Path
    suppression: timedelta

    @classmethod
    def from_hours(cls, state_file: Path, hours: float) -> AlertDeduper:
        if hours < 0:
            raise ValueError(f"suppression hours must be >= 0; got {hours}")
        return cls(
            state_file=state_file,
            suppression=timedelta(hours=hours),
        )

    def _load_state(self) -> dict[str, datetime]:
        if not self.state_file.is_file():
            return {}
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # v0.9.3 F-V93-Q10 review fix: corrupted dedup state
            # shouldn't block alerting (fail-open), but the original
            # file is preserved as `.json.corrupt-<utc-iso>` and a
            # WARNING audit event fires so operators see the loss of
            # suppression history. Best-effort: if backup fails (e.g.,
            # permission denied), fall through to the alert-anyway
            # behavior so the daemon stays useful.
            backup_ts = datetime.now(tz=UTC).strftime("%Y%m%dT%H%M%SZ")
            backup_path = self.state_file.with_suffix(
                f"{self.state_file.suffix}.corrupt-{backup_ts}"
            )
            with contextlib.suppress(OSError):
                self.state_file.rename(backup_path)
            _log.warning(
                action=EventAction.CONMON_ALERT_SUPPRESSED,
                outcome=EventOutcome.FAILURE,
                message=(
                    f"alert dedup state {self.state_file} corrupted "
                    f"({exc.__class__.__name__}); reset (backup: "
                    f"{backup_path.name}). Suppression history lost; "
                    f"next poll may re-alert on already-handled cycles."
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
        return out

    def _save_state(self, state: dict[str, datetime]) -> None:
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_file.with_suffix(self.state_file.suffix + ".tmp")
        serializable = {k: v.isoformat() for k, v in state.items()}
        tmp.write_text(
            json.dumps(serializable, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        tmp.replace(self.state_file)

    @staticmethod
    def _key(obs: CycleObservation) -> str:
        return f"{obs.cadence.slug}|{obs.state.value}"

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

        Single-writer contract (v0.9.3 F-V93-Q3 review note): this
        method does a read-modify-write on the dedup state file
        without taking a file lock. Concurrent callers may clobber
        each other's mark entries (last-writer-wins). The expected
        deployment model is one daemon process per state file —
        matches the precedent set by ``poam_store`` (v0.9.0) and
        ``vendor_store`` (v0.7.9). Operators running multiple
        daemons against shared state should partition by slug
        prefix or wire a higher-level lock.
        """
        state = self._load_state()
        state[self._key(obs)] = (
            now if now is not None else datetime.now(tz=UTC)
        )
        self._save_state(state)


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
