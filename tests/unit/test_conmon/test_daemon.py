"""Unit tests for evidentia_core.conmon.daemon (v0.9.3 P1.1)."""

from __future__ import annotations

import threading
from datetime import date
from pathlib import Path

import pytest
from evidentia_core.audit import EventAction
from evidentia_core.conmon import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    CycleObservation,
    DaemonConfig,
    load_state_file,
    mark_completed,
    poll_once,
    run_daemon,
    save_state_file,
)

# ── DaemonConfig validation ───────────────────────────────────────


class TestDaemonConfig:
    """Constructor invariants and defaults."""

    def test_defaults(self, tmp_path: Path) -> None:
        cfg = DaemonConfig(state_file=tmp_path / "state.yaml")
        assert cfg.poll_interval_seconds == DEFAULT_POLL_INTERVAL_SECONDS
        assert cfg.window_days == 14

    def test_rejects_sub_minimum_poll_interval(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="poll_interval_seconds"):
            DaemonConfig(
                state_file=tmp_path / "state.yaml",
                poll_interval_seconds=MIN_POLL_INTERVAL_SECONDS - 1,
            )

    def test_accepts_exact_minimum(self, tmp_path: Path) -> None:
        cfg = DaemonConfig(
            state_file=tmp_path / "state.yaml",
            poll_interval_seconds=MIN_POLL_INTERVAL_SECONDS,
        )
        assert cfg.poll_interval_seconds == MIN_POLL_INTERVAL_SECONDS

    def test_rejects_negative_window_days(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="window_days"):
            DaemonConfig(
                state_file=tmp_path / "state.yaml",
                window_days=-1,
            )

    def test_accepts_zero_window_days(self, tmp_path: Path) -> None:
        cfg = DaemonConfig(
            state_file=tmp_path / "state.yaml",
            window_days=0,
        )
        assert cfg.window_days == 0


# ── State file round-trip ─────────────────────────────────────────


class TestStateFileRoundTrip:
    """load + save are inverses."""

    def test_save_then_load_roundtrips(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        state = {
            "nist-800-53-rev5-ca7": date(2026, 4, 1),
            "fedramp-conmon-poam": date(2026, 4, 15),
        }
        save_state_file(state_file, state)
        loaded = load_state_file(state_file)
        assert loaded == state

    def test_save_creates_parent_dir(self, tmp_path: Path) -> None:
        state_file = tmp_path / "nested" / "deep" / "state.yaml"
        save_state_file(state_file, {"nist-800-53-rev5-ca7": date(2026, 4, 1)})
        assert state_file.is_file()

    def test_load_rejects_non_dict(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text("- just\n- a\n- list\n", encoding="utf-8")
        with pytest.raises(ValueError, match="YAML mapping"):
            load_state_file(state_file)

    def test_load_rejects_non_iso_date(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text(
            "nist-800-53-rev5-ca7: not-a-date\n", encoding="utf-8"
        )
        with pytest.raises(ValueError, match="ISO-8601 date"):
            load_state_file(state_file)

    def test_load_rejects_invalid_yaml(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        state_file.write_text("nist:: not valid: yaml:\n", encoding="utf-8")
        with pytest.raises(ValueError, match="could not parse"):
            load_state_file(state_file)


# ── mark_completed ────────────────────────────────────────────────


class TestMarkCompleted:
    """Cycle completion recording + audit emission."""

    def test_first_mark_returns_none_previous(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        previous = mark_completed(
            state_file,
            "nist-800-53-rev5-ca7",
            date(2026, 5, 1),
        )
        assert previous is None
        # And the state file now reflects the mark
        loaded = load_state_file(state_file)
        assert loaded == {"nist-800-53-rev5-ca7": date(2026, 5, 1)}

    def test_subsequent_mark_returns_previous(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        mark_completed(
            state_file, "nist-800-53-rev5-ca7", date(2026, 4, 1)
        )
        previous = mark_completed(
            state_file, "nist-800-53-rev5-ca7", date(2026, 5, 1)
        )
        assert previous == date(2026, 4, 1)

    def test_unknown_slug_raises(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        with pytest.raises(ValueError, match="unknown cadence slug"):
            mark_completed(state_file, "no-such-cadence", date(2026, 5, 1))

    def test_emits_audit_event(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        state_file = tmp_path / "state.yaml"
        with caplog.at_level("INFO", logger="evidentia_core.conmon.daemon"):
            mark_completed(
                state_file,
                "nist-800-53-rev5-ca7",
                date(2026, 5, 1),
            )
        actions = [
            getattr(r, "ecs_record", {}).get("event", {}).get("action")
            for r in caplog.records
        ]
        assert EventAction.CONMON_CYCLE_MARKED_COMPLETED.value in actions


# ── poll_once ─────────────────────────────────────────────────────


class TestPollOnce:
    """Pure classification path (no audit emission, no callbacks)."""

    def test_buckets_overdue_due_soon_current(
        self, tmp_path: Path
    ) -> None:
        state_file = tmp_path / "state.yaml"
        save_state_file(
            state_file,
            {
                # Monthly cadence, last completed 2026-01-01 -> next-
                # due 2026-02-01 -> overdue as of 2026-05-15
                "nist-800-53-rev5-ca7": date(2026, 1, 1),
                # Monthly cadence, last completed 2026-05-10 -> next-
                # due 2026-06-10 -> current as of 2026-05-15
                "fedramp-conmon-poam": date(2026, 5, 10),
                # Annual cadence, last completed 2025-06-01 -> next-
                # due 2026-06-01 -> due-soon as of 2026-05-25
                "fedramp-conmon-annual": date(2025, 6, 1),
            },
        )
        cfg = DaemonConfig(state_file=state_file, window_days=14)
        result = poll_once(cfg, today=date(2026, 5, 25))

        assert {o.cadence.slug for o in result.overdue} == {
            "nist-800-53-rev5-ca7"
        }
        assert {o.cadence.slug for o in result.due_soon} == {
            "fedramp-conmon-annual"
        }
        assert {o.cadence.slug for o in result.current} == {
            "fedramp-conmon-poam"
        }
        assert result.unknown_slugs == []

    def test_unknown_slugs_collected(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        save_state_file(
            state_file,
            {"made-up-slug-xyz": date(2026, 1, 1)},
        )
        cfg = DaemonConfig(state_file=state_file)
        result = poll_once(cfg, today=date(2026, 5, 15))
        assert result.unknown_slugs == ["made-up-slug-xyz"]


# ── run_daemon (with injected sleep_fn for finite loops) ──────────


class TestRunDaemon:
    """The full poll loop with synchronous sleep injection."""

    def test_emits_started_and_stopped_events(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        state_file = tmp_path / "state.yaml"
        save_state_file(state_file, {})
        cfg = DaemonConfig(
            state_file=state_file,
            poll_interval_seconds=MIN_POLL_INTERVAL_SECONDS,
        )

        # Shutdown after the first sleep call.
        shutdown = threading.Event()

        def fake_sleep(_seconds: float) -> None:
            shutdown.set()

        with caplog.at_level("INFO", logger="evidentia_core.conmon.daemon"):
            run_daemon(cfg, shutdown_event=shutdown, sleep_fn=fake_sleep)

        action_values = {
            getattr(r, "ecs_record", {}).get("event", {}).get("action")
            for r in caplog.records
        }
        assert EventAction.CONMON_DAEMON_STARTED.value in action_values
        assert EventAction.CONMON_DAEMON_STOPPED.value in action_values

    def test_invokes_overdue_callback(self, tmp_path: Path) -> None:
        state_file = tmp_path / "state.yaml"
        save_state_file(
            state_file,
            {"nist-800-53-rev5-ca7": date(2025, 1, 1)},
        )
        cfg = DaemonConfig(
            state_file=state_file,
            poll_interval_seconds=MIN_POLL_INTERVAL_SECONDS,
        )

        observations: list[CycleObservation] = []
        shutdown = threading.Event()

        def fake_sleep(_seconds: float) -> None:
            shutdown.set()

        def overdue_handler(obs: CycleObservation) -> None:
            observations.append(obs)

        run_daemon(
            cfg,
            on_overdue=overdue_handler,
            shutdown_event=shutdown,
            sleep_fn=fake_sleep,
        )

        assert len(observations) == 1
        assert observations[0].cadence.slug == "nist-800-53-rev5-ca7"

    def test_callback_exception_does_not_stop_daemon(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        state_file = tmp_path / "state.yaml"
        save_state_file(
            state_file,
            {"nist-800-53-rev5-ca7": date(2025, 1, 1)},
        )
        cfg = DaemonConfig(
            state_file=state_file,
            poll_interval_seconds=MIN_POLL_INTERVAL_SECONDS,
        )

        shutdown = threading.Event()

        def fake_sleep(_seconds: float) -> None:
            shutdown.set()

        def bad_handler(_obs: CycleObservation) -> None:
            raise RuntimeError("simulated downstream failure")

        # Should NOT raise; should still emit DAEMON_STOPPED.
        with caplog.at_level("INFO", logger="evidentia_core.conmon.daemon"):
            run_daemon(
                cfg,
                on_overdue=bad_handler,
                shutdown_event=shutdown,
                sleep_fn=fake_sleep,
            )

        action_values = {
            getattr(r, "ecs_record", {}).get("event", {}).get("action")
            for r in caplog.records
        }
        assert EventAction.CONMON_DAEMON_STOPPED.value in action_values

    def test_missing_state_file_keeps_polling(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        state_file = tmp_path / "does_not_exist.yaml"
        cfg = DaemonConfig(
            state_file=state_file,
            poll_interval_seconds=MIN_POLL_INTERVAL_SECONDS,
        )

        shutdown = threading.Event()

        def fake_sleep(_seconds: float) -> None:
            shutdown.set()

        # Should not raise; should still emit DAEMON_STOPPED.
        with caplog.at_level("INFO", logger="evidentia_core.conmon.daemon"):
            run_daemon(cfg, shutdown_event=shutdown, sleep_fn=fake_sleep)

        action_values = {
            getattr(r, "ecs_record", {}).get("event", {}).get("action")
            for r in caplog.records
        }
        assert EventAction.CONMON_DAEMON_STOPPED.value in action_values
