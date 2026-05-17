"""Unit tests for evidentia_core.conmon.alerting (v0.9.3 P1.2)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from evidentia_core.audit import EventAction
from evidentia_core.conmon import (
    AlertDeduper,
    CycleObservation,
    get_cadence,
    make_alert_handler,
    resolve_secret,
)
from evidentia_core.conmon.calendar import CycleAttentionState


@pytest.fixture()
def sample_observation() -> CycleObservation:
    cadence = get_cadence("nist-800-53-rev5-ca7")
    assert cadence is not None
    return CycleObservation(
        cadence=cadence,
        last_completed=date(2025, 1, 1),
        next_due=date(2025, 2, 1),
        state=CycleAttentionState.OVERDUE,
        days_until_due=-469,
    )


# ── resolve_secret ────────────────────────────────────────────────


class TestResolveSecret:
    """File > env > error precedence per v0.9.3 cycle-open sign-off."""

    def test_file_takes_precedence(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        secret_file = tmp_path / "secret"
        secret_file.write_text("from-file\n", encoding="utf-8")
        monkeypatch.setenv("TEST_SECRET", "from-env")
        assert (
            resolve_secret(secret_file, "TEST_SECRET", "test")
            == "from-file"
        )

    def test_env_used_when_no_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEST_SECRET", "from-env")
        assert resolve_secret(None, "TEST_SECRET", "test") == "from-env"

    def test_raises_when_neither_source(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("TEST_SECRET", raising=False)
        with pytest.raises(ValueError, match="--\\*-file flag"):
            resolve_secret(None, "TEST_SECRET", "test")

    def test_strips_whitespace_from_file(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "secret"
        secret_file.write_text("  padded  \n\n", encoding="utf-8")
        assert resolve_secret(secret_file, "X", "test") == "padded"

    def test_rejects_empty_file(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "secret"
        secret_file.write_text("\n\n", encoding="utf-8")
        with pytest.raises(ValueError, match="is empty"):
            resolve_secret(secret_file, "X", "test")

    def test_treats_whitespace_only_env_as_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TEST_SECRET", "   ")
        with pytest.raises(ValueError):
            resolve_secret(None, "TEST_SECRET", "test")


# ── AlertDeduper ──────────────────────────────────────────────────


class TestAlertDeduper:
    """File-backed per-(slug, state) suppression window."""

    def test_first_alert_not_suppressed(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        assert dd.should_suppress(sample_observation) is False

    def test_within_window_suppressed(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        now = datetime(2026, 5, 16, 0, 0, tzinfo=UTC)
        dd.mark_dispatched(sample_observation, now=now)
        # 12 hours later — still suppressed
        later = now + timedelta(hours=12)
        assert dd.should_suppress(sample_observation, now=later) is True

    def test_outside_window_not_suppressed(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        now = datetime(2026, 5, 16, 0, 0, tzinfo=UTC)
        dd.mark_dispatched(sample_observation, now=now)
        later = now + timedelta(hours=25)
        assert dd.should_suppress(sample_observation, now=later) is False

    def test_different_state_not_dedupd(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        now = datetime(2026, 5, 16, 0, 0, tzinfo=UTC)
        dd.mark_dispatched(sample_observation, now=now)
        # Same cadence, different state — must NOT be suppressed
        # because the operator needs to see the transition.
        other = CycleObservation(
            cadence=sample_observation.cadence,
            last_completed=sample_observation.last_completed,
            next_due=sample_observation.next_due,
            state=CycleAttentionState.DUE_SOON,
            days_until_due=5,
        )
        assert dd.should_suppress(other, now=now) is False

    def test_corrupted_state_file_tolerated(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        dedup_file = tmp_path / "dedup.json"
        dedup_file.write_text("{ not valid json ", encoding="utf-8")
        dd = AlertDeduper.from_hours(dedup_file, 24.0)
        # Treats as empty + alert fires.
        assert dd.should_suppress(sample_observation) is False

    def test_negative_hours_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="suppression hours"):
            AlertDeduper.from_hours(tmp_path / "dedup.json", -1.0)


# ── make_alert_handler ────────────────────────────────────────────


class _FakeChannel:
    """Test-only AlertChannel implementation that records dispatches."""

    def __init__(self, name: str = "fake", should_fail: bool = False) -> None:
        self.name = name
        self.dispatched: list[CycleObservation] = []
        self._should_fail = should_fail

    def dispatch(self, obs: CycleObservation) -> None:
        if self._should_fail:
            raise RuntimeError(f"simulated failure on {self.name}")
        self.dispatched.append(obs)


class TestMakeAlertHandler:
    """Wire channels + deduper into a CycleHandler."""

    def test_dispatches_to_all_channels(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        ch1 = _FakeChannel(name="primary")
        ch2 = _FakeChannel(name="secondary")
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        handler = make_alert_handler([ch1, ch2], deduper=dd)

        handler(sample_observation)

        assert len(ch1.dispatched) == 1
        assert len(ch2.dispatched) == 1

    def test_dedup_suppresses_second_call(
        self,
        tmp_path: Path,
        sample_observation: CycleObservation,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        ch = _FakeChannel()
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        handler = make_alert_handler([ch], deduper=dd)

        handler(sample_observation)
        with caplog.at_level(
            "INFO", logger="evidentia_core.conmon.alerting"
        ):
            handler(sample_observation)

        assert len(ch.dispatched) == 1  # second call suppressed
        actions = [
            getattr(r, "ecs_record", {}).get("event", {}).get("action")
            for r in caplog.records
        ]
        assert EventAction.CONMON_ALERT_SUPPRESSED.value in actions

    def test_failing_channel_does_not_block_siblings(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        bad = _FakeChannel(name="broken", should_fail=True)
        good = _FakeChannel(name="working")
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        handler = make_alert_handler([bad, good], deduper=dd)

        handler(sample_observation)

        assert len(good.dispatched) == 1

    def test_all_failing_channels_means_no_dedup_mark(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        bad = _FakeChannel(name="broken", should_fail=True)
        dd = AlertDeduper.from_hours(tmp_path / "dedup.json", 24.0)
        handler = make_alert_handler([bad], deduper=dd)

        handler(sample_observation)
        # Next poll should retry (no dedup mark since dispatch failed)
        assert dd.should_suppress(sample_observation) is False

    def test_no_deduper_dispatches_every_time(
        self, tmp_path: Path, sample_observation: CycleObservation
    ) -> None:
        ch = _FakeChannel()
        handler = make_alert_handler([ch], deduper=None)

        handler(sample_observation)
        handler(sample_observation)
        handler(sample_observation)
        assert len(ch.dispatched) == 3

    def test_empty_channel_list_is_noop(
        self, sample_observation: CycleObservation
    ) -> None:
        handler = make_alert_handler([], deduper=None)
        # Just verify no raise.
        handler(sample_observation)
