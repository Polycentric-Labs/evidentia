"""Unit tests for evidentia_core.poam.milestone (v0.9.0 P1)."""

from __future__ import annotations

from datetime import date

import pytest
from evidentia_core.models.gap import Milestone, POAMState
from evidentia_core.poam.milestone import (
    derive_attention_state,
    group_milestones_by_state,
    sort_milestones_by_target_date,
    upcoming_milestones,
)


def _ms(
    target: date,
    status: POAMState = POAMState.PLANNED,
    description: str = "do the thing",
) -> Milestone:
    return Milestone(
        target_date=target,
        description=description,
        status=status,
    )


# ── sort_milestones_by_target_date ─────────────────────────────────


class TestSortByTargetDate:
    def test_sort_ascending_by_default(self) -> None:
        a = _ms(date(2026, 6, 1))
        b = _ms(date(2026, 5, 1))
        c = _ms(date(2026, 7, 1))
        result = sort_milestones_by_target_date([a, b, c])
        assert [m.target_date for m in result] == [
            date(2026, 5, 1),
            date(2026, 6, 1),
            date(2026, 7, 1),
        ]

    def test_sort_descending_with_reverse(self) -> None:
        a = _ms(date(2026, 6, 1))
        b = _ms(date(2026, 5, 1))
        result = sort_milestones_by_target_date([a, b], reverse=True)
        assert [m.target_date for m in result] == [
            date(2026, 6, 1),
            date(2026, 5, 1),
        ]

    def test_sort_is_stable_for_equal_dates(self) -> None:
        a = _ms(date(2026, 5, 1), description="first")
        b = _ms(date(2026, 5, 1), description="second")
        result = sort_milestones_by_target_date([a, b])
        assert result[0].description == "first"
        assert result[1].description == "second"

    def test_empty_input_returns_empty_list(self) -> None:
        assert sort_milestones_by_target_date([]) == []


# ── group_milestones_by_state ──────────────────────────────────────


class TestGroupByState:
    def test_all_states_present_even_when_empty(self) -> None:
        result = group_milestones_by_state([])
        assert set(result.keys()) == set(POAMState)
        for bucket in result.values():
            assert bucket == []

    def test_milestones_land_in_correct_buckets(self) -> None:
        a = _ms(date(2026, 5, 1), status=POAMState.PLANNED)
        b = _ms(date(2026, 5, 2), status=POAMState.IN_PROGRESS)
        c = _ms(date(2026, 5, 3), status=POAMState.COMPLETED)
        d = _ms(date(2026, 5, 4), status=POAMState.PLANNED)
        result = group_milestones_by_state([a, b, c, d])
        assert len(result[POAMState.PLANNED]) == 2
        assert len(result[POAMState.IN_PROGRESS]) == 1
        assert len(result[POAMState.COMPLETED]) == 1
        assert len(result[POAMState.VERIFIED]) == 0
        assert len(result[POAMState.OVERDUE]) == 0

    def test_buckets_sorted_by_target_date_ascending(self) -> None:
        a = _ms(date(2026, 6, 1), status=POAMState.PLANNED)
        b = _ms(date(2026, 5, 1), status=POAMState.PLANNED)
        c = _ms(date(2026, 7, 1), status=POAMState.PLANNED)
        result = group_milestones_by_state([a, b, c])
        planned = result[POAMState.PLANNED]
        assert [m.target_date for m in planned] == [
            date(2026, 5, 1),
            date(2026, 6, 1),
            date(2026, 7, 1),
        ]


# ── upcoming_milestones ────────────────────────────────────────────


class TestUpcomingMilestones:
    def test_returns_milestones_within_window(self) -> None:
        today = date(2026, 5, 8)
        a = _ms(date(2026, 5, 15))  # within 30-day window
        b = _ms(date(2026, 7, 15))  # outside 30-day window
        c = _ms(date(2026, 4, 15))  # in the past
        result = upcoming_milestones([a, b, c], today=today)
        assert len(result) == 1
        assert result[0].target_date == date(2026, 5, 15)

    def test_due_today_is_upcoming(self) -> None:
        today = date(2026, 5, 8)
        a = _ms(today)
        result = upcoming_milestones([a], today=today)
        assert len(result) == 1

    def test_excludes_completed_and_verified(self) -> None:
        today = date(2026, 5, 8)
        a = _ms(date(2026, 5, 15), status=POAMState.PLANNED)
        b = _ms(date(2026, 5, 15), status=POAMState.COMPLETED)
        c = _ms(date(2026, 5, 15), status=POAMState.VERIFIED)
        result = upcoming_milestones([a, b, c], today=today)
        assert len(result) == 1
        assert result[0].status == POAMState.PLANNED

    def test_window_zero_returns_only_due_today(self) -> None:
        today = date(2026, 5, 8)
        a = _ms(today)
        b = _ms(date(2026, 5, 9))
        result = upcoming_milestones([a, b], today=today, window_days=0)
        assert len(result) == 1
        assert result[0].target_date == today

    def test_negative_window_raises(self) -> None:
        today = date(2026, 5, 8)
        with pytest.raises(ValueError, match="window_days must be >= 0"):
            upcoming_milestones([], today=today, window_days=-1)

    def test_sorted_ascending(self) -> None:
        today = date(2026, 5, 8)
        a = _ms(date(2026, 5, 20))
        b = _ms(date(2026, 5, 12))
        c = _ms(date(2026, 5, 25))
        result = upcoming_milestones([a, b, c], today=today)
        assert [m.target_date for m in result] == [
            date(2026, 5, 12),
            date(2026, 5, 20),
            date(2026, 5, 25),
        ]


# ── derive_attention_state ─────────────────────────────────────────


class TestDeriveAttentionState:
    def test_returns_three_buckets_always(self) -> None:
        today = date(2026, 5, 8)
        result = derive_attention_state([], today=today)
        assert set(result.keys()) == {"overdue", "due_soon", "closed"}
        for bucket in result.values():
            assert bucket == []

    def test_overdue_bucket_catches_past_planned(self) -> None:
        today = date(2026, 5, 8)
        late = _ms(date(2026, 4, 1), status=POAMState.PLANNED)
        result = derive_attention_state([late], today=today)
        assert len(result["overdue"]) == 1
        assert len(result["due_soon"]) == 0
        assert len(result["closed"]) == 0

    def test_due_soon_bucket_catches_within_7_days(self) -> None:
        today = date(2026, 5, 8)
        soon = _ms(date(2026, 5, 12))  # 4 days
        far = _ms(date(2026, 6, 30))  # outside 7-day window
        result = derive_attention_state([soon, far], today=today)
        assert len(result["due_soon"]) == 1
        assert result["due_soon"][0].target_date == date(2026, 5, 12)

    def test_closed_bucket_catches_completed_and_verified(self) -> None:
        today = date(2026, 5, 8)
        done = _ms(date(2026, 4, 1), status=POAMState.COMPLETED)
        verified = _ms(date(2026, 4, 5), status=POAMState.VERIFIED)
        result = derive_attention_state([done, verified], today=today)
        assert len(result["closed"]) == 2
        # COMPLETED with past target_date is NOT overdue (work done).
        assert len(result["overdue"]) == 0

    def test_explicit_overdue_status_lands_in_overdue_even_if_future_target(
        self,
    ) -> None:
        today = date(2026, 5, 8)
        m = _ms(date(2026, 6, 30), status=POAMState.OVERDUE)
        result = derive_attention_state([m], today=today)
        assert len(result["overdue"]) == 1

    def test_overdue_takes_precedence_over_due_soon(self) -> None:
        # A milestone whose target_date is in the past with PLANNED
        # status is overdue — it does NOT also appear in due_soon.
        today = date(2026, 5, 8)
        late = _ms(date(2026, 5, 1), status=POAMState.PLANNED)
        result = derive_attention_state([late], today=today)
        assert len(result["overdue"]) == 1
        assert len(result["due_soon"]) == 0

    def test_due_today_lands_in_due_soon(self) -> None:
        today = date(2026, 5, 8)
        m = _ms(today, status=POAMState.IN_PROGRESS)
        result = derive_attention_state([m], today=today)
        assert len(result["due_soon"]) == 1
        assert len(result["overdue"]) == 0
