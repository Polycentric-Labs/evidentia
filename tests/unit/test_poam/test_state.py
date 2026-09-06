"""Unit tests for evidentia_core.poam.state (v0.9.0 P1)."""

from __future__ import annotations

from datetime import date

from evidentia_core.models.gap import POAMState
from evidentia_core.poam.state import (
    TERMINAL_STATES,
    derive_overdue,
    is_valid_transition,
    valid_next_states,
)

# ── valid_next_states ──────────────────────────────────────────────


class TestValidNextStates:
    def test_planned_can_advance_to_in_progress_overdue_or_completed(
        self,
    ) -> None:
        result = valid_next_states(POAMState.PLANNED)
        assert result == frozenset(
            {
                POAMState.IN_PROGRESS,
                POAMState.OVERDUE,
                POAMState.COMPLETED,
            }
        )

    def test_in_progress_cannot_revert_to_planned(self) -> None:
        result = valid_next_states(POAMState.IN_PROGRESS)
        assert POAMState.PLANNED not in result
        assert POAMState.OVERDUE in result
        assert POAMState.COMPLETED in result

    def test_overdue_can_recover_or_complete(self) -> None:
        result = valid_next_states(POAMState.OVERDUE)
        assert POAMState.IN_PROGRESS in result
        assert POAMState.COMPLETED in result
        # Cannot bounce back to PLANNED — auditors interpret that
        # as timeline mismanagement; correct move is a NEW milestone.
        assert POAMState.PLANNED not in result

    def test_completed_can_only_go_to_verified(self) -> None:
        result = valid_next_states(POAMState.COMPLETED)
        assert result == frozenset({POAMState.VERIFIED})

    def test_verified_is_terminal(self) -> None:
        assert valid_next_states(POAMState.VERIFIED) == frozenset()

    def test_terminal_states_constant_matches(self) -> None:
        assert frozenset({POAMState.VERIFIED}) == TERMINAL_STATES


# ── is_valid_transition ────────────────────────────────────────────


class TestIsValidTransition:
    def test_planned_to_in_progress_is_valid(self) -> None:
        assert is_valid_transition(POAMState.PLANNED, POAMState.IN_PROGRESS)

    def test_in_progress_to_completed_is_valid(self) -> None:
        assert is_valid_transition(POAMState.IN_PROGRESS, POAMState.COMPLETED)

    def test_completed_to_verified_is_valid(self) -> None:
        assert is_valid_transition(POAMState.COMPLETED, POAMState.VERIFIED)

    def test_completed_to_in_progress_is_invalid(self) -> None:
        # Backward transition explicitly forbidden — auditor integrity.
        assert not is_valid_transition(POAMState.COMPLETED, POAMState.IN_PROGRESS)

    def test_verified_to_anything_is_invalid(self) -> None:
        for target in POAMState:
            assert not is_valid_transition(POAMState.VERIFIED, target)

    def test_self_transition_returns_false(self) -> None:
        # Re-saving the same state isn't a transition; the caller
        # should detect this case and skip the audit emit.
        for state in POAMState:
            assert not is_valid_transition(state, state)

    def test_overdue_to_planned_is_invalid(self) -> None:
        assert not is_valid_transition(POAMState.OVERDUE, POAMState.PLANNED)

    def test_planned_to_overdue_is_valid(self) -> None:
        # An operator can manually set OVERDUE on a planned milestone
        # they know they're going to miss.
        assert is_valid_transition(POAMState.PLANNED, POAMState.OVERDUE)


# ── derive_overdue ─────────────────────────────────────────────────


class TestDeriveOverdue:
    def test_planned_in_past_is_overdue(self) -> None:
        target = date(2026, 1, 1)
        today = date(2026, 5, 8)
        assert derive_overdue(target, POAMState.PLANNED, today)

    def test_in_progress_in_past_is_overdue(self) -> None:
        target = date(2026, 1, 1)
        today = date(2026, 5, 8)
        assert derive_overdue(target, POAMState.IN_PROGRESS, today)

    def test_planned_in_future_is_not_overdue(self) -> None:
        target = date(2026, 12, 31)
        today = date(2026, 5, 8)
        assert not derive_overdue(target, POAMState.PLANNED, today)

    def test_planned_today_is_not_overdue(self) -> None:
        # target_date == today: not yet "in the past"
        today = date(2026, 5, 8)
        assert not derive_overdue(today, POAMState.PLANNED, today)

    def test_completed_never_overdue_even_if_past_target(self) -> None:
        target = date(2026, 1, 1)
        today = date(2026, 5, 8)
        # Work is done — by definition not overdue.
        assert not derive_overdue(target, POAMState.COMPLETED, today)

    def test_verified_never_overdue(self) -> None:
        target = date(2026, 1, 1)
        today = date(2026, 5, 8)
        assert not derive_overdue(target, POAMState.VERIFIED, today)

    def test_explicit_overdue_status_is_trivially_overdue(self) -> None:
        # Even if target_date is in the FUTURE, if operator set
        # status=OVERDUE the predicate returns True.
        target = date(2026, 12, 31)
        today = date(2026, 5, 8)
        assert derive_overdue(target, POAMState.OVERDUE, today)
