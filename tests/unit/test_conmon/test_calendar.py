"""Unit tests for evidentia_core.conmon.calendar (v0.9.0 P3)."""

from __future__ import annotations

from datetime import date

import pytest
from evidentia_core.conmon import (
    BUNDLED_CADENCES,
    CONMON_FREQUENCIES,
    CONMON_FREQUENCY_DAYS,
    CadenceFrequency,
    ConmonCadence,
    CycleAttentionState,
    derive_status,
    get_cadence,
    list_cadences,
    next_due,
    register_cadence,
)


@pytest.fixture(autouse=True)
def _isolated_conmon_registry() -> object:
    """Snapshot + restore the process-local cadence registry per test.

    ``register_cadence`` writes to a module-level ``_REGISTRY``.
    Without isolation, a test that registers a custom cadence would
    pollute sibling tests. This fixture takes a copy before the test
    and restores it after — replaces the v0.9.0 P3 per-test
    try/finally cleanup pattern with a single autouse fixture.
    """
    import evidentia_core.conmon.calendar as cal

    snapshot = dict(cal._REGISTRY)
    yield
    cal._REGISTRY.clear()
    cal._REGISTRY.update(snapshot)


# ── bundled cadence catalog ────────────────────────────────────────


class TestBundledCadences:
    def test_at_least_7_bundled_cadences(self) -> None:
        # NIST CA-7 + 3 FedRAMP + CMMC + DoD RMF + OCC 2026-13a
        assert len(BUNDLED_CADENCES) >= 7

    def test_all_cadences_have_unique_slugs(self) -> None:
        slugs = [c.slug for c in BUNDLED_CADENCES]
        assert len(slugs) == len(set(slugs))

    def test_all_cadences_have_required_fields(self) -> None:
        for cadence in BUNDLED_CADENCES:
            assert cadence.slug
            assert cadence.framework
            assert cadence.activity
            assert cadence.frequency in {f for f in CadenceFrequency}
            assert cadence.description

    def test_nist_ca7_is_monthly(self) -> None:
        cadence = get_cadence("nist-800-53-rev5-ca7")
        assert cadence is not None
        assert cadence.frequency == CadenceFrequency.MONTHLY

    def test_fedramp_annual_is_annual(self) -> None:
        cadence = get_cadence("fedramp-conmon-annual")
        assert cadence is not None
        assert cadence.frequency == CadenceFrequency.ANNUAL

    def test_cmmc_is_triennial(self) -> None:
        cadence = get_cadence("cmmc-l2-triennial")
        assert cadence is not None
        assert cadence.frequency == CadenceFrequency.TRIENNIAL


# ── list_cadences / get_cadence ────────────────────────────────────


class TestListCadences:
    def test_unfiltered_returns_all_bundled(self) -> None:
        cadences = list_cadences()
        assert len(cadences) >= len(BUNDLED_CADENCES)

    def test_framework_filter(self) -> None:
        cadences = list_cadences(framework="fedramp-rev5-mod")
        assert all(c.framework == "fedramp-rev5-mod" for c in cadences)
        assert len(cadences) >= 3  # POA&M + scans + annual

    def test_unknown_framework_returns_empty(self) -> None:
        cadences = list_cadences(framework="totally-not-a-real-framework")
        assert cadences == []

    def test_sort_is_deterministic(self) -> None:
        first = list_cadences()
        second = list_cadences()
        assert [c.slug for c in first] == [c.slug for c in second]


class TestGetCadence:
    def test_unknown_slug_returns_none(self) -> None:
        assert get_cadence("not-a-real-slug") is None


# ── register_cadence ────────────────────────────────────────────────


class TestRegisterCadence:
    def test_register_new_cadence_appears_in_list(self) -> None:
        custom = ConmonCadence(
            slug="custom-org-monthly",
            framework="custom-internal",
            activity="custom-review",
            frequency=CadenceFrequency.MONTHLY,
            description="Internal review cycle.",
        )
        register_cadence(custom)
        assert get_cadence("custom-org-monthly") is not None
        assert custom in list_cadences()
        # Cleanup handled by the autouse _isolated_conmon_registry fixture.


# ── next_due ───────────────────────────────────────────────────────


class TestNextDue:
    def test_monthly_adds_one_month(self) -> None:
        result = next_due("nist-800-53-rev5-ca7", date(2026, 4, 1))
        assert result == date(2026, 5, 1)

    def test_quarterly_adds_three_months(self) -> None:
        custom = ConmonCadence(
            slug="test-quarterly",
            framework="test",
            activity="test",
            frequency=CadenceFrequency.QUARTERLY,
            description="Test.",
        )
        register_cadence(custom)
        result = next_due("test-quarterly", date(2026, 1, 15))
        assert result == date(2026, 4, 15)
        # Cleanup handled by the autouse _isolated_conmon_registry fixture.

    def test_annual_adds_twelve_months(self) -> None:
        result = next_due("fedramp-conmon-annual", date(2026, 4, 1))
        assert result == date(2027, 4, 1)

    def test_triennial_adds_thirty_six_months(self) -> None:
        result = next_due("cmmc-l2-triennial", date(2026, 4, 1))
        assert result == date(2029, 4, 1)

    def test_year_roll_works(self) -> None:
        # NIST monthly cadence in December rolls year
        result = next_due("nist-800-53-rev5-ca7", date(2026, 12, 15))
        assert result == date(2027, 1, 15)

    def test_last_day_clamp_jan_31_plus_one_month(self) -> None:
        # 2026-01-31 + 1 month → 2026-02-28 (clamped, not invalid date)
        result = next_due("nist-800-53-rev5-ca7", date(2026, 1, 31))
        assert result == date(2026, 2, 28)

    def test_last_day_clamp_leap_year(self) -> None:
        # 2024 is a leap year; 2024-01-31 + 1 month → 2024-02-29
        result = next_due("nist-800-53-rev5-ca7", date(2024, 1, 31))
        assert result == date(2024, 2, 29)

    def test_last_day_clamp_annual(self) -> None:
        # 2024-02-29 + 12 months → 2025-02-28 (clamped)
        result = next_due("fedramp-conmon-annual", date(2024, 2, 29))
        assert result == date(2025, 2, 28)

    def test_unknown_slug_raises_key_error(self) -> None:
        with pytest.raises(KeyError, match="Unknown CONMON cadence"):
            next_due("not-a-real-slug", date(2026, 4, 1))


# ── derive_status ─────────────────────────────────────────────────


class TestDeriveStatus:
    def test_overdue_when_due_in_past(self) -> None:
        result = derive_status(
            next_due_date=date(2026, 4, 1),
            today=date(2026, 5, 8),
        )
        assert result == CycleAttentionState.OVERDUE

    def test_due_soon_when_within_window(self) -> None:
        result = derive_status(
            next_due_date=date(2026, 5, 15),  # 7 days out
            today=date(2026, 5, 8),
            window_days=14,
        )
        assert result == CycleAttentionState.DUE_SOON

    def test_current_when_past_window(self) -> None:
        result = derive_status(
            next_due_date=date(2026, 7, 1),
            today=date(2026, 5, 8),
            window_days=14,
        )
        assert result == CycleAttentionState.CURRENT

    def test_due_today_is_due_soon(self) -> None:
        today = date(2026, 5, 8)
        result = derive_status(today, today, window_days=14)
        assert result == CycleAttentionState.DUE_SOON

    def test_boundary_at_window_edge_is_due_soon(self) -> None:
        # Day = today + window_days exactly → DUE_SOON (inclusive)
        result = derive_status(
            next_due_date=date(2026, 5, 22),  # +14 days
            today=date(2026, 5, 8),
            window_days=14,
        )
        assert result == CycleAttentionState.DUE_SOON

    def test_negative_window_raises(self) -> None:
        with pytest.raises(ValueError, match="window_days must be >= 0"):
            derive_status(
                next_due_date=date(2026, 5, 8),
                today=date(2026, 5, 8),
                window_days=-1,
            )

    def test_window_zero_only_due_today_is_due_soon(self) -> None:
        today = date(2026, 5, 8)
        # Due today with window=0 → DUE_SOON
        assert derive_status(today, today, window_days=0) == CycleAttentionState.DUE_SOON
        # Due tomorrow with window=0 → CURRENT
        assert derive_status(date(2026, 5, 9), today, window_days=0) == CycleAttentionState.CURRENT


# ── frequency map ──────────────────────────────────────────────────


class TestConmonFrequenciesMap:
    def test_map_covers_all_enum_values(self) -> None:
        # v0.13: day-granular members live in CONMON_FREQUENCY_DAYS and CUSTOM
        # reads ConmonCadence.interval_days; every member has exactly one home.
        for freq in CadenceFrequency:
            homes = [freq in CONMON_FREQUENCIES, freq in CONMON_FREQUENCY_DAYS, freq is CadenceFrequency.CUSTOM]
            assert sum(homes) == 1, freq

    def test_monthly_is_one_month(self) -> None:
        assert CONMON_FREQUENCIES[CadenceFrequency.MONTHLY] == 1

    def test_triennial_is_thirty_six_months(self) -> None:
        assert CONMON_FREQUENCIES[CadenceFrequency.TRIENNIAL] == 36
