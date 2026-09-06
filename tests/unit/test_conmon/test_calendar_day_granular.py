"""Day-granular cadences (v0.13, V13-01).

``weekly`` and ``biweekly`` add a fixed day count, ``semiannual`` is six months
of calendar-aware arithmetic, and ``custom`` takes its interval from
``ConmonCadence.interval_days``. The validator keeps one source of truth: a
custom cadence needs the interval, every other frequency refuses it.
"""

from __future__ import annotations

from datetime import date

import pytest
from evidentia_core.conmon.calendar import (
    BUNDLED_CADENCES,
    CONMON_FREQUENCIES,
    CONMON_FREQUENCY_DAYS,
    CadenceFrequency,
    ConmonCadence,
    get_cadence,
    interval_days_for,
    next_due,
    register_cadence,
)
from pydantic import ValidationError


def _cadence(slug: str, frequency: CadenceFrequency, **extra: object) -> ConmonCadence:
    return ConmonCadence(
        slug=slug,
        framework="test-framework",
        activity="test-activity",
        frequency=frequency,
        description="Test cadence.",
        **extra,  # type: ignore[arg-type]
    )


class TestFrequencyTables:
    def test_day_table_covers_weekly_and_biweekly_only(self) -> None:
        assert CONMON_FREQUENCY_DAYS == {
            CadenceFrequency.WEEKLY: 7,
            CadenceFrequency.BIWEEKLY: 14,
        }

    def test_semiannual_is_six_months(self) -> None:
        assert CONMON_FREQUENCIES[CadenceFrequency.SEMIANNUAL] == 6

    def test_custom_is_in_neither_table(self) -> None:
        assert CadenceFrequency.CUSTOM not in CONMON_FREQUENCIES
        assert CadenceFrequency.CUSTOM not in CONMON_FREQUENCY_DAYS


class TestValidator:
    def test_custom_requires_interval_days(self) -> None:
        with pytest.raises(ValidationError, match="interval_days"):
            _cadence("test-custom-missing", CadenceFrequency.CUSTOM)

    def test_interval_days_refused_for_month_based(self) -> None:
        with pytest.raises(ValidationError, match="only allowed"):
            _cadence("test-monthly-with-days", CadenceFrequency.MONTHLY, interval_days=10)

    def test_interval_days_bounds(self) -> None:
        with pytest.raises(ValidationError):
            _cadence("test-custom-zero", CadenceFrequency.CUSTOM, interval_days=0)
        assert _cadence("test-custom-ok", CadenceFrequency.CUSTOM, interval_days=35).interval_days == 35


class TestIntervalDaysFor:
    def test_weekly_and_biweekly(self) -> None:
        assert interval_days_for(_cadence("test-w", CadenceFrequency.WEEKLY)) == 7
        assert interval_days_for(_cadence("test-bw", CadenceFrequency.BIWEEKLY)) == 14

    def test_custom_reads_the_field(self) -> None:
        assert interval_days_for(_cadence("test-c", CadenceFrequency.CUSTOM, interval_days=35)) == 35

    def test_month_based_returns_none(self) -> None:
        for frequency in (
            CadenceFrequency.MONTHLY,
            CadenceFrequency.QUARTERLY,
            CadenceFrequency.SEMIANNUAL,
            CadenceFrequency.ANNUAL,
        ):
            assert interval_days_for(_cadence(f"test-{frequency.value}", frequency)) is None


class TestNextDue:
    def test_weekly_adds_seven_days(self) -> None:
        register_cadence(_cadence("test-next-weekly", CadenceFrequency.WEEKLY))
        assert next_due("test-next-weekly", date(2026, 2, 26)) == date(2026, 3, 5)

    def test_biweekly_adds_fourteen_days(self) -> None:
        register_cadence(_cadence("test-next-biweekly", CadenceFrequency.BIWEEKLY))
        assert next_due("test-next-biweekly", date(2026, 12, 25)) == date(2027, 1, 8)

    def test_custom_adds_the_interval(self) -> None:
        register_cadence(_cadence("test-next-custom", CadenceFrequency.CUSTOM, interval_days=35))
        assert next_due("test-next-custom", date(2026, 1, 1)) == date(2026, 2, 5)

    def test_semiannual_is_calendar_aware(self) -> None:
        register_cadence(_cadence("test-next-semiannual", CadenceFrequency.SEMIANNUAL))
        assert next_due("test-next-semiannual", date(2026, 1, 31)) == date(2026, 7, 31)
        assert next_due("test-next-semiannual", date(2026, 8, 31)) == date(2027, 2, 28)


class TestBundledAdditions:
    @pytest.mark.parametrize(
        ("slug", "frequency", "interval"),
        [
            ("pci-dss-11-6-1-weekly", CadenceFrequency.WEEKLY, 7),
            ("nerc-cip-007-r2-patch-evaluation", CadenceFrequency.CUSTOM, 35),
            ("irs-pub-1345-weekly-asv-scan", CadenceFrequency.WEEKLY, 7),
            ("glba-314-4-d-semiannual-vulnerability-assessment", CadenceFrequency.SEMIANNUAL, None),
            ("glba-314-4-d-annual-penetration-test", CadenceFrequency.ANNUAL, None),
        ],
    )
    def test_bundled_cadence_shape(self, slug: str, frequency: CadenceFrequency, interval: int | None) -> None:
        cadence = get_cadence(slug)
        assert cadence is not None, slug
        assert CadenceFrequency(cadence.frequency) is frequency
        assert interval_days_for(cadence) == interval
        assert cadence.citation

    def test_nerc_clock_is_thirty_five_days(self) -> None:
        assert next_due("nerc-cip-007-r2-patch-evaluation", date(2026, 3, 1)) == date(2026, 4, 5)

    def test_bundled_set_grew_and_stayed_unique(self) -> None:
        slugs = [c.slug for c in BUNDLED_CADENCES]
        assert len(slugs) >= 12
        assert len(slugs) == len(set(slugs))
