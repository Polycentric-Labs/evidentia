"""Cadence series assertion (v0.13, V13-01): verdicts, gaps, tolerance, wording."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

import pytest
from evidentia_core.conmon.series import (
    CADENCE_SLUG_METADATA_KEY,
    CADENCE_SOURCE_SYSTEM,
    CadenceSeries,
    SeriesVerdict,
    assert_series,
    default_window,
    series_to_finding,
)
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType
from evidentia_core.models.finding import ComplianceStatus

WEEKLY = "pci-dss-11-6-1-weekly"
MONTHLY = "nist-800-53-rev5-ca7"


def _artifact(collected: datetime, slug: str | None = WEEKLY, source: str = "nessus") -> EvidenceArtifact:
    metadata = {CADENCE_SLUG_METADATA_KEY: slug} if slug else {}
    return EvidenceArtifact.model_validate(
        {
            "title": f"scan {collected.date().isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": source,
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": metadata,
        }
    )


def _weekly_series(start: datetime, count: int, step_days: int = 7) -> list[EvidenceArtifact]:
    return [_artifact(start + timedelta(days=step_days * i)) for i in range(count)]


START = datetime(2026, 6, 1, 12, tzinfo=UTC)


class TestVerdicts:
    def test_continuous_weekly(self) -> None:
        artifacts = _weekly_series(START, 8)
        series = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=49))
        assert series.verdict == SeriesVerdict.CONTINUOUS
        assert series.gaps == []
        assert len(series.observations) == 8
        assert series.tolerance_days == 2
        assert series.interval_days == 7

    def test_missing_week_is_a_gap(self) -> None:
        artifacts = _weekly_series(START, 8)
        del artifacts[3]
        series = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=49))
        assert series.verdict == SeriesVerdict.GAPPED
        assert len(series.gaps) == 1
        gap = series.gaps[0]
        assert (gap.days, gap.allowed_days, gap.boundary) == (14, 9, False)

    def test_tolerance_edge(self) -> None:
        on_edge = _weekly_series(START, 4, step_days=9)
        over = _weekly_series(START, 4, step_days=10)
        window_end = START + timedelta(days=30)
        assert (
            assert_series(WEEKLY, on_edge, window_start=START, window_end=window_end).verdict
            == SeriesVerdict.CONTINUOUS
        )
        assert assert_series(WEEKLY, over, window_start=START, window_end=window_end).verdict == SeriesVerdict.GAPPED

    def test_explicit_tolerance_overrides_default(self) -> None:
        artifacts = _weekly_series(START, 4, step_days=10)
        series = assert_series(
            WEEKLY,
            artifacts,
            window_start=START,
            window_end=START + timedelta(days=30),
            tolerance_days=3,
        )
        assert series.verdict == SeriesVerdict.CONTINUOUS

    def test_silence_after_last_observation_is_a_boundary_gap(self) -> None:
        artifacts = _weekly_series(START, 4)
        series = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=60))
        assert series.verdict == SeriesVerdict.GAPPED
        assert [g.boundary for g in series.gaps] == [True]
        assert series.gaps[0].days == 39

    def test_single_observation_is_insufficient(self) -> None:
        series = assert_series(WEEKLY, [_artifact(START)], window_start=START, window_end=START + timedelta(days=30))
        assert series.verdict == SeriesVerdict.INSUFFICIENT
        assert series.gaps == []

    def test_unknown_slug(self) -> None:
        series = assert_series(
            "no-such-cadence",
            [_artifact(START, slug="no-such-cadence")],
            window_start=START,
            window_end=START + timedelta(days=30),
        )
        assert series.verdict == SeriesVerdict.UNKNOWN
        assert len(series.observations) == 1

    def test_only_matching_slug_and_window_count(self) -> None:
        inside = _weekly_series(START, 3)
        other = [_artifact(START + timedelta(days=1), slug=MONTHLY)]
        unlinked = [_artifact(START + timedelta(days=2), slug=None)]
        outside = [_artifact(START - timedelta(days=30))]
        series = assert_series(
            WEEKLY,
            inside + other + unlinked + outside,
            window_start=START,
            window_end=START + timedelta(days=14),
        )
        assert len(series.observations) == 3

    def test_window_order_is_validated(self) -> None:
        with pytest.raises(ValueError, match="window_end"):
            assert_series(WEEKLY, [], window_start=START, window_end=START - timedelta(days=1))


class TestMonthBased:
    def test_month_end_drift_is_not_a_gap(self) -> None:
        dates = [date(2026, 1, 31), date(2026, 2, 28), date(2026, 3, 31), date(2026, 4, 30)]
        artifacts = [_artifact(datetime(d.year, d.month, d.day, 9, tzinfo=UTC), slug=MONTHLY) for d in dates]
        series = assert_series(
            MONTHLY,
            artifacts,
            window_start=datetime(2026, 1, 31, tzinfo=UTC),
            window_end=datetime(2026, 4, 30, 23, 59, tzinfo=UTC),
        )
        assert series.verdict == SeriesVerdict.CONTINUOUS
        assert series.tolerance_days == 5
        assert series.interval_days is None
        assert series.frequency == "monthly"

    def test_skipped_month_is_a_gap(self) -> None:
        dates = [date(2026, 1, 31), date(2026, 3, 31), date(2026, 4, 30)]
        artifacts = [_artifact(datetime(d.year, d.month, d.day, 9, tzinfo=UTC), slug=MONTHLY) for d in dates]
        series = assert_series(
            MONTHLY,
            artifacts,
            window_start=datetime(2026, 1, 31, tzinfo=UTC),
            window_end=datetime(2026, 4, 30, 23, 59, tzinfo=UTC),
        )
        assert series.verdict == SeriesVerdict.GAPPED
        assert series.gaps[0].days == 59
        assert series.gaps[0].allowed_days == 33


class TestWording:
    def test_describe_never_claims_compliance(self) -> None:
        for artifacts, window_end in (
            (_weekly_series(START, 8), START + timedelta(days=49)),
            (_weekly_series(START, 3, step_days=20), START + timedelta(days=60)),
            ([_artifact(START)], START + timedelta(days=10)),
        ):
            text = assert_series(WEEKLY, artifacts, window_start=START, window_end=window_end).describe()
            assert "complian" not in text.lower()
            assert "evidence of cadence" in text

    def test_describe_names_the_widest_gap(self) -> None:
        artifacts = _weekly_series(START, 8)
        del artifacts[3]
        text = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=49)).describe()
        assert "14 days after 2026-06-15 against an allowed 9" in text
        assert "Verdict: gapped." in text


class TestFinding:
    def _gapped(self) -> CadenceSeries:
        artifacts = _weekly_series(START, 8)
        del artifacts[3]
        return assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=49))

    def test_gapped_series_becomes_a_failed_cadence_check(self) -> None:
        finding = series_to_finding(self._gapped(), run_id="01TESTRUN")
        assert finding is not None
        assert finding.compliance_status == ComplianceStatus.FAIL
        assert finding.source_system == CADENCE_SOURCE_SYSTEM
        assert finding.source_finding_id == f"{WEEKLY}:2026-06-01:2026-07-20"
        assert finding.collection_context.run_id == "01TESTRUN"
        assert "complian" not in finding.description.lower()
        assert finding.raw_data["citation"] == "PCI DSS v4.0.1 Requirement 11.6.1"

    def test_finding_id_is_deterministic_in_slug_and_window(self) -> None:
        first = series_to_finding(self._gapped())
        second = series_to_finding(self._gapped())
        assert first is not None and second is not None
        assert first.id == second.id

    def test_continuous_series_emits_nothing(self) -> None:
        series = assert_series(
            WEEKLY,
            _weekly_series(START, 8),
            window_start=START,
            window_end=START + timedelta(days=49),
        )
        assert series_to_finding(series) is None

    def test_insufficient_series_is_unknown_status(self) -> None:
        series = assert_series(WEEKLY, [_artifact(START)], window_start=START, window_end=START + timedelta(days=10))
        finding = series_to_finding(series)
        assert finding is not None
        assert finding.compliance_status == ComplianceStatus.UNKNOWN


class TestDefaultWindow:
    def test_default_window_is_a_year_ending_today(self) -> None:
        start, end = default_window(date(2026, 9, 6))
        assert (start.date(), end.date()) == (date(2025, 9, 6), date(2026, 9, 6))
        assert start.tzinfo is UTC and end.tzinfo is UTC

    def test_lookback_must_be_positive(self) -> None:
        with pytest.raises(ValueError):
            default_window(date(2026, 9, 6), lookback_days=0)
