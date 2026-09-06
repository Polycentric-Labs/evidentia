"""Evidence-store helpers behind `conmon check --evidence-store` (v0.13, batch 5)."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta, timezone

from evidentia_core.conmon import (
    CADENCE_SLUG_METADATA_KEY,
    SeriesVerdict,
    latest_observations,
    merge_evidence_anchors,
    series_verdicts,
)
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

WEEKLY = "pci-dss-11-6-1-weekly"
MONTHLY = "nist-800-53-rev5-ca7"
START = datetime(2026, 6, 1, 12, tzinfo=UTC)


def _artifact(collected: datetime, slug: str | None = WEEKLY) -> EvidenceArtifact:
    metadata = {CADENCE_SLUG_METADATA_KEY: slug} if slug else {}
    return EvidenceArtifact.model_validate(
        {
            "title": f"scan {collected.isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": "nessus",
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": metadata,
        }
    )


class TestLatestObservations:
    def test_latest_date_per_slug(self) -> None:
        artifacts = [
            _artifact(START),
            _artifact(START + timedelta(days=7)),
            _artifact(START + timedelta(days=3), slug=MONTHLY),
        ]
        assert latest_observations(artifacts) == {
            WEEKLY: date(2026, 6, 8),
            MONTHLY: date(2026, 6, 4),
        }

    def test_unlinked_artifacts_are_ignored(self) -> None:
        assert latest_observations([_artifact(START, slug=None)]) == {}

    def test_dates_are_taken_in_utc(self) -> None:
        # 23:30 on 1 June in UTC-5 is 04:30 on 2 June in UTC.
        local = datetime(2026, 6, 1, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
        assert latest_observations([_artifact(local)]) == {WEEKLY: date(2026, 6, 2)}


class TestMergeEvidenceAnchors:
    def test_state_file_wins_and_gaps_are_filled(self) -> None:
        state = {WEEKLY: date(2026, 5, 1)}
        observed = {WEEKLY: date(2026, 6, 8), MONTHLY: date(2026, 6, 4)}
        assert merge_evidence_anchors(state, observed) == {
            WEEKLY: date(2026, 5, 1),
            MONTHLY: date(2026, 6, 4),
        }

    def test_inputs_are_not_mutated(self) -> None:
        state = {WEEKLY: date(2026, 5, 1)}
        observed = {MONTHLY: date(2026, 6, 4)}
        merged = merge_evidence_anchors(state, observed)
        assert state == {WEEKLY: date(2026, 5, 1)}
        assert observed == {MONTHLY: date(2026, 6, 4)}
        assert merged is not state and merged is not observed


class TestSeriesVerdicts:
    def test_verdict_per_slug_over_the_window(self) -> None:
        artifacts = [_artifact(START + timedelta(days=7 * i)) for i in range(8)]
        verdicts = series_verdicts(
            artifacts, [WEEKLY, MONTHLY, "no-such-cadence"], today=date(2026, 7, 20), lookback_days=49
        )
        assert verdicts == {
            WEEKLY: SeriesVerdict.CONTINUOUS,
            MONTHLY: SeriesVerdict.INSUFFICIENT,
            "no-such-cadence": SeriesVerdict.UNKNOWN,
        }

    def test_default_window_flags_the_silence_before_the_first_observation(self) -> None:
        artifacts = [_artifact(START + timedelta(days=7 * i)) for i in range(8)]
        verdicts = series_verdicts(artifacts, [WEEKLY], today=date(2026, 7, 20))
        assert verdicts[WEEKLY] == SeriesVerdict.GAPPED
