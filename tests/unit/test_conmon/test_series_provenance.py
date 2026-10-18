"""Cadence series provenance (v0.13.0 review H5, decision D11).

Lineages count once at their current version; an importer-marked
incomplete run or collection-time timestamp is excluded and counted; the
evidence anchor honours the as-of date.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta

from evidentia_core.conmon.series import (
    CADENCE_SLUG_METADATA_KEY,
    COLLECTION_COMPLETE_METADATA_KEY,
    TIMESTAMP_SOURCE_COLLECTION_TIME,
    TIMESTAMP_SOURCE_METADATA_KEY,
    TIMESTAMP_SOURCE_RECORD,
    SeriesVerdict,
    assert_series,
    latest_observations,
)
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

WEEKLY = "pci-dss-11-6-1-weekly"
START = datetime(2026, 6, 1, 12, tzinfo=UTC)


def _artifact(collected: datetime, **metadata: object) -> EvidenceArtifact:
    return EvidenceArtifact.model_validate(
        {
            "title": f"scan {collected.date().isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": "nessus",
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": {CADENCE_SLUG_METADATA_KEY: WEEKLY, **metadata},
        }
    )


def _weekly(count: int) -> list[EvidenceArtifact]:
    return [_artifact(START + timedelta(days=7 * i)) for i in range(count)]


def test_corrected_version_is_the_same_observation() -> None:
    artifacts = _weekly(3)
    corrected = artifacts[1].new_version(collected_at=artifacts[1].collected_at + timedelta(hours=6))
    series = assert_series(WEEKLY, [*artifacts, corrected], window_start=START, window_end=START + timedelta(days=15))
    assert len(series.observations) == 3
    chosen = [o for o in series.observations if o.lineage_id == artifacts[1].effective_lineage_id]
    assert len(chosen) == 1
    assert chosen[0].version == 2
    assert series.excluded_observations == 0


def test_annotation_version_moves_the_lineage_instead_of_adding_one() -> None:
    first = _artifact(START)
    second = _artifact(START + timedelta(days=14))
    # Re-saving the first observation with a later date re-dates that one
    # observation (the lineage's current version is its truth); it never
    # becomes a second observation.
    annotated = first.new_version(collected_at=START + timedelta(days=7), content={"note": "re-saved"})
    series = assert_series(
        WEEKLY, [first, second, annotated], window_start=START, window_end=START + timedelta(days=14)
    )
    assert len(series.observations) == 2
    dates = {o.collected_at for o in series.observations}
    assert START not in dates
    assert START + timedelta(days=7) in dates
    assert {o.lineage_id for o in series.observations} == {first.effective_lineage_id, second.effective_lineage_id}


def test_incomplete_run_is_excluded_and_counted() -> None:
    artifacts = _weekly(3)
    artifacts[1].metadata[COLLECTION_COMPLETE_METADATA_KEY] = False
    series = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=14))
    assert len(series.observations) == 2
    assert series.excluded_observations == 1
    assert series.verdict == SeriesVerdict.GAPPED
    assert "left out" in series.describe()
    assert "compliance" not in series.describe().lower().replace("not a compliance", "")


def test_collection_time_timestamp_is_excluded() -> None:
    artifacts = _weekly(3)
    for artifact in artifacts:
        artifact.metadata[TIMESTAMP_SOURCE_METADATA_KEY] = TIMESTAMP_SOURCE_COLLECTION_TIME
    series = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=14))
    assert series.observations == []
    assert series.excluded_observations == 3
    assert series.verdict == SeriesVerdict.INSUFFICIENT


def test_record_timestamp_and_complete_run_count_as_before() -> None:
    artifacts = _weekly(3)
    for artifact in artifacts:
        artifact.metadata[TIMESTAMP_SOURCE_METADATA_KEY] = TIMESTAMP_SOURCE_RECORD
        artifact.metadata[COLLECTION_COMPLETE_METADATA_KEY] = True
    series = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=14))
    assert len(series.observations) == 3
    assert series.verdict == SeriesVerdict.CONTINUOUS
    assert series.excluded_observations == 0


def test_series_json_carries_the_exclusion_count() -> None:
    artifacts = _weekly(2)
    artifacts[0].metadata[COLLECTION_COMPLETE_METADATA_KEY] = False
    series = assert_series(WEEKLY, artifacts, window_start=START, window_end=START + timedelta(days=7))
    assert series.model_dump(mode="json")["excluded_observations"] == 1


def test_latest_observations_honours_as_of_and_provenance() -> None:
    on_time = _artifact(START)
    future = _artifact(datetime(2099, 12, 31, tzinfo=UTC))
    clock_dated = _artifact(
        START + timedelta(days=30), **{TIMESTAMP_SOURCE_METADATA_KEY: TIMESTAMP_SOURCE_COLLECTION_TIME}
    )
    bounded = latest_observations([on_time, future, clock_dated], as_of=START.date() + timedelta(days=60))
    assert bounded == {WEEKLY: START.date()}
    assert latest_observations([on_time, future, clock_dated]) == {WEEKLY: date(2099, 12, 31)}


def test_latest_observations_reads_the_current_version() -> None:
    first = _artifact(START)
    corrected = first.new_version(collected_at=START - timedelta(days=3))
    assert latest_observations([first, corrected]) == {WEEKLY: (START - timedelta(days=3)).date()}
