"""``iter_artifacts`` (v0.13, V13-01): the filtered walk over the evidence store."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from evidentia_core.evidence_store import iter_artifacts, save_evidence
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType

T0 = datetime(2026, 6, 1, 12, tzinfo=UTC)


def _artifact(collected: datetime, source: str = "nessus", **metadata: object) -> EvidenceArtifact:
    return EvidenceArtifact.model_validate(
        {
            "title": f"{source} {collected.isoformat()}",
            "evidence_type": EvidenceType.TEST_RESULT,
            "source_system": source,
            "collected_by": "test-runner@example.com",
            "collected_at": collected,
            "content": {"ok": True},
            "metadata": metadata,
        }
    )


@pytest.fixture()
def populated(tmp_path: Path) -> Path:
    store = tmp_path / "store"
    for offset in range(5):
        save_evidence(
            _artifact(T0 + timedelta(days=7 * offset), cadence_slug="pci-dss-11-6-1-weekly"),
            evidence_store_dir=store,
        )
    save_evidence(_artifact(T0 + timedelta(days=3), source="okta"), evidence_store_dir=store)
    save_evidence(
        _artifact(T0 + timedelta(days=100), cadence_slug="nist-800-53-rev5-ca7"),
        evidence_store_dir=store,
    )
    return store


def test_unfiltered_walk_yields_every_version(populated: Path) -> None:
    assert len(list(iter_artifacts(populated))) == 7


def test_metadata_filter(populated: Path) -> None:
    got = list(iter_artifacts(populated, metadata={"cadence_slug": "pci-dss-11-6-1-weekly"}))
    assert len(got) == 5
    assert {a.source_system for a in got} == {"nessus"}


def test_source_system_filter(populated: Path) -> None:
    assert [a.source_system for a in iter_artifacts(populated, source_system="okta")] == ["okta"]


def test_time_window_is_inclusive(populated: Path) -> None:
    got = list(iter_artifacts(populated, since=T0 + timedelta(days=7), until=T0 + timedelta(days=21)))
    assert sorted(a.collected_at for a in got) == [
        T0 + timedelta(days=7),
        T0 + timedelta(days=14),
        T0 + timedelta(days=21),
    ]


def test_naive_bounds_are_read_as_utc(populated: Path) -> None:
    naive = (T0 + timedelta(days=100)).replace(tzinfo=None)
    got = list(iter_artifacts(populated, since=naive))
    assert len(got) == 1
    assert got[0].metadata["cadence_slug"] == "nist-800-53-rev5-ca7"


def test_versions_within_a_lineage_are_all_visible(tmp_path: Path) -> None:
    store = tmp_path / "store"
    v1 = _artifact(T0, cadence_slug="pci-dss-11-6-1-weekly")
    save_evidence(v1, evidence_store_dir=store)
    v2 = v1.new_version(collected_at=T0 + timedelta(days=7))
    save_evidence(v2, evidence_store_dir=store)
    got = sorted(iter_artifacts(store), key=lambda a: a.version)
    assert [a.version for a in got] == [1, 2]
    assert got[1].effective_lineage_id == got[0].effective_lineage_id


def test_missing_store_yields_nothing(tmp_path: Path) -> None:
    assert list(iter_artifacts(tmp_path / "absent")) == []
