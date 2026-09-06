"""Unit tests for the OMB M-25-22 acquisition-lifecycle surface (v0.11).

Model + store. Lifecycle phases verified against the memo text
2026-07-14 (§4(a)–(f)); the store clones the registry_store pattern
and gets the same isolation + traversal-guard coverage.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.ai_governance import (
    AcquisitionPhase,
    AcquisitionPhaseRecord,
    AcquisitionPhaseStatus,
    AIAcquisition,
    AIAcquisitionStore,
    acquisition_progress,
)
from evidentia_core.ai_governance.acquisition_store import (
    InvalidAcquisitionIdError,
)


class TestAcquisitionPhase:
    def test_six_phases_present(self) -> None:
        assert len(AcquisitionPhase) == 6

    def test_phase_values_stable(self) -> None:
        """String values are persisted in records — never change them."""
        assert {p.value for p in AcquisitionPhase} == {
            "identification_of_requirements",
            "market_research_and_planning",
            "solicitation_development",
            "selection_and_award",
            "contract_administration",
            "contract_closeout",
        }


class TestAcquisitionProgress:
    def test_empty_phases_all_missing(self) -> None:
        summary = acquisition_progress(AIAcquisition(name="x"))
        assert summary.total == 6
        assert len(summary.missing) == 6
        assert not summary.lifecycle_complete

    def test_all_complete_is_lifecycle_complete(self) -> None:
        acquisition = AIAcquisition(
            name="x",
            phases={p: AcquisitionPhaseRecord(status=AcquisitionPhaseStatus.COMPLETE) for p in AcquisitionPhase},
        )
        summary = acquisition_progress(acquisition)
        assert summary.lifecycle_complete
        assert summary.complete == 6
        assert summary.missing == []

    def test_in_progress_blocks_completion(self) -> None:
        phases = {p: AcquisitionPhaseRecord(status=AcquisitionPhaseStatus.COMPLETE) for p in AcquisitionPhase}
        phases[AcquisitionPhase.CONTRACT_CLOSEOUT] = AcquisitionPhaseRecord(status=AcquisitionPhaseStatus.IN_PROGRESS)
        summary = acquisition_progress(AIAcquisition(name="x", phases=phases))
        assert not summary.lifecycle_complete
        assert summary.in_progress == 1

    def test_string_keyed_phases_from_persisted_json(self) -> None:
        """Store persistence round-trips enum keys as strings."""
        loaded = AIAcquisition.model_validate(
            {
                "name": "x",
                "phases": {
                    "selection_and_award": {"status": "in_progress"},
                },
            }
        )
        summary = acquisition_progress(loaded)
        assert summary.in_progress == 1
        assert len(summary.missing) == 5

    def test_default_high_impact_determination_is_not_assessed(self) -> None:
        acquisition = AIAcquisition(name="x")
        determination = acquisition.likely_high_impact
        assert (determination if isinstance(determination, str) else determination.value) == "not_assessed"


class TestAIAcquisitionStore:
    @pytest.fixture()
    def store(self, tmp_path: Path) -> AIAcquisitionStore:
        return AIAcquisitionStore(tmp_path / "acquisitions")

    def test_save_load_round_trip(self, store: AIAcquisitionStore) -> None:
        acquisition = AIAcquisition(
            name="Case-triage LLM service",
            solicitation_reference="RFP-26-0141",
        )
        store.save(acquisition)
        loaded = store.load(acquisition.acquisition_id)
        assert loaded is not None
        assert loaded.name == "Case-triage LLM service"
        assert loaded.solicitation_reference == "RFP-26-0141"

    def test_save_bumps_updated_at(self, store: AIAcquisitionStore) -> None:
        acquisition = AIAcquisition(name="x")
        before = acquisition.updated_at
        store.save(acquisition)
        assert acquisition.updated_at >= before

    def test_load_unknown_id_returns_none(self, store: AIAcquisitionStore) -> None:
        assert store.load("11111111-1111-4111-8111-111111111111") is None

    def test_load_invalid_id_raises(self, store: AIAcquisitionStore) -> None:
        with pytest.raises(InvalidAcquisitionIdError):
            store.load("../../etc/passwd")

    def test_list_all_sorted_by_created_at(self, store: AIAcquisitionStore) -> None:
        first = AIAcquisition(name="first")
        second = AIAcquisition(name="second")
        store.save(second)
        store.save(first)
        names = [a.name for a in store.list_all()]
        assert names == sorted(
            names,
            key=lambda n: (first if n == "first" else second).created_at,
        )

    def test_delete(self, store: AIAcquisitionStore) -> None:
        acquisition = AIAcquisition(name="x")
        store.save(acquisition)
        assert store.delete(acquisition.acquisition_id) is True
        assert store.load(acquisition.acquisition_id) is None
        assert store.delete(acquisition.acquisition_id) is False

    def test_malformed_file_skipped_by_list_all(self, store: AIAcquisitionStore, tmp_path: Path) -> None:
        acquisition = AIAcquisition(name="x")
        store.save(acquisition)
        rogue = store.directory / "22222222-2222-4222-8222-222222222222.json"
        rogue.write_text("{not json", encoding="utf-8")
        records = store.list_all()
        assert [a.name for a in records] == ["x"]


class TestAcquisitionFieldBounds:
    def test_linked_system_id_is_length_bounded(self) -> None:
        """linked_system_id is capped like every sibling string field."""
        from pydantic import ValidationError

        AIAcquisition(name="ok", linked_system_id="s" * 256)
        with pytest.raises(ValidationError):
            AIAcquisition(name="ok", linked_system_id="s" * 257)
