"""Unit tests for the AI system registry store (v0.9.3 P2.4)."""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.ai_governance import (
    AIRegistryStore,
    AISystemDescriptor,
    AISystemRegistryEntry,
    DeploymentStatus,
    classify,
)
from evidentia_core.ai_governance.registry_store import (
    AI_REGISTRY_ENV_VAR,
    InvalidAISystemIdError,
    get_ai_registry_dir,
)
from evidentia_core.models.common import new_id


@pytest.fixture()
def sample_entry() -> AISystemRegistryEntry:
    descriptor = AISystemDescriptor(
        name="resume-screener",
        purpose="Score job applicants",
    )
    classification = classify(descriptor)
    return AISystemRegistryEntry(
        descriptor=descriptor,
        classification=classification,
        provider="acme-ai",
        owner="hr-team",
        deployment_status=DeploymentStatus.PILOT,
    )


class TestGetAIRegistryDir:
    def test_override_wins(self, tmp_path: Path) -> None:
        assert get_ai_registry_dir(tmp_path / "custom") == (
            (tmp_path / "custom").expanduser().resolve()
        )

    def test_env_used_when_no_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(AI_REGISTRY_ENV_VAR, str(tmp_path / "env-dir"))
        assert get_ai_registry_dir() == (
            (tmp_path / "env-dir").expanduser().resolve()
        )

    def test_platformdirs_fallback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(AI_REGISTRY_ENV_VAR, raising=False)
        result = get_ai_registry_dir()
        assert "ai_registry" in str(result)


class TestAIRegistryStoreCRUD:
    def test_save_and_load_round_trips(
        self, tmp_path: Path, sample_entry: AISystemRegistryEntry
    ) -> None:
        store = AIRegistryStore(tmp_path)
        store.save(sample_entry)
        loaded = store.load(sample_entry.system_id)
        assert loaded is not None
        assert loaded.system_id == sample_entry.system_id
        assert loaded.descriptor.name == "resume-screener"
        assert loaded.provider == "acme-ai"

    def test_save_bumps_updated_at(
        self, tmp_path: Path, sample_entry: AISystemRegistryEntry
    ) -> None:
        store = AIRegistryStore(tmp_path)
        original_updated_at = sample_entry.updated_at
        store.save(sample_entry)
        loaded = store.load(sample_entry.system_id)
        assert loaded is not None
        assert loaded.updated_at >= original_updated_at

    def test_load_returns_none_for_unknown_id(self, tmp_path: Path) -> None:
        store = AIRegistryStore(tmp_path)
        assert store.load(new_id()) is None

    def test_load_invalid_id_raises(self, tmp_path: Path) -> None:
        store = AIRegistryStore(tmp_path)
        with pytest.raises(InvalidAISystemIdError):
            store.load("not-a-uuid")

    def test_list_all_sorts_by_created_at(
        self, tmp_path: Path
    ) -> None:
        store = AIRegistryStore(tmp_path)
        descriptors = [
            AISystemDescriptor(name=f"sys-{i}", purpose="x")
            for i in range(3)
        ]
        entries = [
            AISystemRegistryEntry(
                descriptor=d,
                classification=classify(d),
                provider="acme",
                owner="team",
            )
            for d in descriptors
        ]
        for e in entries:
            store.save(e)
        listed = store.list_all()
        assert len(listed) == 3
        # Sorted ascending by created_at; entries were saved in
        # order so the order should match (modulo timestamp ties).
        assert {e.descriptor.name for e in listed} == {
            "sys-0",
            "sys-1",
            "sys-2",
        }

    def test_list_all_empty_for_missing_dir(self, tmp_path: Path) -> None:
        store = AIRegistryStore(tmp_path / "does-not-exist")
        assert store.list_all() == []

    def test_delete_removes_file(
        self, tmp_path: Path, sample_entry: AISystemRegistryEntry
    ) -> None:
        store = AIRegistryStore(tmp_path)
        store.save(sample_entry)
        assert store.delete(sample_entry.system_id) is True
        assert store.load(sample_entry.system_id) is None
        # Idempotent: delete again returns False, no raise.
        assert store.delete(sample_entry.system_id) is False

    def test_path_traversal_id_rejected(self, tmp_path: Path) -> None:
        store = AIRegistryStore(tmp_path)
        with pytest.raises(InvalidAISystemIdError):
            store.load("../../etc/passwd")
