"""Unit tests for evidentia_core.model_risk_store (v0.7.10 P0.6.1)."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from evidentia_core.model_risk_store import (
    InvalidModelIdError,
    delete_model,
    get_model_store_dir,
    list_models,
    load_model_by_id,
    save_model,
)
from evidentia_core.models.model_risk import (
    Methodology,
    ModelInventory,
    Provenance,
    Tier,
    ValidationFinding,
    ValidationSeverity,
)


def _make_model(
    name: str = "Test Model",
    tier: Tier = Tier.TIER_1,
    methodology: Methodology = Methodology.ML,
) -> ModelInventory:
    return ModelInventory(
        name=name,
        purpose="Test purpose",
        methodology=methodology,
        vendor_or_internal=Provenance.INTERNAL,
        tier=tier,
        owner="ml-team@example.com",
    )


# ── store-dir resolution ───────────────────────────────────────────


class TestGetModelStoreDir:
    def test_explicit_override_wins(self, tmp_path: Path) -> None:
        result = get_model_store_dir(tmp_path)
        assert result == tmp_path.expanduser().resolve()

    def test_env_var_used_when_no_override(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EVIDENTIA_MODEL_STORE_DIR", str(tmp_path))
        result = get_model_store_dir()
        assert result == tmp_path.expanduser().resolve()

    def test_explicit_override_beats_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        env_dir = tmp_path / "env"
        override = tmp_path / "override"
        env_dir.mkdir()
        override.mkdir()
        monkeypatch.setenv("EVIDENTIA_MODEL_STORE_DIR", str(env_dir))
        result = get_model_store_dir(override)
        assert result == override.expanduser().resolve()


# ── ID-shape validation ────────────────────────────────────────────


class TestIdShapeValidation:
    def test_save_rejects_non_uuid(self, tmp_path: Path) -> None:
        m = _make_model()
        m.id = "../../etc/passwd"  # type: ignore[assignment]
        with pytest.raises(InvalidModelIdError):
            save_model(m, model_store_dir=tmp_path)

    def test_load_rejects_non_uuid(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidModelIdError):
            load_model_by_id("not-a-uuid", model_store_dir=tmp_path)

    def test_delete_rejects_non_uuid(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidModelIdError):
            delete_model("../traversal", model_store_dir=tmp_path)


# ── save/load roundtrip ────────────────────────────────────────────


class TestSaveLoadRoundtrip:
    def test_save_then_load(self, tmp_path: Path) -> None:
        m = _make_model("Original")
        save_model(m, model_store_dir=tmp_path)
        loaded = load_model_by_id(m.id, model_store_dir=tmp_path)
        assert loaded is not None
        assert loaded.name == "Original"
        assert loaded.id == m.id

    def test_load_returns_none_for_unknown_id(self, tmp_path: Path) -> None:
        result = load_model_by_id(
            "00000000-0000-0000-0000-000000000000",
            model_store_dir=tmp_path,
        )
        assert result is None

    def test_save_overwrites(self, tmp_path: Path) -> None:
        m = _make_model("First")
        save_model(m, model_store_dir=tmp_path)
        m.name = "Updated"
        save_model(m, model_store_dir=tmp_path)
        loaded = load_model_by_id(m.id, model_store_dir=tmp_path)
        assert loaded is not None
        assert loaded.name == "Updated"

    def test_save_atomic_no_tmp_left_behind(self, tmp_path: Path) -> None:
        m = _make_model()
        save_model(m, model_store_dir=tmp_path)
        # No <id>.json.tmp leftover
        tmp_files = list(tmp_path.glob("*.tmp"))
        assert tmp_files == []

    def test_save_refreshes_updated_at(self, tmp_path: Path) -> None:
        m = _make_model()
        original_updated = m.updated_at
        # Sleep nothing — utc_now() resolution should differentiate
        save_model(m, model_store_dir=tmp_path)
        # save_model mutates the in-memory model's updated_at
        assert m.updated_at >= original_updated

    def test_save_preserves_validation_findings(self, tmp_path: Path) -> None:
        m = _make_model()
        m.validation_findings = [
            ValidationFinding(
                title="Open finding",
                description="Detected during validation",
                severity=ValidationSeverity.HIGH,
                detected_at=date(2026, 1, 15),
            ),
        ]
        save_model(m, model_store_dir=tmp_path)
        loaded = load_model_by_id(m.id, model_store_dir=tmp_path)
        assert loaded is not None
        assert len(loaded.validation_findings) == 1
        assert loaded.validation_findings[0].severity == ValidationSeverity.HIGH


# ── list_models ────────────────────────────────────────────────────


class TestListModels:
    def test_empty_dir(self, tmp_path: Path) -> None:
        assert list_models(model_store_dir=tmp_path) == []

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        result = list_models(model_store_dir=tmp_path / "nope")
        assert result == []

    def test_returns_all_saved(self, tmp_path: Path) -> None:
        m1 = _make_model("Alpha", tier=Tier.TIER_1)
        m2 = _make_model("Beta", tier=Tier.TIER_2)
        save_model(m1, model_store_dir=tmp_path)
        save_model(m2, model_store_dir=tmp_path)
        result = list_models(model_store_dir=tmp_path)
        names = {m.name for m in result}
        assert names == {"Alpha", "Beta"}

    def test_sort_by_tier_then_name(self, tmp_path: Path) -> None:
        save_model(
            _make_model("Z-tier-3", tier=Tier.TIER_3),
            model_store_dir=tmp_path,
        )
        save_model(
            _make_model("A-tier-3", tier=Tier.TIER_3),
            model_store_dir=tmp_path,
        )
        save_model(
            _make_model("B-tier-1", tier=Tier.TIER_1),
            model_store_dir=tmp_path,
        )
        save_model(
            _make_model("C-tier-2", tier=Tier.TIER_2),
            model_store_dir=tmp_path,
        )
        result = list_models(model_store_dir=tmp_path)
        names = [m.name for m in result]
        # Tier 1 first → Tier 2 → Tier 3 (alphabetical within tier)
        assert names == ["B-tier-1", "C-tier-2", "A-tier-3", "Z-tier-3"]


# ── delete_model ───────────────────────────────────────────────────


class TestDeleteModel:
    def test_delete_existing_returns_true(self, tmp_path: Path) -> None:
        m = _make_model()
        save_model(m, model_store_dir=tmp_path)
        result = delete_model(m.id, model_store_dir=tmp_path)
        assert result is True
        # Confirm gone
        assert load_model_by_id(m.id, model_store_dir=tmp_path) is None

    def test_delete_unknown_returns_false(self, tmp_path: Path) -> None:
        result = delete_model(
            "00000000-0000-0000-0000-000000000000",
            model_store_dir=tmp_path,
        )
        assert result is False
