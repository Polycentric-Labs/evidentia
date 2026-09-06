"""Unit tests for evidentia_core.retention.metadata (v0.7.11 P0)."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
    RetentionPolicy,
    RetentionTransitionError,
    default_retention_days,
    generate_retention_report,
    is_locked,
    transition_lifecycle,
)
from evidentia_core.retention_metadata_store import (
    RETENTION_STORE_ENV_VAR,
    InvalidRetentionIdError,
    delete_retention,
    list_retention,
    load_retention_by_id,
    save_retention,
)

# ── enum sanity ────────────────────────────────────────────────────


class TestEnums:
    def test_classifications(self) -> None:
        values = {c.value for c in RetentionClassification}
        assert "sec-17a-4" in values
        assert "finra-3110" in values
        assert "model-risk" in values
        assert "gdpr" in values
        assert "generic" in values

    def test_lifecycle_stages(self) -> None:
        assert {s.value for s in RetentionLifecycleStage} == {"active", "preserved", "expired", "purged"}


class TestDefaultRetentionDays:
    @pytest.mark.parametrize(
        "cls,expected",
        [
            ("sec-17a-4", 6 * 365),
            ("finra-3110", 6 * 365),
            ("irs-tax", 7 * 365),
            ("sox-404", 7 * 365),
            ("hipaa", 6 * 365),
            ("glba", 5 * 365),
            ("pci-dss", 365),
            ("model-risk", 7 * 365),
            ("gdpr", 0),
            ("generic", 7 * 365),
        ],
    )
    def test_per_classification_default(self, cls: str, expected: int) -> None:
        assert default_retention_days(cls) == expected

    def test_unknown_returns_safe_default(self) -> None:
        assert default_retention_days("not-a-real-class") == 7 * 365


# ── RetentionMetadata construction + lock-until auto-population ────


class TestRetentionMetadata:
    def test_minimal_construction(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=7 * 365,
        )
        assert m.id  # auto-UUID
        assert m.lifecycle_stage == RetentionLifecycleStage.ACTIVE.value
        assert m.legal_hold is False

    def test_lock_until_auto_populated(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.PCI_DSS,
            retention_period_days=365,
        )
        # lock_until should be approximately created_at + 365 days
        assert m.lock_until is not None
        expected = m.created_at.date() + timedelta(days=365)
        assert m.lock_until == expected

    def test_zero_retention_no_lock(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.GDPR,
            retention_period_days=0,
        )
        # GDPR purpose-limited — no automatic lock
        assert m.lock_until is None

    def test_explicit_lock_until_overrides(self) -> None:
        explicit = date(2030, 1, 1)
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lock_until=explicit,
        )
        assert m.lock_until == explicit

    def test_extra_fields_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            RetentionMetadata(  # type: ignore[call-arg]
                classification=RetentionClassification.SOX_404,
                retention_period_days=365,
                bogus="should fail",
            )


# ── RetentionPolicy ────────────────────────────────────────────────


class TestRetentionPolicy:
    def test_minimal_construction(self) -> None:
        p = RetentionPolicy(
            name="sox-evidence",
            description="SOX §404 audit evidence",
            classification=RetentionClassification.SOX_404,
            retention_period_days=7 * 365,
        )
        assert p.lock_enforced is True

    def test_negative_period_rejected(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            RetentionPolicy(
                name="x",
                description="x",
                classification=RetentionClassification.GENERIC,
                retention_period_days=-1,
            )


# ── is_locked ──────────────────────────────────────────────────────


class TestIsLocked:
    def test_legal_hold_always_locked(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=0,
            legal_hold=True,
        )
        assert is_locked(m) is True

    def test_inside_window(self) -> None:
        future = date.today() + timedelta(days=365)
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lock_until=future,
        )
        assert is_locked(m, today=date.today()) is True

    def test_past_window(self) -> None:
        past = date.today() - timedelta(days=1)
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lock_until=past,
        )
        assert is_locked(m, today=date.today()) is False

    def test_purged_not_locked(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lifecycle_stage=RetentionLifecycleStage.PURGED,
        )
        assert is_locked(m) is False

    def test_no_lock_until_not_locked(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.GDPR,
            retention_period_days=0,
        )
        assert is_locked(m) is False


# ── transition_lifecycle ───────────────────────────────────────────


class TestTransitionLifecycle:
    def test_active_to_preserved(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        new = transition_lifecycle(m, RetentionLifecycleStage.PRESERVED)
        assert new.lifecycle_stage == RetentionLifecycleStage.PRESERVED.value

    def test_preserved_back_to_active(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lifecycle_stage=RetentionLifecycleStage.PRESERVED,
        )
        new = transition_lifecycle(m, RetentionLifecycleStage.ACTIVE)
        assert new.lifecycle_stage == RetentionLifecycleStage.ACTIVE.value

    def test_active_to_expired_inside_window_rejected(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        with pytest.raises(RetentionTransitionError):
            transition_lifecycle(m, RetentionLifecycleStage.EXPIRED)

    def test_active_to_expired_after_window(self) -> None:
        # Past lock-until
        past = date.today() - timedelta(days=1)
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lock_until=past,
        )
        new = transition_lifecycle(m, RetentionLifecycleStage.EXPIRED)
        assert new.lifecycle_stage == RetentionLifecycleStage.EXPIRED.value

    def test_legal_hold_blocks_expiration(self) -> None:
        past = date.today() - timedelta(days=1)
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lock_until=past,
            legal_hold=True,
        )
        with pytest.raises(RetentionTransitionError):
            transition_lifecycle(m, RetentionLifecycleStage.EXPIRED)

    def test_purged_terminal(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lifecycle_stage=RetentionLifecycleStage.PURGED,
        )
        with pytest.raises(RetentionTransitionError):
            transition_lifecycle(m, RetentionLifecycleStage.ACTIVE)

    def test_expired_to_purged(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lifecycle_stage=RetentionLifecycleStage.EXPIRED,
        )
        new = transition_lifecycle(m, RetentionLifecycleStage.PURGED)
        assert new.lifecycle_stage == RetentionLifecycleStage.PURGED.value

    def test_illegal_skip_active_to_purged(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        with pytest.raises(RetentionTransitionError):
            transition_lifecycle(m, RetentionLifecycleStage.PURGED)


# ── generate_retention_report ──────────────────────────────────────


class TestGenerateRetentionReport:
    def test_empty_minimal(self) -> None:
        out = generate_retention_report([])
        assert "No records" in out

    def test_includes_classification_table(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        out = generate_retention_report([m])
        assert "Per-classification" in out
        assert "sox-404" in out

    def test_purge_eligible_callout_when_expired(self) -> None:
        past = date.today() - timedelta(days=1)
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            lock_until=past,
            lifecycle_stage=RetentionLifecycleStage.EXPIRED,
        )
        out = generate_retention_report([m])
        assert "eligible for secure purge" in out
        assert "## Records eligible for purge" in out

    def test_legal_hold_section(self) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
            legal_hold=True,
            notes="Litigation pending",
        )
        out = generate_retention_report([m])
        assert "## Records under legal hold" in out
        assert "Litigation pending" in out


# ── retention_metadata_store ───────────────────────────────────────


@pytest.fixture()
def isolated_retention_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    store = tmp_path / "retention-store"
    monkeypatch.setenv(RETENTION_STORE_ENV_VAR, str(store))
    return store


class TestRetentionStore:
    def test_save_and_load(self, isolated_retention_store: Path) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        save_retention(m)
        loaded = load_retention_by_id(m.id)
        assert loaded is not None
        assert loaded.id == m.id

    def test_atomic_save(self, isolated_retention_store: Path) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        save_retention(m)
        assert list(isolated_retention_store.glob("*.tmp")) == []

    def test_load_unknown_returns_none(self, isolated_retention_store: Path) -> None:
        assert load_retention_by_id("00000000-0000-0000-0000-000000000000") is None

    def test_load_invalid_id_raises(self, isolated_retention_store: Path) -> None:
        with pytest.raises(InvalidRetentionIdError):
            load_retention_by_id("not-a-uuid")

    def test_delete(self, isolated_retention_store: Path) -> None:
        m = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        save_retention(m)
        assert delete_retention(m.id) is True
        assert load_retention_by_id(m.id) is None

    def test_delete_unknown_returns_false(self, isolated_retention_store: Path) -> None:
        assert delete_retention("00000000-0000-0000-0000-000000000000") is False

    def test_list_sort_order(self, isolated_retention_store: Path) -> None:
        m1 = RetentionMetadata(
            classification=RetentionClassification.SOX_404,
            retention_period_days=365,
        )
        m2 = RetentionMetadata(
            classification=RetentionClassification.PCI_DSS,
            retention_period_days=365,
        )
        save_retention(m1)
        save_retention(m2)
        listed = list_retention()
        # Sort by classification (alphabetical) — pci-dss < sox-404
        assert listed[0].classification == "pci-dss"
        assert listed[1].classification == "sox-404"
