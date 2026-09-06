"""Unit tests for evidentia_core.retention.worm (v0.7.11 P0)."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

import pytest
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
)
from evidentia_core.retention.worm import (
    LocalFilesystemWORM,
    WORMBackendError,
)


@pytest.fixture()
def worm(tmp_path: Path) -> LocalFilesystemWORM:
    return LocalFilesystemWORM(root=tmp_path / "worm")


def _meta(**overrides: object) -> RetentionMetadata:
    base: dict[str, object] = {
        "classification": RetentionClassification.SOX_404,
        "retention_period_days": 365,
    }
    base.update(overrides)
    return RetentionMetadata.model_validate(base)


# ── put / get round-trip ───────────────────────────────────────────


class TestPutGet:
    def test_round_trip(self, worm: LocalFilesystemWORM) -> None:
        m = _meta()
        worm.put(m.id, b"payload bytes", m)
        assert worm.get(m.id) == b"payload bytes"
        loaded_meta = worm.get_metadata(m.id)
        assert loaded_meta.id == m.id
        assert loaded_meta.classification == m.classification

    def test_get_missing_raises(self, worm: LocalFilesystemWORM) -> None:
        with pytest.raises(WORMBackendError):
            worm.get("aaaaaaaa-1111-2222-3333-444444444444")

    def test_get_metadata_missing_raises(self, worm: LocalFilesystemWORM) -> None:
        with pytest.raises(WORMBackendError):
            worm.get_metadata("aaaaaaaa-1111-2222-3333-444444444444")

    def test_double_put_rejected(self, worm: LocalFilesystemWORM) -> None:
        m = _meta()
        worm.put(m.id, b"first", m)
        with pytest.raises(WORMBackendError):
            worm.put(m.id, b"second", m)

    def test_path_traversal_rejected(self, worm: LocalFilesystemWORM) -> None:
        m = _meta()
        m_evil = m.model_copy(update={"id": "../../etc/passwd"})
        with pytest.raises(WORMBackendError):
            worm.put(m_evil.id, b"x", m_evil)


# ── delete enforcement ─────────────────────────────────────────────


class TestDelete:
    def test_delete_inside_window_rejected(self, worm: LocalFilesystemWORM) -> None:
        future = date.today() + timedelta(days=365)
        m = _meta(lock_until=future)
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError):
            worm.delete(m.id)

    def test_delete_under_legal_hold_rejected(self, worm: LocalFilesystemWORM) -> None:
        past = date.today() - timedelta(days=1)
        m = _meta(
            lock_until=past,
            legal_hold=True,
            lifecycle_stage=RetentionLifecycleStage.EXPIRED,
        )
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError):
            worm.delete(m.id)

    def test_delete_active_stage_rejected(self, worm: LocalFilesystemWORM) -> None:
        past = date.today() - timedelta(days=1)
        m = _meta(lock_until=past)  # stage stays ACTIVE
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError):
            worm.delete(m.id)

    def test_delete_expired_no_hold_succeeds(self, worm: LocalFilesystemWORM) -> None:
        past = date.today() - timedelta(days=1)
        m = _meta(
            lock_until=past,
            lifecycle_stage=RetentionLifecycleStage.EXPIRED,
        )
        worm.put(m.id, b"x", m)
        worm.delete(m.id)
        with pytest.raises(WORMBackendError):
            worm.get(m.id)


# ── extend_retention ───────────────────────────────────────────────


class TestExtendRetention:
    def test_extend_lock_until_succeeds(self, worm: LocalFilesystemWORM) -> None:
        future = date.today() + timedelta(days=30)
        m = _meta(lock_until=future)
        worm.put(m.id, b"x", m)
        farther = date.today() + timedelta(days=365 * 5)
        new_meta = worm.extend_retention(m.id, farther)
        assert new_meta.lock_until == farther
        # Verify persistence
        loaded = worm.get_metadata(m.id)
        assert loaded.lock_until == farther

    def test_shortening_lock_until_rejected(self, worm: LocalFilesystemWORM) -> None:
        future = date.today() + timedelta(days=365)
        m = _meta(lock_until=future)
        worm.put(m.id, b"x", m)
        sooner = date.today() + timedelta(days=30)
        with pytest.raises(WORMBackendError):
            worm.extend_retention(m.id, sooner)
