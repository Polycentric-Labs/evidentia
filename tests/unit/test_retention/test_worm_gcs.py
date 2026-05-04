"""Unit tests for evidentia_core.retention.worm_gcs (v0.7.12 P0).

GCS doesn't have a moto equivalent. The Google Cloud Storage SDK
is mocked with a stateful in-memory simulator that matches the
surface used by GCSBucketLockWORM.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
)
from evidentia_core.retention.worm import WORMBackendError
from evidentia_core.retention.worm_gcs import GCSBucketLockWORM
from google.api_core.exceptions import NotFound

# ── In-memory GCS SDK stub ─────────────────────────────────────────


class _BlobStub:
    def __init__(self, store: dict[str, Any], name: str) -> None:
        self._store = store
        self._name = name
        self.temporary_hold = False
        self.event_based_hold = False

    def exists(self) -> bool:
        return self._name in self._store

    def upload_from_string(
        self,
        data: bytes | str,
        *,
        if_generation_match: int | None = None,
        content_type: str | None = None,
    ) -> None:
        if (
            if_generation_match == 0
            and self._name in self._store
        ):
            from google.api_core.exceptions import PreconditionFailed

            raise PreconditionFailed(
                "Object already exists (if_generation_match=0)"
            )
        body = data.encode("utf-8") if isinstance(data, str) else data
        self._store[self._name] = {
            "data": body,
            "temporary_hold": self.temporary_hold,
            "event_based_hold": self.event_based_hold,
            "content_type": content_type,
        }

    def download_as_bytes(self) -> bytes:
        if self._name not in self._store:
            raise NotFound(f"Blob {self._name} not found")
        result: bytes = self._store[self._name]["data"]
        return result

    def delete(self) -> None:
        if self._name not in self._store:
            raise NotFound(f"Blob {self._name} not found")
        rec = self._store[self._name]
        if rec.get("temporary_hold") or rec.get("event_based_hold"):
            from google.api_core.exceptions import Forbidden

            raise Forbidden("Blob is under hold; cannot delete")
        del self._store[self._name]

    def patch(self) -> None:
        if self._name not in self._store:
            raise NotFound(f"Blob {self._name} not found")
        # Patch persists the hold state from this BlobStub instance
        rec = self._store[self._name]
        rec["temporary_hold"] = self.temporary_hold
        rec["event_based_hold"] = self.event_based_hold


class _BucketStub:
    def __init__(self, store: dict[str, Any]) -> None:
        self._store = store

    def blob(self, name: str) -> _BlobStub:
        return _BlobStub(self._store, name)


class _ClientStub:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    def bucket(self, name: str) -> _BucketStub:
        return _BucketStub(self.store)


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def client() -> _ClientStub:
    return _ClientStub()


@pytest.fixture
def worm(client: _ClientStub) -> GCSBucketLockWORM:
    return GCSBucketLockWORM(
        bucket_name="evidentia-worm",
        client_factory=lambda: client,
    )


def _meta(**overrides: object) -> RetentionMetadata:
    base: dict[str, object] = {
        "classification": RetentionClassification.SOX_404,
        "retention_period_days": 365,
    }
    base.update(overrides)
    return RetentionMetadata.model_validate(base)


# ── Tests (mirror S3 + Azure structure) ────────────────────────────


class TestPutGet:
    def test_round_trip(self, worm: GCSBucketLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"payload-bytes", m)
        assert worm.get(m.id) == b"payload-bytes"
        loaded = worm.get_metadata(m.id)
        assert loaded.id == m.id

    def test_get_missing_raises(self, worm: GCSBucketLockWORM) -> None:
        with pytest.raises(WORMBackendError, match="not found"):
            worm.get("aaaaaaaa-1111-2222-3333-444444444444")

    def test_double_put_rejected(self, worm: GCSBucketLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"first", m)
        with pytest.raises(WORMBackendError, match="already exists"):
            worm.put(m.id, b"second", m)

    def test_put_with_legal_hold(self, worm: GCSBucketLockWORM) -> None:
        m = _meta(legal_hold=True)
        worm.put(m.id, b"with-hold", m)
        assert worm.get_metadata(m.id).legal_hold is True

    def test_put_zero_retention_gdpr(
        self, worm: GCSBucketLockWORM
    ) -> None:
        m = _meta(
            classification=RetentionClassification.GDPR,
            retention_period_days=0,
        )
        worm.put(m.id, b"gdpr-payload", m)
        assert worm.get(m.id) == b"gdpr-payload"


class TestDelete:
    def test_delete_active_within_window_rejected(
        self, worm: GCSBucketLockWORM
    ) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="retention window"):
            worm.delete(m.id)

    def test_delete_legal_hold_rejected(
        self, worm: GCSBucketLockWORM
    ) -> None:
        m = _meta(legal_hold=True)
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="legal hold"):
            worm.delete(m.id)

    def test_delete_non_expired_rejected(
        self, worm: GCSBucketLockWORM
    ) -> None:
        m = _meta(lock_until=date.today() - timedelta(days=10))
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="lifecycle"):
            worm.delete(m.id)

    def test_delete_expired_succeeds(
        self, worm: GCSBucketLockWORM
    ) -> None:
        past = date.today() - timedelta(days=5)
        m = _meta(
            lock_until=past,
            lifecycle_stage=RetentionLifecycleStage.EXPIRED,
        )
        worm.put(m.id, b"x", m)
        worm.delete(m.id)
        with pytest.raises(WORMBackendError, match="not found"):
            worm.get(m.id)


class TestExtendRetention:
    def test_extend_succeeds(self, worm: GCSBucketLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        new_until = date.today() + timedelta(days=730)
        new_meta = worm.extend_retention(m.id, new_until)
        assert new_meta.lock_until == new_until

    def test_extend_backward_rejected(
        self, worm: GCSBucketLockWORM
    ) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="shortening"):
            worm.extend_retention(m.id, date.today() + timedelta(days=10))


class TestLegalHold:
    def test_apply_and_release(self, worm: GCSBucketLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        held = worm.apply_legal_hold(m.id)
        assert held.legal_hold is True
        released = worm.release_legal_hold(m.id)
        assert released.legal_hold is False


class TestConstruction:
    def test_empty_bucket_name_rejected(self) -> None:
        with pytest.raises(WORMBackendError, match="non-empty"):
            GCSBucketLockWORM(
                bucket_name="",
                client_factory=lambda: _ClientStub(),
            )

    def test_repr_contains_bucket(
        self, worm: GCSBucketLockWORM
    ) -> None:
        assert "evidentia-worm" in repr(worm)


class TestPrefix:
    def test_prefix_isolates_records(self, client: _ClientStub) -> None:
        worm_a = GCSBucketLockWORM(
            bucket_name="x",
            prefix="tenant-a/",
            client_factory=lambda: client,
        )
        worm_b = GCSBucketLockWORM(
            bucket_name="x",
            prefix="tenant-b/",
            client_factory=lambda: client,
        )
        m = _meta()
        worm_a.put(m.id, b"tenant-a-data", m)
        with pytest.raises(WORMBackendError, match="not found"):
            worm_b.get(m.id)
        assert worm_a.get(m.id) == b"tenant-a-data"


def test_metadata_round_trip_matches_local_filesystem(
    worm: GCSBucketLockWORM,
) -> None:
    m = _meta(
        classification=RetentionClassification.MODEL_RISK,
        retention_period_days=2555,
        notes="SR 11-7 model documentation",
        record_pointer="model-inventory:risk/credit-default/v3",
    )
    worm.put(m.id, b"model-doc", m)
    loaded = worm.get_metadata(m.id)
    assert loaded.classification == m.classification
    assert loaded.retention_period_days == m.retention_period_days
    assert loaded.notes == m.notes
    assert loaded.record_pointer == m.record_pointer
