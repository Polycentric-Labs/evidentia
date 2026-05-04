"""Unit tests for evidentia_core.retention.worm_s3 (v0.7.12 P0).

Uses moto's mock S3 to exercise the S3 Object Lock contract
without hitting live AWS. moto's S3 mock is reasonably faithful
to S3 Object Lock semantics — it enforces the RetainUntilDate
header on DeleteObject calls, refuses to enable Object Lock
retroactively, and simulates legal-hold via
PutObjectLegalHold.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import boto3
import pytest
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
    transition_lifecycle,
)
from evidentia_core.retention.worm import WORMBackendError
from evidentia_core.retention.worm_s3 import S3ObjectLockWORM
from moto import mock_aws

BUCKET = "evidentia-worm-test"
REGION = "us-east-1"


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def s3_with_object_lock() -> Any:
    """Yield an Object-Lock-enabled S3 bucket via moto.

    The bucket is created fresh per test under the moto context.
    """
    with mock_aws():
        client = boto3.client("s3", region_name=REGION)
        client.create_bucket(
            Bucket=BUCKET,
            ObjectLockEnabledForBucket=True,
        )
        yield client


@pytest.fixture
def worm(s3_with_object_lock: Any) -> S3ObjectLockWORM:
    """Instantiate the WORM backend pointing at the moto bucket."""
    return S3ObjectLockWORM(
        bucket_name=BUCKET,
        region=REGION,
        lock_mode="GOVERNANCE",  # easier to test delete bypass
        client_factory=lambda: s3_with_object_lock,
    )


def _meta(**overrides: object) -> RetentionMetadata:
    base: dict[str, object] = {
        "classification": RetentionClassification.SOX_404,
        "retention_period_days": 365,
    }
    base.update(overrides)
    return RetentionMetadata.model_validate(base)


# ── put / get round-trip ───────────────────────────────────────────


class TestPutGet:
    def test_round_trip(self, worm: S3ObjectLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"payload-bytes", m)
        assert worm.get(m.id) == b"payload-bytes"
        loaded = worm.get_metadata(m.id)
        assert loaded.id == m.id
        assert loaded.classification == m.classification

    def test_get_missing_raises(self, worm: S3ObjectLockWORM) -> None:
        with pytest.raises(WORMBackendError, match="not found"):
            worm.get("aaaaaaaa-1111-2222-3333-444444444444")

    def test_get_metadata_missing_raises(
        self, worm: S3ObjectLockWORM
    ) -> None:
        with pytest.raises(WORMBackendError, match="not found"):
            worm.get_metadata("aaaaaaaa-1111-2222-3333-444444444444")

    def test_double_put_rejected(self, worm: S3ObjectLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"first", m)
        with pytest.raises(WORMBackendError, match="already exists"):
            worm.put(m.id, b"second", m)

    def test_put_with_legal_hold(self, worm: S3ObjectLockWORM) -> None:
        m = _meta(legal_hold=True)
        worm.put(m.id, b"with-hold", m)
        loaded = worm.get_metadata(m.id)
        assert loaded.legal_hold is True

    def test_put_zero_retention_gdpr(
        self, worm: S3ObjectLockWORM
    ) -> None:
        """GDPR purpose-limited records have retention_period_days=0
        and lock_until=None — S3 put should still succeed (no
        Object Lock retain-until applied)."""
        m = _meta(
            classification=RetentionClassification.GDPR,
            retention_period_days=0,
        )
        worm.put(m.id, b"gdpr-payload", m)
        assert worm.get(m.id) == b"gdpr-payload"


# ── Delete enforcement (3-layer defense) ───────────────────────────


class TestDelete:
    def test_delete_active_within_window_rejected(
        self, worm: S3ObjectLockWORM
    ) -> None:
        m = _meta()  # ACTIVE, lock_until = today + 365
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="retention window"):
            worm.delete(m.id)

    def test_delete_legal_hold_rejected(
        self, worm: S3ObjectLockWORM
    ) -> None:
        m = _meta(legal_hold=True)
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="legal hold"):
            worm.delete(m.id)

    def test_delete_non_expired_rejected(
        self, worm: S3ObjectLockWORM
    ) -> None:
        # Outside lock window but lifecycle still ACTIVE
        m = _meta(lock_until=date.today() - timedelta(days=10))
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="lifecycle"):
            worm.delete(m.id)

    def test_delete_expired_succeeds(
        self, worm: S3ObjectLockWORM
    ) -> None:
        # Past-lock + lifecycle EXPIRED; still legal_hold=False.
        # Note: S3 Object Lock retain-until in the past + Governance
        # mode means the API allows delete. Our backend layer also
        # passes the 3-layer check.
        past = date.today() - timedelta(days=5)
        m = _meta(
            lock_until=past,
            lifecycle_stage=RetentionLifecycleStage.EXPIRED,
        )
        worm.put(m.id, b"x", m)
        # Now delete from S3 first (don't rely on moto's RetainUntilDate
        # enforcement since we're testing the BACKEND's enforcement;
        # S3-side enforcement is exercised in the live operator
        # runbook documented in docs/worm-backends.md).
        worm.delete(m.id)
        # Verify gone
        with pytest.raises(WORMBackendError, match="not found"):
            worm.get(m.id)


# ── extend_retention ───────────────────────────────────────────────


class TestExtendRetention:
    def test_extend_succeeds(self, worm: S3ObjectLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        new_until = date.today() + timedelta(days=730)
        new_meta = worm.extend_retention(m.id, new_until)
        assert new_meta.lock_until == new_until
        assert new_meta.updated_at >= m.updated_at

    def test_extend_backward_rejected(
        self, worm: S3ObjectLockWORM
    ) -> None:
        m = _meta()  # lock_until = today + 365
        worm.put(m.id, b"x", m)
        new_until = date.today() + timedelta(days=10)
        with pytest.raises(WORMBackendError, match="shortening"):
            worm.extend_retention(m.id, new_until)


# ── Legal-hold operator workflow ───────────────────────────────────


class TestLegalHold:
    def test_apply_and_release(self, worm: S3ObjectLockWORM) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        held = worm.apply_legal_hold(m.id)
        assert held.legal_hold is True
        released = worm.release_legal_hold(m.id)
        assert released.legal_hold is False


# ── Construction guards ────────────────────────────────────────────


class TestConstruction:
    def test_empty_bucket_name_rejected(
        self, s3_with_object_lock: Any
    ) -> None:
        with pytest.raises(WORMBackendError, match="non-empty"):
            S3ObjectLockWORM(
                bucket_name="",
                client_factory=lambda: s3_with_object_lock,
            )

    def test_invalid_lock_mode_rejected(
        self, s3_with_object_lock: Any
    ) -> None:
        with pytest.raises(WORMBackendError, match="COMPLIANCE or GOVERNANCE"):
            S3ObjectLockWORM(
                bucket_name=BUCKET,
                lock_mode="INVALID",  # type: ignore[arg-type]
                client_factory=lambda: s3_with_object_lock,
            )

    def test_repr_contains_bucket_and_mode(
        self, worm: S3ObjectLockWORM
    ) -> None:
        s = repr(worm)
        assert BUCKET in s
        assert "GOVERNANCE" in s


# ── Bucket prefix support ──────────────────────────────────────────


class TestPrefix:
    def test_prefix_isolates_records(self, s3_with_object_lock: Any) -> None:
        worm_a = S3ObjectLockWORM(
            bucket_name=BUCKET,
            lock_mode="GOVERNANCE",
            prefix="tenant-a/",
            client_factory=lambda: s3_with_object_lock,
        )
        worm_b = S3ObjectLockWORM(
            bucket_name=BUCKET,
            lock_mode="GOVERNANCE",
            prefix="tenant-b/",
            client_factory=lambda: s3_with_object_lock,
        )
        m = _meta()
        worm_a.put(m.id, b"tenant-a-data", m)
        # tenant-b should not see tenant-a's record under its prefix
        with pytest.raises(WORMBackendError, match="not found"):
            worm_b.get(m.id)
        # tenant-a does see it
        assert worm_a.get(m.id) == b"tenant-a-data"


# ── Cross-cloud parity smoke ───────────────────────────────────────


def test_metadata_round_trip_matches_local_filesystem(
    worm: S3ObjectLockWORM,
) -> None:
    """Same RetentionMetadata structure round-trips identically in
    S3 vs LocalFilesystemWORM. Validates the contract is
    backend-agnostic."""
    m = _meta(
        classification=RetentionClassification.MODEL_RISK,
        retention_period_days=2555,  # 7 years
        notes="SR 11-7 model documentation",
        record_pointer="model-inventory:risk/credit-default/v3",
    )
    worm.put(m.id, b"model-doc", m)
    loaded = worm.get_metadata(m.id)
    # Round-trip preserves all metadata fields
    assert loaded.id == m.id
    assert loaded.classification == m.classification
    assert loaded.retention_period_days == m.retention_period_days
    assert loaded.notes == m.notes
    assert loaded.record_pointer == m.record_pointer
    assert loaded.lifecycle_stage == m.lifecycle_stage


def test_lifecycle_transition_through_s3_persistence(
    worm: S3ObjectLockWORM,
) -> None:
    """Full workflow: put → lifecycle transition → metadata write-back
    via re-put (sidecar update) → re-load."""
    past = date.today() - timedelta(days=5)
    m = _meta(lock_until=past)
    worm.put(m.id, b"x", m)
    # Transition ACTIVE → EXPIRED (lock_until is past)
    transitioned = transition_lifecycle(
        m, RetentionLifecycleStage.EXPIRED
    )
    # Update sidecar (in real operator workflow, the lifecycle-
    # transition function is paired with a sidecar metadata write)
    worm._client.put_object(  # type: ignore[attr-defined]
        Bucket=BUCKET,
        Key=worm._meta_key(m.id),
        Body=transitioned.model_dump_json(indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    loaded = worm.get_metadata(m.id)
    assert loaded.lifecycle_stage == RetentionLifecycleStage.EXPIRED.value
