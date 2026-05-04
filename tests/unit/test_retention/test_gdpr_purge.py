"""GDPR Article 17 (right-to-erasure) purge flow tests (v0.7.12 P1).

Closes the v0.7.11 functional gap surfaced by the Step-4
/security-review: GDPR purpose-limited records
(``retention_period_days=0``, ``lock_until=None``) cannot
transition ACTIVE→EXPIRED via :func:`transition_lifecycle`
because the standard ``can_expire`` precondition requires
``lock_until is not None and today >= lock_until``.

The fix: ``transition_lifecycle(force_gdpr_purge=True)`` permits
the transition for GDPR-shaped records ONLY (legal_hold still
trumps; non-GDPR records still follow the standard path).

The operator-friendly entry point is
:meth:`WORMBackend.purge_immediately`, which runs the full purge
workflow (validation → lifecycle transition → backend delete →
audit-trail snapshot) atomically.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
    RetentionTransitionError,
    transition_lifecycle,
)
from evidentia_core.retention.worm import (
    LocalFilesystemWORM,
    WORMBackendError,
)


def _gdpr_meta(**overrides: object) -> RetentionMetadata:
    base: dict[str, object] = {
        "classification": RetentionClassification.GDPR,
        "retention_period_days": 0,
    }
    base.update(overrides)
    return RetentionMetadata.model_validate(base)


def _non_gdpr_meta(**overrides: object) -> RetentionMetadata:
    base: dict[str, object] = {
        "classification": RetentionClassification.SOX_404,
        "retention_period_days": 365,
    }
    base.update(overrides)
    return RetentionMetadata.model_validate(base)


# ── transition_lifecycle force_gdpr_purge override ─────────────────


class TestForceGdprPurgeTransition:
    def test_gdpr_record_active_to_expired_with_override(self) -> None:
        """v0.7.11 functional gap closure: GDPR purpose-limited
        record (lock_until=None) can transition ACTIVE→EXPIRED
        ONLY with force_gdpr_purge=True."""
        m = _gdpr_meta()
        assert m.lock_until is None  # GDPR invariant

        # Without override: rejected (standard can_expire fails)
        with pytest.raises(RetentionTransitionError):
            transition_lifecycle(m, RetentionLifecycleStage.EXPIRED)

        # With override: succeeds
        new_m = transition_lifecycle(
            m,
            RetentionLifecycleStage.EXPIRED,
            force_gdpr_purge=True,
        )
        assert new_m.lifecycle_stage == RetentionLifecycleStage.EXPIRED.value

    def test_non_gdpr_record_force_override_does_not_apply(self) -> None:
        """Override is scoped to GDPR-shaped records only. A non-
        GDPR record (retention_period_days > 0) still has to satisfy
        the standard retention-window precondition.
        """
        # Non-GDPR record still inside its lock window
        m = _non_gdpr_meta()  # lock_until = today + 365
        with pytest.raises(RetentionTransitionError):
            transition_lifecycle(
                m,
                RetentionLifecycleStage.EXPIRED,
                force_gdpr_purge=True,  # override should NOT apply
            )

    def test_legal_hold_trumps_force_override(self) -> None:
        """Legal hold blocks even GDPR purge — operator must
        release the hold first (per legal-counsel guidance for
        most legal frameworks)."""
        m = _gdpr_meta(legal_hold=True)
        with pytest.raises(RetentionTransitionError):
            transition_lifecycle(
                m,
                RetentionLifecycleStage.EXPIRED,
                force_gdpr_purge=True,
            )


# ── purge_immediately operator workflow (LocalFilesystemWORM) ──────


class TestPurgeImmediatelyLocal:
    @pytest.fixture
    def worm(self, tmp_path: Path) -> LocalFilesystemWORM:
        return LocalFilesystemWORM(root=tmp_path / "worm")

    def test_purge_succeeds_for_gdpr_record(
        self, worm: LocalFilesystemWORM
    ) -> None:
        m = _gdpr_meta()
        worm.put(m.id, b"gdpr-payload", m)

        snapshot = worm.purge_immediately(
            m.id,
            gdpr_request_ref="GDPR-REQ-2026-001",
            operator_id="alice@evidentia.dev",
        )
        # Returns the terminal PURGED snapshot for audit trail
        assert snapshot.lifecycle_stage == RetentionLifecycleStage.PURGED.value
        # Record is gone
        with pytest.raises(WORMBackendError, match="not found"):
            worm.get(m.id)

    def test_purge_rejected_for_non_gdpr_record(
        self, worm: LocalFilesystemWORM
    ) -> None:
        m = _non_gdpr_meta()
        worm.put(m.id, b"sox-payload", m)
        with pytest.raises(WORMBackendError, match="GDPR-only"):
            worm.purge_immediately(
                m.id,
                gdpr_request_ref="GDPR-REQ-2026-002",
                operator_id="alice",
            )

    def test_purge_rejected_under_legal_hold(
        self, worm: LocalFilesystemWORM
    ) -> None:
        m = _gdpr_meta(legal_hold=True)
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="legal hold"):
            worm.purge_immediately(
                m.id,
                gdpr_request_ref="GDPR-REQ-2026-003",
                operator_id="alice",
            )

    def test_purge_requires_gdpr_request_ref(
        self, worm: LocalFilesystemWORM
    ) -> None:
        m = _gdpr_meta()
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="gdpr_request_ref"):
            worm.purge_immediately(
                m.id, gdpr_request_ref="", operator_id="alice"
            )
        with pytest.raises(WORMBackendError, match="gdpr_request_ref"):
            worm.purge_immediately(
                m.id, gdpr_request_ref=None, operator_id="alice"  # type: ignore[arg-type]
            )

    def test_purge_requires_operator_id(
        self, worm: LocalFilesystemWORM
    ) -> None:
        m = _gdpr_meta()
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="operator_id"):
            worm.purge_immediately(
                m.id, gdpr_request_ref="X", operator_id=""
            )

    def test_purge_audit_trail_snapshot(
        self, worm: LocalFilesystemWORM
    ) -> None:
        """The returned snapshot serves as the audit-trail record.
        It should preserve the original record's ID + classification
        + GDPR-request-ref-able fields."""
        m = _gdpr_meta(notes="Deletion request from data subject")
        worm.put(m.id, b"x", m)
        snapshot = worm.purge_immediately(
            m.id,
            gdpr_request_ref="GDPR-REQ-2026-004",
            operator_id="alice@evidentia.dev",
        )
        assert snapshot.id == m.id
        assert snapshot.classification == RetentionClassification.GDPR.value
        assert snapshot.notes == m.notes
        assert snapshot.lifecycle_stage == RetentionLifecycleStage.PURGED.value

    def test_purge_emits_gdpr_audit_event(
        self, worm: LocalFilesystemWORM
    ) -> None:
        """v0.7.12 closure of Step-3 /security-review observation:
        every successful GDPR purge MUST emit a
        RETENTION_GDPR_PURGE audit event with operator + request-ref
        provenance.

        Patches the audit-log call to spy on its keyword arguments;
        verifies the event payload carries the canonical fields the
        threat-model.md v0.7.12 delta promises (record_id +
        gdpr_request_ref + operator_id + classification +
        retention_period_days).
        """
        from unittest.mock import MagicMock, patch

        m = _gdpr_meta(notes="Article 17 request")
        worm.put(m.id, b"gdpr-payload", m)

        captured_calls: list[dict[str, object]] = []

        def _spy_logger(_name: str) -> MagicMock:
            spy = MagicMock()

            def _capture_info(**kwargs: object) -> None:
                captured_calls.append(kwargs)

            spy.info = _capture_info
            return spy

        with patch(
            "evidentia_core.audit.get_logger",
            side_effect=_spy_logger,
        ):
            worm.purge_immediately(
                m.id,
                gdpr_request_ref="GDPR-REQ-2026-AUDIT",
                operator_id="alice@evidentia.dev",
            )

        from evidentia_core.audit import EventAction

        gdpr_events = [
            c for c in captured_calls
            if c.get("action") == EventAction.RETENTION_GDPR_PURGE
        ]
        assert len(gdpr_events) == 1, (
            f"Expected exactly one RETENTION_GDPR_PURGE event, "
            f"got {len(gdpr_events)}: {captured_calls}"
        )
        event = gdpr_events[0]
        assert "evidentia" in event
        evidentia_payload = event["evidentia"]
        assert isinstance(evidentia_payload, dict)
        assert evidentia_payload["record_id"] == m.id
        assert evidentia_payload["gdpr_request_ref"] == "GDPR-REQ-2026-AUDIT"
        assert evidentia_payload["operator_id"] == "alice@evidentia.dev"
        assert evidentia_payload["classification"] == "gdpr"
        assert evidentia_payload["retention_period_days"] == 0


# ── Cross-cloud parity (S3 + Azure + GCS) ──────────────────────────


class TestPurgeImmediatelyS3:
    """S3 backend follows the same purge_immediately contract."""

    def _setup(self) -> object:
        from typing import Any

        import boto3
        from evidentia_core.retention.worm_s3 import S3ObjectLockWORM
        from moto import mock_aws

        ctx = mock_aws()
        ctx.__enter__()
        client: Any = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(
            Bucket="evidentia-gdpr-test",
            ObjectLockEnabledForBucket=True,
        )
        worm = S3ObjectLockWORM(
            bucket_name="evidentia-gdpr-test",
            region="us-east-1",
            lock_mode="GOVERNANCE",
            client_factory=lambda: client,
        )
        return worm, ctx

    def test_purge_succeeds_for_gdpr(self) -> None:
        worm, ctx = self._setup()  # type: ignore[misc]
        try:
            m = _gdpr_meta()
            worm.put(m.id, b"gdpr-payload", m)  # type: ignore[attr-defined]
            snap = worm.purge_immediately(  # type: ignore[attr-defined]
                m.id,
                gdpr_request_ref="GDPR-S3-001",
                operator_id="alice",
            )
            assert snap.lifecycle_stage == RetentionLifecycleStage.PURGED.value
            with pytest.raises(WORMBackendError):
                worm.get(m.id)  # type: ignore[attr-defined]
        finally:
            ctx.__exit__(None, None, None)  # type: ignore[attr-defined]


# Note: Azure + GCS cross-cloud parity for GDPR purge is established
# implicitly via the contract: each backend's `_update_metadata`
# override + standard `delete` are exercised by the existing
# test_worm_azure.py + test_worm_gcs.py suites; the GDPR purge
# workflow (validate → transition → _update_metadata → delete) flows
# through the same CRUD paths. The TestForceGdprPurgeTransition +
# TestPurgeImmediatelyLocal + TestPurgeImmediatelyS3 classes above
# fully validate the contract semantics; replicating against Azure +
# GCS stubs adds no unique signal. The operator runbook in
# docs/gdpr-purge-flow.md documents the cross-cloud invocation.


# ── Edge case: lock_until is None safety ───────────────────────────


def test_is_locked_handles_gdpr_record() -> None:
    """is_locked() correctly returns False for GDPR records (no
    lock window). Required precondition for purge_immediately's
    delete step to succeed."""
    from evidentia_core.retention.metadata import is_locked

    m = _gdpr_meta()
    assert m.lock_until is None
    assert is_locked(m) is False
