"""WORM (Write-Once-Read-Many) backend abstraction (v0.7.11 P0).

Defines the contract that concrete WORM-storage backends (S3
Object Lock, Azure Immutable Blob Storage, GCS Bucket Lock)
implement. Concrete cloud implementations land in v0.7.12 with
their respective extras (`evidentia[worm-s3]` /
`evidentia[worm-azure]` / `evidentia[worm-gcs]`).

This file ships the abstract base class + a reference local-
filesystem implementation suitable for development + testing.
The local-filesystem implementation does NOT enforce hardware-
level WORM semantics — it only enforces them via the metadata
+ application-level checks. Real cloud-backed WORM semantics
(S3 Object Lock retention modes, Azure Immutable Blob policies,
GCS bucket retention locks) are required for regulator-grade
chain-of-custody.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from datetime import date
from pathlib import Path

from evidentia_core.retention.metadata import (
    RetentionMetadata,
    is_locked,
)
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)


class WORMBackendError(RuntimeError):
    """Raised when a WORM-backend operation violates the WORM contract."""


class WORMBackend(ABC):
    """Abstract base for Write-Once-Read-Many storage backends.

    Concrete subclasses (in v0.7.12: ``S3ObjectLockWORM``,
    ``AzureImmutableBlobWORM``, ``GCSBucketLockWORM``) provide the
    cloud-side enforcement. The contract:

      - :meth:`put` writes a record + retention metadata. Once
        stored, the record is immutable until ``lock_until``.
      - :meth:`get` reads the record by ID.
      - :meth:`get_metadata` returns the retention metadata.
      - :meth:`delete` is allowed ONLY if the retention metadata
        indicates the record is purgeable (lifecycle EXPIRED + not
        under legal hold). On any violation, raises
        :class:`WORMBackendError`.
      - :meth:`extend_retention` extends ``lock_until`` (operator
        deliberately holds the record longer; legal-hold pattern).
        Cannot SHORTEN retention — that would violate WORM.

    All subclasses MUST raise :class:`WORMBackendError` on any
    contract violation rather than silently accepting non-WORM
    operations.
    """

    @abstractmethod
    def put(
        self,
        record_id: str,
        payload: bytes,
        metadata: RetentionMetadata,
    ) -> None:
        """Write a new record + its retention metadata."""
        ...

    @abstractmethod
    def get(self, record_id: str) -> bytes:
        """Read a record by ID. Raises if missing."""
        ...

    @abstractmethod
    def get_metadata(self, record_id: str) -> RetentionMetadata:
        """Read a record's retention metadata."""
        ...

    @abstractmethod
    def delete(self, record_id: str, today: date | None = None) -> None:
        """Delete a record IF retention permits.

        Raises :class:`WORMBackendError` when:
          - The record is still inside its lock window
          - The record is under legal hold
          - The record's lifecycle stage is not EXPIRED
        """
        ...

    @abstractmethod
    def extend_retention(
        self, record_id: str, new_lock_until: date
    ) -> RetentionMetadata:
        """Extend the lock-until date (cannot shorten).

        Raises :class:`WORMBackendError` if ``new_lock_until`` is
        earlier than the current ``lock_until``.
        """
        ...

    def purge_immediately(
        self,
        record_id: str,
        *,
        gdpr_request_ref: str,
        operator_id: str,
    ) -> RetentionMetadata:
        """GDPR Article 17 (right-to-erasure) immediate purge.

        Permits delete bypassing the standard retention checks,
        but ONLY when the underlying record's
        ``retention_period_days == 0`` (the Pydantic invariant for
        GDPR purpose-limited records). Closes the v0.7.11
        functional gap where GDPR records could not transition
        ACTIVE→EXPIRED via :func:`transition_lifecycle` because
        ``lock_until`` was None.

        The pre-conditions:

          1. ``metadata.retention_period_days == 0`` — operator
             cannot use this path to purge non-GDPR records
             (which must follow the retention-window path)
          2. ``metadata.legal_hold`` is False — legal hold trumps
             GDPR per most legal frameworks (the operator must
             release the legal hold first if a GDPR request
             arrives during litigation hold)
          3. ``operator_id`` and ``gdpr_request_ref`` are
             populated — for audit-trail provenance

        The default impl raises :class:`WORMBackendError` for
        any precondition violation, then delegates to
        :meth:`delete` after transitioning the record's
        lifecycle to EXPIRED via the
        ``force_gdpr_purge=True`` path. Concrete subclasses MAY
        override to add cloud-specific Governance-mode bypass
        logic.

        Args:
            record_id: Record to purge.
            gdpr_request_ref: Free-text reference to the GDPR
                request (ticket ID, email subject, regulator
                inquiry ID). Persisted to the audit trail.
            operator_id: Identity of the operator authorizing
                the purge. Persisted to the audit trail.

        Returns:
            The terminal RetentionMetadata snapshot (lifecycle
            PURGED) for audit-trail purposes — the actual
            record bytes are deleted.

        Raises:
            WORMBackendError: when any precondition fails OR the
                cloud-side delete is rejected.
        """
        from evidentia_core.models.common import utc_now
        from evidentia_core.retention.metadata import (
            RetentionLifecycleStage,
        )

        if not gdpr_request_ref or not isinstance(gdpr_request_ref, str):
            raise WORMBackendError(
                "purge_immediately requires a non-empty gdpr_request_ref"
            )
        if not operator_id or not isinstance(operator_id, str):
            raise WORMBackendError(
                "purge_immediately requires a non-empty operator_id"
            )

        metadata = self.get_metadata(record_id)
        if metadata.retention_period_days != 0:
            raise WORMBackendError(
                f"purge_immediately is GDPR-only (Article 17): record "
                f"{record_id!r} has retention_period_days="
                f"{metadata.retention_period_days}, must be 0 for "
                f"GDPR purpose-limited records. Use the standard "
                f"retention-window path for non-GDPR records."
            )
        if metadata.legal_hold:
            raise WORMBackendError(
                f"purge_immediately rejected: record {record_id!r} is "
                f"under legal hold. Legal hold trumps GDPR — release "
                f"the hold first (if appropriate per legal counsel)."
            )

        # Force-transition to EXPIRED via the gdpr override (audit
        # trail of the lifecycle change), then transition to PURGED,
        # then delegate to delete() which will respect the EXPIRED
        # state. The metadata snapshot returned reflects PURGED.
        from evidentia_core.retention.metadata import transition_lifecycle

        expired_metadata = transition_lifecycle(
            metadata,
            RetentionLifecycleStage.EXPIRED,
            force_gdpr_purge=True,
        )
        # Persist the EXPIRED state to the sidecar so delete() will
        # accept it. Subclasses store metadata differently (file
        # sidecar, S3 object, Azure blob, GCS blob) — re-put via the
        # same path the original put used.
        self._update_metadata(record_id, expired_metadata)
        # Now delete (lifecycle is EXPIRED, no legal hold, lock_until
        # is None so is_locked() returns False)
        self.delete(record_id)
        # v0.7.12 P1 closure of Step-3 /security-review observation:
        # emit the canonical RETENTION_GDPR_PURGE audit event so the
        # audit log carries non-repudiable provenance for every
        # Article 17 purge. Without this, the threat-model claim that
        # "every put / delete / extend_retention / legal_hold
        # operation flows through the audit logger" is incomplete —
        # GDPR purges are the most legally-consequential operation
        # in the retention contract and MUST hit the audit trail.
        # Emitted AFTER delete completes so the event is only logged
        # on successful purge (failures surface as WORMBackendError
        # without an audit-trail false-positive).
        try:
            from evidentia_core.audit import (
                EventAction,
                EventOutcome,
                get_logger,
            )

            _audit_log = get_logger("evidentia.retention.gdpr_purge")
            _audit_log.info(
                action=EventAction.RETENTION_GDPR_PURGE,
                outcome=EventOutcome.SUCCESS,
                message=(
                    f"GDPR Article 17 purge completed for record "
                    f"{record_id!r}"
                ),
                evidentia={
                    "record_id": record_id,
                    "gdpr_request_ref": gdpr_request_ref,
                    "operator_id": operator_id,
                    "classification": metadata.classification,
                    "retention_period_days": metadata.retention_period_days,
                },
            )
        except Exception:  # pragma: no cover — audit must not break purge
            # If the audit logger itself fails, the record is already
            # purged from storage; do NOT raise (the purge succeeded).
            # The returned snapshot still serves as the
            # caller-visible audit trail.
            pass
        # Return a "PURGED" terminal snapshot for audit-trail
        # callers. The underlying record is gone; this object exists
        # only as a return value capturing the final state.
        return expired_metadata.model_copy(
            update={
                "lifecycle_stage": RetentionLifecycleStage.PURGED.value,
                "updated_at": utc_now(),
            }
        )

    def _update_metadata(
        self, record_id: str, new_metadata: RetentionMetadata
    ) -> None:
        """Persist a fresh metadata snapshot to the backend.

        Default implementation expects subclasses to override OR
        to compose their existing extend_retention / put paths.
        Subclasses with sidecar metadata (LocalFilesystemWORM,
        S3, Azure, GCS) override this with a backend-specific
        rewrite that does NOT touch the payload.
        """
        raise NotImplementedError(
            "_update_metadata must be overridden by concrete "
            "WORMBackend subclasses to support purge_immediately."
        )


class LocalFilesystemWORM(WORMBackend):
    """Reference local-filesystem WORM implementation.

    Stores records as ``<root>/<record_id>.bin`` with a sibling
    ``<record_id>.meta.json`` for retention metadata. Enforces
    WORM semantics via application-level checks against the
    metadata; the underlying filesystem provides NO hardware-level
    WORM guarantee. Suitable for development + testing; for
    regulator-grade chain-of-custody, operators must use a
    cloud-backed WORM backend (S3 Object Lock / Azure Immutable
    Blob / GCS Bucket Lock).

    Use:
      ```
      backend = LocalFilesystemWORM(root="/var/evidentia/worm")
      backend.put(record_id, payload, metadata)
      ```
    """

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root).expanduser().resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def _record_path(self, record_id: str) -> tuple[Path, Path]:
        """Return ``(payload_path, meta_path)`` validated within root."""
        candidate_payload = self._root / f"{record_id}.bin"
        candidate_meta = self._root / f"{record_id}.meta.json"
        try:
            payload_path = validate_within(candidate_payload, self._root)
            meta_path = validate_within(candidate_meta, self._root)
        except PathTraversalError as e:
            raise WORMBackendError(
                f"record_id {record_id!r} would escape store root"
            ) from e
        return payload_path, meta_path

    def put(
        self,
        record_id: str,
        payload: bytes,
        metadata: RetentionMetadata,
    ) -> None:
        payload_path, meta_path = self._record_path(record_id)
        if payload_path.exists():
            raise WORMBackendError(
                f"record {record_id!r} already exists; WORM forbids overwrite"
            )
        # Atomic write of payload + metadata
        tmp_payload = payload_path.with_suffix(".bin.tmp")
        tmp_payload.write_bytes(payload)
        tmp_meta = meta_path.with_suffix(".meta.tmp")
        tmp_meta.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
        # os.replace is atomic on both POSIX and Windows
        os.replace(tmp_payload, payload_path)
        os.replace(tmp_meta, meta_path)

    def get(self, record_id: str) -> bytes:
        payload_path, _ = self._record_path(record_id)
        if not payload_path.exists():
            raise WORMBackendError(f"record {record_id!r} not found")
        return payload_path.read_bytes()

    def get_metadata(self, record_id: str) -> RetentionMetadata:
        _, meta_path = self._record_path(record_id)
        if not meta_path.exists():
            raise WORMBackendError(
                f"metadata for record {record_id!r} not found"
            )
        return RetentionMetadata.model_validate_json(
            meta_path.read_text(encoding="utf-8")
        )

    def delete(self, record_id: str, today: date | None = None) -> None:
        from evidentia_core.retention.metadata import RetentionLifecycleStage

        payload_path, meta_path = self._record_path(record_id)
        if not payload_path.exists() or not meta_path.exists():
            raise WORMBackendError(f"record {record_id!r} not found")
        metadata = self.get_metadata(record_id)
        if metadata.legal_hold:
            raise WORMBackendError(
                f"record {record_id!r} is under legal hold; cannot delete"
            )
        if is_locked(metadata, today=today):
            raise WORMBackendError(
                f"record {record_id!r} is still inside its retention "
                f"window (lock_until={metadata.lock_until}); cannot delete"
            )
        if metadata.lifecycle_stage != RetentionLifecycleStage.EXPIRED.value:
            raise WORMBackendError(
                f"record {record_id!r} lifecycle is "
                f"{metadata.lifecycle_stage}; only EXPIRED records can "
                f"be deleted"
            )
        payload_path.unlink()
        meta_path.unlink()

    def extend_retention(
        self, record_id: str, new_lock_until: date
    ) -> RetentionMetadata:
        metadata = self.get_metadata(record_id)
        if metadata.lock_until is not None and new_lock_until < metadata.lock_until:
            raise WORMBackendError(
                f"WORM forbids shortening retention: current lock_until="
                f"{metadata.lock_until}, attempted={new_lock_until}"
            )
        from evidentia_core.models.common import utc_now

        new_metadata = metadata.model_copy(
            update={
                "lock_until": new_lock_until,
                "updated_at": utc_now(),
            }
        )
        _, meta_path = self._record_path(record_id)
        # Overwriting metadata is permitted (it's tracking only, not
        # the underlying record). Atomic write.
        tmp = meta_path.with_suffix(".meta.tmp")
        tmp.write_text(
            new_metadata.model_dump_json(indent=2), encoding="utf-8"
        )
        os.replace(tmp, meta_path)
        return new_metadata

    def _update_metadata(
        self, record_id: str, new_metadata: RetentionMetadata
    ) -> None:
        """Atomic sidecar metadata rewrite (does NOT touch payload)."""
        _, meta_path = self._record_path(record_id)
        if not meta_path.exists():
            raise WORMBackendError(
                f"metadata for record {record_id!r} not found"
            )
        tmp = meta_path.with_suffix(".meta.tmp")
        tmp.write_text(
            new_metadata.model_dump_json(indent=2), encoding="utf-8"
        )
        os.replace(tmp, meta_path)

    def root(self) -> Path:
        """Return the resolved root directory (for inspection / tests)."""
        return self._root

    def __repr__(self) -> str:
        return f"LocalFilesystemWORM(root={self._root!r})"
