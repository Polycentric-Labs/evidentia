"""GCS Bucket Lock-backed WORM implementation (v0.7.12 P0).

Concrete :class:`evidentia_core.retention.worm.WORMBackend` impl
that stores records in a Google Cloud Storage bucket with a
**locked retention policy**. Bucket Lock is GCS's WORM primitive —
once locked, the retention policy cannot be reduced or removed
even by the bucket owner; the storage service refuses
``DeleteBlob`` until the retention period expires.

GCS's retention model is bucket-WIDE rather than per-object, which
differs from S3 (per-object lock) and Azure (per-blob immutability
policy). The implication for this backend:

  - The operator pre-creates the bucket with a retention period
    >= the longest expected per-record lock_until. The bucket-side
    enforcement is a floor (no record can be deleted before the
    bucket policy permits, regardless of metadata).
  - Per-record lock_until is tracked in the sidecar metadata; the
    application-level delete check enforces the per-record value.
  - Per-object holds (``temporary_hold``, ``event_based_hold``)
    are GCS's mechanism for legal-hold semantics. We use
    ``temporary_hold`` for operator-controlled holds.

See ``docs/worm-backends.md`` for the operator setup runbook
(bucket retention period selection, lock_retention_policy, IAM).

Per-record layout matches S3 + Azure:

  - ``<bucket>/<prefix><record_id>.bin``      payload
  - ``<bucket>/<prefix><record_id>.meta.json`` metadata sidecar

Usage::

    from evidentia_core.retention.worm_gcs import GCSBucketLockWORM

    backend = GCSBucketLockWORM(
        bucket_name="evidentia-worm",
        # uses ADC by default (env, gcloud, GCE metadata)
    )
    backend.put(record_id="rec-1", payload=b"...", metadata=meta)

The ``google-cloud-storage`` dependency is gated behind the
``evidentia[worm-gcs]`` extra. Importing without it installed
raises a clear ``ImportError``.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from evidentia_core.retention.metadata import (
    RetentionLifecycleStage,
    RetentionMetadata,
    is_locked,
)
from evidentia_core.retention.worm import WORMBackend, WORMBackendError

try:
    from google.api_core.exceptions import (
        GoogleAPIError,
        NotFound,
    )
    from google.cloud import storage as gcs_storage
except ImportError as _exc:  # pragma: no cover — import-time gate
    raise ImportError(
        "GCSBucketLockWORM requires google-cloud-storage. Install "
        "with: pip install 'evidentia[worm-gcs]' (or "
        "'evidentia-core[worm-gcs]' for the library-only install)."
    ) from _exc


class GCSBucketLockWORM(WORMBackend):
    """Cloud-backed WORM via GCS Bucket Lock.

    Args:
        bucket_name: Pre-created bucket with bucket-wide retention
            policy already configured (and ideally locked).
        client: Optional pre-configured ``google.cloud.storage.Client``.
            When None, falls back to Application Default Credentials
            (env, gcloud, GCE metadata).
        prefix: Optional blob name prefix for multi-tenant
            isolation.
        client_factory: Optional callable returning a
            ``storage.Client`` instance. Useful for tests.

    Raises:
        WORMBackendError: when args are invalid OR the bucket
            cannot be reached.
    """

    def __init__(
        self,
        bucket_name: str,
        *,
        client: Any = None,
        prefix: str = "",
        client_factory: Any = None,
    ) -> None:
        if not bucket_name or not isinstance(bucket_name, str):
            raise WORMBackendError(
                "GCSBucketLockWORM requires a non-empty bucket_name"
            )
        self._bucket_name = bucket_name
        self._prefix = prefix
        if client_factory is not None:
            self._client = client_factory()
        elif client is not None:
            self._client = client
        else:
            self._client = gcs_storage.Client()
        try:
            self._bucket = self._client.bucket(bucket_name)
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS bucket {bucket_name!r} cannot be reached: {e}"
            ) from e

    # ── Key helpers ────────────────────────────────────────────────

    def _payload_key(self, record_id: str) -> str:
        return f"{self._prefix}{record_id}.bin"

    def _meta_key(self, record_id: str) -> str:
        return f"{self._prefix}{record_id}.meta.json"

    # ── WORMBackend contract ───────────────────────────────────────

    def put(
        self,
        record_id: str,
        payload: bytes,
        metadata: RetentionMetadata,
    ) -> None:
        payload_blob = self._bucket.blob(self._payload_key(record_id))
        if payload_blob.exists():
            raise WORMBackendError(
                f"GCS record {record_id!r} already exists in bucket "
                f"{self._bucket_name!r}; WORM forbids overwrite"
            )
        try:
            # if_generation_match=0 ensures atomic create (refuses
            # if blob exists at upload time — race-condition-safe)
            payload_blob.upload_from_string(
                payload, if_generation_match=0
            )
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS put failed for record {record_id!r}: {e}"
            ) from e

        # Apply per-object hold for legal-hold semantics. The
        # bucket's retention period is set at creation time; per-
        # record lock_until is tracked in the metadata sidecar.
        if metadata.legal_hold:
            try:
                payload_blob.temporary_hold = True
                payload_blob.patch()
            except GoogleAPIError as e:
                raise WORMBackendError(
                    f"GCS temporary_hold failed for record "
                    f"{record_id!r}: {e}"
                ) from e

        # Metadata sidecar
        meta_blob = self._bucket.blob(self._meta_key(record_id))
        try:
            meta_blob.upload_from_string(
                metadata.model_dump_json(indent=2),
                content_type="application/json",
            )
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS metadata put failed for record {record_id!r}: {e}"
            ) from e

    def get(self, record_id: str) -> bytes:
        blob = self._bucket.blob(self._payload_key(record_id))
        try:
            data = blob.download_as_bytes()
            return bytes(data)
        except NotFound as e:
            raise WORMBackendError(
                f"GCS record {record_id!r} not found in bucket "
                f"{self._bucket_name!r}"
            ) from e
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS get failed for record {record_id!r}: {e}"
            ) from e

    def get_metadata(self, record_id: str) -> RetentionMetadata:
        blob = self._bucket.blob(self._meta_key(record_id))
        try:
            raw = bytes(blob.download_as_bytes())
        except NotFound as e:
            raise WORMBackendError(
                f"GCS metadata for record {record_id!r} not found"
            ) from e
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS metadata get failed for record {record_id!r}: {e}"
            ) from e
        return RetentionMetadata.model_validate_json(raw.decode("utf-8"))

    def delete(self, record_id: str, today: date | None = None) -> None:
        metadata = self.get_metadata(record_id)
        if metadata.legal_hold:
            raise WORMBackendError(
                f"GCS record {record_id!r} is under legal hold; "
                f"cannot delete"
            )
        if is_locked(metadata, today=today):
            raise WORMBackendError(
                f"GCS record {record_id!r} is still inside its "
                f"retention window (lock_until={metadata.lock_until}); "
                f"cannot delete"
            )
        if metadata.lifecycle_stage != RetentionLifecycleStage.EXPIRED.value:
            raise WORMBackendError(
                f"GCS record {record_id!r} lifecycle is "
                f"{metadata.lifecycle_stage}; only EXPIRED records can "
                f"be deleted"
            )
        try:
            payload_blob = self._bucket.blob(self._payload_key(record_id))
            payload_blob.delete()
            meta_blob = self._bucket.blob(self._meta_key(record_id))
            meta_blob.delete()
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS delete failed for record {record_id!r}: {e}"
            ) from e

    def extend_retention(
        self, record_id: str, new_lock_until: date
    ) -> RetentionMetadata:
        from evidentia_core.models.common import utc_now

        metadata = self.get_metadata(record_id)
        if (
            metadata.lock_until is not None
            and new_lock_until < metadata.lock_until
        ):
            raise WORMBackendError(
                f"WORM forbids shortening retention: current lock_until="
                f"{metadata.lock_until}, attempted={new_lock_until}"
            )
        # GCS bucket-wide retention is set at bucket creation. Per-
        # record lock_until is tracked in the metadata sidecar; the
        # bucket-side enforcement is a FLOOR — it ensures no record
        # can be deleted before the bucket retention period elapses,
        # but the metadata-driven check ensures per-record extensions
        # are honored at the application layer.
        new_metadata = metadata.model_copy(
            update={
                "lock_until": new_lock_until,
                "updated_at": utc_now(),
            }
        )
        meta_blob = self._bucket.blob(self._meta_key(record_id))
        try:
            meta_blob.upload_from_string(
                new_metadata.model_dump_json(indent=2),
                content_type="application/json",
            )
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS metadata update failed for record {record_id!r}: {e}"
            ) from e
        return new_metadata

    def apply_legal_hold(self, record_id: str) -> RetentionMetadata:
        from evidentia_core.models.common import utc_now

        payload_blob = self._bucket.blob(self._payload_key(record_id))
        try:
            payload_blob.temporary_hold = True
            payload_blob.patch()
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS temporary_hold (apply) failed for record "
                f"{record_id!r}: {e}"
            ) from e
        metadata = self.get_metadata(record_id)
        new_metadata = metadata.model_copy(
            update={"legal_hold": True, "updated_at": utc_now()}
        )
        meta_blob = self._bucket.blob(self._meta_key(record_id))
        meta_blob.upload_from_string(
            new_metadata.model_dump_json(indent=2),
            content_type="application/json",
        )
        return new_metadata

    def release_legal_hold(self, record_id: str) -> RetentionMetadata:
        from evidentia_core.models.common import utc_now

        payload_blob = self._bucket.blob(self._payload_key(record_id))
        try:
            payload_blob.temporary_hold = False
            payload_blob.patch()
        except GoogleAPIError as e:
            raise WORMBackendError(
                f"GCS temporary_hold (release) failed for record "
                f"{record_id!r}: {e}"
            ) from e
        metadata = self.get_metadata(record_id)
        new_metadata = metadata.model_copy(
            update={"legal_hold": False, "updated_at": utc_now()}
        )
        meta_blob = self._bucket.blob(self._meta_key(record_id))
        meta_blob.upload_from_string(
            new_metadata.model_dump_json(indent=2),
            content_type="application/json",
        )
        return new_metadata

    def __repr__(self) -> str:
        return (
            f"GCSBucketLockWORM(bucket={self._bucket_name!r}, "
            f"prefix={self._prefix!r})"
        )
