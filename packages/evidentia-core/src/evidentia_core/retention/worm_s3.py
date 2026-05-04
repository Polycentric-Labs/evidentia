"""S3 Object Lock-backed WORM implementation (v0.7.12 P0).

Concrete :class:`evidentia_core.retention.worm.WORMBackend` impl
that stores records in an S3 bucket configured with **Object Lock**
in either Compliance or Governance mode. Object Lock is the
canonical AWS primitive for regulator-grade WORM enforcement —
once a payload is uploaded with a ``RetainUntilDate`` header, the
S3 service refuses ``DeleteObject`` requests until the date
passes (Compliance mode: even root cannot bypass; Governance
mode: holders of the ``s3:BypassGovernanceRetention`` permission
can override, useful for operator-led GDPR purge).

The bucket MUST be created with Object Lock enabled at creation
time — it cannot be added retroactively. See
``docs/worm-backends.md`` for the operator setup runbook.

Per-record layout:

  - ``<bucket>/<prefix><record_id>.bin``      payload (Object Locked)
  - ``<bucket>/<prefix><record_id>.meta.json`` metadata sidecar (NOT
    locked, so we can update it on retention extensions / lifecycle
    transitions / legal-hold toggles without violating WORM)

The split is the same pattern as :class:`LocalFilesystemWORM`: the
*payload* is the regulator-protected artifact; the *metadata* is
operator-managed lifecycle tracking.

Usage::

    from evidentia_core.retention.worm_s3 import S3ObjectLockWORM

    backend = S3ObjectLockWORM(
        bucket_name="my-evidentia-worm",
        region="us-east-1",
        lock_mode="COMPLIANCE",
    )
    backend.put(record_id="rec-1", payload=b"...", metadata=meta)
    assert backend.get("rec-1") == b"..."

The ``boto3`` dependency is gated behind the
``evidentia[worm-s3]`` extra (or ``evidentia-core[worm-s3]``).
Importing this module without ``boto3`` installed raises a clear
``ImportError`` directing the operator to install the extra.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from typing import TYPE_CHECKING, Any

from evidentia_core.retention.metadata import (
    RetentionLifecycleStage,
    RetentionMetadata,
    is_locked,
)
from evidentia_core.retention.worm import WORMBackend, WORMBackendError

if TYPE_CHECKING:
    pass

try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError as _exc:  # pragma: no cover — import-time gate
    raise ImportError(
        "S3ObjectLockWORM requires the boto3 dependency. Install "
        "with: pip install 'evidentia[worm-s3]' (or "
        "'evidentia-core[worm-s3]' for the library-only install)."
    ) from _exc


# S3 Object Lock retention modes per the S3 API.
S3LockMode = str  # Literal["COMPLIANCE", "GOVERNANCE"]
DEFAULT_LOCK_MODE: S3LockMode = "COMPLIANCE"


class S3ObjectLockWORM(WORMBackend):
    """Cloud-backed WORM via AWS S3 Object Lock.

    Args:
        bucket_name: Name of the pre-configured S3 bucket. The
            bucket MUST have Object Lock enabled at creation
            time; this class will not enable it retroactively.
        region: AWS region. Defaults to the boto3 default chain
            (``AWS_REGION`` env var or ``~/.aws/config``).
        lock_mode: ``"COMPLIANCE"`` (root-cannot-bypass) or
            ``"GOVERNANCE"`` (operator-with-permission bypass for
            GDPR purge). Defaults to Compliance.
        prefix: Optional bucket key prefix (e.g.
            ``"evidentia/v1/"``). Defaults to no prefix.
        client_factory: Optional callable returning a
            ``boto3.client('s3')`` instance. When None, the
            class constructs a default client. Useful for tests
            (substitute a moto-mocked client).

    Raises:
        WORMBackendError: when boto3 fails to initialize the
            client OR the bucket cannot be reached.
    """

    def __init__(
        self,
        bucket_name: str,
        *,
        region: str | None = None,
        lock_mode: S3LockMode = DEFAULT_LOCK_MODE,
        prefix: str = "",
        client_factory: Any = None,
    ) -> None:
        if not bucket_name or not isinstance(bucket_name, str):
            raise WORMBackendError(
                "S3ObjectLockWORM requires a non-empty bucket_name"
            )
        if lock_mode not in ("COMPLIANCE", "GOVERNANCE"):
            raise WORMBackendError(
                f"S3 lock_mode must be COMPLIANCE or GOVERNANCE, got "
                f"{lock_mode!r}"
            )
        self._bucket = bucket_name
        self._lock_mode = lock_mode
        self._prefix = prefix
        if client_factory is not None:
            self._client = client_factory()
        else:
            self._client = boto3.client("s3", region_name=region)

    # ── Key helpers ────────────────────────────────────────────────

    def _payload_key(self, record_id: str) -> str:
        return f"{self._prefix}{record_id}.bin"

    def _meta_key(self, record_id: str) -> str:
        return f"{self._prefix}{record_id}.meta.json"

    def _object_exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
            return True
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def _retain_until_datetime(
        self, metadata: RetentionMetadata
    ) -> datetime | None:
        """Convert the metadata.lock_until ``date`` to a UTC
        ``datetime`` for the S3 RetainUntilDate header. Returns None
        when retention is purpose-limited (GDPR with
        ``retention_period_days=0``)."""
        if metadata.lock_until is None:
            return None
        # Normalize to start-of-day UTC; S3 needs a tz-aware datetime
        return datetime.combine(
            metadata.lock_until,
            datetime.min.time(),
            tzinfo=UTC,
        )

    # ── WORMBackend contract ───────────────────────────────────────

    def put(
        self,
        record_id: str,
        payload: bytes,
        metadata: RetentionMetadata,
    ) -> None:
        payload_key = self._payload_key(record_id)
        if self._object_exists(payload_key):
            raise WORMBackendError(
                f"S3 record {record_id!r} already exists in bucket "
                f"{self._bucket!r}; WORM forbids overwrite"
            )

        retain_until = self._retain_until_datetime(metadata)
        put_kwargs: dict[str, Any] = {
            "Bucket": self._bucket,
            "Key": payload_key,
            "Body": payload,
            "ObjectLockLegalHoldStatus": "ON" if metadata.legal_hold else "OFF",
        }
        if retain_until is not None:
            put_kwargs["ObjectLockMode"] = self._lock_mode
            put_kwargs["ObjectLockRetainUntilDate"] = retain_until
        try:
            self._client.put_object(**put_kwargs)
        except ClientError as e:
            raise WORMBackendError(
                f"S3 put failed for record {record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e

        # Metadata sidecar — NOT under Object Lock (so we can
        # update on retention extension / lifecycle transition).
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=self._meta_key(record_id),
                Body=metadata.model_dump_json(indent=2).encode("utf-8"),
                ContentType="application/json",
            )
        except ClientError as e:
            raise WORMBackendError(
                f"S3 metadata put failed for record {record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e

    def get(self, record_id: str) -> bytes:
        try:
            resp = self._client.get_object(
                Bucket=self._bucket, Key=self._payload_key(record_id)
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404"):
                raise WORMBackendError(
                    f"S3 record {record_id!r} not found in bucket "
                    f"{self._bucket!r}"
                ) from e
            raise WORMBackendError(
                f"S3 get failed for record {record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e
        body = resp["Body"]
        return bytes(body.read())

    def get_metadata(self, record_id: str) -> RetentionMetadata:
        try:
            resp = self._client.get_object(
                Bucket=self._bucket, Key=self._meta_key(record_id)
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("NoSuchKey", "404"):
                raise WORMBackendError(
                    f"S3 metadata for record {record_id!r} not found"
                ) from e
            raise WORMBackendError(
                f"S3 metadata get failed for record {record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e
        raw_body = bytes(resp["Body"].read())
        return RetentionMetadata.model_validate_json(raw_body.decode("utf-8"))

    def delete(self, record_id: str, today: date | None = None) -> None:
        # Application-level 3-layer defense (mirrors
        # LocalFilesystemWORM). S3 also enforces at the API level
        # via Object Lock — if the application check passes but
        # S3 still rejects (e.g., RetainUntilDate not yet reached
        # because of clock skew), we surface the S3 error.
        metadata = self.get_metadata(record_id)
        if metadata.legal_hold:
            raise WORMBackendError(
                f"S3 record {record_id!r} is under legal hold; cannot delete"
            )
        if is_locked(metadata, today=today):
            raise WORMBackendError(
                f"S3 record {record_id!r} is still inside its retention "
                f"window (lock_until={metadata.lock_until}); cannot delete"
            )
        if metadata.lifecycle_stage != RetentionLifecycleStage.EXPIRED.value:
            raise WORMBackendError(
                f"S3 record {record_id!r} lifecycle is "
                f"{metadata.lifecycle_stage}; only EXPIRED records can "
                f"be deleted"
            )

        # S3 API delete. With Compliance mode + retention not yet
        # expired, S3 will refuse with a 403. We surface that as
        # WORMBackendError preserving the original S3 message.
        try:
            self._client.delete_object(
                Bucket=self._bucket, Key=self._payload_key(record_id)
            )
            self._client.delete_object(
                Bucket=self._bucket, Key=self._meta_key(record_id)
            )
        except ClientError as e:
            raise WORMBackendError(
                f"S3 delete failed for record {record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
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

        # Update the S3-side Object Lock retention via
        # put_object_retention. This is allowed under both
        # Compliance and Governance modes for EXTENSIONS only.
        new_retain_dt = datetime.combine(
            new_lock_until,
            datetime.min.time(),
            tzinfo=UTC,
        )
        try:
            self._client.put_object_retention(
                Bucket=self._bucket,
                Key=self._payload_key(record_id),
                Retention={
                    "Mode": self._lock_mode,
                    "RetainUntilDate": new_retain_dt,
                },
            )
        except ClientError as e:
            raise WORMBackendError(
                f"S3 put_object_retention failed for record "
                f"{record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e

        # Update sidecar metadata
        new_metadata = metadata.model_copy(
            update={
                "lock_until": new_lock_until,
                "updated_at": utc_now(),
            }
        )
        try:
            self._client.put_object(
                Bucket=self._bucket,
                Key=self._meta_key(record_id),
                Body=new_metadata.model_dump_json(indent=2).encode("utf-8"),
                ContentType="application/json",
            )
        except ClientError as e:
            raise WORMBackendError(
                f"S3 metadata update failed for record {record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e
        return new_metadata

    def apply_legal_hold(self, record_id: str) -> RetentionMetadata:
        """Apply S3 legal-hold AND update sidecar metadata.

        Legal hold blocks deletion regardless of retention mode,
        even in Governance mode bypass paths. Operator workflow
        for litigation hold / regulatory inquiry.
        """
        from evidentia_core.models.common import utc_now

        try:
            self._client.put_object_legal_hold(
                Bucket=self._bucket,
                Key=self._payload_key(record_id),
                LegalHold={"Status": "ON"},
            )
        except ClientError as e:
            raise WORMBackendError(
                f"S3 put_object_legal_hold failed for record "
                f"{record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e
        metadata = self.get_metadata(record_id)
        new_metadata = metadata.model_copy(
            update={"legal_hold": True, "updated_at": utc_now()}
        )
        self._client.put_object(
            Bucket=self._bucket,
            Key=self._meta_key(record_id),
            Body=new_metadata.model_dump_json(indent=2).encode("utf-8"),
            ContentType="application/json",
        )
        return new_metadata

    def release_legal_hold(self, record_id: str) -> RetentionMetadata:
        """Release S3 legal-hold AND update sidecar metadata."""
        from evidentia_core.models.common import utc_now

        try:
            self._client.put_object_legal_hold(
                Bucket=self._bucket,
                Key=self._payload_key(record_id),
                LegalHold={"Status": "OFF"},
            )
        except ClientError as e:
            raise WORMBackendError(
                f"S3 release_legal_hold failed for record "
                f"{record_id!r}: "
                f"{e.response.get('Error', {}).get('Message', str(e))}"
            ) from e
        metadata = self.get_metadata(record_id)
        new_metadata = metadata.model_copy(
            update={"legal_hold": False, "updated_at": utc_now()}
        )
        self._client.put_object(
            Bucket=self._bucket,
            Key=self._meta_key(record_id),
            Body=new_metadata.model_dump_json(indent=2).encode("utf-8"),
            ContentType="application/json",
        )
        return new_metadata

    def __repr__(self) -> str:
        return (
            f"S3ObjectLockWORM(bucket={self._bucket!r}, "
            f"lock_mode={self._lock_mode!r}, prefix={self._prefix!r})"
        )


# Avoid "imported but unused" on `timedelta` when typing-only refs
_ = timedelta
