"""Azure Immutable Blob Storage-backed WORM implementation (v0.7.12 P0).

Concrete :class:`evidentia_core.retention.worm.WORMBackend` impl
that stores records in an Azure Storage container with **immutable
storage policies** in either Unlocked (mutable retention) or
Locked (immutable retention) mode. Locked mode is the canonical
Azure primitive for regulator-grade WORM enforcement — once the
policy is locked, neither root nor account-owner can shorten the
retention; the storage service refuses ``DeleteBlob`` until the
expiry date passes.

The container MUST be created with version-level immutability
support. See ``docs/worm-backends.md`` for the operator setup
runbook (storage account properties + container properties + IAM).

Per-record layout matches the S3 backend:

  - ``<container>/<prefix><record_id>.bin``      payload (immutable)
  - ``<container>/<prefix><record_id>.meta.json`` metadata sidecar

Usage::

    from evidentia_core.retention.worm_azure import AzureImmutableBlobWORM

    backend = AzureImmutableBlobWORM(
        account_url="https://myaccount.blob.core.windows.net",
        container_name="evidentia-worm",
        # uses DefaultAzureCredential by default (managed identity,
        # az CLI, env vars, etc.) — pass `credential=` to override.
    )
    backend.put(record_id="rec-1", payload=b"...", metadata=meta)

The ``azure-storage-blob`` + ``azure-identity`` dependencies are
gated behind the ``evidentia[worm-azure]`` extra. Importing this
module without those installed raises a clear ``ImportError``.
"""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from evidentia_core.retention.metadata import (
    RetentionLifecycleStage,
    RetentionMetadata,
    is_locked,
)
from evidentia_core.retention.worm import WORMBackend, WORMBackendError

try:
    from azure.core.exceptions import (
        HttpResponseError,
        ResourceExistsError,
        ResourceNotFoundError,
    )
    from azure.storage.blob import BlobServiceClient, ImmutabilityPolicy
except ImportError as _exc:  # pragma: no cover — import-time gate
    raise ImportError(
        "AzureImmutableBlobWORM requires azure-storage-blob + "
        "azure-identity. Install with: "
        "pip install 'evidentia[worm-azure]' (or "
        "'evidentia-core[worm-azure]' for the library-only install)."
    ) from _exc

# azure-identity is imported lazily inside __init__ when no
# credential is supplied — keeps the import surface small.


# Azure Immutable Blob policy modes.
AzureLockMode = str  # Literal["Locked", "Unlocked"]
DEFAULT_LOCK_MODE: AzureLockMode = "Locked"


class AzureImmutableBlobWORM(WORMBackend):
    """Cloud-backed WORM via Azure Immutable Blob Storage.

    Args:
        account_url: Azure Storage account URL
            (``https://<acct>.blob.core.windows.net``).
        container_name: Pre-created container with version-level
            immutability support enabled.
        credential: Auth credential. When None, falls back to
            ``DefaultAzureCredential`` (managed identity, az CLI,
            env vars, etc.).
        lock_mode: ``"Locked"`` (immutable retention; canonical for
            regulator-grade WORM) or ``"Unlocked"`` (operator can
            shorten retention; useful for development). Default
            ``"Locked"``.
        prefix: Optional blob name prefix (for multi-tenant
            isolation within a single container).
        client_factory: Optional callable returning a
            ``BlobServiceClient``. Useful for tests (substitute a
            mocked client).

    Raises:
        WORMBackendError: when args are invalid OR the service
            cannot be reached.
    """

    def __init__(
        self,
        account_url: str,
        container_name: str,
        *,
        credential: Any = None,
        lock_mode: AzureLockMode = DEFAULT_LOCK_MODE,
        prefix: str = "",
        client_factory: Any = None,
    ) -> None:
        if not container_name or not isinstance(container_name, str):
            raise WORMBackendError(
                "AzureImmutableBlobWORM requires a non-empty container_name"
            )
        if lock_mode not in ("Locked", "Unlocked"):
            raise WORMBackendError(
                f"Azure lock_mode must be Locked or Unlocked, got "
                f"{lock_mode!r}"
            )
        self._container_name = container_name
        self._lock_mode = lock_mode
        self._prefix = prefix
        if client_factory is not None:
            self._service: BlobServiceClient = client_factory()
        else:
            if credential is None:
                from azure.identity import DefaultAzureCredential

                credential = DefaultAzureCredential()
            self._service = BlobServiceClient(
                account_url=account_url, credential=credential
            )
        self._container = self._service.get_container_client(container_name)

    # ── Key helpers ────────────────────────────────────────────────

    def _payload_key(self, record_id: str) -> str:
        return f"{self._prefix}{record_id}.bin"

    def _meta_key(self, record_id: str) -> str:
        return f"{self._prefix}{record_id}.meta.json"

    def _retain_until_datetime(
        self, metadata: RetentionMetadata
    ) -> datetime | None:
        if metadata.lock_until is None:
            return None
        return datetime.combine(
            metadata.lock_until, datetime.min.time(), tzinfo=UTC
        )

    # ── WORMBackend contract ───────────────────────────────────────

    def put(
        self,
        record_id: str,
        payload: bytes,
        metadata: RetentionMetadata,
    ) -> None:
        payload_blob = self._container.get_blob_client(
            self._payload_key(record_id)
        )
        if payload_blob.exists():
            raise WORMBackendError(
                f"Azure record {record_id!r} already exists in container "
                f"{self._container_name!r}; WORM forbids overwrite"
            )
        # Upload payload first
        try:
            payload_blob.upload_blob(payload, overwrite=False)
        except ResourceExistsError as e:
            raise WORMBackendError(
                f"Azure record {record_id!r} already exists "
                f"(server-side); WORM forbids overwrite"
            ) from e
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure put failed for record {record_id!r}: "
                f"{getattr(e, 'message', str(e))}"
            ) from e

        # Apply immutability policy if retention applies
        retain_until = self._retain_until_datetime(metadata)
        if retain_until is not None:
            try:
                payload_blob.set_immutability_policy(
                    ImmutabilityPolicy(
                        expiry_time=retain_until,
                        policy_mode=self._lock_mode,
                    )
                )
            except HttpResponseError as e:
                raise WORMBackendError(
                    f"Azure set_immutability_policy failed for "
                    f"record {record_id!r}: "
                    f"{getattr(e, 'message', str(e))}"
                ) from e
        # Apply legal-hold if requested
        if metadata.legal_hold:
            try:
                payload_blob.set_legal_hold(legal_hold=True)
            except HttpResponseError as e:
                raise WORMBackendError(
                    f"Azure set_legal_hold failed for record "
                    f"{record_id!r}: {getattr(e, 'message', str(e))}"
                ) from e

        # Metadata sidecar — NOT under immutability policy (so we
        # can update on retention extension / lifecycle transition).
        meta_blob = self._container.get_blob_client(
            self._meta_key(record_id)
        )
        try:
            meta_blob.upload_blob(
                metadata.model_dump_json(indent=2).encode("utf-8"),
                overwrite=True,
            )
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure metadata put failed for record {record_id!r}: "
                f"{getattr(e, 'message', str(e))}"
            ) from e

    def get(self, record_id: str) -> bytes:
        blob = self._container.get_blob_client(
            self._payload_key(record_id)
        )
        try:
            stream = blob.download_blob()
            return bytes(stream.readall())
        except ResourceNotFoundError as e:
            raise WORMBackendError(
                f"Azure record {record_id!r} not found in container "
                f"{self._container_name!r}"
            ) from e
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure get failed for record {record_id!r}: "
                f"{getattr(e, 'message', str(e))}"
            ) from e

    def get_metadata(self, record_id: str) -> RetentionMetadata:
        blob = self._container.get_blob_client(self._meta_key(record_id))
        try:
            raw = bytes(blob.download_blob().readall())
        except ResourceNotFoundError as e:
            raise WORMBackendError(
                f"Azure metadata for record {record_id!r} not found"
            ) from e
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure metadata get failed for record {record_id!r}: "
                f"{getattr(e, 'message', str(e))}"
            ) from e
        return RetentionMetadata.model_validate_json(raw.decode("utf-8"))

    def delete(self, record_id: str, today: date | None = None) -> None:
        metadata = self.get_metadata(record_id)
        if metadata.legal_hold:
            raise WORMBackendError(
                f"Azure record {record_id!r} is under legal hold; "
                f"cannot delete"
            )
        if is_locked(metadata, today=today):
            raise WORMBackendError(
                f"Azure record {record_id!r} is still inside its "
                f"retention window (lock_until={metadata.lock_until}); "
                f"cannot delete"
            )
        if metadata.lifecycle_stage != RetentionLifecycleStage.EXPIRED.value:
            raise WORMBackendError(
                f"Azure record {record_id!r} lifecycle is "
                f"{metadata.lifecycle_stage}; only EXPIRED records can "
                f"be deleted"
            )
        try:
            self._container.delete_blob(self._payload_key(record_id))
            self._container.delete_blob(self._meta_key(record_id))
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure delete failed for record {record_id!r}: "
                f"{getattr(e, 'message', str(e))}"
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

        new_retain_dt = datetime.combine(
            new_lock_until, datetime.min.time(), tzinfo=UTC
        )
        payload_blob = self._container.get_blob_client(
            self._payload_key(record_id)
        )
        try:
            payload_blob.set_immutability_policy(
                ImmutabilityPolicy(
                    expiry_time=new_retain_dt,
                    policy_mode=self._lock_mode,
                )
            )
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure set_immutability_policy failed for record "
                f"{record_id!r}: {getattr(e, 'message', str(e))}"
            ) from e

        new_metadata = metadata.model_copy(
            update={
                "lock_until": new_lock_until,
                "updated_at": utc_now(),
            }
        )
        meta_blob = self._container.get_blob_client(
            self._meta_key(record_id)
        )
        try:
            meta_blob.upload_blob(
                new_metadata.model_dump_json(indent=2).encode("utf-8"),
                overwrite=True,
            )
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure metadata update failed for record {record_id!r}: "
                f"{getattr(e, 'message', str(e))}"
            ) from e
        return new_metadata

    def apply_legal_hold(self, record_id: str) -> RetentionMetadata:
        from evidentia_core.models.common import utc_now

        payload_blob = self._container.get_blob_client(
            self._payload_key(record_id)
        )
        try:
            payload_blob.set_legal_hold(legal_hold=True)
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure set_legal_hold failed for record {record_id!r}: "
                f"{getattr(e, 'message', str(e))}"
            ) from e
        metadata = self.get_metadata(record_id)
        new_metadata = metadata.model_copy(
            update={"legal_hold": True, "updated_at": utc_now()}
        )
        meta_blob = self._container.get_blob_client(
            self._meta_key(record_id)
        )
        meta_blob.upload_blob(
            new_metadata.model_dump_json(indent=2).encode("utf-8"),
            overwrite=True,
        )
        return new_metadata

    def release_legal_hold(self, record_id: str) -> RetentionMetadata:
        from evidentia_core.models.common import utc_now

        payload_blob = self._container.get_blob_client(
            self._payload_key(record_id)
        )
        try:
            payload_blob.set_legal_hold(legal_hold=False)
        except HttpResponseError as e:
            raise WORMBackendError(
                f"Azure release_legal_hold failed for record "
                f"{record_id!r}: {getattr(e, 'message', str(e))}"
            ) from e
        metadata = self.get_metadata(record_id)
        new_metadata = metadata.model_copy(
            update={"legal_hold": False, "updated_at": utc_now()}
        )
        meta_blob = self._container.get_blob_client(
            self._meta_key(record_id)
        )
        meta_blob.upload_blob(
            new_metadata.model_dump_json(indent=2).encode("utf-8"),
            overwrite=True,
        )
        return new_metadata

    def __repr__(self) -> str:
        return (
            f"AzureImmutableBlobWORM(container={self._container_name!r}, "
            f"lock_mode={self._lock_mode!r}, prefix={self._prefix!r})"
        )
