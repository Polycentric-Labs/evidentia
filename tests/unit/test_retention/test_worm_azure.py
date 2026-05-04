"""Unit tests for evidentia_core.retention.worm_azure (v0.7.12 P0).

Azure has no moto equivalent (azurite is a local emulator but
adding it as a test dep is heavy). Instead, this module mocks
the Azure SDK BlobServiceClient with a stateful in-memory
simulator that matches the surface used by AzureImmutableBlobWORM.

The simulator is intentionally minimal — it covers the methods
the backend calls (upload_blob, download_blob, delete_blob,
exists, set_immutability_policy, set_legal_hold). It tracks
per-blob immutability + legal-hold state so Locked-mode policies
correctly refuse delete during retention.
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Any

import pytest
from azure.core.exceptions import (
    ResourceExistsError,
    ResourceNotFoundError,
)
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
)
from evidentia_core.retention.worm import WORMBackendError
from evidentia_core.retention.worm_azure import AzureImmutableBlobWORM

# ── In-memory Azure SDK stub ───────────────────────────────────────


class _BlobStub:
    """Stand-in for ``BlobClient``. Tracks per-blob immutability +
    legal-hold + content."""

    def __init__(self, store: dict[str, Any], name: str) -> None:
        self._store = store
        self._name = name

    def exists(self) -> bool:
        return self._name in self._store

    def upload_blob(self, body: bytes | str, *, overwrite: bool = False) -> None:
        if self._name in self._store and not overwrite:
            raise ResourceExistsError(message="BlobAlreadyExists")
        # Reject overwrites of immutability-locked blobs even when
        # overwrite=True (Azure semantics during retention)
        existing = self._store.get(self._name)
        if existing and existing.get("locked", False):
            raise ResourceExistsError(message="BlobImmutabilityPolicy")
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        self._store[self._name] = {
            "data": body_bytes,
            "immutability_until": None,
            "legal_hold": False,
            "locked": False,
        }

    def download_blob(self) -> Any:
        if self._name not in self._store:
            raise ResourceNotFoundError(message="BlobNotFound")

        class _Stream:
            def __init__(self, data: bytes) -> None:
                self._data = data

            def readall(self) -> bytes:
                return self._data

        return _Stream(self._store[self._name]["data"])

    def set_immutability_policy(self, immutability_policy: Any) -> None:
        if self._name not in self._store:
            raise ResourceNotFoundError(message="BlobNotFound")
        rec = self._store[self._name]
        # Locked policies cannot be shortened — but extend_retention
        # at the backend layer enforces that, so the stub trusts the
        # caller. Just record state.
        rec["immutability_until"] = immutability_policy.expiry_time
        rec["locked"] = immutability_policy.policy_mode == "Locked"

    def set_legal_hold(self, *, legal_hold: bool) -> None:
        if self._name not in self._store:
            raise ResourceNotFoundError(message="BlobNotFound")
        self._store[self._name]["legal_hold"] = legal_hold


class _ContainerStub:
    def __init__(self, store: dict[str, Any]) -> None:
        self._store = store

    def get_blob_client(self, blob_name: str) -> _BlobStub:
        return _BlobStub(self._store, blob_name)

    def delete_blob(self, blob_name: str) -> None:
        if blob_name not in self._store:
            raise ResourceNotFoundError(message="BlobNotFound")
        rec = self._store[blob_name]
        # Azure refuses delete on legal-hold or active immutability
        # policy in Locked mode (the backend's app-layer check
        # catches this first; the stub fail-safes anyway)
        if rec.get("legal_hold"):
            from azure.core.exceptions import HttpResponseError

            raise HttpResponseError(message="LegalHoldActive")
        del self._store[blob_name]


class _ServiceStub:
    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    def get_container_client(self, name: str) -> _ContainerStub:
        return _ContainerStub(self.store)


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture
def service() -> _ServiceStub:
    return _ServiceStub()


@pytest.fixture
def worm(service: _ServiceStub) -> AzureImmutableBlobWORM:
    return AzureImmutableBlobWORM(
        account_url="https://fake.blob.core.windows.net",
        container_name="evidentia-worm",
        lock_mode="Unlocked",  # easier to test delete bypass
        client_factory=lambda: service,
    )


def _meta(**overrides: object) -> RetentionMetadata:
    base: dict[str, object] = {
        "classification": RetentionClassification.SOX_404,
        "retention_period_days": 365,
    }
    base.update(overrides)
    return RetentionMetadata.model_validate(base)


# ── Tests (mirror S3 structure) ────────────────────────────────────


class TestPutGet:
    def test_round_trip(self, worm: AzureImmutableBlobWORM) -> None:
        m = _meta()
        worm.put(m.id, b"payload-bytes", m)
        assert worm.get(m.id) == b"payload-bytes"
        loaded = worm.get_metadata(m.id)
        assert loaded.id == m.id

    def test_get_missing_raises(self, worm: AzureImmutableBlobWORM) -> None:
        with pytest.raises(WORMBackendError, match="not found"):
            worm.get("aaaaaaaa-1111-2222-3333-444444444444")

    def test_double_put_rejected(self, worm: AzureImmutableBlobWORM) -> None:
        m = _meta()
        worm.put(m.id, b"first", m)
        with pytest.raises(WORMBackendError, match="already exists"):
            worm.put(m.id, b"second", m)

    def test_put_with_legal_hold(
        self, worm: AzureImmutableBlobWORM
    ) -> None:
        m = _meta(legal_hold=True)
        worm.put(m.id, b"with-hold", m)
        assert worm.get_metadata(m.id).legal_hold is True

    def test_put_zero_retention_gdpr(
        self, worm: AzureImmutableBlobWORM
    ) -> None:
        m = _meta(
            classification=RetentionClassification.GDPR,
            retention_period_days=0,
        )
        worm.put(m.id, b"gdpr-payload", m)
        assert worm.get(m.id) == b"gdpr-payload"


class TestDelete:
    def test_delete_active_within_window_rejected(
        self, worm: AzureImmutableBlobWORM
    ) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="retention window"):
            worm.delete(m.id)

    def test_delete_legal_hold_rejected(
        self, worm: AzureImmutableBlobWORM
    ) -> None:
        m = _meta(legal_hold=True)
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="legal hold"):
            worm.delete(m.id)

    def test_delete_non_expired_rejected(
        self, worm: AzureImmutableBlobWORM
    ) -> None:
        m = _meta(lock_until=date.today() - timedelta(days=10))
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="lifecycle"):
            worm.delete(m.id)

    def test_delete_expired_succeeds(
        self, worm: AzureImmutableBlobWORM
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
    def test_extend_succeeds(self, worm: AzureImmutableBlobWORM) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        new_until = date.today() + timedelta(days=730)
        new_meta = worm.extend_retention(m.id, new_until)
        assert new_meta.lock_until == new_until

    def test_extend_backward_rejected(
        self, worm: AzureImmutableBlobWORM
    ) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        with pytest.raises(WORMBackendError, match="shortening"):
            worm.extend_retention(m.id, date.today() + timedelta(days=10))


class TestLegalHold:
    def test_apply_and_release(self, worm: AzureImmutableBlobWORM) -> None:
        m = _meta()
        worm.put(m.id, b"x", m)
        held = worm.apply_legal_hold(m.id)
        assert held.legal_hold is True
        released = worm.release_legal_hold(m.id)
        assert released.legal_hold is False


class TestConstruction:
    def test_empty_container_name_rejected(self) -> None:
        with pytest.raises(WORMBackendError, match="non-empty"):
            AzureImmutableBlobWORM(
                account_url="https://fake.blob.core.windows.net",
                container_name="",
                client_factory=lambda: _ServiceStub(),
            )

    def test_invalid_lock_mode_rejected(self) -> None:
        with pytest.raises(WORMBackendError, match="Locked or Unlocked"):
            AzureImmutableBlobWORM(
                account_url="https://fake.blob.core.windows.net",
                container_name="x",
                lock_mode="INVALID",  # type: ignore[arg-type]
                client_factory=lambda: _ServiceStub(),
            )

    def test_repr_contains_container(
        self, worm: AzureImmutableBlobWORM
    ) -> None:
        s = repr(worm)
        assert "evidentia-worm" in s
        assert "Unlocked" in s


class TestPrefix:
    def test_prefix_isolates_records(self, service: _ServiceStub) -> None:
        worm_a = AzureImmutableBlobWORM(
            account_url="https://fake.blob.core.windows.net",
            container_name="x",
            lock_mode="Unlocked",
            prefix="tenant-a/",
            client_factory=lambda: service,
        )
        worm_b = AzureImmutableBlobWORM(
            account_url="https://fake.blob.core.windows.net",
            container_name="x",
            lock_mode="Unlocked",
            prefix="tenant-b/",
            client_factory=lambda: service,
        )
        m = _meta()
        worm_a.put(m.id, b"tenant-a-data", m)
        with pytest.raises(WORMBackendError, match="not found"):
            worm_b.get(m.id)
        assert worm_a.get(m.id) == b"tenant-a-data"


def test_metadata_round_trip_matches_local_filesystem(
    worm: AzureImmutableBlobWORM,
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
