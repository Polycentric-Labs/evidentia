"""Collection entry point for selected storage retention configuration."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from importlib import import_module as _import_module
from time import monotonic, sleep
from types import TracebackType
from typing import Self

import httpx
from evidentia_core.audit.provenance import new_run_id
from evidentia_core.models.finding import SecurityFinding

from ._client import ClientFault, StorageReadSession
from ._contracts import (
    COLLECTOR_ID,
    SOURCE_SYSTEM,
    AzureTarget,
    S3Target,
    StorageRetentionCollectRequest,
    StorageRetentionCollectResult,
    StorageRetentionComponentResult,
    StorageRetentionDiagnostic,
    StorageTarget,
    make_result,
    target_identity,
    validated_request,
)
from ._credentials import EnvironmentCredentialProvider, StorageCredentialProvider


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _read_target(target: StorageTarget, session: StorageReadSession) -> list[StorageRetentionComponentResult]:
    if isinstance(target, S3Target):
        from .aws import read_s3

        return read_s3(target, session)
    if isinstance(target, AzureTarget):
        from .azure import read_azure

        return read_azure(target, session)
    from .gcs import read_gcs

    return read_gcs(target, session)


class StorageRetentionCollector:
    """Collect configuration for a finite set of operator-selected resources.

    Construction reads no credentials. Each call owns its transport, run
    clocks, credential resolution and result. Injected transport factories
    create a fresh transport whose ownership transfers to that call.
    """

    COLLECTOR_ID = COLLECTOR_ID
    SOURCE_SYSTEM = SOURCE_SYSTEM

    def __init__(
        self,
        *,
        credentials: StorageCredentialProvider | None = None,
        transport_factory: Callable[[], httpx.BaseTransport] | None = None,
        utc_clock: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], float] = monotonic,
        sleep: Callable[[float], None] = sleep,
        run_id_factory: Callable[[], str] = new_run_id,
    ) -> None:
        self._credentials = credentials if credentials is not None else EnvironmentCredentialProvider()
        self._transport_factory = transport_factory
        self._utc_clock = utc_clock
        self._monotonic_clock = monotonic_clock
        self._sleep = sleep
        self._run_id_factory = run_id_factory
        self._closed = False

    def __enter__(self) -> Self:
        if self._closed:
            raise ValueError("collector_closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True

    def collect(self, request: StorageRetentionCollectRequest) -> list[SecurityFinding]:
        """Return findings only; collect_v2 also retains incomplete observations."""
        return list(self.collect_v2(request).findings)

    def collect_v2(self, request: StorageRetentionCollectRequest) -> StorageRetentionCollectResult:
        """Return every selected resource, component state and collection manifest."""
        if self._closed:
            raise ValueError("collector_closed")
        selected = validated_request(request)
        if selected.root.provider == "s3":
            # Only exact missing top-level packages are optional absence.
            # Signing still checks its pinned SDK contract before helper imports.
            _import_module("botocore")
            _import_module("defusedxml.ElementTree")
        try:
            session = StorageReadSession(
                selected,
                credentials=self._credentials,
                transport_factory=self._transport_factory,
                utc_clock=self._utc_clock,
                monotonic_clock=self._monotonic_clock,
                sleep=self._sleep,
                run_id_factory=self._run_id_factory,
            )
            components: dict[str, list[StorageRetentionComponentResult]] = {}
            try:
                for target in session.context.request.root.targets:
                    identity = target_identity(target)
                    components[identity] = _read_target(target, session)
            finally:
                session.close()
            finished_at = session.context.utc_now()
            try:
                session.context.remaining()
            except ClientFault as error:
                if error.code != "run_budget_exhausted":
                    raise
            diagnostics = []
            if session.cleanup_failed:
                diagnostics.append(StorageRetentionDiagnostic(code="cleanup_failed", http_status=None))
            if session.context.exhausted:
                diagnostics.append(StorageRetentionDiagnostic(code="run_budget_exhausted", http_status=None))
            observed = [item for items in components.values() for item in items]
            if (
                sum(item.raw_bytes for item in observed) != session.context.raw_bytes
                or sum(item.decoded_bytes for item in observed) != session.context.decoded_bytes
            ):
                raise ValueError("component_accounting_mismatch")
            return make_result(
                selected,
                run_id=session.context.run_id,
                started_at=session.context.started_at,
                finished_at=finished_at,
                components=components,
                diagnostics=tuple(diagnostics),
            )
        except Exception:
            raise ValueError("collector_failed") from None
