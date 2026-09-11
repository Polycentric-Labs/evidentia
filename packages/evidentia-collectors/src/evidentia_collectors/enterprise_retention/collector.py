"""Collect selected enterprise retention configuration through a trusted profile."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic, sleep
from types import TracebackType
from typing import Any, Self

from evidentia_core.audit.provenance import new_run_id
from evidentia_core.models.finding import SecurityFinding

from ._client import EnterpriseReadSession, EnterpriseRetentionOperationalError, TransportFactory
from ._contracts import (
    ElasticIndexTarget,
    EnterpriseRetentionCollectRequest,
    EnterpriseRetentionCollectResult,
    EnterpriseRetentionResourceResult,
    EnterpriseTarget,
    SplunkIndexTarget,
    VaultMatterTarget,
    validated_request,
)
from ._profiles import AuthorizedProfile


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _read_target(target: EnterpriseTarget, session: EnterpriseReadSession) -> EnterpriseRetentionResourceResult[Any]:
    if type(target) is VaultMatterTarget:
        from .vault import read_vault

        return read_vault(target, session)
    if type(target) is SplunkIndexTarget:
        from .splunk import read_splunk

        return read_splunk(target, session)
    if type(target) is ElasticIndexTarget:
        from .elastic import read_elastic

        return read_elastic(target, session)
    raise EnterpriseRetentionOperationalError()


class EnterpriseRetentionCollector:
    """Read a finite selection using one previously authorized profile.

    Construction detaches the profile without reading credentials or opening
    a connection. Each collection owns its session, clocks, read ledger and
    credential resolution. A test transport factory transfers ownership of
    each transport it creates to the session.
    """

    COLLECTOR_ID = "enterprise-retention"
    SOURCE_SYSTEM = "enterprise-retention"

    def __init__(
        self,
        *,
        profile: AuthorizedProfile,
        transport_factory: TransportFactory | None = None,
        utc_clock: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], float] = monotonic,
        sleep: Callable[[float], None] = sleep,
        run_id_factory: Callable[[], str] = new_run_id,
    ) -> None:
        if type(profile) is not AuthorizedProfile:
            raise EnterpriseRetentionOperationalError()
        try:
            self._profile = AuthorizedProfile(profile.profile, profile.resolver)
        except Exception:
            raise EnterpriseRetentionOperationalError() from None
        if transport_factory is not None and not callable(transport_factory):
            raise EnterpriseRetentionOperationalError()
        self._transport_factory = transport_factory
        self._utc_clock = utc_clock
        self._monotonic_clock = monotonic_clock
        self._sleep = sleep
        self._run_id_factory = run_id_factory
        self._closed = False

    def __enter__(self) -> Self:
        if self._closed:
            raise EnterpriseRetentionOperationalError()
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

    def collect(self, request: EnterpriseRetentionCollectRequest) -> list[SecurityFinding]:
        """Return findings while collect_v2 also retains incomplete observations."""
        return list(self.collect_v2(request).root.findings)

    def collect_v2(self, request: EnterpriseRetentionCollectRequest) -> EnterpriseRetentionCollectResult:
        """Return all selected resources and their unique source-read evidence."""
        if self._closed:
            raise EnterpriseRetentionOperationalError()
        selected = validated_request(request)
        try:
            with EnterpriseReadSession(
                selected,
                profile=self._profile,
                transport_factory=self._transport_factory,
                utc_clock=self._utc_clock,
                monotonic_clock=self._monotonic_clock,
                sleep=self._sleep,
                run_id_factory=self._run_id_factory,
            ) as session:
                resources = tuple(_read_target(target, session) for target in session.context.request.root.targets)
                return session.finish(resources)
        except Exception:
            raise EnterpriseRetentionOperationalError() from None
