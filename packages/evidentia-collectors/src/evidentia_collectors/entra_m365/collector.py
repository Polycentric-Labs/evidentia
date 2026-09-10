"""Collection entry point for bounded Entra and M365 evidence."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime
from time import monotonic, sleep
from types import TracebackType
from typing import Self
from uuid import uuid4

import httpx
from evidentia_core.models.finding import SecurityFinding
from pydantic import ValidationError

from . import _client
from ._client import _CredentialProvider, _EnvironmentCredentials
from ._contracts import (
    CapabilityName,
    EntraM365CapabilityRead,
    EntraM365CollectRequest,
    EntraM365CollectResult,
    EntraM365DlpExport,
    EntraM365InputError,
    EntraM365RunContext,
)
from .defender import read_defender_alerts, read_defender_incidents
from .devices import read_managed_devices
from .dlp_export import parse_dlp_export, read_dlp_export
from .identity import (
    read_authentication_registration,
    read_conditional_access,
    read_directory_roles,
    read_sign_ins,
)
from .purview import read_retention_labels

type _Reader = Callable[
    [EntraM365CollectRequest, _client.EntraM365GraphReader, EntraM365RunContext, EntraM365DlpExport | None],
    EntraM365CapabilityRead,
]
_READERS: tuple[tuple[CapabilityName, _Reader], ...] = (
    ("conditional-access", read_conditional_access),
    ("authentication-registration", read_authentication_registration),
    ("sign-ins", read_sign_ins),
    ("directory-roles", read_directory_roles),
    ("managed-devices", read_managed_devices),
    ("retention-labels", read_retention_labels),
    ("dlp-export", read_dlp_export),
    ("defender-alerts", read_defender_alerts),
    ("defender-incidents", read_defender_incidents),
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _new_run_id() -> str:
    return str(uuid4())


class EntraM365Collector:
    """Collect declared evidence scope using fixed credential references.

    Construction is lazy. Each call owns its run context and any HTTP client
    it creates; an explicitly supplied HTTPX client remains caller-owned.
    """

    COLLECTOR_ID = "entra-m365-scan"
    SOURCE_SYSTEM = "entra-m365"

    def __init__(
        self,
        *,
        credentials: _CredentialProvider | None = None,
        client: httpx.Client | None = None,
        utc_clock: Callable[[], datetime] = _utc_now,
        monotonic_clock: Callable[[], float] = monotonic,
        sleep: Callable[[float], None] = sleep,
        run_id_factory: Callable[[], str] = _new_run_id,
    ) -> None:
        self._credentials = credentials if credentials is not None else _EnvironmentCredentials()
        self._client = client
        self._utc_clock = utc_clock
        self._monotonic_clock = monotonic_clock
        self._sleep = sleep
        self._run_id_factory = run_id_factory
        self._closed = False

    @staticmethod
    def _configuration_status() -> dict[str, bool]:
        """Report fixed reference presence without resolving tenant identity."""
        primary = bool(os.environ.get("ENTRA_M365_ACCESS_TOKEN"))
        retention = bool(os.environ.get("ENTRA_M365_RETENTION_ACCESS_TOKEN"))
        valid_mode = os.environ.get("ENTRA_M365_AUTH_MODE", "application") in {"application", "delegated"}
        return {
            "configured": primary and retention and valid_mode,
            "primary_token_configured": primary,
            "retention_token_configured": retention,
            "primary_auth_mode_valid": valid_mode,
            "live_validated": False,
            "credential_identity_verified": False,
        }

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

    def collect(self, request: EntraM365CollectRequest) -> list[SecurityFinding]:
        """Return findings only; use collect_v2 to retain completeness evidence."""
        return list(self.collect_v2(request).findings)

    def collect_v2(self, request: EntraM365CollectRequest) -> EntraM365CollectResult:
        """Return every capability state, accepted finding and run manifest."""
        if self._closed:
            raise ValueError("collector_closed")
        try:
            validated = EntraM365CollectRequest.model_validate(request)
        except ValidationError:
            raise EntraM365InputError("invalid_field") from None
        dlp_export = (
            parse_dlp_export(validated.dlp_content, format=validated.dlp_format)
            if validated.dlp_content is not None
            else None
        )
        try:
            context = EntraM365RunContext.start(
                validated,
                utc_clock=self._utc_clock,
                monotonic_clock=self._monotonic_clock,
                sleep=self._sleep,
                run_id_factory=self._run_id_factory,
            )
            reader = _client.EntraM365GraphReader(credentials=self._credentials, client=self._client)
            try:
                reads = [
                    read(context.request, reader, context, dlp_export)
                    for name, read in _READERS
                    if name in context.request.capabilities
                ]
                return context.build_result(reads)
            finally:
                reader.close()
        except Exception:
            raise ValueError("collector_failed") from None
