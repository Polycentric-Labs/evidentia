"""Collect one authorized incident workflow observation with owned source evidence."""

from __future__ import annotations

from importlib import import_module
from types import TracebackType
from typing import Self, cast

from evidentia_core.models.finding import SecurityFinding

from ._client import IncidentReadSession
from ._contracts import IncidentClockResult, _result_authority, result_bytes
from ._profiles import AuthorizedSelection, ProfileUnavailable, validated_selection


class IncidentClockCollector:
    """Validate the selected request before credentials and own each read session."""

    COLLECTOR_ID = "incident-clock"
    SOURCE_SYSTEM = "incident-clock"

    def __init__(self, selection: AuthorizedSelection) -> None:
        if type(selection) is not AuthorizedSelection:
            raise ProfileUnavailable()
        self._selection = validated_selection(selection, selection.request)
        self._closed = False

    def __enter__(self) -> Self:
        if self._closed:
            raise ValueError("collector_closed")
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, traceback: TracebackType | None
    ) -> None:
        self.close()

    def close(self) -> None:
        self._closed = True

    def collect(self, request: object) -> list[SecurityFinding]:
        """Return the finding view; collect_v2 retains the complete observation."""
        return list(self.collect_v2(request).findings)

    def collect_v2(self, request: object) -> IncidentClockResult:
        """Compare adapter output with a result reconstructed from the owned session."""
        if self._closed:
            raise ValueError("collector_closed")
        selected = validated_selection(self._selection, request)
        session: IncidentReadSession | None = None
        try:
            adapter = import_module("evidentia_collectors.incident_clock." + selected.provider)
            session = IncidentReadSession(selected)
            result = adapter.collect(session)
            authority = session.finish()
            if _result_authority(result) is not authority:
                raise ValueError("collector_failed")
            result_bytes(result)
            return cast(IncidentClockResult, result)
        except Exception:
            raise ValueError("collector_failed") from None
        finally:
            if session is not None:
                session.close()
