"""Dispatch one bounded public registry lookup through an owned read session."""

from __future__ import annotations

from collections.abc import Callable
from importlib import import_module
from types import TracebackType
from typing import Self, cast

from evidentia_core.models.finding import SecurityFinding

from ._client import RegistryReadSession
from ._contracts import RegistryLookupRequest, RegistryLookupResult, result_bytes, validated_request

_MODULES = {
    "tls": "tls",
    "rdap": "rdap",
    "sam-entity": "sam_entity",
    "sam-exclusions": "sam_exclusions",
    "gleif": "gleif",
    "fedramp": "fedramp",
    "cmvp": "cmvp",
    "fcc-covered-list": "fcc",
    "incommon": "incommon",
    "ssl-labs": "ssl_labs",
    "security-txt": "security_txt",
}


def _read_registry(session: RegistryReadSession) -> RegistryLookupResult:
    module = import_module("." + _MODULES[session.request.root.registry], __package__)
    lookup = cast(Callable[[RegistryReadSession], RegistryLookupResult], module.lookup)
    return lookup(session)


class RegistryCollector:
    """Collect selected-query evidence without I/O during construction.

    Each call owns a separate session. The private session factory is a trusted
    local testing capability and is never accepted in a public request.
    """

    COLLECTOR_ID = "public-registry"
    SOURCE_SYSTEM = "public-registry"

    def __init__(
        self,
        *,
        _session_factory: Callable[[RegistryLookupRequest], RegistryReadSession] = RegistryReadSession,
    ) -> None:
        if not callable(_session_factory):
            raise ValueError("registry_collection_failed")
        self._session_factory = _session_factory
        self._closed = False

    def __enter__(self) -> Self:
        if self._closed:
            raise ValueError("registry_collection_failed")
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

    def collect(self, request: object) -> list[SecurityFinding]:
        """Return findings only; this view cannot establish success or completeness."""
        return list(self.collect_v2(request).findings)

    def collect_v2(self, request: object) -> RegistryLookupResult:
        """Return the full validated result bound to the original selected request."""
        if self._closed:
            raise ValueError("registry_collection_failed")
        selected = validated_request(request)
        original = selected.model_dump(mode="python", warnings="error")
        try:
            session = self._session_factory(selected)
            if type(session) is not RegistryReadSession:
                raise ValueError("invalid_session")
            observed = _read_registry(session)
            if type(observed) is not RegistryLookupResult:
                raise ValueError("invalid_result")
            published = RegistryLookupResult.model_validate_json(result_bytes(observed))
            if published.request.model_dump(mode="python", warnings="error") != original:
                raise ValueError("result_request_mismatch")
            return published
        except Exception:
            raise ValueError("registry_collection_failed") from None
