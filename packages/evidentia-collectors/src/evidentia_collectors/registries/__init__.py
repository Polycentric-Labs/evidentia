"""Strict models for evidence about a selected public registry identity."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._contracts import (
    RegistryContext,
    RegistryDiagnostic,
    RegistryInputError,
    RegistryLookupRequest,
    RegistryLookupResult,
    RegistryManifest,
    RegistryObservation,
    SourceRead,
)

if TYPE_CHECKING:
    from .collector import RegistryCollector


__all__ = [
    "RegistryCollector",
    "RegistryContext",
    "RegistryDiagnostic",
    "RegistryInputError",
    "RegistryLookupRequest",
    "RegistryLookupResult",
    "RegistryManifest",
    "RegistryObservation",
    "SourceRead",
]


def __getattr__(name: str) -> type[RegistryCollector]:
    """Load execution support only when the collector class is requested."""
    if name == "RegistryCollector":
        from .collector import RegistryCollector

        return RegistryCollector
    raise AttributeError("Unknown registry export.")
