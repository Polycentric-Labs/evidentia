"""Collection and strict models for selected enterprise retention configuration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._contracts import (
    EnterpriseRetentionCollectRequest,
    EnterpriseRetentionCollectResult,
    EnterpriseRetentionDiagnostic,
    EnterpriseRetentionInputError,
    EnterpriseRetentionManifest,
    EnterpriseRetentionObservation,
    EnterpriseRetentionReadResult,
    EnterpriseRetentionResourceResult,
)

if TYPE_CHECKING:
    from .collector import EnterpriseRetentionCollector


__all__ = [
    "EnterpriseRetentionCollectRequest",
    "EnterpriseRetentionCollectResult",
    "EnterpriseRetentionCollector",
    "EnterpriseRetentionDiagnostic",
    "EnterpriseRetentionInputError",
    "EnterpriseRetentionManifest",
    "EnterpriseRetentionObservation",
    "EnterpriseRetentionReadResult",
    "EnterpriseRetentionResourceResult",
]


def __getattr__(name: str) -> type[EnterpriseRetentionCollector]:
    """Load execution support only when the collector class is requested."""
    if name == "EnterpriseRetentionCollector":
        from .collector import EnterpriseRetentionCollector

        return EnterpriseRetentionCollector
    raise AttributeError("Unknown enterprise retention export.")
