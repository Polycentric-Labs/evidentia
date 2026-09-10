"""Bounded Entra and Microsoft 365 evidence collection."""

from ._contracts import (
    EntraM365CapabilityResult,
    EntraM365CollectRequest,
    EntraM365CollectResult,
    EntraM365Diagnostic,
    EntraM365InputError,
)
from .collector import EntraM365Collector

__all__ = [
    "EntraM365CapabilityResult",
    "EntraM365CollectRequest",
    "EntraM365CollectResult",
    "EntraM365Collector",
    "EntraM365Diagnostic",
    "EntraM365InputError",
]
