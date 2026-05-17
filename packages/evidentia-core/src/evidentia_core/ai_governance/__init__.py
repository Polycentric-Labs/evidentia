"""AI governance primitives (v0.9.3 P2).

EU AI Act + NIST AI RMF + ISO 42001 aligned data models and a
rule-based AI risk classifier. Operators consume this via:

- :mod:`evidentia_core.ai_governance.classification` — classify an
  AI system into EU AI Act tier + NIST AI RMF applicable functions.
- :mod:`evidentia_core.ai_governance.registry` — Pydantic models +
  JSON file store for the AI system inventory.

CLI surface lives in ``evidentia ai-gov``; REST in ``/api/ai-gov/*``.

Time-aligned with EU AI Act high-risk obligations (Aug 2026).
Per the v0.9.3 cycle-open sign-off, this ships as Allen's best-effort
authoring with explicit confidence flagging + community-PR pathway
for refinement.
"""

from __future__ import annotations

from evidentia_core.ai_governance.classification import (
    AISystemClassification,
    AISystemDescriptor,
    AnnexIIIDomain,
    EUAIActTier,
    NISTAIRMFFunction,
    classify,
)
from evidentia_core.ai_governance.registry import (
    AISystemRegistryEntry,
    DeploymentStatus,
)
from evidentia_core.ai_governance.registry_store import (
    AIRegistryStore,
    get_default_registry_store,
)

__all__ = [
    "AIRegistryStore",
    "AISystemClassification",
    "AISystemDescriptor",
    "AISystemRegistryEntry",
    "AnnexIIIDomain",
    "DeploymentStatus",
    "EUAIActTier",
    "NISTAIRMFFunction",
    "classify",
    "get_default_registry_store",
]
