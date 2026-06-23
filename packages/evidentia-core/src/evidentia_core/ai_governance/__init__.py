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
from evidentia_core.ai_governance.fips199 import (
    FIPS199Categorization,
    FIPS199Impact,
)
from evidentia_core.ai_governance.omb_m_24_10 import (
    OMBImpactCategory,
    triggers_minimum_practices,
)
from evidentia_core.ai_governance.omb_m_25_21 import (
    HighImpactBasis,
    HighImpactDetermination,
    OMBHighImpactAssessment,
    crosswalk_from_legacy,
)
from evidentia_core.ai_governance.registry import (
    AISystemRegistryEntry,
    ATOReference,
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
    "ATOReference",
    "AnnexIIIDomain",
    "DeploymentStatus",
    "EUAIActTier",
    "FIPS199Categorization",
    "FIPS199Impact",
    "HighImpactBasis",
    "HighImpactDetermination",
    "NISTAIRMFFunction",
    "OMBHighImpactAssessment",
    "OMBImpactCategory",
    "classify",
    "crosswalk_from_legacy",
    "get_default_registry_store",
    "triggers_minimum_practices",
]
