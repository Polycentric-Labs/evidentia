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

from evidentia_core.ai_governance.acquisition_store import (
    AIAcquisitionStore,
    get_ai_acquisition_dir,
)
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
    MinimumPractice,
    MinimumPracticeRecord,
    OMBHighImpactAssessment,
    PracticeComplianceSummary,
    PracticeStatus,
    PracticeWaiver,
    crosswalk_from_legacy,
    practice_compliance,
    waiver_certification_due,
    waiver_omb_report_overdue,
)
from evidentia_core.ai_governance.omb_m_25_22 import (
    AcquisitionPhase,
    AcquisitionPhaseRecord,
    AcquisitionPhaseStatus,
    AcquisitionProgressSummary,
    AIAcquisition,
    acquisition_progress,
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
    "AIAcquisition",
    "AIAcquisitionStore",
    "AIRegistryStore",
    "AISystemClassification",
    "AISystemDescriptor",
    "AISystemRegistryEntry",
    "ATOReference",
    "AcquisitionPhase",
    "AcquisitionPhaseRecord",
    "AcquisitionPhaseStatus",
    "AcquisitionProgressSummary",
    "AnnexIIIDomain",
    "DeploymentStatus",
    "EUAIActTier",
    "FIPS199Categorization",
    "FIPS199Impact",
    "HighImpactBasis",
    "HighImpactDetermination",
    "MinimumPractice",
    "MinimumPracticeRecord",
    "NISTAIRMFFunction",
    "OMBHighImpactAssessment",
    "OMBImpactCategory",
    "PracticeComplianceSummary",
    "PracticeStatus",
    "PracticeWaiver",
    "acquisition_progress",
    "classify",
    "crosswalk_from_legacy",
    "get_ai_acquisition_dir",
    "get_default_registry_store",
    "practice_compliance",
    "triggers_minimum_practices",
    "waiver_certification_due",
    "waiver_omb_report_overdue",
]
