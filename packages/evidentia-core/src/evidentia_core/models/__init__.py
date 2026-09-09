"""Pydantic data models for Evidentia."""

from evidentia_core.models.catalog import (
    CatalogControl,
    CatalogSourceRow,
    ControlCatalog,
    CrosswalkDefinition,
    FrameworkMapping,
    RelationshipType,
    StatementRow,
    TextDepth,
    derive_text_depth,
    has_statement,
)
from evidentia_core.models.common import (
    ControlMapping,
    EvidentiaModel,
    Severity,
    current_version,
    new_id,
    utc_now,
)
from evidentia_core.models.control import (
    ControlImplementation,
    ControlInventory,
    ControlStatus,
)
from evidentia_core.models.evidence import (
    EvidenceArtifact,
    EvidenceBundle,
    EvidenceSufficiency,
    EvidenceType,
)

# v0.7.0: evidentia_core.models.finding is NOT re-exported from this
# package root because it pulls in evidentia_core.audit.provenance,
# which itself depends on evidentia_core.models.common — eager re-export
# here creates a circular import when ``audit`` is loaded first (e.g.,
# by a collector). Callers should ``from evidentia_core.models.finding
# import SecurityFinding, FindingStatus`` directly. No production code
# used the convenience path before v0.7.0.
from evidentia_core.models.gap import (
    ControlGap,
    EfficiencyOpportunity,
    GapAnalysisReport,
    GapSeverity,
    GapStatus,
    ImplementationEffort,
)
from evidentia_core.models.obligation import (
    ObligationCatalog,
    PrivacyObligation,
    PrivacyRegime,
    SubjectRight,
)

# v0.7.1: evidentia_core.models.risk is NOT re-exported from this
# package root for the same reason as finding (above) — risk.py now
# carries a ``GenerationContext`` field which lives in
# ``evidentia_core.audit.provenance``, and that module already imports
# ``EvidentiaModel`` from ``models.common``. Eager re-export here would
# trigger a circular import on first ``audit.*`` access. Callers must
# ``from evidentia_core.models.risk import RiskStatement, RiskRegister, ...``
# directly. All existing callers already do.
from evidentia_core.models.threat import (
    AttackTechnique,
    TechniqueCatalog,
    ThreatCategory,
    Vulnerability,
    VulnerabilityCatalog,
)
from evidentia_core.models.tprm import (
    CriticalityTier,
    EvidenceRef,
    FourthParty,
    RegulatoryClassification,
    Vendor,
    VendorType,
)

# v0.3.0: ``FrameworkId`` removed (was deprecated in v0.2.0; the module-level
# ``__getattr__`` that emitted the DeprecationWarning is gone, and no
# production code references it — only the deprecation-warning test did,
# which has also been removed).

__all__ = [
    "AttackTechnique",
    "CatalogControl",
    "CatalogSourceRow",
    "ControlCatalog",
    "ControlGap",
    "ControlImplementation",
    "ControlInventory",
    "ControlMapping",
    "ControlStatus",
    "CriticalityTier",
    "CrosswalkDefinition",
    "EfficiencyOpportunity",
    "EvidenceArtifact",
    "EvidenceBundle",
    "EvidenceRef",
    "EvidenceSufficiency",
    "EvidenceType",
    "EvidentiaModel",
    "FourthParty",
    "FrameworkMapping",
    "GapAnalysisReport",
    "GapSeverity",
    "GapStatus",
    "ImplementationEffort",
    "ObligationCatalog",
    "PrivacyObligation",
    "PrivacyRegime",
    "RegulatoryClassification",
    "RelationshipType",
    "Severity",
    "StatementRow",
    "SubjectRight",
    "TechniqueCatalog",
    "TextDepth",
    "ThreatCategory",
    "Vendor",
    "VendorType",
    "Vulnerability",
    "VulnerabilityCatalog",
    "current_version",
    "derive_text_depth",
    "has_statement",
    "new_id",
    "utc_now",
]
