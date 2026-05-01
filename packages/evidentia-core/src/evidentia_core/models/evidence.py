"""Evidence artifact and bundle models.

Represents compliance evidence collected from systems or uploaded manually.
Evidence is the proof that a control is implemented and operating effectively.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import Field

from evidentia_core.models.common import (
    ControlMapping,
    EvidentiaModel,
    current_version,
    new_id,
    utc_now,
)


class EvidenceType(str, Enum):
    """Classification of evidence artifacts by type."""

    CONFIGURATION = "configuration"
    LOG = "log"
    SCREENSHOT = "screenshot"
    POLICY_DOCUMENT = "policy_document"
    AUDIT_REPORT = "audit_report"
    API_RESPONSE = "api_response"
    TEST_RESULT = "test_result"
    ATTESTATION = "attestation"
    REPOSITORY_METADATA = "repository_metadata"
    IDENTITY_DATA = "identity_data"


class EvidenceSufficiency(str, Enum):
    """AI-assessed sufficiency of evidence for a control."""

    SUFFICIENT = "sufficient"
    PARTIAL = "partial"
    INSUFFICIENT = "insufficient"
    STALE = "stale"
    UNKNOWN = "unknown"


class EvidenceArtifact(EvidentiaModel):
    """A single piece of compliance evidence.

    An artifact represents one discrete piece of proof that a control is
    implemented and operating effectively. Artifacts are collected by
    collectors (automated) or uploaded manually.
    """

    id: str = Field(
        default_factory=new_id,
        description="Unique identifier (UUID v4)",
    )
    title: str = Field(
        description="Human-readable title describing what this evidence shows",
    )
    description: str | None = Field(
        default=None,
        description="Detailed description of the evidence content and context",
    )
    evidence_type: EvidenceType = Field(
        description="Classification of this evidence artifact",
    )
    source_system: str = Field(
        description="System that produced this evidence",
    )
    collected_at: datetime = Field(
        default_factory=utc_now,
        description="When this evidence was collected (UTC)",
    )
    collected_by: str = Field(
        description="Collector name or user email that produced this evidence",
    )
    # Content
    content: Any | None = Field(
        default=None,
        description="The actual evidence content",
    )
    content_hash: str | None = Field(
        default=None,
        description="SHA-256 hash of content for tamper detection",
    )
    content_format: str = Field(
        default="json",
        description="Format of content: 'json', 'text', 'base64', 'html'",
    )
    file_path: str | None = Field(
        default=None,
        description="Path to the evidence file if stored on disk",
    )
    file_size_bytes: int | None = Field(
        default=None,
        description="Size of the evidence file in bytes",
    )
    # Control mappings
    control_mappings: list[ControlMapping] = Field(
        default_factory=list,
        description="Controls that this evidence supports, across one or more frameworks",
    )
    # Validation (populated by evidence validator)
    sufficiency: EvidenceSufficiency = Field(
        default=EvidenceSufficiency.UNKNOWN,
        description="AI-assessed sufficiency of this evidence for its mapped controls",
    )
    sufficiency_rationale: str | None = Field(
        default=None,
        description="Explanation of the sufficiency assessment",
    )
    missing_elements: list[str] = Field(
        default_factory=list,
        description="Elements needed to make this evidence sufficient",
    )
    validator_confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Validator confidence in the sufficiency assessment (0.0–1.0)",
    )
    validated_at: datetime | None = Field(
        default=None,
        description="When the sufficiency assessment was performed",
    )
    validated_by: str | None = Field(
        default=None,
        description="Model or person that performed the validation",
    )
    # Staleness
    expires_at: datetime | None = Field(
        default=None,
        description="When this evidence becomes stale",
    )
    # Metadata
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Collector-specific metadata (region, account ID, etc.)",
    )

    def compute_hash(self) -> str:
        """Compute SHA-256 hash of content for tamper detection."""
        if self.content is not None:
            content_str = json.dumps(self.content, sort_keys=True, default=str)
            self.content_hash = hashlib.sha256(content_str.encode()).hexdigest()
        elif self.file_path:
            h = hashlib.sha256()
            with open(self.file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            self.content_hash = h.hexdigest()
        return self.content_hash or ""

    @property
    def is_stale(self) -> bool:
        """Check if this evidence has passed its expiration date."""
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at


class EvidenceBundle(EvidentiaModel):
    """A collection of evidence artifacts for an assessment scope."""

    id: str = Field(default_factory=new_id)
    title: str = Field(
        description="Bundle title, e.g. 'SOC 2 Type II Evidence — Q1 2026'",
    )
    assessment_scope: str = Field(
        description="What this bundle covers, e.g. 'SOC 2 Type II 2026'",
    )
    frameworks: list[str] = Field(
        description="Frameworks this evidence bundle supports",
    )
    artifacts: list[EvidenceArtifact] = Field(
        default_factory=list,
        description="Evidence artifacts in this bundle",
    )
    created_at: datetime = Field(default_factory=utc_now)
    created_by: str = Field(
        description="User or process that created this bundle",
    )
    valid_until: datetime | None = Field(
        default=None,
        description="When this bundle expires (e.g., end of audit period)",
    )
    notes: str | None = Field(default=None)
    evidentia_version: str = Field(
        default_factory=current_version,
        description="Version of evidentia-core that produced this bundle",
    )

    @property
    def artifact_count(self) -> int:
        return len(self.artifacts)

    @property
    def sufficient_count(self) -> int:
        return sum(
            1
            for a in self.artifacts
            if a.sufficiency == EvidenceSufficiency.SUFFICIENT.value
        )

    @property
    def stale_count(self) -> int:
        return sum(1 for a in self.artifacts if a.is_stale)

    def coverage_by_control(self) -> dict[str, list[EvidenceArtifact]]:
        """Group artifacts by control mapping for coverage analysis."""
        coverage: dict[str, list[EvidenceArtifact]] = {}
        for artifact in self.artifacts:
            for mapping in artifact.control_mappings:
                key = f"{mapping.framework}:{mapping.control_id}"
                coverage.setdefault(key, []).append(artifact)
        return coverage
