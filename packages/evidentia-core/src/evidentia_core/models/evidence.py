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
    # ── Append-only versioning (v0.9.5 P3.2) ─────────────────────────
    # All three fields Optional + backward-compat with v0.7.x → v0.9.4
    # artifacts (deserializing legacy JSON populates them as
    # ``version=1`` + ``lineage_id=None`` + ``predecessor_id=None``).
    # The lineage chain semantics:
    #
    # - **First version of an artifact**: ``version=1``,
    #   ``lineage_id=self.id`` OR ``None`` (both equivalent — the
    #   artifact IS the root). ``predecessor_id=None``.
    # - **Subsequent versions**: NEW ``id`` (fresh UUID), same
    #   ``lineage_id`` as the root, ``predecessor_id=`` the prior
    #   version's ``id``, ``version=N+1``.
    #
    # The :func:`new_version` factory helper constructs N+1 from N
    # in one call. Stores should treat lineage-chained artifacts as
    # IMMUTABLE: once a version is persisted, its content cannot
    # change. Edits create N+1; deletes mark the lineage tombstoned
    # via a follow-up sentinel artifact (deferred to v0.9.6
    # store-side enforcement). For v0.9.5, the fields are present
    # on the model + a helper ships; the actual append-only
    # store-side enforcement (WORM integration) lands in v0.9.6.
    version: int = Field(
        default=1,
        ge=1,
        description=(
            "v0.9.5 P3.2: sequence number within the artifact's "
            "lineage chain. First version = 1; each subsequent edit "
            "creates a new artifact with version=N+1. Backward-"
            "compat default of 1 means v0.7.x → v0.9.4 artifacts "
            "load as version 1 of their own (single-element) chain."
        ),
    )
    lineage_id: str | None = Field(
        default=None,
        description=(
            "v0.9.5 P3.2: UUID identifying the lineage chain across "
            "versions. When ``None`` (default), the artifact IS the "
            "lineage root + the ``id`` field serves as the implicit "
            "lineage_id. Set explicitly on versions > 1 to point at "
            "the chain root."
        ),
    )
    predecessor_id: str | None = Field(
        default=None,
        description=(
            "v0.9.5 P3.2: ``id`` of the prior version in the lineage "
            "chain. ``None`` for the lineage root (version 1). "
            "Allows ``evidentia evidence show <lineage_id> --version "
            "N`` to walk the chain to the target version."
        ),
    )

    @property
    def effective_lineage_id(self) -> str:
        """Return the canonical lineage identifier.

        v0.9.5 P3.2: when ``lineage_id`` is explicitly set, it's the
        canonical chain ID. Otherwise the artifact's own ``id`` IS
        the lineage root + serves as the implicit lineage_id.
        Centralizes the "chain root resolution" logic so callers
        don't repeat the ``lineage_id or id`` ternary at every use.
        """
        return self.lineage_id if self.lineage_id is not None else self.id

    def new_version(self, **field_updates: object) -> EvidenceArtifact:
        """Construct the next version in this artifact's lineage chain.

        v0.9.5 P3.2 helper. Returns a NEW :class:`EvidenceArtifact`
        with:

        - ``version = self.version + 1``
        - ``lineage_id = self.effective_lineage_id``
        - ``predecessor_id = self.id``
        - ``id`` = fresh UUID (always a new artifact)
        - All other fields copy from ``self``, then ``field_updates``
          override (validated through Pydantic's ``model_validate``
          so field validators run on the new version — matches the
          v0.9.5 F-V94-S12 model-copy-validator pattern).

        Example::

            v1 = EvidenceArtifact(...)
            store.save(v1)
            v2 = v1.new_version(
                content={"updated": "payload"},
                collected_at=utc_now(),
            )
            store.save(v2)  # store enforces append-only: cannot overwrite v1
        """
        base = self.model_dump(mode="python")
        # Force a fresh UUID for the new version — DO NOT carry the
        # prior ``id`` over.
        base.pop("id", None)
        base.update(field_updates)
        base["version"] = self.version + 1
        base["lineage_id"] = self.effective_lineage_id
        base["predecessor_id"] = self.id
        # collected_at default-refreshes via the default_factory; the
        # caller can override via field_updates if they want to
        # preserve the original collection time.
        return type(self).model_validate(base)

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
