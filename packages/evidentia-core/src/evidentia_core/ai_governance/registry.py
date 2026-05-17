"""AI system inventory data model (v0.9.3 P2.4).

Pydantic models for registering AI systems in the operator's
governance inventory. Each entry links a descriptor to its
classification + deployment status + responsible operator.

Storage lives in :mod:`evidentia_core.ai_governance.registry_store`
(JSON file-backed; mirrors v0.7.9 vendor_store + v0.9.0 poam_store
pattern).
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import Field

from evidentia_core.ai_governance.classification import (
    AISystemClassification,
    AISystemDescriptor,
)
from evidentia_core.models.common import EvidentiaModel, new_id, utc_now


class DeploymentStatus(str, Enum):
    """Operational lifecycle status of a registered AI system."""

    PROPOSED = "proposed"
    """Identified as a candidate; not yet in development."""

    IN_DEVELOPMENT = "in_development"
    """Active build / training / integration phase."""

    PILOT = "pilot"
    """Limited production use; observed via CONMON cadences."""

    PRODUCTION = "production"
    """Full deployment; subject to all applicable governance
    obligations (Article 9 risk management, etc. for HIGH tier)."""

    RETIRED = "retired"
    """No longer in use; record retained for audit history."""


class AISystemRegistryEntry(EvidentiaModel):
    """One AI system in the operator's governance inventory."""

    system_id: str = Field(
        default_factory=new_id,
        description="Stable UUID v4 string; assigned at registration time.",
    )
    descriptor: AISystemDescriptor = Field(
        description="Operator-supplied use-case attributes."
    )
    classification: AISystemClassification = Field(
        description=(
            "Result of running the classifier over the descriptor. "
            "Re-classify + persist via `evidentia ai-gov update` "
            "when the descriptor changes."
        ),
    )
    provider: str = Field(
        min_length=1,
        max_length=256,
        description=(
            "Who built or supplies the AI system (vendor name, "
            "in-house team name, or 'self-built')."
        ),
    )
    owner: str = Field(
        min_length=1,
        max_length=256,
        description="Responsible person or team within operator org.",
    )
    deployment_status: DeploymentStatus = Field(
        default=DeploymentStatus.PROPOSED,
        description="Where in the lifecycle this system sits.",
    )
    linked_controls: list[str] = Field(
        default_factory=list,
        description=(
            "Catalog control IDs (e.g., 'AIA.Art.9', 'GOVERN-1.1') "
            "the operator considers applicable to this system. "
            "Free-form; not validated against catalog content here."
        ),
    )
    last_assessed_at: datetime | None = Field(
        default=None,
        description=(
            "When the operator last reviewed the descriptor + "
            "classification against the live system. Null on "
            "initial registration; bump on each review."
        ),
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        description="Registration timestamp; never mutated.",
    )
    updated_at: datetime = Field(
        default_factory=utc_now,
        description="Last persistence timestamp; bumped on save.",
    )
