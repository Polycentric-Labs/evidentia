"""AI governance router — v0.9.3 P2.5.

REST surface for the v0.9.3 P2 AI governance work. Endpoints
under ``/api/ai-gov`` mirror the CLI verbs:

  - ``POST   /api/ai-gov/classify`` — one-shot classification
  - ``POST   /api/ai-gov/register`` — classify + persist
  - ``GET    /api/ai-gov/systems`` — list registered systems with
    optional ``?tier=`` filter
  - ``GET    /api/ai-gov/systems/{system_id}`` — get single entry
  - ``DELETE /api/ai-gov/systems/{system_id}`` — remove entry

Auth posture: open (matches v0.9.0 POA&M router + v0.9.1 CONMON
router; transport auth applied at the app layer via
AuthProviderMiddleware).
"""

from __future__ import annotations

from typing import Any

from evidentia_core.ai_governance import (
    AIRegistryStore,
    AISystemClassification,
    AISystemDescriptor,
    AISystemRegistryEntry,
    DeploymentStatus,
    EUAIActTier,
    classify,
)
from evidentia_core.ai_governance.registry_store import (
    InvalidAISystemIdError,
)
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()


# ── request / response models ─────────────────────────────────────


class RegisterRequest(BaseModel):
    descriptor: AISystemDescriptor
    provider: str = Field(min_length=1, max_length=256)
    owner: str = Field(min_length=1, max_length=256)
    deployment_status: DeploymentStatus = Field(
        default=DeploymentStatus.PROPOSED
    )


# ── classify ──────────────────────────────────────────────────────


@router.post("/ai-gov/classify")
async def ai_gov_classify(
    descriptor: AISystemDescriptor,
) -> AISystemClassification:
    """One-shot AI system classification. No persistence."""
    return classify(descriptor)


# ── register ──────────────────────────────────────────────────────


@router.post("/ai-gov/register")
async def ai_gov_register(body: RegisterRequest) -> dict[str, Any]:
    """Classify + persist an AI system. Returns the registry entry."""
    classification = classify(body.descriptor)
    entry = AISystemRegistryEntry(
        descriptor=body.descriptor,
        classification=classification,
        provider=body.provider,
        owner=body.owner,
        deployment_status=body.deployment_status,
    )
    AIRegistryStore().save(entry)
    return {
        "system_id": entry.system_id,
        "entry": entry.model_dump(mode="json"),
    }


# ── list ──────────────────────────────────────────────────────────


@router.get("/ai-gov/systems")
async def ai_gov_list_systems(
    tier: str | None = Query(
        default=None,
        description=(
            "Optional EU AI Act tier filter: unacceptable, high, "
            "limited, minimal."
        ),
    ),
) -> list[dict[str, Any]]:
    """List registered AI systems with optional tier filter."""
    entries = AIRegistryStore().list_all()
    if tier is not None:
        try:
            tier_enum = EUAIActTier(tier)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Unknown tier {tier!r}; valid: "
                    f"{', '.join(t.value for t in EUAIActTier)}"
                ),
            ) from exc
        entries = [
            e
            for e in entries
            if str(e.classification.eu_ai_act_tier) == tier_enum.value
        ]
    return [e.model_dump(mode="json") for e in entries]


# ── show ──────────────────────────────────────────────────────────


@router.get("/ai-gov/systems/{system_id}")
async def ai_gov_get_system(system_id: str) -> dict[str, Any]:
    """Fetch a single registered AI system by ID."""
    try:
        entry = AIRegistryStore().load(system_id)
    except InvalidAISystemIdError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if entry is None:
        raise HTTPException(
            status_code=404,
            detail=f"No registered AI system with ID {system_id!r}",
        )
    return entry.model_dump(mode="json")


# ── delete ────────────────────────────────────────────────────────


@router.delete("/ai-gov/systems/{system_id}")
async def ai_gov_delete_system(system_id: str) -> dict[str, Any]:
    """Remove a registered AI system. Returns whether a record was
    actually removed (idempotent: no-op on unknown ID)."""
    try:
        removed = AIRegistryStore().delete(system_id)
    except InvalidAISystemIdError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"system_id": system_id, "removed": removed}
