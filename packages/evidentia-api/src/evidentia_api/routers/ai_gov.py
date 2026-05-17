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

import contextlib
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
    get_ai_registry_dir,
)
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.security import FileLock
from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()
# v0.9.3 F-V93-Q2 review fix: REST surface emits audit events at
# parity with the CLI surface (cli/ai_gov.py). Auditors filtering on
# event.action:evidentia.ai_governance.* see both surfaces.
_log = get_logger("evidentia_api.routers.ai_gov")


# ── request / response models ─────────────────────────────────────


class RegisterRequest(BaseModel):
    descriptor: AISystemDescriptor
    provider: str = Field(min_length=1, max_length=256)
    owner: str = Field(min_length=1, max_length=256)
    deployment_status: DeploymentStatus = Field(
        default=DeploymentStatus.PROPOSED
    )


# ── idempotency (v0.9.4 P1.3 + v0.9.4 Step 5.A F-V94-Q1 closure) ──


_IDEMPOTENCY_STORE_FILENAME = "_idempotency.json"

IDEMPOTENCY_TTL_HOURS = 24.0
"""TTL on idempotency entries (v0.9.4 Step 5.A F-V94-Q1 closure).
Entries older than this are dropped at next write. 24h matches the
operator workday + the AlertDeduper default suppression window."""

IDEMPOTENCY_MAX_ENTRIES = 10_000
"""Hard cap on idempotency-store entry count. When exceeded, the
oldest entries are FIFO-evicted at write time. Matches the
``TokenBucketRateLimiter`` LRU bound. With the default 60req/min
rate-limit, this caps the store at ~2.8 hours of sustained-burst
register traffic — well above any legitimate retry pattern but
below the file-size regression threshold."""


def _idempotency_store_path() -> Path:
    """Return the path to the per-process idempotency state file."""
    return get_ai_registry_dir() / _IDEMPOTENCY_STORE_FILENAME


def _hash_request_body(body: RegisterRequest) -> str:
    """Stable SHA-256 of the canonical JSON form of the request body.

    Uses Pydantic's ``model_dump(mode='json')`` for canonical form,
    then sorts keys + dumps with ``separators=(',', ':')`` for
    bit-stable output. Idempotency-key reuse with different body
    content surfaces as a 409 via this hash mismatch.
    """
    payload = body.model_dump(mode="json")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _load_idempotency_store() -> dict[str, dict[str, str]]:
    path = _idempotency_store_path()
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    # Each entry: {key: {"body_hash": str, "system_id": str,
    # "recorded_at": isoformat-str}}. Legacy entries without
    # recorded_at are treated as epoch (will be pruned first by TTL).
    out: dict[str, dict[str, str]] = {}
    for k, v in raw.items():
        if (
            isinstance(k, str)
            and isinstance(v, dict)
            and isinstance(v.get("body_hash"), str)
            and isinstance(v.get("system_id"), str)
        ):
            entry = {
                "body_hash": v["body_hash"],
                "system_id": v["system_id"],
                "recorded_at": v.get("recorded_at", "1970-01-01T00:00:00+00:00"),
            }
            out[k] = entry
    return out


def _prune_idempotency_store(
    store: dict[str, dict[str, str]],
    *,
    now: datetime | None = None,
) -> dict[str, dict[str, str]]:
    """Apply TTL + max-entries caps to the idempotency store.

    v0.9.4 Step 5.A F-V94-Q1 closure: previously the store grew
    unbounded, accumulating ~600k entries/week at the default
    60req/min rate limit. This helper:

    1. Drops entries whose ``recorded_at`` is older than
       :data:`IDEMPOTENCY_TTL_HOURS` (default 24h).
    2. If still over :data:`IDEMPOTENCY_MAX_ENTRIES`, FIFO-evicts
       the oldest entries (by ``recorded_at`` ascending) until at
       cap.

    Pure function; returns a new dict. Called from
    :func:`_save_idempotency_store` so the on-disk file is always
    bounded.
    """
    if not store:
        return store
    now = now if now is not None else datetime.now(tz=UTC)
    ttl_cutoff = now - timedelta(hours=IDEMPOTENCY_TTL_HOURS)
    cutoff_iso = ttl_cutoff.isoformat()

    # Drop entries older than the TTL.
    fresh = {
        k: v for k, v in store.items() if v.get("recorded_at", "") >= cutoff_iso
    }

    # If still over cap, FIFO-evict oldest by recorded_at ascending.
    if len(fresh) > IDEMPOTENCY_MAX_ENTRIES:
        sorted_keys = sorted(
            fresh.keys(), key=lambda k: fresh[k].get("recorded_at", "")
        )
        keep_keys = set(sorted_keys[-IDEMPOTENCY_MAX_ENTRIES:])
        fresh = {k: v for k, v in fresh.items() if k in keep_keys}

    return fresh


def _save_idempotency_store(store: dict[str, dict[str, str]]) -> None:
    """Atomically write the idempotency store, pruning TTL + cap first."""
    pruned = _prune_idempotency_store(store)
    path = _idempotency_store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    try:
        tmp.write_text(
            json.dumps(pruned, indent=2, sort_keys=True), encoding="utf-8"
        )
        tmp.replace(path)
    except OSError:
        # v0.9.4 Step 5.A F-V94-Q3 partial closure: clean up the
        # orphaned .tmp on write failure so disk-full / permission
        # errors don't accumulate sidecar artifacts. Note: the
        # shared atomic_write_text helper is a v0.9.5 follow-up;
        # this is the inline mitigation for the idempotency-store
        # call site specifically.
        with contextlib.suppress(OSError):
            tmp.unlink(missing_ok=True)
        raise


# ── classify ──────────────────────────────────────────────────────


@router.post("/ai-gov/classify")
async def ai_gov_classify(
    descriptor: AISystemDescriptor,
) -> AISystemClassification:
    """One-shot AI system classification. No persistence."""
    classification = classify(descriptor)
    _log.info(
        action=EventAction.AI_SYSTEM_CLASSIFIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {descriptor.name!r} classified "
            f"(tier={classification.eu_ai_act_tier})"
        ),
        evidentia={
            "descriptor_name": descriptor.name,
            "eu_ai_act_tier": str(classification.eu_ai_act_tier),
        },
    )
    return classification


# ── register ──────────────────────────────────────────────────────


@router.post("/ai-gov/register")
async def ai_gov_register(
    body: RegisterRequest,
    x_idempotency_key: str | None = Header(
        default=None,
        alias="X-Idempotency-Key",
        max_length=128,
        description=(
            "Optional client-supplied idempotency key. Same key + "
            "same body returns the prior system_id without creating "
            "a duplicate. Same key + different body returns 409."
        ),
    ),
) -> dict[str, Any]:
    """Classify + persist an AI system. Returns the registry entry.

    Idempotency (v0.9.4 P1.3): set the ``X-Idempotency-Key`` header
    to make this call safely retryable. The server stores a
    ``key → (body_hash, system_id)`` mapping in a sidecar file
    inside ``EVIDENTIA_AI_REGISTRY_DIR``; replay with the same key
    + body returns the original ``system_id`` (no duplicate
    creation). Replay with the same key + different body returns
    ``409 Conflict``. Closes v0.9.3 F-V93-S10 LOW (no duplicate-
    name detection).
    """
    body_hash = _hash_request_body(body)

    if x_idempotency_key is not None:
        # Lock the idempotency-store read-modify-write to prevent
        # racing concurrent retries from creating duplicates.
        lock_path = _idempotency_store_path().with_suffix(
            _idempotency_store_path().suffix + ".lock"
        )
        with FileLock(lock_path, timeout_seconds=5.0):
            store = _load_idempotency_store()
            existing = store.get(x_idempotency_key)
            if existing is not None:
                if existing["body_hash"] == body_hash:
                    # Idempotent replay: return prior system_id.
                    prior_entry = AIRegistryStore().load(
                        existing["system_id"]
                    )
                    return {
                        "system_id": existing["system_id"],
                        "entry": (
                            prior_entry.model_dump(mode="json")
                            if prior_entry is not None
                            else None
                        ),
                        "idempotent_replay": True,
                    }
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"Idempotency-Key {x_idempotency_key!r} was "
                        f"previously used with a different request "
                        f"body. Use a fresh key or send the original "
                        f"body."
                    ),
                )

            # Fresh key path: create entry, then record.
            classification = classify(body.descriptor)
            entry = AISystemRegistryEntry(
                descriptor=body.descriptor,
                classification=classification,
                provider=body.provider,
                owner=body.owner,
                deployment_status=body.deployment_status,
            )
            AIRegistryStore().save(entry)
            store[x_idempotency_key] = {
                "body_hash": body_hash,
                "system_id": entry.system_id,
                "recorded_at": datetime.now(tz=UTC).isoformat(),
            }
            _save_idempotency_store(store)
    else:
        # No idempotency key: standard create path.
        classification = classify(body.descriptor)
        entry = AISystemRegistryEntry(
            descriptor=body.descriptor,
            classification=classification,
            provider=body.provider,
            owner=body.owner,
            deployment_status=body.deployment_status,
        )
        AIRegistryStore().save(entry)

    _log.info(
        action=EventAction.AI_SYSTEM_REGISTERED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {entry.descriptor.name!r} registered "
            f"(system_id={entry.system_id})"
        ),
        evidentia={
            "system_id": entry.system_id,
            "descriptor_name": entry.descriptor.name,
            "eu_ai_act_tier": str(entry.classification.eu_ai_act_tier),
            "provider": entry.provider,
            "owner": entry.owner,
            "deployment_status": str(entry.deployment_status),
            "idempotency_key": x_idempotency_key,
        },
    )
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
        # v0.9.3 F-V93-Q7 review fix: drop redundant str() — Pydantic
        # round-trips eu_ai_act_tier as the raw string value (the model
        # sets use_enum_values=True), so direct equality is correct and
        # robust to future model-config changes.
        entries = [
            e
            for e in entries
            if e.classification.eu_ai_act_tier == tier_enum.value
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
    if removed:
        # v0.9.4 Step 5.A F-V94-Q12 closure: emit the new
        # AI_SYSTEM_DELETED action (instead of overloading
        # AI_SYSTEM_RETIRED) so auditors can distinguish hard-delete
        # from lifecycle-retirement by event.action alone.
        _log.info(
            action=EventAction.AI_SYSTEM_DELETED,
            outcome=EventOutcome.SUCCESS,
            message=f"AI system registry entry {system_id!r} hard-deleted",
            evidentia={"system_id": system_id},
        )
    return {"system_id": system_id, "removed": removed}
