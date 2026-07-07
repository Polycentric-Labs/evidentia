"""AI governance router — v0.9.3 P2.5; v0.10.12 mutation verbs.

REST surface for the v0.9.3 P2 AI governance work. Endpoints
under ``/api/ai-gov`` mirror the CLI verbs:

  - ``POST   /api/ai-gov/classify`` — one-shot classification
  - ``POST   /api/ai-gov/register`` — classify + persist
  - ``GET    /api/ai-gov/systems`` — list registered systems with
    optional ``?tier=`` filter
  - ``GET    /api/ai-gov/systems/{system_id}`` — get single entry
  - ``PUT    /api/ai-gov/systems/{system_id}`` — partial-update a
    registration (v0.10.12; mirrors ``ai-gov update``)
  - ``POST   /api/ai-gov/systems/{system_id}/retire`` — lifecycle
    retirement, entry preserved (v0.10.12; mirrors ``ai-gov retire``)
  - ``POST   /api/ai-gov/systems/{system_id}/categorize-fips`` — set
    FIPS 199 categorization (v0.10.12; mirrors ``ai-gov
    categorize-fips``)
  - ``POST   /api/ai-gov/systems/{system_id}/set-omb-impact`` — set
    legacy OMB M-24-10 impact category (v0.10.12; mirrors ``ai-gov
    set-omb-impact``; DEPRECATED — M-24-10 rescinded 2025-04-03)
  - ``POST   /api/ai-gov/systems/{system_id}/set-high-impact`` — set
    OMB M-25-21 high-impact determination (v0.10.12; mirrors ``ai-gov
    set-high-impact``)
  - ``DELETE /api/ai-gov/systems/{system_id}`` — remove entry

Auth posture: reads are open (matches v0.9.0 POA&M router + v0.9.1
CONMON router; transport auth applied at the app layer via
AuthProviderMiddleware). The v0.10.12 mutation verbs carry an opt-in
``require_role("write")`` RBAC gate — inert under the default
permissive policy, denying under an operator-configured deny-by-
default policy (matches the governance router).
"""

from __future__ import annotations

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
    FIPS199Categorization,
    FIPS199Impact,
    HighImpactBasis,
    HighImpactDetermination,
    OMBHighImpactAssessment,
    OMBImpactCategory,
    classify,
)
from evidentia_core.ai_governance.registry_store import (
    InvalidAISystemIdError,
    get_ai_registry_dir,
)
from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.security import FileLock, atomic_write_text
from fastapi import APIRouter, Header, Query
from fastapi import Path as FastAPIPath
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from evidentia_api.errors import (
    BODY_PARSE_ERROR_400,
    RATE_LIMITED_429,
    RBAC_DENIED_403,
    api_error,
    error_responses,
)
from evidentia_api.rbac_dependency import require_role

router = APIRouter()
# v0.9.3 F-V93-Q2 review fix: REST surface emits audit events at
# parity with the CLI surface (cli/ai_gov.py). Auditors filtering on
# event.action:evidentia.ai_governance.* see both surfaces.
_log = get_logger("evidentia_api.routers.ai_gov")


# ── request / response models ─────────────────────────────────────


_SYSTEM_ID_UUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_SYSTEM_ID_PATH = FastAPIPath(
    description="Registered AI system ID (UUID).",
    # 2026-07-06 stateful-DAST finding (H-2 Step 4): the path param was
    # undecorated ``str`` — any string is "positive data" per the
    # published schema, so schemathesis's positive_data_acceptance
    # check flagged the route's legitimate 400 (``invalid_id``, via
    # ``_validate_id_shape``'s ``UUID(system_id)`` parse) as rejecting
    # schema-valid data. ``json_schema_extra`` (NOT ``pattern=``,
    # which Pydantic would enforce as an ACTUAL request-validation
    # constraint, turning today's manual 400/404 into an automatic
    # 422 — a real behavior change this deliverable must not make)
    # documents the shape for schemathesis/the OpenAPI doc with zero
    # runtime effect, mirroring the docs-only json_schema_extra
    # pattern used elsewhere (EvidenceRef, UpdateSystemRequest). The
    # pattern mirrors the DOMINANT accepted shape (canonical hyphenated
    # UUID); it's narrower than ``uuid.UUID()`` itself (which also
    # accepts hyphen-less/URN/brace-wrapped forms) but that's fine —
    # the goal is to steer generation toward realistic positive
    # examples, not exhaustively enumerate every tolerated textual
    # form. Applied only to the three ops this DAST suite's OpenAPI
    # links target (GET/PUT/DELETE); the other system_id-bearing verbs
    # (retire/categorize-fips/set-omb-impact/set-high-impact) are out
    # of this deliverable's scope.
    json_schema_extra={"pattern": _SYSTEM_ID_UUID_PATTERN},
)


class RegisterRequest(BaseModel):
    # A documented valid example: seeds schemathesis's explicit phase so
    # the stateful DAST suite can reliably create a system (the complex
    # descriptor body is otherwise rarely generated valid) and then walk
    # the register -> get/put/delete lifecycle. Also improves the
    # generated OpenAPI docs / UI "try it out" defaults.
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "descriptor": {
                        "name": "resume-screener",
                        "purpose": "Score job applicants for interview shortlisting",
                    },
                    "provider": "acme-corp",
                    "owner": "risk-team",
                    "deployment_status": "production",
                }
            ]
        }
    )

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
    # v0.9.5 P1.5: now uses the shared atomic_write_text helper
    # (previously inline at this call site per v0.9.4 Step 5.A
    # F-V94-Q3 closure). Helper centralizes .tmp cleanup behavior.
    atomic_write_text(
        path,
        json.dumps(pruned, indent=2, sort_keys=True),
    )


# ── classify ──────────────────────────────────────────────────────


@router.post(
    "/ai-gov/classify",
    responses=error_responses({429: RATE_LIMITED_429}),
)
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


@router.post(
    "/ai-gov/register",
    responses=error_responses(
        {
            400: (
                "Body-content/id validation failure "
                "(``error: invalid_body``), or an undecodable request "
                f"body ({BODY_PARSE_ERROR_400})."
            ),
            409: (
                "``X-Idempotency-Key`` reuse with a different body "
                "(``error: idempotency_key_conflict``)."
            ),
            429: RATE_LIMITED_429,
        }
    ),
    # 2026-07-06 stateful-DAST prep (Step 2): OpenAPI ``links`` giving
    # schemathesis's stateful state machine real create -> read/update/
    # delete transitions to walk over the ai-gov lifecycle, chaining off
    # this response's ``system_id``. FastAPI deep-merges ``openapi_extra``
    # onto the operation object, so this coexists with the ``responses=``
    # 4xx documentation above rather than clobbering it (verified via
    # ``scripts/dump_openapi.py`` post-merge).
    openapi_extra={
        "responses": {
            "200": {
                "links": {
                    "GetSystem": {
                        "operationId": (
                            "ai_gov_get_system_api_ai_gov_systems"
                            "__system_id__get"
                        ),
                        "parameters": {
                            "system_id": "$response.body#/system_id"
                        },
                    },
                    "UpdateSystem": {
                        "operationId": (
                            "ai_gov_update_system_api_ai_gov_systems"
                            "__system_id__put"
                        ),
                        "parameters": {
                            "system_id": "$response.body#/system_id"
                        },
                    },
                    "DeleteSystem": {
                        "operationId": (
                            "ai_gov_delete_system_api_ai_gov_systems"
                            "__system_id__delete"
                        ),
                        "parameters": {
                            "system_id": "$response.body#/system_id"
                        },
                    },
                }
            }
        }
    },
)
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

    **Replay-after-target-deleted semantics** (v0.9.5 F-V94-Q2
    documentation): if the original ``system_id`` has been deleted
    from the registry between the original request and a replay,
    the replay still returns the original ``system_id`` plus
    ``entry: null`` (the prior entry no longer exists). Operators
    treating the absence of ``entry`` as authoritative will detect
    the deletion; operators treating the response as "request
    accepted, ok to retire idempotency-key" will continue using
    the same key. We deliberately do NOT auto-create a new entry
    on this code path — that would mask the deletion + violate the
    "same key = same result" guarantee. Test coverage:
    ``test_register_replay_after_delete_returns_null_entry``.
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
                raise api_error(
                    409,
                    "idempotency_key_conflict",
                    (
                        f"Idempotency-Key {x_idempotency_key!r} was "
                        f"previously used with a different request "
                        f"body. Use a fresh key or send the original "
                        f"body."
                    ),
                )

            # Fresh key path: create entry, then record.
            classification = classify(body.descriptor)
            try:
                entry = AISystemRegistryEntry(
                    descriptor=body.descriptor,
                    classification=classification,
                    provider=body.provider,
                    owner=body.owner,
                    deployment_status=body.deployment_status,
                )
            except (ValidationError, ValueError) as exc:
                # A field that passes RegisterRequest's raw min_length
                # but fails the registry model's post-strip validation
                # (e.g. whitespace-only provider/owner) must normalize
                # to 400, not crash to 500 — mirrors the PUT handler.
                raise api_error(400, "invalid_body", str(exc)) from exc
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
        try:
            entry = AISystemRegistryEntry(
                descriptor=body.descriptor,
                classification=classification,
                provider=body.provider,
                owner=body.owner,
                deployment_status=body.deployment_status,
            )
        except (ValidationError, ValueError) as exc:
            # See the fresh-key path above: post-strip validation
            # failure normalizes to 400, not a 500.
            raise api_error(400, "invalid_body", str(exc)) from exc
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


@router.get(
    "/ai-gov/systems",
    responses=error_responses(
        {
            400: (
                "Unknown ``tier`` filter value (``error: "
                "unknown_tier``); ``detail`` carries ``tier`` + "
                "``valid``."
            ),
        }
    ),
)
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
            # 2026-07-06 DAST (schemathesis) follow-up: structured,
            # machine-readable detail (cf. rbac_denied) — the 400 is
            # documented on the route decorator's ``responses``.
            raise api_error(
                400,
                "unknown_tier",
                (
                    f"Unknown tier {tier!r}; valid: "
                    f"{', '.join(t.value for t in EUAIActTier)}"
                ),
                tier=tier,
                valid=[t.value for t in EUAIActTier],
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


@router.get(
    "/ai-gov/systems/{system_id}",
    responses=error_responses(
        {
            400: "Malformed ``system_id`` (``error: invalid_id``).",
            404: "No such registered system (``error: not_found``).",
        }
    ),
)
async def ai_gov_get_system(
    system_id: str = _SYSTEM_ID_PATH,
) -> dict[str, Any]:
    """Fetch a single registered AI system by ID."""
    try:
        entry = AIRegistryStore().load(system_id)
    except InvalidAISystemIdError as exc:
        raise api_error(
            400, "invalid_id", str(exc), resource="ai_system"
        ) from exc
    if entry is None:
        raise api_error(
            404,
            "not_found",
            f"No registered AI system with ID {system_id!r}",
            resource="ai_system",
            resource_id=system_id,
        )
    return entry.model_dump(mode="json")


# ── delete ────────────────────────────────────────────────────────


@router.delete(
    "/ai-gov/systems/{system_id}",
    responses=error_responses(
        {400: "Malformed ``system_id`` (``error: invalid_id``)."}
    ),
)
async def ai_gov_delete_system(
    system_id: str = _SYSTEM_ID_PATH,
) -> dict[str, Any]:
    """Remove a registered AI system. Returns whether a record was
    actually removed (idempotent: no-op on unknown ID)."""
    try:
        removed = AIRegistryStore().delete(system_id)
    except InvalidAISystemIdError as exc:
        raise api_error(
            400, "invalid_id", str(exc), resource="ai_system"
        ) from exc
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


# ── mutation verbs (v0.10.12) ──────────────────────────────────────
# REST parity with the ``ai-gov update / retire / categorize-fips /
# set-omb-impact`` CLI verbs. Error-normalization mirrors the poam
# router: invalid-ID-shape + unknown-ID → 404; domain / body-content
# errors → 400; malformed request bodies → 422 (FastAPI/Pydantic
# request-validation). All four carry require_role("write").


def _load_entry_or_404(system_id: str) -> AISystemRegistryEntry:
    """Load a registry entry; raise 404 on invalid-shape OR unknown ID.

    Mirrors the poam router's load-or-404 normalization: an
    ``InvalidAISystemIdError`` (UUID shape violation) and a
    well-formed-but-absent ID both surface as 404 from the client's
    perspective.
    """
    try:
        entry = AIRegistryStore().load(system_id)
    except InvalidAISystemIdError as exc:
        raise api_error(
            404,
            "not_found",
            f"No registered AI system with ID {system_id!r}",
            resource="ai_system",
            resource_id=system_id,
        ) from exc
    if entry is None:
        raise api_error(
            404,
            "not_found",
            f"No registered AI system with ID {system_id!r}",
            resource="ai_system",
            resource_id=system_id,
        )
    return entry


class UpdateSystemRequest(BaseModel):
    """Body for ``PUT /ai-gov/systems/{system_id}`` (partial update).

    All fields optional — only the supplied ones are changed
    (partial-update semantics matching the ``ai-gov update`` CLI verb).
    An empty body (no fields) is a 400 (nothing to update).
    """

    # 2026-07-06 stateful-DAST prep (Step 3): JSON-Schema mirror of the
    # handler's ``if not updates: raise api_error(400, "invalid_body",
    # ...)`` check (``ai_gov_update_system``, ~line 656-664 pre-Step-3) —
    # "at least one of these 4 fields must be present and non-null" isn't
    # otherwise expressible in vanilla JSON Schema (every field here is
    # optional/nullable), so schemathesis generated ``{}`` as schema-valid
    # positive data and flagged the handler's 400 as a
    # ``positive_data_acceptance`` violation on PUT
    # /api/ai-gov/systems/{system_id} (the analogous EvidenceRef fix in
    # ``evidentia_core.models.tprm`` cites the same finding shape on POST
    # /api/model-risk/models). Each branch uses ``{"not": {"type":
    # "null"}}`` rather than a type re-assertion (cf. EvidenceRef) because
    # ``deployment_status`` is an enum $ref, not a plain string — "present
    # AND non-null" is the uniform semantics that matches the handler's
    # ``is not None`` checks across all 4 fields. Keep both in sync.
    model_config = ConfigDict(
        json_schema_extra={
            "anyOf": [
                {
                    "required": ["owner"],
                    "properties": {"owner": {"not": {"type": "null"}}},
                },
                {
                    "required": ["provider"],
                    "properties": {"provider": {"not": {"type": "null"}}},
                },
                {
                    "required": ["deployment_status"],
                    "properties": {
                        "deployment_status": {"not": {"type": "null"}}
                    },
                },
                {
                    "required": ["ssp_reference"],
                    "properties": {
                        "ssp_reference": {"not": {"type": "null"}}
                    },
                },
            ]
        }
    )

    owner: str | None = Field(default=None, min_length=1, max_length=256)
    provider: str | None = Field(default=None, min_length=1, max_length=256)
    deployment_status: DeploymentStatus | None = Field(default=None)
    ssp_reference: str | None = Field(default=None, max_length=2048)


class FIPS199CategorizeRequest(BaseModel):
    """Body for ``POST /ai-gov/systems/{system_id}/categorize-fips``.

    The three per-objective ratings are required; ``overall`` is
    optional (auto-computed high-water-mark when omitted, validated
    when supplied — a mismatch is a 400 domain error).
    """

    confidentiality: FIPS199Impact = Field(
        description="FIPS 199 confidentiality impact: low / moderate / high."
    )
    integrity: FIPS199Impact = Field(
        description="FIPS 199 integrity impact: low / moderate / high."
    )
    availability: FIPS199Impact = Field(
        description="FIPS 199 availability impact: low / moderate / high."
    )
    overall: FIPS199Impact | None = Field(
        default=None,
        description=(
            "Optional explicit high-water-mark. Omit to auto-compute; "
            "if supplied it MUST equal max(C, I, A) or the request is "
            "rejected as a paperwork error (400)."
        ),
    )
    rationale: str | None = Field(default=None, max_length=4000)


class OMBImpactRequest(BaseModel):
    """Body for ``POST /ai-gov/systems/{system_id}/set-omb-impact``.

    DEPRECATED (v0.10.12): legacy OMB M-24-10 surface. M-24-10 was
    rescinded 2025-04-03 by M-25-21 — use the ``set-high-impact``
    endpoint + :class:`HighImpactRequest`. Retained for backward
    compatibility.
    """

    category: OMBImpactCategory = Field(
        description=(
            "OMB M-24-10 §5(b) category: rights_impacting / "
            "safety_impacting / rights_and_safety_impacting / neither."
        )
    )


class HighImpactRequest(BaseModel):
    """Body for ``POST /ai-gov/systems/{system_id}/set-high-impact``.

    OMB M-25-21 high-impact AI determination + consequence bases.
    Supersedes :class:`OMBImpactRequest` after M-24-10's rescission.
    """

    determination: HighImpactDetermination = Field(
        description=(
            "OMB M-25-21 high-impact determination: high_impact / "
            "not_high_impact / not_assessed."
        )
    )
    bases: list[HighImpactBasis] = Field(
        default_factory=list,
        description=(
            "Consequence area(s) that make the system high-impact. "
            "Meaningful only when determination is high_impact."
        ),
    )
    rationale: str | None = Field(default=None, max_length=4000)


@router.put(
    "/ai-gov/systems/{system_id}",
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            400: (
                "Empty update or domain-validation failure "
                "(``error: invalid_body``), or an undecodable request "
                f"body ({BODY_PARSE_ERROR_400})."
            ),
            403: RBAC_DENIED_403,
            404: "No such registered system (``error: not_found``).",
        }
    ),
)
async def ai_gov_update_system(
    body: UpdateSystemRequest, system_id: str = _SYSTEM_ID_PATH
) -> dict[str, Any]:
    """Partially update a registered AI system.

    Fields omitted from the body are left unchanged. The merged entry
    is re-validated through ``model_validate`` so field validators run
    on the partial-update path (mirrors the v0.9.5 F-V94-S12 closure
    on the CLI ``ai-gov update`` verb). Returns the updated entry.
    """
    entry = _load_entry_or_404(system_id)

    updates: dict[str, object] = {}
    if body.owner is not None:
        updates["owner"] = body.owner
    if body.provider is not None:
        updates["provider"] = body.provider
    if body.deployment_status is not None:
        updates["deployment_status"] = body.deployment_status
    if body.ssp_reference is not None:
        updates["ssp_reference"] = body.ssp_reference

    if not updates:
        raise api_error(
            400,
            "invalid_body",
            (
                "No fields to update — supply at least one of owner / "
                "provider / deployment_status / ssp_reference."
            ),
        )

    # Re-validate the merged dict so field validators run (a raw
    # model_copy(update=...) would bypass them). A domain validation
    # failure normalizes to 400.
    merged = {**entry.model_dump(mode="python"), **updates}
    try:
        updated = type(entry).model_validate(merged)
    except (ValidationError, ValueError) as exc:
        raise api_error(400, "invalid_body", str(exc)) from exc
    AIRegistryStore().save(updated)

    _log.info(
        action=EventAction.AI_SYSTEM_UPDATED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {entry.descriptor.name!r} updated via API "
            f"(system_id={system_id}; fields={sorted(updates.keys())})"
        ),
        evidentia={
            "system_id": system_id,
            "descriptor_name": entry.descriptor.name,
            "changed_fields": sorted(updates.keys()),
        },
    )
    return {
        "system_id": system_id,
        "entry": updated.model_dump(mode="json"),
    }


@router.post(
    "/ai-gov/systems/{system_id}/retire",
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: "No such registered system (``error: not_found``).",
        }
    ),
)
async def ai_gov_retire_system(system_id: str) -> dict[str, Any]:
    """Retire a registered AI system (deployment_status=retired).

    Unlike DELETE, the entry is PRESERVED so historical audits can
    still see the system's classification + ownership history.
    Idempotent: retiring an already-retired system is a no-op success.
    """
    entry = _load_entry_or_404(system_id)

    if entry.deployment_status == DeploymentStatus.RETIRED:
        # Already retired — idempotent success, no audit re-emit.
        return {
            "system_id": system_id,
            "entry": entry.model_dump(mode="json"),
            "already_retired": True,
        }

    prior_status = entry.deployment_status
    retired = entry.model_copy(
        update={"deployment_status": DeploymentStatus.RETIRED}
    )
    AIRegistryStore().save(retired)

    _log.info(
        action=EventAction.AI_SYSTEM_RETIRED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"AI system {entry.descriptor.name!r} retired via API "
            f"(system_id={system_id})"
        ),
        evidentia={
            "system_id": system_id,
            "descriptor_name": entry.descriptor.name,
            "previous_status": str(prior_status),
            "retirement_kind": "lifecycle",
        },
    )
    return {
        "system_id": system_id,
        "entry": retired.model_dump(mode="json"),
    }


@router.post(
    "/ai-gov/systems/{system_id}/categorize-fips",
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            400: (
                "FIPS 199 domain-validation failure, e.g. an "
                "``overall`` high-water-mark mismatch "
                "(``error: invalid_body``)."
            ),
            403: RBAC_DENIED_403,
            404: "No such registered system (``error: not_found``).",
        }
    ),
)
async def ai_gov_categorize_fips(
    system_id: str, body: FIPS199CategorizeRequest
) -> dict[str, Any]:
    """Set FIPS 199 categorization on a registered AI system.

    The overall high-water-mark is auto-computed from the three
    per-objective ratings per FIPS 199 §3 (or validated against the
    supplied ``overall`` — a mismatch is a 400 paperwork error).
    """
    entry = _load_entry_or_404(system_id)

    try:
        cat = FIPS199Categorization(
            confidentiality_impact=body.confidentiality,
            integrity_impact=body.integrity,
            availability_impact=body.availability,
            overall=body.overall,
            rationale=body.rationale,
        )
    except (ValidationError, ValueError) as exc:
        raise api_error(400, "invalid_body", str(exc)) from exc

    updated = entry.model_copy(update={"fips_199_categorization": cat})
    AIRegistryStore().save(updated)

    _log.info(
        action=EventAction.AI_SYSTEM_FIPS_CATEGORIZED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"FIPS 199 categorized AI system {entry.descriptor.name!r} "
            f"via API as {cat.overall} (system_id={system_id})"
        ),
        evidentia={
            "system_id": system_id,
            "confidentiality": str(cat.confidentiality_impact),
            "integrity": str(cat.integrity_impact),
            "availability": str(cat.availability_impact),
            "overall": str(cat.overall),
        },
    )
    return {
        "system_id": system_id,
        "entry": updated.model_dump(mode="json"),
    }


@router.post(
    "/ai-gov/systems/{system_id}/set-omb-impact",
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            403: RBAC_DENIED_403,
            404: "No such registered system (``error: not_found``).",
        }
    ),
)
async def ai_gov_set_omb_impact(
    system_id: str, body: OMBImpactRequest
) -> dict[str, Any]:
    """Set the OMB M-24-10 impact category on a registered AI system."""
    entry = _load_entry_or_404(system_id)

    updated = entry.model_copy(update={"omb_impact": body.category})
    AIRegistryStore().save(updated)

    _log.info(
        action=EventAction.AI_SYSTEM_OMB_CLASSIFIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"OMB M-24-10 classified AI system "
            f"{entry.descriptor.name!r} via API as {body.category} "
            f"(system_id={system_id})"
        ),
        evidentia={
            "system_id": system_id,
            "omb_impact": str(body.category),
        },
    )
    return {
        "system_id": system_id,
        "entry": updated.model_dump(mode="json"),
    }


@router.post(
    "/ai-gov/systems/{system_id}/set-high-impact",
    dependencies=[require_role("write")],
    responses=error_responses(
        {
            400: (
                "M-25-21 domain-validation failure "
                "(``error: invalid_body``)."
            ),
            403: RBAC_DENIED_403,
            404: "No such registered system (``error: not_found``).",
        }
    ),
)
async def ai_gov_set_high_impact(
    system_id: str, body: HighImpactRequest
) -> dict[str, Any]:
    """Set the OMB M-25-21 high-impact AI determination on a system.

    Supersedes ``set-omb-impact`` after M-24-10's 2025-04-03 rescission
    by M-25-21. A ``high_impact`` determination triggers the M-25-21
    minimum risk-management practices.
    """
    entry = _load_entry_or_404(system_id)

    try:
        assessment = OMBHighImpactAssessment(
            determination=body.determination,
            bases=body.bases,
            rationale=body.rationale,
        )
    except (ValidationError, ValueError) as exc:
        raise api_error(400, "invalid_body", str(exc)) from exc

    updated = entry.model_copy(update={"omb_high_impact": assessment})
    AIRegistryStore().save(updated)

    _log.info(
        action=EventAction.AI_SYSTEM_HIGH_IMPACT_CLASSIFIED,
        outcome=EventOutcome.SUCCESS,
        message=(
            f"OMB M-25-21 high-impact classified AI system "
            f"{entry.descriptor.name!r} via API as {body.determination} "
            f"(system_id={system_id})"
        ),
        evidentia={
            "system_id": system_id,
            "determination": str(body.determination),
            "bases": [str(b) for b in body.bases],
        },
    )
    return {
        "system_id": system_id,
        "entry": updated.model_dump(mode="json"),
    }
