"""Authenticate and authorize a selected incident clock before credentialed reads."""

from __future__ import annotations

import os
from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
from typing import Any

from evidentia_core.plugins.auth import AuthProvider
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import TypeAdapter
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from evidentia_api.errors import ErrorEnvelope, api_error, error_responses
from evidentia_api.rbac_dependency import require_role

router = APIRouter()


def _feature_absent(error: ModuleNotFoundError) -> bool:
    if error.name not in {"evidentia_collectors", "evidentia_collectors.incident_clock"}:
        return False
    try:
        return find_spec(error.name) is None
    except Exception:
        return False


try:
    from evidentia_collectors.incident_clock import (
        IncidentClockCollector,
        IncidentClockRequest,
        IncidentClockResult,
        IncidentInputError,
    )
    from evidentia_collectors.incident_clock._contracts import (
        REQUEST_BYTE_LIMIT,
        parse_request,
        request_identity,
        result_bytes,
    )
    from evidentia_collectors.incident_clock._profiles import (
        AuthorizedSelection,
        ProfileStore,
        ProfileUnavailable,
        authorize_api_selection,
        load_profile_store,
    )

    for _provider in ("jira", "servicenow", "pagerduty"):
        adapter = import_module("evidentia_collectors.incident_clock." + _provider)
        if not callable(getattr(adapter, "collect", None)):
            raise ImportError("invalid_provider_export")
except ModuleNotFoundError as error:
    if not _feature_absent(error):
        raise RuntimeError("Incident clock collection could not be loaded.") from None
    INCIDENT_CLOCK_AVAILABLE = False
except Exception:
    raise RuntimeError("Incident clock collection could not be loaded.") from None
else:
    INCIDENT_CLOCK_AVAILABLE = True


def configuration_status() -> dict[str, Any]:
    """Report installation without reading profiles, credentials or remote state."""
    return {"installed": INCIDENT_CLOCK_AVAILABLE, "live_validated": False, "credential_identity_verified": False}


def _authenticated_principal(request: Request) -> str:
    principal = getattr(request.state, "auth_principal", None)
    if (
        not isinstance(getattr(request.app.state, "auth_provider", None), AuthProvider)
        or type(principal) is not str
        or not principal.strip()
    ):
        raise api_error(403, "auth_not_configured", "Incident clock collection requires configured API authentication.")
    return principal


_ERRORS = {
    **error_responses(
        {
            400: "Invalid JSON or bounded request fields.",
            403: "Authentication, read permission or profile authorization is required.",
            413: "The request body exceeds 16384 bytes.",
            415: "Only application/json is supported.",
            500: "Collection could not produce a valid result.",
            503: "The optional incident clock collector is not installed.",
        }
    ),
    401: {
        "description": "API authentication required.",
        "content": {
            "application/json": {
                "schema": {
                    "type": "object",
                    "required": ["detail", "reason", "provider"],
                    "properties": {
                        "detail": {"type": "string"},
                        "reason": {"anyOf": [{"type": "string"}, {"type": "null"}]},
                        "provider": {"type": "string"},
                    },
                }
            }
        },
    },
}


if INCIDENT_CLOCK_AVAILABLE:

    def _request_schema() -> dict[str, Any]:
        """Describe strict input without asking FastAPI to read the body before authorization."""
        schema = TypeAdapter(IncidentClockRequest).json_schema()
        definitions = schema.pop("$defs", {})

        def expand(value: Any) -> Any:
            if isinstance(value, list):
                return [expand(item) for item in value]
            if not isinstance(value, dict):
                return value
            if "$ref" in value:
                reference = value["$ref"]
                if not reference.startswith("#/$defs/"):
                    raise ValueError("unexpected_request_schema_reference")
                return expand(
                    {
                        **definitions[reference.removeprefix("#/$defs/")],
                        **{key: item for key, item in value.items() if key != "$ref"},
                    }
                )
            return {key: expand(item) for key, item in value.items() if key != "discriminator"}

        expanded: dict[str, Any] = expand(schema)
        return expanded

    def _authorize(request: Request, selected: IncidentClockRequest, principal: str) -> AuthorizedSelection:
        configured = getattr(request.app.state, "incident_clock_profiles", None)
        if configured is None:
            location = os.environ.get("EVIDENTIA_INCIDENT_CLOCK_PROFILES_FILE")
            if not location:
                raise ProfileUnavailable()
            configured = load_profile_store(Path(location))
        if type(configured) is not ProfileStore:
            raise ProfileUnavailable()
        return authorize_api_selection(configured, selected, principal=principal)

    def _collect_incident_clock(selected: IncidentClockRequest, profile: AuthorizedSelection) -> IncidentClockResult:
        with IncidentClockCollector(profile) as collector:
            return collector.collect_v2(selected)

    def _publication(result: object, expected: str) -> bytes:
        if type(result) is not IncidentClockResult or request_identity(result.request) != expected:
            raise ValueError("result_selection_mismatch")
        return result_bytes(result)

    @router.post(
        "/collectors/incident-clock",
        operation_id="collect_incident_clock",
        response_model=IncidentClockResult,
        dependencies=[require_role("read")],
        responses=_ERRORS,
        openapi_extra={
            "requestBody": {"required": True, "content": {"application/json": {"schema": _request_schema()}}}
        },
    )
    async def collect_incident_clock(request: Request) -> Response:
        """Return the full observation with source completeness and clock status kept separate."""
        principal = _authenticated_principal(request)
        if request.headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
            raise api_error(415, "unsupported_format", "An application/json body is required.")
        body = bytearray()
        try:
            async for chunk in request.stream():
                if len(chunk) > REQUEST_BYTE_LIMIT - len(body):
                    raise api_error(413, "response_limit", "Request body exceeds 16384 bytes.")
                body.extend(chunk)
        except ClientDisconnect:
            raise api_error(400, "invalid_body", "The request body is incomplete.") from None
        except HTTPException:
            raise
        except Exception:
            raise api_error(
                500, "collector_failed", "Incident clock collection could not produce a valid result."
            ) from None
        try:
            selected = parse_request(bytes(body))
        except IncidentInputError:
            raise api_error(400, "invalid_body", "A valid incident clock request is required.") from None
        expected = request_identity(selected)
        try:
            profile = await run_in_threadpool(_authorize, request, selected, principal)
        except (ValueError, TypeError, OSError):
            raise api_error(403, "profile_unavailable", "The selected collection profile is unavailable.") from None
        except Exception:
            raise api_error(
                500, "collector_failed", "Incident clock collection could not produce a valid result."
            ) from None
        try:
            result = await run_in_threadpool(_collect_incident_clock, selected, profile)
            return Response(content=_publication(result, expected), media_type="application/json")
        except Exception:
            raise api_error(
                500, "collector_failed", "Incident clock collection could not produce a valid result."
            ) from None
else:

    @router.post(
        "/collectors/incident-clock",
        operation_id="collect_incident_clock",
        status_code=503,
        response_model=ErrorEnvelope,
        dependencies=[require_role("read")],
        responses=_ERRORS,
    )
    async def incident_clock_unavailable(request: Request) -> ErrorEnvelope:
        """Refuse absent collection before reading the body or profile configuration."""
        _authenticated_principal(request)
        raise api_error(503, "feature_unavailable", "The incident clock collector is not installed.")
