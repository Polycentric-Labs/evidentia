"""Authenticate before a bounded selected public registry lookup."""

from __future__ import annotations

import os
from importlib.util import find_spec
from typing import Any

from evidentia_core.plugins.auth import AuthProvider
from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from evidentia_api.errors import ErrorEnvelope, api_error, error_responses
from evidentia_api.rbac_dependency import require_role

router = APIRouter()
_SELECTORS = (
    "tls",
    "rdap",
    "sam-entity",
    "sam-exclusions",
    "gleif",
    "fedramp",
    "cmvp",
    "fcc-covered-list",
    "incommon",
    "ssl-labs",
    "security-txt",
)
_REQUEST_BYTES = 65_536


def _whole_enterprise_namespace_is_absent(error: ModuleNotFoundError) -> bool:
    namespace = "evidentia_collectors.enterprise_retention"
    if error.name != namespace:
        return False
    try:
        return find_spec(namespace) is None
    except Exception:
        return False


try:
    from evidentia_collectors.registries import RegistryInputError, RegistryLookupRequest, RegistryLookupResult
    from evidentia_collectors.registries._contracts import parse_request, result_bytes
except ModuleNotFoundError as error:
    if error.name not in {
        "evidentia_collectors",
        "evidentia_collectors.registries",
    } and not _whole_enterprise_namespace_is_absent(error):
        raise RuntimeError("Registry collection could not be loaded.") from None
    REGISTRY_AVAILABLE = False
except Exception:
    raise RuntimeError("Registry collection could not be loaded.") from None
else:
    REGISTRY_AVAILABLE = True


def configuration_status() -> dict[str, Any]:
    """Report package and credential presence without resolving credentials."""
    if not REGISTRY_AVAILABLE:
        return {"installed": False, "selectors": [], "live_validated": False}
    sam_present = "EVIDENTIA_REGISTRY_SAM_API_KEY" in os.environ
    verifier_present = all(find_spec(name) is not None for name in ("defusedxml", "signxml"))
    selectors = []
    for selector in _SELECTORS:
        if selector == "ssl-labs":
            mode = "live_disabled"
        elif selector in {"fedramp", "cmvp", "fcc-covered-list"}:
            mode = "bundled_snapshot"
        elif selector in {"sam-entity", "sam-exclusions"}:
            mode = "configured" if sam_present else "unconfigured"
        elif selector == "incommon":
            mode = "configured" if verifier_present else "unconfigured"
        else:
            mode = "configured"
        selectors.append({"registry": selector, "mode": mode})
    return {
        "installed": True,
        "selectors": selectors,
        "sam_credential_present": sam_present,
        "xml_extra_present": verifier_present,
        "credential_identity_verified": False,
        "live_validated": False,
    }


def _authenticated_principal(request: Request) -> str:
    principal = getattr(request.state, "auth_principal", None)
    if (
        not isinstance(getattr(request.app.state, "auth_provider", None), AuthProvider)
        or type(principal) is not str
        or not principal.strip()
    ):
        raise api_error(403, "auth_not_configured", "Registry collection requires configured API authentication.")
    return principal


_ERRORS = {
    **error_responses(
        {
            403: "Configured authentication and read permission are required.",
            422: "The bounded registry request is invalid.",
            500: "Collection could not produce a valid result.",
            503: "The optional registry collector is not installed.",
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


if REGISTRY_AVAILABLE:

    def _request_schema() -> dict[str, Any]:
        """Keep strict input constraints while authenticating before body reads."""
        schema = RegistryLookupRequest.model_json_schema()
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

    def _collect_registry(selected: RegistryLookupRequest) -> RegistryLookupResult:
        from evidentia_collectors.registries import RegistryCollector

        with RegistryCollector() as collector:
            return collector.collect_v2(selected)

    def _publication(result: object, expected: dict[str, Any]) -> bytes:
        if type(result) is not RegistryLookupResult:
            raise ValueError("invalid_registry_result")
        raw = result_bytes(result)
        published = RegistryLookupResult.model_validate_json(raw)
        if published.request.model_dump(mode="python", warnings="error") != expected:
            raise ValueError("result_selection_mismatch")
        return raw

    @router.post(
        "/collectors/registry",
        operation_id="collect_registry",
        response_model=RegistryLookupResult,
        dependencies=[require_role("read")],
        responses=_ERRORS,
        openapi_extra={
            "requestBody": {"required": True, "content": {"application/json": {"schema": _request_schema()}}}
        },
    )
    async def collect_registry(request: Request) -> Response:
        """Return the complete selected-query result, including source limitations."""
        _authenticated_principal(request)
        if request.headers.get("content-type", "").partition(";")[0].strip().lower() != "application/json":
            raise api_error(422, "unsupported_format", "An application/json body is required.")
        body = bytearray()
        try:
            async for chunk in request.stream():
                if len(chunk) > _REQUEST_BYTES - len(body):
                    raise api_error(422, "invalid_body", "Request body exceeds 65536 bytes.")
                body.extend(chunk)
        except ClientDisconnect:
            raise api_error(422, "invalid_body", "The request body is incomplete.") from None
        except HTTPException:
            raise
        except Exception:
            raise api_error(500, "collector_failed", "Registry collection could not produce a valid result.") from None
        try:
            selected = parse_request(bytes(body))
        except RegistryInputError:
            raise api_error(422, "invalid_body", "A valid registry request is required.") from None
        expected = selected.model_dump(mode="python", warnings="error")
        try:
            result = await run_in_threadpool(_collect_registry, selected)
            return Response(content=_publication(result, expected), media_type="application/json")
        except Exception:
            raise api_error(500, "collector_failed", "Registry collection could not produce a valid result.") from None
else:

    @router.post(
        "/collectors/registry",
        operation_id="collect_registry",
        status_code=503,
        response_model=ErrorEnvelope,
        dependencies=[require_role("read")],
        responses=_ERRORS,
    )
    async def registry_unavailable(request: Request) -> ErrorEnvelope:
        """Refuse an absent collector before reading input or configuration."""
        _authenticated_principal(request)
        raise api_error(503, "feature_unavailable", "The registry collector is not installed.")
