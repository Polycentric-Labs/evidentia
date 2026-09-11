"""Authenticated, profile-authorized reads of selected enterprise configuration."""

from __future__ import annotations

from typing import Any

from evidentia_core.plugins.auth import AuthProvider
from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from evidentia_api.errors import ErrorEnvelope, api_error, error_responses
from evidentia_api.rbac_dependency import require_role

router = APIRouter()

try:
    from evidentia_collectors.enterprise_retention import (
        EnterpriseRetentionCollector,
        EnterpriseRetentionCollectRequest,
        EnterpriseRetentionCollectResult,
        EnterpriseRetentionInputError,
    )
    from evidentia_collectors.enterprise_retention._contracts import REQUEST_BYTE_LIMIT, parse_request
    from evidentia_collectors.enterprise_retention._profiles import (
        AuthorizedProfile,
        ProfileUnavailable,
        authorize_api_profile,
    )
except ModuleNotFoundError as error:
    if error.name not in {"evidentia_collectors", "evidentia_collectors.enterprise_retention"}:
        raise RuntimeError("Enterprise retention collection could not be loaded.") from None
    ENTERPRISE_RETENTION_AVAILABLE = False
except Exception:
    raise RuntimeError("Enterprise retention collection could not be loaded.") from None
else:
    ENTERPRISE_RETENTION_AVAILABLE = True


def configuration_status() -> dict[str, Any]:
    """Report feature availability without inspecting profiles or credentials."""
    return {
        "installed": ENTERPRISE_RETENTION_AVAILABLE,
        "live_validated": False,
        "credential_identity_verified": False,
    }


def _authenticated_principal(request: Request) -> str:
    principal = getattr(request.state, "auth_principal", None)
    if (
        not isinstance(getattr(request.app.state, "auth_provider", None), AuthProvider)
        or type(principal) is not str
        or not principal.strip()
    ):
        raise api_error(403, "auth_not_configured", "Enterprise collection requires configured API authentication.")
    return principal


_ERRORS = {
    **error_responses(
        {
            400: "Invalid JSON or bounded request fields.",
            403: "Read permission, configured authentication or profile authorization is required.",
            413: "The request body exceeds 65536 bytes.",
            415: "Only application/json is supported.",
            500: "Collection could not produce a valid result.",
            503: "The optional enterprise collector is not installed.",
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


if ENTERPRISE_RETENTION_AVAILABLE:

    def _request_schema() -> dict[str, Any]:
        """Keep strict input constraints while authenticating before body reads."""
        schema = EnterpriseRetentionCollectRequest.model_json_schema()
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

    def _collect_enterprise_retention(
        selected: EnterpriseRetentionCollectRequest, profile: AuthorizedProfile
    ) -> EnterpriseRetentionCollectResult:
        with EnterpriseRetentionCollector(profile=profile) as collector:
            return collector.collect_v2(selected)

    def _publication(result: object, expected: dict[str, Any]) -> bytes:
        if type(result) is not EnterpriseRetentionCollectResult:
            raise ValueError("invalid_collection_result")
        raw = result.publication_bytes()
        published = EnterpriseRetentionCollectResult.model_validate_json(raw)
        actual = {
            "provider": published.root.provider,
            "profile_alias": published.root.profile_alias,
            "scope_label": published.root.scope_label,
            "targets": [resource.target.model_dump(mode="python") for resource in published.root.resources],
        }
        if actual != expected:
            raise ValueError("result_selection_mismatch")
        return raw

    @router.post(
        "/collectors/enterprise-retention/collect",
        response_model=EnterpriseRetentionCollectResult,
        dependencies=[require_role("read")],
        responses=_ERRORS,
        openapi_extra={
            "requestBody": {"required": True, "content": {"application/json": {"schema": _request_schema()}}}
        },
    )
    async def enterprise_retention_collect(request: Request) -> Response:
        """Return bounded evidence for a profile-authorized resource selection."""
        principal = _authenticated_principal(request)
        media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
        if media_type != "application/json":
            raise api_error(415, "unsupported_format", "An application/json body is required.")
        body = bytearray()
        try:
            async for chunk in request.stream():
                if len(chunk) > REQUEST_BYTE_LIMIT - len(body):
                    raise api_error(413, "response_limit", "Request body exceeds the size limit.")
                body.extend(chunk)
        except ClientDisconnect:
            raise api_error(400, "invalid_body", "The request body is incomplete.") from None
        except HTTPException:
            raise
        except Exception:
            raise api_error(500, "collector_failed", "Collection could not produce a valid result.") from None
        try:
            selected = parse_request(bytes(body))
        except EnterpriseRetentionInputError:
            raise api_error(400, "invalid_body", "A valid enterprise collection request is required.") from None
        expected = selected.model_dump(mode="python", warnings="error")
        try:
            profile = authorize_api_profile(
                request.app.state.enterprise_retention_profiles,
                provider=selected.root.provider,
                alias=selected.root.profile_alias,
                principal=principal,
            )
        except ProfileUnavailable:
            raise api_error(403, "profile_unavailable", "The selected collection profile is unavailable.") from None
        except Exception:
            raise api_error(500, "collector_failed", "Collection could not produce a valid result.") from None
        try:
            result = await run_in_threadpool(_collect_enterprise_retention, selected, profile)
            raw = _publication(result, expected)
            return Response(content=raw, media_type="application/json")
        except Exception:
            raise api_error(500, "collector_failed", "Collection could not produce a valid result.") from None
else:

    @router.post(
        "/collectors/enterprise-retention/collect",
        status_code=503,
        response_model=ErrorEnvelope,
        dependencies=[require_role("read")],
        responses=_ERRORS,
    )
    async def enterprise_retention_unavailable(request: Request) -> ErrorEnvelope:
        """Refuse absent-feature collection without consuming a body or profile."""
        _authenticated_principal(request)
        raise api_error(503, "feature_unavailable", "The enterprise retention collector is not installed.")
