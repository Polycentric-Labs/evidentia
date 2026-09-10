"""Authenticated, bounded collection of selected storage configuration."""

from __future__ import annotations

import os
from typing import Any

from evidentia_core.plugins.auth import AuthProvider
from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from evidentia_api.errors import ErrorEnvelope, api_error, error_responses
from evidentia_api.rbac_dependency import require_role

router = APIRouter()

try:
    from evidentia_collectors.retention import (
        StorageRetentionCollector,
        StorageRetentionCollectRequest,
        StorageRetentionCollectResult,
        StorageRetentionInputError,
    )
    from evidentia_collectors.retention._contracts import REQUEST_BYTE_LIMIT, parse_request
except ModuleNotFoundError as error:
    if error.name not in {"evidentia_collectors", "evidentia_collectors.retention"}:
        raise
    _RETENTION_AVAILABLE = False
else:
    _RETENTION_AVAILABLE = True


def configuration_status() -> dict[str, Any]:
    """Report fixed credential-reference presence without resolving credentials."""
    references = {
        "s3": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"),
        "azure": ("STORAGE_RETENTION_AZURE_ACCESS_TOKEN",),
        "gcs": ("STORAGE_RETENTION_GCS_ACCESS_TOKEN",),
    }
    return {
        "installed": _RETENTION_AVAILABLE,
        "providers": {
            provider: {"configured": all(bool(os.environ.get(name)) for name in names)}
            for provider, names in references.items()
        },
        "live_validated": False,
        "credential_identity_verified": False,
    }


def _authenticated_actor(request: Request) -> None:
    principal = getattr(request.state, "auth_principal", None)
    if (
        not isinstance(getattr(request.app.state, "auth_provider", None), AuthProvider)
        or type(principal) is not str
        or not principal.strip()
    ):
        raise api_error(403, "auth_not_configured", "Storage collection requires configured API authentication.")


_ERRORS = {
    **error_responses(
        {
            400: "Invalid JSON or bounded request fields.",
            403: "Read permission denied or API authentication is not configured.",
            413: "The request body exceeds 65536 bytes.",
            415: "Only application/json is supported.",
            500: "Collection could not produce a valid result.",
            503: "The selected optional collector is not installed.",
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


if _RETENTION_AVAILABLE:

    def _request_schema() -> dict[str, Any]:
        """Inline the finite input models so every OpenAPI reference resolves.

        Body parsing is manual to keep authentication ahead of body reads.
        Each oneOf branch retains its provider const and complete constraints;
        a discriminator mapping is unnecessary for these disjoint branches.
        """
        schema = StorageRetentionCollectRequest.model_json_schema()
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

    def _collect_storage_retention(selected: StorageRetentionCollectRequest) -> StorageRetentionCollectResult:
        expected = selected.model_dump(mode="json", warnings="error")
        with StorageRetentionCollector() as collector:
            result = StorageRetentionCollectResult.model_validate_json(
                collector.collect_v2(selected).model_dump_json(warnings="error")
            )
        actual = {
            "provider": result.provider,
            "scope_label": result.scope_label,
            "targets": [resource.target.model_dump(mode="json", warnings="error") for resource in result.resources],
        }
        if actual != expected:
            raise ValueError("result_selection_mismatch")
        return result

    @router.post(
        "/collectors/retention/collect",
        response_model=StorageRetentionCollectResult,
        dependencies=[require_role("read")],
        responses=_ERRORS,
        openapi_extra={
            "requestBody": {"required": True, "content": {"application/json": {"schema": _request_schema()}}}
        },
    )
    async def storage_retention_collect(request: Request) -> StorageRetentionCollectResult:
        """Return full observations for every operator-selected resource."""
        _authenticated_actor(request)
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
        try:
            selected = parse_request(bytes(body))
        except StorageRetentionInputError:
            raise api_error(400, "invalid_body", "A valid storage collection request is required.") from None
        provider = selected.root.provider
        try:
            return await run_in_threadpool(_collect_storage_retention, selected)
        except ModuleNotFoundError as error:
            if provider == "s3" and error.name in {"botocore", "defusedxml"}:
                raise api_error(
                    503, "feature_unavailable", "The storage retention S3 extra is not installed."
                ) from None
            raise api_error(500, "collector_failed", "Collection could not produce a valid result.") from None
        except Exception:
            raise api_error(500, "collector_failed", "Collection could not produce a valid result.") from None
else:

    @router.post(
        "/collectors/retention/collect",
        status_code=503,
        response_model=ErrorEnvelope,
        dependencies=[require_role("read")],
        responses=_ERRORS,
    )
    async def storage_retention_unavailable(request: Request) -> ErrorEnvelope:
        """Refuse collection when the optional package is absent."""
        _authenticated_actor(request)
        raise api_error(503, "feature_unavailable", "The storage retention collector is not installed.")
