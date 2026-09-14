"""Authenticate before bounded raw SCAP input and publish the complete accepted result."""

from __future__ import annotations

import asyncio
import time
from importlib.util import find_spec
from typing import TYPE_CHECKING, Any

from evidentia_core.plugins.auth import AuthProvider
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from evidentia_api.errors import api_error, error_responses
from evidentia_api.rbac_dependency import require_role

if TYPE_CHECKING:
    from evidentia_collectors.scap.collector import _Import

router = APIRouter()
_PROFILES = ["xccdf-1.2-results", "oval-5.8-core-results", "oval-5.11.2-core-results", "oval-5.12.3-core-results"]
_CLAIM_HEADER = b"x-evidentia-scap-completion-assertion"


def _proven_absent(error: ModuleNotFoundError) -> bool:
    if error.name not in {"evidentia_collectors", "evidentia_collectors.scap"}:
        return False
    try:
        return find_spec(error.name) is None
    except Exception:
        return False


try:
    from evidentia_collectors.scap._contracts import ScapCollectionResult, ScapError
    from evidentia_collectors.scap._json import load_json
    from evidentia_collectors.scap._limits import CLAIM_LIMIT, PUBLICATION_RESERVE, RAW_LIMIT, ScapFailure
except ModuleNotFoundError as error:
    _PACKAGE_STATE = "absent" if _proven_absent(error) else "broken"
except Exception:
    _PACKAGE_STATE = "broken"
else:
    _PACKAGE_STATE = "available"


def _require_authentication(request: Request) -> None:
    principal = getattr(request.state, "auth_principal", None)
    provider = getattr(request.state, "auth_provider", None)
    if not isinstance(provider, AuthProvider) or type(principal) is not str or not principal.strip():
        raise api_error(403, "auth_not_configured", "SCAP import requires configured API authentication.")


_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    **error_responses({403: "Configured authentication and read permission are required."}),
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

if _PACKAGE_STATE == "available":
    _ERROR_RESPONSES.update(
        {
            status: {"model": ScapError, "description": description}
            for status, description in {
                400: "The complete raw source is unreadable, unsafe or invalid.",
                413: "A finite source or full-result limit was exceeded.",
                415: "Only UTF-8 application/xml and identity encoding are supported.",
                422: "The explicit options, selection or completion assertion are invalid.",
                500: "A fixed internal validation or publication failure occurred.",
                503: "Support is unavailable or the original deadline was exceeded.",
            }.items()
        }
    )

    def _header(request: Request, name: bytes, code: str = "invalid_request") -> bytes | None:
        found = None
        for key, value in request.scope.get("headers", []):
            if key.lower() == name:
                if found is not None:
                    raise ScapFailure("completion_assertion_invalid" if code == "claim" else "invalid_request")
                found = value
        return found

    def _component(raw: bytes) -> str:
        decoded = bytearray()
        index = 0
        while index < len(raw):
            item = raw[index]
            if item == 37:
                pair = raw[index + 1 : index + 3]
                if len(pair) != 2 or any(char not in b"0123456789abcdefABCDEF" for char in pair):
                    raise ScapFailure("invalid_request")
                decoded.append(int(pair, 16))
                index += 3
            else:
                decoded.append(32 if item == 43 else item)
                index += 1
        try:
            return decoded.decode("utf-8", errors="strict")
        except UnicodeError:
            raise ScapFailure("invalid_request") from None

    def _options(request: Request) -> dict[str, object]:
        raw = request.scope.get("query_string", b"")
        if type(raw) is not bytes or len(raw) > 1024:
            raise ScapFailure("invalid_request")
        parts = raw.split(b"&")
        if not 2 <= len(parts) <= 3:
            raise ScapFailure("invalid_request")
        values = {}
        for part in parts:
            if b"=" not in part:
                raise ScapFailure("invalid_request")
            key, value = (_component(item) for item in part.split(b"=", 1))
            if key not in {"source_profile", "assessment_index", "cadence_slug"} or key in values:
                raise ScapFailure("invalid_request")
            values[key] = value
        if not {"source_profile", "assessment_index"} <= values.keys():
            raise ScapFailure("invalid_request")
        index = values["assessment_index"]
        if (
            not 1 <= len(index) <= 3
            or any(char not in "0123456789" for char in index)
            or (len(index) > 1 and index[0] == "0")
            or int(index) > 255
        ):
            raise ScapFailure("invalid_request")
        return {
            "source_profile": values["source_profile"],
            "assessment_index": int(index),
            "cadence_slug": values.get("cadence_slug"),
        }

    def _claim(request: Request) -> object:
        raw = _header(request, _CLAIM_HEADER, "claim")
        if raw is None:
            return None
        if len(raw) > CLAIM_LIMIT or any(char < 32 or char > 126 for char in raw):
            raise ScapFailure("completion_assertion_invalid")
        try:
            claim = load_json(raw, CLAIM_LIMIT)
            if type(claim) is not dict:
                raise ScapFailure("completion_assertion_invalid")
            return claim
        except ScapFailure:
            raise ScapFailure("completion_assertion_invalid") from None

    def _media(request: Request) -> None:
        media = _header(request, b"content-type")
        encoding = _header(request, b"content-encoding")
        if media is None or len(media) > 64:
            raise ScapFailure("unsupported_media")
        normalized = media.strip().lower()
        if normalized not in {
            b"application/xml",
            b"application/xml;charset=utf-8",
            b"application/xml; charset=utf-8",
            b'application/xml;charset="utf-8"',
            b'application/xml; charset="utf-8"',
        } or (encoding is not None and (len(encoding) > 16 or encoding.strip().lower() != b"identity")):
            raise ScapFailure("unsupported_media")

    def _begin(options: dict[str, object], claim: object, actor: object) -> _Import:
        try:
            from evidentia_collectors.scap.collector import _begin_import
        except Exception:
            raise ScapFailure("internal_dependency_failure") from None
        return _begin_import(
            source_profile=options["source_profile"],
            assessment_index=options["assessment_index"],
            cadence_slug=options["cadence_slug"],
            completion_assertion=claim,
            actor=actor,
        )

    @router.post(
        "/collectors/scap/collect",
        operation_id="collect_scap",
        response_model=ScapCollectionResult,
        dependencies=[Depends(_require_authentication), require_role("read")],
        responses=_ERROR_RESPONSES,
        openapi_extra={
            "requestBody": {"required": True, "content": {"application/xml": {"schema": {"type": "string"}}}},
            "parameters": [
                {
                    "name": "source_profile",
                    "in": "query",
                    "required": True,
                    "schema": {"type": "string", "enum": _PROFILES},
                },
                {
                    "name": "assessment_index",
                    "in": "query",
                    "required": True,
                    "description": (
                        "Zero-based occurrence in canonical decimal form. The entire query is at most 1024 bytes."
                    ),
                    "schema": {"type": "integer", "minimum": 0, "maximum": 255},
                },
                {"name": "cadence_slug", "in": "query", "required": False, "schema": {"type": "string"}},
                {
                    "name": "X-Evidentia-SCAP-Completion-Assertion",
                    "in": "header",
                    "required": False,
                    "description": (
                        "One ASCII JSON value with the six completion-assertion fields. "
                        "Actor identity comes from authentication."
                    ),
                    "schema": {"type": "string", "maxLength": 2048},
                },
            ],
        },
    )
    async def collect_scap(request: Request) -> Response:
        """Return every validated field, including a required nullable artifact."""
        _require_authentication(request)
        body = bytearray()
        try:
            _media(request)
            options = _options(request)
            claim = _claim(request)
            actor = None
            if claim is not None:
                actor = {
                    "basis": "api_authenticated",
                    "subject": request.state.auth_principal,
                    "provider": request.state.auth_provider.name(),
                }
            operation = _begin(options, claim, actor)
            remaining = operation.budget.deadline - PUBLICATION_RESERVE - time.monotonic()
            if remaining <= 0:
                raise ScapFailure("processing_deadline_exceeded")
            try:
                async with asyncio.timeout(remaining):
                    async for chunk in request.stream():
                        operation.budget.check()
                        if type(chunk) is not bytes:
                            raise ScapFailure("source_read_failed")
                        if len(chunk) > RAW_LIMIT - len(body):
                            raise ScapFailure("source_limit_exceeded")
                        body.extend(chunk)
                    operation.budget.check()
            except TimeoutError:
                raise ScapFailure("processing_deadline_exceeded") from None
            except (ClientDisconnect, OSError):
                raise ScapFailure("source_read_failed") from None
            except ExceptionGroup as group:
                _, remainder = group.split((ClientDisconnect, OSError))
                if remainder is None:
                    raise ScapFailure("source_read_failed") from None
                raise
            accepted = await run_in_threadpool(operation.consume, bytes(body))
            return Response(content=accepted.output_bytes(), media_type="application/json")
        except ScapFailure as error:
            return JSONResponse(status_code=error.http_status or 500, content=error.as_dict())
        except Exception:
            failure = ScapFailure()
            return JSONResponse(status_code=500, content=failure.as_dict())
        finally:
            body.clear()

else:

    @router.post(
        "/collectors/scap/collect",
        operation_id="collect_scap",
        dependencies=[Depends(_require_authentication), require_role("read")],
        responses=_ERROR_RESPONSES,
    )
    async def scap_unavailable(request: Request) -> Response:
        """Retain auth precedence and distinguish proven absence from broken imports."""
        _require_authentication(request)
        if _PACKAGE_STATE == "absent":
            code, message, status = "collector_unavailable", "The SCAP collector is unavailable.", 503
        else:
            code, message, status = "internal_dependency_failure", "SCAP import support failed.", 500
        return JSONResponse(
            status_code=status, content={"schema_version": "scap-error-v1", "code": code, "message": message}
        )
