"""Actual bounded release endpoints with one clock and captured API authority."""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import re
from collections.abc import Callable
from typing import Any, cast

from evidentia_core.release_cadence._contracts import (
    PollRequest,
    PollResult,
    ReleaseError,
    ReleaseSeriesRequest,
    ReleaseSeriesResult,
    native_model,
)
from evidentia_core.release_cadence._json import canonical_bytes, load_json
from evidentia_core.release_cadence._limits import (
    ERRORS,
    REQUEST_BYTES,
    RESULT_BYTES,
    ReleaseFailure,
    _Invocation,
    _start_invocation,
)
from evidentia_core.release_cadence._series import _evaluate_wire
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from evidentia_api._release_cadence_authority import capture_authority

router = APIRouter()


def _load_poll() -> Callable[..., Any]:
    """Distinguish proven feature absence from a broken installed dependency."""
    try:
        module = importlib.import_module("evidentia_collectors.release_cadence.collector")
    except ModuleNotFoundError as error:
        absent = False
        if type(error.name) is str and error.name in {"evidentia_collectors", "evidentia_collectors.release_cadence"}:
            try:
                absent = importlib.util.find_spec(error.name) is None
            except Exception:
                absent = False
        raise ReleaseFailure("support_unavailable" if absent else "support_broken") from None
    except Exception:
        raise ReleaseFailure("support_broken") from None
    function = getattr(module, "_prepare_poll_from_clock", None)
    if not callable(function):
        raise ReleaseFailure("support_broken")
    return cast(Callable[..., Any], function)


def configuration_status() -> dict[str, object]:
    try:
        _load_poll()
    except ReleaseFailure as error:
        return {"installed": False, "state": "absent" if error.code == "support_unavailable" else "broken"}
    return {"installed": True, "state": "available"}


def _failure(error: ReleaseFailure) -> Response:
    if error.code == "persistence_outcome_unavailable":
        error = ReleaseFailure("operation_failed")
    value = {"schema_version": "release-error-v1", "code": error.code, "message": error.message}
    ReleaseError.model_validate(value)
    return Response(canonical_bytes(value, 1024), status_code=error.status, media_type="application/json")


def _header(request: Request, name: bytes, *, media: bool = False) -> bytes | None:
    found = None
    for key, value in request.scope.get("headers", []):
        if type(key) is not bytes or type(value) is not bytes:
            raise ReleaseFailure("invalid_request")
        if key.lower() == name:
            if found is not None:
                raise ReleaseFailure("unsupported_media" if media else "invalid_request")
            found = value
    return found


def _ingress(request: Request) -> int | None:
    query = request.scope.get("query_string", b"")
    if type(query) is not bytes or query:
        raise ReleaseFailure("invalid_request")
    for name in (b"x-evidentia-tenant", b"x-evidentia-evidence-store", b"x-tenant-id", b"x-evidence-store"):
        if _header(request, name) is not None:
            raise ReleaseFailure("invalid_request")
    media = _header(request, b"content-type", media=True)
    encoding = _header(request, b"content-encoding", media=True)
    if (
        media is None
        or re.fullmatch(
            rb'[ \t]*application/json[ \t]*(?:;[ \t]*charset[ \t]*=[ \t]*(?:utf-8|"utf-8")[ \t]*)?',
            media,
            flags=re.IGNORECASE | re.ASCII,
        )
        is None
        or (encoding is not None and encoding.strip().lower() != b"identity")
    ):
        raise ReleaseFailure("unsupported_media")
    length = _header(request, b"content-length")
    if length is None:
        return None
    if not length or len(length) > 20 or any(byte < 48 or byte > 57 for byte in length):
        raise ReleaseFailure("invalid_request")
    expected = int(length)
    if expected > REQUEST_BYTES:
        raise ReleaseFailure("request_limit_exceeded")
    return expected


async def _read_request(request: Request, clock: _Invocation, *, series: bool) -> tuple[bytes, dict[str, Any]]:
    expected = _ingress(request)
    reserve = 5 if series else 15
    body = bytearray()
    try:
        clock.check(reserve)
        remaining = clock.budget.remaining() - reserve
        if remaining <= 0:
            raise ReleaseFailure("deadline_exceeded")
        try:
            async with asyncio.timeout(remaining):
                async for chunk in request.stream():
                    clock.check(reserve)
                    if type(chunk) is not bytes:
                        raise ReleaseFailure("invalid_request")
                    if len(chunk) > REQUEST_BYTES - len(body):
                        raise ReleaseFailure("request_limit_exceeded")
                    body.extend(chunk)
                clock.check(reserve)
        except TimeoutError:
            raise ReleaseFailure("deadline_exceeded") from None
        except (ClientDisconnect, OSError):
            raise ReleaseFailure("invalid_request") from None
        if expected is not None and len(body) != expected:
            raise ReleaseFailure("invalid_request")
        try:
            decoded = load_json(
                bytes(body),
                REQUEST_BYTES,
                budget=clock.budget,
                max_values=64,
                max_depth=8,
                max_string_bytes=REQUEST_BYTES,
            )
            checked = ReleaseSeriesRequest.model_validate(decoded) if series else PollRequest.model_validate(decoded)
            value = native_model(checked)
            captured = canonical_bytes(value, REQUEST_BYTES, budget=clock.budget, max_depth=8, max_values=64)
        except ValidationError:
            raise ReleaseFailure("invalid_request") from None
        except ReleaseFailure as error:
            if error.reason in {"deadline_exceeded", "clock_invalid"}:
                raise
            code = (
                "request_limit_exceeded"
                if error.reason in {"json_depth", "json_count", "result_limit_exceeded"}
                else "invalid_request"
            )
            raise ReleaseFailure(code) from None
        clock.check(reserve)
        return captured, value
    finally:
        body.clear()


def _accepted(wire: object, captured: bytes, clock: _Invocation, *, series: bool) -> Response:
    clock.check()
    if type(wire) is not bytes or len(wire) > RESULT_BYTES:
        raise ReleaseFailure("operation_failed")
    restored = load_json(wire, RESULT_BYTES, budget=clock.budget, max_values=RESULT_BYTES)
    model = ReleaseSeriesResult if series else PollResult
    checked = model.model_validate(restored)
    if canonical_bytes(native_model(checked)["request"], REQUEST_BYTES, budget=clock.budget) != captured:
        raise ReleaseFailure("operation_failed")
    if canonical_bytes(restored, RESULT_BYTES, budget=clock.budget, max_values=RESULT_BYTES) != wire:
        raise ReleaseFailure("operation_failed")
    clock.check()
    return Response(wire, media_type="application/json")


async def _execute(request: Request, *, series: bool) -> Response:
    clock = None
    try:
        clock = _start_invocation()
        authority = capture_authority(request)
        captured, value = await _read_request(request, clock, series=series)
        authority.require("write" if not series and value["persist"] else "read")
        # Decode the retained request afresh before lending it to the operation.
        value = cast(
            dict[str, Any], load_json(captured, REQUEST_BYTES, budget=clock.budget, max_values=64, max_depth=8)
        )
        if series:
            root = authority.store_root(clock.budget)
            wire, _ = await run_in_threadpool(_evaluate_wire, value, root, _clock=clock)
        else:
            prepare = _load_poll()
            root = authority.store_root(clock.budget) if value["persist"] else None
            operation = prepare(clock)
            accepted = await run_in_threadpool(operation.begin, value, evidence_store_dir=root)
            wire = accepted.output_bytes()
        authority.require("read")
        return _accepted(wire, captured, clock, series=series)
    except HTTPException:
        raise
    except Exception as error:
        if clock is not None:
            failure = clock.persistence.failure(error)
            if failure is not None:
                return Response(clock.persistence.wire(failure), status_code=500, media_type="application/json")
        return _failure(error if isinstance(error, ReleaseFailure) else ReleaseFailure("operation_failed"))


_RESPONSES: dict[int | str, dict[str, Any]] = {
    status: {"model": ReleaseError, "description": "A fixed bounded release refusal."}
    for status in {value[0] for value in ERRORS.values()}
}
_RESPONSES.update(
    {
        401: {"description": "Existing authentication middleware response."},
        403: {"description": "Configured authentication and granted read/write permission are required."},
    }
)


@router.post(
    "/collect/release-cadence",
    response_model=PollResult,
    responses=_RESPONSES,
    operation_id="collect_release_cadence",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": PollRequest.model_json_schema(mode="validation")}},
        }
    },
)
async def collect_release_cadence(request: Request) -> Response:
    return await _execute(request, series=False)


@router.post(
    "/conmon/release-series",
    response_model=ReleaseSeriesResult,
    responses=_RESPONSES,
    operation_id="evaluate_release_series",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {"application/json": {"schema": ReleaseSeriesRequest.model_json_schema(mode="validation")}},
        }
    },
)
async def evaluate_release_series(request: Request) -> Response:
    return await _execute(request, series=True)
