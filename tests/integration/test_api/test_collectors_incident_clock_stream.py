"""Bound actual ASGI input before incident profile access."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import Sequence
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_api.routers import incident_clock
from evidentia_collectors.incident_clock import IncidentClockResult
from evidentia_collectors.incident_clock._contracts import validated_request
from evidentia_collectors.incident_clock._profiles import ProfileStore, authorize_api_selection
from fastapi import FastAPI, HTTPException, Response
from jsonschema import Draft202012Validator
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from .test_collectors_incident_clock import CONFIG, VALID, Actor, actual_result, configuration


def run_stream(
    monkeypatch: pytest.MonkeyPatch,
    messages: Sequence[dict[str, Any] | Exception],
    *,
    authenticated: bool = True,
    content_type: str = "application/json",
    length: bytes | None = None,
    result: IncidentClockResult | None = None,
) -> tuple[Any, int, Mock]:
    application = FastAPI()
    application.state.auth_provider = Actor() if authenticated else None
    application.state.incident_clock_profiles = ProfileStore(CONFIG)
    headers = [(b"content-type", content_type.encode())]
    if length is not None:
        headers.append((b"content-length", length))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/collectors/incident-clock",
        "app": application,
        "headers": headers,
        "state": {"auth_principal": "synthetic-reader" if authenticated else None},
    }
    index = 0

    async def receive() -> dict[str, Any]:
        nonlocal index
        assert index < len(messages), "Read beyond supplied input"
        message = messages[index]
        index += 1
        if isinstance(message, Exception):
            raise message
        return message

    worker = Mock(return_value=result or actual_result(monkeypatch))
    monkeypatch.setattr(incident_clock, "_collect_incident_clock", worker)
    try:
        response: Any = asyncio.run(incident_clock.collect_incident_clock(Request(scope, receive)))
    except HTTPException as error:
        response = error
    return response, index, worker


@pytest.mark.parametrize(
    "authenticated,media,status",
    [(False, "application/json", 403), (False, "text/plain", 403), (True, "text/plain", 415)],
)
def test_denial_consumes_no_body(monkeypatch: pytest.MonkeyPatch, authenticated: bool, media: str, status: int) -> None:
    response, reads, worker = run_stream(monkeypatch, [], authenticated=authenticated, content_type=media)
    assert isinstance(response, HTTPException) and response.status_code == status and reads == 0
    worker.assert_not_called()


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("length", [None, b"1", b"9999999", b"invalid"])
def test_actual_limit_with_fragmented_input(monkeypatch: pytest.MonkeyPatch, extra: int, length: bytes | None) -> None:
    raw = json.dumps(VALID).encode()
    messages = [
        {"type": "http.request", "body": raw[:13], "more_body": True},
        {"type": "http.request", "body": raw[13:], "more_body": True},
        {"type": "http.request", "body": b" " * (16384 + extra - len(raw)), "more_body": False},
    ]
    response, reads, worker = run_stream(monkeypatch, messages, length=length)
    assert reads == 3 and response.status_code == (413 if extra else 200)
    if extra:
        worker.assert_not_called()
    else:
        assert isinstance(response, Response)
        IncidentClockResult.model_validate_json(bytes(response.body))
        worker.assert_called_once()


def test_oversized_chunk_stops_before_another_read(monkeypatch: pytest.MonkeyPatch) -> None:
    response, reads, worker = run_stream(
        monkeypatch, [{"type": "http.request", "body": b" " * 16385, "more_body": True}]
    )
    assert response.status_code == 413 and reads == 1
    worker.assert_not_called()


@pytest.mark.parametrize("tail,status", [({"type": "http.disconnect"}, 400), (OSError("synthetic-stream-detail"), 500)])
def test_incomplete_and_failed_streams_are_fixed(monkeypatch: pytest.MonkeyPatch, tail: Any, status: int) -> None:
    response, reads, worker = run_stream(
        monkeypatch, [{"type": "http.request", "body": b'{"scope_label":"incomplete', "more_body": True}, tail]
    )
    assert response.status_code == status and reads == 2
    assert "synthetic-stream-detail" not in json.dumps(response.detail)
    worker.assert_not_called()


def test_multibyte_input_uses_byte_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = json.dumps({**VALID, "scope_label": "é" * 9000}, ensure_ascii=False).encode()
    response, reads, worker = run_stream(monkeypatch, [{"type": "http.request", "body": raw, "more_body": False}])
    assert response.status_code == 413 and reads == 1
    worker.assert_not_called()


def test_collection_runs_in_a_worker_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    caller = threading.get_ident()
    observed: list[int] = []
    result = actual_result(monkeypatch)
    from evidentia_collectors.incident_clock import IncidentClockCollector

    def collect(self: IncidentClockCollector, request: object) -> IncidentClockResult:
        observed.append(threading.get_ident())
        return result

    monkeypatch.setattr(IncidentClockCollector, "collect_v2", collect)
    selected = validated_request(VALID)
    profile = authorize_api_selection(ProfileStore(CONFIG), selected, principal="synthetic-reader")
    actual = asyncio.run(run_in_threadpool(incident_clock._collect_incident_clock, selected, profile))
    assert actual is result and len(observed) == 1 and observed[0] != caller


def test_openapi_describes_exact_request_variants_and_errors() -> None:
    application = FastAPI()
    application.include_router(incident_clock.router, prefix="/api")
    document = application.openapi()
    operation = document["paths"]["/api/collectors/incident-clock"]["post"]
    assert operation["operationId"] == "collect_incident_clock"
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    Draft202012Validator.check_schema(schema)
    validate = Draft202012Validator(schema)
    for provider in ("jira", "servicenow", "pagerduty"):
        request, _ = configuration(provider)
        validate.validate(request)
        for extra in ({**request, "extra": 1}, {**request, "record_id": False}, {**request, "profile_alias": 1}):
            assert not validate.is_valid(extra)
    assert set(operation["responses"]) == {"200", "400", "401", "403", "413", "415", "500", "503"}
