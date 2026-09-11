"""Bound raw ASGI bytes before parsing and expose complete strict schemas."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_api.routers import enterprise_retention
from evidentia_collectors.enterprise_retention import _contracts as contracts
from fastapi import FastAPI, HTTPException, Response
from jsonschema import Draft202012Validator
from starlette.requests import Request

from .test_collectors_enterprise_retention import VALID, Actor, full_result, registry


def run_stream(
    monkeypatch: pytest.MonkeyPatch,
    messages: Sequence[dict[str, Any] | Exception],
    *,
    authenticated: bool = True,
    content_type: str = "application/json",
    length: bytes | None = b"1",
) -> tuple[Any, int, Mock]:
    app = FastAPI()
    app.state.auth_provider = Actor() if authenticated else None
    app.state.enterprise_retention_profiles = registry()
    headers = [(b"content-type", content_type.encode())]
    if length is not None:
        headers.append((b"content-length", length))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/collectors/enterprise-retention/collect",
        "app": app,
        "headers": headers,
        "state": {"auth_principal": "synthetic-reader" if authenticated else None},
    }
    index = 0

    async def receive() -> dict[str, Any]:
        nonlocal index
        assert index < len(messages), "Read beyond the supplied body"
        message = messages[index]
        index += 1
        if isinstance(message, Exception):
            raise message
        return message

    worker = Mock(return_value=full_result())
    monkeypatch.setattr(enterprise_retention, "_collect_enterprise_retention", worker)
    try:
        result: Any = asyncio.run(enterprise_retention.enterprise_retention_collect(Request(scope, receive)))
    except HTTPException as error:
        result = error
    return result, index, worker


@pytest.mark.parametrize(
    "authenticated,media,status",
    [(False, "application/json", 403), (False, "text/plain", 403), (True, "text/plain", 415)],
)
def test_actor_and_media_denial_read_zero_chunks(
    monkeypatch: pytest.MonkeyPatch, authenticated: bool, media: str, status: int
) -> None:
    result, reads, worker = run_stream(monkeypatch, [], authenticated=authenticated, content_type=media)
    assert isinstance(result, HTTPException) and result.status_code == status
    assert reads == 0
    worker.assert_not_called()


@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("length", [None, b"1", b"9999999", b"invalid"])
def test_fragmented_actual_limit_is_independent_of_declared_size(
    monkeypatch: pytest.MonkeyPatch, extra: int, length: bytes | None
) -> None:
    raw = json.dumps(VALID).encode()
    messages = [
        {"type": "http.request", "body": raw[:13], "more_body": True},
        {"type": "http.request", "body": raw[13:], "more_body": True},
        {"type": "http.request", "body": b" " * (65536 + extra - len(raw)), "more_body": False},
    ]
    result, reads, worker = run_stream(monkeypatch, messages, length=length)
    assert reads == 3
    if extra:
        assert isinstance(result, HTTPException) and result.status_code == 413
        worker.assert_not_called()
    else:
        assert isinstance(result, Response) and result.status_code == 200
        assert (
            contracts.EnterpriseRetentionCollectResult.model_validate_json(bytes(result.body)).root.status == "complete"
        )
        worker.assert_called_once()


def test_oversized_chunk_refuses_before_next_receive(monkeypatch: pytest.MonkeyPatch) -> None:
    result, reads, worker = run_stream(monkeypatch, [{"type": "http.request", "body": b" " * 65537, "more_body": True}])
    assert isinstance(result, HTTPException) and result.status_code == 413 and reads == 1
    worker.assert_not_called()


def test_disconnect_does_not_publish_partial_input(monkeypatch: pytest.MonkeyPatch) -> None:
    result, reads, worker = run_stream(
        monkeypatch,
        [
            {"type": "http.request", "body": b'{"scope_label":"synthetic-private', "more_body": True},
            {"type": "http.disconnect"},
        ],
    )
    assert isinstance(result, HTTPException) and result.status_code == 400 and reads == 2
    assert "synthetic-private" not in json.dumps(result.detail)
    worker.assert_not_called()


def test_multibyte_utf8_is_counted_as_received_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = json.dumps({**VALID, "scope_label": "synthetic-" + "\u00e9" * 33000}, ensure_ascii=False).encode()
    result, reads, worker = run_stream(
        monkeypatch,
        [
            {"type": "http.request", "body": raw[:40000], "more_body": True},
            {"type": "http.request", "body": raw[40000:], "more_body": False},
        ],
    )
    assert isinstance(result, HTTPException) and result.status_code == 413 and reads == 2
    worker.assert_not_called()


@pytest.mark.parametrize("error_type", [RuntimeError, OSError])
def test_unexpected_stream_failure_returns_fixed_error(
    monkeypatch: pytest.MonkeyPatch, error_type: type[Exception]
) -> None:
    result, reads, worker = run_stream(
        monkeypatch,
        [
            {"type": "http.request", "body": b'{"scope_label":"synthetic-private', "more_body": True},
            error_type("synthetic-private-stream-error"),
        ],
    )
    assert isinstance(result, HTTPException) and result.status_code == 500 and reads == 2
    detail: object = result.detail
    assert detail == {
        "error": "collector_failed",
        "message": "Collection could not produce a valid result.",
    }
    assert "synthetic-private" not in json.dumps(result.detail)
    worker.assert_not_called()


def test_openapi_retains_every_request_branch_and_error_contract() -> None:
    app = FastAPI()
    app.include_router(enterprise_retention.router, prefix="/api")
    document = app.openapi()
    operation = document["paths"]["/api/collectors/enterprise-retention/collect"]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert "$ref" not in json.dumps(schema)
    Draft202012Validator.check_schema(schema)
    validate = Draft202012Validator(schema)
    selections: list[dict[str, Any]] = [
        VALID,
        {**VALID, "provider": "google-vault", "targets": [{"matter_id": "selected-matter"}]},
        {**VALID, "provider": "elastic-ilm"},
    ]
    for request in selections:
        validate.validate(request)
        updates: tuple[dict[str, Any], ...] = (
            {"scope_label": "invalid\n"},
            {"profile_alias": "invalid\n"},
            {"profile_alias": True},
            {"targets": []},
            {"extra": 1},
            {"targets": request["targets"] * 2},
        )
        for update in updates:
            assert not validate.is_valid({**request, **update})
    assert {"200", "400", "401", "403", "413", "415", "500", "503"} <= set(operation["responses"])
    assert "422" not in operation["responses"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/EnterpriseRetentionCollectResult"
    )
