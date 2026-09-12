"""Bound actual ASGI input and verify full registry wire parity."""

from __future__ import annotations

import asyncio
import json
import re
import threading
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_api.routers import registry
from evidentia_collectors.registries import RegistryLookupRequest, RegistryLookupResult
from evidentia_collectors.registries._contracts import result_bytes
from fastapi import FastAPI, HTTPException, Response
from jsonschema import Draft202012Validator
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request

from .test_collectors_registry import VALID, Actor, actual_result


def demo_results() -> list[tuple[str, RegistryLookupResult, bytes]]:
    """Read unchanged real-collector synthetic wires from the public console corpus."""
    source = Path(__file__).resolve().parents[3] / "packages/evidentia-ui/src/lib/demo/registry-fixtures.ts"
    text = source.read_text(encoding="utf-8")
    match = re.search(r"const FIXTURES[^=]+ = (\[.*?\]);\s*export function registryDemoCases", text, re.DOTALL)
    assert match is not None
    rows = json.loads(match.group(1))
    results = []
    for row in rows:
        raw = row["raw"].encode("utf-8")
        result = RegistryLookupResult.model_validate_json(raw)
        wire = result_bytes(result)
        assert raw in (wire, wire + b"\n")
        results.append((row["name"], result, wire))
    assert len({result.registry for _, result, _ in results}) == 11
    return results


def run_stream(
    monkeypatch: pytest.MonkeyPatch,
    messages: Sequence[dict[str, Any] | Exception],
    *,
    authenticated: bool = True,
    content_type: str = "application/json",
    length: bytes | None = None,
    result: RegistryLookupResult | None = None,
) -> tuple[Any, int, Mock]:
    application = FastAPI()
    application.state.auth_provider = Actor() if authenticated else None
    headers = [(b"content-type", content_type.encode())]
    if length is not None:
        headers.append((b"content-length", length))
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/collectors/registry",
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

    worker = Mock(return_value=result or actual_result())
    monkeypatch.setattr(registry, "_collect_registry", worker)
    try:
        response: Any = asyncio.run(registry.collect_registry(Request(scope, receive)))
    except HTTPException as error:
        response = error
    return response, index, worker


@pytest.mark.parametrize(
    "authenticated,media,status",
    [(False, "application/json", 403), (False, "text/plain", 403), (True, "text/plain", 422)],
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
        {"type": "http.request", "body": b" " * (65536 + extra - len(raw)), "more_body": False},
    ]
    response, reads, worker = run_stream(monkeypatch, messages, length=length)
    assert reads == 3 and response.status_code == (422 if extra else 200)
    if extra:
        worker.assert_not_called()
    else:
        assert isinstance(response, Response)
        RegistryLookupResult.model_validate_json(bytes(response.body))
        worker.assert_called_once()


def test_oversized_chunk_stops_before_another_read(monkeypatch: pytest.MonkeyPatch) -> None:
    response, reads, worker = run_stream(
        monkeypatch, [{"type": "http.request", "body": b" " * 65537, "more_body": True}]
    )
    assert response.status_code == 422 and reads == 1
    worker.assert_not_called()


@pytest.mark.parametrize("tail,status", [({"type": "http.disconnect"}, 422), (OSError("synthetic-stream-detail"), 500)])
def test_incomplete_and_failed_streams_are_fixed(monkeypatch: pytest.MonkeyPatch, tail: Any, status: int) -> None:
    response, reads, worker = run_stream(
        monkeypatch, [{"type": "http.request", "body": b'{"scope_label":"incomplete', "more_body": True}, tail]
    )
    assert response.status_code == status and reads == 2
    assert "synthetic-stream-detail" not in json.dumps(response.detail)
    worker.assert_not_called()


def test_multibyte_input_uses_byte_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    raw = json.dumps({**VALID, "scope_label": "é" * 33000}, ensure_ascii=False).encode()
    response, reads, worker = run_stream(monkeypatch, [{"type": "http.request", "body": raw, "more_body": False}])
    assert response.status_code == 422 and reads == 1
    worker.assert_not_called()


@pytest.mark.parametrize("name,result,raw", demo_results(), ids=[item[0] for item in demo_results()])
def test_all_selector_wires_publish_exactly(
    monkeypatch: pytest.MonkeyPatch, name: str, result: RegistryLookupResult, raw: bytes
) -> None:
    body = result.request.model_dump_json().encode()
    response, reads, worker = run_stream(
        monkeypatch, [{"type": "http.request", "body": body, "more_body": False}], result=result
    )
    assert response.status_code == 200 and response.body == raw, name
    assert reads == 1
    worker.assert_called_once()


def test_collection_runs_in_one_worker_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    caller = threading.get_ident()
    observed: list[int] = []
    from evidentia_collectors.registries import RegistryCollector

    def collect(self: RegistryCollector, request: object) -> RegistryLookupResult:
        observed.append(threading.get_ident())
        return actual_result(request)

    monkeypatch.setattr(RegistryCollector, "collect_v2", collect)
    result = asyncio.run(run_in_threadpool(registry._collect_registry, RegistryLookupRequest.model_validate(VALID)))
    assert result.registry == "ssl-labs" and len(observed) == 1 and observed[0] != caller


def test_openapi_matches_full_request_and_authentication_contract() -> None:
    application = FastAPI()
    application.include_router(registry.router, prefix="/api")
    document = application.openapi()
    operation = document["paths"]["/api/collectors/registry"]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    Draft202012Validator.check_schema(schema)
    validate = Draft202012Validator(schema)
    for _, result, _ in demo_results():
        request = result.request.model_dump(mode="json")
        validate.validate(request)
        for extra in ({**request, "extra": 1}, {**request, "target": {}}, {**request, "scope_label": False}):
            assert not validate.is_valid(extra)
    auth = operation["responses"]["401"]["content"]["application/json"]["schema"]
    Draft202012Validator(auth).validate({"detail": "Unauthorized", "reason": None, "provider": "synthetic-provider"})
    assert set(operation["responses"]) == {"200", "401", "403", "422", "500", "503"}
