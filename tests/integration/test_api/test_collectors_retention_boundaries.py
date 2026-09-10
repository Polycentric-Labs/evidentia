"""Fragmented input, schema references and optional-package boundaries."""

from __future__ import annotations

import asyncio
import builtins
import importlib.util
import json
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_api.routers import storage_retention
from fastapi import FastAPI, HTTPException
from jsonschema import Draft202012Validator
from starlette.requests import Request

from .test_collectors_retention import VALID, Actor, full_result


def run_stream(
    monkeypatch: pytest.MonkeyPatch,
    messages: list[dict[str, Any]],
    *,
    authenticated: bool = True,
    content_type: str = "application/json",
) -> tuple[Any, int, Mock]:
    app = FastAPI()
    app.state.auth_provider = Actor() if authenticated else None
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/collectors/retention/collect",
        "app": app,
        "headers": [(b"content-type", content_type.encode()), (b"content-length", b"1")],
        "state": {"auth_principal": "synthetic-reader" if authenticated else None},
    }
    index = 0

    async def receive() -> dict[str, Any]:
        nonlocal index
        if index >= len(messages):
            raise AssertionError("read beyond the supplied body")
        message = messages[index]
        index += 1
        return message

    collect = Mock(return_value=full_result())
    monkeypatch.setattr(storage_retention, "_collect_storage_retention", collect)
    try:
        result: Any = asyncio.run(storage_retention.storage_retention_collect(Request(scope, receive)))
    except HTTPException as error:
        result = error
    return result, index, collect


@pytest.mark.parametrize("authenticated,media,expected", [(False, "text/plain", 403), (True, "text/plain", 415)])
def test_actor_and_media_denial_read_zero_stream_messages(
    monkeypatch: pytest.MonkeyPatch, authenticated: bool, media: str, expected: int
) -> None:
    result, reads, collect = run_stream(monkeypatch, [], authenticated=authenticated, content_type=media)
    assert isinstance(result, HTTPException) and result.status_code == expected
    assert reads == 0
    collect.assert_not_called()


@pytest.mark.parametrize("extra,expected", [(0, 200), (1, 413)])
def test_fragmented_cumulative_limit_stops_without_trusting_content_length(
    monkeypatch: pytest.MonkeyPatch, extra: int, expected: int
) -> None:
    body = json.dumps(VALID).encode()
    messages = [
        {"type": "http.request", "body": body[:17], "more_body": True},
        {"type": "http.request", "body": body[17:], "more_body": True},
        {"type": "http.request", "body": b" " * (65536 + extra - len(body)), "more_body": False},
    ]
    result, reads, collect = run_stream(monkeypatch, messages)
    assert reads == 3
    if expected == 200:
        assert result.status == "complete"
        collect.assert_called_once()
    else:
        assert isinstance(result, HTTPException) and result.status_code == expected
        collect.assert_not_called()


def test_disconnect_retains_no_partial_input(monkeypatch: pytest.MonkeyPatch) -> None:
    result, reads, collect = run_stream(
        monkeypatch,
        [
            {"type": "http.request", "body": b'{"scope_label":"private-value', "more_body": True},
            {"type": "http.disconnect"},
        ],
    )
    assert isinstance(result, HTTPException) and result.status_code == 400
    assert reads == 2
    assert "private-value" not in json.dumps(result.detail)
    collect.assert_not_called()


def test_openapi_input_union_has_resolvable_complete_constraints() -> None:
    app = FastAPI()
    app.include_router(storage_retention.router, prefix="/api")
    operation = app.openapi()["paths"]["/api/collectors/retention/collect"]["post"]
    schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert "$ref" not in json.dumps(schema)
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    valid_requests = [
        VALID,
        {
            "provider": "s3",
            "scope_label": "example",
            "targets": [{"bucket": "bucket-1", "region": "us-east-1"}],
        },
        {
            "provider": "azure",
            "scope_label": "example",
            "targets": [
                {
                    "subscription_id": "12345678-abcd-1234-abcd-123456789abc",
                    "resource_group": "Example",
                    "account": "account123",
                    "container": "container-1",
                }
            ],
        },
    ]
    invalid_updates: list[dict[str, object]] = [
        {"scope_label": "wrong\n"},
        {"scope_label": True},
        {"targets": []},
        {"extra": 1},
    ]
    for selected in valid_requests:
        validator.validate(selected)
        for update in invalid_updates:
            assert not validator.is_valid({**selected, **update})
    assert {"200", "400", "401", "403", "413", "415", "500", "503"} <= set(operation["responses"])
    assert "422" not in operation["responses"]


@pytest.fixture
def optional_probe(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    original = builtins.__import__

    def load(error: ImportError) -> ModuleType:
        def intercept(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "evidentia_collectors.retention":
                raise error
            return original(name, *args, **kwargs)

        spec = importlib.util.spec_from_file_location("retention_optional_probe", Path(storage_retention.__file__))
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with monkeypatch.context() as patch:
            patch.setattr(builtins, "__import__", intercept)
            spec.loader.exec_module(module)
        return module

    yield load


@pytest.mark.parametrize("missing", ["evidentia_collectors", "evidentia_collectors.retention"])
def test_only_exact_package_absence_registers_protected_fallback(optional_probe: Any, missing: str) -> None:
    module = optional_probe(ModuleNotFoundError("private-path", name=missing))
    assert module.configuration_status()["installed"] is False
    app = FastAPI()
    app.state.auth_provider = None
    scope = {"type": "http", "method": "POST", "path": "/", "app": app, "headers": []}
    with pytest.raises(HTTPException) as error:
        asyncio.run(module.storage_retention_unavailable(Request(scope)))
    assert error.value.status_code == 403
    app.state.auth_provider = Actor()
    scope["state"] = {"auth_principal": "synthetic-reader"}
    with pytest.raises(HTTPException) as error:
        asyncio.run(module.storage_retention_unavailable(Request(scope)))
    assert error.value.status_code == 503
    assert "private-path" not in json.dumps(error.value.detail)
    route = module.router.routes[0]
    assert len(route.dependencies) == 1


@pytest.mark.parametrize("missing", ["botocore.auth", "defusedxml.common", "unrelated_internal_module"])
def test_broken_transitive_package_is_not_optional_absence(optional_probe: Any, missing: str) -> None:
    with pytest.raises(ModuleNotFoundError) as error:
        optional_probe(ModuleNotFoundError("private-path", name=missing))
    assert error.value.name == missing


def test_import_error_is_not_optional_absence(optional_probe: Any) -> None:
    with pytest.raises(ImportError, match="private-path"):
        optional_probe(ImportError("private-path"))
