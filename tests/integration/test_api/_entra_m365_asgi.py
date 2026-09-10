"""Synthetic ASGI transport support without credentials or network access."""

from __future__ import annotations

import asyncio
import json
import socket
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

import pytest
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from evidentia_core.rbac import RBACPolicy, TenantRBACPolicy
from fastapi import FastAPI

ROUTE = "/api/collectors/entra-m365/collect"
LIMIT = 8_388_608
AUTH = b"Bearer SYNTHETIC_REVIEW_ACTOR"


class Provider(AuthProvider):
    def __init__(self, principal: str = "reviewer") -> None:
        self.principal = principal

    def authenticate(self, *, authorization_header: str | None) -> AuthResult:
        return AuthResult(
            authenticated=authorization_header == AUTH.decode(), principal=self.principal, reason="fixed refusal"
        )

    def name(self) -> str:
        return "synthetic-review"


def isolate(patch: pytest.MonkeyPatch, directory: Path) -> None:
    for name in (
        "EVIDENTIA_API_AUTH_TOKEN_FILE",
        "EVIDENTIA_RBAC_POLICY_FILE",
        "ENTRA_M365_ACCESS_TOKEN",
        "ENTRA_M365_RETENTION_ACCESS_TOKEN",
        "ENTRA_M365_AUTH_MODE",
        "EVIDENTIA_API_OFFLINE",
    ):
        patch.delenv(name, raising=False)
    patch.setenv("LITELLM_LOCAL_MODEL_COST_MAP", "true")
    patch.setenv("EVIDENTIA_GAP_STORE_DIR", str(directory / "gaps"))
    patch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(directory / "evidence"))
    patch.chdir(directory)

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("Real network is forbidden in API review")

    patch.setattr(socket, "getaddrinfo", refuse)
    patch.setattr(socket.socket, "connect", refuse)


def app(*, provider: AuthProvider | None = None, policy: RBACPolicy | TenantRBACPolicy | None = None) -> FastAPI:
    from evidentia_api.app import create_app

    application = create_app(auth_provider=provider, trust_proxy_headers=False)
    if policy is not None:
        application.state.rbac_policy = policy
    assert isinstance(application, FastAPI)
    return application


async def deliver(
    application: FastAPI,
    chunks: list[bytes],
    *,
    headers: list[tuple[bytes, bytes]] | None = None,
    disconnect: bool = False,
) -> tuple[int, dict[str, Any], int]:
    consumed = 0
    done = asyncio.Event()
    sent: list[MutableMapping[str, Any]] = []
    actual_headers = [(b"content-type", b"application/json"), (b"authorization", AUTH)] if headers is None else headers
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": ROUTE,
        "raw_path": ROUTE.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": actual_headers,
        "client": ("127.0.0.1", 42311),
        "server": ("review.invalid", 80),
        "state": {},
    }

    async def receive() -> dict[str, Any]:
        nonlocal consumed
        if consumed < len(chunks):
            index = consumed
            consumed += 1
            await asyncio.sleep(0)
            return {"type": "http.request", "body": chunks[index], "more_body": index < len(chunks) - 1 or disconnect}
        if disconnect:
            return {"type": "http.disconnect"}
        await done.wait()
        return {"type": "http.disconnect"}

    async def send(message: MutableMapping[str, Any]) -> None:
        sent.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            done.set()

    async with application.router.lifespan_context(application):
        await asyncio.wait_for(application(scope, receive, send), timeout=30)
    status = next(message["status"] for message in sent if message["type"] == "http.response.start")
    data = b"".join(message.get("body", b"") for message in sent if message["type"] == "http.response.body")
    return status, json.loads(data), consumed


def export(*, partial: bool = False, literal: str = "Policy") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": {
            "kind": "authored-synthetic",
            "producer": "Synthetic API transport fixture",
            "producer_version": None,
            "captured_at": None,
            "parent_sha256": None,
            "source_uri": None,
            "sanitization": "synthetic",
        },
        "policies": [
            {
                "Guid": "p",
                "Name": literal,
                "Mode": "Enable",
                "DistributionStatus": "Pending",
                "Workload": "Exchange",
                "Enabled": True,
                "IsValid": True,
            }
        ]
        if partial or literal != "Policy"
        else [],
        "rules": [
            {
                "Guid": "r",
                "Policy": "unmatched",
                "ParentPolicyName": None,
                "Mode": "Enforce",
                "Workload": "Exchange",
                "Disabled": False,
                "IsValid": True,
            }
        ]
        if partial
        else [],
    }


def request_body(state: str = "complete", *, literal: str = "Policy") -> bytes:
    value: dict[str, Any] = {"tenant_label": "review", "capabilities": ["dlp-export"]}
    if state != "unavailable":
        value["dlp_content"] = json.dumps(export(partial=state == "partial", literal=literal), ensure_ascii=False)
    return json.dumps(value, ensure_ascii=False).encode()
