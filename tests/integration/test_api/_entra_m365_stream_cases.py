"""Fragmented request streams, full results, and safe API serialization."""

from __future__ import annotations

import asyncio
import json
import threading
import warnings
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from evidentia_core.rbac import RBACPolicy, Role, TenantRBACPolicy

from ._entra_m365_asgi import AUTH, LIMIT, Provider, app, deliver, isolate, request_body


@pytest.fixture(autouse=True)
async def environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> AsyncIterator[None]:
    isolate(monkeypatch, tmp_path)
    from evidentia_collectors.entra_m365 import _client

    refuse = Mock(side_effect=AssertionError("No environment credential or Graph access"))
    monkeypatch.setattr(_client._EnvironmentCredentials, "resolve", refuse)
    monkeypatch.setattr(_client.EntraM365GraphReader, "read_collection", refuse)
    yield
    assert refuse.call_count == 0


@pytest.mark.parametrize("content_length", [None, b"1", b"999999999"])
@pytest.mark.parametrize("excess", [0, 1])
async def test_raw_fragmented_asgi_size_boundary(
    content_length: bytes | None, excess: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_api.routers import collectors

    collect = Mock(side_effect=AssertionError("No collector expected"))
    monkeypatch.setattr(collectors, "_collect_entra_m365", collect)
    start = b'{"tenant_label":"review","capabilities":["directory-roles"]}'
    body = start + b" " * (LIMIT + excess - len(start))
    chunks = [body[index : index + 1048576] for index in range(0, len(body), 1048576)]
    if excess:
        chunks.append(b"SENTINEL_MUST_NOT_BE_READ")
    headers = [(b"content-type", b"application/json")]
    if content_length is not None:
        headers.append((b"content-length", content_length))
    status, payload, consumed = await deliver(app(), chunks, headers=headers)
    assert status == (413 if excess else 403)
    assert payload["detail"]["error"] == ("response_limit" if excess else "auth_not_configured")
    assert consumed == (len(chunks) - 1 if excess else len(chunks))
    assert collect.call_count == 0


@pytest.mark.parametrize("state", ["complete", "partial", "unavailable"])
async def test_actual_collector_preserves_200_full_result_schema(state: str) -> None:
    application = app(
        provider=Provider(), policy=RBACPolicy(identities={"reviewer": Role.READER}, default_role=Role.DENY)
    )
    raw = request_body(state)
    status, payload, consumed = await deliver(application, [raw[:3], b"", raw[3:21], raw[21:]])
    assert status == 200 and payload["status"] == state and consumed == 4
    assert len(payload["capabilities"]) == 9
    assert payload["capabilities"][6]["state"] == state
    assert payload["manifest"]["is_complete"] is (state == "complete")
    assert payload["capabilities"][6]["requests_attempted"] == 0
    assert payload["capabilities"][6]["credential_basis"] == "unverified:dlp-export"
    assert payload["capabilities"][6]["declared_auth_mode"] is None
    assert payload["provenance"]["authenticated_identity_verified"] is False
    assert len(payload["findings"]) == (2 if state == "partial" else 0)
    assert payload["manifest"]["empty_categories"] == (["dlp-export"] if state == "complete" else [])
    from evidentia_collectors.entra_m365 import EntraM365CollectResult

    checked = EntraM365CollectResult.model_validate_json(json.dumps(payload))
    assert checked.model_dump(mode="json") == payload
    operation = application.openapi()["paths"]["/api/collectors/entra-m365/collect"]["post"]
    assert operation["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith(
        "/EntraM365CollectResult"
    )


async def test_utf8_split_inside_literal_export_scalar() -> None:
    raw = request_body(literal="literal \u00e9 and <script>text</script>")
    index = raw.index(b"\xc3\xa9")
    status, payload, _ = await deliver(app(), [raw[: index + 1], raw[index + 1 :]])
    assert status == 200
    assert payload["findings"][0]["raw_data"]["source"]["Name"] == "literal \u00e9 and <script>text</script>"


@pytest.mark.parametrize("case", ["unauthenticated", "invalid_auth", "actor_deny", "tenant_deny", "anonymous_deny"])
async def test_auth_refusal_never_consumes_asgi_body_or_calls_collector(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from evidentia_api.routers import collectors

    collect = Mock(side_effect=AssertionError("No denied collector"))
    monkeypatch.setattr(collectors, "_collect_entra_m365", collect)
    provider: Provider | None = Provider()
    policy: RBACPolicy | TenantRBACPolicy = RBACPolicy(default_role=Role.READER)
    headers = [(b"content-type", b"application/json"), (b"authorization", AUTH)]
    if case in ("unauthenticated", "invalid_auth"):
        headers = [(b"content-type", b"application/json")]
        if case == "invalid_auth":
            headers.append((b"authorization", b"Bearer invalid-synthetic"))
    elif case == "actor_deny":
        policy = RBACPolicy(identities={"body-tenant-alias": Role.READER}, default_role=Role.DENY)
    elif case == "tenant_deny":
        provider = Provider("reviewer@@denied")
        policy = TenantRBACPolicy(
            tenants={
                "denied": RBACPolicy(default_role=Role.DENY),
                "body-tenant-alias": RBACPolicy(default_role=Role.READER),
            }
        )
    else:
        provider = None
        policy = RBACPolicy(default_role=Role.DENY)
    status, payload, consumed = await deliver(
        app(provider=provider, policy=policy), [b"SENSITIVE_MALFORMED_BODY"], headers=headers
    )
    assert status == (401 if case in ("unauthenticated", "invalid_auth") else 403)
    assert consumed == 0 and collect.call_count == 0
    assert "SENSITIVE_MALFORMED_BODY" not in json.dumps(payload)


async def test_real_client_disconnect_is_sanitized_without_collection(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_api.routers import collectors

    collect = Mock(side_effect=AssertionError("No incomplete collector"))
    monkeypatch.setattr(collectors, "_collect_entra_m365", collect)
    status, payload, consumed = await deliver(app(), [b'{"secret":'], disconnect=True)
    assert (status, consumed) == (400, 1) and collect.call_count == 0
    assert payload["detail"] == {"error": "invalid_body", "message": "The request body is incomplete."}


@pytest.mark.parametrize("failure", ["exception", "wrong_type", "invalid_total", "invalid_clock"])
async def test_invalid_collector_result_is_fixed_500(
    failure: str, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    from evidentia_api.routers import collectors
    from evidentia_collectors.entra_m365 import EntraM365Collector, EntraM365CollectRequest

    real = EntraM365Collector.collect_v2

    def bad(self: Any, request: EntraM365CollectRequest) -> Any:
        if failure == "exception":
            raise RuntimeError("SENSITIVE_RESULT_MARKER")
        if failure == "wrong_type":
            return {"SENSITIVE_RESULT_MARKER": True}
        result = real(self, request)
        if failure == "invalid_total":
            result.manifest.total_findings = 999
        else:
            result.manifest = result.manifest.model_copy(update={"collection_finished_at": "SENSITIVE_RESULT_MARKER"})
        return result

    monkeypatch.setattr(collectors.EntraM365Collector, "collect_v2", bad)
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        status, payload, _ = await deliver(app(), [request_body()])
    captured = capsys.readouterr()
    assert status == 500
    assert payload["detail"] == {"error": "collector_failed", "message": "Collection could not produce a valid result."}
    diagnostic_text = json.dumps(payload) + caplog.text + captured.out + captured.err
    diagnostic_text += "".join(str(item.message) for item in observed)
    assert "SENSITIVE_RESULT_MARKER" not in diagnostic_text
    assert not observed


async def test_real_collection_runs_off_event_loop_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_api.routers import collectors

    original = collectors.EntraM365Collector.collect_v2
    called: list[int] = []

    def record(self: Any, request: Any) -> Any:
        called.append(threading.get_ident())
        return original(self, request)

    monkeypatch.setattr(collectors.EntraM365Collector, "collect_v2", record)
    loop_thread = threading.get_ident()
    status, _, _ = await deliver(app(), [request_body()])
    assert status == 200 and len(called) == 1 and called[0] != loop_thread
    await asyncio.sleep(0)
