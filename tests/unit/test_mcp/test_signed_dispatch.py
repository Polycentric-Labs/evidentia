"""Verify signed MCP results, wire aliases, and authorization composition."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import math
import sys
import types
from collections.abc import Callable
from datetime import UTC, date, datetime
from decimal import Decimal
from typing import Any
from unittest.mock import AsyncMock, MagicMock, Mock

import anyio
import pytest
from evidentia_mcp.cimd import CIMDDocument, CIMDRegistry
from evidentia_mcp.server import EvidentiaMCPServer, build_server
from evidentia_mcp.signatures import (
    EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR,
    EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
)
from evidentia_mcp.signed_dispatch import SIGNED_OUTPUT_META_KEY, wrap_signed_output
from mcp import Client
from mcp.client._memory import InMemoryTransport
from mcp.client.session import ClientSession
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.server.session import ServerSession
from mcp.shared.exceptions import MCPError
from mcp.types import (
    INVALID_PARAMS,
    Annotations,
    AudioContent,
    BlobResourceContents,
    CallToolRequestParams,
    CallToolResult,
    ClientCapabilities,
    ContentBlock,
    EmbeddedResource,
    ImageContent,
    Implementation,
    InitializedNotification,
    InitializeRequest,
    InitializeRequestParams,
    InitializeResult,
    InputRequiredResult,
    ResourceLink,
    TextContent,
    TextResourceContents,
)
from pydantic import BaseModel, Field

_TEST_HMAC_KEY = b"v0.9.8-signed-dispatch-test-key"


def make_test_signer() -> Callable[[bytes], dict[str, str]]:
    """Return a deterministic synthetic signer for environment opt-in tests."""

    def sign(payload: bytes) -> dict[str, str]:
        return {"alg": "hmac-sha256", "sig": hmac.new(_TEST_HMAC_KEY, payload, hashlib.sha256).hexdigest()}

    return sign


def make_failing_signer() -> Callable[[bytes], dict[str, str]]:
    """Exercise the existing nonfatal signer-error envelope."""

    def sign(payload: bytes) -> dict[str, str]:
        raise RuntimeError("HSM unavailable in test")

    return sign


@pytest.fixture(autouse=True)
def register_test_module(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("test_signed_dispatch_helpers")
    module.__dict__.update(make_test_signer=make_test_signer, make_failing_signer=make_failing_signer)
    monkeypatch.setitem(sys.modules, module.__name__, module)


def enable_signing(monkeypatch: pytest.MonkeyPatch, *, factory: str = "make_test_signer") -> None:
    monkeypatch.setenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, "1")
    monkeypatch.setenv(EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR, f"test_signed_dispatch_helpers:{factory}")


def server_returning(result: CallToolResult | InputRequiredResult) -> tuple[EvidentiaMCPServer, AsyncMock]:
    server = EvidentiaMCPServer("test-signed-dispatch")
    inner = AsyncMock(return_value=result)
    server._evidentia_dispatch = inner
    return server, inner


def envelope(result: CallToolResult | InputRequiredResult) -> dict[str, Any]:
    assert isinstance(result, CallToolResult)
    assert result.meta is not None
    value = result.meta[SIGNED_OUTPUT_META_KEY]
    assert isinstance(value, dict)
    return value


def request_context(
    server: EvidentiaMCPServer, client_id: str, *, protocol_version: str = "2026-07-28"
) -> Context[Any, Any]:
    return Context(
        mcp_server=server,
        request_context=ServerRequestContext(
            session=MagicMock(spec=ServerSession),
            lifespan_context={},
            protocol_version=protocol_version,
            method="tools/call",
            meta=CallToolRequestParams.model_validate({"name": "synthetic", "_meta": {"client_id": client_id}}).meta,
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("structured", [None, {}, {"ok": True}])
@pytest.mark.parametrize("is_error", [False, True])
async def test_disabled_signing_returns_original_result(structured: dict[str, Any] | None, is_error: bool) -> None:
    original = CallToolResult(content=[TextContent(text="plain")], structured_content=structured, is_error=is_error)
    original.meta = {"other/provenance": {"retained": True}}
    server, inner = server_returning(original)
    wrap_signed_output(server)

    assert await server.call_tool("tool", {}) is original
    inner.assert_awaited_once_with("tool", {}, None)


@pytest.mark.asyncio
@pytest.mark.parametrize("with_context", [False, True])
async def test_forwards_original_arguments_and_context(with_context: bool, synthetic_signer: list[bytes]) -> None:
    server, inner = server_returning(CallToolResult(content=[], structured_content={"ok": True}))
    context = request_context(server, "synthetic-client") if with_context else None
    arguments = {"nested": [1, {"flag": True}]}
    wrap_signed_output(server)

    result = await server.call_tool("tool", arguments, context)

    inner.assert_awaited_once_with("tool", arguments, context)
    assert inner.await_args is not None
    assert inner.await_args.args[1] is arguments
    assert inner.await_args.args[2] is context
    assert envelope(result)["payload"] == {"ok": True}
    assert len(synthetic_signer) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("structured", [{}, {"z": 2, "a": [True, None, "\u2603"]}])
async def test_structured_payload_has_independent_canonical_digest(
    monkeypatch: pytest.MonkeyPatch, structured: dict[str, Any]
) -> None:
    enable_signing(monkeypatch)
    original = CallToolResult(content=[TextContent(text="alternate display")], structured_content=structured)
    server, _ = server_returning(original)
    wrap_signed_output(server)

    result = await server.call_tool("get_control", {})

    assert isinstance(result, CallToolResult)
    assert result.structured_content == structured
    assert result.content == original.content
    signed = envelope(result)
    expected = b"{}" if structured == {} else b'{"a":[true,null,"\\u2603"],"z":2}'
    assert signed["payload"] == structured
    assert signed["schema_version"] == 1
    assert signed["tool_name"] == "get_control"
    assert signed["signing_error"] is None
    assert signed["signature"] == {
        "alg": "hmac-sha256",
        "sig": hmac.new(_TEST_HMAC_KEY, expected, hashlib.sha256).hexdigest(),
    }


class NestedAliasedValue(BaseModel):
    optional: str | None = None
    named_value: str = Field(serialization_alias="namedValue")


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["default", "legacy"])
@pytest.mark.parametrize(
    ("value", "wire_value"),
    [
        (datetime(2000, 1, 2, 3, 4, 5, tzinfo=UTC), "2000-01-02T03:04:05Z"),
        (date(2000, 1, 2), "2000-01-02"),
        (b"synthetic", "synthetic"),
        (Decimal("1.20"), "1.20"),
        (math.nan, None),
        (math.inf, None),
        (-math.inf, None),
        ((1, "two"), [1, "two"]),
        (NestedAliasedValue(named_value="aliased"), {"namedValue": "aliased"}),
        (
            {"plain_null": None, "model": NestedAliasedValue(named_value="nested")},
            {"plain_null": None, "model": {"namedValue": "nested"}},
        ),
    ],
)
async def test_real_protocol_digest_matches_transported_structured_value(
    monkeypatch: pytest.MonkeyPatch, mode: str, value: Any, wire_value: Any
) -> None:
    enable_signing(monkeypatch)
    server = EvidentiaMCPServer("wire-normalization")

    @server.tool()
    def synthetic_value() -> CallToolResult:
        return CallToolResult(content=[TextContent(text="synthetic display")], structured_content={"value": value})

    wrap_signed_output(server)
    client = Client(server) if mode == "default" else Client(server, mode="legacy")
    with anyio.fail_after(8):
        async with client:
            result = await client.call_tool("synthetic_value", {})

    assert not result.is_error
    expected_payload = {"value": wire_value}
    expected_bytes = json.dumps(expected_payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    assert result.structured_content == expected_payload
    signed = envelope(result)
    assert signed["payload"] == expected_payload
    assert signed["signature"] == {
        "alg": "hmac-sha256",
        "sig": hmac.new(_TEST_HMAC_KEY, expected_bytes, hashlib.sha256).hexdigest(),
    }


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["default", "legacy"])
async def test_real_protocol_content_metadata_normalization(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    enable_signing(monkeypatch)
    server = EvidentiaMCPServer("content-normalization")

    @server.tool()
    def synthetic_content() -> CallToolResult:
        return CallToolResult(
            content=[
                TextContent(
                    text="synthetic",
                    meta={
                        "model": NestedAliasedValue(named_value="aliased"),
                        "raw_null": None,
                        "measurement": math.nan,
                    },
                )
            ]
        )

    wrap_signed_output(server)
    client = Client(server) if mode == "default" else Client(server, mode="legacy")
    with anyio.fail_after(8):
        async with client:
            result = await client.call_tool("synthetic_content", {})

    assert not result.is_error
    expected_metadata: dict[str, Any] = {"model": {"namedValue": "aliased"}}
    if mode == "legacy":
        expected_metadata.update(raw_null=None, measurement=None)
    expected_payload = {
        "result": [{"type": "text", "text": "synthetic", "annotations": None, "_meta": expected_metadata}]
    }
    expected_bytes = json.dumps(expected_payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    assert result.content[0].meta == expected_metadata
    signed = envelope(result)
    assert signed["payload"] == expected_payload
    assert signed["signature"]["sig"] == hmac.new(_TEST_HMAC_KEY, expected_bytes, hashlib.sha256).hexdigest()


@pytest.mark.asyncio
@pytest.mark.parametrize("with_context", [False, True])
async def test_direct_content_normalizes_nested_models_without_assuming_protocol(
    synthetic_signer: list[bytes], with_context: bool
) -> None:
    content = TextContent(text="direct", meta={"model": NestedAliasedValue(named_value="aliased"), "raw_null": None})
    server, _ = server_returning(CallToolResult(content=[content]))
    wrap_signed_output(server)
    context = Context[Any, Any]() if with_context else None

    result = await server.call_tool("tool", {}, context)

    expected_payload = {
        "result": [
            {
                "type": "text",
                "text": "direct",
                "annotations": None,
                "_meta": {"model": {"namedValue": "aliased"}, "raw_null": None},
            }
        ]
    }
    assert envelope(result)["payload"] == expected_payload
    assert len(synthetic_signer) == 1


@pytest.mark.anyio
@pytest.mark.parametrize("protocol_version", ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"])
async def test_negotiated_handshake_versions_preserve_structured_signing(
    protocol_version: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    enable_signing(monkeypatch)
    server = EvidentiaMCPServer("handshake-versions")

    @server.tool()
    def synthetic_value() -> CallToolResult:
        return CallToolResult(
            content=[TextContent(text="older display")], structured_content={"value": "newer structure"}
        )

    wrap_signed_output(server)
    with anyio.fail_after(8):
        async with InMemoryTransport(server) as (read, write), ClientSession(read, write) as session:
            initialized = await session.send_request(
                InitializeRequest(
                    params=InitializeRequestParams(
                        protocol_version=protocol_version,
                        capabilities=ClientCapabilities(),
                        client_info=Implementation(name="synthetic-signing-test", version="1"),
                    )
                ),
                InitializeResult,
            )
            assert initialized.protocol_version == protocol_version
            session.adopt(initialized)
            await session.send_notification(InitializedNotification())
            result = await session.call_tool("synthetic_value", {})
            assert len((await session.list_tools()).tools) == 1

    assert not result.is_error
    assert isinstance(result, CallToolResult)
    expected_payload = {"value": "newer structure"}
    assert result.structured_content == expected_payload
    assert envelope(result)["payload"] == expected_payload
    expected_bytes = b'{"value":"newer structure"}'
    assert envelope(result)["signature"]["sig"] == hmac.new(_TEST_HMAC_KEY, expected_bytes, hashlib.sha256).hexdigest()


def content_cases() -> list[tuple[ContentBlock, dict[str, Any]]]:
    """Specify expected wire objects independently of model serialization."""
    return [
        (
            TextContent(text="alpha", meta={"source": "synthetic"}),
            {"type": "text", "text": "alpha", "annotations": None, "_meta": {"source": "synthetic"}},
        ),
        (
            ImageContent(
                data="AA==",
                mime_type="image/png",
                annotations=Annotations(audience=["user"], priority=0.5, last_modified="2000-01-01T00:00:00Z"),
            ),
            {
                "type": "image",
                "data": "AA==",
                "mimeType": "image/png",
                "annotations": {"audience": ["user"], "priority": 0.5, "lastModified": "2000-01-01T00:00:00Z"},
                "_meta": None,
            },
        ),
        (
            AudioContent(data="AQ==", mime_type="audio/wav"),
            {"type": "audio", "data": "AQ==", "mimeType": "audio/wav", "annotations": None, "_meta": None},
        ),
        (
            EmbeddedResource(
                resource=TextResourceContents(uri="evidentia://synthetic/text", mime_type="text/plain", text="source")
            ),
            {
                "type": "resource",
                "resource": {
                    "uri": "evidentia://synthetic/text",
                    "mimeType": "text/plain",
                    "text": "source",
                    "_meta": None,
                },
                "annotations": None,
                "_meta": None,
            },
        ),
        (
            EmbeddedResource(
                resource=BlobResourceContents(
                    uri="evidentia://synthetic/blob",
                    mime_type="application/octet-stream",
                    blob="Ag==",
                    meta={"source": "fixture"},
                )
            ),
            {
                "type": "resource",
                "resource": {
                    "uri": "evidentia://synthetic/blob",
                    "mimeType": "application/octet-stream",
                    "blob": "Ag==",
                    "_meta": {"source": "fixture"},
                },
                "annotations": None,
                "_meta": None,
            },
        ),
        (
            ResourceLink(name="fixture", uri="evidentia://synthetic/link", mime_type="text/plain", size=3),
            {
                "name": "fixture",
                "title": None,
                "uri": "evidentia://synthetic/link",
                "description": None,
                "mimeType": "text/plain",
                "size": 3,
                "icons": None,
                "annotations": None,
                "_meta": None,
                "type": "resource_link",
            },
        ),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(("content", "expected_wire"), content_cases())
async def test_content_only_digest_uses_wire_aliases(
    content: ContentBlock, expected_wire: dict[str, Any], synthetic_signer: list[bytes]
) -> None:
    original = CallToolResult(content=[content])
    server, _ = server_returning(original)
    wrap_signed_output(server)

    result = await server.call_tool("content_tool", {})

    assert isinstance(result, CallToolResult)
    assert result.content == [content]
    assert result.structured_content is None
    payload = {"result": [expected_wire]}
    expected = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert envelope(result)["payload"] == payload
    assert synthetic_signer == [expected]
    assert envelope(result)["signature"]["digest"] == hashlib.sha256(expected).hexdigest()


@pytest.mark.asyncio
async def test_empty_content_signs_empty_result_array(synthetic_signer: list[bytes]) -> None:
    server, _ = server_returning(CallToolResult(content=[]))
    wrap_signed_output(server)
    result = await server.call_tool("empty_tool", {})
    assert envelope(result)["payload"] == {"result": []}
    assert synthetic_signer == [b'{"result":[]}']


@pytest.mark.asyncio
async def test_preserves_sdk_type_fields_and_metadata_without_mutating_input(synthetic_signer: list[bytes]) -> None:
    class ExtendedResult(CallToolResult):
        diagnostic: str

    original = ExtendedResult(
        content=[TextContent(text="existing tool failure")],
        structured_content={"error": "synthetic"},
        is_error=True,
        result_type="complete",
        meta={"other/provenance": {"value": [1, 2]}, SIGNED_OUTPUT_META_KEY: {"old": True}},
        diagnostic="retained extension",
    )
    before = original.model_dump(mode="json", by_alias=True)
    server, _ = server_returning(original)
    wrap_signed_output(server)

    result = await server.call_tool("failing_tool", {})

    assert type(result) is ExtendedResult
    assert isinstance(result, CallToolResult)
    assert result is not original
    assert result.content is original.content
    assert result.structured_content is original.structured_content
    assert result.is_error is True
    assert result.result_type == "complete"
    assert result.meta is not original.meta
    assert result.model_dump(mode="json", by_alias=True, exclude={"meta"}) == original.model_dump(
        mode="json", by_alias=True, exclude={"meta"}
    )
    assert result.meta is not None
    assert result.meta["other/provenance"] == {"value": [1, 2]}
    assert envelope(result)["payload"] == {"error": "synthetic"}
    assert original.model_dump(mode="json", by_alias=True) == before
    assert synthetic_signer == [b'{"error":"synthetic"}']


@pytest.mark.asyncio
@pytest.mark.parametrize("is_error", [False, True])
async def test_signer_failure_preserves_existing_result(monkeypatch: pytest.MonkeyPatch, is_error: bool) -> None:
    enable_signing(monkeypatch, factory="make_failing_signer")
    original = CallToolResult(content=[TextContent(text="x")], structured_content={"ok": True}, is_error=is_error)
    server, _ = server_returning(original)
    wrap_signed_output(server)

    result = await server.call_tool("tool", {})

    assert isinstance(result, CallToolResult)
    assert result.content == original.content
    assert result.structured_content == original.structured_content
    assert result.is_error is is_error
    assert envelope(result)["signature"] is None
    assert envelope(result)["signing_error"] == "HSM unavailable in test"


@pytest.mark.asyncio
async def test_signer_is_resolved_once_after_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []

    async def inner(name: str, arguments: dict[str, Any], context: Context[Any, Any] | None) -> CallToolResult:
        events.append("handler")
        return CallToolResult(content=[], structured_content={"ok": True})

    def signer(payload: bytes) -> dict[str, str]:
        events.append("signer")
        return {"digest": hashlib.sha256(payload).hexdigest()}

    def resolve() -> Callable[[bytes], dict[str, str]]:
        events.append("resolve")
        return signer

    monkeypatch.setattr("evidentia_mcp.signed_dispatch._resolve_signer_factory", resolve)
    duplicate_resolution = Mock(side_effect=AssertionError("signer resolved twice"))
    monkeypatch.setattr("evidentia_mcp.signatures._resolve_signer_factory", duplicate_resolution)
    server = EvidentiaMCPServer("signer-order")
    server._evidentia_dispatch = inner
    wrap_signed_output(server)

    assert envelope(await server.call_tool("tool", {}))["signature"] is not None
    assert events == ["handler", "resolve", "signer"]
    duplicate_resolution.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("structured", [[], [1, {"ok": True}], "scalar", 7, 1.5, False])
async def test_non_object_structured_results_pass_through_without_signer_resolution(
    monkeypatch: pytest.MonkeyPatch, structured: Any
) -> None:
    original = CallToolResult(
        content=[TextContent(text="display")], structured_content=structured, meta={"other": "retained"}
    )
    resolver = Mock(side_effect=AssertionError("unsupported output must not resolve signer"))
    monkeypatch.setattr("evidentia_mcp.signed_dispatch._resolve_signer_factory", resolver)
    server, _ = server_returning(original)
    wrap_signed_output(server)

    assert await server.call_tool("tool", {}) is original
    resolver.assert_not_called()


@pytest.mark.asyncio
async def test_input_required_passes_through_without_signer_resolution(monkeypatch: pytest.MonkeyPatch) -> None:
    original = InputRequiredResult(request_state="synthetic-state", meta={"other": {"retained": True}})
    resolver = Mock(side_effect=AssertionError("input-required output must not resolve signer"))
    monkeypatch.setattr("evidentia_mcp.signed_dispatch._resolve_signer_factory", resolver)
    server, inner = server_returning(original)
    context = request_context(server, "synthetic-client")
    wrap_signed_output(server)

    assert await server.call_tool("tool", {}, context) is original
    inner.assert_awaited_once_with("tool", {}, context)
    resolver.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [RuntimeError("handler failed"), MCPError(INVALID_PARAMS, "denied"), asyncio.CancelledError()],
)
async def test_inner_failure_never_resolves_signer(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    server = EvidentiaMCPServer("inner-error")
    server._evidentia_dispatch = AsyncMock(side_effect=error)
    resolver = Mock(side_effect=AssertionError("failed dispatch must not resolve signer"))
    monkeypatch.setattr("evidentia_mcp.signed_dispatch._resolve_signer_factory", resolver)
    wrap_signed_output(server)

    with pytest.raises(type(error)) as raised:
        await server.call_tool("tool", {})
    assert raised.value is error
    resolver.assert_not_called()


@pytest.mark.asyncio
async def test_scope_denial_excludes_handler_and_signer(monkeypatch: pytest.MonkeyPatch) -> None:
    from evidentia_mcp.scope import enforce_cimd_scope

    server, inner = server_returning(CallToolResult(content=[], structured_content={"ok": True}))
    server.evidentia_cimd = CIMDRegistry(
        clients={"test-client": CIMDDocument(client_id="test-client", client_name="Test", scope="other_tool")}
    )
    resolver = Mock(side_effect=AssertionError("denied dispatch must not resolve signer"))
    monkeypatch.setattr("evidentia_mcp.signed_dispatch._resolve_signer_factory", resolver)
    enforce_cimd_scope(server)
    wrap_signed_output(server)

    with pytest.raises(MCPError) as raised:
        await server.call_tool("denied_tool", {}, request_context(server, "test-client"))
    assert raised.value.code == INVALID_PARAMS
    inner.assert_not_awaited()
    resolver.assert_not_called()


def test_double_wrap_rejects_without_replacing_dispatch() -> None:
    server = EvidentiaMCPServer("double-wrap")
    wrap_signed_output(server)
    dispatch = server._evidentia_dispatch
    with pytest.raises(RuntimeError, match="already wired"):
        wrap_signed_output(server)
    assert server._evidentia_dispatch is dispatch


@pytest.mark.asyncio
async def test_repeated_signing_has_same_payload_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    enable_signing(monkeypatch)
    server, _ = server_returning(CallToolResult(content=[], structured_content={"ok": True}))
    wrap_signed_output(server)
    first = envelope(await server.call_tool("tool", {}))
    second = envelope(await server.call_tool("tool", {}))
    assert first["payload"] == second["payload"] == {"ok": True}
    assert first["signature"] == second["signature"]


@pytest.mark.asyncio
@pytest.mark.parametrize("signed", [False, True])
async def test_real_sdk_tool_conversion_preserves_structured_output(
    monkeypatch: pytest.MonkeyPatch, signed: bool
) -> None:
    server = EvidentiaMCPServer("real-conversion")

    @server.tool()
    def double_it(x: int) -> dict[str, Any]:
        """Return a synthetic structured result from a synchronous handler."""
        return {"doubled": x * 2, "tool": "double_it"}

    if signed:
        enable_signing(monkeypatch)
    wrap_signed_output(server)

    result = await server.call_tool("double_it", {"x": 21})

    assert isinstance(result, CallToolResult)
    assert result.is_error is False
    assert result.structured_content == {"doubled": 42, "tool": "double_it"}
    assert len(result.content) == 1
    assert isinstance(result.content[0], TextContent)
    assert json.loads(result.content[0].text) == result.structured_content
    if signed:
        assert envelope(result)["payload"] == result.structured_content
    else:
        assert result.meta is None or SIGNED_OUTPUT_META_KEY not in result.meta


@pytest.mark.asyncio
async def test_build_server_wires_real_tool_signing(monkeypatch: pytest.MonkeyPatch) -> None:
    enable_signing(monkeypatch)
    server = build_server()
    assert server._evidentia_scope_wrapped is True
    assert server._evidentia_signed_wrapped is True

    result = await server.call_tool("list_frameworks", {})

    assert isinstance(result, CallToolResult)
    assert result.is_error is False
    assert isinstance(result.structured_content, dict)
    frameworks = result.structured_content["result"]
    assert isinstance(frameworks, list)
    assert any(item["id"] == "cisa-cpgs" for item in frameworks)
    assert envelope(result)["payload"] == result.structured_content
    assert envelope(result)["tool_name"] == "list_frameworks"
