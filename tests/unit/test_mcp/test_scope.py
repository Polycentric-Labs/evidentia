"""CIMD decisions use the supplied SDK context and one audit event per call."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from uuid import UUID

import pytest
from evidentia_core.audit import EventAction, EventOutcome
from evidentia_mcp.cimd import CIMDDocument, CIMDRegistry
from evidentia_mcp.scope import enforce_cimd_scope
from evidentia_mcp.server import EvidentiaMCPServer
from mcp.server.context import ServerRequestContext
from mcp.server.mcpserver import Context
from mcp.server.session import ServerSession
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, CallToolRequestParams, CallToolResult, InputRequiredResult, TextContent

_SCOPE_LOG = "evidentia.mcp.scope"
_MISSING_MESSAGE = (
    "tool call denied: no client_id resolved "
    "(set client_id in request _meta or pass --default-client-id at server start)"
)


def _make_registry(**scopes: str) -> CIMDRegistry:
    return CIMDRegistry(
        clients={
            client_id: CIMDDocument(client_id=client_id, client_name=client_id, scope=scope)
            for client_id, scope in scopes.items()
        }
    )


def _make_server(registry: CIMDRegistry | None = None) -> tuple[EvidentiaMCPServer, AsyncMock]:
    server = EvidentiaMCPServer(name="test-evidentia")
    server.evidentia_cimd = registry
    delegate = AsyncMock(return_value=CallToolResult(content=[TextContent(type="text", text="delegated")]))
    server._evidentia_dispatch = delegate
    return server, delegate


def _context(meta: dict[str, object] | None = None) -> Context[Any, Any]:
    request_context: ServerRequestContext[Any, Any] = ServerRequestContext(
        session=MagicMock(spec=ServerSession),
        lifespan_context={},
        protocol_version="2026-07-28",
        method="tools/call",
        request_id="synthetic-scope-request",
        meta=CallToolRequestParams.model_validate({"name": "synthetic", "_meta": meta}).meta,
    )
    return Context(request_context=request_context)


def _scope_events(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    events = []
    for record in caplog.records:
        if record.name == _SCOPE_LOG:
            event = getattr(record, "ecs_record", None)
            assert isinstance(event, dict)
            events.append(event)
    return events


def _assert_decision(
    event: dict[str, Any],
    *,
    allowed: bool,
    client_id: str | None,
    tool_name: str,
    scope: str | None,
) -> None:
    assert event["event"]["action"] == (
        EventAction.AI_MCP_TOOL_AUTHORIZED.value if allowed else EventAction.AI_MCP_TOOL_DENIED.value
    )
    assert event["event"]["outcome"] == (EventOutcome.SUCCESS.value if allowed else EventOutcome.FAILURE.value)
    details = event["evidentia"]
    assert details["client_id"] == client_id
    assert details["tool_name"] == tool_name
    assert details["scope_allowlist"] == scope
    assert UUID(details["run_id"]).version == 4


@pytest.mark.asyncio
@pytest.mark.parametrize("with_context", [False, True])
async def test_no_registry_preserves_result_arguments_and_context_without_audit(
    caplog: pytest.LogCaptureFixture, with_context: bool
) -> None:
    server, delegate = _make_server()
    context = _context({"client_id": "unregistered"}) if with_context else None
    arguments = {"x": 1}
    enforce_cimd_scope(server)

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        result = await server.call_tool("any_tool", arguments, context)

    assert result is delegate.return_value
    delegate.assert_awaited_once_with("any_tool", arguments, context)
    assert delegate.await_args is not None
    assert delegate.await_args.args[1] is arguments
    assert delegate.await_args.args[2] is context
    assert _scope_events(caplog) == []
    assert "call_tool" not in vars(server)


@pytest.mark.asyncio
@pytest.mark.parametrize("context_kind", ["none", "direct", "no-meta", "no-client", "null-client", "empty-client"])
async def test_missing_identity_denies_without_delegation(caplog: pytest.LogCaptureFixture, context_kind: str) -> None:
    server, delegate = _make_server(_make_registry(allowed="list_frameworks"))
    contexts: dict[str, Context[Any, Any] | None] = {
        "none": None,
        "direct": Context(),
        "no-meta": _context(),
        "no-client": _context({"progress_token": "synthetic-progress"}),
        "null-client": _context({"client_id": None}),
        "empty-client": _context({"client_id": ""}),
    }
    enforce_cimd_scope(server)

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG), pytest.raises(MCPError) as error:
        await server.call_tool("list_frameworks", {}, contexts[context_kind])

    assert error.value.code == INVALID_PARAMS == -32602
    assert error.value.message == _MISSING_MESSAGE
    assert error.value.error.model_dump(exclude_unset=True) == {"code": -32602, "message": _MISSING_MESSAGE}
    delegate.assert_not_awaited()
    events = _scope_events(caplog)
    assert len(events) == 1
    _assert_decision(events[0], allowed=False, client_id=None, tool_name="list_frameworks", scope=None)


@pytest.mark.asyncio
@pytest.mark.parametrize("metadata_id", [None, ""])
async def test_missing_metadata_identity_uses_configured_fallback(
    caplog: pytest.LogCaptureFixture, metadata_id: str | None
) -> None:
    server, delegate = _make_server(_make_registry(fallback="list_frameworks"))
    context = _context({"client_id": metadata_id})
    enforce_cimd_scope(server, default_client_id="fallback")

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        result = await server.call_tool("list_frameworks", {}, context)

    assert result is delegate.return_value
    delegate.assert_awaited_once_with("list_frameworks", {}, context)
    events = _scope_events(caplog)
    assert len(events) == 1
    _assert_decision(
        events[0], allowed=True, client_id="fallback", tool_name="list_frameworks", scope="list_frameworks"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("with_empty_context", [False, True])
async def test_direct_call_uses_fallback_and_forwards_original_context(
    caplog: pytest.LogCaptureFixture, with_empty_context: bool
) -> None:
    server, delegate = _make_server(_make_registry(fallback="list_frameworks"))
    context: Context[Any, Any] | None = Context() if with_empty_context else None
    enforce_cimd_scope(server, default_client_id="fallback")

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        result = await server.call_tool("list_frameworks", {}, context)

    assert result is delegate.return_value
    assert delegate.await_args is not None
    assert delegate.await_args.args[2] is context
    assert len(_scope_events(caplog)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("metadata_id", "scope", "message"),
    [
        ("unknown", None, "tool call denied: client 'unknown' is not registered"),
        ("readonly", "get_control", "tool call denied: client 'readonly' is not authorized to call 'list_frameworks'"),
    ],
)
async def test_metadata_denial_cannot_inherit_allowed_fallback(
    caplog: pytest.LogCaptureFixture, metadata_id: str, scope: str | None, message: str
) -> None:
    server, delegate = _make_server(_make_registry(fallback="list_frameworks", readonly="get_control"))
    enforce_cimd_scope(server, default_client_id="fallback")

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG), pytest.raises(MCPError) as error:
        await server.call_tool("list_frameworks", {}, _context({"client_id": metadata_id}))

    assert error.value.error.model_dump(exclude_unset=True) == {"code": -32602, "message": message}
    delegate.assert_not_awaited()
    events = _scope_events(caplog)
    assert len(events) == 1
    _assert_decision(events[0], allowed=False, client_id=metadata_id, tool_name="list_frameworks", scope=scope)


@pytest.mark.asyncio
async def test_allowed_metadata_overrides_unknown_fallback(caplog: pytest.LogCaptureFixture) -> None:
    scope = "get_control list_frameworks gap_analyze"
    server, delegate = _make_server(_make_registry(permitted=scope))
    context = _context({"client_id": "permitted", "progress_token": 4})
    arguments = {"framework_id": "synthetic"}
    enforce_cimd_scope(server, default_client_id="unknown")

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        result = await server.call_tool("get_control", arguments, context)

    assert result is delegate.return_value
    delegate.assert_awaited_once_with("get_control", arguments, context)
    assert delegate.await_args is not None
    assert delegate.await_args.args[1] is arguments
    assert delegate.await_args.args[2] is context
    assert context.request_context.meta == {"client_id": "permitted", "progress_token": 4}
    events = _scope_events(caplog)
    assert len(events) == 1
    _assert_decision(events[0], allowed=True, client_id="permitted", tool_name="get_control", scope=scope)


@pytest.mark.asyncio
@pytest.mark.parametrize("scope", ["", "list_frameworks_extra", "LIST_FRAMEWORKS", "get_control"])
async def test_scope_requires_exact_tool_token(caplog: pytest.LogCaptureFixture, scope: str) -> None:
    server, delegate = _make_server(_make_registry(client=scope))
    enforce_cimd_scope(server, default_client_id="client")

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG), pytest.raises(MCPError) as error:
        await server.call_tool("list_frameworks", {})

    assert error.value.code == -32602
    assert error.value.message == "tool call denied: client 'client' is not authorized to call 'list_frameworks'"
    delegate.assert_not_awaited()
    events = _scope_events(caplog)
    assert len(events) == 1
    _assert_decision(events[0], allowed=False, client_id="client", tool_name="list_frameworks", scope=scope)


@pytest.mark.asyncio
async def test_registered_scope_updates_remain_visible(caplog: pytest.LogCaptureFixture) -> None:
    registry = _make_registry(client="get_control")
    server, delegate = _make_server(registry)
    enforce_cimd_scope(server, default_client_id="client")
    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        with pytest.raises(MCPError):
            await server.call_tool("list_frameworks", {})
        registry.clients["client"].scope = "list_frameworks"
        result = await server.call_tool("list_frameworks", {})

    assert result is delegate.return_value
    delegate.assert_awaited_once_with("list_frameworks", {}, None)
    events = _scope_events(caplog)
    assert len(events) == 2
    assert events[0]["evidentia"]["scope_allowlist"] == "get_control"
    assert events[1]["evidentia"]["scope_allowlist"] == "list_frameworks"


@pytest.mark.asyncio
@pytest.mark.parametrize("result_kind", ["tool", "input-required"])
async def test_authorized_sdk_result_is_not_rebuilt(result_kind: str, caplog: pytest.LogCaptureFixture) -> None:
    server, delegate = _make_server(_make_registry(client="list_frameworks"))
    expected: CallToolResult | InputRequiredResult
    if result_kind == "tool":
        expected = CallToolResult(content=[], is_error=True, _meta={"synthetic": {"unchanged": True}})
    else:
        expected = InputRequiredResult(request_state="synthetic-state")
    delegate.return_value = expected
    enforce_cimd_scope(server, default_client_id="client")

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        result = await server.call_tool("list_frameworks", {})

    assert result is expected
    assert len(_scope_events(caplog)) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol_error", [False, True])
async def test_delegate_exception_propagates_after_one_authorization(
    protocol_error: bool, caplog: pytest.LogCaptureFixture
) -> None:
    server, delegate = _make_server(_make_registry(client="list_frameworks"))
    expected = (
        MCPError(-32603, "synthetic failure", {"unchanged": True})
        if protocol_error
        else ValueError("synthetic failure")
    )
    delegate.side_effect = expected
    enforce_cimd_scope(server, default_client_id="client")

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG), pytest.raises(type(expected)) as error:
        await server.call_tool("list_frameworks", {})

    assert error.value is expected
    events = _scope_events(caplog)
    assert len(events) == 1
    _assert_decision(events[0], allowed=True, client_id="client", tool_name="list_frameworks", scope="list_frameworks")


def test_double_wire_raises_without_replacing_dispatch() -> None:
    server, _ = _make_server()
    enforce_cimd_scope(server)
    installed = server._evidentia_dispatch

    with pytest.raises(RuntimeError, match="enforce_cimd_scope already wired"):
        enforce_cimd_scope(server)

    assert server._evidentia_dispatch is installed


@pytest.mark.asyncio
async def test_sequential_requests_do_not_reuse_identity(caplog: pytest.LogCaptureFixture) -> None:
    server, delegate = _make_server(_make_registry(alpha="get_control", beta="list_frameworks"))
    enforce_cimd_scope(server)
    alpha = _context({"client_id": "alpha"})
    beta = _context({"client_id": "beta"})

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        await server.call_tool("get_control", {}, alpha)
        with pytest.raises(MCPError):
            await server.call_tool("get_control", {}, beta)
        await server.call_tool("list_frameworks", {}, beta)
        with pytest.raises(MCPError, match="no client_id"):
            await server.call_tool("list_frameworks", {})
        with pytest.raises(MCPError):
            await server.call_tool("list_frameworks", {}, alpha)

    assert delegate.await_count == 2
    events = _scope_events(caplog)
    assert [(event["evidentia"]["client_id"], event["event"]["outcome"]) for event in events] == [
        ("alpha", "success"),
        ("beta", "failure"),
        ("beta", "success"),
        (None, "failure"),
        ("alpha", "failure"),
    ]
    assert len({event["evidentia"]["run_id"] for event in events}) == 5


@pytest.mark.asyncio
async def test_overlapping_contexts_stay_isolated_during_denied_request(caplog: pytest.LogCaptureFixture) -> None:
    server, _ = _make_server(_make_registry(alpha="alpha_tool", beta="beta_tool"))
    alpha = _context({"client_id": "alpha"})
    beta = _context({"client_id": "beta"})
    both_started = asyncio.Event()
    release = asyncio.Event()
    observed: list[tuple[str, Context[Any, Any] | None, str]] = []

    async def delegate(
        name: str, arguments: dict[str, Any], context: Context[Any, Any] | None = None
    ) -> CallToolResult:
        assert context is not None
        metadata = context.request_context.meta
        assert metadata is not None
        client_id = metadata.get("client_id")
        assert isinstance(client_id, str)
        observed.append((name, context, client_id))
        if len(observed) == 2:
            both_started.set()
        await release.wait()
        assert context.request_context.meta == {"client_id": client_id}
        return CallToolResult(content=[TextContent(type="text", text=arguments["label"])])

    server._evidentia_dispatch = delegate
    enforce_cimd_scope(server)
    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        async with asyncio.TaskGroup() as group:
            alpha_call = group.create_task(server.call_tool("alpha_tool", {"label": "alpha-result"}, alpha))
            beta_call = group.create_task(server.call_tool("beta_tool", {"label": "beta-result"}, beta))
            try:
                await asyncio.wait_for(both_started.wait(), timeout=3)
                with pytest.raises(MCPError, match="not registered"):
                    await server.call_tool("alpha_tool", {}, _context({"client_id": "unknown"}))
                assert not alpha_call.done()
                assert not beta_call.done()
            finally:
                release.set()

    assert observed == [("alpha_tool", alpha, "alpha"), ("beta_tool", beta, "beta")]
    assert observed[0][1] is alpha
    assert observed[1][1] is beta
    assert alpha_call.result() == CallToolResult(content=[TextContent(type="text", text="alpha-result")])
    assert beta_call.result() == CallToolResult(content=[TextContent(type="text", text="beta-result")])
    events = _scope_events(caplog)
    assert [(event["evidentia"]["client_id"], event["event"]["outcome"]) for event in events] == [
        ("alpha", "success"),
        ("beta", "success"),
        ("unknown", "failure"),
    ]
    assert len({event["evidentia"]["run_id"] for event in events}) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("identity", [False, True, 0, 1, 1.5, [], ["fallback"], {}, {"client_id": "fallback"}])
async def test_malformed_identity_denies_without_allowed_fallback(
    identity: object, caplog: pytest.LogCaptureFixture
) -> None:
    server, delegate = _make_server(_make_registry(fallback="list_frameworks"))
    enforce_cimd_scope(server, default_client_id="fallback")
    context = _context({"client_id": identity})

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG), pytest.raises(MCPError) as error:
        await server.call_tool("list_frameworks", {}, context)

    assert error.value.error.model_dump(exclude_unset=True) == {
        "code": -32602,
        "message": "tool call denied: client_id in request _meta must be a string",
    }
    delegate.assert_not_awaited()
    events = _scope_events(caplog)
    assert len(events) == 1
    _assert_decision(events[0], allowed=False, client_id=None, tool_name="list_frameworks", scope=None)
    assert events[0]["message"] == "MCP tool 'list_frameworks' denied: client_id in request _meta must be a string"


@pytest.mark.asyncio
async def test_no_registry_does_not_inspect_malformed_metadata(caplog: pytest.LogCaptureFixture) -> None:
    server, delegate = _make_server()
    context = _context({"client_id": ["synthetic"]})
    enforce_cimd_scope(server)

    with caplog.at_level(logging.INFO, logger=_SCOPE_LOG):
        result = await server.call_tool("list_frameworks", {}, context)

    assert result is delegate.return_value
    assert _scope_events(caplog) == []
