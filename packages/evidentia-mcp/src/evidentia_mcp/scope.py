"""CIMD tool allowlists and audit decisions for the SDK dispatch chain.

The server's typed dispatch slot places this gate inside the signing wrapper.
When a CIMD registry is configured, each call emits one authorization or denial
with a fresh UUID4 run_id. Denials raise MCPError with code -32602 before the
handler or signer runs. Without a registry, calls pass through without scope
audit events.

Identity comes from the supplied request context's _meta.client_id, followed by
--default-client-id when metadata is missing, null, or empty text. Non-string
metadata is rejected. The context and arguments are forwarded unchanged.

CIMD metadata is not authentication. A client can claim another client's ID
unless the transport authenticates that claim. Non-loopback HTTP/SSE deployments
need external transport authentication. Stdio inherits the operator's identity
and filesystem authority; its configured fallback supports audit attribution.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError
from mcp.types import INVALID_PARAMS, CallToolResult, InputRequiredResult

if TYPE_CHECKING:
    from evidentia_mcp.server import EvidentiaMCPServer, ToolDispatch

_log = get_logger("evidentia.mcp.scope")


def _request_client_id(context: Context[Any, Any] | None) -> object:
    """Read only this call's metadata; direct calls may have no request context."""
    if context is None:
        return None
    try:
        request_context = context.request_context
    except ValueError:
        return None
    if request_context.meta is None:
        return None
    client_id: object = request_context.meta.get("client_id")
    return client_id


def enforce_cimd_scope(
    server: EvidentiaMCPServer,
    *,
    default_client_id: str | None = None,
) -> None:
    """Install one scope gate on the server's typed dispatch slot.

    The configured registry is captured when the gate is installed. Updates to
    that registry's clients remain visible to subsequent calls. A missing
    registry preserves passthrough behavior without scope audit events.

    Args:
        server: The server constructed by build_server.
        default_client_id: Identity fallback for requests without a metadata ID.

    Raises:
        RuntimeError: The gate has already been installed on this server.
    """
    if server._evidentia_scope_wrapped:
        raise RuntimeError("enforce_cimd_scope already wired on this server; call once per build_server invocation.")

    original_call_tool: ToolDispatch = server._evidentia_dispatch
    cimd_registry = server.evidentia_cimd

    @functools.wraps(original_call_tool)
    async def _gated_call_tool(
        name: str,
        arguments: dict[str, Any],
        context: Context[Any, Any] | None = None,
    ) -> CallToolResult | InputRequiredResult:
        if cimd_registry is None:
            return await original_call_tool(name, arguments, context)

        run_id = uuid4().hex
        metadata_client_id = _request_client_id(context)
        if metadata_client_id is not None and not isinstance(metadata_client_id, str):
            _log.warning(
                action=EventAction.AI_MCP_TOOL_DENIED,
                outcome=EventOutcome.FAILURE,
                message=f"MCP tool {name!r} denied: client_id in request _meta must be a string",
                evidentia={
                    "run_id": run_id,
                    "client_id": None,
                    "tool_name": name,
                    "scope_allowlist": None,
                },
            )
            raise MCPError(
                code=INVALID_PARAMS,
                message="tool call denied: client_id in request _meta must be a string",
            )

        client_id = metadata_client_id or default_client_id
        if client_id is None:
            _log.warning(
                action=EventAction.AI_MCP_TOOL_DENIED,
                outcome=EventOutcome.FAILURE,
                message=(
                    f"MCP tool {name!r} denied: no client_id could be resolved "
                    "(request _meta.client_id is absent and --default-client-id is unset)"
                ),
                evidentia={
                    "run_id": run_id,
                    "client_id": None,
                    "tool_name": name,
                    "scope_allowlist": None,
                },
            )
            raise MCPError(
                code=INVALID_PARAMS,
                message=(
                    "tool call denied: no client_id resolved "
                    "(set client_id in request _meta or pass "
                    "--default-client-id at server start)"
                ),
            )

        doc = cimd_registry.get(client_id)
        if doc is None:
            _log.warning(
                action=EventAction.AI_MCP_TOOL_DENIED,
                outcome=EventOutcome.FAILURE,
                message=f"MCP tool {name!r} denied: client_id {client_id!r} is not in the CIMD registry",
                evidentia={
                    "run_id": run_id,
                    "client_id": client_id,
                    "tool_name": name,
                    "scope_allowlist": None,
                },
            )
            raise MCPError(
                code=INVALID_PARAMS,
                message=f"tool call denied: client {client_id!r} is not registered",
            )

        if not doc.has_scope(name):
            _log.warning(
                action=EventAction.AI_MCP_TOOL_DENIED,
                outcome=EventOutcome.FAILURE,
                message=f"MCP tool {name!r} denied: client_id {client_id!r} scope does not include this tool",
                evidentia={
                    "run_id": run_id,
                    "client_id": client_id,
                    "tool_name": name,
                    "scope_allowlist": doc.scope,
                },
            )
            raise MCPError(
                code=INVALID_PARAMS,
                message=f"tool call denied: client {client_id!r} is not authorized to call {name!r}",
            )

        _log.info(
            action=EventAction.AI_MCP_TOOL_AUTHORIZED,
            outcome=EventOutcome.SUCCESS,
            message=f"MCP tool {name!r} authorized for client {client_id!r}",
            evidentia={
                "run_id": run_id,
                "client_id": client_id,
                "tool_name": name,
                "scope_allowlist": doc.scope,
            },
        )
        return await original_call_tool(name, arguments, context)

    server._evidentia_dispatch = _gated_call_tool
    server._evidentia_scope_wrapped = True


__all__ = ["enforce_cimd_scope"]
