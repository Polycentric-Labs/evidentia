"""Attach opt-in signatures to authorized MCP tool results.

Structured object results retain the existing signed payload contract.
Content-only results use the content blocks' wire field names. The signature
is additive metadata; content, structured data, error state, and other result
fields remain unchanged. Unsupported multi-round results and non-object
structured values pass through unsigned.
"""

from __future__ import annotations

import functools
import json
from typing import TYPE_CHECKING, Any

from mcp.server.mcpserver import Context
from mcp.types import CallToolResult, InputRequiredResult
from mcp.types.methods import serialize_server_result

from evidentia_mcp.signatures import _resolve_signer_factory, sign_tool_output

if TYPE_CHECKING:
    from evidentia_mcp.server import EvidentiaMCPServer, ToolDispatch

SIGNED_OUTPUT_META_KEY = "evidentia/signed-tool-output"
"""Result metadata key containing the SignedToolOutput envelope."""


def wrap_signed_output(server: EvidentiaMCPServer) -> None:
    """Sign supported results after the inner authorization and tool dispatch.

    Install the scope wrapper first so denied calls never resolve or invoke a
    signer. Signing failures retain the existing nonfatal error envelope.
    Calling this function twice on one server raises RuntimeError.
    """
    if server._evidentia_signed_wrapped:
        raise RuntimeError("wrap_signed_output already wired on this server; call once per build_server invocation.")

    inner_call_tool: ToolDispatch = server._evidentia_dispatch

    @functools.wraps(inner_call_tool)
    async def signed_call_tool(
        name: str,
        arguments: dict[str, Any],
        context: Context[Any, Any] | None = None,
    ) -> CallToolResult | InputRequiredResult:
        result = await inner_call_tool(name, arguments, context)

        if isinstance(result, InputRequiredResult):
            return result
        structured = result.structured_content
        if structured is not None and not isinstance(structured, dict):
            # The existing signature envelope accepts object payloads only.
            # Signing display content would omit this structured value.
            return result

        signer = _resolve_signer_factory()
        if signer is None:
            return result

        # Match SDK framing, including nested model aliases, optional fields,
        # nonfinite JSON values, and the negotiated protocol's metadata rules.
        wire_result = json.loads(result.model_dump_json(by_alias=True, exclude_none=True))
        if context is not None:
            try:
                protocol_version = context.request_context.protocol_version
            except ValueError:
                # A direct SDK call can supply a context without a request.
                pass
            else:
                wire_result = serialize_server_result("tools/call", protocol_version, wire_result)

        payload: dict[str, Any]
        if structured is not None:
            payload = wire_result["structuredContent"]
        else:
            # Restore standard content-model defaults after wire normalization
            # to preserve the existing envelope's explicit optional nulls.
            wire_content = CallToolResult.model_validate(wire_result).content
            payload = {"result": [block.model_dump(mode="json", by_alias=True) for block in wire_content]}

        envelope = sign_tool_output(payload, tool_name=name, signer=signer)
        metadata = {
            **(result.meta or {}),
            SIGNED_OUTPUT_META_KEY: envelope.model_dump(mode="json"),
        }
        return result.model_copy(update={"meta": metadata})

    server._evidentia_dispatch = signed_call_tool
    server._evidentia_signed_wrapped = True


__all__ = ["SIGNED_OUTPUT_META_KEY", "wrap_signed_output"]
