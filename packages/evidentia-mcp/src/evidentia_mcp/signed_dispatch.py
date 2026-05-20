"""FastMCP dispatch-layer auto-wrap of SignedToolOutput (v0.9.8 P1.1).

Wires the v0.9.7 :mod:`evidentia_mcp.signatures` primitives at the
tool-dispatch layer. When operators set
:data:`evidentia_mcp.signatures.EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR` +
configure a signer via
:data:`evidentia_mcp.signatures.EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR`,
every tool dispatch through the server carries a cryptographic
signature over the tool's output.

Closes the v0.9.7 P2.4 deferral noted in :mod:`evidentia_mcp.signatures`
("auto-wrap at the FastMCP dispatch layer").

Design — signature as additive ``_meta`` provenance
----------------------------------------------------

A v0.9.8 pre-release review (finding F-V98-01) caught that an earlier
draft of this module **replaced** the tool's output with a
:class:`SignedToolOutput` envelope dict. That collided with FastMCP's
contract: :meth:`FastMCP.call_tool` runs ``convert_result``, which for
any tool with an output schema returns a ``(unstructured, structured)``
tuple, and the lowlevel MCP server validates the structured content
against the tool's declared ``outputSchema``. Replacing the structured
content with an envelope failed that validation for every real tool.

The corrected design makes the signature **additive metadata**, not a
replacement:

1. The wrapper normalizes whatever :meth:`FastMCP.call_tool` returns —
   a ``(unstructured, structured)`` tuple, a bare structured dict, a
   :class:`~mcp.types.CallToolResult`, or an unstructured content list
   — into ``(content, structured_content)``.
2. It signs the **structured content** (the tool's semantic payload —
   a JSON object). No-schema tools, which have no structured dict, get
   a ``{"result": [...]}`` wrap of their content blocks.
3. It returns a :class:`~mcp.types.CallToolResult` whose ``content``
   and ``structuredContent`` are the tool's **unchanged** output, and
   whose ``_meta`` carries the :class:`SignedToolOutput` envelope under
   the :data:`SIGNED_OUTPUT_META_KEY` key.

Because the wrapper returns a ``CallToolResult``, the lowlevel server
returns it as-is and skips re-validation — and since the structured
content is untouched it would pass anyway. A signing-aware MCP client
reads ``result._meta["evidentia/signed-tool-output"]`` to recover the
envelope and verify the ``signature`` over the ``payload``. A signing-
unaware client sees a perfectly normal tool result and ignores the
extra ``_meta`` key. No wire-format break either way.

Design rules
------------

1. **Opt-in via env vars**. Gate env var unset → the wrapper returns
   the inner result completely unchanged (v0.9.7 behavior; the default
   for ``evidentia mcp serve``).
2. **Non-fatal signing failures**. :func:`sign_tool_output` returns an
   envelope with ``signature=None`` + ``signing_error`` populated when
   the signer raises. A misbehaving signer cannot break a tool call.
3. **Additive, not destructive**. The tool's ``content`` +
   ``structuredContent`` are returned verbatim. The signature rides in
   ``_meta``. Output-schema validity is preserved.
4. **Idempotent wrap**. Calling :func:`wrap_signed_output` twice on the
   same server raises :class:`RuntimeError` (``_evidentia_signed_wrapped``
   marker). Mirrors :func:`evidentia_mcp.scope.enforce_cimd_scope`.
5. **Layer order with the CIMD scope gate**. ``enforce_cimd_scope``
   wraps ``server.call_tool`` first; ``wrap_signed_output`` wraps
   second (outermost). A scope-denied call raises
   :class:`~mcp.shared.exceptions.McpError` in the inner layer and
   never reaches signing — no envelope is emitted for denied calls.
"""

from __future__ import annotations

import functools
import json
from collections.abc import Awaitable, Callable, Iterable
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, ContentBlock, TextContent

from evidentia_mcp.signatures import (
    _resolve_signer_factory,
    sign_tool_output,
)

# Mirrors the type alias used by :mod:`evidentia_mcp.scope` so both
# wrappers compose against the same FastMCP dispatch shape.
_CallToolFn = Callable[[str, dict[str, Any]], Awaitable[Any]]

#: ``_meta`` key under which the :class:`SignedToolOutput` envelope is
#: attached to a signed tool result. Namespaced per the MCP ``_meta``
#: convention. A signing-aware client reads this key; everything else
#: ignores it.
SIGNED_OUTPUT_META_KEY = "evidentia/signed-tool-output"


def _normalize_call_tool_result(
    result: Any,
) -> tuple[list[ContentBlock], dict[str, Any] | None, dict[str, Any], bool] | None:
    """Normalize a FastMCP ``call_tool`` return into its components.

    :meth:`FastMCP.call_tool` (via ``convert_result``) can return:

    - a ``(unstructured, structured)`` 2-tuple — for output-schema tools
      (every Evidentia MCP tool has a typed return, so this is the
      common case)
    - an unstructured :class:`~mcp.types.ContentBlock` sequence — for
      tools without an output schema
    - a :class:`~mcp.types.CallToolResult` — if the tool returned one
      directly
    - a bare structured ``dict`` — only from lowlevel-registered tools,
      handled defensively

    Returns ``(content, structured, existing_meta, is_error)``, or
    ``None`` when the shape is unrecognized (e.g. a task-augmented
    ``CreateTaskResult``) — in which case the caller passes the result
    through unsigned rather than risk corrupting it.
    """
    if isinstance(result, CallToolResult):
        return (
            list(result.content),
            result.structuredContent,
            dict(result.meta) if result.meta else {},
            result.isError,
        )
    if isinstance(result, tuple) and len(result) == 2:
        unstructured, structured = result
        return list(unstructured), structured, {}, False
    if isinstance(result, dict):
        # Bare structured dict — mirror the lowlevel server's own
        # unstructured-content synthesis so the result stays well-formed.
        text = json.dumps(result, indent=2, default=str)
        return [TextContent(type="text", text=text)], result, {}, False
    if isinstance(result, Iterable) and not isinstance(result, str | bytes):
        return list(result), None, {}, False
    return None


def wrap_signed_output(server: FastMCP) -> None:
    """Wire the SignedToolOutput auto-wrap onto a FastMCP server.

    Replaces ``server.call_tool`` with a wrapper that — when operators
    have configured a signer via env vars — attaches a
    :class:`evidentia_mcp.signatures.SignedToolOutput` envelope to every
    tool result's ``_meta`` (under :data:`SIGNED_OUTPUT_META_KEY`),
    leaving the tool's ``content`` and ``structuredContent`` unchanged.

    Args:
        server: A FastMCP server instance, typically returned by
            :func:`evidentia_mcp.server.build_server`. Wiring order
            matters: :func:`evidentia_mcp.scope.enforce_cimd_scope` MUST
            be wired before this function so an authorization-deny
            short-circuits before the signing layer runs.
            :func:`evidentia_mcp.server.build_server` wires them in the
            correct order.

    Raises:
        RuntimeError: When the signed-output wrap is already wired on
            this server (``_evidentia_signed_wrapped`` marker).
    """
    if getattr(server, "_evidentia_signed_wrapped", False):
        raise RuntimeError(
            "wrap_signed_output already wired on this server; "
            "call once per build_server invocation."
        )

    inner_call_tool: _CallToolFn = server.call_tool

    @functools.wraps(inner_call_tool)
    async def _signed_call_tool(
        name: str, arguments: dict[str, Any]
    ) -> Any:
        # Delegate to the inner dispatch (which may itself be the CIMD
        # scope-enforcement wrapper). A scope denial raises McpError
        # here, before signing — denied calls get no envelope.
        result = await inner_call_tool(name, arguments)

        # Resolve the signer fresh each call. factory_resolver caches
        # the result keyed on env-var values, so the import + factory
        # invocation happen once per process lifetime.
        signer = _resolve_signer_factory()
        if signer is None:
            # Signing not enabled → return the inner result verbatim.
            return result

        normalized = _normalize_call_tool_result(result)
        if normalized is None:
            # Unrecognized result shape — pass through unsigned rather
            # than risk corrupting a result type we don't model.
            return result
        content, structured, existing_meta, is_error = normalized

        # Sign the tool's semantic payload. The structured dict is the
        # canonical payload; no-schema tools (no structured dict) get a
        # {"result": [...]} wrap of their JSON-able content blocks.
        if structured is not None:
            payload: dict[str, Any] = structured
        else:
            payload = {
                "result": [
                    block.model_dump(mode="json") for block in content
                ]
            }

        envelope = sign_tool_output(payload, tool_name=name)

        # The signature rides in _meta as ADDITIVE provenance. content
        # + structuredContent are the tool's unchanged output, so
        # output-schema validity + client compatibility are preserved.
        signed_result = CallToolResult(
            content=content,
            structuredContent=structured,
            isError=is_error,
        )
        signed_result.meta = {
            **existing_meta,
            SIGNED_OUTPUT_META_KEY: envelope.model_dump(mode="json"),
        }
        return signed_result

    server.call_tool = _signed_call_tool  # type: ignore[method-assign]
    server._evidentia_signed_wrapped = True  # type: ignore[attr-defined]


__all__ = [
    "SIGNED_OUTPUT_META_KEY",
    "wrap_signed_output",
]
