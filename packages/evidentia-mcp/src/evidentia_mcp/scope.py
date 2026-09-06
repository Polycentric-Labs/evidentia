"""CIMD per-tool scope enforcement gate (v0.8.6 P1).

Wraps :meth:`mcp.server.fastmcp.FastMCP.call_tool` so every tool
dispatch routes through one authorization choke-point. The gate
is opt-in: when the server is built without a CIMDRegistry
attached, calls pass through with no audit emit (preserves
v0.8.5 behavior). When a CIMDRegistry IS attached + the gate is
wired, every call emits exactly one of two structured audit
events:

- :attr:`EventAction.AI_MCP_TOOL_AUTHORIZED` — call permitted
  (client_id is registered AND scope contains tool_name)
- :attr:`EventAction.AI_MCP_TOOL_DENIED` — call rejected;
  raised back to the MCP client as an
  :class:`mcp.shared.exceptions.McpError` with code
  ``-32602`` (Invalid Params per JSON-RPC 2.0)

Design rationale
----------------

The MCP Python SDK 1.27 does NOT expose a public
``before_tool_call`` hook or ``tool_call_middleware``
decorator. The only chokepoint that intercepts EVERY
``tools/call`` request is :meth:`FastMCP.call_tool` (defined at
``.venv/Lib/site-packages/mcp/server/fastmcp/server.py:343``).
The canonical patch pattern is to MONKEY-BIND a wrapper to the
already-instantiated server's ``call_tool`` attribute (vs
subclassing FastMCP, which would require re-declaring all
tool registrations under the subclass). Monkey-binding is the
minimum-blast-radius approach: it intercepts the same dispatch
the SDK uses internally for ``ListToolsResult`` + ``CallToolResult``,
and reverts cleanly when the server is destroyed.

Verify-during-implementation sentinel: if the ``mcp`` SDK ever
ships a public ``tool_call_middleware`` decorator (target:
1.28+), refactor this module to register through that
decorator instead. The audit-event emission semantics stay the
same; only the wrapping mechanism changes.

Per-transport client_id resolution
-----------------------------------

stdio transport
    The MCP wire protocol does NOT carry a per-request
    ``client_id`` field on stdio. Stdio is a single-client
    transport — one MCP host process talks to one server
    process via standard input + output. The
    ``--default-client-id`` flag on
    ``evidentia mcp serve`` IS THE client_id for stdio
    deployments. **This is informational, not a security
    boundary** — a malicious stdio host process could trivially
    invoke tools regardless of CIMD configuration since stdio
    transport runs as the operator's UID. CIMD on stdio is
    primarily for audit-trail granularity ("which named client
    invoked this tool"), not for AuthZ.

HTTP / SSE transports
    The MCP request meta-block CAN carry a ``client_id`` field
    set by the calling MCP client. FastMCP surfaces it via
    :attr:`Context.client_id` (the ``request_context.meta.client_id``
    accessor at line 1286). When that value is None (client
    didn't set it), the gate falls back to the
    ``--default-client-id`` flag. When BOTH are None, the gate
    DENIES — ambiguous-caller policy. Operators deploying
    non-loopback HTTP/SSE deployments MUST also wire
    transport-level authentication (reverse-proxy mTLS, bearer
    tokens) so clients cannot impersonate each other's
    ``client_id`` declarations.

The threat model
----------------

CIMD is NOT authentication. Documented prominently in
:mod:`evidentia_mcp.cimd` and re-asserted here: the gate gives
operators (1) per-client allowlist control over which tools
each client may call AND (2) a structured audit trail of every
authorize + deny decision. It does NOT prevent a transport-
unauthenticated client from claiming any client_id it wants.
Transport-level authentication is the prerequisite for using
CIMD as an AuthZ control.

Audit events
------------

Both events carry the same evidentia-extension fields:

* ``run_id`` — ULID per call (NOT correlated with the
  DFAH ``run_id`` ULID; this one is per-MCP-tool-call)
* ``client_id`` — the resolved client_id (precedence:
  ``Context.client_id`` → ``default_client_id`` → ``None``)
* ``tool_name`` — the requested tool name
* ``scope_allowlist`` — the registered scope string for
  ``client_id`` (or ``None`` if unregistered / ambiguous)

Plan: §29 v0.8.6 P1.
"""

from __future__ import annotations

import functools
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from mcp.server.fastmcp import FastMCP
from mcp.shared.exceptions import McpError
from mcp.types import INVALID_PARAMS, ErrorData

from evidentia_mcp.cimd import CIMDRegistry

_log = get_logger("evidentia.mcp.scope")


# Type alias matching FastMCP.call_tool signature exactly. Keeps
# the wrapper compatible with both ContentBlock-list returns +
# structured-result-dict returns (FastMCP supports both).
_CallToolFn = Callable[[str, dict[str, Any]], Awaitable[Any]]


def enforce_cimd_scope(
    server: FastMCP,
    *,
    default_client_id: str | None = None,
) -> None:
    """Wire the CIMD scope-enforcement gate onto a FastMCP server.

    Replaces ``server.call_tool`` with a wrapper that consults
    the attached CIMD registry on every tool dispatch + emits
    structured audit events for the authorize / deny outcome.

    Idempotent: calling this function twice on the same server
    raises :class:`RuntimeError` rather than double-wrapping.

    Args:
        server: A FastMCP server instance, typically returned by
            :func:`evidentia_mcp.server.build_server`. The server's
            ``evidentia_cimd`` attribute (custom-attached in
            ``build_server``) is consulted to resolve the
            CIMDRegistry; when ``None``, this function still wires
            a wrapper but the wrapper passes through with no audit
            emit (registry-absent = v0.8.5 no-gating behavior).
        default_client_id: Fallback ``client_id`` when
            :attr:`Context.client_id` is None at call time. Set
            via the ``--default-client-id`` CLI flag on
            ``evidentia mcp serve``. Documentated as informational
            on stdio transports + as a fallback on HTTP/SSE; see
            module docstring.

    Raises:
        RuntimeError: if the gate is already wired on this server
            (detected via the ``_evidentia_scope_wrapped`` marker).
    """
    if getattr(server, "_evidentia_scope_wrapped", False):
        raise RuntimeError("enforce_cimd_scope already wired on this server; call once per build_server invocation.")

    original_call_tool: _CallToolFn = server.call_tool
    cimd_registry: CIMDRegistry | None = getattr(server, "evidentia_cimd", None)

    @functools.wraps(original_call_tool)
    async def _gated_call_tool(name: str, arguments: dict[str, Any]) -> Any:
        # Pass-through when CIMD is not configured. Preserves the
        # v0.8.5 behavior of no-gating + no-audit when the operator
        # builds the server without a registry. Documented in the
        # cimd.py threat model.
        if cimd_registry is None:
            return await original_call_tool(name, arguments)

        # Per-call run_id for audit correlation. Distinct from
        # DFAH run_id which lives in the eval namespace.
        run_id = uuid4().hex

        # Resolve client_id with stdio-fallback semantics.
        ctx = server.get_context()
        ctx_client_id: str | None = ctx.client_id
        client_id = ctx_client_id or default_client_id

        if client_id is None:
            # Ambiguous-caller policy — neither the request meta
            # nor the operator-configured fallback identifies the
            # client. Deny + emit, mirroring the unregistered
            # path below.
            _log.warning(
                action=EventAction.AI_MCP_TOOL_DENIED,
                outcome=EventOutcome.FAILURE,
                message=(
                    f"MCP tool {name!r} denied: no client_id "
                    f"could be resolved (Context.client_id is "
                    f"None and --default-client-id is unset)"
                ),
                evidentia={
                    "run_id": run_id,
                    "client_id": None,
                    "tool_name": name,
                    "scope_allowlist": None,
                },
            )
            raise McpError(
                ErrorData(
                    code=INVALID_PARAMS,
                    message=(
                        "tool call denied: no client_id resolved "
                        "(set client_id in request _meta or pass "
                        "--default-client-id at server start)"
                    ),
                )
            )

        # Lookup CIMDDocument for the resolved client_id.
        doc = cimd_registry.get(client_id)
        if doc is None:
            _log.warning(
                action=EventAction.AI_MCP_TOOL_DENIED,
                outcome=EventOutcome.FAILURE,
                message=(f"MCP tool {name!r} denied: client_id {client_id!r} is not in the CIMD registry"),
                evidentia={
                    "run_id": run_id,
                    "client_id": client_id,
                    "tool_name": name,
                    "scope_allowlist": None,
                },
            )
            raise McpError(
                ErrorData(
                    code=INVALID_PARAMS,
                    message=(f"tool call denied: client {client_id!r} is not registered"),
                )
            )

        # has_scope implements the deny-by-default allowlist
        # semantics shipped in v0.8.5 P4. Empty scope = deny-all.
        if not doc.has_scope(name):
            _log.warning(
                action=EventAction.AI_MCP_TOOL_DENIED,
                outcome=EventOutcome.FAILURE,
                message=(f"MCP tool {name!r} denied: client_id {client_id!r} scope does not include this tool"),
                evidentia={
                    "run_id": run_id,
                    "client_id": client_id,
                    "tool_name": name,
                    "scope_allowlist": doc.scope,
                },
            )
            raise McpError(
                ErrorData(
                    code=INVALID_PARAMS,
                    message=(f"tool call denied: client {client_id!r} is not authorized to call {name!r}"),
                )
            )

        # All checks pass — emit AUTHORIZED + delegate.
        _log.info(
            action=EventAction.AI_MCP_TOOL_AUTHORIZED,
            outcome=EventOutcome.SUCCESS,
            message=(f"MCP tool {name!r} authorized for client {client_id!r}"),
            evidentia={
                "run_id": run_id,
                "client_id": client_id,
                "tool_name": name,
                "scope_allowlist": doc.scope,
            },
        )
        return await original_call_tool(name, arguments)

    # Replace + mark to prevent double-wrap.
    server.call_tool = _gated_call_tool  # type: ignore[method-assign]
    server._evidentia_scope_wrapped = True  # type: ignore[attr-defined]


__all__ = [
    "enforce_cimd_scope",
]
