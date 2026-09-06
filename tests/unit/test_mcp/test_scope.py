"""Unit tests for the CIMD scope-enforcement gate (v0.8.6 P1).

6 test classes mirroring the surface added in v0.8.6 P1:

1. :class:`TestPassThroughWithoutCIMD` — when ``server.evidentia_cimd``
   is ``None``, the gate routes calls through with no audit emit.
2. :class:`TestDenyAmbiguousClientId` — when neither
   ``Context.client_id`` nor ``default_client_id`` resolves a
   client, the gate denies.
3. :class:`TestDenyUnregisteredClientId` — when the resolved
   client_id is not in the registry, the gate denies.
4. :class:`TestDenyOutOfScope` — when the registered CIMDDocument's
   scope does not include the requested tool, the gate denies.
5. :class:`TestAllowInScope` — happy path: registered client_id +
   scope contains tool → AUTHORIZED + delegate.
6. :class:`TestIdempotency` — calling ``enforce_cimd_scope`` twice
   on the same server raises RuntimeError.
"""

from __future__ import annotations

import logging
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from evidentia_mcp.cimd import CIMDDocument, CIMDRegistry
from evidentia_mcp.scope import enforce_cimd_scope
from mcp.server.fastmcp import FastMCP
from mcp.shared.exceptions import McpError


def _make_server(
    *,
    cimd_registry: CIMDRegistry | None = None,
    ctx_client_id: str | None = None,
) -> FastMCP:
    """Build a minimal FastMCP fixture for gate tests.

    Avoids the full ``build_server`` import path so tests stay
    isolated to the scope module's behavior. Stubs:
    - ``server.evidentia_cimd`` = the supplied registry
    - ``server.call_tool`` = AsyncMock returning a sentinel
    - ``server.get_context`` = MagicMock returning a Context-
      shaped object whose ``.client_id`` is ``ctx_client_id``
    """
    server = FastMCP(name="test-evidentia")
    server.evidentia_cimd = cimd_registry  # type: ignore[attr-defined]

    # Stub call_tool — returns a sentinel so we can assert
    # delegation happened.
    delegate = AsyncMock(return_value="delegated-result")
    server.call_tool = delegate  # type: ignore[method-assign]

    # Stub get_context — returns a Context-shaped object with
    # the configured client_id.
    fake_ctx = MagicMock()
    fake_ctx.client_id = ctx_client_id
    server.get_context = MagicMock(return_value=fake_ctx)  # type: ignore[method-assign]

    return server


def _make_registry(*, client_id: str = "test-client", scope: str = "") -> CIMDRegistry:
    """Build a single-client CIMD registry fixture."""
    return CIMDRegistry(
        clients={
            client_id: CIMDDocument(
                client_id=client_id,
                client_name=f"Test client {client_id}",
                scope=scope,
            )
        }
    )


# ── 1. Pass-through when CIMD registry is None ───────────────────


class TestPassThroughWithoutCIMD:
    @pytest.mark.asyncio
    async def test_no_registry_passes_through(self, caplog: pytest.LogCaptureFixture) -> None:
        """When evidentia_cimd is None, the gate delegates without
        emitting any audit events. This is the v0.8.5 behavior
        preserved for operators who haven't opted into CIMD.
        """
        server = _make_server(cimd_registry=None)
        original_delegate = server.call_tool
        enforce_cimd_scope(server)

        with caplog.at_level(logging.INFO, logger="evidentia.mcp.scope"):
            result = await server.call_tool("any_tool", {"x": 1})

        assert result == "delegated-result"
        original_delegate.assert_awaited_once_with("any_tool", {"x": 1})
        # No audit events emit when registry is absent.
        assert len([r for r in caplog.records if r.name == "evidentia.mcp.scope"]) == 0


# ── 2. Deny when client_id cannot be resolved ────────────────────


class TestDenyAmbiguousClientId:
    @pytest.mark.asyncio
    async def test_neither_ctx_nor_default_denies(self, caplog: pytest.LogCaptureFixture) -> None:
        """When Context.client_id is None AND default_client_id is
        None, the gate denies the call as ambiguous-caller.
        """
        registry = _make_registry(scope="any_tool")
        server = _make_server(cimd_registry=registry, ctx_client_id=None)
        enforce_cimd_scope(server, default_client_id=None)

        with (
            caplog.at_level(logging.WARNING, logger="evidentia.mcp.scope"),
            pytest.raises(McpError) as exc_info,
        ):
            await server.call_tool("any_tool", {})

        # Error message surfaces the no-client_id condition.
        assert "no client_id" in str(exc_info.value).lower()
        # AI_MCP_TOOL_DENIED audit event emitted.
        deny_records = [
            r for r in caplog.records if r.name == "evidentia.mcp.scope" and "denied" in r.getMessage().lower()
        ]
        assert len(deny_records) == 1


# ── 3. Deny when client_id is not registered ─────────────────────


class TestDenyUnregisteredClientId:
    @pytest.mark.asyncio
    async def test_unregistered_client_id_denies(self, caplog: pytest.LogCaptureFixture) -> None:
        """Registry has 'registered-client'; request comes in as
        'unknown-client' via default_client_id → DENY.
        """
        registry = _make_registry(client_id="registered-client", scope="any_tool")
        server = _make_server(cimd_registry=registry, ctx_client_id=None)
        enforce_cimd_scope(server, default_client_id="unknown-client")

        with (
            caplog.at_level(logging.WARNING, logger="evidentia.mcp.scope"),
            pytest.raises(McpError) as exc_info,
        ):
            await server.call_tool("any_tool", {})

        # Error message names the unregistered client_id.
        assert "unknown-client" in str(exc_info.value)
        deny_records = [
            r
            for r in caplog.records
            if r.name == "evidentia.mcp.scope" and "not in the cimd registry" in r.getMessage().lower()
        ]
        assert len(deny_records) == 1


# ── 4. Deny when scope does not include the tool ─────────────────


class TestDenyOutOfScope:
    @pytest.mark.asyncio
    async def test_out_of_scope_tool_denies(self, caplog: pytest.LogCaptureFixture) -> None:
        """Registry's CIMDDocument has scope='list_frameworks';
        request to call 'gap_analyze' → DENY (deny-by-default
        allowlist).
        """
        registry = _make_registry(client_id="readonly-client", scope="list_frameworks")
        server = _make_server(cimd_registry=registry, ctx_client_id="readonly-client")
        enforce_cimd_scope(server)

        with (
            caplog.at_level(logging.WARNING, logger="evidentia.mcp.scope"),
            pytest.raises(McpError) as exc_info,
        ):
            await server.call_tool("gap_analyze", {})

        assert "not authorized" in str(exc_info.value).lower()
        # AI_MCP_TOOL_DENIED audit event includes scope_allowlist.
        deny_records = [
            r for r in caplog.records if r.name == "evidentia.mcp.scope" and "scope" in r.getMessage().lower()
        ]
        assert len(deny_records) == 1
        # Verify scope_allowlist field is on the structured event.
        ecs_record = getattr(deny_records[0], "ecs_record", None)
        assert ecs_record is not None
        evidentia_extra = ecs_record.get("evidentia", {})
        assert evidentia_extra["scope_allowlist"] == "list_frameworks"
        assert evidentia_extra["client_id"] == "readonly-client"
        assert evidentia_extra["tool_name"] == "gap_analyze"


# ── 5. Allow + delegate when scope includes the tool ─────────────


class TestAllowInScope:
    @pytest.mark.asyncio
    async def test_in_scope_tool_authorizes_and_delegates(self, caplog: pytest.LogCaptureFixture) -> None:
        """Happy path: registered client_id + scope contains tool
        → AUTHORIZED audit emit + delegate to original call_tool.
        """
        registry = _make_registry(
            client_id="power-client",
            scope="list_frameworks gap_analyze gap_diff",
        )
        server = _make_server(cimd_registry=registry, ctx_client_id="power-client")
        original_delegate = server.call_tool
        enforce_cimd_scope(server)

        with caplog.at_level(logging.INFO, logger="evidentia.mcp.scope"):
            result = await server.call_tool("gap_analyze", {"inventory_path": "/tmp/foo"})

        assert result == "delegated-result"
        original_delegate.assert_awaited_once_with("gap_analyze", {"inventory_path": "/tmp/foo"})
        # AI_MCP_TOOL_AUTHORIZED audit event emitted.
        auth_records = [
            r for r in caplog.records if r.name == "evidentia.mcp.scope" and "authorized" in r.getMessage().lower()
        ]
        assert len(auth_records) == 1
        ecs_record = getattr(auth_records[0], "ecs_record", None)
        assert ecs_record is not None
        evidentia_extra = ecs_record.get("evidentia", {})
        assert evidentia_extra["client_id"] == "power-client"
        assert evidentia_extra["tool_name"] == "gap_analyze"
        assert "gap_analyze" in evidentia_extra["scope_allowlist"]

    @pytest.mark.asyncio
    async def test_default_client_id_fallback_when_ctx_none(self, caplog: pytest.LogCaptureFixture) -> None:
        """Stdio canonical case: Context.client_id is None;
        default_client_id supplies the slug → AUTHORIZED.
        """
        registry = _make_registry(client_id="stdio-client", scope="list_frameworks")
        server = _make_server(cimd_registry=registry, ctx_client_id=None)
        enforce_cimd_scope(server, default_client_id="stdio-client")

        with caplog.at_level(logging.INFO, logger="evidentia.mcp.scope"):
            result = await server.call_tool("list_frameworks", {})

        assert result == "delegated-result"


# ── 6. Idempotency guard ─────────────────────────────────────────


class TestIdempotency:
    def test_double_wire_raises(self) -> None:
        """Calling enforce_cimd_scope twice on the same server
        raises RuntimeError to prevent silent double-wrapping."""
        server = _make_server()
        enforce_cimd_scope(server)
        with pytest.raises(RuntimeError, match="already wired"):
            enforce_cimd_scope(server)


# ── 7. Audit-event evidentia.run_id field present ────────────────


class TestRunIdField:
    @pytest.mark.asyncio
    async def test_each_call_emits_unique_run_id(self, caplog: pytest.LogCaptureFixture) -> None:
        """Each tool call should produce a fresh UUID4 run_id so
        auditors can correlate requests in the audit stream.
        """
        registry = _make_registry(client_id="x", scope="list_frameworks")
        server = _make_server(cimd_registry=registry, ctx_client_id="x")
        enforce_cimd_scope(server)

        with caplog.at_level(logging.INFO, logger="evidentia.mcp.scope"):
            await server.call_tool("list_frameworks", {})
            await server.call_tool("list_frameworks", {})

        run_ids: list[Any] = [
            (getattr(r, "ecs_record", {}) or {}).get("evidentia", {}).get("run_id")
            for r in caplog.records
            if r.name == "evidentia.mcp.scope"
        ]
        assert len(run_ids) == 2
        assert run_ids[0] != run_ids[1]
        assert all(isinstance(rid, str) for rid in run_ids)
