"""Tests for the v0.9.8 P1.1 FastMCP dispatch-layer auto-wrap.

Verifies :func:`evidentia_mcp.signed_dispatch.wrap_signed_output`:

- normalizes FastMCP's real ``call_tool`` return shapes — the
  ``(unstructured, structured)`` tuple, a content-block list, a
  ``CallToolResult``, a bare dict;
- signs the structured payload + attaches the envelope to ``_meta``
  WITHOUT mutating the tool's ``content`` / ``structuredContent``;
- composes with the CIMD scope gate.

v0.9.8 review note (F-V98-01): an earlier draft stubbed ``call_tool``
with bare return values, so it never exercised FastMCP's real tuple
contract and missed that the wrapper broke every output-schema tool.
This suite now uses the correct shapes AND a real-``FastMCP``-server
integration test (:class:`TestRealServerIntegration`).
"""

from __future__ import annotations

import hashlib
import hmac
import sys
import types
from typing import Any
from unittest.mock import AsyncMock

import pytest
from evidentia_core.factory_resolver import clear_factory_cache
from evidentia_mcp.signatures import (
    EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR,
    EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
)
from evidentia_mcp.signed_dispatch import (
    SIGNED_OUTPUT_META_KEY,
    wrap_signed_output,
)
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

# ── Deterministic test signer ──────────────────────────────────────


_TEST_HMAC_KEY = b"v0.9.8-signed-dispatch-test-key"


def make_test_signer() -> Any:
    """Factory referenced via dotted-path in env-var tests."""

    def _sign(payload: bytes) -> dict[str, str]:
        mac = hmac.new(_TEST_HMAC_KEY, payload, hashlib.sha256).hexdigest()
        return {"alg": "hmac-sha256", "sig": mac}

    return _sign


def make_failing_signer() -> Any:
    """Factory whose signer always raises — exercises signing_error path."""

    def _sign(payload: bytes) -> dict[str, str]:
        raise RuntimeError("HSM unavailable in test")

    return _sign


# ── Fixtures ───────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_factory_cache() -> None:
    """Drop the shared factory_resolver cache between tests."""
    clear_factory_cache()


@pytest.fixture(autouse=True)
def _register_test_module() -> None:
    """Make this module discoverable via dotted-path import."""
    mod = types.ModuleType("test_signed_dispatch_helpers")
    mod.make_test_signer = make_test_signer  # type: ignore[attr-defined]
    mod.make_failing_signer = make_failing_signer  # type: ignore[attr-defined]
    sys.modules["test_signed_dispatch_helpers"] = mod


def _make_server_returning(result: Any) -> FastMCP:
    """Build a FastMCP fixture whose ``call_tool`` returns ``result``.

    The stub mimics whatever shape FastMCP's real ``call_tool`` would
    produce — callers pass the realistic tuple / content-list / dict /
    CallToolResult shapes, NOT bare scalars.
    """
    server = FastMCP(name="test-signed-dispatch")
    server.call_tool = AsyncMock(return_value=result)  # type: ignore[method-assign]
    return server


def _enable_signing(
    monkeypatch: pytest.MonkeyPatch,
    *,
    factory_attr: str = "make_test_signer",
) -> None:
    monkeypatch.setenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, "1")
    monkeypatch.setenv(
        EVIDENCE_MCP_SIGNER_FACTORY_ENV_VAR,
        f"test_signed_dispatch_helpers:{factory_attr}",
    )


def _text(s: str) -> TextContent:
    return TextContent(type="text", text=s)


# ── 1. Pass-through when signing is disabled ──────────────────────


class TestPassThroughWhenSigningOff:
    @pytest.mark.asyncio
    async def test_unset_env_returns_tuple_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Signing off → the inner result (a tuple) is returned as-is."""
        monkeypatch.delenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, raising=False)
        inner = ([_text('{"k":"v"}')], {"k": "v"})
        server = _make_server_returning(inner)
        wrap_signed_output(server)

        result = await server.call_tool("get_control", {})
        assert result is inner  # identical object — no wrapping

    @pytest.mark.asyncio
    async def test_unset_env_returns_content_list_verbatim(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, raising=False)
        inner = [_text("plain")]
        server = _make_server_returning(inner)
        wrap_signed_output(server)
        assert await server.call_tool("t", {}) is inner


# ── 2. Envelope-in-_meta wrap (signing enabled) ──────────────────


class TestEnvelopeInMeta:
    @pytest.mark.asyncio
    async def test_tuple_result_signs_structured_content(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The real output-schema-tool shape: (content, structured).

        The wrapper must return a CallToolResult whose structuredContent
        is UNCHANGED + whose _meta carries the envelope.
        """
        _enable_signing(monkeypatch)
        structured = {"control_id": "AC-2", "title": "Account Management"}
        content = [_text('{"control_id":"AC-2"}')]
        server = _make_server_returning((content, structured))
        wrap_signed_output(server)

        result = await server.call_tool("get_control", {})

        assert isinstance(result, CallToolResult)
        # Tool output is UNTOUCHED.
        assert result.structuredContent == structured
        assert result.content == content
        assert result.isError is False
        # Signature rides in _meta.
        assert result.meta is not None
        envelope = result.meta[SIGNED_OUTPUT_META_KEY]
        assert envelope["signature"] is not None
        assert envelope["signature"]["alg"] == "hmac-sha256"
        assert envelope["schema_version"] == 1
        # The envelope signs the structured content verbatim.
        assert envelope["payload"] == structured
        assert envelope["tool_name"] == "get_control"

    @pytest.mark.asyncio
    async def test_content_list_result_wraps_under_result_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A no-output-schema tool returns only a content list."""
        _enable_signing(monkeypatch)
        content = [_text("alpha"), _text("beta")]
        server = _make_server_returning(content)
        wrap_signed_output(server)

        result = await server.call_tool("t", {})
        assert isinstance(result, CallToolResult)
        assert result.structuredContent is None
        assert result.content == content
        envelope = result.meta[SIGNED_OUTPUT_META_KEY]
        # No structured dict → payload is a {"result": [...]} wrap of
        # the JSON-able content blocks.
        assert "result" in envelope["payload"]
        assert len(envelope["payload"]["result"]) == 2
        assert envelope["signature"] is not None

    @pytest.mark.asyncio
    async def test_bare_dict_result_synthesizes_content(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A bare structured dict gets a synthesized TextContent block."""
        _enable_signing(monkeypatch)
        server = _make_server_returning({"ok": True})
        wrap_signed_output(server)

        result = await server.call_tool("t", {})
        assert isinstance(result, CallToolResult)
        assert result.structuredContent == {"ok": True}
        assert len(result.content) == 1
        assert result.content[0].type == "text"
        assert result.meta[SIGNED_OUTPUT_META_KEY]["payload"] == {"ok": True}

    @pytest.mark.asyncio
    async def test_calltoolresult_input_merges_existing_meta(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A CallToolResult input keeps its existing _meta + adds the envelope."""
        _enable_signing(monkeypatch)
        inner = CallToolResult(
            content=[_text('{"a":1}')],
            structuredContent={"a": 1},
            isError=False,
        )
        inner.meta = {"pre-existing/key": "keep-me"}
        server = _make_server_returning(inner)
        wrap_signed_output(server)

        result = await server.call_tool("t", {})
        assert isinstance(result, CallToolResult)
        assert result.structuredContent == {"a": 1}
        # Existing meta preserved + envelope added.
        assert result.meta["pre-existing/key"] == "keep-me"
        assert SIGNED_OUTPUT_META_KEY in result.meta

    @pytest.mark.asyncio
    async def test_unrecognized_shape_passes_through_unsigned(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A shape the normalizer doesn't model is returned unsigned."""
        _enable_signing(monkeypatch)
        sentinel = 42  # not tuple/dict/CallToolResult/iterable
        server = _make_server_returning(sentinel)
        wrap_signed_output(server)
        assert await server.call_tool("t", {}) == 42

    @pytest.mark.asyncio
    async def test_signing_is_deterministic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _enable_signing(monkeypatch)
        server = _make_server_returning(([_text("x")], {"x": 1}))
        wrap_signed_output(server)
        a = await server.call_tool("t", {})
        b = await server.call_tool("t", {})
        assert (
            a.meta[SIGNED_OUTPUT_META_KEY]["signature"]
            == b.meta[SIGNED_OUTPUT_META_KEY]["signature"]
        )


# ── 3. Signer-failure non-fatal ──────────────────────────────────


class TestSignerFailureNonFatal:
    @pytest.mark.asyncio
    async def test_signer_raises_yields_signing_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A failing signer → envelope carries signing_error; result still valid."""
        _enable_signing(monkeypatch, factory_attr="make_failing_signer")
        server = _make_server_returning(([_text("x")], {"ok": True}))
        wrap_signed_output(server)

        result = await server.call_tool("t", {})
        assert isinstance(result, CallToolResult)
        # Tool output still intact.
        assert result.structuredContent == {"ok": True}
        envelope = result.meta[SIGNED_OUTPUT_META_KEY]
        assert envelope["signature"] is None
        assert "HSM unavailable" in envelope["signing_error"]


# ── 4. Layer composition with the CIMD scope gate ────────────────


class TestLayerComposition:
    @pytest.mark.asyncio
    async def test_scope_denial_short_circuits_signing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A scope-gate denial raises before signing — no envelope emitted."""
        from unittest.mock import MagicMock

        from evidentia_mcp.cimd import CIMDDocument, CIMDRegistry
        from evidentia_mcp.scope import enforce_cimd_scope
        from mcp.shared.exceptions import McpError

        _enable_signing(monkeypatch)
        server = _make_server_returning(([_text("x")], {"ok": True}))
        registry = CIMDRegistry(
            clients={
                "test-client": CIMDDocument(
                    client_id="test-client",
                    client_name="Test",
                    scope="other_tool",
                )
            }
        )
        server.evidentia_cimd = registry  # type: ignore[attr-defined]
        fake_ctx = MagicMock()
        fake_ctx.client_id = "test-client"
        server.get_context = MagicMock(return_value=fake_ctx)  # type: ignore[method-assign]

        enforce_cimd_scope(server)
        wrap_signed_output(server)

        with pytest.raises(McpError):
            await server.call_tool("denied_tool", {})


# ── 5. Idempotency ───────────────────────────────────────────────


class TestIdempotency:
    def test_double_wrap_raises(self) -> None:
        server = FastMCP(name="test")
        server.call_tool = AsyncMock(return_value=([], {}))  # type: ignore[method-assign]
        wrap_signed_output(server)
        with pytest.raises(RuntimeError, match="already wired"):
            wrap_signed_output(server)


# ── 6. Real-FastMCP integration (the test that catches F-V98-01) ──


class TestRealServerIntegration:
    """Exercises a REAL FastMCP server + a REAL registered tool.

    This is the coverage gap that let F-V98-01 ship in the first
    draft: stubbed ``call_tool`` never produced FastMCP's real
    ``(unstructured, structured)`` tuple, so the wrapper's mishandling
    of it went unnoticed. These tests call through the genuine
    ``convert_result`` path.
    """

    def _build_real_server(self) -> FastMCP:
        server = FastMCP(name="test-real-integration")

        @server.tool()
        def double_it(x: int) -> dict[str, Any]:
            """A real tool with a typed dict return → gets an output schema."""
            return {"doubled": x * 2, "tool": "double_it"}

        return server

    @pytest.mark.asyncio
    async def test_real_tool_signing_off_is_unwrapped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Signing off → the real tuple from convert_result passes through."""
        monkeypatch.delenv(EVIDENCE_MCP_SIGN_OUTPUTS_ENV_VAR, raising=False)
        server = self._build_real_server()
        wrap_signed_output(server)

        result = await server.call_tool("double_it", {"x": 21})
        # FastMCP's convert_result returns a (unstructured, structured)
        # tuple for an output-schema tool — unchanged by the wrapper.
        assert isinstance(result, tuple)
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_real_tool_signing_on_produces_valid_signed_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Signing on → a well-formed CallToolResult with the envelope in _meta.

        Crucially: the structured content is the tool's REAL output,
        unchanged — so the lowlevel server's outputSchema validation
        (which the wrapper's earlier draft broke) is satisfied.
        """
        _enable_signing(monkeypatch)
        server = self._build_real_server()
        wrap_signed_output(server)

        result = await server.call_tool("double_it", {"x": 21})

        assert isinstance(result, CallToolResult)
        assert result.isError is False
        # The tool's real structured output, unchanged.
        assert result.structuredContent is not None
        assert result.structuredContent["doubled"] == 42
        assert result.structuredContent["tool"] == "double_it"
        # Unstructured content present (clients that ignore structured
        # output still get a usable result).
        assert len(result.content) >= 1
        # The signature rides in _meta and signs the exact structured
        # content — a verifier can cross-check payload == structuredContent.
        assert result.meta is not None
        envelope = result.meta[SIGNED_OUTPUT_META_KEY]
        assert envelope["signature"] is not None
        assert envelope["payload"] == result.structuredContent
        assert envelope["tool_name"] == "double_it"


# ── 7. build_server wiring ───────────────────────────────────────


class TestBuildServerWiring:
    def test_build_server_wires_signed_dispatch(self) -> None:
        from evidentia_mcp.server import build_server

        server = build_server()
        assert getattr(server, "_evidentia_signed_wrapped", False) is True
        assert getattr(server, "_evidentia_scope_wrapped", False) is True

    @pytest.mark.asyncio
    async def test_build_server_real_tool_signed_end_to_end(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """build_server() + a real bundled tool + signing on → valid result."""
        from evidentia_mcp.server import build_server

        _enable_signing(monkeypatch)
        server = build_server()
        result = await server.call_tool("list_frameworks", {})

        assert isinstance(result, CallToolResult)
        assert result.isError is False
        assert result.meta is not None
        envelope = result.meta[SIGNED_OUTPUT_META_KEY]
        assert envelope["signature"] is not None
        assert envelope["tool_name"] == "list_frameworks"
