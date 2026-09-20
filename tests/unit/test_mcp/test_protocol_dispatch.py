"""Exercise published tools through the SDK's normal connected protocol client."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
import threading
import types
from pathlib import Path
from typing import Any
from unittest.mock import patch

import anyio
import pytest
from evidentia_mcp.cimd import CIMDDocument, CIMDRegistry
from evidentia_mcp.server import build_server
from evidentia_mcp.signed_dispatch import SIGNED_OUTPUT_META_KEY
from mcp import Client
from mcp.client.stdio import StdioServerParameters
from mcp.server.mcpserver import Context
from mcp.shared.exceptions import MCPError
from mcp_types import CallToolResult, EmbeddedResource, ImageContent, TextContent, TextResourceContents


@pytest.fixture(params=["default", "legacy"])
def protocol_mode(request: pytest.FixtureRequest) -> str:
    return str(request.param)


def _client(server: Any, mode: str) -> Client:
    return Client(server) if mode == "default" else Client(server, mode="legacy")


def _registry(tool: str = "authorization_probe") -> CIMDRegistry:
    return CIMDRegistry(
        clients={
            name: CIMDDocument(client_id=name, client_name=f"Synthetic {name}", scope=scope)
            for name, scope in (("allowed", tool), ("also-allowed", tool), ("denied", "list_frameworks"))
        }
    )


@pytest.mark.anyio
async def test_frozen_tool_contracts(tmp_path: Path, protocol_mode: str) -> None:
    """Compare the server listing with the independently captured v1 wire contract."""
    fixture = Path(__file__).parent / "fixtures" / "tool-contracts-v1.json"
    oracle = json.loads(fixture.read_text(encoding="utf-8"))
    assert oracle["sdk_version"] == "1.29.1"
    server = build_server(allow_root=tmp_path)
    with anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            listing = await client.list_tools()
    contracts = []
    for tool in listing.tools:
        wire = tool.model_dump(mode="json", by_alias=True)
        contracts.append({key: wire[key] for key in ("name", "description", "inputSchema", "outputSchema")})
    native_fixture = Path(__file__).parent / "fixtures" / "tool-contracts-native-v1.json"
    native_oracle = json.loads(native_fixture.read_text(encoding="utf-8"))
    expected = [*oracle["tools"], *native_oracle["tools"]]
    # CPython 3.13+ dedents docstrings during compilation. Compare their prose
    # with standard docstring cleaning; names and schemas remain exact.
    for contract in [*contracts, *expected]:
        contract["description"] = inspect.cleandoc(contract["description"])
    assert len(contracts) == 15
    assert sorted(contracts, key=lambda tool: tool["name"]) == sorted(expected, key=lambda tool: tool["name"])


@pytest.mark.anyio
async def test_harmless_connected_dispatch(tmp_path: Path, protocol_mode: str) -> None:
    """Initialize, list frameworks and fetch a control without external state."""
    server = build_server(allow_root=tmp_path)
    with anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            frameworks = await client.call_tool("list_frameworks", {})
            control = await client.call_tool(
                "get_control",
                {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"},
            )
    assert not frameworks.is_error
    assert frameworks.structured_content is not None
    assert any(item["id"] == "nist-800-53-rev5-moderate" for item in frameworks.structured_content["result"])
    assert not control.is_error
    assert control.structured_content is not None
    assert control.structured_content["id"] == "AC-2"
    assert SIGNED_OUTPUT_META_KEY not in (control.meta or {})


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("gated", "fallback", "identity", "permitted"),
    [
        (False, None, None, True),
        (True, "allowed", None, True),
        (True, "denied", None, False),
        (True, None, None, False),
        (True, "unknown", None, False),
        (True, "allowed", "denied", False),
        (True, "denied", "allowed", True),
    ],
)
async def test_scope_and_signing_through_protocol(
    tmp_path: Path,
    protocol_mode: str,
    synthetic_signer: list[bytes],
    gated: bool,
    fallback: str | None,
    identity: str | None,
    permitted: bool,
) -> None:
    """A denied request cannot execute or sign, and records one denial."""
    server = build_server(
        allow_root=tmp_path,
        cimd_registry=_registry() if gated else None,
        default_client_id=fallback,
    )
    handlers: list[str] = []

    @server.tool()
    def authorization_probe() -> dict[str, str]:
        handlers.append("executed")
        return {"marker": "synthetic-authorized-output"}

    metadata = {"client_id": identity} if identity is not None else None
    with patch("evidentia_mcp.scope._log") as audit, anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            if permitted:
                result = await client.call_tool("authorization_probe", {}, meta=metadata)
                assert not result.is_error
                assert result.structured_content == {"marker": "synthetic-authorized-output"}
                envelope = (result.meta or {})[SIGNED_OUTPUT_META_KEY]
                canonical = b'{"marker":"synthetic-authorized-output"}'
                assert envelope["payload"] == result.structured_content
                assert envelope["tool_name"] == "authorization_probe"
                assert envelope["signature"]["digest"] == hashlib.sha256(canonical).hexdigest()
                assert synthetic_signer == [canonical]
            else:
                with pytest.raises(MCPError) as raised:
                    await client.call_tool("authorization_probe", {}, meta=metadata)
                assert raised.value.code == -32602
                assert raised.value.data is None
                assert "denied" in raised.value.message
                assert synthetic_signer == []
            assert len((await client.list_tools()).tools) == 16
        assert len(handlers) == int(permitted)
        assert len(audit.method_calls) == int(gated)
        if gated:
            decision = audit.method_calls[0]
            assert decision[0] == ("info" if permitted else "warning")
            assert decision.kwargs["evidentia"]["client_id"] == (identity or fallback)


@pytest.mark.anyio
@pytest.mark.parametrize("identity", [False, 0, [], {}])
async def test_malformed_identity_cannot_use_allowed_fallback(
    tmp_path: Path, protocol_mode: str, synthetic_signer: list[bytes], identity: Any
) -> None:
    server = build_server(allow_root=tmp_path, cimd_registry=_registry(), default_client_id="allowed")
    handlers: list[str] = []

    @server.tool()
    def authorization_probe() -> dict[str, str]:
        handlers.append("executed")
        return {"marker": "synthetic"}

    with patch("evidentia_mcp.scope._log") as audit, anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            with pytest.raises(MCPError) as raised:
                await client.call_tool("authorization_probe", {}, meta={"client_id": identity})
            assert raised.value.code == -32602
            assert raised.value.data is None
            assert len((await client.list_tools()).tools) == 16
        assert len(audit.method_calls) == 1
        assert audit.warning.call_args.kwargs["evidentia"]["client_id"] is None
    assert handlers == []
    assert synthetic_signer == []


@pytest.mark.anyio
async def test_sequential_identities_do_not_leak(tmp_path: Path, protocol_mode: str) -> None:
    server = build_server(allow_root=tmp_path, cimd_registry=_registry())
    seen: list[str] = []

    @server.tool()
    def authorization_probe(ctx: Context) -> dict[str, str]:
        identity = str((ctx.request_context.meta or {})["client_id"])
        seen.append(identity)
        return {"identity": identity}

    with patch("evidentia_mcp.scope._log") as audit, anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            for identity in ("allowed", "denied", None, "unknown", "also-allowed"):
                metadata = {"client_id": identity} if identity is not None else None
                if identity in {"allowed", "also-allowed"}:
                    result = await client.call_tool("authorization_probe", {}, meta=metadata)
                    assert result.structured_content == {"identity": identity}
                else:
                    with pytest.raises(MCPError) as raised:
                        await client.call_tool("authorization_probe", {}, meta=metadata)
                    assert raised.value.code == -32602
            assert len((await client.list_tools()).tools) == 16
        assert len(audit.method_calls) == 5
    assert seen == ["allowed", "also-allowed"]


@pytest.mark.anyio
async def test_overlapping_identities_keep_their_context(
    tmp_path: Path, protocol_mode: str, synthetic_signer: list[bytes]
) -> None:
    """Hold both permitted handlers open while a concurrent denied call completes."""
    server = build_server(allow_root=tmp_path, cimd_registry=_registry())
    entered: list[str] = []
    release = anyio.Event()
    both_entered = anyio.Event()
    denied_finished = anyio.Event()
    outputs: dict[str, str] = {}

    @server.tool()
    async def authorization_probe(ctx: Context) -> dict[str, str]:
        before = str((ctx.request_context.meta or {})["client_id"])
        entered.append(before)
        if len(entered) == 2:
            both_entered.set()
        await release.wait()
        after = str((ctx.request_context.meta or {})["client_id"])
        assert before == after
        return {"identity": after}

    with patch("evidentia_mcp.scope._log") as audit, anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:

            async def request(identity: str) -> None:
                if identity == "denied":
                    with pytest.raises(MCPError) as raised:
                        await client.call_tool("authorization_probe", {}, meta={"client_id": identity})
                    assert raised.value.code == -32602
                    denied_finished.set()
                else:
                    result = await client.call_tool("authorization_probe", {}, meta={"client_id": identity})
                    assert result.structured_content is not None
                    outputs[identity] = result.structured_content["identity"]

            async with anyio.create_task_group() as group:
                group.start_soon(request, "allowed")
                group.start_soon(request, "also-allowed")
                await both_entered.wait()
                group.start_soon(request, "denied")
                await denied_finished.wait()
                assert synthetic_signer == []
                release.set()
            assert len((await client.list_tools()).tools) == 16
        assert len(audit.method_calls) == 3
    assert sorted(entered) == ["allowed", "also-allowed"]
    assert outputs == {"allowed": "allowed", "also-allowed": "also-allowed"}
    assert len(synthetic_signer) == 2


@pytest.mark.anyio
@pytest.mark.parametrize("error_result", [False, True])
async def test_signed_content_keeps_wire_fields_and_metadata(
    tmp_path: Path,
    protocol_mode: str,
    synthetic_signer: list[bytes],
    monkeypatch: pytest.MonkeyPatch,
    error_result: bool,
) -> None:
    server = build_server(allow_root=tmp_path)

    @server.tool()
    def content_probe() -> CallToolResult:
        return CallToolResult(
            content=[
                TextContent(type="text", text="synthetic content"),
                ImageContent(type="image", data="AA==", mime_type="image/png"),
                EmbeddedResource(
                    type="resource",
                    resource=TextResourceContents(
                        uri="synthetic://record/1", mime_type="text/plain", text="synthetic resource"
                    ),
                ),
            ],
            is_error=error_result,
            meta={"synthetic/source": {"fixture": "wire"}},
        )

    with anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            with monkeypatch.context() as unsigned:
                unsigned.setattr("evidentia_mcp.signed_dispatch._resolve_signer_factory", lambda: None)
                original = await client.call_tool("content_probe", {})
            result = await client.call_tool("content_probe", {})
    assert result.content == original.content
    assert result.is_error == original.is_error == error_result
    assert result.structured_content == original.structured_content
    assert result.meta is not None
    assert {key: value for key, value in result.meta.items() if key != SIGNED_OUTPUT_META_KEY} == original.meta
    envelope = result.meta[SIGNED_OUTPUT_META_KEY]
    payload = {"result": [block.model_dump(mode="json", by_alias=True) for block in result.content]}
    assert envelope["payload"] == payload
    assert payload["result"][1]["mimeType"] == "image/png"
    assert payload["result"][2]["resource"]["mimeType"] == "text/plain"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert synthetic_signer == [canonical]
    assert envelope["signature"]["digest"] == hashlib.sha256(canonical).hexdigest()


@pytest.mark.anyio
async def test_enabled_empty_signer_factory_is_an_error(
    tmp_path: Path, protocol_mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Configured signing cannot disappear when an importable factory returns None."""
    module = types.ModuleType("synthetic_empty_protocol_signer")
    monkeypatch.setattr(module, "make_signer", lambda: None, raising=False)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setenv("EVIDENTIA_MCP_SIGN_OUTPUTS", "1")
    monkeypatch.setenv("EVIDENTIA_MCP_SIGNER_FACTORY", f"{module.__name__}:make_signer")
    server = build_server(allow_root=tmp_path)
    with anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            for _ in range(2):
                result = await client.call_tool(
                    "get_control", {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"}
                )
                assert result.is_error
                assert SIGNED_OUTPUT_META_KEY not in (result.meta or {})
            monkeypatch.setenv("EVIDENTIA_MCP_SIGN_OUTPUTS", "")
            recovered = await client.call_tool(
                "get_control", {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"}
            )
            assert not recovered.is_error


@pytest.mark.anyio
async def test_error_channels_and_client_recovery(tmp_path: Path, mcp_test_inventory: Path, protocol_mode: str) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    server = build_server(allow_root=allowed)

    @server.tool()
    def ordinary_failure() -> dict[str, str]:
        raise ValueError("synthetic ordinary error")

    @server.tool()
    def protocol_failure() -> dict[str, str]:
        raise MCPError(code=-32602, message="synthetic protocol error", data={"synthetic": True})

    cases = [
        ("not_a_registered_tool", {}),
        ("get_control", {}),
        ("get_control", {"framework_id": [], "control_id": {}}),
        ("ordinary_failure", {}),
        (
            "gap_analyze",
            {"inventory_path": str(mcp_test_inventory), "frameworks": ["nist-800-53-rev5-moderate"]},
        ),
    ]
    with anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            for name, arguments in cases:
                result = await client.call_tool(name, arguments)
                assert result.is_error, name
                if name == "gap_analyze":
                    assert result.content == [TextContent(type="text", text="Error executing tool gap_analyze")]
                followup = await client.call_tool(
                    "get_control", {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"}
                )
                assert not followup.is_error
            with pytest.raises(MCPError) as raised:
                await client.call_tool("protocol_failure", {})
            assert raised.value.code == -32602
            assert raised.value.data == {"synthetic": True}
            assert len((await client.list_tools()).tools) == 17


@pytest.mark.anyio
async def test_synchronous_file_tool_on_worker_thread(
    tmp_path: Path, mcp_test_inventory: Path, protocol_mode: str
) -> None:
    server = build_server(allow_root=tmp_path)
    original_bytes = mcp_test_inventory.read_bytes()

    @server.tool()
    def thread_probe() -> dict[str, bool]:
        return {"worker_thread": threading.current_thread() is not threading.main_thread()}

    with anyio.fail_after(30):
        async with _client(server, protocol_mode) as client:
            result = await client.call_tool(
                "gap_analyze",
                {
                    "inventory_path": str(mcp_test_inventory),
                    "frameworks": ["nist-800-53-rev5-moderate"],
                    "show_efficiency": False,
                },
            )
            thread = await client.call_tool("thread_probe", {})
    assert not result.is_error
    assert result.structured_content
    assert mcp_test_inventory.read_bytes() == original_bytes
    assert thread.structured_content == {"worker_thread": True}


@pytest.mark.anyio
async def test_stdio_child_initialization_call_and_shutdown(tmp_path: Path) -> None:
    """Run the public CLI in an isolated child and close its protocol session."""
    registry = _registry("get_control")
    registry_path = tmp_path / "cimd.json"
    registry_path.write_text(registry.model_dump_json(), encoding="utf-8", newline="\n")
    config_path = tmp_path / "evidentia.yaml"
    config_path.write_text("{}\n", encoding="utf-8", newline="\n")
    allowed_names = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed_names}
    environment.update(
        {
            "EVIDENTIA_CATALOG_DIR": str(tmp_path / "catalogs"),
            "EVIDENTIA_MCP_SIGN_OUTPUTS": "",
            "EVIDENTIA_MCP_SIGNER_FACTORY": "",
            "HOME": str(tmp_path),
            "USERPROFILE": str(tmp_path),
            "APPDATA": str(tmp_path / "appdata"),
            "LOCALAPPDATA": str(tmp_path / "localappdata"),
            "HOMEDRIVE": tmp_path.drive,
            "HOMEPATH": str(tmp_path)[len(tmp_path.drive) :],
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
            "TMPDIR": str(tmp_path),
            "PYTHONIOENCODING": "utf-8",
            "COLUMNS": "200",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "evidentia.cli.main",
            "--config",
            str(config_path),
            "mcp",
            "serve",
            "--allow-root",
            str(tmp_path),
            "--cimd-registry",
            str(registry_path),
            "--default-client-id",
            "allowed",
        ],
        cwd=tmp_path,
        env=environment,
    )
    with anyio.fail_after(40):
        async with Client(parameters, mode="legacy") as client:
            assert len((await client.list_tools()).tools) == 15
            result = await client.call_tool(
                "get_control", {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"}
            )
            assert not result.is_error
            assert result.structured_content is not None
            assert result.structured_content["id"] == "AC-2"
            assert SIGNED_OUTPUT_META_KEY not in (result.meta or {})
            with pytest.raises(MCPError) as raised:
                await client.call_tool("list_frameworks", {})
            assert raised.value.code == -32602


@pytest.mark.anyio
@pytest.mark.parametrize(
    "arguments",
    [
        {"framework_id": "au-ism", "bundle_sha256": "a" * 64, "extra": "not admitted"},
        {"framework_id": '"au-ism"', "bundle_sha256": "a" * 64},
        {"framework_id": "au-ism"},
        {"framework_id": "au-ism", "bundle_sha256": False},
        {"framework_id": "au-ism", "bundle_sha256": "A" * 64},
        {"framework_id": "unknown", "bundle_sha256": "a" * 64},
    ],
)
async def test_f3_native_raw_arguments_precede_sdk_and_signer(
    tmp_path: Path, protocol_mode: str, synthetic_signer: list[bytes], arguments: dict[str, Any]
) -> None:
    """SDK preprocessing cannot manufacture a closed native request."""
    server = build_server(
        allow_root=tmp_path, cimd_registry=_registry("get_catalog_native"), default_client_id="allowed"
    )
    with patch("evidentia_mcp.server.FrameworkRegistry") as registry, anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            with pytest.raises(MCPError) as raised:
                await client.call_tool("get_catalog_native", arguments)
            assert raised.value.code == -32602
            assert raised.value.message == "invalid get_catalog_native arguments"
            assert raised.value.data is None
    registry.assert_not_called()
    assert synthetic_signer == []


@pytest.mark.anyio
@pytest.mark.parametrize("granted", [False, True])
async def test_f3_native_grant_precedes_handler_and_signer(
    tmp_path: Path, protocol_mode: str, synthetic_signer: list[bytes], granted: bool
) -> None:
    server = build_server(
        allow_root=tmp_path,
        cimd_registry=_registry("get_catalog_native") if granted else None,
        default_client_id="allowed",
    )
    from evidentia_core.catalogs.registry import FrameworkRegistry

    selection = FrameworkRegistry().get_catalog("au-ism").native_source.bundle_sha256 if granted else "0" * 64
    # The real source operation retains its own 60-second budget. This outer
    # harness also includes SDK validation, signing, and protocol shutdown.
    with (
        patch("evidentia_mcp.server.FrameworkRegistry", wraps=FrameworkRegistry) as registry,
        anyio.fail_after(90 if granted else 20),
    ):
        async with _client(server, protocol_mode) as client:
            if granted:
                result = await client.call_tool(
                    "get_catalog_native", {"framework_id": "au-ism", "bundle_sha256": selection}
                )
                assert not result.is_error
                _assert_native_bundle_sources(result.structured_content)
            else:
                with pytest.raises(MCPError) as raised:
                    await client.call_tool("get_catalog_native", {"extra": "not parsed before denial"})
                assert raised.value.code == -32602
    assert registry.call_count == int(granted)
    assert len(synthetic_signer) == int(granted)


@pytest.mark.anyio
async def test_f3_independent_native_tool_record_preserves_old_fourteen(tmp_path: Path, protocol_mode: str) -> None:
    """Compare the production native registration and all fourteen prior records."""
    server = build_server(allow_root=tmp_path)
    with anyio.fail_after(20):
        async with _client(server, protocol_mode) as client:
            listing = await client.list_tools()
    contracts = []
    for item in listing.tools:
        wire = item.model_dump(mode="json", by_alias=True)
        contracts.append({key: wire[key] for key in ("name", "description", "inputSchema", "outputSchema")})
    directory = Path(__file__).parent / "fixtures"
    old = json.loads((directory / "tool-contracts-v1.json").read_text(encoding="utf-8"))
    native = json.loads((directory / "tool-contracts-native-v1.json").read_text(encoding="utf-8"))
    expected = [*old["tools"], *native["tools"]]
    for contract in [*contracts, *expected]:
        contract["description"] = inspect.cleandoc(contract["description"])
    assert len(contracts) == 15
    assert sorted(contracts, key=lambda row: row["name"]) == sorted(expected, key=lambda row: row["name"])


def _assert_native_bundle_sources(payload: dict[str, Any]) -> None:
    """Compare transported source bytes with the pinned on-disk publisher inputs."""
    import hashlib

    from evidentia_core.models.open_corpora import NativeBundle

    NativeBundle.model_validate(payload)
    directory = Path(__file__).resolve().parents[3] / (
        "packages/evidentia-core/src/evidentia_core/catalogs/data/sources/au-ism/2026.09.4"
    )
    index = json.loads((directory / "source-index.json").read_text(encoding="utf-8"))
    expected = []
    for source in index["sources"]:
        storage = source["storage"]
        if storage["kind"] == "chunks":
            raw = b"".join(
                json.loads((directory / part["path"]).read_text(encoding="utf-8"))["raw_utf8"].encode("utf-8")
                for part in storage["parts"]
            )
        else:
            raw = (directory / storage["path"]).read_bytes()
        assert len(raw) == source["binding"]["raw_bytes"]
        assert hashlib.sha256(raw).hexdigest() == source["binding"]["raw_sha256"]
        expected.append({"binding": source["binding"], "raw_utf8": raw.decode("utf-8")})
    data = payload["data"]
    assert data["catalog_id"] == "au-ism"
    assert data["profile"] == "au-ism-2026.09.4"
    assert data["documents"] == expected
    compact = json.dumps(data, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
    assert hashlib.sha256(b"evidentia.catalog-native.v1\0" + compact).hexdigest() == payload["bundle_sha256"]


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["default", "legacy"])
async def test_stdio_native_source_denial_stale_generation_and_recovery(tmp_path: Path, mode: str) -> None:
    """Carry exact native source bytes through the real public stdio child."""
    from evidentia_core.catalogs.registry import FrameworkRegistry

    selection = FrameworkRegistry().get_catalog("au-ism").native_source.bundle_sha256
    registry = _registry("get_control get_catalog_native")
    registry_path = tmp_path / "cimd.json"
    registry_path.write_text(registry.model_dump_json(), encoding="utf-8", newline="\n")
    config_path = tmp_path / "evidentia.yaml"
    config_path.write_text("{}\n", encoding="utf-8", newline="\n")
    allowed_names = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE", "LANG", "LC_ALL"}
    environment = {key: value for key, value in os.environ.items() if key.upper() in allowed_names}
    environment.update(
        {
            "EVIDENTIA_CATALOG_DIR": str(tmp_path / "catalogs"),
            "EVIDENTIA_MCP_SIGN_OUTPUTS": "",
            "EVIDENTIA_MCP_SIGNER_FACTORY": "",
            "HOME": str(tmp_path),
            "USERPROFILE": str(tmp_path),
            "APPDATA": str(tmp_path / "appdata"),
            "LOCALAPPDATA": str(tmp_path / "localappdata"),
            "HOMEDRIVE": tmp_path.drive,
            "HOMEPATH": str(tmp_path)[len(tmp_path.drive) :],
            "TEMP": str(tmp_path),
            "TMP": str(tmp_path),
            "TMPDIR": str(tmp_path),
            "PYTHONIOENCODING": "utf-8",
            "COLUMNS": "200",
        }
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "evidentia.cli.main",
            "--config",
            str(config_path),
            "mcp",
            "serve",
            "--allow-root",
            str(tmp_path),
            "--cimd-registry",
            str(registry_path),
            "--default-client-id",
            "allowed",
        ],
        cwd=tmp_path,
        env=environment,
    )
    with anyio.fail_after(180):
        async with Client(parameters, **({} if mode == "default" else {"mode": mode})) as client:
            assert len((await client.list_tools()).tools) == 15
            with pytest.raises(MCPError) as denied:
                await client.call_tool("get_catalog_native", {"extra": "unparsed"}, meta={"client_id": "denied"})
            assert denied.value.code == -32602
            stale = await client.call_tool("get_catalog_native", {"framework_id": "au-ism", "bundle_sha256": "0" * 64})
            assert stale.is_error
            assert "catalog_generation_changed" in str(stale.content)
            native = await client.call_tool(
                "get_catalog_native", {"framework_id": "au-ism", "bundle_sha256": selection}
            )
            assert not native.is_error
            _assert_native_bundle_sources(native.structured_content)
            assert len(native.content) == 1
            assert isinstance(native.content[0], TextContent)
            assert json.loads(native.content[0].text) == native.structured_content
            assert SIGNED_OUTPUT_META_KEY not in (native.meta or {})
            result = await client.call_tool(
                "get_control", {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"}
            )
            assert not result.is_error
            assert result.structured_content is not None
            assert result.structured_content["id"] == "AC-2"
            assert SIGNED_OUTPUT_META_KEY not in (result.meta or {})
            with pytest.raises(MCPError) as raised:
                await client.call_tool("list_frameworks", {})
            assert raised.value.code == -32602
