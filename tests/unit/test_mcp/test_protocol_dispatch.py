"""Exercise published tools through the SDK's normal connected protocol client."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest
from evidentia_mcp.server import build_server
from mcp.shared.memory import create_connected_server_and_client_session


@pytest.mark.anyio
async def test_frozen_tool_contracts(tmp_path: Path) -> None:
    """Compare the server listing with the independently captured v1 wire contract."""
    fixture = Path(__file__).parent / "fixtures" / "tool-contracts-v1.json"
    oracle = json.loads(fixture.read_text(encoding="utf-8"))
    assert oracle["sdk_version"] == "1.29.1"
    server = build_server(allow_root=tmp_path)
    with anyio.fail_after(20):
        async with create_connected_server_and_client_session(server) as client:
            listing = await client.list_tools()
    contracts = []
    for tool in listing.tools:
        wire = tool.model_dump(mode="json", by_alias=True)
        contracts.append({key: wire[key] for key in ("name", "description", "inputSchema", "outputSchema")})
    assert sorted(contracts, key=lambda tool: tool["name"]) == oracle["tools"]


@pytest.mark.anyio
async def test_harmless_connected_dispatch(tmp_path: Path) -> None:
    """Initialize, list frameworks and fetch a control without external state."""
    server = build_server(allow_root=tmp_path)
    with anyio.fail_after(20):
        async with create_connected_server_and_client_session(server) as client:
            frameworks = await client.call_tool("list_frameworks", {})
            control = await client.call_tool(
                "get_control",
                {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"},
            )
    assert not frameworks.isError
    assert frameworks.structuredContent is not None
    assert any(item["id"] == "nist-800-53-rev5-moderate" for item in frameworks.structuredContent["result"])
    assert not control.isError
    assert control.structuredContent is not None
    assert control.structuredContent["id"] == "AC-2"
