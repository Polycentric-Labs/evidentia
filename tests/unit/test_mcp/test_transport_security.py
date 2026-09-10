"""Exercise production HTTP and SSE configuration without opening a listener."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs, urlsplit

import anyio
import httpx
import pytest
from anyio.streams.memory import MemoryObjectReceiveStream
from evidentia_mcp import server as server_module
from evidentia_mcp.cimd import CIMDDocument, CIMDRegistry
from evidentia_mcp.cli import app as cli_app
from evidentia_mcp.server import EvidentiaMCPServer
from starlette.applications import Starlette
from starlette.types import Message, Scope
from typer.testing import CliRunner

Transport = Literal["sse", "http"]
PROTOCOL_VERSION = "2025-11-25"
BASE_URL = "http://127.0.0.1:8765"
BODY_LIMIT = 4 * 1024 * 1024
HEADERS = {
    "Accept": "application/json, text/event-stream",
    "Content-Type": "application/json",
}


@dataclass
class ProductionApp:
    server: EvidentiaMCPServer
    app: Starlette
    options: dict[str, Any]


def _production_app(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    transport: Transport,
    *,
    host: str = "127.0.0.1",
) -> ProductionApp:
    """Build the ASGI app from the exact arguments sent by the public runner."""
    captures: list[ProductionApp] = []

    def capture_run(server: EvidentiaMCPServer, transport: str, **kwargs: Any) -> None:
        options = dict(kwargs)
        app_options = dict(kwargs)
        assert app_options.pop("port") == 8765
        if transport == "sse":
            app = server.sse_app(**app_options)
        else:
            assert transport == "streamable-http"
            app = server.streamable_http_app(**app_options)
        captures.append(ProductionApp(server, app, options))

    monkeypatch.setattr(EvidentiaMCPServer, "run", capture_run)
    runner = server_module.run_sse if transport == "sse" else server_module.run_http
    runner(host=host, port=8765, allow_root=tmp_path)
    assert len(captures) == 1
    return captures[0]


def _rpc(request_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def _initialize_message() -> dict[str, Any]:
    return _rpc(
        1,
        "initialize",
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "synthetic-transport-test", "version": "1"},
        },
    )


def _response_json(response: httpx.Response) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    if response.headers["content-type"].startswith("application/json"):
        value = response.json()
    else:
        assert response.headers["content-type"].startswith("text/event-stream")
        data_lines = [line.removeprefix("data: ") for line in response.text.splitlines() if line.startswith("data: ")]
        assert len(data_lines) == 1
        value = json.loads(data_lines[0])
    assert isinstance(value, dict)
    return value


async def _initialize_http(client: httpx.AsyncClient) -> dict[str, str]:
    response = await client.post("/mcp", json=_initialize_message())
    result = _response_json(response)
    assert result["result"]["serverInfo"]["name"] == "evidentia"
    assert result["result"]["protocolVersion"] == PROTOCOL_VERSION
    session = response.headers["mcp-session-id"]
    assert session
    headers = {"Mcp-Session-Id": session, "MCP-Protocol-Version": PROTOCOL_VERSION}
    notification = await client.post(
        "/mcp", headers=headers, json={"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    assert notification.status_code == 202
    return headers


@dataclass
class SSEStream:
    messages: MemoryObjectReceiveStream[Message]
    buffer: bytes = b""
    pending: list[tuple[str, str]] = field(default_factory=list)

    async def next_event(self) -> tuple[str, str]:
        """Read real ASGI response frames, including split SSE records."""
        while not self.pending:
            message = await self.messages.receive()
            assert message["type"] == "http.response.body"
            self.buffer += message.get("body", b"").replace(b"\r\n", b"\n")
            while b"\n\n" in self.buffer:
                record, self.buffer = self.buffer.split(b"\n\n", 1)
                event = "message"
                data: list[str] = []
                for line in record.decode("utf-8").split("\n"):
                    if line.startswith("event: "):
                        event = line.removeprefix("event: ")
                    elif line.startswith("data: "):
                        data.append(line.removeprefix("data: "))
                if data:
                    self.pending.append((event, "\n".join(data)))
        return self.pending.pop(0)

    async def next_json(self) -> dict[str, Any]:
        event, data = await self.next_event()
        assert event == "message"
        value = json.loads(data)
        assert isinstance(value, dict)
        return value


@asynccontextmanager
async def _sse_stream(app: Starlette, origin: str | None = None) -> AsyncIterator[SSEStream]:
    """Keep the advertised SSE session alive while POST requests use its route."""
    outgoing, incoming = anyio.create_memory_object_stream[Message](16)
    disconnect = anyio.Event()
    sent_request = False
    headers = [(b"host", b"127.0.0.1:8765"), (b"accept", b"text/event-stream")]
    if origin is not None:
        headers.append((b"origin", origin.encode("ascii")))
    scope: Scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/sse",
        "raw_path": b"/sse",
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 54321),
        "server": ("127.0.0.1", 8765),
    }

    async def receive() -> Message:
        nonlocal sent_request
        if not sent_request:
            sent_request = True
            return {"type": "http.request", "body": b"", "more_body": False}
        await disconnect.wait()
        return {"type": "http.disconnect"}

    async def send(message: Message) -> None:
        await outgoing.send(message)

    async with outgoing, incoming, anyio.create_task_group() as tasks:
        tasks.start_soon(app, scope, receive, send)
        try:
            response = await incoming.receive()
            assert response["type"] == "http.response.start"
            assert response["status"] == 200
            yield SSEStream(incoming)
        finally:
            disconnect.set()
            tasks.cancel_scope.cancel()


async def _initialize_sse(client: httpx.AsyncClient, stream: SSEStream) -> str:
    event, endpoint = await stream.next_event()
    assert event == "endpoint"
    parsed = urlsplit(endpoint)
    assert parsed.path == "/messages/"
    assert not parsed.scheme and not parsed.netloc
    session_id = parse_qs(parsed.query)["session_id"]
    assert len(session_id) == 1 and len(session_id[0]) == 32
    response = await client.post(endpoint, json=_initialize_message())
    assert response.status_code == 202
    initialized = await stream.next_json()
    assert initialized["id"] == 1
    assert initialized["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert initialized["result"]["serverInfo"]["name"] == "evidentia"
    response = await client.post(endpoint, json={"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert response.status_code == 202
    return endpoint


@pytest.mark.parametrize("transport", ["sse", "http"])
def test_production_limits_and_bind_forwarding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, transport: Transport
) -> None:
    configured = _production_app(monkeypatch, tmp_path, transport)
    assert configured.options["host"] == "127.0.0.1"
    assert configured.options["port"] == 8765
    assert configured.options["max_request_body_size"] == BODY_LIMIT
    assert "transport_security" not in configured.options
    if transport == "http":
        assert configured.options["stateless_http"] is False
        assert configured.options["session_idle_timeout"] == 1800
        assert configured.options["max_sessions"] == 10_000
    alternate = _production_app(monkeypatch, tmp_path, transport, host="0.0.0.0")
    assert alternate.options["host"] == "0.0.0.0"
    assert alternate.options["max_request_body_size"] == BODY_LIMIT


@pytest.mark.parametrize("transport", ["stdio", "sse", "http"])
@pytest.mark.parametrize("explicit", [False, True])
def test_cli_transport_options_reach_server(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, transport: str, explicit: bool
) -> None:
    calls: list[tuple[EvidentiaMCPServer, str, dict[str, Any]]] = []
    builds: list[tuple[Path | None, CIMDRegistry | None, str | None]] = []
    original_build = server_module.build_server

    def capture_build(
        *,
        allow_root: Path | None = None,
        cimd_registry: CIMDRegistry | None = None,
        default_client_id: str | None = None,
    ) -> EvidentiaMCPServer:
        builds.append((allow_root, cimd_registry, default_client_id))
        return original_build(allow_root=allow_root, cimd_registry=cimd_registry, default_client_id=default_client_id)

    monkeypatch.setattr(server_module, "build_server", capture_build)

    def capture(server: EvidentiaMCPServer, transport: str, **kwargs: Any) -> None:
        calls.append((server, transport, kwargs))

    monkeypatch.setattr(EvidentiaMCPServer, "run", capture)
    args = ["serve", "--transport", transport]
    if explicit:
        registry = CIMDRegistry(
            clients={"synthetic": CIMDDocument(client_id="synthetic", client_name="Synthetic", scope="get_control")}
        )
        registry_path = tmp_path / "registry.json"
        registry_path.write_text(registry.model_dump_json(), encoding="utf-8", newline="\n")
        args.extend(
            [
                "--host",
                "0.0.0.0",
                "--port",
                "9876",
                "--allow-root",
                str(tmp_path),
                "--cimd-registry",
                str(registry_path),
                "--default-client-id",
                "synthetic",
            ]
        )
        if transport != "stdio":
            args.append("--no-stdio")
    result = CliRunner().invoke(cli_app, args)
    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    server, selected, options = calls[0]
    assert len(builds) == 1
    allowed_root, configured_registry, default_client = builds[0]
    assert allowed_root == (tmp_path if explicit else None)
    assert configured_registry is server.evidentia_cimd
    assert default_client == ("synthetic" if explicit else None)
    assert selected == {"stdio": "stdio", "sse": "sse", "http": "streamable-http"}[transport]
    if transport == "stdio":
        assert options == {}
    else:
        assert options["host"] == ("0.0.0.0" if explicit else "127.0.0.1")
        assert options["port"] == (9876 if explicit else 8765)
    if explicit:
        assert server.evidentia_cimd is not None
        client = server.evidentia_cimd.get("synthetic")
        assert client is not None
        assert client.scope == "get_control"
    else:
        assert server.evidentia_cimd is None


@pytest.mark.anyio
@pytest.mark.parametrize("origin", [None, BASE_URL])
async def test_http_initialization_and_tool_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, origin: str | None
) -> None:
    configured = _production_app(monkeypatch, tmp_path, "http")
    headers = dict(HEADERS)
    if origin is not None:
        headers["Origin"] = origin
    with anyio.fail_after(20):
        async with configured.app.router.lifespan_context(configured.app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=configured.app), base_url=BASE_URL, headers=headers
            ) as client:
                session_headers = await _initialize_http(client)
                response = await client.post(
                    "/mcp",
                    headers=session_headers,
                    json=_rpc(
                        2,
                        "tools/call",
                        {
                            "name": "get_control",
                            "arguments": {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"},
                        },
                    ),
                )
                result = _response_json(response)
                assert result["id"] == 2
                assert not result["result"].get("isError", False)
                assert result["result"]["structuredContent"]["id"] == "AC-2"
                listing = _response_json(await client.post("/mcp", headers=session_headers, json=_rpc(3, "tools/list")))
                assert len(listing["result"]["tools"]) == 14
                closed = await client.delete("/mcp", headers=session_headers)
                assert closed.status_code == 200


@pytest.mark.anyio
@pytest.mark.parametrize("origin", [None, BASE_URL])
async def test_sse_advertised_route_initialization_and_tool_call(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, origin: str | None
) -> None:
    configured = _production_app(monkeypatch, tmp_path, "sse")
    headers = dict(HEADERS)
    if origin is not None:
        headers["Origin"] = origin
    with anyio.fail_after(20):
        async with configured.app.router.lifespan_context(configured.app):
            async with (
                httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=configured.app), base_url=BASE_URL, headers=headers
                ) as client,
                _sse_stream(configured.app, origin) as stream,
            ):
                endpoint = await _initialize_sse(client, stream)
                response = await client.post(
                    endpoint,
                    json=_rpc(
                        2,
                        "tools/call",
                        {
                            "name": "get_control",
                            "arguments": {"framework_id": "nist-800-53-rev5-moderate", "control_id": "AC-2"},
                        },
                    ),
                )
                assert response.status_code == 202
                result = await stream.next_json()
                assert result["id"] == 2
                assert not result["result"].get("isError", False)
                assert result["result"]["structuredContent"]["id"] == "AC-2"
                response = await client.post(endpoint, json=_rpc(3, "tools/list"))
                assert response.status_code == 202
                assert len((await stream.next_json())["result"]["tools"]) == 14
                wrong_session = endpoint.split("?", 1)[0] + "?session_id=" + "0" * 32
                response = await client.post(wrong_session, json=_rpc(4, "tools/list"))
                assert response.status_code == 404
                response = await client.get(endpoint)
                assert response.status_code == 405


@pytest.mark.anyio
@pytest.mark.parametrize("transport", ["sse", "http"])
@pytest.mark.parametrize(
    ("extra_headers", "expected"),
    [
        ({"Host": "attacker.example:8765"}, 421),
        ({"Origin": "https://attacker.example"}, 403),
        ({"Content-Type": "text/plain"}, 400),
    ],
)
async def test_post_rejects_invalid_transport_headers(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    transport: Transport,
    extra_headers: dict[str, str],
    expected: int,
) -> None:
    configured = _production_app(monkeypatch, tmp_path, transport)
    headers = HEADERS | extra_headers
    path = "/messages/?session_id=" + "0" * 32 if transport == "sse" else "/mcp"
    with anyio.fail_after(20):
        async with configured.app.router.lifespan_context(configured.app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=configured.app), base_url=BASE_URL, headers=headers
            ) as client:
                response = await client.post(path, json=_initialize_message())
                assert response.status_code == expected


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("header", "value", "expected"),
    [
        ("Host", "attacker.example:8765", 421),
        ("Origin", "https://attacker.example", 403),
    ],
)
async def test_sse_connection_rejects_invalid_host_and_origin(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    header: str,
    value: str,
    expected: int,
) -> None:
    configured = _production_app(monkeypatch, tmp_path, "sse")
    with anyio.fail_after(20):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=configured.app, raise_app_exceptions=False),
            base_url=BASE_URL,
            headers={header: value},
        ) as client:
            response = await client.get("/sse")
    assert response.status_code == expected


async def _chunks(body: bytes) -> AsyncIterator[bytes]:
    for start in range(0, len(body), 128 * 1024):
        yield body[start : start + 128 * 1024]


@pytest.mark.anyio
@pytest.mark.parametrize("transport", ["sse", "http"])
@pytest.mark.parametrize(
    ("size", "declared", "expected"),
    [
        (BODY_LIMIT, "exact", 200),
        (BODY_LIMIT, None, 200),
        (BODY_LIMIT + 1, "exact", 413),
        (BODY_LIMIT + 1, None, 413),
        (BODY_LIMIT + 1, "0", 413),
        (BODY_LIMIT + 1, "1", 413),
        (BODY_LIMIT + 1, "invalid", 413),
        (1024, str(BODY_LIMIT + 1), 413),
    ],
)
async def test_actual_body_limit_including_untrusted_lengths(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    transport: Transport,
    size: int,
    declared: str | None,
    expected: int,
) -> None:
    configured = _production_app(monkeypatch, tmp_path, transport)
    executions: list[str] = []

    @configured.server.tool()
    def body_probe() -> dict[str, bool]:
        executions.append("called")
        return {"ok": True}

    message = json.dumps(_rpc(2, "tools/call", {"name": "body_probe", "arguments": {}})).encode("utf-8")
    body = message + b" " * (size - len(message))
    assert len(body) == size
    body_headers = {} if declared is None else {"Content-Length": str(size) if declared == "exact" else declared}
    with anyio.fail_after(30):
        async with configured.app.router.lifespan_context(configured.app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=configured.app), base_url=BASE_URL, headers=HEADERS
            ) as client:
                if transport == "http":
                    session_headers = await _initialize_http(client)
                    response = await client.post("/mcp", headers=session_headers | body_headers, content=_chunks(body))
                    assert response.status_code == expected
                    if expected == 200:
                        assert _response_json(response)["result"]["structuredContent"] == {"ok": True}
                else:
                    async with _sse_stream(configured.app) as stream:
                        endpoint = await _initialize_sse(client, stream)
                        response = await client.post(endpoint, headers=body_headers, content=_chunks(body))
                        assert response.status_code == (202 if expected == 200 else expected)
                        if expected == 200:
                            assert (await stream.next_json())["result"]["structuredContent"] == {"ok": True}
    assert executions == (["called"] if expected == 200 else [])
