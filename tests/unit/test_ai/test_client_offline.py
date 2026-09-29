"""Offline protocol and network-boundary checks with synthetic HTTP replies."""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from evidentia_ai import client
from evidentia_ai.exceptions import LLM_TRANSIENT_EXCEPTIONS
from evidentia_core.network_guard import OfflineViolationError, offline_mode
from pydantic import BaseModel

LOCAL = "http://127.0.0.1:11434"
REMOTE = "https://llm.example.invalid"
MESSAGES = [{"role": "user", "content": "synthetic private context"}]
MODELS = [
    "ollama/llama3.3",
    "ollama_chat/llama3.3",
    "openai/local-model",
    "vllm/local-model",
    "hosted_vllm/local-model",
    "organization/local-model",
]


class SyntheticResult(BaseModel):
    summary: str


@pytest.fixture
def probe(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"requests": [], "closed": [], "status": 200, "structured": False, "fail_first": False}
    for name in (
        "OLLAMA_API_BASE",
        "OPENAI_API_BASE",
        "OPENAI_BASE_URL",
        "HOSTED_VLLM_API_BASE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.setenv(name, REMOTE)
    monkeypatch.setattr(client.litellm, "api_base", None)
    monkeypatch.setattr(client.litellm, "model_alias_map", {})
    monkeypatch.setattr(
        client.litellm, "completion", MagicMock(side_effect=AssertionError("Offline call entered provider routing"))
    )
    monkeypatch.setattr(
        client.litellm, "acompletion", AsyncMock(side_effect=AssertionError("Offline call entered provider routing"))
    )
    monkeypatch.setattr(
        client.litellm, "get_model_info", MagicMock(side_effect=AssertionError("Offline metadata lookup"))
    )

    def respond(owned: Any, request: httpx.Request) -> httpx.Response:
        assert request.url.host == "127.0.0.1", "Unexpected endpoint or followed redirect"
        assert getattr(owned._pool, "_proxy_url", None) is None, "An ambient proxy was selected"
        body = json.loads(request.content)
        state["requests"].append({"url": str(request.url), "body": body})
        if state["fail_first"] and len(state["requests"]) == 1:
            raise httpx.ConnectError("synthetic retry", request=request)
        native = request.url.path.endswith("/api/chat")
        legacy = request.url.path.endswith("/completions") and not request.url.path.endswith("/chat/completions")
        tools = body.get("tools") or []
        message: dict[str, Any] = {"role": "assistant", "content": "synthetic result"}
        if state["structured"]:
            assert tools, "Instructor schema was lost"
            message = {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "synthetic-call",
                        "type": "function",
                        "function": {
                            "name": tools[0]["function"]["name"],
                            "arguments": {"summary": "validated result"}
                            if native
                            else json.dumps({"summary": "validated result"}),
                        },
                    }
                ],
            }
        if native and "native_tool_calls" in state:
            message = {"role": "assistant", "content": "", "tool_calls": state["native_tool_calls"]}
        if native:
            raw = {"model": body["model"], "message": message, "done": True, "prompt_eval_count": 2, "eval_count": 3}
        else:
            raw = {
                "id": "synthetic",
                "object": "chat.completion",
                "created": 1,
                "model": body["model"],
                "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if tools else "stop"}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 3, "total_tokens": 5},
            }
            if legacy:
                raw["object"] = "text_completion"
                raw["choices"] = [{"index": 0, "text": "synthetic result", "finish_reason": "stop"}]
        if body.get("stream"):
            if native and "native_frames" in state:
                content = "".join(json.dumps(frame) + "\n" for frame in state["native_frames"])
            elif native:
                content = (
                    json.dumps(
                        {"model": body["model"], "message": {"role": "assistant", "content": "part"}, "done": False}
                    )
                    + "\n"
                    + json.dumps(raw)
                    + "\n"
                )
            else:
                first = {
                    "id": "synthetic",
                    "object": "chat.completion.chunk",
                    "created": 1,
                    "model": body["model"],
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": "part"}, "finish_reason": None}],
                }
                last = {**first, "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}
                if legacy:
                    first["choices"] = [{"index": 0, "text": "part", "finish_reason": None}]
                    last["choices"] = [{"index": 0, "text": "", "finish_reason": "stop"}]
                content = "data: " + json.dumps(first) + "\n\ndata: " + json.dumps(last) + "\n\ndata: [DONE]\n\n"
            return httpx.Response(state["status"], text=content, request=request, headers={"Location": REMOTE})
        return httpx.Response(state["status"], json=raw, request=request, headers={"Location": REMOTE})

    async def arespond(owned: Any, request: httpx.Request) -> httpx.Response:
        return respond(owned, request)

    original_close, original_aclose = httpx.Client.close, httpx.AsyncClient.aclose

    def close(owned: httpx.Client) -> None:
        original_close(owned)
        state["closed"].append(owned)

    async def aclose(owned: httpx.AsyncClient) -> None:
        await original_aclose(owned)
        state["closed"].append(owned)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", respond)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", arespond)
    monkeypatch.setattr(httpx.Client, "close", close)
    monkeypatch.setattr(httpx.AsyncClient, "aclose", aclose)
    return state


async def invoke(mode: str, **kwargs: Any) -> Any:
    if mode == "sync":
        return client._guarded_completion(**kwargs)
    return await client._guarded_acompletion(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("model", MODELS)
async def test_local_completion_has_one_owned_request(mode: str, model: str, probe: dict[str, Any]) -> None:
    with offline_mode():
        result = await invoke(mode, model=model, api_base=LOCAL, messages=MESSAGES, temperature=0.2)
    assert result.choices[0].message.content == "synthetic result"
    assert result.usage.total_tokens == 5
    assert len(probe["requests"]) == len(probe["closed"]) == 1
    assert all(owned.is_closed and not owned.trust_env and not owned.follow_redirects for owned in probe["closed"])
    assert probe["requests"][0]["body"]["messages"] == MESSAGES
    client.litellm.get_model_info.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("model", MODELS)
async def test_real_instructor_schema_and_parsing(mode: str, model: str, probe: dict[str, Any]) -> None:
    probe["structured"] = True
    client.get_instructor_client.cache_clear()
    client.get_async_instructor_client.cache_clear()
    options = {
        "model": model,
        "api_base": LOCAL,
        "messages": MESSAGES,
        "response_model": SyntheticResult,
        "max_retries": 1,
    }
    with offline_mode():
        if mode == "sync":
            result = client.get_instructor_client().chat.completions.create(**options)
        else:
            result = await client.get_async_instructor_client().chat.completions.create(**options)
    assert result.summary == "validated result"
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("model", MODELS)
@pytest.mark.parametrize("early_close", [False, True])
async def test_streaming_and_early_close(mode: str, model: str, early_close: bool, probe: dict[str, Any]) -> None:
    with offline_mode():
        stream = await invoke(mode, model=model, api_base=LOCAL, messages=MESSAGES, stream=True)
    assert not probe["requests"]
    if mode == "sync":
        assert next(stream).choices[0].delta.content == "part"
        if early_close:
            stream.close()
        else:
            assert list(stream)[-1].choices[0].finish_reason == "stop"
    else:
        assert (await anext(stream)).choices[0].delta.content == "part"
        if early_close:
            await stream.aclose()
        else:
            assert [item async for item in stream][-1].choices[0].finish_reason == "stop"
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("status", [307, 308, 401, 500])
async def test_redirects_and_errors_close_without_forwarding(mode: str, status: int, probe: dict[str, Any]) -> None:
    probe["status"] = status
    expected = (
        OfflineViolationError
        if status in {307, 308}
        else (client.litellm.AuthenticationError if status == 401 else client.litellm.InternalServerError)
    )
    with offline_mode(), pytest.raises(expected):
        await invoke(mode, model="ollama/llama3.3", api_base=LOCAL, messages=MESSAGES)
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_explicit_retry_uses_fresh_closed_clients(mode: str, probe: dict[str, Any]) -> None:
    probe["fail_first"] = True
    with offline_mode():
        result = await invoke(mode, model="openai/local", api_base=LOCAL, messages=MESSAGES, num_retries=1)
    assert result.choices[0].message.content == "synthetic result"
    assert len(probe["requests"]) == len(probe["closed"]) == 2
    assert probe["closed"][0] is not probe["closed"][1]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize(
    "options",
    [
        {"api_base": REMOTE},
        {"api_base": "http://user@127.0.0.1"},
        {"api_base": LOCAL, "base_url": REMOTE},
        {"api_base": LOCAL, "fallbacks": ["openai/cloud"]},
        {"api_base": LOCAL, "client": object()},
        {"api_base": LOCAL, "tools": [{"type": "web_search"}]},
        {
            "api_base": LOCAL,
            "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": REMOTE}}]}],
        },
        {"api_base": LOCAL, "stream": "false"},
        {"api_base": LOCAL, "num_retries": -1},
    ],
)
async def test_unsafe_configuration_never_reaches_http(
    mode: str, options: dict[str, Any], probe: dict[str, Any]
) -> None:
    with offline_mode(), pytest.raises(OfflineViolationError):
        await invoke(mode, **{"model": "ollama_chat/llama3.3", "messages": MESSAGES, **options})
    assert not probe["requests"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_online_still_uses_original_litellm_sink(mode: str, monkeypatch: pytest.MonkeyPatch) -> None:
    sink = MagicMock(return_value="online") if mode == "sync" else AsyncMock(return_value="online")
    monkeypatch.setattr(client.litellm, "completion" if mode == "sync" else "acompletion", sink)
    options = {"model": "gpt-4o", "messages": MESSAGES, "custom_extension": "unchanged"}
    with offline_mode(False):
        assert await invoke(mode, **options) == "online"
    sink.assert_called_once_with(**options)


@pytest.mark.asyncio
async def test_concurrent_requests_keep_distinct_models_and_endpoints(probe: dict[str, Any]) -> None:
    with offline_mode():
        results = await asyncio.gather(
            *[
                client._guarded_acompletion(
                    model="openai/model-" + str(index), api_base=LOCAL + "/server-" + str(index), messages=MESSAGES
                )
                for index in range(3)
            ]
        )
    assert [result.model for result in results] == ["model-0", "model-1", "model-2"]
    assert {row["url"] for row in probe["requests"]} == {
        LOCAL + "/server-" + str(index) + "/chat/completions" for index in range(3)
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("streaming", [False, True])
async def test_legacy_text_protocol(mode: str, streaming: bool, probe: dict[str, Any]) -> None:
    with offline_mode():
        result = await invoke(
            mode, model="text-completion-openai/local", api_base=LOCAL + "/v1", messages=MESSAGES, stream=streaming
        )
    if streaming:
        chunks = list(result) if mode == "sync" else [chunk async for chunk in result]
        assert chunks[0].choices[0].delta.content == "part"
    else:
        assert result.choices[0].message.content == "synthetic result"
    assert probe["requests"][0]["url"] == LOCAL + "/v1/completions"
    assert probe["requests"][0]["body"]["prompt"] == MESSAGES[0]["content"]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_stream_retry_only_before_first_chunk(mode: str, probe: dict[str, Any]) -> None:
    probe["fail_first"] = True
    with offline_mode():
        stream = await invoke(mode, model="openai/local", api_base=LOCAL, messages=MESSAGES, stream=True, num_retries=1)
    chunks = list(stream) if mode == "sync" else [chunk async for chunk in stream]
    assert chunks[0].choices[0].delta.content == "part"
    assert len(probe["requests"]) == len(probe["closed"]) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize(
    "model,variable",
    [
        ("ollama/local", "OLLAMA_API_BASE"),
        ("openai/local", "OPENAI_API_BASE"),
        ("hosted_vllm/local", "HOSTED_VLLM_API_BASE"),
    ],
)
async def test_provider_endpoint_environment(
    mode: str, model: str, variable: str, probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    with offline_mode(), pytest.raises(OfflineViolationError):
        await invoke(mode, model=model, messages=MESSAGES)
    assert not probe["requests"]
    monkeypatch.setenv(variable, LOCAL)
    with offline_mode():
        assert (await invoke(mode, model=model, messages=MESSAGES)).choices[0].message.content == "synthetic result"
    assert len(probe["requests"]) == 1


@pytest.mark.asyncio
async def test_completion_cancellation_waits_for_cleanup(
    probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, closing, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
    original_close = httpx.AsyncHTTPTransport.aclose

    async def wait_for_cancel(owned: Any, request: httpx.Request) -> httpx.Response:
        entered.set()
        await asyncio.Event().wait()
        raise AssertionError("Unreachable request completion")

    async def delayed_close(owned: Any) -> None:
        closing.set()
        await release.wait()
        await original_close(owned)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", wait_for_cancel)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "aclose", delayed_close)
    with offline_mode():
        task = asyncio.create_task(client._guarded_acompletion(model="ollama/local", api_base=LOCAL, messages=MESSAGES))
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        await asyncio.wait_for(closing.wait(), 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_stream_is_not_replayed_after_a_chunk(
    mode: str, probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    first = (
        b'data: {"id":"synthetic","object":"chat.completion.chunk","created":1,"model":"local",'
        b'"choices":[{"index":0,"delta":{"content":"part"},"finish_reason":null}]}\n\n'
    )

    class BrokenStream(httpx.SyncByteStream, httpx.AsyncByteStream):
        def __iter__(self):
            yield first
            raise httpx.ReadError("synthetic mid-stream failure")

        async def __aiter__(self):
            yield first
            raise httpx.ReadError("synthetic mid-stream failure")

    def respond(owned: Any, request: httpx.Request) -> httpx.Response:
        probe["requests"].append({"url": str(request.url)})
        return httpx.Response(200, stream=BrokenStream(), request=request)

    async def arespond(owned: Any, request: httpx.Request) -> httpx.Response:
        return respond(owned, request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", respond)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", arespond)
    with offline_mode():
        stream = await invoke(mode, model="openai/local", api_base=LOCAL, messages=MESSAGES, stream=True, num_retries=2)
    if mode == "sync":
        assert next(stream).choices[0].delta.content == "part"
        with pytest.raises(client.litellm.APIConnectionError):
            next(stream)
    else:
        assert (await anext(stream)).choices[0].delta.content == "part"
        with pytest.raises(client.litellm.APIConnectionError):
            await anext(stream)
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize(
    "status,transient",
    [
        (400, False),
        (401, False),
        (403, False),
        (404, False),
        (408, True),
        (429, True),
        (500, True),
        (502, True),
        (503, True),
        (504, True),
    ],
)
async def test_error_contract_preserves_transient_classification(
    mode: str, status: int, transient: bool, probe: dict[str, Any]
) -> None:
    probe["status"] = status
    with offline_mode(), pytest.raises(Exception) as caught:
        await invoke(mode, model="openai/local", api_base=LOCAL, messages=MESSAGES)
    assert isinstance(caught.value, LLM_TRANSIENT_EXCEPTIONS) is transient
    assert isinstance(caught.value.__cause__, httpx.HTTPStatusError)
    assert "synthetic private context" not in str(caught.value)
    assert len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("provider,variable", [("ollama_chat", "OLLAMA_API_KEY"), ("openai", "OPENAI_API_KEY")])
async def test_selected_provider_credentials_are_not_crossed(
    mode: str, provider: str, variable: str, probe: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OLLAMA_API_KEY", "synthetic-ollama-value")
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-openai-value")
    expected = "Bearer synthetic-ollama-value" if variable == "OLLAMA_API_KEY" else "Bearer synthetic-openai-value"
    original_sync = httpx.HTTPTransport.handle_request
    original_async = httpx.AsyncHTTPTransport.handle_async_request

    def respond(owned: Any, request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == expected
        return original_sync(owned, request)

    async def arespond(owned: Any, request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == expected
        return await original_async(owned, request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", respond)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", arespond)
    with offline_mode():
        await invoke(mode, model=provider + "/local", api_base=LOCAL, messages=MESSAGES)
    assert len(probe["requests"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("indexed", [False, True])
@pytest.mark.parametrize("separate_frames", [False, True])
@pytest.mark.parametrize("done_reason", ["stop", "length"])
async def test_native_stream_keeps_distinct_tool_calls(
    mode: str, indexed: bool, separate_frames: bool, done_reason: str, probe: dict[str, Any]
) -> None:
    calls = [
        {"function": {"name": name, "arguments": {"value": index}}}
        for index, name in enumerate(("first", "second"))
    ]
    if indexed:
        for index, call in enumerate(calls):
            call["function"]["index"] = index
    groups = [[call] for call in calls] if separate_frames else [calls]
    probe["native_frames"] = [
        {"message": {"role": "assistant", "content": "", "tool_calls": group}, "done": False}
        for group in groups
    ] + [{"message": {"content": ""}, "done": True, "done_reason": done_reason}]
    with offline_mode():
        stream = await invoke(mode, model="ollama/local", api_base=LOCAL, messages=MESSAGES, stream=True)
    chunks = list(stream) if mode == "sync" else [chunk async for chunk in stream]
    converted = [call for chunk in chunks for call in chunk.choices[0].delta.tool_calls or []]
    assert [call.index for call in converted] == [0, 1]
    assert len({call.id for call in converted}) == 2
    assert [call.function.name for call in converted] == ["first", "second"]
    assert [json.loads(call.function.arguments) for call in converted] == [{"value": 0}, {"value": 1}]
    assert all("index" not in call.function.model_dump(exclude_none=True) for call in converted)
    assert chunks[-1].choices[0].finish_reason == ("tool_calls" if done_reason == "stop" else "length")
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_native_stream_maps_sparse_indices_for_the_openai_consumer(mode: str, probe: dict[str, Any]) -> None:
    from openai.lib.streaming.chat import ChatCompletionStreamState

    probe["native_frames"] = [
        {"message": {"tool_calls": [{"function": {"index": index, "name": name, "arguments": {}}}]}, "done": False}
        for index, name in ((3, "first"), (7, "second"))
    ] + [{"message": {"content": ""}, "done": True}]
    with offline_mode():
        stream = await invoke(mode, model="ollama/local", api_base=LOCAL, messages=MESSAGES, stream=True)
    chunks = list(stream) if mode == "sync" else [chunk async for chunk in stream]
    calls = [chunk.choices[0].delta.tool_calls[0] for chunk in chunks[:-1]]
    assert [call.index for call in calls] == [0, 1]
    assert calls[0].id != calls[1].id
    assert chunks[-1].choices[0].finish_reason == "tool_calls"
    consumer = ChatCompletionStreamState()
    for chunk in chunks:
        list(consumer.handle_chunk(chunk))
    completed = consumer.get_final_completion().choices[0].message.tool_calls
    assert [call.function.name for call in completed] == ["first", "second"]
    assert [json.loads(call.function.arguments) for call in completed] == [{}, {}]
    assert [call.id for call in completed] == [call.id for call in calls]


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_native_stream_refuses_repeated_snapshots_without_replay(mode: str, probe: dict[str, Any]) -> None:
    probe["native_frames"] = [
        {"message": {"tool_calls": [{"function": {"index": 3, "name": "first", "arguments": {}}}]}, "done": False}
        for _ in range(2)
    ]
    with offline_mode():
        stream = await invoke(mode, model="ollama/local", api_base=LOCAL, messages=MESSAGES, stream=True, num_retries=2)
    first = next(stream) if mode == "sync" else await anext(stream)
    assert first.choices[0].delta.tool_calls[0].index == 0
    with pytest.raises(ValueError, match="Repeated native tool-call snapshots"):
        if mode == "sync":
            next(stream)
        else:
            await anext(stream)
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_native_nonstream_keeps_full_calls_with_repeated_index_metadata(mode: str, probe: dict[str, Any]) -> None:
    probe["native_tool_calls"] = [
        {"function": {"index": 0, "name": name, "arguments": {"value": name}}}
        for name in ("first", "second")
    ]
    with offline_mode():
        result = await invoke(mode, model="ollama/local", api_base=LOCAL, messages=MESSAGES)
    calls = result.choices[0].message.tool_calls
    assert [call.function.name for call in calls] == ["first", "second"]
    assert [json.loads(call.function.arguments) for call in calls] == [{"value": "first"}, {"value": "second"}]
    assert len({call.id for call in calls}) == 2
    assert all("index" not in call.model_dump(exclude_none=True) for call in calls)
    assert result.choices[0].finish_reason == "tool_calls"
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("invalid", [-1, True, "0", 1.5])
async def test_native_stream_rejects_invalid_indices(mode: str, invalid: Any, probe: dict[str, Any]) -> None:
    probe["native_frames"] = [
        {"message": {"tool_calls": [{"function": {"index": invalid, "name": "first", "arguments": {}}}]}}
    ]
    with offline_mode():
        stream = await invoke(mode, model="ollama/local", api_base=LOCAL, messages=MESSAGES, stream=True, num_retries=2)
    with pytest.raises(ValueError, match="invalid tool-call index"):
        if mode == "sync":
            list(stream)
        else:
            _ = [chunk async for chunk in stream]
    assert len(probe["requests"]) == len(probe["closed"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_native_stream_state_is_scoped_to_one_request(mode: str, probe: dict[str, Any]) -> None:
    probe["native_frames"] = [
        {"message": {"tool_calls": [{"function": {"name": "first", "arguments": {}}}]}, "done": False},
        {"message": {"content": ""}, "done": True},
    ]
    streams = []
    with offline_mode():
        for _ in range(2):
            streams.append(await invoke(mode, model="ollama/local", api_base=LOCAL, messages=MESSAGES, stream=True))
    first = [next(stream) if mode == "sync" else await anext(stream) for stream in streams]
    calls = [chunk.choices[0].delta.tool_calls[0] for chunk in first]
    assert [call.index for call in calls] == [0, 0]
    assert calls[0].id != calls[1].id
    for stream in streams:
        if mode == "sync":
            stream.close()
        else:
            await stream.aclose()
    assert len(probe["requests"]) == len(probe["closed"]) == 2
