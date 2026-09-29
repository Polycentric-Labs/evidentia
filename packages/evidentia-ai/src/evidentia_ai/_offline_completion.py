"""Local completion protocols that do not invoke provider routing or metadata.

Ollama model prefixes use its chat protocol, including tools and streaming.
OpenAI-compatible local servers use their chat or legacy completion protocol.
The operator remains responsible for the local server's own network policy.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import Any, NoReturn

import httpx
import litellm
import litellm.exceptions as llm_errors
from evidentia_core.network_guard import OfflineViolationError
from openai.types.chat import ChatCompletion, ChatCompletionChunk

from evidentia_ai import _offline_transport as transport

_BODY_KEYS = frozenset(
    {
        "model",
        "messages",
        "temperature",
        "top_p",
        "n",
        "stream",
        "stream_options",
        "stop",
        "max_completion_tokens",
        "max_tokens",
        "presence_penalty",
        "frequency_penalty",
        "logit_bias",
        "user",
        "response_format",
        "seed",
        "tools",
        "tool_choice",
        "logprobs",
        "top_logprobs",
        "parallel_tool_calls",
        "functions",
        "function_call",
    }
)
_CONFIG_KEYS = frozenset(
    {"api_base", "base_url", "custom_llm_provider", "api_key", "timeout", "max_retries", "num_retries"}
)
_OLLAMA_OPTIONS = {
    "temperature": "temperature",
    "top_p": "top_p",
    "stop": "stop",
    "seed": "seed",
    "max_tokens": "num_predict",
    "max_completion_tokens": "num_predict",
    "frequency_penalty": "frequency_penalty",
    "presence_penalty": "presence_penalty",
}


def _refuse(reason: str) -> NoReturn:
    raise OfflineViolationError(
        subsystem="evidentia_ai",
        target="unsupported offline completion configuration",
        remediation=reason,
    )


@dataclass(frozen=True)
class _Request:
    url: str
    payload: dict[str, Any]
    headers: dict[str, str]
    timeout: float | httpx.Timeout | None
    protocol: str
    model: str
    stream: bool
    retries: int


def _prepare(args: tuple[Any, ...], kwargs: dict[str, Any]) -> _Request:
    call = kwargs.copy()
    if len(args) > 2:
        _refuse("Pass completion options by keyword.")
    for key, value in zip(("model", "messages"), args, strict=False):
        if key in call:
            _refuse("A completion argument was supplied twice.")
        call[key] = value
    if call.keys() - _BODY_KEYS - _CONFIG_KEYS:
        _refuse("Use supported completion options without routing or callback extensions.")
    model = call.get("model")
    if not isinstance(model, str) or not model:
        _refuse("Specify a local model name.")
    if model in (getattr(litellm, "model_alias_map", None) or {}):
        _refuse("Use the direct local model name instead of a LiteLLM alias.")
    prefix, separator, suffix = model.partition("/")
    known = {"ollama", "ollama_chat", "openai", "hosted_vllm", "vllm", "text-completion-openai"}
    override = call.get("custom_llm_provider")
    if separator and prefix in known:
        provider, model_name = prefix, suffix
        if override not in (None, provider):
            _refuse("The provider override differs from the model prefix.")
    elif override in (None, "openai", "hosted_vllm", "text-completion-openai"):
        # A bare or organization-qualified model ID needs an explicit local
        # OpenAI-compatible endpoint. No provider inference runs here.
        provider, model_name = override or "openai", model
    else:
        _refuse("Use an Ollama or OpenAI-compatible local server.")
    if not model_name:
        _refuse("Specify a nonempty local model name.")

    api_base, base_url = call.get("api_base"), call.get("base_url")
    if api_base is not None and base_url is not None and api_base != base_url:
        _refuse("api_base and base_url disagree.")
    explicit = base_url if base_url is not None else api_base
    global_base = getattr(litellm, "api_base", None)
    ollama = provider in {"ollama", "ollama_chat"}
    if ollama:
        if global_base and explicit is not None and global_base != explicit:
            _refuse("The global Ollama endpoint conflicts with the per-call endpoint.")
        base = global_base or (
            explicit if explicit is not None else os.environ.get("OLLAMA_API_BASE") or "http://localhost:11434"
        )
    else:
        env_base = (
            os.environ.get("HOSTED_VLLM_API_BASE")
            if provider in {"vllm", "hosted_vllm"}
            else (os.environ.get("OPENAI_API_BASE") or os.environ.get("OPENAI_BASE_URL"))
        )
        base = explicit if explicit is not None else global_base or env_base
    if not isinstance(base, str) or not base:
        _refuse("Configure an explicit local API base for this model server.")
    base = transport._validated_url(base).rstrip("/")
    stream = call.get("stream", False)
    if stream is None:
        stream = False
    if type(stream) is not bool:
        _refuse("stream must be a boolean.")
    retries = call.get("num_retries", call.get("max_retries", 0))
    if type(retries) is not int or retries < 0:
        _refuse("The retry count must be a nonnegative integer.")
    if "num_retries" in call and "max_retries" in call and call["num_retries"] != call["max_retries"]:
        _refuse("The retry counts disagree.")

    messages = call.get("messages", [])
    if not isinstance(messages, list) or any(
        not isinstance(message, dict) or not isinstance(message.get("content", ""), (str, type(None)))
        for message in messages
    ):
        _refuse("Offline completion supports text messages and function schemas.")
    tools = call.get("tools") or []
    if not isinstance(tools, list) or any(
        not isinstance(tool, dict) or tool.get("type") != "function" for tool in tools
    ):
        _refuse("Offline completion accepts function-schema tools only.")
    # Snapshot request data before returning a lazy stream. No provider callback,
    # model discovery, tokenizer download, or global client cache is consulted.
    body = json.loads(json.dumps({key: value for key, value in call.items() if key in _BODY_KEYS}))
    body.update(model=model_name, messages=messages, stream=stream)
    body = json.loads(json.dumps(body))
    protocol = "ollama" if ollama else "text" if provider == "text-completion-openai" else "chat"
    if ollama:
        body = _ollama_body(body)
        for ending in ("/api/chat", "/api/generate"):
            if base.endswith(ending):
                base = base[: -len(ending)]
        url = base + "/api/chat"
    elif protocol == "text":
        body["prompt"] = "\n".join(message.get("content") or "" for message in body.pop("messages"))
        if any(body.get(key) for key in ("tools", "tool_choice", "functions", "function_call")):
            _refuse("Function schemas require the server's chat-completion protocol.")
        url = base + "/completions"
    else:
        url = base + "/chat/completions"
    headers = {}
    api_key = call.get("api_key")
    if api_key is None:
        # Resolve only the selected provider's credential. No secret-manager
        # callback runs and the value is never included in diagnostics.
        api_key = os.environ.get("OLLAMA_API_KEY" if ollama else "OPENAI_API_KEY")
    if api_key is not None:
        if not isinstance(api_key, str) or any(ord(char) < 32 for char in api_key):
            _refuse("Supply a valid explicit local-server API key.")
        headers["Authorization"] = "Bearer " + api_key
    return _Request(url, body, headers, call.get("timeout", 600.0), protocol, model_name, stream, retries)


def _ollama_body(body: dict[str, Any]) -> dict[str, Any]:
    if body.get("n", 1) != 1 or body.get("logit_bias"):
        _refuse("This Ollama route supports one completion without logit bias.")
    result = {key: body[key] for key in ("model", "messages", "stream")}
    result["options"] = {destination: body[key] for key, destination in _OLLAMA_OPTIONS.items() if key in body}
    tools = body.get("tools") or [{"type": "function", "function": value} for value in body.get("functions", [])]
    choice = body.get("tool_choice", body.get("function_call"))
    if choice == "none":
        tools = []
    elif isinstance(choice, dict):
        name = choice.get("function", choice).get("name")
        tools = [tool for tool in tools if tool["function"].get("name") == name]
        if not tools:
            _refuse("The chosen function must be present in the supplied tools.")
    if tools:
        result["tools"] = tools
    response_format = body.get("response_format")
    if isinstance(response_format, dict):
        if response_format.get("type") == "json_object":
            result["format"] = "json"
        elif response_format.get("type") == "json_schema":
            result["format"] = response_format["json_schema"]["schema"]
    for key in ("logprobs", "top_logprobs"):
        if key in body:
            result[key] = body[key]
    for message in result["messages"]:
        for tool in message.get("tool_calls") or []:
            arguments = tool.get("function", {}).get("arguments")
            if isinstance(arguments, str):
                tool["function"]["arguments"] = json.loads(arguments)
    return result


@dataclass
class _OllamaStream:
    next_index: int = 0
    native_indices: dict[int, int] = field(default_factory=dict)
    ids: dict[int, str] = field(default_factory=dict)

    def index_for(self, native_index: Any) -> int:
        if native_index is not None:
            if type(native_index) is not int or native_index < 0:
                raise ValueError("The local model server returned an invalid tool-call index.")
            if native_index in self.native_indices:
                raise ValueError(
                    "Repeated native tool-call snapshots are not supported by this local completion route."
                )
        index = self.next_index
        self.next_index += 1
        if native_index is not None:
            self.native_indices[native_index] = index
        return index


def _converted(
    raw: dict[str, Any], request: _Request, stream_id: str, state: _OllamaStream | None = None
) -> dict[str, Any]:
    if "error" in raw:
        raise ValueError("The local model server returned an error response.")
    if request.protocol == "chat":
        return raw
    if request.protocol == "text":
        result = raw.copy()
        result["object"] = "chat.completion.chunk" if request.stream else "chat.completion"
        result["choices"] = []
        for choice in raw.get("choices", []):
            converted = {key: value for key, value in choice.items() if key != "text"}
            converted["delta" if request.stream else "message"] = {
                "role": "assistant",
                "content": choice.get("text", ""),
            }
            result["choices"].append(converted)
        return result
    message = raw.get("message", {"role": "assistant", "content": raw.get("response", "")}).copy()
    state = state if state is not None else _OllamaStream()
    calls = []
    for tool in message.pop("tool_calls", None) or []:
        function = tool["function"].copy()
        native_index = function.pop("index", None)
        index = state.index_for(native_index if request.stream else None)
        if not isinstance(function.get("arguments"), str):
            function["arguments"] = json.dumps(function.get("arguments", {}))
        entry: dict[str, Any] = {
            "id": tool.get("id") or f"{stream_id}-{index}",
            "type": "function",
            "function": function,
        }
        state.ids[index] = entry["id"]
        if request.stream:
            entry["index"] = index
        calls.append(entry)
    if calls:
        message["tool_calls"] = calls
    finish = (raw.get("done_reason") or "stop") if raw.get("done") else None
    if finish == "stop" and state.ids:
        finish = "tool_calls"
    result = {
        "id": stream_id,
        "created": int(time.time()),
        "model": raw.get("model", request.model),
        "object": "chat.completion.chunk" if request.stream else "chat.completion",
        "choices": [{"index": 0, "delta" if request.stream else "message": message, "finish_reason": finish}],
    }
    if "prompt_eval_count" in raw and "eval_count" in raw:
        prompt, completion = raw["prompt_eval_count"], raw["eval_count"]
        result["usage"] = {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        }
    return result


def _retryable(exc: Exception) -> bool:
    return isinstance(exc, httpx.TransportError) or (
        isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code in {408, 429, 500, 502, 503, 504}
    )


def _raise_failure(exc: Exception, request: _Request) -> NoReturn:
    """Preserve the existing AI subsystem's typed transient-error contract."""
    details: dict[str, Any] = {
        "message": "The local model request failed.",
        "model": request.model,
        "llm_provider": "ollama" if request.protocol == "ollama" else "openai",
    }
    mapped: Exception
    if isinstance(exc, httpx.TimeoutException):
        mapped = llm_errors.Timeout(**details)
    elif isinstance(exc, httpx.TransportError):
        mapped = llm_errors.APIConnectionError(**details)
    elif isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if 300 <= status < 400:
            _refuse("The local model endpoint returned a redirect. Configure its final local address.")
        if status == 408:
            mapped = llm_errors.Timeout(**details)
        else:
            classes: dict[int, Any] = {
                400: llm_errors.BadRequestError,
                401: llm_errors.AuthenticationError,
                403: llm_errors.PermissionDeniedError,
                404: llm_errors.NotFoundError,
                429: llm_errors.RateLimitError,
                500: llm_errors.InternalServerError,
                502: llm_errors.BadGatewayError,
                503: llm_errors.ServiceUnavailableError,
                504: llm_errors.InternalServerError,
            }
            error_type = classes.get(status)
            if error_type is None:
                mapped = llm_errors.APIError(status_code=status, **details)
            else:
                mapped = error_type(response=exc.response, **details)
    else:
        raise exc
    raise mapped from exc


def _sync_stream(request: _Request) -> Iterator[ChatCompletionChunk]:
    stream_id = "local-" + uuid.uuid4().hex
    yielded = False
    for attempt in range(request.retries + 1):
        state = _OllamaStream()
        frames = transport.stream_json(
            request.url,
            request.payload,
            sse=request.protocol != "ollama",
            headers=request.headers,
            timeout=request.timeout,
        )
        try:
            for raw in frames:
                chunk = ChatCompletionChunk.model_validate(_converted(raw, request, stream_id, state))
                yielded = True
                yield chunk
            return
        except Exception as exc:
            if yielded or attempt == request.retries or not _retryable(exc):
                _raise_failure(exc, request)
        finally:
            frames.close()


async def _async_stream(request: _Request) -> AsyncIterator[ChatCompletionChunk]:
    stream_id = "local-" + uuid.uuid4().hex
    yielded = False
    for attempt in range(request.retries + 1):
        state = _OllamaStream()
        frames = transport.astream_json(
            request.url,
            request.payload,
            sse=request.protocol != "ollama",
            headers=request.headers,
            timeout=request.timeout,
        )
        try:
            async for raw in frames:
                chunk = ChatCompletionChunk.model_validate(_converted(raw, request, stream_id, state))
                yielded = True
                yield chunk
            return
        except Exception as exc:
            if yielded or attempt == request.retries or not _retryable(exc):
                _raise_failure(exc, request)
        finally:
            await frames.aclose()


def completion(*args: Any, **kwargs: Any) -> Any:
    request = _prepare(args, kwargs)
    if request.stream:
        return _sync_stream(request)
    for attempt in range(request.retries + 1):
        try:
            raw = transport.post_json(request.url, request.payload, headers=request.headers, timeout=request.timeout)
            return ChatCompletion.model_validate(_converted(raw, request, "local-" + uuid.uuid4().hex))
        except Exception as exc:
            if attempt == request.retries or not _retryable(exc):
                _raise_failure(exc, request)
    raise AssertionError("Unreachable retry state")


async def acompletion(*args: Any, **kwargs: Any) -> Any:
    request = _prepare(args, kwargs)
    if request.stream:
        return _async_stream(request)
    for attempt in range(request.retries + 1):
        try:
            raw = await transport.apost_json(
                request.url, request.payload, headers=request.headers, timeout=request.timeout
            )
            return ChatCompletion.model_validate(_converted(raw, request, "local-" + uuid.uuid4().hex))
        except Exception as exc:
            if attempt == request.retries or not _retryable(exc):
                _raise_failure(exc, request)
    raise AssertionError("Unreachable retry state")
