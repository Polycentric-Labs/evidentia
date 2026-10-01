"""Per-request local HTTP transport without provider routing or metadata calls.

Clients remain owned by a single call or stream. Environment proxies and
redirects are disabled, and cancellation waits for transport cleanup.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator, Generator
from typing import Any
from urllib.parse import urlsplit

import httpx
from evidentia_core.network_guard import OfflineViolationError, is_loopback_or_private


def _validated_url(url: str) -> str:
    try:
        parts = urlsplit(url)
        allowed = (
            parts.scheme in {"http", "https"}
            and is_loopback_or_private(parts.hostname or "")
            and parts.username is None
            and parts.password is None
            and not parts.query
            and not parts.fragment
            and "\\" not in url
            and not any(char.isspace() or ord(char) < 32 for char in url)
        )
        _ = parts.port
    except (TypeError, ValueError):
        allowed = False
    if not allowed:
        raise OfflineViolationError(
            subsystem="evidentia_ai",
            target="unsupported offline endpoint",
            remediation="Configure an absolute HTTP endpoint on a local or private address.",
        )
    return url


def _object(raw: str) -> dict[str, Any]:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("The local model returned a non-object response.")
    return value


def _client(timeout: float | httpx.Timeout | None) -> httpx.Client:
    return httpx.Client(timeout=timeout, trust_env=False, follow_redirects=False)


class _AsyncClient(httpx.AsyncClient):
    """Complete transport closure before propagating repeated cancellation."""

    def __init__(self, timeout: float | httpx.Timeout | None) -> None:
        super().__init__(timeout=timeout, trust_env=False, follow_redirects=False)
        self._close_task: asyncio.Task[None] | None = None

    async def aclose(self) -> None:
        if self._close_task is None:
            self._close_task = asyncio.create_task(super().aclose())
        interrupted = False
        while not self._close_task.done():
            try:
                await asyncio.shield(self._close_task)
            except asyncio.CancelledError:
                interrupted = True
        self._close_task.result()
        if interrupted:
            raise asyncio.CancelledError


def post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float | httpx.Timeout | None = 600.0,
) -> dict[str, Any]:
    """Send one local JSON request and close its owned client on every outcome."""
    destination = _validated_url(url)
    client = _client(timeout)
    try:
        response = client.post(destination, json=payload, headers=headers)
        response.raise_for_status()
        return _object(response.text)
    finally:
        client.close()


async def apost_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float | httpx.Timeout | None = 600.0,
) -> dict[str, Any]:
    """Async JSON request with cancellation-safe transport cleanup."""
    destination = _validated_url(url)
    client = _AsyncClient(timeout)
    try:
        response = await client.post(destination, json=payload, headers=headers)
        response.raise_for_status()
        return _object(response.text)
    finally:
        await client.aclose()


class _Frames:
    """Decode Ollama NDJSON or OpenAI-compatible SSE data frames."""

    def __init__(self, sse: bool) -> None:
        self.sse = sse
        self.pending: list[str] = []
        self.done = False

    def feed(self, line: str) -> dict[str, Any] | None:
        if self.done:
            return None
        if not self.sse:
            return _object(line) if line.strip() else None
        if line.startswith("data:"):
            value = line[5:]
            self.pending.append(value[1:] if value.startswith(" ") else value)
            return None
        if line or not self.pending:
            return None
        data = "\n".join(self.pending)
        self.pending.clear()
        if data == "[DONE]":
            self.done = True
            return None
        return _object(data)


def stream_json(
    url: str,
    payload: dict[str, Any],
    *,
    sse: bool = False,
    headers: dict[str, str] | None = None,
    timeout: float | httpx.Timeout | None = 600.0,
) -> Generator[dict[str, Any], None, None]:
    """Own the client until exhaustion, error, or explicit generator close."""
    destination = _validated_url(url)
    client = _client(timeout)
    try:
        with client.stream("POST", destination, json=payload, headers=headers) as response:
            response.raise_for_status()
            frames = _Frames(sse)
            for line in response.iter_lines():
                item = frames.feed(line)
                if item is not None:
                    yield item
                if frames.done:
                    return
            if frames.pending:
                raise ValueError("The local model returned an incomplete SSE frame.")
    finally:
        client.close()


async def astream_json(
    url: str,
    payload: dict[str, Any],
    *,
    sse: bool = False,
    headers: dict[str, str] | None = None,
    timeout: float | httpx.Timeout | None = 600.0,
) -> AsyncGenerator[dict[str, Any], None]:
    """Async stream with owned transport and explicit early-close support."""
    destination = _validated_url(url)
    client = _AsyncClient(timeout)
    try:
        async with client.stream("POST", destination, json=payload, headers=headers) as response:
            response.raise_for_status()
            frames = _Frames(sse)
            async for line in response.aiter_lines():
                item = frames.feed(line)
                if item is not None:
                    yield item
                if frames.done:
                    return
            if frames.pending:
                raise ValueError("The local model returned an incomplete SSE frame.")
    finally:
        await client.aclose()
