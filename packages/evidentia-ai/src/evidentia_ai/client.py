"""LiteLLM + Instructor client setup.

Provides a configured Instructor client that works with any LLM provider
supported by LiteLLM. Model selection is determined by (in priority order):
1. Explicit model parameter
2. EVIDENTIA_LLM_MODEL environment variable
3. Default: "gpt-4o"

Offline calls use an owned HTTP transport for Ollama and OpenAI-compatible
local servers. They do not enter LiteLLM provider routing, metadata discovery,
callbacks or client caches. Both Ollama prefixes use its chat protocol.
A local vLLM server requires an explicit API base. Online calls retain
LiteLLM routing. The local server must enforce its own network policy.
"""

from __future__ import annotations

import getpass
import os
import socket
from functools import lru_cache
from typing import Any, cast

import instructor
import litellm
from evidentia_core.network_guard import is_offline

from evidentia_ai import _offline_completion
from evidentia_ai.config import get_default_model as get_default_model

# Suppress LiteLLM's verbose logging by default
litellm.suppress_debug_info = True


def get_temperature() -> float:
    """Get the default temperature from environment or config."""
    return float(os.environ.get("EVIDENTIA_LLM_TEMPERATURE", "0.1"))


def get_operator_identity() -> str:
    """Best-effort operator identity for AI generation provenance (v0.7.1).

    Returned string lands in :attr:`evidentia_core.audit.provenance.
    GenerationContext.credential_identity` so an auditor can answer
    "who authorized this LLM call". NEVER returns the API key itself.

    Resolution order:

    1. ``$EVIDENTIA_AI_OPERATOR`` if set \u2014 the operator-supplied label
       (e.g., ``alice@acme.com``, ``ci-runner``, ``service-account-grc``).
    2. Otherwise: ``getpass.getuser() + "@" + socket.gethostname()``
       \u2014 best-effort OS-level fallback.
    3. ``"unknown"`` if both fallbacks raise (sandboxed environments).
    """
    explicit = os.environ.get("EVIDENTIA_AI_OPERATOR")
    if explicit:
        return explicit
    try:
        return f"{getpass.getuser()}@{socket.gethostname()}"
    except Exception:
        return "unknown"


def _guarded_completion(*args: Any, **kwargs: Any) -> Any:
    """Sync wrapper around ``litellm.completion`` that enforces offline mode."""
    if is_offline():
        return _offline_completion.completion(*args, **kwargs)
    return litellm.completion(*args, **kwargs)


async def _guarded_acompletion(*args: Any, **kwargs: Any) -> Any:
    """Async wrapper around ``litellm.acompletion`` that enforces offline mode."""
    if is_offline():
        return await _offline_completion.acompletion(*args, **kwargs)
    return await litellm.acompletion(*args, **kwargs)


@lru_cache(maxsize=1)
def get_instructor_client() -> instructor.Instructor:
    """Get a configured Instructor client.

    Uses `instructor.from_litellm` with a guarded completion wrapper so
    air-gapped mode stops cloud LLM calls before they leave the process.
    """
    return instructor.from_litellm(_guarded_completion)


@lru_cache(maxsize=1)
def get_async_instructor_client() -> instructor.AsyncInstructor:
    """Get an async Instructor client for concurrent operations.

    Same guarded-completion wrapper as the sync client ; concurrent
    calls (e.g. "generate risk statements for top 10 gaps in parallel")
    get the same offline enforcement.
    """
    return cast(instructor.AsyncInstructor, instructor.from_litellm(_guarded_acompletion))
