"""LiteLLM + Instructor client setup.

Provides a configured Instructor client that works with any LLM provider
supported by LiteLLM. Model selection is determined by (in priority order):
1. Explicit model parameter
2. EVIDENTIA_LLM_MODEL environment variable
3. llm.model in evidentia.yaml
4. Default: "gpt-4o"

v0.4.0: every completion call is guarded by
:func:`evidentia_core.network_guard.check_llm_model`. When offline
mode is on (set by the CLI's ``--offline`` flag or the FastAPI app's
``app.state.offline``), cloud models raise :class:`OfflineViolationError`
before any network IO is issued. Local models (``ollama/*``, ``vllm/*``)
and custom endpoints pointing at loopback / RFC-1918 pass through.
"""

from __future__ import annotations

import getpass
import os
import socket
from functools import lru_cache
from typing import Any, cast

import instructor
import litellm
from evidentia_core.network_guard import check_llm_model

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
    model = kwargs.get("model", "")
    api_base = kwargs.get("api_base") or kwargs.get("base_url")
    check_llm_model(model, api_base=api_base, subsystem="evidentia_ai")
    return litellm.completion(*args, **kwargs)


async def _guarded_acompletion(*args: Any, **kwargs: Any) -> Any:
    """Async wrapper around ``litellm.acompletion`` that enforces offline mode."""
    model = kwargs.get("model", "")
    api_base = kwargs.get("api_base") or kwargs.get("base_url")
    check_llm_model(model, api_base=api_base, subsystem="evidentia_ai")
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
