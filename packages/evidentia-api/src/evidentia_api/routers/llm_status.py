"""LLM-status router — provider configuration state **without** key values.

Honors the global CLAUDE.md secrets-through-context rule strictly: this
endpoint never returns key values, only presence booleans and source
identifiers. Users configure keys via env vars or a ``.env`` file the
backend reads at startup; the browser never sees them.
"""

from __future__ import annotations

import os

from evidentia_ai.client import get_default_model
from fastapi import APIRouter

from evidentia_api.schemas import LlmProviderState, LlmStatusResponse

router = APIRouter()

# Provider label -> env-var-name pairs. Ollama is special-cased: presence
# is detected by model prefix rather than by a key since local deployments
# don't need one.
_CLOUD_PROVIDERS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
    "azure_openai": "AZURE_OPENAI_API_KEY",
}


@router.get("/llm-status", response_model=LlmStatusResponse)
async def llm_status() -> LlmStatusResponse:
    """Report which LLM providers are configured and where keys come from.

    Returns structured state for each provider; the UI renders per-provider
    badges in the Settings page.
    """
    providers: dict[str, LlmProviderState] = {}
    for provider, env_var in _CLOUD_PROVIDERS.items():
        configured = bool(os.environ.get(env_var))
        providers[provider] = LlmProviderState(
            configured=configured,
            source=f"env:{env_var}" if configured else None,
        )

    # Ollama and other local providers: configured=True if model prefix is
    # ollama/* or similar, or if a local api_base is set.
    from evidentia_core.network_guard import LOCAL_LLM_PREFIXES

    model = get_default_model()
    local_configured = any(model.lower().startswith(p) for p in LOCAL_LLM_PREFIXES) or bool(
        os.environ.get("EVIDENTIA_LLM_API_BASE")
    )
    providers["ollama"] = LlmProviderState(
        configured=local_configured,
        source=(
            f"model:{model}"
            if any(model.lower().startswith(p) for p in LOCAL_LLM_PREFIXES)
            else ("env:EVIDENTIA_LLM_API_BASE" if local_configured else None)
        ),
    )

    return LlmStatusResponse(providers=providers, configured_model=model)
