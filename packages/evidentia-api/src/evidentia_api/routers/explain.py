"""Explain router — plain-English control explanations.

Wraps :class:`evidentia_ai.ExplanationGenerator` (which caches to
disk per (framework, control, model, temperature) tuple). Returns the
explanation as JSON for cached hits, or as an SSE stream for cache
misses where the LLM might take several seconds.

In v0.4.0 both paths return the same JSON shape; the SSE variant just
emits a single ``data:`` event with the result. v0.4.1 will add true
token-level streaming once LiteLLM's Anthropic streaming adapter is
confirmed stable across all configured providers.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator

from fastapi import APIRouter, Query
from sse_starlette.sse import EventSourceResponse

from evidentia_api.errors import api_error, error_responses

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post(
    "/explain/{framework}/{control_id:path}",
    responses=error_responses(
        {
            404: (
                "Unknown ``framework`` or ``control_id`` "
                "(``error: not_found``)."
            ),
            500: (
                "evidentia-ai import failure "
                "(``error: feature_unavailable``)."
            ),
        }
    ),
)
async def explain(
    framework: str,
    control_id: str,
    refresh: bool = Query(
        False, description="Bypass the on-disk cache and re-generate."
    ),
    model: str | None = Query(
        None,
        description="LLM model override; falls back to EVIDENTIA_LLM_MODEL/config.",
    ),
) -> EventSourceResponse:
    """Return a plain-English explanation of a control, streamed via SSE."""
    # Defer heavy imports so /api/explain is fast to register even when
    # evidentia-ai is slow to import.
    try:
        from evidentia_ai.explain import ExplanationGenerator
    except ImportError as e:  # pragma: no cover — evidentia-ai is required
        raise api_error(
            500,
            "feature_unavailable",
            f"evidentia-ai unavailable: {e}",
        ) from e

    from evidentia_core.catalogs.registry import FrameworkRegistry

    registry = FrameworkRegistry.get_instance()
    try:
        catalog = registry.get_catalog(framework)
    except (FileNotFoundError, KeyError, ValueError) as e:
        raise api_error(
            404,
            "not_found",
            f"Framework '{framework}' not found.",
            resource="framework",
            resource_id=framework,
        ) from e

    control = catalog.get_control(control_id)
    if control is None:
        raise api_error(
            404,
            "not_found",
            f"Control '{control_id}' not found in '{framework}'.",
            resource="control",
            resource_id=control_id,
        )

    gen = ExplanationGenerator(model=model) if model else ExplanationGenerator()

    async def _stream() -> AsyncIterator[dict[str, str]]:
        yield {
            "data": json.dumps(
                {"phase": "start", "framework": framework, "control_id": control.id}
            )
        }
        try:
            # ExplanationGenerator is sync-only + has on-disk cache, so
            # offloading to a thread is almost always instantaneous for
            # cache hits. Cold-cache first calls block the thread for
            # the duration of the LLM call; the SSE "start" event above
            # keeps the browser responsive meanwhile.
            import asyncio

            result = await asyncio.to_thread(
                gen.generate,
                control=control,
                framework_id=framework,
                refresh=refresh,
            )
            payload = result.model_dump(mode="json")
            yield {"data": json.dumps({"phase": "done", "explanation": payload})}
        except Exception as e:
            logger.exception("Explanation failed")
            yield {
                "data": json.dumps(
                    {"phase": "error", "detail": str(e), "type": type(e).__name__}
                )
            }

    return EventSourceResponse(_stream())
