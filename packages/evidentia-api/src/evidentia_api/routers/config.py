"""Config router — read / write ``evidentia.yaml``.

GET returns the current config (walking CWD -> parents for the file).
PUT accepts a :class:`EvidentiaConfig` payload, validates it via
Pydantic, and writes the YAML back to the same path.

No secrets ever flow through this endpoint's request/response bodies —
the ``llm`` subsection is model + temperature only (no API keys). Keys
are handled separately via the ``/api/llm-status`` endpoint, which never
returns key values, only booleans + source identifiers.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from evidentia_core.config import (
    CONFIG_FILENAME,
    EvidentiaConfig,
    find_config_file,
    load_config,
)
from fastapi import APIRouter

from evidentia_api.errors import api_error, error_responses

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/config", response_model=EvidentiaConfig)
async def get_config() -> EvidentiaConfig:
    """Return the currently-loaded evidentia.yaml contents.

    If no file exists in CWD or any parent, returns a default
    (empty) :class:`EvidentiaConfig`.
    """
    return load_config()


@router.put(
    "/config",
    response_model=EvidentiaConfig,
    responses=error_responses(
        {
            500: (
                "Config file write failure "
                "(``error: internal_error``)."
            ),
        }
    ),
)
async def put_config(payload: EvidentiaConfig) -> EvidentiaConfig:
    """Persist ``evidentia.yaml`` with the validated payload.

    Writes to the discovered path (walking CWD -> parents), or to
    ``./evidentia.yaml`` if none exists yet. Returns the persisted
    config (with ``source_path`` populated so callers can confirm where
    the write landed).
    """
    target = find_config_file() or (Path.cwd() / CONFIG_FILENAME)
    try:
        dumped: dict[str, Any] = payload.model_dump(
            exclude={"source_path"}, exclude_defaults=False
        )
        yaml_text = yaml.safe_dump(
            dumped, sort_keys=False, default_flow_style=False
        )
        target.write_text(yaml_text, encoding="utf-8")
    except OSError as e:
        logger.error("Failed to write %s: %s", target, e)
        raise api_error(
            500,
            "internal_error",
            f"Could not write config to {target}: {e}",
        ) from e

    # Clear the LRU cache so subsequent reads see the new contents.
    from evidentia_core.config import _load_config_cached

    _load_config_cached.cache_clear()

    refreshed = load_config(target)
    logger.info("Wrote %s (%d bytes)", target, len(yaml_text))
    return refreshed
