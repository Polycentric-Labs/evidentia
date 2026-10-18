"""Config router: read and write ``evidentia.yaml``.

GET returns the current config file as written (walking CWD -> parents
for the file). PUT accepts an :class:`EvidentiaConfig` payload, validates
it via Pydantic, and writes the YAML back to the same path.

Neither route expands ``${VAR}`` references. The library expands them at
load time (:func:`evidentia_core.config.load_config`), so a value written
as ``${SOME_TOKEN}`` would otherwise come back as the live server value in
the response body (v0.13.0 review finding C1). Both routes read through
:func:`evidentia_core.config.load_config_raw`, which returns the
placeholder text. The ``llm`` subsection is model + temperature only (no
API keys); keys are handled by ``/api/llm-status``, which returns booleans
and source identifiers only.

RBAC: ``GET`` requires ``read``; ``PUT`` requires ``admin`` because it
rewrites the operator's project configuration. Under the default
permissive policy both gates are inert.
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
    load_config_raw,
)
from evidentia_core.security.atomic_write import atomic_write_text
from fastapi import APIRouter

from evidentia_api.errors import api_error, error_responses
from evidentia_api.rbac_dependency import require_role

logger = logging.getLogger(__name__)
router = APIRouter()

# Upper bound on the serialised document. evidentia.yaml holds a handful
# of scalars and a framework list; anything near this size is a mistake
# or an attempt to fill the disk through the API.
_MAX_CONFIG_BYTES = 1_048_576


def _read_raw(path: Path) -> EvidentiaConfig:
    try:
        return load_config_raw(path)
    except ValueError as exc:
        logger.error("Config file %s is not a YAML mapping: %s", path, exc)
        raise api_error(
            500,
            "internal_error",
            "The configuration file could not be parsed; see the server log.",
        ) from exc


@router.get(
    "/config",
    response_model=EvidentiaConfig,
    dependencies=[require_role("read")],
    responses=error_responses(
        {
            403: "Read permission denied (``error: rbac_denied``).",
            500: "Config file is not a YAML mapping (``error: internal_error``).",
        }
    ),
)
async def get_config() -> EvidentiaConfig:
    """Return the current evidentia.yaml contents as written.

    If no file exists in CWD or any parent, returns a default (empty)
    :class:`EvidentiaConfig`. ``${VAR}`` references are returned as
    placeholders, not expanded.
    """
    path = find_config_file()
    if path is None:
        return EvidentiaConfig()
    return _read_raw(path)


@router.put(
    "/config",
    response_model=EvidentiaConfig,
    dependencies=[require_role("admin")],
    responses=error_responses(
        {
            400: "Unknown top-level key in the payload (``error: invalid_body``).",
            403: "Admin permission denied (``error: rbac_denied``).",
            413: "Serialised document larger than 1 MiB (``error: payload_too_large``).",
            500: "Config file write failure (``error: internal_error``).",
        }
    ),
)
async def put_config(payload: EvidentiaConfig) -> EvidentiaConfig:
    """Persist ``evidentia.yaml`` with the validated payload.

    Writes to the discovered path (walking CWD -> parents), or to
    ``./evidentia.yaml`` if none exists yet. Returns the persisted
    config as written (with ``source_path`` populated so callers can
    confirm where the write landed). Unknown top-level keys are refused:
    the file model tolerates legacy keys on load, but the API only
    writes the keys it documents.
    """
    unknown = sorted((payload.model_extra or {}).keys())
    if unknown:
        raise api_error(
            400,
            "invalid_body",
            f"Unknown top-level key(s): {', '.join(unknown)}. Only the documented evidentia.yaml keys are accepted.",
            unknown_keys=unknown,
        )
    target = find_config_file() or (Path.cwd() / CONFIG_FILENAME)
    dumped: dict[str, Any] = payload.model_dump(exclude={"source_path"}, exclude_defaults=False)
    yaml_text = yaml.safe_dump(dumped, sort_keys=False, default_flow_style=False)
    size = len(yaml_text.encode("utf-8"))
    if size > _MAX_CONFIG_BYTES:
        raise api_error(
            413,
            "payload_too_large",
            f"Serialised configuration is {size} bytes; the limit is {_MAX_CONFIG_BYTES}.",
            limit_bytes=_MAX_CONFIG_BYTES,
        )
    try:
        atomic_write_text(target, yaml_text)
    except OSError as e:
        logger.error("Failed to write %s: %s", target, e)
        raise api_error(
            500,
            "internal_error",
            "Could not write the configuration file; see the server log.",
        ) from e

    # Clear the LRU cache so subsequent library reads see the new contents.
    from evidentia_core.config import _load_config_cached

    _load_config_cached.cache_clear()

    refreshed = _read_raw(target)
    logger.info("Wrote %s (%d bytes)", target, size)
    return refreshed
