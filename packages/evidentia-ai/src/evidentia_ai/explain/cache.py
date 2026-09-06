"""On-disk cache for LLM-generated control explanations.

Explanations are deterministic given (framework, control, model,
temperature) — cache them forever by that tuple. A single explanation
can take 5-15 seconds to generate and cost a few cents; re-paying for
the same lookup every time is wasteful.

Cache location (follows the user_dir pattern from the catalog and
gap-store facilities): ``<platformdirs-cache>/evidentia/explanations/``.
Override via ``EVIDENTIA_EXPLAIN_CACHE_DIR`` environment variable
or an explicit argument.
"""

from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from platformdirs import user_cache_dir

from evidentia_ai.explain.models import PlainEnglishExplanation

logger = logging.getLogger(__name__)

EXPLAIN_CACHE_ENV_VAR = "EVIDENTIA_EXPLAIN_CACHE_DIR"


def get_cache_dir(override: Path | None = None) -> Path:
    """Resolve the explanation cache directory.

    Precedence: explicit argument > env var > platformdirs default.
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(EXPLAIN_CACHE_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    return Path(user_cache_dir("evidentia", "Evidentia")) / "explanations"


def _cache_key(framework_id: str, control_id: str, model: str, temperature: float) -> str:
    """Stable 16-hex-char key for a (fw, ctrl, model, temp) tuple."""
    seed = f"{framework_id}|{control_id}|{model}|{temperature:.3f}"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def load_cached(
    framework_id: str,
    control_id: str,
    model: str,
    temperature: float,
    cache_dir: Path | None = None,
) -> PlainEnglishExplanation | None:
    """Return a cached explanation if one exists for this (fw, ctrl, model, temp)."""
    key = _cache_key(framework_id, control_id, model, temperature)
    path = get_cache_dir(cache_dir) / f"{key}.json"
    if not path.exists():
        return None
    try:
        return PlainEnglishExplanation.model_validate_json(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Corrupt cache file %s (%s); ignoring", path, exc)
        return None


def store(
    explanation: PlainEnglishExplanation,
    model: str,
    temperature: float,
    cache_dir: Path | None = None,
) -> Path:
    """Persist an explanation to the cache; return the file path written."""
    key = _cache_key(explanation.framework_id, explanation.control_id, model, temperature)
    dest = get_cache_dir(cache_dir)
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{key}.json"
    path.write_text(explanation.model_dump_json(indent=2) + "\n", encoding="utf-8")
    logger.debug("Cached explanation: %s", path)
    return path


def clear_cache(cache_dir: Path | None = None) -> int:
    """Remove all cached explanations; return how many files were deleted."""
    dest = get_cache_dir(cache_dir)
    if not dest.exists():
        return 0
    count = 0
    for p in dest.glob("*.json"):
        p.unlink()
        count += 1
    return count
