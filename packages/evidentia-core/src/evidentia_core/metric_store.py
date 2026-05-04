"""Persistent KRI/KPI/KGI metric store (v0.7.11 P1.5 G3).

JSON-file-per-record persistence mirroring the v0.7.10 P0.6.1
:mod:`evidentia_core.model_risk_store` + v0.7.10 P1.5 G2
:mod:`evidentia_core.effective_challenge_store` patterns adapted
for the :class:`evidentia_core.governance.metrics.Metric` schema.

Storage location precedence:
    1. Explicit ``override`` argument
    2. ``EVIDENTIA_METRIC_STORE_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir``

Atomic-write semantics + UUID-shape gate + ``validate_within``
belt-and-suspenders all match the harmonized v0.7.11 store
pattern.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.governance.metrics import Metric
from evidentia_core.models.common import utc_now
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

METRIC_STORE_ENV_VAR = "EVIDENTIA_METRIC_STORE_DIR"


class InvalidMetricIdError(ValueError):
    """Raised when a candidate metric ID isn't a valid UUID string."""


def _validate_id_shape(metric_id: str) -> None:
    if not isinstance(metric_id, str) or not metric_id:
        raise InvalidMetricIdError(
            f"Invalid metric ID: empty or non-string: {metric_id!r}"
        )
    try:
        UUID(metric_id)
    except (ValueError, AttributeError, TypeError) as e:
        raise InvalidMetricIdError(
            f"Invalid metric ID: not a UUID-shaped string: "
            f"{metric_id!r} ({type(e).__name__}: {e})"
        ) from e


def get_metric_store_dir(override: Path | None = None) -> Path:
    """Resolve the metric store directory."""
    if override is not None:
        return Path(override)
    env = os.environ.get(METRIC_STORE_ENV_VAR)
    if env:
        return Path(env)
    return Path(user_data_dir("evidentia", appauthor=False)) / "metric_store"


def save_metric(
    metric: Metric, *, override: Path | None = None
) -> Path:
    """Persist a metric record. Atomic via os.replace.

    Mirrors the harmonized v0.7.11 store pattern:
    UUID-shape gate + ``validate_within`` belt-and-suspenders +
    atomic ``os.replace(tmp, out_path)`` semantics.
    """
    _validate_id_shape(metric.id)
    store_dir = get_metric_store_dir(override)
    store_dir.mkdir(parents=True, exist_ok=True)

    refreshed = metric.model_copy(update={"updated_at": utc_now()})
    payload = refreshed.model_dump_json(indent=2)

    candidate = store_dir / f"{metric.id}.json"
    try:
        out_path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidMetricIdError(
            f"Invalid metric ID: path-traversal violation: {metric.id!r}"
        ) from e
    tmp_path = store_dir / f"{metric.id}.json.tmp"
    tmp_path.write_text(payload, encoding="utf-8")
    os.replace(tmp_path, out_path)
    logger.debug("saved metric %s to %s", metric.id, out_path)
    return out_path


def load_metric_by_id(
    metric_id: str, *, override: Path | None = None
) -> Metric | None:
    """Load a metric by ID. Returns None for well-formed-unknown IDs."""
    _validate_id_shape(metric_id)
    store_dir = get_metric_store_dir(override)
    candidate = store_dir / f"{metric_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidMetricIdError(
            f"Invalid metric ID: path-traversal violation: {metric_id!r}"
        ) from e
    if not path.exists():
        return None
    return Metric.model_validate_json(path.read_text(encoding="utf-8"))


def list_metrics(
    *, override: Path | None = None
) -> list[Metric]:
    """List all metrics sorted by kind (KRI → KPI → KGI) then name."""
    store_dir = get_metric_store_dir(override)
    if not store_dir.exists():
        return []
    metrics: list[Metric] = []
    for path in store_dir.glob("*.json"):
        if path.name.endswith(".tmp"):
            continue
        try:
            metrics.append(
                Metric.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            )
        except Exception as e:
            logger.warning("Skipping malformed metric file %s: %s", path, e)
            continue
    # Sort by kind (KRI/KPI/KGI alphabetical) then name (case-insensitive)
    metrics.sort(key=lambda m: (m.kind, m.name.lower()))
    return metrics


def delete_metric(
    metric_id: str, *, override: Path | None = None
) -> bool:
    """Delete a metric by ID. Returns True if removed."""
    _validate_id_shape(metric_id)
    store_dir = get_metric_store_dir(override)
    candidate = store_dir / f"{metric_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidMetricIdError(
            f"Invalid metric ID: path-traversal violation: {metric_id!r}"
        ) from e
    if not path.exists():
        return False
    path.unlink()
    return True
