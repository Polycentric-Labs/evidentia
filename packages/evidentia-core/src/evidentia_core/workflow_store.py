"""Persistent governance-workflow store (v0.7.11 P1.5 G5).

JSON-file-per-record persistence following the harmonized v0.7.11
store pattern (UUID-shape gate + ``validate_within`` belt-and-
suspenders + atomic ``os.replace``). Storage location precedence:

    1. Explicit ``override`` argument
    2. ``EVIDENTIA_WORKFLOW_STORE_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir``
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.governance.workflows import Workflow
from evidentia_core.models.common import utc_now
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

WORKFLOW_STORE_ENV_VAR = "EVIDENTIA_WORKFLOW_STORE_DIR"


class InvalidWorkflowIdError(ValueError):
    """Raised when a candidate workflow ID isn't a valid UUID string."""


def _validate_id_shape(workflow_id: str) -> None:
    if not isinstance(workflow_id, str) or not workflow_id:
        raise InvalidWorkflowIdError(
            f"Invalid workflow ID: empty or non-string: {workflow_id!r}"
        )
    try:
        UUID(workflow_id)
    except (ValueError, AttributeError, TypeError) as e:
        raise InvalidWorkflowIdError(
            f"Invalid workflow ID: not a UUID-shaped string: "
            f"{workflow_id!r} ({type(e).__name__}: {e})"
        ) from e


def get_workflow_store_dir(override: Path | None = None) -> Path:
    """Resolve the workflow store directory."""
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(WORKFLOW_STORE_ENV_VAR)
    if env:
        # v0.7.12 P3 cosmetic harmonization: match vendor_store +
        # model_risk_store pattern.
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", appauthor=False)) / "workflow_store"


def save_workflow(
    workflow: Workflow, *, override: Path | None = None
) -> Path:
    """Persist a workflow record. Atomic via os.replace."""
    _validate_id_shape(workflow.id)
    store_dir = get_workflow_store_dir(override)
    store_dir.mkdir(parents=True, exist_ok=True)

    refreshed = workflow.model_copy(update={"updated_at": utc_now()})
    payload = refreshed.model_dump_json(indent=2)

    candidate = store_dir / f"{workflow.id}.json"
    try:
        out_path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidWorkflowIdError(
            f"Invalid workflow ID: path-traversal violation: {workflow.id!r}"
        ) from e
    tmp_path = store_dir / f"{workflow.id}.json.tmp"
    tmp_path.write_text(payload, encoding="utf-8")
    os.replace(tmp_path, out_path)
    logger.debug("saved workflow %s to %s", workflow.id, out_path)
    return out_path


def load_workflow_by_id(
    workflow_id: str, *, override: Path | None = None
) -> Workflow | None:
    """Load a workflow by ID. Returns None for well-formed-unknown IDs."""
    _validate_id_shape(workflow_id)
    store_dir = get_workflow_store_dir(override)
    candidate = store_dir / f"{workflow_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidWorkflowIdError(
            f"Invalid workflow ID: path-traversal violation: {workflow_id!r}"
        ) from e
    if not path.exists():
        return None
    return Workflow.model_validate_json(path.read_text(encoding="utf-8"))


def list_workflows(
    *, override: Path | None = None
) -> list[Workflow]:
    """List all workflows sorted by created_at DESC then id."""
    store_dir = get_workflow_store_dir(override)
    if not store_dir.exists():
        return []
    workflows: list[Workflow] = []
    for path in store_dir.glob("*.json"):
        if path.name.endswith(".tmp"):
            continue
        try:
            workflows.append(
                Workflow.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            )
        except Exception as e:
            logger.warning("Skipping malformed workflow file %s: %s", path, e)
            continue
    # Newest first
    workflows.sort(key=lambda w: (-w.created_at.timestamp(), w.id))
    return workflows


def delete_workflow(
    workflow_id: str, *, override: Path | None = None
) -> bool:
    """Delete a workflow by ID. Returns True if removed."""
    _validate_id_shape(workflow_id)
    store_dir = get_workflow_store_dir(override)
    candidate = store_dir / f"{workflow_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidWorkflowIdError(
            f"Invalid workflow ID: path-traversal violation: {workflow_id!r}"
        ) from e
    if not path.exists():
        return False
    path.unlink()
    return True
