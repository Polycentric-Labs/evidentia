"""Read v0.6-era SecurityFinding JSON under the v0.7.0 schema.

v0.7.0 added two required fields to SecurityFinding:

- ``control_mappings: list[ControlMapping]`` (replacing
  ``control_ids: list[str]``)
- ``collection_context: CollectionContext``

SecurityFinding's ``@model_validator(mode="before")`` already handles
Python-constructor backward compat. This module handles the *JSON*
path: load a v0.6-era report file that may have ``control_ids: list[str]``
as a top-level field and no ``collection_context`` at all, synthesize
the missing v0.7.0 fields with clearly-marked legacy placeholders, and
emit a structured log event so auditors can identify evidence that
predates the enterprise provenance model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from evidentia_core.audit.events import EventAction
from evidentia_core.audit.logger import get_logger
from evidentia_core.models.finding import SecurityFinding

_log = get_logger("evidentia.models.migrations.v0_6_to_v0_7")


def is_legacy_finding_payload(payload: Any) -> bool:
    """Return True if ``payload`` looks like a v0.6-era SecurityFinding.

    Heuristic: has top-level ``control_ids`` but no ``collection_context``
    or ``control_mappings``.
    """
    if not isinstance(payload, dict):
        return False
    has_legacy_field = "control_ids" in payload
    lacks_v07_fields = "collection_context" not in payload and "control_mappings" not in payload
    return has_legacy_field and lacks_v07_fields


def load_legacy_finding(payload: dict[str, Any]) -> SecurityFinding:
    """Construct a :class:`SecurityFinding` from v0.6-era JSON.

    Emits an ``evidentia.config.resolved`` event logging the legacy
    migration for audit visibility.
    """
    if is_legacy_finding_payload(payload):
        _log.warning(
            action=EventAction.CONFIG_RESOLVED,
            message=(
                "Loading legacy v0.6-era SecurityFinding; "
                "collection_context will be synthesized as "
                "'legacy-pre-v0.7.0' and control_ids auto-converted "
                "to RELATED_TO ControlMappings."
            ),
            evidentia={
                "migration": "v0_6_to_v0_7",
                "source_finding_id": payload.get("id"),
                "legacy_control_ids_count": len(payload.get("control_ids") or []),
            },
        )

    return SecurityFinding.model_validate(payload)


def migrate_findings_json(path: str | Path) -> list[SecurityFinding]:
    """Read a v0.6-era findings JSON file and return v0.7.0 SecurityFindings.

    Accepts both single-finding and array-of-findings shapes.
    """
    path = Path(path)
    raw = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(raw, list):
        return [load_legacy_finding(item) for item in raw]
    if isinstance(raw, dict):
        return [load_legacy_finding(raw)]

    raise ValueError(
        f"Unsupported findings payload shape ({type(raw).__name__}); expected JSON object or array of objects"
    )


__all__ = [
    "is_legacy_finding_payload",
    "load_legacy_finding",
    "migrate_findings_json",
]
