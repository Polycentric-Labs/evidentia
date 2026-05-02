"""Multi-format control inventory parser.

Supports four input formats with auto-detection:
1. Evidentia YAML (preferred)
2. CSV with fuzzy header matching
3. OSCAL component definition JSON
4. CISO Assistant JSON export
"""

from __future__ import annotations

import csv
import json
import logging
from io import StringIO
from pathlib import Path
from typing import Any

import yaml
from thefuzz import fuzz

from evidentia_core.models.control import (
    ControlImplementation,
    ControlInventory,
    ControlStatus,
)

logger = logging.getLogger(__name__)

# Known CSV column names and their canonical mappings
CSV_COLUMN_ALIASES: dict[str, list[str]] = {
    "control_id": [
        "control_id",
        "control id",
        "id",
        "control",
        "ctrl_id",
        "ctrl",
        "requirement_id",
        "requirement",
    ],
    "title": ["title", "control_title", "control title", "name", "control_name"],
    "status": [
        "status",
        "implementation_status",
        "implementation status",
        "state",
        "impl_status",
    ],
    "description": [
        "description",
        "notes",
        "implementation_notes",
        "details",
        "comments",
    ],
    "owner": [
        "owner",
        "control_owner",
        "responsible",
        "assignee",
        "responsible_party",
    ],
}

# Status aliases for fuzzy matching
STATUS_ALIASES: dict[str, ControlStatus] = {
    "implemented": ControlStatus.IMPLEMENTED,
    "fully implemented": ControlStatus.IMPLEMENTED,
    "complete": ControlStatus.IMPLEMENTED,
    "yes": ControlStatus.IMPLEMENTED,
    "partial": ControlStatus.PARTIALLY_IMPLEMENTED,
    "partially implemented": ControlStatus.PARTIALLY_IMPLEMENTED,
    "partially_implemented": ControlStatus.PARTIALLY_IMPLEMENTED,
    "in progress": ControlStatus.PARTIALLY_IMPLEMENTED,
    "planned": ControlStatus.PLANNED,
    "scheduled": ControlStatus.PLANNED,
    "not implemented": ControlStatus.NOT_IMPLEMENTED,
    "not_implemented": ControlStatus.NOT_IMPLEMENTED,
    "missing": ControlStatus.NOT_IMPLEMENTED,
    "no": ControlStatus.NOT_IMPLEMENTED,
    "not applicable": ControlStatus.NOT_APPLICABLE,
    "not_applicable": ControlStatus.NOT_APPLICABLE,
    "n/a": ControlStatus.NOT_APPLICABLE,
    "na": ControlStatus.NOT_APPLICABLE,
}


def load_inventory(path: str | Path) -> ControlInventory:
    """Load a control inventory from any supported format.

    Auto-detects format based on file extension and content structure.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Inventory file not found: {path}")

    suffix = path.suffix.lower()
    content = path.read_text(encoding="utf-8")

    if suffix in (".yaml", ".yml"):
        return _parse_evidentia_yaml(content, str(path))
    if suffix == ".csv":
        return _parse_csv(content, str(path))
    if suffix == ".json":
        return _parse_json(content, str(path))

    raise ValueError(
        f"Unsupported file extension '{suffix}'. "
        f"Supported: .yaml, .yml, .json, .csv"
    )


def _parse_json(content: str, source_path: str) -> ControlInventory:
    """Parse a JSON inventory — auto-detect OSCAL vs CISO Assistant vs Evidentia."""
    data = json.loads(content)

    if "component-definition" in data:
        return _parse_oscal_component_definition(data, source_path)
    if "ciso_assistant" in data or (
        isinstance(data, dict) and "framework" in data and "assessments" in data
    ):
        return _parse_ciso_assistant(data, source_path)
    if "controls" in data:
        return _parse_evidentia_dict(data, source_path, "evidentia-json")

    raise ValueError(
        "Unrecognized JSON format. Expected one of: "
        "OSCAL component-definition, CISO Assistant export, "
        "or Evidentia format with 'controls' key."
    )


def _parse_evidentia_yaml(content: str, source_path: str) -> ControlInventory:
    """Parse Evidentia YAML format."""
    data = yaml.safe_load(content)
    if not isinstance(data, dict) or "controls" not in data:
        raise ValueError(
            "Invalid Evidentia YAML: expected a mapping with 'controls' key"
        )
    return _parse_evidentia_dict(data, source_path, "evidentia")


def _parse_evidentia_dict(
    data: dict[str, Any], source_path: str, format_name: str
) -> ControlInventory:
    """Parse a Evidentia-format dict (from YAML or JSON)."""
    controls: list[ControlImplementation] = []
    for item in data.get("controls", []):
        status_str = str(item.get("status", "not_implemented")).lower().strip()
        status = STATUS_ALIASES.get(status_str, ControlStatus.NOT_IMPLEMENTED)

        controls.append(
            ControlImplementation(
                id=str(item["id"]).strip(),
                title=item.get("title"),
                description=item.get("description"),
                status=status,
                implementation_notes=item.get("implementation_notes")
                or item.get("notes"),
                responsible_roles=item.get("responsible_roles", []),
                evidence_references=item.get("evidence_references", []),
                owner=item.get("owner"),
                frameworks=item.get("frameworks", []),
                tags=item.get("tags", []),
            )
        )

    return ControlInventory(
        organization=data.get("organization", "Unknown Organization"),
        controls=controls,
        source_format=format_name,
        source_file=source_path,
    )


def _parse_csv(content: str, source_path: str) -> ControlInventory:
    """Parse CSV with fuzzy header matching."""
    reader = csv.DictReader(StringIO(content))
    if not reader.fieldnames:
        raise ValueError("CSV file has no headers")

    # Map CSV headers to canonical names using fuzzy matching
    header_map: dict[str, str] = {}
    for canonical, aliases in CSV_COLUMN_ALIASES.items():
        best_match: str | None = None
        best_score = 0
        for csv_header in reader.fieldnames:
            for alias in aliases:
                score = fuzz.ratio(csv_header.lower().strip(), alias.lower())
                if score > best_score and score >= 70:
                    best_score = score
                    best_match = csv_header
        if best_match:
            header_map[canonical] = best_match

    if "control_id" not in header_map:
        raise ValueError(
            f"CSV must have a control ID column. "
            f"Found headers: {reader.fieldnames}. "
            f"Expected one of: {CSV_COLUMN_ALIASES['control_id']}"
        )

    controls: list[ControlImplementation] = []
    for row in reader:
        control_id = row.get(header_map["control_id"], "").strip()
        if not control_id:
            continue

        status_str = (
            row.get(header_map.get("status", ""), "not_implemented") or "not_implemented"
        ).lower().strip()
        status = STATUS_ALIASES.get(status_str, ControlStatus.NOT_IMPLEMENTED)

        controls.append(
            ControlImplementation(
                id=control_id,
                title=row.get(header_map.get("title", ""), None) or None,
                description=row.get(header_map.get("description", ""), None) or None,
                status=status,
                owner=row.get(header_map.get("owner", ""), None) or None,
            )
        )

    # %r (repr) escapes control chars in user-controlled source_path —
    # closes CodeQL py/log-injection alert #80 (CWE-117) per v0.7.8
    # P0.5 S2.
    logger.info("Parsed CSV inventory: %d controls from %r", len(controls), source_path)
    # v0.2.1: CSV format has no dedicated organization field, so we fall
    # back to a neutral placeholder. Callers that want a real org name
    # should pass `--organization` on the CLI or set it in
    # `evidentia.yaml` — both paths apply `model_copy(update=...)` after
    # load. The old ``"Unknown Organization (from CSV)"`` string leaked into
    # every exported report header and had no override path.
    return ControlInventory(
        organization="Unknown Organization",
        controls=controls,
        source_format="csv",
        source_file=source_path,
    )


def _parse_oscal_component_definition(
    data: dict[str, Any], source_path: str
) -> ControlInventory:
    """Parse an OSCAL component-definition JSON into a ControlInventory."""
    comp_def = data["component-definition"]
    metadata = comp_def.get("metadata", {})

    controls: list[ControlImplementation] = []
    for component in comp_def.get("components", []):
        for ctrl_impl in component.get("control-implementations", []):
            for impl_req in ctrl_impl.get("implemented-requirements", []):
                control_id = impl_req.get("control-id", "").upper()

                # Determine status from OSCAL properties
                status = ControlStatus.IMPLEMENTED
                for prop in impl_req.get("props", []):
                    if prop.get("name") == "implementation-status":
                        oscal_status = prop.get("value", "").lower()
                        if "partial" in oscal_status:
                            status = ControlStatus.PARTIALLY_IMPLEMENTED
                        elif "planned" in oscal_status:
                            status = ControlStatus.PLANNED
                        elif "not" in oscal_status:
                            status = ControlStatus.NOT_IMPLEMENTED

                description = ""
                for statement in impl_req.get("statements", []):
                    description += statement.get("description", "") + "\n"

                controls.append(
                    ControlImplementation(
                        id=control_id,
                        title=None,
                        description=description.strip() or None,
                        status=status,
                    )
                )

    return ControlInventory(
        organization=metadata.get("title", "Unknown Organization"),
        controls=controls,
        source_format="oscal",
        source_file=source_path,
    )


def _parse_ciso_assistant(data: dict[str, Any], source_path: str) -> ControlInventory:
    """Parse a CISO Assistant JSON export into a ControlInventory."""
    controls: list[ControlImplementation] = []

    for assessment in data.get("assessments", data.get("compliance_assessments", [])):
        for req in assessment.get("requirements", []):
            control_id = req.get("ref_id", req.get("urn", "")).strip()
            if not control_id:
                continue

            status_value = req.get("status", "").lower()
            status_map = {
                "compliant": ControlStatus.IMPLEMENTED,
                "partially_compliant": ControlStatus.PARTIALLY_IMPLEMENTED,
                "non_compliant": ControlStatus.NOT_IMPLEMENTED,
                "not_applicable": ControlStatus.NOT_APPLICABLE,
            }
            status = status_map.get(status_value, ControlStatus.NOT_IMPLEMENTED)

            controls.append(
                ControlImplementation(
                    id=control_id,
                    title=req.get("name"),
                    description=req.get("description"),
                    status=status,
                    implementation_notes=req.get("observation"),
                )
            )

    return ControlInventory(
        organization=data.get("organization", {}).get("name", "Unknown Organization"),
        controls=controls,
        source_format="ciso-assistant",
        source_file=source_path,
    )
