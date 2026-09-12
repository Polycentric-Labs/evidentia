"""Read the named-organization scope of the reviewed FCC dated snapshot."""

from __future__ import annotations

from typing import Any

from ._client import RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult
from ._parsing import canonical_json, checked_json

_CELL: dict[str, Any] = {
    "document": str,
    "pdf_page": int,
    "appendix": str,
    "printed_appendix_page": str,
    "table_index_one_based": int,
    "physical_table_row_index_one_based": int,
    "physical_column_index_one_based": int,
    "source_literal_lines": str,
}
_NAMED: dict[str, Any] = {
    "derived_appendix_a_row_ordinal": int,
    "publisher_row_identifier_presence": str,
    "names_source_literal": [str],
    "equipment_service_scope_source_literal": str,
    "inclusion_date_source_literal": str,
    "applicable_appendix_a_footnote_markers": [str],
    "source_occurrences": [
        {"snapshot_update_source_literal": str, "equipment_service_cell": _CELL, "inclusion_date_cell": _CELL}
    ],
}
_CATEGORY: dict[str, Any] = {
    "derived_appendix_a_row_ordinal": int,
    "category": str,
    "publisher_row_identifier_presence": str,
    "equipment_service_scope_source_literal": str,
    "date_cell_source_literals": [str],
    "source_occurrences": [
        {"snapshot_update_source_literal": str, "equipment_service_cells": [_CELL], "date_cells": [_CELL]}
    ],
    "date_entries": [{"role": str, "source_literal": str}],
    "applicable_appendix_a_footnote_markers": [str],
    "disclosures": [{"kind": str, "source_literal": str}],
}
_FOOTNOTE: dict[str, Any] = {
    "appendix": str,
    "marker_source_literal": str,
    "text_source_literal": str,
    "applies_to": str,
    "source_occurrences": [
        {
            "document": str,
            "pdf_page": int,
            "appendix": str,
            "printed_appendix_page": str,
            "footnote_marker_source_literal": str,
            "source_literal_lines": str,
        }
    ],
}
_APPROVAL: dict[str, Any] = {
    "category": str,
    "derived_category_row_ordinal": int,
    "publisher_row_identifier_presence": str,
    "device_scope_source_literal": str,
    "approval_groups": [
        {
            "derived_group_ordinal": int,
            "device_scope_source_literal": str,
            "date_range_source_literal": str,
            "starts_source_literal": str,
            "termination_component": {"presence": str, "source_literal": str},
        }
    ],
    "applicable_footnote": {"appendix": str, "marker_source_literal": str},
    "source_occurrences": [{"device_scope_cells": [_CELL], "date_cells": [_CELL]}],
}
_CLAUSE: dict[str, Any] = {"source_clause_label": str, "text_source_literal": str, "pdf_pages": [int]}
_DEFINITION: dict[str, Any] = {
    "definition": str,
    "role": str,
    "document": str,
    "appendix": str,
    "printed_appendix_pages": [str],
    "determination_date_source_literal": str,
    "heading_source_literal": str,
    "clauses": [_CLAUSE],
    "foreign_produced_heading_source_literal": str,
    "foreign_produced_clauses": [_CLAUSE],
    "source_method": str,
    "parallel_source_occurrence": {
        "document": str,
        "pdf_page": int,
        "section": str,
        "location": str,
        "source_literal_lines": str,
    },
    "determination_received_date_source_literal": str,
    "notice_release_date_source_literal": str,
}
_CONTEXT: dict[str, Any] = {
    "kind": str,
    "document": str,
    "pdf_pages": [int],
    "location": str,
    "text_source_literal": str,
}
FACT_SCHEMAS: dict[str, dict[str, Any]] = {
    "named_entries": _NAMED,
    "category_rows": _CATEGORY,
    "footnotes": _FOOTNOTE,
    "conditional_approvals": _APPROVAL,
    "definition_context": _DEFINITION,
    "source_context": _CONTEXT,
}
_SOURCE: dict[str, Any] = {
    "source_id": str,
    "url": str,
    "media_type": str,
    "raw_sha256": str,
    "raw_bytes": int,
    "captured_started_at": str,
    "captured_finished_at": str,
    "publisher_version": str,
    "publisher_cutoff": {"source_path": str, "literal": str, "representation": str},
    "role": str,
    "release_date_source_literal": str,
    "pdf_page_count": int,
}
_OBSERVATION: dict[str, Any] = {
    "named_entry": _NAMED,
    "linked_footnotes": [_FOOTNOTE],
    "named_scope_context": [_CONTEXT],
    "scope_limits": {
        "category_applicability": str,
        "conditional_approval_applicability": str,
        "deployment_applicability": str,
        "indirect_affiliate_applicability": str,
        "later_currency": str,
        "legal_applicability": str,
        "query_scope": str,
    },
    "snapshot_context": {
        "as_of": {"basis": str, "date": str, "literal": str, "representation": str, "source_ids": [str]},
        "fact_counts": {
            "category_rows": int,
            "conditional_approvals": int,
            "definition_context": int,
            "footnotes": int,
            "named_entries": int,
            "source_context": int,
        },
        "full_tuple_sha256": str,
        "retention": str,
        "snapshot_sha256": str,
        "sources": [_SOURCE],
    },
}


def _select(value: Any, schema: Any) -> Any:
    if type(schema) is dict:
        if type(value) is not dict:
            raise ValueError("invalid_snapshot_fields")
        return {key: _select(value[key], child) for key, child in schema.items() if key in value}
    if type(schema) is list:
        if type(value) is not list:
            raise ValueError("invalid_snapshot_fields")
        return [_select(item, schema[0]) for item in value]
    if type(value) is not schema or (schema is int and value < 0):
        raise ValueError("invalid_snapshot_fields")
    return value


def _project(source: object, schema: dict[str, Any]) -> dict[str, Any]:
    native = checked_json(source)
    selected: dict[str, Any] = _select(native, schema)
    if len(canonical_json(selected)) > 65_536:
        raise ValueError("invalid_snapshot_fields")
    return selected


def project_fact(family: str, source: object) -> dict[str, Any]:
    """Select one declared reviewed PDF fact without a generic PDF parser."""
    if type(family) is not str or family not in FACT_SCHEMAS:
        raise ValueError("invalid_snapshot_fields")
    return _project(source, FACT_SCHEMAS[family])


def project_named_entry(source: dict[str, Any]) -> dict[str, Any]:
    """Keep named entries, scope footnotes and exclusions visibly separate."""
    return _project(source, _OBSERVATION)


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    request = session.request.root
    if request.registry != "fcc-covered-list":
        raise RegistryInputError()
    return session.read_snapshot(request.target, project_named_entry)
