"""Regenerate the reviewed FCC PDF-fact snapshot without parsing or fetching PDFs.

Run with python -m scripts.registries.refresh_fcc. Named entries, categories,
conditional approvals, definitions and source context remain separate fact families.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from evidentia_collectors.registries import fcc
from evidentia_collectors.registries._contracts import normalized_organization_name

from scripts.registries.refresh_fedramp import (
    MAX_RECORDS,
    RefreshError,
    count,
    hash_value,
    main,
    native,
    obj,
    package,
    rows,
    text_value,
    tuple_binding,
)

_FAMILIES = (
    "named_entries",
    "category_rows",
    "footnotes",
    "conditional_approvals",
    "definition_context",
    "source_context",
)
_A_HEADERS = ["Covered Equipment or Services*", "Date of Inclusion on Covered List"]
_B_HEADERS = [
    "UAS Conditional Approvals",
    "Dates of Conditional Approval*",
    "Routers Conditional Approvals",
    "Dates of Conditional Approval",
    "Robotic Devices Conditional Approvals",
    "Dates of Conditional Approval",
]
_ROOT_KEYS = {
    "schema_version",
    "registry",
    "source_kind",
    "query_scope",
    "snapshot_date",
    "sources",
    "appendix_a_column_headers_source_literal",
    "appendix_b_column_headers_source_literal",
    "scope_limits",
    "literal_policy",
    "row_identity_policy",
    "source_review_sha256",
    *_FAMILIES,
}
_SOURCE_KEYS = {
    "source_id",
    "url",
    "media_type",
    "raw_sha256",
    "raw_bytes",
    "captured_started_at",
    "captured_finished_at",
    "publisher_version",
    "publisher_cutoff",
    "role",
    "release_date_source_literal",
    "pdf_page_count",
}


def _positive_positions(value: Any) -> None:
    if type(value) is int and value < 1:
        raise RefreshError()
    if type(value) is dict:
        for child in value.values():
            _positive_positions(child)
    elif type(value) is list:
        for child in value:
            _positive_positions(child)


def _facts(document: dict[str, Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {}
    for family in _FAMILIES:
        facts[family] = []
        for item in rows(document[family]):
            selected = fcc.project_fact(family, item)
            if selected != item:
                raise RefreshError()
            _positive_positions(selected)
            facts[family].append(selected)
    if sum(len(values) for values in facts.values()) > MAX_RECORDS:
        raise RefreshError()
    ordinals = [
        row["derived_appendix_a_row_ordinal"] for family in ("named_entries", "category_rows") for row in facts[family]
    ]
    if set(ordinals) != set(range(1, len(ordinals) + 1)) or len(set(ordinals)) != len(ordinals):
        raise RefreshError()
    aliases: set[str] = set()
    for row in facts["named_entries"]:
        if (
            row["publisher_row_identifier_presence"] != "absent"
            or row["applicable_appendix_a_footnote_markers"] != ["*", "\u00b1"]
            or not row["names_source_literal"]
        ):
            raise RefreshError()
        for alias in row["names_source_literal"]:
            normalized = normalized_organization_name(alias)
            if not normalized or normalized in aliases:
                raise RefreshError()
            aliases.add(normalized)
    markers = [(row["appendix"], row["marker_source_literal"]) for row in facts["footnotes"]]
    if len(set(markers)) != len(markers):
        raise RefreshError()
    for family in ("named_entries", "category_rows"):
        for row in facts[family]:
            if row["publisher_row_identifier_presence"] != "absent" or not row["source_occurrences"]:
                raise RefreshError()
            for marker in row["applicable_appendix_a_footnote_markers"]:
                if ("A", marker) not in markers:
                    raise RefreshError()
    groups: dict[str, list[int]] = {}
    for row in facts["conditional_approvals"]:
        if row["publisher_row_identifier_presence"] != "absent" or not row["source_occurrences"]:
            raise RefreshError()
        groups.setdefault(row["category"], []).append(row["derived_category_row_ordinal"])
        approvals = rows(row["approval_groups"])
        if [group["derived_group_ordinal"] for group in approvals] != list(range(1, len(approvals) + 1)):
            raise RefreshError()
        for group in approvals:
            termination = obj(group["termination_component"])
            if termination.get("presence") == "empty":
                if set(termination) != {"presence", "source_literal"} or termination["source_literal"] != "":
                    raise RefreshError()
            elif termination.get("presence") == "present":
                if set(termination) != {"presence", "source_literal"} or not termination["source_literal"]:
                    raise RefreshError()
            else:
                raise RefreshError()
        if (
            "applicable_footnote" in row
            and (row["applicable_footnote"]["appendix"], row["applicable_footnote"]["marker_source_literal"])
            not in markers
        ):
            raise RefreshError()
    for ordinals in groups.values():
        if ordinals != list(range(1, len(ordinals) + 1)):
            raise RefreshError()
    return facts


def regenerate(document: object, tuple_input: dict[str, Any]) -> dict[str, Any]:
    """Validate the finite fact schema and construct a complete new envelope."""
    value = obj(native(document), _ROOT_KEYS)
    if (
        value["schema_version"] != "1"
        or value["registry"] != "fcc-covered-list"
        or value["source_kind"] != "reviewed_pdf_facts_v1"
        or value["query_scope"] != "named_organization_entries"
    ):
        raise RefreshError()
    binding = tuple_binding(tuple_input, "reviewed_pdf_facts_v1")
    hash_value(value["source_review_sha256"])
    text_value(value["literal_policy"])
    text_value(value["row_identity_policy"])
    if (
        value["appendix_a_column_headers_source_literal"] != _A_HEADERS
        or value["appendix_b_column_headers_source_literal"] != _B_HEADERS
    ):
        raise RefreshError()
    sources = rows(value["sources"], limit=3)
    if [obj(source).get("source_id") for source in sources] != ["DA 26-786", "DA 26-870", "DA 26-957"]:
        raise RefreshError()
    for source in sources:
        obj(source, _SOURCE_KEYS)
        for key in _SOURCE_KEYS - {"raw_bytes", "pdf_page_count", "publisher_cutoff"}:
            text_value(source[key])
        hash_value(source["raw_sha256"])
        count(source["raw_bytes"])
        if (
            count(source["pdf_page_count"], 10_000) < 1
            or source["publisher_version"] != source["source_id"]
            or source["media_type"] != "application/pdf"
        ):
            raise RefreshError()
        for key in ("captured_started_at", "captured_finished_at"):
            if datetime.fromisoformat(source[key]).utcoffset() is None:
                raise RefreshError()
        cutoff = obj(source["publisher_cutoff"], {"source_path", "literal", "representation"})
        if cutoff["representation"] != "source_text":
            raise RefreshError()
        for part in cutoff.values():
            text_value(part)
    snapshot_date = obj(value["snapshot_date"], {"derived_iso_date", "source_literal"})
    if (
        date.fromisoformat(text_value(snapshot_date["derived_iso_date"])).isoformat()
        != snapshot_date["derived_iso_date"]
        or snapshot_date["source_literal"] != sources[2]["publisher_cutoff"]["literal"]
    ):
        raise RefreshError()
    limits = obj(
        value["scope_limits"],
        {
            "category_applicability",
            "deployment_applicability",
            "indirect_affiliate_applicability",
            "later_currency",
            "legal_applicability",
            "named_no_match",
        },
    )
    for key, item in limits.items():
        text_value(item)
        if key not in {"named_no_match", "later_currency"} and item != "not_assessed":
            raise RefreshError()
    if limits["later_currency"] != "not_established":
        raise RefreshError()
    facts = _facts(value)
    manifest = {
        "as_of": {
            "basis": "selected_dated_snapshot",
            "date": snapshot_date["derived_iso_date"],
            "literal": snapshot_date["source_literal"],
            "representation": "source_text",
            "source_ids": ["DA 26-957"],
        },
        "column_headers": {
            "appendix_a": value["appendix_a_column_headers_source_literal"],
            "appendix_b": value["appendix_b_column_headers_source_literal"],
        },
        "query_scope": value["query_scope"],
        "scope_limits": limits,
        "source_occurrence_counts": {family: len(values) for family, values in facts.items()},
        "sources": sources,
    }
    return package("fcc-covered-list", binding, manifest, facts)


if __name__ == "__main__":
    raise SystemExit(main("fcc-covered-list", regenerate))
