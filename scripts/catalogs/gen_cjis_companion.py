"""Build the reviewed FBI CJIS 6.1 companion reference from a pinned text projection.

The default path needs no workbook parser or network. The projection preserves
physical cells and formatting metadata; actual merge anchors are resolved
separately. Reference units require entity and scenario tailoring. They do not
establish a complete policy import or an official requirement count.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

SOURCE_PATH = Path(__file__).parent / "sources/cjis-v6.1-source.json"
OUTPUT_PATH = (
    Path(__file__).resolve().parents[2]
    / "packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal/cjis-v6.1.json"
)
SOURCE_SHA256 = "11e8fe4f133cf83063730d2641b25cf20d611d1e3461650afd949800613db5e1"
PROJECTION_SHA256 = "fc220499282a43032e1315f1a221bd32ac5d60c479fa36bb2a83b0265204eb77"
SOURCE_URL = (
    "https://le.fbi.gov/cjis-division/cjis-security-policy-resource-center/requirements-companion-document-excel"
)
POLICY_URL = "https://le.fbi.gov/file-repository/cjis_security_policy_v6-1_20260625-1.pdf"
COLUMNS = tuple("ABCDEFGHIJKLMNOPQRSTUVWXY")
HEADER_VALUES = (
    (
        None,
        "Ver 4.5 Location",
        "Ver 5.0 Location and/or New Requirement/Date",
        "Ver 5.1 Location and/or New Requirement/Date",
        "Ver 5.2 Location and/or New Requirement/Date",
        "Ver 5.3 Location and New Requirement",
        "Ver 5.4 Location and New Requirement",
        "Ver 5.6 Location and New Requirement",
        "Ver 5.7 Location and New Requirement",
        "Ver 5.8 Location and New Requirement",
        "Ver 5.9 Location and New Requirement",
        "Ver 5.9.1 Location and New Requirement",
        "Ver 5.9.2 Location and New Requirement",
        "Ver 5.9.3 Location and New Requirement",
        "Ver 5.9.4 Location and New Requirement",
        "Ver 5.9.5 Location and New Requirement",
        "Ver 6.0 Location and New Requirement",
        "Ver 6.1 Location and New Requirement",
        "Title",
        "Shall Statement / Requirement",
        "Audit / Sanction Date",
        "Priority",
        "Agency Responsibility by Cloud Model",
        None,
        None,
    ),
    (None,) * 22 + ("IaaS", "PaaS", "SaaS"),
)
GROUP_ROWS = (
    3,
    63,
    73,
    205,
    288,
    355,
    450,
    520,
    579,
    926,
    975,
    1014,
    1038,
    1094,
    1142,
    1195,
    1235,
    1317,
    1377,
    1442,
    1460,
)
CLAUSES = {"3.2.2(1)", "3.2.2(2)", "3.2.2(3)"}
SOURCE_NOTES = {
    1464: (
        "T1464 preserves pre-80.11i. The primary policy says pre-802.11i on PDF page 288. "
        "Reviewed source difference; the companion text is unchanged."
    ),
    1514: (
        "T1514 preserves 5.20.8.1. The primary policy refers to 5.20.7.1 on PDF page 291. "
        "Reviewed source difference; the companion text is unchanged."
    ),
    1529: (
        "T1529 refers to Section 5.3 Incident Response, also present in the primary policy on PDF page 293. "
        "This inherited reference is flagged without claiming a verified correction."
    ),
}
SCOPE_NOTE = (
    "Companion reference only. Review the assessed actor, device, scenario and selected alternative before assessment. "
    "Applicability is unknown until that review; another actor's duty is not an automatic pass. "
    "Priority, audit dates and cloud responsibility do not select applicable requirements."
)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"Nonfinite JSON number: {value}")


def read_source(path: Path = SOURCE_PATH) -> dict[str, Any]:
    """Load a JSON projection without discarding duplicate object keys."""
    data = json.loads(
        path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant
    )
    if not isinstance(data, dict):
        raise ValueError("Source projection must be an object")
    return data


def _normalize_id(value: str) -> str:
    return re.sub(r"\(([^()]{1,16})\)", r".\1", value.strip().upper())


def _validate_source(source: dict[str, Any]) -> None:
    """Reject new editions, changed cells and unreviewed interpretation inputs."""
    try:
        _require(source["schema"] == "cjis-companion-source-v1", "Unexpected projection schema")
        _require(source["source_sha256"] == SOURCE_SHA256, "Unreviewed workbook hash")
        _require(source["source_bytes"] == 509453, "Unexpected workbook size")
        _require(source["version"] == "6.1" and source["published_on"] == "2026-06-25", "Unreviewed edition")
        _require(source["sheet"] == "v6.1" and source["dimensions"] == [1556, 25], "Unexpected sheet shape")
        _require(tuple(source["columns"]) == COLUMNS, "Unexpected column order")
        headers = source["headers"]
        _require([h["row"] for h in headers] == [1, 2], "Unexpected header rows")
        actual_headers = tuple(tuple(h["cells"][c][0] for c in COLUMNS) for h in headers)
        _require(actual_headers == HEADER_VALUES, "Unexpected exact worksheet headers")
        _require("W1:Y1" in source["merges"], "Cloud parent header must retain W1:Y1")
        _require(tuple(g["row"] for g in source["groups"]) == GROUP_ROWS, "Unexpected group rows")
        rows = source["rows"]
        row_numbers = [r["row"] for r in rows]
        _require(all(type(r) is int for r in row_numbers), "Worksheet rows must be strict integers")
        _require(len(set(row_numbers)) == len(row_numbers), "Duplicate physical source row")
        _require(row_numbers == [r for r in range(3, 1557) if r not in GROUP_ROWS], "Missing or reordered source rows")
        for record in rows:
            _require(tuple(record["cells"]) == COLUMNS, "Unexpected source cell columns")
            _require(
                all(isinstance(record["cells"][c], list) and len(record["cells"][c]) >= 4 for c in COLUMNS),
                "Malformed cell metadata",
            )
            _require(isinstance(record["cells"]["T"][0], str), "Statement must remain literal text")
        index = {r["row"]: r["cells"] for r in rows}
        _require("R233:R264" in source["merges"], "AT-3 interpretation requires the exact blank merge")
        _require(all(index[r]["R"][0] is None for r in range(233, 265)), "AT-3 interpretation requires original blanks")
        _require(
            index[1461]["R"][:3] == [5.2, "n", "0.00"], "5.20 interpretation requires numeric 5.2 with format 0.00"
        )
        _require(type(index[1461]["R"][0]) is float, "5.20 source scalar type changed")
        _require("R1461:R1463" in source["merges"], "5.20 interpretation requires its original merge")
        _require(
            index[40]["S"][0] == "CJIS System Agency Information Secrurity Officer (CSA ISO)",
            "CSA ISO title precondition changed",
        )
        _require(
            index[1312]["S"][0] == "(1)(3) DEVELOPMENT PROCESS, STANDARDS, AND TOOLS |CRITICALITY ANALYSIS",
            "SA-15(3) title precondition changed",
        )
        for row, token in ((1464, "pre-80.11i"), (1514, "5.20.8.1"), (1529, "Section 5.3 Incident Response")):
            _require(token in index[row]["T"][0], f"Source annotation precondition changed at T{row}")
        locations = source["locations"]
        _require(all(isinstance(n["id"], str) for n in locations), "Location IDs must be strings")
        identifiers = [_normalize_id(n["id"]) for n in locations]
        _require(
            len(locations) == 327 and len(set(identifiers)) == len(identifiers), "Duplicate or unexpected location IDs"
        )
        assigned = [r for n in locations for r in n["rows"]]
        _require(
            len(assigned) == 1533 and sorted(assigned) == row_numbers, "Rows must belong to exactly one source location"
        )
        _require(
            next(n["rows"] for n in locations if n["id"] == "AT-3") == list(range(228, 285)),
            "AT-3 row assignment changed",
        )
        scopes = source["reviewed_scopes"]
        _require(len(scopes) == 33 and len({s["location"] for s in scopes}) == 33, "Unexpected disposition scopes")
        _require(
            {s["location"] for s in scopes if s["reference_unit"] != s["location"]} == CLAUSES,
            "Unexpected clause grouping",
        )
        _require(
            all(s["reference_unit"] == "3.2.2" for s in scopes if s["location"] in CLAUSES),
            "CSO clauses must stay under 3.2.2",
        )
        _require(
            hashlib.sha256(_json(source).encode("ascii")).hexdigest() == PROJECTION_SHA256,
            "Projection content changed; a new source review is required",
        )
    except (KeyError, TypeError, IndexError, StopIteration) as exc:
        raise ValueError("Malformed CJIS source projection") from exc


def _merge_index(source: dict[str, Any]) -> dict[tuple[int, str], tuple[int, str, str]]:
    merges: dict[tuple[int, str], tuple[int, str, str]] = {}
    for area in source["merges"]:
        match = re.fullmatch(r"([A-Y])(\d+):([A-Y])(\d+)", area)
        if match is None:
            raise ValueError("Unexpected merged range")
        left, top, right, bottom = match.groups()
        for row in range(int(top), int(bottom) + 1):
            for col in COLUMNS[COLUMNS.index(left) : COLUMNS.index(right) + 1]:
                _require((row, col) not in merges, "Overlapping merged ranges")
                merges[row, col] = (int(top), left, area)
    return merges


def _column_labels() -> dict[str, str]:
    # The unlabeled column is retained with its coordinate as its display label.
    labels = {c: str(HEADER_VALUES[0][i]) for i, c in enumerate(COLUMNS)}
    labels.update({"A": "A (unlabeled)", "W": "IaaS", "X": "PaaS", "Y": "SaaS"})
    _require(len(set(labels.values())) == 25, "Duplicate source column labels")
    return labels


def _source_rows(source: dict[str, Any]) -> dict[int, dict[str, Any]]:
    labels = _column_labels()
    cells = {r["row"]: r["cells"] for r in source["headers"] + source["groups"] + source["rows"]}
    merges = _merge_index(source)
    groups = {g["row"]: g for g in source["groups"]}
    locations = {r: n for n in source["locations"] for r in n["rows"]}
    result = {}
    for raw in source["rows"]:
        row, physical = raw["row"], raw["cells"]
        location = locations[row]
        resolved = {}
        provenance = {
            "source_url": SOURCE_URL,
            "source_location": location["id"],
            "reference_unit": "3.2.2" if location["id"] in CLAUSES else location["id"],
            "source_group": groups[location["group_row"]]["heading"],
            "source_group_anchor": f"P{location['group_row']}",
            "columns": _json({label: col for col, label in labels.items()}),
            "cell_metadata": _json({col: physical[col][1:] for col in COLUMNS}),
            "cell_metadata_fields": "parsed_type,parsed_number_format,xml_style_id,optional_comment_or_hyperlink",
            "cloud_header": "IaaS=W2, PaaS=X2, SaaS=Y2; parent W1:Y1: Agency Responsibility by Cloud Model",
            "location_basis": (
                "Literal location or its actual merge anchor; whitespace removed from the display ID only"
            ),
        }
        for col in COLUMNS:
            if (row, col) not in merges:
                continue
            anchor_row, anchor_col, area = merges[row, col]
            label = labels[col]
            resolved[label] = cells[anchor_row][anchor_col][0]
            provenance[f"{label}.anchor"] = f"{anchor_col}{anchor_row}"
            provenance[f"{label}.merged_range"] = area
        if 233 <= row <= 264:
            provenance["location_basis"] = (
                "Reviewed AT-3 interpretation of the blank R233:R264 merge, bound to this workbook hash; "
                "primary policy PDF pages 61-62"
            )
        if 1461 <= row <= 1463:
            provenance["location_basis"] = (
                "Reviewed 5.20 display of numeric 5.2 with format 0.00 at R1461, bound to this workbook hash"
            )
        if row in SOURCE_NOTES:
            provenance["source_annotation"] = SOURCE_NOTES[row]
            provenance["annotation_source"] = POLICY_URL
        if row == 40:
            provenance["title_annotation"] = (
                "Display uses the primary TOC heading: CJIS Systems Agency Information Security Officer (CSA ISO). "
                "Raw S40 remains unchanged."
            )
            provenance["annotation_source"] = POLICY_URL
        if row == 1312:
            provenance["title_annotation"] = (
                "Display uses enhancement (3), confirmed by primary policy PDF page 254. Raw S1312 retains (1)(3)."
            )
            provenance["annotation_source"] = POLICY_URL
        result[row] = {
            "source_sha256": SOURCE_SHA256,
            "sheet": "v6.1",
            "row": row,
            "source_id": physical["R"][0],
            "source_id_format": physical["R"][2],
            "interpreted_id": location["id"],
            "kind": "fragment",
            "values": {labels[c]: physical[c][0] for c in COLUMNS},
            "resolved_values": resolved,
            "provenance": provenance,
        }
    return result


def _title(node: dict[str, Any]) -> str:
    if node["id"] == "3.2.8":
        return "CJIS Systems Agency Information Security Officer (CSA ISO)"
    if node["id"] == "SA-15(3)":
        return "DEVELOPMENT PROCESS, STANDARDS, AND TOOLS |CRITICALITY ANALYSIS"
    title = node["first_title"]
    _require(isinstance(title, str), f"Missing reviewed title for {node['id']}")
    if node["kind"] == "enhancement":
        marker = re.search(r"\(\d+\)$", node["id"])
        if marker and title.startswith(marker.group()):
            title = title[len(marker.group()) :].lstrip()
    return str(title)


def _summarize(rows: list[dict[str, Any]], label: str) -> tuple[str, str, list[Any]]:
    values: list[Any] = []
    for row in rows:
        value = row["resolved_values"].get(label, row["values"][label])
        if not any(type(value) is type(previous) and value == previous for previous in values):
            values.append(value)
    state = (
        "unknown"
        if values == [None]
        else "uniform"
        if len(values) == 1
        else "mixed-with-unknown"
        if None in values
        else "mixed"
    )
    return state, _json(values), values


def build_catalog(source: dict[str, Any]) -> dict[str, Any]:
    """Build a catalog without reading, writing or fetching external resources."""
    _validate_source(source)
    source_rows = _source_rows(source)
    nodes = {n["id"]: n for n in source["locations"]}
    ancestors = {n["id"]: n for n in source["structural_ancestors"]}
    all_nodes = nodes | ancestors
    family_names = {key: f"{key}: {node['title']}" for key, node in ancestors.items()}

    def structural_parent(node: dict[str, Any]) -> str | None:
        parent: str | None = node["parent"]
        while parent is not None and parent not in ancestors:
            parent = all_nodes[parent]["parent"]
        return parent

    hierarchy: dict[str, list[str]] = defaultdict(list)
    for node in ancestors.values():
        parent = structural_parent(node)
        if parent is not None:
            hierarchy[family_names[parent]].append(family_names[node["id"]])
    scopes = {s["location"]: s["scope"] for s in source["reviewed_scopes"]}
    unit_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in source_rows.values():
        unit_rows[row["provenance"]["reference_unit"]].append(row)
    controls: list[dict[str, Any]] = []
    for ident, rows in unit_rows.items():
        node = nodes[ident]
        parent = structural_parent(node)
        _require(parent is not None, f"Missing structural family for {ident}")
        properties = {
            "source_url": SOURCE_URL,
            "source_parent": node["parent"],
            "source_unit_kind": node["kind"],
            "source_fragment_count": str(len(rows)),
            "applicability": "unknown; entity and scenario review required",
            "published_on": "2026-06-25",
        }
        priority = None
        for key, label in (
            ("audit_sanction", "Audit / Sanction Date"),
            ("priority", "Priority"),
            ("iaas", "IaaS"),
            ("paas", "PaaS"),
            ("saas", "SaaS"),
        ):
            state, raw_values, values = _summarize(rows, label)
            properties[f"{key}_state"] = state
            properties[f"{key}_source_values"] = raw_values
            if key == "priority" and state == "uniform" and isinstance(values[0], str):
                priority = values[0]
        controls.append(
            {
                "id": ident,
                "title": _title(node),
                "description": "\n\n".join(row["values"]["Shall Statement / Requirement"] for row in rows),
                "guidance": " ".join(filter(None, (scopes.get(ident), SCOPE_NOTE))),
                "family": family_names[parent],
                "ordering": rows[0]["row"],
                "tier": "A",
                "priority": priority,
                "properties": properties,
                "source_rows": rows,
            }
        )
    _require(len(controls) == 324, "Unexpected reference-unit count")
    _require(len({_normalize_id(c["id"]) for c in controls}) == 324, "Normalized reference IDs collide")
    return {
        "framework_id": "cjis-v6.1",
        "framework_name": "FBI CJIS Security Policy v6.1 - Requirements Companion Reference",
        "version": "6.1",
        "source": SOURCE_URL,
        "controls": controls,
        "families": list(family_names.values()),
        "family_hierarchy": dict(hierarchy),
        "tier": "A",
        "status": "current",
        "verified_on": "2026-09-09",
        "license_terms": (
            "Government-authored FBI companion text with source attribution. FBI policy section 1.5 permits sharing "
            "version 6.0 and later. This classification does not cover separately copyrighted third-party material, "
            "seals or logos. Referenced third-party standards and workbook artwork are not included."
        ),
        "license_url": "https://www.justice.gov/legalpolicies",
        "notes": (
            "Companion edition 6.1, published 2026-06-25. The 20260723 filename is not the edition date. "
            "Retains 1,533 physical statement fragments in 324 reference units: 294 modern control/enhancement "
            "addresses and 30 numeric sections. The three CSO clause addresses remain under 3.2.2; 27 structural "
            "ancestors are navigation metadata only. These are implementation groupings, not an official FBI "
            "requirement count or a universal assessment denominator. Ordered context, role qualifications, "
            "alternatives, exceptions, table fragments and source omissions are retained. Full policy prose, "
            "discussion and appendices are outside this companion import. No automatic assessment migration "
            "from cjis-v6 or automatic applicability determination is performed. " + SCOPE_NOTE
        ),
        "audit_contexts": {
            "US-TX": {
                "authority": "Texas Department of Public Safety",
                "version": "5.9.5",
                "source_url": "https://www.dps.texas.gov/section/crime-records/cjis-documents",
                "verified_on": "2026-09-09",
                "valid_through": "2027-03-31",
                "notes": (
                    "Texas CJIS audits through this date use 5.9.5. "
                    "The following Texas period and other CSAs remain unknown. "
                    "Publication currency does not determine audit applicability."
                ),
            },
        },
    }


def _render(catalog: dict[str, Any]) -> str:
    return json.dumps(catalog, ensure_ascii=True, indent=2, allow_nan=False) + "\n"


def generate(source_path: Path = SOURCE_PATH, output_path: Path = OUTPUT_PATH) -> Path:
    """Write only the requested catalog after the full source contract passes."""
    if source_path.resolve() == output_path.resolve() or (output_path.exists() and source_path.samefile(output_path)):
        raise ValueError("Source and output refer to the same file")
    catalog = build_catalog(read_source(source_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(_render(catalog), encoding="utf-8", newline="\n")
    return output_path


def main(argv: list[str] | None = None) -> int:
    """Generate or check the selected output without fetching source material."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE_PATH)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--check", action="store_true", help="Compare the selected output without writing files")
    args = parser.parse_args(argv)
    try:
        if args.check:
            expected = _render(build_catalog(read_source(args.source))).encode("utf-8")
            actual = args.output.read_bytes().replace(b"\r\n", b"\n")
            if actual != expected:
                print(f"CJIS catalog differs from the reviewed source: {args.output}", file=sys.stderr)
                return 1
            print(f"CJIS catalog matches the reviewed source: {args.output}")
            return 0
        output = generate(args.source, args.output)
    except (OSError, ValueError) as exc:
        print(f"CJIS generation failed: {exc}", file=sys.stderr)
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
