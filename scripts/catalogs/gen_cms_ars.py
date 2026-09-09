"""Generate CMS ARS 5.2 from the reviewed, pinned worksheet cell projection.

Default generation is offline and does not require a workbook parser. The source
JSON retains cell types, formats, styles and annotations; its workbook hash names
the separately archived original. Source rows preserve exact parsed values while
aggregate descriptions and guidance remain ordinary catalog presentation fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from evidentia_core.models.catalog import CatalogSourceRow, ControlCatalog, _normalize_control_id

ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = Path(__file__).parent / "sources/cms-ars-5.2-source.json"
OUTPUT_PATH = ROOT / "packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal/cms-ars-5.2.json"
SOURCE_PROJECTION = "scripts/catalogs/sources/cms-ars-5.2-source.json"
SOURCE_SHA256 = "6d7881b1c186aa1df10b3e91dd7c7287b030f7aa8e61390ca83d08117987a444"
PROJECTION_SHA256 = "3de2ba8b263cd5a1d00fa6c4f16368275afdc000937ed12bb774d86fb770aa8c"
SCHEMA_VERSION = "cms-ars-cells-v1"
HEADERS = (
    "Control Family",
    "Control Number",
    "Control Name",
    "Control Statement",
    "Control Review Frequency",
    "Assessment Frequency",
    "CMS Baseline",
    "MAC ARS",
    "HVA Overlay",
    "FTI Overlay",
    "CMS Discussion\n",
    "Priority",
    "Related Controls",
    "Reference Policy",
)
SOURCE_IDENTITY = {
    "url": "https://www.cms.gov/files/document/acceptable-risk-safeguards-5-2.xlsx",
    "sha256": SOURCE_SHA256,
    "bytes": 432804,
    "sheet": "ARS 5.2",
    "edition": "5.2",
    "edition_date": "2026-07-01",
    "publisher_reviewed_on": "2026-07-16",
    "verified_on": "2026-09-09",
    "currency_url": "https://security.cms.gov/policy-guidance/cms-acceptable-risk-safeguards-ars",
    "license_url": "https://www.cms.gov/about-cms/web-policies-important-links/about-website/link-to-us",
}
ID_INTERPRETATIONS = {
    823: ("MA04(04)a", "MA-04(04)a"),
    824: ("MA04(04)b", "MA-04(04)b"),
    1654: ("SR04(04)", "SR-04(04)"),
}
_BASE = re.compile(r"[A-Z]{2}-\d{2}")
_ENHANCEMENT = re.compile(r"([A-Z]{2}-\d{2})\(\d{2}\)")
_CLAUSE = re.compile(r"([A-Z]{2}-\d{2}(?:\(\d{2}\))?)[a-z]+")


def _checksum(value: object) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def load_source(path: Path = SOURCE_PATH) -> dict[str, Any]:
    """Read a JSON cell projection; validation happens in the pure builder."""
    source: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(source, dict):
        raise ValueError("CMS source projection must be an object")
    return source


def _interpret_id(source_id: str, row: int) -> tuple[str, str, str | None]:
    interpreted = source_id
    if row in ID_INTERPRETATIONS:
        expected, interpreted = ID_INTERPRETATIONS[row]
        if source_id != expected:
            raise ValueError(f"CMS identifier repair precondition failed at row {row}")
    elif source_id in {old for old, _ in ID_INTERPRETATIONS.values()}:
        raise ValueError(f"CMS identifier repair precondition failed at row {row}")
    if _BASE.fullmatch(interpreted):
        return interpreted, "base", None
    enhancement = _ENHANCEMENT.fullmatch(interpreted)
    if enhancement:
        return interpreted, "enhancement", enhancement.group(1)
    clause = _CLAUSE.fullmatch(interpreted)
    if clause:
        return interpreted, "clause", clause.group(1)
    raise ValueError(f"Unsupported source ID at row {row}: {source_id!r}")


def _validate_projection(source: dict[str, Any]) -> list[dict[str, Any]]:
    expected_keys = {
        "schema_version",
        "source",
        "headers",
        "header_cell_metadata",
        "sheet_metadata",
        "rows",
        "cell_annotations",
    }
    if set(source) != expected_keys:
        raise ValueError("Unexpected CMS source projection fields")
    if source["schema_version"] != SCHEMA_VERSION:
        raise ValueError("Unsupported CMS source schema version")
    if source["source"] != SOURCE_IDENTITY:
        raise ValueError("CMS source identity differs from the reviewed workbook")
    if source["headers"] != list(HEADERS):
        raise ValueError("CMS source headers must be the 14 exact, unique reviewed headers")
    rows = source["rows"]
    if not isinstance(rows, list) or len(rows) != 1681:
        raise ValueError("CMS source must contain all 1681 physical data rows")
    records: list[dict[str, Any]] = []
    normalized_ids: set[str] = set()
    raw_ids: set[str] = set()
    for expected_row, row in enumerate(rows, start=2):
        if not isinstance(row, dict) or set(row) != {"row", "values", "data_types", "number_formats", "style_ids"}:
            raise ValueError("Unexpected CMS source row fields")
        if type(row["row"]) is not int or row["row"] != expected_row:
            raise ValueError("CMS physical row sequence must be exactly 2 through 1682")
        for field in ("values", "data_types", "number_formats", "style_ids"):
            if not isinstance(row[field], list) or len(row[field]) != 14:
                raise ValueError(f"CMS row {expected_row} must retain all 14 cells and metadata entries")
        values = row["values"]
        if any(type(value) not in (str, type(None)) for value in values):
            raise ValueError("CMS cell values differ from the pinned string/null source types")
        expected_types = ["s" if value is not None else "n" for value in values]
        if row["data_types"] != expected_types:
            raise ValueError("CMS cell data types differ from the formula-free reviewed source")
        if any(not isinstance(value, str) for value in row["number_formats"]):
            raise ValueError("CMS cell number formats must remain literal strings")
        if any(type(value) is not int or value < 0 for value in row["style_ids"]):
            raise ValueError("CMS cell style identifiers must remain nonnegative integers")
        source_id = values[1]
        if not isinstance(source_id, str):
            raise ValueError(f"Unsupported source ID at row {expected_row}: {source_id!r}")
        interpreted, kind, parent = _interpret_id(source_id, expected_row)
        normalized = _normalize_control_id(interpreted)
        if source_id in raw_ids or normalized in normalized_ids:
            raise ValueError(f"CMS duplicate source or normalized ID at row {expected_row}")
        raw_ids.add(source_id)
        normalized_ids.add(normalized)
        records.append({"source": row, "id": interpreted, "source_id": source_id, "kind": kind, "parent_id": parent})
    aggregate_ids = {record["id"] for record in records if record["kind"] != "clause"}
    for record in records:
        if record["kind"] == "clause" and record["parent_id"] not in aggregate_ids:
            raise ValueError(f"Missing aggregate for CMS clause {record['source_id']!r}")
    if Counter(record["kind"] for record in records) != {"base": 243, "enhancement": 362, "clause": 1076}:
        raise ValueError("CMS aggregate and clause counts differ from the reviewed source")
    if _checksum(source) != PROJECTION_SHA256:
        raise ValueError("CMS source projection checksum differs from the reviewed cell and metadata snapshot")
    return records


def _source_row(record: dict[str, Any], aggregate_id: str, annotations: list[dict[str, Any]]) -> dict[str, Any]:
    raw = record["source"]
    row_number = raw["row"]
    provenance = {
        "source_projection": SOURCE_PROJECTION,
        "source_schema": SCHEMA_VERSION,
        "source_cells": f"A{row_number}:N{row_number}",
        "source_record_kind": record["kind"],
        "aggregate_id": aggregate_id,
    }
    if record["parent_id"] is not None:
        provenance["source_parent_id"] = record["parent_id"]
    for annotation in annotations:
        if re.fullmatch(rf"[A-N]{row_number}", annotation["cell"]) is None:
            continue
        link = annotation["hyperlink"]
        if link is not None:
            for key, value in link.items():
                if value is not None:
                    provenance[f"{annotation['cell']}.hyperlink.{key}"] = value
        comment = annotation["comment"]
        if comment is not None:
            for key, value in comment.items():
                provenance[f"{annotation['cell']}.comment.{key}"] = value
    row = CatalogSourceRow(
        source_sha256=SOURCE_SHA256,
        sheet="ARS 5.2",
        row=row_number,
        source_id=record["source_id"],
        source_id_format=raw["number_formats"][1],
        interpreted_id=record["id"] if record["id"] != record["source_id"] else None,
        kind="clause" if record["kind"] == "clause" else "aggregate",
        values=dict(zip(HEADERS, raw["values"], strict=True)),
        provenance=provenance,
    )
    return row.model_dump(mode="json")


def build_catalog(source: dict[str, Any]) -> dict[str, Any]:
    """Build the full reviewed reference catalog without reads, writes or inference."""
    records = _validate_projection(source)
    aggregate_records = [record for record in records if record["kind"] != "clause"]
    aggregate_ids = {record["id"] for record in aggregate_records}
    clauses: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        if record["kind"] == "clause":
            clauses.setdefault(record["parent_id"], []).append(record)
    controls = []
    for record in aggregate_records:
        raw = record["source"]
        values = raw["values"]
        properties = {"source_record_kind": record["kind"], "source_projection": SOURCE_PROJECTION}
        if record["parent_id"] is not None:
            properties["source_parent_id"] = record["parent_id"]
            properties["source_parent_present"] = str(record["parent_id"] in aggregate_ids).lower()
        source_rows = [_source_row(record, record["id"], source["cell_annotations"])]
        source_rows.extend(
            _source_row(clause, record["id"], source["cell_annotations"]) for clause in clauses.get(record["id"], [])
        )
        controls.append(
            {
                "id": record["id"],
                "title": values[2],
                "description": values[3],
                "family": values[0],
                "guidance": values[10],
                "priority": values[11],
                "ordering": raw["row"],
                "properties": properties,
                "source_rows": source_rows,
            }
        )
    result: dict[str, Any] = {
        "framework_id": "cms-ars-5.2",
        "framework_name": "CMS Acceptable Risk Safeguards (ARS) 5.2",
        "version": "5.2",
        "source": SOURCE_IDENTITY["url"],
        "tier": "A",
        "category": "control",
        "placeholder": False,
        "license_required": False,
        "status": "current",
        "verified_on": SOURCE_IDENTITY["verified_on"],
        "license_url": SOURCE_IDENTITY["license_url"],
        "license_terms": (
            "CMS-authored text is treated as U.S. government material with attribution. "
            "Referenced third-party standards and workbook artwork are not bundled. "
            "This does not claim a universal public-domain or CC0 grant."
        ),
        "notes": (
            "CMS ARS 5.2 edition dated 2026-07-01, publisher review 2026-07-16. "
            "Complete A2:N1682 cell projection: 605 aggregate reference controls and enhancements, "
            "with 1076 clause records retained as source evidence. The 605 count describes the "
            "imported workbook; it is not a universal assessment scope. CMS Baseline, MAC ARS, "
            "HVA Overlay, FTI Overlay and priorities remain independent source values. Blank values "
            "are unknown and do not inherit applicability. Select the appropriate CMS and organization "
            "scope before assessment; this is not a blanket requirement for every hospital. "
            "Three documented identifier interpretations preserve the original values. No automatic "
            "mapping from historical CMS-* IDs or NIST equivalence is asserted. Source hyperlinks "
            "are retained without fetching their targets. Raw source rows preserve whitespace; "
            "presentation fields use existing catalog model behavior. Workbook SHA-256: "
            f"{SOURCE_SHA256}. Source projection: {SOURCE_PROJECTION}."
        ),
        "families": list(dict.fromkeys(control["family"] for control in controls)),
        "controls": controls,
    }
    ControlCatalog.model_validate(result)
    return result


def generate(*, source_path: Path = SOURCE_PATH, output_path: Path = OUTPUT_PATH, check: bool = False) -> bool:
    """Write only the chosen catalog, or compare checkout-normalized bytes."""
    if source_path.resolve() == output_path.resolve() or (output_path.exists() and source_path.samefile(output_path)):
        raise ValueError("CMS input and output paths must differ")
    catalog = build_catalog(load_source(source_path))
    text = json.dumps(catalog, ensure_ascii=True, indent=2, allow_nan=False) + "\n"
    if check:
        return output_path.is_file() and output_path.read_bytes().replace(b"\r\n", b"\n") == text.encode("ascii")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8", newline="\n")
    return True


def main(argv: list[str] | None = None) -> int:
    """Generate or verify the reviewed catalog using explicit input/output paths."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=SOURCE_PATH, help="Reviewed CMS cell projection JSON")
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH, help="Catalog JSON destination")
    parser.add_argument("--check", action="store_true", help="Compare without writing files")
    args = parser.parse_args(argv)
    try:
        matches = generate(source_path=args.source, output_path=args.output, check=args.check)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"CMS ARS generation failed: {exc}\n")
    if not matches:
        print(f"CMS ARS catalog differs: {args.output}")
        return 1
    print(f"CMS ARS catalog {'verified' if args.check else 'generated'}: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
