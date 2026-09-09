"""Generate dated CISA, Swift, and CMMC heading catalogs from reviewed inputs.

The compact input records publisher IDs, short headings, and provenance. It
contains no vendor control body text. Imports never write catalog files.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import _generators as helpers

SOURCE_PATH = Path(__file__).resolve().parent / "sources" / "currency-headings.json"
FRAMEWORK_IDS = ("cisa-cpgs", "swift-cscf-2024", "swift-cscf-2026", "cmmc-2-l1")


def load_definitions() -> list[dict[str, Any]]:
    """Read and validate the entire input before any catalog is emitted."""
    data = json.loads(SOURCE_PATH.read_text(encoding="utf-8"))
    definitions = data.get("catalogs") if isinstance(data, dict) else None
    if not isinstance(definitions, list):
        raise ValueError("currency heading input must contain a catalogs list")
    frameworks: set[str] = set()
    for definition in definitions:
        if not isinstance(definition, dict) or not isinstance(definition.get("metadata"), dict):
            raise ValueError("currency heading catalog must contain metadata")
        metadata = definition["metadata"]
        framework_id = metadata.get("framework_id")
        if framework_id not in FRAMEWORK_IDS or framework_id in frameworks:
            raise ValueError(f"unexpected or duplicate framework ID: {framework_id}")
        frameworks.add(framework_id)
        families = metadata.get("families")
        if not isinstance(families, list) or not all(isinstance(family, str) and family for family in families):
            raise ValueError(f"{framework_id}: families must be nonempty strings")
        if len(families) != len(set(families)):
            raise ValueError(f"{framework_id}: duplicate family")
        if metadata.get("tier") not in {"A", "C"}:
            raise ValueError(f"{framework_id}: expected redistribution tier A or C")
        controls = definition.get("controls")
        if not isinstance(controls, list) or not controls:
            raise ValueError(f"{framework_id}: controls must be a nonempty list")
        control_ids: set[str] = set()
        for row in controls:
            if not isinstance(row, dict) or not all(
                isinstance(row.get(key), str) and row[key] for key in ("id", "title", "family")
            ):
                raise ValueError(f"{framework_id}: each control requires an ID, title, and family")
            if row["id"] in control_ids:
                raise ValueError(f"{framework_id}: duplicate control ID: {row['id']}")
            control_ids.add(row["id"])
            if row["family"] not in families:
                raise ValueError(f"{framework_id}: undeclared family: {row['family']}")
            if set(row) - {"id", "title", "family", "properties"}:
                raise ValueError(f"{framework_id}: only heading fields and properties are allowed")
            properties = row.get("properties", {})
            if not isinstance(properties, dict) or not all(
                isinstance(key, str) and isinstance(value, str) for key, value in properties.items()
            ):
                raise ValueError(f"{framework_id}: control properties must be strings")
    if frameworks != set(FRAMEWORK_IDS):
        raise ValueError("currency heading input must contain all four catalog definitions")
    return definitions


def _generate(framework_ids: tuple[str, ...], output_dir: Path | None) -> list[Path]:
    """Emit only the requested catalog definitions into the selected data root."""
    definitions = {definition["metadata"]["framework_id"]: definition for definition in load_definitions()}
    paths = []
    for framework_id in framework_ids:
        definition = definitions[framework_id]
        metadata = dict(definition["metadata"])
        controls = []
        for row in definition["controls"]:
            if metadata["tier"] == "C":
                if framework_id == "swift-cscf-2024":
                    # Preserve the previously bundled placeholder and row fields exactly.
                    control = helpers.make_stub_control(row["id"], row["title"], row["family"], metadata["license_url"])
                else:
                    control = helpers.make_stub_control(
                        row["id"],
                        row["title"],
                        row["family"],
                        metadata["license_url"],
                        placeholder_text="[Licensed content. See license_url for authoritative text.]",
                    )
            else:
                control = {"id": row["id"], "title": row["title"], "description": row["title"], "family": row["family"]}
            if row.get("properties"):
                control["properties"] = dict(row["properties"])
            controls.append(control)
        if output_dir is not None:
            partition = "stubs" if metadata["tier"] == "C" else "us-federal"
            metadata["subdir"] = str((output_dir / partition).resolve())
        paths.append(helpers.emit_control_catalog(controls=controls, **metadata))
    return paths


def generate_cisa_catalog(*, output_dir: Path | None = None) -> list[Path]:
    """Generate the CISA CPG 2.0 heading catalog."""
    return _generate(("cisa-cpgs",), output_dir)


def generate_swift_catalogs(*, output_dir: Path | None = None) -> list[Path]:
    """Retain the historical Swift table and add the verified v2026 headings."""
    return _generate(("swift-cscf-2024", "swift-cscf-2026"), output_dir)


def generate_cmmc_level1(*, output_dir: Path | None = None) -> list[Path]:
    """Generate the 15 FAR-based CMMC Level 1 requirement headings."""
    return _generate(("cmmc-2-l1",), output_dir)


def main() -> None:
    """Regenerate these four catalogs, optionally under an isolated data root."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir", type=Path, help="Write under this data root instead of the bundled catalog directory"
    )
    args = parser.parse_args()
    for path in _generate(FRAMEWORK_IDS, args.output_dir):
        print(path)


if __name__ == "__main__":
    main()
