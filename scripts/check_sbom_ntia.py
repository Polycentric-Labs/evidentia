"""NTIA minimum-elements gate for the release-asset CycloneDX SBOM (H4).

Fails the release build when the generated + enriched release SBOM
(``evidentia-sbom.cdx.json``) is structurally present but useless — the
"SBOM theater" failure mode: a file ships, but a consumer's tooling can't
identify who supplied what at which version.

Checks the NTIA minimum elements (NTIA "The Minimum Elements For a
Software Bill of Materials", 2021-07-12) as they map onto CycloneDX JSON:

HARD (exit 1):
  1. Author of SBOM data  — ``metadata.supplier.name`` or
     ``metadata.authors`` non-empty.
  2. Timestamp            — ``metadata.timestamp`` present.
  3. Supplier name        — ``metadata.supplier.name`` present, and every
     FIRST-PARTY (evidentia*) component + the root component carries a
     ``supplier.name`` (the identity this project actually controls).
  4. Component name       — every component has ``name``.
  5. Component version    — every component has ``version``.
  6. Other unique IDs     — every component has a ``purl``.
  7. Dependency relationship — top-level ``dependencies`` non-empty.

ADVISORY (reported, never fails):
  - Third-party components missing ``supplier`` — PyPI packaging metadata
    carries no supplier identity, so cyclonedx-py cannot populate it and
    inventing one would be fabrication. The unique ID (purl) + complete
    dependency graph are the elements a consumer's tooling resolves those
    components by. Reported as a count so the gap stays visible.

Why a first-party checker instead of the planned ``ntia-conformance-
checker``: that tool is SPDX-only ("Check SPDX SBOM for NTIA minimum
elements", v5.0.3 PyPI metadata, verified 2026-07-10) and cannot parse
this project's CycloneDX SBOMs. The alternative third-party checker
(interlynk-io/sbomqs, a Go binary) would add a new pinned supply-chain
dependency for what is a fixed, documented list of deterministic JSON
assertions — the same trade this repo already makes with its other
first-party gate scripts. Swap for sbomqs later if an external
conformance stamp becomes worth the dependency.

Stdlib only. Usage: python scripts/check_sbom_ntia.py <sbom.cdx.json>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _is_first_party(component: dict) -> bool:
    name = component.get("name", "")
    return name == "evidentia" or name.startswith("evidentia-")


def check(doc: dict) -> tuple[list[str], list[str]]:
    """Return (hard_failures, advisories) for the NTIA minimum elements."""
    failures: list[str] = []
    advisories: list[str] = []

    metadata = doc.get("metadata", {})

    # 1. Author of SBOM data.
    supplier_name = (metadata.get("supplier") or {}).get("name")
    authors = metadata.get("authors") or []
    if not supplier_name and not authors:
        failures.append("metadata.supplier.name / metadata.authors missing — no SBOM author")

    # 2. Timestamp.
    if not metadata.get("timestamp"):
        failures.append("metadata.timestamp missing")

    # 3. Supplier name (document-level + the identity we control).
    if not supplier_name:
        failures.append("metadata.supplier.name missing")

    components = list(doc.get("components", []))
    root = metadata.get("component")
    labeled: list[tuple[str, dict]] = []
    if isinstance(root, dict):
        labeled.append(("(root)", root))
    labeled.extend(("", c) for c in components)

    third_party_missing_supplier = 0
    for label, comp in labeled:
        name = comp.get("name")
        where = f"{label} {name or comp.get('bom-ref', '<unnamed>')}".strip()
        # 4. Component name.
        if not name:
            failures.append(f"component {where}: name missing")
        # 5. Component version.
        if not comp.get("version"):
            failures.append(f"component {where}: version missing")
        # 6. Unique ID.
        if not comp.get("purl"):
            failures.append(f"component {where}: purl (unique ID) missing")
        # 3. Supplier — hard for first-party + root, advisory for third-party.
        has_supplier = bool((comp.get("supplier") or {}).get("name"))
        if label == "(root)" or _is_first_party(comp):
            if not has_supplier:
                failures.append(f"component {where}: supplier missing (first-party)")
        elif not has_supplier:
            third_party_missing_supplier += 1

    # 7. Dependency relationships.
    if not doc.get("dependencies"):
        failures.append("top-level dependencies array missing/empty")

    if third_party_missing_supplier:
        advisories.append(
            f"{third_party_missing_supplier} third-party component(s) carry no "
            "supplier (PyPI metadata has none; identified by purl instead)"
        )
    return failures, advisories


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", help="path to the CycloneDX JSON SBOM to check")
    args = parser.parse_args(argv)

    path = Path(args.sbom)
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERROR: cannot read SBOM {path}: {exc}", file=sys.stderr)
        return 1
    if doc.get("bomFormat") != "CycloneDX":
        print(f"ERROR: {path} is not a CycloneDX SBOM", file=sys.stderr)
        return 1

    failures, advisories = check(doc)
    n_components = len(doc.get("components", []))
    for adv in advisories:
        print(f"ADVISORY: {adv}")
    if failures:
        print(
            f"NTIA GATE: FAIL — {len(failures)} finding(s) across {n_components} components:",
            file=sys.stderr,
        )
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print(
        f"NTIA GATE: PASS — {n_components} components carry name/version/purl; "
        "supplier + author + timestamp + dependency graph present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
