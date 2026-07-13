"""Enrich the release-asset CycloneDX SBOM with first-party identity (#17).

``cyclonedx-py environment`` (release.yml "Generate CycloneDX SBOM") emits
an SBOM whose FIRST-PARTY surface is anonymous: no ``metadata.supplier``,
and the workspace's own ``evidentia*`` components carry no ``purl`` (the
local-wheel install path yields no registry metadata), so the 8 first-party
packages look like opaque local artifacts — osv-scanner even reports
"Neither CPE nor PURL found" for each of them and skips them entirely
(observed against the published v0.10.17 SBOM). Third-party components are
fine (purl + version from PyPI metadata).

This script post-processes the generated SBOM in place, deterministically:

- ``metadata.supplier`` + ``metadata.authors`` — Polycentric Labs (the
  same SUPPLIER identity ``gen_package_sboms.py`` stamps into the PEP 770
  per-wheel SBOMs, so the two SBOM surfaces agree).
- ``metadata.component`` (the root) and every ``evidentia*`` component:
  ``supplier``, ``publisher``, a ``pkg:pypi/<name>@<version>`` purl, and a
  ``vcs`` external reference to the canonical repo (added only if absent).

Pedigree/evidence enrichment was considered and deliberately skipped:
CycloneDX ``pedigree`` describes ancestry/variant lineage, which these
first-party components do not have; the SLSA provenance attestation
already binds the wheels to repo + commit, and a decorative pedigree block
would claim lineage data we do not track. The substantive #17 gap is
supplier + unique-ID (purl), which this closes.

Stdlib only. Usage: python scripts/enrich_release_sbom.py <sbom.cdx.json>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SUPPLIER = {"name": "Polycentric Labs", "url": ["https://polycentriclabs.com"]}
PUBLISHER = "Polycentric Labs"
REPO_URL = "https://github.com/Polycentric-Labs/evidentia"


def _is_first_party(component: dict) -> bool:
    name = component.get("name", "")
    return name == "evidentia" or name.startswith("evidentia-")


def _enrich_component(component: dict) -> list[str]:
    """Add supplier/publisher/purl/vcs-ref to one first-party component.

    Returns the list of field names actually added (idempotent: existing
    values are never overwritten, so re-running is a no-op).
    """
    added: list[str] = []
    if not component.get("supplier"):
        component["supplier"] = SUPPLIER
        added.append("supplier")
    if not component.get("publisher"):
        component["publisher"] = PUBLISHER
        added.append("publisher")
    name = component.get("name")
    version = component.get("version")
    if not component.get("purl") and name and version:
        component["purl"] = f"pkg:pypi/{name}@{version}"
        added.append("purl")
    refs = component.setdefault("externalReferences", [])
    if not any(r.get("type") == "vcs" for r in refs):
        refs.append({"type": "vcs", "url": REPO_URL})
        added.append("vcs-ref")
    return added


def enrich(doc: dict) -> dict[str, list[str]]:
    """Enrich ``doc`` in place; return {component-name: [fields added]}."""
    report: dict[str, list[str]] = {}
    metadata = doc.setdefault("metadata", {})
    doc_added: list[str] = []
    if not metadata.get("supplier"):
        metadata["supplier"] = SUPPLIER
        doc_added.append("metadata.supplier")
    if not metadata.get("authors"):
        metadata["authors"] = [{"name": PUBLISHER}]
        doc_added.append("metadata.authors")
    if doc_added:
        report["(document)"] = doc_added

    root = metadata.get("component")
    if isinstance(root, dict):
        added = _enrich_component(root)
        if added:
            report[f"(root) {root.get('name', '?')}"] = added

    for component in doc.get("components", []):
        if _is_first_party(component):
            added = _enrich_component(component)
            if added:
                report[component.get("name", "?")] = added
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", help="path to the CycloneDX JSON SBOM to enrich")
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

    report = enrich(doc)
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if report:
        for name, fields in sorted(report.items()):
            print(f"enriched {name}: {', '.join(fields)}")
    else:
        print("SBOM already fully enriched (no-op).")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
