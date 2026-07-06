"""Generate deterministic per-package CycloneDX SBOMs (PEP 770).

Writes packages/<dir>/sbom/<name>.cdx.json for every workspace package.
Included into each wheel's .dist-info/sboms/ by the hatchling config
(see per-package pyproject.toml). Deterministic by construction:
serialNumber is a UUIDv5 over the purl, timestamp only appears when
SOURCE_DATE_EPOCH is set, and JSON is dumped with sorted keys — so the
release double-build reproducibility gate stays byte-stable.

Stdlib only. Usage: python scripts/gen_package_sboms.py [--only NAME]
[--out-root DIR (tests)].
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - py<3.11 unsupported anyway
    sys.exit("python >= 3.11 required (tomllib)")

REPO_ROOT = Path(__file__).resolve().parents[1]
SUPPLIER = {"name": "Polycentric Labs", "url": ["https://polycentriclabs.com"]}


def discover_packages(root: Path) -> list[dict]:
    """Read every packages/*/pyproject.toml into {name, version, deps, dir}."""
    out: list[dict] = []
    for pyproj in sorted((root / "packages").glob("*/pyproject.toml")):
        if pyproj.parent.name == "evidentia-ui":
            continue  # npm package, not a wheel
        data = tomllib.loads(pyproj.read_text(encoding="utf-8"))
        proj = data.get("project", {})
        if "name" not in proj:
            continue
        deps = list(proj.get("dependencies", []))
        for extra_deps in proj.get("optional-dependencies", {}).values():
            deps.extend(extra_deps)
        out.append(
            {
                "name": proj["name"],
                "version": proj["version"],
                "dependencies": deps,
                "dir": pyproj.parent,
            }
        )
    return out


def _dep_name(requirement: str) -> str:
    """'litellm>=1.83.7,<2.0' -> 'litellm'; handles extras + env markers."""
    base = requirement.split(";")[0].strip()
    for sep in ("[", ">", "<", "=", "!", "~", " "):
        idx = base.find(sep)
        if idx != -1:
            base = base[:idx]
    return base.strip()


def build_sbom(pkg: dict) -> dict:
    purl = f"pkg:pypi/{pkg['name']}@{pkg['version']}"
    bom_ref = purl
    metadata: dict = {
        "supplier": SUPPLIER,
        "component": {
            "type": "library",
            "bom-ref": bom_ref,
            "name": pkg["name"],
            "version": pkg["version"],
            "purl": purl,
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "supplier": SUPPLIER,
        },
    }
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch:
        metadata["timestamp"] = datetime.fromtimestamp(
            int(epoch), tz=UTC
        ).isoformat()
    seen: set[str] = set()
    components: list[dict] = []
    dep_refs: list[str] = []
    for dep in pkg["dependencies"]:
        name = _dep_name(dep)
        if not name or name in seen:
            continue
        seen.add(name)
        ref = f"pkg:pypi/{name}"
        components.append(
            {"type": "library", "bom-ref": ref, "name": name, "purl": ref}
        )
        dep_refs.append(ref)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, purl)}",
        "version": 1,
        "metadata": metadata,
        "components": components,
        "dependencies": [{"ref": bom_ref, "dependsOn": sorted(dep_refs)}],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", help="generate for one package name only")
    parser.add_argument(
        "--out-root",
        help="write to DIR/<pkgdir>/sbom/ instead of in-tree (tests)",
    )
    args = parser.parse_args(argv)
    count = 0
    for pkg in discover_packages(REPO_ROOT):
        if args.only and pkg["name"] != args.only:
            continue
        out_dir = (
            Path(args.out_root) / pkg["dir"].name / "sbom"
            if args.out_root
            else pkg["dir"] / "sbom"
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"{pkg['name']}.cdx.json"
        doc = build_sbom(pkg)
        out.write_text(
            json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"wrote {out.relative_to(REPO_ROOT) if not args.out_root else out}")
        count += 1
    if count == 0:
        print("no packages matched", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
