"""Regenerate frameworks.yaml by scanning bundled catalog JSONs on disk.

This makes the manifest truthful by construction — the contents of
data/<tier>/ ARE the manifest. No hand-maintained sync required.

Two columns are derived rather than copied: ``text_depth`` is computed by
loading every catalog through the same loaders the runtime uses, and
``crosswalk_family`` comes from the :data:`CROSSWALK_FAMILIES` table below,
which names the catalogs that are baselines or maturity levels of a larger
catalog and therefore inherit its crosswalks.

Run this script whenever catalogs are added/removed/modified
(``uv run python scripts/catalogs/regenerate_manifest.py``; it imports
``evidentia_core``).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from _generators import DATA_ROOT  # type: ignore[import-not-found]
from evidentia_core.catalogs.loader import (
    load_evidentia_catalog,
    load_non_control_catalog,
    load_oscal_catalog,
)

# Member catalog id -> family id. A crosswalk keyed on the family applies to
# every member (see evidentia_core.catalogs.crosswalk). The NIST baselines
# and the FedRAMP baselines are subsets of the full Rev 5 catalog; the legacy
# 16-control sample is a subset too; the three OSPS maturity levels are
# applicability filters over one baseline whose crosswalks key on
# ``osps-baseline``.
CROSSWALK_FAMILIES: dict[str, str] = {
    "nist-800-53-rev5-low": "nist-800-53-rev5",
    "nist-800-53-rev5-moderate": "nist-800-53-rev5",
    "nist-800-53-rev5-high": "nist-800-53-rev5",
    "nist-800-53-rev5-privacy": "nist-800-53-rev5",
    "fedramp-rev5-low": "nist-800-53-rev5",
    "fedramp-rev5-moderate": "nist-800-53-rev5",
    "fedramp-rev5-high": "nist-800-53-rev5",
    "fedramp-rev5-li-saas": "nist-800-53-rev5",
    "nist-800-53-mod": "nist-800-53-rev5",
    "osps-baseline-m1": "osps-baseline",
    "osps-baseline-m2": "osps-baseline",
    "osps-baseline-m3": "osps-baseline",
}


def derive_text_depth(path: Path, data: dict) -> str:
    """Load the catalog file the way the runtime does and read its text depth."""
    if "catalog" in data:
        return load_oscal_catalog(path).text_depth
    if data.get("category", "control") != "control":
        depth = load_non_control_catalog(path).text_depth
        return str(depth)
    return load_evidentia_catalog(path).text_depth


TIER_DIRS: dict[str, tuple[str, str]] = {
    # dir_name: (default_tier_guess, default_category_guess)
    "us-federal": ("A", "control"),
    "international": ("A", "control"),
    "state-privacy": ("D", "obligation"),
    "stubs": ("C", "control"),
    "threats": ("B", "technique"),
}

# Preferred ordering to keep the YAML readable
TIER_ORDER = ["us-federal", "international", "state-privacy", "threats", "stubs"]


def infer_refresh(tier: str, category: str) -> str:
    """Best-guess refresh cadence based on tier and category."""
    if category in ("vulnerability",):
        return "daily"
    if category in ("technique",):
        return "weekly"
    if tier == "A":
        return "monthly"
    if tier == "D":
        return "monthly"  # watch statute updates
    return "manual"


def scan_dir(subdir: str) -> list[dict]:
    """Return manifest entries for all catalog files in DATA_ROOT/subdir.

    Accepts both JSON (``.json``) and YAML (``.yaml`` / ``.yml``) catalog
    files (v0.10.3+). Both formats produce the same dict shape; the
    extension is preserved in the manifest's ``path`` field so the
    loader knows which parser to dispatch.
    """
    dir_path = DATA_ROOT / subdir
    if not dir_path.exists():
        return []
    tier_default, category_default = TIER_DIRS[subdir]
    entries: list[dict] = []

    candidates = sorted(list(dir_path.glob("*.json")) + list(dir_path.glob("*.yaml")) + list(dir_path.glob("*.yml")))
    # v0.10.6 P1: skip OSCAL-Catalog sidecar artifacts (`*.oscal.json` /
    # `*.oscal.yaml`). These are downstream-consumption artifacts (e.g.,
    # `osps-baseline.oscal.json` is the OSCAL Catalog 1.2.1 serialization
    # of the OSPS Baseline) and are NOT Evidentia framework catalogs —
    # they don't carry `framework_id` and shouldn't appear as a separate
    # manifest entry. The companion Evidentia YAMLs (e.g.
    # `osps-baseline-m1.yaml`) are the manifest-registered entries.
    candidates = [p for p in candidates if not (p.name.endswith(".oscal.json") or p.name.endswith(".oscal.yaml"))]
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8")
            if path.suffix.lower() in (".yaml", ".yml"):
                data = yaml.safe_load(text)
                if not isinstance(data, dict):
                    raise ValueError(f"YAML top-level must be a mapping, got {type(data).__name__}")
            else:
                data = json.loads(text)
        except (OSError, json.JSONDecodeError, yaml.YAMLError, ValueError) as exc:
            # Surface the skip explicitly (stderr, not stdout, so it
            # doesn't pollute the manifest summary going to a pipe).
            # Silent drops would otherwise produce a smaller frameworks.yaml
            # that only the catalog-refresh.yml workflow's pytest step
            # would notice (via test_all_bundled.py's count assertion) —
            # devs running the script locally see nothing without this.
            print(
                f"WARN: skipped malformed catalog file {path}: {exc!r}",
                file=sys.stderr,
            )
            continue

        entry = {
            "id": data.get("framework_id", path.stem),
            "name": data.get("framework_name", path.stem),
            "version": data.get("version", "unknown"),
            "tier": data.get("tier", tier_default),
            "category": data.get("category", category_default),
            "path": f"{subdir}/{path.name}",
        }
        # Optional fields — only emit when present so YAML stays readable
        for src_field, dst_field in [
            ("source", "source_url"),
            ("license_terms", "license"),
            ("license_url", "license_url"),
        ]:
            val = data.get(src_field)
            if val:
                entry[dst_field] = val
        if data.get("license_required"):
            entry["license_required"] = True
        if data.get("placeholder"):
            entry["placeholder"] = True
        entry["refresh"] = infer_refresh(entry["tier"], entry["category"])
        entry["text_depth"] = derive_text_depth(path, data)
        family = CROSSWALK_FAMILIES.get(entry["id"])
        if family is not None:
            entry["crosswalk_family"] = family
        entries.append(entry)

    # v0.10.4 P3 collision guard: assert no two entries in the same
    # tier directory share a framework_id. The realistic failure mode
    # is a contributor converting `foo.json` -> `foo.yaml` for the
    # YAML-format affordance (v0.10.3+) without deleting the JSON
    # — both would land here, both would resolve to the same
    # framework_id at load time, and the resulting manifest would
    # carry a duplicate row that confuses the loader's path-resolution
    # precedence. Fail loud at manifest-regen time so the drift is
    # caught before frameworks.yaml ships.
    seen: dict[str, str] = {}
    for entry in entries:
        fid = entry["id"]
        if fid in seen:
            raise ValueError(
                f"framework_id collision in {subdir}/: {fid!r} appears in "
                f"both {seen[fid]} and {entry['path']}. "
                f"Most likely cause: a JSON -> YAML conversion left the "
                f"original JSON in place. Delete the older format file "
                f"and re-run the script."
            )
        seen[fid] = entry["path"]

    return entries


def main() -> None:
    all_entries: list[dict] = []
    for subdir in TIER_ORDER:
        all_entries.extend(scan_dir(subdir))

    manifest = {
        "version": 1,
        "frameworks": all_entries,
    }

    out_path = DATA_ROOT / "frameworks.yaml"

    # Write the YAML with a header comment preserved
    header = """# Evidentia framework manifest — single source of truth for bundled catalogs.
#
# GENERATED BY scripts/catalogs/regenerate_manifest.py — do not hand-edit.
# To add/remove a framework: change the JSON in data/<tier-dir>/ then re-run the
# regeneration script. The manifest reflects what is on disk.
#
# Schema is validated by evidentia_core.catalogs.manifest.FrameworkManifest.
# Fields:
#   id            Canonical framework ID (kebab-case; stable across versions).
#   name          Human-readable name shown in `catalog list`.
#   version       Framework version string.
#   tier          A | B | C | D, the redistribution tier (docs/contributing-a-catalog.md).
#   category      control | technique | vulnerability | obligation.
#   path          JSON path relative to data/ directory.
#   source_url    Upstream URL.
#   license       Short license statement.
#   license_required  true if control text is copyrighted (Tier C stub).
#   license_url   URL where users can license/download authoritative text.
#   placeholder   true if this catalog is a stub (no authoritative text).
#   refresh       Adapter schedule: daily | weekly | monthly | manual.
#   text_depth    full | partial | headings; derived from the catalog file, never declared.
#   crosswalk_family  family id whose crosswalks also apply (baselines, maturity levels).

"""
    # width=200 pins PyYAML's word-wrap behavior so the regenerated
    # frameworks.yaml is byte-stable across PyYAML versions and
    # platform locales. The default (width=80) silently re-wraps long
    # license: strings on different column boundaries depending on
    # PyYAML's exact version, producing whitespace-only diffs that
    # the catalog-refresh.yml workflow flagged as drift (issues #1-#4
    # at v0.7.1 ship time). 200 keeps lines readable while reducing
    # wrap-induced churn for the SOC 2 / ISO 27001 / similar long
    # license-disclaimer strings.
    body = yaml.safe_dump(
        manifest,
        sort_keys=False,
        default_flow_style=False,
        allow_unicode=True,
        width=200,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(header)
        f.write(body)

    print(f"Wrote manifest with {len(all_entries)} frameworks to {out_path}")
    by_tier: dict[str, int] = {}
    for e in all_entries:
        by_tier[e["tier"]] = by_tier.get(e["tier"], 0) + 1
    for tier in sorted(by_tier):
        print(f"  Tier {tier}: {by_tier[tier]}")


if __name__ == "__main__":
    main()
