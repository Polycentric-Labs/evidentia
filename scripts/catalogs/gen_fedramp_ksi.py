#!/usr/bin/env python3
"""Deterministic generator for the FedRAMP CR26 KSI catalog + crosswalk.

Generates, from the pinned upstream ``FedRAMP/rules``
``fedramp-consolidated-rules.json`` dataset:

1. ``packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal/
   fedramp-ksi-2026.json`` — the Key Security Indicator catalog (10
   families / 46 indicators at the pinned revision; Tier A — US federal
   work, verbatim redistribution).
2. ``.../catalogs/data/mappings/fedramp-ksi-2026_to_nist-800-53-rev5.json``
   — the KSI→800-53 crosswalk from each indicator's upstream ``controls``
   field. Upstream cites base controls and enhancements (``at-2.2``);
   the bundled ``nist-800-53-rev5`` catalog carries base controls only,
   so mappings are recorded at base-control granularity with the exact
   upstream citation (including enhancements) preserved verbatim in
   ``notes``.

The upstream pin (commit SHA + dataset sha256) lives in
``packages/evidentia-core/src/evidentia_core/fedramp/schemas/UPSTREAM.json``
— the same provenance file the vendored SDR schemas and the
``fedramp-schema-watch`` sentinel use, so one re-sync updates everything
together (see the README next to it).

Modes
-----
``gen_fedramp_ksi.py``
    Regenerate both JSONs in place from the pinned upstream revision.
``gen_fedramp_ksi.py --check``
    Exit 0 if regenerated output matches the committed files
    byte-for-byte; exit 1 + a per-file summary on drift.

After regenerating, run ``scripts/catalogs/regenerate_manifest.py`` so
``frameworks.yaml`` picks up the catalog.

Upstream fetch + cache
----------------------
The dataset is fetched via the ``gh`` CLI at the PINNED commit and cached
under ``.local/fedramp-upstream-<sha>/`` (gitignored); its sha256 must
match the pin or the script aborts. Subsequent runs reuse the cache.
Network-dependent regeneration is acceptable for this dev-time tool
(same posture as ``gen_osps_crosswalks.py``); every ``gh`` invocation
uses ``subprocess.run`` with an argument list (no shell).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from _generators import (  # type: ignore[import-not-found]
    DATA_ROOT,
    REPO_ROOT,
    emit_control_catalog,
)

PIN_PATH = (
    REPO_ROOT
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "fedramp"
    / "schemas"
    / "UPSTREAM.json"
)

CATALOG_ID = "fedramp-ksi-2026"
TARGET_FRAMEWORK = "nist-800-53-rev5"
CATALOG_PATH = DATA_ROOT / "us-federal" / f"{CATALOG_ID}.json"
CROSSWALK_PATH = DATA_ROOT / "mappings" / f"{CATALOG_ID}_to_{TARGET_FRAMEWORK}.json"


def load_pin() -> dict[str, Any]:
    """Read the upstream pin from the shared provenance file."""
    with open(PIN_PATH, encoding="utf-8") as f:
        pins: dict[str, Any] = json.load(f)
    return pins


def fetch_dataset(pin: dict[str, Any]) -> dict[str, Any]:
    """Fetch (or reuse cached) upstream dataset at the pinned commit."""
    rules = pin["rules"]
    commit: str = rules["commit"]
    filename: str = rules["file"]
    cache_dir = REPO_ROOT / ".local" / f"fedramp-upstream-{commit[:12]}"
    cache_file = cache_dir / filename

    if not cache_file.exists():
        cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                [
                    "gh",
                    "api",
                    f"repos/{rules['repo']}/contents/{filename}?ref={commit}",
                    "-H",
                    "Accept: application/vnd.github.raw+json",
                ],
                capture_output=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            sys.exit(
                f"could not fetch {rules['repo']}@{commit[:12]}/{filename} "
                f"via `gh api` ({exc}). Populate the cache manually: save "
                f"the file at that revision to {cache_file}"
            )
        cache_file.write_bytes(result.stdout)

    raw = cache_file.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != rules["sha256"]:
        sys.exit(
            f"sha256 mismatch for {cache_file}: got {digest}, pinned "
            f"{rules['sha256']}. Delete the cache and re-fetch; if the "
            f"mismatch persists, upstream moved under the pin — re-verify "
            f"before bumping UPSTREAM.json."
        )
    dataset: dict[str, Any] = json.loads(raw.decode("utf-8"))
    return dataset


def _split_control_ref(ref: str) -> tuple[str, str | None]:
    """Split an upstream control ref into (BASE-ID, enhancement or None).

    Upstream cites lowercase 800-53 ids, with enhancements dot-suffixed:
    ``cp-3`` → (``CP-3``, None); ``at-2.2`` → (``AT-2``, ``AT-2(2)``).
    """
    base, dot, enhancement = ref.partition(".")
    base_id = base.upper()
    if not dot:
        return base_id, None
    return base_id, f"{base_id}({enhancement})"


def build_catalog_controls(
    dataset: dict[str, Any],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Transform the dataset's KSI section into catalog families + controls."""
    families: list[str] = []
    controls: list[dict[str, Any]] = []
    for family in dataset["KSI"].values():
        families.append(family["name"])
        for ksi_id, indicator in family["indicators"].items():
            # Five indicators carry no base statement — upstream defines
            # them only per certification class (`varies_by_class`), where
            # class C holds the canonical unprefixed text and class B marks
            # it "**Optional:**". Use the class-C statement as the
            # description; every class variant is preserved verbatim in
            # guidance below.
            statement = indicator.get("statement")
            if statement is None:
                variants = indicator.get("varies_by_class", {})
                if "c" in variants:
                    statement = variants["c"]["statement"]
                elif variants:
                    statement = next(iter(variants.values()))["statement"]
                else:
                    sys.exit(
                        f"{ksi_id}: no `statement` and no `varies_by_class` "
                        f"in the upstream dataset — the KSI shape moved; "
                        f"re-verify before regenerating."
                    )
            if indicator["controls"]:
                guidance_parts = [
                    "NIST SP 800-53 Rev 5 mapping (upstream `controls`, "
                    "verbatim): " + ", ".join(indicator["controls"]) + "."
                ]
            else:
                guidance_parts = [
                    "No NIST SP 800-53 Rev 5 mapping declared upstream "
                    "(`controls: []` at the pinned revision)."
                ]
            if indicator.get("terms"):
                guidance_parts.append(
                    "Related FedRAMP terms: " + ", ".join(indicator["terms"]) + "."
                )
            for cls, variant in indicator.get("varies_by_class", {}).items():
                guidance_parts.append(
                    f"Class-{cls.upper()} variant statement (upstream "
                    f"`varies_by_class`, verbatim): {variant['statement']}"
                )
            controls.append(
                {
                    "id": ksi_id,
                    "title": indicator["name"],
                    "description": statement,
                    "family": family["name"],
                    "guidance": "\n\n".join(guidance_parts),
                }
            )
    return families, controls


def build_crosswalk(
    dataset: dict[str, Any], pin: dict[str, Any]
) -> dict[str, Any]:
    """Build the KSI→800-53 crosswalk at base-control granularity."""
    from evidentia_core.catalogs.loader import load_catalog

    target_titles = {
        control.id: control.title
        for control in load_catalog(TARGET_FRAMEWORK).controls
    }

    # (ksi_id, base_id) -> {"title": ..., "refs": [verbatim upstream refs]}
    pairs: dict[tuple[str, str], dict[str, Any]] = {}
    for family in dataset["KSI"].values():
        for ksi_id, indicator in family["indicators"].items():
            for ref in indicator["controls"]:
                base_id, _enhancement = _split_control_ref(ref)
                pair = pairs.setdefault(
                    (ksi_id, base_id),
                    {"title": indicator["name"], "refs": []},
                )
                pair["refs"].append(ref)

    mappings: list[dict[str, Any]] = []
    for (ksi_id, base_id), pair in sorted(pairs.items()):
        mappings.append(
            {
                "source_control_id": ksi_id,
                "source_control_title": pair["title"],
                "target_control_id": base_id,
                "target_control_title": target_titles.get(base_id, ""),
                "relationship": "related",
                "confidence": "high",
                "notes": (
                    "Upstream FedRAMP KSI `controls` citation (verbatim, "
                    "enhancements dot-suffixed): " + ", ".join(pair["refs"])
                ),
            }
        )

    rules = pin["rules"]
    return {
        "source_framework": CATALOG_ID,
        "target_framework": TARGET_FRAMEWORK,
        "version": f"FedRAMP Consolidated Rules {rules['dataset_version']} / NIST 800-53 Rev 5",
        "generated_at": dataset["info"]["last_updated"],
        "source": (
            f"https://github.com/{rules['repo']} @ {rules['commit'][:12]} "
            f"({rules['file']}, dataset version {rules['dataset_version']})"
        ),
        "verification": "self-attested-via-upstream",
        "verification_note": (
            "Control mappings are declared by FedRAMP itself in each KSI "
            "indicator's `controls` field; extracted verbatim at the pinned "
            "revision, folded to base-control granularity (the bundled "
            "nist-800-53-rev5 catalog carries base controls only) with the "
            "exact upstream citation preserved in notes."
        ),
        "mappings": mappings,
    }


def generate(pin: dict[str, Any], dataset: dict[str, Any]) -> dict[Path, str]:
    """Render both artifacts; returns {path: content} without writing."""
    rules = pin["rules"]
    families, controls = build_catalog_controls(dataset)

    catalog: dict[str, Any] = {
        "framework_id": CATALOG_ID,
        "framework_name": (
            "FedRAMP Key Security Indicators (Consolidated Rules for 2026)"
        ),
        "version": f"{rules['dataset_version']} (CR26)",
        "source": (
            f"FedRAMP — https://github.com/{rules['repo']} @ "
            f"{rules['commit'][:12]} ({rules['file']})"
        ),
        "tier": "A",
        "category": "control",
        "placeholder": False,
        "families": families,
        "controls": controls,
    }
    crosswalk = build_crosswalk(dataset, pin)
    return {
        CATALOG_PATH: json.dumps(catalog, indent=2, ensure_ascii=False) + "\n",
        CROSSWALK_PATH: json.dumps(crosswalk, indent=2, ensure_ascii=False) + "\n",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify committed artifacts match regenerated output (no writes)",
    )
    args = parser.parse_args()

    pin = load_pin()
    dataset = fetch_dataset(pin)
    rendered = generate(pin, dataset)

    if args.check:
        drifted = []
        for path, content in rendered.items():
            on_disk = path.read_text(encoding="utf-8") if path.exists() else None
            if on_disk != content:
                drifted.append(path)
        if drifted:
            for path in drifted:
                print(f"DRIFT: {path.relative_to(REPO_ROOT)}")
            print(
                "regenerated output differs from committed files; run "
                "scripts/catalogs/gen_fedramp_ksi.py (then "
                "regenerate_manifest.py) and review the diff."
            )
            return 1
        print("OK: fedramp-ksi-2026 catalog + crosswalk match the pinned upstream.")
        return 0

    for path, content in rendered.items():
        path.write_text(content, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO_ROOT)}")
    print(
        "Next: run `uv run python scripts/catalogs/regenerate_manifest.py` "
        "and commit frameworks.yaml alongside."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
