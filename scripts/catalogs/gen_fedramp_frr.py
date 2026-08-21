#!/usr/bin/env python3
"""Deterministic generator for the FedRAMP CR26 FRR (requirements) catalog.

Generates, from the pinned upstream ``FedRAMP/rules``
``fedramp-consolidated-rules.json`` dataset, the provider-facing
FedRAMP Requirements catalog:

    packages/evidentia-core/src/evidentia_core/catalogs/data/us-federal/
    fedramp-frr-2026.json

Why this catalog exists
-----------------------
``SDR-CSO-FRR`` is a MUST: a Security Decision Record "MUST include at
least" an explanation, verification, validation, and related statements
*for each applicable FedRAMP rule*. ``evidentia conmon ksi`` emits the
SDR's ``fedRampRequirements`` block from the operator's status file, and
this catalog is what the block's ``frrID`` values are checked against —
the same role ``fedramp-ksi-2026`` plays for ``keySecurityIndicators``.

Scope: provider-facing rules only
---------------------------------
The consolidated dataset carries ~250 rules across many actors (FedRAMP
itself, assessors, agencies, the marketplace). An SDR is the *provider's*
record, so only rules whose upstream ``affects`` list names Providers are
included; a rule addressed to FedRAMP staff is not something a provider
can implement, and listing it would make the coverage report noise.
Upstream's applicability tiers (``all`` / ``20x`` / ``rev5``) and the
rule's force (MUST / SHOULD / MAY) are preserved verbatim in guidance so
the operator can prioritise.

The upstream pin is the shared one in
``packages/evidentia-core/src/evidentia_core/fedramp/schemas/UPSTREAM.json``
— one re-sync updates the vendored schemas, the KSI catalog, and this
catalog together. Fetch + cache + sha256 verification are delegated to
``gen_fedramp_ksi.py`` so the two generators cannot disagree about the
dataset they read.

Modes
-----
``gen_fedramp_frr.py``           regenerate in place
``gen_fedramp_frr.py --check``   exit 0 if the committed file matches
                                 byte-for-byte; exit 1 on drift

After regenerating, run ``scripts/catalogs/regenerate_manifest.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from _generators import DATA_ROOT, REPO_ROOT  # type: ignore[import-not-found]
from gen_fedramp_ksi import fetch_dataset, load_pin  # type: ignore[import-not-found]

CATALOG_ID = "fedramp-frr-2026"
CATALOG_PATH = DATA_ROOT / "us-federal" / f"{CATALOG_ID}.json"

#: The ``affects`` value that marks a rule as provider-facing.
PROVIDER_ACTOR = "Providers"


def build_catalog_controls(
    dataset: dict[str, Any],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Transform the dataset's FRR section into catalog families + controls.

    One family per upstream rule family (``AFC``, ``CCM``, …), titled
    with the family's own ``name``. One control per provider-facing rule.
    """
    families: list[str] = []
    controls: list[dict[str, Any]] = []

    for family_key, family in dataset["FRR"].items():
        info = family.get("info", {})
        family_name = info.get("name") or family_key
        family_controls: list[dict[str, Any]] = []

        # data -> {applicability: {actor_code: {rule_id: rule}}}
        for applicability, actors in family.get("data", {}).items():
            for _actor_code, rules in actors.items():
                for rule_id, rule in rules.items():
                    if PROVIDER_ACTOR not in rule.get("affects", []):
                        continue
                    statement, force = _canonical_statement(rule_id, rule)
                    family_controls.append(
                        {
                            "id": rule_id,
                            "title": rule.get("name") or rule_id,
                            "description": statement,
                            "family": family_name,
                            "guidance": _guidance(rule, applicability, force),
                        }
                    )

        if family_controls:
            families.append(family_name)
            controls.extend(sorted(family_controls, key=lambda c: c["id"]))

    return families, controls


def _canonical_statement(rule_id: str, rule: dict[str, Any]) -> tuple[str, str | None]:
    """Pick the rule's description statement and its force.

    Most rules carry a base ``statement`` + ``force``. Some (29 at the
    pinned revision) are defined only per certification class under
    ``varies_by_class`` — the same shape the KSI generator handles.
    Mirror it: prefer class C as canonical (the unprefixed text), else
    the first class present; every variant is preserved verbatim in
    guidance so nothing is lost by the choice.
    """
    statement = rule.get("statement")
    if statement is not None:
        return statement, rule.get("force")

    variants = rule.get("varies_by_class") or {}
    if not variants:
        sys.exit(
            f"{rule_id}: no `statement` and no `varies_by_class` in the "
            f"upstream dataset — the FRR shape moved; re-verify before "
            f"regenerating."
        )
    chosen = variants["c"] if "c" in variants else next(iter(variants.values()))
    return chosen["statement"], chosen.get("force")


def _guidance(
    rule: dict[str, Any], applicability: str, force: str | None
) -> str:
    """Render the rule's force, applicability, and sub-points verbatim."""
    parts: list[str] = []

    if force:
        parts.append(f"Force: {force}.")

    applies = {
        "all": "Applies to all FedRAMP authorizations.",
        "20x": "Applies to FedRAMP 20x authorizations.",
        "rev5": "Applies to FedRAMP Rev 5 authorizations.",
    }.get(applicability, f"Applicability: {applicability}.")
    parts.append(applies)

    following = rule.get("following_information")
    if following:
        parts.append(
            "Required information (upstream `following_information`, "
            "verbatim):\n" + "\n".join(f"- {item}" for item in following)
        )

    note = rule.get("note")
    if note:
        parts.append(f"Upstream note (verbatim): {note}")

    for cls, variant in (rule.get("varies_by_class") or {}).items():
        parts.append(
            f"Class-{cls.upper()} variant (upstream `varies_by_class`, "
            f"verbatim; force {variant.get('force', '?')}): "
            f"{variant['statement']}"
        )

    terms = rule.get("terms")
    if terms:
        parts.append("Related FedRAMP terms: " + ", ".join(terms) + ".")

    schema = rule.get("schema")
    if isinstance(schema, dict) and schema.get("url"):
        parts.append(f"Machine-readable schema: {schema['url']}")

    return "\n\n".join(parts)


def generate(pin: dict[str, Any], dataset: dict[str, Any]) -> dict[Path, str]:
    """Render the catalog; returns {path: content} without writing."""
    rules = pin["rules"]
    families, controls = build_catalog_controls(dataset)
    catalog: dict[str, Any] = {
        "framework_id": CATALOG_ID,
        "framework_name": (
            "FedRAMP Requirements — provider-facing rules "
            "(Consolidated Rules for 2026)"
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
    return {CATALOG_PATH: json.dumps(catalog, indent=2, ensure_ascii=False) + "\n"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the committed catalog matches regenerated output (no writes)",
    )
    args = parser.parse_args()

    pin = load_pin()
    dataset = fetch_dataset(pin)
    rendered = generate(pin, dataset)

    if args.check:
        drifted = [
            path
            for path, content in rendered.items()
            if (path.read_text(encoding="utf-8") if path.exists() else None)
            != content
        ]
        if drifted:
            for path in drifted:
                print(f"DRIFT: {path.relative_to(REPO_ROOT)}")
            print(
                "regenerated output differs from the committed file; run "
                "scripts/catalogs/gen_fedramp_frr.py (then "
                "regenerate_manifest.py) and review the diff."
            )
            return 1
        print(f"OK: {CATALOG_ID} catalog matches the pinned upstream.")
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
