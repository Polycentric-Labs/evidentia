"""Parametric smoke test — every bundled catalog loads cleanly.

One test case per framework in the manifest. Guards against:
- Malformed JSON
- Schema mismatches (new catalog fields missing from older JSONs)
- Broken path references in frameworks.yaml
- Loader regressions

Also asserts tier invariants: every Tier-C stub must have
``placeholder=true`` and ``license_required=true``; Tier-A content
catalogs must not be placeholders.
"""

from __future__ import annotations

import pytest
from evidentia_core.catalogs.loader import load_any_catalog
from evidentia_core.catalogs.manifest import load_manifest


def _all_framework_ids() -> list[str]:
    return [fw.id for fw in load_manifest().frameworks]


@pytest.mark.parametrize("framework_id", _all_framework_ids())
def test_framework_loads(framework_id: str) -> None:
    """Every bundled framework loads and has at least one entry."""
    catalog = load_any_catalog(framework_id)
    assert catalog is not None, f"{framework_id} returned None from load_any_catalog"

    # Count entries by catalog type
    entry_count = 0
    entry_attr: str | None = None
    for attr in ("controls", "techniques", "vulnerabilities", "obligations"):
        if hasattr(catalog, attr):
            items = getattr(catalog, attr)
            if items:
                entry_count = len(items)
                entry_attr = attr
                break

    assert entry_count > 0, f"{framework_id} has no entries in any known attribute — check JSON structure"
    # Sanity — the first entry has some kind of identifier.
    # Control/Technique/Obligation use ``id``; Vulnerability uses ``cve_id``.
    first = getattr(catalog, entry_attr)[0]
    identifier = getattr(first, "id", None) or getattr(first, "cve_id", None)
    assert identifier, f"{framework_id} first entry has no id or cve_id"


def test_tier_c_stubs_are_placeholders() -> None:
    """Every Tier-C entry in the manifest must be a stub.

    Architecture invariant — Tier C means copyrighted content that
    cannot be bundled. If any Tier-C catalog isn't a placeholder, the
    repo has leaked licensed text.
    """
    manifest = load_manifest()
    for fw in manifest.by_tier("C"):
        assert fw.placeholder, f"Tier-C framework {fw.id} must have placeholder=true"
        assert fw.license_required, f"Tier-C framework {fw.id} must have license_required=true"


def test_tier_a_is_not_placeholder() -> None:
    """Tier A frameworks ship real content, not stubs."""
    manifest = load_manifest()
    for fw in manifest.by_tier("A"):
        assert not fw.placeholder, f"Tier-A framework {fw.id} should not be a placeholder"


def test_bundled_framework_count_by_tier() -> None:
    """Guard against accidental framework removal."""
    manifest = load_manifest()
    counts = {tier: len(manifest.by_tier(tier)) for tier in ("A", "B", "C", "D")}
    # v0.2.0 ships roughly these volumes — allow headroom but catch gross regressions
    assert counts["A"] >= 30, f"Expected 30+ Tier A, got {counts['A']}"
    assert counts["B"] >= 3, f"Expected 3+ Tier B (threats/vulns), got {counts['B']}"
    assert counts["C"] >= 15, f"Expected 15+ Tier C stubs, got {counts['C']}"
    assert counts["D"] >= 15, f"Expected 15+ Tier D (statutes), got {counts['D']}"
