"""Framework manifest — single source of truth for bundled catalogs.

Loads ``data/frameworks.yaml`` into typed Pydantic records. The registry
and loader read from here instead of hand-maintained dicts, so adding a
new bundled framework is one YAML edit + one JSON file drop — no Python
changes required.

v0.2.0 introduced this module to replace three parallel sources of truth
in v0.1.x: ``FRAMEWORK_METADATA`` in registry.py, ``framework_files`` in
loader.py, and the ``FrameworkId`` enum in models/common.py.
"""

from __future__ import annotations

import logging
from functools import cache
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)

# Redistribution tiers. See ATTRIBUTION.md for the full framework-by-framework
# legal analysis; short version:
#   A — verbatim redistribution OK (US federal works, CC-BY, public-domain).
#   B — free to use but with conditions (MITRE ATT&CK, CISA KEV).
#   C — copyrighted, stub only (ISO, SOC 2 TSC, PCI DSS, HITRUST, CIS).
#   D — government regulation text, may be bundled with attribution (GDPR,
#       EU AI Act, state privacy laws — uncopyrightable as law).
Tier = Literal["A", "B", "C", "D"]

# Non-control catalog types that extend the core ControlCatalog concept.
# See models/threat.py and models/obligation.py for the concrete shapes.
Category = Literal["control", "technique", "vulnerability", "obligation"]

# How often the refresh CI workflow checks this framework's upstream source
# for updates. ``manual`` = never refreshed automatically (stub catalogs
# whose content is owned by us, e.g., SOC 2 TSC stub).
RefreshSchedule = Literal["daily", "weekly", "monthly", "manual"]


class FrameworkManifestEntry(BaseModel):
    """One framework in the bundled catalog manifest."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(
        description="Canonical framework ID, kebab-case, stable across versions",
    )
    name: str = Field(description="Human-readable framework name")
    version: str = Field(description="Framework version (e.g. 'Rev 5', '2022')")
    tier: Tier = Field(description="Redistribution tier")
    category: Category = Field(
        default="control",
        description="Catalog type — control/technique/vulnerability/obligation",
    )
    path: str = Field(
        description="JSON catalog path relative to data/ directory",
    )
    source_url: str | None = Field(default=None, description="Upstream URL for this framework")
    license: str | None = Field(
        default=None,
        description="Short human-readable license statement",
    )
    license_required: bool = Field(
        default=False,
        description="True if control text is copyrighted and this is a stub",
    )
    license_url: str | None = Field(
        default=None,
        description="URL where users can license/download authoritative text",
    )
    placeholder: bool = Field(
        default=False,
        description="True if catalog is a stub without authoritative text",
    )
    extras: str | None = Field(
        default=None,
        description="Install extra gating this framework (e.g., 'stigs')",
    )
    refresh: RefreshSchedule = Field(
        default="manual",
        description="Refresh CI schedule — daily/weekly/monthly/manual",
    )


class FrameworkManifest(BaseModel):
    """Root document of frameworks.yaml."""

    model_config = ConfigDict(extra="forbid")

    version: int = Field(description="Manifest schema version")
    frameworks: list[FrameworkManifestEntry] = Field(description="All frameworks bundled in this release")

    def get(self, framework_id: str) -> FrameworkManifestEntry | None:
        """Look up a manifest entry by framework ID (case-sensitive)."""
        for fw in self.frameworks:
            if fw.id == framework_id:
                return fw
        return None

    def by_tier(self, tier: Tier) -> list[FrameworkManifestEntry]:
        """All entries in a given tier."""
        return [fw for fw in self.frameworks if fw.tier == tier]

    def by_category(self, category: Category) -> list[FrameworkManifestEntry]:
        """All entries in a given category."""
        return [fw for fw in self.frameworks if fw.category == category]


# Path to the bundled manifest file (same directory as the catalog JSONs).
MANIFEST_PATH = Path(__file__).parent / "data" / "frameworks.yaml"


@cache
def load_manifest(path: Path | None = None) -> FrameworkManifest:
    """Load and validate the bundled framework manifest.

    Cached — the manifest is immutable at runtime once loaded. Tests that
    need to reload (e.g., to point at a test fixture) should pass an
    explicit ``path``; the cache keys on the path argument.
    """
    manifest_path = path or MANIFEST_PATH
    with open(manifest_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    manifest = FrameworkManifest.model_validate(raw)

    # Integrity check — duplicate IDs would silently shadow each other via
    # `get()`; fail loud at load time instead.
    seen: dict[str, int] = {}
    for fw in manifest.frameworks:
        seen[fw.id] = seen.get(fw.id, 0) + 1
    dups = [fid for fid, count in seen.items() if count > 1]
    if dups:
        raise ValueError(f"Duplicate framework IDs in manifest: {', '.join(sorted(dups))}")

    logger.debug(
        "Loaded manifest v%d: %d frameworks (%d tier-A, %d tier-B, %d tier-C stubs, %d tier-D)",
        manifest.version,
        len(manifest.frameworks),
        len(manifest.by_tier("A")),
        len(manifest.by_tier("B")),
        len(manifest.by_tier("C")),
        len(manifest.by_tier("D")),
    )
    return manifest
