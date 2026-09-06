"""Framework registry — discovers and caches available catalogs and crosswalks.

Singleton that initializes at first use and provides the central access
point for all catalog and crosswalk operations.

v0.2.0 reads its framework list from ``data/frameworks.yaml`` via
:mod:`evidentia_core.catalogs.manifest`; the previous hand-kept
``FRAMEWORK_METADATA`` dict is preserved as a compatibility view built
from the manifest at import time.
"""

from __future__ import annotations

import logging
from pathlib import Path

from evidentia_core.catalogs.crosswalk import CrosswalkEngine
from evidentia_core.catalogs.loader import load_catalog
from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.models.catalog import CatalogControl, ControlCatalog

logger = logging.getLogger(__name__)


def _build_framework_metadata(
    manifest: FrameworkManifest,
) -> dict[str, dict[str, str]]:
    """Back-compat view used by :func:`FrameworkRegistry.list_frameworks`.

    v0.1.x consumers expected a plain dict. The manifest is the real
    source of truth — prefer ``load_manifest()`` / the ``manifest``
    property on the registry for new code.
    """
    out: dict[str, dict[str, str]] = {}
    for fw in manifest.frameworks:
        out[fw.id] = {
            "name": fw.name,
            "tier": fw.tier,
            "category": fw.category,
            "version": fw.version,
            "placeholder": str(fw.placeholder).lower(),
            "license_required": str(fw.license_required).lower(),
        }
    return out


# Computed once at import time from the bundled manifest. Retained as a
# module-level constant for backward compatibility with v0.1.x callers
# that imported it directly.
FRAMEWORK_METADATA: dict[str, dict[str, str]] = _build_framework_metadata(load_manifest())


class FrameworkRegistry:
    """Central registry for framework catalogs and cross-framework mappings.

    Lazily loads catalogs on first access. Caches all loaded catalogs
    in memory for the lifetime of the process.

    v0.2.0: framework list is sourced from ``data/frameworks.yaml`` —
    :attr:`manifest` exposes the typed manifest for tier/category filtering.
    """

    _instance: FrameworkRegistry | None = None

    def __init__(self, data_dir: Path | None = None) -> None:
        self._data_dir = data_dir or Path(__file__).parent / "data"
        self._catalogs: dict[str, ControlCatalog] = {}
        self._manifest = load_manifest()
        self._crosswalk_engine = CrosswalkEngine(mappings_dir=self._data_dir / "mappings")
        self._crosswalk_loaded = False

    @classmethod
    def get_instance(cls) -> FrameworkRegistry:
        """Get or create the singleton registry instance."""
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Clear the singleton (useful for tests)."""
        cls._instance = None

    @property
    def manifest(self) -> FrameworkManifest:
        """Typed access to the bundled framework manifest."""
        return self._manifest

    @property
    def crosswalk(self) -> CrosswalkEngine:
        """Access the crosswalk engine (lazy-loaded)."""
        if not self._crosswalk_loaded:
            self._crosswalk_engine.load_all()
            self._crosswalk_loaded = True
        return self._crosswalk_engine

    def list_frameworks(
        self,
        tier: str | None = None,
        category: str | None = None,
    ) -> list[dict[str, str]]:
        """List available framework IDs with metadata, optionally filtered.

        Filters are case-sensitive against the manifest's tier and category
        fields. Returns entries in manifest declaration order.
        """
        entries: list[FrameworkManifestEntry] = list(self._manifest.frameworks)
        if tier:
            entries = [e for e in entries if e.tier == tier]
        if category:
            entries = [e for e in entries if e.category == category]
        return [
            {
                "id": e.id,
                "name": e.name,
                "version": e.version,
                "tier": e.tier,
                "category": e.category,
                "placeholder": str(e.placeholder).lower(),
                "license_required": str(e.license_required).lower(),
            }
            for e in entries
        ]

    def get_catalog(self, framework_id: str) -> ControlCatalog:
        """Get a catalog by framework ID (cached)."""
        if framework_id not in self._catalogs:
            self._catalogs[framework_id] = load_catalog(framework_id)
        return self._catalogs[framework_id]

    def get_control(self, framework_id: str, control_id: str) -> CatalogControl | None:
        """Get a specific control from a framework catalog."""
        catalog = self.get_catalog(framework_id)
        return catalog.get_control(control_id)
