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
from evidentia_core.catalogs.loader import load_any_catalog, load_catalog
from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
    load_manifest,
)
from evidentia_core.models.catalog import CatalogControl, ControlCatalog, _normalize_control_id

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


def _crosswalk_families(manifest: FrameworkManifest) -> dict[str, str]:
    """Member framework id -> family id, from the manifest's ``crosswalk_family`` column."""
    return {fw.id: fw.crosswalk_family for fw in manifest.frameworks if fw.crosswalk_family}


def _catalog_entry_ids(catalog: object) -> frozenset[str]:
    """Every entry id of a loaded catalog, normalized the way the catalog index is.

    Control catalogs contribute every control and enhancement; technique,
    vulnerability and obligation catalogs contribute their entries' ids.
    """
    ids: set[str] = set()
    if isinstance(catalog, ControlCatalog):

        def _walk(ctrl: CatalogControl) -> None:
            ids.add(_normalize_control_id(ctrl.id))
            for enhancement in ctrl.enhancements:
                _walk(enhancement)

        for control in catalog.controls:
            _walk(control)
        return frozenset(ids)
    for attr in ("obligations", "techniques", "vulnerabilities"):
        entries = getattr(catalog, attr, None)
        if entries is None:
            continue
        for entry in entries:
            raw = getattr(entry, "id", None) or getattr(entry, "cve_id", None)
            if raw:
                ids.add(_normalize_control_id(str(raw)))
    return frozenset(ids)


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
        self._crosswalk_engine = CrosswalkEngine(
            mappings_dir=self._data_dir / "mappings",
            families=_crosswalk_families(self._manifest),
        )
        self._crosswalk_loaded = False
        self._entry_ids: dict[str, frozenset[str]] = {}

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
                "text_depth": e.text_depth or "",
                "status": e.status or "",
                "notes": e.notes or "",
                "verified_on": e.verified_on.isoformat() if e.verified_on else "",
                "superseded_by": e.superseded_by or "",
            }
            for e in entries
        ]

    def family_members(self, family_id: str) -> list[str]:
        """Bundled framework ids whose ``crosswalk_family`` is ``family_id``."""
        return [fw.id for fw in self._manifest.frameworks if fw.crosswalk_family == family_id]

    def control_ids_for(self, framework_id: str) -> frozenset[str] | None:
        """Normalized entry ids for a bundled framework or a crosswalk family.

        A bundled catalog of any category returns its own ids; a family id
        returns the union over its members; anything else returns ``None``,
        which callers read as "not bundled, nothing to resolve against".
        """
        if self._manifest.get(framework_id) is not None:
            return self._ids_of(framework_id)
        members = self.family_members(framework_id)
        if not members:
            return None
        union: set[str] = set()
        for member in members:
            union |= self._ids_of(member)
        return frozenset(union)

    def _ids_of(self, framework_id: str) -> frozenset[str]:
        if framework_id not in self._entry_ids:
            self._entry_ids[framework_id] = _catalog_entry_ids(load_any_catalog(framework_id))
        return self._entry_ids[framework_id]

    def get_catalog(self, framework_id: str) -> ControlCatalog:
        """Get a catalog by framework ID (cached)."""
        if framework_id not in self._catalogs:
            self._catalogs[framework_id] = load_catalog(framework_id)
        return self._catalogs[framework_id]

    def get_control(self, framework_id: str, control_id: str) -> CatalogControl | None:
        """Get a specific control from a framework catalog."""
        catalog = self.get_catalog(framework_id)
        return catalog.get_control(control_id)
