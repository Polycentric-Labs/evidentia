"""Cross-framework mapping engine.

Loads crosswalk definitions and provides bidirectional mapping between
framework controls. The mapping graph is built at startup and cached
for fast lookups during gap analysis.

Framework families
------------------
Several bundled catalogs are views of a larger one: the NIST SP 800-53
Rev 5 Low, Moderate, High and Privacy baselines and the FedRAMP Rev 5
baselines all draw their controls from the full ``nist-800-53-rev5``
catalog, and the three OSPS Baseline maturity levels draw their
assessment requirements from one baseline. A crosswalk authored against
the parent (the *family*) applies to every member, so the engine accepts
a ``families`` mapping (member id to family id, sourced from the manifest's
``crosswalk_family`` column) and consults both the member's own key and
its family's key on every lookup. Without it, a gap found against
``fedramp-rev5-moderate`` would receive no cross-framework value from a
crosswalk keyed on ``nist-800-53-rev5``, which is exactly what happened
through v0.12.

:func:`resolve_crosswalk` measures how many of a crosswalk's source and
target ids exist in the bundled catalogs. The catalog-truth gate and the
generated crosswalk reference page both read it.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

from evidentia_core.models.catalog import (
    CrosswalkDefinition,
    FrameworkMapping,
    _normalize_control_id,
)

logger = logging.getLogger(__name__)

MAPPINGS_DIR = Path(__file__).parent / "data" / "mappings"


class CrosswalkEngine:
    """Bidirectional cross-framework control mapping engine.

    Loads all available crosswalk definitions and builds an in-memory
    mapping graph for fast lookups.
    """

    def __init__(
        self,
        mappings_dir: Path | None = None,
        families: Mapping[str, str] | None = None,
    ) -> None:
        self._dir = mappings_dir or MAPPINGS_DIR
        # member framework id -> family framework id
        self._families: dict[str, str] = dict(families or {})
        # Forward index: (source_fw, source_ctl, target_fw) → [FrameworkMapping]
        self._forward: dict[tuple[str, str, str], list[FrameworkMapping]] = {}
        # Reverse index built from each forward entry
        self._reverse: dict[tuple[str, str, str], list[FrameworkMapping]] = {}
        self._crosswalks: list[CrosswalkDefinition] = []

    @property
    def families(self) -> Mapping[str, str]:
        """Member framework id to family id, as configured (read-only)."""
        return MappingProxyType(self._families)

    def lookup_keys(self, framework_id: str) -> tuple[str, ...]:
        """The framework ids consulted for ``framework_id``: itself, then its family."""
        family = self._families.get(framework_id)
        if family is None or family == framework_id:
            return (framework_id,)
        return (framework_id, family)

    def load_all(self) -> None:
        """Load all crosswalk JSON files from the mappings directory."""
        if not self._dir.exists():
            logger.warning("Mappings directory not found: %s", self._dir)
            return

        for json_file in sorted(self._dir.glob("*.json")):
            self.load_crosswalk(json_file)

        logger.info(
            "Loaded %d crosswalks with %d total mappings",
            len(self._crosswalks),
            sum(len(c.mappings) for c in self._crosswalks),
        )

    def load_crosswalk(self, path: Path) -> CrosswalkDefinition:
        """Load a single crosswalk definition and index it."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        crosswalk = CrosswalkDefinition(**data)
        self._crosswalks.append(crosswalk)

        for mapping in crosswalk.mappings:
            src_key = (
                crosswalk.source_framework,
                mapping.source_control_id.upper(),
                crosswalk.target_framework,
            )
            self._forward.setdefault(src_key, []).append(mapping)

            # Reverse mapping (swap source/target)
            rev_mapping = FrameworkMapping(
                source_control_id=mapping.target_control_id,
                source_control_title=mapping.target_control_title,
                target_control_id=mapping.source_control_id,
                target_control_title=mapping.source_control_title,
                relationship=mapping.relationship,
                notes=mapping.notes,
            )
            rev_key = (
                crosswalk.target_framework,
                mapping.target_control_id.upper(),
                crosswalk.source_framework,
            )
            self._reverse.setdefault(rev_key, []).append(rev_mapping)

        return crosswalk

    def get_mapped_controls(
        self,
        source_framework: str,
        source_control_id: str,
        target_framework: str,
    ) -> list[FrameworkMapping]:
        """Get controls in target_framework that map from source_control_id.

        Checks both forward and reverse indexes, for the framework ids
        themselves and for their families.
        """
        ctl = source_control_id.strip().upper()

        # Deduplicate by target_control_id
        seen: set[str] = set()
        results: list[FrameworkMapping] = []
        for src_key in self.lookup_keys(source_framework):
            for tgt_key in self.lookup_keys(target_framework):
                key = (src_key, ctl, tgt_key)
                for m in self._forward.get(key, []) + self._reverse.get(key, []):
                    if m.target_control_id.upper() not in seen:
                        seen.add(m.target_control_id.upper())
                        results.append(m)

        return results

    def get_all_mapped_controls(
        self,
        framework: str,
        control_id: str,
    ) -> dict[str, list[FrameworkMapping]]:
        """Get all controls across ALL frameworks that map to/from this control.

        Returns a dict keyed by target framework ID. A member framework
        also receives every crosswalk keyed on its family.
        """
        ctl = control_id.strip().upper()
        keys = set(self.lookup_keys(framework))
        results: dict[str, list[FrameworkMapping]] = {}

        for (src_fw, src_ctl, tgt_fw), mappings in self._forward.items():
            if src_fw in keys and src_ctl == ctl:
                results.setdefault(tgt_fw, []).extend(mappings)

        for (src_fw, src_ctl, tgt_fw), mappings in self._reverse.items():
            if src_fw in keys and src_ctl == ctl:
                results.setdefault(tgt_fw, []).extend(mappings)

        return results

    def get_cross_framework_value(
        self,
        framework: str,
        control_id: str,
    ) -> list[str]:
        """Get a flat list of 'framework:control_id' pairs that this control maps to.

        Used for gap prioritization — controls that satisfy more frameworks
        are higher value to implement.
        """
        all_mappings = self.get_all_mapped_controls(framework, control_id)
        result: list[str] = []
        for target_fw, mappings in all_mappings.items():
            for m in mappings:
                result.append(f"{target_fw}:{m.target_control_id}")
        return result

    @property
    def available_frameworks(self) -> set[str]:
        """All framework IDs that appear in loaded crosswalks."""
        frameworks: set[str] = set()
        for crosswalk in self._crosswalks:
            frameworks.add(crosswalk.source_framework)
            frameworks.add(crosswalk.target_framework)
        return frameworks


@dataclass(frozen=True)
class CrosswalkResolution:
    """How many of a crosswalk's rows point at ids that exist in a bundled catalog.

    ``source_ids_known`` / ``target_ids_known`` are False when no bundled
    catalog (or family) exists for that side, in which case the resolved
    count is 0 and the ratio is ``None`` rather than a misleading zero.
    """

    file: str
    source_framework: str
    target_framework: str
    rows: int
    source_ids_known: bool
    target_ids_known: bool
    source_resolved: int
    target_resolved: int
    unresolved_source_ids: tuple[str, ...]
    unresolved_target_ids: tuple[str, ...]

    @property
    def source_ratio(self) -> float | None:
        """Share of rows whose source id resolves; ``None`` when unknowable."""
        if not self.source_ids_known:
            return None
        return 1.0 if self.rows == 0 else self.source_resolved / self.rows

    @property
    def target_ratio(self) -> float | None:
        """Share of rows whose target id resolves; ``None`` when unknowable."""
        if not self.target_ids_known:
            return None
        return 1.0 if self.rows == 0 else self.target_resolved / self.rows


def resolve_crosswalk(
    crosswalk: CrosswalkDefinition,
    *,
    source_ids: Collection[str] | None,
    target_ids: Collection[str] | None,
    file: str = "",
) -> CrosswalkResolution:
    """Measure a crosswalk against the normalized id sets of its two catalogs.

    ``source_ids`` and ``target_ids`` hold ids already normalized with the
    catalog index rule (``AC-2(1)`` and ``ac-2.1`` both become ``AC-2.1``),
    or ``None`` when that side has no bundled catalog. Pure: no I/O.
    """
    src_known = source_ids is not None
    tgt_known = target_ids is not None
    src_set = frozenset(source_ids or ())
    tgt_set = frozenset(target_ids or ())
    src_resolved = 0
    tgt_resolved = 0
    src_missing: set[str] = set()
    tgt_missing: set[str] = set()
    for mapping in crosswalk.mappings:
        if src_known:
            if _normalize_control_id(mapping.source_control_id) in src_set:
                src_resolved += 1
            else:
                src_missing.add(mapping.source_control_id)
        if tgt_known:
            if _normalize_control_id(mapping.target_control_id) in tgt_set:
                tgt_resolved += 1
            else:
                tgt_missing.add(mapping.target_control_id)
    return CrosswalkResolution(
        file=file,
        source_framework=crosswalk.source_framework,
        target_framework=crosswalk.target_framework,
        rows=len(crosswalk.mappings),
        source_ids_known=src_known,
        target_ids_known=tgt_known,
        source_resolved=src_resolved,
        target_resolved=tgt_resolved,
        unresolved_source_ids=tuple(sorted(src_missing)),
        unresolved_target_ids=tuple(sorted(tgt_missing)),
    )
