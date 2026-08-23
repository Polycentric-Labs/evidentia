"""Rewrite FedRAMP pointer catalogs to carry real NIST 800-53 text.

v0.2.1: FedRAMP baselines in ``data/us-federal/fedramp-rev5-*.json`` were
pointer-only — each control's description was the literal placeholder
"See nist-800-53-rev5 catalog for full control text...". Now that the
full NIST catalog is bundled (see ``fetch_nist_oscal.py``), we can
populate real titles and descriptions by control-ID lookup.

A control that does not resolve against the bundled NIST catalog FAILS the
run (exit 1). Through v0.11.2 this script only logged such controls, which is
how four withdrawn Rev 5 ids (CM-8(5), CP-2(4), SA-12, SC-13(1)) sat in the
shipped baselines unnoticed while the membership itself was wrong. A baseline
that claims a nonexistent control is a defect, so it is now loud.

Run via: ``uv run python scripts/catalogs/rewrite_fedramp_pointers.py``
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

logger = logging.getLogger("rewrite_fedramp")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_DIR = (
    REPO_ROOT
    / "packages"
    / "evidentia-core"
    / "src"
    / "evidentia_core"
    / "catalogs"
    / "data"
    / "us-federal"
)

FEDRAMP_FILES = [
    "fedramp-rev5-low.json",
    "fedramp-rev5-moderate.json",
    "fedramp-rev5-high.json",
    "fedramp-rev5-li-saas.json",
]


def _load_nist_lookup() -> dict:
    """Return a dict keyed by normalized control ID → (title, description).

    Uses the same normalization rule as ``ControlCatalog._normalize_control_id``
    so NIST-pub style (``AC-2(1)``) and OSCAL style (``ac-2.1``) both resolve
    to the same key.
    """
    sys.path.insert(0, str(REPO_ROOT / "packages" / "evidentia-core" / "src"))
    from evidentia_core.catalogs.loader import load_oscal_catalog

    nist_path = DATA_DIR / "nist-800-53-rev5.json"
    catalog = load_oscal_catalog(nist_path)
    # catalog._index is a dict[normalized_id -> CatalogControl] but it's
    # private. Walk .controls recursively to build our lookup directly.

    from evidentia_core.models.catalog import _normalize_control_id

    lookup: dict[str, tuple[str, str]] = {}

    def _walk(ctrl) -> None:
        lookup[_normalize_control_id(ctrl.id)] = (ctrl.title, ctrl.description)
        for enh in ctrl.enhancements:
            _walk(enh)

    for c in catalog.controls:
        _walk(c)

    logger.info("Built NIST lookup: %d control IDs", len(lookup))
    return lookup, _normalize_control_id


def rewrite_fedramp(path: Path, nist_lookup, normalize) -> list[str]:
    """In-place rewrite: replace pointer descriptions with NIST content.

    Returns the control IDs that could not be resolved against the bundled NIST
    catalog. An unresolved ID is a DEFECT, not a curiosity: it means a baseline
    claims a control that does not exist in NIST SP 800-53 Rev 5, which is how
    the four withdrawn controls (CM-8(5), CP-2(4), SA-12, SC-13(1)) survived in
    the shipped baselines while the membership itself was wrong. The caller
    fails the run on any unresolved ID.
    """
    data = json.loads(path.read_text(encoding="utf-8"))
    controls = data.get("controls", [])

    resolved_count = 0
    unresolved_count = 0
    unresolved_ids: list[str] = []

    for ctrl in controls:
        raw_id = ctrl.get("id", "")
        norm_id = normalize(raw_id)
        desc = ctrl.get("description", "")
        # Only rewrite pointers; if a human has already given the control
        # a real description, leave it alone.
        if "See nist-800-53-rev5 catalog" not in desc:
            continue
        if norm_id in nist_lookup:
            real_title, real_desc = nist_lookup[norm_id]
            ctrl["title"] = real_title
            ctrl["description"] = real_desc
            resolved_count += 1
        else:
            unresolved_count += 1
            unresolved_ids.append(raw_id)

    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    logger.info(
        "%s: resolved=%d unresolved=%d",
        path.name,
        resolved_count,
        unresolved_count,
    )
    if unresolved_ids:
        logger.error(
            "  UNRESOLVED IDs (no such active control in NIST SP 800-53 Rev 5): %s",
            ", ".join(unresolved_ids),
        )
    return unresolved_ids


def main() -> None:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
    )
    nist_lookup, normalize = _load_nist_lookup()
    unresolved: dict[str, list[str]] = {}
    for fname in FEDRAMP_FILES:
        path = DATA_DIR / fname
        if not path.exists():
            logger.warning("Skipping missing file: %s", path)
            continue
        bad = rewrite_fedramp(path, nist_lookup, normalize)
        if bad:
            unresolved[fname] = bad
    if unresolved:
        logger.error(
            "FAILED: %d baseline file(s) reference controls that do not exist in "
            "NIST SP 800-53 Rev 5. A baseline must never claim a withdrawn or "
            "nonexistent control. Fix the membership in "
            "scripts/catalogs/upstream/fedramp-rev5-baselines.json, do not "
            "suppress this check.",
            len(unresolved),
        )
        for fname, ids in unresolved.items():
            logger.error("  %s: %s", fname, ", ".join(ids))
        raise SystemExit(1)
    logger.info("Done, every control resolved. Re-run scripts/catalogs/regenerate_manifest.py.")


if __name__ == "__main__":
    main()
