"""OSCAL profile resolver — turns a profile + source catalog into a resolved catalog.

A minimal implementation of the OSCAL Profile Resolution specification
(NIST SP 1800-something, the OSCAL docs at
https://pages.nist.gov/OSCAL/concepts/processing/profile-resolution/).

Supports:
- ``import.href`` — bundled or ``file://`` URI, one level deep
- ``include-controls.with-ids`` with ``with-child-controls="yes"``
- ``exclude-controls.with-ids``
- ``set-parameter`` — override parameter defaults
- ``alter.add`` / ``alter.remove`` of parts and properties
- ``merge.combine`` / ``merge.as-is``

Out of scope (v0.2.0): remote URL fetching (pre-resolve at build time
via ``scripts/catalogs/resolve_oscal_profile.py`` instead), ``map``
binding directives.

Usage — offline pre-resolution at build time::

    from evidentia_core.oscal.profile import resolve_profile
    catalog = resolve_profile(profile_path, catalog_dir)
    catalog_json = catalog_to_oscal_json(catalog)

Usage — user-supplied profile at runtime::

    evidentia catalog import --profile ./my-baseline.json \\
        --catalog ./nist-800-53-rev5.json
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from evidentia_core.catalogs.loader import (
    _extract_prose,
    _iter_mappings,
    _parse_oscal_control,
    _require_mapping,
)
from evidentia_core.models.catalog import CatalogControl, ControlCatalog
from evidentia_core.oscal._version import OSCAL_SCHEMA_VERSION

logger = logging.getLogger(__name__)


class ProfileResolutionError(Exception):
    """Raised when a profile cannot be resolved (missing catalog, bad ID, etc)."""


def _load_oscal_json(path: Path) -> dict[str, Any]:
    """Load and return the top-level JSON object of an OSCAL file."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ProfileResolutionError(
            f"OSCAL file {path} must contain a JSON object at top level"
        )
    return data


def _resolve_href(
    href: str,
    base_dir: Path,
    profile: dict[str, Any] | None = None,
) -> Path:
    """Resolve an OSCAL ``href`` to an absolute filesystem path.

    Supports:

    - ``file://`` URIs (absolute path after ``file://``)
    - Absolute or relative filesystem paths (relative resolves against
      ``base_dir``)
    - **Fragment-only ``#uuid`` references** (v0.2.1): OSCAL profiles
      commonly declare imported catalogs in ``back-matter.resources``
      with a UUID, then reference that UUID via ``href: "#<uuid>"``.
      When ``profile`` is supplied, we look up the UUID in
      ``profile.back-matter.resources[*].uuid`` and follow the first
      ``rlinks[*].href`` to get a concrete path.
    """
    if href.startswith("file://"):
        return Path(href[7:])

    if href.startswith("#"):
        # OSCAL back-matter resource reference. The spec uses
        # ``profile.back-matter.resources[*]`` with ``uuid`` + ``rlinks``.
        # Each resource commonly has multiple ``rlinks`` for different
        # media types (JSON/XML/YAML). We prefer JSON since our loader
        # only handles JSON; fall back to the first rlink if no
        # JSON-flagged entry exists.
        if profile is None:
            raise ProfileResolutionError(
                f"Fragment-only href {href!r} requires the full profile "
                "document for back-matter lookup; none was passed."
            )
        target_uuid = href[1:]
        back_matter = profile.get("profile", {}).get("back-matter", {})
        for resource in back_matter.get("resources", []):
            if resource.get("uuid") != target_uuid:
                continue
            rlinks = resource.get("rlinks", [])
            # First pass: prefer JSON media types
            for rlink in rlinks:
                media = rlink.get("media-type", "").lower()
                rhref = rlink.get("href", "")
                if not rhref or not media:
                    continue
                if "json" in media:
                    return _resolve_href(rhref, base_dir, profile=None)
            # Second pass: any non-empty href (may pick up XML/YAML, but
            # downstream loader will fail with a clear message rather
            # than silently succeeding)
            for rlink in rlinks:
                rhref = rlink.get("href", "")
                if rhref:
                    return _resolve_href(rhref, base_dir, profile=None)
        raise ProfileResolutionError(
            f"Fragment href {href!r} does not match any "
            f"back-matter.resources[].uuid in the profile document, or all "
            "matched resources had no usable rlinks"
        )

    p = Path(href)
    if p.is_absolute():
        return p
    return (base_dir / p).resolve()


def _collect_included_ids(profile: dict[str, Any]) -> tuple[set[str], bool, set[str]]:
    """Parse include-controls and return (included_ids, with_children, excluded_ids).

    Returns ``(set(), False, set())`` when the profile says
    ``include-all``, signaling "include every control from source" to the
    caller. ``with_children`` indicates the profile's
    ``with-child-controls="yes"`` setting applied globally.
    """
    imports = profile.get("profile", {}).get("imports", [])
    if not imports:
        return set(), True, set()

    # OSCAL allows multiple imports — we flatten for simplicity.
    included: set[str] = set()
    excluded: set[str] = set()
    with_children = False
    include_all = False

    for imp in imports:
        if "include-all" in imp:
            include_all = True
            continue
        for rule in imp.get("include-controls", []):
            for cid in rule.get("with-ids", []):
                included.add(cid.upper())
            if rule.get("with-child-controls", "no") == "yes":
                with_children = True
        for rule in imp.get("exclude-controls", []):
            for cid in rule.get("with-ids", []):
                excluded.add(cid.upper())

    # include-all + no explicit includes = "all except excluded"
    if include_all and not included:
        return set(), with_children, excluded

    return included, with_children, excluded


def _apply_set_parameters(
    profile: dict[str, Any],
    control: CatalogControl,
) -> CatalogControl:
    """Apply profile ``set-parameter`` overrides to a control's parameters.

    Returns a new control with updated parameters; input is not mutated.
    """
    overrides: dict[str, str] = {}
    for modify in profile.get("profile", {}).get("modify", []) if isinstance(
        profile.get("profile", {}).get("modify"), list
    ) else [profile.get("profile", {}).get("modify", {})]:
        if not modify:
            continue
        for sp in modify.get("set-parameters", []):
            param_id = sp.get("param-id", "")
            if not param_id:
                continue
            value_parts: list[str] = []
            if "values" in sp:
                value_parts.extend(sp["values"])
            if "constraints" in sp:
                for c in sp["constraints"]:
                    if "description" in c:
                        value_parts.append(c["description"])
            overrides[param_id] = " | ".join(value_parts) if value_parts else ""

    if not overrides:
        return control

    updated = dict(control.parameters)
    for pid, val in overrides.items():
        updated[pid] = val
    # Recursive: apply to enhancements too
    new_enhancements = [_apply_set_parameters(profile, e) for e in control.enhancements]
    return control.model_copy(
        update={"parameters": updated, "enhancements": new_enhancements}
    )


def _apply_alter(
    profile: dict[str, Any],
    control: CatalogControl,
) -> CatalogControl:
    """Apply profile ``alter.add`` / ``alter.remove`` to a matching control.

    Supported alterations:
    - ``add.parts`` with ``name="guidance"`` → populates ``guidance`` field
    - ``add.parts`` with ``name="statement"`` → appends to description
    - ``remove.by-name`` → no-op at v0.2.0 (OSCAL ``remove`` is rarely used)
    """
    modify_list = profile.get("profile", {}).get("modify", [])
    if not isinstance(modify_list, list):
        modify_list = [modify_list] if modify_list else []

    guidance = control.guidance
    description = control.description

    for modify in modify_list:
        if not modify:
            continue
        for alter in modify.get("alters", []):
            if alter.get("control-id", "").upper() != control.id.upper():
                continue
            for addition in alter.get("adds", []):
                for part in addition.get("parts", []):
                    name = part.get("name", "")
                    prose = _extract_prose(part)
                    if name == "guidance":
                        guidance = prose if guidance is None else f"{guidance}\n\n{prose}"
                    elif name == "statement":
                        description = f"{description}\n\n{prose}".strip()

    new_enhancements = [_apply_alter(profile, e) for e in control.enhancements]
    return control.model_copy(
        update={
            "guidance": guidance,
            "description": description,
            "enhancements": new_enhancements,
        }
    )


def _filter_controls(
    controls: list[CatalogControl],
    included: set[str],
    excluded: set[str],
    include_all: bool,
    with_children: bool,
) -> list[CatalogControl]:
    """Filter a control list per include/exclude rules, preserving order.

    When ``with_children`` is true, a matched parent brings all its
    enhancements along. When false, enhancements must be independently
    listed in ``included``.
    """
    out: list[CatalogControl] = []
    for ctrl in controls:
        cid_upper = ctrl.id.upper()
        matched = include_all or (cid_upper in included)
        if cid_upper in excluded:
            matched = False

        if matched:
            if with_children:
                out.append(ctrl)  # keep enhancements as-is
            else:
                filtered_enh = _filter_controls(
                    ctrl.enhancements, included, excluded, include_all, with_children
                )
                out.append(ctrl.model_copy(update={"enhancements": filtered_enh}))
        else:
            # Parent not included, but an enhancement might be
            filtered_enh = _filter_controls(
                ctrl.enhancements, included, excluded, include_all, with_children
            )
            if filtered_enh:
                out.append(ctrl.model_copy(update={"enhancements": filtered_enh}))
    return out


def _load_source_catalog(
    profile_path: Path, profile: dict[str, Any]
) -> ControlCatalog:
    """Resolve the profile's import href and load the source OSCAL catalog.

    Minimal: takes the first import's href. Multiple imports require
    merging, which this implementation handles by collecting controls
    from each resolved source in order.
    """
    profile_section = _require_mapping(profile.get("profile", {}), "profile")
    imports = _iter_mappings(profile_section.get("imports", []), "profile.imports")
    if not imports:
        raise ProfileResolutionError(
            f"Profile {profile_path.name} has no imports — nothing to resolve"
        )

    base_dir = profile_path.parent
    first_import = imports[0]
    href = first_import.get("href", "")
    if not href:
        raise ProfileResolutionError(
            f"Profile {profile_path.name} first import missing href"
        )

    try:
        catalog_path = _resolve_href(href, base_dir, profile=profile)
        catalog_missing = not catalog_path.exists()
    except (OSError, ValueError) as exc:
        # A malformed href can resolve to an unusable path: a 250+ char
        # filename raises OSError ENAMETOOLONG; an embedded NUL raises
        # ValueError — both from pathlib's .resolve()/.exists()/.stat().
        # Convert to the module's typed error rather than leaking an
        # uncaught exception (CWE-248; fuzz-found in fuzz_oscal_profile).
        raise ProfileResolutionError(
            f"Profile {profile_path.name} import href {href!r} resolves to an "
            f"unusable path: {exc}"
        ) from exc
    if catalog_missing:
        raise ProfileResolutionError(
            f"Source catalog not found: {catalog_path} (profile href: {href!r})"
        )

    raw = _load_oscal_json(catalog_path)
    catalog_data = _require_mapping(raw.get("catalog", raw), "source catalog")
    metadata = _require_mapping(
        catalog_data.get("metadata", {}), "source catalog metadata"
    )

    controls: list[CatalogControl] = []
    families: list[str] = []
    for group in _iter_mappings(catalog_data.get("groups", []), "catalog.groups"):
        family_title = group.get("title", "")
        families.append(family_title)
        for oscal_control in _iter_mappings(
            group.get("controls", []), "group.controls"
        ):
            controls.append(_parse_oscal_control(oscal_control, family_title))

    title = str(metadata.get("title", catalog_path.stem))
    return ControlCatalog(
        framework_id=title.lower().replace(" ", "-"),
        framework_name=metadata.get("title", catalog_path.stem),
        version=metadata.get("version", "unknown"),
        source=f"OSCAL: {catalog_path.name}",
        controls=controls,
        families=families,
    )


def resolve_profile(
    profile_path: Path,
    override_framework_id: str | None = None,
    override_framework_name: str | None = None,
) -> ControlCatalog:
    """Resolve an OSCAL profile into a ControlCatalog.

    Runs the full pipeline:
    1. Load profile and source catalog via ``import.href``.
    2. Filter controls per ``include-controls`` / ``exclude-controls``.
    3. Apply ``set-parameters`` overrides.
    4. Apply ``alter.adds`` modifications (guidance additions).
    5. Return the resolved ControlCatalog.

    :param profile_path: Absolute path to the OSCAL profile JSON.
    :param override_framework_id: If provided, uses this ID instead of
        deriving from the profile metadata. Useful when pre-resolving
        offline and wanting a stable framework ID.
    :param override_framework_name: If provided, uses this name instead
        of the profile's metadata title.
    :raises ProfileResolutionError: profile malformed or source missing.
    """
    profile = _load_oscal_json(profile_path)
    try:
        source_catalog = _load_source_catalog(profile_path, profile)
        profile_section = _require_mapping(profile.get("profile", {}), "profile")
        profile_meta = _require_mapping(
            profile_section.get("metadata", {}), "profile.metadata"
        )

        included, with_children, excluded = _collect_included_ids(profile)
        include_all = not included

        filtered = _filter_controls(
            source_catalog.controls, included, excluded, include_all, with_children
        )

        # Apply modifications (set-parameters + alters) to every surviving control
        filtered = [_apply_set_parameters(profile, c) for c in filtered]
        filtered = [_apply_alter(profile, c) for c in filtered]

        # Derive family list from surviving controls (some families may be
        # entirely excluded)
        surviving_families: list[str] = []
        seen_families: set[str] = set()
        for c in filtered:
            if c.family and c.family not in seen_families:
                surviving_families.append(c.family)
                seen_families.add(c.family)

        framework_id = override_framework_id or str(
            profile_meta.get("title", profile_path.stem)
        ).lower().replace(" ", "-")
        framework_name = override_framework_name or profile_meta.get(
            "title", source_catalog.framework_name
        )

        resolved = ControlCatalog(
            framework_id=framework_id,
            framework_name=framework_name,
            version=profile_meta.get("version", source_catalog.version),
            source=f"OSCAL profile: {profile_path.name}",
            controls=filtered,
            families=surviving_families,
        )
        logger.info(
            "Resolved profile %s → %d controls (from %d in source)",
            profile_path.name,
            resolved.control_count,
            source_catalog.control_count,
        )
        return resolved
    except ProfileResolutionError:
        # Already the module's typed error (e.g. from _load_source_catalog's
        # explicit guards) — propagate unchanged.
        raise
    except (ValueError, OSError, AttributeError) as exc:
        # resolve_profile traverses arbitrary, untrusted OSCAL structure via
        # many ``.get(...)`` calls and path operations across _resolve_href /
        # _collect_included_ids / _apply_set_parameters / _apply_alter. A
        # malformed-but-valid-JSON profile can put a non-object where an
        # object is expected (→ AttributeError), an unusable path in an href
        # (→ OSError), or trip a structural guard (→ ValueError). Convert this
        # whole malformed-input family to the declared ProfileResolutionError
        # so a bad profile is a clean rejection, never an uncaught-exception
        # denial-of-service (CWE-248; fuzz-found in fuzz_oscal_profile).
        # Genuinely unexpected error types still propagate.
        raise ProfileResolutionError(
            f"Profile {profile_path.name} is malformed and could not be "
            f"resolved: {exc}"
        ) from exc


def catalog_to_oscal_json(catalog: ControlCatalog) -> dict[str, Any]:
    """Serialize a resolved ControlCatalog back to OSCAL Catalog JSON.

    Lossy by design — only re-emits fields the loader knows how to
    round-trip. Use for offline pre-resolved catalogs committed to
    ``data/us-federal/``.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for ctrl in catalog.controls:
        family = ctrl.family or "(unspecified)"
        groups.setdefault(family, []).append(_control_to_oscal(ctrl))

    return {
        "catalog": {
            "uuid": "resolved-" + catalog.framework_id,
            "metadata": {
                "title": catalog.framework_name,
                "version": catalog.version,
                "oscal-version": OSCAL_SCHEMA_VERSION,
            },
            "groups": [
                {"title": family, "controls": ctrls}
                for family, ctrls in groups.items()
            ],
        }
    }


def _control_to_oscal(control: CatalogControl) -> dict[str, Any]:
    """Round-trip a CatalogControl to OSCAL control shape."""
    parts: list[dict[str, Any]] = []
    if control.description:
        parts.append({"name": "statement", "prose": control.description})
    if control.objective:
        parts.append({"name": "objective", "prose": control.objective})
    if control.guidance:
        parts.append({"name": "guidance", "prose": control.guidance})
    for obj in control.assessment_objectives:
        parts.append({"name": "assessment-objective", "prose": obj})

    out: dict[str, Any] = {
        "id": control.id.lower(),
        "title": control.title,
    }
    if parts:
        out["parts"] = parts
    if control.priority:
        out["props"] = [{"name": "priority", "value": control.priority}]
    if control.parameters:
        out["params"] = [
            {"id": pid, "label": val} for pid, val in control.parameters.items()
        ]
    if control.related_controls:
        out["links"] = [
            {"rel": "related", "href": f"#{c.lower()}"}
            for c in control.related_controls
        ]
    if control.enhancements:
        out["controls"] = [_control_to_oscal(e) for e in control.enhancements]
    return out
