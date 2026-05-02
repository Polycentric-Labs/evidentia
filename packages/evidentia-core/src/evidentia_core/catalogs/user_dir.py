"""User-imported catalog directory management.

v0.2.0 introduces a user-writable catalog directory so organizations
can load their own licensed copies of Tier-C stubs (ISO 27001, SOC 2,
PCI DSS, HITRUST, etc.) without touching the installed package. The
directory location follows platform conventions via ``platformdirs``:

- Windows:  ``%APPDATA%\\Evidentia\\catalogs\\``
- macOS:    ``~/Library/Application Support/evidentia/catalogs/``
- Linux:    ``~/.local/share/evidentia/catalogs/``

Override with the ``EVIDENTIA_CATALOG_DIR`` environment variable
or the ``--catalog-dir`` CLI flag (passed through to callers).

User-dir catalogs **shadow bundled catalogs of the same framework_id**
— precedence is user > bundled. This lets a user import, e.g., a real
AICPA TSC JSON and have ``evidentia catalog show soc2-tsc CC6.1``
render their licensed text instead of the stub.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml
from platformdirs import user_data_dir

from evidentia_core.catalogs.manifest import (
    FrameworkManifest,
    FrameworkManifestEntry,
)

logger = logging.getLogger(__name__)

CATALOG_DIR_ENV_VAR = "EVIDENTIA_CATALOG_DIR"
USER_MANIFEST_FILENAME = "frameworks.yaml"


def get_user_catalog_dir(override: Path | None = None) -> Path:
    """Resolve the user catalog directory.

    Precedence:
    1. Explicit ``override`` argument (CLI flag)
    2. ``EVIDENTIA_CATALOG_DIR`` environment variable
    3. Platform default from ``platformdirs.user_data_dir``
    """
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(CATALOG_DIR_ENV_VAR)
    if env:
        return Path(env).expanduser().resolve()
    # "evidentia" = app name, "Evidentia" = app author
    return Path(user_data_dir("evidentia", "Evidentia")) / "catalogs"


def ensure_user_dir(override: Path | None = None) -> Path:
    """Get the user catalog directory, creating it if it doesn't exist."""
    path = get_user_catalog_dir(override)
    path.mkdir(parents=True, exist_ok=True)
    return path


def user_manifest_path(override: Path | None = None) -> Path:
    """Path to the user-dir ``frameworks.yaml`` (may not yet exist)."""
    return get_user_catalog_dir(override) / USER_MANIFEST_FILENAME


def load_user_manifest(override: Path | None = None) -> FrameworkManifest:
    """Load the user-dir manifest, or return an empty one if it doesn't exist.

    A missing manifest is not an error — most users won't have imported
    anything yet. Returns a manifest with empty ``frameworks`` list.
    """
    path = user_manifest_path(override)
    if not path.exists():
        return FrameworkManifest(version=1, frameworks=[])
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    # Tolerate legacy or hand-edited manifests missing version
    raw.setdefault("version", 1)
    raw.setdefault("frameworks", [])
    return FrameworkManifest.model_validate(raw)


def save_user_manifest(
    manifest: FrameworkManifest, override: Path | None = None
) -> Path:
    """Persist the user-dir manifest as YAML."""
    ensure_user_dir(override)
    path = user_manifest_path(override)
    # model_dump(mode="json") gives us plain dicts with JSON-safe values;
    # yaml.safe_dump then handles the serialization.
    payload = manifest.model_dump(mode="json", exclude_none=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.safe_dump(payload, f, sort_keys=False, default_flow_style=False)
    return path


def resolve_catalog_path(
    framework_id: str,
    bundled_manifest: FrameworkManifest,
    user_manifest: FrameworkManifest | None = None,
    user_dir_override: Path | None = None,
    bundled_data_dir: Path | None = None,
) -> tuple[Path, FrameworkManifestEntry, str]:
    """Resolve a framework ID to a catalog path, respecting user-dir precedence.

    Returns ``(path, entry, source)`` where ``source`` is ``"user"`` or
    ``"bundled"``. Raises ``ValueError`` if the framework isn't found in
    either manifest.
    """
    # User manifest wins if the framework is declared there
    if user_manifest is None:
        user_manifest = load_user_manifest(user_dir_override)
    user_entry = user_manifest.get(framework_id)
    if user_entry is not None:
        user_dir = get_user_catalog_dir(user_dir_override)
        path = user_dir / user_entry.path
        # %r (repr) escapes control chars in user-controlled framework_id
        # + path — closes CodeQL py/log-injection alert #81 (CWE-117)
        # per v0.7.8 P0.5 S2. framework_id comes from CLI/API arg;
        # path derives from user_entry which is loaded from user-supplied
        # manifest YAML.
        logger.info(
            "Framework %r resolved from user dir (%r) — shadows bundled catalog"
            if bundled_manifest.get(framework_id)
            else "Framework %r resolved from user dir (%r)",
            framework_id,
            path,
        )
        return path, user_entry, "user"

    # Fall back to bundled
    bundled_entry = bundled_manifest.get(framework_id)
    if bundled_entry is None:
        all_ids = sorted(
            {fw.id for fw in bundled_manifest.frameworks}
            | {fw.id for fw in user_manifest.frameworks}
        )
        raise ValueError(
            f"Unknown framework '{framework_id}'. Available: {', '.join(all_ids)}"
        )

    if bundled_data_dir is None:
        from evidentia_core.catalogs.loader import DATA_DIR

        bundled_data_dir = DATA_DIR
    return bundled_data_dir / bundled_entry.path, bundled_entry, "bundled"
