"""Local-directory MarketplaceProvider reference implementation
(v0.8.0 P0.4).

Loads OSCAL catalogs from a local directory tree. Each catalog
is a single ``<catalog_id>.json`` file. An optional
``manifest.json`` at the directory root carries enriched
metadata (title, version, license); without it, the provider
falls back to filename-based heuristics.

This is intentionally a thin filesystem wrapper so out-of-tree
authors can copy + modify it as a starting point for HTTPS-
backed / cloud-hosted / registry-passthrough providers.

Path traversal is gated via the canonical
:func:`evidentia_core.security.paths.validate_within` helper.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from evidentia_core.plugins.marketplace._base import (
    CatalogManifest,
    MarketplaceProvider,
)
from evidentia_core.security.paths import validate_within


class LocalDirectoryMarketplaceProvider(MarketplaceProvider):
    """Reference :class:`MarketplaceProvider` implementation.

    Loads OSCAL catalogs from ``<base_dir>/<catalog_id>.json``.
    An optional ``<base_dir>/manifest.json`` provides enriched
    metadata; without it, manifest fields are inferred from
    filename / file stat.

    Args:
        base_dir: The directory containing OSCAL catalog JSON
            files.
        provider_name: Optional name for audit-log identification.
            Defaults to ``"local-directory"``.

    Raises:
        FileNotFoundError: ``base_dir`` doesn't exist.

    Manifest format (optional file at ``<base_dir>/manifest.json``):

    .. code-block:: json

        {
          "catalogs": [
            {
              "catalog_id": "my-org-baseline",
              "title": "My Org Compliance Baseline",
              "version": "2026.01",
              "license": "Apache-2.0"
            }
          ]
        }
    """

    def __init__(
        self,
        *,
        base_dir: Path | str,
        provider_name: str = "local-directory",
    ) -> None:
        path = Path(base_dir).expanduser().resolve()
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(
                f"MarketplaceProvider base_dir not found at {path}"
            )
        self._base = path
        self._name = provider_name
        self._manifest: dict[str, dict[str, Any]] = {}
        manifest_file = path / "manifest.json"
        if manifest_file.exists():
            try:
                data = json.loads(manifest_file.read_text(encoding="utf-8"))
                for entry in data.get("catalogs", []):
                    cid = entry.get("catalog_id")
                    if isinstance(cid, str):
                        self._manifest[cid] = entry
            except (json.JSONDecodeError, ValueError) as exc:
                # v0.8.1 F-V08-S5: emit an audit warning so the
                # operator sees the misconfiguration. v0.8.0
                # silently fell back to filename heuristics; the
                # silence masked configuration drift. Provider
                # still works (filename heuristics are the v0.8.0
                # fallback path); operator now knows to fix.
                from evidentia_core.audit import (
                    EventAction,
                    EventOutcome,
                    get_logger,
                )

                _log = get_logger("evidentia.plugins.marketplace.local_directory")
                _log.warning(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.UNKNOWN,
                    message=(
                        f"LocalDirectoryMarketplaceProvider: "
                        f"manifest.json at {manifest_file} is "
                        f"malformed ({type(exc).__name__}); "
                        f"falling back to filename heuristics. "
                        f"Catalog metadata will be limited to "
                        f"defaults until the manifest is repaired."
                    ),
                    evidentia={
                        "manifest_path": str(manifest_file),
                        "error_type": type(exc).__name__,
                    },
                )

    def list_catalogs(self) -> Iterator[CatalogManifest]:
        for catalog_file in self._base.glob("*.json"):
            if catalog_file.name == "manifest.json":
                continue
            cid = catalog_file.stem
            stat = catalog_file.stat()
            entry = self._manifest.get(cid, {})
            yield CatalogManifest(
                catalog_id=cid,
                title=entry.get("title", cid),
                version=entry.get("version", "unknown"),
                provider=self._name,
                license=entry.get("license"),
                size_bytes=stat.st_size,
                provider_metadata={"path": str(catalog_file)},
            )

    def fetch_catalog(self, catalog_id: str) -> dict[str, Any]:
        candidate = self._base / f"{catalog_id}.json"
        # Defense-in-depth path-traversal guard.
        path = validate_within(candidate, self._base)
        if not path.exists():
            raise KeyError(f"No catalog at {catalog_id!r}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, ValueError) as e:
            raise ValueError(
                f"Catalog {catalog_id!r} cannot be parsed as JSON: {e}"
            ) from e
        if not isinstance(data, dict):
            raise ValueError(
                f"Catalog {catalog_id!r} is not a JSON object"
            )
        return data

    def name(self) -> str:
        return self._name
