"""Hatchling build hook — bundle the Vite-built React SPA into the wheel.

Runs before wheel packaging when ``uv build`` (or ``python -m build``) is
invoked for the ``evidentia-api`` package:

1. Checks if ``packages/evidentia-ui/dist/`` exists and is non-empty.
2. If yes, copies ``dist/*`` into ``src/evidentia_api/static/``.
3. If no, runs ``npm ci && npm run build`` in the UI directory to produce
   ``dist/`` first, then copies. Gracefully skips with a warning if Node
   isn't installed on the build machine — for Python-only contributors
   who only touch backend code.

The hook is a no-op on machines that set the ``EVIDENTIA_SKIP_FRONTEND_BUILD``
environment variable — convenient for CI matrices that separate concerns
between Python tests and frontend builds.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

logger = logging.getLogger("hatch.build.evidentia-api")

# Paths are resolved relative to the evidentia-api package root at
# build time. The UI sits one directory up.
_PKG_ROOT = Path(__file__).parent
_UI_DIR = (_PKG_ROOT.parent / "evidentia-ui").resolve()
_UI_DIST = _UI_DIR / "dist"
_STATIC_DEST = _PKG_ROOT / "src" / "evidentia_api" / "static"


class FrontendBundleHook(BuildHookInterface):  # type: ignore[misc]
    """Copies the React SPA build output into the Python package tree."""

    PLUGIN_NAME = "evidentia-frontend"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Invoked by hatchling before the wheel/sdist is assembled."""
        del version, build_data  # unused

        if os.environ.get("EVIDENTIA_SKIP_FRONTEND_BUILD"):
            logger.info(
                "EVIDENTIA_SKIP_FRONTEND_BUILD set; leaving static/ untouched."
            )
            return

        if not _UI_DIR.is_dir():
            logger.warning(
                "Frontend dir %s not found; skipping static bundle. "
                "The wheel will serve a dev-placeholder page.",
                _UI_DIR,
            )
            return

        # If the user hasn't run `npm run build` yet, try to do it now.
        if (not _UI_DIST.is_dir() or not any(_UI_DIST.iterdir())) and not _try_npm_build():
            # Node unavailable or build failed. Ship without the SPA.
            logger.warning(
                "Frontend build unavailable; static/ will remain empty. "
                "The wheel will serve a dev-placeholder page."
            )
            return

        self._copy_dist_to_static()

    def _copy_dist_to_static(self) -> None:
        """Sync ``dist/*`` -> ``static/``. Wipes stale assets first."""
        _STATIC_DEST.mkdir(parents=True, exist_ok=True)

        # Clear stale assets but keep the .gitkeep file so the directory
        # is preserved even when fresh checkouts haven't built yet.
        for item in _STATIC_DEST.iterdir():
            if item.name == ".gitkeep":
                continue
            if item.is_file() or item.is_symlink():
                item.unlink()
            else:
                shutil.rmtree(item)

        for src in _UI_DIST.iterdir():
            dest = _STATIC_DEST / src.name
            if src.is_dir():
                shutil.copytree(src, dest)
            else:
                shutil.copy2(src, dest)

        logger.info("Copied frontend bundle from %s -> %s", _UI_DIST, _STATIC_DEST)


def _try_npm_build() -> bool:
    """Attempt ``npm install && npm run build`` in the UI dir. Return True on success.

    Uses ``npm ci`` when ``package-lock.json`` already exists (faster + deterministic)
    and falls back to ``npm install`` when it doesn't — this covers fresh checkouts
    where the lockfile hasn't been committed yet.
    """
    npm = shutil.which("npm")
    if npm is None:
        logger.warning(
            "`npm` not found on PATH; cannot auto-build frontend. "
            "Install Node 20+ or run `npm install && npm run build` manually "
            "in packages/evidentia-ui/ before `uv build`."
        )
        return False

    lockfile = _UI_DIR / "package-lock.json"
    install_cmd = (
        [npm, "ci", "--no-audit", "--no-fund"]
        if lockfile.is_file()
        else [npm, "install", "--no-audit", "--no-fund"]
    )

    for cmd in (install_cmd, [npm, "run", "build"]):
        logger.info("Running: %s (cwd=%s)", " ".join(cmd), _UI_DIR)
        try:
            subprocess.run(cmd, cwd=_UI_DIR, check=True)
        except subprocess.CalledProcessError as e:
            logger.error("Frontend build step failed: %s", e)
            return False
    return True
