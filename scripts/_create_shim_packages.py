"""[DEPRECATED 2026-04-24] Historical reference: shim package generator.

The 6 controlbridge-* shim workspace members were removed at v0.7.0 per the
public contract documented in README.md, RENAMED.md, and CHANGELOG.md. The
v0.5.1 shim wheels remain on PyPI for installed users (manually yanked at
the v0.7.0 ship).

This script is preserved for historical reference only and no longer
needs to be run. Do not use it to regenerate the shim packages — the
contract has been satisfied.

----- Original docstring (v0.6.0) -----

Generate six transitional shim packages for the v0.6.0 ControlBridge -> Evidentia rename.

Each shim is a v0.5.1 patch release of the old `controlbridge-*` PyPI name
that depends on its `evidentia-*` replacement and emits a DeprecationWarning
on first import. The shim re-exports top-level names + aliases every
submodule via `sys.modules`, so pre-rename code like

    from controlbridge_core.models import GapReport

continues to work (with the warning) until the shim is yanked at v0.7.0.

Run once. Produces:
  packages/shim-controlbridge/
  packages/shim-controlbridge-core/
  packages/shim-controlbridge-ai/
  packages/shim-controlbridge-api/
  packages/shim-controlbridge-collectors/
  packages/shim-controlbridge-integrations/

After running, add the new members to the workspace root pyproject.toml.
"""

from __future__ import annotations

import sys
from pathlib import Path
from textwrap import dedent

# ---------------------------------------------------------------------------
# Shim configuration — one row per old package.
# ---------------------------------------------------------------------------
# Columns:
#   old_pypi         old PyPI distribution name (e.g., controlbridge-core)
#   old_module       old import name            (e.g., controlbridge_core)
#   new_pypi         new PyPI distribution name (e.g., evidentia-core)
#   new_module       new import name            (e.g., evidentia_core)
#   description      shipped in pyproject.toml
#   keywords         shipped in pyproject.toml
#   cli_entry        console-script entry point (or None)

SHIMS: list[dict[str, object]] = [
    {
        "old_pypi": "controlbridge",
        "old_module": "controlbridge",
        "new_pypi": "evidentia",
        "new_module": "evidentia",
        "description": "DEPRECATED: renamed to 'evidentia'. Transitional re-export shim; removed in v0.7.0.",
        "keywords": ["grc", "compliance", "deprecated", "renamed", "evidentia"],
        # The new `evidentia` package owns both `evidentia` and `cb` CLI entry
        # points. The shim only provides `controlbridge` to avoid collision on
        # `cb` when both packages are installed during migration.
        "cli_entries": {"controlbridge": "controlbridge.cli.main:app"},
    },
    {
        "old_pypi": "controlbridge-core",
        "old_module": "controlbridge_core",
        "new_pypi": "evidentia-core",
        "new_module": "evidentia_core",
        "description": "DEPRECATED: renamed to 'evidentia-core'. Transitional re-export shim; removed in v0.7.0.",
        "keywords": ["grc", "compliance", "deprecated", "renamed", "evidentia-core"],
        "cli_entries": {},
    },
    {
        "old_pypi": "controlbridge-ai",
        "old_module": "controlbridge_ai",
        "new_pypi": "evidentia-ai",
        "new_module": "evidentia_ai",
        "description": "DEPRECATED: renamed to 'evidentia-ai'. Transitional re-export shim; removed in v0.7.0.",
        "keywords": ["grc", "compliance", "deprecated", "renamed", "evidentia-ai"],
        "cli_entries": {},
    },
    {
        "old_pypi": "controlbridge-api",
        "old_module": "controlbridge_api",
        "new_pypi": "evidentia-api",
        "new_module": "evidentia_api",
        "description": "DEPRECATED: renamed to 'evidentia-api'. Transitional re-export shim; removed in v0.7.0.",
        "keywords": ["grc", "compliance", "deprecated", "renamed", "evidentia-api"],
        "cli_entries": {},
    },
    {
        "old_pypi": "controlbridge-collectors",
        "old_module": "controlbridge_collectors",
        "new_pypi": "evidentia-collectors",
        "new_module": "evidentia_collectors",
        "description": "DEPRECATED: renamed to 'evidentia-collectors'. Transitional re-export shim; removed in v0.7.0.",
        "keywords": ["grc", "compliance", "deprecated", "renamed", "evidentia-collectors"],
        "cli_entries": {},
    },
    {
        "old_pypi": "controlbridge-integrations",
        "old_module": "controlbridge_integrations",
        "new_pypi": "evidentia-integrations",
        "new_module": "evidentia_integrations",
        "description": (
            "DEPRECATED: renamed to 'evidentia-integrations'. "
            "Transitional re-export shim; removed in v0.7.0."
        ),
        "keywords": ["grc", "compliance", "deprecated", "renamed", "evidentia-integrations"],
        "cli_entries": {},
    },
]


def make_pyproject(row: dict[str, object]) -> str:
    keywords_list = ", ".join(f'"{k}"' for k in row["keywords"])  # type: ignore[union-attr]
    scripts_block = ""
    cli_entries: dict[str, str] = row["cli_entries"]  # type: ignore[assignment]
    if cli_entries:
        lines = "\n".join(f'{name} = "{path}"' for name, path in cli_entries.items())
        scripts_block = f"\n[project.scripts]\n{lines}\n"
    return dedent(
        f'''\
[project]
name = "{row["old_pypi"]}"
version = "0.5.1"
description = "{row["description"]}"
readme = "README.md"
authors = [{{name = "Allen Byrd", email = "allen@allenfbyrd.com"}}]
license = "Apache-2.0"
requires-python = ">=3.12"
keywords = [{keywords_list}]
classifiers = [
    "Development Status :: 7 - Inactive",
    "Intended Audience :: Information Technology",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: OS Independent",
    "Programming Language :: Python :: 3.12",
    "Typing :: Typed",
]
dependencies = [
    "{row["new_pypi"]}>=0.6.0,<0.7.0",
]
{scripts_block}
[project.urls]
Homepage = "https://github.com/polycentric-labs/evidentia"
Repository = "https://github.com/polycentric-labs/evidentia"
Issues = "https://github.com/polycentric-labs/evidentia/issues"
Changelog = "https://github.com/polycentric-labs/evidentia/blob/main/CHANGELOG.md"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["src/{row["old_module"]}"]

[tool.uv.sources]
{row["new_pypi"]} = {{ workspace = true }}
'''
    )


def make_init(row: dict[str, object]) -> str:
    return dedent(
        f'''\
"""DEPRECATED — {row["old_pypi"]} has been renamed to {row["new_pypi"]}.

This transitional shim re-exports everything from `{row["new_module"]}` and aliases
every submodule into `{row["old_module"]}.*` via `sys.modules`, so pre-rename imports
like `from {row["old_module"]}.submodule import Foo` continue to work.

The shim will be removed in v0.7.0 (~6 months after v0.6.0 ships).

Migration:
    pip install {row["new_pypi"]}

Then rewrite `{row["old_module"]}` to `{row["new_module"]}` in your imports.
"""

from __future__ import annotations

import importlib as _importlib
import pkgutil as _pkgutil
import sys as _sys
import warnings as _warnings

_OLD_PYPI = "{row["old_pypi"]}"
_NEW_PYPI = "{row["new_pypi"]}"
_OLD_MODULE = "{row["old_module"]}"
_NEW_MODULE = "{row["new_module"]}"

_warnings.warn(
    f"'{{_OLD_PYPI}}' has been renamed to '{{_NEW_PYPI}}' to resolve a naming "
    "collision with an unrelated commercial product. Install the replacement "
    f"with `pip install {{_NEW_PYPI}}` and update imports from "
    f"`{{_OLD_MODULE}}` to `{{_NEW_MODULE}}`. This shim will be removed in "
    "v0.7.0. See https://github.com/polycentric-labs/evidentia/blob/main/CHANGELOG.md",
    DeprecationWarning,
    stacklevel=2,
)

_new_pkg = _importlib.import_module(_NEW_MODULE)

# Walk the new package's submodule tree FIRST so every `foo.bar.baz` module
# is present in `sys.modules` and attached as an attribute of its parent.
# We then register each submodule under the old name (both in `sys.modules`
# for import-machinery lookups AND as an attribute of the appropriate
# aliased parent module for attribute-access lookups — Python does NOT
# fall through to `sys.modules` when resolving `pkg.sub` via `.` access).
if hasattr(_new_pkg, "__path__"):
    for _info in _pkgutil.walk_packages(_new_pkg.__path__, prefix=f"{{_NEW_MODULE}}."):
        try:
            _mod = _importlib.import_module(_info.name)
        except ImportError:
            # Optional extras-gated submodules may fail without the extra
            # installed — safe to skip; the user will get the same
            # ImportError if they try to use that submodule directly.
            continue
        _aliased = _info.name.replace(_NEW_MODULE, _OLD_MODULE, 1)
        _sys.modules[_aliased] = _mod

# Re-export EVERY top-level public attribute the new package exposes, now
# that submodule imports above have populated `evidentia_*`'s namespace.
for _attr in dir(_new_pkg):
    if not _attr.startswith("_"):
        globals()[_attr] = getattr(_new_pkg, _attr)

# Preserve `__version__` (the no-underscore filter above drops dunders).
if hasattr(_new_pkg, "__version__"):
    __version__ = _new_pkg.__version__
'''
    )


def make_readme(row: dict[str, object]) -> str:
    return dedent(
        f'''\
# {row["old_pypi"]} (DEPRECATED)

**This package has been renamed to [`{row["new_pypi"]}`](https://pypi.org/project/{row["new_pypi"]}/).**

The name change resolves a conflict with an unrelated commercial product.
This v0.5.1 release is a transitional re-export shim that forwards every
import to `{row["new_pypi"]}`. It will be **removed in v0.7.0 (~October 2026)**.

## Migration

```bash
pip uninstall {row["old_pypi"]}
pip install {row["new_pypi"]}
```

Then update any imports:

```python
# before
import {row["old_module"]}
from {row["old_module"]}.submodule import Thing

# after
import {row["new_module"]}
from {row["new_module"]}.submodule import Thing
```

## Why

See the [v0.6.0 CHANGELOG entry](https://github.com/polycentric-labs/evidentia/blob/main/CHANGELOG.md)
for the full rename rationale.
'''
    )


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    pkg_dir = repo_root / "packages"
    if not pkg_dir.is_dir():
        print(f"error: expected {pkg_dir} to exist", file=sys.stderr)
        return 1

    created = 0
    for row in SHIMS:
        old_pypi = row["old_pypi"]
        old_module = row["old_module"]
        shim_root = pkg_dir / f"shim-{old_pypi}"
        src = shim_root / "src" / old_module  # type: ignore[operator]
        src.mkdir(parents=True, exist_ok=True)

        (shim_root / "pyproject.toml").write_text(make_pyproject(row), encoding="utf-8")
        (shim_root / "README.md").write_text(make_readme(row), encoding="utf-8")
        (src / "__init__.py").write_text(make_init(row), encoding="utf-8")
        # Provide a py.typed marker so tools treat the shim as typed; the
        # re-exports pick up the new package's types automatically.
        (src / "py.typed").write_text("", encoding="utf-8")

        print(f"  created {shim_root.relative_to(repo_root)}")
        created += 1

    print(f"shims_created={created}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
