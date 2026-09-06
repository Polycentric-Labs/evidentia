#!/usr/bin/env python3
"""Self-lift watcher for the workspace's ``requires-python<3.15`` cap.

The workspace's true Python ceiling is ``<3.15`` because litellm
(evidentia-ai dep) declares ``requires_python "<3.15,>=3.10"``; the root
``pyproject.toml`` is capped to ``>=3.12,<3.15`` to keep Dependabot's
resolver out of the unsatisfiable ``>=3.15`` fork. This
sentinel WATCHES litellm's published ``requires_python`` on PyPI and NUDGES
(opens a tracking issue) once it relaxes past the target Python — the signal
that the cap can be lifted.

Detect-and-nudge only: this script never edits ``pyproject.toml`` or
``uv.lock``. It is fail-soft — a PyPI fetch failure, malformed JSON, or a
missing/null ``requires_python`` field must never turn this sentinel red
(mirrors ``check_workflow_liveness.py``); it is treated as "can't tell yet,
don't nudge" and the script still exits 0.

Keyed on ``info.requires_python`` specifically, NOT on PyPI classifiers —
litellm ships empty ``Programming Language :: Python`` classifiers, so a
classifier-based check would silently never fire.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion

DEFAULT_PACKAGE = "litellm"
DEFAULT_TARGET = "3.15.0"

_Opener = Callable[..., Any]


def fetch_requires_python(package: str, opener: _Opener = urllib.request.urlopen) -> str | None:
    """GET PyPI's JSON API and return ``info.requires_python`` (may be None
    if the field is null/absent). FAIL-SOFT: any of a network error, a
    malformed payload, or a missing key returns None rather than raising —
    the caller treats None as "can't tell, don't nudge, don't fail"."""
    url = f"https://pypi.org/pypi/{package}/json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with opener(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        value = data["info"]["requires_python"]
    except (OSError, ValueError, KeyError):
        # OSError covers URLError/HTTPError/read-phase TimeoutError; ValueError
        # covers JSONDecodeError; KeyError covers a missing info/requires_python.
        return None
    return value if isinstance(value, str) else None


def ceiling_allows(requires_python: str | None, target: str = DEFAULT_TARGET) -> bool:
    """True when the published ``requires_python`` specifier now allows
    ``target`` — i.e. the cap can be lifted. None/empty always means False
    (nothing to lift yet, or we couldn't tell)."""
    if not requires_python:
        return False
    try:
        return SpecifierSet(requires_python).contains(target, prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        # A malformed specifier (an unexpected PyPI value) or a malformed target
        # must not crash the sentinel — "can't tell" means don't nudge, don't
        # fail (the exit-0 detect-and-nudge doctrine).
        return False


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--package", default=DEFAULT_PACKAGE, help="PyPI package to watch")
    ap.add_argument("--target", default=DEFAULT_TARGET, help="Python version the cap is blocking")
    ap.add_argument("--output", required=True, help="nudge markdown path")
    args = ap.parse_args(argv)

    requires_python = fetch_requires_python(args.package)
    if requires_python is None:
        print(
            f"WARN: could not determine {args.package}'s requires_python "
            "(fetch failed or field absent/null) — skipping, no nudge",
            file=sys.stderr,
        )
        Path(args.output).write_text("", encoding="utf-8")
        print(f"check_python_ceiling: {args.package} requires_python unknown, 0 finding(s)")
        return 0

    if ceiling_allows(requires_python, args.target):
        finding = (
            f'- **{args.package}** now declares `requires_python = "{requires_python}"`, '
            f"which allows Python {args.target}, so the `requires-python<3.15` cap in the "
            "root `pyproject.toml` can be lifted."
        )
        Path(args.output).write_text(finding + "\n", encoding="utf-8")
        print(finding)
        print(f"check_python_ceiling: {args.package} ceiling now allows {args.target}, 1 finding")
    else:
        Path(args.output).write_text("", encoding="utf-8")
        print(
            f"check_python_ceiling: {args.package} requires_python "
            f'"{requires_python}" still caps below {args.target}, 0 finding(s)'
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
