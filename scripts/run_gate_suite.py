#!/usr/bin/env python3
"""Single-source-of-truth gate runner (v0.10.8 Phase A-1).

Evidentia's release-path quality gates lived in three places that could
silently diverge: the ``.githooks/pre-push`` hook (version + docs
staleness guards), the per-job checks scattered across
``.github/workflows/test.yml`` (pytest / mypy / ruff / osv), and the
documented release-checklist commands. The irreversible PyPI publish
(``release.yml``, fires on ``git push origin vX.Y.Z``) ran NONE of them
at tag time. The v0.9.8 ship taught the gate-fidelity lesson: a CI gate
and its checklist counterpart must run the EXACT same check, or a break
slips through the gap between them.

This module is that one definition. It is a DECLARATIVE list of named
checks, each pairing a ``name`` with the argv of an EXISTING repo script
(no check logic is reimplemented here). Every surface — the tag-time
``gate`` job in ``release.yml``, the push/PR ``consistency.yml``
workflow, and ad-hoc local runs — invokes this runner, so they cannot
drift.

Scopes
======

* ``consistency`` — the fast staleness guards (no test/type/scan run):
  ``version_consistency`` + ``docs_health`` + ``readme_releases``. This
  is the set the pre-push hook and the push/PR ``consistency.yml``
  enforce on every change.
* ``full`` — ``consistency`` PLUS the heavyweight gates
  (``pytest`` + ``mypy`` + ``ruff`` + ``osv``). This is the set the
  tag-time ``gate`` job runs before any artifact is published.

``full`` is a strict superset of ``consistency`` by construction (it is
the consistency tuple extended with the heavy checks), so a tag that
passes ``full`` has necessarily passed ``consistency``.

Each check's argv reuses the corresponding repo script verbatim — the
SAME invocation the standalone CI jobs use — and is shelled out to via
``uv run`` so it resolves against the synced workspace venv. The mypy
argv is copied verbatim from ``test.yml``'s ``typecheck`` job (the
7-package ``--strict-optional`` invocation).

Exit codes:
    0 — ``--list`` mode, or every selected check passed.
    1 — at least one selected check failed (the runner reports which).
    2 — usage error (argparse handles this).

Usage:
    python scripts/run_gate_suite.py --scope full
    python scripts/run_gate_suite.py --scope consistency
    python scripts/run_gate_suite.py --scope full --list
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from dataclasses import dataclass

# The seven evidentia-* packages mypy type-checks. Copied verbatim from
# the ``typecheck`` job in .github/workflows/test.yml so the tag-time
# gate and the standalone CI job run byte-identical mypy invocations.
_MYPY_PACKAGES = (
    "packages/evidentia-core/src/evidentia_core",
    "packages/evidentia/src/evidentia",
    "packages/evidentia-api/src/evidentia_api",
    "packages/evidentia-integrations/src/evidentia_integrations",
    "packages/evidentia-collectors/src/evidentia_collectors",
    "packages/evidentia-ai/src/evidentia_ai",
    "packages/evidentia-mcp/src/evidentia_mcp",
)


@dataclass(frozen=True)
class Check:
    """One named gate check.

    ``argv`` is the command tail AFTER ``uv run`` (the runner prepends
    ``uv run`` at execution time so every check resolves against the
    synced workspace venv). ``argv`` reuses an existing repo script
    verbatim — this runner never reimplements a check's logic.
    """

    name: str
    argv: tuple[str, ...]


# The staleness guards: fast, no test/type/scan execution. These three
# are the consistency scope AND the checks the pre-push hook already
# runs locally — mirroring them into push/PR CI catches drift on PRs
# independent of whether a contributor has the local hook configured.
_CONSISTENCY_CHECKS: tuple[Check, ...] = (
    Check(
        "version_consistency",
        ("python", "scripts/check_version_consistency.py"),
    ),
    Check(
        "docs_health",
        ("python", "scripts/check_docs_health.py", "--strict"),
    ),
    Check(
        "readme_releases",
        ("python", "scripts/gen_readme_releases.py", "--check"),
    ),
)

# The heavyweight gates, appended to the consistency tuple to form
# ``full``. Listing them as an extension (rather than a separate set)
# is what guarantees ``consistency`` is a strict subset of ``full``.
_FULL_ONLY_CHECKS: tuple[Check, ...] = (
    Check("pytest", ("python", "-m", "pytest", "tests/", "-q")),
    Check("mypy", ("mypy", *_MYPY_PACKAGES, "--strict-optional")),
    Check("ruff", ("ruff", "check", ".")),
    Check("osv", ("python", "scripts/run_osv_scan.py")),
)

# scope name -> ordered checks. ``full`` is ``consistency`` + the heavy
# checks, so the subset invariant the tests assert holds by construction.
_SCOPES: dict[str, tuple[Check, ...]] = {
    "consistency": _CONSISTENCY_CHECKS,
    "full": _CONSISTENCY_CHECKS + _FULL_ONLY_CHECKS,
}


def checks_for_scope(scope: str) -> tuple[Check, ...]:
    """Return the ordered checks for ``scope`` (``full`` or ``consistency``)."""
    try:
        return _SCOPES[scope]
    except KeyError:  # pragma: no cover - argparse `choices` guards the CLI
        raise ValueError(
            f"unknown scope {scope!r}; expected one of {sorted(_SCOPES)}"
        ) from None


def _run_check(check: Check) -> int:
    """Shell out to one check via ``uv run``; return its exit code."""
    cmd = ["uv", "run", *check.argv]
    print(f"\n--- {check.name} ---")
    print(f"$ {' '.join(cmd)}")
    proc = subprocess.run(cmd, check=False)
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--scope",
        choices=sorted(_SCOPES),
        default="full",
        help=(
            "which set of checks to run: 'consistency' (the staleness "
            "guards) or 'full' (consistency + pytest/mypy/ruff/osv). "
            "Default: full."
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        dest="list_only",
        help="print the selected check names (one per line) and exit 0.",
    )
    args = parser.parse_args(argv)

    selected = checks_for_scope(args.scope)

    if args.list_only:
        for check in selected:
            print(check.name)
        return 0

    print(
        f"Running the '{args.scope}' gate suite "
        f"({len(selected)} check(s)): {', '.join(c.name for c in selected)}"
    )

    failures: list[str] = []
    for check in selected:
        if _run_check(check) != 0:
            failures.append(check.name)

    print("\n" + "=" * 62)
    if failures:
        print(
            f"GATE SUITE ({args.scope}): FAILED — "
            f"{len(failures)} of {len(selected)} check(s) failed:"
        )
        for name in failures:
            print(f"  - {name}")
        print("=" * 62)
        return 1

    print(f"GATE SUITE ({args.scope}): PASS — all {len(selected)} check(s) green.")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
