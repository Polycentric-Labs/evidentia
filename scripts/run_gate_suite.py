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
  ``version_consistency`` + ``docs_health`` + ``readme_releases`` +
  ``doc_counts`` + the three wiki drift gates (``wiki_mirrors_drift`` +
  ``wiki_reference_drift`` + ``wiki_api_docs_drift``). This is the set the
  pre-push hook and the push/PR ``consistency.yml`` enforce on every change.
* ``full`` — ``consistency`` PLUS the heavyweight gates
  (``pytest`` + ``mypy`` + ``ruff`` + ``ruff_format`` + ``osv`` + ``parity``). This is
  the set the tag-time ``gate`` job runs before any artifact is
  published.

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


# The staleness guards: fast, no test/type/scan execution. These four
# are the consistency scope AND the checks the pre-push hook already
# runs locally — mirroring them into push/PR CI catches drift on PRs
# independent of whether a contributor has the local hook configured.
# All are pure-filesystem (no evidentia package import), keeping this
# scope importable in a light CI install.
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
    # README capability-count drift: the at-a-glance counts (catalogs /
    # crosswalks / collectors / MCP-tools) must equal the code-derived
    # truth. Pure-filesystem (parses the catalogs manifest + openapi.json +
    # the MCP server source), so it stays in the fast consistency scope.
    Check(
        "doc_counts",
        ("python", "scripts/check_doc_counts.py"),
    ),
    # Wiki mirror/reference/API drift gates (docs-airtightness A1.1). Each
    # generator has a --check mode that regenerates its wiki pages in memory
    # and byte-compares them against the committed copies; a non-zero exit is
    # drift. These previously ran ONLY inside sync-wiki.yml's regenerate steps
    # (which overwrite + push, so drift was silently corrected at deploy time,
    # never surfaced as a failing PR/push check) — a mirror drift shipped
    # undetected this cycle. Wiring them into the consistency scope makes them
    # blocking in consistency.yml (push/PR/merge_group) AND the pre-push hook,
    # with no ruleset change. They read the workspace (sync_reference imports
    # the Typer app; sync_api_docs reads each package's source), which the
    # `uv run --all-extras --all-packages` env in _run_check + consistency.yml's
    # `uv sync --all-packages` both provide. All three PASS on HEAD.
    Check(
        "wiki_mirrors_drift",
        ("python", "scripts/wiki/sync_mirrors.py", "--check"),
    ),
    Check(
        "wiki_reference_drift",
        ("python", "scripts/wiki/sync_reference.py", "--check"),
    ),
    Check(
        "wiki_api_docs_drift",
        ("python", "scripts/wiki/sync_api_docs.py", "--check"),
    ),
    # ROADMAP↔CHANGELOG currency gate (v0.11 cycle-open; engineering-practices
    # lesson 11). Status headings must agree with the CHANGELOG's shipped
    # blocks (four shipped releases sat mis-marked PLANNED through v0.10.17),
    # exactly one cycle may be open, and the open cycle must link an on-disk
    # plan doc. Pure-filesystem (reads docs/ROADMAP.md + CHANGELOG.md, stats
    # plan-doc paths — deliberately NOT git tags, which the shallow CI
    # checkout cannot see), so it stays in the fast consistency scope.
    Check(
        "roadmap_currency",
        ("python", "scripts/check_roadmap_currency.py"),
    ),
    # api-stability↔code drift gate (v0.12 freeze-prep). docs/api-stability.md
    # has been NORMATIVE since v0.9.7 with nothing mechanically enforcing it;
    # the gate's first run found four §5 frozen imports that had never
    # resolved on any shipped release. It executes every §5 import, compares
    # the frozen MCP tool table against the live server, and asserts every
    # frozen env var still appears in packages/*/src. Needs the workspace
    # importable (it spawns subprocesses that import evidentia_mcp), which the
    # `uv run --all-extras --all-packages` env in _run_check + consistency.yml's
    # `uv sync --all-packages` both provide — same requirement as the wiki
    # drift checks above, so it belongs in the same fast scope.
    Check(
        "public_surface",
        ("python", "scripts/check_public_surface.py"),
    ),
)

# The heavyweight gates, appended to the consistency tuple to form
# ``full``. Listing them as an extension (rather than a separate set)
# is what guarantees ``consistency`` is a strict subset of ``full``.
_FULL_ONLY_CHECKS: tuple[Check, ...] = (
    Check("pytest", ("python", "-m", "pytest", "tests/", "-q")),
    Check("mypy", ("mypy", *_MYPY_PACKAGES, "--strict-optional")),
    Check("ruff", ("ruff", "check", ".")),
    Check("ruff_format", ("ruff", "format", "--check", ".")),
    Check("osv", ("python", "scripts/run_osv_scan.py")),
    # The CLI<->GUI parity gate (v0.10.9 item D: advisory -> blocking).
    # Full-only because it imports the live CLI app for the leaf walk —
    # too heavy for the pre-push consistency scope, and parity.yml
    # already gives per-push early signal.
    Check("parity", ("python", "scripts/check_parity.py")),
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
        raise ValueError(f"unknown scope {scope!r}; expected one of {sorted(_SCOPES)}") from None


def _run_check(check: Check) -> int:
    """Shell out to one check via ``uv run``; return its exit code."""
    # Gate fidelity: resolve every check against the SAME --all-extras
    # --all-packages environment CI uses (test.yml's pytest / mypy / osv jobs
    # sync ``--all-extras --all-packages``). Without this, the local pre-push
    # gate ran pytest in the default no-extras env, so the collector-SSRF tests
    # that import optional DB/cloud drivers (snowflake / databricks / psycopg)
    # failed locally with ModuleNotFoundError while passing in CI — a false-red
    # that erodes trust in the gate. One environment definition, used locally
    # AND in CI, so "passes locally" and "passes in CI" cannot mean two
    # different things.
    cmd = ["uv", "run", "--all-extras", "--all-packages", *check.argv]
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
            "guards) or 'full' (consistency + pytest/mypy/ruff/osv/"
            "parity). Default: full."
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

    print(f"Running the '{args.scope}' gate suite ({len(selected)} check(s)): {', '.join(c.name for c in selected)}")

    failures: list[str] = []
    for check in selected:
        if _run_check(check) != 0:
            failures.append(check.name)

    print("\n" + "=" * 62)
    if failures:
        print(f"GATE SUITE ({args.scope}): FAILED — {len(failures)} of {len(selected)} check(s) failed:")
        for name in failures:
            print(f"  - {name}")
        print("=" * 62)
        return 1

    print(f"GATE SUITE ({args.scope}): PASS — all {len(selected)} check(s) green.")
    print("=" * 62)
    return 0


if __name__ == "__main__":
    sys.exit(main())
