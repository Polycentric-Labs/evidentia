"""Tests for ``scripts/run_gate_suite.py`` (v0.10.8 Phase A-1).

The single-source-of-truth gate runner: a declarative list of named checks
that the tag-time gate, push/PR consistency CI, and the pre-push hook all
call through, so the three surfaces can never diverge (the v0.9.8
gate-fidelity lesson).

These tests pin the declarative contract — the scope sets and the ``--list``
mode — without shelling out to the underlying checks (so they stay fast and
network-free). ``scripts/`` has no ``__init__.py``; the repo root is placed
on ``sys.path`` so it resolves as a PEP 420 namespace package, matching the
``from scripts import …`` import form used across the gate tooling.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import run_gate_suite as g  # noqa: E402


def test_scopes_are_declarative() -> None:
    full = {c.name for c in g.checks_for_scope("full")}
    consistency = {c.name for c in g.checks_for_scope("consistency")}
    # The staleness guards are the consistency scope and a subset of full.
    # roadmap_currency is the v0.11 cycle-open doc-currency gate (lesson 11).
    assert {
        "version_consistency",
        "docs_health",
        "readme_releases",
        "roadmap_currency",
    } <= consistency
    assert consistency < full
    assert {"pytest", "mypy", "ruff", "ruff_format", "osv", "parity"} <= full
    # parity is full-only (v0.10.9 item D): the tag-time gate hard-blocks a
    # parity regression; the fast consistency scope stays staleness-only.
    assert "parity" not in consistency


def test_cli_lists_checks_without_running(capsys) -> None:
    rc = g.main(["--scope", "consistency", "--list"])
    out = capsys.readouterr().out
    assert rc == 0 and "version_consistency" in out
