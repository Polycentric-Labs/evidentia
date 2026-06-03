"""Tests for ``scripts/check_parity.py`` (v0.10.8 Phase C-2).

The CLI<->GUI parity gate. Four PURE check functions (completeness,
api-existence, gui-existence, debt-ratchet) plus loaders that derive the
real inputs from the live Typer app, openapi.json, App.tsx + lib/api.ts.

These tests pin the four invariants against tiny in-memory fixtures (a fake
manifest + fake openapi ops + fake App.tsx/lib/api.ts sets) so they stay
fast and filesystem-/network-free. ``scripts/`` has no ``__init__.py``; the
repo root is placed on ``sys.path`` so it resolves as a PEP 420 namespace
package, matching the ``from scripts import …`` import form used across the
gate tooling.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import check_parity as p  # noqa: E402


def test_completeness_fails_on_unlisted_cli_leaf() -> None:
    # a live CLI leaf missing from the manifest -> error
    errs = p.check_completeness(
        cli_leaves={"gap analyze", "poam list"},
        manifest_clis={"gap analyze"},
    )
    assert any("poam list" in e for e in errs)


def test_api_existence_fails_when_op_absent() -> None:
    errs = p.check_api_existence(
        rows=[{"cli": "x", "api": "GET /api/nope"}],
        openapi_ops={"GET /api/gap/analyze"},
    )
    assert errs


def test_gui_existence_requires_route_and_wiring() -> None:
    # status:full but route absent from App.tsx -> error (the types-only illusion)
    errs = p.check_gui_existence(
        rows=[{"cli": "x", "gui": "/poam", "status": "full"}],
        app_routes=set(),
        api_ts_paths=set(),
    )
    assert errs


def test_debt_ratchet_fails_when_cli_only_increases() -> None:
    errs = p.check_debt_ratchet(current_cli_only=8, baseline_cli_only=6)
    assert errs
