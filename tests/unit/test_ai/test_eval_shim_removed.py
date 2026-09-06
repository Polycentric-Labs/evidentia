"""Removal contract for the ``evidentia_ai.eval`` deprecation shim (v0.12.0).

The DFAH determinism + faithfulness harness was extracted from
``evidentia-ai`` to the dedicated ``evidentia-eval`` workspace
package in v0.10.5 P9. The old ``evidentia_ai.eval.*`` import
paths were kept as re-export shims (firing a
``DeprecationWarning`` at import time) through the v0.11.x
maintenance window, with removal announced for **v0.12.0** in
three places: the shim docstring, `docs/api-stability.md` §5, and
the `evidentia-ai` base-dependency comment.

v0.12.0 executes that removal. These tests pin it so the shim
cannot silently return — a re-added shim would resurrect the
air-gap install weight the extraction removed, and would make the
published removal notice false.

Migration for downstream callers::

    from evidentia_eval import DFAHarness, EvalSample  # v0.10.5+

The ``evidentia-ai[eval-faithfulness]`` install extra is NOT
removed — it still proxies to
``evidentia-eval[faithfulness-semantic]``. Only the import path
and the unconditional base dependency are gone.
"""

from __future__ import annotations

import importlib.util

import pytest

# Every module the v0.10.5 P9 shim package exposed. Each must be
# unimportable after the v0.12.0 removal.
REMOVED_SHIM_MODULES = [
    "evidentia_ai.eval",
    "evidentia_ai.eval.claim_extraction",
    "evidentia_ai.eval.faithfulness",
    "evidentia_ai.eval.faithfulness_semantic",
    "evidentia_ai.eval.harness",
    "evidentia_ai.eval.metrics",
    "evidentia_ai.eval.seeds",
    "evidentia_ai.eval.signing",
]


def test_eval_shim_package_has_no_import_spec() -> None:
    """``evidentia_ai.eval`` must not resolve to a module spec."""
    assert importlib.util.find_spec("evidentia_ai.eval") is None, (
        "the evidentia_ai.eval deprecation shim was removed in v0.12.0 "
        "but still resolves — did a stale package directory survive?"
    )


@pytest.mark.parametrize("module_name", REMOVED_SHIM_MODULES)
def test_removed_shim_module_raises_module_not_found(module_name: str) -> None:
    """Importing any removed shim module raises ``ModuleNotFoundError``."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module_name)


def test_evidentia_eval_remains_importable() -> None:
    """The replacement package is still the supported import path.

    The removal is of the *shim*, not the harness. Downstream code
    that already migrated to ``evidentia_eval`` keeps working.
    """
    spec = importlib.util.find_spec("evidentia_eval")
    assert spec is not None, (
        "evidentia_eval must remain importable — it is the migration target published in the v0.10.5 deprecation notice"
    )
