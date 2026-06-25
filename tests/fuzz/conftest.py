"""Hypothesis profile setup for the fuzz-parity property tests.

Mirrors ``tests/property/conftest.py`` so the property tests that
complement the atheris harnesses run under the same deterministic
``ci`` profile (derandomized, bounded deadline, reproducible across
machines). Set ``HYPOTHESIS_PROFILE=dev`` for a wider local search.

The atheris ``fuzz_*.py`` harnesses in this directory are NOT pytest
tests — they have no ``test_`` functions and are skipped by collection.
They are built + run by ClusterFuzzLite (``.clusterfuzzlite/``). The
``test_parser_robustness.py`` module here is the cross-platform
Hypothesis complement that DOES run under pytest.
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "ci",
    # deadline=None: same reason as tests/property/conftest.py — a per-example
    # wall-clock deadline flakes in CI (these parser harnesses do temp-file IO,
    # so they are even more timing-sensitive). Hangs are caught by the job
    # timeout; perf belongs in explicit benchmarks.
    deadline=None,
    derandomize=True,
    max_examples=200,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "dev",
    deadline=1000,
    derandomize=False,
    max_examples=500,
)

settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "ci"))
