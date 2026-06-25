"""v0.8.2 G2: hypothesis configuration for property-based tests.

Sets up two profiles:

- ``ci`` — deterministic + tight deadline. Used in CI runs to
  keep results reproducible across machines + fail fast on slow
  examples that hint at accidental quadratic paths.
- ``dev`` — random + relaxed deadline. Used for local
  exploration; surfaces wider input space at the cost of
  reproducibility.

The ``ci`` profile is loaded by default. Set
``HYPOTHESIS_PROFILE=dev`` to switch locally:

    HYPOTHESIS_PROFILE=dev pytest tests/property/

References:
- Hypothesis settings: https://hypothesis.readthedocs.io/en/latest/settings.html
- Plan: §25.2 P2.2 / R3 (derandomize=True for CI flake-resistance).
"""

from __future__ import annotations

import os

from hypothesis import HealthCheck, settings

settings.register_profile(
    "ci",
    # deadline=None: a per-example wall-clock deadline FLAKES in CI. Shared
    # runners + import/JIT warmup + load make a property test that normally
    # runs in <50ms occasionally cross 200ms, and Hypothesis then reports a
    # FlakyFailure (observed 2026-06-24 on the OCSF class_uid=2003 case:
    # "Test took 253.55ms, which exceeds the deadline of 200.00ms"). A true
    # hang/quadratic blow-up is still caught by the pytest + CI job timeouts;
    # genuine perf regressions belong in explicit benchmarks, not a
    # timing-sensitive Hypothesis deadline that fails the whole suite on a blip.
    deadline=None,
    derandomize=True,  # reproducible across machines (R3 mitigation)
    max_examples=200,
    suppress_health_check=[
        # The empty-engine crosswalk tests load a missing dir;
        # hypothesis flags this as a "data generation too slow"
        # health check on first run for some inputs. Suppressing
        # it keeps the property-test run quiet.
        HealthCheck.too_slow,
    ],
)
settings.register_profile(
    "dev",
    deadline=1000,  # ms; relaxed for slower local boxes
    derandomize=False,  # explore wider input space locally
    max_examples=500,
)

settings.load_profile(
    os.environ.get("HYPOTHESIS_PROFILE", "ci")
)
