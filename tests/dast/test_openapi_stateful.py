r"""Schemathesis STATEFUL DAST — operation-sequence fuzzing (Horizon-A H-2).

Complements ``test_openapi_fuzz.py`` (stateless): walks
create -> read -> update -> delete chains via the OpenAPI ``links``
this deliverable added to the ai-gov and catalog lifecycles, hunting
IDOR / state-leak / stale-reference / sequence-dependent 5xx classes
that operation-by-operation fuzzing cannot reach. Opt-in like the rest
of ``tests/dast/`` (root ``addopts --ignore``). CI:
``.github/workflows/dast.yml`` (weekly + dispatch + api-path PRs;
non-required, observe-first).

Auth/RBAC note (probed 2026-07-06): ``create_app(offline=True)`` builds
the app under ``RBACPolicy``'s permissive ``DEFAULT_POLICY``, so the
``require_role(...)`` gates on the mutating routes are inert — all six
operations in the two linked lifecycles are reachable anonymously
(the RBAC-enforcement integration tests install a *separate*
deny-by-default policy to prove the gates bite by contrast). No
auth-bypass fixture is needed, matching the stateless suite's usage.

Registry isolation: the ai-gov handlers instantiate ``AIRegistryStore``
per request, which reads ``EVIDENTIA_AI_REGISTRY_DIR`` at construction.
The state machine and its app are built at MODULE IMPORT (below), before
any function-scoped fixture could run, so the isolation env var is set
here at import time to a throwaway temp dir — otherwise the fuzz run
would read and pollute the developer's real local registry.

Sequencing on this branch (``feat/stateful-dast-v2``): commits
``dc6c89a`` + ``998271d`` landed the substrate + true-fixes this
harness needs to run green with schemathesis's FULL DEFAULT CHECK SET:

1. A genuine unauthenticated 500 on ``POST /api/ai-gov/register``
   (whitespace-only ``provider``/``owner`` passed the request model's
   raw ``min_length=1`` then failed the whitespace-stripping registry
   model, uncaught) was fixed — normalized to 400, mirroring the
   sibling PUT handler.
2. The OpenAPI ``links`` this state machine walks (the six operations
   scoped below) were added to the ai-gov + catalog routers.
3. Schema mirrors of business rules the OpenAPI contract couldn't
   otherwise express: ``UpdateSystemRequest``'s at-least-one-field
   ``anyOf``; ``AISystemDescriptor.name``/``.purpose``'s ``pattern=r"\S"``
   (mirrors ``str_strip_whitespace`` + ``min_length``); ``system_id``'s
   UUID-shape pattern on the three ``{system_id}`` lifecycle ops;
   ``RegisterRequest``'s documented example.
4. An app-wide handler normalizing FastAPI's own hardcoded body-decode
   400 ("There was an error parsing the body") to the structured
   ``ErrorEnvelope`` shape (``response_schema_conformance``).

Rate-limit neutralization: the token-bucket limiter (60/min, burst 10
on POST /ai-gov/register) throttles the hundreds of rapid calls a
stateful run makes, surfacing 429s that are the limiter working AS
DESIGNED — not a lifecycle bug — which schemathesis's
positive_data_acceptance check would (correctly, but unhelpfully here)
flag as "valid data rejected". A business-logic-sequence fuzzer must
exercise the routes, not the throttle; rate-limit behavior has its own
dedicated tests (test_rate_limit.py). Test-side only: clear the
default rate-limited path set before the app + middleware are
constructed below — no production code changes, and
RateLimitMiddleware still installs.

Generation-reliability note: Hypothesis's stateful engine intermittently
raised ``Unsatisfiable`` ("N of N examples failed a filter/assume
condition") under ``phases=[Phase.generate]`` with a small example
budget, because ``AISystemDescriptor``'s multi-constraint nested body
(``name``/``purpose`` non-blank + ``max_length`` + the enum fields) is
comparatively hard to hit by unguided random generation within a single
state-machine step's budget — most generated ``register`` bodies failed
validation, starving the walk of a live ``system_id`` to chain the
GET/PUT/DELETE links off of. ``max_examples`` is raised well above the
original 25 so the run reliably produces at least one valid ``register``
body per invocation; ``derandomize=True`` (a fixed, version-pinned PRNG
seed schedule) + ``database=None`` (skip Hypothesis's local example
cache) keep the run deterministic across CI invocations rather than
depending on machine-local cached examples or wall-clock-seeded
randomness.
"""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest

schemathesis = pytest.importorskip("schemathesis")

from hypothesis import HealthCheck, Phase, settings  # noqa: E402

# Isolate the AI registry AND the user-catalog store BEFORE the app/schema
# are constructed below. Module-level, not a fixture: the state machine is
# built at import time, and both stores read these env vars per request.
# The state machine walks BOTH lifecycles — ai-gov register (AIRegistryStore,
# EVIDENTIA_AI_REGISTRY_DIR) and catalog import/delete (get_user_catalog_dir,
# EVIDENTIA_CATALOG_DIR) — so a run left un-isolated would write fuzz catalogs,
# rewrite the real frameworks.yaml manifest, and could unlink a real
# user-imported catalog in the developer's actual store.
os.environ["EVIDENTIA_AI_REGISTRY_DIR"] = tempfile.mkdtemp(prefix="evidentia-dast-stateful-registry-")
os.environ["EVIDENTIA_CATALOG_DIR"] = tempfile.mkdtemp(prefix="evidentia-dast-stateful-catalog-")

# Neutralize the token-bucket rate limiter for the fuzz. The limiter
# (60/min, burst 10 on POST /ai-gov/register) throttles the hundreds of
# rapid calls a stateful run makes, surfacing 429s that are the limiter
# working AS DESIGNED — not a lifecycle bug — which schemathesis's
# positive_data_acceptance check (correctly) flags as "valid data
# rejected". A business-logic-sequence fuzzer must exercise the routes,
# not the throttle; rate-limit behavior has its own dedicated tests
# (test_rate_limit.py). Test-side only: clear the default rate-limited
# path set before the app + middleware are constructed below — no
# production code changes, and RateLimitMiddleware still installs.
import evidentia_api.rate_limit as _rate_limit  # noqa: E402

_rate_limit.DEFAULT_RATE_LIMITED_PATHS = frozenset()

from evidentia_api.app import create_app  # noqa: E402

# Scope the state machine to exactly the six operations that are sources
# or targets of this deliverable's two ``links`` blocks. as_state_machine()
# would otherwise walk the ENTIRE schema and bury link-chain findings
# under noise from unrelated endpoints (schema-inexpressible cross-field
# validators, etc.). Resolves to:
#   POST   /api/ai-gov/register
#   GET    /api/ai-gov/systems/{system_id}
#   PUT    /api/ai-gov/systems/{system_id}
#   DELETE /api/ai-gov/systems/{system_id}
#   POST   /api/catalog/import
#   DELETE /api/catalog/{framework_id}
_LINKED_LIFECYCLES = (
    r"^/api/(ai-gov/(register|systems/\{system_id\})"
    r"|catalog/(import|\{framework_id\}))$"
)


def _make_state_machine() -> type:
    schema = schemathesis.openapi.from_asgi("/api/openapi.json", create_app(offline=True))
    schema = schema.include(path_regex=_LINKED_LIFECYCLES)
    return schema.as_state_machine()


APIWorkflow = _make_state_machine()


class BoundedAPIWorkflow(APIWorkflow):  # type: ignore[misc,valid-type]
    """CI-bounded profile: enough steps to traverse the linked
    lifecycles, small enough to keep the job in single-digit minutes."""

    def setup(self) -> None:
        # Fresh registry and catalog stores for EVERY example. Hypothesis
        # replays choice sequences while shrinking, and the two stores are
        # process-wide: a system registered by an earlier example (plus its
        # idempotency-store entry) or a catalog it imported changes the
        # responses a replayed sequence sees, which changes which
        # link-derived rules are available at the same draw, and Hypothesis
        # then raises FlakyStrategyDefinition ("Inconsistent data
        # generation", CI run 34004542188 on 2026-09-06). Both stores read
        # their env var per request, so repointing the vars is enough; the
        # previous example's directory is removed to keep the run bounded.
        for var, prefix in (
            ("EVIDENTIA_AI_REGISTRY_DIR", "evidentia-dast-stateful-registry-"),
            ("EVIDENTIA_CATALOG_DIR", "evidentia-dast-stateful-catalog-"),
        ):
            previous = os.environ.get(var)
            os.environ[var] = tempfile.mkdtemp(prefix=prefix)
            if previous:
                shutil.rmtree(previous, ignore_errors=True)


TestStateful = BoundedAPIWorkflow.TestCase
TestStateful.settings = settings(
    # Raised from 25: the nested AISystemDescriptor body (name/purpose
    # non-blank + max_length + enum fields) needs a wider example budget
    # to reliably produce at least one valid `register` body per run —
    # see the "Generation-reliability note" above. derandomize=True (a
    # fixed, version-pinned PRNG seed schedule) + database=None (skip
    # Hypothesis's local example cache) make this deterministic across
    # CI invocations instead of depending on machine-local cached
    # examples or wall-clock-seeded randomness.
    max_examples=200,
    stateful_step_count=6,
    deadline=None,
    derandomize=True,
    database=None,
    phases=[Phase.generate],
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)
