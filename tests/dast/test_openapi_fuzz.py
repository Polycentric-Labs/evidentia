"""Schemathesis OpenAPI fuzz baseline (v0.9.5 P1.2 scaffold).

Reads the FastAPI OpenAPI schema directly from ``create_app()``
and runs Schemathesis's stateless property-based test suite
against each operation. Failures surface as Schemathesis-formatted
case reports including a curl-replay command for triage.

This test file is intentionally minimal — it's the seed of a
broader DAST suite. v0.9.5+ ship cycles can extend with
operation-specific tests (auth, rate-limit, schema-violation
edge cases) as DAST findings accumulate.

Pre-flight (one-time per environment):

  uv sync --all-packages

Invocation:

  uv run pytest tests/dast/test_openapi_fuzz.py -v

CI integration: this suite is OPT-IN. Not part of the default
``pytest tests/`` collection. Wire into a dedicated GH Actions
job (``dast.yml``) or run on-demand at pre-release-review Step 4.
"""

from __future__ import annotations

import pytest


def _have_schemathesis() -> bool:
    try:
        import schemathesis  # noqa: F401
        return True
    except ImportError:
        return False


pytestmark = pytest.mark.skipif(
    not _have_schemathesis(),
    reason=(
        "schemathesis not installed; run `uv sync --all-packages` "
        "(dev-deps include it)"
    ),
)


def test_openapi_schema_is_loadable() -> None:
    """Smoke check: the FastAPI OpenAPI schema can be extracted +
    parsed by schemathesis. Failing this points at a schema-
    generation bug in FastAPI itself (rare) or a Pydantic
    serialization edge case Schemathesis can't normalize.

    Real fuzz tests build on this — once the schema loads cleanly,
    operation-by-operation property tests follow.
    """
    import schemathesis
    from evidentia_api.app import create_app

    app = create_app(offline=True)
    # Schemathesis 3.x API: from_asgi(...).
    schema = schemathesis.from_asgi("/api/openapi.json", app)
    assert schema is not None
    # Sanity: at least one operation discovered.
    operations = list(schema.get_all_operations())
    assert len(operations) > 0
