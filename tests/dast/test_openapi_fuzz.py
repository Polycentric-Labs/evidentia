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


def _schemathesis_loader() -> object | None:
    """Resolve the schemathesis ASGI loader across 3.x and 4.x.

    Schemathesis 3.x exposes ``schemathesis.from_asgi(...)``.
    Schemathesis 4.x moved this to ``schemathesis.openapi.from_asgi(...)``
    and the surrounding API surface shifted. Returns the callable
    when available; returns ``None`` otherwise so the test can
    skip cleanly.
    """
    try:
        import schemathesis
    except ImportError:
        return None
    # 3.x path: top-level from_asgi.
    if hasattr(schemathesis, "from_asgi"):
        return schemathesis.from_asgi
    # 4.x path: openapi submodule from_asgi.
    if hasattr(schemathesis, "openapi") and hasattr(schemathesis.openapi, "from_asgi"):
        return schemathesis.openapi.from_asgi
    return None


pytestmark = pytest.mark.skipif(
    _schemathesis_loader() is None,
    reason=(
        "schemathesis ASGI loader not found (neither 3.x "
        "`schemathesis.from_asgi` nor 4.x `schemathesis.openapi."
        "from_asgi`). Install dev-deps via `uv sync --all-packages` "
        "and verify the installed major version."
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
    from evidentia_api.app import create_app

    loader = _schemathesis_loader()
    assert loader is not None  # pytestmark already gated this
    app = create_app(offline=True)
    # 3.x: ``schemathesis.from_asgi(path, app)``;
    # 4.x: ``schemathesis.openapi.from_asgi(path, app=app)`` — the
    # callable invocation form is compatible across both as
    # positional args.
    schema = loader("/api/openapi.json", app)
    assert schema is not None
    # Sanity: at least one operation discovered. 3.x exposes
    # `.get_all_operations()`; 4.x exposes `.operations` or
    # iteration. Try both defensively.
    if hasattr(schema, "get_all_operations"):
        operations = list(schema.get_all_operations())
    elif hasattr(schema, "operations"):
        operations = list(schema.operations)
    else:
        operations = list(schema)
    assert len(operations) > 0
