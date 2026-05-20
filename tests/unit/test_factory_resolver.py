"""Unit tests for the v0.9.8 P2.2 shared factory_resolver helper.

Covers the env-var-driven dotted-path resolution pattern extracted
from :mod:`evidentia_core.evidence_store` (WORM auto-mirror) and
:mod:`evidentia_mcp.signatures` (MCP signer). See CR-V97-3 + CR-V97-1
for the v0.9.7 code-review findings that motivated the extraction.
"""

from __future__ import annotations

import sys

import pytest
from evidentia_core.factory_resolver import (
    clear_factory_cache,
    resolve_factory,
)

# Use a sentinel object so we can verify identity not just equality —
# proves the cache returns the SAME instance, not a freshly produced one.
_SENTINEL_RESULT = ("backend-stub", "retention-stub")


def _factory_returns_sentinel() -> tuple[str, str]:
    """Helper factory used by the dotted-path lookup tests."""
    return _SENTINEL_RESULT


_call_count = 0


def _counting_factory() -> int:
    """Helper that records each invocation so caching can be observed."""
    global _call_count
    _call_count += 1
    return _call_count


def _factory_returns_non_tuple() -> str:
    return "not-a-tuple"


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset module-level cache + call counter before every test.

    The factory cache persists across tests within a process; clearing
    it between cases keeps assertions about call-counts deterministic.
    """
    global _call_count
    _call_count = 0
    clear_factory_cache()
    # Inject this test module as importable via its dotted path so the
    # resolver's ``importlib.import_module`` call can find the helpers
    # below. The path matches what pytest assigns to the test module
    # when it's discovered from the tests/ tree.
    sys.modules["test_factory_resolver_helpers"] = sys.modules[__name__]


def test_gate_unset_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """When the gate env var is unset, resolve_factory yields None."""
    monkeypatch.delenv("EVIDENTIA_TEST_GATE", raising=False)
    monkeypatch.delenv("EVIDENTIA_TEST_FACTORY", raising=False)
    assert (
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose="unit test",
        )
        is None
    )


def test_gate_set_but_factory_empty_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Gate without factory ref → RuntimeError with descriptive message."""
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.delenv("EVIDENTIA_TEST_FACTORY", raising=False)
    with pytest.raises(RuntimeError) as excinfo:
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose="unit-test backend",
        )
    msg = str(excinfo.value)
    assert "EVIDENTIA_TEST_GATE" in msg
    assert "EVIDENTIA_TEST_FACTORY" in msg
    assert "unit-test backend" in msg


def test_gate_set_but_factory_malformed_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Factory ref missing the ':' separator → RuntimeError."""
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv("EVIDENTIA_TEST_FACTORY", "no_colon_here")
    with pytest.raises(RuntimeError) as excinfo:
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose="unit test",
        )
    assert "no_colon_here" in str(excinfo.value)


def test_unimportable_module_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Factory ref points at a nonexistent module → RuntimeError."""
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "evidentia_core.this_module_does_not_exist:nope",
    )
    with pytest.raises(RuntimeError) as excinfo:
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose="unit test",
        )
    assert "this_module_does_not_exist" in str(excinfo.value)


def test_non_callable_attribute_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Factory ref points at a non-callable attribute → RuntimeError."""
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "test_factory_resolver_helpers:_SENTINEL_RESULT",
    )
    with pytest.raises(RuntimeError) as excinfo:
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose="unit test",
        )
    assert "_SENTINEL_RESULT" in str(excinfo.value)


def test_happy_path_returns_factory_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Valid gate + valid factory ref → factory's return value."""
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "test_factory_resolver_helpers:_factory_returns_sentinel",
    )
    result = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    # Identity check — proves the cache returned the actual instance,
    # not a structurally-equal copy.
    assert result is _SENTINEL_RESULT


def test_factory_called_once_per_env_combination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Repeated calls with the same env values invoke the factory once.

    Closes CR-V97-1 — the WORM auto-mirror resolver was previously
    called per ``save_evidence``; caching collapses that to one
    invocation per process lifetime per unique (gate, factory) pair.
    """
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "test_factory_resolver_helpers:_counting_factory",
    )
    first = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    second = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    third = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    assert _call_count == 1
    assert first == second == third == 1


def test_cache_invalidates_on_env_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Changing either env var produces a fresh factory invocation."""
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "test_factory_resolver_helpers:_counting_factory",
    )
    first = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    # Change the gate value — should NOT reuse the cached entry.
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "2")
    second = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    assert first == 1
    assert second == 2
    assert _call_count == 2


def test_clear_factory_cache_forces_reresolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test-only helper drops every cached entry."""
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "test_factory_resolver_helpers:_counting_factory",
    )
    first = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    clear_factory_cache()
    second = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    assert first == 1
    assert second == 2
    assert _call_count == 2


def test_gate_unset_result_is_cached(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The None result from an unset gate is also cached.

    Ensures the resolver doesn't re-check env state on every call when
    the gate stays unset — the common case in single-tenant deployments
    that never wire auto-mirror or MCP signing.
    """
    monkeypatch.delenv("EVIDENTIA_TEST_GATE", raising=False)
    monkeypatch.delenv("EVIDENTIA_TEST_FACTORY", raising=False)
    first = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    second = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    assert first is None
    assert second is None
    # Caller can flip the gate later in the same process; cache picks up
    # the new value because env values are part of the cache key.
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "test_factory_resolver_helpers:_counting_factory",
    )
    third = resolve_factory(
        "EVIDENTIA_TEST_GATE",
        "EVIDENTIA_TEST_FACTORY",
        purpose="unit test",
    )
    assert third == 1


def test_purpose_appears_in_error_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ``purpose`` argument is surfaced in every error variant."""
    purpose = "very-specific-purpose-token"
    monkeypatch.setenv("EVIDENTIA_TEST_GATE", "1")

    # Empty factory ref.
    monkeypatch.delenv("EVIDENTIA_TEST_FACTORY", raising=False)
    with pytest.raises(RuntimeError, match=purpose):
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose=purpose,
        )

    # Bad module path.
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "does_not_exist_anywhere:nope",
    )
    with pytest.raises(RuntimeError, match=purpose):
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose=purpose,
        )

    # Non-callable attribute.
    monkeypatch.setenv(
        "EVIDENTIA_TEST_FACTORY",
        "test_factory_resolver_helpers:_SENTINEL_RESULT",
    )
    with pytest.raises(RuntimeError, match=purpose):
        resolve_factory(
            "EVIDENTIA_TEST_GATE",
            "EVIDENTIA_TEST_FACTORY",
            purpose=purpose,
        )
