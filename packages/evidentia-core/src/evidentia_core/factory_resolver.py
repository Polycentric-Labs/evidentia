"""Env-var-driven dotted-path factory resolver (v0.9.8 P2.2 / CR-V97-3).

v0.9.7 shipped two near-identical implementations of the
`gate-env-var + factory-env-var + importlib + dotted-path + call`
pattern:

- :func:`evidentia_core.evidence_store._resolve_auto_mirror_backend`
  resolving ``EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY`` to a
  ``(backend, retention_metadata)`` tuple.
- :func:`evidentia_mcp.signatures._resolve_signer_factory` resolving
  ``EVIDENTIA_MCP_SIGNER_FACTORY`` to a
  ``Callable[[bytes], dict[str, str]]``.

CR-V97-3 (v0.9.7 code-review finding) flagged the duplication for
extraction. CR-V97-1 (separately) flagged that the WORM resolver is
called on every ``save_evidence`` → opportunity for caching.

This module provides the shared resolver + a built-in cache keyed on
the (gate, factory) env-var values. When operators change either env
var at runtime, the cache invalidates automatically on the next call.
The factory itself runs once per (gate_value, factory_value) tuple
within a process lifetime — sufficient for the v0.9.7 use cases
(WORM mirror per save, signer per MCP dispatch) without imposing a
per-call import cost.

**Threat-model boundary**: cached resolution does NOT bypass the
v0.9.7 misconfiguration-detection guarantee — a malformed factory
ref still raises on FIRST attempted resolution. The cache only
short-circuits subsequent identical-env-var calls.

**Why "factory" not "callable"**: each call site needs to decide
what shape to validate the factory's return value against. The
shared helper resolves + invokes the factory + caches the result;
callers do post-call shape validation (tuple vs callable vs other)
and downstream-specific error messaging.
"""

from __future__ import annotations

import importlib
import os
from typing import Any

__all__ = [
    "clear_factory_cache",
    "resolve_factory",
]


# Module-level cache keyed on (gate_env_var_name, factory_env_var_name,
# resolved_gate_value, resolved_factory_value). Resolved values are
# captured at lookup time, so a change in env at runtime invalidates
# the prior entry transparently.
_factory_cache: dict[
    tuple[str, str, str | None, str | None],
    Any,
] = {}


def clear_factory_cache() -> None:
    """Drop every cached factory result.

    Test-only helper. Production callers should not need to invoke
    this — the cache invalidates automatically when env-var values
    change. Tests that exercise env-var transitions on the same
    `(gate, factory)` tuple may call this to force re-resolution
    without mutating the env between assertions.
    """
    _factory_cache.clear()


def resolve_factory(
    gate_env_var: str,
    factory_env_var: str,
    *,
    purpose: str,
) -> Any | None:
    """Resolve an env-var-driven dotted-path factory and invoke it.

    Pattern shared between :mod:`evidentia_core.evidence_store` and
    :mod:`evidentia_mcp.signatures`:

    1. If ``gate_env_var`` is unset / empty → return ``None`` (no-op).
    2. Otherwise ``factory_env_var`` MUST be set to a
       ``module.submodule:callable_name`` reference.
    3. Import the module + resolve the attribute + invoke it (zero
       args) + return the result.

    Results are cached at module scope keyed on the resolved env-var
    values — a stable env produces one factory invocation per process
    lifetime; an env change between calls invalidates the prior entry.

    Args:
        gate_env_var: Name of the env var that GATES feature
            activation. Common values: ``EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM``,
            ``EVIDENTIA_MCP_SIGN_OUTPUTS``.
        factory_env_var: Name of the env var carrying the dotted-path
            factory reference. Required when ``gate_env_var`` is set.
        purpose: Short human-readable string ("WORM auto-mirror
            backend", "MCP signer", etc.) embedded in error messages
            so misconfigured operators see contextual diagnostics.

    Returns:
        The factory's return value, or ``None`` when the gate is unset.
        Shape validation is the caller's responsibility (e.g., the
        WORM caller expects ``tuple[WORMBackend, RetentionMetadata]``;
        the MCP-signer caller expects a callable).

    Raises:
        RuntimeError: When the gate is set but factory_env_var is
            empty / malformed / unimportable / non-callable. Mirrors
            the v0.9.7 error semantics of the per-callsite helpers.
    """
    gate_value = os.environ.get(gate_env_var) or None
    factory_value = os.environ.get(factory_env_var) or None
    cache_key = (gate_env_var, factory_env_var, gate_value, factory_value)
    if cache_key in _factory_cache:
        return _factory_cache[cache_key]

    if gate_value is None:
        _factory_cache[cache_key] = None
        return None

    if not factory_value:
        raise RuntimeError(
            f"{gate_env_var} is set but {factory_env_var} is empty. "
            f"Format: 'module.submodule:callable_name'. The callable "
            f"must produce the {purpose}."
        )

    if ":" not in factory_value:
        raise RuntimeError(
            f"{factory_env_var}={factory_value!r} must be of the form "
            f"'module.submodule:callable_name' (got no ':' separator)."
        )

    module_path, _, attr = factory_value.partition(":")
    try:
        module = importlib.import_module(module_path)
    except ImportError as exc:
        raise RuntimeError(
            f"Could not import {module_path!r} for {purpose} factory: {exc}"
        ) from exc

    factory = getattr(module, attr, None)
    if factory is None or not callable(factory):
        raise RuntimeError(
            f"{factory_value!r} did not resolve to a callable attribute "
            f"in {module_path!r} (purpose: {purpose})."
        )

    result = factory()
    _factory_cache[cache_key] = result
    return result
