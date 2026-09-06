"""Process-lifetime RBAC policy + identity resolution (v0.9.6 P1.3; v0.9.8 P1.3 adds tenant).

The CLI mirrors the FastAPI ``app.state.rbac_policy`` pattern at the
process layer: one policy load per process, kept in module-level
state, cleared only by tests via :func:`_reset_rbac_cache`. Reloading
on the running process is intentionally not supported — operators
restart the CLI to pick up policy changes (matches the FastAPI
``startup`` semantic from v0.9.5).

Identity arrives from the ``EVIDENTIA_RBAC_IDENTITY`` env var. The
FastAPI side draws identity from the v0.8.1 :class:`AuthProvider`'s
authentication result on the request; the CLI has no equivalent
authentication step, so the operator (or wrapping CI job) supplies
the identity directly via env.

v0.9.8 P1.3 adds multi-tenant support:

- :func:`get_rbac_policy` now auto-detects single-tenant vs.
  multi-tenant policy files. A YAML with a top-level ``tenants:``
  key loads as :class:`TenantRBACPolicy`; everything else loads as
  :class:`RBACPolicy` (preserves v0.9.6 backward compat).
- :data:`ENV_RBAC_TENANT` env var (and the new ``--rbac-tenant``
  global CLI flag) supplies a tenant claim to combine with the
  identity. Operators with multi-tenant policies set both
  ``--rbac-identity alice@example.com`` AND ``--rbac-tenant acme-corp``
  to authorize against the ``acme-corp`` slice. Equivalently,
  operators bake the claim into the identity string itself
  (``alice@example.com@@acme-corp``) — the v0.9.7 ``@@<tenant>``
  convention.

Threat-model note: a CLI invocation that wants to spoof an identity
can simply set ``EVIDENTIA_RBAC_IDENTITY=alice@example.com``. RBAC at
the CLI layer is therefore an **authorization** model that assumes
the surrounding environment (OS user, sudo policy, file
permissions on the policy file) authenticates the operator. The
policy file SHOULD be ``chmod 0600`` and owned by a service user,
per the v0.9.5 F-V95-rbac-trust finding. The v0.9.7
F-V97-multi-tenant-claim-spoofing finding extends this — the tenant
claim is operator-asserted on the CLI side; per-request provenance
from an authenticated :class:`AuthProvider` is the FastAPI-side
mitigation (v0.9.8 P1.4).
"""

from __future__ import annotations

import os
from pathlib import Path

from evidentia_core.rbac import (
    DEFAULT_POLICY,
    TENANT_CLAIM_SEPARATOR,
    RBACPolicy,
    TenantRBACPolicy,
    load_rbac_policy_auto,
    resolve_tenant_from_identity,
)

ENV_RBAC_POLICY_FILE = "EVIDENTIA_RBAC_POLICY_FILE"
"""Env var holding an absolute path to a YAML/JSON policy file."""

ENV_RBAC_IDENTITY = "EVIDENTIA_RBAC_IDENTITY"
"""Env var holding the identity string for the current invocation."""

ENV_RBAC_TENANT = "EVIDENTIA_RBAC_TENANT"
"""v0.9.8 P1.3. Env var holding the tenant claim for the current
invocation. Equivalent to baking ``@@<tenant>`` into the identity
string but kept separate so operators can wire identity (from one
source — e.g., SSO upstream) and tenant (from another — e.g., a
per-cron-job env) without string-munging."""

_CACHED_POLICY: RBACPolicy | TenantRBACPolicy | None = None
"""Process-lifetime cache. Set on first :func:`get_rbac_policy` call.

v0.9.8: now holds either single-tenant :class:`RBACPolicy` (v0.9.5
+ v0.9.6 surface) or multi-tenant :class:`TenantRBACPolicy` (new
v0.9.7 surface). Callers branch on type to dispatch to the correct
``check_permission`` variant."""

_CACHED_POLICY_LOADED: bool = False
"""Sentinel so a deliberately-loaded ``DEFAULT_POLICY`` (no env var
set) is not re-resolved on every call. Distinct from ``None`` so
tests can distinguish "never loaded" from "loaded the default"."""

_OVERRIDE_IDENTITY: str | None = None
"""Optional override set by the CLI ``--rbac-identity`` global
flag. Takes precedence over :data:`ENV_RBAC_IDENTITY` so operators
can override per-invocation without re-exporting the env var."""

_OVERRIDE_TENANT: str | None = None
"""v0.9.8. Optional tenant override set by the CLI ``--rbac-tenant``
global flag. Takes precedence over :data:`ENV_RBAC_TENANT`."""


def get_rbac_policy() -> RBACPolicy | TenantRBACPolicy:
    """Return the RBAC policy for this process.

    Loaded from :data:`ENV_RBAC_POLICY_FILE` on the first call;
    cached for the process lifetime. Returns :data:`DEFAULT_POLICY`
    (permissive single-tenant) when the env var is unset.

    v0.9.8 P1.3: auto-detects the policy shape via the shared
    :func:`evidentia_core.rbac.load_rbac_policy_auto`. A file with a
    ``tenants:`` top-level key loads as :class:`TenantRBACPolicy`;
    everything else loads as :class:`RBACPolicy`. Callers branch on
    ``isinstance(policy, TenantRBACPolicy)`` to dispatch through
    the multi-tenant decision function.

    v0.9.8 P1.4 (finding F-V98-02): detection now goes through the
    shared ``load_rbac_policy_auto`` helper so the CLI and the FastAPI
    app classify the same policy file identically.

    Raises:
        FileNotFoundError: If the env var is set but the path does
            not exist. Surfaces as a CLI startup error rather than
            silently falling back to the permissive default — an
            operator who set the var expects it to be honored.
        ValueError: If the file contents are not valid YAML/JSON OR
            don't match the policy schema.
    """
    global _CACHED_POLICY, _CACHED_POLICY_LOADED
    if _CACHED_POLICY_LOADED:
        assert _CACHED_POLICY is not None  # invariant; load sets both
        return _CACHED_POLICY
    policy_path = os.environ.get(ENV_RBAC_POLICY_FILE)
    _CACHED_POLICY = load_rbac_policy_auto(Path(policy_path)) if policy_path else DEFAULT_POLICY
    _CACHED_POLICY_LOADED = True
    return _CACHED_POLICY


def get_rbac_identity() -> str | None:
    """Return the identity for the current invocation.

    Precedence:

    1. ``--rbac-identity`` global CLI flag (set via
       :func:`set_rbac_identity_override`).
    2. :data:`ENV_RBAC_IDENTITY` env var.
    3. ``None`` (anonymous; resolves to ``policy.default_role``).

    v0.9.8: the returned identity may carry an embedded ``@@<tenant>``
    claim (the v0.9.7 multi-tenant convention). Callers wanting the
    *combined* identity (resolved tenant claim merged in from the
    ``--rbac-tenant`` override / env var) use
    :func:`get_rbac_identity_with_tenant_claim` instead.
    """
    if _OVERRIDE_IDENTITY is not None:
        return _OVERRIDE_IDENTITY
    return os.environ.get(ENV_RBAC_IDENTITY) or None


def get_rbac_tenant() -> str | None:
    """Return the tenant claim for the current invocation (v0.9.8 P1.3).

    Precedence:

    1. ``--rbac-tenant`` global CLI flag (set via
       :func:`set_rbac_tenant_override`).
    2. :data:`ENV_RBAC_TENANT` env var.
    3. ``None`` (no operator-supplied claim; if the identity itself
       carries a ``@@<tenant>`` claim that's used instead; otherwise
       the policy's ``default_tenant`` resolves).
    """
    if _OVERRIDE_TENANT is not None:
        return _OVERRIDE_TENANT
    return os.environ.get(ENV_RBAC_TENANT) or None


def get_rbac_identity_with_tenant_claim() -> str | None:
    """Return the identity merged with the resolved tenant claim.

    Combines :func:`get_rbac_identity` + :func:`get_rbac_tenant` into
    the canonical ``<identity>@@<tenant>`` form that
    :func:`evidentia_core.rbac.check_permission_multi_tenant` consumes.

    Resolution rules:

    1. ``identity = get_rbac_identity()``; if ``None``, return ``None``
       (anonymous — multi-tenant check denies via no-claim path).
    2. ``tenant = get_rbac_tenant()``; if ``None``, return ``identity``
       unchanged (identity-embedded claim, if any, is preserved; else
       falls through to ``default_tenant`` at decision time).
    3. If ``identity`` already carries a ``@@<embedded>`` claim AND
       ``tenant`` is also supplied AND they differ, raise
       :class:`ValueError`. Catches operator-config drift (env says
       acme-corp but identity says globex) before it becomes a
       silent escalation.
    4. Otherwise return ``f"{bare_identity}{TENANT_CLAIM_SEPARATOR}{tenant}"``.
    """
    identity = get_rbac_identity()
    tenant = get_rbac_tenant()
    if identity is None:
        return None
    if tenant is None:
        return identity
    bare_identity, embedded_tenant = resolve_tenant_from_identity(identity)
    if embedded_tenant is not None and embedded_tenant != tenant:
        raise ValueError(
            f"Conflicting tenant claims: identity carries "
            f"@@{embedded_tenant!r} but --rbac-tenant / "
            f"{ENV_RBAC_TENANT}={tenant!r}. Resolve the conflict by "
            f"removing one of the two sources."
        )
    # bare_identity is guaranteed non-None when identity is non-None
    # per resolve_tenant_from_identity's contract.
    return f"{bare_identity}{TENANT_CLAIM_SEPARATOR}{tenant}"


def set_rbac_identity_override(identity: str | None) -> None:
    """Set the per-invocation identity override (CLI callback path).

    The ``@app.callback()`` in :mod:`evidentia.cli.main` wires the
    global ``--rbac-identity`` flag through this setter. Tests use
    it to inject an identity without mutating ``os.environ``.

    Passing ``None`` clears the override (the env-var fallback then
    applies). The override is process-lifetime; it does NOT reset
    automatically between Typer invocations within the same Python
    process (tests should call this with ``None`` in teardown if
    they set it in setup).
    """
    global _OVERRIDE_IDENTITY
    _OVERRIDE_IDENTITY = identity


def set_rbac_tenant_override(tenant: str | None) -> None:
    """v0.9.8 P1.3. Set the per-invocation tenant override.

    The ``@app.callback()`` in :mod:`evidentia.cli.main` wires the
    global ``--rbac-tenant`` flag through this setter. Mirrors the
    v0.9.6 identity-override pattern.
    """
    global _OVERRIDE_TENANT
    _OVERRIDE_TENANT = tenant


def _reset_rbac_cache() -> None:
    """Clear the policy cache + identity/tenant overrides (test-only helper).

    Public-but-underscored: production code MUST NOT call this. Tests
    invoke it in fixtures so each test sees a clean cache. Future
    runtime-reload features (if any) would land as a new public
    function with explicit operator-facing ergonomics.
    """
    global _CACHED_POLICY, _CACHED_POLICY_LOADED
    global _OVERRIDE_IDENTITY, _OVERRIDE_TENANT
    _CACHED_POLICY = None
    _CACHED_POLICY_LOADED = False
    _OVERRIDE_IDENTITY = None
    _OVERRIDE_TENANT = None
