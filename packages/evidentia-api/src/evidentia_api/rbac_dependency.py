"""FastAPI dependency factory for opt-in RBAC enforcement (v0.9.5 P3.3; v0.9.8 P1.4 multi-tenant).

Operators wire RBAC at the router or per-route level via the
:func:`require_role` factory::

    from evidentia_api.rbac_dependency import require_role
    from evidentia_core.rbac import Role

    @router.post(
        "/poam/items",
        dependencies=[require_role("write")],
    )
    async def create_poam_item(...): ...

Or at the router level::

    router = APIRouter(dependencies=[require_role("read")])

Default policy (no policy file loaded) is permissive — every
identity gets admin role + every action is allowed. Operators
enabling RBAC set ``EVIDENTIA_RBAC_POLICY_FILE`` to a YAML
policy file path; the policy is loaded ONCE at app construction
time and stored on ``app.state.rbac_policy``.

The dependency reads the identity from the v0.8.1
:class:`AuthProvider`'s authentication result, which is already
captured on the request via :class:`AuthProviderMiddleware`.
When no AuthProvider is configured (anonymous mode), the
identity is None — combined with the default permissive policy,
this maintains v0.9.4 backward-compat.

v0.9.8 P1.4 — multi-tenant
--------------------------

Closes the v0.9.7 F-V97-multi-tenant-claim-spoofing INFO finding.
When ``app.state.rbac_policy`` is a :class:`TenantRBACPolicy`, the
dependency dispatches to :func:`check_permission_multi_tenant`. The
tenant claim is extracted from the principal's ``@@<tenant>`` suffix
— and only from there. Env vars + request headers are NOT honored
on the FastAPI side, so an unauthenticated client cannot assert a
tenant claim it doesn't actually hold. The principal string is set
by :class:`AuthProviderMiddleware` from the result of
:meth:`AuthProvider.authenticate`, which validates the credential
against the operator's token / mTLS / SSO config — provenance is
end-to-end from the credential to the RBAC decision.

Threat-model boundary: RBAC does NOT replace authentication.
Identity arrives from the AuthProvider; RBAC consumes it. If
the AuthProvider is not configured, every request is anonymous
+ the default policy decides what's allowed (permissive by
default; deny-by-default when operator opts in).
"""

from __future__ import annotations

from typing import Any

from evidentia_core.rbac import (
    DEFAULT_POLICY,
    RBACPolicy,
    TenantRBACPolicy,
    check_permission,
    check_permission_multi_tenant,
)
from fastapi import Depends, HTTPException, Request


def _get_request_identity(request: Request) -> str | None:
    """Extract the authenticated identity string from the request.

    Resolution order:

    1. ``request.state.auth_principal`` — set by
       :class:`AuthProviderMiddleware` from
       :attr:`AuthResult.principal` (v0.8.1 + v0.8.2 F-V81-S2).
       This is the canonical authenticated-identity source.
    2. ``request.state.identity`` — kept for backward compat with
       any custom middleware that uses the v0.9.5 attribute name
       (documented but never populated by the upstream middleware
       — closes a latent attribute-name disconnect).
    3. ``None`` — anonymous (no AuthProvider configured OR token
       rejected at the middleware layer).

    Centralized here so the source-of-truth for "who is the
    caller?" is one function — the dependency below + future
    audit-logging hooks share the resolution.

    v0.9.8 P1.4: the returned string may carry an embedded
    ``@@<tenant>`` claim (the v0.9.7 multi-tenant convention).
    Multi-tenant policy decisions consume it via
    :func:`check_permission_multi_tenant`; single-tenant policy
    decisions ignore the suffix.
    """
    principal = getattr(request.state, "auth_principal", None)
    if principal is not None:
        return principal  # type: ignore[no-any-return]
    return getattr(request.state, "identity", None)


def require_role(action: str) -> Any:
    """Dependency factory for action-scoped RBAC enforcement.

    Args:
        action: One of ``"read"`` / ``"write"`` / ``"admin"`` (the
            keys of :data:`evidentia_core.rbac.policy.ACTION_MIN_ROLE`).
            Raises ``KeyError`` at app-startup time if unknown,
            so misuse surfaces in tests rather than at request
            dispatch.

    Returns:
        A FastAPI dependency that:

        1. Extracts the identity via :func:`_get_request_identity`.
        2. Resolves the per-app RBAC policy via
           ``request.app.state.rbac_policy`` (falls back to
           :data:`DEFAULT_POLICY` if unset).
        3. v0.9.8 P1.4: if the policy is a
           :class:`TenantRBACPolicy`, calls
           :func:`check_permission_multi_tenant` (which honors the
           identity-embedded ``@@<tenant>`` claim). Otherwise calls
           the single-tenant :func:`check_permission` — preserves
           v0.9.5 + v0.9.6 behavior for non-multi-tenant deployments.
        4. Raises ``HTTPException(403)`` on deny; returns ``None``
           on allow (FastAPI dependency convention — return value
           is unused).

    Example::

        @router.post(
            "/poam/items",
            dependencies=[Depends(require_role("write"))],
        )
        async def create_poam_item(...): ...
    """

    def _dependency(request: Request) -> None:
        identity = _get_request_identity(request)
        policy: RBACPolicy | TenantRBACPolicy = getattr(request.app.state, "rbac_policy", DEFAULT_POLICY)
        # v0.9.8 P1.4: dispatch to multi-tenant when the operator's
        # policy demands it. The principal carries any tenant claim
        # as an ``@@<tenant>`` suffix; the multi-tenant decision
        # function parses + applies it. Closes F-V97-multi-tenant-
        # claim-spoofing by routing the claim through the
        # authenticated principal, NOT through env vars or headers.
        if isinstance(policy, TenantRBACPolicy):
            granted = check_permission_multi_tenant(identity, action, policy=policy)
        else:
            granted = check_permission(identity, action, policy=policy)
        if not granted:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "rbac_denied",
                    "action": action,
                    "identity": identity or "anonymous",
                    "message": (
                        "Identity does not have permission for this "
                        "action. Operators configure RBAC via "
                        "EVIDENTIA_RBAC_POLICY_FILE."
                    ),
                },
            )

    # Wrap in Depends() so callers can use the factory output
    # directly in ``dependencies=[require_role("write")]`` lists
    # without an extra Depends() at each call site. Return type
    # is intentionally Any — Depends() is not a Callable[..., None]
    # at the typing layer; FastAPI's dependencies list accepts
    # Depends instances directly.
    return Depends(_dependency)
