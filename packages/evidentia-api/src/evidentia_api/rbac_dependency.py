"""FastAPI dependency factory for opt-in RBAC enforcement (v0.9.5 P3.3).

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
    check_permission,
)
from fastapi import Depends, HTTPException, Request


def _get_request_identity(request: Request) -> str | None:
    """Extract the authenticated identity string from the request.

    Reads ``request.state.identity`` if set by the AuthProvider
    middleware. Returns ``None`` for anonymous requests (no
    AuthProvider configured OR token rejected at middleware).

    Centralized here so the source-of-truth for "who is the
    caller?" is one function — the dependency below + future
    audit-logging hooks share the resolution.
    """
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
        3. Calls :func:`check_permission(identity, action, policy)`.
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
        policy: RBACPolicy = getattr(
            request.app.state, "rbac_policy", DEFAULT_POLICY
        )
        if not check_permission(identity, action, policy=policy):
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
