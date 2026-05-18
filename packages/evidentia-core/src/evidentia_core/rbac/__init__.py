"""Role-based access-control primitives (v0.9.5 P3.3).

Introduces a minimal, opt-in RBAC model for Evidentia's CLI + API
surfaces. The primitives are deliberately conservative:

- Three canonical roles: ``reader`` / ``editor`` / ``admin``.
- Config-file-driven identity → role mapping. Default policy when
  no config is loaded = single-tenant ``admin`` (matches v0.9.4
  behavior; nothing breaks for existing operators).
- Single ``check_permission(identity, action)`` entry point so
  CLI + API enforcement converge on one decision function.
- FastAPI dependency factory ``require_role(min_role)`` makes
  router-level enforcement a one-liner.

Scope boundaries:

- This is NOT authentication. Identity arrives from a v0.8.1
  :class:`AuthProvider` (token / mTLS / SSO) — RBAC consumes the
  authenticated identity string + maps it to a role.
- The policy file is intentionally simple (YAML or JSON dict of
  ``identity → role``). Group-based + claim-based policies are
  v0.9.6+ scope.
- Default policy is permissive (everyone-is-admin) so existing
  single-operator deployments continue to function without any
  policy file. Operators opting into RBAC point
  ``EVIDENTIA_RBAC_POLICY_FILE`` at their YAML and the default
  flips to deny-by-default.

Cross-references:

- See :mod:`evidentia_core.plugins.auth` for the identity-
  resolution layer.
- See ``docs/threat-model.md`` v0.9.5 delta for the threat-model
  implications of opt-in RBAC.
"""

from evidentia_core.rbac.policy import (
    DEFAULT_POLICY,
    RBACPolicy,
    Role,
    check_permission,
    load_policy_from_file,
)

__all__ = [
    "DEFAULT_POLICY",
    "RBACPolicy",
    "Role",
    "check_permission",
    "load_policy_from_file",
]
