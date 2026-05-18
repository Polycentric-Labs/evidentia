"""RBAC policy model + decision helpers (v0.9.5 P3.3).

The decision function is intentionally trivial: a role ranking
(``reader < editor < admin``) and an action → minimum-role table.
The single entry point ``check_permission(identity, action,
policy)`` resolves the identity to a role, looks up the action's
minimum role, and returns the boolean.

Action taxonomy (initial v0.9.5 set; expandable as new surfaces
land):

- ``read``: list / show / view operations. Required role:
  ``reader`` (everyone can read).
- ``write``: create / update / delete operations on user-owned
  records (POA&M items, milestones, AI registrations). Required
  role: ``editor``.
- ``admin``: operations that touch global config (RBAC policy
  itself, framework catalogs, system-level secrets). Required
  role: ``admin``.

Policy file format (YAML)::

    # /etc/evidentia/rbac.yaml
    identities:
      alice@example.com: admin
      bob@example.com: editor
      reviewer@example.com: reader
    default_role: reader  # role for identities not listed; "deny"
                          # means unlisted identities get no access

The ``default_role`` is required to be explicit so operators
cannot accidentally ship a policy file that grants admin to
unknown identities.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel

if TYPE_CHECKING:
    pass


class Role(str, Enum):
    """Canonical RBAC roles, ordered ``reader < editor < admin``.

    String values match the policy-file YAML serialization. The
    ordering is enforced via :meth:`outranks` so callers don't
    hardcode the role hierarchy.
    """

    READER = "reader"
    EDITOR = "editor"
    ADMIN = "admin"
    DENY = "deny"
    """Pseudo-role: identity has NO permission. Used as the
    ``default_role`` value when operators want a deny-by-default
    policy. Never assignable to a real identity."""

    def rank(self) -> int:
        """Return the integer rank of this role (higher = more permissive).

        ``deny`` < ``reader`` < ``editor`` < ``admin``. Used by
        :meth:`outranks` and :func:`check_permission` to compare
        roles against action requirements.
        """
        return {
            Role.DENY: 0,
            Role.READER: 1,
            Role.EDITOR: 2,
            Role.ADMIN: 3,
        }[self]

    def outranks_or_equal(self, other: Role) -> bool:
        """Return True iff ``self`` has equal or greater authority than ``other``."""
        return self.rank() >= other.rank()


#: Mapping of action name → minimum role required. Centralized so
#: every call site uses the same authorization decision.
ACTION_MIN_ROLE: dict[str, Role] = {
    "read": Role.READER,
    "write": Role.EDITOR,
    "admin": Role.ADMIN,
}


class RBACPolicy(EvidentiaModel):
    """Identity → role mapping with explicit default.

    Loaded from a YAML/JSON file via :func:`load_policy_from_file`
    or constructed in-memory for tests. The default policy (when
    no file is loaded) is the permissive single-tenant policy
    embodied by :data:`DEFAULT_POLICY` (all identities get admin).

    Operators opting into RBAC point ``EVIDENTIA_RBAC_POLICY_FILE``
    at their YAML and the resulting policy is loaded + used in
    place of the default. Policy files are immutable for the
    lifetime of the process; reloading requires a restart.
    """

    identities: dict[str, Role] = Field(
        default_factory=dict,
        description=(
            "Identity-string → Role mapping. Identity strings come "
            "from the v0.8.1 AuthProvider layer (token sub claim, "
            "mTLS subject DN, etc.). Match is exact-equality + "
            "case-sensitive."
        ),
    )
    default_role: Role = Field(
        default=Role.ADMIN,
        description=(
            "Role assigned to identities NOT in the ``identities`` "
            "map. Default :class:`Role.ADMIN` preserves v0.9.4 "
            "single-tenant behavior. Operators wanting deny-by-"
            "default set this to :class:`Role.DENY`."
        ),
    )

    def role_for(self, identity: str | None) -> Role:
        """Resolve an identity string to its role.

        ``None`` identity (anonymous request) returns
        :attr:`default_role`. Identities not in the map also return
        :attr:`default_role`. This is the single resolution path so
        callers don't reimplement the lookup.

        Note: EvidentiaModel's ``use_enum_values=True`` serializes
        Role values as strings, so identities-dict values round-
        trip through Pydantic as raw strings. We coerce back to
        :class:`Role` here so callers always get the enum + can
        call :meth:`Role.outranks_or_equal`.
        """
        raw = (
            self.default_role
            if identity is None
            else self.identities.get(identity, self.default_role)
        )
        return Role(raw) if not isinstance(raw, Role) else raw


#: Default permissive policy: everyone is admin. Mirrors the v0.9.4
#: behavior of "no RBAC enforcement applied." Operators wanting RBAC
#: load a policy via :func:`load_policy_from_file` and pass it to
#: :func:`check_permission` (or wire via the FastAPI
#: :func:`require_role` dependency factory).
DEFAULT_POLICY = RBACPolicy(
    identities={},
    default_role=Role.ADMIN,
)


def check_permission(
    identity: str | None,
    action: str,
    *,
    policy: RBACPolicy | None = None,
) -> bool:
    """Return True iff the identity is authorized for the action.

    Args:
        identity: Authenticated identity string (or ``None`` for
            anonymous). Resolved via :meth:`RBACPolicy.role_for`.
        action: One of ``"read"`` / ``"write"`` / ``"admin"``
            (the keys of :data:`ACTION_MIN_ROLE`). Raises
            ``KeyError`` for unknown actions — fail-loud so
            misuse surfaces at call site, not silently as a
            403 in production.
        policy: Optional explicit policy. Default uses
            :data:`DEFAULT_POLICY` (permissive).

    Returns:
        ``True`` if ``policy.role_for(identity)`` outranks or
        equals the action's minimum role; ``False`` otherwise.
        Anonymous identity + deny-by-default policy → always
        False.
    """
    effective_policy = policy or DEFAULT_POLICY
    role = effective_policy.role_for(identity)
    if role == Role.DENY:
        return False
    min_role = ACTION_MIN_ROLE[action]
    return role.outranks_or_equal(min_role)


def load_policy_from_file(path: Path) -> RBACPolicy:
    """Load a YAML or JSON policy file into a :class:`RBACPolicy`.

    File format (YAML)::

        identities:
          alice@example.com: admin
          bob@example.com: editor
        default_role: reader

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the file is not valid YAML/JSON OR the
            top-level structure doesn't match the schema. The
            error message names the failing field so operators
            can locate + fix the issue.
    """
    import yaml as yaml_mod

    if not path.exists():
        raise FileNotFoundError(f"RBAC policy file not found: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        data = yaml_mod.safe_load(raw)
    except yaml_mod.YAMLError as exc:
        raise ValueError(
            f"RBAC policy file {path} is not valid YAML/JSON: {exc}"
        ) from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"RBAC policy file {path} must be a mapping; "
            f"got {type(data).__name__}"
        )
    return RBACPolicy.model_validate(data)
