"""Multi-tenant RBAC primitives (v0.9.7 P2.3 — v1.0 prep).

Adds a per-tenant layer above the v0.9.5 single-tenant
:class:`evidentia_core.rbac.policy.RBACPolicy`. The single-tenant
surface remains frozen + canonical for single-operator deployments;
multi-tenant is an additive opt-in for organizations that need
distinct authorization domains in one Evidentia instance.

**Policy file format (multi-tenant)**::

    tenants:
      acme-corp:
        identities:
          alice@acme.com: admin
          bob@acme.com: editor
        default_role: reader
      globex:
        identities:
          carol@globex.com: admin
        default_role: deny
    default_tenant: acme-corp  # tenant assigned to identities
                               # without an explicit tenant claim
    cross_tenant_admin_role: admin  # optional: identities holding
                                    # this role IN their tenant ALSO
                                    # have admin in all other tenants

**Identity claim format**:
- single-tenant identity (no claim): ``alice@example.com``
- tenant-claim identity: ``alice@example.com@@acme-corp``
  (the ``@@<tenant>`` suffix is the canonical Evidentia tenant claim)

The double-``@`` separator is chosen to (a) be lexically distinct
from any RFC 5322 valid email + (b) avoid collision with the
domain part of normal email addresses.

**v0.9.7 partial scope** (what ships now):

- :class:`TenantRBACPolicy` Pydantic model (root multi-tenant policy)
- :func:`check_permission_multi_tenant(identity, action, policy)`
  decision helper
- :func:`load_multi_tenant_policy_from_file(path)` YAML loader
- :func:`resolve_tenant_from_identity(identity)` parse helper

**v1.0 follow-up scope** (deferred):

- CLI integration: `--rbac-tenant` global flag + tenant-aware
  policy loader auto-detection in :mod:`evidentia.cli._rbac_lifecycle`
- FastAPI integration: tenant claim extraction from the v0.8.1
  AuthProvider result + per-request tenant-policy resolution
- Cross-tenant impersonation audit trail (RBAC_TENANT_BOUNDARY_CROSSED)
- Tenant-scoped storage paths (one POA&M / evidence store per tenant)

The v0.9.7 surface is enough for operators to model multi-tenant
authorization in their YAML + call ``check_permission_multi_tenant``
from custom code; the CLI + REST integration ships in v1.0 after
walk-through-driven validation.

Threat-model boundary: multi-tenant RBAC does NOT replace
authentication. Identity (with or without a tenant claim) arrives
from the v0.8.1 AuthProvider; multi-tenant RBAC consumes it. If
the AuthProvider does not propagate tenant claims, every identity
defaults to ``default_tenant``.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import Field, field_validator

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.models.common import EvidentiaModel
from evidentia_core.rbac.policy import (
    ACTION_MIN_ROLE,
    RBACPolicy,
    Role,
    load_policy_from_file,
)

_log = get_logger("evidentia.rbac.multi_tenant")

#: Canonical tenant-claim separator in identity strings.
TENANT_CLAIM_SEPARATOR = "@@"

#: Pattern restricting tenant IDs to a safe slug shape.
#:
#: The canonical convention (per :class:`TenantRBACPolicy.tenants`
#: docstring) is lowercase + hyphenated (``acme-corp``, ``globex-inc``).
#: This pattern accepts the canonical form plus uppercase letters +
#: underscores for operators with legacy naming conventions, while
#: rejecting anything that could escape a filesystem path component
#: (slashes, dots, NUL, etc.). v0.9.8 P1.6 enforces this at the
#: storage-path layer to prevent a tenant-id-as-traversal-attack.
_TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$")


class InvalidTenantIdError(ValueError):
    """Raised when a tenant id contains characters that could escape a path component."""


def validate_tenant_id(tenant_id: str) -> str:
    """Validate + return a tenant id as a safe filesystem path component (v0.9.8 P1.6).

    Used by :mod:`evidentia_core.evidence_store` and
    :mod:`evidentia_core.poam_store` to gate the tenant-scoped
    path layout. The tenant id is rejected when:

    - Empty / whitespace-only
    - Longer than 63 characters (POSIX path-component soft limit)
    - Contains any character outside ``[A-Za-z0-9_-]``
    - Starts with a non-alphanumeric character (no leading hyphens /
      underscores so the slug stays git-friendly + URL-safe)

    Args:
        tenant_id: Operator-supplied tenant slug.

    Returns:
        The same string, returned for convenience so callers can
        chain :func:`validate_tenant_id` into a path construction.

    Raises:
        InvalidTenantIdError: When the id fails the format check.
    """
    if not isinstance(tenant_id, str) or not _TENANT_ID_PATTERN.match(tenant_id):
        raise InvalidTenantIdError(
            f"Invalid tenant id {tenant_id!r}: must match "
            f"{_TENANT_ID_PATTERN.pattern} (alphanumeric start, "
            f"alphanumeric / hyphen / underscore body, max 63 chars)."
        )
    return tenant_id


def resolve_tenant_from_identity(
    identity: str | None,
) -> tuple[str | None, str | None]:
    """Parse an identity into ``(bare_identity, tenant_claim)``.

    Conventions:

    - ``None`` identity → ``(None, None)`` (anonymous; no tenant).
    - ``alice@example.com`` (no claim) → ``("alice@example.com", None)``.
    - ``alice@example.com@@acme-corp`` → ``("alice@example.com", "acme-corp")``.
    - Empty string → ``(None, None)`` (treated as anonymous, matching
      the v0.9.5 :func:`evidentia.cli._rbac_lifecycle.get_rbac_identity`
      empty-env-var convention).

    Multiple ``@@`` separators are interpreted as: first separator
    splits identity from tenant; the tenant portion may contain
    further ``@@`` (unusual but allowed for forward compat).
    """
    if not identity:
        return None, None
    if TENANT_CLAIM_SEPARATOR not in identity:
        return identity, None
    bare, _, tenant = identity.partition(TENANT_CLAIM_SEPARATOR)
    return bare, tenant or None


class TenantRBACPolicy(EvidentiaModel):
    """Multi-tenant RBAC policy.

    Contains a per-tenant :class:`RBACPolicy` map + a default-tenant
    fallback + an optional cross-tenant admin role. Backward-compat
    with single-tenant: a single-tenant policy file can be wrapped
    via :meth:`from_single_tenant_policy` to use this multi-tenant
    decision path uniformly.
    """

    tenants: dict[str, RBACPolicy] = Field(
        default_factory=dict,
        description=(
            "Map of tenant_id → :class:`RBACPolicy` for that tenant. "
            "Each per-tenant policy is a complete v0.9.5 RBACPolicy "
            "(identities map + default_role). Tenant IDs are operator-"
            "defined slugs; conventionally lowercase + hyphenated "
            "(e.g., 'acme-corp', 'globex-inc')."
        ),
    )
    default_tenant: str | None = Field(
        default=None,
        description=(
            "Tenant assigned to identities arriving WITHOUT an "
            "explicit ``@@tenant`` claim. When ``None``, no-claim "
            "identities are treated as anonymous + resolve to the "
            "tenant's ``default_role``. Operators wanting strict "
            "tenant-claim enforcement leave this ``None``; operators "
            "wanting backward-compat with v0.9.5 single-tenant "
            "behavior set it to their primary tenant_id."
        ),
    )
    cross_tenant_admin_role: Role = Field(
        default=Role.DENY,
        description=(
            "Intended semantic (full v1.0): identities holding THIS "
            "role in their assigned HOME tenant are also granted "
            "admin in ALL other tenants when invoked against a "
            "target tenant. Default :attr:`Role.DENY` disables the "
            "feature entirely (recommended for v0.9.7).\n\n"
            "**v0.9.7 LIMITED IMPL** — the decision function "
            ":func:`check_permission_multi_tenant` only sees ONE "
            "tenant (the claim's). Without a separate home-tenant "
            "claim propagation path (deferred to v1.0 CLI/REST "
            "wiring), this field DEGRADES to: 'if the identity "
            "holds the escalation role IN THE TARGET TENANT, allow "
            "admin scope.' This is NOT cross-tenant escalation in "
            "the full sense; it is a slight in-tenant permissions "
            "widening. Most operators leave the field at "
            ":attr:`Role.DENY` until v1.0 wires the full semantic. "
            "v0.9.8 P1.5 emits :attr:`EventAction.RBAC_TENANT_"
            "BOUNDARY_CROSSED` on every escalation decision so SIEM "
            "operators see the deterministic record (closes the "
            "v0.9.7 reservation).\n\n"
            "**v0.9.8 P1.4 (F-V98-04)** — constrained to "
            ":attr:`Role.ADMIN` or :attr:`Role.DENY` only. A sub-admin "
            "value (editor / reader) would, under the limited "
            "semantic, let a target-tenant editor escalate to an "
            "action the per-tenant check denied — a privilege-widening "
            "footgun. The validator below rejects anything else."
        ),
    )

    @field_validator("cross_tenant_admin_role")
    @classmethod
    def _restrict_cross_tenant_admin_role(cls, value: object) -> object:
        """Reject sub-admin escalation roles (v0.9.8 P1.4 / F-V98-04).

        The field is named ``cross_tenant_admin_role``; the only
        meaningful settings are :attr:`Role.ADMIN` (enable the
        v1.0-bound escalation scaffolding) or :attr:`Role.DENY`
        (disable it — the safe default). A sub-admin value would be a
        privilege-widening footgun under the v0.9.7 limited semantic,
        so it is rejected at model-construction time.
        """
        role = value if isinstance(value, Role) else Role(value)
        if role not in (Role.ADMIN, Role.DENY):
            raise ValueError(
                f"cross_tenant_admin_role must be 'admin' or 'deny'; "
                f"got {role.value!r}. A sub-admin escalation role is a "
                f"privilege-widening footgun under the v0.9.7 limited "
                f"cross-tenant semantic (see F-V98-04)."
            )
        return value

    @classmethod
    def from_single_tenant_policy(
        cls,
        policy: RBACPolicy,
        tenant_id: str = "default",
    ) -> TenantRBACPolicy:
        """Wrap a v0.9.5 RBACPolicy as a single-tenant
        :class:`TenantRBACPolicy`.

        Used by tests + by the v1.0 single-tenant-config-as-multi-
        tenant compat shim. The resulting policy has exactly one
        tenant + sets it as the default so identities without a
        tenant claim resolve to it.
        """
        return cls(
            tenants={tenant_id: policy},
            default_tenant=tenant_id,
        )

    def policy_for_tenant(self, tenant_id: str | None) -> RBACPolicy | None:
        """Resolve a tenant_id (or default) to its :class:`RBACPolicy`.

        Returns ``None`` when:
        - ``tenant_id`` is None AND :attr:`default_tenant` is also None
          (operator wants strict tenant-claim enforcement; no-claim →
          no policy → deny)
        - The resolved tenant_id is not in :attr:`tenants`

        Otherwise returns the per-tenant :class:`RBACPolicy`.
        """
        effective_tenant = tenant_id or self.default_tenant
        if effective_tenant is None:
            return None
        return self.tenants.get(effective_tenant)


def check_permission_multi_tenant(
    identity: str | None,
    action: str,
    *,
    policy: TenantRBACPolicy,
) -> bool:
    """Multi-tenant variant of :func:`evidentia_core.rbac.check_permission`.

    Decision sequence:

    1. Parse the identity into ``(bare_identity, tenant_claim)`` via
       :func:`resolve_tenant_from_identity`. ``None`` identity → tenant
       claim is also None.
    2. Resolve the tenant_claim (or :attr:`TenantRBACPolicy.default_tenant`
       if no claim) to a per-tenant :class:`RBACPolicy`. Unknown tenant
       OR no-claim-and-no-default → return False (deny).
    3. Check ``bare_identity``'s role in that tenant's policy via the
       v0.9.5 :func:`evidentia_core.rbac.check_permission`.
    4. Cross-tenant admin escalation: if the per-tenant check denies,
       check whether the bare_identity has the policy's
       :attr:`cross_tenant_admin_role` in ITS OWN tenant. If so,
       grant admin-scope access in the target tenant.

    Raises ``KeyError`` for unknown ``action`` values — same fail-loud
    semantic as the single-tenant decision function.
    """
    bare_identity, tenant_claim = resolve_tenant_from_identity(identity)
    tenant_policy = policy.policy_for_tenant(tenant_claim)
    if tenant_policy is None:
        return False

    # Per-tenant check.
    role = tenant_policy.role_for(bare_identity)
    if role == Role.DENY:
        # Per-tenant deny; fall through to cross-tenant check below.
        pass
    else:
        min_role = ACTION_MIN_ROLE[action]
        if role.outranks_or_equal(min_role):
            return True

    # Cross-tenant admin escalation: only meaningful when policy
    # explicitly enables it (cross_tenant_admin_role != DENY).
    #
    # :class:`EvidentiaModel` sets ``use_enum_values=True``, so
    # ``policy.cross_tenant_admin_role`` round-trips as the raw
    # string (``'deny'`` / ``'admin'`` / etc.) rather than the
    # :class:`Role` enum. Coerce once so the comparison + method
    # calls below operate on enum instances. Closes a v0.9.7 latent
    # bug where ``outranks_or_equal`` would raise ``AttributeError``
    # on the string. The bug was never triggered in v0.9.7 because
    # most operators leave the field at the default DENY (which
    # short-circuits before any coercion is needed).
    escalation_role = (
        policy.cross_tenant_admin_role
        if isinstance(policy.cross_tenant_admin_role, Role)
        else Role(policy.cross_tenant_admin_role)
    )
    if escalation_role == Role.DENY:
        return False
    # v0.9.7 LIMITED IMPL — name vs behavior caveat:
    #
    # The field is named `cross_tenant_admin_role` and the
    # docstring promises "identities holding THIS role in their
    # assigned tenant are also granted admin in ALL other tenants."
    # The FULL semantic requires re-resolving the identity's HOME
    # tenant from a server-side claim, independently of the target
    # tenant the caller asked about — that re-resolution path
    # depends on v1.0 CLI/REST wiring that propagates the
    # authenticated home-tenant claim separately from the requested
    # target tenant.
    #
    # In v0.9.7, the function only sees ONE tenant (the claimed
    # one). So this block effectively checks whether the identity
    # has the escalation role IN THE TARGET TENANT — which is
    # equivalent to: "if the user holds cross_tenant_admin_role in
    # this tenant, allow the action." It is NOT cross-tenant
    # escalation in the full sense.
    #
    # Result: v0.9.7 callers that opt into cross_tenant_admin_role
    # get a SLIGHT permissions widening (escalation-role holders
    # in the target tenant get admin-scope) but NOT the
    # cross-tenant semantic. Most operators leave the field at
    # DENY (default) and wait for v1.0 to wire it properly.
    #
    # This block is preserved for forward-compat: v1.0's wiring
    # path inserts a `home_tenant` parameter and re-resolves the
    # home policy independently; today's callers can still set the
    # field without breaking when v1.0 lands.
    home_role = tenant_policy.role_for(bare_identity)
    escalation_granted = home_role.outranks_or_equal(escalation_role)
    # v0.9.8 P1.5 — emit the audit event the v0.9.7 docstring
    # reserved. Fires on every escalation DECISION (granted or
    # denied via escalation degradation), so SIEM operators see a
    # deterministic record per attempted boundary crossing.
    #
    # v0.9.8 P1.4 (F-V98-03): supply the structured `evidentia=`
    # payload documented in EventAction.RBAC_TENANT_BOUNDARY_CROSSED
    # so SIEM filters can pivot on the fields directly rather than
    # regex-ing the human-readable message. Mirrors every other audit
    # emitter (scope.py, poam.py, conmon.py, ai_gov.py).
    _log.warning(
        action=EventAction.RBAC_TENANT_BOUNDARY_CROSSED,
        outcome=(EventOutcome.SUCCESS if escalation_granted else EventOutcome.FAILURE),
        message=(
            f"Cross-tenant escalation {'granted' if escalation_granted else 'denied'} "
            f"for identity {bare_identity!r} (claimed_tenant={tenant_claim!r}, "
            f"action={action!r}, escalation_role={escalation_role.value!r})"
        ),
        evidentia={
            "identity": bare_identity,
            "claimed_tenant": tenant_claim,
            "escalation_role": escalation_role.value,
            "action": action,
        },
    )
    return escalation_granted


def load_multi_tenant_policy_from_file(path: Path) -> TenantRBACPolicy:
    """Load a multi-tenant policy file (YAML / JSON).

    File schema::

        tenants:
          acme-corp:
            identities:
              alice@acme.com: admin
              bob@acme.com: editor
            default_role: reader
          globex:
            identities:
              carol@globex.com: admin
            default_role: deny
        default_tenant: acme-corp
        cross_tenant_admin_role: deny  # default; explicit for clarity

    Raises:
        FileNotFoundError: If ``path`` does not exist.
        ValueError: If the file is not valid YAML/JSON OR the top-level
            structure does not match the schema. The error message
            names the failing field so operators can locate + fix.
    """
    import yaml as yaml_mod

    if not path.exists():
        raise FileNotFoundError(f"Multi-tenant RBAC policy file not found: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        data = yaml_mod.safe_load(raw)
    except yaml_mod.YAMLError as exc:
        raise ValueError(f"Multi-tenant RBAC policy file {path} is not valid YAML/JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Multi-tenant RBAC policy file {path} must be a mapping; got {type(data).__name__}")
    return TenantRBACPolicy.model_validate(data)


def load_rbac_policy_auto(path: Path) -> RBACPolicy | TenantRBACPolicy:
    """Load an RBAC policy file, auto-detecting single- vs multi-tenant (v0.9.8 P1.4).

    A YAML/JSON file with a top-level ``tenants:`` key is a multi-tenant
    policy and loads as :class:`TenantRBACPolicy`; everything else loads
    as a single-tenant :class:`RBACPolicy`.

    This is the single detection point shared by BOTH RBAC enforcement
    surfaces — the CLI process-lifetime loader
    (:mod:`evidentia.cli._rbac_lifecycle`) and the FastAPI app
    (:func:`evidentia_api.app.create_app`). Sharing it guarantees the
    CLI and the REST API classify the same policy file identically;
    a v0.9.8 pre-release review (finding F-V98-02) caught the API side
    silently lacking the detection the CLI had.

    Args:
        path: Path to the policy file.

    Returns:
        :class:`TenantRBACPolicy` when the file has a ``tenants:`` key,
        else :class:`RBACPolicy`. Callers branch on the type to dispatch
        to :func:`check_permission_multi_tenant` vs
        :func:`evidentia_core.rbac.check_permission`.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        ValueError: The file is not valid YAML/JSON, the top-level value
            is not a mapping, or it fails the policy schema. Propagated
            from the underlying single/multi loaders.
    """
    import yaml as yaml_mod

    if not path.exists():
        raise FileNotFoundError(f"RBAC policy file not found: {path}")
    try:
        data = yaml_mod.safe_load(path.read_text(encoding="utf-8"))
    except yaml_mod.YAMLError as exc:
        raise ValueError(f"RBAC policy file {path} is not valid YAML/JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"RBAC policy file {path} must be a mapping at top level; got {type(data).__name__}")
    if "tenants" in data:
        return load_multi_tenant_policy_from_file(path)
    return load_policy_from_file(path)


__all__ = [
    "TENANT_CLAIM_SEPARATOR",
    "InvalidTenantIdError",
    "TenantRBACPolicy",
    "check_permission_multi_tenant",
    "load_multi_tenant_policy_from_file",
    "load_rbac_policy_auto",
    "resolve_tenant_from_identity",
    "validate_tenant_id",
]
