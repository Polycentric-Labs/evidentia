# RBAC and multi-tenancy

Evidentia ships role-based access-control (RBAC) primitives and a multi-tenant extension on top of them. This page explains what those primitives do, how the decision functions work, and — critically — what is and is not wired yet. The single-tenant RBAC layer is enforced on every mutating REST operation and on the `evidence`, `catalog`, `collect` and `conmon release-series` CLI verbs today (the other CLI mutators rely on the operator shell; CLI gating is a v0.13.1 item); the **multi-tenant** layer is a data-plus-decision layer whose CLI/REST integration is a roadmap item for v0.11+. This page is precise about that boundary so you do not overclaim a capability that hasn't shipped.

The code lives in `packages/evidentia-core/src/evidentia_core/rbac/` (`policy.py` for single-tenant, `multi_tenant.py` for multi-tenant).

> **Scope, up front.** RBAC is **not authentication.** Identity arrives from a separate `AuthProvider` layer (token `sub` claim, mTLS subject DN, SSO); RBAC consumes the authenticated identity string and maps it to a role. If you haven't wired authentication, RBAC has nothing to enforce against.

## Single-tenant RBAC (`rbac/policy.py`)

The single-tenant model is deliberately minimal: a small role hierarchy and one action→minimum-role table, with a single decision entry point so the CLI and the REST API converge on the same logic.

### Roles

`Role` is a 4-member string enum, ordered `deny < reader < editor < admin`:

| Member | Value | Rank | Meaning |
|---|---|---|---|
| `DENY` | `deny` | 0 | Pseudo-role — no permission. Used as `default_role` for deny-by-default; never assignable to a real identity. |
| `READER` | `reader` | 1 | list / show / view operations. |
| `EDITOR` | `editor` | 2 | create / update / delete on user-owned records (POA&M items, milestones, AI registrations). |
| `ADMIN` | `admin` | 3 | global config (RBAC policy itself, catalogs, system secrets). |

The ordering is encoded in `Role.rank()` and compared via `Role.outranks_or_equal(other)`, so callers never hardcode the hierarchy. The action taxonomy is the module-level `ACTION_MIN_ROLE` dict: `read → READER`, `write → EDITOR`, `admin → ADMIN`.

### Policy and decision

`RBACPolicy` (an `EvidentiaModel`) maps identities to roles with an explicit default:

- `identities: dict[str, Role]` — exact-match, case-sensitive identity→role mapping.
- `default_role: Role` — the role for identities not in the map. **Default `ADMIN`**, which preserves single-tenant "no enforcement" behavior so existing single-operator deployments don't break. Operators wanting deny-by-default set this to `DENY`. (`role_for(identity)` is the single resolution path; it coerces the `use_enum_values` string back to a `Role` so callers always get the enum.)

The decision function:

```python
check_permission(identity, action, *, policy=None) -> bool
```

It resolves the identity to a role, returns `False` immediately if the role is `DENY`, otherwise returns whether the role outranks-or-equals the action's minimum. An **unknown `action`** raises `KeyError` — a deliberate fail-loud choice so misuse surfaces at the call site rather than silently becoming a production 403. The default policy (`DEFAULT_POLICY`, everyone-is-admin) is used when no explicit policy is passed.

Policies load from YAML or JSON via `load_policy_from_file(path)`:

```yaml
# /etc/evidentia/rbac.yaml
identities:
  alice@example.com: admin
  bob@example.com: editor
  reviewer@example.com: reader
default_role: reader   # role for unlisted identities; "deny" = no access
```

`default_role` is required to be explicit so an operator cannot accidentally ship a policy that grants admin to unknown identities.

### What's wired (single-tenant)

The single-tenant layer is enforced at runtime: operators point `EVIDENTIA_RBAC_POLICY_FILE` at their YAML, the CLI accepts a per-invocation `--rbac-identity` override (and the `EVIDENTIA_RBAC_IDENTITY` env var), and the FastAPI side has a `require_role(min_role)` dependency factory (`evidentia_api.rbac_dependency`) that makes router-level enforcement a one-liner. `Role`, `RBACPolicy`, `check_permission`, and `load_policy_from_file` are all frozen library entry points per [api-stability](../6-project/api-stability.md).

## Multi-tenant RBAC (`rbac/multi_tenant.py`)

The multi-tenant layer (v0.9.7) adds a per-tenant layer *above* the single-tenant policy — distinct authorization domains within one Evidentia instance — without disturbing the single-tenant surface, which stays frozen and canonical for single-operator deployments. It is an **additive opt-in.**

### Tenant claims and policy shape

Identity strings can carry a tenant claim using the canonical `@@` separator:

- `alice@example.com` — no claim.
- `alice@example.com@@acme-corp` — claims tenant `acme-corp`.

`resolve_tenant_from_identity(identity)` parses an identity into `(bare_identity, tenant_claim)`. The `@@` separator (the `TENANT_CLAIM_SEPARATOR` constant) is chosen to be lexically distinct from any RFC 5322 valid email and not collide with the domain part of normal addresses. Tenant IDs are validated by `validate_tenant_id` against a safe-slug pattern (`^[A-Za-z0-9][A-Za-z0-9_-]{0,62}$`) so a tenant ID can't escape a filesystem path component (raising `InvalidTenantIdError` otherwise) — this gates the tenant-scoped store path layout.

`TenantRBACPolicy` (an `EvidentiaModel`) holds:

- `tenants: dict[str, RBACPolicy]` — a complete single-tenant `RBACPolicy` per tenant.
- `default_tenant: str | None` — the tenant for identities arriving *without* a claim. `None` means strict claim-enforcement (no-claim → no policy → deny); set it to a primary tenant for v0.9.5-style backward compatibility.
- `cross_tenant_admin_role: Role` — default `DENY` (feature disabled). A `field_validator` constrains this to `ADMIN` or `DENY` only; a sub-admin value is rejected because it would be a privilege-widening footgun (finding F-V98-04).

The loader is `load_multi_tenant_policy_from_file(path)`, and `load_rbac_policy_auto(path)` auto-detects single- versus multi-tenant by the presence of a top-level `tenants:` key — the single detection point shared by both enforcement surfaces (a v0.9.8 review, F-V98-02, caught the API side previously lacking the detection the CLI had).

```yaml
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
cross_tenant_admin_role: deny   # default; explicit for clarity
```

### Decision function and the v0.9.7 limited semantic

`check_permission_multi_tenant(identity, action, *, policy)` runs: parse the identity → resolve the tenant (claim or `default_tenant`) to a per-tenant `RBACPolicy` (unknown tenant or no-claim-and-no-default → deny) → run the v0.9.5 `check_permission` against that tenant's policy → optionally apply cross-tenant admin escalation. Unknown actions raise `KeyError`, same fail-loud semantic as single-tenant.

**An honest caveat about `cross_tenant_admin_role`.** The field's *intended* full semantic (the v1.0 target) is: an identity holding this role in its assigned **home** tenant is also granted admin in **all other** tenants. The full semantic requires re-resolving the identity's home tenant from a server-side claim *independently* of the target tenant — and that re-resolution path depends on the v1.0 CLI/REST wiring that propagates an authenticated home-tenant claim separately. In v0.9.7 the decision function only ever sees **one** tenant (the claimed one). So with the field enabled, the block effectively degrades to "if the identity holds the escalation role *in the target tenant*, grant admin scope" — a slight in-tenant permissions widening, **not** true cross-tenant escalation. Most operators leave the field at the `DENY` default until v1.0 wires it properly. (Every escalation *decision* — granted or denied — emits the `RBAC_TENANT_BOUNDARY_CROSSED` audit event, added in v0.9.8 P1.5, so SIEM operators get a deterministic record of each attempted boundary crossing.)

### What's wired (multi-tenant) — and what is not

This is the part to be precise about. The v0.9.7 multi-tenant scope, per the `multi_tenant.py` module docstring, is **data + decision only**:

**Ships now:** the `TenantRBACPolicy` model, the `check_permission_multi_tenant` decision helper, the `load_multi_tenant_policy_from_file` loader, and the `resolve_tenant_from_identity` / `validate_tenant_id` parse helpers. An operator can model multi-tenant authorization in YAML and call the decision function from custom code today.

**Deferred to v0.11+ (roadmap, not shipped):**

- **CLI integration** — a `--rbac-tenant` global flag and tenant-aware policy-loader auto-detection in the CLI lifecycle.
- **FastAPI integration** — tenant-claim extraction from the `AuthProvider` result + per-request tenant-policy resolution.
- **The full cross-tenant escalation semantic** — independent home-tenant claim propagation (see the caveat above).
- **Tenant-scoped storage paths** — one POA&M / evidence store per tenant.

In other words: the multi-tenant *decision logic* is real, frozen, and tested, but you cannot today flip a CLI flag or a REST header and have Evidentia transparently enforce multi-tenant boundaries end-to-end. That wiring is the v1.0/v0.11+ work, intentionally deferred until walk-through-driven validation. Treat multi-tenancy as a building block you can compose against, not a turnkey deployment mode.

## Related reading

- [Evidence integrity](evidence-integrity.md) — the CIMD scope layer (MCP-client tool gating), which complements RBAC's identity→role gating.
- [Frozen surfaces and stability](frozen-surfaces-and-stability.md) — which RBAC symbols are frozen versus the wiring roadmap.
- [Architecture](architecture.md) — where authorization sits relative to the rest of the pipeline.
- [`6-project/api-stability.md`](../6-project/api-stability.md) — the frozen RBAC library entry points + env-var contract.
- [`6-project/roadmap.md`](../6-project/roadmap.md) — the v0.11+ CLI/REST wiring direction.
