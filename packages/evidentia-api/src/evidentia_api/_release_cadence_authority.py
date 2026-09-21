"""Bind release operations to the application's actual authenticated policy."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast
from weakref import WeakKeyDictionary

from evidentia_core.plugins.auth import AuthProvider
from evidentia_core.rbac import RBACPolicy, TenantRBACPolicy, check_permission, check_permission_multi_tenant
from evidentia_core.rbac.policy import Role
from evidentia_core.release_cadence._limits import Budget, ReleaseFailure
from evidentia_core.release_cadence._store import _TenantRoot, lexical_store_root
from fastapi import FastAPI, Request

from evidentia_api.errors import api_error


@dataclass(frozen=True, slots=True)
class _PolicyBinding:
    policy: object
    state: str
    signature: tuple[object, ...] | None


_BINDINGS: WeakKeyDictionary[FastAPI, _PolicyBinding] = WeakKeyDictionary()


def _role(value: object) -> str:
    if type(value) is Role:
        return value.value
    if type(value) is str and value in {"reader", "editor", "admin", "deny"}:
        return value
    raise ReleaseFailure("authority_unavailable")


def _fields(policy: object, expected: type, keys: set[str]) -> dict[str, Any]:
    if type(policy) is not expected:
        raise ReleaseFailure("authority_unavailable")
    values = object.__getattribute__(policy, "__dict__")
    if type(values) is not dict or any(type(key) is not str for key in values) or set(values) != keys:
        raise ReleaseFailure("authority_unavailable")
    extras = object.__getattribute__(policy, "__pydantic_extra__")
    if extras is not None and (type(extras) is not dict or extras):
        raise ReleaseFailure("authority_unavailable")
    return values


def _single(policy: object) -> tuple[object, ...]:
    values = _fields(policy, RBACPolicy, {"identities", "default_role"})
    identities = values["identities"]
    if type(identities) is not dict or any(type(key) is not str for key in identities):
        raise ReleaseFailure("authority_unavailable")
    return ("single", tuple((key, _role(identities[key])) for key in sorted(identities)), _role(values["default_role"]))


def _tenant(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", value) is None:
        raise ReleaseFailure("authority_unavailable")
    return value


def _signature(policy: object) -> tuple[object, ...]:
    if type(policy) is RBACPolicy:
        return _single(policy)
    values = _fields(policy, TenantRBACPolicy, {"tenants", "default_tenant", "cross_tenant_admin_role"})
    tenants = values["tenants"]
    if type(tenants) is not dict:
        raise ReleaseFailure("authority_unavailable")
    spellings = [_tenant(key) for key in tenants]
    if len({key.lower() for key in spellings}) != len(spellings):
        raise ReleaseFailure("authority_unavailable")
    default = values["default_tenant"]
    if default is not None and _tenant(default) not in tenants:
        raise ReleaseFailure("authority_unavailable")
    cross = _role(values["cross_tenant_admin_role"])
    if cross not in {"admin", "deny"}:
        raise ReleaseFailure("authority_unavailable")
    return ("tenant", tuple((key, _single(tenants[key])) for key in sorted(spellings)), default, cross)


def _record_policy(app: FastAPI, policy: object, state: str) -> None:
    """Called only at the existing app-owned policy-load branch."""
    signature = None
    try:
        if type(state) is str and state in {"default", "loaded"}:
            signature = _signature(policy)
    except Exception:
        signature = None
    binding = _PolicyBinding(policy, state, signature)
    _BINDINGS[app] = binding
    app.state.release_cadence_policy_provenance = state
    app.state._release_cadence_policy_binding = binding


@dataclass(frozen=True, slots=True)
class ReleaseAuthority:
    _require: Callable[[str], None]
    _root: Callable[[Budget], object]

    def require(self, action: str) -> None:
        self._require(action)

    def store_root(self, budget: Budget) -> object:
        return self._root(budget)


def capture_authority(request: Request) -> ReleaseAuthority:
    app = request.app
    provider = getattr(app.state, "auth_provider", None)
    principal = getattr(request.state, "auth_principal", None)
    authenticated_provider = getattr(request.state, "auth_provider", None)
    if (
        not isinstance(provider, AuthProvider)
        or authenticated_provider is not provider
        or type(principal) is not str
        or not principal.strip()
    ):
        raise api_error(403, "auth_not_configured", "Release operations require configured API authentication.")
    candidate_binding = _BINDINGS.get(app)
    if candidate_binding is None or candidate_binding.signature is None:
        raise ReleaseFailure("authority_unavailable")
    binding = cast(_PolicyBinding, candidate_binding)
    tenant = None
    if type(binding.policy) is TenantRBACPolicy:
        bare, marker, claim = principal.partition("@@")
        if marker:
            if not bare.strip():
                raise ReleaseFailure("authority_unavailable")
            tenant = _tenant(claim)
        else:
            tenant = _tenant(binding.policy.default_tenant)
        if tenant not in binding.policy.tenants:
            raise ReleaseFailure("authority_unavailable")

    def require(action: str) -> None:
        if type(action) is not str or action not in {"read", "write"}:
            raise ReleaseFailure("authority_unavailable")
        if (
            _BINDINGS.get(app) is not binding
            or getattr(app.state, "_release_cadence_policy_binding", None) is not binding
            or getattr(app.state, "rbac_policy", None) is not binding.policy
            or type(getattr(app.state, "release_cadence_policy_provenance", None)) is not str
            or app.state.release_cadence_policy_provenance != binding.state
            or getattr(app.state, "auth_provider", None) is not provider
            or getattr(request.state, "auth_provider", None) is not provider
            or type(getattr(request.state, "auth_principal", None)) is not str
            or request.state.auth_principal != principal
            or _signature(binding.policy) != binding.signature
        ):
            raise ReleaseFailure("authority_unavailable")
        if type(binding.policy) is TenantRBACPolicy:
            allowed = check_permission_multi_tenant(principal, action, policy=binding.policy)
        elif type(binding.policy) is RBACPolicy:
            allowed = check_permission(principal, action, policy=binding.policy)
        else:
            raise ReleaseFailure("authority_unavailable")
        if _signature(binding.policy) != binding.signature:
            raise ReleaseFailure("authority_unavailable")
        if allowed is not True:
            raise api_error(
                403,
                "rbac_denied",
                "Identity does not have permission for this action. "
                "Operators configure RBAC via EVIDENTIA_RBAC_POLICY_FILE.",
                action=action,
                identity=principal,
            )

    def root(budget: Budget) -> object:
        require("read")
        budget.check()
        selected = lexical_store_root(tenant=tenant)
        if tenant is not None and type(selected) is not _TenantRoot:
            raise ReleaseFailure("authority_unavailable")
        budget.check()
        return selected

    require("read")
    return ReleaseAuthority(require, root)
