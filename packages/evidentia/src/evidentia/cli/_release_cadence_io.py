"""Publish accepted release bytes under one CLI invocation and policy binding."""

from __future__ import annotations

import importlib
import importlib.util
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, Never, cast

import typer
from evidentia_core.rbac import RBACPolicy, Role, TenantRBACPolicy, check_permission, check_permission_multi_tenant
from evidentia_core.release_cadence._contracts import (
    PollRequest,
    PollResult,
    ReleaseSeriesRequest,
    ReleaseSeriesResult,
    native_model,
)
from evidentia_core.release_cadence._json import canonical_bytes, load_json
from evidentia_core.release_cadence._limits import (
    REQUEST_BYTES,
    RESULT_BYTES,
    SOURCE_PROFILE,
    ReleaseFailure,
    _Invocation,
)
from pydantic import ValidationError

from evidentia.cli import _rbac_lifecycle


def _exit(message: str, code: int) -> Never:
    typer.echo(message, err=True)
    raise typer.Exit(code)


def _fields(value: object, kind: type, names: set[str]) -> dict[str, Any]:
    if type(value) is not kind:
        raise ReleaseFailure("authority_unavailable")
    fields = object.__getattribute__(value, "__dict__")
    extras = object.__getattribute__(value, "__pydantic_extra__")
    if (
        type(fields) is not dict
        or any(type(key) is not str for key in fields)
        or set(fields) != names
        or (extras is not None and (type(extras) is not dict or extras))
    ):
        raise ReleaseFailure("authority_unavailable")
    return cast(dict[str, Any], fields)


def _role(value: object) -> str:
    if type(value) is Role:
        return value.value
    if type(value) is str and value in {"reader", "editor", "admin", "deny"}:
        return value
    raise ReleaseFailure("authority_unavailable")


def _tenant(value: object) -> str:
    if type(value) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}", value) is None:
        raise ReleaseFailure("authority_unavailable")
    return value


def _signature(policy: object) -> tuple[object, ...]:
    if type(policy) is RBACPolicy:
        fields = _fields(policy, RBACPolicy, {"identities", "default_role"})
        identities = fields["identities"]
        if type(identities) is not dict or any(type(key) is not str for key in identities):
            raise ReleaseFailure("authority_unavailable")
        return (
            "single",
            tuple((key, _role(identities[key])) for key in sorted(identities)),
            _role(fields["default_role"]),
        )
    fields = _fields(policy, TenantRBACPolicy, {"tenants", "default_tenant", "cross_tenant_admin_role"})
    tenants = fields["tenants"]
    if type(tenants) is not dict:
        raise ReleaseFailure("authority_unavailable")
    names = [_tenant(name) for name in tenants]
    if len({name.lower() for name in names}) != len(names):
        raise ReleaseFailure("authority_unavailable")
    default = fields["default_tenant"]
    if default is not None and _tenant(default) not in tenants:
        raise ReleaseFailure("authority_unavailable")
    role = _role(fields["cross_tenant_admin_role"])
    if role not in {"admin", "deny"}:
        raise ReleaseFailure("authority_unavailable")
    nested = []
    for name in sorted(names):
        if type(tenants[name]) is not RBACPolicy:
            raise ReleaseFailure("authority_unavailable")
        nested.append((name, _signature(tenants[name])))
    return ("tenant", tuple(nested), default, role)


def _authority() -> tuple[Callable[[str], None], str | None]:
    policy = _rbac_lifecycle.get_rbac_policy()
    signature = _signature(policy)
    multi = type(policy) is TenantRBACPolicy
    identity_reader = (
        _rbac_lifecycle.get_rbac_identity_with_tenant_claim if multi else _rbac_lifecycle.get_rbac_identity
    )
    identity = identity_reader()
    if identity is not None and type(identity) is not str:
        raise ReleaseFailure("authority_unavailable")
    tenant = None
    if multi:
        if identity is not None and "@@" in identity:
            bare, _, claim = identity.partition("@@")
            if not bare.strip():
                raise ReleaseFailure("authority_unavailable")
            tenant = _tenant(claim)
        else:
            tenant = _tenant(cast(TenantRBACPolicy, policy).default_tenant)
        if tenant not in cast(TenantRBACPolicy, policy).tenants:
            raise ReleaseFailure("authority_unavailable")

    def require(action: str) -> None:
        current_identity = identity_reader()
        if current_identity is not None and type(current_identity) is not str:
            raise ReleaseFailure("authority_unavailable")
        if (
            _rbac_lifecycle.get_rbac_policy() is not policy
            or _signature(policy) != signature
            or current_identity != identity
        ):
            raise ReleaseFailure("authority_unavailable")
        granted = (
            check_permission_multi_tenant(identity, action, policy=cast(TenantRBACPolicy, policy))
            if multi
            else check_permission(identity, action, policy=cast(RBACPolicy, policy))
        )
        if not granted:
            _exit("Permission denied for the release operation.", 77)

    require("read")
    return require, tenant


def _load_poll() -> Callable[..., Any]:
    try:
        module = importlib.import_module("evidentia_collectors.release_cadence.collector")
    except ModuleNotFoundError as error:
        absent = False
        if type(error.name) is str and error.name in {"evidentia_collectors", "evidentia_collectors.release_cadence"}:
            try:
                absent = importlib.util.find_spec(error.name) is None
            except Exception:
                absent = False
        raise ReleaseFailure("support_unavailable" if absent else "support_broken") from None
    except Exception:
        raise ReleaseFailure("support_broken") from None
    function = getattr(module, "_prepare_poll_from_clock", None)
    if not callable(function):
        raise ReleaseFailure("support_broken")
    return cast(Callable[..., Any], function)


def _request(value: dict[str, object], clock: _Invocation, *, series: bool) -> tuple[dict[str, object], bytes]:
    clock.check()
    try:
        model = ReleaseSeriesRequest.model_validate(value) if series else PollRequest.model_validate(value)
        native = native_model(model)
        encoded = canonical_bytes(native, REQUEST_BYTES, budget=clock.budget, max_depth=8, max_values=64)
    except ValidationError:
        raise ReleaseFailure("invalid_request") from None
    clock.check()
    return native, encoded


def _accepted(wire: object, captured: bytes, clock: _Invocation, *, series: bool) -> int:
    clock.check()
    if type(wire) is not bytes or not 0 < len(wire) <= RESULT_BYTES:
        raise ReleaseFailure("operation_failed")
    native = load_json(wire, RESULT_BYTES, budget=clock.budget, max_values=RESULT_BYTES)
    model = ReleaseSeriesResult.model_validate(native) if series else PollResult.model_validate(native)
    checked = native_model(model)
    if canonical_bytes(checked["request"], REQUEST_BYTES, budget=clock.budget) != captured:
        raise ReleaseFailure("operation_failed")
    if canonical_bytes(native, RESULT_BYTES, budget=clock.budget, max_values=RESULT_BYTES) != wire:
        raise ReleaseFailure("operation_failed")
    clock.check()
    if series:
        return 0 if checked["state"] in {"continuous", "gapped", "insufficient"} else 1
    persistence = cast(dict[str, object], checked["persistence"])
    return (
        0 if checked["collection_state"] == "complete" and persistence["state"] in {"not_requested", "complete"} else 1
    )


def _publish(wire: bytes, clock: _Invocation) -> None:
    """Publication checks are cooperative; synchronous writes cannot be preempted."""
    clock.check()
    stream = sys.stdout.buffer
    for offset in range(0, len(wire), 65_536):
        clock.check()
        chunk = wire[offset : offset + 65_536]
        written = stream.write(chunk)
        if type(written) is not int or written != len(chunk):
            raise ReleaseFailure("publication_failed")
        clock.check()
    stream.flush()
    clock.check()


def _failure(error: Exception, clock: _Invocation) -> Never:
    owned = clock.persistence.failure(error)
    if owned is not None:
        _exit(owned.message, 1)
    failure = error if isinstance(error, ReleaseFailure) else ReleaseFailure("operation_failed")
    if failure.code == "persistence_outcome_unavailable":
        failure = ReleaseFailure("operation_failed")
    _exit(failure.message, 2 if failure.code in {"invalid_request", "request_limit_exceeded"} else 1)


def run_release_cadence(
    *,
    _clock: _Invocation,
    owner: str,
    repository: str,
    channel: str,
    persist: bool = False,
    evidence_store: Path | None = None,
) -> None:
    """Observe or explicitly persist, with the callback's original invocation."""
    if type(_clock) is not _Invocation:
        _exit("The release operation failed.", 1)
    try:
        _clock.check()
        require, tenant = _authority()
        value, captured = _request(
            {
                "schema_version": "release-poll-request-v1",
                "source_profile": SOURCE_PROFILE,
                "owner": owner,
                "repository": repository,
                "channel": channel,
                "persist": persist,
            },
            _clock,
            series=False,
        )
        require("write" if persist else "read")
        prepare = _load_poll()
        _clock.check()
        root = None
        if persist:
            from evidentia_core.release_cadence._store import lexical_store_root

            root = lexical_store_root(evidence_store, tenant=tenant)
        operation = prepare(_clock)
        wire = operation.begin(value, evidence_store_dir=root).output_bytes()
        require("read")
        code = _accepted(wire, captured, _clock, series=False)
        _publish(wire, _clock)
    except typer.Exit:
        raise
    except Exception as error:
        _failure(error, _clock)
    raise typer.Exit(code)


def run_release_series(
    *,
    _clock: _Invocation,
    owner: str,
    repository: str,
    channel: str,
    window_start: str,
    window_end: str,
    interval_days: int,
    tolerance_days: int,
    evidence_store: Path | None = None,
) -> None:
    """Read recorded publication spacing without importing an optional collector."""
    if type(_clock) is not _Invocation:
        _exit("The release operation failed.", 1)
    try:
        _clock.check()
        require, tenant = _authority()
        value, captured = _request(
            {
                "schema_version": "release-series-request-v1",
                "source_profile": SOURCE_PROFILE,
                "owner": owner,
                "repository": repository,
                "channel": channel,
                "window_start": window_start,
                "window_end": window_end,
                "interval_days": interval_days,
                "tolerance_days": tolerance_days,
            },
            _clock,
            series=True,
        )
        from evidentia_core.release_cadence._series import _evaluate_wire
        from evidentia_core.release_cadence._store import lexical_store_root

        root = lexical_store_root(evidence_store, tenant=tenant)
        wire, _ = _evaluate_wire(value, root, _clock=_clock)
        require("read")
        code = _accepted(wire, captured, _clock, series=True)
        _publish(wire, _clock)
    except typer.Exit:
        raise
    except Exception as error:
        _failure(error, _clock)
    raise typer.Exit(code)
