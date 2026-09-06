"""Typer-side RBAC enforcement decorator (v0.9.6 P1).

Mirrors :func:`evidentia_api.rbac_dependency.require_role` at the CLI
layer. The two enforcement paths share a single decision function
(:func:`evidentia_core.rbac.check_permission`), one policy schema, and
identical action taxonomy so an operator's YAML policy applies
uniformly across CLI + API surfaces.

Usage::

    from evidentia.cli._rbac import require_role_cli

    @app.command("save")
    @require_role_cli("write")
    def save_evidence(...) -> None: ...

The decorator runs BEFORE the wrapped function. On deny it prints a
structured error to stderr + raises ``typer.Exit(code=77)`` (BSD
``EX_NOPERM``). On allow it invokes the function normally + returns
its value.

Identity + policy come from the process-lifetime singletons in
:mod:`evidentia.cli._rbac_lifecycle` (env-var-driven; loaded once
per CLI invocation). Tests can inject overrides via that module.
"""

from __future__ import annotations

import functools
import sys
from collections.abc import Callable
from typing import Any, TypeVar

import typer
from evidentia_core.rbac import (
    TenantRBACPolicy,
    check_permission,
    check_permission_multi_tenant,
)
from rich.console import Console

from evidentia.cli._rbac_lifecycle import (
    get_rbac_identity,
    get_rbac_identity_with_tenant_claim,
    get_rbac_policy,
)

F = TypeVar("F", bound=Callable[..., Any])

EXIT_CODE_RBAC_DENIED = 77
"""BSD ``EX_NOPERM``. CI jobs distinguish RBAC denial (77) from
generic failure (1) and from CLI usage errors (2 — Click's default)."""

_stderr_console = Console(stderr=True)


def require_role_cli(action: str) -> Callable[[F], F]:
    """Decorator factory that gates a Typer command behind RBAC.

    Args:
        action: One of ``"read"`` / ``"write"`` / ``"admin"`` —
            the keys of :data:`evidentia_core.rbac.policy.
            ACTION_MIN_ROLE`. Validated at decoration time
            (process startup) by a probe call into
            :func:`check_permission`; unknown actions surface a
            ``KeyError`` at import rather than at command dispatch.

    Returns:
        A decorator that wraps the target callable with an RBAC
        check. The wrapped callable preserves its signature so
        Typer's introspection of CLI options + arguments still
        works (Typer inspects the wrapped function's annotations).

    Behavior on deny:

    1. Print a structured error to ``stderr`` containing the
       action, identity (or ``"anonymous"``), and remediation hint
       pointing at the ``EVIDENTIA_RBAC_POLICY_FILE`` env var.
    2. Raise ``typer.Exit(code=77)`` so CI jobs can distinguish
       permission denial from other failures.

    Behavior on allow: call the wrapped function with original
    arguments + return its value.

    The decoration-time probe (line below ``def decorator``) calls
    ``check_permission`` with a sentinel identity + the requested
    action. Unknown actions raise ``KeyError`` here, NOT at command
    dispatch — protects operators against typos like
    ``require_role_cli("wirte")`` shipping as a 403 in production.
    """
    # Probe the action exists in ACTION_MIN_ROLE. Fail-loud at
    # decoration time (import time) rather than at command run.
    # Uses a sentinel identity that never matches any policy entry;
    # since DEFAULT_POLICY has default_role=ADMIN, the probe
    # returns True for known actions — we only care that the call
    # does NOT raise KeyError.
    check_permission("__rbac_probe__", action)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            policy = get_rbac_policy()
            # v0.9.8 P1.3: dispatch to the multi-tenant decision
            # function when the operator's policy is multi-tenant.
            # Combined identity merges --rbac-tenant / env-tenant
            # into the identity string as ``<bare>@@<tenant>`` so
            # ``check_permission_multi_tenant`` sees a uniform input.
            if isinstance(policy, TenantRBACPolicy):
                try:
                    identity = get_rbac_identity_with_tenant_claim()
                except ValueError as exc:
                    _stderr_console.print(f"[bold red]RBAC config error[/bold red] {exc}")
                    sys.stderr.flush()
                    raise typer.Exit(code=EXIT_CODE_RBAC_DENIED) from exc
                granted = check_permission_multi_tenant(identity, action, policy=policy)
            else:
                identity = get_rbac_identity()
                granted = check_permission(identity, action, policy=policy)
            if not granted:
                _stderr_console.print(
                    f"[bold red]Permission denied[/bold red] "
                    f"(action=[cyan]{action}[/cyan], "
                    f"identity=[yellow]{identity or 'anonymous'}[/yellow])"
                )
                _stderr_console.print(
                    "[dim]Configure RBAC via "
                    "EVIDENTIA_RBAC_POLICY_FILE + "
                    "EVIDENTIA_RBAC_IDENTITY env vars, or "
                    "--rbac-identity / --rbac-tenant flags.[/dim]"
                )
                sys.stderr.flush()
                raise typer.Exit(code=EXIT_CODE_RBAC_DENIED)
            return func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
