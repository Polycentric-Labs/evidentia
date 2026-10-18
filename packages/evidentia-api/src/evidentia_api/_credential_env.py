"""Validate request-body names of server-side credential env vars.

Several collector and integration routes let the request body name the
environment variable that holds a credential (``token_env``,
``password_env``, ``pat_name_env``, ``pat_secret_env``,
``client_secret_env``) so an operator can keep more than one token per
integration (``VANTA_API_TOKEN_EU`` next to ``VANTA_API_TOKEN``). Before
v0.13.0 any name was accepted, so a caller could point a route at an
unrelated variable (``AWS_SECRET_ACCESS_KEY``) and have the server send its
value to a host the same body chose (review finding C2, CWE-201).

:func:`resolve_credential_env_name` keeps the flexibility and closes the
disclosure class: the name must look like an environment variable
(``^[A-Z][A-Z0-9_]{0,63}$``) and start with one of the integration's own
prefixes. Anything else is a 400 ``invalid_field`` raised before any
environment read.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from evidentia_api.errors import api_error

ENV_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def resolve_credential_env_name(
    body: Mapping[str, Any],
    field: str,
    default: str,
    *,
    allowed_prefixes: tuple[str, ...],
) -> str:
    """Return the env var name a route may read for ``field``.

    A missing, ``None`` or blank value selects ``default``. Any other
    value must be a string matching :data:`ENV_NAME_PATTERN` and starting
    with one of ``allowed_prefixes``; otherwise a 400 ``invalid_field``
    error is raised, naming the field and the accepted prefixes but never
    reading the environment.
    """
    if not allowed_prefixes:
        raise ValueError("allowed_prefixes must name at least one prefix")
    raw = body.get(field)
    if raw is None:
        return default
    if not isinstance(raw, str):
        raise api_error(
            400,
            "invalid_field",
            f"{field} must be a string naming a server-side environment variable.",
            field=field,
        )
    name = raw.strip()
    if not name:
        return default
    if not ENV_NAME_PATTERN.match(name) or not name.startswith(allowed_prefixes):
        raise api_error(
            400,
            "invalid_field",
            (
                f"{field} must name an environment variable matching "
                f"{ENV_NAME_PATTERN.pattern} and starting with "
                f"{' or '.join(allowed_prefixes)}; got {name!r}."
            ),
            field=field,
            allowed_prefixes=list(allowed_prefixes),
        )
    return name
