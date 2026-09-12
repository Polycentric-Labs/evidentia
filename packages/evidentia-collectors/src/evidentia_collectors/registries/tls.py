"""Project the fields exposed by one verified TLS negotiation."""

from __future__ import annotations

from typing import Any, cast

from ._client import RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult, TLSRequest
from ._parsing import checked_json


def _select(value: object, names: tuple[str, ...]) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not dict:
        raise ValueError("invalid TLS projection shape")
    source = cast(dict[str, Any], value)
    return {name: source[name] for name in names if name in source}


def project_tls(source: dict[str, Any]) -> dict[str, Any]:
    """Keep literal negotiated values and omit unselected certificate details."""
    copied = checked_json(source)
    selected = _select(copied, ("protocol", "cipher", "peer_address", "der_sha256", "certificate"))
    if selected is None:
        raise ValueError("invalid TLS projection shape")
    if "cipher" in selected:
        selected["cipher"] = _select(selected["cipher"], ("name", "protocol", "secret_bits"))
    if "certificate" in selected:
        selected["certificate"] = _select(
            selected["certificate"], ("subject", "issuer", "subjectAltName", "notBefore", "notAfter")
        )
    return selected


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Read the selected hostname through the session's verified TLS reader."""
    request = session.request.root
    if not isinstance(request, TLSRequest):
        raise RegistryInputError()
    return session.read_tls(request.target, project_tls)
