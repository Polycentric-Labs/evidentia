"""Project ordered security.txt field occurrences from the owned text adapter."""

from __future__ import annotations

from typing import Any

from ._client import RegistryReadSession
from ._contracts import RegistryInputError, RegistryLookupResult, SecurityTxtRequest
from ._parsing import checked_json


def project_security_txt(source: dict[str, Any]) -> dict[str, Any]:
    """Keep raw field values and line positions with the declared signature state."""
    copied = checked_json(source)
    if type(copied) is not dict:
        raise ValueError("invalid security.txt projection shape")
    selected: dict[str, Any] = {
        name: copied[name] for name in ("fields", "signed", "signature_state") if name in copied
    }
    if "fields" in selected:
        fields = selected["fields"]
        if type(fields) is not list:
            raise ValueError("invalid security.txt projection shape")
        occurrences: list[dict[str, Any]] = []
        for field in fields:
            if type(field) is not dict:
                raise ValueError("invalid security.txt projection shape")
            occurrences.append(
                {name: field[name] for name in ("name", "value", "source_line", "body_line") if name in field}
            )
        selected["fields"] = occurrences
    return selected


def lookup(session: RegistryReadSession) -> RegistryLookupResult:
    """Read only the selected hostname's permitted security.txt retrieval scope."""
    request = session.request.root
    if not isinstance(request, SecurityTxtRequest):
        raise RegistryInputError()
    return session.read_security_txt(request.target, project_security_txt)
