"""Tenant aliases have the same bounded ASCII language in runtime and schemas."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, Literal, cast

import pytest
from evidentia_collectors.entra_m365 import _contracts as c
from evidentia_core.models.common import NON_BLANK_PATTERN
from pydantic import ValidationError

ALIAS_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}(?![\s\S])"
VALID_ALIASES = ("A", "z", "0", "9", "Synthetic_Tenant-1", "A._-9", "a" * 64)
WHITESPACE = tuple(chr(code) for code in range(0x110000) if chr(code).isspace())
INVALID_ALIASES = (
    "",
    *WHITESPACE,
    "".join(WHITESPACE),
    "-first",
    "_first",
    ".first",
    "/first",
    "first/last",
    "space inside",
    " alias",
    "alias ",
    "alias\n",
    "alias\r\n",
    "alias\r",
    "alias\u0085",
    "alias\u2028",
    "alias\u2029",
    "a" * 65,
    "\u00e9",
    "alias\u00e9",
    "\u03b1lias",
    "\uff21lias",
    "alias\x00",
    "alias\u200b",
    "alias\ufeff",
)
Surface = Literal["request", "result"]
SchemaMode = Literal["validation", "serialization"]
SCHEMA_MODES: tuple[SchemaMode, ...] = ("validation", "serialization")


def _alias_schema(surface: Surface, mode: SchemaMode) -> dict[str, Any]:
    if surface == "request":
        return cast(
            dict[str, Any], c.EntraM365CollectRequest.model_json_schema(mode=mode)["properties"]["tenant_label"]
        )
    schema = c.EntraM365CollectResult.model_json_schema(mode=mode)
    reference = schema["properties"]["provenance"]["$ref"]
    assert reference.startswith("#/$defs/")
    return cast(dict[str, Any], schema["$defs"][reference.removeprefix("#/$defs/")]["properties"]["tenant_label"])


def _schema_accepts_alias(schema: dict[str, Any], value: object) -> bool:
    """Evaluate the published string constraints without another dependency."""
    assert set(schema) in (
        {"type", "title", "minLength", "maxLength", "pattern"},
        {"type", "title", "minLength", "maxLength", "pattern", "allOf"},
    )
    assert schema["type"] == "string"
    extra = schema.get("allOf", [])
    assert isinstance(extra, list) and all(set(item) == {"pattern"} for item in extra)
    patterns = [schema["pattern"], *(item["pattern"] for item in extra)]
    return bool(
        type(value) is str
        and schema["minLength"] <= len(value) <= schema["maxLength"]
        and all(re.search(pattern, value) is not None for pattern in patterns)
    )


def _result(label: str) -> c.EntraM365CollectResult:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    request = c.EntraM365CollectRequest(tenant_label=label, capabilities=["conditional-access"])
    context = c.EntraM365RunContext.start(
        request,
        utc_clock=lambda: now,
        monotonic_clock=lambda: 0.0,
        sleep=lambda _seconds: None,
        run_id_factory=lambda: "synthetic-alias-schema",
    )
    reading = context.begin("conditional-access", "application")
    reading.note_attempt()
    reading.admit_page([], continuation=False)
    source = reading.finish_source()
    return context.build_result([context.finish_read(source, findings=[])])


@pytest.mark.parametrize("surface", ["request", "result"])
@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_alias_schema_keeps_core_nonblank_and_ascii_constraints(surface: Surface, mode: SchemaMode) -> None:
    schema = _alias_schema(surface, mode)
    assert schema["minLength"] == 1
    assert schema["maxLength"] == 64
    if surface == "result":
        assert schema["pattern"] == NON_BLANK_PATTERN
        assert schema["allOf"] == [{"pattern": ALIAS_PATTERN}]
    else:
        assert schema["pattern"] == ALIAS_PATTERN


@pytest.mark.parametrize("surface", ["request", "result"])
@pytest.mark.parametrize("alias", VALID_ALIASES)
def test_alias_runtime_and_full_model_schema_accept_valid_values(surface: Surface, alias: str) -> None:
    model: c.EntraM365CollectRequest | c.EntraM365CollectResult
    model = c.EntraM365CollectRequest(tenant_label=alias) if surface == "request" else _result(alias)
    encoded = model.model_dump_json(exclude_unset=surface == "request", warnings="error")
    restored = type(model).model_validate_json(encoded)
    assert restored.model_dump_json(exclude_unset=surface == "request", warnings="error") == encoded
    payload = json.loads(encoded)
    assert (payload["tenant_label"] if surface == "request" else payload["provenance"]["tenant_label"]) == alias
    for mode in SCHEMA_MODES:
        assert _schema_accepts_alias(_alias_schema(surface, mode), alias)


@pytest.mark.parametrize("surface", ["request", "result"])
@pytest.mark.parametrize("alias", INVALID_ALIASES)
def test_alias_runtime_and_full_model_schema_reject_invalid_values(surface: Surface, alias: str) -> None:
    model_type: type[c.EntraM365CollectRequest] | type[c.EntraM365CollectResult]
    location: tuple[str, ...]
    if surface == "request":
        model_type = c.EntraM365CollectRequest
        data: dict[str, Any] = {"tenant_label": alias}
        location = ("tenant_label",)
    else:
        model_type = c.EntraM365CollectResult
        data = json.loads(_result("synthetic").model_dump_json(warnings="error"))
        data["provenance"]["tenant_label"] = alias
        location = ("provenance", "tenant_label")
    with pytest.raises(ValidationError) as failure:
        model_type.model_validate_json(json.dumps(data))
    assert location in [error["loc"] for error in failure.value.errors(include_input=False)]
    for mode in SCHEMA_MODES:
        assert not _schema_accepts_alias(_alias_schema(surface, mode), alias)


@pytest.mark.parametrize("surface", ["request", "result"])
@pytest.mark.parametrize("alias", [None, False, 0, 1.0, [], {}])
def test_alias_rejects_non_string_values(surface: Surface, alias: object) -> None:
    model_type: type[c.EntraM365CollectRequest] | type[c.EntraM365CollectResult]
    location: tuple[str, ...]
    if surface == "request":
        model_type = c.EntraM365CollectRequest
        data: dict[str, Any] = {"tenant_label": alias}
        location = ("tenant_label",)
    else:
        model_type = c.EntraM365CollectResult
        data = json.loads(_result("synthetic").model_dump_json(warnings="error"))
        data["provenance"]["tenant_label"] = alias
        location = ("provenance", "tenant_label")
    with pytest.raises(ValidationError) as failure:
        model_type.model_validate_json(json.dumps(data))
    assert location in [error["loc"] for error in failure.value.errors(include_input=False)]
    for mode in SCHEMA_MODES:
        assert not _schema_accepts_alias(_alias_schema(surface, mode), alias)
