"""Every published string property with ``minLength: 1`` must also carry the
non-blank pattern.

The stripping runtime (``EvidentiaModel.str_strip_whitespace``) rejects a
whitespace-only value that a bare ``minLength: 1`` schema accepts, and the
stateful DAST suite reports that disagreement as RejectedPositiveData (a lone
U+0085 owner on 2026-09-06, U+00A0 on 2026-09-03). ``NonBlankStr`` (core) and
``_NON_BLANK_SCHEMA`` (the ai-gov request models) publish the pattern; this test
keeps a new field from reopening the gap. It reads the committed
``openapi.json`` so it fails in the same place the CI drift gate does.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from evidentia_core.models.common import NON_BLANK_PATTERN, NonBlankStr
from pydantic import BaseModel, ValidationError

REPO_ROOT = Path(__file__).resolve().parents[2]
OPENAPI = REPO_ROOT / "packages" / "evidentia-ui" / "openapi.json"


def _string_props_with_min_length_1() -> list[tuple[str, dict[str, object]]]:
    spec = json.loads(OPENAPI.read_text(encoding="utf-8"))
    found: list[tuple[str, dict[str, object]]] = []
    for name, schema in spec["components"]["schemas"].items():
        for prop, body in (schema.get("properties") or {}).items():
            for variant in [body, *body.get("anyOf", [])]:
                if variant.get("type") == "string" and variant.get("minLength") == 1:
                    found.append((f"{name}.{prop}", variant))
    return found


def test_gate_is_not_vacuous() -> None:
    assert len(_string_props_with_min_length_1()) >= 10


def test_every_min_length_1_string_publishes_the_non_blank_pattern() -> None:
    missing = sorted(
        name
        for name, variant in _string_props_with_min_length_1()
        if variant.get("pattern") != NON_BLANK_PATTERN
    )
    assert missing == [], (
        "string fields whose schema admits a whitespace-only value the runtime "
        f"rejects; use NonBlankStr (or _NON_BLANK_SCHEMA in ai_gov.py): {missing}"
    )


class _Probe(BaseModel):
    value: NonBlankStr


@pytest.mark.parametrize(
    "blank", ["", " ", "\t\n", " ", "", "　  "]
)
def test_non_blank_str_rejects_whitespace_only(blank: str) -> None:
    with pytest.raises(ValidationError):
        _Probe(value=blank)


@pytest.mark.parametrize("value", ["a", " a ", " x ", "0"])
def test_non_blank_str_accepts_any_visible_character(value: str) -> None:
    assert _Probe(value=value).value == value


def test_pattern_rejects_every_python_whitespace_code_point() -> None:
    leaked = [
        hex(cp)
        for cp in range(0x110000)
        if chr(cp).isspace() and re.search(NON_BLANK_PATTERN, chr(cp))
    ]
    assert leaked == []
