"""FedRAMP validators assert date formats and the SCR model validates its URI (v0.13.0 review M4)."""

from __future__ import annotations

import pytest
from evidentia_core.fedramp import validate_scn_document
from pydantic import ValidationError

# The test directory is not a package; pytest puts it on sys.path at collection.
from test_scn_writer import _full_form  # type: ignore[import-not-found]


def test_golden_form_is_still_schema_valid() -> None:
    assert validate_scn_document(_full_form().to_scn_document()) == []


def test_malformed_planned_start_date_is_reported() -> None:
    document = _full_form().to_scn_document()
    document["planAndTimeline"]["plannedStart"] = "31/31/2026"
    errors = validate_scn_document(document)
    assert errors, "a non-ISO date passed as schema-valid"
    assert any("plannedStart" in error for error in errors)


@pytest.mark.parametrize("value", ["not a uri at all", "/relative/path", "ftp://files.example/overview"])
def test_overview_uri_must_be_absolute_http(value: str) -> None:
    form = _full_form()
    with pytest.raises(ValidationError, match="absolute http"):
        form.model_copy(update={"certification_package_overview_uri": value}).model_validate(
            {**form.model_dump(), "certification_package_overview_uri": value}
        )


def test_overview_uri_accepts_https() -> None:
    form = _full_form()
    payload = {**form.model_dump(), "certification_package_overview_uri": "https://provider.example/overview"}
    assert type(form).model_validate(payload).certification_package_overview_uri == "https://provider.example/overview"
