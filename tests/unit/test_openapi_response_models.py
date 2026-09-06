"""The federal AI-gov verbs must declare typed response models (v0.12 WU-3).

The five OMB M-25-21 / M-25-22 verbs shipped in v0.11.0 as api-only rows
in ``docs/cli-gui-parity.yaml``. Building their web-console surface needs
real generated TypeScript, and a handler annotated ``-> dict[str, Any]``
with no ``response_model`` produces an OpenAPI schema of
``{"additionalProperties": true}`` — which ``openapi-typescript`` renders
as an index signature carrying no field information at all. The UI would
then be typed against `unknown`, which is how a rename reaches production
silently.

So the backend goes first: declare the response models, regenerate
``openapi.json`` and the TS types, and only then write the console
against types that mean something.

These assertions also stand as a regression guard — a future refactor
that drops a ``response_model`` back to a bare dict would be caught here
rather than in a UI runtime error.
"""

from __future__ import annotations

from typing import Any

import pytest
from evidentia_api.app import create_app

#: (path, method, the component schema name the 200 response must resolve to)
FEDERAL_OPERATIONS = [
    (
        "/api/ai-gov/systems/{system_id}/set-practice",
        "post",
        "SetPracticeResponse",
    ),
    ("/api/ai-gov/acquisitions", "post", "RegisterAcquisitionResponse"),
    ("/api/ai-gov/acquisitions", "get", "ListAcquisitionsResponse"),
    (
        "/api/ai-gov/acquisitions/{acquisition_id}",
        "get",
        "AcquisitionDetailResponse",
    ),
    (
        "/api/ai-gov/acquisitions/{acquisition_id}/set-phase",
        "post",
        "AcquisitionDetailResponse",
    ),
]


@pytest.fixture(scope="module")
def openapi_schema() -> dict[str, Any]:
    return create_app(offline=True).openapi()


def _success_schema(schema: dict[str, Any], path: str, method: str) -> dict[str, Any]:
    operation = schema["paths"][path][method]
    content = operation["responses"]["200"]["content"]["application/json"]
    return content["schema"]


@pytest.mark.parametrize(("path", "method", "model"), FEDERAL_OPERATIONS)
def test_success_response_references_a_named_model(
    openapi_schema: dict[str, Any], path: str, method: str, model: str
) -> None:
    """The 200 response must ``$ref`` a component, not an open dict."""
    resolved = _success_schema(openapi_schema, path, method)
    assert resolved.get("$ref") == f"#/components/schemas/{model}", (
        f"{method.upper()} {path} still returns an untyped object "
        f"({resolved}); declare response_model={model} so the generated "
        f"TypeScript carries real field types"
    )


@pytest.mark.parametrize(("path", "method", "model"), FEDERAL_OPERATIONS)
def test_response_model_has_declared_properties(
    openapi_schema: dict[str, Any], path: str, method: str, model: str
) -> None:
    """A named-but-empty model would satisfy the $ref check vacuously."""
    component = openapi_schema["components"]["schemas"][model]
    assert component.get("properties"), (
        f"{model} declares no properties — a $ref to an empty object is "
        f"no more useful to the console than additionalProperties: true"
    )


def test_acquisition_detail_is_shared_by_show_and_set_phase(
    openapi_schema: dict[str, Any],
) -> None:
    """Both return record + progress; one model keeps the console simple."""
    show = _success_schema(openapi_schema, "/api/ai-gov/acquisitions/{acquisition_id}", "get")
    set_phase = _success_schema(
        openapi_schema,
        "/api/ai-gov/acquisitions/{acquisition_id}/set-phase",
        "post",
    )
    assert show == set_phase


def test_list_response_exposes_count_and_items(
    openapi_schema: dict[str, Any],
) -> None:
    """The console renders a count badge and iterates the array."""
    component = openapi_schema["components"]["schemas"]["ListAcquisitionsResponse"]
    properties = component["properties"]
    assert "count" in properties
    assert properties["acquisitions"]["type"] == "array"
