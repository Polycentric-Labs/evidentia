"""Unit tests for the stateful-DAST-prep OpenAPI surface (2026-07-06,
Steps 2 + 3 of the H-2 stateful DAST deliverable).

Step 2: asserts the ``openapi_extra``-declared ``links`` on the ai-gov
register and catalog import operations survive FastAPI's deep-merge
with the pre-existing ``responses=error_responses({...})`` 4xx
documentation — i.e. neither clobbers the other. These links are the
substrate ``tests/dast/test_openapi_stateful.py``'s state machine walks
to chain create -> read/update/delete transitions.

Step 3: asserts ``UpdateSystemRequest``'s ``json_schema_extra`` mirrors
the "at least one field" business rule its handler enforces at
runtime, closing a schemathesis ``positive_data_acceptance`` finding on
PUT /api/ai-gov/systems/{system_id}.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any

import pytest


@pytest.fixture
def openapi_schema() -> dict[str, Any]:
    """Build the OpenAPI schema with an isolated AI registry dir.

    Mirrors the isolation pattern used elsewhere (an isolated
    ``EVIDENTIA_AI_REGISTRY_DIR`` set before app construction) so this
    test never touches a developer's real registry store.
    """
    os.environ["EVIDENTIA_AI_REGISTRY_DIR"] = tempfile.mkdtemp(
        prefix="evidentia-openapi-links-test-"
    )
    from evidentia_api.app import create_app

    return create_app(offline=True).openapi()


class TestAiGovRegisterLinks:
    def test_links_present_with_correct_operation_ids_and_parameters(
        self, openapi_schema: dict[str, Any]
    ) -> None:
        register_op = openapi_schema["paths"]["/api/ai-gov/register"]["post"]
        links = register_op["responses"]["200"]["links"]

        assert set(links.keys()) == {
            "GetSystem",
            "UpdateSystem",
            "DeleteSystem",
        }

        # Derive expected operationIds from the schema itself (the GET/PUT/
        # DELETE ops on the same resource) so this assertion is robust to
        # operationId spelling drift rather than hardcoding a duplicate.
        system_id_path = openapi_schema["paths"][
            "/api/ai-gov/systems/{system_id}"
        ]
        expected_get_op_id = system_id_path["get"]["operationId"]
        expected_put_op_id = system_id_path["put"]["operationId"]
        expected_delete_op_id = system_id_path["delete"]["operationId"]

        assert links["GetSystem"]["operationId"] == expected_get_op_id
        assert links["UpdateSystem"]["operationId"] == expected_put_op_id
        assert links["DeleteSystem"]["operationId"] == expected_delete_op_id

        for name in ("GetSystem", "UpdateSystem", "DeleteSystem"):
            assert links[name]["parameters"] == {
                "system_id": "$response.body#/system_id"
            }

    def test_existing_4xx_responses_unchanged_after_openapi_extra_merge(
        self, openapi_schema: dict[str, Any]
    ) -> None:
        """Proves the ``openapi_extra`` link merge didn't clobber the
        ``error_responses()`` 4xx documentation already on the route."""
        register_responses = openapi_schema["paths"]["/api/ai-gov/register"][
            "post"
        ]["responses"]
        assert "400" in register_responses
        assert "409" in register_responses
        assert "429" in register_responses
        # Sanity: the descriptions still carry the documented error keys.
        assert "invalid_body" in register_responses["400"]["description"]
        assert (
            "idempotency_key_conflict"
            in register_responses["409"]["description"]
        )


class TestCatalogImportLinks:
    def test_delete_link_present_with_correct_operation_id_and_parameters(
        self, openapi_schema: dict[str, Any]
    ) -> None:
        import_op = openapi_schema["paths"]["/api/catalog/import"]["post"]
        links = import_op["responses"]["201"]["links"]

        assert len(links) == 1
        (_link_name, link) = next(iter(links.items()))

        expected_delete_op_id = openapi_schema["paths"][
            "/api/catalog/{framework_id}"
        ]["delete"]["operationId"]
        assert link["operationId"] == expected_delete_op_id
        assert link["parameters"] == {
            "framework_id": "$response.body#/framework_id"
        }

    def test_existing_4xx_responses_unchanged_after_openapi_extra_merge(
        self, openapi_schema: dict[str, Any]
    ) -> None:
        import_responses = openapi_schema["paths"]["/api/catalog/import"][
            "post"
        ]["responses"]
        assert "400" in import_responses
        assert "403" in import_responses
        assert "invalid_id" in import_responses["400"]["description"]
        assert "already_exists" in import_responses["400"]["description"]


class TestUpdateSystemRequestAtLeastOneFieldSchema:
    """Step 3: ``UpdateSystemRequest.model_json_schema()`` must mirror the
    handler's ``if not updates: raise api_error(400, "invalid_body", ...)``
    rule via a top-level ``anyOf`` of 4 branches (one per optional field),
    each requiring that field present AND non-null — otherwise
    schemathesis treats ``{}`` as schema-valid positive data and flags the
    handler's 400 as a ``positive_data_acceptance`` violation."""

    def test_any_of_has_exactly_4_branches_one_per_field(self) -> None:
        from evidentia_api.routers.ai_gov import UpdateSystemRequest

        schema = UpdateSystemRequest.model_json_schema()
        any_of = schema["anyOf"]
        assert len(any_of) == 4

        expected_fields = {
            "owner",
            "provider",
            "deployment_status",
            "ssp_reference",
        }
        seen_fields = set()
        for branch in any_of:
            assert len(branch["required"]) == 1
            (field,) = branch["required"]
            seen_fields.add(field)
            assert branch["properties"][field] == {"not": {"type": "null"}}
        assert seen_fields == expected_fields

    def test_schema_appears_verbatim_in_dumped_openapi_doc(
        self, openapi_schema: dict[str, Any]
    ) -> None:
        """The same ``anyOf`` shape must also show up in the dumped
        OpenAPI doc's component schema (not just the standalone
        ``model_json_schema()`` call) — this is what schemathesis
        actually reads to generate request bodies."""
        component = openapi_schema["components"]["schemas"][
            "UpdateSystemRequest"
        ]
        assert len(component["anyOf"]) == 4
