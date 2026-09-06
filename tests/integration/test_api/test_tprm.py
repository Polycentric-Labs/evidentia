"""TestClient coverage for /api/tprm/vendors/* endpoints (v0.7.9 P0.1.4).

Each test scopes the vendor store to ``tmp_path`` via the
``EVIDENTIA_VENDOR_STORE_DIR`` env var so no state leaks across
tests or into the real user profile. Reuses the project-wide
``api_client`` fixture from conftest.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _isolated_vendor_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point EVIDENTIA_VENDOR_STORE_DIR at an isolated tmp for each test."""
    store = tmp_path / "vendor-store"
    monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(store))
    return store


@pytest.fixture
def tprm_readonly_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """A TPRM TestClient under a restrictive read-only RBAC policy.

    Mirrors ``gov_readonly_client`` in ``test_governance_router``: a local
    app holding ONLY the tprm router, with a deny-by-default policy whose
    ``default_role`` is ``reader``. An anonymous request (identity None)
    resolves to that role, so reads pass while ``require_role("write")``
    gates deny — proving the ingest gate actually bites (it is inert under
    the permissive DEFAULT_POLICY the other tests run with).
    """
    from evidentia_api.routers import tprm as tprm_router
    from evidentia_core.rbac import RBACPolicy, Role
    from fastapi import FastAPI

    store = tmp_path / "vendor-store"
    monkeypatch.setenv("EVIDENTIA_VENDOR_STORE_DIR", str(store))

    app = FastAPI()
    app.include_router(tprm_router.router, prefix="/api")
    app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.READER)
    with TestClient(app) as client:
        yield client


def _make_payload(
    name: str = "Acme Cloud",
    type_: str = "cloud_provider",
    criticality_tier: str = "critical",
) -> dict[str, object]:
    return {
        "name": name,
        "type": type_,
        "criticality_tier": criticality_tier,
        "relationship_owner": "allen@allenfbyrd.com",
        "contract_start_date": "2025-01-01",
    }


# ── POST /api/tprm/vendors ─────────────────────────────────────────


class TestCreateVendor:
    def test_minimal_create_returns_201_with_stamped_fields(self, api_client: TestClient) -> None:
        r = api_client.post("/api/tprm/vendors", json=_make_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        # Server stamped these via Pydantic default_factory
        assert body["id"]
        assert body["created_at"]
        assert body["updated_at"]
        assert body["evidentia_version"]
        assert body["name"] == "Acme Cloud"

    def test_create_auto_computes_next_review_due(self, api_client: TestClient) -> None:
        payload = _make_payload(criticality_tier="high")
        payload["last_due_diligence_review"] = "2025-06-15"
        r = api_client.post("/api/tprm/vendors", json=payload)
        assert r.status_code == 201, r.text
        # high → annual cadence
        assert r.json()["next_review_due"] == "2026-06-15"

    def test_invalid_enum_returns_422_via_pydantic(self, api_client: TestClient) -> None:
        payload = _make_payload(type_="not-a-real-type")
        r = api_client.post("/api/tprm/vendors", json=payload)
        # FastAPI's auto-validation 422 with array-shape detail
        assert r.status_code == 422
        assert isinstance(r.json()["detail"], list)

    def test_missing_required_field_returns_422_via_pydantic(self, api_client: TestClient) -> None:
        payload = _make_payload()
        del payload["name"]
        r = api_client.post("/api/tprm/vendors", json=payload)
        assert r.status_code == 422


# ── GET /api/tprm/vendors ──────────────────────────────────────────


class TestListVendors:
    def test_empty_store(self, api_client: TestClient) -> None:
        r = api_client.get("/api/tprm/vendors")
        assert r.status_code == 200
        body = r.json()
        assert body == {"total": 0, "skip": 0, "limit": 100, "vendors": []}

    def test_list_returns_pagination_envelope(self, api_client: TestClient) -> None:
        for n in ["A", "B", "C"]:
            api_client.post("/api/tprm/vendors", json=_make_payload(name=n))
        r = api_client.get("/api/tprm/vendors")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 3
        assert body["skip"] == 0
        assert body["limit"] == 100
        assert len(body["vendors"]) == 3

    def test_pagination_skip_limit(self, api_client: TestClient) -> None:
        for n in range(5):
            api_client.post(
                "/api/tprm/vendors",
                json=_make_payload(name=f"Vendor {n}"),
            )
        r = api_client.get("/api/tprm/vendors?skip=2&limit=2")
        body = r.json()
        assert body["total"] == 5
        assert body["skip"] == 2
        assert body["limit"] == 2
        assert len(body["vendors"]) == 2

    def test_filter_by_criticality_tier(self, api_client: TestClient) -> None:
        api_client.post(
            "/api/tprm/vendors",
            json=_make_payload(name="Crit", criticality_tier="critical"),
        )
        api_client.post(
            "/api/tprm/vendors",
            json=_make_payload(name="Low", criticality_tier="low"),
        )
        r = api_client.get("/api/tprm/vendors?criticality_tier=critical")
        body = r.json()
        assert body["total"] == 1
        assert body["vendors"][0]["name"] == "Crit"

    def test_filter_by_type_via_alias(self, api_client: TestClient) -> None:
        api_client.post("/api/tprm/vendors", json=_make_payload(type_="cloud_provider"))
        api_client.post("/api/tprm/vendors", json=_make_payload(type_="saas"))
        # ``type`` is the query alias for ``type_`` per the router signature
        r = api_client.get("/api/tprm/vendors?type=saas")
        body = r.json()
        assert body["total"] == 1
        assert body["vendors"][0]["type"] == "saas"

    def test_unknown_criticality_tier_returns_400(self, api_client: TestClient) -> None:
        r = api_client.get("/api/tprm/vendors?criticality_tier=ultra-critical")
        assert r.status_code == 400
        # F-V08-DAST-3 status normalization: manual 4xx carries the
        # structured object detail (2026-07-06 convergence) — still
        # distinguishable from Pydantic's 422 array.
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_criticality_tier"
        assert detail["criticality_tier"] == "ultra-critical"
        assert "message" in detail

    def test_unknown_type_returns_400(self, api_client: TestClient) -> None:
        r = api_client.get("/api/tprm/vendors?type=not-a-type")
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_type"
        assert "message" in detail


# ── GET /api/tprm/vendors/{vendor_id} ──────────────────────────────


class TestGetVendor:
    def test_known_id_returns_200(self, api_client: TestClient) -> None:
        post = api_client.post("/api/tprm/vendors", json=_make_payload())
        vid = post.json()["id"]
        r = api_client.get(f"/api/tprm/vendors/{vid}")
        assert r.status_code == 200
        assert r.json()["id"] == vid

    def test_unknown_well_formed_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.get("/api/tprm/vendors/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_malformed_id_returns_404(self, api_client: TestClient) -> None:
        # F-V08-DAST-1 widening pattern: shape violation also normalizes
        # to 404 (rather than letting the unhandled InvalidVendorIdError
        # propagate to 500).
        r = api_client.get("/api/tprm/vendors/not-a-uuid")
        assert r.status_code == 404


# ── PUT /api/tprm/vendors/{vendor_id} ──────────────────────────────


class TestReplaceVendor:
    def test_replace_preserves_id_and_created_at(self, api_client: TestClient) -> None:
        post = api_client.post("/api/tprm/vendors", json=_make_payload(name="Original"))
        original = post.json()
        vid = original["id"]
        original_created = original["created_at"]

        new_payload = _make_payload(name="Replaced")
        # Client tries to spoof id + created_at — server should ignore
        new_payload["id"] = "spoofed-id"
        new_payload["created_at"] = "2020-01-01T00:00:00Z"
        r = api_client.put(f"/api/tprm/vendors/{vid}", json=new_payload)
        assert r.status_code == 200
        body = r.json()
        assert body["id"] == vid
        assert body["created_at"] == original_created
        assert body["name"] == "Replaced"

    def test_replace_unknown_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.put(
            "/api/tprm/vendors/00000000-0000-0000-0000-000000000000",
            json=_make_payload(),
        )
        assert r.status_code == 404

    def test_replace_malformed_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.put(
            "/api/tprm/vendors/not-a-uuid",
            json=_make_payload(),
        )
        assert r.status_code == 404


# ── DELETE /api/tprm/vendors/{vendor_id} ───────────────────────────


class TestDeleteVendor:
    def test_known_id_returns_204(self, api_client: TestClient) -> None:
        post = api_client.post("/api/tprm/vendors", json=_make_payload())
        vid = post.json()["id"]
        r = api_client.delete(f"/api/tprm/vendors/{vid}")
        assert r.status_code == 204
        # Verify gone
        get_r = api_client.get(f"/api/tprm/vendors/{vid}")
        assert get_r.status_code == 404

    def test_unknown_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.delete("/api/tprm/vendors/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_malformed_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.delete("/api/tprm/vendors/not-a-uuid")
        assert r.status_code == 404


# ── GET /api/tprm/vendors/{vendor_id}/next-review-due ──────────────


class TestPreviewNextReviewDue:
    def test_with_dd_review_returns_computed_date(self, api_client: TestClient) -> None:
        payload = _make_payload(criticality_tier="medium")
        payload["last_due_diligence_review"] = "2025-06-15"
        post = api_client.post("/api/tprm/vendors", json=payload)
        vid = post.json()["id"]
        r = api_client.get(f"/api/tprm/vendors/{vid}/next-review-due")
        assert r.status_code == 200
        # medium → biennial cadence
        assert r.json() == {"next_review_due": "2027-06-15"}

    def test_without_dd_review_returns_null(self, api_client: TestClient) -> None:
        post = api_client.post("/api/tprm/vendors", json=_make_payload())
        vid = post.json()["id"]
        r = api_client.get(f"/api/tprm/vendors/{vid}/next-review-due")
        assert r.status_code == 200
        assert r.json() == {"next_review_due": None}

    def test_unknown_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.get("/api/tprm/vendors/00000000-0000-0000-0000-000000000000/next-review-due")
        assert r.status_code == 404


# ── concentration-risk reporting (v0.7.9 P0.3) ─────────────────────


class TestConcentrationEndpoint:
    def _seed(self, api_client: TestClient) -> None:
        for name, region in [
            ("US-A", "us-east-1"),
            ("US-B", "us-east-1"),
            ("EU-A", "eu-west-1"),
        ]:
            payload = _make_payload(name=name)
            payload["region"] = region
            r = api_client.post("/api/tprm/vendors", json=payload)
            assert r.status_code == 201, r.text

    def test_default_dimensions_returns_200(self, api_client: TestClient) -> None:
        self._seed(api_client)
        r = api_client.get("/api/tprm/concentration?by=region")
        assert r.status_code == 200
        body = r.json()
        assert body["total_vendors"] == 3
        assert body["dimensions"][0]["dimension"] == "region"

    def test_threshold_flags_in_json(self, api_client: TestClient) -> None:
        self._seed(api_client)
        # 2 of 3 in us-east-1 = 66.7%; threshold=50 → flag us-east-1
        r = api_client.get("/api/tprm/concentration?by=region&threshold=50")
        body = r.json()
        flagged = [v for v in body["dimensions"][0]["distribution"] if v["exceeds_threshold"]]
        assert len(flagged) == 1
        assert flagged[0]["value"] == "us-east-1"

    def test_unsupported_dimension_returns_400(self, api_client: TestClient) -> None:
        r = api_client.get("/api/tprm/concentration?by=not-a-dim")
        assert r.status_code == 400
        # F-V08-DAST-3 status normalization: manual 4xx carries the
        # structured object detail (2026-07-06 convergence) — still
        # distinguishable from Pydantic's 422 array.
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_dimension"
        assert detail["dimensions"] == ["not-a-dim"]
        assert "message" in detail

    def test_empty_by_returns_400(self, api_client: TestClient) -> None:
        r = api_client.get("/api/tprm/concentration?by=")
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_field"
        assert detail["field"] == "by"

    def test_threshold_out_of_range_returns_422(self, api_client: TestClient) -> None:
        # FastAPI Query(ge=0, le=100) — out-of-range hits Pydantic
        # auto-validation 422 with array-shape detail
        r = api_client.get("/api/tprm/concentration?by=region&threshold=200")
        assert r.status_code == 422
        assert isinstance(r.json()["detail"], list)

    def test_multiple_dimensions(self, api_client: TestClient) -> None:
        self._seed(api_client)
        r = api_client.get("/api/tprm/concentration?by=region,service-category")
        body = r.json()
        assert [d["dimension"] for d in body["dimensions"]] == [
            "region",
            "service-category",
        ]


# ── DD-questionnaire generation (v0.7.9 P0.2) ─────────────────────


class TestDDQuestionnaireEndpoint:
    def _add_vendor(self, api_client: TestClient) -> str:
        r = api_client.post("/api/tprm/vendors", json=_make_payload())
        assert r.status_code == 201
        return str(r.json()["id"])

    def test_generic_returns_201_with_pre_fill(self, api_client: TestClient) -> None:
        vid = self._add_vendor(api_client)
        r = api_client.post(f"/api/tprm/vendors/{vid}/dd-questionnaire?format=evidentia-generic")
        assert r.status_code == 201
        body = r.json()
        assert body["format"] == "evidentia-generic"
        assert body["vendor"]["vendor_id"] == vid
        assert len(body["questions"]) >= 15

    def test_caiq_lite_includes_attribution(self, api_client: TestClient) -> None:
        vid = self._add_vendor(api_client)
        r = api_client.post(f"/api/tprm/vendors/{vid}/dd-questionnaire?format=caiq-lite")
        assert r.status_code == 201
        body = r.json()
        assert body["licensing_attribution"]
        assert "CC BY 4.0" in body["licensing_attribution"]

    def test_unknown_format_returns_400(self, api_client: TestClient) -> None:
        vid = self._add_vendor(api_client)
        r = api_client.post(f"/api/tprm/vendors/{vid}/dd-questionnaire?format=not-a-format")
        assert r.status_code == 400
        # F-V08-DAST-3 status normalization: manual 4xx carries the
        # structured object detail (2026-07-06 convergence) — still
        # distinguishable from Pydantic's 422 array.
        detail = r.json()["detail"]
        assert detail["error"] == "unknown_format"
        assert detail["format"] == "not-a-format"
        assert "message" in detail

    def test_sig_format_returns_501(self, api_client: TestClient) -> None:
        # SIG / SIG-Lite stubs — reachable via the enum (so format
        # validation passes) but generate_questionnaire raises
        # NotImplementedError → router translates to 501.
        vid = self._add_vendor(api_client)
        r = api_client.post(f"/api/tprm/vendors/{vid}/dd-questionnaire?format=sig")
        assert r.status_code == 501
        detail = r.json()["detail"]
        assert detail["error"] == "not_implemented"
        # Message references the BYO-template path
        assert "Shared Assessments" in detail["message"]

    def test_unknown_vendor_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/tprm/vendors/00000000-0000-0000-0000-000000000000/dd-questionnaire?format=evidentia-generic"
        )
        assert r.status_code == 404

    def test_malformed_vendor_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post("/api/tprm/vendors/not-a-uuid/dd-questionnaire?format=evidentia-generic")
        assert r.status_code == 404


# ── DD-questionnaire INGEST (POST .../dd-questionnaire/ingest) ──────


class TestDDQuestionnaireIngestEndpoint:
    """Parse + correlate a completed DD questionnaire (parse-only).

    Mirrors the ``evidentia tprm dd-questionnaire ingest`` CLI verb
    exactly: the endpoint PARSES the completed-questionnaire document
    (the canonical Questionnaire shape, with per-question
    ``vendor_response`` values) and CORRELATES it to the vendor record,
    then RETURNS the correlation result. It does NOT mutate the vendor
    (no EvidenceRef appended) — persistence stays deferred, matching the
    CLI's documented scope.
    """

    def _add_vendor(self, api_client: TestClient) -> str:
        r = api_client.post("/api/tprm/vendors", json=_make_payload())
        assert r.status_code == 201, r.text
        return str(r.json()["id"])

    def _completed_body(self) -> dict[str, object]:
        """A completed questionnaire in the canonical Questionnaire shape.

        Matches what ``parse_completed_questionnaire`` consumes for the
        ``.json`` path: per-question ``vendor_response`` values, plus
        top-level ``id`` / ``format`` for correlation context.
        """
        return {
            "id": "33333333-3333-3333-3333-333333333333",
            "format": "evidentia-generic",
            "questions": [
                {
                    "id": "EVG-GOV-01",
                    "vendor_response": "Yes — board-approved infosec policy.",
                },
                {
                    "id": "EVG-GOV-02",
                    "vendor_response": "SOC 2 Type II on file.",
                },
            ],
        }

    def test_ingest_returns_correlation_result(self, api_client: TestClient) -> None:
        vid = self._add_vendor(api_client)
        r = api_client.post(
            f"/api/tprm/vendors/{vid}/dd-questionnaire/ingest",
            json=self._completed_body(),
        )
        assert r.status_code == 200, r.text
        body = r.json()
        # The correlation result: vendor identity + parsed responses
        # correlated by question.id, plus carry-forward context.
        assert body["vendor"]["id"] == vid
        assert body["vendor"]["name"] == "Acme Cloud"
        assert body["questionnaire_id"] == ("33333333-3333-3333-3333-333333333333")
        assert body["format"] == "evidentia-generic"
        assert body["responses"] == {
            "EVG-GOV-01": "Yes — board-approved infosec policy.",
            "EVG-GOV-02": "SOC 2 Type II on file.",
        }

    def test_ingest_does_not_mutate_vendor(self, api_client: TestClient) -> None:
        vid = self._add_vendor(api_client)
        before = api_client.get(f"/api/tprm/vendors/{vid}").json()
        assert before["evidence_refs"] == []

        r = api_client.post(
            f"/api/tprm/vendors/{vid}/dd-questionnaire/ingest",
            json=self._completed_body(),
        )
        assert r.status_code == 200, r.text

        # Parse-only: the vendor record is UNCHANGED — no EvidenceRef
        # appended, updated_at not bumped.
        after = api_client.get(f"/api/tprm/vendors/{vid}").json()
        assert after["evidence_refs"] == []
        assert after["updated_at"] == before["updated_at"]

    def test_ingest_unknown_vendor_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/tprm/vendors/00000000-0000-0000-0000-000000000000/dd-questionnaire/ingest",
            json=self._completed_body(),
        )
        assert r.status_code == 404

    def test_ingest_malformed_vendor_id_returns_404(self, api_client: TestClient) -> None:
        r = api_client.post(
            "/api/tprm/vendors/not-a-uuid/dd-questionnaire/ingest",
            json=self._completed_body(),
        )
        assert r.status_code == 404

    def test_ingest_empty_questions_returns_400(self, api_client: TestClient) -> None:
        # Unparseable / empty questionnaire content: nothing correlates.
        # F-V08-DAST-3 status normalization: the manual 400 carries the
        # structured object detail (2026-07-06 convergence) — still
        # distinguishable from Pydantic's 422 array.
        vid = self._add_vendor(api_client)
        r = api_client.post(
            f"/api/tprm/vendors/{vid}/dd-questionnaire/ingest",
            json={"questions": []},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "message" in detail

    def test_ingest_wrong_typed_body_returns_422(self, api_client: TestClient) -> None:
        # The body must be a JSON object (the questionnaire document).
        # A top-level non-object (here a JSON array) fails Pydantic
        # auto-validation with array-shape detail (422).
        vid = self._add_vendor(api_client)
        r = api_client.post(
            f"/api/tprm/vendors/{vid}/dd-questionnaire/ingest",
            json=["not", "an", "object"],
        )
        assert r.status_code == 422
        assert isinstance(r.json()["detail"], list)

    def test_ingest_unparseable_object_returns_400(self, api_client: TestClient) -> None:
        # A well-formed JSON object whose `questions` value is not a list
        # correlates to zero responses → structured-detail 400
        # (parse-only; F-V08-DAST-3 status normalization, 2026-07-06
        # convergence), not a Pydantic 422.
        vid = self._add_vendor(api_client)
        r = api_client.post(
            f"/api/tprm/vendors/{vid}/dd-questionnaire/ingest",
            json={"questions": "not-a-list"},
        )
        assert r.status_code == 400
        detail = r.json()["detail"]
        assert detail["error"] == "invalid_body"
        assert "message" in detail

    def test_ingest_open_under_readonly_policy(self, tprm_readonly_client: TestClient) -> None:
        # Parse-only is a READ-style operation: it no longer requires the
        # ``write`` role. Under a deny-by-default reader policy the ingest
        # is OPEN (200), matching the other read endpoints on this router.
        from datetime import date

        from evidentia_core.models.tprm import Vendor
        from evidentia_core.vendor_store import save_vendor

        vendor = Vendor(
            name="Reader Co",
            type="saas",  # type: ignore[arg-type]
            criticality_tier="high",  # type: ignore[arg-type]
            relationship_owner="allen@allenfbyrd.com",
            contract_start_date=date(2025, 1, 1),
        )
        save_vendor(vendor)
        r = tprm_readonly_client.post(
            f"/api/tprm/vendors/{vendor.id}/dd-questionnaire/ingest",
            json=self._completed_body(),
        )
        assert r.status_code == 200, r.text
        assert r.json()["vendor"]["id"] == vendor.id


# ── OpenAPI error-status documentation (2026-07-06 convergence) ─────


def test_tprm_error_statuses_documented_in_openapi(
    api_client: TestClient,
) -> None:
    """Every status the tprm router deliberately raises is documented
    on the operation's ``responses`` (schemathesis undocumented-status
    noise → contract; companion to the ai_gov openapi test)."""
    schema = api_client.get("/api/openapi.json").json()
    expected: list[tuple[str, str, list[str]]] = [
        ("/api/tprm/vendors", "get", ["400"]),
        ("/api/tprm/vendors", "post", ["422"]),
        ("/api/tprm/vendors/{vendor_id}", "get", ["404"]),
        ("/api/tprm/vendors/{vendor_id}", "put", ["404"]),
        ("/api/tprm/vendors/{vendor_id}", "delete", ["404"]),
        (
            "/api/tprm/vendors/{vendor_id}/next-review-due",
            "get",
            ["404"],
        ),
        ("/api/tprm/concentration", "get", ["400"]),
        (
            "/api/tprm/vendors/{vendor_id}/dd-questionnaire",
            "post",
            ["400", "404", "501"],
        ),
        (
            "/api/tprm/vendors/{vendor_id}/dd-questionnaire/ingest",
            "post",
            ["400", "404"],
        ),
    ]
    for path, method, statuses in expected:
        op = schema["paths"][path][method]
        for status in statuses:
            assert status in op["responses"], f"{method.upper()} {path} missing documented {status}"
