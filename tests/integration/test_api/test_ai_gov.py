"""Integration tests for /api/ai-gov/* (v0.9.3 P2.5; v0.10.12 mutation verbs)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

import pytest
from fastapi.testclient import TestClient

# A well-formed-but-absent UUID (v4 shape) reused across not-found cases.
_UNKNOWN_UUID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture(autouse=True)
def isolated_registry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Per-test isolated AI registry; matches CLI test fixture."""
    registry_dir = tmp_path / "ai_registry"
    monkeypatch.setenv("EVIDENTIA_AI_REGISTRY_DIR", str(registry_dir))
    return registry_dir


@pytest.fixture
def ai_gov_readonly_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    """A TestClient over a local app holding ONLY the ai_gov router
    under a deny-by-default (read-only) RBAC policy.

    Mirrors ``gov_readonly_client`` in test_governance_router.py: an
    anonymous request (identity None) resolves to ``Role.READER``, so
    reads pass while ``require_role("write")`` gates deny — proving
    those gates actually bite (they are inert under the permissive
    DEFAULT_POLICY the other tests run with). The registry store is
    isolated to tmp_path via the autouse ``isolated_registry`` fixture.
    """
    from evidentia_api.routers import ai_gov as ai_gov_router
    from evidentia_core.rbac import RBACPolicy, Role
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(ai_gov_router.router, prefix="/api")
    app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.READER)
    with TestClient(app) as client:
        yield client


def _register_system(
    client: TestClient,
    *,
    name: str = "resume-screener",
    annex_iii_domain: str = "employment",
    provider: str = "acme-ai",
    owner: str = "hr-team",
    deployment_status: str = "pilot",
) -> str:
    """Register a system via the API and return its system_id."""
    resp = client.post(
        "/api/ai-gov/register",
        json={
            "descriptor": {
                "name": name,
                "purpose": "Score job applicants",
                "annex_iii_domain": annex_iii_domain,
            },
            "provider": provider,
            "owner": owner,
            "deployment_status": deployment_status,
        },
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["system_id"]


class TestClassify:
    def test_classify_returns_high_for_annex_iii(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/ai-gov/classify",
            json={
                "name": "resume-screener",
                "purpose": "Score job applicants",
                "annex_iii_domain": "employment",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["eu_ai_act_tier"] == "high"

    def test_classify_returns_minimal_for_default(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/ai-gov/classify",
            json={"name": "spam-filter", "purpose": "Internal spam"},
        )
        assert resp.status_code == 200
        assert resp.json()["eu_ai_act_tier"] == "minimal"


class TestRegisterListGetDelete:
    def test_full_lifecycle(self, api_client: TestClient) -> None:
        # Register
        register = api_client.post(
            "/api/ai-gov/register",
            json={
                "descriptor": {
                    "name": "resume-screener",
                    "purpose": "Score job applicants",
                    "annex_iii_domain": "employment",
                },
                "provider": "acme-ai",
                "owner": "hr-team",
                "deployment_status": "pilot",
            },
        )
        assert register.status_code == 200
        system_id = register.json()["system_id"]

        # List
        listed = api_client.get("/api/ai-gov/systems")
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        # Get
        got = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert got.status_code == 200
        assert got.json()["descriptor"]["name"] == "resume-screener"

        # Delete
        deleted = api_client.delete(f"/api/ai-gov/systems/{system_id}")
        assert deleted.status_code == 200
        assert deleted.json()["removed"] is True

        # Get after delete → 404
        gone = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert gone.status_code == 404

    def test_list_with_tier_filter(self, api_client: TestClient) -> None:
        api_client.post(
            "/api/ai-gov/register",
            json={
                "descriptor": {
                    "name": "high-risk",
                    "purpose": "x",
                    "annex_iii_domain": "employment",
                },
                "provider": "p",
                "owner": "o",
            },
        )
        api_client.post(
            "/api/ai-gov/register",
            json={
                "descriptor": {"name": "minimal", "purpose": "x"},
                "provider": "p",
                "owner": "o",
            },
        )

        high = api_client.get("/api/ai-gov/systems?tier=high")
        assert high.status_code == 200
        assert len(high.json()) == 1

        minimal = api_client.get("/api/ai-gov/systems?tier=minimal")
        assert minimal.status_code == 200
        assert len(minimal.json()) == 1

    def test_unknown_tier_returns_structured_400(
        self, api_client: TestClient
    ) -> None:
        """2026-07-06 DAST (schemathesis) follow-up: the unknown-tier
        400 must carry the structured ``detail`` shape the API uses
        for machine-readable errors (cf. ``rbac_denied``), not a bare
        string."""
        resp = api_client.get("/api/ai-gov/systems?tier=bogus")
        assert resp.status_code == 400
        detail = resp.json()["detail"]
        assert detail["error"] == "unknown_tier"
        assert detail["tier"] == "bogus"
        assert detail["valid"] == [
            "unacceptable",
            "high",
            "limited",
            "minimal",
        ]
        assert "message" in detail

    def test_unknown_tier_400_documented_in_openapi(
        self, api_client: TestClient
    ) -> None:
        """Companion to the structured-400 test: schemathesis also
        flagged the 400 as undocumented (missing from the operation's
        ``responses``)."""
        schema = api_client.get("/api/openapi.json").json()
        op = schema["paths"]["/api/ai-gov/systems"]["get"]
        assert "400" in op["responses"]

    def test_invalid_uuid_returns_400(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get("/api/ai-gov/systems/not-a-uuid")
        assert resp.status_code == 400
        assert resp.json()["detail"]["error"] == "invalid_id"

    def test_unknown_uuid_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.get(
            "/api/ai-gov/systems/11111111-1111-4111-8111-111111111111"
        )
        assert resp.status_code == 404
        detail = resp.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "ai_system"

    def test_delete_unknown_id_is_idempotent(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.delete(
            "/api/ai-gov/systems/11111111-1111-4111-8111-111111111111"
        )
        assert resp.status_code == 200
        assert resp.json()["removed"] is False


# ── v0.9.4 P1.3: rate-limit + idempotency on register ───────────────


class TestIdempotency:
    """v0.9.4 P1.3 closes F-V93-S10 LOW (register has no duplicate-
    name detection). X-Idempotency-Key header lets clients retry
    safely without creating duplicates."""

    _SAMPLE_BODY: ClassVar[dict] = {
        "descriptor": {
            "name": "resume-screener",
            "purpose": "Score job applicants",
            "annex_iii_domain": "employment",
        },
        "provider": "acme-ai",
        "owner": "hr-team",
    }

    def test_same_key_same_body_returns_prior_system_id(
        self, api_client: TestClient
    ) -> None:
        """Idempotent replay: identical key + body returns the
        original system_id and the entry is NOT duplicated."""
        first = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "test-key-1"},
        )
        assert first.status_code == 200
        first_id = first.json()["system_id"]
        assert first.json().get("idempotent_replay") is not True

        second = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "test-key-1"},
        )
        assert second.status_code == 200
        assert second.json()["system_id"] == first_id
        assert second.json()["idempotent_replay"] is True

        # Confirm no duplicate created.
        listing = api_client.get("/api/ai-gov/systems")
        assert listing.status_code == 200
        assert len(listing.json()) == 1

    def test_same_key_different_body_returns_409(
        self, api_client: TestClient
    ) -> None:
        """Same key + different body = 409 Conflict (operator error
        signal). Prevents key-reuse bugs from silently creating
        wrong-data entries."""
        first = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "test-key-2"},
        )
        assert first.status_code == 200

        different_body = {
            **self._SAMPLE_BODY,
            "owner": "different-team",
        }
        second = api_client.post(
            "/api/ai-gov/register",
            json=different_body,
            headers={"X-Idempotency-Key": "test-key-2"},
        )
        assert second.status_code == 409
        detail = second.json()["detail"]
        assert detail["error"] == "idempotency_key_conflict"
        assert "test-key-2" in detail["message"]

    def test_no_key_creates_fresh_entry_each_call(
        self, api_client: TestClient
    ) -> None:
        """Without X-Idempotency-Key, repeated POSTs create separate
        entries (legacy v0.9.3 behavior preserved)."""
        first = api_client.post(
            "/api/ai-gov/register", json=self._SAMPLE_BODY
        )
        second = api_client.post(
            "/api/ai-gov/register", json=self._SAMPLE_BODY
        )
        assert first.status_code == 200
        assert second.status_code == 200
        assert first.json()["system_id"] != second.json()["system_id"]

    def test_register_replay_after_delete_returns_null_entry(
        self, api_client: TestClient
    ) -> None:
        """v0.9.5 F-V94-Q2 regression test: idempotency replay after
        the target system_id has been deleted returns the original
        ``system_id`` with ``entry: null`` (not a 500, not a re-
        create). Documents the "same key = same result, even after
        backing entry deletion" guarantee from the docstring."""
        # First register with idempotency key.
        first = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "replay-after-delete-key"},
        )
        assert first.status_code == 200
        system_id = first.json()["system_id"]
        assert first.json()["entry"] is not None

        # Delete the target.
        del_resp = api_client.delete(f"/api/ai-gov/systems/{system_id}")
        assert del_resp.status_code == 200

        # Replay with the same key + same body.
        replay = api_client.post(
            "/api/ai-gov/register",
            json=self._SAMPLE_BODY,
            headers={"X-Idempotency-Key": "replay-after-delete-key"},
        )
        # Returns 200 with the prior system_id, entry: null, idempotent_replay: True.
        assert replay.status_code == 200
        replay_body = replay.json()
        assert replay_body["system_id"] == system_id
        assert replay_body["entry"] is None
        assert replay_body.get("idempotent_replay") is True


class TestRateLimit:
    """v0.9.4 P1.3 — token-bucket rate limit on POST /classify +
    POST /register. Default burst=10 + 60/min. Tests rely on TestClient
    setting a stable client.host (per Starlette's TestClient default,
    requests appear from 'testclient')."""

    _SAMPLE_CLASSIFY_BODY: ClassVar[dict] = {
        "name": "spam-filter",
        "purpose": "Internal spam",
    }

    def test_burst_then_throttle(self, api_client: TestClient) -> None:
        """Burst capacity of 10 → 10 succeed, 11th returns 429."""
        # First 10 should all succeed (burst).
        for i in range(10):
            resp = api_client.post(
                "/api/ai-gov/classify",
                json={
                    "name": f"item-{i}",
                    "purpose": "test",
                },
            )
            assert resp.status_code == 200, (
                f"burst {i} should be allowed but got {resp.status_code}"
            )
        # 11th hits empty bucket → 429.
        resp = api_client.post(
            "/api/ai-gov/classify", json=self._SAMPLE_CLASSIFY_BODY
        )
        assert resp.status_code == 429
        detail = resp.json()["detail"]
        assert detail["error"] == "rate_limited"
        assert "Rate limit" in detail["message"]
        assert resp.headers.get("Retry-After") == "5"

    def test_get_endpoints_not_rate_limited(
        self, api_client: TestClient
    ) -> None:
        """GET endpoints (list/show) aren't on the allowlist —
        many calls in a row all succeed."""
        for _ in range(50):
            resp = api_client.get("/api/ai-gov/systems")
            assert resp.status_code == 200


# ── v0.10.12: mutation verbs (update / retire / categorize-fips /
#    set-omb-impact) — REST parity with the CLI ai-gov verbs ──────────


class TestUpdateSystem:
    """PUT /ai-gov/systems/{system_id} — partial update of a registration."""

    def test_update_mutates_and_persists(self, api_client: TestClient) -> None:
        system_id = _register_system(api_client)
        resp = api_client.put(
            f"/api/ai-gov/systems/{system_id}",
            json={"owner": "new-owner", "deployment_status": "production"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["entry"]["owner"] == "new-owner"
        assert body["entry"]["deployment_status"] == "production"
        # Untouched fields preserved.
        assert body["entry"]["provider"] == "acme-ai"

        # Persisted: a fresh GET reflects the change.
        got = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert got.status_code == 200
        assert got.json()["owner"] == "new-owner"
        assert got.json()["deployment_status"] == "production"

    def test_update_unknown_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.put(
            f"/api/ai-gov/systems/{_UNKNOWN_UUID}",
            json={"owner": "x"},
        )
        assert resp.status_code == 404

    def test_update_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.put(
            "/api/ai-gov/systems/not-a-uuid",
            json={"owner": "x"},
        )
        assert resp.status_code == 404

    def test_update_no_fields_returns_400(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.put(f"/api/ai-gov/systems/{system_id}", json={})
        assert resp.status_code == 400

    def test_update_bad_deployment_status_returns_422(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.put(
            f"/api/ai-gov/systems/{system_id}",
            json={"deployment_status": "bogus"},
        )
        assert resp.status_code == 422


class TestRetireSystem:
    """POST /ai-gov/systems/{system_id}/retire — lifecycle retirement."""

    def test_retire_mutates_and_persists(self, api_client: TestClient) -> None:
        system_id = _register_system(api_client, deployment_status="pilot")
        resp = api_client.post(f"/api/ai-gov/systems/{system_id}/retire")
        assert resp.status_code == 200, resp.text
        assert resp.json()["entry"]["deployment_status"] == "retired"

        # Persisted — and the entry is preserved (not deleted).
        got = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert got.status_code == 200
        assert got.json()["deployment_status"] == "retired"

    def test_retire_already_retired_is_idempotent(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client, deployment_status="pilot")
        first = api_client.post(f"/api/ai-gov/systems/{system_id}/retire")
        assert first.status_code == 200
        second = api_client.post(f"/api/ai-gov/systems/{system_id}/retire")
        assert second.status_code == 200
        assert second.json()["entry"]["deployment_status"] == "retired"

    def test_retire_unknown_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(f"/api/ai-gov/systems/{_UNKNOWN_UUID}/retire")
        assert resp.status_code == 404

    def test_retire_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post("/api/ai-gov/systems/not-a-uuid/retire")
        assert resp.status_code == 404


class TestCategorizeFips:
    """POST /ai-gov/systems/{system_id}/categorize-fips — FIPS 199."""

    def test_categorize_mutates_and_persists(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/categorize-fips",
            json={
                "confidentiality": "moderate",
                "integrity": "high",
                "availability": "low",
            },
        )
        assert resp.status_code == 200, resp.text
        cat = resp.json()["entry"]["fips_199_categorization"]
        assert cat["confidentiality_impact"] == "moderate"
        assert cat["integrity_impact"] == "high"
        assert cat["availability_impact"] == "low"
        # high-water-mark auto-computed.
        assert cat["overall"] == "high"

        # Persisted.
        got = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert got.json()["fips_199_categorization"]["overall"] == "high"

    def test_categorize_unknown_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            f"/api/ai-gov/systems/{_UNKNOWN_UUID}/categorize-fips",
            json={
                "confidentiality": "low",
                "integrity": "low",
                "availability": "low",
            },
        )
        assert resp.status_code == 404

    def test_categorize_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/ai-gov/systems/not-a-uuid/categorize-fips",
            json={
                "confidentiality": "low",
                "integrity": "low",
                "availability": "low",
            },
        )
        assert resp.status_code == 404

    def test_categorize_bad_impact_value_returns_422(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/categorize-fips",
            json={
                "confidentiality": "bogus",
                "integrity": "low",
                "availability": "low",
            },
        )
        assert resp.status_code == 422

    def test_categorize_high_water_mark_mismatch_returns_400(
        self, api_client: TestClient
    ) -> None:
        # overall=low while integrity=high is a paperwork error the
        # core validator rejects → domain error normalizes to 400.
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/categorize-fips",
            json={
                "confidentiality": "low",
                "integrity": "high",
                "availability": "low",
                "overall": "low",
            },
        )
        assert resp.status_code == 400


class TestSetOmbImpact:
    """POST /ai-gov/systems/{system_id}/set-omb-impact — OMB M-24-10."""

    def test_set_omb_mutates_and_persists(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/set-omb-impact",
            json={"category": "rights_impacting"},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json()["entry"]["omb_impact"] == "rights_impacting"

        # Persisted.
        got = api_client.get(f"/api/ai-gov/systems/{system_id}")
        assert got.json()["omb_impact"] == "rights_impacting"

    def test_set_omb_unknown_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            f"/api/ai-gov/systems/{_UNKNOWN_UUID}/set-omb-impact",
            json={"category": "neither"},
        )
        assert resp.status_code == 404

    def test_set_omb_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/ai-gov/systems/not-a-uuid/set-omb-impact",
            json={"category": "neither"},
        )
        assert resp.status_code == 404

    def test_set_omb_bad_category_returns_422(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/set-omb-impact",
            json={"category": "bogus"},
        )
        assert resp.status_code == 422


class TestSetHighImpact:
    """POST /ai-gov/systems/{system_id}/set-high-impact — OMB M-25-21."""

    def test_set_high_impact_mutates_and_persists(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/set-high-impact",
            json={
                "determination": "high_impact",
                "bases": [
                    "civil_rights_liberties_privacy",
                    "essential_services_access",
                ],
                "rationale": "Adjudicates access to an essential service.",
            },
        )
        assert resp.status_code == 200, resp.text
        hi = resp.json()["entry"]["omb_high_impact"]
        assert hi["determination"] == "high_impact"
        assert "civil_rights_liberties_privacy" in hi["bases"]

        # Persisted + independent of the legacy field.
        got = api_client.get(f"/api/ai-gov/systems/{system_id}").json()
        assert got["omb_high_impact"]["determination"] == "high_impact"
        assert got["omb_impact"] is None

    def test_set_high_impact_unknown_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            f"/api/ai-gov/systems/{_UNKNOWN_UUID}/set-high-impact",
            json={"determination": "not_high_impact"},
        )
        assert resp.status_code == 404

    def test_set_high_impact_invalid_id_returns_404(
        self, api_client: TestClient
    ) -> None:
        resp = api_client.post(
            "/api/ai-gov/systems/not-a-uuid/set-high-impact",
            json={"determination": "not_high_impact"},
        )
        assert resp.status_code == 404

    def test_set_high_impact_bad_determination_returns_422(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/set-high-impact",
            json={"determination": "extremely_high"},
        )
        assert resp.status_code == 422

    def test_set_high_impact_bad_basis_returns_422(
        self, api_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = api_client.post(
            f"/api/ai-gov/systems/{system_id}/set-high-impact",
            json={
                "determination": "high_impact",
                "bases": ["national_pride"],
            },
        )
        assert resp.status_code == 422


# ── v0.10.12: RBAC enforcement (proves the require_role gates bite) ──


class TestAiGovRBAC:
    """Under a read-only policy the write gates on the mutation verbs
    must deny.

    The other tests run under the permissive DEFAULT_POLICY, where the
    ``require_role("write")`` gates are inert. This installs a deny-by-
    default (read-only) policy and proves an anonymous update / retire
    → 403, while a read (show) still resolves through the gate-free
    path. Mirrors ``TestGovernanceRBAC`` in test_governance_router.py.
    """

    def test_anonymous_update_denied_403(
        self, api_client: TestClient, ai_gov_readonly_client: TestClient
    ) -> None:
        # Seed via the permissive full-app client (shares the isolated
        # registry env var), then attempt the write under the read-only
        # policy.
        system_id = _register_system(api_client)
        resp = ai_gov_readonly_client.put(
            f"/api/ai-gov/systems/{system_id}",
            json={"owner": "x"},
        )
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_retire_denied_403(
        self, api_client: TestClient, ai_gov_readonly_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = ai_gov_readonly_client.post(
            f"/api/ai-gov/systems/{system_id}/retire"
        )
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_set_high_impact_denied_403(
        self, api_client: TestClient, ai_gov_readonly_client: TestClient
    ) -> None:
        system_id = _register_system(api_client)
        resp = ai_gov_readonly_client.post(
            f"/api/ai-gov/systems/{system_id}/set-high-impact",
            json={"determination": "high_impact"},
        )
        assert resp.status_code == 403, resp.text
        assert resp.json()["detail"]["error"] == "rbac_denied"
