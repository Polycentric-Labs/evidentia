"""TestClient coverage for /api/evidence/* endpoints (v0.10.12).

Surfaces the v0.9.6 WORM-enforced evidence store (3 CLI verbs:
``evidence save / history / show``) over HTTP. Each test scopes the
evidence store to ``tmp_path`` via ``EVIDENTIA_EVIDENCE_STORE_DIR`` so
no state leaks across tests or into the real user profile.

The evidence router is NOT (yet) registered in ``app.py`` — the
controller integrates it. So these tests build a standalone FastAPI
app that includes the router under the same ``/api`` prefix the other
routers use, keeping the request paths identical to production once it
IS registered.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_api.routers import evidence as evidence_router
from evidentia_core.evidence_store import save_evidence
from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType
from evidentia_core.rbac import RBACPolicy, Role
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Fresh TestClient backed by an isolated tmp evidence store.

    Builds a minimal app that mounts ONLY the evidence router under
    the canonical ``/api`` prefix. The RBAC dependency falls back to
    the permissive DEFAULT_POLICY when ``app.state.rbac_policy`` is
    unset, so anonymous requests pass (mirrors the production default).
    """
    store = tmp_path / "evidence-store"
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(store))
    app = FastAPI()
    app.include_router(
        evidence_router.router, prefix="/api", tags=["evidence"]
    )
    return TestClient(app)


@pytest.fixture
def readonly_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> TestClient:
    """TestClient under a restrictive read-only RBAC policy.

    Sets ``app.state.rbac_policy`` to a deny-by-default policy whose
    ``default_role`` is ``reader`` — so an anonymous request (no
    AuthProvider configured → identity None → ``role_for(None)`` resolves
    to ``default_role``) can READ but NOT write. This proves the
    ``require_role("write")`` gate on ``POST /evidence`` actually bites
    rather than being inert under the permissive DEFAULT_POLICY.
    """
    store = tmp_path / "evidence-store"
    monkeypatch.setenv("EVIDENTIA_EVIDENCE_STORE_DIR", str(store))
    app = FastAPI()
    app.include_router(
        evidence_router.router, prefix="/api", tags=["evidence"]
    )
    app.state.rbac_policy = RBACPolicy(
        identities={}, default_role=Role.READER
    )
    return TestClient(app)


def _make_payload(
    *,
    title: str = "AC-2 account-listing snapshot",
    version: int = 1,
    lineage_id: str | None = None,
    predecessor_id: str | None = None,
) -> dict[str, object]:
    """Minimal valid EvidenceArtifact body."""
    body: dict[str, object] = {
        "title": title,
        "evidence_type": EvidenceType.CONFIGURATION.value,
        "source_system": "okta",
        "collected_by": "collector:okta",
        "content": {"users": 42},
        "version": version,
    }
    if lineage_id is not None:
        body["lineage_id"] = lineage_id
    if predecessor_id is not None:
        body["predecessor_id"] = predecessor_id
    return body


def _make_artifact(title: str = "AC-2 snapshot") -> EvidenceArtifact:
    return EvidenceArtifact(
        title=title,
        evidence_type=EvidenceType.CONFIGURATION,
        source_system="okta",
        collected_by="collector:okta",
        content={"users": 42},
    )


# ── POST /api/evidence ─────────────────────────────────────────────


class TestSaveEvidence:
    def test_save_returns_summary_and_persists(
        self, client: TestClient, tmp_path: Path
    ) -> None:
        r = client.post("/api/evidence", json=_make_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        # Summary shape mirrors the CLI save output, MINUS the on-disk
        # path: the REST surface must not leak the absolute evidence-
        # store path (a different trust boundary than the local CLI).
        assert set(body) == {
            "artifact_id",
            "lineage_id",
            "version",
            "predecessor_id",
        }
        assert "path" not in body
        assert body["version"] == 1
        assert body["predecessor_id"] is None
        # lineage_id defaults to the artifact's own id (chain root).
        assert body["lineage_id"] == body["artifact_id"]
        # Persisted on disk under <store>/<lineage>/v1.json. The path is
        # NOT in the response (by design), so we derive it locally from
        # the store dir + lineage_id + version rather than trusting the
        # API to disclose it.
        out = (
            tmp_path
            / "evidence-store"
            / body["lineage_id"]
            / f"v{body['version']}.json"
        )
        assert out.is_file()
        assert out.name == "v1.json"

    def test_save_new_version_chains(self, client: TestClient) -> None:
        # v1 via the store directly so we control the lineage id.
        v1 = _make_artifact()
        save_evidence(v1)
        v2 = v1.new_version(content={"users": 43})
        r = client.post(
            "/api/evidence",
            json=v2.model_dump(mode="json"),
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["version"] == 2
        assert body["lineage_id"] == v1.id
        assert body["predecessor_id"] == v1.id

    def test_resave_same_version_returns_409_with_next_version(
        self, client: TestClient
    ) -> None:
        artifact = _make_artifact()
        save_evidence(artifact)
        # Re-save the SAME version (same lineage + version=1) → WORM block.
        payload = _make_payload(
            version=1, lineage_id=artifact.effective_lineage_id
        )
        r = client.post("/api/evidence", json=payload)
        assert r.status_code == 409, r.text
        detail = r.json()["detail"]
        # 2026-07-06 error-shape convergence: the WORM 409 carries the
        # structured machine-readable detail (cf. rbac_denied) instead
        # of the ad-hoc ``{detail, next_version}`` shape.
        assert detail["error"] == "worm_violation"
        assert detail["next_version"] == 2
        assert detail["lineage_id"] == artifact.effective_lineage_id
        assert "message" in detail

    def test_save_invalid_lineage_id_returns_404(
        self, client: TestClient
    ) -> None:
        payload = _make_payload(version=2, lineage_id="not-a-uuid")
        r = client.post("/api/evidence", json=payload)
        assert r.status_code == 404, r.text

    def test_save_rejects_unknown_field(self, client: TestClient) -> None:
        payload = _make_payload()
        payload["bogus_field"] = "x"
        r = client.post("/api/evidence", json=payload)
        # EvidentiaModel sets extra="forbid" → 422.
        assert r.status_code == 422, r.text


# ── GET /api/evidence/{lineage_id}/history ─────────────────────────


class TestHistory:
    def test_history_lists_versions_ascending(
        self, client: TestClient
    ) -> None:
        v1 = _make_artifact()
        save_evidence(v1)
        v2 = v1.new_version(content={"users": 43})
        save_evidence(v2)
        r = client.get(f"/api/evidence/{v1.id}/history")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 2
        versions = [item["version"] for item in body["items"]]
        assert versions == [1, 2]

    def test_history_unknown_lineage_returns_empty(
        self, client: TestClient
    ) -> None:
        r = client.get(
            "/api/evidence/00000000-0000-0000-0000-000000000000/history"
        )
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_history_invalid_lineage_returns_404(
        self, client: TestClient
    ) -> None:
        r = client.get("/api/evidence/not-a-uuid/history")
        assert r.status_code == 404


# ── GET /api/evidence/{lineage_id}/versions/{version} ──────────────


class TestShow:
    def test_show_returns_version(self, client: TestClient) -> None:
        artifact = _make_artifact()
        save_evidence(artifact)
        r = client.get(f"/api/evidence/{artifact.id}/versions/1")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["id"] == artifact.id
        assert body["version"] == 1
        assert body["title"] == artifact.title

    def test_show_missing_version_returns_404(
        self, client: TestClient
    ) -> None:
        artifact = _make_artifact()
        save_evidence(artifact)
        r = client.get(f"/api/evidence/{artifact.id}/versions/2")
        assert r.status_code == 404

    def test_show_unknown_lineage_returns_404(
        self, client: TestClient
    ) -> None:
        r = client.get(
            "/api/evidence/00000000-0000-0000-0000-000000000000/versions/1"
        )
        assert r.status_code == 404

    def test_show_invalid_lineage_returns_404(
        self, client: TestClient
    ) -> None:
        r = client.get("/api/evidence/not-a-uuid/versions/1")
        assert r.status_code == 404

    def test_show_version_zero_rejected(self, client: TestClient) -> None:
        artifact = _make_artifact()
        save_evidence(artifact)
        # version path param has ge=1 → 422 for 0.
        r = client.get(f"/api/evidence/{artifact.id}/versions/0")
        assert r.status_code == 422


# ── RBAC enforcement (proves the require_role gates bite) ──────────


class TestEvidenceRBAC:
    """Under a restrictive read-only policy the write gate must deny.

    The default permissive DEFAULT_POLICY lets every anonymous request
    through, so the ``require_role("write")`` gate is normally inert in
    the other tests. These tests install a deny-by-default (read-only)
    policy and prove the gate actually returns 403 on a write while
    reads still succeed.
    """

    def test_anonymous_write_denied_403(
        self, readonly_client: TestClient
    ) -> None:
        # POST /evidence is gated on require_role("write"); anonymous
        # identity resolves to the reader default_role → denied.
        r = readonly_client.post("/api/evidence", json=_make_payload())
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_read_allowed_200(
        self, readonly_client: TestClient
    ) -> None:
        # The read gate (require_role("read")) is satisfied by the reader
        # default_role, so a history GET still returns 200 — proving the
        # policy is read-allowed, not blanket-deny.
        artifact = _make_artifact()
        save_evidence(artifact)
        r = readonly_client.get(f"/api/evidence/{artifact.id}/history")
        assert r.status_code == 200, r.text
        assert r.json()["total"] == 1
