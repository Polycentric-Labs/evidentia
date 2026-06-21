"""TestClient coverage for /api/catalog/* management endpoints (v0.10.12).

Surfaces the catalog management CLI verbs (crosswalk / where / license-info
/ import / remove) over HTTP. This is the WRITE/management surface — it is
distinct from the read-only ``frameworks`` browse router, which already
exists under ``/api/frameworks``.

Hermetic: a LOCAL ``FastAPI()`` app includes ONLY the catalog router under
``prefix="/api"`` (the router is NOT registered in
``evidentia_api.app.create_app``, so the project-wide ``api_client``
fixture cannot be reused). The user catalog directory is isolated to
``tmp_path`` via ``EVIDENTIA_CATALOG_DIR`` so imports/removes never leak
across tests or touch the real user-data dir. Bundled catalogs +
crosswalks are read-only and shared.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from evidentia_core.rbac import RBACPolicy, Role
from fastapi import FastAPI
from fastapi.testclient import TestClient

# A small, valid Evidentia-format control catalog used for import tests.
_SAMPLE_CATALOG: dict[str, object] = {
    "framework_id": "acme-internal",
    "framework_name": "ACME Internal Controls",
    "version": "1.0",
    "category": "control",
    "controls": [
        {
            "id": "AC-1",
            "title": "Access policy",
            "description": "Maintain a documented access policy.",
            "family": "Access Control",
        }
    ],
}


@pytest.fixture
def cat_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    """A TestClient over a local app holding ONLY the catalog router.

    The user catalog dir is redirected to an isolated tmp subdirectory so
    imported catalogs never touch the developer's real user-data dir or
    leak across tests.
    """
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path / "user-catalogs"))
    from evidentia_api.routers import catalog as catalog_router

    app = FastAPI()
    app.include_router(catalog_router.router, prefix="/api")
    with TestClient(app) as client:
        yield client


@pytest.fixture
def cat_readonly_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[TestClient]:
    """A catalog TestClient under a restrictive read-only RBAC policy.

    Identical user-dir isolation to ``cat_client``, but installs a
    deny-by-default policy whose ``default_role`` is ``reader``. An
    anonymous request (identity None) resolves to that role, so reads
    pass while ``require_role("write")`` / ``require_role("admin")`` gates
    deny — proving those gates actually bite (they are inert under the
    permissive DEFAULT_POLICY the other tests run with).
    """
    monkeypatch.setenv("EVIDENTIA_CATALOG_DIR", str(tmp_path / "user-catalogs"))
    from evidentia_api.routers import catalog as catalog_router

    app = FastAPI()
    app.include_router(catalog_router.router, prefix="/api")
    app.state.rbac_policy = RBACPolicy(identities={}, default_role=Role.READER)
    with TestClient(app) as client:
        yield client


def _import_payload(
    framework_id: str = "acme-internal",
    license_terms: str | None = "Internal use only.",
) -> dict[str, object]:
    catalog = {**_SAMPLE_CATALOG, "framework_id": framework_id}
    payload: dict[str, object] = {
        "framework_id": framework_id,
        "content": json.dumps(catalog),
        "format": "json",
    }
    if license_terms is not None:
        payload["license_terms"] = license_terms
    return payload


# ════════════════════════════════════════════════════════════════════
# where
# ════════════════════════════════════════════════════════════════════


class TestWhere:
    def test_bundled_framework_resolves(self, cat_client: TestClient) -> None:
        r = cat_client.get("/api/catalog/where?framework_id=nist-csf-2.0")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["framework_id"] == "nist-csf-2.0"
        assert body["source"] == "bundled"
        assert body["path"]
        assert body["shadowed"] is False

    def test_unknown_framework_returns_404(self, cat_client: TestClient) -> None:
        r = cat_client.get("/api/catalog/where?framework_id=does-not-exist")
        assert r.status_code == 404, r.text

    def test_imported_framework_resolves_from_user(
        self, cat_client: TestClient
    ) -> None:
        cat_client.post("/api/catalog/import", json=_import_payload())
        r = cat_client.get("/api/catalog/where?framework_id=acme-internal")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["source"] == "user"


# ════════════════════════════════════════════════════════════════════
# license-info
# ════════════════════════════════════════════════════════════════════


class TestLicenseInfo:
    def test_known_bundled_framework(self, cat_client: TestClient) -> None:
        r = cat_client.get("/api/catalog/license-info/nist-csf-2.0")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["framework_id"] == "nist-csf-2.0"
        assert "tier" in body
        assert "license_required" in body
        assert "placeholder" in body

    def test_unknown_framework_returns_404(self, cat_client: TestClient) -> None:
        r = cat_client.get("/api/catalog/license-info/does-not-exist")
        assert r.status_code == 404, r.text

    def test_imported_framework_license(self, cat_client: TestClient) -> None:
        cat_client.post("/api/catalog/import", json=_import_payload())
        r = cat_client.get("/api/catalog/license-info/acme-internal")
        assert r.status_code == 200, r.text
        assert r.json()["license"] == "Internal use only."


# ════════════════════════════════════════════════════════════════════
# crosswalk
# ════════════════════════════════════════════════════════════════════


class TestCrosswalk:
    def test_returns_mappings_for_known_pair(
        self, cat_client: TestClient
    ) -> None:
        # GV.OC-01 in nist-csf-2.0 maps to AC-1 in nist-800-53-mod
        # (bundled crosswalk nist-csf-2.0_to_nist-800-53-mod.json).
        r = cat_client.get(
            "/api/catalog/crosswalk"
            "?source=nist-csf-2.0&target=nist-800-53-mod&control=GV.OC-01"
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["source"] == "nist-csf-2.0"
        assert body["target"] == "nist-800-53-mod"
        assert body["control"] == "GV.OC-01"
        assert body["total"] >= 1
        target_ids = {m["target_control_id"] for m in body["mappings"]}
        assert "AC-1" in target_ids

    def test_no_mappings_returns_empty_envelope(
        self, cat_client: TestClient
    ) -> None:
        r = cat_client.get(
            "/api/catalog/crosswalk"
            "?source=nist-csf-2.0&target=nist-800-53-mod"
            "&control=ZZ.NO-99"
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["total"] == 0
        assert body["mappings"] == []


# ════════════════════════════════════════════════════════════════════
# import
# ════════════════════════════════════════════════════════════════════


class TestImport:
    def test_import_then_listed_in_where(self, cat_client: TestClient) -> None:
        r = cat_client.post("/api/catalog/import", json=_import_payload())
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["framework_id"] == "acme-internal"
        assert body["source"] == "user"
        # confirm it now resolves from the user dir
        w = cat_client.get("/api/catalog/where?framework_id=acme-internal")
        assert w.json()["source"] == "user"

    def test_duplicate_import_without_force_returns_400(
        self, cat_client: TestClient
    ) -> None:
        assert (
            cat_client.post("/api/catalog/import", json=_import_payload()).status_code
            == 201
        )
        r = cat_client.post("/api/catalog/import", json=_import_payload())
        assert r.status_code == 400, r.text

    def test_duplicate_import_with_force_overwrites(
        self, cat_client: TestClient
    ) -> None:
        assert (
            cat_client.post("/api/catalog/import", json=_import_payload()).status_code
            == 201
        )
        payload = {**_import_payload(), "force": True}
        r = cat_client.post("/api/catalog/import", json=payload)
        assert r.status_code == 201, r.text

    def test_malformed_content_returns_400(self, cat_client: TestClient) -> None:
        payload = {
            "framework_id": "acme-internal",
            "content": "{ this is not valid json",
            "format": "json",
        }
        r = cat_client.post("/api/catalog/import", json=payload)
        assert r.status_code == 400, r.text

    def test_path_traversal_framework_id_rejected(
        self, cat_client: TestClient
    ) -> None:
        # A framework_id with path separators / .. must never reach the
        # filesystem helper — the router rejects the shape outright.
        payload = {
            "framework_id": "../escape",
            "content": json.dumps(_SAMPLE_CATALOG),
            "format": "json",
        }
        r = cat_client.post("/api/catalog/import", json=payload)
        assert r.status_code == 400, r.text

    def test_content_framework_id_mismatch_uses_path_id(
        self, cat_client: TestClient
    ) -> None:
        # The path/body framework_id is authoritative for where the file
        # lands; a mismatching framework_id inside the content is rewritten.
        catalog = {**_SAMPLE_CATALOG, "framework_id": "something-else"}
        payload = {
            "framework_id": "acme-internal",
            "content": json.dumps(catalog),
            "format": "json",
        }
        r = cat_client.post("/api/catalog/import", json=payload)
        assert r.status_code == 201, r.text
        assert r.json()["framework_id"] == "acme-internal"


# ════════════════════════════════════════════════════════════════════
# remove
# ════════════════════════════════════════════════════════════════════


class TestRemove:
    def test_remove_imported_returns_204(self, cat_client: TestClient) -> None:
        cat_client.post("/api/catalog/import", json=_import_payload())
        r = cat_client.delete("/api/catalog/acme-internal")
        assert r.status_code == 204, r.text
        # gone from the user dir
        w = cat_client.get("/api/catalog/where?framework_id=acme-internal")
        assert w.status_code == 404

    def test_remove_unknown_returns_404(self, cat_client: TestClient) -> None:
        r = cat_client.delete("/api/catalog/never-imported")
        assert r.status_code == 404, r.text

    def test_remove_bundled_returns_404(self, cat_client: TestClient) -> None:
        # A bundled catalog is not user-imported, so it cannot be removed.
        r = cat_client.delete("/api/catalog/nist-csf-2.0")
        assert r.status_code == 404, r.text

    def test_remove_path_traversal_rejected(
        self, cat_client: TestClient
    ) -> None:
        r = cat_client.delete("/api/catalog/..%2Fescape")
        assert r.status_code in (400, 404), r.text


# ════════════════════════════════════════════════════════════════════
# RBAC enforcement (proves the require_role gates bite)
# ════════════════════════════════════════════════════════════════════


class TestCatalogRBAC:
    """Under a read-only policy the write + admin gates must deny.

    The other tests run under the permissive DEFAULT_POLICY, where the
    ``require_role`` gates are inert. These install a deny-by-default
    (read-only) policy and prove a write (import) → 403, an admin DELETE
    (remove) → 403, while a read (where) still returns 200.
    """

    def test_anonymous_import_denied_403(
        self, cat_readonly_client: TestClient
    ) -> None:
        r = cat_readonly_client.post(
            "/api/catalog/import", json=_import_payload()
        )
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_remove_denied_403(
        self, cat_readonly_client: TestClient
    ) -> None:
        r = cat_readonly_client.delete("/api/catalog/acme-internal")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_where_allowed_200(
        self, cat_readonly_client: TestClient
    ) -> None:
        # The read endpoint carries no require_role gate (reads are open),
        # so it returns 200 even under the read-only policy.
        r = cat_readonly_client.get(
            "/api/catalog/where?framework_id=nist-csf-2.0"
        )
        assert r.status_code == 200, r.text
