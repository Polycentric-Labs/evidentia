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
import math
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from evidentia_core.rbac import RBACPolicy, Role
from fastapi import FastAPI, HTTPException
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
def cat_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
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
def cat_readonly_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
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
        # nist-csf-2.0 carries authoritative NIST subcategory text end to end.
        assert body["text_depth"] == "full"

    def test_headings_only_framework_reports_its_depth(self, cat_client: TestClient) -> None:
        # iso-27001-2022 is a Tier C stub: public Annex A numbering and
        # neutral titles only, no statement text.
        r = cat_client.get("/api/catalog/where?framework_id=iso-27001-2022")
        assert r.status_code == 200, r.text
        assert r.json()["text_depth"] == "headings"

    def test_unknown_framework_returns_404(self, cat_client: TestClient) -> None:
        r = cat_client.get("/api/catalog/where?framework_id=does-not-exist")
        assert r.status_code == 404, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "framework"

    def test_imported_framework_resolves_from_user(self, cat_client: TestClient) -> None:
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
        assert body["text_depth"] == "full"

    def test_headings_only_framework_reports_its_depth(self, cat_client: TestClient) -> None:
        r = cat_client.get("/api/catalog/license-info/iso-27001-2022")
        assert r.status_code == 200, r.text
        assert r.json()["text_depth"] == "headings"

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
    def test_returns_mappings_for_known_pair(self, cat_client: TestClient) -> None:
        # GV.OC-01 in nist-csf-2.0 maps to AC-1 in nist-800-53-rev5
        # (bundled crosswalk nist-csf-2.0_to_nist-800-53-rev5.json).
        r = cat_client.get("/api/catalog/crosswalk?source=nist-csf-2.0&target=nist-800-53-rev5&control=GV.OC-01")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["source"] == "nist-csf-2.0"
        assert body["target"] == "nist-800-53-rev5"
        assert body["control"] == "GV.OC-01"
        assert body["total"] >= 1
        target_ids = {m["target_control_id"] for m in body["mappings"]}
        assert "AC-1" in target_ids

    def test_baseline_member_resolves_through_its_family(self, cat_client: TestClient) -> None:
        # The crosswalk is keyed on the full catalog; the moderate baseline is a
        # member of that family, so the same lookup answers for it.
        r = cat_client.get(
            "/api/catalog/crosswalk?source=nist-csf-2.0&target=nist-800-53-rev5-moderate&control=GV.OC-01"
        )
        assert r.status_code == 200, r.text
        assert "AC-1" in {m["target_control_id"] for m in r.json()["mappings"]}

    def test_no_mappings_returns_empty_envelope(self, cat_client: TestClient) -> None:
        r = cat_client.get("/api/catalog/crosswalk?source=nist-csf-2.0&target=nist-800-53-rev5&control=ZZ.NO-99")
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

    def test_duplicate_import_without_force_returns_400(self, cat_client: TestClient) -> None:
        assert cat_client.post("/api/catalog/import", json=_import_payload()).status_code == 201
        r = cat_client.post("/api/catalog/import", json=_import_payload())
        assert r.status_code == 400, r.text
        detail = r.json()["detail"]
        assert detail["error"] == "already_exists"
        assert detail["resource"] == "user_catalog"

    def test_duplicate_import_with_force_overwrites(self, cat_client: TestClient, tmp_path: Path) -> None:
        assert cat_client.post("/api/catalog/import", json=_import_payload()).status_code == 201
        replacement = {**_SAMPLE_CATALOG, "version": "2.0", "framework_name": "Revised ACME Controls"}
        payload = {**_import_payload(), "force": True, "content": json.dumps(replacement)}
        r = cat_client.post("/api/catalog/import", json=payload)
        assert r.status_code == 201, r.text
        persisted = json.loads((tmp_path / "user-catalogs" / "acme-internal.json").read_text(encoding="utf-8"))
        assert persisted == replacement
        metadata = cat_client.get("/api/catalog/license-info/acme-internal")
        assert metadata.status_code == 200, metadata.text
        assert metadata.json()["name"] == "Revised ACME Controls"
        manifest = yaml.safe_load((tmp_path / "user-catalogs" / "frameworks.yaml").read_text(encoding="utf-8"))
        assert manifest["frameworks"][0]["version"] == "2.0"
        assert not list((tmp_path / "user-catalogs").glob(".catalog-import-*"))

    @pytest.mark.parametrize("existing", [False, True])
    @pytest.mark.parametrize("fmt", ["json", "yaml"])
    def test_invalid_catalog_preserves_installed_state(
        self, cat_client: TestClient, tmp_path: Path, existing: bool, fmt: str
    ) -> None:
        user_dir = tmp_path / "user-catalogs"
        catalog_path = user_dir / "acme-internal.json"
        manifest_path = user_dir / "frameworks.yaml"
        if existing:
            assert cat_client.post("/api/catalog/import", json=_import_payload()).status_code == 201
        catalog_before = catalog_path.read_bytes() if existing else None
        manifest_before = manifest_path.read_bytes() if existing else None
        invalid_catalog = {**_SAMPLE_CATALOG, "controls": "not a list"}
        payload = {
            **_import_payload(),
            "content": json.dumps(invalid_catalog) if fmt == "json" else yaml.safe_dump(invalid_catalog),
            "format": fmt,
            "force": existing,
        }

        response = cat_client.post("/api/catalog/import", json=payload)

        assert response.status_code == 400, response.text
        assert response.json()["detail"]["error"] == "invalid_body"
        if existing:
            assert catalog_path.read_bytes() == catalog_before
            assert manifest_path.read_bytes() == manifest_before
            resolved = cat_client.get("/api/catalog/where?framework_id=acme-internal")
            assert resolved.status_code == 200, resolved.text
            assert resolved.json()["source"] == "user"
        else:
            assert not catalog_path.exists()
            assert not manifest_path.exists()
        assert not list(user_dir.glob(".catalog-import-*"))

    @pytest.mark.parametrize("existing", [False, True])
    def test_cleanup_failure_does_not_interrupt_replacement(
        self, cat_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
    ) -> None:
        if existing:
            assert cat_client.post("/api/catalog/import", json=_import_payload()).status_code == 201
        original_rmdir = os.rmdir
        original_unlink = os.unlink
        cleanup_roots: list[Path] = []
        cleanup_manifests: list[bytes] = []
        user_dir = tmp_path / "user-catalogs"
        manifest_path = user_dir / "frameworks.yaml"

        def deny_staging_cleanup(path: str | Path, *, dir_fd: int | None = None) -> None:
            if Path(path).name.startswith(".catalog-import-"):
                cleanup_roots.append(Path(path))
                cleanup_manifests.append(manifest_path.read_bytes())
                raise PermissionError("Synthetic temporary-directory cleanup failure")
            original_rmdir(path, dir_fd=dir_fd)

        def reject_directory_unlink(path: str | Path, *, dir_fd: int | None = None) -> None:
            if Path(path).name.startswith(".catalog-import-"):
                # POSIX reports a directory here, which can trigger recursive cleanup.
                raise IsADirectoryError("Synthetic POSIX directory unlink failure")
            original_unlink(path, dir_fd=dir_fd)

        replacement = {**_SAMPLE_CATALOG, "version": "2.0"}
        payload = {**_import_payload(), "force": existing, "content": json.dumps(replacement)}
        with monkeypatch.context() as patch:
            patch.setattr(os, "rmdir", deny_staging_cleanup)
            patch.setattr(os, "unlink", reject_directory_unlink)
            response = cat_client.post("/api/catalog/import", json=payload)

        assert response.status_code == 201, response.text
        assert cleanup_roots
        assert all(path.parent == user_dir for path in cleanup_roots)
        assert json.loads((user_dir / "acme-internal.json").read_text(encoding="utf-8")) == replacement
        assert all(snapshot == manifest_path.read_bytes() for snapshot in cleanup_manifests)
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        assert manifest["frameworks"][0]["version"] == "2.0"
        assert manifest["frameworks"][0]["license"] == "Internal use only."
        assert manifest["frameworks"][0]["text_depth"] == "full"
        resolved = cat_client.get("/api/catalog/where?framework_id=acme-internal")
        assert resolved.status_code == 200, resolved.text
        assert resolved.json()["source"] == "user"
        assert Path(resolved.json()["path"]) == user_dir / "acme-internal.json"
        assert resolved.json()["text_depth"] == "full"

    @pytest.mark.parametrize("existing", [False, True])
    def test_cleanup_failure_does_not_hide_validation_error(
        self, cat_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: bool
    ) -> None:
        if existing:
            assert cat_client.post("/api/catalog/import", json=_import_payload()).status_code == 201
        user_dir = tmp_path / "user-catalogs"
        catalog_path = user_dir / "acme-internal.json"
        manifest_path = user_dir / "frameworks.yaml"
        catalog_before = catalog_path.read_bytes() if existing else None
        manifest_before = manifest_path.read_bytes() if existing else None
        original_rmdir = os.rmdir
        original_unlink = os.unlink
        cleanup_roots: list[Path] = []

        def deny_staging_cleanup(path: str | Path, *, dir_fd: int | None = None) -> None:
            if Path(path).name.startswith(".catalog-import-"):
                cleanup_roots.append(Path(path))
                raise PermissionError("Synthetic temporary-directory cleanup failure")
            original_rmdir(path, dir_fd=dir_fd)

        def reject_directory_unlink(path: str | Path, *, dir_fd: int | None = None) -> None:
            if Path(path).name.startswith(".catalog-import-"):
                raise IsADirectoryError("Synthetic POSIX directory unlink failure")
            original_unlink(path, dir_fd=dir_fd)

        invalid_catalog = {**_SAMPLE_CATALOG, "controls": "not a list"}
        payload = {**_import_payload(), "force": existing, "content": json.dumps(invalid_catalog)}
        with monkeypatch.context() as patch:
            patch.setattr(os, "rmdir", deny_staging_cleanup)
            patch.setattr(os, "unlink", reject_directory_unlink)
            response = cat_client.post("/api/catalog/import", json=payload)

        assert response.status_code == 400, response.text
        assert response.json()["detail"]["error"] == "invalid_body"
        assert cleanup_roots
        assert all(path.parent == user_dir for path in cleanup_roots)
        assert (catalog_path.read_bytes() if catalog_path.exists() else None) == catalog_before
        assert (manifest_path.read_bytes() if manifest_path.exists() else None) == manifest_before

    def test_malformed_content_returns_400(self, cat_client: TestClient) -> None:
        payload = {
            "framework_id": "acme-internal",
            "content": "{ this is not valid json",
            "format": "json",
        }
        r = cat_client.post("/api/catalog/import", json=payload)
        assert r.status_code == 400, r.text

    @pytest.mark.parametrize(
        "framework_id", ["../escape", "..\\escape", "/escape", "C:\\escape", "nested/name", "nested\\name", "name\n"]
    )
    def test_path_traversal_framework_id_rejected(self, cat_client: TestClient, framework_id: str) -> None:
        # A framework_id with path separators / .. must never reach the
        # filesystem helper — the router rejects the shape outright.
        payload = {
            "framework_id": framework_id,
            "content": json.dumps(_SAMPLE_CATALOG),
            "format": "json",
        }
        r = cat_client.post("/api/catalog/import", json=payload)
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "invalid_id"

    @pytest.mark.parametrize("basename", ["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"])
    @pytest.mark.parametrize("suffix", ["", ".controls"])
    def test_device_framework_id_rejected_without_filesystem_access(self, basename: str, suffix: str) -> None:
        from evidentia_api.routers.catalog import _validate_framework_id

        with pytest.raises(HTTPException) as error:
            _validate_framework_id(basename + suffix)

        assert error.value.status_code == 400
        assert error.value.detail["error"] == "invalid_id"

    @pytest.mark.parametrize(
        "framework_id", ["console", "con-controls", "con_controls", "auxiliary", "com10", "lpt10", "x.con", "x.nul"]
    )
    def test_device_name_lookalikes_remain_valid(self, framework_id: str) -> None:
        from evidentia_api.routers.catalog import _validate_framework_id

        assert _validate_framework_id(framework_id) == framework_id

    def test_bundled_framework_ids_remain_valid(self) -> None:
        from evidentia_api.routers.catalog import _validate_framework_id
        from evidentia_core.catalogs.manifest import load_manifest

        manifest = load_manifest()
        assert manifest.frameworks
        for entry in manifest.frameworks:
            assert _validate_framework_id(entry.id) == entry.id

    @pytest.mark.parametrize("outside_directory", ["user-catalogs-sibling", "outside"])
    def test_resolved_destination_escape_preserves_existing_files(
        self, cat_client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outside_directory: str
    ) -> None:
        from evidentia_api.routers import catalog as catalog_router

        assert cat_client.post("/api/catalog/import", json=_import_payload()).status_code == 201
        user_dir = tmp_path / "user-catalogs"
        catalog_path = user_dir / "acme-internal.json"
        manifest_path = user_dir / "frameworks.yaml"
        catalog_before = catalog_path.read_bytes()
        manifest_before = manifest_path.read_bytes()
        outside_path = tmp_path / outside_directory / "acme-internal.json"
        outside_path.parent.mkdir()
        outside_path.write_bytes(b"Unrelated catalog bytes")
        original_realpath = os.path.realpath

        def resolve_candidate_outside(path: str | Path, *, strict: bool = False) -> str:
            if Path(path) == catalog_path:
                # Model the canonical target of an existing link without platform privileges.
                return str(outside_path)
            return original_realpath(path, strict=strict)

        with monkeypatch.context() as patch:
            patch.setattr(catalog_router.os.path, "realpath", resolve_candidate_outside)
            response = cat_client.post("/api/catalog/import", json={**_import_payload(), "force": True})

        assert response.status_code == 400, response.text
        assert response.json()["detail"]["error"] == "invalid_id"
        assert outside_path.read_bytes() == b"Unrelated catalog bytes"
        assert catalog_path.read_bytes() == catalog_before
        assert manifest_path.read_bytes() == manifest_before
        assert not list(user_dir.glob(".catalog-import-*"))

    def test_import_sets_text_depth_on_manifest_entry(self, cat_client: TestClient) -> None:
        # _SAMPLE_CATALOG's one control carries a real description, distinct
        # from its title, so the imported entry derives to "full".
        r = cat_client.post("/api/catalog/import", json=_import_payload())
        assert r.status_code == 201, r.text
        w = cat_client.get("/api/catalog/where?framework_id=acme-internal")
        assert w.status_code == 200, w.text
        text_depth = w.json()["text_depth"]
        assert isinstance(text_depth, str)
        assert text_depth == "full"

    def test_content_framework_id_mismatch_uses_path_id(self, cat_client: TestClient) -> None:
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
        detail = r.json()["detail"]
        assert detail["error"] == "not_found"
        assert detail["resource"] == "user_catalog"

    def test_remove_bundled_returns_404(self, cat_client: TestClient) -> None:
        # A bundled catalog is not user-imported, so it cannot be removed.
        r = cat_client.delete("/api/catalog/nist-csf-2.0")
        assert r.status_code == 404, r.text

    def test_remove_path_traversal_rejected(self, cat_client: TestClient) -> None:
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

    def test_anonymous_import_denied_403(self, cat_readonly_client: TestClient) -> None:
        r = cat_readonly_client.post("/api/catalog/import", json=_import_payload())
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_remove_denied_403(self, cat_readonly_client: TestClient) -> None:
        r = cat_readonly_client.delete("/api/catalog/acme-internal")
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "rbac_denied"

    def test_anonymous_where_allowed_200(self, cat_readonly_client: TestClient) -> None:
        # The read endpoint carries no require_role gate (reads are open),
        # so it returns 200 even under the read-only policy.
        r = cat_readonly_client.get("/api/catalog/where?framework_id=nist-csf-2.0")
        assert r.status_code == 200, r.text


# ════════════════════════════════════════════════════════════════════
# OpenAPI error documentation (2026-07-06 error-shape convergence)
# ════════════════════════════════════════════════════════════════════


class TestCatalogOpenApiErrorDocs:
    """Every deliberate 4xx the catalog router raises is documented on
    its OpenAPI operation. Uses the project-wide app so the schema
    reflects the registered router."""

    def test_catalog_error_statuses_documented_in_openapi(self, api_client: TestClient) -> None:
        schema = api_client.get("/api/openapi.json").json()
        expected: list[tuple[str, str, list[str]]] = [
            ("/api/catalog/where", "get", ["400", "404"]),
            (
                "/api/catalog/license-info/{framework_id}",
                "get",
                ["400", "404"],
            ),
            ("/api/catalog/import", "post", ["400", "403"]),
            (
                "/api/catalog/{framework_id}",
                "delete",
                ["400", "403", "404"],
            ),
        ]
        for path, method, statuses in expected:
            responses = schema["paths"][path][method]["responses"]
            for status in statuses:
                assert status in responses, f"{method.upper()} {path} missing {status}"


def test_import_preserves_currency_in_where_and_license_info(cat_client: TestClient) -> None:
    data = {
        **_SAMPLE_CATALOG,
        "status": "retired",
        "notes": "Use the successor catalog.",
        "verified_on": "2026-09-09",
        "superseded_by": "acme-next",
        "source": "https://example.org/source",
        "license_url": "https://example.org/license",
        "license_required": True,
    }
    payload = {"framework_id": "acme-internal", "content": json.dumps(data), "tier": "C"}
    response = cat_client.post("/api/catalog/import", json=payload)
    assert response.status_code == 201, response.text
    for url in ("/api/catalog/where?framework_id=acme-internal", "/api/catalog/license-info/acme-internal"):
        response = cat_client.get(url)
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "retired"
        assert body["notes"] == "Use the successor catalog."
        assert body["verified_on"] == "2026-09-09"
        assert body["superseded_by"] == "acme-next"
    body = cat_client.get("/api/catalog/license-info/acme-internal").json()
    assert body["source_url"] == "https://example.org/source"
    assert body["license_url"] == "https://example.org/license"
    assert body["license_required"] is True


def test_yaml_import_preserves_unquoted_nested_dates(cat_client: TestClient, tmp_path: Path) -> None:
    content = (
        yaml.safe_dump(_SAMPLE_CATALOG)
        + """
verified_on: 2026-09-09
audit_contexts:
  US-TX:
    authority: Example CSA
    version: '5.9.5'
    source_url: https://example.org/audit
    verified_on: 2026-09-09
    valid_through: 2027-03-31
publication_notices:
  - id: FUTURE-1
    title: Future publication
    status: approved-future
    source_url: https://example.org/revision
    approved_on: 2026-08-10
    effective_on: 2029-10-01
"""
    )
    response = cat_client.post(
        "/api/catalog/import", json={"framework_id": "acme-internal", "format": "yaml", "content": content}
    )
    assert response.status_code == 201, response.text
    saved = json.loads((tmp_path / "user-catalogs/acme-internal.json").read_text(encoding="utf-8"))
    assert saved["verified_on"] == "2026-09-09"
    assert saved["audit_contexts"]["US-TX"]["valid_through"] == "2027-03-31"
    assert saved["publication_notices"][0]["effective_on"] == "2029-10-01"
    assert cat_client.get("/api/catalog/license-info/acme-internal").json()["verified_on"] == "2026-09-09"


def test_yaml_non_json_value_rejection_preserves_existing_import(cat_client: TestClient, tmp_path: Path) -> None:
    assert cat_client.post("/api/catalog/import", json=_import_payload()).status_code == 201
    folder = tmp_path / "user-catalogs"
    before = {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()}
    content = yaml.safe_dump(_SAMPLE_CATALOG) + "notes: !!set {one: null, two: null}\n"
    response = cat_client.post(
        "/api/catalog/import",
        json={"framework_id": "acme-internal", "format": "yaml", "content": content, "force": True},
    )
    assert response.status_code == 400, response.text
    assert response.json()["detail"]["error"] == "invalid_body"
    assert {p.name: p.read_bytes() for p in folder.iterdir() if p.is_file()} == before


def _source_row_catalog_payload() -> dict[str, object]:
    from datetime import date

    row = {
        "source_sha256": "b" * 64,
        "sheet": " v6.1 ",
        "row": 1461,
        "source_id": 5.2,
        "source_id_format": "0.00",
        "interpreted_id": "5.20",
        "kind": "fragment",
        "values": {" raw\n": " \u00a0 ", "null": None, "empty": "", "bool": True, "int": 5, "float": 5.0, "U": None},
        "resolved_values": {"U": "Existing", "null": None, "bool": True, "int": 5, "float": 5.0, "zero": -0.0},
        "provenance": {"U:anchor": "U1460", "U:merged_range": "U1460:U1461"},
    }
    dated_row = {
        **row,
        "row": 1462,
        "source_id": date(2026, 7, 23),
        "values": {"date": date(2026, 7, 23), "date_text": "2026-07-23"},
        "resolved_values": {"date": date(2026, 7, 23)},
    }
    return {
        "framework_id": "acme-source-rows",
        "framework_name": "Source rows",
        "source": "test",
        "version": "1",
        "controls": [
            {
                "id": "AC-1",
                "title": "Top",
                "description": "Maintain a policy.",
                "source_rows": [row],
                "enhancements": [
                    {
                        "id": "AC-1(1)",
                        "title": "Child",
                        "description": "Apply the policy.",
                        "enhancements": [
                            {
                                "id": "AC-1(1)(a)",
                                "title": "Leaf",
                                "description": "Review the policy.",
                                "source_rows": [dated_row],
                            }
                        ],
                    }
                ],
            }
        ],
    }


@pytest.mark.parametrize("fmt", ["json", "yaml"])
@pytest.mark.parametrize("source_id", [None, "", "005", 0, 2**80, 5.0, 5.2, -0.0, True, False])
def test_imported_source_rows_survive_saved_reload_and_both_http_responses(
    cat_client: TestClient, fmt: str, source_id: object
) -> None:
    from evidentia_api.routers import frameworks
    from evidentia_core.catalogs.loader import load_evidentia_catalog
    from evidentia_core.catalogs.registry import FrameworkRegistry

    app = cat_client.app
    assert isinstance(app, FastAPI)
    app.include_router(frameworks.router, prefix="/api")
    data = _source_row_catalog_payload()
    data["controls"][0]["source_rows"][0]["source_id"] = source_id
    json_content = json.dumps(data, default=lambda value: value.isoformat())
    expected = json.loads(json_content)
    content = json_content if fmt == "json" else yaml.safe_dump(data, sort_keys=False)
    FrameworkRegistry.reset_instance()
    try:
        imported = cat_client.post(
            "/api/catalog/import", json={"framework_id": "acme-source-rows", "format": fmt, "content": content}
        )
        assert imported.status_code == 201, imported.text
        saved_path = Path(imported.json()["path"])
        saved = json.loads(saved_path.read_text(encoding="utf-8"))
        assert saved["controls"] == expected["controls"]
        loaded = load_evidentia_catalog(saved_path)
        assert loaded.control_count == 3
        assert loaded.get_control("5.20") is None
        top = cat_client.get("/api/frameworks/acme-source-rows")
        leaf = cat_client.get("/api/frameworks/acme-source-rows/controls/AC-1.1.A")
        assert top.status_code == leaf.status_code == 200
        expected_top = expected["controls"][0]
        expected_leaf = expected_top["enhancements"][0]["enhancements"][0]
        assert top.json()["controls"][0]["source_rows"] == expected_top["source_rows"]
        assert leaf.json()["source_rows"] == expected_leaf["source_rows"]
        assert (
            top.json()["controls"][0]["enhancements"][0]["enhancements"][0]["source_rows"]
            == expected_leaf["source_rows"]
        )
        actual_row = top.json()["controls"][0]["source_rows"][0]
        assert type(actual_row["source_id"]) is type(source_id)
        if isinstance(source_id, float) and source_id == 0:
            assert math.copysign(1, actual_row["source_id"]) == math.copysign(1, source_id)
        for mapping in ("values", "resolved_values"):
            for key, expected_value in expected_top["source_rows"][0][mapping].items():
                actual_value = actual_row[mapping][key]
                assert type(actual_value) is type(expected_value)
                if isinstance(expected_value, float) and expected_value == 0:
                    assert math.copysign(1, actual_value) == math.copysign(1, expected_value)
        assert type(top.json()["controls"][0]["source_rows"][0]["values"]["int"]) is int
        assert type(top.json()["controls"][0]["source_rows"][0]["values"]["float"]) is float
        assert cat_client.get("/api/frameworks/acme-source-rows/controls/5.20").status_code == 404
    finally:
        FrameworkRegistry.reset_instance()


@pytest.mark.parametrize("fmt", ["json", "yaml"])
@pytest.mark.parametrize("field", ["source_id", "values", "resolved_values"])
def test_invalid_source_evidence_force_import_preserves_installed_bytes(
    cat_client: TestClient, fmt: str, field: str
) -> None:
    data = _source_row_catalog_payload()
    content = json.dumps(data, default=lambda value: value.isoformat())
    valid_payload = {"framework_id": "acme-source-rows", "format": "json", "content": content}
    created = cat_client.post("/api/catalog/import", json=valid_payload)
    assert created.status_code == 201, created.text
    saved = Path(created.json()["path"])
    before = {path.name: path.read_bytes() for path in saved.parent.iterdir() if path.is_file()}
    changed = json.loads(content)
    row = changed["controls"][0]["source_rows"][0]
    row[field] = float("nan") if field == "source_id" else {"bad": float("nan")}
    invalid_content = json.dumps(changed) if fmt == "json" else yaml.safe_dump(changed, sort_keys=False)
    rejected = cat_client.post(
        "/api/catalog/import",
        json={"framework_id": "acme-source-rows", "format": fmt, "content": invalid_content, "force": True},
    )
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["detail"]["error"] == "invalid_body"
    assert {path.name: path.read_bytes() for path in saved.parent.iterdir() if path.is_file()} == before
    assert not list(saved.parent.glob(".catalog-import-*"))


@pytest.mark.parametrize("field", ["values", "resolved_values", "provenance"])
@pytest.mark.parametrize("nested", [False, True])
@pytest.mark.parametrize("bad_key", [1, 1.5, False, None])
def test_yaml_non_string_source_keys_reject_before_lossy_json_staging(
    cat_client: TestClient, field: str, nested: bool, bad_key: object
) -> None:
    data = _source_row_catalog_payload()
    created = cat_client.post(
        "/api/catalog/import",
        json={"framework_id": "acme-source-rows", "format": "yaml", "content": yaml.safe_dump(data, sort_keys=False)},
    )
    assert created.status_code == 201, created.text
    saved = Path(created.json()["path"])
    before = {path.name: path.read_bytes() for path in saved.parent.iterdir() if path.is_file()}
    control = data["controls"][0]
    if nested:
        control = control["enhancements"][0]["enhancements"][0]
    control["source_rows"][0][field] = {bad_key: "non-string key cell", str(bad_key): "string key cell"}
    rejected = cat_client.post(
        "/api/catalog/import",
        json={
            "framework_id": "acme-source-rows",
            "format": "yaml",
            "content": yaml.safe_dump(data, sort_keys=False),
            "force": True,
        },
    )
    assert rejected.status_code == 400, rejected.text
    assert rejected.json()["detail"]["error"] == "invalid_body"
    assert {path.name: path.read_bytes() for path in saved.parent.iterdir() if path.is_file()} == before
    assert not list(saved.parent.glob(".catalog-import-*"))
