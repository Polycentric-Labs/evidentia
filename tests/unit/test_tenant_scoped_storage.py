"""Unit tests for v0.9.8 P1.6 tenant-scoped storage paths.

Verifies that :func:`evidentia_core.evidence_store.get_evidence_store_dir`
and :func:`evidentia_core.poam_store.get_poam_store_dir` correctly
append ``tenants/<tenant-id>/`` to the resolved base when the
``tenant`` kwarg is supplied, while preserving v0.9.7 behavior
when the kwarg is omitted (backward compat for single-tenant
deployments).

Also covers tenant-id validation (the gate against path-traversal
injection) and cross-tenant isolation (tenant A reads cannot reach
tenant B's lineages).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from evidentia_core.evidence_store import (
    EVIDENCE_STORE_ENV_VAR,
    get_evidence_store_dir,
    list_lineages,
    load_evidence_version,
    save_evidence,
)
from evidentia_core.models.evidence import (
    EvidenceArtifact,
    EvidenceType,
)
from evidentia_core.poam_store import (
    POAM_STORE_ENV_VAR,
    get_poam_store_dir,
)
from evidentia_core.rbac import InvalidTenantIdError, validate_tenant_id

# ── 1. validate_tenant_id ─────────────────────────────────────────


class TestValidateTenantId:
    @pytest.mark.parametrize(
        "valid_id",
        [
            "acme-corp",
            "globex",
            "Acme",
            "test123",
            "a",
            "TENANT_X",
            "tenant-with-many-segments",
        ],
    )
    def test_valid_ids_accepted(self, valid_id: str) -> None:
        assert validate_tenant_id(valid_id) == valid_id

    @pytest.mark.parametrize(
        "invalid_id",
        [
            "",  # empty
            "../escape",  # path traversal
            "tenant/with/slash",
            "tenant\\with\\backslash",
            "..",  # parent dir
            ".hidden",  # leading dot
            "tenant.with.dots",
            "-leading-hyphen",
            "_leading_underscore",
            "tenant with space",
            "x" * 64,  # too long
            "tenant\x00null",
        ],
    )
    def test_invalid_ids_rejected(self, invalid_id: str) -> None:
        with pytest.raises(InvalidTenantIdError):
            validate_tenant_id(invalid_id)


# ── 2. get_evidence_store_dir tenant scoping ─────────────────────


class TestEvidenceStoreDirTenantScoping:
    def test_no_tenant_returns_base_unchanged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Backward compat — single-tenant call yields v0.9.7 path."""
        monkeypatch.setenv(EVIDENCE_STORE_ENV_VAR, str(tmp_path))
        assert get_evidence_store_dir() == tmp_path.resolve()

    def test_tenant_appends_under_tenants_subdir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """``tenant="acme-corp"`` → ``<base>/tenants/acme-corp``."""
        monkeypatch.setenv(EVIDENCE_STORE_ENV_VAR, str(tmp_path))
        resolved = get_evidence_store_dir(tenant="acme-corp")
        assert resolved == tmp_path.resolve() / "tenants" / "acme-corp"

    def test_tenant_with_explicit_override(self, tmp_path: Path) -> None:
        """``override=`` + ``tenant=`` compose correctly."""
        resolved = get_evidence_store_dir(override=tmp_path, tenant="globex")
        assert resolved == tmp_path.resolve() / "tenants" / "globex"

    def test_invalid_tenant_id_raises(self, tmp_path: Path) -> None:
        """A malicious tenant id is rejected before path construction."""
        with pytest.raises(InvalidTenantIdError):
            get_evidence_store_dir(override=tmp_path, tenant="../escape")


# ── 3. get_poam_store_dir tenant scoping ─────────────────────────


class TestPoamStoreDirTenantScoping:
    def test_no_tenant_returns_base_unchanged(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(POAM_STORE_ENV_VAR, str(tmp_path))
        assert get_poam_store_dir() == tmp_path.resolve()

    def test_tenant_appends_under_tenants_subdir(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(POAM_STORE_ENV_VAR, str(tmp_path))
        resolved = get_poam_store_dir(tenant="acme-corp")
        assert resolved == tmp_path.resolve() / "tenants" / "acme-corp"

    def test_tenant_with_explicit_override(self, tmp_path: Path) -> None:
        resolved = get_poam_store_dir(override=tmp_path, tenant="globex")
        assert resolved == tmp_path.resolve() / "tenants" / "globex"

    def test_invalid_tenant_id_raises(self, tmp_path: Path) -> None:
        with pytest.raises(InvalidTenantIdError):
            get_poam_store_dir(override=tmp_path, tenant="../etc/passwd")


# ── 4. Cross-tenant isolation (end-to-end with evidence store) ──


def _make_artifact(title: str) -> EvidenceArtifact:
    return EvidenceArtifact(
        title=title,
        evidence_type=EvidenceType.CONFIGURATION,
        source_system="aws",
        collected_by="test-runner@example.com",
        content={"x": title},
    )


class TestCrossTenantIsolation:
    def test_evidence_in_tenant_a_not_visible_in_tenant_b(self, tmp_path: Path) -> None:
        """Save under tenant A; list under tenant B → A's data is invisible."""
        acme_dir = get_evidence_store_dir(override=tmp_path, tenant="acme-corp")
        globex_dir = get_evidence_store_dir(override=tmp_path, tenant="globex")
        # Save one artifact under acme-corp.
        save_evidence(
            _make_artifact("acme-only"),
            evidence_store_dir=acme_dir,
        )
        # acme-corp sees the lineage.
        assert len(list_lineages(evidence_store_dir=acme_dir)) == 1
        # globex sees nothing.
        assert list_lineages(evidence_store_dir=globex_dir) == []

    def test_lineages_truly_in_distinct_subdirs(self, tmp_path: Path) -> None:
        """Physical layout: each tenant's lineages live under tenants/<tenant>/."""
        acme_dir = get_evidence_store_dir(override=tmp_path, tenant="acme-corp")
        save_evidence(_make_artifact("a"), evidence_store_dir=acme_dir)

        # The on-disk path includes the tenants/acme-corp prefix.
        expected_prefix = tmp_path.resolve() / "tenants" / "acme-corp"
        assert acme_dir == expected_prefix
        assert acme_dir.exists()
        # The base override path itself does NOT contain lineage
        # subdirectories — they're all under tenants/.
        base_children = {p.name for p in tmp_path.iterdir() if p.is_dir()}
        assert base_children == {"tenants"}

    def test_load_evidence_version_respects_tenant_scope(self, tmp_path: Path) -> None:
        """Saving in tenant A, loading from tenant B → not found."""
        acme_dir = get_evidence_store_dir(override=tmp_path, tenant="acme-corp")
        globex_dir = get_evidence_store_dir(override=tmp_path, tenant="globex")
        artifact = _make_artifact("acme-secret")
        save_evidence(artifact, evidence_store_dir=acme_dir)
        # Loading from acme-corp succeeds.
        loaded = load_evidence_version(
            lineage_id=artifact.effective_lineage_id,
            version=1,
            evidence_store_dir=acme_dir,
        )
        assert loaded is not None
        assert loaded.title == "acme-secret"
        # Loading the SAME lineage from globex returns None — the
        # store contract returns None for missing well-formed IDs
        # (vs. raising for malformed IDs). Tenant isolation lands
        # as the load surfacing the lineage absence rather than the
        # raw FileNotFoundError.
        missing = load_evidence_version(
            lineage_id=artifact.effective_lineage_id,
            version=1,
            evidence_store_dir=globex_dir,
        )
        assert missing is None

    def test_single_tenant_unchanged(self, tmp_path: Path) -> None:
        """v0.9.7 single-tenant deployments see no new directory structure.

        Save without tenant → artifact lives directly under the
        override path, NOT under tenants/. Backward compat asserted.
        """
        save_evidence(
            _make_artifact("single-tenant"),
            evidence_store_dir=tmp_path,
        )
        # No tenants/ subdir created — the lineage lives at the
        # override path's top level.
        children = {p.name for p in tmp_path.iterdir() if p.is_dir()}
        assert "tenants" not in children
        # Lineages directory should exist at top level.
        assert any(p.is_dir() for p in tmp_path.iterdir())
