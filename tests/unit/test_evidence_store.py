"""Unit tests for the v0.9.6 P2 evidence store + cloud-WORM mirror.

Covers:

- :mod:`evidentia_core.evidence_store` — append-only enforcement,
  lineage walk, version-N lookup, UUID canonicalization,
  path-traversal rejection.
- :mod:`evidentia_core.evidence_store_worm` — cloud-WORM mirror
  round-trip via the reference :class:`LocalFilesystemWORM` backend.
"""

from __future__ import annotations

import logging
from datetime import date
from pathlib import Path
from uuid import uuid4

import pytest
from evidentia_core.evidence_store import (
    EVIDENCE_STORE_ENV_VAR,
    EvidenceWORMViolation,
    InvalidEvidenceIdError,
    _chain_head_version,
    get_evidence_store_dir,
    list_lineage,
    list_lineages,
    load_evidence_version,
    save_evidence,
)
from evidentia_core.evidence_store_worm import (
    fetch_from_worm,
    mirror_to_worm,
)
from evidentia_core.models.evidence import (
    EvidenceArtifact,
    EvidenceType,
)
from evidentia_core.retention.metadata import (
    RetentionClassification,
    RetentionLifecycleStage,
    RetentionMetadata,
)
from evidentia_core.retention.worm import (
    LocalFilesystemWORM,
    WORMBackendError,
)


def _make_artifact(
    title: str = "S3 bucket policy snapshot",
    **kwargs: object,
) -> EvidenceArtifact:
    """Construct a minimal EvidenceArtifact for tests."""
    base: dict[str, object] = {
        "title": title,
        "evidence_type": EvidenceType.CONFIGURATION,
        "source_system": "aws",
        "collected_by": "test-runner@example.com",
        "content": {"bucket": "test-bucket", "policy": "deny-all"},
    }
    base.update(kwargs)
    return EvidenceArtifact.model_validate(base)


@pytest.fixture()
def store_dir(tmp_path: Path) -> Path:
    """Per-test evidence store directory."""
    return tmp_path / "evidence_store"


# ── get_evidence_store_dir precedence ───────────────────────────────


class TestGetStoreDir:
    def test_override_wins(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(EVIDENCE_STORE_ENV_VAR, str(tmp_path / "env-dir"))
        result = get_evidence_store_dir(override=tmp_path / "override-dir")
        assert result == (tmp_path / "override-dir").resolve()

    def test_env_var_wins_over_default(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv(EVIDENCE_STORE_ENV_VAR, str(tmp_path / "env-dir"))
        result = get_evidence_store_dir()
        assert result == (tmp_path / "env-dir").resolve()

    def test_platform_default_when_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(EVIDENCE_STORE_ENV_VAR, raising=False)
        result = get_evidence_store_dir()
        assert result.name == "evidence_store"
        # The parent path varies per OS; checking the leaf is the
        # portable assertion.


# ── UUID validation ────────────────────────────────────────────────


class TestUuidValidation:
    def test_canonical_uuid_accepted(self, store_dir: Path) -> None:
        artifact = _make_artifact(lineage_id=str(uuid4()))
        path = save_evidence(artifact, evidence_store_dir=store_dir)
        assert path.exists()

    def test_brace_wrapped_uuid_canonicalized(
        self, store_dir: Path
    ) -> None:
        raw = uuid4()
        artifact = _make_artifact(lineage_id=f"{{{raw}}}")
        save_evidence(artifact, evidence_store_dir=store_dir)
        # After save, the lineage_id should be the canonical form.
        assert artifact.lineage_id == str(raw)

    def test_invalid_id_rejected(self, store_dir: Path) -> None:
        artifact = _make_artifact(lineage_id="../../etc/passwd")
        with pytest.raises(InvalidEvidenceIdError):
            save_evidence(artifact, evidence_store_dir=store_dir)

    def test_empty_id_rejected(self, store_dir: Path) -> None:
        artifact = _make_artifact(lineage_id="")
        with pytest.raises(InvalidEvidenceIdError):
            save_evidence(artifact, evidence_store_dir=store_dir)


# ── save_evidence happy path ───────────────────────────────────────


class TestSavePath:
    def test_writes_v1_for_new_lineage(self, store_dir: Path) -> None:
        artifact = _make_artifact()
        path = save_evidence(artifact, evidence_store_dir=store_dir)
        assert path.exists()
        assert path.name == "v1.json"
        # Directory name matches the artifact's id (lineage root).
        assert path.parent.name == artifact.id

    def test_writes_v2_via_new_version_helper(
        self, store_dir: Path
    ) -> None:
        v1 = _make_artifact()
        save_evidence(v1, evidence_store_dir=store_dir)
        v2 = v1.new_version(content={"bucket": "v2", "policy": "allow"})
        path_v2 = save_evidence(v2, evidence_store_dir=store_dir)
        assert path_v2.name == "v2.json"
        assert path_v2.parent.name == v1.id
        # v2.lineage_id explicitly points at v1.id (the chain root).
        assert v2.lineage_id == v1.id
        assert v2.predecessor_id == v1.id

    def test_writes_v3_chain(self, store_dir: Path) -> None:
        v1 = _make_artifact()
        save_evidence(v1, evidence_store_dir=store_dir)
        v2 = v1.new_version(content={"x": 2})
        save_evidence(v2, evidence_store_dir=store_dir)
        v3 = v2.new_version(content={"x": 3})
        path_v3 = save_evidence(v3, evidence_store_dir=store_dir)
        assert path_v3.name == "v3.json"
        # v3 still anchors to v1 as the lineage root.
        assert v3.effective_lineage_id == v1.id

    def test_explicit_lineage_id_persisted(self, store_dir: Path) -> None:
        lineage = str(uuid4())
        artifact = _make_artifact(lineage_id=lineage)
        path = save_evidence(artifact, evidence_store_dir=store_dir)
        assert path.parent.name == lineage

    def test_save_returns_absolute_path(self, store_dir: Path) -> None:
        artifact = _make_artifact()
        path = save_evidence(artifact, evidence_store_dir=store_dir)
        assert path.is_absolute()


# ── WORM enforcement ───────────────────────────────────────────────


class TestWORMEnforcement:
    def test_overwrite_v1_blocked(self, store_dir: Path) -> None:
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        # Same id + same version=1 → conflict.
        with pytest.raises(EvidenceWORMViolation) as exc_info:
            save_evidence(artifact, evidence_store_dir=store_dir)
        assert exc_info.value.attempted_version == 1
        assert exc_info.value.next_version == 2

    def test_violation_carries_lineage_id(self, store_dir: Path) -> None:
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        with pytest.raises(EvidenceWORMViolation) as exc_info:
            save_evidence(artifact, evidence_store_dir=store_dir)
        assert exc_info.value.lineage_id == artifact.id

    def test_violation_suggests_new_version_in_message(
        self, store_dir: Path
    ) -> None:
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        with pytest.raises(EvidenceWORMViolation) as exc_info:
            save_evidence(artifact, evidence_store_dir=store_dir)
        assert "new_version" in str(exc_info.value)
        assert "v2" in str(exc_info.value)

    def test_overwrite_at_chain_head_blocked(
        self, store_dir: Path
    ) -> None:
        v1 = _make_artifact()
        save_evidence(v1, evidence_store_dir=store_dir)
        v2 = v1.new_version(content={"x": 2})
        save_evidence(v2, evidence_store_dir=store_dir)
        # Trying to save v2 again → conflict.
        with pytest.raises(EvidenceWORMViolation) as exc_info:
            save_evidence(v2, evidence_store_dir=store_dir)
        # Suggested next = current head (2) + 1 = 3.
        assert exc_info.value.next_version == 3

    def test_no_temp_file_left_after_violation(
        self, store_dir: Path
    ) -> None:
        import contextlib

        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        with contextlib.suppress(EvidenceWORMViolation):
            save_evidence(artifact, evidence_store_dir=store_dir)
        # No half-written .tmp file should remain in the lineage dir.
        lineage_dir = store_dir / artifact.id
        tmp_files = list(lineage_dir.glob("*.tmp"))
        assert tmp_files == []


# ── load / list ────────────────────────────────────────────────────


class TestLoadEvidenceVersion:
    def test_round_trip(self, store_dir: Path) -> None:
        artifact = _make_artifact(
            title="Round-trip test",
            content={"key": "value", "nested": [1, 2, 3]},
        )
        save_evidence(artifact, evidence_store_dir=store_dir)
        loaded = load_evidence_version(
            artifact.id, 1, evidence_store_dir=store_dir
        )
        assert loaded is not None
        assert loaded.title == "Round-trip test"
        assert loaded.content == {"key": "value", "nested": [1, 2, 3]}

    def test_load_unknown_lineage_returns_none(
        self, store_dir: Path
    ) -> None:
        unknown = str(uuid4())
        result = load_evidence_version(
            unknown, 1, evidence_store_dir=store_dir
        )
        assert result is None

    def test_load_missing_version_returns_none(
        self, store_dir: Path
    ) -> None:
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        # v1 exists; v2 doesn't.
        result = load_evidence_version(
            artifact.id, 2, evidence_store_dir=store_dir
        )
        assert result is None

    def test_load_invalid_uuid_raises(self, store_dir: Path) -> None:
        with pytest.raises(InvalidEvidenceIdError):
            load_evidence_version(
                "not-a-uuid", 1, evidence_store_dir=store_dir
            )

    def test_load_version_zero_rejected(self, store_dir: Path) -> None:
        with pytest.raises(ValueError):
            load_evidence_version(
                str(uuid4()), 0, evidence_store_dir=store_dir
            )

    def test_load_negative_version_rejected(
        self, store_dir: Path
    ) -> None:
        with pytest.raises(ValueError):
            load_evidence_version(
                str(uuid4()), -1, evidence_store_dir=store_dir
            )


class TestListLineage:
    def test_empty_for_unknown_lineage(self, store_dir: Path) -> None:
        assert list_lineage(
            str(uuid4()), evidence_store_dir=store_dir
        ) == []

    def test_single_version_chain(self, store_dir: Path) -> None:
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        chain = list_lineage(
            artifact.id, evidence_store_dir=store_dir
        )
        assert len(chain) == 1
        assert chain[0].version == 1

    def test_returns_versions_ascending(self, store_dir: Path) -> None:
        v1 = _make_artifact()
        save_evidence(v1, evidence_store_dir=store_dir)
        v2 = v1.new_version(content={"x": 2})
        save_evidence(v2, evidence_store_dir=store_dir)
        v3 = v2.new_version(content={"x": 3})
        save_evidence(v3, evidence_store_dir=store_dir)
        chain = list_lineage(v1.id, evidence_store_dir=store_dir)
        assert [a.version for a in chain] == [1, 2, 3]

    def test_chain_traversal_preserves_predecessors(
        self, store_dir: Path
    ) -> None:
        v1 = _make_artifact()
        save_evidence(v1, evidence_store_dir=store_dir)
        v2 = v1.new_version(content={"x": 2})
        save_evidence(v2, evidence_store_dir=store_dir)
        chain = list_lineage(v1.id, evidence_store_dir=store_dir)
        # v1 is the root → predecessor_id is None.
        # v2 → predecessor_id is v1.id.
        assert chain[0].predecessor_id is None
        assert chain[1].predecessor_id == v1.id


class TestListLineages:
    def test_empty_store(self, store_dir: Path) -> None:
        assert list_lineages(evidence_store_dir=store_dir) == []

    def test_returns_all_lineage_dirs(self, store_dir: Path) -> None:
        a = _make_artifact()
        b = _make_artifact()
        save_evidence(a, evidence_store_dir=store_dir)
        save_evidence(b, evidence_store_dir=store_dir)
        lineages = list_lineages(evidence_store_dir=store_dir)
        assert sorted(lineages) == sorted([a.id, b.id])

    def test_skips_non_uuid_dirs(self, store_dir: Path) -> None:
        store_dir.mkdir(parents=True, exist_ok=True)
        (store_dir / "not-a-uuid").mkdir()
        a = _make_artifact()
        save_evidence(a, evidence_store_dir=store_dir)
        lineages = list_lineages(evidence_store_dir=store_dir)
        assert lineages == [a.id]


# ── _chain_head_version helper ─────────────────────────────────────


class TestChainHeadVersion:
    def test_zero_for_empty_lineage(self, store_dir: Path) -> None:
        store_dir.mkdir(parents=True, exist_ok=True)
        assert _chain_head_version(str(uuid4()), store_dir) == 0

    def test_one_after_v1_save(self, store_dir: Path) -> None:
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        store_root = get_evidence_store_dir(store_dir)
        assert _chain_head_version(artifact.id, store_root) == 1

    def test_three_after_v3_save(self, store_dir: Path) -> None:
        v1 = _make_artifact()
        save_evidence(v1, evidence_store_dir=store_dir)
        v2 = v1.new_version(content={"x": 2})
        save_evidence(v2, evidence_store_dir=store_dir)
        v3 = v2.new_version(content={"x": 3})
        save_evidence(v3, evidence_store_dir=store_dir)
        store_root = get_evidence_store_dir(store_dir)
        assert _chain_head_version(v1.id, store_root) == 3


# ── Cloud-WORM mirror (LocalFilesystemWORM as backend) ─────────────


@pytest.fixture()
def worm_backend(tmp_path: Path) -> LocalFilesystemWORM:
    """Reference WORM backend for mirror tests."""
    root = tmp_path / "worm_root"
    return LocalFilesystemWORM(root=root)


def _retention_metadata() -> RetentionMetadata:
    """Sensible default retention metadata for mirror tests."""
    return RetentionMetadata(
        classification=RetentionClassification.IRS_TAX.value,
        retention_period_days=2555,  # 7 years per IRS
        lock_until=date(2033, 5, 18),
        legal_hold=False,
        lifecycle_stage=RetentionLifecycleStage.ACTIVE.value,
    )


class TestMirrorToWORM:
    def test_round_trip(
        self,
        worm_backend: LocalFilesystemWORM,
    ) -> None:
        artifact = _make_artifact(title="Mirror round-trip")
        record_id = mirror_to_worm(
            artifact, worm_backend, _retention_metadata()
        )
        loaded = fetch_from_worm(
            artifact.effective_lineage_id,
            artifact.version,
            worm_backend,
        )
        assert loaded.title == "Mirror round-trip"
        assert loaded.id == artifact.id
        assert "_v1" in record_id

    def test_record_id_format(
        self,
        worm_backend: LocalFilesystemWORM,
    ) -> None:
        artifact = _make_artifact()
        record_id = mirror_to_worm(
            artifact, worm_backend, _retention_metadata()
        )
        assert record_id == f"{artifact.effective_lineage_id}_v1"

    def test_duplicate_mirror_raises_worm_error(
        self,
        worm_backend: LocalFilesystemWORM,
    ) -> None:
        artifact = _make_artifact()
        mirror_to_worm(artifact, worm_backend, _retention_metadata())
        with pytest.raises(WORMBackendError):
            mirror_to_worm(
                artifact, worm_backend, _retention_metadata()
            )

    def test_mirror_chain_versions_distinct(
        self,
        worm_backend: LocalFilesystemWORM,
    ) -> None:
        v1 = _make_artifact()
        v2 = v1.new_version(content={"x": 2})
        rec1 = mirror_to_worm(v1, worm_backend, _retention_metadata())
        rec2 = mirror_to_worm(v2, worm_backend, _retention_metadata())
        assert rec1 != rec2
        assert rec1.endswith("_v1")
        assert rec2.endswith("_v2")

    def test_fetch_unknown_raises(
        self,
        worm_backend: LocalFilesystemWORM,
    ) -> None:
        with pytest.raises(WORMBackendError):
            fetch_from_worm(str(uuid4()), 1, worm_backend)


# ── Atomic-write hygiene ───────────────────────────────────────────


class TestAtomicWrite:
    def test_tmp_file_replaced(self, store_dir: Path) -> None:
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)
        # The canonical v1.json should exist; no .tmp file should
        # remain after a successful save.
        lineage_dir = store_dir / artifact.id
        tmp_files = list(lineage_dir.glob("*.tmp"))
        assert tmp_files == []
        assert (lineage_dir / "v1.json").exists()


# ── v0.9.7 P1.1 auto-mirror env-var path ──────────────────────────


class TestAutoMirrorEnvVar:
    """v0.9.7 P1.1: closes F-V96-worm-app-layer.

    The auto-mirror path consults two env vars at save time:
    EVIDENTIA_EVIDENCE_AUTO_MIRROR_WORM (gating) +
    EVIDENTIA_EVIDENCE_WORM_BACKEND_FACTORY (factory ref).
    """

    def test_no_auto_mirror_when_env_unset(
        self,
        store_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_core.evidence_store import (
            EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR,
            _resolve_auto_mirror_backend,
        )

        monkeypatch.delenv(
            EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, raising=False
        )
        # save proceeds without invoking the mirror; resolver
        # returns None signaling "no mirror".
        assert _resolve_auto_mirror_backend() is None
        artifact = _make_artifact()
        save_evidence(artifact, evidence_store_dir=store_dir)

    def test_auto_mirror_set_without_factory_errors(
        self,
        store_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_core.evidence_store import (
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
            EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR,
        )

        monkeypatch.setenv(EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, "1")
        monkeypatch.delenv(
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR, raising=False
        )
        artifact = _make_artifact()
        with pytest.raises(RuntimeError, match="BACKEND_FACTORY"):
            save_evidence(artifact, evidence_store_dir=store_dir)

    def test_malformed_factory_ref_errors(
        self,
        store_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_core.evidence_store import (
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
            EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR,
        )

        monkeypatch.setenv(EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, "1")
        # Missing the ':' separator.
        monkeypatch.setenv(
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
            "module.without.callable.ref",
        )
        artifact = _make_artifact()
        with pytest.raises(RuntimeError, match=r"'module.submodule:callable_name'"):
            save_evidence(artifact, evidence_store_dir=store_dir)

    def test_unimportable_module_errors(
        self,
        store_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_core.evidence_store import (
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
            EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR,
        )

        monkeypatch.setenv(EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, "1")
        monkeypatch.setenv(
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
            "no_such_module_xyz_abc:make_backend",
        )
        artifact = _make_artifact()
        with pytest.raises(RuntimeError, match="Could not import"):
            save_evidence(artifact, evidence_store_dir=store_dir)

    def test_callable_attr_missing_errors(
        self,
        store_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        from evidentia_core.evidence_store import (
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
            EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR,
        )

        monkeypatch.setenv(EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, "1")
        monkeypatch.setenv(
            EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
            "evidentia_core.evidence_store:no_such_callable",
        )
        artifact = _make_artifact()
        with pytest.raises(RuntimeError, match="did not resolve to a callable"):
            save_evidence(artifact, evidence_store_dir=store_dir)

    def test_auto_mirror_invokes_factory_and_pushes(
        self,
        tmp_path: Path,
        store_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """End-to-end: factory is invoked + mirror writes to WORM root."""
        import sys
        import types

        # Build a synthetic module exposing make_backend() that
        # returns a LocalFilesystemWORM backend + retention metadata.
        worm_root = tmp_path / "worm_root"
        module = types.ModuleType("test_auto_mirror_factory_mod")
        backend = LocalFilesystemWORM(root=worm_root)

        def make_backend() -> (
            tuple[LocalFilesystemWORM, RetentionMetadata]
        ):
            return backend, RetentionMetadata(
                classification=RetentionClassification.IRS_TAX.value,
                retention_period_days=2555,
                lock_until=date(2033, 5, 18),
                legal_hold=False,
                lifecycle_stage=RetentionLifecycleStage.ACTIVE.value,
            )

        module.make_backend = make_backend  # type: ignore[attr-defined]
        sys.modules["test_auto_mirror_factory_mod"] = module
        try:
            from evidentia_core.evidence_store import (
                EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
                EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR,
            )

            monkeypatch.setenv(EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, "1")
            monkeypatch.setenv(
                EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
                "test_auto_mirror_factory_mod:make_backend",
            )
            artifact = _make_artifact()
            save_evidence(artifact, evidence_store_dir=store_dir)
            # Mirror record_id = <lineage>_v1; backend stores it as
            # <root>/<record_id>.bin sidecar.
            expected_record = (
                worm_root / f"{artifact.effective_lineage_id}_v1.bin"
            )
            assert expected_record.exists()
        finally:
            sys.modules.pop("test_auto_mirror_factory_mod", None)

    def test_mirror_failure_non_fatal(
        self,
        tmp_path: Path,
        store_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """Mirror failure logs a warning but the save still succeeds."""
        import sys
        import types

        module = types.ModuleType("test_failing_mirror_mod")

        def make_backend() -> (
            tuple[LocalFilesystemWORM, RetentionMetadata]
        ):
            class BrokenBackend(LocalFilesystemWORM):
                def put(self, *args: object, **kwargs: object) -> None:
                    raise WORMBackendError("simulated failure")

            return BrokenBackend(root=tmp_path / "broken_worm"), RetentionMetadata(
                classification=RetentionClassification.IRS_TAX.value,
                retention_period_days=2555,
                lock_until=date(2033, 5, 18),
                legal_hold=False,
                lifecycle_stage=RetentionLifecycleStage.ACTIVE.value,
            )

        module.make_backend = make_backend  # type: ignore[attr-defined]
        sys.modules["test_failing_mirror_mod"] = module
        try:
            from evidentia_core.evidence_store import (
                EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
                EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR,
            )

            monkeypatch.setenv(EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, "1")
            monkeypatch.setenv(
                EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR,
                "test_failing_mirror_mod:make_backend",
            )
            artifact = _make_artifact()
            # Should NOT raise — local-store write succeeds; mirror
            # failure is logged as a warning.
            with caplog.at_level(logging.WARNING):
                path = save_evidence(
                    artifact, evidence_store_dir=store_dir
                )
            assert path.exists()
            assert "Auto-mirror to WORM backend failed" in caplog.text
        finally:
            sys.modules.pop("test_failing_mirror_mod", None)
