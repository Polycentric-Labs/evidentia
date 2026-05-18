"""Unit tests for v0.9.5 P3.2 evidence append-only versioning."""

from __future__ import annotations

from evidentia_core.models.evidence import EvidenceArtifact, EvidenceType


class TestVersionFields:
    def test_default_version_is_one(self) -> None:
        artifact = EvidenceArtifact(
            title="t",
            evidence_type=EvidenceType.CONFIGURATION,
            source_system="src",
            collected_by="alice",
        )
        assert artifact.version == 1
        assert artifact.lineage_id is None
        assert artifact.predecessor_id is None

    def test_effective_lineage_id_falls_back_to_id(self) -> None:
        artifact = EvidenceArtifact(
            title="t",
            evidence_type=EvidenceType.LOG,
            source_system="src",
            collected_by="alice",
        )
        # When lineage_id is None, the artifact IS the root + its
        # id serves as the lineage_id.
        assert artifact.effective_lineage_id == artifact.id


class TestNewVersionHelper:
    def test_new_version_bumps_version(self) -> None:
        v1 = EvidenceArtifact(
            title="t",
            evidence_type=EvidenceType.LOG,
            source_system="src",
            collected_by="alice",
        )
        v2 = v1.new_version(content={"updated": "payload"})
        assert v2.version == 2
        assert v2.predecessor_id == v1.id
        assert v2.lineage_id == v1.id  # falls back to v1's own id

    def test_new_version_has_fresh_id(self) -> None:
        v1 = EvidenceArtifact(
            title="t",
            evidence_type=EvidenceType.LOG,
            source_system="src",
            collected_by="alice",
        )
        v2 = v1.new_version()
        assert v2.id != v1.id

    def test_chain_of_versions_preserves_lineage(self) -> None:
        v1 = EvidenceArtifact(
            title="t",
            evidence_type=EvidenceType.LOG,
            source_system="src",
            collected_by="alice",
        )
        v2 = v1.new_version()
        v3 = v2.new_version()
        v4 = v3.new_version()
        assert v2.lineage_id == v1.id
        assert v3.lineage_id == v1.id
        assert v4.lineage_id == v1.id
        assert v4.version == 4
        assert v4.predecessor_id == v3.id

    def test_field_updates_override(self) -> None:
        v1 = EvidenceArtifact(
            title="original-title",
            evidence_type=EvidenceType.LOG,
            source_system="src",
            collected_by="alice",
        )
        v2 = v1.new_version(title="new-title")
        assert v2.title == "new-title"
        # Other fields carry through.
        assert v2.evidence_type == EvidenceType.LOG
        assert v2.source_system == "src"

    def test_backward_compat_v094_artifacts_load_as_v1(self) -> None:
        """v0.7.x → v0.9.4 artifacts (no version fields in JSON)
        deserialize as version=1, lineage_id=None, predecessor_id=
        None — backward-compat preserved."""
        legacy_json = {
            "title": "legacy artifact",
            "evidence_type": "log",
            "source_system": "src",
            "collected_by": "alice",
        }
        artifact = EvidenceArtifact.model_validate(legacy_json)
        assert artifact.version == 1
        assert artifact.lineage_id is None
        assert artifact.predecessor_id is None
