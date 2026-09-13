"""Verify SCAP cadence linkage and explicit append-only evidence saving."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from evidentia_collectors.scap._contracts import SourceProfile
from evidentia_collectors.scap.collector import ScapCompletionAssertion, collect_scap_bytes
from evidentia_core import evidence_store
from evidentia_core.conmon.series import SeriesVerdict, assert_series
from evidentia_core.models.evidence import EvidenceArtifact

from .test_cli.test_scap_io import assertion_bytes, source_bytes

SLUG = "fedramp-conmon-scans"


@pytest.fixture(autouse=True)
def no_mirror(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(evidence_store.EVIDENCE_AUTO_MIRROR_WORM_ENV_VAR, raising=False)
    monkeypatch.delenv(evidence_store.EVIDENCE_AUTO_MIRROR_BACKEND_ENV_VAR, raising=False)


@pytest.mark.parametrize("mode,count", [("counted", 1), ("unevaluated", 0), ("empty", 0)])
def test_one_summary_does_not_manufacture_a_cadence_observation(mode: str, count: int) -> None:
    raw = source_bytes("xccdf-1.2-native.xml")
    if mode == "unevaluated":
        raw = raw.replace(b"pa<!--split-->ss", b"notselected")
    elif mode == "empty":
        raw = re.sub(rb"\s*<rule-result\b.*?</rule-result>", b"", raw, flags=re.DOTALL)
    result = collect_scap_bytes(raw, source_profile="xccdf-1.2-results", assessment_index=0, cadence_slug=SLUG)
    assert len(result.findings) == 1 and result.evidence_artifact is not None
    assert result.assessment.coverage.countable_top_level_outcome_count == count
    assert result.cadence.state == ("linked" if count else "ineligible")
    assert result.cadence.linked_slug == (SLUG if count else None)
    assert result.evidence_artifact.metadata.model_dump().get("cadence_slug") == (SLUG if count else None)


def test_undated_oval_cannot_link_cadence_without_explicit_assertion() -> None:
    raw = source_bytes("oval-5.8-native.xml")
    unqualified = collect_scap_bytes(raw, source_profile="oval-5.8-core-results", assessment_index=0, cadence_slug=SLUG)
    assert unqualified.evidence_artifact is None and unqualified.cadence.linked_slug is None
    claim = ScapCompletionAssertion.model_validate(json.loads(assertion_bytes(raw)))
    qualified = collect_scap_bytes(
        raw,
        source_profile="oval-5.8-core-results",
        assessment_index=0,
        cadence_slug=SLUG,
        completion_assertion=claim,
        asserted_by="Synthetic operator",
    )
    assert qualified.evidence_artifact is not None and qualified.cadence.linked_slug == SLUG
    assert qualified.evidence_artifact.collected_at == "2024-03-01T00:00:00Z"
    assert qualified.completion.basis == "operator_asserted"


@pytest.mark.parametrize("asserted", [False, True])
def test_reimport_and_explicit_save_add_only_one_unchanged_version(tmp_path: Path, asserted: bool) -> None:
    raw = source_bytes("oval-5.8-native.xml" if asserted else "xccdf-1.2-native.xml")
    profile: SourceProfile = "oval-5.8-core-results" if asserted else "xccdf-1.2-results"
    claim = ScapCompletionAssertion.model_validate(json.loads(assertion_bytes(raw))) if asserted else None
    first = collect_scap_bytes(
        raw,
        source_profile=profile,
        assessment_index=0,
        cadence_slug=SLUG,
        completion_assertion=claim,
        asserted_by="Synthetic operator" if asserted else None,
    )
    second = collect_scap_bytes(
        raw,
        source_profile=profile,
        assessment_index=0,
        cadence_slug=SLUG,
        completion_assertion=claim,
        asserted_by="Synthetic operator" if asserted else None,
    )
    assert first.evidence_artifact is not None and second.evidence_artifact is not None
    assert first.evidence_artifact == second.evidence_artifact
    assert first.manifest.run_id != second.manifest.run_id
    store = tmp_path / "explicit-evidence"
    assert not store.exists()
    artifact = EvidenceArtifact.model_validate(first.evidence_artifact.model_dump())
    target = evidence_store.save_evidence(artifact, store)
    original = target.read_bytes()
    with pytest.raises(evidence_store.EvidenceWORMViolation):
        evidence_store.save_evidence(EvidenceArtifact.model_validate(second.evidence_artifact.model_dump()), store)
    assert target.read_bytes() == original
    stored = list(evidence_store.iter_artifacts(store))
    assert len(stored) == 1 and stored[0].version == 1
    series = assert_series(
        SLUG, stored, window_start=datetime(2024, 2, 1, tzinfo=UTC), window_end=datetime(2024, 4, 1, tzinfo=UTC)
    )
    assert len(series.observations) == 1 and series.verdict == SeriesVerdict.INSUFFICIENT
    assert "compliant" not in series.describe().lower() and "compliance" not in series.describe().lower()


def test_changed_assertion_actor_has_a_different_stable_identity() -> None:
    raw = source_bytes("oval-5.8-native.xml")
    claim = ScapCompletionAssertion.model_validate(json.loads(assertion_bytes(raw)))
    artifacts = [
        collect_scap_bytes(
            raw,
            source_profile="oval-5.8-core-results",
            assessment_index=0,
            completion_assertion=claim,
            asserted_by=actor,
        ).evidence_artifact
        for actor in ("Synthetic first operator", "Synthetic second operator")
    ]
    assert artifacts[0] is not None and artifacts[1] is not None
    assert artifacts[0].id != artifacts[1].id
    assert artifacts[0].content_hash != artifacts[1].content_hash
