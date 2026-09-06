"""Unit tests for v0.8.2 §25.2 P3.1 DFAH faithfulness scoring.

Covers the three intrinsic invariants of
:func:`evidentia_eval.faithfulness.faithfulness_score`:

1. **Score range** — output ``score`` always in ``[0.0, 1.0]``.
2. **Empty source** — empty ``source_clauses`` produces score
   0.0 + empty evidence list (never raises).
3. **Top-3 evidence** — returned ``evidence_clauses`` are at
   most 3, sorted descending by similarity.
4. **Threshold validation** — out-of-range threshold raises
   ``ValueError``.
5. **Faithful claim** — a claim with high token overlap to a
   source clause scores high + passes the default threshold.
6. **Hallucinated claim** — a claim with no token overlap
   scores 0 + fails the threshold.
"""

from __future__ import annotations

import pytest
from evidentia_eval.faithfulness import (
    DEFAULT_FAITHFULNESS_THRESHOLD,
    FaithfulnessResult,
    faithfulness_score,
)


class TestFaithfulnessScore:
    def test_score_in_unit_interval(self) -> None:
        result = faithfulness_score(
            "The system enforces account management",
            ["AC-2 requires account management procedures"],
        )
        assert 0.0 <= result.score <= 1.0

    def test_empty_source_clauses_returns_zero_score(self) -> None:
        """No source → score 0.0, no evidence, no raise."""
        result = faithfulness_score("Some claim", [])
        assert result.score == 0.0
        assert result.evidence_clauses == []
        # score < default threshold → fails (correct: hallucination
        # signal when there's no source to anchor against).
        assert not result.passed

    def test_top_3_evidence_clauses(self) -> None:
        """``evidence_clauses`` capped at 3 + sorted descending."""
        clauses = [
            "Account management policies enforce least privilege",
            "Configuration management baselines maintained",
            "Information system inventory documented",
            "Auditor access controls reviewed quarterly",
            "Change management workflow approves all changes",
        ]
        result = faithfulness_score(
            "Account management policies enforce least privilege",
            clauses,
        )
        assert len(result.evidence_clauses) <= 3
        # The verbatim-match clause MUST be the first evidence entry.
        assert result.evidence_clauses[0] == clauses[0]

    def test_invalid_threshold_raises(self) -> None:
        """Threshold outside [0, 1] is a ValueError."""
        with pytest.raises(ValueError, match="threshold"):
            faithfulness_score("c", ["x"], threshold=1.5)
        with pytest.raises(ValueError, match="threshold"):
            faithfulness_score("c", ["x"], threshold=-0.1)

    def test_high_overlap_claim_scores_high(self) -> None:
        """A claim that's a near-verbatim copy of a clause scores ~1."""
        clause = "Configuration management baselines documented quarterly"
        result = faithfulness_score(clause, [clause])
        # Identical token sets → Jaccard 1.0.
        assert result.score == 1.0
        assert result.passed
        assert result.evidence_clauses[0] == clause

    def test_zero_overlap_claim_fails_threshold(self) -> None:
        """A claim with no token overlap to any clause scores 0."""
        result = faithfulness_score(
            "The quick brown fox jumps over",
            [
                "Account management procedures enforce least privilege",
                "Information system inventory documented",
            ],
        )
        # Zero token overlap (after lowercase normalization).
        assert result.score == 0.0
        assert not result.passed

    def test_threshold_stored_on_result(self) -> None:
        """``FaithfulnessResult.threshold`` reflects the input threshold."""
        result = faithfulness_score("claim", ["clause"], threshold=0.5)
        assert result.threshold == 0.5

    def test_default_threshold_constant(self) -> None:
        """The default threshold is exposed as a module-level constant."""
        assert 0.0 <= DEFAULT_FAITHFULNESS_THRESHOLD <= 1.0
        # When no threshold passed, the constant is what's stored.
        result = faithfulness_score("c", ["x"])
        assert result.threshold == DEFAULT_FAITHFULNESS_THRESHOLD

    def test_method_field_identifies_stdlib_baseline(self) -> None:
        """The ``method`` field distinguishes stdlib from semantic paths."""
        result = faithfulness_score("c", ["x"])
        assert result.method == "jaccard-stdlib"

    def test_result_is_serializable(self) -> None:
        """The result model is Sigstore-signable as part of the
        wider eval output — JSON-roundtrips cleanly."""
        result = faithfulness_score(
            "Account management is enforced",
            ["AC-2 requires account management"],
        )
        json_str = result.model_dump_json()
        # Parse back and verify the canonical fields present.
        roundtripped = FaithfulnessResult.model_validate_json(json_str)
        assert roundtripped.claim == result.claim
        assert roundtripped.score == result.score
        assert roundtripped.method == result.method


# ── v0.8.6 P3 — confidence + framework-aware threshold tests ─────


class TestConfidence:
    """Per-claim bootstrap-resampled confidence."""

    def test_compute_confidence_default_off(self) -> None:
        """Default behavior: confidence is None (cost-aware)."""
        result = faithfulness_score(
            "Account management procedures must enforce least privilege",
            ["Account management procedures must enforce least privilege"],
        )
        assert result.confidence is None

    def test_compute_confidence_high_for_consistent_match(
        self,
    ) -> None:
        """Verbatim match → resample stddev low → confidence high.
        Use a fixed seed for deterministic test value.
        """
        from evidentia_eval.faithfulness import faithfulness_score

        result = faithfulness_score(
            "Account management procedures enforce least privilege",
            ["Account management procedures enforce least privilege"],
            compute_confidence=True,
            n_resamples=50,
            confidence_seed=42,
        )
        assert result.confidence is not None
        assert 0.0 <= result.confidence <= 1.0
        # Verbatim match resamples score ~1.0 consistently → high
        # confidence.
        assert result.confidence >= 0.7

    def test_compute_confidence_zero_on_empty_clauses(self) -> None:
        """No clauses → bootstrap can't compute → confidence 0.0."""
        result = faithfulness_score(
            "Anything",
            [],
            compute_confidence=True,
            n_resamples=10,
            confidence_seed=1,
        )
        assert result.confidence == 0.0

    def test_compute_confidence_zero_on_empty_claim(self) -> None:
        """No claim tokens → bootstrap can't compute → 0.0."""
        result = faithfulness_score(
            "",
            ["something here"],
            compute_confidence=True,
            n_resamples=10,
            confidence_seed=1,
        )
        assert result.confidence == 0.0


class TestFrameworkField:
    """Framework persisted on result for audit-trail re-derivation."""

    def test_framework_default_none(self) -> None:
        result = faithfulness_score("test claim", ["test clause"])
        assert result.framework is None

    def test_framework_persisted_when_set(self) -> None:
        result = faithfulness_score(
            "test claim",
            ["test clause"],
            framework="nist-800-53",
        )
        assert result.framework == "nist-800-53"


class TestResolveThreshold:
    """v0.8.6 P3 framework-aware default threshold resolution."""

    def test_known_framework_returns_mapped_threshold(self) -> None:
        from evidentia_eval.faithfulness import resolve_threshold

        assert resolve_threshold("nist-800-53") == 0.60
        assert resolve_threshold("ffiec-it-handbook") == 0.35
        assert resolve_threshold("iso-27001") == 0.30

    def test_unknown_framework_falls_back_to_default(self) -> None:
        from evidentia_eval.faithfulness import resolve_threshold

        assert resolve_threshold("not-a-framework") == DEFAULT_FAITHFULNESS_THRESHOLD

    def test_none_framework_returns_default(self) -> None:
        from evidentia_eval.faithfulness import resolve_threshold

        assert resolve_threshold(None) == DEFAULT_FAITHFULNESS_THRESHOLD

    def test_non_jaccard_method_returns_default(self) -> None:
        """Semantic method has no framework-aware map shipped in
        v0.8.6 — returns the framework-agnostic default."""
        from evidentia_eval.faithfulness import resolve_threshold

        # Even with a known framework, the non-jaccard method
        # path returns the agnostic default.
        assert resolve_threshold("nist-800-53", method="semantic") == DEFAULT_FAITHFULNESS_THRESHOLD
