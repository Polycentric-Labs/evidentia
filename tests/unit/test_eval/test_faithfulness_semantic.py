"""Unit tests for v0.8.3 P1.1 sentence-transformers faithfulness path.

Covers the semantic-similarity scoring contract:

1. **Score range** — output ``score`` always in ``[0.0, 1.0]``
   (cosine similarity clamped from [-1, 1]).
2. **Empty source** — empty ``source_clauses`` produces score
   0.0 + empty evidence list (never raises).
3. **Top-3 evidence** — returned ``evidence_clauses`` are at
   most 3, sorted descending by similarity.
4. **Threshold validation** — out-of-range threshold raises
   ``ValueError``.
5. **Method field** — result.method == "sentence-transformers"
   to distinguish from the stdlib Jaccard baseline.
6. **Missing extra graceful error** — when sentence-transformers
   isn't importable, raises ``SemanticFaithfulnessNotAvailableError``
   with a clear install hint.

The tests mock the sentence-transformers import + model so CI
runs without the ~90 MB model download. Real-model integration
tests can opt in via the EVIDENTIA_SENTENCE_TRANSFORMERS_INTEGRATION
env var (deferred to v0.8.4).
"""

from __future__ import annotations

import sys
from unittest import mock

import numpy as np
import pytest
from evidentia_eval.faithfulness_semantic import (
    DEFAULT_SEMANTIC_MODEL,
    DEFAULT_SEMANTIC_THRESHOLD,
    SemanticFaithfulnessNotAvailableError,
    faithfulness_score_semantic,
)


@pytest.fixture(autouse=True)
def _clear_model_cache() -> None:
    """Reset the module-level model cache between tests.

    Prevents a mocked model from leaking into other tests +
    keeps the cached-load assertion in the cache test reliable.
    """
    from evidentia_eval import faithfulness_semantic

    faithfulness_semantic._MODEL_CACHE.clear()


def _make_mock_model(
    embedding_pairs: dict[str, list[float]],
) -> mock.MagicMock:
    """Build a mock SentenceTransformer that returns canned embeddings.

    Each test passes ``embedding_pairs`` mapping input text →
    embedding vector. The mock's ``encode()`` returns the
    embeddings in input order. Tests that don't care about
    specific vectors can pass random small embeddings.
    """
    model = mock.MagicMock()

    def fake_encode(texts: list[str], **kwargs: object) -> np.ndarray:
        rows = [embedding_pairs[t] for t in texts]
        return np.array(rows, dtype=np.float64)

    model.encode = fake_encode
    return model


def _patch_import_returning(module: object) -> object:
    """Build a context manager that patches the lazy-import helper.

    Returns the patched value; tests use the context manager via
    ``with mock.patch(...)``.
    """
    fake_st = mock.MagicMock()
    fake_st.SentenceTransformer.return_value = module
    return fake_st


class TestFaithfulnessSemanticBasics:
    def test_score_in_unit_interval(self) -> None:
        """Cosine similarity is clamped to [0, 1]."""
        # Two identical vectors → cosine 1.0; clamps to 1.0.
        embeddings = {
            "claim text": [1.0, 0.0, 0.0],
            "matching clause": [1.0, 0.0, 0.0],
        }
        model = _make_mock_model(embeddings)
        with mock.patch(
            "evidentia_eval.faithfulness_semantic._import_sentence_transformers",
            return_value=_patch_import_returning(model),
        ):
            result = faithfulness_score_semantic("claim text", ["matching clause"])
        assert 0.0 <= result.score <= 1.0
        assert result.score == pytest.approx(1.0)

    def test_empty_source_clauses_returns_zero(self) -> None:
        """No source → score 0.0, no evidence, no raise."""
        # Mock isn't actually used (early return); patch anyway
        # for symmetry.
        with mock.patch("evidentia_eval.faithfulness_semantic._import_sentence_transformers"):
            result = faithfulness_score_semantic("claim", [])
        assert result.score == 0.0
        assert result.evidence_clauses == []
        assert not result.passed

    def test_top_3_evidence_clauses(self) -> None:
        """``evidence_clauses`` capped at 3 + sorted descending."""
        # Five clauses with descending similarity to claim.
        embeddings = {
            "claim": [1.0, 0.0, 0.0],
            "best match": [1.0, 0.0, 0.0],  # cos=1.0
            "second match": [0.9, 0.1, 0.0],  # cos~0.99
            "third match": [0.5, 0.5, 0.0],  # cos~0.71
            "fourth match": [0.0, 1.0, 0.0],  # cos=0.0
            "fifth match": [0.0, 0.0, 1.0],  # cos=0.0
        }
        model = _make_mock_model(embeddings)
        with mock.patch(
            "evidentia_eval.faithfulness_semantic._import_sentence_transformers",
            return_value=_patch_import_returning(model),
        ):
            result = faithfulness_score_semantic(
                "claim",
                [
                    "fourth match",
                    "best match",
                    "third match",
                    "fifth match",
                    "second match",
                ],
            )
        # Top 3 (descending similarity): best, second, third.
        assert len(result.evidence_clauses) == 3
        assert result.evidence_clauses[0] == "best match"
        assert result.evidence_clauses[1] == "second match"
        assert result.evidence_clauses[2] == "third match"

    def test_invalid_threshold_raises(self) -> None:
        """Threshold outside [0, 1] is a ValueError."""
        with pytest.raises(ValueError, match="threshold"):
            faithfulness_score_semantic("c", ["x"], threshold=1.5)
        with pytest.raises(ValueError, match="threshold"):
            faithfulness_score_semantic("c", ["x"], threshold=-0.1)

    def test_method_field_identifies_semantic_path(self) -> None:
        """method == 'sentence-transformers' to distinguish from Jaccard."""
        embeddings = {"c": [1.0, 0.0], "x": [0.5, 0.5]}
        model = _make_mock_model(embeddings)
        with mock.patch(
            "evidentia_eval.faithfulness_semantic._import_sentence_transformers",
            return_value=_patch_import_returning(model),
        ):
            result = faithfulness_score_semantic("c", ["x"])
        assert result.method == "sentence-transformers"


class TestSemanticFaithfulnessNotAvailable:
    def test_missing_extra_raises_with_hint(self) -> None:
        """Without sentence-transformers installed → clear error."""
        # Force the import inside _import_sentence_transformers to
        # raise ImportError.
        with (
            mock.patch.dict(sys.modules, {"sentence_transformers": None}),
            pytest.raises(
                SemanticFaithfulnessNotAvailableError,
                match="evidentia-ai\\[eval-faithfulness\\]",
            ),
        ):
            faithfulness_score_semantic("c", ["x"])

    def test_error_subclasses_importerror(self) -> None:
        """Existing ``except ImportError:`` chains catch it."""
        assert issubclass(SemanticFaithfulnessNotAvailableError, ImportError)


class TestSemanticFaithfulnessThreshold:
    def test_default_threshold_constant_is_set(self) -> None:
        assert 0.0 <= DEFAULT_SEMANTIC_THRESHOLD <= 1.0
        # 0.7 is the documented default (per arXiv 2601.15322
        # calibration); locked-in here to catch unintended drift.
        assert DEFAULT_SEMANTIC_THRESHOLD == 0.7

    def test_default_model_constant_is_set(self) -> None:
        assert DEFAULT_SEMANTIC_MODEL.startswith("sentence-transformers/")

    def test_threshold_stored_on_result(self) -> None:
        embeddings = {"c": [1.0, 0.0], "x": [0.0, 1.0]}
        model = _make_mock_model(embeddings)
        with mock.patch(
            "evidentia_eval.faithfulness_semantic._import_sentence_transformers",
            return_value=_patch_import_returning(model),
        ):
            result = faithfulness_score_semantic("c", ["x"], threshold=0.5)
        assert result.threshold == 0.5
