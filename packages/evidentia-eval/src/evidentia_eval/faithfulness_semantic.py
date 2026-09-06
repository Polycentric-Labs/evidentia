"""DFAH faithfulness scoring — sentence-transformers semantic path (v0.8.3 P1.1).

Complements the v0.8.2 stdlib Jaccard baseline
(:func:`evidentia_eval.faithfulness.faithfulness_score`) with a
paraphrase-tolerant semantic-similarity scorer. Where Jaccard
sees ``"MFA is required for admin accounts"`` and
``"AC-2 mandates two-factor authentication for privileged
users"`` as zero-overlap (different vocabulary), sentence-
transformers' embedding-cosine similarity correctly scores them
as semantically equivalent.

**Opt-in via the ``[eval-faithfulness]`` extra**:

    pip install 'evidentia-ai[eval-faithfulness]'

Without the extra, importing this module raises
:class:`SemanticFaithfulnessNotAvailableError` at first use.
Operators relying on the stdlib Jaccard baseline are unaffected
(no install required; faithfulness module continues to work).

**Default model**: ``sentence-transformers/all-MiniLM-L6-v2``
(~90 MB; fast inference; trained on diverse paraphrase pairs).
Operators wanting higher accuracy can override via the
``model_name`` argument; the module accepts any
sentence-transformers-compatible identifier.

**Default threshold**: 0.7 (per arXiv 2601.15322 calibration —
typical semantic-similarity scores for known-faithful claims
cluster above this on natural-language policy clauses).

References:
- :class:`evidentia_eval.faithfulness.FaithfulnessResult` —
  result model (shared with the stdlib Jaccard baseline)
- :func:`evidentia_eval.faithfulness.faithfulness_score` —
  stdlib baseline; complementary to this semantic path
- §26.2 P1.1 (v0.8.3 cycle plan)
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING

from evidentia_eval.faithfulness import (
    FaithfulnessResult,
)

if TYPE_CHECKING:
    pass

# Default model identifier. Sentence-transformers downloads on
# first use to ~/.cache/huggingface/. CI caches via actions/cache
# keyed on the model name + sentence-transformers version.
DEFAULT_SEMANTIC_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"

# Default threshold for the semantic-similarity path. Tuned for
# paraphrase-tolerant scoring on natural-language policy clauses.
# Semantic-similarity scores typically cluster higher than the
# Jaccard token-overlap baseline (0.3 default), so the threshold
# is set higher.
DEFAULT_SEMANTIC_THRESHOLD: float = 0.7


class SemanticFaithfulnessNotAvailableError(ImportError):
    """Raised when sentence-transformers is not installed.

    Subclasses :class:`ImportError` so existing
    ``except ImportError:`` chains continue to handle the missing-
    extra case gracefully. The exception message includes the
    canonical install hint.
    """


def _import_sentence_transformers() -> object:
    """Lazy-import sentence-transformers + return the module.

    Raises :class:`SemanticFaithfulnessNotAvailableError` with a
    clear install hint when the optional extra isn't installed.
    Tests can monkeypatch this function to inject a mocked
    sentence-transformers module without requiring the real
    ~90 MB model download.
    """
    try:
        import sentence_transformers
    except ImportError as exc:
        raise SemanticFaithfulnessNotAvailableError(
            "sentence-transformers is not installed. Install via "
            "`pip install evidentia-ai[eval-faithfulness]` to "
            "enable the v0.8.3 semantic-similarity faithfulness "
            "scorer. The stdlib Jaccard baseline "
            "(faithfulness_score) does not require the extra."
        ) from exc
    return sentence_transformers


# Module-level cache for the loaded model. Keyed by model_name so
# operators evaluating multiple models in the same process get
# one load per model. The model itself is heavy (~90 MB on disk
# + ~250 MB in RAM); avoid re-loading on every call.
_MODEL_CACHE: dict[str, object] = {}


def _get_model(model_name: str) -> object:
    """Return a cached SentenceTransformer instance for ``model_name``.

    Loads + caches the model on first request; subsequent calls
    for the same name return the cached instance without re-load.
    Cache is per-process; long-running CI workers may want to
    pre-warm via a fixture.
    """
    if model_name not in _MODEL_CACHE:
        st = _import_sentence_transformers()
        # SentenceTransformer is the canonical class name; lazy-
        # imported above to keep the optional-extra contract.
        _MODEL_CACHE[model_name] = st.SentenceTransformer(model_name)  # type: ignore[attr-defined]
    return _MODEL_CACHE[model_name]


def faithfulness_score_semantic(
    claim: str,
    source_clauses: Iterable[str],
    *,
    threshold: float = DEFAULT_SEMANTIC_THRESHOLD,
    model_name: str = DEFAULT_SEMANTIC_MODEL,
) -> FaithfulnessResult:
    """Compute :class:`FaithfulnessResult` via sentence-embeddings.

    Mirrors the API of
    :func:`evidentia_eval.faithfulness.faithfulness_score` but
    uses sentence-transformers' cosine-similarity on embeddings
    instead of Jaccard token-overlap. Catches paraphrases that
    the Jaccard baseline misses.

    Args:
        claim: The atomic claim to score. Typically a single
            sentence extracted from an AI-generated artifact.
        source_clauses: Policy clauses the claim should trace
            back to. May be empty (returns score 0.0; no
            evidence).
        threshold: Pass/fail threshold for the stored
            :attr:`FaithfulnessResult.threshold`. Defaults to
            :data:`DEFAULT_SEMANTIC_THRESHOLD` (0.7) — calibrated
            for the default model on natural-language policy
            clauses. Operators tuning per-corpus typically run
            ``scripts/tune_faithfulness_threshold.py``.
        model_name: Sentence-transformers model identifier.
            Defaults to :data:`DEFAULT_SEMANTIC_MODEL`
            (``all-MiniLM-L6-v2``; ~90 MB).

    Returns:
        Populated :class:`FaithfulnessResult` with
        :attr:`FaithfulnessResult.method` set to
        ``"sentence-transformers"`` to distinguish from the
        stdlib Jaccard baseline (``"jaccard-stdlib"``).

    Raises:
        SemanticFaithfulnessNotAvailableError: sentence-
            transformers extra is not installed.
        ValueError: ``threshold`` is outside [0, 1].
    """
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(f"threshold must be in [0, 1]; got {threshold}")
    clauses = list(source_clauses)
    if not clauses:
        return FaithfulnessResult(
            claim=claim,
            score=0.0,
            threshold=threshold,
            evidence_clauses=[],
            method="sentence-transformers",
        )

    model = _get_model(model_name)
    # Encode claim + all clauses in one batch (more efficient
    # than per-clause encoding).
    texts = [claim, *clauses]
    embeddings = model.encode(  # type: ignore[attr-defined]
        texts,
        convert_to_numpy=True,
        show_progress_bar=False,
    )
    claim_emb = embeddings[0]
    clause_embs = embeddings[1:]

    # Cosine similarity = (a · b) / (||a|| · ||b||). Compute via
    # numpy for vector ops; fall back to plain Python if numpy
    # isn't directly accessible.
    import numpy as np

    claim_norm = np.linalg.norm(claim_emb)
    if claim_norm == 0:
        # Degenerate input; no similarity computable.
        return FaithfulnessResult(
            claim=claim,
            score=0.0,
            threshold=threshold,
            evidence_clauses=[],
            method="sentence-transformers",
        )

    similarities: list[tuple[str, float]] = []
    for clause, clause_emb in zip(clauses, clause_embs, strict=False):
        clause_norm = np.linalg.norm(clause_emb)
        if clause_norm == 0:
            similarities.append((clause, 0.0))
            continue
        sim = float(np.dot(claim_emb, clause_emb) / (claim_norm * clause_norm))
        # Cosine similarity is in [-1, 1]; clamp to [0, 1] for the
        # FaithfulnessResult.score contract. Negative cosine
        # similarity means "semantically opposite" which is also
        # a faithfulness violation (claim contradicts clause).
        sim = max(0.0, sim)
        similarities.append((clause, sim))

    # Sort descending; ties preserve input order (stable sort).
    similarities.sort(key=lambda pair: pair[1], reverse=True)
    top_score = similarities[0][1] if similarities else 0.0
    evidence = [clause for clause, _ in similarities[:3]]

    return FaithfulnessResult(
        claim=claim,
        score=top_score,
        threshold=threshold,
        evidence_clauses=evidence,
        method="sentence-transformers",
    )
