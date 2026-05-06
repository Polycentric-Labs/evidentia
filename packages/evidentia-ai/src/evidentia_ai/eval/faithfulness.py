"""DFAH faithfulness scoring (v0.8.2 §25.2 P3.1).

Second arXiv 2601.15322 metric, alongside the v0.8.0 determinism +
replay-equivalence gates. Faithfulness asks: do the claims in a
generated risk statement (or any AI-produced artifact) trace back
to the source policy clauses, or did the LLM hallucinate content
not present in the input?

Methodology (v0.8.2 stdlib baseline):

The :func:`faithfulness_score` function uses a Jaccard token-
overlap similarity over a normalized lowercase token set. For a
given claim and a list of source clauses, we compute the
similarity between the claim and each clause, then return the
maximum similarity as the faithfulness score. The top-3
clauses (by similarity) are returned as evidence so an auditor
reviewing a low-faithfulness flag can see what the LLM was
plausibly riffing on.

The Jaccard baseline is intentionally conservative — it catches
gross hallucinations (claims with zero token overlap to any
clause) but misses paraphrases. Operators wanting semantic-
similarity scoring can install the optional
``[eval-faithfulness]`` extra carrying ``sentence-transformers``;
when present, :func:`faithfulness_score_semantic` (v0.8.3 work)
will use sentence embeddings instead. For v0.8.2 we ship the
stdlib path as the floor; semantic upgrades are additive.

The result model :class:`FaithfulnessResult` is JSON-serializable
+ Sigstore-signable as part of the wider DFAH eval output.
Per-claim scores below the configurable threshold (default 0.3
for the stdlib Jaccard baseline; semantic scoring would tune
the default upward) emit
:attr:`EventAction.AI_EVAL_FAITHFULNESS_VIOLATION` for audit
visibility.

References:
- arXiv 2601.15322: DFAH framework
- :class:`evidentia_ai.eval.metrics.DeterminismResult` —
  pattern this model mirrors
- §25.2 P3.1: v0.8.2 cycle plan
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from evidentia_core.models.common import EvidentiaModel
from pydantic import Field

# Default threshold for the stdlib Jaccard token-overlap baseline.
# 0.3 is conservative — Jaccard scores tend to be lower than
# semantic-similarity scores for paraphrases. A semantic
# (sentence-transformers) implementation would raise this to ~0.7.
DEFAULT_FAITHFULNESS_THRESHOLD: float = 0.3

# Token-extraction regex: ASCII alphanumerics in word-boundary
# groups. This intentionally drops punctuation, whitespace, and
# Unicode (control IDs and policy clauses are ASCII by
# convention). The lower-casing happens after extraction.
_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")


class FaithfulnessResult(EvidentiaModel):
    """One claim's faithfulness outcome.

    Computed by :func:`faithfulness_score`. The :attr:`passed`
    property answers the audit-relevant binary question; the
    :attr:`score` + :attr:`evidence_clauses` fields support
    deeper inspection when a claim fails the threshold.
    """

    claim: str = Field(
        description=(
            "The atomic claim under evaluation — typically a "
            "sentence extracted from a generated risk statement "
            "or other AI-produced artifact."
        ),
    )
    score: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "Faithfulness score in [0, 1]. 1.0 = the claim's "
            "tokens fully overlap with at least one source "
            "clause; 0.0 = no token overlap with any clause "
            "(strong hallucination signal)."
        ),
    )
    threshold: float = Field(
        ge=0.0,
        le=1.0,
        description=(
            "The threshold this score was evaluated against. "
            "Stored on the result so an auditor reviewing the "
            "JSON output can re-derive the pass/fail outcome "
            "without consulting the original CLI invocation."
        ),
    )
    evidence_clauses: list[str] = Field(
        description=(
            "Up to 3 source clauses with the highest similarity "
            "to the claim, sorted descending. The first entry "
            "is the clause that supplied the :attr:`score`; the "
            "rest are returned for auditor context. Empty when "
            "no source clauses were provided."
        ),
    )
    method: str = Field(
        default="jaccard-stdlib",
        description=(
            "Identifier for the scoring method. v0.8.2 ships "
            "``jaccard-stdlib`` (token-overlap baseline). Future "
            "semantic-similarity paths will register under "
            "``sentence-transformers`` or similar identifiers."
        ),
    )

    @property
    def passed(self) -> bool:
        """True iff :attr:`score` >= :attr:`threshold`."""
        return self.score >= self.threshold


class PromptFaithfulnessResult(EvidentiaModel):
    """Per-prompt faithfulness aggregation (v0.8.4 P1 wiring).

    Carries the per-claim FaithfulnessResult list for one prompt
    plus pass/fail aggregations. Auditors filter by
    :attr:`overall_faithful` for fast triage; auditors digging
    into a low-score case use :attr:`claims` to see exactly
    which atomic claim failed + what evidence clauses were
    closest.

    Populated by :meth:`evidentia_ai.eval.harness.DFAHarness.run`
    when ``check_faithfulness=True`` and the corresponding
    :class:`EvalSample` has ``source_clauses`` set. Pairs with
    the v0.8.0-reserved + v0.8.4-activated audit events:
    ``AI_EVAL_FAITHFULNESS_CHECKED`` (per-prompt; fired even
    when all claims pass) + ``AI_EVAL_FAITHFULNESS_VIOLATION``
    (per below-threshold claim).
    """

    prompt_id: str = Field(
        description=(
            "Caller-supplied identifier for the prompt under "
            "test (matches :class:`EvalSample.prompt_id`)."
        ),
    )
    claims: list[FaithfulnessResult] = Field(
        description=(
            "One :class:`FaithfulnessResult` per atomic claim "
            "extracted from the prompt's modal output. Empty "
            "when claim extraction returned no claims (empty "
            "input or LLM returned empty response)."
        ),
    )

    @property
    def overall_faithful(self) -> bool:
        """True iff every claim passed its threshold.

        Empty-claims case (no atomic claims extracted) treats
        as ``True`` (vacuously faithful — there's nothing to
        contradict the source). Operators wanting stricter
        semantics filter on ``len(claims) > 0`` separately.
        """
        return all(c.passed for c in self.claims)

    @property
    def passed_count(self) -> int:
        """Number of claims that passed their threshold."""
        return sum(1 for c in self.claims if c.passed)

    @property
    def failed_count(self) -> int:
        """Number of claims that failed their threshold."""
        return sum(1 for c in self.claims if not c.passed)


def _tokenize(text: str) -> set[str]:
    """Extract a lowercase token set from ``text``.

    Uses :data:`_TOKEN_RE` to match ASCII-alphanumeric tokens
    only — punctuation, whitespace, and non-ASCII characters
    are dropped. The empty-string and pure-punctuation inputs
    return an empty set, which the Jaccard formula handles by
    returning 0.0 (no overlap possible).
    """
    return {match.group(0).lower() for match in _TOKEN_RE.finditer(text)}


def _jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity between two token sets.

    ``|A ∩ B| / |A ∪ B|``. Returns 0.0 for two empty sets
    (avoids ZeroDivisionError; matches the "no overlap"
    interpretation operators expect).
    """
    if not a and not b:
        return 0.0
    intersection = a & b
    union = a | b
    return len(intersection) / len(union)


def faithfulness_score(
    claim: str,
    source_clauses: Iterable[str],
    *,
    threshold: float = DEFAULT_FAITHFULNESS_THRESHOLD,
) -> FaithfulnessResult:
    """Compute :class:`FaithfulnessResult` for one claim.

    For each source clause, compute the Jaccard token-overlap
    similarity between ``claim`` and the clause. Return a result
    whose :attr:`score` is the MAX similarity across all clauses
    + whose :attr:`evidence_clauses` are the top-3 clauses by
    similarity (descending).

    Args:
        claim: The atomic claim to score. Typically a single
            sentence extracted from an AI-generated artifact.
        source_clauses: The policy clauses the claim should
            trace back to. May be empty (returns score 0.0,
            no evidence).
        threshold: Pass/fail threshold for the stored
            :attr:`FaithfulnessResult.threshold`. Defaults to
            :data:`DEFAULT_FAITHFULNESS_THRESHOLD` (0.3 for the
            Jaccard baseline). Operators tuning for a paraphrase-
            heavy corpus typically lower this; tuning for a
            verbatim-quote corpus typically raise it.

    Returns:
        Populated :class:`FaithfulnessResult`. The
        :attr:`passed` property answers the binary CI gate.

    Raises:
        ValueError: ``threshold`` is outside [0, 1].
    """
    if not (0.0 <= threshold <= 1.0):
        raise ValueError(
            f"threshold must be in [0, 1]; got {threshold}"
        )
    clauses = list(source_clauses)
    claim_tokens = _tokenize(claim)

    # Score each clause; preserve original-clause order in ties.
    scored: list[tuple[str, float]] = [
        (clause, _jaccard(claim_tokens, _tokenize(clause)))
        for clause in clauses
    ]
    # Sort descending by score; stable on ties (preserves input
    # order, which is the conventional auditor-friendly default).
    scored.sort(key=lambda pair: pair[1], reverse=True)

    if scored:
        top_score = scored[0][1]
        # Top-3 evidence clauses; descending score order.
        evidence = [clause for clause, _ in scored[:3]]
    else:
        top_score = 0.0
        evidence = []

    return FaithfulnessResult(
        claim=claim,
        score=top_score,
        threshold=threshold,
        evidence_clauses=evidence,
    )
