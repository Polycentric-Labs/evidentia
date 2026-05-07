"""Real-LLM integration tests for DFAH faithfulness path (v0.8.5 P3).

Opt-in tests gated by ``EVIDENTIA_LLM_INTEGRATION=1`` env var.
Mocked-LLM unit tests (``tests/unit/test_eval/``) gate the
faithfulness library + harness wiring on every commit; these
integration tests exercise the same code paths against a real
LiteLLM endpoint to catch behavioral drift between the tested
mocks + actual LLM behavior.

Cost expectation: ~5-10 LLM calls per test run × ~$0.001 per
call ≈ $0.005–$0.05 per full run with gpt-4o-mini. Operators
who opt in MUST have LiteLLM env vars configured (e.g.,
``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY``) before invocation;
the tests do NOT consume credits without explicit opt-in.

Per the secret-handling protocol, these tests never accept
credentials in arguments — LLM provider creds are read from
LiteLLM env vars by the underlying ``_guarded_completion``.

Triggering the suite:

.. code-block:: bash

    EVIDENTIA_LLM_INTEGRATION=1 \
        ANTHROPIC_API_KEY=... \
        uv run pytest \
            tests/integration/test_eval/test_real_llm_extraction.py \
            -v

Tests assert STRUCTURAL properties (≥ N claims, each claim
≥ K tokens, score distributions trend in expected direction)
rather than exact-match strings — different LLM model versions
produce different claim splits, so exact-match would be flaky
across provider/model upgrades.

Plan: §28 v0.8.5 P3.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

LLM_INTEGRATION_ENABLED = os.environ.get("EVIDENTIA_LLM_INTEGRATION") == "1"

# Per-test skipif decorator (NOT module-level pytestmark) — the
# test_extract_claims_empty_input_returns_empty_list_no_llm_call
# test below intentionally runs always (no LLM call fires for
# empty input; verifies the cost-aware short-circuit).
_skip_if_no_llm = pytest.mark.skipif(
    not LLM_INTEGRATION_ENABLED,
    reason=(
        "Real-LLM integration tests are opt-in. Set "
        "EVIDENTIA_LLM_INTEGRATION=1 + LiteLLM provider env vars "
        "(ANTHROPIC_API_KEY / OPENAI_API_KEY / etc.) to enable. "
        "Tests consume real LLM credits — review cost expectation "
        "in test_real_llm_extraction.py docstring before opting in."
    ),
)


@_skip_if_no_llm
def test_extract_claims_real_llm_produces_claims() -> None:
    """``extract_claims()`` against a real LLM endpoint produces
    ≥ 2 atomic claims for a known multi-claim risk-statement
    fixture.

    Asserts STRUCTURAL properties (claim count, per-claim
    token count) rather than exact-match strings — different
    LLM models produce different splits.
    """
    from evidentia_ai.eval.claim_extraction import extract_claims

    # 3-claim risk-statement input. Whatever model the operator
    # runs against should split this into roughly 3 atomic
    # claims; we accept ≥ 2 to absorb model-specific variance.
    risk_text = (
        "The information system enforces approved authorizations "
        "for logical access. Account management procedures "
        "provision and deprovision accounts within 24 hours of "
        "role change. Multi-factor authentication is required "
        "for privileged accounts."
    )
    claims = extract_claims(risk_text)
    assert isinstance(claims, list), "extract_claims must return list"
    assert len(claims) >= 2, (
        f"Expected ≥ 2 claims from 3-claim input; got "
        f"{len(claims)}: {claims!r}"
    )
    for claim in claims:
        assert isinstance(claim, str), "each claim must be str"
        # ≥ 5 tokens per claim — guards against the LLM returning
        # one-word fragments.
        assert len(claim.split()) >= 5, (
            f"Claim too short (likely fragment): {claim!r}"
        )


def test_extract_claims_empty_input_returns_empty_list_no_llm_call() -> None:
    """Empty input short-circuits before any LLM call fires —
    cost-aware behavior. This test runs even without
    EVIDENTIA_LLM_INTEGRATION because the empty-input path
    never reaches the LLM.

    Inverted skip: this single test is allowed even without
    the env var (it's effectively a unit test in disguise).
    """
    from evidentia_ai.eval.claim_extraction import extract_claims

    assert extract_claims("") == []
    assert extract_claims("   ") == []


@_skip_if_no_llm
def test_dfa_harness_check_faithfulness_end_to_end_against_corpus() -> None:
    """End-to-end DFAHarness with check_faithfulness=True against
    a small corpus subset. Asserts per-claim score distribution
    trends in the expected direction (faithful entries score
    higher than unfaithful) without asserting exact thresholds.

    Loads 4 entries from corpus.jsonl (1 verbatim faithful, 1
    paraphrase faithful, 1 semi-related unfaithful, 1
    hallucination) → builds 1 EvalSample per entry → runs the
    harness with the real ``extract_claims`` + real
    ``faithfulness_score`` (jaccard).

    The jaccard scorer on stdlib (no LLM call) is deterministic;
    extract_claims fires once per sample and burns a small token
    budget. ~4 LLM calls total (one per sample's modal output).
    """
    from evidentia_ai.eval import (
        DFAHarness,
        EvalSample,
    )
    from evidentia_core.audit.provenance import (
        GenerationContext,
        compute_prompt_hash,
    )

    corpus_path = Path("tests/data/dfah-calibration/corpus.jsonl")
    assert corpus_path.is_file(), (
        "v0.8.3 P1.3 corpus must be present for integration test"
    )

    # Pick 4 representative entries.
    selected: list[dict[str, object]] = []
    seen_categories: set[str] = set()
    with corpus_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            cat = str(entry.get("category", ""))
            if cat in seen_categories:
                continue
            seen_categories.add(cat)
            selected.append(entry)
            if len(selected) == 4:
                break
    assert len(selected) == 4, (
        f"Expected 4 distinct categories; got {seen_categories}"
    )

    # Generator returns the corpus claim verbatim — the harness
    # then runs extract_claims on the modal output (=claim) and
    # scores against source_clauses.
    def _stub_generator(prompt: str, _ctx: GenerationContext) -> str:
        # prompt = entry["id"] (we set EvalSample.prompt = id).
        for entry in selected:
            if entry["id"] == prompt:
                return str(entry["claim"])
        raise KeyError(f"Unknown prompt: {prompt!r}")

    samples = [
        EvalSample(
            prompt_id=str(entry["id"]),
            prompt=str(entry["id"]),
            source_clauses=[
                str(c)
                for c in cast(list[object], entry["source_clauses"])
            ],
        )
        for entry in selected
    ]

    def _ctx_factory(prompt_id: str) -> GenerationContext:
        return GenerationContext(
            model="integration-stub",
            temperature=0.0,
            prompt_hash=compute_prompt_hash(
                "real-llm-integration-test", prompt_id
            ),
        )

    harness = DFAHarness(
        generator=_stub_generator,
        sample_count_per_prompt=1,
    )
    result = harness.run(
        samples=samples,
        context_factory=_ctx_factory,
        check_replay=False,
        check_faithfulness=True,
        faithfulness_threshold=0.3,
        faithfulness_method="jaccard",
    )

    assert len(result.faithfulness_results) == 4, (
        f"Expected 4 faithfulness results; got "
        f"{len(result.faithfulness_results)}"
    )
    # No exact-threshold asserts — different LLM models produce
    # different claim splits, so a verbatim-faithful entry might
    # score 0.6 with model A + 0.9 with model B. We just assert
    # the structure: each result has ≥ 1 claim scored.
    for pfr in result.faithfulness_results:
        assert len(pfr.claims) >= 1, (
            f"prompt_id={pfr.prompt_id!r} produced 0 scored claims"
        )


@_skip_if_no_llm
def test_dfa_harness_score_distribution_trend() -> None:
    """Run the harness across all 4 categories from corpus.jsonl
    + assert mean score for faithful entries > mean score for
    unfaithful entries.

    This is the canonical "scorer works" sanity check — if
    faithful entries average BELOW unfaithful entries, something
    is fundamentally broken (LLM extraction returning the wrong
    claims, scorer inverted, etc.).
    """
    from evidentia_ai.eval import (
        DFAHarness,
        EvalSample,
    )
    from evidentia_core.audit.provenance import (
        GenerationContext,
        compute_prompt_hash,
    )

    corpus_path = Path("tests/data/dfah-calibration/corpus.jsonl")
    samples_by_id: dict[str, dict[str, object]] = {}
    with corpus_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            samples_by_id[str(entry["id"])] = entry

    # Use full corpus for the trend signal.
    eval_samples = [
        EvalSample(
            prompt_id=str(entry["id"]),
            prompt=str(entry["id"]),
            source_clauses=[
                str(c)
                for c in cast(list[object], entry["source_clauses"])
            ],
        )
        for entry in samples_by_id.values()
    ]

    def _stub_generator(prompt: str, _ctx: GenerationContext) -> str:
        return str(samples_by_id[prompt]["claim"])

    def _ctx_factory(prompt_id: str) -> GenerationContext:
        return GenerationContext(
            model="integration-stub",
            temperature=0.0,
            prompt_hash=compute_prompt_hash(
                "real-llm-integration-test", prompt_id
            ),
        )

    harness = DFAHarness(
        generator=_stub_generator,
        sample_count_per_prompt=1,
    )
    result = harness.run(
        samples=eval_samples,
        context_factory=_ctx_factory,
        check_replay=False,
        check_faithfulness=True,
        faithfulness_threshold=0.3,
        faithfulness_method="jaccard",
    )

    faithful_scores: list[float] = []
    unfaithful_scores: list[float] = []
    for pfr in result.faithfulness_results:
        entry = samples_by_id[pfr.prompt_id]
        is_faithful = bool(entry["faithful"])
        for c in pfr.claims:
            if is_faithful:
                faithful_scores.append(c.score)
            else:
                unfaithful_scores.append(c.score)

    assert faithful_scores, "Expected at least one faithful claim"
    assert unfaithful_scores, (
        "Expected at least one unfaithful claim"
    )
    mean_faithful = sum(faithful_scores) / len(faithful_scores)
    mean_unfaithful = sum(unfaithful_scores) / len(unfaithful_scores)
    assert mean_faithful > mean_unfaithful, (
        f"Faithful claims should score higher on average than "
        f"unfaithful. faithful_mean={mean_faithful:.3f}, "
        f"unfaithful_mean={mean_unfaithful:.3f}. If this assert "
        f"fires, suspect: (a) LLM extract_claims returning wrong "
        f"claims, (b) scorer inverted, (c) source_clauses not "
        f"plumbed through correctly."
    )

    # Sanity: capture timestamp for log-grep correlation.
    print(
        f"\nReal-LLM trend test passed at "
        f"{datetime.now(UTC).isoformat()}: "
        f"faithful_mean={mean_faithful:.3f}, "
        f"unfaithful_mean={mean_unfaithful:.3f}, "
        f"faithful_n={len(faithful_scores)}, "
        f"unfaithful_n={len(unfaithful_scores)}"
    )
