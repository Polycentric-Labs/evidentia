"""DFAH harness — orchestrates determinism + replay runs (v0.8.0 P0.1).

The harness is intentionally generator-agnostic: it accepts
any callable ``(prompt: str, context: GenerationContext) -> str``
so the same machinery validates risk statements, control
explanations, future PRT-traced outputs, and any third-party
plugin's AI-generated artifact production.

Live operator runs wire :meth:`evidentia_ai.risk_statements.
generator.RiskStatementGenerator.generate` (or equivalent) into
:meth:`DFAHarness.run`. CI runs against a deterministic stub
that returns a fixed string per prompt — proves the harness
mechanics work without burning LLM tokens.

Audit posture: every harness invocation emits a
:attr:`EventAction.AI_EVAL_STARTED` /
:attr:`EventAction.AI_EVAL_COMPLETED` pair, plus one
:attr:`EventAction.AI_EVAL_DETERMINISM_VIOLATION` per prompt
that fails the determinism gate. The
:attr:`EventAction.AI_EVAL_FAITHFULNESS_VIOLATION` event is
reserved ahead of time for the v0.8.1 faithfulness scoring
follow-up.

The :class:`EvalResult` output model is JSON-serializable +
Sigstore-signable — it IS audit evidence.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from typing import Any

from evidentia_core.audit import EventAction, EventOutcome, get_logger
from evidentia_core.audit.provenance import GenerationContext, new_run_id
from evidentia_core.models.common import EvidentiaModel, current_version, utc_now
from pydantic import Field

from evidentia_ai.eval.faithfulness import (
    DEFAULT_FAITHFULNESS_THRESHOLD,
    PromptFaithfulnessResult,
    faithfulness_score,
)
from evidentia_ai.eval.metrics import (
    DeterminismResult,
    ReplayResult,
    determinism_score,
)
from evidentia_ai.eval.seeds import hash_output

_log = get_logger("evidentia.ai.eval")


# A generator callable: takes a prompt string + context, returns
# the raw output string. The harness intentionally does not
# require the callable to return anything richer (e.g., a
# Pydantic model) so a stub generator is trivial to write.
GeneratorFn = Callable[[str, GenerationContext], str]


class EvalSample(EvidentiaModel):
    """One prompt's inputs (immutable; audit-trail-stable)."""

    prompt_id: str = Field(
        description=(
            "Caller-supplied identifier for the prompt. Should "
            "be unique within an EvalResult."
        ),
    )
    prompt: str = Field(
        description=(
            "The prompt text fed to the generator. Surfaces in "
            "the audit log so an auditor reviewing a CI failure "
            "can re-run the violating prompt by hand."
        ),
    )
    source_clauses: list[str] | None = Field(
        default=None,
        description=(
            "v0.8.4 P1: optional list of policy clauses the "
            "prompt's generated output should trace back to. "
            "Required for the harness's ``check_faithfulness=True`` "
            "path; the harness extracts atomic claims from the "
            "modal output via :func:`evidentia_ai.eval.claim_extraction.extract_claims` "
            "+ scores each claim against these source_clauses "
            "via :func:`evidentia_ai.eval.faithfulness.faithfulness_score`. "
            "When ``None``, the faithfulness check is skipped "
            "for this sample even if the harness was asked to "
            "run it. Backward-compatible: existing samples "
            "without source_clauses continue to work."
        ),
    )


class EvalResult(EvidentiaModel):
    """Top-level harness output covering all prompts in one run."""

    run_id: str = Field(
        description=(
            "ULID identifying this harness run. Threaded into "
            "every audit event the run emits."
        ),
    )
    started_at: datetime = Field(
        description="UTC timestamp when the harness started.",
    )
    completed_at: datetime = Field(
        description="UTC timestamp when the harness finished.",
    )
    evidentia_version: str = Field(
        description=(
            "Version of evidentia-core orchestrating the eval. "
            "Pinned so an auditor can reproduce the run."
        ),
    )
    sample_count_per_prompt: int = Field(
        ge=1,
        description=(
            "Number of generation calls per prompt for the "
            "determinism check."
        ),
    )
    samples: list[EvalSample] = Field(
        description="The prompts under test.",
    )
    determinism_results: list[DeterminismResult] = Field(
        description=(
            "One :class:`DeterminismResult` per prompt, in the "
            "same order as :attr:`samples`."
        ),
    )
    replay_results: list[ReplayResult] = Field(
        default_factory=list,
        description=(
            "Optional :class:`ReplayResult` per prompt. Empty "
            "when the harness was run without --check-replay."
        ),
    )
    faithfulness_results: list[PromptFaithfulnessResult] = Field(
        default_factory=list,
        description=(
            "v0.8.4 P1 wiring: optional per-prompt "
            ":class:`PromptFaithfulnessResult`. Empty when the "
            "harness was run without ``check_faithfulness=True`` "
            "OR no samples had ``source_clauses`` populated. "
            "When non-empty, contains one entry per sample "
            "whose source_clauses was set (samples without "
            "source_clauses are skipped per the harness "
            "contract)."
        ),
    )

    @property
    def overall_determinism_rate(self) -> float:
        """Sample-weighted mean determinism rate across prompts (0..1).

        Returns 1.0 on an empty result set (vacuously pass — the
        CLI requires at least one prompt so this branch is only
        hit by harness-internal callers).
        """
        if not self.determinism_results:
            return 1.0
        total_samples = sum(r.sample_count for r in self.determinism_results)
        modal_samples = sum(r.modal_count for r in self.determinism_results)
        return modal_samples / total_samples

    @property
    def determinism_violations(self) -> list[DeterminismResult]:
        """Determinism results that failed (any non-deterministic prompt)."""
        return [r for r in self.determinism_results if not r.passed]

    @property
    def replay_violations(self) -> list[ReplayResult]:
        """Replay results that failed (replay hash != original hash)."""
        return [r for r in self.replay_results if not r.equivalent]


class DFAHarness:
    """Run determinism + replay checks against a generator function.

    Args:
        generator: A callable taking ``(prompt, context)`` and
            returning the raw output string.
        sample_count_per_prompt: How many times to invoke
            ``generator`` per prompt for the determinism check.
            Default 5 — enough to catch obvious non-determinism
            without burning excessive LLM tokens.

    The harness DOES NOT manage retries, timeouts, or LLM
    provider config — those are the caller's concern. The
    contract is "give me a callable that produces strings; I'll
    run it N times + measure".

    RESOURCE BOUNDS (v0.8.1 F-V08-S4 defense-in-depth note):
    the harness fires ``sample_count_per_prompt × len(samples)``
    generator calls with no per-call timeout, no aggregate-
    time budget, and no token-budget tracking. A pathological
    generator (third-party plugin, custom CLI script) can
    exhaust CPU / memory / LLM-token-budget. This is by design
    — the harness is a library API the operator wires up; the
    operator owns the resource discipline. Recommended
    operator-side guardrails:

    1. Wrap third-party generators in a
       :class:`concurrent.futures.ThreadPoolExecutor` with a
       per-call timeout via ``Future.result(timeout=...)``.
    2. Configure the LLM provider's per-request timeout +
       max-tokens at the caller (LiteLLM env vars or
       ``RiskStatementGenerator(...)`` constructor args).
    3. Cap ``sample_count_per_prompt`` based on the corpus
       size — 5 × 50 = 250 LLM calls; budget accordingly.

    A future v0.8.x slice may add a ``max_total_calls`` +
    ``per_call_timeout_seconds`` kwarg as first-class
    safeguards; for now the operator owns the guardrails.
    """

    def __init__(
        self,
        *,
        generator: GeneratorFn,
        sample_count_per_prompt: int = 5,
    ) -> None:
        if sample_count_per_prompt < 1:
            raise ValueError(
                f"sample_count_per_prompt must be >= 1; got "
                f"{sample_count_per_prompt}"
            )
        self._generator = generator
        self._sample_count = sample_count_per_prompt

    def run(
        self,
        *,
        samples: list[EvalSample],
        context_factory: Callable[[str], GenerationContext],
        check_replay: bool = False,
        check_faithfulness: bool = False,
        faithfulness_threshold: float = DEFAULT_FAITHFULNESS_THRESHOLD,
        faithfulness_method: str = "jaccard",
        claim_extraction_fn: Callable[[str], list[str]] | None = None,
        faithfulness_score_fn: Callable[[str, list[str], float], object] | None = None,
    ) -> EvalResult:
        """Run the harness across all prompts.

        Args:
            samples: Prompts under test. The harness fires
                ``sample_count_per_prompt`` calls per sample
                for the determinism check.
            context_factory: Builds a fresh
                :class:`GenerationContext` per prompt — the
                harness threads this through to the generator
                so the audit chain ties back to a specific
                ``model + temperature + prompt_hash``.
            check_replay: When True, the harness fires one
                additional generation call per prompt with a
                pinned context (re-using the same ``run_id``
                + prompt_hash from the first call) and
                compares the output's hash to the determinism
                modal hash.

        Returns:
            Populated :class:`EvalResult`. Every prompt
            contributes exactly one :class:`DeterminismResult`
            entry; replay results are present iff ``check_replay``.
        """
        run_id = new_run_id()
        started_at = utc_now()
        _log.info(
            action=EventAction.AI_EVAL_STARTED,
            outcome=EventOutcome.UNKNOWN,
            message=(
                f"DFAH eval started — {len(samples)} prompt(s), "
                f"{self._sample_count} sample(s) per prompt"
            ),
            evidentia={
                "run_id": run_id,
                "sample_count_per_prompt": self._sample_count,
                "prompt_count": len(samples),
                "check_replay": check_replay,
            },
        )

        determinism_results: list[DeterminismResult] = []
        replay_results: list[ReplayResult] = []
        faithfulness_results: list[PromptFaithfulnessResult] = []

        # v0.8.4 P1: resolve the claim-extraction + faithfulness-
        # scoring callables ONCE up front. Tests inject mocks via
        # the kwargs; production resolves to the canonical library
        # functions.
        if check_faithfulness:
            from evidentia_ai.eval.claim_extraction import (
                extract_claims as _real_extract_claims,
            )

            resolved_extract: Callable[[str], list[str]]
            if claim_extraction_fn is None:
                # Default: use the real LLM-driven extraction.
                # Tests inject a mock to avoid LLM token burn.
                def _default_extract(text: str) -> list[str]:
                    return _real_extract_claims(text)

                resolved_extract = _default_extract
            else:
                resolved_extract = claim_extraction_fn

            if faithfulness_score_fn is None:
                if faithfulness_method == "semantic":
                    from evidentia_ai.eval.faithfulness_semantic import (
                        faithfulness_score_semantic as _semantic_fn,
                    )

                    def _default_score(
                        claim: str,
                        clauses: list[str],
                        threshold: float,
                    ) -> object:
                        return _semantic_fn(
                            claim, clauses, threshold=threshold
                        )

                    resolved_score: Callable[..., object] = (
                        _default_score
                    )
                else:
                    # Default: stdlib Jaccard.
                    def _default_score_jaccard(
                        claim: str,
                        clauses: list[str],
                        threshold: float,
                    ) -> object:
                        return faithfulness_score(
                            claim, clauses, threshold=threshold
                        )

                    resolved_score = _default_score_jaccard
            else:
                resolved_score = faithfulness_score_fn

        for sample in samples:
            outputs: list[str] = []
            ctx = context_factory(sample.prompt_id)
            for _ in range(self._sample_count):
                outputs.append(self._generator(sample.prompt, ctx))
            det_result = determinism_score(outputs, prompt_id=sample.prompt_id)
            determinism_results.append(det_result)
            if not det_result.passed:
                _log.warning(
                    action=EventAction.AI_EVAL_DETERMINISM_VIOLATION,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"Determinism violation on prompt "
                        f"{sample.prompt_id!r}: "
                        f"{det_result.distinct_outputs} distinct "
                        f"outputs across {det_result.sample_count} "
                        f"samples"
                    ),
                    evidentia={
                        "run_id": run_id,
                        "prompt_id": sample.prompt_id,
                        "distinct_outputs": det_result.distinct_outputs,
                        "modal_count": det_result.modal_count,
                        "sample_count": det_result.sample_count,
                        "determinism_rate": det_result.determinism_rate,
                    },
                )
            if check_replay:
                # Use the same context for the replay so model +
                # temperature + prompt_hash are pinned. Compare
                # against the determinism MODAL hash (most-frequent
                # sample) rather than outputs[0] — when the first
                # sample happened to be a determinism outlier, the
                # modal hash is what canonical replay should match.
                # v0.8.0 P0.1 review fix (F7).
                replay_output = self._generator(sample.prompt, ctx)
                replay_hash = hash_output(replay_output)
                replay_result = ReplayResult(
                    prompt_id=sample.prompt_id,
                    original_hash=det_result.modal_hash,
                    replay_hash=replay_hash,
                )
                replay_results.append(replay_result)

            # v0.8.4 P1: faithfulness check. Skips samples
            # without source_clauses (backward-compat). Uses the
            # MODAL output (post-determinism) so we score the
            # canonical generation, not a noise sample.
            if check_faithfulness and sample.source_clauses:
                # Find the modal output by re-using the modal_hash
                # → matching the first sample whose hash equals
                # det_result.modal_hash. (Same modal-tied logic
                # as check_replay above.)
                modal_output = next(
                    (
                        o
                        for o in outputs
                        if hash_output(o) == det_result.modal_hash
                    ),
                    outputs[0],
                )
                claims = resolved_extract(modal_output)
                claim_results: list[Any] = []
                for claim in claims:
                    cr = resolved_score(
                        claim,
                        sample.source_clauses,
                        faithfulness_threshold,
                    )
                    claim_results.append(cr)
                    # Per-claim violation event.
                    if not cr.passed:  # type: ignore[attr-defined]
                        _log.warning(
                            action=EventAction.AI_EVAL_FAITHFULNESS_VIOLATION,
                            outcome=EventOutcome.FAILURE,
                            message=(
                                f"Faithfulness violation on prompt "
                                f"{sample.prompt_id!r}, claim "
                                f"{claim!r}: score "
                                f"{cr.score:.3f} < threshold "  # type: ignore[attr-defined]
                                f"{faithfulness_threshold:.3f}"
                            ),
                            evidentia={
                                "run_id": run_id,
                                "prompt_id": sample.prompt_id,
                                "claim": claim,
                                "score": cr.score,  # type: ignore[attr-defined]
                                "threshold": faithfulness_threshold,
                                "method": faithfulness_method,
                            },
                        )
                pfr = PromptFaithfulnessResult(
                    prompt_id=sample.prompt_id,
                    claims=claim_results,
                )
                faithfulness_results.append(pfr)
                # Per-prompt CHECKED event (fired even when all
                # claims pass — distinguishes "we ran the check"
                # from "we found a violation").
                _log.info(
                    action=EventAction.AI_EVAL_FAITHFULNESS_CHECKED,
                    outcome=(
                        EventOutcome.SUCCESS
                        if pfr.overall_faithful
                        else EventOutcome.FAILURE
                    ),
                    message=(
                        f"Faithfulness check completed on prompt "
                        f"{sample.prompt_id!r}: "
                        f"{pfr.passed_count}/{len(pfr.claims)} "
                        f"claims passed (method "
                        f"{faithfulness_method})"
                    ),
                    evidentia={
                        "run_id": run_id,
                        "prompt_id": sample.prompt_id,
                        "claim_count": len(pfr.claims),
                        "passed_count": pfr.passed_count,
                        "failed_count": pfr.failed_count,
                        "overall_faithful": pfr.overall_faithful,
                        "method": faithfulness_method,
                    },
                )

        completed_at = utc_now()
        result = EvalResult(
            run_id=run_id,
            started_at=started_at,
            completed_at=completed_at,
            evidentia_version=current_version(),
            sample_count_per_prompt=self._sample_count,
            samples=samples,
            determinism_results=determinism_results,
            replay_results=replay_results,
            faithfulness_results=faithfulness_results,
        )

        violations = result.determinism_violations
        replay_violations = result.replay_violations
        all_pass = not violations and not replay_violations
        _log.info(
            action=EventAction.AI_EVAL_COMPLETED,
            outcome=(
                EventOutcome.SUCCESS if all_pass else EventOutcome.FAILURE
            ),
            message=(
                f"DFAH eval completed — overall determinism rate "
                f"{result.overall_determinism_rate:.4f}; "
                f"{len(violations)} determinism violation(s); "
                f"{len(replay_violations)} replay violation(s)"
            ),
            evidentia={
                "run_id": run_id,
                "overall_determinism_rate": (
                    result.overall_determinism_rate
                ),
                "determinism_violations": len(violations),
                "replay_violations": len(replay_violations),
                "prompt_count": len(samples),
            },
        )
        return result
