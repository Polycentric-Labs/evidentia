"""DFAH determinism harness — `evidentia eval` (v0.8.0 P0.1).

Decision-Faithfulness Assessment Harness per arXiv 2601.15322.
Validates that risk-statement generation (or any AI-driven
artifact production) is auditor-defensibly stable: same input +
same model + same temperature produces the same output, and a
re-run with pinned ``(input, model, temperature, prompt_hash,
run_id)`` is byte-equivalent to the original.

Two metrics ship in v0.8.0:

- **Decision determinism** — same prompt produces the same
  normalized output across N samples. The pass rate is the
  fraction of samples that match the modal output (modulo
  whitespace + punctuation normalization). Reported as a 0..1
  score; CI-gateable via
  ``evidentia eval --fail-on-determinism-rate-below 0.95``.
- **Replay equivalence** — re-running with a pinned context
  (``GenerationContext`` instance) produces an output whose
  SHA-256 hash matches the original. Either the run is replay-
  equivalent or it isn't — there is no graceful degradation.

Faithfulness scoring (do generated claims trace back to the
input control + system context?) is the v0.8.1 follow-up. The
``AI_EVAL_FAITHFULNESS_VIOLATION`` audit event is reserved
ahead of time.

Public API:

- :class:`DFAHarness` — owns the run loop + audit emit.
- :class:`DeterminismResult` — Pydantic model summarizing one
  prompt's determinism outcome (modal output + pass rate +
  per-sample hashes).
- :class:`ReplayResult` — Pydantic model summarizing replay-
  equivalence for a single ``GenerationContext`` re-run.
- :class:`EvalResult` — top-level harness output covering all
  prompts in one ``run_id``.
- :func:`normalize_for_determinism` — canonical normalization
  (whitespace + punctuation) used by the determinism check.
- :func:`hash_output` — SHA-256 hex of normalized output.

The harness is generator-agnostic: it accepts any callable
``(prompt: str, context: GenerationContext) -> str`` so the
same machinery validates risk statements, control
explanations, future PRT-traced outputs, and any third-party
plugin's AI-generated artifacts. Unit tests use a deterministic
fake generator; live operator runs wire in
``evidentia_ai.risk_statements.RiskStatementGenerator.generate``.
"""

from __future__ import annotations

from evidentia_ai.eval.claim_extraction import (
    CLAIM_EXTRACTION_PROMPT,
    extract_claims,
)
from evidentia_ai.eval.faithfulness import (
    DEFAULT_FAITHFULNESS_THRESHOLD,
    FaithfulnessResult,
    faithfulness_score,
)
from evidentia_ai.eval.faithfulness_semantic import (
    DEFAULT_SEMANTIC_MODEL,
    DEFAULT_SEMANTIC_THRESHOLD,
    SemanticFaithfulnessNotAvailableError,
    faithfulness_score_semantic,
)
from evidentia_ai.eval.harness import DFAHarness, EvalResult, EvalSample
from evidentia_ai.eval.metrics import (
    DeterminismResult,
    ReplayResult,
    determinism_score,
    replay_equivalent,
)
from evidentia_ai.eval.seeds import hash_output, normalize_for_determinism
from evidentia_ai.eval.signing import (
    sign_eval_result,
    verify_eval_result,
)

__all__ = [
    "CLAIM_EXTRACTION_PROMPT",
    "DEFAULT_FAITHFULNESS_THRESHOLD",
    "DEFAULT_SEMANTIC_MODEL",
    "DEFAULT_SEMANTIC_THRESHOLD",
    "DFAHarness",
    "DeterminismResult",
    "EvalResult",
    "EvalSample",
    "FaithfulnessResult",
    "ReplayResult",
    "SemanticFaithfulnessNotAvailableError",
    "determinism_score",
    "extract_claims",
    "faithfulness_score",
    "faithfulness_score_semantic",
    "hash_output",
    "normalize_for_determinism",
    "replay_equivalent",
    "sign_eval_result",
    "verify_eval_result",
]
