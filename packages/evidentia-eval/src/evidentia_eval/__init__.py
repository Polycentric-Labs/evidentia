"""evidentia-eval — DFAH determinism + faithfulness harness for Evidentia.

Decision-Faithfulness Assessment Harness per arXiv 2601.15322.
Validates that risk-statement generation (or any AI-driven
artifact production) is auditor-defensibly stable: same input +
same model + same temperature produces the same output, and a
re-run with pinned ``(input, model, temperature, prompt_hash,
run_id)`` is byte-equivalent to the original.

Three metrics ship:

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
- **Faithfulness** — do the atomic claims in a generated artifact
  trace back to source policy clauses? Stdlib Jaccard baseline
  (always available) + optional sentence-transformers semantic
  path (``[faithfulness-semantic]`` extra).

Public API:

- :class:`DFAHarness` — owns the run loop + audit emit.
- :class:`DeterminismResult` — Pydantic model summarizing one
  prompt's determinism outcome (modal output + pass rate +
  per-sample hashes).
- :class:`ReplayResult` — Pydantic model summarizing replay-
  equivalence for a single ``GenerationContext`` re-run.
- :class:`EvalResult` — top-level harness output covering all
  prompts in one ``run_id``.
- :class:`FaithfulnessResult` — per-claim faithfulness outcome.
- :class:`PromptFaithfulnessResult` — aggregated per-prompt
  faithfulness outcome.
- :func:`faithfulness_score` — stdlib Jaccard token-overlap
  baseline.
- :func:`faithfulness_score_semantic` — sentence-transformers
  semantic-similarity path (opt-in extra).
- :func:`extract_claims` — atomic-claim extraction from generated
  artifacts.
- :func:`normalize_for_determinism` — canonical normalization
  (whitespace + punctuation) used by the determinism check.
- :func:`hash_output` — SHA-256 hex of normalized output.
- :func:`sign_eval_result` / :func:`verify_eval_result` —
  Sigstore-sign + verify the eval output.

The harness is generator-agnostic: it accepts any callable
``(prompt: str, context: GenerationContext) -> str`` so the
same machinery validates risk statements, control
explanations, future PRT-traced outputs, and any third-party
plugin's AI-generated artifacts. Unit tests use a deterministic
fake generator; live operator runs wire in
``evidentia_ai.risk_statements.RiskStatementGenerator.generate``.

v0.10.5 P9 extraction: this package was carved out of
``evidentia_ai.eval.*`` to keep air-gap installs of the
risk-statement runtime from pulling sentence-transformers /
numpy / instructor heavy-dep stacks. The dev-time eval harness
now installs separately (or via ``pip install
evidentia-eval[faithfulness-semantic]`` for the optional
semantic path). v0.12.0 completed the extraction by removing the
``evidentia_ai.eval.*`` re-export shims and the unconditional
``evidentia-eval`` dependency on ``evidentia-ai``; this module is
the sole supported import path.
"""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

from evidentia_eval.claim_extraction import (
    CLAIM_EXTRACTION_PROMPT,
    extract_claims,
)
from evidentia_eval.faithfulness import (
    DEFAULT_FAITHFULNESS_THRESHOLD,
    FaithfulnessResult,
    PromptFaithfulnessResult,
    faithfulness_score,
)
from evidentia_eval.faithfulness_semantic import (
    DEFAULT_SEMANTIC_MODEL,
    DEFAULT_SEMANTIC_THRESHOLD,
    SemanticFaithfulnessNotAvailableError,
    faithfulness_score_semantic,
)
from evidentia_eval.harness import DFAHarness, EvalResult, EvalSample
from evidentia_eval.metrics import (
    DeterminismResult,
    ReplayResult,
    determinism_score,
    replay_equivalent,
)
from evidentia_eval.seeds import hash_output, normalize_for_determinism
from evidentia_eval.signing import (
    sign_eval_result,
    verify_eval_result,
)

try:
    __version__ = _pkg_version("evidentia-eval")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0+unknown"

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
    "PromptFaithfulnessResult",
    "ReplayResult",
    "SemanticFaithfulnessNotAvailableError",
    "__version__",
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
