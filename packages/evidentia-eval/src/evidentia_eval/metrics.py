"""Determinism + replay-equivalence metrics (v0.8.0 P0.1).

Two Pydantic result models + their compute functions:

- :class:`DeterminismResult` covers one prompt run N times.
  Reports the modal output's hash + per-sample hashes + the
  pass rate (fraction of samples matching the modal output).
- :class:`ReplayResult` covers a single replay attempt — was
  the re-run output byte-equivalent to the original (after
  normalization)?

Both models are JSON-serializable + survive Sigstore signing
(the harness output IS audit evidence; it's the artifact that
proves the operator ran the determinism check before
shipping).
"""

from __future__ import annotations

from collections import Counter

from evidentia_core.models.common import EvidentiaModel
from pydantic import Field

from evidentia_eval.seeds import hash_output


class DeterminismResult(EvidentiaModel):
    """One prompt's determinism outcome over N samples."""

    prompt_id: str = Field(
        description=(
            "Caller-supplied identifier for the prompt under "
            "test (e.g., 'risk-stmt-AC-2-meridian-fintech'). "
            "Used by the harness to correlate samples in the "
            "audit log + the JSON output."
        ),
    )
    sample_count: int = Field(
        ge=1,
        description=("Number of generation calls run for this prompt."),
    )
    sample_hashes: list[str] = Field(
        description=(
            "SHA-256 hex digests of each sample's normalized output, in call order. Length equals sample_count."
        ),
    )
    modal_hash: str = Field(
        description=(
            "Hash of the modal output (most-frequent output). When sample_count == 1 this is the only output."
        ),
    )
    modal_count: int = Field(
        ge=1,
        description=("Number of samples whose hash matches modal_hash. Determinism rate = modal_count / sample_count."),
    )
    distinct_outputs: int = Field(
        ge=1,
        description=(
            "Number of distinct normalized outputs across the "
            "samples. 1 = perfect determinism; sample_count = "
            "fully non-deterministic."
        ),
    )

    @property
    def determinism_rate(self) -> float:
        """Fraction of samples matching the modal output (0..1)."""
        return self.modal_count / self.sample_count

    @property
    def passed(self) -> bool:
        """True iff determinism_rate == 1.0 (perfect determinism)."""
        return self.distinct_outputs == 1


class ReplayResult(EvidentiaModel):
    """One prompt's replay-equivalence outcome.

    Replay equivalence is binary: re-running with a pinned
    ``GenerationContext`` (same model + temperature +
    prompt_hash + run_id) either produces a normalized output
    whose hash matches the original, or it does not.
    """

    prompt_id: str = Field(
        description=("Caller-supplied identifier for the prompt under test."),
    )
    original_hash: str = Field(
        description=("Hash of the original (first-run) normalized output."),
    )
    replay_hash: str = Field(
        description=("Hash of the replay-run normalized output."),
    )

    @property
    def equivalent(self) -> bool:
        """True iff replay_hash == original_hash."""
        return self.replay_hash == self.original_hash


def determinism_score(samples: list[str], prompt_id: str) -> DeterminismResult:
    """Compute :class:`DeterminismResult` from raw sample outputs.

    Args:
        samples: Raw outputs from N successive generation
            calls against the same prompt + context. Must be
            non-empty.
        prompt_id: Caller-supplied prompt identifier.

    Returns:
        Populated :class:`DeterminismResult`.

    Raises:
        ValueError: ``samples`` is empty.
    """
    if not samples:
        raise ValueError("determinism_score requires at least one sample")
    hashes = [hash_output(s) for s in samples]
    counter = Counter(hashes)
    modal_hash, modal_count = counter.most_common(1)[0]
    return DeterminismResult(
        prompt_id=prompt_id,
        sample_count=len(samples),
        sample_hashes=hashes,
        modal_hash=modal_hash,
        modal_count=modal_count,
        distinct_outputs=len(counter),
    )


def replay_equivalent(*, original: str, replay: str, prompt_id: str) -> ReplayResult:
    """Build a :class:`ReplayResult` from two raw outputs.

    Args:
        original: First-run output.
        replay: Re-run output (same context, fresh call).
        prompt_id: Caller-supplied prompt identifier.

    Returns:
        Populated :class:`ReplayResult`. The :attr:`equivalent`
        property answers the audit-relevant question.
    """
    return ReplayResult(
        prompt_id=prompt_id,
        original_hash=hash_output(original),
        replay_hash=hash_output(replay),
    )
