"""LLM-driven atomic-claim extraction (v0.8.3 P1.2).

Decomposes a generated artifact (risk statement, control
explanation, OSCAL narrative) into atomic verifiable claims for
faithfulness scoring. Reuses the v0.8.1 PRT decomposition pattern
without requiring the artifact to be a structured ``RiskStatement``
— operates on any raw text the operator wants to validate against
source policy clauses.

The DFAH harness (:meth:`evidentia_ai.eval.harness.DFAHarness.run`)
wires this in via the new ``check_faithfulness=True`` parameter.
For each prompt's generated output, the harness:

1. Calls :func:`extract_claims` to get a ``list[str]`` of atomic
   claims.
2. For each claim, calls
   :func:`evidentia_ai.eval.faithfulness.faithfulness_score` (or
   the semantic path if installed) against the operator-provided
   source clauses.
3. Per-claim scores below the threshold fire
   :attr:`evidentia_core.audit.EventAction.AI_EVAL_FAITHFULNESS_VIOLATION`;
   the run summary fires
   :attr:`evidentia_core.audit.EventAction.AI_EVAL_FAITHFULNESS_CHECKED`.

Tests inject a mock ``completion_fn`` so CI runs without an LLM
provider credential. Live-LLM integration tests opt-in via
``EVIDENTIA_LLM_INTEGRATION=1`` env var (deferred to v0.8.4).

References:
- v0.8.1 PRT pattern: ``evidentia_ai.risk_statements.RISK_STATEMENT_TRACE_PROMPT``
- §26.2 P1.2 / §26.3 step 7 (v0.8.3 cycle plan)
"""

from __future__ import annotations

from collections.abc import Callable

# v0.8.3 P1.2: claim-extraction prompt. Aligned with the v0.8.1
# PRT decomposition pattern (3-7 atomic claims; self-contained;
# no qualifications) but simpler — returns plain text, no
# Pydantic structure, no per-claim citations or confidence
# (those richer fields live on the v0.8.1 PRT path; the eval
# harness only needs the claim text for scoring).
CLAIM_EXTRACTION_PROMPT = """\
Decompose the following text into atomic claims, one per line.

Each claim must be:
1. **Self-contained** — interpretable without reading the
   surrounding text.
2. **Verifiable** — a single, concrete statement that can be
   checked against source material.
3. **Concise** — one sentence; no qualifications, hedges, or
   meta-commentary.

Return ONLY the list of claims, one per line. No bullet points,
no numbering, no preamble, no explanation. If the text contains
fewer than 3 distinct atomic claims, return only those. If the
text is empty or contains no factual claims, return an empty
response.

TEXT:
{text}

CLAIMS:
"""


def _default_completion_fn(
    *,
    model: str,
    messages: list[dict[str, str]],
    temperature: float,
) -> str:
    """Production LLM completion path via guarded LiteLLM.

    Tests inject a mock instead of using this; CI runs with
    no LLM provider credential are unaffected.
    """
    from evidentia_ai.client import _guarded_completion

    response = _guarded_completion(
        model=model,
        messages=messages,
        temperature=temperature,
    )
    # LiteLLM's response shape:
    # {"choices": [{"message": {"content": "..."}}]}
    return str(response.choices[0].message.content)


def extract_claims(
    generated_text: str,
    *,
    model: str | None = None,
    temperature: float = 0.0,
    max_claims: int = 10,
    completion_fn: Callable[..., str] | None = None,
) -> list[str]:
    """Extract atomic claims from generated text via LLM.

    Args:
        generated_text: The artifact (risk statement, control
            explanation, narrative) to decompose. Empty string
            returns ``[]``.
        model: LiteLLM model identifier (e.g., ``"gpt-4o"``,
            ``"claude-sonnet-4"``, ``"ollama/llama3"``).
            Defaults to ``$EVIDENTIA_LLM_MODEL`` env var or
            ``"gpt-4o"``.
        temperature: Sampling temperature. Default 0.0 for
            maximum determinism (atomic claims should be
            reproducible across runs).
        max_claims: Hard cap on returned list length. Default
            10 — atomic decomposition rarely needs more; if the
            LLM returns more, we truncate to keep the
            faithfulness check tractable.
        completion_fn: Dependency-injection point for the LLM
            call. Defaults to :func:`_default_completion_fn`
            (guarded LiteLLM). Tests inject a mock to avoid
            burning LLM tokens.

    Returns:
        ``list[str]`` of atomic claims, one per line. Empty
        list when ``generated_text`` is empty or the LLM
        returned no claims.
    """
    if not generated_text or not generated_text.strip():
        return []

    if completion_fn is None:
        completion_fn = _default_completion_fn

    if model is None:
        from evidentia_ai.client import get_default_model

        model = get_default_model()

    prompt = CLAIM_EXTRACTION_PROMPT.format(text=generated_text)
    messages: list[dict[str, str]] = [
        {"role": "user", "content": prompt},
    ]

    raw_response = completion_fn(
        model=model,
        messages=messages,
        temperature=temperature,
    )

    # Parse line-separated claims. Strip leading/trailing
    # whitespace; drop empty lines + meta-prefixes like "1." or
    # "- " that some models add despite the prompt instructing
    # otherwise. Defensive against the LLM ignoring the no-
    # numbering directive.
    claims: list[str] = []
    for raw_line in raw_response.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Strip common bullet/numbering prefixes.
        for prefix in ("- ", "* ", "• "):
            if line.startswith(prefix):
                line = line[len(prefix):].strip()
                break
        # Strip "N." or "N)" numbering at start.
        if len(line) >= 2 and line[0].isdigit():
            sep_idx = -1
            for i, ch in enumerate(line[:4]):
                if ch in ".)" and i > 0:
                    sep_idx = i
                    break
            if sep_idx > 0:
                rest = line[sep_idx + 1:].strip()
                if rest:
                    line = rest
        if line:
            claims.append(line)
        if len(claims) >= max_claims:
            break

    return claims
