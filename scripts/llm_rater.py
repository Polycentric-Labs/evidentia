"""LLM-assisted faithfulness rater for DFAH calibration corpus (v0.9.1 P2).

Classifies corpus entries as faithful/unfaithful using a configured LLM.
Deterministic (temperature=0). Results are persisted to a JSONL sidecar
file for reproducibility and audit.

Usage (standalone):

    EVIDENTIA_LLM_MODEL=gpt-4o uv run python scripts/llm_rater.py \
        --corpus tests/data/dfah-calibration/corpus.jsonl \
        --output tests/data/dfah-calibration/labels-llm-rater.jsonl

The output file satisfies the ``--rater2`` format expected by
``compute_inter_rater_kappa.py``.

Integration with kappa script (v0.9.1):

    uv run python scripts/compute_inter_rater_kappa.py \
        --rater1 tests/data/dfah-calibration/corpus.jsonl \
        --rater2 tests/data/dfah-calibration/labels-llm-rater.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

_SYSTEM_PROMPT = """\
You are a compliance-engineering faithfulness evaluator. Your task is to \
determine whether a CLAIM is faithfully supported by the provided SOURCE \
CLAUSES.

A claim is FAITHFUL if and only if:
- Every factual assertion in the claim can be directly traced to or \
logically inferred from the source clauses.
- The claim does not introduce information, specifics, or assertions \
that go beyond what the source clauses state or imply.

A claim is UNFAITHFUL if:
- It introduces facts, numbers, or assertions not present in the sources.
- It misattributes information from one source to another context.
- It contradicts the source clauses.
- It makes definitive claims where the sources are uncertain or qualified.

Respond with EXACTLY one JSON object on a single line:
{"faithful": true} or {"faithful": false}

Do not include any other text, explanation, or formatting."""

_USER_PROMPT_TEMPLATE = """\
SOURCE CLAUSES:
{source_clauses}

CLAIM:
{claim}

Is this claim faithfully supported by the source clauses above?"""


def _build_user_prompt(entry: dict[str, Any]) -> str:
    clauses = entry.get("source_clauses", [])
    formatted = "\n".join(f"- {c}" for c in clauses) if isinstance(clauses, list) else str(clauses)
    claim = str(entry.get("claim", ""))
    return _USER_PROMPT_TEMPLATE.format(
        source_clauses=formatted, claim=claim
    )


def _call_llm(
    model: str, system_prompt: str, user_prompt: str
) -> bool:
    """Call the LLM and parse a faithful/unfaithful boolean response."""
    import litellm

    litellm.suppress_debug_info = True

    response = litellm.completion(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0,
        max_tokens=50,
    )
    text = response.choices[0].message.content.strip()
    try:
        parsed = json.loads(text)
        return bool(parsed.get("faithful", False))
    except (json.JSONDecodeError, AttributeError):
        lower = text.lower()
        return bool("true" in lower or '"faithful": true' in lower)


def rate_corpus(
    corpus_path: Path,
    output_path: Path,
    model: str | None = None,
    max_retries: int = 3,
    delay_between: float = 0.5,
) -> dict[str, bool]:
    """Rate all entries in a corpus file and write results.

    Returns a dict of {id: faithful_bool} for all successfully rated entries.
    """
    if model is None:
        model = os.environ.get("EVIDENTIA_LLM_MODEL", "gpt-4o")

    entries: list[dict[str, Any]] = []
    with corpus_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                entries.append(json.loads(line))

    results: dict[str, bool] = {}
    output_lines: list[str] = []

    for i, entry in enumerate(entries):
        entry_id = str(entry.get("id", f"line-{i}"))
        user_prompt = _build_user_prompt(entry)

        label: bool | None = None
        for attempt in range(max_retries):
            try:
                label = _call_llm(model, _SYSTEM_PROMPT, user_prompt)
                break
            except Exception as exc:
                if attempt < max_retries - 1:
                    print(
                        f"  retry {attempt + 1}/{max_retries} for "
                        f"{entry_id}: {exc}",
                        file=sys.stderr,
                    )
                    time.sleep(delay_between * (attempt + 1))
                else:
                    print(
                        f"  FAILED after {max_retries} attempts for "
                        f"{entry_id}: {exc}",
                        file=sys.stderr,
                    )

        if label is not None:
            results[entry_id] = label
            output_lines.append(
                json.dumps({"id": entry_id, "faithful": label})
            )
            print(
                f"  [{i + 1}/{len(entries)}] {entry_id}: "
                f"{'faithful' if label else 'unfaithful'}"
            )
        else:
            print(
                f"  [{i + 1}/{len(entries)}] {entry_id}: SKIPPED (LLM error)"
            )

        if delay_between > 0 and i < len(entries) - 1:
            time.sleep(delay_between)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(output_lines) + "\n")

    print(f"\nRated {len(results)}/{len(entries)} entries")
    print(f"Output: {output_path}")
    faithful_count = sum(results.values())
    print(
        f"Distribution: {faithful_count} faithful, "
        f"{len(results) - faithful_count} unfaithful"
    )
    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        required=True,
        help="Path to JSONL calibration corpus file.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Path to write LLM-rater labels (JSONL).",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="LLM model to use (default: $EVIDENTIA_LLM_MODEL or gpt-4o).",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Max retries per entry on LLM failure.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Seconds between LLM calls (rate limiting).",
    )
    args = parser.parse_args()

    if not args.corpus.is_file():
        print(f"Corpus file not found: {args.corpus}", file=sys.stderr)
        return 2

    print("LLM rater starting")
    print(f"  Corpus: {args.corpus}")
    print(f"  Model: {args.model or os.environ.get('EVIDENTIA_LLM_MODEL', 'gpt-4o')}")
    print(f"  Output: {args.output}")
    print()

    rate_corpus(
        corpus_path=args.corpus,
        output_path=args.output,
        model=args.model,
        max_retries=args.max_retries,
        delay_between=args.delay,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
