#!/usr/bin/env python3
"""Cohen's Kappa for DFAH calibration corpus rater agreement (v0.8.6 P2).

Closes the v0.8.5 P2 reservation for multi-rater methodology.
Computes Cohen's Kappa κ between two raters' faithfulness
labels for a calibration corpus.

Usage
-----

Two modes:

1. **Two-rater file mode** — supply two JSONL files; each line a
   ``{"id": ..., "faithful": bool}`` entry. Computes κ over the
   intersection of IDs.

   ::

       uv run python scripts/compute_inter_rater_kappa.py \\
           --rater1 tests/data/dfah-calibration/corpus.jsonl \\
           --rater2 tests/data/dfah-calibration/labels-rater2.jsonl

2. **Rule-based rater mode** — supply one rater file + a rule
   that Compute the second rater's labels deterministically (no
   LLM, no human time). Useful as a label-quality probe
   surfacing edge cases where the rule disagrees with the
   hand-labels.

   ::

       uv run python scripts/compute_inter_rater_kappa.py \\
           --rater1 tests/data/dfah-calibration/corpus.jsonl \\
           --rule jaccard \\
           --rule-threshold 0.5

Cohen's Kappa formula
---------------------

::

    κ = (po - pe) / (1 - pe)

where ``po`` is the observed agreement rate and ``pe`` is the
expected agreement under random labeling (computed from
per-rater marginals).

Landis & Koch 1977 interpretation:

- κ < 0.00: poor agreement
- 0.00 ≤ κ ≤ 0.20: slight agreement
- 0.21 ≤ κ ≤ 0.40: fair agreement
- 0.41 ≤ κ ≤ 0.60: moderate agreement
- 0.61 ≤ κ ≤ 0.80: substantial agreement
- 0.81 ≤ κ ≤ 1.00: almost-perfect agreement

Threat model
------------

A "rule-based rater" is NOT ground truth — it's a deterministic
heuristic. High κ between Allen's hand-labels + a rule means
"the rule mostly agrees with Allen", NOT "Allen's labels are
correct". Low κ surfaces label-quality issues OR edge cases
where the rule under-performs (paraphrase entries, semantic
overlap below the jaccard floor). Both cases are useful audit
signals; neither concludes the corpus is "right" or "wrong".

CI gate
-------

Exit code 0 if κ ≥ ``--target`` (default 0.80, per the v0.8.6
plan §29 acceptance criterion). Exit code 1 otherwise. Lets
operators bake this into a release-pipeline gate.

Plan: §29 v0.8.6 P2.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Literal


def _load_corpus_with_labels(
    path: Path,
) -> dict[str, dict[str, Any]]:
    """Parse a JSONL corpus file; return ``{id: entry}`` map."""
    entries: dict[str, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"WARN: line {line_no} of {path} not valid "
                    f"JSON; skipping ({exc})",
                    file=sys.stderr,
                )
                continue
            if "id" not in entry:
                print(
                    f"WARN: line {line_no} missing 'id' field; "
                    f"skipping",
                    file=sys.stderr,
                )
                continue
            entries[str(entry["id"])] = entry
    return entries


def _jaccard_label(
    entry: dict[str, Any], threshold: float
) -> bool:
    """Rule-based rater: claim is faithful iff jaccard score
    against the most-similar source clause meets threshold.

    Stdlib token-set Jaccard; matches the v0.8.2-shipped
    ``faithfulness_score`` semantics modulo per-clause
    aggregation (this helper takes the max across clauses).
    """
    claim = str(entry.get("claim", ""))
    clauses = entry.get("source_clauses", [])
    if not isinstance(clauses, list) or not clauses:
        return False
    # Tokenize claim once.
    claim_tokens = set(_tokenize(claim))
    if not claim_tokens:
        return False
    best = 0.0
    for clause in clauses:
        clause_tokens = set(_tokenize(str(clause)))
        if not clause_tokens:
            continue
        intersection = claim_tokens & clause_tokens
        union = claim_tokens | clause_tokens
        score = len(intersection) / len(union) if union else 0.0
        if score > best:
            best = score
    return best >= threshold


def _tokenize(text: str) -> list[str]:
    """Lowercase + strip non-alphanumeric → token list. Mirrors
    the v0.8.2 jaccard scorer's tokenization for consistency
    with the production faithfulness_score helper."""
    import re

    # Strip punctuation, lowercase, split on whitespace.
    cleaned = re.sub(r"[^\w\s]", " ", text.lower())
    return [t for t in cleaned.split() if t]


def cohens_kappa(
    rater1_labels: list[bool], rater2_labels: list[bool]
) -> tuple[float, float, float]:
    """Compute Cohen's Kappa over two parallel label arrays.

    Returns ``(kappa, observed_agreement, expected_agreement)``.

    Args:
        rater1_labels: List of bool labels from rater 1.
        rater2_labels: List of bool labels from rater 2 (same
            length + same ordering as ``rater1_labels``).

    Raises:
        ValueError: if the two arrays have different lengths or
            either is empty.
    """
    if len(rater1_labels) != len(rater2_labels):
        raise ValueError(
            f"Rater label arrays have different lengths: "
            f"{len(rater1_labels)} vs {len(rater2_labels)}"
        )
    n = len(rater1_labels)
    if n == 0:
        raise ValueError("Cannot compute kappa over 0 entries")

    # Observed agreement: fraction of entries where both raters
    # agree.
    agreements = sum(
        1 for r1, r2 in zip(rater1_labels, rater2_labels, strict=True) if r1 == r2
    )
    po = agreements / n

    # Expected agreement: probability of agreement under random
    # labeling (computed from per-rater marginals).
    r1_pos = sum(rater1_labels) / n
    r1_neg = 1 - r1_pos
    r2_pos = sum(rater2_labels) / n
    r2_neg = 1 - r2_pos
    pe = (r1_pos * r2_pos) + (r1_neg * r2_neg)

    if pe >= 1.0:
        # Both raters labeled all-same — kappa is undefined
        # (perfect chance agreement). Return 1.0 if also
        # observed-perfect, else 0.0.
        return (1.0 if po >= 1.0 else 0.0, po, pe)

    kappa = (po - pe) / (1 - pe)
    return (kappa, po, pe)


def landis_koch_label(kappa: float) -> str:
    """Map kappa to the Landis & Koch 1977 verbal interpretation."""
    if kappa < 0.0:
        return "poor"
    if kappa <= 0.20:
        return "slight"
    if kappa <= 0.40:
        return "fair"
    if kappa <= 0.60:
        return "moderate"
    if kappa <= 0.80:
        return "substantial"
    return "almost-perfect"


def _llm_rate_entries(
    corpus: dict[str, dict[str, Any]],
    ids: list[str],
    model: str | None,
    output_path: Path | None,
    rater1_path: Path,
) -> list[bool]:
    """Rate corpus entries using the LLM rater (v0.9.1 P2).

    Imports the llm_rater module and calls _call_llm for each entry.
    Persists results to a JSONL sidecar for reproducibility.
    """
    import os
    import time

    # Resolve output path
    if output_path is None:
        output_path = rater1_path.parent / "labels-llm-rater.jsonl"

    resolved_model = model or os.environ.get("EVIDENTIA_LLM_MODEL", "gpt-4o")
    print(f"LLM rater: model={resolved_model}, entries={len(ids)}")

    # Import the LLM rater's call function
    sys.path.insert(0, str(Path(__file__).parent))
    from llm_rater import _SYSTEM_PROMPT, _build_user_prompt, _call_llm

    labels: list[bool] = []
    output_lines: list[str] = []

    for i, entry_id in enumerate(ids):
        entry = corpus[entry_id]
        user_prompt = _build_user_prompt(entry)
        try:
            label = _call_llm(resolved_model, _SYSTEM_PROMPT, user_prompt)
        except Exception as exc:
            print(
                f"  [{i + 1}/{len(ids)}] {entry_id}: ERROR ({exc}); "
                f"defaulting to unfaithful",
                file=sys.stderr,
            )
            label = False
        labels.append(label)
        output_lines.append(json.dumps({"id": entry_id, "faithful": label}))
        if i < len(ids) - 1:
            time.sleep(0.3)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(output_lines) + "\n")
    print(f"  LLM labels persisted to: {output_path}")

    return labels


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--rater1",
        type=Path,
        required=True,
        help="Path to JSONL file with rater 1's labels (each "
        "line: {'id': ..., 'faithful': bool}). The bundled "
        "calibration corpus files satisfy this format.",
    )
    parser.add_argument(
        "--rater2",
        type=Path,
        default=None,
        help="Path to JSONL file with rater 2's labels. "
        "Mutually exclusive with --rule.",
    )
    parser.add_argument(
        "--rule",
        choices=["jaccard", "llm"],
        default=None,
        help="Rule-based rater 2: deterministically compute "
        "labels from the corpus entries themselves. 'jaccard' is "
        "a zero-cost token-overlap heuristic; 'llm' calls the "
        "configured LLM (requires EVIDENTIA_LLM_MODEL or "
        "defaults to gpt-4o; incurs API cost).",
    )
    parser.add_argument(
        "--rule-threshold",
        type=float,
        default=0.5,
        help="Threshold for jaccard rule-based rater (default 0.5).",
    )
    parser.add_argument(
        "--llm-model",
        type=str,
        default=None,
        help="LLM model for --rule llm (default: $EVIDENTIA_LLM_MODEL "
        "or gpt-4o). Only used when --rule llm.",
    )
    parser.add_argument(
        "--llm-output",
        type=Path,
        default=None,
        help="Path to persist LLM-rater labels as JSONL sidecar. "
        "Default: <rater1-dir>/labels-llm-rater.jsonl. Only "
        "used when --rule llm.",
    )
    parser.add_argument(
        "--target",
        type=float,
        default=0.80,
        help="κ target for CI gate; exit 0 when κ ≥ target, "
        "exit 1 otherwise. Default 0.80 per Landis-Koch "
        "'substantial' boundary + the v0.8.6 plan §29 "
        "acceptance criterion.",
    )
    args = parser.parse_args()

    if (args.rater2 is None) == (args.rule is None):
        print(
            "Provide exactly one of --rater2 or --rule",
            file=sys.stderr,
        )
        return 2

    if not args.rater1.is_file():
        print(
            f"Rater 1 file not found: {args.rater1}",
            file=sys.stderr,
        )
        return 2

    rater1_corpus = _load_corpus_with_labels(args.rater1)
    if not rater1_corpus:
        print(
            f"Rater 1 corpus is empty: {args.rater1}",
            file=sys.stderr,
        )
        return 2

    # Build rater 2 labels from either file or rule.
    rater_mode: Literal["file", "rule"]
    if args.rater2 is not None:
        rater_mode = "file"
        if not args.rater2.is_file():
            print(
                f"Rater 2 file not found: {args.rater2}",
                file=sys.stderr,
            )
            return 2
        rater2_corpus = _load_corpus_with_labels(args.rater2)
        if not rater2_corpus:
            print(
                f"Rater 2 corpus is empty: {args.rater2}",
                file=sys.stderr,
            )
            return 2
        # Intersection of IDs.
        common_ids = sorted(
            set(rater1_corpus.keys()) & set(rater2_corpus.keys())
        )
        if not common_ids:
            print(
                "No overlapping IDs between rater 1 + rater 2 "
                "corpora",
                file=sys.stderr,
            )
            return 2
        r1_labels = [
            bool(rater1_corpus[i]["faithful"])
            for i in common_ids
        ]
        r2_labels = [
            bool(rater2_corpus[i]["faithful"])
            for i in common_ids
        ]
    else:
        rater_mode = "rule"
        common_ids = sorted(rater1_corpus.keys())
        r1_labels = [
            bool(rater1_corpus[i]["faithful"])
            for i in common_ids
        ]
        if args.rule == "jaccard":
            r2_labels = [
                _jaccard_label(rater1_corpus[i], args.rule_threshold)
                for i in common_ids
            ]
        elif args.rule == "llm":
            r2_labels = _llm_rate_entries(
                rater1_corpus, common_ids, args.llm_model, args.llm_output, args.rater1
            )
        else:
            print(f"Unknown rule: {args.rule}", file=sys.stderr)
            return 2

    # Compute kappa.
    kappa, po, pe = cohens_kappa(r1_labels, r2_labels)
    label = landis_koch_label(kappa)

    # Report.
    print(f"Rater 1: {args.rater1}")
    if rater_mode == "file":
        print(f"Rater 2: {args.rater2}")
    else:
        print(
            f"Rater 2: rule={args.rule!r} "
            f"(threshold {args.rule_threshold:.2f})"
        )
    print(f"Entries compared: {len(common_ids)}")
    print(f"  rater 1 faithful: {sum(r1_labels)}")
    print(f"  rater 2 faithful: {sum(r2_labels)}")
    print(f"Observed agreement: {po:.4f}")
    print(f"Expected agreement: {pe:.4f}")
    # ASCII output for Windows-cp1252 portability — Greek
    # letters (κ) are not in cp1252; spell out "kappa" instead.
    print(f"Cohen's Kappa: kappa = {kappa:.4f} ({label})")
    print(f"CI target: kappa >= {args.target:.2f}")

    if kappa >= args.target:
        print(
            f"PASS: kappa ({kappa:.4f}) >= "
            f"target ({args.target:.2f})"
        )
        return 0
    else:
        print(
            f"FAIL: kappa ({kappa:.4f}) < "
            f"target ({args.target:.2f})"
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
