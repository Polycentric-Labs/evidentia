#!/usr/bin/env python3
"""DFAH faithfulness threshold-tuning utility (v0.8.3 P1.3).

Measures false-positive rate (FPR) and false-negative rate (FNR)
of the Jaccard or sentence-transformers faithfulness scorer
across threshold values 0.0–1.0 in 0.05 increments. Recommends
the threshold that maximizes Youden's J statistic
(``sensitivity + specificity − 1``) — the canonical balanced
measure when both error types matter equally.

Usage:

    # Default — Jaccard scorer against the bundled corpus
    uv run python scripts/tune_faithfulness_threshold.py

    # Sentence-transformers (requires [eval-faithfulness] extra)
    uv run python scripts/tune_faithfulness_threshold.py \\
        --method semantic

    # Custom corpus
    uv run python scripts/tune_faithfulness_threshold.py \\
        --corpus path/to/your-corpus.jsonl

    # Per-category breakdown (verbatim / paraphrase / semi /
    # hallucination)
    uv run python scripts/tune_faithfulness_threshold.py \\
        --by-category

The script does NOT modify the source code's default threshold
constants. After running, operators update their explicit
``threshold=`` parameter at call sites + revisit the constant
in a future cycle if the empirical optimum drifts materially.

Plan: §26.2 P1.3 / §26.3 step 8 (v0.8.3 cycle).
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any


def _load_corpus(path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL calibration corpus file."""
    entries: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                print(
                    f"  WARN: line {line_no} of {path} is not valid "
                    f"JSON; skipping ({exc})",
                    file=sys.stderr,
                )
                continue
            for required in ("claim", "source_clauses", "faithful"):
                if required not in entry:
                    print(
                        f"  WARN: line {line_no} missing field "
                        f"{required!r}; skipping",
                        file=sys.stderr,
                    )
                    break
            else:
                entries.append(entry)
    return entries


def _tune_threshold(
    corpus: list[dict[str, Any]],
    score_fn: Callable[[str, list[str]], float],
    *,
    step: float = 0.05,
) -> tuple[float, float, list[tuple[float, float, float, float]]]:
    """Sweep thresholds across [0, 1]; return best + per-step stats.

    Returns:
        (best_threshold, best_youden_j, per_step_stats) where
        per_step_stats is list of (threshold, fpr, fnr, youden_j).
    """
    # Compute scores once; reuse across all thresholds.
    scores: list[tuple[float, bool]] = []
    for entry in corpus:
        score = score_fn(entry["claim"], entry["source_clauses"])
        scores.append((score, bool(entry["faithful"])))

    n = len(scores)
    if n == 0:
        return 0.5, 0.0, []
    n_pos = sum(1 for _, f in scores if f)
    n_neg = n - n_pos

    per_step: list[tuple[float, float, float, float]] = []
    best_j = -1.0
    best_threshold = 0.5
    threshold = 0.0
    while threshold <= 1.0001:  # +0.0001 to include 1.0 in the sweep
        threshold = round(threshold, 3)
        # TP = faithful AND score >= threshold
        # FP = unfaithful AND score >= threshold
        # TN = unfaithful AND score < threshold
        # FN = faithful AND score < threshold
        tp = sum(1 for s, f in scores if f and s >= threshold)
        fp = sum(1 for s, f in scores if not f and s >= threshold)
        tn = n_neg - fp
        fn = n_pos - tp

        sensitivity = tp / n_pos if n_pos else 0.0
        specificity = tn / n_neg if n_neg else 0.0
        fpr = fp / n_neg if n_neg else 0.0
        fnr = fn / n_pos if n_pos else 0.0
        youden_j = sensitivity + specificity - 1.0

        per_step.append((threshold, fpr, fnr, youden_j))

        if youden_j > best_j:
            best_j = youden_j
            best_threshold = threshold

        threshold += step

    return best_threshold, best_j, per_step


def _print_per_step(
    per_step: list[tuple[float, float, float, float]],
) -> None:
    print(f"{'threshold':>10} {'fpr':>8} {'fnr':>8} {'youden_j':>10}")
    print("-" * 40)
    for threshold, fpr, fnr, youden_j in per_step:
        print(
            f"{threshold:>10.2f} {fpr:>8.3f} {fnr:>8.3f} "
            f"{youden_j:>10.3f}"
        )


def _resolve_score_fn(
    method: str,
) -> Callable[[str, list[str]], float] | None:
    """v0.8.5 P2: resolve scorer function for a given method.

    Returns None on failure (with stderr message already printed).
    Centralized so both the single-corpus path AND the
    --corpus-pattern multi-corpus path use one resolution
    pipeline.
    """
    if method == "jaccard":
        from evidentia_ai.eval.faithfulness import faithfulness_score

        def jaccard_score(claim: str, clauses: list[str]) -> float:
            return faithfulness_score(claim, clauses).score

        return jaccard_score
    elif method == "semantic":
        try:
            from evidentia_ai.eval.faithfulness_semantic import (
                faithfulness_score_semantic,
            )

            def semantic_score(claim: str, clauses: list[str]) -> float:
                return faithfulness_score_semantic(claim, clauses).score

            return semantic_score
        except ImportError as exc:
            print(
                f"Semantic scorer unavailable: {exc}", file=sys.stderr
            )
            print(
                "Install via "
                "`pip install evidentia-ai[eval-faithfulness]`",
                file=sys.stderr,
            )
            return None
    else:  # pragma: no cover — exhaustive choice
        print(f"Unknown method: {method}", file=sys.stderr)
        return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        default=Path("tests/data/dfah-calibration/corpus.jsonl"),
        help="Path to JSONL calibration corpus (default: bundled "
        "framework-agnostic corpus)",
    )
    parser.add_argument(
        "--corpus-pattern",
        type=str,
        default=None,
        help="v0.8.5: glob pattern matching multiple corpus JSONL "
        "files. When set, sweeps each matching file separately + "
        "reports per-file recommended thresholds. Useful for "
        "per-framework calibration: "
        "'tests/data/dfah-calibration/corpus_*.jsonl'. "
        "Mutually exclusive with --corpus + --by-category.",
    )
    parser.add_argument(
        "--method",
        choices=["jaccard", "semantic"],
        default="jaccard",
        help="Scorer to tune (jaccard = stdlib; semantic requires "
        "[eval-faithfulness] extra)",
    )
    parser.add_argument(
        "--step",
        type=float,
        default=0.05,
        help="Threshold step size (default 0.05)",
    )
    parser.add_argument(
        "--by-category",
        action="store_true",
        help="Also report optimum threshold per-category. Ignored "
        "when --corpus-pattern is used.",
    )
    args = parser.parse_args()

    # v0.8.5 P2: --corpus-pattern path — sweep multiple files.
    if args.corpus_pattern is not None:
        import glob as _glob

        matches = sorted(_glob.glob(args.corpus_pattern))
        if not matches:
            print(
                f"--corpus-pattern matched 0 files: "
                f"{args.corpus_pattern}",
                file=sys.stderr,
            )
            return 2
        print(
            f"Sweeping {len(matches)} corpus file(s) matched by "
            f"pattern '{args.corpus_pattern}':"
        )
        print()
        # Wire up scorer once.
        score_fn = _resolve_score_fn(args.method)
        if score_fn is None:
            return 2
        for match in matches:
            match_path = Path(match)
            sub_corpus = _load_corpus(match_path)
            if not sub_corpus:
                print(f"  {match_path}: empty; skipping")
                continue
            sub_best_t, sub_best_j, _ = _tune_threshold(
                sub_corpus, score_fn, step=args.step
            )
            n_faithful = sum(1 for e in sub_corpus if e["faithful"])
            n_unfaithful = len(sub_corpus) - n_faithful
            print(
                f"  {match_path.name:>30} "
                f"({len(sub_corpus):>3} entries; "
                f"{n_faithful} faithful, {n_unfaithful} unfaithful) "
                f"-> threshold={sub_best_t:.2f}, J={sub_best_j:.3f}"
            )
        return 0

    if not args.corpus.is_file():
        print(
            f"Corpus file not found: {args.corpus}", file=sys.stderr
        )
        return 2

    corpus = _load_corpus(args.corpus)
    if not corpus:
        print(
            f"Corpus is empty: {args.corpus}", file=sys.stderr
        )
        return 2

    print(f"Loaded {len(corpus)} corpus entries from {args.corpus}")
    print(f"Tuning method: {args.method}")
    print()

    # Wire up the scorer.
    score_fn = _resolve_score_fn(args.method)
    if score_fn is None:
        return 2

    # Overall sweep.
    best_t, best_j, per_step = _tune_threshold(
        corpus, score_fn, step=args.step
    )
    print("=== Overall sweep ===")
    _print_per_step(per_step)
    print()
    print(
        f"OPTIMAL THRESHOLD: {best_t:.2f} (Youden's J = {best_j:.3f})"
    )

    # Per-category breakdown.
    if args.by_category:
        print()
        print("=== Per-category breakdown ===")
        categories = sorted({e.get("category", "uncategorized") for e in corpus})
        for cat in categories:
            cat_entries = [e for e in corpus if e.get("category") == cat]
            cat_best_t, cat_best_j, _ = _tune_threshold(
                cat_entries, score_fn, step=args.step
            )
            n_faithful = sum(1 for e in cat_entries if e["faithful"])
            n_unfaithful = len(cat_entries) - n_faithful
            print(
                f"  {cat:>15} ({len(cat_entries):>3} entries; "
                f"{n_faithful} faithful, {n_unfaithful} unfaithful) "
                f"-> threshold={cat_best_t:.2f}, J={cat_best_j:.3f}"
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
