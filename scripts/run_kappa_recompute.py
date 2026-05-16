#!/usr/bin/env python3
"""Full LLM-rater kappa recompute across all calibration corpus subsets (v0.9.3 P3).

Orchestrates:
1. Run llm_rater.py against each corpus file (5 subsets, 147 entries total)
2. Compute Cohen's Kappa per-subset via compute_inter_rater_kappa.py
3. Print summary table for documentation

Usage:

    EVIDENTIA_LLM_MODEL=gpt-4o OPENAI_API_KEY=... uv run python scripts/run_kappa_recompute.py

Or with a different provider:

    EVIDENTIA_LLM_MODEL=openrouter/openai/gpt-4o OPENROUTER_API_KEY=... \
        uv run python scripts/run_kappa_recompute.py

The script persists per-subset labels to the calibration directory
and prints a markdown-formatted summary table suitable for pasting
into inter-rater-agreement.md.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
from pathlib import Path

CALIBRATION_DIR = Path("tests/data/dfah-calibration")

CORPUS_FILES = [
    ("corpus.jsonl", "Framework-agnostic", 51),
    ("corpus_nist.jsonl", "NIST 800-53", 24),
    ("corpus_ffiec.jsonl", "FFIEC", 24),
    ("corpus_iso27001.jsonl", "ISO 27001", 24),
    ("corpus_federal.jsonl", "FedRAMP/CA-7", 24),
]


def run_llm_rater(corpus_file: str, output_file: str) -> int:
    corpus_path = CALIBRATION_DIR / corpus_file
    output_path = CALIBRATION_DIR / output_file
    cmd = [
        sys.executable,
        "scripts/llm_rater.py",
        "--corpus", str(corpus_path),
        "--output", str(output_path),
        "--delay", "0.3",
    ]
    print(f"\n{'='*60}")
    print(f"Rating: {corpus_file} -> {output_file}")
    print(f"{'='*60}")
    result = subprocess.run(cmd, check=False)
    return result.returncode


def run_kappa(corpus_file: str, labels_file: str) -> tuple[float, str, int] | None:
    corpus_path = CALIBRATION_DIR / corpus_file
    labels_path = CALIBRATION_DIR / labels_file
    if not labels_path.is_file():
        print(f"  Labels file missing: {labels_path}", file=sys.stderr)
        return None
    cmd = [
        sys.executable,
        "scripts/compute_inter_rater_kappa.py",
        "--rater1", str(corpus_path),
        "--rater2", str(labels_path),
        "--target", "0.80",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    print(result.stdout)
    if result.stderr:
        print(result.stderr, file=sys.stderr)

    kappa = None
    label = "unknown"
    for line in result.stdout.splitlines():
        if "Cohen's Kappa:" in line:
            parts = line.split("=")
            if len(parts) >= 2:
                val_part = parts[1].strip().split()[0]
                with contextlib.suppress(ValueError):
                    kappa = float(val_part)
            paren_start = line.find("(")
            paren_end = line.find(")")
            if paren_start != -1 and paren_end != -1:
                label = line[paren_start + 1:paren_end]

    if kappa is None:
        return None
    return kappa, label, result.returncode


def main() -> int:
    print("=" * 60)
    print("v0.9.3 P3: Full LLM-rater kappa recompute")
    print("=" * 60)
    print(f"Corpus directory: {CALIBRATION_DIR.resolve()}")
    print(f"Total entries: 147 across {len(CORPUS_FILES)} subsets")
    print()

    failed_rating = []
    for corpus_file, _domain, _count in CORPUS_FILES:
        stem = corpus_file.replace(".jsonl", "")
        output_file = f"labels-llm-{stem}.jsonl"
        rc = run_llm_rater(corpus_file, output_file)
        if rc != 0:
            failed_rating.append(corpus_file)
            print(f"  WARNING: LLM rater returned {rc} for {corpus_file}")

    if failed_rating:
        print(f"\nWARNING: {len(failed_rating)} corpus files had rating errors")
        print("Continuing with kappa computation for available labels...\n")

    print("\n" + "=" * 60)
    print("KAPPA COMPUTATION")
    print("=" * 60)

    results: list[tuple[str, str, int, float, str, bool]] = []
    for corpus_file, domain, count in CORPUS_FILES:
        stem = corpus_file.replace(".jsonl", "")
        labels_file = f"labels-llm-{stem}.jsonl"
        print(f"\n--- {domain} ({corpus_file}) ---")
        outcome = run_kappa(corpus_file, labels_file)
        if outcome:
            kappa, label, rc = outcome
            passed = kappa >= 0.80
            results.append((corpus_file, domain, count, kappa, label, passed))

    print("\n\n" + "=" * 60)
    print("SUMMARY TABLE (markdown)")
    print("=" * 60)
    print()
    print("| Subset | Entries | kappa | Landis-Koch | Target (0.80) |")
    print("|--------|---------|-------|-------------|---------------|")
    for _corpus_file, domain, count, kappa, label, passed in results:
        status = "PASS" if passed else "FAIL"
        print(f"| {domain} | {count} | {kappa:.4f} | {label} | {status} |")

    any_pass = any(passed for _, _, _, _, _, passed in results)
    all_pass = all(passed for _, _, _, _, _, passed in results)

    print()
    if all_pass:
        print("RESULT: ALL subsets meet kappa >= 0.80 (substantial agreement)")
    elif any_pass:
        print("RESULT: At least one subset meets kappa >= 0.80 (substantial agreement)")
        print("        Acceptance criterion MET per v0.9.3 plan")
    else:
        print("RESULT: No subset meets kappa >= 0.80")
        print("        Ship with documented improvement path per v0.8.6 R3 mitigation")

    overall_labels_path = CALIBRATION_DIR / "labels-llm-all.jsonl"
    all_labels: list[str] = []
    for corpus_file, _, _ in CORPUS_FILES:
        stem = corpus_file.replace(".jsonl", "")
        labels_path = CALIBRATION_DIR / f"labels-llm-{stem}.jsonl"
        if labels_path.is_file():
            all_labels.extend(labels_path.read_text(encoding="utf-8").splitlines())
    if all_labels:
        overall_labels_path.write_text(
            "\n".join(all_labels) + "\n", encoding="utf-8"
        )
        print(f"\nConsolidated labels written to: {overall_labels_path}")

    all_corpus_path = CALIBRATION_DIR / "corpus-all.jsonl"
    all_corpus_lines: list[str] = []
    for corpus_file, _, _ in CORPUS_FILES:
        cp = CALIBRATION_DIR / corpus_file
        if cp.is_file():
            all_corpus_lines.extend(cp.read_text(encoding="utf-8").splitlines())
    if all_corpus_lines:
        all_corpus_path.write_text(
            "\n".join(all_corpus_lines) + "\n", encoding="utf-8"
        )
        print("\n--- Overall (all 147 entries) ---")
        outcome = run_kappa("corpus-all.jsonl", "labels-llm-all.jsonl")
        if outcome:
            kappa, label, _ = outcome
            passed = kappa >= 0.80
            status = "PASS" if passed else "FAIL"
            print(f"\n| Overall (all) | 147 | {kappa:.4f} | {label} | {status} |")

    return 0 if any_pass else 1


if __name__ == "__main__":
    sys.exit(main())
