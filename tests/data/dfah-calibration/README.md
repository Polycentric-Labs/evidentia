# DFAH faithfulness calibration corpus (v0.8.3 P1.3)

> Status: 50-entry starter corpus. Operators tune their threshold
> via `scripts/tune_faithfulness_threshold.py` against this
> corpus or extend it with their own labeled data.

## Purpose

The DFAH faithfulness scorers (stdlib Jaccard +
sentence-transformers semantic) take a `threshold` parameter
that determines pass/fail. The default thresholds — 0.3 for
Jaccard, 0.7 for semantic — are conservative starting points
calibrated for natural-language policy clauses.

This corpus is the empirical ground-truth for tuning the
threshold per-deployment. Each entry has:

- `claim`: An atomic claim (sentence-shaped statement)
- `source_clauses`: List of policy clauses the claim should
  trace back to
- `faithful`: Boolean ground-truth label (`true` = the claim
  IS faithful to the source; `false` = it's a hallucination)

The `tune_faithfulness_threshold.py` script measures
false-positive rate (FPR) and false-negative rate (FNR) across
threshold values 0.0–1.0 in 0.05 increments, recommending the
threshold that minimizes Youden's J statistic
(`sensitivity + specificity − 1`) or balanced accuracy.

## Entry categories (50 total, balanced)

The starter corpus has 4 entry shapes, ~12-13 entries each:

1. **Verbatim faithful** (~12 entries) — claim is a near-verbatim
   copy of a source clause. Both Jaccard + semantic should
   score high. `faithful: true`. Tests both scorers' upper
   tail.

2. **Paraphrase faithful** (~12 entries) — claim semantically
   matches a source clause but uses different vocabulary.
   Jaccard scores low (token overlap minimal); semantic scores
   high. `faithful: true`. Tests the differentiator between
   the two scorers — paraphrase precision is exactly where
   sentence-transformers earns its keep.

3. **Semi-related unfaithful** (~13 entries) — claim shares
   tokens with source clauses but is about a different topic
   (e.g., "MFA is required for admins" vs source about
   "MFA is required for end users" — same vocabulary, different
   subject). Jaccard scores high (false positive); semantic
   should score lower (true rejection). `faithful: false`.
   Tests both scorers' false-positive resistance.

4. **Pure hallucination** (~13 entries) — claim has no token
   overlap AND no semantic similarity to any source clause.
   Both scorers should score 0.0. `faithful: false`. Easy-
   case sanity check.

## Format

JSONL (one JSON object per line) — easy to extend, easy to
diff. Each line:

```json
{"id": "v-001", "category": "verbatim", "claim": "...", "source_clauses": ["..."], "faithful": true}
```

The `id` field is `<category-prefix>-<3-digit-counter>`:

- `v-` for verbatim
- `p-` for paraphrase
- `s-` for semi-related
- `h-` for hallucination

## Methodology

The corpus is hand-crafted by Allen + LLM-assisted on the
source-clauses generation (synthetic but plausible policy
text drawn from FFIEC IT Examination Handbook + NIST 800-53
control families). Multi-rater agreement target ≥ 80% — for
v0.8.3 the corpus is single-rater (Allen); v0.8.4 polish may
bring in a second rater + reconciliation pass.

## Extending the corpus

Operators tuning for their own use-case:

```bash
# Append your own entries
cat >> tests/data/dfah-calibration/corpus.jsonl <<EOF
{"id": "custom-001", "category": "verbatim", "claim": "...", "source_clauses": ["..."], "faithful": true}
EOF

# Re-run threshold tuning
uv run python scripts/tune_faithfulness_threshold.py \\
    --corpus tests/data/dfah-calibration/corpus.jsonl \\
    --method jaccard
```

## v0.8.4 expansion

Reservations carried forward:

- Expand to 100-200 entries with a wider distribution of
  paraphrase difficulty
- Multi-rater labeling + Cohen's Kappa agreement metric
- Per-framework subsets (NIST-only, FFIEC-only, ISO-27001-only)
  for operators who want framework-specific tuning
- Real-LLM atomic-claim extraction integration tests using the
  corpus as ground truth

## References

- §26.2 P1.3 / §26.3 step 8 (v0.8.3 cycle plan)
- `scripts/tune_faithfulness_threshold.py` — tuning script
- `docs/dfah-faithfulness.md` — operator guide
- arXiv 2601.15322 — DFAH framework
