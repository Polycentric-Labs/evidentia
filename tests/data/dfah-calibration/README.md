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

## v0.8.5 expansion

Lands in v0.8.5 P2:

- **Corpus growth 51 → 123 entries** distributed across
  4 jsonl files. The original `corpus.jsonl` keeps its 51
  framework-agnostic entries; three new framework-tagged
  subsets bring the total to 123 (within the 100-200 target).
- **Per-framework subsets**:
  - `corpus_nist.jsonl` (24 entries) — NIST 800-53 control
    text shapes (account review cadence, audit retention,
    cryptographic key management, vulnerability scanning,
    session timeout, backup recovery)
  - `corpus_ffiec.jsonl` (24 entries) — FFIEC IT Examination
    Handbook + OCC bulletin shapes (board oversight,
    independent audit, third-party risk management, business
    continuity, customer authentication, encryption in
    transit, incident reporting)
  - `corpus_iso27001.jsonl` (24 entries) — ISO 27001:2022
    Annex A shapes (security objectives, risk treatment,
    personnel screening, removable media, supplier
    relationships, cryptographic review, performance
    evaluation)
- Operators tune thresholds per framework family via
  `scripts/tune_faithfulness_threshold.py --corpus-pattern
  'tests/data/dfah-calibration/corpus_*.jsonl'`.
- Each framework-tagged entry carries a `framework` field
  (`"nist-800-53"` / `"ffiec-it-handbook"` / `"iso-27001"`)
  for downstream filtering.

## Multi-rater methodology

The v0.8.5 expansion remains primarily single-rater (Allen)
with **LLM-assisted generation followed by manual spot-check**
on ~20% of new entries. The hand-craft + LLM-assist split:

1. Allen authored representative anchor entries per category
   per framework (the "verbatim" entries especially).
2. LLM-assist generated paraphrase + semi-related entries
   modeled on the verbatim anchors. Each LLM-generated entry
   was reviewed for category fit before commit.
3. Hallucination entries are hand-crafted only — they require
   creative non-sequiturs that don't pattern-match policy text.

**Cohen's Kappa target**: ≥ 0.80 for inter-rater agreement
once a second rater is brought in. Single-rater corpus
should not be used to judge edge cases without a second
opinion. v0.8.5 ships single-rater (Allen) + flags this as
a known limitation; a future cycle introduces a second
domain-expert rater + computes Cohen's Kappa over the
disagreement subset.

## Per-framework tuning

To tune the threshold for a specific framework family:

```bash
# NIST 800-53 only
uv run python scripts/tune_faithfulness_threshold.py \
    --corpus tests/data/dfah-calibration/corpus_nist.jsonl \
    --method jaccard

# FFIEC IT Handbook only
uv run python scripts/tune_faithfulness_threshold.py \
    --corpus tests/data/dfah-calibration/corpus_ffiec.jsonl \
    --method jaccard

# ISO 27001:2022 only
uv run python scripts/tune_faithfulness_threshold.py \
    --corpus tests/data/dfah-calibration/corpus_iso27001.jsonl \
    --method jaccard
```

Or sweep all framework files at once via
`--corpus-pattern`:

```bash
uv run python scripts/tune_faithfulness_threshold.py \
    --corpus-pattern 'tests/data/dfah-calibration/corpus_*.jsonl' \
    --method jaccard
```

The per-framework recommended thresholds appear in
`docs/dfah-faithfulness.md` operator guide.

## v0.8.6 reservations

- Multi-rater labeling pass + Cohen's Kappa over the
  disagreement subset
- Real-LLM atomic-claim extraction integration tests using
  the corpus as ground truth (gated by
  `EVIDENTIA_LLM_INTEGRATION=1`)

## References

- §26.2 P1.3 / §26.3 step 8 (v0.8.3 cycle plan)
- §27 v0.8.4 plan (DFAHarness `check_faithfulness=True`
  wiring; CLI flags deferred to v0.8.5)
- §28 v0.8.5 plan (CLI flags + corpus expansion +
  real-LLM tests + CIMD)
- `scripts/tune_faithfulness_threshold.py` — tuning script
- `docs/dfah-faithfulness.md` — operator guide
- arXiv 2601.15322 — DFAH framework
