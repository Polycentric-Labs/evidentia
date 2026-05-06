# DFAH faithfulness scoring (v0.8.2 P3.1 → v0.8.3 P1)

> Status: v0.8.3 ships sentence-transformers semantic path
> (P1.1) + LLM atomic-claim extraction (P1.2) + 50-entry
> calibration corpus + threshold-tuning script (P1.3) on top of
> the v0.8.2 stdlib Jaccard baseline. Library APIs:
> `evidentia_ai.eval.{faithfulness, faithfulness_semantic,
> claim_extraction}`. Sister docs: `docs/eval-harness.md`
> (determinism + replay), §25/§26 plan (cycle context).

## What faithfulness scoring measures

The Decision-Faithfulness Assessment Harness (DFAH; arXiv
2601.15322) defines three audit-grade metrics for AI-produced
artifacts:

1. **Determinism** — same input + same model + same temperature
   produces the same output across N samples. Shipped in v0.8.0.
2. **Replay equivalence** — re-running with a pinned
   `GenerationContext` produces a hash-identical output. Shipped
   in v0.8.0.
3. **Faithfulness** — generated claims trace back to the source
   policy clauses. **Shipped in v0.8.2**.

Faithfulness catches a different failure mode from determinism.
A model can be perfectly deterministic (same output every run)
and still hallucinate — generating plausible-sounding text that
doesn't actually appear in the source policy. Faithfulness
scoring quantifies how grounded each generated claim is in the
input clauses.

## v0.8.2 stdlib baseline (Jaccard token-overlap)

The v0.8.2 implementation uses Jaccard token-overlap similarity:

```
faithfulness(claim, clauses) = max over c in clauses of
    |tokens(claim) ∩ tokens(c)| / |tokens(claim) ∪ tokens(c)|
```

Token extraction strips punctuation + lowercases + drops non-
ASCII. The default threshold is **0.3** — conservative for the
stdlib baseline (Jaccard scores tend to be lower than semantic-
similarity scores for paraphrases).

This baseline is intentionally conservative:

- **Catches gross hallucinations** — a claim with zero token
  overlap to any clause scores 0.0 + fails the threshold.
- **Misses paraphrases** — "the system enforces account
  management" vs "AC-2 requires account management procedures"
  share enough tokens to pass; "MFA is required for admin
  accounts" vs "AC-2 mandates two-factor authentication for
  privileged users" share very few tokens despite being
  semantically equivalent.

For paraphrase-tolerant scoring, see "Future work" below.

## Library API

```python
from evidentia_ai.eval import faithfulness_score

result = faithfulness_score(
    claim="The system enforces account management procedures",
    source_clauses=[
        "AC-2 requires the organization to manage user accounts",
        "AC-3 enforces access enforcement policies",
        "AU-2 specifies auditable events",
    ],
    threshold=0.3,
)

print(result.score)            # e.g., 0.4
print(result.passed)           # True (score >= threshold)
print(result.evidence_clauses) # ["AC-2 requires...", ...]  (top-3)
print(result.method)           # "jaccard-stdlib"
```

The result is a Pydantic model — JSON-serializable + Sigstore-
signable as part of a wider `EvalResult`.

## When to wire this into your pipeline

Faithfulness scoring is most valuable AFTER determinism
scoring passes. The flow:

1. Generate the AI artifact (e.g., a risk statement) N times
   under the same context. Determinism check confirms the
   output is stable.
2. For each atomic claim in the modal output, run
   `faithfulness_score(claim, source_clauses)`. Source clauses
   are the policy-document text the operator wants to anchor
   against.
3. CI gate fails if any per-claim score is below the threshold
   (the harness fires
   `EventAction.AI_EVAL_FAITHFULNESS_VIOLATION` per failing
   claim for audit visibility).

The atomic-claim extraction step is **not yet automated** in
v0.8.2 — operators bring their own decomposition (e.g., split
on sentence boundaries; or use the v0.8.1 PRT trace's
per-claim list directly via
`risk_statement.reasoning_trace.claims`). v0.8.3 will land
LLM-driven atomic-claim extraction reusing the PRT pattern.

## Tuning the threshold

The default 0.3 is conservative. Operator-side tuning:

- **Lower** (e.g., 0.1) for paraphrase-heavy corpora — your
  policy clauses don't share much vocabulary with the LLM's
  preferred phrasing.
- **Raise** (e.g., 0.5) for verbatim-quote corpora — your
  policy clauses are written in plain English the LLM
  reproduces literally.

Always pair threshold-tuning with a small audit set: hand-
label 20-50 known-faithful + known-unfaithful claims, then
choose the threshold that minimizes false-positives on
known-faithful + false-negatives on known-unfaithful.

## v0.8.3 additions

### Sentence-transformers semantic path (P1.1)

Opt-in via the `[eval-faithfulness]` extra:

```bash
pip install 'evidentia-ai[eval-faithfulness]'
```

Library API mirrors the stdlib Jaccard baseline:

```python
from evidentia_ai.eval import faithfulness_score_semantic

result = faithfulness_score_semantic(
    claim="MFA is required for admin accounts",
    source_clauses=[
        "AC-2 mandates two-factor authentication for privileged users",
        "Account management procedures enforce least privilege",
    ],
    threshold=0.7,  # higher than stdlib default (0.3)
)
print(result.score)            # e.g., 0.83
print(result.passed)           # True
print(result.method)           # "sentence-transformers"
```

Default model: `sentence-transformers/all-MiniLM-L6-v2` (~90 MB
on first use; cached at `~/.cache/huggingface/`). Operators
override via `model_name=` argument.

The semantic path catches paraphrases that the Jaccard baseline
misses — same claim with different vocabulary scores 0.83 via
embeddings vs ~0.05 via token-overlap.

### LLM atomic-claim extraction (P1.2)

```python
from evidentia_ai.eval import extract_claims

claims = extract_claims(
    "The system enforces account management procedures + "
    "requires MFA for admin accounts. Audit logs are retained "
    "for 90 days.",
    model="gpt-4o",
    temperature=0.0,
)
# → ["The system enforces account management procedures.",
#    "MFA is required for admin accounts.",
#    "Audit logs are retained for 90 days."]
```

Operators wire this into their own loop alongside
`faithfulness_score()` (or `faithfulness_score_semantic()`):

```python
from evidentia_ai.eval import extract_claims, faithfulness_score

claims = extract_claims(generated_text)
results = [
    faithfulness_score(claim, source_clauses, threshold=0.3)
    for claim in claims
]
# Per-claim faithfulness; operator-side aggregation
```

DFAHarness wiring (v0.8.4): `DFAHarness.run(check_faithfulness=
True, source_clauses=...)` will close this loop automatically +
fire `EventAction.AI_EVAL_FAITHFULNESS_CHECKED` per-prompt +
`AI_EVAL_FAITHFULNESS_VIOLATION` per below-threshold claim.
The `_CHECKED` event is reserved in v0.8.3 (events.py); the
harness firing path lands in v0.8.4.

### Calibration corpus + threshold tuning (P1.3)

50-entry starter corpus at
`tests/data/dfah-calibration/corpus.jsonl`. Four categories
(verbatim faithful, paraphrase faithful, semi-related
unfaithful, hallucination unfaithful). Methodology in
`tests/data/dfah-calibration/README.md`.

Threshold-tuning script:

```bash
# Default — Jaccard scorer, bundled corpus
uv run python scripts/tune_faithfulness_threshold.py

# Sentence-transformers (requires extra)
uv run python scripts/tune_faithfulness_threshold.py \
    --method semantic

# Per-category breakdown
uv run python scripts/tune_faithfulness_threshold.py \
    --by-category

# Custom corpus
uv run python scripts/tune_faithfulness_threshold.py \
    --corpus path/to/your-corpus.jsonl
```

Reports false-positive rate (FPR) + false-negative rate (FNR)
across thresholds 0.0-1.0 in 0.05 increments + recommends the
threshold that maximizes Youden's J statistic
(`sensitivity + specificity − 1`).

Empirical findings against the bundled corpus (v0.8.3 ship):
Jaccard scorer's optimum is **0.85** (vs the v0.8.2 default
of 0.3) — paraphrase entries drag the optimum upward. This
empirically demonstrates the v0.8.2 R3 mitigation: the Jaccard
baseline is conservative on paraphrases. Operators tuning for
paraphrase-heavy corpora should either raise the Jaccard
threshold or install `[eval-faithfulness]` for semantic scoring.

The script does NOT auto-update the source defaults — operators
update their explicit `threshold=` parameter at call sites.

## Future work (v0.8.4+)

- **DFAHarness CI gate wiring**: extend `evidentia eval
  risk-determinism --check-faithfulness --faithfulness-threshold
  N --source-clauses-file <yaml>` to fire the full faithfulness
  check inline alongside determinism. Reserved
  `EventAction.AI_EVAL_FAITHFULNESS_CHECKED` event lands here.
- **Calibration corpus expansion**: 100-200 entries with wider
  paraphrase difficulty distribution + multi-rater labeling +
  Cohen's Kappa agreement metric.
- **Real-LLM integration tests**: gated by
  `EVIDENTIA_LLM_INTEGRATION=1` env var. Use the calibration
  corpus as ground truth.
- **Per-framework subsets** (NIST-only, FFIEC-only,
  ISO-27001-only) for operators tuning per-framework.

## References

- arXiv 2601.15322 — DFAH framework
- `evidentia_ai.eval.faithfulness` — library implementation
- `tests/unit/test_eval/test_faithfulness.py` — invariants +
  example inputs
- §25.2 P3.1 / §25.3 step 6 (v0.8.2 cycle plan)
- Sister doc: `docs/dockerfile-pinning.md` (v0.8.2 G4 closure
  — supply-chain hardening companion)
