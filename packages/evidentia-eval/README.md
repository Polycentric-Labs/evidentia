# evidentia-eval

Dev-time AI-output quality eval harness for Evidentia.

Hosts the **DFAH (Decision-Faithfulness Assessment Harness)** —
the auditor-defensible numerical proof layer that validates
LLM-driven artifact production is deterministic, replay-
equivalent, and faithful to its source policy clauses.

## Why this package exists (v0.10.5 P9 extraction)

The DFAH harness was originally bundled into `evidentia-ai` (the
risk-statement generator + control explainer package). That
conflated two very different deployment surfaces:

- **`evidentia-ai`** — PRODUCTION runtime. Needed in air-gap
  installs to actually generate risk statements.
- **`evidentia-eval`** — DEVELOPMENT-time evaluation. NOT needed
  in air-gap installs; only fires when a CI pipeline runs a
  determinism / faithfulness gate before tagging a release.

Extracting the eval harness lets air-gap installs of
`evidentia-ai` skip the optional sentence-transformers stack
entirely (it now lives behind `evidentia-eval[faithfulness-semantic]`
instead of `evidentia-ai[eval-faithfulness]`).

## Quick start

```bash
# Stdlib Jaccard baseline (no extra needed; <10 MB install)
pip install evidentia-eval

# Optional semantic-similarity faithfulness (~250 MB extra
# for sentence-transformers + numpy + model cache on first use)
pip install 'evidentia-eval[faithfulness-semantic]'
```

CLI verbs:

```bash
# Smoke test against a deterministic stub generator (no LLM
# tokens burned)
evidentia eval stub-smoke

# Real-LLM determinism gate against the risk-statement generator
evidentia eval risk-determinism --gap-report gaps.json \
    --system-context ctx.yaml \
    --fail-on-determinism-rate-below 0.95

# Verify a previously-signed eval bundle
evidentia eval verify path/to/eval-output.json
```

The CLI verbs live in `evidentia.cli.eval` (the meta-package);
this package contributes the underlying library.

## Public API

| Symbol | Purpose |
|---|---|
| `DFAHarness` | Owns the run loop + audit emit |
| `EvalResult` | Top-level harness output (JSON-serializable, Sigstore-signable) |
| `EvalSample` | One prompt's inputs (immutable; audit-trail-stable) |
| `DeterminismResult` | Per-prompt determinism outcome |
| `ReplayResult` | Per-prompt replay-equivalence outcome |
| `FaithfulnessResult` | Per-claim faithfulness outcome |
| `PromptFaithfulnessResult` | Aggregated per-prompt faithfulness |
| `faithfulness_score` | Stdlib Jaccard token-overlap baseline |
| `faithfulness_score_semantic` | Sentence-transformers path (optional extra) |
| `determinism_score` | Computes the modal-output pass rate |
| `replay_equivalent` | Binary replay-equivalence check |
| `extract_claims` | Atomic-claim extraction from generated artifacts |
| `normalize_for_determinism` | Canonical whitespace + punctuation normalization |
| `hash_output` | SHA-256 hex of normalized output |
| `sign_eval_result` | Sigstore-sign an `EvalResult` JSON |
| `verify_eval_result` | Verify a previously-signed eval bundle |

## Migrating from `evidentia_ai.eval`

The v0.10.5 P9 extraction left `evidentia_ai.eval.*` in place as
re-export shims that warned once at import time. **They were
removed in v0.12.0** as announced, together with the
unconditional `evidentia-eval` dependency on `evidentia-ai`.
Replace every `from evidentia_ai.eval import X` with
`from evidentia_eval import X` — same symbols, same signatures.

The `evidentia-ai[eval-faithfulness]` install extra still works;
only the import path is gone.

## License

Apache-2.0. See the workspace root LICENSE file.
