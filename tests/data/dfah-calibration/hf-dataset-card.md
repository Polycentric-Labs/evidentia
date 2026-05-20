---
license: apache-2.0
task_categories:
  - text-classification
language:
  - en
tags:
  - compliance
  - grc
  - governance-risk-compliance
  - faithfulness
  - hallucination-detection
  - nist-800-53
  - iso-27001
  - ffiec
  - fedramp
  - cmmc
  - oscal
  - llm-evaluation
pretty_name: Evidentia GRC LLM Faithfulness Eval Suite
size_categories:
  - n<1K
configs:
  - config_name: base
    data_files: corpus.jsonl
  - config_name: nist-800-53
    data_files: corpus_nist.jsonl
  - config_name: ffiec
    data_files: corpus_ffiec.jsonl
  - config_name: iso-27001
    data_files: corpus_iso27001.jsonl
  - config_name: federal
    data_files: corpus_federal.jsonl
  - config_name: fedramp-rev5-high
    data_files: corpus_fedramp_high.jsonl
  - config_name: cmmc-l2
    data_files: corpus_cmmc_l2.jsonl
  - config_name: all
    data_files: corpus-all.jsonl
---

# Evidentia GRC LLM Faithfulness Eval Suite

A calibration + evaluation corpus for measuring whether LLM-generated
governance, risk, and compliance (GRC) artifacts are **faithful** to the
control text they claim to be grounded in.

Published by [Polycentric Labs](https://github.com/Polycentric-Labs/evidentia)
as part of the open-source [Evidentia](https://github.com/Polycentric-Labs/evidentia)
GRC tool (Apache-2.0).

## Why this dataset exists

LLM-generated compliance artifacts — risk statements, control-mapping
rationales, gap-analysis findings — are increasingly shipped to FedRAMP
3PAOs, SOC 2 auditors, and AI risk officers. Most carry no integrity
guarantee and no measurable faithfulness signal.

As of the dataset's first publication, the Hugging Face Hub returned
**zero results** for "OSCAL", "NIST 800-53", or "SOC 2" evaluation
datasets. This is the first canonical GRC-faithfulness eval suite on the
Hub. It is the seed corpus behind Evidentia's Determinism + Faithfulness
AI Harness (DFAH).

## Dataset structure

Each entry is one JSON object (JSONL — one object per line):

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | Stable identifier (`<category-prefix>-<counter>`) |
| `category` | string | `verbatim` / `paraphrase` / `semi-related` / `hallucination` |
| `framework` | string | Framework slug (absent on the framework-agnostic `base` subset) |
| `claim` | string | An atomic claim — a sentence-shaped assertion |
| `source_clauses` | list[string] | The control-text clauses the claim should trace back to |
| `faithful` | bool | Ground-truth label: `true` = faithful to the sources; `false` = hallucination / misattribution |

### The four entry categories

1. **`verbatim`** (faithful) — the claim is a near-verbatim copy of a
   source clause. Both token-overlap and semantic scorers should score
   high.
2. **`paraphrase`** (faithful) — the claim semantically matches a source
   clause but uses different vocabulary. Token-overlap scores low;
   semantic similarity scores high. This is where a semantic scorer
   earns its keep over a Jaccard baseline.
3. **`semi-related`** (unfaithful) — the claim shares vocabulary with the
   sources but asserts something different (changed scope, changed
   number, changed subject). Token-overlap produces a false positive;
   a good semantic scorer rejects it.
4. **`hallucination`** (unfaithful) — the claim has no basis in the
   source clauses at all. Both scorers should score near zero. An
   easy-case sanity check.

### Subsets (configs)

| Config | Framework | Entries |
|--------|-----------|---------|
| `base` | Framework-agnostic | 51 |
| `nist-800-53` | NIST SP 800-53 Rev 5 | 24 |
| `ffiec` | FFIEC IT Examination Handbook | 24 |
| `iso-27001` | ISO/IEC 27001:2022 | 24 |
| `federal` | FedRAMP ConMon + NIST 800-53 CA-7 | 24 |
| `fedramp-rev5-high` | FedRAMP Rev 5 High baseline | 24 |
| `cmmc-l2` | CMMC Level 2 (NIST SP 800-171-aligned) | 24 |
| `all` | Every entry combined | 195 |

```python
from datasets import load_dataset

# One framework subset
nist = load_dataset("Polycentric-Labs/evidentia-grc-eval", "nist-800-53")

# Everything
full = load_dataset("Polycentric-Labs/evidentia-grc-eval", "all")
```

## Methodology

Entries are **synthetic but plausible** policy text — hand-crafted by the
maintainer with LLM-assisted generation of the paraphrase and
semi-related variants modeled on hand-authored verbatim anchors.
Hallucination entries are hand-crafted only (they require deliberate
non-sequiturs that do not pattern-match policy text). No real
copyrighted control text is reproduced; the clauses are representative
shapes drawn from the public structure of each framework.

**Inter-rater agreement**: the corpus is currently primarily
single-rater. A rule-based-rater probe (Jaccard token overlap as a
deliberately weak proxy second rater) yields a best Cohen's Kappa of
0.4848 (moderate) — see `inter-rater-agreement.md` in the source repo.
That moderate-to-poor agreement is itself the empirical motivation for a
semantic faithfulness scorer over a token-overlap baseline. A second
human rater to reach the κ ≥ 0.80 substantial-agreement target is
tracked work in the Evidentia v0.9.x → v1.0 line.

## Intended use

1. Download a subset matching the framework you evaluate against.
2. Score your model's outputs with the Apache-2.0
   [`evidentia-ai`](https://pypi.org/project/evidentia-ai/) package:
   `evidentia eval risk-determinism --check-faithfulness --source-clauses-file ...`.
3. Compare framework-aware faithfulness + determinism scores across
   models and papers on a common corpus.

The dataset is **not** a leaderboard and **not** a substitute for human
audit review. It is a calibration instrument: it tells you where a
model's faithfulness scorer sits relative to a labeled ground truth.

## Limitations

- Synthetic clauses, not authoritative control text. Calibration
  transfers to real text only as far as the synthetic shapes are
  representative.
- 24 entries per framework subset — enough to calibrate a threshold,
  not enough to claim model ranking with statistical confidence.
  Expansion toward 100+ per framework is ongoing.
- Single-rater labels on most subsets (see Methodology).
- English only.

## Citation

```bibtex
@misc{evidentia_grc_eval,
  title  = {Evidentia GRC LLM Faithfulness Eval Suite},
  author = {Byrd, Allen},
  year   = {2026},
  howpublished = {Hugging Face Hub},
  note   = {https://huggingface.co/datasets/Polycentric-Labs/evidentia-grc-eval}
}
```

## License

Apache-2.0, matching the Evidentia project. You may use, redistribute,
and adapt the corpus with attribution.

## Source + maintenance

- Source repository: <https://github.com/Polycentric-Labs/evidentia>
- Corpus files: `tests/data/dfah-calibration/corpus*.jsonl`
- The DFAH methodology: `docs/dfah-faithfulness.md` in the source repo
- Each Evidentia release that touches the corpus tags a matching
  dataset revision on the Hub.
