# Evidentia GRC LLM eval suite — HF Hub publication scaffolding

> **Status**: SCAFFOLDING (v0.9.7 P4). Full publish deferred to
> v0.9.8 or v1.0 depending on dataset-curation cadence.
>
> **Canonical location**: `docs/hf-eval-suite-scaffolding.md`.

---

## Context — the first-in-class opportunity

Per the v0.7.8 quarterly resync (and confirmed in the v0.9.5 Q3 2026
resync per `docs/positioning-and-value.md` line 1159), **Hugging Face
Hub returns ZERO results for "OSCAL" / "NIST 800-53" / "SOC 2"
datasets**. Evidentia is positioned to publish the first canonical
GRC LLM evaluation suite to HF Hub.

Existing relevant datasets (precedent):

- **AIReg-Bench** (camlsys/AIReg-Bench, arXiv 2510.01474, Nov 2025) —
  120 expert-annotated EU AI Act samples. Methodologically aligned
  with Evidentia's planned suite; demonstrates the publication path.
- **CompliBench** (arXiv 2604.12312, April 14 2026) — LLM-judge
  benchmark methodology Evidentia could parallel.

Evidentia's existing v0.8.x DFAH calibration corpus
(`tests/data/dfah-calibration/corpus*.jsonl`) is the seed dataset —
123 framework-tagged entries (NIST + FFIEC + ISO27001 subsets, 24
each + the base 51).

## Planned dataset structure

### Phase 1 — Single-framework subsets (already exists in-repo)

| Subset | Framework | Entries | Source |
|---|---|---|---|
| `corpus_nist.jsonl` | NIST 800-53 Rev 5 | 24 | `tests/data/dfah-calibration/` |
| `corpus_ffiec.jsonl` | FFIEC IT Handbook | 24 | `tests/data/dfah-calibration/` |
| `corpus_iso27001.jsonl` | ISO 27001:2022 | 24 | `tests/data/dfah-calibration/` |
| `corpus_base.jsonl` | Mixed | 51 | `tests/data/dfah-calibration/` |

### Phase 2 — Expansion targets (v0.9.8+)

Per the Q3 2026 resync — target 100-200 entries per framework with
expert annotation:

| Subset | Framework | Target size | Source priority |
|---|---|---|---|
| `corpus_fedramp_high.jsonl` | FedRAMP Rev 5 High | 100+ | High — federal-SI walk-through driver |
| `corpus_cmmc_l2.jsonl` | CMMC Level 2 | 100+ | High — Phase 2 enforcement Nov 10 2026 |
| `corpus_omb_m_24_10.jsonl` | OMB M-24-10 AI gov | 50+ | Medium — federal-AI inventory |
| `corpus_eu_ai_act.jsonl` | EU AI Act Articles 9-15 | 100+ | Medium — overlap with AIReg-Bench |
| `corpus_pcaobas1105.jsonl` | PCAOB AS 1105 + GenAI | 50+ | Low (specialized audit) |

### Phase 3 — Eval methodology (matches DFAH)

Each entry carries:

- **prompt_id**: stable identifier (e.g., `nist-800-53-rev5/AC-3/risk-statement-001`)
- **framework**: framework slug
- **control_ids**: list of control IDs the entry exercises
- **source_clauses**: ground-truth control text excerpts
- **prompt**: the LLM-facing query
- **reference_output**: the expert-annotated reference answer
- **acceptable_outputs**: alternate phrasings that count as correct
- **adversarial_outputs**: known-bad outputs (for refusal-detection
  scoring)
- **annotator**: expert reviewer identity (or "AI-persona-v0.9.5"
  for the AI-persona-driven baseline)

The eval suite ships with Evidentia's `evidentia eval` CLI verbs
+ DFAH determinism harness so that:

1. Researchers download the dataset from HF Hub.
2. Run `evidentia eval risk-determinism --corpus <hf-download-path>`
   against their model.
3. Get framework-aware faithfulness + determinism scores comparable
   across models + papers.

## HF Hub publication path

1. **Dataset card**: `README.md` at the HF dataset root explaining
   scope + methodology + license. Apache 2.0 to match the project.
2. **Loading script**: a small Python loader so
   `datasets.load_dataset("evidentia/grc-eval-suite")` Just Works.
3. **Citation block**: BibTeX entry pointing at the project +
   any companion paper (TBD — Marino & Lane frame suggests
   submission to a computational-compliance venue).
4. **Versioning**: HF Hub supports dataset revisions; each Evidentia
   release that touches the corpus tags a corresponding revision.

## Scaffolding status (v0.9.7)

- ✅ Single-framework subsets exist at
  `tests/data/dfah-calibration/corpus_{nist,ffiec,iso27001}.jsonl`
  (v0.8.5 ship).
- ✅ Eval methodology documented in `docs/v0.8.6-plan.md` § P3 +
  `docs/security-review-v0.8.6.md`.
- ⏳ Dataset card draft (this doc).
- ⏳ HF Hub repository creation (operator action — not in v0.9.7 scope).
- ⏳ Loading script (v0.9.8 candidate).
- ⏳ Expansion to FedRAMP Rev 5 High + CMMC L2 (v0.9.8+ candidate).

## Cross-references

- [`positioning-and-value.md`](positioning-and-value.md) §11.2.B —
  the first-in-class framing.
- [`v0.8.6-plan.md`](v0.8.6-plan.md) — the DFAH calibration corpus
  origin.
- [`security-review-v0.8.6.md`](security-review-v0.8.6.md) — the
  Cohen's Kappa methodology baseline.
- [`v1.0-transition.md`](v1.0-transition.md) — the v1.0 acceptance
  gates that the eval-suite publish would satisfy
  ("1+ external operator validation" via the published dataset's
  external use).
