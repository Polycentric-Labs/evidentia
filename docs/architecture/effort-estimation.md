# Gap effort estimation — architecture notes

v0.2.1 replaces the v0.1.x–v0.2.0 single-factor effort estimator with a
three-layer hybrid heuristic. This doc exists so future reviewers can
understand the keyword lists and scoring thresholds without re-deriving
them from code.

## Problem

`GapAnalyzer._compute_priority(gap)` computes:

```
priority = severity_weight × (1 + 0.2 × cross_framework_count) × (1 / effort_weight)
```

The v0.2.0 estimator scored effort by the structural complexity of a
control:

```python
complexity_score = len(control.enhancements) + len(control.assessment_objectives)
```

This is accurate when OSCAL structure is populated (full NIST 800-53 Rev 5
has dozens of enhancements per top-level control, several assessment
objectives per control, etc.). It fails for every non-OSCAL catalog we
ship — HIPAA Security Rule, FedRAMP baselines (as pointer catalogs),
CMMC, the ISO/PCI/SOC 2 Tier-C stubs — none of which populate
`enhancements[]` or `assessment_objectives[]`.

Result: 100% of bundled catalogs' controls scored `complexity_score = 0`,
which mapped to `ImplementationEffort.LOW`. Every gap had the same
effort weight. The priority formula collapsed to
`severity × (1 + 0.2 × cross_fw)`, eliminating the "easy wins first"
dimension that effort weighting was supposed to contribute.

## Replacement — three-layer cascade

Implementation: `packages/evidentia-core/src/evidentia_core/gap_analyzer/analyzer.py::_estimate_effort`.

### Layer 1 — structural score (preserved from v0.1.x)

Thresholds unchanged, so catalogs with real OSCAL content (NIST 800-53
Rev 5 full catalog + 4 baselines bundled in v0.2.1) estimate identically
to v0.1.x:

| `enhancements + assessment_objectives` | Effort        |
|----------------------------------------|---------------|
| ≥ 10                                   | VERY_HIGH     |
| ≥ 5                                    | HIGH          |
| ≥ 2                                    | MEDIUM        |
| < 2                                    | *fall through* |

### Layer 2 — keyword presence in description

When structural score is zero, scan the control description for
domain-specific vocabulary. High-effort keywords indicate architectural
complexity or cross-team coordination; medium-effort keywords indicate
documentation or policy work.

```python
_HIGH_EFFORT_KEYWORDS = (
    "architecture",
    "audit log",
    "authentication",
    "continuous monitoring",
    "cryptograph",  # matches "cryptographic", "cryptography"
    "encrypt",
    "incident response plan",
    "key management",
    "least privilege",
    "multi-factor",
    "penetration test",
    "public key infrastructure",
    "separation of duties",
    "siem",
    "single sign-on",
    "zero trust",
)

_MEDIUM_EFFORT_KEYWORDS = (
    "assess",
    "configuration",
    "document",
    "monitor",
    "patch",
    "policy",
    "procedure",
    "review",
    "training",
    "vulnerability scan",
)
```

Keyword source: curated from the NIST SP 800-53 Rev 5 control family
descriptions, HIPAA Security Rule section titles, and CMMC L2 practice
statements. High-effort keywords bias toward controls that require
net-new capability (crypto, SSO, SIEM). Medium-effort keywords bias
toward controls that require formal process (policies, reviews,
training).

High wins over medium — a control with both "cryptographic" and "policy"
in its description resolves to `HIGH`.

### Layer 3 — description length

When neither structural nor keyword signals fire, description length is
the fallback signal. Controls with short, concrete descriptions
("Maintain signage at facility entrances") are genuinely low-effort
bookkeeping. Controls with long descriptions usually describe complex
multi-stakeholder workflows even when they don't use any of our
keywords.

Threshold: `> 400 chars` → `MEDIUM`. Otherwise `LOW`.

## Tuning guidance

When adding new keywords: prefer domain nouns and compound phrases to
generic verbs. "monitoring" is too broad (triggers on "monitor access
logs" which is LOW effort); "continuous monitoring" is specific enough
to indicate real program complexity. Run
`uv run pytest tests/unit/test_gap_analyzer/test_effort_estimator.py -v`
after any keyword change to see the 44 parameterized test cases exercise
the new list.

## Future work (v0.3.0+)

- Replace keyword match with a domain-embedded cosine similarity against
  a canonical corpus of high/medium/low-effort control descriptions
- Per-framework tuning: CMMC descriptions read differently from HIPAA;
  family-specific thresholds could improve accuracy
- User override mechanism — let users tag specific control IDs with
  explicit effort values in `evidentia.yaml`
