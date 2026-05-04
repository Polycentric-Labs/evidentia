# FAIR Monte Carlo simulation

Evidentia's Open FAIR (Factor Analysis of Information Risk)
quantification ships in two complementary forms:

| Form | Module | Use case |
|---|---|---|
| Deterministic PERT-mean | `evidentia_core.risk_quant.open_fair` | Fast, repeatable, single-number ALE per scenario. Good for high-cadence triage. |
| Monte Carlo simulation | `evidentia_core.risk_quant.monte_carlo` | Per-iteration sampling over Beta-PERT distributions; produces P10/P50/P90 percentile bands. Good for board-level decision support and capital-allocation decisions. |

Both share the same `OpenFAIRScenario` input schema — switching
methods is a single CLI flag.

---

## CLI usage

### Deterministic (v0.7.11+)

```bash
evidentia risk quantify \
    --method open-fair \
    --scenarios scenarios.yaml
```

Produces a Markdown report with per-scenario LEF / LM / ALE +
risk band classification (Severe / High / Significant / Moderate
/ Low).

### Monte Carlo (v0.7.12+)

```bash
evidentia risk quantify \
    --method fair-mc \
    --scenarios scenarios.yaml \
    --iterations 10000 \
    --seed 42 \
    --csv simulation.csv
```

Produces a Markdown report with per-scenario P10/P50/P90 +
optional CSV export of every per-iteration ALE sample.

---

## Beta-PERT formulation

The FAIR-U canonical Monte Carlo path samples each PERT factor
from a Beta-PERT distribution:

```
α = 1 + 4 × (most_likely - low) / (high - low)
β = 1 + 4 × (high - most_likely) / (high - low)
sample = low + (high - low) × Beta(α, β)
```

Where `Beta(α, β)` is the standard Beta distribution sampler
(Python's `random.Random.betavariate`). The lambda parameter
(here implicit at 4) controls the distribution's "tightness"
around the most-likely value — higher lambda = tighter peak.

Scalar factors (no PERT range) contribute zero variance —
the Monte Carlo path collapses to the deterministic value
for those factors only.

Per-iteration ALE: `(TEF × Vulnerability) × (PrimaryLoss + SecondaryLoss)`.

---

## Iteration count tuning

The default of **10,000 iterations** is the FAIR-U recommended
convergence point. Empirical observation:

| Iterations | P50 stability | P10/P90 stability | Runtime (typical scenario) |
|---|---|---|---|
| 100 | ±5% | ±15% | <0.01s |
| 1,000 | ±1.5% | ±5% | <0.05s |
| 10,000 | ±0.5% | ±1.5% | <0.5s |
| 100,000 | ±0.15% | ±0.5% | ~3s |

Scale up to 100,000+ for board-level "is this worth $X mitigation
investment?" decisions where percentile precision matters. Stick
with 10,000 for routine quarterly risk-register reviews.

---

## Percentile interpretation

The FAIR canonical reporting set:

- **P10** ("optimistic floor"): there is a 90% chance that ALE
  exceeds this value in any given year. Useful for the
  "best-realistic-case" conversation with the CFO.
- **P50** ("central estimate"): the median outcome. Half the
  time ALE is below this; half above. The default headline
  number for risk registers.
- **P90** ("pessimistic ceiling"): there is a 10% chance that
  ALE exceeds this value. Useful for the "what's our worst
  reasonably-likely year?" conversation with the board + for
  insurance-coverage decisions.

The risk band on the P50 (`risk_category_p50`) maps to the
Open Group's published FAIR bands:

| Band | P50 ALE range |
|---|---|
| Severe | > $10M |
| High | $1M - $10M |
| Significant | $100k - $1M |
| Moderate | $10k - $100k |
| Low | ≤ $10k |

---

## Reproducible outputs

Pass `--seed N` for deterministic runs:

```bash
evidentia risk quantify \
    --method fair-mc \
    --scenarios scenarios.yaml \
    --seed 2026
```

Same seed + same scenarios + same iteration count → bit-identical
output. Useful for:

- **Audit trail**: regulator can re-run the same simulation and
  reproduce the exact P10/P50/P90 numbers.
- **Diff-testing**: catch unintended changes to the Monte Carlo
  algorithm (golden-file pattern).
- **Reproducible board decks**: the deck saved Q3 2026 still
  produces the same numbers when re-run Q4 2026 with the same
  inputs + seed.

When `--seed` is omitted, the implementation uses Python's
default seed (system time-derived) — every run produces a
different sample distribution, but at 10,000+ iterations the
P10/P50/P90 estimates converge to within ±1.5%.

---

## CSV export

`--csv <path>` writes a single CSV file with all per-iteration
samples across all scenarios:

```csv
scenario_name,iteration,ale
credential-stuffing,1,127456.32
credential-stuffing,2,89234.11
credential-stuffing,3,234567.89
...
ransomware,1,1234567.00
ransomware,2,876543.21
...
```

Suitable for downstream analysis in pandas, Excel, or any
visualization tool. Common downstream uses:

- Histogram per scenario (aggregate `ale` column grouped by
  `scenario_name`)
- Cross-scenario correlation analysis (do high-impact scenarios
  share Beta-PERT structures that imply correlated risks?)
- Custom percentiles outside the default P10/P50/P90 (e.g., P95
  for catastrophic-tail analysis)

---

## Example: the "credential-stuffing" scenario

`scenarios.yaml`:

```yaml
- name: credential-stuffing
  description: |
    External attackers reuse leaked credentials against the
    customer login endpoint. Modeled annually.
  tef:
    low: 12        # 1/month minimum
    most_likely: 52  # weekly attempts most-likely
    high: 200      # multiple-per-week burst
  vulnerability:
    low: 0.05    # MFA + password rate-limiting catches most
    most_likely: 0.10
    high: 0.25   # post-incident-response gap windows
  primary_loss:
    low: 10000   # response cost minimum
    most_likely: 50000
    high: 200000  # full forensics + customer-notification engagement
  secondary_loss:
    low: 20000   # reputational baseline
    most_likely: 100000
    high: 500000  # multi-state breach-notification statutory penalties
```

Running:

```bash
evidentia risk quantify --method fair-mc \
    --scenarios scenarios.yaml \
    --iterations 10000 \
    --seed 2026
```

Produces (representative output):

```markdown
# FAIR Monte Carlo Simulation — credential-stuffing

_10,000 iterations, seed=2026_

| Statistic | ALE ($) |
|---|---|
| P10  | $35.4k |
| P50  | $187.0k |
| P90  | $1.12M |
| Mean | $356.0k |
| Std-dev | $498.3k |
| Risk band (P50) | **significant** |

P10=    $35.4k  ├──┼──────────────────────────────────────────────┤  P90=$1.12M
                    P50=$187.0k
```

Interpretation:

- **P50 = $187k** lands in the **Significant** band. The
  scenario is real but not catastrophic. It deserves
  mitigation investment but not at the cost of higher-priority
  Severe-band scenarios.
- **P90 = $1.12M** crosses into the High band. There's a 10%
  chance any given year produces a $1M+ loss. This is the
  number to use for the "worst reasonably-likely year"
  insurance-coverage discussion.
- **P10 = $35.4k** is the optimistic floor. The Beta-PERT
  distribution's right-skew is visible in the gap between
  Mean ($356k) and P50 ($187k) — the mean is pulled up by
  the long right tail.

---

## Cross-references

- Deterministic PERT-mean: [`docs/risk-quantification.md`](risk-quantification.md)
- Open FAIR primitives: `evidentia_core.risk_quant.open_fair`
- Monte Carlo implementation: `evidentia_core.risk_quant.monte_carlo`
- WORM-backed audit trail for Monte Carlo outputs: [`docs/worm-backends.md`](worm-backends.md)
