# Generate and quantify risk

Evidentia turns a gap analysis into two complementary risk artifacts. The
`evidentia risk quantify` command produces **dollarized** risk estimates with the
Open FAIR (Factor Analysis of Information Risk) taxonomy — fully deterministic and
LLM-free, so the same input always yields the same number and the math is
auditable. The `evidentia risk generate` command produces **qualitative** NIST
SP 800-30 risk statements with an LLM, narrating each gap as a threat-source /
vulnerability / likelihood / impact story. This guide leads with the runnable,
deterministic quantification spine, then covers the LLM-backed statement
generator (which requires an API key).

## Prerequisites

- Evidentia installed (`pip install evidentia`; verify the build with
  `evidentia version`).
- For **`risk quantify`**: nothing else — it is pure arithmetic over a scenario
  file you write. No API key, no network.
- For **`risk generate`**: a gap-analysis report JSON (see
  [Run a gap analysis](run-gap-analysis.md)) **and** an LLM API key.

> **Set `PYTHONIOENCODING=utf-8` before running `evidentia`** if your terminal is
> a legacy code page (Windows `cp1252`). Several reports and `--help` screens
> contain Unicode (the box-and-whisker glyphs, `×`, `→`); without UTF-8 output
> encoding the CLI can raise a `UnicodeEncodeError` while printing.

## The FAIR model in one table

`risk quantify` decomposes each scenario into four factors and composes them into
an Annualized Loss Expectancy (ALE):

| FAIR factor | Field | Meaning |
| --- | --- | --- |
| Threat Event Frequency (TEF) | `tef` | Attempts per year that threat actors make |
| Vulnerability | `vulnerability` | Probability (0–1) an attempt succeeds given controls |
| Primary Loss | `primary_loss` | Direct response + replacement cost of one event ($) |
| Secondary Loss | `secondary_loss` | Downstream cost of one event — fines, churn, legal ($); defaults to `0` |

The composition is:

```
LEF (Loss Event Frequency) = TEF × Vulnerability
LM  (Loss Magnitude)       = Primary Loss + Secondary Loss
ALE                        = LEF × LM
```

Every factor accepts **either** a single number **or** a 3-point PERT range
(`low` / `most_likely` / `high`, requiring `low <= most_likely <= high`). The
`open-fair` method collapses each PERT range to its mean
`(low + 4×most_likely + high) / 6`; the `fair-mc` method samples it. The
resulting ALE is mapped to a fixed FAIR risk band:

| Band | ALE range |
| --- | --- |
| `severe` | > $10M |
| `high` | $1M – $10M |
| `significant` | $100k – $1M |
| `moderate` | $10k – $100k |
| `low` | <= $10k |

## Step 1 — Write a scenario file

`risk quantify` reads a **list** of scenarios from a YAML or JSON file. Create
`scenarios.yaml`:

```yaml
- name: Ransomware on the primary file server
  description: An opportunistic external actor encrypts the primary file server.
  tef: 0.5
  vulnerability: 0.8
  primary_loss: 50000
  secondary_loss: 0
  asset: Primary file server
  threat_actor: opportunistic external
```

Only `name`, `description`, `tef`, `vulnerability`, and `primary_loss` are
required; `secondary_loss` defaults to `0` and `asset` / `threat_actor` / `notes`
are optional metadata. This scenario sets TEF = 0.5 attempts/yr and Vulnerability
= 0.8, so LEF = 0.4 events/yr, and Loss Magnitude = $50k, giving ALE =
0.4 × $50k = **$20k**.

## Step 2 — Compute the deterministic ALE (`--method open-fair`)

`open-fair` is the default method. Point it at the scenario file:

```bash
evidentia risk quantify --method open-fair --scenarios scenarios.yaml
```

With no `--output`, the Markdown report prints to stdout:

```
# FAIR Risk Quantification Report

_Open FAIR (Factor Analysis of Information Risk) quantification across 1 scenario(s) per the Open Group's Open Risk Taxonomy Standard._

**Total Annualized Loss Expectancy (ALE)**: $20.0k

| Risk category | Scenario count |
| --- | --- |
| severe | 0 |
| high | 0 |
| significant | 0 |
| moderate | 1 |
| low | 0 |
| **Total** | **1** |

## Per-scenario detail

### Ransomware on the primary file server — $20.0k ALE (moderate)

**Description**: An opportunistic external actor encrypts the primary file server.

| Factor | Value |
| --- | --- |
| TEF | 0.5 events/yr |
| Vulnerability | 0.8  |
| LEF (computed) | 0.4000 events/yr |
| Primary loss | 50000.0 USD |
| Secondary loss | 0.0 USD |
| LM (computed) | $50.0k |
| **ALE** | **$20.0k** |
```

The report is **deterministic** — the same scenario file always produces this
exact output, character for character. That is what makes `open-fair` suitable
for golden-file tests and reproducible audit trails.

To write the report to a file instead of stdout, add `--output`:

```bash
evidentia risk quantify --method open-fair --scenarios scenarios.yaml --output fair-report.md
```

```
Wrote FAIR quantification report to fair-report.md (1 scenario(s)).
```

`risk quantify` refuses to clobber an existing `--output` file unless you pass
`--force`:

```
Error: fair-report.md already exists; pass --force to overwrite.
```

## Step 3 — Model uncertainty with PERT ranges

A single-point estimate hides how unsure you are. FAIR's answer is a 3-point PERT
range. Add a second scenario to `scenarios.yaml` whose secondary loss is a range
rather than a scalar:

```yaml
- name: Credential stuffing on customer login
  description: External attackers replay leaked credential pairs against the login API.
  tef: 365
  vulnerability: 0.001
  primary_loss: 5000
  secondary_loss:
    low: 10000
    most_likely: 50000
    high: 250000
  asset: Customer login API
  threat_actor: opportunistic external
```

Under `open-fair`, the PERT range collapses to its mean before the ALE is
computed, so you still get one deterministic number per scenario. Ranges become
visible as a distribution under the Monte Carlo method in the next step.

## Step 4 — Simulate the distribution (`--method fair-mc`)

`fair-mc` runs a Monte Carlo simulation: it draws a sample from each factor's
Beta-PERT distribution per iteration, computes the ALE for that draw, and reports
the P10 / P50 / P90 percentile bands. A scalar factor contributes zero variance;
a PERT-range factor varies. The run is deterministic **only if you pass an
explicit `--seed`** — without one, the system clock seeds the generator and every
run differs.

**Bash / Linux / macOS**

```bash
evidentia risk quantify \
  --method fair-mc \
  --scenarios scenarios.yaml \
  --iterations 1000 \
  --seed 42
```

**PowerShell (Windows)**

```powershell
evidentia risk quantify `
  --method fair-mc `
  --scenarios scenarios.yaml `
  --iterations 1000 `
  --seed 42
```

~~~text
# FAIR Monte Carlo Risk Quantification Report

Sorted by P50 ALE descending.

| # | Scenario | P10 | P50 | P90 | Risk band (P50) |
|---|---|---|---|---|---|
| 1 | Credential stuffing on customer login | $12.7k | $28.2k | $49.8k | **moderate** |
| 2 | Ransomware on the primary file server | $20.0k | $20.0k | $20.0k | **moderate** |

---

# FAIR Monte Carlo Simulation — Credential stuffing on customer login

_1,000 iterations, seed=42_

| Statistic | ALE ($) |
|---|---|
| P10  | $12.7k |
| P50  | $28.2k |
| P90  | $49.8k |
| Mean | $30.1k |
| Std-dev | $14.5k |
| Risk band (P50) | **moderate** |

```
P10=    $12.7k  ├────────────────────────┼──────────────────────────────────┤  P90=$49.8k
                                        P50=$28.2k
```

# FAIR Monte Carlo Simulation — Ransomware on the primary file server

_1,000 iterations, seed=42_

| Statistic | ALE ($) |
|---|---|
| P10  | $20.0k |
| P50  | $20.0k |
| P90  | $20.0k |
| Mean | $20.0k |
| Std-dev | $0.00 |
| Risk band (P50) | **moderate** |

```
$20.0k (degenerate distribution)
```
~~~

Two things to read here. The credential-stuffing scenario has a PERT-range
factor, so its ALE spreads across a P10–P90 band ($12.7k–$49.8k). The ransomware
scenario is all scalars, so the simulation is a **degenerate distribution** — a
point mass at $20.0k with zero standard deviation, matching the `open-fair`
result exactly. That cross-check (scalars under `fair-mc` reproduce the
deterministic ALE) is a useful sanity test.

Notes on the flags:

- `--iterations` defaults to **10,000** (the FAIR-U recommended convergence
  point); 1,000 is used above to keep the demo fast. Higher counts tighten the
  percentile estimates.
- `--seed` is what makes the run reproducible. Re-running the command above with
  `--seed 42` yields byte-identical percentiles every time. Omit it for an
  independent draw.
- `--iterations`, `--seed`, and `--csv` apply **only** to `--method fair-mc`;
  they are silently ignored under `open-fair`.

## Step 5 — Export per-iteration samples to CSV

For downstream analysis in pandas or a spreadsheet, write every iteration's ALE
sample to CSV with `--csv`:

**Bash / Linux / macOS**

```bash
evidentia risk quantify \
  --method fair-mc \
  --scenarios scenarios.yaml \
  --iterations 1000 \
  --seed 42 \
  --csv samples.csv
```

**PowerShell (Windows)**

```powershell
evidentia risk quantify `
  --method fair-mc `
  --scenarios scenarios.yaml `
  --iterations 1000 `
  --seed 42 `
  --csv samples.csv
```

```
Wrote 2 scenario(s) × 1000 iterations to samples.csv
```

The CSV has three columns — `scenario_name`, `iteration`, `ale` — with one row
per scenario per iteration (here 2 × 1,000 = 2,000 data rows plus the header):

```csv
scenario_name,iteration,ale
Ransomware on the primary file server,1,20000.0
Ransomware on the primary file server,2,20000.0
Ransomware on the primary file server,3,20000.0
Ransomware on the primary file server,4,20000.0
```

`--csv` writes the samples *in addition to* the Markdown report on stdout; it is
not a replacement output mode.

## Step 6 — Generate qualitative risk statements (`risk generate`)

The quantification above is deterministic and offline. The complementary
`risk generate` command produces **NIST SP 800-30 narrative risk statements** for
your gaps using an LLM. It reads a gap report (the `--gaps` input is the JSON from
[Run a gap analysis](run-gap-analysis.md)) plus a system-context YAML describing
your environment.

> **Requires an LLM API key.** `risk generate` calls a model provider through
> LiteLLM. You must export the provider's key (for example `OPENAI_API_KEY`,
> `ANTHROPIC_API_KEY`) — or point `--model` at a local model such as
> `ollama/llama3.3`. Without a key the command fails cleanly (shown below); it
> does **not** produce risk statements.

First write a `context.yaml` describing the system. The required fields are
`organization`, `system_name`, `system_description`, and `hosting`:

```yaml
organization: Meridian Fintech
system_name: Payments Platform
system_description: >-
  A PCI-scoped payments platform: a React front end, a Node.js API tier,
  and a PostgreSQL cardholder datastore.
hosting: AWS (us-east-1)
data_classification:
  - PCI-CDE
  - PII
threat_actors:
  - External threat actors (financial)
frameworks:
  - soc2-tsc
```

Then point `risk generate` at the gap report and the context, choosing a model:

**Bash / Linux / macOS**

```bash
evidentia risk generate \
  --context context.yaml \
  --gaps gap-report.json \
  --model gpt-4o \
  --output risks.json
```

**PowerShell (Windows)**

```powershell
evidentia risk generate `
  --context context.yaml `
  --gaps gap-report.json `
  --model gpt-4o `
  --output risks.json
```

Key flags (confirm the full set with `evidentia risk generate --help`):

| Flag | Purpose |
| --- | --- |
| `--context`, `-c` | **Required.** System-context YAML. |
| `--gaps`, `-g` | Gap report JSON from `evidentia gap analyze`. If omitted, the most recent report from the per-user gap store is used. |
| `--gap-id` | Generate a statement for a single gap by its ID instead of the whole report. |
| `--model`, `-m` | LLM model name (`gpt-4o`, `claude-sonnet-4`, `ollama/llama3.3`, …). |
| `--output`, `-o` | Output path for the generated risks (default `risks.json`). |
| `--limit`, `-n` | Cap the number of gaps processed (handy for a quick test run). |
| `--emit-trace` | Attach a Policy Reasoning Trace (PRT) to each statement; the trace flows through OSCAL emit and Sigstore signing. |

You must supply either `--gaps` or `--gap-id`; with neither, the command exits
with `Error: must provide either --gaps or --gap-id.`

### What you'll see without a key configured

Running `risk generate` with no provider key set is a clean failure, not a crash.
The context and gap report load, the model is invoked, the provider raises an
authentication error, Evidentia catches it per gap (after a few Instructor
retries), and the run finishes by reporting zero statements generated:

```
Loading system context from context.yaml...
Loaded: Meridian Fintech / Payments Platform
Generating risk statements for 1 gaps using model gpt-4o...
LiteLLM completion() model= gpt-4o; provider = openai
[ERROR] evidentia.ai.risk_statements: Risk-statement generation failed for soc2-tsc:CC7.1 (validation_exhausted): ...
    litellm.AuthenticationError: AuthenticationError: OpenAIException - The api_key client option must be set either by passing api_key to the client or by setting the OPENAI_API_KEY environment variable
...
Generated 0/1 risk statements
Output: risks.json
```

Export the appropriate key and re-run to get real, populated risk statements
written to `--output`.

## What's next

- **Produce the `--gaps` input**: [Run a gap analysis](run-gap-analysis.md).
- **Track remediation of those gaps**: [Manage a POA&M](manage-poam.md).
- **Full flag reference**: [CLI reference → `evidentia risk`](../4-reference/cli.md).

## Got stuck?

- **`Error: <file> must be a list of scenario records (got dict).`** —
  `risk quantify --scenarios` expects a top-level YAML/JSON **list**. Wrap your
  scenario(s) in `-` list items, even for a single scenario.
- **`failed validation: ... primary_loss / Field required`** — every scenario
  needs `name`, `description`, `tef`, `vulnerability`, and `primary_loss`.
  `secondary_loss` is the only loss factor that defaults (`0`).
- **`Value error, PERTRange must satisfy low <= most_likely <= high`** — a
  3-point range was supplied out of order. Fix the ordering of `low` /
  `most_likely` / `high`.
- **Monte Carlo numbers change every run** — you did not pass `--seed`. Add an
  explicit `--seed <int>` for reproducible P10/P50/P90 bands.
- **`--iterations` / `--seed` / `--csv` seem to do nothing** — they apply only to
  `--method fair-mc`. Under the default `open-fair` they are ignored.
- **`risk generate` reports `Generated 0/N risk statements`** — almost always a
  missing or invalid LLM API key (see the auth-error transcript above). Export
  the provider key for your `--model` and re-run.
- **`Error: must provide either --gaps or --gap-id.`** — `risk generate` needs a
  gap source. Pass `--gaps <report.json>`, or run a `gap analyze` first so the
  per-user gap store has a latest report to fall back on.
