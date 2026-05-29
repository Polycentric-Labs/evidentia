# Quickstart — your first gap analysis in 5 minutes

This guide gets you from a fresh install to a real OSCAL Assessment Results document.

## Prerequisites

- Python 3.12+ (`python --version` to check)
- No prior setup — this quickstart uses `evidentia init` to scaffold a starter control inventory, so you can run end-to-end from a fresh install

## Step 1 — Install (30 seconds)

```bash
pip install evidentia
```

Verify:

```bash
evidentia version
# → Evidentia v0.10.6 / Python 3.12.x
```

## Step 2 — Pick a framework (10 seconds)

```bash
evidentia catalog list --tier=A
```

You'll see ~30 Tier-A (production-grade, verbatim-licensed) frameworks. For this quickstart, we'll use NIST 800-53 Rev 5 Low baseline (~149 controls — small enough to inspect by hand).

## Step 3 — Scaffold an inventory and run gap analysis (60 seconds)

`evidentia gap analyze` is inventory-driven: you give it a file describing the
controls your organization *has* (`--inventory`) and the frameworks to measure
*against* (`--frameworks`). Scaffold a starter inventory — this writes
`evidentia.yaml`, `my-controls.yaml`, and `system-context.yaml` into the current
directory:

```bash
evidentia init --preset nist-moderate-starter
```

Then run the analysis against the Low baseline (`--inventory`, `--frameworks`,
and `--output` are the three flags you need):

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-low \
  --output=gap-report.json
```

Evidentia prints a summary table to the console and writes the full report to
`gap-report.json`:

```
                 Gap Analysis Summary
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ Metric                     ┃     Value ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ Total controls required    │       149 │
│ Total gaps                 │       112 │
│ Critical                   │         6 │
│ High                       │        24 │
│ Medium                     │        58 │
│ Low                        │        24 │
│ Coverage                   │     24.8% │
│ Efficiency opportunities   │         3 │
└────────────────────────────┴───────────┘
```

(Counts are illustrative — the starter inventory is intentionally small, so most
Low-baseline controls show up as gaps. Edit `my-controls.yaml` with your real
controls to see your true posture.)

## Step 4 — Emit OSCAL Assessment Results (10 seconds)

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-low \
  --format=oscal-ar \
  --output=assessment-results.json
```

This produces a NIST OSCAL Assessment Results 1.2.1 document. Validate with:

```bash
pip install compliance-trestle
trestle validate --type oscal-ar --file assessment-results.json
# → PASS
```

## Step 5 — Verify the artifact chain (60 seconds)

The wheel you installed has a PEP 740 attestation:

```bash
pip install pypi-attestations
pypi-attestations verify pypi \
  --repository https://github.com/Polycentric-Labs/evidentia \
  "pypi:evidentia-0.10.6-py3-none-any.whl"
# → OK: evidentia-0.10.6-py3-none-any.whl
```

The container image is cosign-signed (if you used the Docker install path):

```bash
cosign verify ghcr.io/polycentric-labs/evidentia:v0.10.6 \
  --certificate-identity-regexp 'https://github\.com/Polycentric-Labs/evidentia/\.github/workflows/release\.yml@refs/tags/v.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
# → "The cosign claims were validated"
```

Full verification recipes: see [`docs/verification.md`](../../verification.md).

## What's next

- **Run against your own controls**: point `--inventory` at your real control inventory (YAML/CSV/JSON). To fold in collected evidence, run a collector (see [first-collection.md](first-collection.md)) and pass `--findings` with `--format oscal-ar`.
- **Wire to a CI gate**: emit SARIF for GitHub Code Scanning ([guide](../2-guides/emit-sarif.md)).
- **Drive from an AI agent**: enable the MCP server ([guide](../2-guides/run-gap-analysis.md)).
- **Add a custom framework**: write your own catalog YAML ([guide](../5-compliance/contributing-a-catalog.md)).

## Got stuck?

- Common issues + fixes: [`6-project/faq.md`](../6-project/faq.md)
- Open a discussion: [github.com/Polycentric-Labs/evidentia/discussions](https://github.com/Polycentric-Labs/evidentia/discussions)
- Report a bug: [github.com/Polycentric-Labs/evidentia/issues/new](https://github.com/Polycentric-Labs/evidentia/issues/new)
