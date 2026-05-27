# Quickstart — your first gap analysis in 5 minutes

This guide gets you from a fresh install to a real OSCAL Assessment Results document.

## Prerequisites

- Python 3.12+ (`python --version` to check)
- A directory of evidence files — for this quickstart, we'll use Evidentia's bundled test fixtures so you can run end-to-end with zero setup

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
evidentia catalog list --maturity=tier-a
```

You'll see ~30 Tier-A (production-grade, verbatim-licensed) frameworks. For this quickstart, we'll use NIST 800-53 Rev 5 Low baseline (~149 controls — small enough to inspect by hand).

## Step 3 — Run gap analysis (60 seconds)

Using Evidentia's bundled test fixtures:

```bash
evidentia gap analyze \
  --framework=nist-800-53-rev5-low \
  --evidence-dir=$(python -c "import evidentia; print(evidentia.__path__[0] + '/test_fixtures/evidence/')")
```

Output:

```
Gap analysis complete: nist-800-53-rev5-low
  ✓ Implemented: 87 controls
  ⚠ Partial: 21 controls
  ✗ Gaps: 41 controls
  ⊘ Not applicable: 0 controls

  Faithfulness score: 0.87 (threshold 0.30; framework-aware)
  Output: 3,536 lines of finding detail
```

## Step 4 — Emit OSCAL Assessment Results (10 seconds)

```bash
evidentia gap analyze \
  --framework=nist-800-53-rev5-low \
  --evidence-dir=$(python -c "import evidentia; print(evidentia.__path__[0] + '/test_fixtures/evidence/')") \
  --format=oscal > my-assessment-results.json
```

This produces a NIST OSCAL Assessment Results 1.2.1 document. Validate with:

```bash
pip install compliance-trestle
trestle validate --type oscal-ar --file my-assessment-results.json
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

- **Run against your own evidence**: point `--evidence-dir` at your real evidence directory (see [first-collection.md](first-collection.md) for the collector setup).
- **Wire to a CI gate**: emit SARIF for GitHub Code Scanning ([guide](../2-guides/emit-sarif.md)).
- **Drive from an AI agent**: enable the MCP server ([guide](../2-guides/run-gap-analysis.md)).
- **Add a custom framework**: write your own catalog YAML ([guide](../5-compliance/contributing-a-catalog.md)).

## Got stuck?

- Common issues + fixes: [`6-project/faq.md`](../6-project/faq.md)
- Open a discussion: [github.com/Polycentric-Labs/evidentia/discussions](https://github.com/Polycentric-Labs/evidentia/discussions)
- Report a bug: [github.com/Polycentric-Labs/evidentia/issues/new](https://github.com/Polycentric-Labs/evidentia/issues/new)
