# Evidentia in 90 seconds

> The shortest path from `pip install` to a signed OSCAL Assessment
> Results document. Five commands, ~90 seconds on a warm Python.

This is the **fastest** way to see Evidentia work. For the deeper
walkthrough — multiple frameworks, AI risk statements, evidence
collection — see [the README "End-to-end walkthrough" section](../README.md#end-to-end-walkthrough-with-sample-data).
For full setup help, see [`troubleshooting.md`](troubleshooting.md).

---

## Prerequisites

- Python 3.12 or newer (`python --version`)
- A virtual environment (recommended)

```bash
python -m venv .venv
source .venv/bin/activate    # macOS/Linux
# or: .venv\Scripts\activate  # Windows
```

---

## The 5 commands

```bash
# 1. Install (~30 seconds; ~50 MB with the bundled web UI)
pip install "evidentia[gui]"

# 2. Verify the install
evidentia version
# expected: Evidentia v0.7.5 (or newer)

# 3. Run gap analysis on the bundled Meridian fintech sample
evidentia gap analyze \
  --inventory examples/meridian-fintech/my-controls.yaml \
  --frameworks nist-800-53-rev5-moderate,soc2-tsc \
  --output report.json \
  --format oscal-ar

# 4. Inspect the OSCAL Assessment Results document
python -c "
import json
ar = json.load(open('report.json'))['assessment-results']
print('Findings:', len(ar.get('local-definitions', {}).get('findings', [])))
print('Schema:', ar['metadata']['oscal-version'])
print('Title:', ar['metadata']['title'])
"

# 5. Verify integrity (re-hashes embedded evidence + checks signature)
evidentia oscal verify report.json
# expected: PASS (or PASS (no verification surface) if AR has no
#           embedded evidence or signature)
```

That's it. The AR is OSCAL 1.1.2-spec, ready to ingest into any
OSCAL-compatible audit pipeline (`compliance-trestle`, RegScale,
oscal-compass, etc.).

---

## What just happened

- **Step 3** ran the same gap analysis Vanta / Drata / AuditBoard
  charge $30K-$80K/year per framework for — except as a library call
  against a bundled NIST 800-53 catalog, with output in OSCAL native
  format (which Vanta/Drata/AuditBoard ship **zero of** today).
- **Step 4** confirmed the output is structurally valid OSCAL.
- **Step 5** ran the integrity verifier — re-hashes every embedded
  evidence resource and checks any GPG / Sigstore signature. The
  v0.7.5 R2 fix means metadata-only ARs return `PASS (no verification
  surface)` (a no-op pass) instead of misleading FAIL.

---

## Add a Sigstore signature

To produce a cryptographically signed AR (Sigstore keyless OIDC,
no key custody required):

```bash
# Install the optional sigstore extra
pip install "evidentia[sigstore]"

# Sign the AR (will open a browser for OIDC; returns
# report.json.sigstore.json next to it)
evidentia oscal sign report.json

# Verify the signature
evidentia oscal verify --require-signature \
  --expected-identity you@example.com \
  --expected-issuer https://github.com/login/oauth \
  report.json
```

For the air-gap path (GPG-only, no internet), see
[`air-gapped.md`](air-gapped.md). For deep Sigstore details, see
[`sigstore-quickstart.md`](sigstore-quickstart.md).

---

## Add the web UI

```bash
evidentia serve
# starts FastAPI + the bundled React SPA at http://127.0.0.1:8000
```

The web UI mirrors the CLI: framework browser, gap analysis, gap
diff, risk-statement generation. Auth is your local network; bind
to `0.0.0.0` only behind a reverse proxy.

For Docker:

```bash
docker run --rm -p 8000:8000 ghcr.io/polycentric-labs/evidentia:v0.7.5
```

The image is cosign-signed + SLSA L3 attested per release. See
[`sigstore-quickstart.md`](sigstore-quickstart.md#verifying-the-published-container-image-v075)
for verification one-liners.

---

## Where to go next

- **Use as a GitHub Action**: [README §Use as a GitHub Action](../README.md#use-as-a-github-action) — drop in `uses: polycentric-labs/evidentia/.github/actions/gap-analysis@v0` for PR-time gap regressions.
- **Generate AI risk statements**: [README §Generate AI risk statements](../README.md#generate-ai-risk-statements) — turn gaps into stakeholder-ready risk-register entries via any LLM provider.
- **Bundle in your own project**: `from evidentia_core import GapAnalyzer; report = GapAnalyzer().analyze(inventory, frameworks)` — Evidentia is library-first; the CLI + REST API are thin wrappers.
- **Run in air-gap**: [`air-gapped.md`](air-gapped.md) covers the offline paths for FedRAMP High / CMMC Level 2 / EU sovereign-cloud deployments.
- **Custom catalog**: [README §Add a new framework catalog](../README.md#add-a-new-framework-catalog) — your licensed copy of any Tier-C framework lands via `evidentia catalog import`.

---

*Last reviewed: v0.7.6 cycle (added in v0.7.6 from `Untitled 18.md`
#8 quickstart polish; replaces ad-hoc scattered first-run guidance
across README and the docs/ tree).*
