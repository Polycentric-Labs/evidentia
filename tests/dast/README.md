# Evidentia DAST tests (v0.9.5 P1.2)

Dynamic Application Security Testing scaffolding for the
pre-release-review Step 4 capability-matrix DAST sub-step.

## What's here

- `test_openapi_fuzz.py` — Schemathesis fuzz the FastAPI OpenAPI
  spec; surfaces input-validation gaps the unit tests don't cover
  (large strings, unicode edge cases, schema-violation requests).
- `playwright.config.ts` — Playwright config for end-to-end UI
  probing against a locally-running `evidentia serve` instance.

The DAST suite is **opt-in** and NOT part of the default pytest
collection. Tests are kept under this dedicated directory + run
via an explicit invocation so a flaky DAST baseline can't gate
the unit/integration suite that the daily CI run depends on.

## Pre-flight (one-time)

```bash
uv sync --all-packages          # pulls schemathesis + playwright
uv run playwright install        # downloads chromium/firefox/webkit
```

## Running

```bash
# OpenAPI fuzz only (faster):
uv run pytest tests/dast/test_openapi_fuzz.py -v

# Playwright UI probing only (requires `evidentia serve` running):
uv run pytest tests/dast/test_playwright_e2e.py -v

# Full DAST suite:
uv run pytest tests/dast/ -v
```

## Integration with pre-release-review

`docs/release-checklist.md` Step 4 (DAST sub-step) prescribes
running the DAST suite at every minor release. Pre-release-review
v4 SKILL guidelines #G11 (DAST runtime probing in Step 4)
captures the framework expectation; the actual scope of DAST per
release is the in-repo capability-matrix.md DAST row.

## Threat model

DAST is **complementary** to the existing SAST (mypy, ruff, code
review). It catches:

- Input validation gaps (length, encoding, schema)
- Missing rate limits on previously-untested endpoints
- Error-message information leakage (stack traces, file paths)
- Authentication bypasses through malformed inputs
- CORS misconfigurations

It does NOT catch:

- Business-logic flaws (those are unit/integration tests)
- Supply-chain compromises (those are osv-scanner + Sigstore)
- Authorization-policy bugs that the test inputs don't trigger
