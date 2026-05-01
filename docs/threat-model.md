# Evidentia threat model

> Public threat model for Evidentia, capturing the external input
> surfaces, the sanitization layers that protect them, and the
> currently-acknowledged gaps. Reviewed each release per
> [`docs/release-checklist.md`](release-checklist.md) Step 5;
> tracked alongside [`docs/enterprise-grade-accepted-findings.md`](enterprise-grade-accepted-findings.md)
> (the per-finding rationale appendix for static-analysis accepts).

**Last full deep-pass**: 2026-05-01 (v0.7.6 P1 Q2). 54 surfaces
walked across 5 tiers. **0 HIGH, 0 MEDIUM, 3 LOW** — all
design-choice or pre-existing intentional patterns. v0.7.5
sanitization patterns confirmed at every callsite.

---

## Why this doc exists

- Auditors + integrators get a single canonical place to map
  "what does Evidentia do with my data?" to "what stops it from
  doing the wrong thing?"
- Pre-release-review v4's G5 gate (CISA Secure by Design Pledge
  alignment) refuses to advance past Step 1 on a minor release
  if `docs/threat-model.md` is missing or > 180 days stale. This
  doc satisfies G5 ahead of the v0.8.0 minor.
- Future deep-pass reviews diff against this doc rather than
  starting from scratch — coverage decay shows up as new
  un-sanitized surfaces vs. the prior version.

---

## Trust boundaries

Evidentia runs on the operator's machine + their controlled
infrastructure. Trust boundaries cross at:

1. **CLI flags + arguments** (operator-controlled; trusted)
2. **Environment variables** (operator-controlled; trusted for
   config, gated for secrets — see "Secret handling" below)
3. **File system reads** (operator-controlled paths; resolved
   through `validate_within` for any user-controlled path)
4. **REST API request bodies** (browser / consumer / CI;
   semi-trusted — Pydantic-validated with `extra="forbid"`)
5. **OSCAL / YAML / JSON deserialization** (semi-trusted — safe
   parsers + strict Pydantic models; never `pickle`, never
   `yaml.unsafe_load`, never `eval`)
6. **Network egress** (LLM providers, Sigstore/Rekor, GitHub,
   PyPI; HTTPS-only with cert validation; air-gap mode refuses
   non-loopback)
7. **Subprocess execution** (only `gpg` for AR signature
   verification; always `shell=False`)

Trust ranks: CLI flags + env > file system > REST body > OSCAL
input > LLM response (treated as untrusted by contract — see
v0.8.0-plan §DFAH for the determinism harness).

---

## Surface coverage by tier

54 external input surfaces grouped into 5 tiers.

### Tier A — REST API request handlers (16 surfaces)

**Status**: clean. All Pydantic-protected with `extra="forbid"`.

- 16 REST endpoints under `/api/*` (POST `/api/gap/analyze`,
  POST `/api/risk/generate`, GET `/api/gap/diff`, etc.)
- Pydantic validation on every request body
- Path validation via `validate_within` for any file path or
  gap-store key flowing through the request
- Network guards on LLM `model` + `api_base` request fields via
  `evidentia_core.network_guard.check_llm_model()`
- CORS origin allowlist on the FastAPI app
- v0.7.5 R2 / `oscal verify` UX fix lives here — `/api/oscal/verify`
  now returns `PASS (no verification surface)` for metadata-only
  ARs instead of misleading FAIL

### Tier B — CLI + file deserialization (18 surfaces)

**Status**: clean. All using `safe_load` + Pydantic models.

- `evidentia gap analyze` (inventory path, findings, output,
  frameworks, organization, system_name, optional GPG signing)
- `evidentia risk generate` (gap report path, gap-id filter, model)
- `evidentia catalog` (load, upload, list, show)
- `evidentia config` (get, set, validate)
- `evidentia.yaml` parsing — `yaml.safe_load` + `EvidentiaConfig.model_validate`
- Bundled + user-imported catalogs via `resolve_catalog_path` with
  allowlist
- OSCAL Assessment Result deserialization via Pydantic models

### Tier C — Network egress + collector integration (10 surfaces)

**Status**: clean except for 1 LOW finding (informational; see
"Accepted findings" below).

- Collector credential env vars (`COLLECTOR_*`) — trusted import
  paths; per-variable character-set allowlist optional for v0.8.0
- LLM provider requests — fixed HTTPS endpoint per provider;
  model + api_base validated against network_guard
- Sigstore / Rekor verification — hardcoded HTTPS; offline-mode
  blocks
- GitHub releases API — hardcoded endpoint; offline-mode blocks
- Config `llm_api_base` validation via `network_guard.check_llm_model()`
- HTTP proxy configuration via standard Python env vars
- TLS certificate validation: `verify=True` default everywhere
- DNS resolution pre-flight via `is_loopback_or_private()` —
  enforces RFC-1918 / loopback-only when `--offline` is set

### Tier D — OSCAL deserialization + verification (7 surfaces)

**Status**: clean except for 1 LOW finding (legacy compatibility;
see "Accepted findings" below).

- OSCAL Catalog parsing (groups → controls → enhancements)
- OSCAL control prose extraction (recursive parts concatenation)
- OSCAL component-definition import
- CISO Assistant JSON export parsing
- Gap report (Assessment Result) loading + verification
- Per-resource SHA-256 digest verification
- GPG signature verification — `shell=False` subprocess to `gpg`

### Tier E — Internal data flow + context injection (3 surfaces)

**Status**: clean except for 1 LOW finding (deferred; see
"Accepted findings" below).

- Risk-context file path (`context_path` parameter)
- LLM prompt generation — structured data only; no free-text
  user prompts that could template-inject
- Evidence reference resolution — metadata annotations only; no
  external URL dereferencing

---

## v0.7.5 sanitization checklist (validated at every release)

- [x] Path-traversal protection via `validate_within()` at 14+
      callsites (added v0.7.5 S1; landed in
      `evidentia_core.security.paths`)
- [x] Request validation: Pydantic `extra="forbid"` on all REST
      schemas
- [x] Safe deserialization: `yaml.safe_load`, `json.load` +
      `model_validate` (never `pickle`, `eval`, `yaml.unsafe_load`)
- [x] Subprocess safety: `shell=False` on all calls (only `gpg`
      for AR signature verification)
- [x] LLM provider gating: `check_llm_model()` whitelist +
      `api_base` validation
- [x] Environment-variable interpolation: ReDoS-safe regex
      (bounded character class, not polynomial alternation; v0.7.5
      S2 fix in `evidentia_core/models/catalog.py`)
- [x] Gap-store key validation: 16-hex-character format enforced
      (no path injection)
- [x] Offline-mode enforcement: `network_guard.set_offline(True)`
      flips a process-wide flag that refuses non-loopback targets
- [x] Stack-trace redaction: API errors logged internally via
      `evidentia_core.audit.logger`, returned externally as generic
      500s correlated by `request_id` (v0.7.5 S3 fix in
      `routers/integrations.py`)

---

## Accepted findings

### LOW — informational / design-choice

The 3 LOW findings from the v0.7.6 deep-pass don't block release.
Each is documented for transparency:

#### C1 — Collector credential env scope (LOW)

- **Issue**: `COLLECTOR_*` environment variables lack a
  per-variable character-set allowlist. A malformed env value
  could pass through to the collector untouched.
- **Mitigation in place**: Collectors are trusted code paths.
  Users only run collectors against systems they own.
- **Action**: Document expected character set in collector docs;
  defer regex enforcement to v0.8.0 once the collector framework
  stabilizes around the v0.7.7 SQL-family additions.

#### D1 — Legacy gap-report `inventory_source` optional (LOW)

- **Issue**: Pre-v0.7.0 gap reports may lack the
  `inventory_source` field; the loader falls back to
  `organization`.
- **Mitigation in place**: Acceptable legacy support boundary.
  New reports (v0.7.0+) always populate `inventory_source`.
- **Action**: Continue accepting legacy reports through the
  v0.7.x line; v0.8.0 may deprecate the fallback path with a
  one-release migration window.

#### E1 — `context_path` validation deferred (LOW)

- **Issue**: The `context_path` parameter passed to
  `RiskStatementGenerator` is validated by Typer at the CLI
  boundary but not by `validate_within` at the REST API
  boundary.
- **Mitigation in place**: The REST `/api/risk/generate` handler
  has Pydantic schema validation; the path itself goes to a
  read-only generator. CLI usage is fully validated.
- **Action**: Add `validate_within(STATIC_DIR)` to the REST
  handler in v0.8.0 alongside the AI-moat hardening work
  ([`v0.8.0-plan.md`](v0.8.0-plan.md) §P0).

### Static-analysis accepts (Scorecard + CodeQL)

See [`docs/enterprise-grade-accepted-findings.md`](enterprise-grade-accepted-findings.md)
for the per-alert rationale on:
- 3 CodeQL `py/path-injection` false positives on the
  `validate_within` sanitizer (#71/#72/#73). Long-term fix
  in v0.7.7 CF3: contribute a custom CodeQL pack declaring
  `validate_within` as a `BarrierGuard`.
- 2 OpenSSF Scorecard accepts: `contents: write` for release-
  notes append (#75 + pre-existing #29/#30) +
  `Pinned-Dependencies` `==X.Y.Z` PyPI pin (#74).

---

## Out of scope

These categories are **not** addressed by this threat model:

- **Supply-chain attacks**: covered separately by the SLSA L3 +
  PEP 740 + cosign + CycloneDX SBOM chain documented in
  [`enterprise-grade.md`](enterprise-grade.md) §HIGH and the
  [`sigstore-quickstart.md`](sigstore-quickstart.md) walkthrough.
- **LLM injection / AI-moat threats**: AI features are designed
  by-contract to treat LLM output as untrusted. Determinism +
  policy-reasoning-trace work for v0.8.0 (DFAH + PRT per
  [`v0.8.0-plan.md`](v0.8.0-plan.md)) hardens this surface.
- **Social engineering** on individual operators
- **Physical security** of operator workstations
- **Denial of service** under sustained load — covered separately
  by [`benchmarks.md`](benchmarks.md) (perf budget) + future
  rate-limiting work in v0.8.0
- **Side-channel attacks** on cryptographic primitives — relies
  on the standard-library + `cryptography` package guarantees
- **Cryptographic key rotation cadence** — covered by the
  release-checklist secret-rotation row + Sigstore short-lived
  cert model

---

## Hardening backlog

### v0.7.7 (in motion)

- **CF3** — CodeQL custom sanitizer pack: contribute a `.qll`
  declaring `validate_within` as a `BarrierGuard` to close the
  3 path-injection false positives (#71/#72/#73) at the analysis
  layer rather than dismissing each instance.
- **CF4** (this doc) — public threat model elevation. ✅
- **C1 partial** — character-set regex allowlist for `COLLECTOR_*`
  env vars (optional; depends on cycle headroom alongside the
  5 SQL adapters).

### v0.8.0 (queued)

- **E1** — `validate_within(STATIC_DIR)` on REST
  `/api/risk/generate` handler.
- Rate-limit enforcement on REST endpoints.
- Telemetry opt-out mechanism.
- AI-moat hardening: DFAH determinism harness + PRT policy
  reasoning traces + plugin contract for out-of-tree extensions.

### v0.9.0+ (open)

- WORM evidence retention backends (S3 Object Lock / Azure
  Immutable Blob / GCS Bucket Lock) per
  [`v0.7.9-plan.md`](v0.7.9-plan.md) P2.
- Continuous Monitoring (CONMON) capability surface for federal
  compliance per the domain-expert input log.

---

## Review cadence

This doc is reviewed at every release per
[`release-checklist.md`](release-checklist.md) Step 5. A full
deep-pass walk (re-walk of every external input surface, not just
diff scope) runs at every minor release per pre-release-review
v4 §G5 + on a quarterly cadence regardless of release activity
per Step 11.

---

*First published v0.7.7 (2026-05). Origin: promoted from a
project-internal deep-pass note to a public-surface doc to
satisfy pre-release-review v4 G5 (threat-model existence gate)
ahead of the v0.8.0 minor release. The internal note remains in
`.local/` for cycle-by-cycle drafting; the public doc here is the
canonical reference for auditors + integrators.*
