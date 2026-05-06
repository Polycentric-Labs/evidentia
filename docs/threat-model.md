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

## v0.7.9 attack-surface delta (SHIPPED 2026-05-04 at tag `v0.7.9`)

The v0.7.9 ship adds **12 new public surfaces** across the TPRM
module + the vendor-risk-collector quartet + OSCAL TPRM emit.
All inherit the established defense baseline (Pydantic
`extra="forbid"`; `validate_within` for path inputs; UUID-shape
validation for IDs; manual `HTTPException(400, ...)` for runtime
body errors per the v0.7.8 F-V08-DAST-3 invariant; never accept
secrets via CLI args or REST request bodies; env-var-only
credential sourcing per CLAUDE.md secret-handling protocol).
Specific new surfaces + their hardening:

### P0.1 — TPRM vendor inventory (CLI + REST + storage)

5 new CLI verbs (`evidentia tprm vendor add/list/show/edit/
delete`), 5 new REST endpoints (`/api/tprm/vendors` CRUD + cadence
preview), and JSON-file persistence under platformdirs-backed
user-dir. Surfaces inherit `validate_within` + UUID-shape
validation; manual `HTTPException` preserves F-V08-DAST-3 invariant.
REST `create_vendor`/`replace_vendor` operate on
`model_copy(update=...)` of the request DTO rather than mutating
it directly (closes Continuous-review H-3). `save_vendor` writes
atomically via tmp-file + `os.replace` (M-1 fix). `EvidenceRef`
enforces its two-mode contract (artifact_id OR file_path+sha256)
via `@model_validator` (H-1 fix).

### P0.2 — Due-diligence questionnaire generator + ingest

`evidentia tprm dd-questionnaire generate/ingest` CLI + 1 REST
endpoint. 5 input formats (evidentia-generic / caiq-lite /
caiq-full all packaged + sig / sig-lite via `--from-template`
BYO XLSX). 3 output formats (JSON / CSV / XLSX behind new
`[xlsx]` extra). Hardening:

- **CSV-injection defense** (CWE-1236) on every operator-supplied
  user-content cell (vendor name, fourth-party names, region,
  relationship_owner, regulatory_classification, question_text,
  notes) via `_csv_safe()` OWASP single-quote prefix. Same
  defense applied to XLSX render path as defense-in-depth even
  though XLSX doesn't auto-evaluate formulas the way CSV
  spreadsheet importers do.
- **Format-string foot-gun** closed: `title_template.replace(
  "{vendor_name}", vendor.name)` instead of
  `title_template.format(vendor_name=...)` so a vendor name
  containing `{}` / `{0}` / `{secret}` cannot raise KeyError or
  walk format args (P0.3+P0.2-first Continuous H-3 fix).
- **Ingest deserialization safety**: `json.loads` (CWE-502-safe;
  never `pickle.loads` / `yaml.unsafe_load`); `csv.reader` (safe);
  `openpyxl.load_workbook(data_only=True)` (no formula evaluation;
  no VBA macro execution per openpyxl's documented behavior).
- **SIG BYO XLSX template path**: CLI-only (no REST exposure).
  Operator-supplied path validated via Typer's `exists=True`;
  uses `Path` typing; openpyxl's read does not auto-execute
  macros.

### P0.3 — Concentration-risk reporting

`evidentia tprm concentration-report` CLI + 1 REST endpoint;
6 dimensions; HTML/JSON/CSV outputs. Hardening:

- **HTML XSS-safe** via `html.escape` on every operator-supplied
  vendor + value name (Continuous H-1 fix). Single-file output
  (no JS deps; sortable tables via inline click-to-sort JS that
  doesn't execute user content).
- **CSV-injection defense** (`_csv_safe`) on user-content cells.
- **Cloud-provider direct-vs-4P collision** resolved with
  `(direct)`/`(4th-party)` source suffix so two vendors with the
  same name (one `vendor.type==cloud_provider` + one disclosed
  as a 4th-party of another vendor) don't silently overwrite each
  other in the aggregate (Continuous H-2 fix).

### P0.4 — Vendor-risk SaaS collectors (Vanta + Drata + BitSight + SecurityScorecard)

4 new CLI commands (`evidentia collect {vanta,drata,bitsight,
securityscorecard}`) + 4 new REST endpoints + 4 status-endpoint
extensions. All read-only against the upstream vendor APIs.
Hardening:

- **Token sourcing**: env-var only (`VANTA_API_TOKEN` /
  `DRATA_API_TOKEN` / `BITSIGHT_API_TOKEN` /
  `SECURITYSCORECARD_API_TOKEN`); never accepted via CLI args or
  REST request bodies; never echoed in log messages or error
  responses.
- **Auth header diversity**: Vanta + Drata use `Authorization:
  Bearer <token>`; BitSight uses HTTP Basic with token-as-username
  + empty password (wrapped internally; never in URLs); SSC uses
  `Authorization: Token <value>`. Each collector's `_ensure_client`
  builds the header in code, not via URL params.
- **Cross-host pagination guards** (Vanta + Drata + BitSight + SSC):
  `_paginate` refuses to follow `next` URLs pointing off-host
  (CWE-319 cross-host info-leak defense). BitSight additionally
  refuses scheme-downgrade (HTTPS→HTTP) `next` URLs to prevent a
  malicious upstream from leaking the HTTP Basic auth header
  over cleartext HTTP (Continuous F-V09-S1 fix per CWE-319
  cleartext transmission).
- **Stuck-cursor guards** (Vanta + Drata + SSC): if upstream API
  returns the same `endCursor` / `nextPageToken` twice or fails
  the monotonic-output-grew check, loop terminates instead of
  running to the `max_vendors`/`max_companies` cap (Continuous
  H-1 / H-3 fixes).
- **Explicit-key payload-priority** (Drata + SSC): rejects
  fall-through `data.get("data") or data.get("results") or []`
  patterns that mishandle legitimate `{"data": []}` empty pages
  (Continuous H-2 fix per CWE-697).
- **Defensive field-shape detection**: each collector's
  `_is_high_risk` / low-rating detector covers 4-6 documented +
  de-facto API field-shape variants. `BLIND_SPOTS` documents
  the field-shape uncertainty for auditor-grade transparency.

### P0.5 — OSCAL TPRM emit

Extends `evidentia_core.oscal.exporter.gap_report_to_oscal_ar()`
+ adds `--vendor-inventory` flag on `evidentia gap analyze`.
Hardening:

- **Tamper-evident vendor records**: each Vendor lands in
  `back-matter.resources[]` with canonical-JSON `base64.value` +
  SHA-256 `rlinks[].hashes[]`. Same integrity model as the v0.7.0
  finding-resource embedding — tampering with vendor record
  changes hash + fails `evidentia oscal verify`.
- **Deterministic canonical JSON**: `json.dumps(sort_keys=True,
  separators=(",", ":"))` so verifier-side recompute is
  bit-for-bit reproducible.
- **Cross-reference resolution**: vendor's party UUID +
  back-matter resource UUID both equal `Vendor.id` so
  `href: "#<vendor-id>"` references resolve intra-document.

### Defense-in-depth: security-headers middleware

A response-headers middleware
(`evidentia_api.security_headers.SecurityHeadersMiddleware`)
landed in this cycle, closing the v0.7.8 Step 5.A deferred
F-V08-DAST-2 LOW finding (CWE-693). When enabled, every response
carries Content-Security-Policy (locks loads to same-origin;
`frame-ancestors 'none'`), X-Frame-Options DENY, X-Content-Type-
Options nosniff, Referrer-Policy strict-origin-when-cross-origin,
Strict-Transport-Security one year + subdomains, and Permissions-
Policy denying camera/microphone/geolocation/payment/USB/FLoC.
The new `--security-headers / --no-security-headers` flag on
`evidentia serve` defaults to auto — ON for non-loopback binds,
OFF for localhost (dev-loop parity). Operators behind a TLS-
terminating reverse proxy that already injects these headers can
suppress duplicates via `--no-security-headers`.

### v0.7.8 carry-over hardening

- **Snowflake quoted-identifier escape** via `_quote_snowflake_
  identifier()` static helper (Snowflake's documented double-up
  convention; defensive against operator-controlled inputs in
  third-party-managed Snowflake accounts).
- **Snowflake masking-policy + row-access-policy count separation**:
  manifest reflects distinct CoverageCount per evidence source.
- **Databricks PermissionDenied typed catch** replaces v0.7.8
  message-string heuristic with `databricks.sdk.errors.
  PermissionDenied` + `Unauthenticated`. ImportError-safe
  fallback to v0.7.8 heuristic on older SDK.
- **Power BI 1MB byte-cap guard**: `push_rows()` bisects batches
  exceeding 950 KB headroom (Power BI's documented 1 MB body
  limit). Single-row exceedance raises clear `PowerBIPublishError`.

## Hardening backlog

### v0.7.7 (shipped)

- **CF3** — CodeQL custom sanitizer pack: contribute a `.qll`
  declaring `validate_within` as a `BarrierGuard` to close the
  3 path-injection false positives (#71/#72/#73) at the analysis
  layer rather than dismissing each instance.
- **CF4** (this doc) — public threat model elevation. ✅
- **C1 partial** — character-set regex allowlist for `COLLECTOR_*`
  env vars (optional; depends on cycle headroom alongside the
  5 SQL adapters).

### v0.7.9 (in motion)

- **F-V08-DAST-2** — defense-in-depth response headers via
  `SecurityHeadersMiddleware`. ✅ (this doc + CHANGELOG entry).
- **TPRM data-layer hardening** — atomic write semantics in
  `vendor_store.save_vendor`; UUID-shape ID validation +
  `validate_within` belt-and-suspenders; FastAPI `model_copy`
  semantic in REST handlers; `@model_validator` enforcement on
  `EvidenceRef` two-mode reference contract. ✅ (P0.1 first
  slice + Continuous-review fixes).
- **F-V08-CR-MEDIUM Snowflake quoted-identifier hardening** —
  carry-over from v0.7.8 deferred list; theoretical
  (Snowflake doesn't allow `"` in db names by convention) but
  defensive. Lands alongside any P1 Snowflake catalog work.
- **F-V08-CR-MEDIUM Power BI 1MB-per-batch byte guard** —
  carry-over from v0.7.8 deferred list. Lands during P3 docs.

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

## v0.7.12 attack-surface delta (PLANNED — concrete WORM + Monte Carlo + GDPR purge)

The v0.7.12 ship adds **5 new public surfaces** plus 1
fundamental contract refinement:

### Cloud-WORM backends — `S3ObjectLockWORM` / `AzureImmutableBlobWORM` / `GCSBucketLockWORM`

Three new WORMBackend subclasses providing regulator-grade
hardware-WORM enforcement on top of the v0.7.11
`LocalFilesystemWORM` reference impl. The cloud SDKs (boto3,
azure-storage-blob, google-cloud-storage) are gated behind
`evidentia[worm-s3]` / `[worm-azure]` / `[worm-gcs]` extras.

**STRIDE coverage** (vs the existing `WORMBackend` ABC threat
model):

- **Spoofing**: cloud SDK auth chains (boto3 default chain,
  Azure DefaultAzureCredential, GCS Application Default
  Credentials) — operator's responsibility per the runbook
  in `docs/worm-backends.md`. No new attack surface
  introduced; reuses existing cloud-IAM trust chains.
- **Tampering**: payload writes use cloud-WORM primitives (S3
  Object Lock RetainUntilDate, Azure Immutable Blob
  ImmutabilityPolicy.Locked, GCS Bucket Lock); cloud-side
  enforcement is the second line of defense. Sidecar
  metadata is intentionally mutable (operator-managed
  lifecycle tracking) and is NOT subject to retention.
- **Repudiation**: every put / delete / extend_retention /
  legal_hold operation flows through the audit logger
  (RETENTION_RECORD_PUT / RETENTION_RECORD_PURGED /
  RETENTION_LEGAL_HOLD_APPLIED / etc.) for non-repudiable
  operator-action provenance.
- **Information disclosure**: cloud auth tokens are never
  logged, displayed, or persisted; standard secret-scrubbing
  applies to all cloud-side error messages surfaced via
  WORMBackendError.
- **Denial of service**: cloud SDK retries via tenacity bounded-
  exponential-backoff (already in `evidentia-core`); cloud
  rate-limits surface as `HttpResponseError` / `ClientError`
  / `GoogleAPIError` and propagate as WORMBackendError.
- **Elevation of privilege**: 3-layer delete defense
  (legal_hold → is_locked → lifecycle != EXPIRED) at the
  application layer, plus cloud-side enforcement (S3
  Compliance mode: even AWS root cannot bypass; Azure
  Locked: even account owner cannot reduce; GCS Bucket
  Lock: even project owner cannot reduce post-lock).

### GDPR Article 17 `purge_immediately` operator workflow

New `WORMBackend.purge_immediately(record_id, *,
gdpr_request_ref, operator_id)` method handles
right-to-erasure with full audit-trail provenance.
Pre-conditions: GDPR-shaped record (retention_period_days=0,
no legal hold), non-empty operator_id + gdpr_request_ref.
The operator override is scoped: it does NOT permit purge of
non-GDPR records (those follow standard retention path) and
does NOT bypass legal_hold (which trumps GDPR per most legal
frameworks). Audit-trail snapshot returned even after delete
— legal-counsel-defensible artifact persists in the audit
log independent of the record itself.

### FAIR Monte Carlo simulation — `evidentia risk quantify --method fair-mc`

Stdlib-only Beta-PERT sampling (no numpy dep added) over the
existing `OpenFAIRScenario` schema. New surface = a CLI flag +
a `SimulationResult` Pydantic model + an optional CSV export
of per-iteration ALE samples. Threat model unchanged from
v0.7.11 deterministic-PERT path; same input validation, same
output sanitization. CSV export uses `csv.writer` (no
injection surface).

### CodeQL CRITICAL #92 closure — `securityscorecard` portfolio_id allow-list

Pre-v0.7.12: REST request body `payload` (dict[str, Any], no
Pydantic validation) flowed `portfolio_id` into
`f"/portfolios/{portfolio_id}/companies"` at
`_paginate_portfolio` line 330; httpx then resolved the
URL against the SSC base URL — letting a path-traversing
portfolio_id rewrite the request path (CVE class: partial
SSRF, CWE-918, CVSS 7.6).

v0.7.12 adds `_validate_portfolio_id_shape` regex
allow-list (`^[A-Za-z0-9_-]{1,128}$`) applied at 3 layers:
REST router (early-fail with 400), collector __init__
(pre-construction reject), and `_resolve_portfolio_id`
(defense-in-depth against malicious SSC API responses).
29 new validation tests cover the allow-list edge cases.

### Codecov path-resolution fix

Not strictly an attack-surface change; the `[tool.coverage.run]
relative_files = true` + codecov.yml `fixes:` removal closes
the v0.7.10/v0.7.11 0%-badge bug. No threat model impact.

### `bump_version.py` inter-package pin tightening

Defensive hardening rather than a new attack surface.
Closes the v0.7.11 PyPI propagation foot-gun where
`pip install evidentia==X.Y.Z` could resolve a cached
`evidentia-core==X.Y.Z-1` against loose `>=0.7.0,<0.8.0`
range pins. v0.7.12 ship has all inter-package pin lower
bounds tightened to the current release version.

---

## v0.7.13 attack-surface delta

v0.7.13 is a wrap-up release for the v0.7.x cycle: dependency
modernization (Dependabot #18 GH Actions major bumps + Dependabot
#21 frontend major bumps), Codecov coverage-upload fix, P3
carry-over closures (M-9 OSCAL UUID test + L-2 high-risk field
shapes + L-4 SIG BYO debug logging + 5 of 9 v0.7.8 LOWs), and
release-notes hygiene (9 stub bodies backfilled + workflow
auto-population from CHANGELOG).

### No new attack surface

v0.7.13 adds zero new public surfaces. The work is entirely:

- **Dependency upgrades** (supply-chain version bumps) — these
  reduce attack surface (newer pinned versions of GitHub Actions
  + npm-dev tooling) without introducing new entry points.
- **Internal hygiene** (Codecov fix, P3 closures, release-notes
  workflow) — these touch test/CI/release tooling, not runtime
  surfaces accessible to external attackers.
- **Documentation** (Dockerfile pinning policy, M-4 deferral
  doc, release-notes audit log) — pure markdown.

### Carry-forward state

All v0.7.12 trust boundaries + STRIDE entries carry forward
unchanged. The 6 retention/WORM stores, the 3 cloud-WORM
backends, the GDPR purge-flow, and the FAIR Monte Carlo
simulator all stay as documented in §v0.7.12.

### `_is_high_risk` extended field shapes (L-2 closure)

The Vanta + Drata vendor-risk collectors gained 7 additional
field-name probes (top-level `severity` / `tier` / `risk` /
`riskRating` / `risk_rating` / `riskClass` / `risk_class`) +
expanded the `riskAssessment` block probe to also cover
`assessment` / `risk_summary` / `riskSummary` blocks. Plus a
3rd matched value (`SEVERE`) alongside the existing `HIGH` /
`CRITICAL`.

This widens the high-risk DETECTION surface but not the
EXPLOITATION surface — the helpers still return `bool` and
the caller still emits the same `vendor-high-risk:<id>` finding
shape. The defensive return-False-on-unknown semantics
preserved.

### `_to_utc_iso` audit-trail tz-cast (v0.7.8 LOW item 4)

The Snowflake collector's `login-failed:<user>:<ts>:<ip>`
finding ID now force-casts naive datetimes to UTC before
emitting the ISO 8601 timestamp (was: ambiguous bare iso
without tz suffix when the connector emitted naive
`event_timestamp`). This tightens audit-trail correlation
across operator infrastructure that mixes UTC + local-tz
timestamps; no new attack surface.

### Pydantic `.value` duck-typing tightening (LOW items 5/7/8)

The PowerBI `_row_value` and Tableau `_serialize` helpers
previously used `hasattr(value, "value")` to detect Pydantic
Enums. This was duck-typing too permissive — any Pydantic model
with a `.value` field would match. Tightened to
`isinstance(value, Enum)` so only true Enum instances take
the value-extraction branch. Plus list/tuple branch now skips
Nones before joining (was: `[None, "x", None]` → `"None;x;None"`).

The previous behavior produced harmless garbage strings in
output rows; the tightening produces correct strings. No
attack-surface change.

### Codecov `source_pkgs` (v0.7.13 P0.3)

The Codecov coverage-upload fix switches `[tool.coverage.run]`
from `source = [<6 directories>]` to `source_pkgs = [<6
package names>]`. The Cobertura XML output now emits full
repo-relative file paths, which Codecov's path-resolver maps
directly to GitHub's tree.

Coverage data is **read-only metadata** about the test suite
— it doesn't expose any code-execution path or sensitive
content. Codecov's processor receives paths + line-coverage
counts; no source code or vendor data flows through the
upload. No trust-boundary change; closes the
`test_statement_coverage80` Silver-tier OpenSSF criterion.

### `release.yml` CHANGELOG auto-population (v0.7.13 P2.2.1)

The `release.yml` workflow gains a CHANGELOG-extraction step
that pulls the `[X.Y.Z]` block from `CHANGELOG.md` and writes
it to the GitHub Release body via `body_path`. The release
content was already public (CHANGELOG is in the public OSS
repo + GitHub Release bodies are public artifacts); this
just reduces manual `gh release edit` overhead. Trust boundary
unchanged.

The extraction runs entirely within the build runner using
shell + python; no external network calls; no new dependencies.

### Standing-rule sweep posture (carries forward)

All 21 forbidden tokens unchanged. The `.local/release-notes-
audit-2026-05-04.md` private audit log stays gitignored
throughout.

---

## v0.7.14 attack-surface delta

v0.7.14 is a wrap-up release for the v0.7.x cycle: frontend
toolchain modernization (TypeScript 5→6, ESLint 9→10, eslint
plugin bumps, jsdom + postcss + @types/node minors), Codecov
P2.1 deeper diagnosis (config-only change), container-build.yml
Wait extension (workflow-only change), 3 v0.7.8 LOW carry-over
closures (defensive code), hash-pinned `docker/requirements.txt`
preview (v0.8.0 G4 foundation; Dockerfile install line
unchanged), and a v0.7.13 in-repo retrospective doc.

### No new attack surface

v0.7.14 adds zero new public surfaces. All work is:

- **Dependency upgrades** (frontend dev-dep bumps + new
  typescript-eslint dep) — tooling-side; no runtime reach
  through the production wheels published to PyPI.
- **Internal hygiene** (3 v0.7.8 LOW closures: Tableau Windows
  tempfile cleanup, Databricks LTS env-var, test-coverage
  gaps) — defensive narrowing + diagnostic debug logging only.
- **CI/observability fixes** (Codecov flag_management removal,
  container-build Wait extension) — workflow-side; no runtime
  attack surface.
- **Documentation** (v0.7.13 retrospective, dockerfile-pinning
  preview-state section, CHANGELOG) — pure markdown.
- **Release-tooling** (`bump_version.py
  --regenerate-requirements`, hash-pinned
  `docker/requirements.txt`) — dev-side; not run inside the
  Dockerfile install path.

### Carry-forward state

All v0.7.13 trust boundaries + STRIDE entries carry forward
unchanged. The 3 cloud-WORM backends, 6 retention stores, GDPR
purge-flow, FAIR Monte Carlo simulator, and TPRM module all stay
as documented in §v0.7.12.

### `DATABRICKS_EXTRA_LTS_RUNTIMES` env var (P1.3 closure)

Operators can supply additional LTS runtime version prefixes
(comma-separated) via this env var. The values are read at call
time + merged into the in-package `_CURRENT_LTS_RUNTIMES`
frozenset for `_is_current_lts()` matching. Trust posture: env
vars are operator-trusted by convention; the values flow only
into a `bool` return + don't reach any sensitive operation. No
new attack surface.

### Tableau `TemporaryDirectory()` refactor (P1.2 closure)

The `publish_csv_datasource` method now uses
`tempfile.TemporaryDirectory()` context manager instead of
`NamedTemporaryFile(delete=False) + try/finally unlink`. The
previous implementation silently leaked .csv tempfiles on
Windows (`shutil.rmtree` retries on the new code). Trust
posture: tempdir cleanup is local file IO; no new exposure.

### `eslint.config.js` flat-config (P0.3 closure)

ESLint 10 requires the flat-config format. Pre-v0.7.14 there
was no ESLint config in evidentia-ui (the lint step was
effectively a no-op); v0.7.14 adds a minimal config with
typescript-eslint + react-hooks + react-refresh rules. The
config file is dev-side tooling; not bundled into the
production wheel.

### `vite-env.d.ts` (P0.2 ancillary)

New triple-slash reference to `vite/client` types so TypeScript
6's stricter side-effect-import resolution finds the `*.css`
module declaration. Pure type declarations; no runtime code.

### Codecov `flag_management` removal (P2.1 attempt 1)

`codecov.yml` `flag_management` block removed entirely.
Coverage flagging by `python` still works via the upload-time
`flags: python` arg in tests.yml. The removal is a config-only
change to Codecov processing semantics; no runtime reach.

### container-build.yml Wait extension (P2.2)

The Wait-for-PyPI step now polls all 6 inter-package deps
instead of just the umbrella. Workflow-only change; no runtime
reach.

### `docker/requirements.txt` preview (P1.5)

Hash-pinned requirements file generated via
`pip-compile --generate-hashes`. The Dockerfile install line is
unchanged in v0.7.14 (still `RUN pip install --no-cache-dir
--user "evidentia[gui]==X.Y.Z"`); the file ships as v0.8.0 G4
foundation. The full switch to `--require-hashes` lands in
v0.8.0 G4 alongside reproducible-build verification.

In v0.7.14 the file is read-only documentation of the
transitive closure at version-bump time. No runtime reach into
the production wheels.

### Standing-rule sweep posture (carries forward)

All 21 forbidden tokens unchanged. The `.local/` private file
tree stays gitignored throughout.

---

## v0.7.15 attack-surface delta

v0.7.15 closes the remaining frontend deferral from v0.7.13 +
v0.7.14 (Tailwind 3→4 migration), refactors `SettingsPage.tsx`
to eliminate the `react-hooks/set-state-in-effect` lint rule
violation, and adds the standing-rule sweep as a pre-commit
hook to close the gap that produced the v0.7.13 cycle 9613e62
commit-message leak.

### No new attack surface

v0.7.15 adds zero new public surfaces. All work is:

- **Frontend dev-tooling rewrite** (Tailwind 3→4) —
  devDependency change; the PostCSS chain becomes a Vite
  plugin; theme config moves from JS to CSS-first `@theme`
  blocks. Production wheel embeds the same compiled CSS
  (35 KB / 6.4 KB gzipped, vs v3's 22 KB / 5 KB gzipped — the
  delta is Tailwind 4's broader default emit, not new
  application code).
- **SettingsPage refactor** — internal pattern fix
  (useEffect+setState seed → key-based remount of inner
  sub-component). Same form fields, same backend interaction,
  same auth model. No new endpoints; no new state escape.
- **Pre-commit hook** — a contributor-side script that runs
  before `git commit` lands locally. Doesn't ship in the
  production wheel; doesn't run on operators' machines;
  exists only to catch leaks before they reach CI/origin.

### Carry-forward state

All v0.7.14 trust boundaries + STRIDE entries carry forward
unchanged. The 3 cloud-WORM backends, 6 retention stores, GDPR
purge-flow, FAIR Monte Carlo simulator, TPRM module, model risk
overlay, and audit chain-of-custody all stay as documented in
prior version sub-sections.

### Tailwind 3→4 migration (P0.1)

The migration replaces:

- `tailwind.config.ts` (deleted) → `@theme {}` blocks in
  `src/index.css`
- `postcss.config.js` (deleted) → `@tailwindcss/vite` plugin
  in `vite.config.ts`
- `tailwindcss-animate@1.0.7` (last v3-era) → `tw-animate-css`
  (v4-compatible community fork)
- `autoprefixer` (removed; Tailwind 4 handles vendor prefixing
  internally)

**Trust posture**: the build pipeline is contributor-side
tooling. Production wheel embeds the compiled output from
`vite build`; no change to the bundle delivery model. Operators
running `evidentia serve` see the same `index.html` + bundled
JS/CSS pattern. No new attack surface.

The new `@tailwindcss/vite` plugin is a first-class Tailwind 4
release artifact (signed npm package; SLSA-built per upstream
release process). Same trust boundary as the v3 PostCSS chain
which used `tailwindcss` + `autoprefixer` — the dependency
count is similar, just consolidated under one package.

### `<SettingsForm/>` refactor (P0.2)

Internal pattern fix; no surface change. The form fields, the
PUT `/api/config` payload shape, and the backend validation
all remain identical. Only the React component composition
changes (parent owns query; child owns form state, mounted
with `key={config.source_path}` for clean remount on data
load).

**Trust posture**: same as before. The settings page is
already authenticated (gated by the v0.4.0 token-auth
foundation); v0.7.15 doesn't change that.

### Pre-commit hook (P0.3)

`scripts/standing_rule_sweep.sh` runs the 21-pattern keyword
guard on staged files. The hook exists to catch
secrecy-vocabulary leaks BEFORE they hit origin/main —
upgrading the v0.7.x sweep from pre-push (publishing-authority
gate) to pre-commit (commit-time gate).

**Trust posture**: contributor-side enforcement. The hook
doesn't ship in any artifact (wheel, container, etc.); it's a
local-machine guard. Bypass via `git commit --no-verify` is
possible but documented as Allen-approval-only in the script
output. No change to operator/runtime trust boundary.

### Standing-rule sweep posture (carries forward)

All 21 forbidden tokens unchanged. The pre-commit hook
extends the sweep's coverage (now runs at commit-time as well
as push-time) but the pattern set + disposition rules are
identical.

---

## v0.7.16 attack-surface delta

v0.7.16 is the FINAL v0.7.x cycle release. Closes the
remaining loose ends (python-dotenv security CVE bump via
PR #23 + commit-msg pre-commit hook variant + in-repo
retrospective + post-ship release.yml hardening) before
v0.8.0 design opens.

### No new attack surface

v0.7.16 adds zero new public surfaces. All work is:

- **Dependency upgrade** (python-dotenv 1.0.1 → 1.2.2 via
  PR #23) — closes 2 Dependabot medium-severity alerts; the
  upgrade itself is a well-known security CVE fix
- **Pre-commit hook variant** (commit-msg stage) —
  contributor-side enforcement; doesn't ship in any artifact
- **Documentation** (v0.7.15-shipped retrospective + CHANGELOG
  + threat-model + ROADMAP + README + answer-sheet refresh)
- **CI/release-pipeline hardening** (release.yml Wait
  extension; commit `fd36e78` landed post-v0.7.15 ship)

### python-dotenv 1.0.1 → 1.2.2 (PR #23 / Dependabot #7 + #8)

The python-dotenv vulnerability (`set_key` symlink-following
allows arbitrary file overwrite via cross-device rename
fallback; CVE applies to < 1.2.2) is a runtime concern only
in code paths that:
1. Use python-dotenv's `set_key()` function to write to a
   .env file
2. Run with the .env file path resolvable to a symlink
3. Run on a system where the symlink target lives on a
   different filesystem than the staging path

Evidentia uses python-dotenv as a transitive dep through
some collector packages; doesn't directly call `set_key()`.
The blast radius if exploited would be limited to whatever
process is running with python-dotenv loaded and writes to
.env files. The fix is a clean version bump; no API
changes; no behavior change for read-only use.

The bump came in via Dependabot's auto-PR generation against
the hash-pinned `docker/requirements.txt` (v0.7.14 P1.5
foundation). This is the FIRST auto-bump from the new
hash-pinned file — validates the workflow. The hash file
self-updated to the new pin + new SHA256 hashes.

### Commit-msg pre-commit hook variant

`standing-rule-sweep-msg` hook stage scans the commit-msg
body. Same `scripts/standing_rule_sweep.sh` is invoked at
both stages (file-content + commit-msg) via different hook
declarations in `.pre-commit-config.yaml`. The script doesn't
distinguish between staged-file-paths and COMMIT_EDITMSG —
both are positional file args from its perspective.

**Trust posture**: contributor-side enforcement. The hook
doesn't ship in any artifact (wheel, container, etc.);
exists only to catch leaks before they reach origin/main.

### release.yml Wait extension (commit fd36e78; post-v0.7.15)

CI/release-pipeline hardening. Workflow-only change; no
runtime reach. Closes the LAST PyPI propagation race surface
in the release pipeline (was: only umbrella package polled;
now: all 6 inter-package deps polled before docker build).

### Standing-rule sweep posture (carries forward)

All 21 forbidden tokens unchanged. v0.7.16 ADDS the
commit-msg variant of the sweep but doesn't change the
pattern set or disposition rules. `.pre-commit-config.yaml`
doc comment paraphrased to remove the literal v0.7.13-cycle
leaked phrase; removed from script's SKIP_FILES list.

---

## v0.8.0 attack-surface delta — "the OSS-native AI moat"

v0.8.0 introduces four new public surfaces. Each is added
with adversaries + mitigations enumerated for the threat-
model audit trail.

### Surface 1: Plugin entry-point discovery (P0.4)

`evidentia_core.plugins.discover_plugins()` walks
`importlib.metadata.entry_points(group='evidentia.plugins')`
returning a dict of registered plugin classes. Operators
wire plugins via setup.py / pyproject.toml entry-point
declarations.

- **Adversary**: malicious package on PyPI registers an
  entry point claiming to be an `AuthProvider` /
  `StorageBackend` / `MarketplaceProvider`. Operator
  pip-installs the package; their Evidentia deployment
  loads the malicious plugin without explicit operator
  opt-in.
- **Mitigation**: `discover_plugins` is OPT-IN — operators
  explicitly invoke it; no auto-load on import. Operators
  control which packages they install (per Evidentia's
  pinned-deps + `uv.lock` hashed-transitive posture).
  Plugin code runs with the operator's UID; no privilege
  escalation. Auditors verifying a deployment inspect
  installed entry points via `pip show -f`.
- **Residual risk**: an operator who blindly installs
  unvetted plugins inherits the plugin's authority.
  Evidentia's posture: vetted plugins only; in-tree
  reference impls (`evidentia_core.plugins.auth.local_token`
  etc.) carry the same audit + signing as core code.

### Surface 2: MCP stdio transport (P0.3)

`evidentia mcp serve` exposes 4 read-only tools
(`list_frameworks`, `get_control`, `gap_analyze`, `gap_diff`)
to MCP-aware AI clients (Claude Desktop, Claude Code,
ChatGPT Desktop) over stdio.

- **Adversary**: malicious MCP client (e.g., compromised
  Claude Desktop config) sends `gap_analyze` / `gap_diff`
  calls with paths outside the operator's intended
  evidence directory.
- **Mitigation**: stdio transport runs in the operator's
  shell context with the operator's UID — no privilege
  escalation possible; the client process already has
  the same filesystem access. The tools accept any path
  the operator's UID can read because that matches the
  trust boundary. Documented inline in
  `SERVER_INSTRUCTIONS` + `evidentia-mcp/README.md`.
- **Residual risk**: future v0.8.1 HTTP/SSE transports
  open the surface to non-local clients. v0.8.1 MUST
  gate file-path tool inputs against an operator-
  configured allow-root via `validate_within`. Tracked
  as v0.8.1 structural requirement.

### Surface 3: `/api/metrics` Prometheus endpoint (P1 G3)

`GET /api/metrics` returns Prometheus exposition format
output covering app version, uptime, per-EventAction
counts, and failure counts.

- **Adversary**: anonymous attacker scraping the endpoint
  on a non-loopback-bound deployment. Endpoint reveals
  server version (fingerprint), audit-event volume
  (operational telemetry), and failure rates (signal an
  attacker can use to time auth-spray attacks).
- **Mitigation**: v0.8.0 default (`uvicorn --host
  127.0.0.1`) shares the same trust boundary as
  `/api/docs` + `/api/health`. `evidentia serve
  --security-headers` (or the auto-on-bind-host=0.0.0.0
  variant) attaches CSP + X-Frame-Options +
  Strict-Transport-Security. Operators binding to
  `0.0.0.0` MUST front the endpoint with reverse-proxy
  basic auth, mTLS, or a network-segregated scrape
  network (documented in `docs/evidence-integrity.md`).
- **Residual risk**: v0.8.1 wires the `AuthProvider`
  plugin contract into the FastAPI dependency stack so
  `/api/metrics` inherits the same auth requirement as
  `/api/risks`. v0.8.0 review F-V08-S3 documents this
  scope.

### Surface 4: DFAH eval harness output (P0.1)

`evidentia eval stub-smoke` (and the future v0.8.1
`risk-determinism` verb) emits per-prompt sample-hash JSON
to stdout/file. The output IS audit evidence — a 3PAO
reviewing the eval can reconstruct exactly which samples
passed determinism + which violated.

- **Adversary**: an attacker who can modify the eval
  output post-emit could fabricate determinism passes
  for non-deterministic LLM output, masking real
  AI-quality regressions.
- **Mitigation**: eval output is SHA-256-hashable
  canonical JSON via Pydantic's `model_dump_json`. CI
  pipelines should pipe `evidentia eval` output through
  Sigstore signing (the existing `evidentia oscal sign`
  pattern is reusable post-v0.8.1 when the eval-result
  signing surface lands). The `EvalResult.run_id` is a
  ULID; same-run-id replay attacks are detectable via
  the audit log.
- **Residual risk**: v0.8.0 doesn't auto-sign eval output.
  Operators wanting end-to-end signing today pipe the
  output through `cosign sign-blob` manually. v0.8.1
  adds first-class Sigstore signing for eval results.

### v0.8.0 PRT (P0.2) attack-surface notes

PRT is a model field on RiskStatement, not a new public
surface. Adversaries can:

- Forge a reasoning trace claiming citations the LLM
  didn't actually produce. Mitigation: SHA-256-hashed
  back-matter resource binds the canonical JSON;
  tampering fails `evidentia oscal verify`. The Sigstore
  signature on the AR transitively binds the trace.
- Submit a low-quality stub trace and have it accepted
  as "AI-derived." Mitigation: stub traces carry
  `trace_kind=v0.8.0-stub` in the audit log; auditors
  filter on the kind field. Per F9 disclosure in v0.8.0
  review.

### Inherited mitigations (carry-forward from v0.7.x)

All v0.7.x mitigations remain in force:

- Read-only collectors + BLIND_SPOTS disclosures
- Sigstore-signed OSCAL AR + per-resource SHA-256 hashes
- Retention metadata + cloud-WORM backends (S3/Azure/GCS)
- GDPR Article 17 purge flow
- Pinned dependencies + uv.lock hashed transitives
- SLSA L3 build provenance + cosign-signed container
- Standing-rule keyword sweep (file content + commit msg)

---

## v0.8.1 attack-surface delta — review-deferral close-out + LLM richness + network surfaces

v0.8.1 closes ALL 12 v0.8.0-bucketed review findings + adds
three new public surfaces (DFAH risk-determinism CLI, MCP
HTTP/SSE transport, FastAPI AuthProvider middleware). The
threat-model delta:

### Surface 5: MCP HTTP/SSE transport (P3.1)

`evidentia mcp serve --transport <sse|http>` exposes the
v0.8.0 4-tool surface to non-local MCP clients. v0.8.0's
stdio-only trust model (operator-trusted client; same UID;
same filesystem) doesn't apply.

- **Adversary**: anonymous attacker on the same network as
  a non-loopback-bound `evidentia mcp serve --host 0.0.0.0`
  invocation. Calls `gap_analyze` / `gap_diff` with paths
  outside the operator's intended evidence directory; reads
  any file the operator's UID can read.
- **Mitigation (v0.8.1 ship)**: bind defaults to `127.0.0.1`
  (loopback-only). Non-loopback bind warns at startup
  pointing at the reverse-proxy auth requirement.
  `SERVER_INSTRUCTIONS` carries the trust-model paragraph
  visible in MCP-client tool-pickers.
- **Residual risk**: file-path tool inputs not gated against
  an operator-configured allow-root. Bucketed as v0.8.2
  finding F-V81-S1 — v0.8.2 adds `validate_within(path,
  allow_root)` gating with `--allow-root` operator flag.

### Surface 6: FastAPI AuthProvider middleware (P3.3)

`create_app(auth_provider=...)` + `evidentia serve
--auth-token-file <path>` gate every `/api/*` route on a
valid Bearer token. Closes the v0.8.0 F-V08-S3 MEDIUM
finding (`/api/metrics` not auth-gated).

- **Adversary**: same as v0.8.0 — anonymous attacker
  scraping `/api/metrics` on a non-loopback-bound
  deployment. v0.8.1 wires the AuthProvider middleware as
  the canonical gating mechanism.
- **Mitigation**: when `auth_provider` is non-None, every
  `/api/*` request requires `Authorization: Bearer <token>`.
  `LocalTokenAuthProvider` reads the token from a file at
  construction time; `hmac.compare_digest` for constant-
  time comparison. UNAUTHENTICATED_PATHS allowlist for
  liveness probes (Kubernetes / load-balancer readiness).
- **Residual risk**: module-load AuthProvider construction
  (F-V81-S2 LOW) — race window narrow; v0.8.2 switches to
  FastAPI `lifespan` event for cleaner wiring.

### Surface 7: DFAH risk-determinism CLI (P2.1)

`evidentia eval risk-determinism` runs the v0.8.0 DFAHarness
against the live `RiskStatementGenerator`. Emits per-prompt
sample-hash JSON suitable for Sigstore signing.

- **Adversary**: same as v0.8.0 — an attacker who can
  modify the eval output post-emit could fabricate
  determinism passes. v0.8.1 doesn't change the threat
  model; CI pipelines should pipe `evidentia eval` output
  through Sigstore signing.
- **Mitigation**: canonical-JSON `model_dump_json` of
  `EvalResult` is SHA-256 hashable. `run_id` is a ULID;
  same-run-id replay attacks are detectable via the audit
  log. The new CLI verb inherits the v0.8.0 audit-event
  posture (`AI_EVAL_STARTED` / `_DETERMINISM_VIOLATION` /
  `_COMPLETED`).
- **Residual risk**: same as v0.8.0 — operators wanting
  end-to-end signing today pipe the output through `cosign
  sign-blob` manually. v0.8.x adds first-class Sigstore
  signing for eval results.

### PRT LLM-driven (P2.2) attack-surface notes

PRT trace authoring shifts from v0.8.0 stub (single
foundational claim, hard-coded confidence=0.5) to LLM-driven
per-claim decomposition. New observability:

- `evidentia.trace_kind` audit-log field distinguishes
  `v0.8.1-llm` (LLM-derived; meaningful confidence values)
  from `v0.8.0-stub` (fallback; ignore for confidence
  filtering).
- Auditors filter on `trace_kind` to scope reviews to LLM-
  derived traces with operator-trusted confidence values.

Inherited mitigations from v0.8.0: SHA-256-hashed back-
matter resource binds canonical JSON; tampering fails
`evidentia oscal verify`.

### v0.8.0 mitigation reinforcements (review-deferral close-out)

All 12 v0.8.0 review findings closed in v0.8.1 strengthen
the existing posture:

- F-V08-CR-1 + F-V08-CR-2: counter-aggregator integrity +
  outcome-contract enforcement.
- F-V08-CR-3: collector observability for non-conformant
  upstream API responses.
- F-V08-CR-4: FastMCP public-API switch (robustness against
  SDK minor-version internal renames).
- F-V08-S2: LocalTokenAuthProvider symlink-rejection (TOCTOU
  hardening).
- F-V08-CR-8: PYTHONOPTIMIZE-resistant invariant checks.
- F-V08-S5: LocalDirectoryMarketplace observability for
  manifest-parse failures.

---

## Review cadence

This doc is reviewed at every release per
[`release-checklist.md`](release-checklist.md) Step 5 (and the
new Step 5.5 doc-consistency sweep introduced in v0.7.12). A
full deep-pass walk (re-walk of every external input surface,
not just diff scope) runs at every minor release per pre-
release-review v4 §G5 + on a quarterly cadence regardless of
release activity per Step 11.

---

*First published v0.7.7 (2026-05). Origin: promoted from a
project-internal deep-pass note to a public-surface doc to
satisfy pre-release-review v4 G5 (threat-model existence gate)
ahead of the v0.8.0 minor release. The internal note remains in
`.local/` for cycle-by-cycle drafting; the public doc here is the
canonical reference for auditors + integrators.*
