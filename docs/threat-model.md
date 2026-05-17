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

## v0.8.2 attack-surface delta — review-deferral closure + supply-chain hardening + test-quality + DFAH faithfulness

> Status: 2026-05-06. v0.8.2 SHIPPED. Closes 8 reservations
> carried out of v0.8.1 (F-V81-S1 + F-V81-S2 + G4 + G1 + G2 +
> faithfulness + Sigstore eval signing); CIMD richness deferred
> further to v0.8.3.

### F-V81-S1 closure: MCP file-path tool input gating

**Surface change**: `evidentia mcp serve --allow-root <path>`
gates the file-path tool inputs (`gap_analyze.inventory_path`,
`gap_diff.{base,head}_report_path`) via
`evidentia_core.security.paths.validate_within`. Out-of-root
paths surface as `PathTraversalError` (a `ValueError` subclass);
the FastMCP runtime converts them to MCP tool errors rather than
crashing the server.

**Threat coverage**: closes the v0.8.1 trust-model gap where
HTTP/SSE-bound MCP servers could read any path the server's UID
had access to. The default (no `--allow-root`) preserves the
v0.8.1 stdio behavior — appropriate for stdio + loopback HTTP/SSE
where the client process runs as the operator's UID. Non-loopback
HTTP/SSE bindings without `--allow-root` now emit an additional
startup warning recommending the flag.

**Residual risk**: operators who deploy non-loopback HTTP/SSE
without setting `--allow-root` get the warning but the server
still starts. Defensive choice — Evidentia doesn't refuse a
deployment shape that may be acceptable behind a properly-
configured reverse proxy. v0.8.3 may revisit + escalate to a
hard refusal pending operator feedback.

### F-V81-S2 closure: AuthProvider construction at FastAPI lifespan

**Surface change**: `EVIDENTIA_API_AUTH_TOKEN_FILE` env var is
now read at FastAPI app STARTUP (lifespan event) instead of
module import time. Importing `evidentia_api.app` is side-
effect-free (no filesystem I/O); explicit injection via
`create_app(auth_provider=...)` continues to take precedence.

**Threat coverage**: closes the v0.8.1 trust-model gap where
tooling that imports `evidentia_api.app` for OpenAPI generation
or mypy plugin discovery would trigger token-file reads + raise
on missing/empty files. Now imports are clean; only actual app
startup (uvicorn, TestClient context-manager) reads the env var.

**Residual risk**: none new. Fail-loud contract preserved (broken
token file → lifespan startup raises → uvicorn fails to start
with a clear error).

### G4 closure: Dockerfile `--require-hashes`

**Surface change**: Dockerfile install line flips from
`pip install evidentia[gui]==X.Y.Z` (exact-version, partially
pinned) to `pip install --require-hashes -r /tmp/requirements.txt`
(every transitive dep pinned to a SHA256 hash from a pip-compile-
generated file).

**Threat coverage**: closes the supply-chain gap where a
compromised PyPI mirror could serve a tampered transitive
dependency without the build catching it. Hash verification
enforces byte-for-byte integrity at install time. Closes the
recurring Scorecard PinnedDependencies false-positive cycle
(alerts #100 / #101 / #102 / #103 / #107 / #108 across v0.7.12 →
v0.8.1) structurally — the alert pattern's regex no longer
matches the install line.

**Residual risk**: regeneration tooling (`pip-compile` via
`scripts/bump_version.py --regenerate-requirements`) must run
inside the Linux base image (uvloop is Linux-only; pip-compile
on Windows hosts misses it). Documented in `docs/dockerfile-
pinning.md`. Bucketed as F-V82-S1 LOW for v0.8.3+ enhancement.

### Test-quality hardening (G1 + G2)

**Surface change**: not a runtime surface — internal CI hardening:

- `[tool.mutmut]` config + `.github/workflows/mutmut.yml`
  (weekly + workflow_dispatch) targets `gap_analyzer` +
  `risk_statements` modules for mutation testing.
- 8 new hypothesis property-based tests in `tests/property/`
  cover canonical invariants on the normalizer + crosswalk
  engine (idempotence, case-folding, prefix-stripping, type-
  stability).

**Threat coverage**: complement existing statement-coverage
gating (Codecov ≥ 80% MUST per OpenSSF Silver). Mutation testing
catches gaps in test ASSERTIONS (not just LINE coverage);
property-based tests catch input-shape regressions hand-written
test corpora miss.

**Residual risk**: no new attack surface. Future work: raise
mutmut baseline + expand `paths_to_mutate` to OSCAL exporter +
plugin contracts.

### DFAH faithfulness scoring (P3.1)

**Surface change**: new `evidentia_ai.eval.faithfulness` module
+ `FaithfulnessResult` Pydantic model + `faithfulness_score()`
function. Stdlib Jaccard token-overlap baseline; default
threshold 0.3.

**Threat coverage**: addresses the v0.7.0 §11.3 risk register
risk #3 ("AI hallucination incident in Evidentia's risk-statement
output") via a third audit metric alongside determinism + replay
equivalence. Operators can now measure how grounded each
generated claim is in the input policy clauses.

**Residual risk**: stdlib Jaccard is conservative — catches gross
hallucinations, misses paraphrases. Bucketed as F-V82-S2 LOW for
v0.8.3 sentence-transformers semantic-similarity enhancement.
Operators wanting paraphrase-tolerant scoring can wire their own
similarity function in the meantime.

### First-class Sigstore signing for `evidentia eval` output (P3.2)

**Surface change**: new `evidentia_ai.eval.signing` module +
CLI flags (`--sign / --no-sign` on stub-smoke + risk-determinism;
new `evidentia eval verify` subcommand). Eval output JSON +
sibling `.sigstore.json` bundle; tri-state default auto-detects
via `GITHUB_ACTIONS` env var.

**Threat coverage**: closes the v0.8.0 §24.4 acceptance criterion
("Sigstore-signed eval output (audit-grade evidence)"). Eval
output is now provenance-bound to a specific OIDC identity at a
specific time via Fulcio cert + Rekor log inclusion proof.

**Residual risk**: requires network to Fulcio + Rekor (no air-gap
support — operators in air-gap deployments use GPG signing
instead). The `verify` CLI surface catches `Exception` broadly;
bucketed as F-V82-S3 LOW for v0.8.3 except-clause tightening.

## v0.8.3 attack-surface delta — supply-chain G4 activation + AI-quality completion

> Status: 2026-05-06. v0.8.3 SHIPPED. Closes 6 of 8
> reservations carried out of v0.8.2 (G4 + 3 LOWs + P1.1 +
> P1.2 + P1.3); MCP CIMD richness deferred 4th time to v0.8.4
> (gated on empirical operator demand); DFAHarness
> `check_faithfulness=True` wiring deferred to v0.8.4 polish.

### G4 Dockerfile `--require-hashes` ACTIVATED

**Surface change**: Dockerfile install line flips from
`pip install evidentia[gui]==X.Y.Z` (exact-version) to
`pip install --require-hashes -r /tmp/requirements.txt` (every
transitive pinned to a SHA256 hash). `release.yml` exports
`SOURCE_DATE_EPOCH=$(git log -1 --format=%ct HEAD)` before
`uv build` → byte-identical wheels across hosts → SHA256
hashes match between local pre-tag pip-compile + PyPI uploads.
New `release.yml` build-twice verification step asserts
`sha256sum` matches before publish.

**Threat coverage**: closes the supply-chain gap structurally +
permanently. A compromised PyPI mirror cannot serve a tampered
transitive without the build catching it (hash verification at
install time). Closes the recurring Scorecard PinnedDependencies
false-positive cycle (alerts #100 → #115 across v0.7.12 →
v0.8.2) — the install line no longer matches the alert
pattern's regex.

**Residual risk**: build determinism depends on uv's
SOURCE_DATE_EPOCH support remaining stable. Locally verified
end-to-end; release.yml first-fire happens at v0.8.3 ship-time.
If uv ever stops honoring SOURCE_DATE_EPOCH, the build-twice
verification step fails fast + blocks the ship, surfacing the
issue immediately rather than letting silent drift propagate.

### F-V82-S1 LOW: bump_version.py platform auto-detect

**Surface change**: `--regenerate-requirements` auto-detects host
platform; on non-Linux hosts auto-invokes pip-compile inside
the pinned `python:3.14-slim` base image so Linux-only
transitives (uvloop) resolve correctly.

**Threat coverage**: removes the v0.8.2 Windows-host caveat
that operators had to manually invoke Docker. Reduces operator
friction; eliminates a foot-gun where a Windows-host
regeneration would silently miss uvloop and produce a Dockerfile
build failure later.

**Residual risk**: requires Docker installed + running on
non-Linux hosts. Documented in `docs/dockerfile-pinning.md`.

### F-V82-S2 LOW: `evidentia eval verify` exception filtering

**Surface change**: replaces broad `except Exception` with
specific `SigstoreError` subclass catches mapped to distinct
exit codes (2 = infrastructure missing; 1 = cryptographic
failure).

**Threat coverage**: reduces info-disclosure surface (broad
except echoed unfiltered exception messages including
potentially-sensitive paths). Lets CI gates distinguish
"install extra + retry" from "real verification failure".

**Residual risk**: none new. The specific catches remain on
documented public exception hierarchy; future SigstoreError
subclasses inherit the broad-failure path until explicitly
added.

### Sentence-transformers semantic faithfulness (P1.1)

**Surface change**: new `evidentia_ai.eval.faithfulness_semantic`
module + `faithfulness_score_semantic()` function. Opt-in via
`pip install evidentia-ai[eval-faithfulness]` carrying
sentence-transformers + numpy. Default model
`all-MiniLM-L6-v2` (~90 MB on first use; cached at
`~/.cache/huggingface/`). Default threshold 0.7.

**Threat coverage**: addresses the v0.7.0 §11.3 risk register
risk #3 ("AI hallucination incident in Evidentia's risk-
statement output") more precisely than the v0.8.2 stdlib
Jaccard baseline. Catches paraphrases (different vocabulary,
same meaning) that token-overlap scoring misses.

**Residual risk**: model download from huggingface.co happens
on first use; air-gap deployments must pre-cache the model in
their build pipeline. Documented in `docs/dfah-faithfulness.md`.

### LLM atomic-claim extraction (P1.2)

**Surface change**: new `evidentia_ai.eval.claim_extraction`
module + `extract_claims()` function decomposes any AI-generated
artifact into atomic verifiable claims via LiteLLM-driven LLM
call. Empty input returns `[]` cost-aware (no LLM call fires).

**Threat coverage**: provides the missing piece between the
generation harness (DFAH) + the faithfulness scorer — operators
can now decompose generated text into atomic claims AND score
each claim independently. Wires the full DFAH pipeline.

**Residual risk**: LLM atomic-claim extraction is non-
deterministic across runs (different LLM responses → different
claim splits). Tests use mocked completion; real-LLM
integration tests gated by `EVIDENTIA_LLM_INTEGRATION=1` env
var. Per the secret-handling protocol, the function never
accepts credentials in arguments — LLM provider creds are
read from LiteLLM env vars by `_guarded_completion`.

### DFAH calibration corpus + threshold tuning (P1.3)

**Surface change**: new `tests/data/dfah-calibration/corpus.jsonl`
(50 entries × 4 categories) + `scripts/tune_faithfulness_threshold.py`
(threshold sweep + Youden's J recommendation).

**Threat coverage**: not a runtime surface — internal
calibration tooling. Empirically demonstrates the v0.8.2 R3
mitigation: the bundled corpus's optimal Jaccard threshold is
0.85 (vs default 0.3). Operators have data-driven guidance for
threshold-tuning.

**Residual risk**: no new attack surface. The corpus is
hand-crafted (single-rater = Allen) for v0.8.3; v0.8.4
multi-rater expansion improves label quality.

---

## v0.8.4 attack-surface delta — G4 Path 2 + DFAHarness wiring

> Status: 2026-05-06. v0.8.4 SHIPPED. Closes the v0.8.3
> ship-failure root cause (G4 Path 1 cross-platform
> reproducibility limitation) via Path 2 (post-PyPI
> regeneration) + the v0.8.3 P1.2 deferred wiring
> (`check_faithfulness=True` first-class on `DFAHarness`).
> CLI flags + corpus expansion + real-LLM integration tests
> deferred to v0.8.5; MCP CIMD richness deferred 5th time to
> v0.8.5 (re-evaluate or formally retire).

### Historical context — v0.8.3.1 hot-fix (G4 Path 1 reverted)

**Surface change**: v0.8.3 attempted G4 via Path 1
(SOURCE_DATE_EPOCH-driven `uv build` → byte-identical wheels
across hosts → matching SHA256 hashes between local pre-tag
pip-compile + PyPI uploads). v0.8.3 release.yml first-fire
revealed `uv build` is NOT byte-identical between Windows local
+ Linux CI runner even with same SOURCE_DATE_EPOCH (file-
ordering / timestamp-precision drift). PyPI publish succeeded
but container build's `pip install --require-hashes` failed:
local-computed hashes ≠ Linux-CI-built wheel hashes. Hot-fix
v0.8.3.1 reverted Dockerfile to exact-version pinning
(`pip install evidentia[gui]==X.Y.Z`) — same v0.8.2 surface,
no regression; container ship recovered same-day.

**Threat coverage**: zero net new surface vs v0.8.2 baseline
during the v0.8.3.1 → v0.8.4 window. Recurring Scorecard
PinnedDependencies false-positive cycle continued (alerts #100
through #116) but is operationally benign per the dismissal
runbook in `docs/dockerfile-pinning.md`.

### G4 Path 2 ACTIVATED — release.yml post-PyPI regeneration

**Surface change**: `release.yml`'s publish-container job adds
a NEW step BETWEEN the existing Wait-for-PyPI step + the docker
build step. The new step writes `docker/requirements.in`
containing `evidentia[gui]==<tag-version>`, then runs
`pip-compile --generate-hashes --no-emit-find-links` against
PyPI's just-published wheels → ephemeral `docker/requirements.txt`
overwrite → docker build picks it up. The Dockerfile install
line re-flips to `pip install --no-cache-dir --user
--require-hashes -r /tmp/requirements.txt`. Cross-platform
reproducibility no longer required because the SHA256 hashes
are computed FROM PyPI's bytes (downloaded by pip-compile in
the Linux CI runner), not from independent local + CI builds.
The committed `docker/requirements.txt` is preview state for
operators reading the repo; release-time regeneration overwrites
it ephemerally before the docker build picks it up. Built-in
3-attempt retry loop with 30s sleeps absorbs PyPI propagation
lag through the CDN.

**Threat coverage**: closes the recurring Scorecard
PinnedDependencies false-positive cycle structurally + permanently
(alerts #100 → #116 across v0.7.12 → v0.8.3.1 all dismissed as
recurring FPs; v0.8.4 expects 0 new related alerts). Closes the
v0.8.3 ship-failure root cause; the G4 supply-chain gap is now
shippable end-to-end. A compromised PyPI mirror cannot serve a
tampered transitive into the v0.8.4+ container — pip-compile
catches the hash mismatch at regeneration time + the container
build's `pip install --require-hashes` catches it again at
install time (defense-in-depth: the hash check fires at two
distinct points in the supply chain).

**Residual risk**: `release.yml` regeneration step is NEW + has
not yet first-fired in production at planning time. Mitigation:
pre-tag workflow_dispatch test against throwaway pre-release
tag recommended per the v3-prototyped pattern — not enforced
this cycle (operator-discretion). PyPI propagation lag through
the CDN is absorbed by the 3-attempt retry; if propagation
exceeds 90 seconds (3 × 30s), the step fails fast + blocks the
ship, surfacing the issue immediately rather than letting silent
drift propagate. Hot-fix tag pattern (v0.8.4.1 mirroring
v0.7.4 / v0.7.7.1 / v0.8.3.1 precedent) available as last
resort.

### DFAHarness `check_faithfulness=True` wiring (P1)

**Surface change**: `EvalSample` schema gains optional
`source_clauses: list[str] | None = None` field; `EvalResult`
schema gains `faithfulness_results: list[PromptFaithfulnessResult]`
list (default empty). `DFAHarness.run()` gains 5 new kwargs:
`check_faithfulness: bool = False`,
`faithfulness_threshold: float = DEFAULT_FAITHFULNESS_THRESHOLD`,
`faithfulness_method: Literal["jaccard", "semantic"] = "jaccard"`,
`claim_extraction_fn: Callable[[str], list[str]] | None = None`,
`faithfulness_score_fn: Callable[..., FaithfulnessResult] | None = None`.
When `check_faithfulness=True`, the harness — for each sample
whose `source_clauses` is set — extracts atomic claims from the
post-determinism modal output (matches v0.8.0 P0.1 review fix F7
canonical replay logic), scores each claim against the
sample's source_clauses via the chosen method, fires
`EventAction.AI_EVAL_FAITHFULNESS_CHECKED` per-prompt
(reserved-but-inactive in v0.8.0; ACTIVATED in v0.8.4) +
`EventAction.AI_EVAL_FAITHFULNESS_VIOLATION` per below-threshold
claim (reserved-but-inactive in v0.8.0; ACTIVATED in v0.8.4),
appends `PromptFaithfulnessResult` to `EvalResult.faithfulness_results`.
The mock-callable injection points (`claim_extraction_fn` +
`faithfulness_score_fn`) keep harness tests cost-zero (no LLM
or sentence-transformers token burn in CI) while exercising
real production code paths. Default callable resolution falls
back to v0.8.3-shipped `extract_claims` + v0.8.2-shipped
`faithfulness_score` / v0.8.3-shipped `faithfulness_score_semantic`
when callers don't inject mocks.

**Threat coverage**: closes the v0.8.3 P1.2 deferral. The DFAH
harness loop now first-class supports the second arXiv
2601.15322 metric (faithfulness scoring) alongside the v0.8.0-
shipped first metric (decision determinism) + replay
equivalence. Operators can now run a single CLI invocation
that produces auditor-defensible artifacts proving (a) the
risk-statement generator is deterministic AND (b) generated
claims trace back to the input control + system context. The
audit-event activation (`AI_EVAL_FAITHFULNESS_CHECKED` +
`AI_EVAL_FAITHFULNESS_VIOLATION`) gives auditors the same
audit-trail granularity for faithfulness violations that the
v0.8.0 baseline gave for determinism violations.

**Residual risk**: per-sample latency multiplier when
`check_faithfulness=True` — extracting claims is an extra LLM
call per sample + per-claim scoring is N additional Jaccard /
semantic-embedding computations. Documented operator guidance
in `docs/dfah-faithfulness.md`; recommend running determinism
+ faithfulness checks separately for cost-sensitive deployments.
Source-clauses-file CLI plumbing deferred to v0.8.5 (operator-
facing CLI flag `--check-faithfulness --source-clauses-file
<yaml>` not yet wired); v0.8.4 ships the library + harness
integration to allow programmatic callers to exercise the path
immediately. v0.8.5 closes the CLI surface.

### MCP CIMD richness — 5th deferral

**Surface change**: none. The Client ID Metadata Document
(CIMD) richness for multi-tenant MCP deployments was reserved
in v0.8.0, deferred to v0.8.1, deferred again to v0.8.2,
deferred again to v0.8.3, deferred again to v0.8.4, and
deferred again to v0.8.5 — pattern consistent across 5 cycles.
Per §24.6 R6 ("infra primitives best explored against real
operator deployments vs guessed at"), v0.8.5 cycle-open
re-evaluates with potential "formally retire" decision if no
demand signal materializes from external operators of v0.8.1+
HTTP/SSE adoption.

**Threat coverage**: not applicable — surface unchanged.

**Residual risk**: not applicable.

---

## v0.8.5 attack-surface delta — DFAH CLI flags + corpus expansion + real-LLM integration tests + MCP CIMD richness

> Status: 2026-05-06. v0.8.5 SHIPPED. Closes ALL 4 v0.8.4
> carry-overs in a single focused session per Allen's
> Comprehensive scope + Implement-CIMD-now lock-in
> (§28). 12th consecutive PROCEED-CLEAN of v0.7.x →
> v0.8.x line.

### DFAH `evidentia eval risk-determinism` faithfulness CLI flags (P1)

**Surface change**: 4 new CLI flags surface the v0.8.4-shipped
DFAHarness `check_faithfulness=True` path to operators.
`--check-faithfulness` enables the path; `--faithfulness-threshold N`
sets the per-claim score threshold; `--faithfulness-method
{jaccard,semantic}` selects the scorer; `--source-clauses-file
<yaml>` loads a YAML mapping `prompt_id → list[str]` of
source clauses. Pre-condition validation rejects malformed
YAML, non-list entries, and `--check-faithfulness` without a
source-clauses file BEFORE any LLM call fires. Stdout summary
on completion adds a faithfulness section (method + threshold
+ total claims scored + violations + per-prompt violation
count). Output JSON includes `faithfulness_results` array per
the v0.8.4-shipped `EvalResult` schema.

**Threat coverage**: closes the v0.8.4 P1.2 CLI-surface
deferral. Operators no longer need to write Python to
exercise the DFAH faithfulness path — `evidentia eval
risk-determinism --check-faithfulness ...` is a single CLI
invocation that produces auditor-defensible faithfulness
artifacts. Pre-condition validation cost-aware: malformed
inputs surface BEFORE LLM calls fire, avoiding wasted token
spend.

**Residual risk**: per-sample latency multiplier when
`--check-faithfulness` is set (extracting claims is an extra
LLM call per sample + per-claim scoring is N additional
Jaccard / semantic-embedding computations). Documented
operator guidance in `docs/dfah-faithfulness.md` recommends
running determinism + faithfulness checks separately for
cost-sensitive deployments. Source-clauses-file format is
human-editable YAML; threats from a malicious source-clauses
file are bounded — worst case is a misleading faithfulness
report, not RCE or data exfiltration (the YAML is parsed via
`yaml.safe_load` + Pydantic-validated as `dict[str, list[str]]`).

### DFAH calibration corpus expansion (P2)

**Surface change**: corpus growth 51 → 123 entries via 3 new
JSONL files (`corpus_nist.jsonl` + `corpus_ffiec.jsonl` +
`corpus_iso27001.jsonl`) with 24 entries each across 4
categories (verbatim faithful / paraphrase faithful /
semi-related unfaithful / hallucination). Each new entry
carries a `framework` field for downstream filtering.
`scripts/tune_faithfulness_threshold.py` extended with
`--corpus-pattern <glob>` flag for per-framework sweep —
operators tune thresholds per framework family.
Multi-rater methodology section added to corpus README:
single-rater (Allen) baseline + LLM-assisted generation +
manual spot-check on ~20% of new entries.

**Threat coverage**: closes the v0.8.4 P1.3-extension
reservation. Empirically demonstrates per-framework threshold
divergence (NIST 0.60 vs ISO27001 0.30 vs FFIEC 0.35 with
jaccard scorer) — operators avoid one-size-fits-all
threshold-tuning mistakes.

**Residual risk**: corpus is hand-crafted (single-rater =
Allen) for v0.8.5; v0.8.6 expansion brings in a second rater
+ Cohen's Kappa agreement metric. Single-rater corpus should
not be used to judge edge cases without a second opinion —
documented in the corpus README.

### Real-LLM integration tests (P3)

**Surface change**: new test suite at
`tests/integration/test_eval/test_real_llm_extraction.py`
with 4 tests (3 LLM-burning + 1 ungated empty-input edge
case). LLM-burning tests gated by `EVIDENTIA_LLM_INTEGRATION=1`
env var; CI never runs them automatically. The empty-input
edge case runs always (verifies the cost-aware short-circuit
without consuming credits). Tests assert STRUCTURAL properties
(claim count, per-claim token count, score distribution
trend) rather than exact-match strings — different LLM models
produce different splits.

**Threat coverage**: catches behavioral drift between mocked
LLMs (used in unit tests) + actual LLM responses. The
score-distribution trend test is the canonical "scorer works"
sanity check — if faithful entries score BELOW unfaithful
entries, something is fundamentally broken. Operators who
opt in get an early-warning system for LLM-provider regressions.

**Residual risk**: real-LLM tests depend on the LiteLLM
provider stack + the operator's API credentials being
correctly configured. Per the secret-handling protocol, tests
NEVER accept credentials in arguments — provider env vars
are read by `_guarded_completion`. Cost expectation
documented: ~5-10 LLM calls × ~$0.001/call ≈ $0.005-$0.05
per full integration run with gpt-4o-mini.

### MCP CIMD richness (P4)

**Surface change**: new `evidentia_mcp.cimd` module ships
`CIMDDocument` (one client's metadata per RFC 7591 + MCP
conventions) + `CIMDRegistry` (version-tagged registry
loaded from JSON via `CIMDRegistry.from_file()`). MCP
server's `build_server()` + `run_*()` accept optional
`cimd_registry=` kwarg; attached as `server.evidentia_cimd`
for tool implementations. CLI: `evidentia mcp serve
--cimd-registry <path>` flag. Loader errors surface as
exit 2 with explicit messages.

**Threat coverage**: enables multi-tenant MCP deployments
where different clients have different scope allowlists.
`CIMDDocument.has_scope(tool_name)` implements
deny-by-default semantics — empty scope = deny-all.
Per-client audit trails distinguish "Client A invoked
gap_analyze" from "Client B invoked the same tool" once
v0.8.6 wires the FastMCP middleware hook.

**Residual risk**: **CIMD is NOT authentication** —
documented prominently in the `cimd.py` docstring + this
threat-model section. CIMD is a metadata + scope layer
running ON TOP of whatever authentication the transport
provides (reverse-proxy auth for HTTP/SSE; UID-based trust
for stdio). A malicious client that bypasses transport auth
can claim any `client_id` it wants. Operators deploying
CIMD MUST also wire transport auth (reverse-proxy mTLS or
bearer tokens) so clients cannot impersonate each other's
CIMD entries. v0.8.5 ships the metadata registry; per-tool
scope enforcement at the MCP-protocol level (rejecting tool
calls when client_id lacks scope) is a v0.8.6 polish.
Cryptographic CIMD signatures (per the Webscale OIDC profile)
are reserved for future cycles.

---

## v0.8.6 attack-surface delta — CIMD scope enforcement at MCP-protocol level + Cohen's Kappa probe + per-claim confidence

> Status: 2026-05-07. v0.8.6 SHIPPED. Closes ALL 3 v0.8.5
> carry-overs (CIMD enforcement + multi-rater corpus probe +
> per-claim confidence/framework-aware thresholds) + 3 cycle-
> additions (v0.7.x retrospective + v1.0 transition narrative
> DRAFT + per-tool scope enforcement audit-trail layer) per
> Allen's Comprehensive scope + CIMD-first sequencing lock-in
> (§29). 13th consecutive PROCEED-CLEAN of v0.7.x → v0.8.x line.

### CIMD scope enforcement at MCP-protocol level (P1)

**Surface change**: NEW `evidentia_mcp.scope` module (~250
LOC) ships `enforce_cimd_scope(server, default_client_id)`
that monkey-binds a wrapper to `FastMCP.call_tool` (mcp Python
SDK 1.27 has no public middleware hook). Every tool dispatch
routes through one authorization choke-point.

`build_server()` + `run_*()` accept `default_client_id=`
kwarg threaded to `enforce_cimd_scope` AFTER `_register_tools`.
New `--default-client-id <slug>` CLI flag wired through stdio +
SSE + HTTP transports. Validation warnings: when set without
`--cimd-registry` (no scope to enforce); when `--cimd-registry`
set without `--default-client-id` on stdio (every call denies
per ambiguous-caller policy).

Per-call audit trail: `EventAction.AI_MCP_TOOL_AUTHORIZED` +
`AI_MCP_TOOL_DENIED` (NEW); both carry `evidentia.run_id`
(per-call UUID4) + `evidentia.client_id` +
`evidentia.tool_name` + `evidentia.scope_allowlist`. Pass-
through path (when `evidentia_cimd is None`) emits no audit
event — preserves v0.8.5 default no-gating behavior; absence
of events is itself an audit signal.

Denial paths: ambiguous-caller (no client_id resolvable) +
unregistered client_id + out-of-scope tool → emit DENY +
raise `McpError` code -32602 (Invalid Params per JSON-RPC 2.0).

Operator-friendly examples: `examples/mcp/cimd-registry-readonly.json`
+ `cimd-registry-power.json`.

**Threat coverage**: closes the v0.8.5 P4 deferral. Per-tool
scope enforcement at the MCP protocol level — unauthorized
tool calls are rejected back to the MCP client. Auditors get
per-call structured evidence of authorize / deny decisions.

**Residual risk**: **CIMD is NOT authentication** — re-asserted
prominently. Documented in both `cimd.py` (v0.8.5 P4) +
`scope.py` (v0.8.6 P1) docstrings. CIMD is a metadata + scope
layer running ON TOP of whatever authentication the transport
provides. A malicious client that bypasses transport auth can
claim any `client_id` it wants. Operators deploying CIMD MUST
wire transport-level authentication (reverse-proxy mTLS or
bearer tokens). Per-transport client_id resolution: stdio =
`--default-client-id` IS the client_id (documented as
INFORMATIONAL audit-trail granularity, NOT a security boundary
on stdio); HTTP/SSE = `Context.client_id` from request meta
with `--default-client-id` fallback. Cryptographic CIMD
signatures (per the Webscale OIDC profile) deferred to v1.0
per `v1.0-transition.md`.

### Cohen's Kappa rater agreement script (P2)

**Surface change**: NEW `scripts/compute_inter_rater_kappa.py`
ships Cohen's Kappa formula κ = (po - pe) / (1 - pe) +
Landis-Koch 1977 verbal interpretation + CI-gateable exit
codes. Two operating modes: two-rater file mode + rule-based-
rater mode (deterministic; no LLM tokens / human time).
Internal tooling — not a runtime surface.

NEW `tests/data/dfah-calibration/inter-rater-agreement.md`
documents the v0.8.6 P2 κ probe: best κ = 0.4848 (moderate)
at jaccard threshold 0.85 — below the ≥ 0.80 acceptance
target. Per §29 R3 mitigation, the corpus ships as "single-
rater + κ probe inconclusive" with documented rationale that
the substantial moderate-to-poor agreement empirically
demonstrates the v0.8.3 sentence-transformers semantic path's
necessity.

**Threat coverage**: not a runtime attack surface; pure label-
quality probe + reproducibility infrastructure.

**Residual risk**: rule-based rater 2 is NOT a human rater.
High κ would mean "the rule mostly agrees with Allen", NOT
"Allen's labels are correct". Low κ surfaces the known +
intended gap on paraphrase + semi-related entries. Real
LLM-assisted second rater + human second rater both reserved
for v0.9.0 walk-through cycle.

### Per-claim bootstrap-resampled confidence + framework-aware threshold defaults (P3)

**Surface change**: 2 new optional Pydantic fields on
`FaithfulnessResult`:
- `confidence: float | None = None` — bootstrap-resampled
  stddev (default-off cost-aware ~100ms/claim; opt-in via
  `compute_confidence=True` kwarg).
- `framework: str | None = None` — persisted on result for
  audit-trail re-derivation.

NEW constants + helper:
- `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD: dict[str, float]`
  (NIST 0.60 / FFIEC 0.35 / ISO27001 0.30 per v0.8.5 P2 sweep)
- `DEFAULT_CONFIDENCE_RESAMPLES: int = 100`
- `resolve_threshold(framework, method)` — framework-aware
  default lookup with fallback to
  `DEFAULT_FAITHFULNESS_THRESHOLD` (0.30) for unknown
  frameworks / non-jaccard methods

`faithfulness_score()` extended with 4 backward-compatible
kwargs: `framework=`, `compute_confidence=`, `n_resamples=`,
`confidence_seed=`. Backward compatible: all 4 default such
that existing callers behave identically to v0.8.5 (no
confidence computed, no framework persisted, confidence field
is None on the result).

**Threat coverage**: surfaces model confidence on each
FaithfulnessResult so operators can filter low-confidence
below-threshold claims separately from high-confidence ones.
Improves auditor triage for borderline edge cases.

**Residual risk**: bootstrap confidence uses Python stdlib
`random.Random` with optional seed (test-only; production
callers leave None). The `_bootstrap_confidence` helper does
not use cryptographic randomness — that's appropriate for
this use case (statistical stability estimation, not security
purposes). Per-framework threshold map references the v0.8.5
empirical sweep; if the corpus expands materially, operators
should re-run `tune_faithfulness_threshold.py` to verify the
defaults haven't drifted.

### v0.7.x retrospective + v1.0 transition narrative DRAFT (P4 + P5)

**Surface change**: 2 new public docs at `docs/v0.7.x-
retrospective.md` + `docs/v1.0-transition.md`. No code; no
runtime surface.

**Threat coverage**: not applicable — narrative docs.

**Residual risk**: standing-rule keyword sweep ran clean on
both docs; no commercialization vocabulary or personal names
leaked.

---

## v0.8.7 attack-surface delta — final v0.8.x wrap-up

> Status: 2026-05-08. v0.8.7 SHIPPED. **FINAL v0.8.x patch.**
> Backfills v0.8.6 cycle-close artifacts deferred during
> single-session compression (Phase 1; docs only) + closes
> the v0.8.6 P3 CLI deferral via `--faithfulness-threshold-
> mode {framework-aware,fixed}` flag (Phase 2). 14th
> consecutive PROCEED-CLEAN of v0.7.x → v0.8.x line.

### `--faithfulness-threshold-mode` CLI flag (P2)

**Surface change**: NEW `--faithfulness-threshold-mode
{framework-aware,fixed}` flag on `evidentia eval risk-
determinism` CLI surface (default `framework-aware`).
Validation: invalid value → exit 2 with error message naming
both valid options.

`--faithfulness-threshold` default changed from `0.3` → `None`
(sentinel for "user did not pass"). Backward compatible:
callers who explicitly pass `--faithfulness-threshold 0.3`
see identical behavior; callers who relied on the implicit
default now get framework-aware resolution.

Resolution precedence:
1. Explicit `--faithfulness-threshold` value always wins.
2. `framework-aware` mode + `check_faithfulness=True` +
   samples non-empty → extract framework from first sample's
   `prompt_id` (canonical `<framework>:<control_id>` format)
   + `resolve_threshold(framework, method)`.
3. `fixed` mode → `DEFAULT_FAITHFULNESS_THRESHOLD` (0.30)
   framework-agnostic.

Stdout summary adds `faithfulness threshold: X.XX (<source>)`
line where source is `explicit` / `framework-aware
(framework=...)` / `fixed (framework-agnostic default)`.

**Threat coverage**: closes the v0.8.6 P3 CLI deferral.
Operators can now opt into framework-aware threshold defaults
via the CLI surface (no Python required). Improves auditor
triage by surfacing the resolved threshold + its source in
the eval output.

**Residual risk**: pure operator-facing input validation; no
runtime reach beyond threshold resolution at harness
invocation. Allowlist-validated mode parameter rejects
unexpected values at parse time. Framework extraction from
`prompt_id` is robust to unrecognized formats — falls back
gracefully to framework-agnostic threshold without disrupting
the LLM call. Bare framework identifier `"nist-800-53"` maps
to 0.60 in `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD`; Rev5
prefix `"nist-800-53-rev5"` falls back to 0.30 (documented in
test_framework_aware_mode_uses_nist_0_60). Operators using
Rev5-prefix gap files can pass `--faithfulness-threshold`
explicitly OR use `--faithfulness-threshold-mode fixed`.

### Phase 1 v0.8.6 cycle-close artifact backfill (docs only)

**Surface change**: 6 docs-only changes per §30 P1 — no
runtime surface; pure narrative/documentation backfill. New
files: `docs/security-review-v0.8.6.md` +
`docs/v0.8.6-plan.md`. Modified: `docs/threat-model.md` (this
delta) + `docs/capability-matrix.md` v0.8.6 snapshot +
`README.md` v0.8.6 entry + `docs/ROADMAP.md` v0.8.6 PLANNED
→ SHIPPED transition.

**Threat coverage**: not applicable — narrative + audit-trail
infrastructure.

**Residual risk**: standing-rule keyword sweep ran clean
across all 8 modified files; no commercialization vocabulary
or personal names leaked.

---

## v0.9.0 attack-surface delta — Federal compliance (POA&M + CONMON)

> Status: 2026-05-08. v0.9.0 SHIPPED. First minor of the v0.9.x
> line. Opens the federal-compliance theme reserved at v0.8.7
> cycle-close. Plan-of-Action-and-Milestones tracking +
> Continuous Monitoring cycle calendar are auditor-expected
> surfaces in any regulated-industry GRC tool; v0.9.0 lands both.

### POA&M data layer + state model (P1)

**Surface change**: NEW `evidentia_core.models.gap.POAMState`
enum + `Milestone` Pydantic record + optional
`ControlGap.poam_milestones` list field (default-empty for
backward-compat with v0.7.x + v0.8.x serialized reports). NEW
`evidentia_core.poam` package with `state.py` (transition rules
+ derived-overdue predicate) + `milestone.py` (cycle helpers).
NEW `evidentia_core.poam_store` JSON file-store mirroring
v0.7.9 P0.1.2 vendor_store pattern (atomic-write +
UUID-shape-validation + `EVIDENTIA_POAM_STORE_DIR` env override
+ platformdirs default). NEW 6 EventActions
(`POAM_CREATED` / `_UPDATED` / `_MILESTONE_REACHED` /
`_OVERDUE` / `_CLOSED` / `_VERIFIED`).

**Threat coverage**:

- *State-machine integrity*: backward state transitions (e.g.,
  `COMPLETED → IN_PROGRESS`) are programmatically blocked by
  `is_valid_transition`. An auditor reading the lifecycle expects
  monotonic forward progress; backward rewinds would corrupt the
  audit-trail interpretation. The CLI + REST surfaces (v0.9.0 P2)
  consult the predicate before persisting any state change. To
  re-open work, operators file a NEW milestone with a fresh
  `target_date` — captured as a fresh `POAM_UPDATED` event, never
  an in-place rewind.
- *Path-traversal defense on the store*: belt-and-suspenders. The
  UUID-shape ID gate rejects anything that isn't canonical UUID
  hex form (including the v0.7.x canonical `../etc/passwd`
  attack); the `validate_within` check provides defense-in-depth
  if the shape gate is ever bypassed via refactor. Mirrors the
  v0.7.9 vendor_store + v0.7.10 model_risk_store pattern.
- *Optional-field backward-compat*: `ControlGap.poam_milestones`
  defaults to `[]` via Pydantic `default_factory=list`. v0.7.x +
  v0.8.x serialized gap reports re-parse cleanly under v0.9.0
  without migration steps — Pydantic adds the empty list on
  parse. No silent data loss on backward-compat reads.

**Residual risk**: minimal. Pure data-layer + state-machine work
with no new I/O surfaces beyond the JSON file-store (which
inherits the well-validated v0.7.9 vendor_store posture). The
6 new EventActions are additive; no existing audit-event shapes
change.

### POA&M CLI + REST + OSCAL emit (P2)

**Surface change**: NEW `evidentia poam` Typer subcommand group
(7 verbs: `create` / `list` / `show` / `update` / `milestone
add|update` / `delete` / `calendar`). NEW `/api/poam/*` FastAPI
router (8 endpoints). NEW
`evidentia_core.oscal.poam_exporter.gap_report_to_oscal_poam()`
emitting OSCAL 1.1.2 plan-of-action-and-milestones JSON with
back-matter SHA-256 integrity protection.

**Threat coverage**:

- *Auto-generation severity-filter default*: `evidentia poam
  create --from-gap-report` materializes only CRITICAL + HIGH
  severity gaps by default per FedRAMP POA&M Template
  Completion Guide v3.0 §3.1. Auditor-defensible: POA&M items
  track material findings; lower-severity gaps are documented
  in the SSP risk register without ceremony. Operators opt into
  the full set via `--all`. The filter is a deliberate
  attack-surface bound — over-materialization (every LOW gap
  becomes a POA&M) would inflate operator workload and dilute
  auditor attention on actual material findings.
- *Idempotency on POST*: `POST /api/poam/items` overwrites an
  existing record with the same `id`. Documented as idempotent
  (re-POST safe). PUT is the explicit-replace verb with `id` +
  `created_at` server-pinned. The path-parameter authority
  matches the v0.7.9 TPRM convention.
- *Error normalization*: 400 for runtime body-content
  validation (per v0.7.8 F-V08-DAST-3 normalization); 404 for
  shape-violation + not-found IDs (per v0.7.9 P0.1 H-3
  widening). Backward-state-transition violations on milestone
  PATCH surface as 400 with a clear "file a NEW milestone"
  remediation hint — operators can't silently corrupt the
  audit-trail interpretation via a malformed PATCH.
- *OSCAL back-matter integrity*: each POA&M record's canonical
  JSON is base64-encoded in
  `back-matter.resources[].base64.value` with SHA-256 in
  `rlinks[].hashes[]`. Mirrors the v0.7.0 finding-resource
  embedding pattern — tampering with an embedded record
  changes the hash and fails the v0.7.0
  `verify_ar_file` chain-of-custody check when the artifact
  reaches the auditor. The
  Evidentia-namespaced extension props
  (`ns=https://evidentia.dev/oscal`) preserve milestone status
  + target-date + evidence-ref through trestle-conformance
  round-trips as opaque extensions (preserved but not
  interpreted by upstream tools).
- *OSCAL emit determinism*: same input → same back-matter hash
  across emits. The top-level POA&M document UUID + per-element
  UUIDs are freshly generated each emit (per OSCAL convention),
  but the back-matter resource hash is integrity-bound to the
  record content only.

**Residual risk**:

- *POA&M item over-disclosure via REST*: open by default,
  matching existing endpoints. The v0.8.0 P0.5 FastAPI
  AuthProvider middleware applies optional token-file auth at
  the app layer — operators wire that for non-loopback
  deployment per the existing pattern. Documented in the
  `poam-runbook.md`.
- *OSCAL POA&M loader (v0.9.0 not in scope)*: the v0.9.0 emit
  is one-way (gap report → OSCAL JSON). The reverse loader
  (OSCAL → ControlGap reconstruction) lands in v0.9.1 if
  operator demand surfaces. Until then, operators producing
  OSCAL outside Evidentia cannot re-import; the trestle-
  conformance round-trip property is the import path.

### CONMON cycle calendar (P3)

**Surface change**: NEW `evidentia_core.conmon` pure-function
read-only library with 7 bundled cadences (NIST 800-53 CA-7
monthly + 3 FedRAMP ConMon + CMMC L2 triennial + DoD RMF annual
+ OCC 2026-13a model-risk annual). NEW `evidentia conmon` CLI
(3 verbs: `list` / `next` / `check`). NEW 2 EventActions
(`CONMON_CYCLE_DUE` + `CONMON_CYCLE_OVERDUE`).

**Threat coverage**:

- *No daemon → no long-running process surface*: operators poll
  via the `check` verb. The CONMON live-trigger daemon
  (`evidentia conmon watch`) is reserved for v1.0 — a daemon
  surface introduces a long-running process + state-file watch
  surface that v0.9.0 explicitly out-of-scopes per the §31.C
  read-only-library-only decision. v0.9.0 ships the math + the
  query CLI; v1.0 ships the daemon when the design has had
  more time to bake.
- *Cadence-slug stability*: slugs are append-only across
  releases — never renamed, never repurposed. Audit-trail
  integrity property: an auditor reviewing six months of CONMON
  events can rely on the slug to consistently identify the
  cycle even as the bundled catalog grows. Slug changes
  require a new entry alongside the old.
- *Absence-of-events invariant*: current cycles (next_due >
  today + window_days) do NOT emit events. The absence IS the
  auditor signal (no attention needed). This avoids audit-log
  inflation — operators querying daily don't multiply event
  records for cycles that aren't actually due.
- *State-file YAML parse hardening*: the `check` verb's YAML
  loader uses `yaml.safe_load` (no arbitrary Python object
  instantiation). Date-format validation surfaces parse errors
  at file-load time with clear messages. Unknown cadence slugs
  warn (don't error) — operators can keep deprecated entries
  during transitions without breaking the check.
- *Calendar arithmetic correctness*: month-add uses the same
  calendar-aware + last-day-clamping pattern as
  `Vendor.compute_next_review_due` (`2026-01-31 + 1 month →
  2026-02-28`, never an invalid date). Leap-year regressions
  covered by unit tests.

**Residual risk**:

- *Runtime-extension shadowing*: `register_cadence()` is
  process-local. A bundled slug can be shadowed by a runtime
  registration with conflicting frequency. Documented as a
  feature (operators tailor org-specific cycles); audit-trail
  records the shadowed cadence's actual frequency at query
  time, so reconstruction is unambiguous. Durable extensions
  via the v0.8.0 P0.4 plugin-contract surface defer to v0.9.1
  if walk-through identifies demand.

### Phase 4 (walk-through-as-validation) — operator-driven

Walk-through scheduling is operator-driven; not Claude-blocking.
If it runs before ship, the capability-matrix snapshot
materializes 3-5 federal-SI scenario rows + the DFAH
calibration corpus gets a Cohen's Kappa recompute with a domain-
expert second rater (closes the v0.8.6 §29 P2 R3 mitigation
acceptance). If deferred, v0.9.0 ships with the v0.8.6 "single-
rater κ probe inconclusive" carry-forward acknowledged; the
walk-through becomes a v0.9.1 reservation per §31.A.

No new attack surface from Phase 4 either way (the walk-through
produces docs + data-corpus entries, not code).

---

## v0.9.3 attack-surface delta — CONMON daemon + AI governance (SHIPPED 2026-05-17 at tag `v0.9.3`)

### Theme A — CONMON daemon (Phase 1)

**New trust boundaries**:

- *Daemon state file* (operator-supplied YAML; CLI `--state-file`):
  read on every poll cycle; written atomically on `mark-completed`.
  Single-writer contract documented (per v0.9.3 F-V93-Q3 review
  note); operators wanting multi-writer semantics defer to v0.9.4
  file-locking helper. `safe_load` enforced.
- *Alert-dedup state file* (`alerting.AlertDeduper.state_file`):
  per-(slug, state) timestamp store. JSON; same atomic-replace
  pattern. v0.9.3 F-V93-Q10 review fix: corrupted state backs up
  to `.json.corrupt-<utc-iso>` with WARNING audit event before
  reset (was silent reset previously).
- *SMTP relay* (outbound network): operator-supplied host + port.
  STARTTLS-only enforced via `SMTPConfig.__post_init__` reject of
  `use_starttls=False` AND runtime `has_extn("STARTTLS")` check
  before sending credentials (v0.9.3 F-V93-S1 fix; was silent
  plaintext fallback risk under MITM strip). Explicit
  `ssl.create_default_context()` passed to `starttls()`.
- *Webhook endpoint* (outbound network): operator-supplied URL.
  Both `http://` + `https://` accepted in v0.9.3 (F-V93-S2 SSRF
  mitigation deferred to v0.9.4 — needs opt-in flag for legitimate
  internal-network deployments; current operator guidance in
  `docs/conmon-daemon-deployment.md` recommends HTTPS + public
  URLs). HMAC-SHA256 signature over `f"{timestamp}.{body}"`
  (v0.9.3 F-V93-S3 fix added timestamp for capture-replay
  defense per Slack/Stripe webhook convention). Receivers MUST
  enforce a 5-minute staleness window via the new
  `X-Evidentia-Timestamp` header.

**Sanitization layers**:

- *Credential resolution*: centralized `resolve_secret(file_arg,
  env_var, purpose)` enforces file > env > error precedence. CLI
  `--smtp-password` / `--webhook-secret` VALUE flags are explicitly
  REJECTED (not just discouraged — Typer parser raises "no such
  option"; test `test_no_password_value_flag` locks the behavior).
  Secrets never transit through argv, env-dump, or audit-event
  payload.
- *Poll-interval floor*: `MIN_POLL_INTERVAL_SECONDS = 60` enforced
  in both `DaemonConfig.__post_init__` and the Typer
  `--poll-interval min=60` constraint (double-enforced).
- *Audit-event vocabulary*: 6 new EventActions
  (CONMON_DAEMON_STARTED / STOPPED / POLL_FAILED /
  CYCLE_MARKED_COMPLETED / ALERT_DISPATCHED / SUPPRESSED /
  HEALTH_REPORT_GENERATED). POLL_FAILED is distinct from
  CYCLE_OVERDUE so SIEMs separate daemon-health from
  control-attention signals (v0.9.3 F-V93-Q5 fix).

**Residual risk (deferred to v0.9.4)**:

- Webhook SSRF + cloud-metadata-service exfiltration (F-V93-S2
  MEDIUM CWE-918): operators must currently self-enforce HTTPS-
  only + public-internet URLs.
- Multi-writer state-file races (F-V93-Q3 HIGH CWE-362):
  documented single-writer contract; file-locking helper reserved.
- Register endpoint rate-limit (F-V93-S10 LOW CWE-770): defer to
  middleware rate-limiter design in v0.9.4 P1.3.

### Theme B — AI governance (Phase 2)

**New trust boundaries**:

- *AI system registry store* (`AIRegistryStore`; JSON file-store
  at `EVIDENTIA_AI_REGISTRY_DIR` or platformdirs default): mirrors
  v0.9.0 `poam_store` + v0.7.9 `vendor_store` pattern. UUID
  validation gate (`InvalidAISystemIdError`) on every load/delete.
  `validate_within(candidate, root)` path-traversal guard. Atomic
  `os.replace()` write. Operator-set env var is a trust boundary
  (per the same posture as the predecessor stores; F-V93-S5 LOW
  acknowledged).
- *AI gov REST router* (`/api/ai-gov/classify`, `/register`,
  `/systems`, `/systems/{id}` GET/DELETE): inherits the v0.8.1
  AuthProviderMiddleware gate at the app layer. v0.9.3 F-V93-Q2
  fix wires audit events on all mutating endpoints
  (AI_SYSTEM_CLASSIFIED / REGISTERED / RETIRED) at parity with
  CLI surface.

**Sanitization layers**:

- *EU AI Act tier classifier* (`classify()`): pure rule-based
  function on `AISystemDescriptor` attributes; no external network
  calls; no LLM inference. Deterministic per-input.
- *Pydantic validation*: `AISystemDescriptor` rejects unknown
  fields (`extra="forbid"`); `EUAIActTier` + `AnnexIIIDomain` +
  `DeploymentStatus` are str-enums with constrained value sets.
  Enum-tier comparison robust to model-config changes (v0.9.3
  F-V93-Q7 fix drops brittle `str()` wrappers).
- *CLI deployment-status validation*: upfront `DeploymentStatus(
  deployment_status)` matching `--tier` pattern (v0.9.3 F-V93-Q8
  fix; was Pydantic mid-construction error).

**Residual risk (deferred to v0.9.4)**:

- AI gov register endpoint rate-limit + duplicate-name handling
  (F-V93-S10 LOW): same mitigation as the CONMON register surface.
- AI gov REST integration test failure-path coverage (F-V93-Q17
  INFO): 3-4 negative tests in v0.9.4.

### Phase-cross sanitization additions

- *Health-score dead code removal* (F-V93-Q1 MEDIUM): the
  `per_fw_unknown` dict + `FrameworkHealth.unknown` field were
  dead code (always 0); removal eliminates silent-false-OK
  regression vector if a future refactor revived them.
- *Catalog model additive Optional fields* (v0.9.3 P2.1/P2.2):
  `CatalogControl.risk_tier` + `applies_to_annex_iii`,
  `ControlCatalog.annex_iii_risk_categories`,
  `CrosswalkDefinition.confidence_rubric`,
  `FrameworkMapping.confidence`. All Optional with default=None;
  v0.9.2 catalogs deserialize cleanly. `extra="forbid"` posture
  preserved.

### v0.9.3 review-cycle summary

| Bucket | Count | Status |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 1 | Closed via doc (F-V93-Q3 single-writer contract) |
| MEDIUM | 10 | 8 fixed inline + 1 deferred (S2 SSRF) + 1 doc (Q6) |
| LOW | 11 | Accepted with rationale |
| INFO | 6 | Documented |

18th consecutive PROCEED-CLEAN of v0.7.x → v0.8.x → v0.9.x line.

---

## v0.9.4 attack-surface delta — Daemon hardening + operator polish (SHIPPED 2026-05-17 at tag `v0.9.4`)

### Phase 1 — Daemon hardening (closes v0.9.3 deferred items)

**Closures**:

- **F-V93-Q3 HIGH** (CWE-362 race-condition): closed via opt-in
  `FileLock` (POSIX `fcntl.flock` / Windows `msvcrt.locking`)
  wrapping `mark_completed` + `AlertDeduper.mark_dispatched`
  read-modify-write. Cross-process 4-writer test confirms no
  last-writer-wins clobbering. Default off (`--state-lock` opt-in)
  preserves v0.9.3 single-writer perf path.
- **F-V93-S2 MEDIUM** (CWE-918 SSRF): closed via default-deny in
  `WebhookConfig.__post_init__`. `http://` rejected without
  `allow_plaintext=True`; loopback/RFC1918/link-local/reserved
  IPs rejected without `allow_private_network=True`. Blocks the
  cloud-metadata-service IAM-credential exfiltration vector
  (POST to 169.254.169.254). DNS resolution at config-construction
  time; DNS-rebinding caveat documented for adversarial-DNS
  environments.
- **F-V93-S10 LOW** (CWE-770 resource allocation): closed via
  per-client-IP token-bucket rate-limit middleware on POST
  /api/ai-gov/register + /classify. Default 60/min + burst 10.
  Plus `X-Idempotency-Key` header support — replay returns prior
  system_id (no duplicate); conflict returns 409.

**New trust boundaries** (all gracefully degrade):

- *Status sidecar JSON file* (`--status-file` operator-supplied):
  daemon writes after each poll cycle; REST endpoint reads via
  `EVIDENTIA_CONMON_DAEMON_STATUS_FILE` env var (server-side).
  Default off. Corrupt-file reads return 404 not 500.
- *Idempotency-store JSON file* (`_idempotency.json` in
  `EVIDENTIA_AI_REGISTRY_DIR`): FileLock-serialized
  read-modify-write; SHA-256 of canonical request-body for collision
  detection; same posture as registry-store atomic-write pattern.

### Phase 2 — Operator polish

**New endpoint surface**: `GET /api/conmon/daemon-status` — read-
only; inherits AuthProviderMiddleware gate at the app layer;
emits `CONMON_DAEMON_STATUS_QUERIED` audit event per query.

**New CLI verbs**:
- `evidentia conmon dedup-list` — read-only inspection of dedup
  state. No new attack surface; reuses existing AlertDeduper
  load path.
- `evidentia ai-gov update` + `retire` — wire previously-reserved
  AI_SYSTEM_UPDATED + AI_SYSTEM_RETIRED EventActions to the CLI
  surface. Retire preserves the registry entry (no hard delete)
  so historical audits retain ownership + classification.

### Phase 3 — Federal-SI walk-through

No new attack surface. Synthetic test data + recipe doc + smoke
test only. P3.2 surfaced 3 fixture/test refinements (invalid
cadence slugs, terminal-truncate-fragile assertions, invalid
enum value); all fixed pre-ship.

### Residual risks (deferred to v0.9.5)

- F-V93-S4 LOW (CWE-295 implicit cert verify) — Python 3.12
  stdlib defaults verify; explicit context is polish.
- F-V93-S5 LOW (CWE-22 env-var trust boundary) — matches
  v0.7.9/v0.9.0 store posture.
- F-V93-S6 LOW (CWE-362 dedup SIGINT race) — orphan .tmp is
  fail-safe.
- F-V93-S7 LOW (CWE-400 unbounded state file) — operator-
  controlled trust boundary.
- F-V93-S8 LOW (CWE-93 RFC 5321 recipient validation edge) —
  EmailMessage policy enforces CRLF guard.
- F-V93-S11 INFO (CWE-209 exception URL host disclosure) —
  non-credential.

### v0.9.4 review-cycle summary

| Bucket | Count | Status |
|---|---|---|
| CRITICAL | 0 | — |
| HIGH | 0 | (F-V93-Q3 closed) |
| MEDIUM | 0 | (F-V93-S2 closed) |
| LOW | 0 NEW | (F-V93-S10 + 4 polish closed; 7 deferred to v0.9.5) |
| INFO | 0 NEW | (F-V93-S9 closed; 4 deferred to v0.9.5) |

**Zero new findings in v0.9.4 source code.** 19th consecutive
PROCEED-CLEAN of v0.7.x → v0.8.x → v0.9.x line.

---

*First published v0.7.7 (2026-05). Origin: promoted from a
project-internal deep-pass note to a public-surface doc to
satisfy pre-release-review v4 G5 (threat-model existence gate)
ahead of the v0.8.0 minor release. The internal note remains in
`.local/` for cycle-by-cycle drafting; the public doc here is the
canonical reference for auditors + integrators.*
