# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.9.4] - 2026-05-17

**Theme**: *Daemon hardening + operator polish + federal-SI walk-through.*
Consolidation pass closing v0.9.3 deferred review items + landing
the federal-SI walk-through reserved since v0.9.0. **19th
consecutive PROCEED-CLEAN** of the v0.7.x → v0.8.x → v0.9.x line.

### Added

- **Cross-platform file-locking helper** (`evidentia_core.security.
  FileLock`): POSIX `fcntl.flock` / Windows `msvcrt.locking`
  advisory locking with polling timeout. Pairs with the new
  `--state-lock` CLI flag on `evidentia conmon watch` and
  `mark-completed` to serialize multi-writer state-file access.
  Closes v0.9.3 F-V93-Q3 HIGH (CWE-362 race-condition).
- **Webhook SSRF mitigation** (`WebhookConfig.__post_init__`):
  default-deny `http://` schemes + loopback/RFC1918/link-local/
  reserved IP destinations. Opt-in flags `allow_plaintext` +
  `allow_private_network` (CLI: `--webhook-allow-plaintext` +
  `--webhook-allow-private-network`) for legitimate internal-
  network deployments. Blocks cloud-metadata-service IAM-
  credential exfiltration. Closes v0.9.3 F-V93-S2 MEDIUM
  (CWE-918).
- **Rate-limit middleware** (`evidentia_api.rate_limit.
  TokenBucketRateLimiter` + `RateLimitMiddleware`): stdlib-only
  per-client-IP token bucket (default 60/min + burst 10) on
  POST /api/ai-gov/register + /classify. Returns 429 with
  Retry-After: 5 header on bucket exhaustion. Closes v0.9.3
  F-V93-S10 LOW (CWE-770).
- **AI gov register idempotency**: `X-Idempotency-Key` header on
  POST /api/ai-gov/register. Replay with same key + body returns
  prior `system_id` (no duplicate); same key + different body
  returns 409. Sidecar `_idempotency.json` in
  `EVIDENTIA_AI_REGISTRY_DIR`; FileLock-serialized.
- **Daemon health endpoint** (v0.9.4 P2.1): NEW
  `GET /api/conmon/daemon-status` reads a JSON sidecar that the
  daemon writes after each poll cycle. CLI flag `--status-file`
  on `evidentia conmon watch`; env var
  `EVIDENTIA_CONMON_DAEMON_STATUS_FILE` on the server. Payload:
  last_poll_at, outcome, error, tracked_cadence_count,
  daemon_uptime_seconds. NEW `CONMON_DAEMON_STATUS_QUERIED`
  EventAction.
- **`evidentia conmon dedup-list` CLI verb**: inspects the
  alert-dedup state file. Shows per-(slug, state) last-dispatched
  timestamps + suppression-window remaining. `--slug` filter +
  `--json` output. NEW `AlertDeduper.list_entries()` public API.
- **`evidentia ai-gov update` + `retire` CLI verbs**: wires the
  `AI_SYSTEM_UPDATED` + `AI_SYSTEM_RETIRED` EventActions from
  the CLI (v0.9.3 reserved both in enum; only REST DELETE fired
  RETIRED). Update: partial field-level patch via
  `model_copy(update={...})`. Retire: sets
  `deployment_status=RETIRED` but PRESERVES the entry for audit.
- **Federal-SI walk-through** (v0.9.4 P3.1): new
  `tests/data/walkthrough-federal-si/` synthetic fixtures
  (state.yaml, ai-systems.yaml, ai-systems-low-risk.yaml) +
  `docs/walkthrough-federal-si.md` 7-step operator recipe + smoke
  test `tests/integration/test_walkthrough_federal_si.py`.
  Validates end-to-end SI workflow against real bundled cadences
  + EU AI Act tier classifier + AI registry lifecycle. Reserved
  since v0.9.0; P3.2 captured 3 refinements (real slug fix,
  truncate-tolerant assertions, valid enum value) from running it.
- **`workflow_dispatch` trigger on `.github/workflows/test.yml`**:
  operators can `gh workflow run test.yml --ref main` for manual
  re-runs (was HTTP 422 before; surfaced during v0.9.3 ship
  cycle).

### Fixed

- **F-V93-Q11**: Webhook User-Agent now `evidentia-conmon-daemon/
  {evidentia_core.__version__}` (was hardcoded "v0.9.3" string).
- **F-V93-Q12**: Windows shutdown-latency note added to
  `docs/conmon-daemon-deployment.md`.
- **F-V93-Q14**: Narrowed `except Exception` to
  `(ValidationError, ValueError)` in `cli/ai_gov.py::_load_descriptor`.
- **F-V93-S9**: Path-disclosure caveat added to
  `docs/log-schema.md` with SIEM-layer redaction guidance.
- **Flaky `TestJiraStatus::test_returns_auth_error_when_credentials_reject`**
  (v0.9.4 P4.4): root cause was a 0.7% probability assertion-
  collision with the random 12-char request_id, NOT fixture leak.
  Scoped the `"401" not in r.text` substring check to
  `payload["error"]` — precisely targets the user-visible error
  field that should not leak the upstream status. More durable
  fix than the planned `pytest-randomly` + fixture-tightening
  approach.
- **`gh secret set` token-rotation doc** (`docs/release-checklist.md`
  Step 7): added correct flag forms (`-f <dotenv-file>` or
  `Get-Content | gh secret set`); explicit note that
  `--body-file` doesn't exist.

### Deferred to v0.9.5

- F-V93 LOW polish residuals (S4, S5, S6, S7, S8, Q4, Q13)
- `pytest-randomly` dev dep + test-ordering audit
- DAST tools (schemathesis + playwright) in dev-tool pre-flight
- Real federal-SI domain-expert walk-through review
- Collaboration primitives (multi-user evidence store, owner/
  reviewer fields, basic RBAC)
- Daemon health REST surface expansion (history endpoint +
  Prometheus gauges)

See `docs/v0.9.5-plan.md` for the full forward scope.

## [0.9.3] - 2026-05-17

**Theme**: *CONMON daemon (A) + AI governance (B) + carry-over closure.*
The largest minor release of the v0.9.x line so far. Combines two
originally-PROPOSED themes — CONMON daemon (Theme A; builds on v0.9.0
read-only library + v0.9.2 REST router) and AI governance (Theme B;
time-aligned with EU AI Act high-risk obligations Aug 2026) — plus
4 carry-over deliverables (LLM-rater κ recompute on 147-entry corpus,
docker/requirements drift CI gate, GHCR public-flip release-checklist,
api-stability.md DRAFT).

### Added

- **`evidentia conmon watch --poll` long-running daemon**: actor-
  pattern transition from the v0.9.0 read-only library + v0.9.2 REST
  router. State-file-driven slug→last_completed tracking,
  configurable poll interval (default 3600s; min 60s double-enforced),
  graceful SIGINT/SIGTERM shutdown. New `evidentia conmon
  mark-completed <slug> --when YYYY-MM-DD` records cycle completion
  atomically. Operator deployment guide at
  `docs/conmon-daemon-deployment.md` with systemd / launchd /
  Windows-service reference configs.
- **CONMON alerting** (SMTP + generic webhook channels): plug-point
  for daemon `on_due_soon` / `on_overdue` callbacks. STARTTLS-only
  SMTP (Step 5.A F-V93-S1 fix adds `has_extn` assertion + explicit
  `ssl.create_default_context()`). Webhook HMAC-SHA256 signing with
  timestamp-included signed material (Step 5.A F-V93-S3 fix adds
  `X-Evidentia-Timestamp` header for capture-replay defense). File-
  backed dedup state with per-(slug, state) suppression (default
  24h). Reference impls in
  `evidentia_integrations.alerting.{smtp,webhook}`.
- **Secret-handling protocol enforced**: file > env > error
  resolution precedence via centralized `resolve_secret()` helper.
  CLI `--smtp-password` / `--webhook-secret` value flags are
  explicitly REJECTED (would leak via shell history + process
  lists). Operators MUST use `--*-password-file` / `--*-secret-file`
  or the corresponding env var. Test
  `test_no_password_value_flag` locks the behavior.
- **CONMON control health scoring**: `evidentia conmon health`
  CLI + `GET /api/conmon/health` REST endpoint produce per-
  framework attention-bucket counts (current / due_soon / overdue)
  plus a cross-framework overall health score. REST payload
  capped at 10000 state entries.
- **ContinuousEvidenceSource plugin Protocol** +
  `NoopContinuousSource` reference impl. The Protocol contract
  ships; production refs (AWS CloudTrail wrapper) deferred to
  v0.9.4 per the documented scope-cut in commit `f6e9ab7`.
- **AI governance suite** (Theme B): NEW `evidentia_core.
  ai_governance` package with `classify()` rule-based EU AI Act
  tier classifier (4 tiers: unacceptable / high / limited /
  minimal), `AISystemDescriptor` + `AISystemClassification` +
  `AISystemRegistryEntry` Pydantic models, file-backed
  `AIRegistryStore` (UUID validation + path-traversal guard +
  atomic write — matches v0.9.0 poam_store / v0.7.9 vendor_store
  pattern).
- **`evidentia ai-gov` CLI** (classify / register / list / get /
  delete verbs). Friendly upfront `--tier` and
  `--deployment-status` validation (Step 5.A F-V93-Q8 fix adds the
  `--deployment-status` upfront-validate matching `--tier`).
- **`/api/ai-gov/*` REST router** (5 endpoints) with audit events
  at parity with the CLI surface (Step 5.A F-V93-Q2 fix wires
  `AI_SYSTEM_CLASSIFIED` / `REGISTERED` / `RETIRED` to the
  mutating endpoints).
- **EU AI Act catalog enrichment**: every Article 9-15 control
  gains `risk_tier` + `applies_to_annex_iii` fields. Tier
  promoted D → A (statutory uncopyrightable + Evidentia primary
  maintainer ownership). 8 Annex III risk categories enumerated.
- **NIST AI RMF crosswalks**: bidirectional mappings to EU AI Act
  (26 entries) and ISO 42001 (23 entries). Catalog model gains
  `confidence` + `confidence_rubric` fields supporting per-
  mapping certainty.
- **LLM-assisted κ recompute** on the full 147-entry corpus:
  framework-agnostic κ = 0.8820; NIST κ = 1.0000; FFIEC κ =
  0.6667; ISO 27001 κ = 0.5000; FedRAMP/CA-7 κ = 0.8333; overall
  κ = 0.7956 (Δ = 0.0044 vs prior). Acceptance MET on 3 of 5
  subsets.
- **Docker/requirements drift CI gate**: new
  `requirements-drift` job in `.github/workflows/test.yml` runs
  `scripts/check_requirements_drift.py` to flag security-sensitive
  package drift between root `pyproject.toml` and
  `docker/requirements.txt`. Covers 8 packages (urllib3, requests,
  cryptography, paramiko, aiohttp, httpx, certifi, pyopenssl).
- **GHCR public-flip release-checklist** item under
  `docs/release-checklist.md` capturing the v0.9.1/v0.9.2 lessons
  about GHCR repo-visibility transitions.
- **API stability DRAFT** at `docs/api-stability.md` (360 LOC)
  scoping the v1.0 NORMATIVE commitment surface.
- **6 new CONMON EventActions**: `CONMON_DAEMON_STARTED`,
  `CONMON_DAEMON_STOPPED`, `CONMON_DAEMON_POLL_FAILED` (Step 5.A
  addition), `CONMON_CYCLE_MARKED_COMPLETED`,
  `CONMON_ALERT_DISPATCHED`, `CONMON_ALERT_SUPPRESSED`,
  `CONMON_HEALTH_REPORT_GENERATED`.
- **4 new AI governance EventActions**: `AI_SYSTEM_CLASSIFIED`,
  `AI_SYSTEM_REGISTERED`, `AI_SYSTEM_UPDATED`, `AI_SYSTEM_RETIRED`.

### Fixed (Step 5.A pre-release-review batch `d813f34`)

- **F-V93-S1** (CWE-319): SMTP STARTTLS-stripping vulnerability.
  `SMTPAlertChannel.dispatch` now asserts `client.has_extn(
  "STARTTLS")` BEFORE calling `starttls()`, refusing to send if a
  MITM strips the EHLO advertisement. Regression test added.
- **F-V93-S3** (CWE-294): Webhook HMAC capture-replay
  vulnerability closed. Signed material now includes a unix-epoch
  timestamp; new `X-Evidentia-Timestamp` header carries it.
- **F-V93-Q1**: Dead `per_fw_unknown` dict + `unknown` field on
  `FrameworkHealth` removed (was never populated; silent-false-OK
  vector).
- **F-V93-Q2**: AI governance REST router audit-trail gap closed.
- **F-V93-Q3** (HIGH; docs-only): Single-writer contract on
  `mark_completed` + `AlertDeduper.mark_dispatched` documented
  matching v0.9.0 poam_store + v0.7.9 vendor_store precedent.
  File-locking helper reserved for v0.9.4.
- **F-V93-Q5**: Daemon poll-loop error now emits the new
  `CONMON_DAEMON_POLL_FAILED` action.
- **F-V93-Q7**: Drop brittle `str()` wrapper on enum comparison.
- **F-V93-Q8**: Upfront validation of `--deployment-status`.
- **F-V93-Q10**: Corrupted alert-dedup state file backed up to
  `.json.corrupt-<utc-iso>` with WARNING audit event before reset.

### Deferred to v0.9.4

- F-V93-S2 (CWE-918): Webhook SSRF + plaintext HTTP mitigation
- F-V93-Q3 file-locking helper (HIGH; design-decision-laden)
- F-V93-S10: AI gov register endpoint rate-limit
- F-V93-Q11/Q12/Q14/S9: LOW polish batch
- Federal-SI walk-through (originally deferred from v0.9.0)

See `docs/v0.9.4-plan.md` for the forward scope.

## [0.9.2] - 2026-05-16

**Theme**: *CONMON REST parity + LLM rater + federal corpus.*
Walk-through-driven refinement delivering HTTP API surface for
continuous-monitoring cadences, multi-rater calibration tooling,
and federal-compliance corpus expansion.

### Added

- **CONMON REST router** (`/api/conmon/*`): 4 endpoints providing
  HTTP parity with the v0.9.0 `evidentia conmon` CLI. List cadences
  with optional `?framework=` filter, get single cadence by slug,
  compute next-due date, and batch attention-state check (overdue /
  due-soon / current bucketing). Batch capped at 100 entries.
- **LLM-assisted second rater** (`scripts/llm_rater.py`): standalone
  faithfulness rater using temperature-0 LLM classification. Produces
  `labels-llm-rater.jsonl` sidecar compatible with the kappa script's
  `--rater2` format.
- **`--rule llm` mode** in `compute_inter_rater_kappa.py`: integrated
  LLM rater invocation within the kappa computation workflow.
- **Federal calibration corpus** (`corpus_federal.jsonl`): 24 entries
  spanning FedRAMP ConMon, FedRAMP POA&M, and NIST 800-53 CA-7 domain
  content. Same 4-category structure as existing corpus files.
- **Federal walk-through scenarios** (FS-1 through FS-10) in
  `docs/capability-matrix.md`: 10 persona-driven scenarios covering
  CSP compliance engineer, 3PAO assessor, ISSO, AO reviewer,
  DevSecOps engineer, and federal auditor workflows.
- **Roadmap refresh**: v0.9.2-v0.9.4 PROPOSED milestones with
  v1.0 RESERVED timeline in `docs/ROADMAP.md`.
- **Inter-rater agreement documentation** update with v0.9.1 LLM
  rater methodology + federal corpus kappa results.
- **v0.9.1 plan document** (`docs/v0.9.1-plan.md`).

### Fixed

- Batch size cap on `POST /api/conmon/check` — `max_length=100`
  prevents unbounded request payloads.
- Stale `v0.8.2` version reference in `signing.py` docstring
  example updated to `v0.9.2`.
- Capability matrix: corrected `GET /api/conmon/check` to
  `POST /api/conmon/check` in FS-1 scenario.

## [0.9.1] - 2026-05-16

**Theme**: *Organization migration to Polycentric Labs.* Patch
release completing the transfer of `allenfbyrd/evidentia` to the
`Polycentric-Labs` GitHub Organization for enterprise credibility
signaling. All supply-chain identity surfaces updated atomically.

### Changed — GitHub Organization migration

- **Repository URL**: `github.com/allenfbyrd/evidentia` →
  `github.com/Polycentric-Labs/evidentia`. GitHub permanent
  redirect ensures all existing links, stars, and forks
  continue to resolve.
- **PyPI project URLs**: Homepage, Repository, Issues, and
  Changelog URLs across all 7 published packages now point to
  `Polycentric-Labs/evidentia`.
- **Container registry path**: GHCR images now publish to
  `ghcr.io/polycentric-labs/evidentia` (lowercase per OCI spec).
- **Cosign certificate identity**: `--certificate-identity-regexp`
  updated to `Polycentric-Labs` (canonical GitHub org casing)
  matching the OIDC token identity issued by GitHub Actions.
- **SLSA build provenance**: attestation subject and verification
  paths updated to the new org namespace.
- **CodeQL pack**: `allenfbyrd/evidentia-python-sanitizers` →
  `polycentric-labs/evidentia-python-sanitizers`.
- **Dockerfile OCI labels**: `org.opencontainers.image.source`,
  `org.opencontainers.image.url`, `org.opencontainers.image.documentation`,
  and `org.opencontainers.image.vendor` updated.
- **CITATION.cff**: `repository-code` URL updated.
- **PyPI Trusted Publishers**: all 7 packages re-registered with
  `owner: Polycentric-Labs` (OIDC binding validated via RC tag).
- **Test fixtures**: `owner="polycentric-labs"` in Dependabot
  collector tests and TPRM vendor store fixtures.
- **Living docs**: `docs/release-checklist.md`,
  `docs/sigstore-quickstart.md`, `docs/evidence-integrity.md`,
  `docs/testing-playbook.md`, and security review documents
  updated with new org references and `Polycentric-Labs` casing
  in attestation verification commands.

### Unchanged (intentionally preserved)

- `allen@allenfbyrd.com` — personal author email (not repo
  ownership; git attribution unchanged).
- `allenfbyrd/evidentia-action` — separate archived repository.
- `CHANGELOG.md` historical link references — GitHub redirects
  handle `allenfbyrd/evidentia` → `Polycentric-Labs/evidentia`.
- `allenfbyrd/controlbridge` predecessor references.
- `bestpractices.dev` project URL updated out-of-band (Allen
  manual step).

### Fixed

- **OIDC casing mismatch**: GitHub's OIDC token embeds the
  canonical org login `Polycentric-Labs` (mixed case). Cosign
  `--certificate-identity-regexp` and `gh attestation verify -R`
  flags now use `Polycentric-Labs` (not `polycentric-labs`) to
  match. GHCR paths remain lowercase per OCI spec. Without this
  fix, post-release cosign verification would fail silently.

### Infrastructure

- 2583 tests passing, 17 skipped. mypy strict 0/0 across 227
  source files. ruff clean.
- RC tag `v0.9.1-rc1` validated PyPI OIDC Trusted Publisher
  authentication under the new `Polycentric-Labs` org identity.
  All 7 wheels + 7 sdists uploaded successfully with PEP 740
  attestations.
- SLSA build provenance attestation uploaded to Rekor
  transparency log and GitHub repository attestations.

## [0.9.0] - 2026-05-15

**Theme**: *Federal compliance — POA&M lifecycle + CONMON cycle
calendar + walk-through-as-validation.* First minor of the
v0.9.x line. Opens the federal-compliance theme reserved at
v0.8.7 cycle-close. Lands operator-facing surfaces auditors
expect in any regulated-industry GRC tool: Plan-of-Action-and-
Milestones tracking + Continuous Monitoring cycle calendar.

### Added — Phase 1: POA&M data layer + state model

- **`evidentia_core.models.gap.POAMState`** — 5-state enum
  (`planned` / `in_progress` / `overdue` / `completed` /
  `verified`) aligned to FedRAMP POA&M Template Completion
  Guide v3.0 + NIST SP 800-53A Rev 5 Appendix F. Forward-only
  state transitions; backward transitions programmatically
  blocked to preserve auditor-defensible monotonic progress.
- **`evidentia_core.models.gap.Milestone`** — Pydantic record
  carrying `target_date` + `description` + `status` +
  optional `evidence_ref` + `created_at` + `updated_at`. UUID
  v4 stamp for OSCAL POA&M back-matter cross-reference.
- **`ControlGap.poam_milestones: list[Milestone]`** optional
  field with default-empty for backward-compat with v0.7.x +
  v0.8.x serialized gap reports.
- **`evidentia_core.poam`** sub-package: `state.py`
  (transition rules + `derive_overdue` predicate) +
  `milestone.py` (sort + group + upcoming + attention
  bucketing helpers).
- **`evidentia_core.poam_store`** — JSON file-store mirroring
  v0.7.9 P0.1.2 vendor_store: atomic-write + UUID-shape ID
  gate + `validate_within` path-traversal defense +
  `EVIDENTIA_POAM_STORE_DIR` env override + platformdirs
  default. Refreshes `Milestone.updated_at` on persisted
  state changes vs the on-disk version.
- **6 new EventActions** in `evidentia_core.audit.events`:
  `POAM_CREATED` / `POAM_UPDATED` / `POAM_MILESTONE_REACHED`
  / `POAM_OVERDUE` / `POAM_CLOSED` / `POAM_VERIFIED`.
- `docs/log-schema.md` — new `evidentia.poam.*` section
  documenting all 6 actions + common evidentia-extension
  fields per the AU-3 contract.

### Added — Phase 2: POA&M CLI + REST + OSCAL emit

- **`evidentia poam` Typer subcommand group** (7 verbs):
  - `create --from-gap-report <path>` — auto-materialize
    POA&M items. Default: CRITICAL + HIGH severity only per
    FedRAMP §3.1; `--all` opts into the full set;
    `--overwrite` replaces existing records.
  - `list [--all] [--severity csv] [--json]` — canonical
    sort (severity rank → has-open-milestones → earliest-
    open-target-date → control_id).
  - `show <poam-id> [--json]` — human-readable detail view.
  - `update <poam-id> --status / --assigned-to /
    --remediation-guidance / --add-tag / --remove-tag` —
    top-level field edits; `--status=remediated`
    additionally fires `POAM_CLOSED` audit event.
  - `milestone add <poam-id>` — append milestone.
  - `milestone update <poam-id> <ms-id>` — backward
    transitions blocked with "file a NEW milestone" hint.
  - `delete <poam-id> [--yes]` — interactive prompt by
    default.
  - `calendar [--window-days N] [--today YYYY-MM-DD]
    [--json]` — attention-state surface across all POA&Ms.
- **`/api/poam/*` FastAPI router** (8 endpoints): items
  CRUD + paginate + filter + milestones POST/PATCH +
  calendar. Mirrors v0.7.9 TPRM router shape + inherits
  v0.7.8 F-V08-DAST-3 error-normalization (400 for runtime
  body-content; 404 for shape-violation + not-found IDs).
  State-machine violations on milestone PATCH surface as
  400.
- **`evidentia_core.oscal.poam_exporter.gap_report_to_oscal_poam`**
  — emit OSCAL 1.1.2 plan-of-action-and-milestones JSON.
  Each `ControlGap` → one (observation, risk, poam-item)
  triple with UUID cross-references resolved via `gap.id`.
  Milestones emit as `tracking-entries` under
  `risks[].remediations[]`. Evidentia-namespaced status +
  target-date + evidence-ref props live under
  `ns=https://evidentia.dev/oscal`. Back-matter integrity:
  canonical JSON in `base64.value` + SHA-256 in
  `rlinks[].hashes[]` — mirrors v0.7.0 finding-resource
  embedding so tampering fails the chain-of-custody check.

### Added — Phase 3: CONMON cycle calendar (read-only)

- **`evidentia_core.conmon`** pure-function library:
  - `ConmonCadence` Pydantic model (slug + framework +
    activity + frequency + description + citation). Slugs
    stable across releases, append-only.
  - `CadenceFrequency` enum (`monthly` / `quarterly` /
    `annual` / `biennial` / `triennial`) + month-delta map.
  - `CycleAttentionState` enum (`current` / `due_soon` /
    `overdue`) — mirrors v0.9.0 P1 POA&M attention
    vocabulary so operator UIs render both signals through
    the same widgets.
  - **7 bundled cadences**: NIST 800-53 CA-7 (monthly) +
    FedRAMP ConMon × 3 (monthly POA&M + monthly scans +
    annual SAR) + CMMC L2 triennial + DoD RMF annual + OCC
    2026-13a model-risk annual. Each carries regulatory
    citation.
  - `next_due()` — calendar-aware + last-day-clamping
    month arithmetic (e.g., `2026-01-31 + 1 month →
    2026-02-28`); never produces invalid dates.
  - `derive_status()` — 3-state attention bucketing.
  - `register_cadence()` — process-local runtime extension
    for organization-specific cycles.
- **`evidentia conmon` CLI** (3 verbs): `list` (catalog
  browse) + `next` (compute single next-due) + `check`
  (state-file YAML → due-soon + overdue surfacing with
  audit-event emit).
- **2 new EventActions**: `CONMON_CYCLE_DUE` +
  `CONMON_CYCLE_OVERDUE`. Audit emit happens at the query
  layer, not in the library — current cycles do NOT emit
  (absence-of-events invariant).
- **NEW operator runbooks**:
  - [`docs/poam-runbook.md`](docs/poam-runbook.md) — end-
    to-end POA&M workflow (bootstrap → milestones →
    attention checks → close-out → OSCAL emit → audit-trail
    interpretation).
  - [`docs/conmon-runbook.md`](docs/conmon-runbook.md) —
    CONMON workflow (discover → compute next-due → state-
    file polling → CI integration → operator-extensible
    cadences → audit interpretation).

### Changed

- CLI JSON output across `cli/conmon.py` + `cli/poam.py`
  now goes through `typer.echo()` rather than `rich`'s
  `Console.print()` — fixes terminal-width wrapping that
  corrupted JSON in CliRunner output.
- **/pre-release-review v4 Pre-tag Step 5.A 14-item batch**
  (commit `ceab880`):
  - **UUID canonicalization** in `poam_store` + `vendor_store`
    `_validate_id_shape` — returns `str(UUID(id))` so brace-
    wrapped / URN-prefixed / hex-no-hyphens alias forms
    collapse to canonical form before filename composition.
    Prevents duplicate-records-per-alias + non-conformant
    OSCAL UUID emit. 8 new regression tests
    (`TestUuidCanonicalization` across both stores).
  - **`enum_value` defensive helper** extracted to
    `evidentia_core.models.common` — single source of truth
    for the `use_enum_values=True` duality; removes
    triplicated inline copies.
  - `evidentia poam create --from-gap-report` wraps malformed
    `gap.id` in try/except so one bad gap doesn't crash the
    materialize loop (surfaces yellow warning per-gap).
  - Cleanup: `GapStatus` + `timedelta` promoted to module-
    level imports; trivial `_add_days` wrapper inlined;
    unused `ConmonStatusLiteral` deleted; `out: dict[str, Any]`
    annotation removes 2 `type: ignore` directives.
  - `docs/log-schema.md` POA&M `overdue` event docs tightened
    — events fire ONLY on operator-set transitions; derived-
    overdue surfaces in `poam calendar` output but does NOT
    emit per-cycle audit (cross-references CONMON's opposite
    choice with design rationale).
  - `docs/capability-matrix.md` v0.9.0 snapshot test-count
    corrections (P2 + P3 carry-forward stats).
  - Autouse `_isolated_conmon_registry` test fixture replaces
    per-test `try/finally` cleanup in `test_conmon/test_calendar.py`.
  - `test_current_cycle_does_not_emit_event` strengthened
    with `caplog` assertion — pins the absence-of-events
    invariant the log-schema doc promises.
  - Stale-doc refresh: `governance/__init__.py` "Future
    v0.7.10" → "Shipped surfaces:"; `evidentia/config.py`
    "v0.5.0 deprecation" → "no deprecation scheduled";
    `generation_context` "tightened in v0.8" → "no
    deprecation scheduled; v1.0 may revisit."

### Notes

- Phase 4 (walk-through-as-validation) is operator-driven.
  If it runs before ship, federal-SI scenario rows
  materialize in `capability-matrix.md` + Cohen's Kappa
  recomputes on the v0.8.5 DFAH corpus (closes the v0.8.6
  §29 P2 R3 mitigation acceptance). If deferred, walk-
  through becomes a v0.9.1 reservation per §31.A POA&M-
  first / walk-through-as-validation triage.
- v1.0 carries-forward unchanged: CONMON live-trigger
  daemon (`evidentia conmon watch`); cryptographic CIMD
  signatures; API-stability commitment; OpenSSF Best
  Practices Gold tier (blocked on ≥ 2 contributors).

## [0.8.7] - 2026-05-08

**Final v0.8.x wrap-up.** Single focused session closing the
v0.8.6 P3 CLI deferral + backfilling v0.8.6 cycle-close
artifacts deferred during single-session compression. 14th
consecutive PROCEED-CLEAN of v0.7.x → v0.8.x line. v0.9.0
opens with a clean slate for the federal-compliance theme.

### Added

- **`--faithfulness-threshold-mode {framework-aware,fixed}`
  CLI flag** on `evidentia eval risk-determinism` (default
  `framework-aware`). Closes the v0.8.6 P3 CLI-surface
  deferral. Library + `resolve_threshold()` helper shipped
  v0.8.6 P3; v0.8.7 closes the operator-facing CLI surface.
- **Resolution precedence**:
  1. Explicit `--faithfulness-threshold` value always wins.
  2. `framework-aware` mode + `check_faithfulness=True` +
     samples non-empty → extract framework from first sample's
     `prompt_id` (canonical `<framework>:<control_id>`
     format) + `resolve_threshold(framework, method)`.
  3. `fixed` mode → `DEFAULT_FAITHFULNESS_THRESHOLD` (0.30)
     framework-agnostic.
- **Stdout summary** adds `faithfulness threshold: X.XX
  (<source>)` line where source is `explicit` /
  `framework-aware (framework=...)` / `fixed (framework-
  agnostic default)`.
- 3 new CLI tests in `TestFaithfulnessThresholdMode`:
  invalid mode → exit 2; fixed mode uses 0.30; framework-
  aware mode + DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD
  lookup verified.
- **6 v0.8.6 cycle-close artifacts backfilled** (P1; docs
  only):
  - `docs/security-review-v0.8.6.md` (5th canonical Pre-tag
    deliverable per v4 §G7).
  - `docs/v0.8.6-plan.md` (public-safe re-statement of §29
    scope).
  - `docs/threat-model.md` v0.8.6 attack-surface delta.
  - `docs/capability-matrix.md` v0.8.6 SHIPPED snapshot.
  - `README.md` Recent Releases v0.8.6 entry prepend.
  - `docs/ROADMAP.md` v0.8.6 PLANNED → SHIPPED transition +
    new v0.8.7 PLANNED section + v0.9.0 RESERVED → PLANNED
    transition.

### Changed

- **`--faithfulness-threshold` default**: `0.3` → `None`
  sentinel for backward-compatible framework-aware default
  resolution. Callers who explicitly pass `--faithfulness-
  threshold 0.3` see identical behavior; callers who relied
  on the implicit default now get framework-aware
  resolution.

### Deferred to v0.9.0

- **Real LLM-assisted second rater + κ ≥ 0.80** —
  v0.9.0 federal-compliance walk-through naturally surfaces
  a HUMAN second rater (domain expert); higher signal than
  LLM rater.

### Deferred to v1.0

- **Cryptographic CIMD signatures** (per Webscale OIDC
  profile) — substantial work; appropriate for v1.0 scope
  per `v1.0-transition.md` carries-forward section.
- **OpenSSF Best Practices Badge Gold tier** — BLOCKED on
  ≥ 2 contributors per bestpractices.dev criteria.

### Quality gates

- pytest 100% green: 2386 passed / 17 skipped (was 2383/17
  at v0.8.6 ship; +3 new)
- mypy strict 0/0 across 217 source files
- ruff clean
- Standing-rule keyword sweep clean across the v0.8.7-cycle
  commits

## [0.8.6] - 2026-05-07

**CIMD scope enforcement at MCP-protocol level + Cohen's Kappa
inter-rater agreement script + per-claim confidence + framework-
aware threshold defaults + v0.7.x retrospective + v1.0
transition narrative DRAFT.** Comprehensive scope closing all
3 v0.8.5 carry-overs + 3 cycle-additions in a single focused
session per Allen's explicit cycle-open lock-in (§29). 13th
consecutive PROCEED-CLEAN of v0.7.x → v0.8.x line.

### Added

- **MCP per-tool scope enforcement at protocol level (P1)**.
  Closes the v0.8.5 P4 deferral. New `evidentia_mcp.scope`
  module with `enforce_cimd_scope(server, default_client_id)`
  monkey-binds a wrapper to `FastMCP.call_tool` that:
  - Pass-through when `server.evidentia_cimd is None`
    (preserves v0.8.5 default no-gating behavior).
  - Resolves `client_id` via precedence
    `Context.client_id → default_client_id → None`.
  - Denies on ambiguous-caller / unregistered client / out-
    of-scope tool with `McpError` code -32602.
  - Emits structured `AI_MCP_TOOL_AUTHORIZED` /
    `AI_MCP_TOOL_DENIED` audit events per call carrying
    `run_id` (UUID4) + `client_id` + `tool_name` +
    `scope_allowlist`.
- **`--default-client-id <slug>` CLI flag** on `evidentia
  mcp serve` (P1). On stdio (canonical case) IS the
  client_id for the entire session (documented as
  INFORMATIONAL — audit-trail granularity, NOT a security
  boundary). On HTTP/SSE, fallback when MCP request meta
  does not carry a client_id.
- **2 new EventActions** (P1): `AI_MCP_TOOL_AUTHORIZED` +
  `AI_MCP_TOOL_DENIED`. Documented in `docs/log-schema.md`
  with the `evidentia.mcp.*` event family.
- **Operator-friendly CIMD example registries**:
  `examples/mcp/cimd-registry-readonly.json` + `cimd-registry-power.json`.
- **`scripts/compute_inter_rater_kappa.py`** (P2). Cohen's
  Kappa formula + Landis & Koch 1977 verbal interpretation
  + CI-gateable exit codes. Two modes: two-rater file mode
  + rule-based-rater mode (deterministic; no LLM tokens or
  human time).
- **`tests/data/dfah-calibration/inter-rater-agreement.md`**
  (P2). Documents the v0.8.6 κ probe results: best κ =
  0.4848 (moderate) at jaccard threshold 0.85 — below the
  ≥ 0.80 acceptance target. Per §29 R3 mitigation, ships
  as "single-rater + κ probe inconclusive" with documented
  rationale that the substantial moderate-to-poor agreement
  empirically demonstrates the v0.8.3 sentence-transformers
  semantic faithfulness path's necessity.
- **Per-claim bootstrap-resampled confidence (P3)**. New
  `FaithfulnessResult.confidence: float | None = None`
  field. Default-off (cost-aware ~100ms/claim). Opt-in via
  new `compute_confidence=True` kwarg + tunable
  `n_resamples` (default 100) + optional `confidence_seed`
  for deterministic test runs.
- **Framework-aware Jaccard threshold map (P3)**. New
  `DEFAULT_THRESHOLDS_BY_FRAMEWORK_JACCARD` constant maps
  `"nist-800-53" → 0.60`, `"ffiec-it-handbook" → 0.35`,
  `"iso-27001" → 0.30` per the v0.8.5 P2 empirical sweep.
  New `resolve_threshold(framework, method)` helper falls
  back to `DEFAULT_FAITHFULNESS_THRESHOLD` (0.30) for
  unknown frameworks / non-jaccard methods.
- **`FaithfulnessResult.framework: str | None = None`**
  field (P3). Persisted on result for audit-trail
  re-derivation.
- **`docs/v0.7.x-retrospective.md`** (P4). v0.7.0 → v0.7.16
  cycle narrative; per-release one-line highlights; what we
  got right / what slipped / carries into v0.8.x.
- **`docs/v1.0-transition.md`** DRAFT (P5). Plan-only
  narrative covering v0.8.x → v1.0 arc; v1.0 theme
  candidates (federal compliance per §10 Q4 / API stability
  commitment); what v1.0 will NOT do; deprecation cycle
  policy; acceptance gates. Footer marks as DRAFT for
  stakeholder review.

### Changed

- `build_server(cimd_registry=, default_client_id=)` calls
  `enforce_cimd_scope` AFTER `_register_tools` so the gate
  sees the same dispatch the SDK uses internally.
- `run_stdio` / `run_sse` / `run_http` all accept + forward
  the new `default_client_id=` kwarg.
- `tests/data/dfah-calibration/README.md` extended with
  v0.8.6 P2 κ-probe-shipped section + cross-link to
  `inter-rater-agreement.md`.
- `faithfulness_score()` extended with 4 backward-compatible
  kwargs: `framework=`, `compute_confidence=`,
  `n_resamples=`, `confidence_seed=`.

### Deferred to v0.8.7 / v0.9.0

- **Real LLM-assisted second rater + κ ≥ 0.80** (P2 R3
  mitigation acceptance). Carries forward to v0.8.7 /
  v0.9.0.
- **Human second rater (domain-expert pass)**. Reserved
  for v0.9.0 federal-compliance walk-through.
- **CLI flag `--faithfulness-threshold-mode {framework-aware,
  fixed}`** on `evidentia eval risk-determinism`. Library +
  helper shipped in v0.8.6 P3; CLI surface lands in v0.8.7.
- **Cryptographic CIMD signatures** (per Webscale OIDC
  profile). Reserved for future cycles.
- **OpenSSF Best Practices Badge Gold tier** (requires
  ≥ 2 contributors).

### Quality gates

- pytest 100% green: 2383 passed / 17 skipped (was 2338/17
  at v0.8.5 ship; +45 new across P1 + P2 + P3)
- mypy strict 0/0 across 217 source files (was 216; +1
  scope module)
- ruff clean
- Standing-rule keyword sweep clean across all 5 v0.8.6-cycle
  commits

## [0.8.5] - 2026-05-06

**DFAH faithfulness CLI flags + corpus expansion + real-LLM
integration tests + MCP CIMD richness.** Comprehensive scope
closing all 4 v0.8.4 carry-overs in a single focused session.
**MCP CIMD implemented** after 5 deferral cycles per Allen's
explicit "implement now" directive. 12th consecutive
PROCEED-CLEAN of v0.7.x → v0.8.x line.

### Added

- **`evidentia eval risk-determinism` faithfulness CLI flags**
  (P1):
  - `--check-faithfulness` enables faithfulness scoring on
    each sample's modal output. Default off.
  - `--faithfulness-threshold N` minimum claim-score below
    which `AI_EVAL_FAITHFULNESS_VIOLATION` fires. Default
    0.3 for jaccard; 0.7 recommended for semantic. Per-corpus
    calibration via `scripts/tune_faithfulness_threshold.py`.
  - `--faithfulness-method {jaccard,semantic}` scoring method.
    `jaccard` (default) is stdlib token-overlap; `semantic`
    requires `pip install evidentia-ai[eval-faithfulness]`.
  - `--source-clauses-file <yaml>` path to YAML mapping
    `prompt_id → list[str]` of source clauses. Required when
    `--check-faithfulness` is set; pre-condition validated
    before any LLM calls fire.

  Stdout summary on completion adds: faithfulness method +
  threshold; total claims scored + prompt count;
  faithfulness violations + per-prompt violation count.
  Closes the v0.8.4 P1.2 CLI-surface deferral.

- **DFAH calibration corpus expansion** to 123 entries (P2):
  - `corpus.jsonl` unchanged (51 framework-agnostic entries
    from v0.8.3 P1.3).
  - **NEW** `corpus_nist.jsonl` (24 entries) — NIST 800-53
    control text shapes.
  - **NEW** `corpus_ffiec.jsonl` (24 entries) — FFIEC IT
    Examination Handbook + OCC bulletin shapes.
  - **NEW** `corpus_iso27001.jsonl` (24 entries) — ISO
    27001:2022 Annex A shapes.

  Each framework-tagged entry carries a `framework` field
  (`"nist-800-53"` / `"ffiec-it-handbook"` / `"iso-27001"`)
  for downstream filtering.

- **`scripts/tune_faithfulness_threshold.py --corpus-pattern
  <glob>`** (P2): new flag for per-framework sweep. Loads
  each matching JSONL file separately and reports per-file
  recommended threshold + Youden's J. Empirical per-framework
  sweep (jaccard scorer, default 0.05 step):
  - `corpus_ffiec.jsonl`: threshold=0.35, J=0.417
  - `corpus_iso27001.jsonl`: threshold=0.30, J=0.417
  - `corpus_nist.jsonl`: threshold=0.60, J=0.417

- **Real-LLM integration tests** (P3):
  `tests/integration/test_eval/test_real_llm_extraction.py`
  with 4 tests gated by `EVIDENTIA_LLM_INTEGRATION=1` env
  var (3 LLM-burning + 1 ungated empty-input edge case).
  Tests validate `extract_claims()` + DFAHarness end-to-end +
  score-distribution trend (faithful entries score higher
  than unfaithful) against the calibration corpus.
  Cost-aware: ~5-10 LLM calls × ~$0.001/call ≈ $0.005-$0.05
  per full integration run with gpt-4o-mini.

- **MCP CIMD richness** (P4) — Client ID Metadata Document
  support for multi-tenant MCP deployments. Implements after
  5 deferral cycles (v0.8.0 → v0.8.4). New module
  `evidentia_mcp.cimd`:
  - `CIMDDocument` Pydantic model — one client's metadata
    per OAuth Dynamic Client Registration spec (RFC 7591) +
    MCP authentication conventions. Fields: `client_id`,
    `client_name`, `scope` (space-separated tool allowlist),
    `redirect_uris`, `policy_uri`, `tos_uri`. `has_scope()`
    method implements deny-by-default allowlist semantics.
  - `CIMDRegistry` — version-tagged registry of CIMDDocuments
    loaded from JSON via `CIMDRegistry.from_file()`.
    Validates top-level JSON object + version match +
    per-CIMDDocument Pydantic validation.

  Wired into MCP server: `build_server()` + `run_stdio()` +
  `run_sse()` + `run_http()` all accept optional
  `cimd_registry=` kwarg. Server attaches the registry as
  `server.evidentia_cimd` for tool implementations that opt
  into manual scope checks.

  Wired into CLI: `evidentia mcp serve --cimd-registry
  <path>` flag. Loader errors surface as exit 2 with explicit
  error messages.

  v0.8.5 ships the registry-loading + attachment infrastructure;
  per-tool scope enforcement at the MCP-protocol level
  (rejecting tool calls when client_id lacks scope) is a
  v0.8.6 polish item.

  Threat model (in `cimd.py` docstring): CIMD is NOT
  authentication — it's a metadata + scope layer that runs
  ON TOP of whatever authentication the transport provides.
  Operators deploying CIMD MUST also wire transport auth
  (reverse-proxy mTLS or bearer tokens) so clients cannot
  impersonate each other's CIMD entries.

### Changed

- `EvalSample.source_clauses` field surfaced via the new
  `--source-clauses-file` CLI flag. Field itself shipped in
  v0.8.4 P1; v0.8.5 closes the operator-facing surface.
- `tests/data/dfah-calibration/README.md` extended with
  multi-rater methodology section + Cohen's Kappa target
  (≥ 0.80 for inter-rater agreement once a second rater is
  brought in; deferred to v0.8.6) + per-framework tuning
  recipe.

### Deferred to v0.8.6

- Per-tool scope enforcement at MCP-protocol level
  (`CIMDDocument.has_scope()` shipped; FastMCP middleware
  hook to actually reject tool calls based on requesting
  `client_id` is the v0.8.6 polish).
- Multi-rater corpus labeling pass + Cohen's Kappa over the
  disagreement subset.
- Per-claim confidence scoring + per-corpus threshold
  defaults adjustment based on operator feedback.

### Quality gates

- pytest 100% green: 2338 passed / 17 skipped (was 2313/14
  at v0.8.4 ship; +25 from P1 + P4 unit tests + P3 real-LLM
  ungated edge case)
- mypy strict 0/0 across 216 source files (was 215; +1
  evidentia-mcp/src/evidentia_mcp/cimd.py)
- ruff clean
- Standing-rule keyword sweep clean across all 4 v0.8.5-cycle
  commits

## [0.8.4] - 2026-05-06

**Supply-chain G4 Path 2 ACTIVATED + DFAHarness check_faithfulness
wiring.** Closes the v0.8.3 ship-failure root cause + the v0.8.3
P1.2 deferred wiring. Aggressive ~3-week scope compressed to a
single focused session. Continues the v0.7.11 → v0.8.3.1
PROCEED-CLEAN streak (11 consecutive at close).

### Added

- **G4 Dockerfile `--require-hashes` ACTIVATED via Path 2**
  (closes the recurring Scorecard PinnedDependencies false-
  positive cycle — alerts #100 → #116 across v0.7.12 → v0.8.3.1
  — structurally + permanently). New `release.yml` step
  "Regenerate hash-pinned requirements.txt against PyPI" runs
  AFTER Wait-for-PyPI-propagation + BEFORE the docker build:
  - Overwrites `docker/requirements.in` to pin
    `evidentia[gui]==<release-version>`.
  - Runs `pip-compile --generate-hashes --no-emit-find-links`
    against PyPI's just-published wheels, computing SHA256
    hashes FROM PyPI's actual bytes.
  - Retry loop (3 × 30s) handles CDN propagation lag.
  - The committed `docker/requirements.txt` ships as preview
    state; release.yml overwrites it ephemerally for the
    container build.

  Path 2 sidesteps the v0.8.3 Path 1 cross-platform
  reproducibility issue (Windows local vs Linux CI uv build
  byte-divergence) because both pip-compile + pip install run
  inside the same Linux runner against the same PyPI bytes.
  Hashes match by construction.

- **DFAHarness `check_faithfulness=True` wiring (P1)** — closes
  the v0.8.3 P1.2 deferred wiring. New schema:
  - `EvalSample.source_clauses: list[str] | None = None` field
  - New `PromptFaithfulnessResult` Pydantic model with
    `prompt_id` + `claims` + `overall_faithful` /
    `passed_count` / `failed_count` properties
  - `EvalResult.faithfulness_results: list[PromptFaithfulnessResult]`
    field (default empty)
  - `DFAHarness.run(check_faithfulness=False,
    faithfulness_threshold=0.3, faithfulness_method="jaccard")`
    new kwargs; harness extracts atomic claims from MODAL
    output (post-determinism) + scores each claim against
    `sample.source_clauses` via stdlib Jaccard or semantic path
  - **`EventAction.AI_EVAL_FAITHFULNESS_CHECKED`** (v0.8.3-
    reserved) and **`AI_EVAL_FAITHFULNESS_VIOLATION`** (v0.8.0-
    reserved) audit events finally ACTIVATED with structured
    log fields (run_id + prompt_id + claim_count + passed_count
    + method)
  - 14 new tests in
    `tests/unit/test_eval/test_harness_faithfulness.py` cover
    default-False / sample-skipping / claim-result aggregation
    / audit-event firing / method-selection / model
    JSON-roundtrip

### Changed

- **`docs/dockerfile-pinning.md`** — v0.8.3.1 narrative
  preserved as historical context; new "v0.8.4 G4 Path 2
  activation (current)" section documents the release-time
  regeneration pipeline + verification recipe + Scorecard
  impact.

### Deferrals to v0.8.5

- **`evidentia eval risk-determinism --check-faithfulness` CLI
  flags** — `--check-faithfulness`, `--faithfulness-threshold N`,
  `--faithfulness-method {jaccard,semantic}`,
  `--source-clauses-file <yaml>`. The library API ships in
  v0.8.4; the CLI surface lands in v0.8.5 polish. Operators
  wire DFAHarness directly via library calls in the meantime.
  Matches the v0.8.3 P1.2 "library ships first; CLI follows"
  pattern.
- **DFAH calibration corpus expansion** to 100-200 entries +
  multi-rater labeling + per-framework subsets (NIST / FFIEC /
  ISO 27001).
- **Real-LLM integration tests** for atomic-claim extraction +
  DFAHarness faithfulness path. Gated by
  `EVIDENTIA_LLM_INTEGRATION=1` env var; uses calibration
  corpus as ground truth.
- **MCP CIMD richness** (5th cycle-deferral; per §24.6 R6
  still gated on empirical operator demand). v0.8.5 cycle-open
  re-evaluates with potential "formally retire" decision if no
  demand signal materializes.

## [0.8.3.1] - 2026-05-06

**Same-day hot-fix tag for v0.8.3**: reverts G4 Dockerfile
`--require-hashes` activation. v0.8.3 PyPI publish succeeded
(7 packages with PEP 740 attestations) but the container build
failed at the `pip install --require-hashes` step because uv
build is NOT byte-identical across host platforms (Windows
local pre-tag regeneration vs Linux CI build runner) even with
the same SOURCE_DATE_EPOCH. The hashes computed by local
pip-compile against Windows-built wheels didn't match what
release.yml uploaded to PyPI from Linux-built wheels. PyPI's
v0.8.3 wheels are valid + verifiable via `pypi-attestations
verify pypi`; the gap is solely the container image which
never published to ghcr.io.

Same-day hot-fix tag pattern follows the v0.7.4 + v0.7.7.1
precedent — small surgical fix to revert the failing change +
ship a working container.

### Fixed

- **Dockerfile install line REVERTED to exact-version pinning**
  (`pip install --no-cache-dir --user "evidentia[gui]==0.8.3.1"`)
  matching the v0.8.2 pattern. Container build at v0.8.3.1
  ship-time will install from PyPI without `--require-hashes`,
  bypassing the cross-platform reproducibility issue.
- **`docs/dockerfile-pinning.md`** updated with v0.8.3 G4
  Path 1 attempt + revert narrative + v0.8.4 G4 Path 2
  closure plan (post-PyPI regeneration in release.yml — pip-
  compile against PyPI's just-published wheels + ephemeral
  docker build; no cross-platform reproducibility required).

### Preserved

The structural foundation that landed across v0.7.14 P1.5 +
v0.8.2 G4 + v0.8.3 G4 Path 1 attempt remains in place:

- `docker/requirements.in` + `docker/requirements.txt`
  regeneration tooling (`bump_version.py --regenerate-requirements`)
- `release.yml` SOURCE_DATE_EPOCH + build-twice verification
  step (kept; provides reproducibility verification value
  independently of `--require-hashes` activation; helps
  v0.8.4 G4 Path 2 design)
- F-V82-S1 platform auto-detect (v0.8.3 P0.2 closure carries
  forward unchanged)
- All v0.8.3 AI-quality work (P1.1 sentence-transformers,
  P1.2 LLM atomic-claim extraction, P1.3 calibration corpus)
  carries forward unchanged

### Deferred to v0.8.4

- **G4 Dockerfile `--require-hashes` activation via Path 2**:
  release.yml regenerates docker/requirements.txt against
  PyPI's just-published wheels between Wait-for-PyPI step +
  docker build step. Path 2 doesn't have Path 1's cross-
  platform issue because hashes are computed FROM PyPI's
  bytes (downloaded by pip), not from independent local + CI
  builds.

## [0.8.3] - 2026-05-06

**Supply-chain G4 activation + AI-quality completion.** Aggressive
~3-week scope executed in a single focused session — closes 6 of
8 v0.8.2 carry-overs (G4 Dockerfile `--require-hashes` activation
via SOURCE_DATE_EPOCH-driven reproducible builds + 3 LOWs +
sentence-transformers faithfulness + LLM atomic-claim extraction
+ DFAH calibration corpus). MCP CIMD richness deferred to v0.8.4
(4th cycle-deferral; per §24.6 R6 still gated on empirical
operator demand). DFAHarness `check_faithfulness=True` wiring
also deferred to v0.8.4 polish — the `extract_claims()` standalone
function is the v0.8.3 ship; operators wire it manually until the
harness integration lands. Continues the v0.7.11 → v0.8.2
PROCEED-CLEAN streak (10 consecutive at close).

### Added

- **G4 Dockerfile `--require-hashes` ACTIVATED** (closes the
  recurring Scorecard PinnedDependencies false-positive cycle —
  alerts #100 → #115 across v0.7.12 → v0.8.2 — structurally +
  permanently). The Dockerfile install line flips to
  `pip install --require-hashes -r /tmp/requirements.txt`
  against `docker/requirements.txt` (every transitive pinned to
  a SHA256 hash). `release.yml` exports `SOURCE_DATE_EPOCH=$(git
  log -1 --format=%ct HEAD)` before `uv build` → byte-identical
  wheels across hosts → SHA256 hashes match between local pre-
  tag pip-compile + PyPI uploads. New `release.yml` "Verify
  reproducible build" step builds wheels twice + asserts
  `sha256sum` matches before publish-pypi proceeds. Locally
  pre-flight verified: 7 wheels matched byte-for-byte across
  two runs with same SOURCE_DATE_EPOCH.
- **Sentence-transformers semantic faithfulness path (P1.1)**
  — new `evidentia_ai.eval.faithfulness_semantic` module +
  `faithfulness_score_semantic()` function. Opt-in via
  `pip install evidentia-ai[eval-faithfulness]`. Default model
  `sentence-transformers/all-MiniLM-L6-v2` (~90 MB; cached at
  `~/.cache/huggingface/`). Default threshold 0.7 (calibrated
  for natural-language policy clauses per arXiv 2601.15322).
  Catches paraphrases that the v0.8.2 Jaccard baseline
  (default 0.3 threshold) misses. Result.method =
  `"sentence-transformers"` distinguishes from the stdlib
  path's `"jaccard-stdlib"`.
- **LLM atomic-claim extraction (P1.2)** — new
  `evidentia_ai.eval.claim_extraction` module + `extract_claims()`
  function. Decomposes any AI-generated artifact into atomic
  verifiable claims via LLM call (LiteLLM-driven). Defensive
  parsing: strips bullet/numbering prefixes; drops empty lines;
  caps at `max_claims`. Empty input returns `[]` without firing
  an LLM call (cost-aware). Tests inject `completion_fn=mock`
  so CI runs without LLM provider creds. New
  `EventAction.AI_EVAL_FAITHFULNESS_CHECKED` reserved (firing
  path lands in v0.8.4 DFAHarness wiring).
- **DFAH calibration corpus + threshold-tuning script (P1.3)**
  — `tests/data/dfah-calibration/corpus.jsonl` (50 entries; 4
  categories: verbatim faithful / paraphrase faithful /
  semi-related unfaithful / hallucination unfaithful). New
  `scripts/tune_faithfulness_threshold.py` measures FPR/FNR
  across thresholds 0.0-1.0 in 0.05 increments + recommends
  optimum via Youden's J. Operators tune per-corpus via
  `--method jaccard|semantic` + optional `--by-category`.
  Methodology + extension recipe in
  `tests/data/dfah-calibration/README.md`.

### Changed

- **F-V82-S1 LOW**: `bump_version.py --regenerate-requirements`
  auto-detects host platform vs target. On non-Linux hosts
  (Windows, macOS), the script auto-invokes pip-compile inside
  the pinned `python:3.14-slim` base image so Linux-only
  transitives (uvloop) resolve correctly. Removes the v0.8.2
  Windows-host caveat.
- **F-V82-S2 LOW**: `evidentia eval verify` CLI replaces broad
  `except Exception` with specific `SigstoreError` subclass
  catches:
  - `SigstoreNotAvailableError` → exit 2 + install hint
  - `SigstoreAirGapError` → exit 2 + GPG-fallback hint
  - `SigstoreVerifyError` → exit 1 (cryptographic failure)
  - `(FileNotFoundError, OSError)` → exit 1 (filesystem issue)
  CI gates can now distinguish "install extra + retry" from
  "real verification failure".
- **F-V82-S3 LOW** (transitive): faithfulness paraphrase
  precision concern from v0.8.2 closes via the P1.1
  sentence-transformers path. Stdlib Jaccard remains the floor;
  semantic is opt-in for paraphrase-tolerant scoring.

### Deferrals to v0.8.4

- **MCP CIMD richness** (4th cycle-deferral) — Client ID
  Metadata Document support for multi-tenant deployments.
  Per §24.6 R6 still gated on empirical operator demand from
  v0.8.1+v0.8.2 HTTP/SSE adoption; no signal observed yet to
  drive the spec design. v0.8.4 cycle-open re-evaluates.
- **DFAHarness `check_faithfulness=True` wiring** — the
  standalone `extract_claims()` ships in v0.8.3; the harness
  integration (`EvalSample.source_clauses` field; per-prompt
  faithfulness aggregation; `AI_EVAL_FAITHFULNESS_CHECKED`
  event firing) lands in v0.8.4 with real-LLM integration
  tests.
- **DFAH calibration corpus expansion** to 100-200 entries +
  multi-rater labeling + per-framework subsets.
- **Real-LLM integration tests** for atomic-claim extraction +
  DFAHarness faithfulness path. Gated by
  `EVIDENTIA_LLM_INTEGRATION=1` env var.

## [0.8.2] - 2026-05-06

**Review-deferral closure + supply-chain hardening + test-quality
+ DFAH faithfulness.** Aggressive ~3-week scope executed in a
single focused session — closes the 8 reservations carried out
of v0.8.1: F-V81-S1 + F-V81-S2 review deferrals + G4 Dockerfile
hash-pinning + G1 mutmut baseline infrastructure + G2 hypothesis
property-tests + DFAH faithfulness scoring + first-class Sigstore
signing for `evidentia eval` output. CIMD richness deferred
further to v0.8.3 per §24.6 R6 (best explored against real
operator demand from v0.8.1 HTTP/SSE adoption). Continues the
v0.7.11 → v0.8.1 PROCEED-CLEAN streak (9 consecutive at close).

### Added

- **F-V81-S1** — `evidentia mcp serve --allow-root <path>` flag
  gates file-path tool inputs (`gap_analyze.inventory_path`,
  `gap_diff.{base,head}_report_path`) via
  `evidentia_core.security.paths.validate_within`. Out-of-root
  paths surface as `PathTraversalError` (a `ValueError`
  subclass); FastMCP runtime converts to MCP tool error rather
  than crashing the server. Non-loopback HTTP/SSE bindings
  without `--allow-root` emit an additional startup warning
  recommending the flag.
- **G4 Dockerfile `--require-hashes` (foundation-only; activation
  deferred to v0.8.3)** — `docker/requirements.txt` is regenerated
  against the v0.8.2 dep tree (~140 transitive deps with SHA256
  hashes); `bump_version.py --regenerate-requirements` wires the
  regeneration into the version-bump flow. Activation of the
  Dockerfile install-line flip (`pip install --require-hashes -r
  /tmp/requirements.txt`) deferred per §25.6 R1: release.yml
  `uv build` is not byte-identical across build hosts (no
  SOURCE_DATE_EPOCH yet), so SHA256 hashes computed pre-tag don't
  match what release.yml uploads to PyPI. v0.8.3 closes this via
  either reproducible-build verification OR release-pipeline-
  integrated regeneration. The recurring Scorecard
  PinnedDependencies false-positive cycle (alerts #100 → #108)
  remains under the dismissal-per-release runbook in
  `docs/dockerfile-pinning.md` until v0.8.3 activation.
- **G1 mutmut mutation-testing baseline** — `[tool.mutmut]`
  config in root `pyproject.toml` targets `gap_analyzer` +
  `risk_statements` modules. New `.github/workflows/mutmut.yml`
  runs weekly + on workflow_dispatch. New
  `docs/mutation-testing.md` operator runbook.
- **G2 hypothesis property-based tests** — 8 new property
  tests in `tests/property/` covering invariants on the
  gap-analyzer normalizer + the catalogs CrosswalkEngine.
  `tests/property/conftest.py` registers `ci` (default,
  derandomized, 200ms deadline) + `dev` (random, 1000ms
  deadline) profiles.
- **DFAH faithfulness scoring (P3.1)** — second arXiv 2601.15322
  metric. New `evidentia_ai.eval.faithfulness` module with
  `FaithfulnessResult` Pydantic model + `faithfulness_score()`
  function using stdlib Jaccard token-overlap. Default
  threshold 0.3; conservative — catches gross hallucinations,
  misses paraphrases. v0.8.3 sentence-transformers semantic-
  similarity path planned. `EventAction.AI_EVAL_FAITHFULNESS_VIOLATION`
  (reserved in v0.8.0) now wired. `docs/dfah-faithfulness.md`
  operator guide.
- **First-class Sigstore signing for `evidentia eval` output
  (P3.2)** — `evidentia_ai.eval.signing` wraps the v0.7.x
  OSCAL Sigstore helpers with eval-output-specific surface.
  CLI: `--sign / --no-sign` flag on `stub-smoke` +
  `risk-determinism` (tri-state default auto-detects via
  `GITHUB_ACTIONS` env); new `evidentia eval verify <output>`
  subcommand. New `EventAction.AI_EVAL_OUTPUT_SIGNED` audit entry.

### Changed

- **F-V81-S2** — AuthProvider construction moved from import-
  time module-level → FastAPI `lifespan` async context
  manager. Importing `evidentia_api.app` is now side-effect-
  free (no filesystem I/O); env var
  `EVIDENTIA_API_AUTH_TOKEN_FILE` is read at app startup
  instead. Explicit injection via
  `create_app(auth_provider=...)` continues to take precedence.
  `AuthProviderMiddleware` is now always-attached + reads
  provider from `request.app.state.auth_provider` at dispatch
  — no-op when None preserves v0.8.0 backward-compat.

### Fixed

- **MCP `serve --help` tests stable on Windows CI** (post-
  v0.8.1 follow-up) — switched the assertion path from
  Rich/Typer-rendered help output (terminal-width-detection
  driven; ANSI escape codes vary by environment) to direct
  introspection of the underlying Click command's `.params`
  list via `typer.main.get_command()`. Deterministic across
  ubuntu / macos / windows runners.

### Deferrals to v0.8.3

- **MCP CIMD richness** — Client ID Metadata Document support
  for multi-tenant deployments. Per §24.6 R6 deferred for
  empirical operator demand from v0.8.1+v0.8.2 HTTP/SSE
  adoption.
- **Sentence-transformers faithfulness path** — opt-in
  `[eval-faithfulness]` extra carrying sentence-transformers
  for paraphrase-tolerant scoring.
- **LLM-driven atomic-claim extraction for faithfulness**
  pipeline — reuses v0.8.1 PRT decomposition pattern.
- **DFAH calibration corpus expansion** — >50 prompt-id corpus
  for faithfulness baseline tuning.

## [0.8.1] - 2026-05-06

**The v0.8.0 review-deferral close-out + LLM-driven richness +
network surfaces.** Aggressive ~4-week scope (per Allen's
v0.8.1 cycle-open lock-in) executed in a single focused
session: ALL 12 v0.8.0 review-bucketed findings closed, the
LLM-driven richness for two of the four v0.8.0 P0 surfaces
(DFAH + PRT), and the FastAPI AuthProvider middleware
integration that closes the v0.8.0 F-V08-S3 ``/api/metrics``
auth gate. Three Phase 4 infra primitives (G4 Dockerfile
``--require-hashes``, G1 mutmut, G2 hypothesis) deferred to
v0.8.2 per §24.6 R6 — they benefit from a thoughtful
integration plan rather than rushing at cycle-end.

### Added

- **DFAH risk-determinism CLI verb (Phase 2.1)** —
  ``evidentia eval risk-determinism --context X --gaps Y``
  runs the v0.8.0 DFAHarness against the live
  :class:`RiskStatementGenerator`. Loads system context YAML
  + gap report JSON (same shape as ``evidentia risk
  generate``); fires N samples per gap; exits 1 if the
  overall determinism rate falls below the CI-gate threshold
  (default 0.95 per arXiv 2601.15322). Supports ``--gap-id``,
  ``--limit``, ``--samples-per-prompt``,
  ``--fail-on-determinism-rate-below``, ``--output``,
  ``--model``, ``--temperature``, ``--check-replay``.
- **PRT LLM-driven per-claim decomposition (Phase 2.2)** —
  ``RISK_STATEMENT_TRACE_PROMPT`` augments the system prompt
  when ``emit_trace=True``. Instructor's structured-output
  extraction populates the ``reasoning_trace`` field with
  3-7 atomic claims, per-claim policy clause citations, and
  self-introspected confidence. Fallback to v0.8.0 stub trace
  when the LLM omits the trace. Audit log distinguishes via
  ``trace_kind=v0.8.1-llm`` vs ``trace_kind=v0.8.0-stub``.
- **MCP HTTP/SSE transport (Phase 3.1)** — ``evidentia mcp
  serve --transport <stdio|sse|http>`` with ``--host`` +
  ``--port`` flags. New ``run_sse(host, port)`` +
  ``run_http(host, port)`` helpers in
  ``evidentia_mcp.server``. Backward-compat
  ``--no-stdio`` flag retained as a deprecated alias with
  migration hint. Default bind is 127.0.0.1; non-loopback
  warns about reverse-proxy auth requirement.
- **FastAPI AuthProvider middleware (Phase 3.3)** — new
  ``evidentia_api.auth_middleware.AuthProviderMiddleware``
  Starlette middleware. Wired via ``create_app(auth_provider=...)``.
  Closes the v0.8.0 F-V08-S3 MEDIUM finding —
  ``/api/metrics`` + ``/api/risks`` + all data-bearing
  ``/api/*`` routes inherit the auth requirement.
  ``UNAUTHENTICATED_PATHS`` allowlist for liveness probes
  (``/api/health``, ``/api/version``, ``/api/openapi.json``,
  ``/api/docs``, ``/api/redoc``). Static SPA paths bypass at
  the API layer (SPA enforces in browser).
- **``evidentia serve --auth-token-file <path>``** flag
  exposes the AuthProvider plumbing ergonomically. Sets
  ``EVIDENTIA_API_AUTH_TOKEN_FILE`` env var; module-level
  ``app`` reads it + constructs LocalTokenAuthProvider on
  module load. When unset, no auth gating fires (v0.8.0
  backward compat for localhost-only deployments).

### Changed

- **F-V08-CR-1 (HIGH)**: ``EvidentiaLogger._emit`` now gates
  the Prometheus counter increment on
  ``self._stdlib.isEnabledFor(stdlib_level)``. Counters and
  log-stream stay in sync regardless of operator log-level
  filtering. Lifted ``record_event`` import from lazy to
  module level.
- **F-V08-CR-2 (HIGH)**: ``evidentia_core.audit.metrics``
  counters encapsulated in a thread-safe
  :class:`MetricsRegistry` class. ``record_event`` now
  enforces the outcome contract via
  ``_VALID_OUTCOMES = {"success", "failure", "unknown"}`` —
  unknown values raise ``ValueError`` rather than silently
  miscount.
- **F-V08-CR-3 (MEDIUM)**: ``BaseSaaSCollector._get`` now
  raises ``QUERY_ERROR_CLASS`` on non-dict JSON responses
  rather than wrapping as ``{"items": data}``. The wrap
  silently masked non-conformant API responses; the new
  raise surfaces them.
- **F-V08-CR-4 (MEDIUM)**: ``evidentia mcp doctor`` +
  ``test_four_core_tools_registered`` /
  ``test_each_tool_has_a_description`` switched from
  FastMCP private API (``_tool_manager._tools``) to the
  public ``list_tools()`` async method. Robust against SDK
  minor-version internal renames.
- **F-V08-CR-11 (LOW)**: ``discover_plugins()`` gains an
  optional ``of_type`` kwarg that narrows the result to
  subclasses of a specific ABC. Eliminates the
  ``isinstance + issubclass`` boilerplate every operator
  was writing.

### Fixed

- **F-V08-S2 (LOW)**: ``LocalTokenAuthProvider`` rejects
  symlinks at construction time via ``os.lstat`` +
  ``stat.S_ISLNK``. Closes the construction-time TOCTOU
  window where a non-operator user with shared parent-dir
  write could swap the symlink target mid-construction.
- **F-V08-CR-5 (LOW)**: ``evidentia mcp doctor``
  initializes report variables at function top so the
  report block is unconditionally safe.
- **F-V08-CR-8 (LOW)**: replaced ``assert`` statements in
  ``oscal/exporter.py`` and ``bitsight/collector.py`` with
  explicit ``if x is None: raise ValueError(...)`` so
  invariants survive PYTHONOPTIMIZE=1 / -O deployments.
- **F-V08-CR-12 (LOW)**: tests in
  ``test_plugins/test_contracts.py`` defensively check
  ``result.reason is not None`` before ``.lower()`` /
  substring access.
- **F-V08-S5 (INFO)**: ``LocalDirectoryMarketplaceProvider``
  manifest parse failure now emits a ``COLLECT_FAILED``
  audit warning rather than silently falling back. Operators
  see misconfigurations in their SIEM.

### Notes

- v0.8.0 review F-V08-CR-10 (LOW): documents why
  ``BaseSaaSCollector`` does NOT use a PEP 695 generic
  ``collect()`` return type (polymorphic shapes:
  ``list[SecurityFinding]`` OR ``tuple[list, manifest]``).
  Inline rationale; no behavior change.
- v0.8.0 review F-V08-S4 (INFO): documents the resource-
  bounds posture in ``DFAHarness`` docstring — the harness
  is a library API; operators own per-call timeouts +
  aggregate budgets via ``concurrent.futures`` wrappers +
  LLM provider config. Future v0.8.x may add
  ``max_total_calls`` + ``per_call_timeout_seconds``
  first-class kwargs.
- **Phase 3.2 deferred to v0.8.2**: MCP CIMD richness (Client
  ID Metadata Document) is best explored against real MCP-
  client deployments than guessed at without empirical
  signals. v0.8.1 HTTP/SSE transports unblock this future
  work; CIMD-aware multi-tenant features iterate against
  actual operator demand.
- **Phase 4.1 + 4.2 + 4.3 deferred to v0.8.2** per §24.6
  R6: G4 Dockerfile ``--require-hashes`` flip needs CI
  release-workflow coordination + build-twice
  sha256sum-match validation; G1 mutmut needs careful per-
  module baseline tuning; G2 hypothesis needs ≥ 5 well-
  designed property tests. These infra primitives benefit
  from shipping together with a thoughtful integration
  plan rather than rushed at cycle-end.

## [0.8.0] - 2026-05-05

**The OSS-native AI moat.** First minor release after the
v0.7.x cycle close (18 patch releases over ~12 days). Lands
the four AI-quality features that distinguish a Vanta-class
dashboard from a compliance-engineering tool: DFAH
determinism harness, Policy Reasoning Traces, MCP server,
and the plugin-contract scaffolding that makes a community
catalog ecosystem possible.

### Added

- **DFAH determinism harness (P0.1)** —
  `evidentia eval stub-smoke` CLI verb + `DFAHarness` library
  API per arXiv 2601.15322. Validates that AI-driven artifact
  generation is auditor-defensibly reproducible (same prompt
  + same model + same temperature → same output across N
  samples). New module `evidentia_ai.eval` with `harness.py`
  / `metrics.py` / `seeds.py` + result models
  (DeterminismResult, ReplayResult, EvalResult). CI-gateable
  via `--fail-on-determinism-rate-below 0.95` (per arXiv
  2601.15322 DFAH guidance). 4 new EventAction entries:
  `AI_EVAL_STARTED`, `AI_EVAL_DETERMINISM_VIOLATION`,
  `AI_EVAL_FAITHFULNESS_VIOLATION`, `AI_EVAL_COMPLETED`.
  Reserves the faithfulness-violation slot for the v0.8.1
  follow-up.
- **Policy Reasoning Traces (P0.2)** —
  `evidentia risk generate --emit-trace` flag +
  `RiskStatementGenerator.generate(emit_trace=True)` kwarg
  per arXiv 2509.23291. Decomposes AI-generated risk
  statements into ordered atomic claims + per-claim policy
  clause citations + confidence scores. New Pydantic models
  `TraceClaim` + `ReasoningTrace`. Optional
  `RiskStatement.reasoning_trace` field — backward
  compatible with pre-v0.8.0 payloads. OSCAL emit gains
  `risk_statements_with_traces` kwarg surfacing traces as
  Evidentia-namespaced back-matter resources with canonical
  JSON + SHA-256 + base64 (Sigstore-signable; tamper-
  evident). Trestle pydantic.v1 round-trip preserves the
  trace data. New EventAction `AI_RISK_TRACE_EMITTED`. v0.8.0
  ships a single-claim stub trace; v0.8.1 ships the
  substantive LLM-driven per-claim decomposition.
- **MCP server (P0.3)** — new `evidentia-mcp` workspace
  member exposing 4 read-only tools (`list_frameworks`,
  `get_control`, `gap_analyze`, `gap_diff`) over the canonical
  stdio transport. `evidentia mcp serve` runs the server;
  `evidentia mcp doctor` runs a 4-check health probe. Built
  on the official `mcp` Python SDK's FastMCP scaffolding;
  graceful CLI degradation when the `evidentia[mcp]` extra
  isn't installed. HTTP/SSE transports + CIMD richness
  defer to v0.8.1.
- **Plugin contract scaffolding (P0.4)** — four ABCs in
  `evidentia_core.plugins`:
  `AuthProvider` (Authorization-header authentication),
  `StorageBackend[T]` (Pydantic-record persistence with
  generic type parameter), `MarketplaceProvider` (OSCAL
  catalog provider with list/fetch separation), and
  `BaseSaaSCollector` (HTTP scaffolding for SaaS API
  collectors with `_auth_header()` hook). Three reference
  implementations (`LocalTokenAuthProvider`,
  `FilesystemStorageBackend`, `LocalDirectoryMarketplaceProvider`)
  + `discover_plugins()` helper using
  `importlib.metadata.entry_points(group='evidentia.plugins')`.
- **M-4 collector base-class refactor** — Vanta, Drata,
  BitSight, and SecurityScorecard collectors now inherit
  from `BaseSaaSCollector`. Per-collector scaffolding LOC
  drops ~60% (130→50 lines); 92 collector tests still pass.
  BitSight + SecurityScorecard override `_auth_header()` for
  HTTP Basic + `Token <key>` schemes respectively.
  Multi-inheritance with the SaaS\* base classes preserves
  existing `pytest.raises(VantaAuthError)` test semantics.
- **Prometheus `/metrics` endpoint (P1 G3)** —
  `GET /api/metrics` returns Prometheus 0.0.4 text-format
  exposition. New `evidentia_core.audit.metrics` stdlib-only
  counter aggregator taps the audit-event-firing path via a
  module-level dict + threading.Lock. Metrics:
  `evidentia_app_info{version=...}`, `evidentia_uptime_seconds`,
  `evidentia_audit_events_total{action=...}`,
  `evidentia_audit_events_failures_total`. Process-local;
  multi-process aggregation defers to v0.8.1.
- **`docs/evidence-integrity.md` (P1 G8)** — anti-tamper
  deployment guidance covering evidence-collection integrity
  + tamper-evident audit + emit pipeline + reproducibility +
  three deployment patterns (SaaS, air-gapped, federal SI) +
  verification commands operators wire into CI gates.

### Changed

- `EvidentiaLogger._emit` now records every audit event into
  the in-process Prometheus counter aggregator. Lazy import
  keeps logger.py free of the metrics module's threading
  primitives at import time.

### Fixed

- `DFAHarness.run` replay-equivalence check now compares
  against `DeterminismResult.modal_hash` (canonical
  determinism modal) rather than `outputs[0]` (potential
  outlier). Closes pre-release-review F-V08-CR-7 correctness
  finding.
- `evidentia_ai.eval.seeds` docstring now accurately
  describes whitespace-collapse + trailing-terminator-strip
  behavior. Closes pre-release-review F-V08-CR-6.
- `RiskStatementGenerator._attach_stub_trace` docstring
  carries auditor disclosure that the v0.8.0 stub
  `confidence=0.5` is a placeholder, not an LLM-introspected
  value. Closes pre-release-review F-V08-CR-9.

### Notes

- This is the first minor release after the v0.7.x cycle
  CLOSED 2026-05-05. The pre-release-review v4 Pre-tag run
  + Step 7 post-tag verification gate the ship.
- Five inline-fixes during pre-release-review Step 5.A
  (correctness + defense-in-depth doc clarifications); 12
  bucketed to v0.8.1 with documented rationale (F-V08-CR-1
  HIGH logger record_event level filter, F-V08-CR-2 HIGH
  metrics counter encapsulation, F-V08-CR-3/4 MEDIUM
  collector base + MCP private API, plus 9 LOW polish).
- `docs/security-review-v0.8.0.md` is the 5th canonical
  Pre-tag deliverable per pre-release-review v4 §G7.
- `docs/threat-model.md` extended with v0.8.0 attack-
  surface delta covering all 4 new public surfaces +
  inherited mitigations.

## [0.7.16] - 2026-05-05

**The v0.7.x cycle wrap — security bump + commit-msg hook variant
+ in-repo retrospective + post-ship release.yml hardening.**
Final v0.7.x release. v0.8.0 design phase opens immediately
post-ship.

### Added

- **`commit-msg` pre-commit hook variant** (`standing-rule-sweep-msg`
  in `.pre-commit-config.yaml`): scans the commit-message body for
  the canonical 21-pattern set. Closes the gap left by the v0.7.15
  P0.3 file-content-only hook — completes the dual-stage coverage
  (committed file content + commit message body). Same script
  (`scripts/standing_rule_sweep.sh`) handles both stages.
- **`docs/v0.7.15-shipped.md`**: in-repo retrospective for v0.7.15
  alongside the memory pointer. Captures the Tailwind 4 migration
  + SettingsPage refactor + standing-rule pre-commit shipment +
  the post-ship release.yml hardening incident.

### Fixed

- **PR #23 — python-dotenv 1.0.1 → 1.2.2** in
  `docker/requirements.txt`. Closes 2 Dependabot medium-severity
  alerts (#7 + #8) for CVE — symlink-following in
  `python-dotenv.set_key` allows arbitrary file overwrite via
  cross-device rename fallback (vulnerable < 1.2.2). The
  v0.7.14 P1.5 hash-pinned requirements.txt generation tooling
  picked this up automatically; first auto-bump from Dependabot
  on the new file.
- **`release.yml` publish-container Wait extension to all 6
  inter-package deps** (commit `fd36e78`; landed post-v0.7.15
  ship as ship-cycle hardening). Same fix as v0.7.14 P2.2 for
  `container-build.yml`. Closes the LAST PyPI propagation race
  surface in the release pipeline. The v0.7.15 first ship
  publish-container fire failed at this gap; recovery via
  `gh run rerun --failed`. v0.7.16 ship validates the fix.

### Changed

- **`.pre-commit-config.yaml`** doc comment paraphrased to remove
  the literal forbidden-token phrase that the v0.7.13-cycle
  9613e62 leak introduced. The file is no longer a self-reference
  exception; removed from `scripts/standing_rule_sweep.sh`'s
  SKIP_FILES list.
- **`scripts/standing_rule_sweep.sh`** docstring + SKIP_FILES
  updated to reflect the dual-stage coverage (commit + commit-msg).

### Notes

- **OpenSSF Silver tier `test_statement_coverage80` MET** as of
  v0.7.14 (Codecov dashboard 82.14%). The answer-sheet refresh
  in `~/.claude/plans/evidentia-badgeapp-silver-gold-answer-sheet.md`
  reflects v0.7.16 ship state for re-submission to bestpractices.dev
  if the form prompts for verification.
- **v0.7.x cycle CLOSED**: 17 releases over ~12 days
  (v0.7.0 → v0.7.16). 5 consecutive PROCEED-CLEAN
  /security-review verdicts (v0.7.11 + v0.7.12 + v0.7.13 +
  v0.7.14 + v0.7.15; v0.7.16 expected to make 6). Pin-trap
  fix validated 5 consecutive releases (will be 5 + 1 at
  v0.7.16). release.yml CHANGELOG auto-population validated
  4 consecutive releases. All 17 v0.7.x release bodies
  substantive.

## [0.7.15] - 2026-05-05

**The Tailwind 4 migration + SettingsPage refactor + pre-commit
standing-rule sweep release.** Final v0.7.x cycle close before
v0.8.0 design opens. Closes the v0.7.13 + v0.7.14 frontend
deferrals + the lesson-learned from the v0.7.13-cycle commit-
message leak. No new public surfaces.

### Added

- **`scripts/standing_rule_sweep.sh`** — pre-commit hook that
  runs the canonical 21-pattern keyword sweep on staged files.
  Closes the gap surfaced by the v0.7.13-cycle 9613e62 leak
  (sweep ran only at pre-push; staged content + commit
  messages weren't checked at commit time). Hook integrates
  via `.pre-commit-config.yaml` `standing-rule-sweep` local
  hook. Limitation documented inline: commit-message body is
  not scanned by this hook; the file-content sweep is the
  primary catch.
- **`@tailwindcss/vite`** + **`tw-animate-css`** as new dev
  dependencies (replace `tailwindcss-animate` + the v3
  PostCSS chain).
- **`<SettingsForm/>`** sub-component in `SettingsPage.tsx` —
  isolated form-state component keyed on
  `configQuery.data.source_path` so each new config-load
  triggers a remount with fresh state seeded by useState
  lazy initializers. React's canonical idiom for "initialize
  state from async data".

### Fixed

- **Tailwind 3 → 4 migration** (P0.1; closes v0.7.13 + v0.7.14
  deferral): full shadcn/ui new-york preset rewritten from
  `tailwind.config.ts` JS-config to CSS-first `@theme {}`
  blocks in `src/index.css`. PostCSS chain replaced with
  the first-class `@tailwindcss/vite` Vite plugin.
  `tailwindcss-animate@1.0.7` (last v3-era release; not
  v4-compatible) replaced with `tw-animate-css@1.4.0`
  (community fork; v4-native). Visual output verified
  unchanged (severity palette, dark-mode toggle, accordion
  animations all carry forward).
- **`react-hooks/set-state-in-effect` lint error** in
  `SettingsPage.tsx` (P0.2; closes v0.7.14 deferral): the
  v0.4.1 useEffect+setState pattern that copied
  `configQuery.data` into local form state replaced with a
  key-based remount of the new `<SettingsForm/>`
  sub-component. Lint rule promoted from `warn` (v0.7.14) →
  `error` (v0.7.15) so any future regression fails CI.

### Changed

- `tailwind.config.ts` (deleted) — config moved to CSS-first
  `@theme` block in `src/index.css`.
- `postcss.config.js` (deleted) — PostCSS chain replaced by
  `@tailwindcss/vite` plugin.
- `vite.config.ts` — added `@tailwindcss/vite` plugin.
- `src/index.css` — `@tailwind base/components/utilities`
  triple replaced with `@import "tailwindcss"` +
  `@import "tw-animate-css"`. All theme tokens (12 shadcn/ui
  colors + Evidentia severity palette + border radius +
  container width) declared as `--color-*` CSS custom
  properties under `@theme {}`. `@custom-variant dark`
  directive enables class-based dark-mode (Tailwind 4
  defaults to media-query without this).
- `eslint.config.js` — `react-hooks/set-state-in-effect`
  promoted to `error`; obsolete `tailwind.config.ts` override
  block removed.

### Notes

- **PR #21 backlog now FULLY ABSORBED** across the v0.7.x
  cycle: 13 frontend bumps total (v0.7.14 P0.2-P0.5: 7 bumps
  including TS 5→6 / ESLint 9→10 / plugin-react-hooks 5→7 /
  jsdom + minors; v0.7.15 P0.1: tailwind 3→4 + the
  tailwindcss-animate replacement). The v0.7.x line ships on
  the latest stable frontend toolchain.
- **Recurring Scorecard PinnedDependencies false-positive** on
  the Dockerfile pip install line continues. v0.8.0 G4
  closes structurally; v0.7.14's `docker/requirements.txt`
  preview is the foundation. Per-release dismissal continues
  per the runbook in `docs/dockerfile-pinning.md`.

## [0.7.14] - 2026-05-05

**The frontend modernization + Codecov P2.1 deep-dive + final
v0.7.x hygiene + v0.8.0 G4 foundation release.** No new public
surfaces — the work is supply-chain modernization, P3 carry-over
closures, internal observability fixes, and the hash-pinned
requirements.txt preview that v0.8.0 G4 reproducible-build
verification will switch the Dockerfile install to.

### Added

- **`docker/requirements.txt`** (~2200 lines; 80 packages with
  SHA256 hashes) generated via `pip-compile --generate-hashes`
  against `evidentia[gui]==0.7.13`. v0.7.14 P1.5 PREVIEW; the
  Dockerfile install line continues to use exact-version pinning.
  The full switch to `pip install --require-hashes` lands in
  v0.8.0 G4 alongside the reproducible-build verification work.
- **`scripts/bump_version.py --regenerate-requirements`** — new
  optional flag that calls pip-compile after the version-bump
  substitutions. Default OFF so routine bumps don't re-resolve
  the transitive closure.
- **`packages/evidentia-ui/eslint.config.js`** — ESLint 10
  flat-config (the legacy `.eslintrc.*` was missing entirely;
  pre-v0.7.14 the `npm run lint` step was effectively a no-op).
  Lints `src/**/*.{ts,tsx}` + `tests/**/*.{ts,tsx}` with
  typescript-eslint + react-hooks + react-refresh rule sets.
- **`packages/evidentia-ui/src/vite-env.d.ts`** — triple-slash
  reference to `vite/client` types so TypeScript 6's stricter
  side-effect-import resolution finds the `*.css` module
  declaration (without this, `import "@/index.css"` in main.tsx
  surfaces TS2882).
- **`DATABRICKS_EXTRA_LTS_RUNTIMES`** env var (Databricks
  collector) — operators on a newer LTS than what
  evidentia-collectors ships can supply additional version
  prefixes (comma-separated). v0.7.8 LOW × 9 item 6 closure.

### Fixed

- **container-build.yml smoke test propagation race** (P2.2):
  the existing Wait step polled only the `evidentia` umbrella
  package, but pip's resolution then failed on
  `evidentia-core<0.8.0,>=0.7.13` if evidentia-core hadn't
  propagated yet (surfaced on the v0.7.13 e32b742 PR #18 merge).
  Extended to poll all 6 inter-package deps (evidentia,
  evidentia-core, evidentia-ai, evidentia-collectors,
  evidentia-integrations, evidentia-api). Closes the same
  race that v0.7.6 P0.5 CI1 closed for the publish-container
  path.
- **Codecov 0% bug — attempt 1 of deeper P2.1 diagnosis**:
  removed the `flag_management.individual_flags[].paths` glob
  `["packages/*/src/"]` block from `codecov.yml`. The Codecov
  upload-state endpoint confirmed uploads land on their side
  but parse to 0 files; most likely cause is the glob filter
  not recursing deep enough into the new full-paths emitted
  by the v0.7.13 `source_pkgs` fix. If this attempt resolves,
  Codecov state will move from `error` to `complete` on
  post-push commits. If still broken, attempt 2 + escalation
  per §23.A.
- **Tableau Windows tempfile cleanup** (P1.2; v0.7.8 LOW × 9
  item 3 closure): refactored `publish_csv_datasource` from
  `tempfile.NamedTemporaryFile(delete=False)` + manual
  `unlink()` wrapped in `contextlib.suppress(OSError)` to
  `tempfile.TemporaryDirectory()` context manager. The
  directory cleanup at context exit reliably removes the file
  on both POSIX and Windows; if a handle is still open at
  exit time, `shutil.rmtree` retries (Python 3.12+ behavior).

### Changed

- **TypeScript 5 → 6** (P0.2): added `"ignoreDeprecations":
  "6.0"` to `tsconfig.json` to silence the `baseUrl` deprecation
  warning. Path-aliases will migrate to a `paths`-only setup
  in v0.7.15 / v0.8.0 when the broader TS6 cleanup cycle opens.
- **ESLint 9 → 10** (P0.3): bumped to flat-config (legacy
  `.eslintrc.*` removed in ESLint 10). NEW typescript-eslint
  ^8.59 dep replacing the deprecated separate
  @typescript-eslint/parser + plugin packages.
- **eslint-plugin-react-hooks 5 → 7** (P0.4): added
  `react-hooks/set-state-in-effect` rule to v7. SettingsPage.tsx
  uses this pattern for a config-load workflow that's
  intentional but needs refactoring in v0.7.15; rule is set
  to `warn` for v0.7.14.
- **eslint-plugin-react-refresh 0.4 → 0.5** (P0.4)
- **jsdom 25 → 29** + **postcss 8.4.47 → 8.5.14** + **@types/node
  22 → 25** (P0.5; minor bumps; no API breakage)
- **`docs/dockerfile-pinning.md`** updated with v0.7.14 P1.5
  preview-state section documenting what shipped + what stays
  deferred to v0.8.0 G4.

### Notes

- **Tailwind 3 → 4 deferred** to v0.7.15 / v0.8.0 P5 per the
  2-day time-box rule (§23.B). The migration requires switching
  from PostCSS chain to `@tailwindcss/vite` plugin + rewriting
  the full shadcn/ui preset config to CSS-first `@theme {}`
  block + replacing `tailwindcss-animate` (last v3-era release)
  with `tw-animate-css` (v4-compatible community fork).
  Estimated 1-2 days of careful work + visual validation;
  doesn't fit the v0.7.14 wrap-up cadence.

- **v0.7.8 LOW × 9 batch FULLY CLOSED** as of v0.7.14:
  - 5 closed in v0.7.13 (items 4 + 5 + 7 + 8 + duck-typing)
  - 1 already closed in v0.7.12 (logger contextlib.suppress)
  - 3 closed in v0.7.14 (items 1 + 3 + 6 — this release)

- **Recurring Scorecard PinnedDependencies false-positive**
  on the Dockerfile pip install line continues. v0.8.0 G4
  closes structurally; v0.7.14's `docker/requirements.txt`
  preview is the foundation. Per-release dismissal continues
  per the runbook in `docs/dockerfile-pinning.md`.

## [0.7.13] - 2026-05-04

**The dependency modernization + Codecov fix + P3 carry-over
closure release.** Wrap-up of the v0.7.x cycle before v0.8.0
opens. No new public surfaces — the work is supply-chain
modernization, internal-hygiene fixes, and release-process
ergonomics that prevent recurring gaps.

### Added

- **`docs/dockerfile-pinning.md`** documenting the exact-version
  pinning policy + recurring-Scorecard-alert dismissal runbook +
  roadmap to full hash-pinning (paired with v0.8.0 G4
  reproducible-build verification).
- **`scripts/extract_changelog_block.py`** + 21 self-tests
  covering every shipped v0.7.x CHANGELOG block — wired into
  `release.yml` so future releases auto-populate their GitHub
  Release body from the matching `[X.Y.Z]` block + canonical
  PEP 740 wheel-verify stanza. Closes the v0.7.5→v0.7.12
  stub-body gap structurally.
- **`tests/integration/test_oscal/test_uuid_in_two_locations.py`
  → `tests/unit/test_oscal/test_trestle_conformance.py`** v0.7.9
  M-9 closure: 2 new tests asserting Vendor UUID identity across
  `metadata.parties[].uuid` AND `back-matter.resources[].uuid`,
  with trestle-conformance round-trip + multi-vendor pairwise
  invariant.
- **Vanta + Drata `_is_high_risk` extended field shapes**
  (v0.7.9 L-2 closure): top-level `severity` / `tier` / `risk` /
  `riskRating` / `riskClass` field probes; nested `assessment` /
  `risk_summary` / `riskSummary` block probes; `SEVERE` matched
  alongside `HIGH` / `CRITICAL`. 2 new test cases (one per
  collector) covering all 7 extended shapes.
- **SIG BYO sparse-row debug logging** (v0.7.9 L-4 closure):
  `generate_from_byo_template` emits per-row `_log.debug(...)`
  on label mismatches, sparse rows, already-populated cells, and
  successful pre-fills. Operators ingesting partially-completed
  SIG templates can diagnose label drift via
  `evidentia --log-level debug`.

### Fixed

- **Codecov 0% on every commit since v0.7.10** (P0.3): root cause
  re-diagnosed against local `coverage.xml` — the v0.7.12 P0.7
  `relative_files = true` fix didn't help because Cobertura
  encodes file paths relative to whichever `<source>` root
  matches, and 6 source roots × filename collisions (every
  package has `__init__.py`, several have `app.py` etc.) made
  the XML fundamentally ambiguous. Switched to `source_pkgs` so
  the Cobertura output records full on-disk paths
  (`packages/evidentia-core/src/evidentia_core/...`) without
  per-source-root disambiguation. Codecov's path-resolver maps
  these directly to the GitHub repo tree.
- **Power BI `_row_value` None handling in lists** (v0.7.8 LOW
  item 5): `[None, "x", None]` was joining as `"None;x;None"`.
  Filtered Nones before join.
- **Power BI + Tableau Pydantic `.value` duck-typing collision**
  (v0.7.8 LOW items 7 + 8): the previous
  `hasattr(value, "value") and not isinstance(value, str|int|float)`
  matched ANY object with a `.value` field — including Pydantic
  models that happen to expose one. Tightened to
  `isinstance(value, Enum)` so only true Enum instances take
  the value-extraction branch.
- **Snowflake LOGIN_HISTORY datetime tz-cast** (v0.7.8 LOW
  item 4): naive `event_timestamp` values now force-cast to
  UTC + emit tz-aware ISO 8601 strings via the new
  `_to_utc_iso(value)` helper, ensuring audit-trail correlation
  works across operator infrastructure that mixes UTC + local-tz
  timestamps.

### Changed

- **`release.yml` GitHub Release body** now auto-populated from
  the matching `CHANGELOG.md` `[X.Y.Z]` block + PEP 740
  wheel-verify stanza template, via the new
  `Extract release body from CHANGELOG` step + `body_path:
  release-body.md` argument to softprops/action-gh-release. The
  publish-container append-step continues unchanged. Workflow
  fails fast (exit 1) if the extracted body is < 1500 bytes
  (a sanity gate against malformed CHANGELOG blocks shipping
  stub releases).
- **`docs/threat-model.md`** appended a v0.7.13 attack-surface
  delta sub-section documenting the no-new-surface state +
  carry-forward of v0.7.12 trust boundaries.
- **`docs/v0.8.0-plan.md`** documents M-4 collector base-class
  refactor as paired with the P0.4 plugin-contract scaffolding
  work. Acceptance criterion: `BaseSaaSCollector` ABC exists;
  v0.7.9 Vanta/Drata/BitSight/SecurityScorecard collectors
  inherit from it; per-collector LOC drops ≥ 25% on common
  scaffolding.
- **`docs/ROADMAP.md`** v0.7.12 promoted from NEXT to SHIPPED;
  v0.7.13 added as new NEXT section; v0.7.14 reserved for patches
  and remaining v0.7.13 deferrals.
- **`README.md`** v0.7.12 added to recent-releases section;
  CHANGELOG version-history range updated to v0.1.0–v0.7.12;
  forward-pointer simplified (v0.7.12-plan.md reference removed
  since v0.7.12 is shipped).

### Notes

- 3 of the 9 v0.7.8 LOW × 9 batch deferred to v0.7.14 with
  rationale: test-coverage gaps (item 1 — needs net-new tests),
  Tableau Windows tempfile cleanup (item 3 — current
  `suppress(OSError)` is acceptable; full fix is feature work),
  Databricks LTS hard-coded list (item 6 — env-var extensibility
  is feature work, paired better with v0.8.0 plugin contracts).
- 1 of the 9 was already closed in v0.7.12: contextlib.suppress
  on logger calls (4 collectors had the wrapping removed in
  v0.7.12 P3).

## [0.7.12] - 2026-05-04

**The cloud-WORM trifecta + GDPR Article 17 + FAIR Monte Carlo
release.** v0.7.12 carries the v0.7.11 P0 audit chain-of-
custody from operator-side-metadata-only to regulator-grade
hardware-WORM enforcement across S3 / Azure / GCS, closes the
v0.7.11 GDPR functional gap surfaced by Step-4 /security-review,
and adds the canonical Monte Carlo simulation form for FAIR risk
quantification (the v0.7.11 P1.5 G4 deterministic PERT-mean
shipped first, simulation here). Plus the v0.7.11 fresh-venv
install propagation foot-gun closure, Codecov 0% bug fix, and
CodeQL CRITICAL #92 (`py/partial-ssrf` in
`securityscorecard/collector.py`) closure.

### Added

- **3 cloud-WORM backends** with regulator-grade enforcement:
  `S3ObjectLockWORM` (`evidentia[worm-s3]` extra; boto3 + S3
  Object Lock), `AzureImmutableBlobWORM` (`evidentia[worm-azure]`;
  azure-storage-blob immutable policies), `GCSBucketLockWORM`
  (`evidentia[worm-gcs]`; google-cloud-storage Bucket Lock). All
  three implement the same `WORMBackend` ABC contract; switching
  clouds is a constructor swap. 53 new tests covering put / get /
  3-layer delete defense / extend_retention / legal_hold workflow
  / multi-tenant prefix isolation / GDPR purpose-limited records.
- **GDPR Article 17 `purge_immediately` flow**:
  `WORMBackend.purge_immediately(record_id, *, gdpr_request_ref,
  operator_id)` operator workflow. Pre-conditions enforced
  (GDPR-shaped record, no legal hold, populated audit fields).
  `transition_lifecycle()` gains `force_gdpr_purge: bool = False`
  parameter that scopes the override to GDPR records only. Closes
  the v0.7.11 functional gap surfaced by Step-4 /security-review.
  11 new tests covering the full workflow.
- **FAIR Monte Carlo simulation** (P1.5 G4.1):
  `evidentia risk quantify --method fair-mc --iterations N
  [--seed N] [--csv path]`. Stdlib-only Beta-PERT sampling (no
  numpy dep). `SimulationResult` Pydantic model with P10/P50/P90
  percentiles, mean, stddev, ASCII box-and-whisker, CSV export.
  Aggregate `generate_monte_carlo_report` sorted by P50
  descending. 24 new tests + 2 new CLI integration tests.
- **CodeQL custom sanitizer for SSC `portfolio_id`**:
  `_validate_portfolio_id_shape` allow-list (`^[A-Za-z0-9_-]
  {1,128}$`) applied at 3 layers (REST router early-fail with
  400; collector __init__ pre-construction reject;
  `_resolve_portfolio_id` defense-in-depth on API responses).
  Closes CodeQL CRITICAL #92 (`py/partial-ssrf`, CWE-918,
  CVSS 7.6). 29 new validation tests + 9 REST endpoint tests.
- **3 new operator runbooks**:
  - `docs/worm-backends.md` (~290 lines): S3 + Azure + GCS
    setup, IAM/auth, Compliance vs Governance modes,
    cross-cloud comparison, troubleshooting
  - `docs/fair-monte-carlo.md` (~205 lines): Beta-PERT
    methodology, iteration tuning, percentile interpretation,
    worked example
  - `docs/gdpr-purge-flow.md` (~260 lines): Article 17 rationale,
    operator 5-step workflow, cloud-specific considerations,
    legal-counsel-defensible audit-trail expectations
- **release-checklist.md Steps 5.5 + 9.5** — codifies the
  per-release doc-consistency sweep + release-notes audit
  practices (per Allen 2026-05-04 directive).
- **threat-model.md v0.7.12 attack-surface delta** — full STRIDE
  coverage for the 3 cloud-WORM backends, GDPR purge workflow,
  Monte Carlo, and SSC #92 closure.

### Fixed

- **Codecov 0% bug** (P0.7): `[tool.coverage.run]
  relative_files = true` in `pyproject.toml` + removed inverted
  `fixes:` mapping in `codecov.yml`. Coverage XML now emits
  literal repo-relative paths (`packages/evidentia-core/src/
  evidentia_core/foo.py`) which Codecov's path matcher resolves
  directly against the GitHub tree. Pre-fix: every commit
  registered `state: error` with `totals: {0,0,0,0.0}` despite
  v0.7.11 reporting 81.87% statement coverage internally.
- **PyPI inter-package pin propagation foot-gun** (P0.5):
  `scripts/bump_version.py` now tightens the LOWER bound of
  inter-package range pins to the current release version on
  every bump (during v0.7.12 ship: pins become `>=0.7.12,<0.8.0`
  not `>=0.7.0,<0.8.0`). Closes the v0.7.11 ship-time issue
  where `pip install evidentia==0.7.11` could resolve a cached
  `evidentia-core==0.7.10` from the loose pin during the PyPI
  propagation window. 13 new tests on `bump_pin_range`.

### Changed

- **v0.7.12 P3 carry-over batch (M-3 + cosmetic harmonization)**:
  Dropped over-defensive `contextlib.suppress(Exception)`
  wrapping on `_log.info` audit-logger calls in 4 collectors
  (vanta / drata / bitsight / securityscorecard). The audit
  logger should never raise; if it does, that's a real bug worth
  surfacing. Plus harmonized `Path(env).expanduser().resolve()`
  pattern across all 6 secure stores (vendor / model_risk /
  effective_challenge / metric / workflow / retention_metadata).
- **Doc consistency pass**: canonical 89 bundled catalogs
  applied across README / CHANGELOG / docs/positioning-and-
  value.md / docs/gui/* / docs/ide-setup.md / packages/
  evidentia-api/README.md (was inconsistently "82" / "88" / "77"
  in different places). README "Recent releases" refreshed with
  v0.7.9 / v0.7.10 / v0.7.11. ROADMAP.md "Last updated" line
  bumped to v0.7.11.

### Quality gates at this point in cycle

- 2074 tests passing (was 1929 at v0.7.11 ship; +145 new this
  cycle including 53 WORM-backend tests + 24 Monte Carlo +
  29 SSC validation + 9 REST SSRF + 13 bump_version + 11 GDPR
  + 6 CLI integration)
- mypy --strict 0/0 across 188 source files (was 184)
- ruff clean
- Standing-rule keyword sweep clean across all 12 v0.7.12
  commits

### v0.7.12 carry-overs (deferred to v0.7.13 or v0.8.0)

- Remaining P3 deferrals (M-4 base-class refactor / M-7 sheet-
  name overflow / M-8 hard-coded sheet name / M-9 OSCAL UUID
  trestle-conformance check / L-2 / L-4 / L-5 / L-8 + 9 v0.7.8
  LOWs)
- CodeQL custom sanitizer pack (deferred to v0.8.0; v0.7.12
  used inline regex validation + per-alert dismissal pattern)

## [0.7.11] - 2026-05-04

**The audit chain-of-custody + governance-trio + Open FAIR ship.**
Brings retention metadata + WORM (Write-Once-Read-Many) backend
abstraction, the third governance primitive (KRI/KPI/KGI metrics),
the fourth (Open FAIR risk quantification), the fifth (process-as-
code workflows), and a substantial deferral roll-up. First v0.7.x
release in this cycle to ship with **zero security findings** —
PROCEED-CLEAN at the Phase final pre-release-review.

Per the v0.7.11 plan, concrete cloud-WORM backends (S3 Object
Lock + Azure Immutable Blob + GCS Bucket Lock) + FAIR Monte Carlo
simulation + remaining ~12 deferrals are deferred to v0.7.12.

### Added

- **`evidentia retention` — audit chain-of-custody primitives**
  (v0.7.11 P0). Brings retention metadata + WORM (Write-Once-Read-
  Many) backend abstraction to Evidentia so collected evidence
  can carry per-record retention policies aligned with US/EU
  regulatory record-retention regimes (SEC Rule 17a-4 / FINRA 3110
  / IRS 1.6001-1 / Sarbanes-Oxley §404 / HIPAA / GLBA / PCI DSS
  10.7 / OCC 2011-12 / SR 11-7 model risk / GDPR purpose-limited).

  New module `evidentia_core.retention`:
  - `RetentionClassification` enum (10 regulator-aligned classes)
  - `RetentionPolicy` reusable policy template
  - `RetentionMetadata` per-record schema with auto-populated
    `lock_until` from `created_at + retention_period_days`
  - `RetentionLifecycleStage` enum (active / preserved / expired
    / purged) with state-machine transitions
  - `is_locked()` predicate (legal-hold-aware)
  - `transition_lifecycle()` enforces legal transitions; raises
    `RetentionTransitionError` on illegal moves (skipping ahead,
    transitioning while locked, transitioning out of PURGED,
    transitioning to EXPIRED while under legal hold)
  - `default_retention_days()` per-classification regulator
    defaults
  - `generate_retention_report()` deterministic Markdown audit
    report with executive summary + per-classification table +
    purge-eligible list + legal-hold list

  WORM backend abstraction:
  - `WORMBackend` ABC defining the put / get / get_metadata /
    delete / extend_retention contract
  - `LocalFilesystemWORM` reference implementation with
    application-level WORM enforcement (no hardware-level WORM —
    suitable for dev/test only). Concrete `S3ObjectLockWORM`,
    `AzureImmutableBlobWORM`, `GCSBucketLockWORM` deferred to
    v0.7.12 with their respective extras
  - `WORMBackendError` raised on contract violations: double-put,
    delete inside retention window, delete under legal hold,
    delete on non-EXPIRED records, retention-shortening attempts

  CLI: `evidentia retention {set, list, show, extend, transition,
  delete, report}`. JSON-file persistence
  (`evidentia_core.retention_metadata_store`) follows the
  harmonized v0.7.11 store pattern (UUID-shape gate +
  `validate_within` + atomic `os.replace`). Brings the secure-store
  pattern to a 6-store harmonization. 72 new tests (55 unit + 17
  CLI integration).

- **`evidentia governance workflow` — process-as-code governance
  workflows** (v0.7.11 P1.5 G5). Closes the v0.7.11 P1.5
  governance trio (G3 KRI/KPI/KGI + G4 Open FAIR + G5 workflows).
  Operators declare governance processes in YAML — change-approval,
  quarterly-review, validation-cycle, etc. — then execute + track
  via the CLI. New module `evidentia_core.governance.workflows`
  ships:
  - `WorkflowStepStatus` enum (5 states: pending / in_progress /
    approved / rejected / skipped)
  - `WorkflowStatus` enum (5 states: draft / in_progress /
    approved / rejected / canceled)
  - `WorkflowStepEvent` schema (timestamped state-transition with
    actor + optional note)
  - `WorkflowStep` schema (name + required_role + sla_days +
    history)
  - `Workflow` schema (name + subject + initiator + steps)
  - `current_step_index()` finds the active step
  - `evaluate_workflow()` derives overall status from step states
    (any rejected → REJECTED; all approved/skipped → APPROVED;
    otherwise IN_PROGRESS or DRAFT)
  - `advance_workflow_step()` enforces ordered execution + auto-
    promotes the next step to IN_PROGRESS on forward transitions;
    raises `WorkflowAdvanceError` on rule violation
  - `generate_workflow_log()` deterministic Markdown audit-log
    with rejection-callout + per-step status table + per-step
    event narrative
  - `evidentia_core.workflow_store` JSON-file persistence
    following the harmonized v0.7.11 store pattern
  CLI: `evidentia governance workflow {run,advance,status,list,
  log,delete}`. 42 new tests (28 unit + 14 CLI integration).
- **`evidentia risk quantify --method open-fair` — Open FAIR risk
  quantification** (v0.7.11 P1.5 G4). Implements the Open Group's
  Open FAIR (Factor Analysis of Information Risk) taxonomy for
  dollarized risk quantification (per the Open Group's Open Risk
  Taxonomy Standard + ISO/IEC 27005 Annex E). New module
  `evidentia_core.risk_quant.open_fair` ships:
  - `OpenFAIRScenario` Pydantic schema with TEF + Vulnerability
    + Primary Loss + Secondary Loss factors. Each factor accepts
    either a scalar OR a `PERTRange` (low / most-likely / high).
  - `PERTRange` 3-point estimate with `low <= most_likely <= high`
    invariant + Beta-PERT mean formula
    `E[X] = (low + 4*most_likely + high) / 6`
  - `compute_lef()` (LEF = TEF × Vulnerability)
  - `compute_loss_magnitude()` (LM = PrimaryLoss + SecondaryLoss)
  - `compute_ale()` (ALE = LEF × LM, the Annualized Loss Expectancy)
  - `categorize_risk()` mapping ALE to FAIR risk bands (severe /
    high / significant / moderate / low)
  - `generate_risk_quantification_report()` deterministic Markdown
    report with executive summary (total ALE + category
    distribution) + per-scenario detail (LEF + LM breakdown +
    each factor's resolved-mean) sorted by ALE descending
  CLI: `evidentia risk quantify --method open-fair --scenarios
  <yaml/json>` reads scenarios from disk + writes the Markdown
  report (stdout or `--output`). Full Monte Carlo simulation is
  deferred to v0.7.12; v0.7.11 ships the deterministic
  PERT-mean expected-value form. 30 new tests (23 unit + 7 CLI).

- **`evidentia governance metrics` — KRI / KPI / KGI metric
  primitives** (v0.7.11 P1.5 G3). Brings the third governance
  primitive into the v0.7.10 governance overlay. New module
  `evidentia_core.governance.metrics` ships:
  - `MetricKind` enum (kri / kpi / kgi) per IIA + COSO ERM
  - `MetricDirection` enum (higher_is_worse / higher_is_better)
  - `MetricStatus` enum (comfortable / watch / breach / no_data)
  - `Metric` Pydantic schema with name + description + kind +
    direction + unit + optional owner_email + optional warning
    + critical thresholds + observation history + notes
  - `MetricObservation` schema (date + value + optional note)
  - `evaluate_metric()` deterministic threshold-evaluation
  - `generate_metrics_report()` deterministic Markdown dashboard
    with executive summary + BREACH-state warning callout +
    per-kind tables + status counts
  - `evidentia_core.metric_store` JSON-file persistence (mirrors
    the v0.7.11-harmonized `validate_within` belt-and-suspenders
    pattern across all 4 stores: vendor_store + model_risk_store
    + effective_challenge_store + metric_store)
  CLI: `evidentia governance metrics {add,list,show,edit,delete,
  observe,report}` with full `--json` machine-readable mode +
  filterable list. 42 new tests cover schema validation +
  evaluate_metric across all 4 status branches + report
  rendering + store CRUD + 14 CLI integration tests.

### Fixed

- **F-V10-S2 closure** (v0.7.11 P3): `evidentia model-risk model
  edit --editor` and `evidentia tprm vendor edit --editor` no
  longer launch arbitrary `$EDITOR` binaries. New helper
  `evidentia.cli._editor.resolve_editor_or_exit` does
  `shutil.which` resolution, parses `$EDITOR` via `shlex.split`
  (handles patterns like `EDITOR='code -w'`), and applies a
  default allowlist of common editors (vi/vim/nvim/nano/emacs/
  micro/pico/code/subl/atom/gedit/kate/notepad). Operators with
  non-standard editors set `EVIDENTIA_EDITOR_ALLOW_ANY=1` to opt
  out. 13 new tests cover the helper across happy-path resolution,
  argv splitting, opt-out semantics, and 5 error paths
  (empty / not-on-PATH / not-allowlisted / unbalanced-quotes /
  custom-allowlist). Closes the v0.7.10 LOW-severity CWE-78 risk
  amplifier finding (F-V10-S2) AND the parallel surface that has
  shipped in the v0.7.9 TPRM CLI since v0.7.9 P0.1.3.

### Changed

- **`validate_within` harmonization across all 3 JSON-file stores**
  (v0.7.11 P3, Step 4 forward-look from v0.7.10 security review).
  The v0.7.10 P1.5 G2 `effective_challenge_store` shipped with
  belt-and-suspenders `validate_within(candidate, store_dir)` on
  every CRUD operation; the older v0.7.9 `vendor_store` and
  v0.7.10 P0.6.1 `model_risk_store` previously relied on UUID-shape
  gate alone for `save_*` paths. This release adds the same
  defense-in-depth check to `save_vendor` and `save_model` so all
  three stores follow identical secure patterns. No behavioral
  change for valid UUIDs; future shape-gate relaxations (e.g.,
  ULID acceptance) won't silently disable the second barrier.
- **v0.7.9 deferral closures (P3 second batch)**:
  - **L-1**: REST collector endpoints (vanta + drata + bitsight
    + securityscorecard + okta + servicenow) replace silent
    `int(body.get("max_x") or 2000)` coercion with explicit type +
    range validation matching the CLI's `min=1, max=100_000` Typer
    gate. Bad input now returns 400 with a clear message instead
    of silently defaulting to 2000.
  - **L-6**: SecurityScorecard CLI verb docstring rewritten with
    PEP-257 single-line summary.
  - **M-5**: BitSight cross-host pagination break + scheme-
    downgrade pagination break now emit structured warning events
    (`COLLECT_ABORTED` action with `reason` evidentia field). The
    previously-silent break is now observable in audit logs.
  - **M-6**: SecurityScorecard `_resolve_portfolio_id` emits a
    structured warning when auto-selecting from multiple
    portfolios so operators know the choice was non-deterministic.



## [0.7.10] - 2026-05-04

**The financial-services Model Risk Management + governance ship.**
Brings Evidentia into alignment with the Model Risk Management
regulatory stack (SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC
Bulletin 2026-13a) and the IIA Three Lines Model 2020 governance
framework. Introduces the `evidentia model-risk` + `evidentia
governance` top-level capability modules; ships 6 new bundled
financial-sector regulatory catalogs (5 FFIEC IT Handbook booklets
+ FFIEC Cybersecurity Assessment Tool + OCC Bulletin 2026-13a /
FRB SR 26-02 model-risk supersession) on top of the v0.7.10 P1
first slice (FFIEC Outsourcing booklet); closes the last remaining
**OpenSSF Best Practices Silver-tier MUST** (`test_statement_
coverage80`) by publishing 81.87% statement coverage to Codecov;
closes 4 of the 17 v0.7.9-deferred MEDIUM/LOW findings (M-1 / M-2 /
L-3 / L-7); and ships comprehensive walkthrough docs covering both
modules. **All 7 OpenSSF Silver MUST criteria are now Met** —
Allen files the Silver application form post-tag.

Per the v0.7.10 plan, P3 follow-up (13 remaining v0.7.9 deferrals
+ 9 v0.7.8 LOWs) is deferred to v0.7.11 with documented rationale
per finding (none are correctness defects or active exploit paths).

### Added

- **Model Risk Management Pydantic schemas** (v0.7.10 P0.6.1
  first slice). New module
  `evidentia_core.models.model_risk` introducing `ModelInventory`
  + `ModelInput` + `ModelOutput` + `ValidationFinding` Pydantic
  models plus 5 supporting enums (`Methodology` / `Provenance` /
  `Tier` / `ValidationStatus` / `ValidationSeverity`) per SR 11-7
  / OCC Bulletin 2011-12 (historical) and SR 26-02 / OCC Bulletin
  2026-13a (April 2026 active guidance). Validation:
  `@model_validator(mode='after')` enforces the vendor-or-internal
  cross-link contract — vendor-provenance models MUST set
  `vendor_id` (cross-links to v0.7.9 TPRM `Vendor.id`); internal-
  provenance models MUST NOT set it. Auto-cadence helper
  `compute_next_validation_due()` maps Tier 1 → annual / Tier 2 →
  biennial / Tier 3 → triennial with leap-year-clamp month
  arithmetic mirroring v0.7.9 P0.1 `Vendor.compute_next_review_due`.
  `EvidenceRef` is reused from the v0.7.9 TPRM module so the same
  artifact_id-or-file_path two-mode contract applies. 22 unit
  tests covering enum coverage / sub-model construction /
  validator firing / cadence math / leap-year clamps / Pydantic
  extra-forbid sanity.
- **`evidentia_core.model_risk_store` JSON-file persistence**
  (v0.7.10 P0.6.1 first slice). One JSON file per ModelInventory
  record under platformdirs-backed user-dir; `EVIDENTIA_MODEL_STORE_DIR`
  env-var override; UUID-shape ID validation rejecting path-
  traversal; atomic `os.replace(tmp, out_path)` save semantics.
  CRUD primitives: `save_model` / `load_model_by_id` /
  `list_models` (sorted by Tier 1 → Tier 3 then name) /
  `delete_model`. 18 unit tests covering store-dir resolution
  precedence / ID-shape gate / save+load round-trip / atomic-tmp
  cleanup / validation-finding preservation / list sort order.
- **`evidentia model-risk model` CLI** (v0.7.10 P0.6 second
  slice). 5 verbs mirroring the v0.7.9 TPRM CLI pattern:
  `add` / `list` / `show` / `edit` / `delete`. Hybrid input model
  on `add` — atomic per-field flags (`--name` / `--purpose` /
  `--methodology` / `--vendor-or-internal` / `--tier` / `--owner`
  / `--last-validation-date` / `--next-validation-due` /
  `--vendor-id` / `--retirement-plan` / `--notes`) for the common
  case + `--from-yaml <path>` for full record including inputs /
  outputs / validation_findings. `edit` supports per-field flags
  + `--from-yaml` (full replace) + `--editor` (open YAML in
  `$EDITOR` for in-place edit). `list` filters by `--tier` /
  `--methodology` / `--vendor-or-internal` and ships a `--json`
  bare-array machine-readable mode. `show` / `delete` accept
  UUIDs only with strict shape validation. Auto-recompute of
  `next_validation_due` from `tier` + `last_validation_date`
  honors operator overrides via `--next-validation-due`. 23 CLI
  integration tests covering every verb + atomic + YAML +
  validation contract.
- **Financial-sector overlay catalogs (full P1 batch — 7 new
  bundled Tier A catalogs)** (v0.7.10 P1). All 7 catalogs that
  the v0.7.10 plan called for now ship with Evidentia. Total
  bundled catalogs: 82 → 89 (matches plan target). Tier A: 37 → 44.
  - **`ffiec-outsourcing`** — FFIEC IT Examination Handbook
    Outsourcing Technology Services booklet (June 2004 + 2008/
    2010 supplements; 30 controls, 7 categories).
  - **`ffiec-audit`** — FFIEC IT Examination Handbook Audit
    booklet (April 2012; 31 controls, 7 categories).
  - **`ffiec-management`** — FFIEC IT Examination Handbook
    Management booklet (November 2015; 25 controls, 7 categories).
  - **`ffiec-operations`** — FFIEC IT Examination Handbook
    Operations booklet (July 2004; 27 controls, 8 categories).
  - **`ffiec-information-security`** — FFIEC IT Examination
    Handbook Information Security booklet (September 2016; 41
    controls, 10 categories).
  - **`ffiec-cat`** — FFIEC Cybersecurity Assessment Tool (2017
    representative subset; 32 controls, 5 domains spanning
    Baseline / Evolving / Intermediate / Advanced maturity tiers).
  - **`occ-sr-26-02`** — OCC Bulletin 2026-13a / FRB SR 26-02
    Supervisory Guidance on Model Risk Management (April 17, 2026
    supersession of OCC 2011-12 / SR 11-7; 35 controls, 9
    categories, includes the explicit GenAI-out-of-scope narrative
    that motivates Evidentia's GenerationContext + AI-feature-
    linkage positioning).
  All catalogs are public domain (US federal inter-agency
  examination guidance per 17 USC §105). Authoring infrastructure
  ships under `scripts/catalogs/gen_ffiec.py` + `scripts/catalogs/
  gen_occ_sr.py`. Tests via `evidentia_core.catalogs.loader`
  exercise every bundled catalog automatically; 1730 tests pass
  total.
- **v0.7.9-deferred-finding closures** (v0.7.10 P3 first batch).
  Closes 4 of the 17 MEDIUM/LOW findings deferred from v0.7.9
  with explicit ship-velocity rationale:
  - **M-1** Whitespace-only token validation across all 4
    vendor-risk SaaS collectors (Vanta + Drata + BitSight +
    SecurityScorecard). Pre-fix `not "  "` is `False` so a
    whitespace-only env var bypassed the auth check, leading to
    silent `Authorization: Bearer    ` headers + opaque 401s on
    first request. Post-fix: `api_token.strip() or None` runs
    pre-check; whitespace tokens raise the typed *AuthError
    immediately with a clear message.
  - **M-2** `int(rating)` → `round(rating)` for BitSight ratings
    + `int(score)` → `round(score)` for SecurityScorecard scores.
    Pre-fix a float rating of 749.6 truncated to 749 and
    silently slipped under the 750 low-rating threshold;
    post-fix it rounds to 750 and triggers the finding.
  - **L-3** `_EXCEL_SHEET_BAD_CHARS` adds tilde (~) for defense
    against legacy Excel-on-Mac workbook-name conflict quirks
    (OOXML doesn't reserve tilde but defensive strip is cheaper
    than debugging an auditor's "Excel doesn't open this" report).
  - **L-7** Re-export `BLIND_SPOTS` + `COLLECTOR_ID` at the
    package level for all 4 vendor-risk SaaS collectors. Callers
    can now do `from evidentia_collectors.vanta import
    BLIND_SPOTS` instead of reaching into the module path.
  9 new tests (token-validation rejection × 4 collectors +
  re-export verification × 4 + BitSight rating-rounding edge
  case).
- **Codecov + statement-coverage80 closure** (v0.7.10 P2). Closes
  the **last remaining OpenSSF Best Practices Silver-tier MUST**
  (`test_statement_coverage80`) — Evidentia now publishes
  statement coverage to Codecov, an independent
  test-coverage service. Initial measurement: **81.87% statement
  coverage** across the in-scope Python source tree (1714 tests
  passing). Workflow: `tests` job on `ubuntu-latest` runs `pytest
  --cov --cov-report=xml` and uploads to Codecov via SHA-pinned
  `codecov/codecov-action@v6.0.0`. `codecov.yml` locks the
  project gate at 80% with a 1% PR-coverage-drop threshold.
  Coverage scope (`[tool.coverage.run]` in pyproject.toml) omits
  display-layer CLI wrappers (`evidentia/cli/{gap,risk,oscal,
  explain,integrations,init,collect}.py`) under the
  library-tested-elsewhere principle, plus environmental-
  dependency modules (`evidentia_api/cli.py`,
  `evidentia_core/oscal/{signing,sigstore}.py` — the latter two
  require Sigstore keyless OIDC env not available in pytest CI).
  CLI verbs introduced fresh in v0.7.9 P0.1 (TPRM) + v0.7.10 P0.6
  (model-risk) + v0.7.10 P1.5 (governance) are kept under coverage
  with their own integration test suites. README badge live.
  `docs/openssf-best-practices-badge.md` updated to reflect Silver
  as ready-to-file.
- **`docs/financial-sector-overlay.md` narrative composition**
  (v0.7.10 P4). Ties the v0.7.9 TPRM + v0.7.10 Model Risk +
  v0.7.10 Governance modules into one coherent financial-services
  regulatory overlay story. Maps the regulatory stack (OCC + FRB
  + FDIC + NCUA + FFIEC + Shared Assessments + IIA Three Lines
  Model + SR 11-7 + SR 26-02) to Evidentia's capability surface,
  walks an end-to-end 8-step example showing vendor + model +
  3LOD + effective-challenge + AI-linkage + OSCAL emit composition
  for a regional bank ML-driven credit-scoring deployment, and
  positions Evidentia as the SR-replacement-grade audit-evidence
  framework for the SR 26-02 / OCC 2026-13a GenAI-exclusion
  regulator-vacuum gap.
- **`docs/model-risk.md` comprehensive walkthrough** (v0.7.10
  P4). Full module-walk: regulatory rationale (SR 11-7 / SR 26-02
  / OCC 2011-12 / OCC 2026-13a + the GenAI-exclusion vacuum),
  module surface (CLI + REST + governance siblings), data model
  (ModelInventory + sub-models + vendor-or-internal contract +
  auto-cadence), quick-start sequence (add/list/doc/validation
  report), AI-feature linkage usage example, Three Lines of
  Defense workflow, Effective Challenge log workflow, OSS
  license + data sovereignty notes, cross-references.
- **`evidentia governance challenge` — Effective Challenge log**
  (v0.7.10 P1.5 G2). New `EffectiveChallenge` Pydantic schema +
  `ChallengeOutcome` enum (accepted/rejected/modify/pending) +
  `evidentia_core.effective_challenge_store` JSON-file persistence
  module mirroring the v0.7.10 P0.6.1 model_risk_store pattern.
  Fields capture the SR 11-7 §III.D + SR 26-02 effective-challenge
  documentation requirements: subject_model_id (cross-link to
  ModelInventory.id), challenger_email + challenger_role
  (substantiates independence), challenge_date, challenge_topic,
  challenge_substance, optional response, outcome + rationale,
  optional resolved_at. CLI: `evidentia governance challenge add`
  (atomic per-field flags), `... list` (filter by
  `--subject-model-id` / `--outcome` + `--json` bare-array mode),
  `... show <id>` (formatted text + `--json` mode). Records
  sorted newest-first by `challenge_date`. Atomic
  `os.replace(tmp, out_path)` save semantics. `EVIDENTIA_CHALLENGE_STORE_DIR`
  env-var override. UUID-shape ID validation rejects path-
  traversal. 28 new tests covering enum coverage / schema
  construction (minimal + with-outcome) / extra-fields rejection
  / store-dir resolution precedence / save+load round-trip /
  atomic-tmp cleanup / updated_at refresh / unknown-id None /
  invalid-id-shape raise / list sort order / delete True/False/
  invalid + 9 CLI verb tests.
- **`evidentia governance lines-report` — Three Lines of Defense
  capability** (v0.7.10 P1.5 G1). New foundation module
  `evidentia_core.governance` ships `LineOfDefense` enum
  (first/second/third per IIA Three Lines Model 2020 revision),
  `Owner` Pydantic model (email + line_of_defense + optional
  team/title), and `generate_lines_report()` deterministic
  Markdown report generator. CLI: `evidentia governance
  lines-report --classifications <yaml> [--output <path>]
  [--force]` reads a YAML overlay listing classified owners and
  produces a 4-section report — executive summary with
  per-line counts/percentages, **3LOD crossover warning callout**
  (any email classified across multiple lines is flagged as a
  regulator-noted anti-pattern; FFIEC + OCC + FRB expect strict
  separation between 1st-line execution / 2nd-line oversight /
  3rd-line audit assurance), per-line owner listing with
  team+title metadata, and per-team breakdown showing which lines
  each team participates in. Empty-input case renders a minimal
  valid report. 23 new tests covering enum coverage / Owner
  validation contract / report distribution math / crossover
  detection / per-line empty-state handling / team breakdown
  / determinism / CLI YAML loading + invalid-yaml + invalid-line
  + scalar-rejection + empty-file + crossover-in-CLI.
- **`evidentia model-risk doc generate` + `validation-report
  generate`** (v0.7.10 P0.6.2 + P0.6.3). New CLI verbs +
  REST endpoints (`GET /api/model-risk/models/{id}/documentation`
  + `GET /api/model-risk/models/{id}/validation-report`) producing
  SR 11-7 / SR 26-02 / OCC Bulletin 2011-12 / OCC Bulletin
  2026-13a-aligned model documentation + validation cycle reports
  from a `ModelInventory` record. Output is plain Markdown —
  diff-able, version-controllable, and consumable by every common
  auditor toolchain (Word via pandoc, PDF via pandoc, HTML, plain
  text). Both generators are deterministic — same input produces
  the same output character-for-character. Doc generator covers 9
  numbered sections (identification, purpose, methodology, inputs,
  outputs, assumptions/limitations, validation history, monitoring/
  retirement, audit trail) per SR 11-7 §III.B framework. Validation
  report includes executive summary with HIGH-open warning callout,
  finding-disposition counts (severity × status × total), detailed
  findings table, per-finding remediation narrative, and tier-driven
  cadence context. CLI surfaces `--output <path>` + `--force` flags
  with stdout default; REST endpoints return `Content-Type:
  text/plain; charset=utf-8` so the Markdown body lands raw. New
  `evidentia_core.model_risk` public module: `generate_model_
  documentation` + `generate_validation_report`. 22 new tests
  (11 unit + 4 CLI + 4 REST + 3 disposition/warning logic).
- **`RiskStatement.model_inventory_ref` AI-feature linkage**
  (v0.7.10 P0.6.4). New optional UUID field on
  `evidentia_core.models.risk.RiskStatement` pointing to a
  `evidentia_core.models.model_risk.ModelInventory.id`. Wired
  through the AI generator: `RiskStatementGenerator` accepts a
  new `model_inventory_id: str | None = None` constructor
  parameter; when set, `_enrich()` propagates the linkage onto
  every produced RiskStatement. Closes the SR 11-7 / SR 26-02 /
  OCC Bulletin 2011-12 / OCC Bulletin 2026-13a audit-traceability
  loop — federally-regulated model-risk-management programs can
  now trace back from a generated risk statement to the model
  inventory entry that documents its tier classification,
  validation history, and approval chain. Backward-compatible
  (default None preserves all pre-v0.7.10 behaviour). 6 new tests
  covering field optionality, JSON round-trip, backward-compat
  deserialization, and generator-path propagation.
- **`/api/model-risk/models` REST CRUD** (v0.7.10 P0.6 third
  slice). 6 endpoints mirroring the v0.7.9 P0.1.4 TPRM router
  pattern: `GET /api/model-risk/models` (list with skip/limit
  pagination + tier/methodology/vendor_or_internal filters),
  `POST /api/model-risk/models` (create; server fills id /
  created_at / updated_at / evidentia_version),
  `GET /api/model-risk/models/{id}` (single fetch),
  `PUT /api/model-risk/models/{id}` (full-replace; preserves
  id + created_at; auto-recomputes next_validation_due if
  anchor changed and operator did not override),
  `DELETE /api/model-risk/models/{id}` (204 no-body),
  `GET /api/model-risk/models/{id}/next-validation-due` (cadence
  preview without persisting). Error normalization follows the
  v0.7.8 F-V08-DAST-3 fix (manual HTTPException uses 400 / 404
  with `{detail: string}` shape; Pydantic 422s preserve
  array-shape detail). Path-traversal-shape IDs normalize to 404
  to match the not-found case. 24 TestClient integration tests.

## [0.7.9] - 2026-05-04

**The financial-services TPRM ship.** Brings Evidentia into the
regulated third-party-risk-management compliance domain via the
new `evidentia tprm` top-level capability module — vendor inventory
CRUD, due-diligence questionnaire generation + ingestion (5
formats incl. SIG BYO + caiq-full), concentration-risk reporting
across 6 dimensions, OSCAL TPRM emit, and 4 vendor-risk SaaS
collectors (Vanta + Drata + BitSight + SecurityScorecard). Plus
the v0.7.8 Step 5.A carry-over batch (4 MEDIUM findings closed),
defense-in-depth security headers middleware (closes v0.7.8
F-V08-DAST-2 LOW), and PR #18 actions-bump workflow fix.

Per the v0.7.9 plan §19 final-scope-narrowing decision, the
TPRM module ships **complete** (P0.1 → P0.5 finished); v0.7.10
will be the "Federal compliance + Model Risk" follow-on (P0.6
Model Risk overlay + P1 7 new bundled catalogs + P1.5 G1+G2
Three Lines of Defense + Effective Challenge governance
primitives), and v0.7.11 the "Audit chain-of-custody" follow-on
(P2 retention metadata + WORM backends + P1.5 G3+G4+G5 KRI/KPI/
KGI + Open FAIR + process-as-code).

### Fixed

- **v0.7.8 Step 5.A carry-over batch** — 4 MEDIUM findings closed +
  PR #18 actions-bump fix. Per the original v0.7.9 plan §"Carry-
  over from v0.7.8 Step 5.A".
  - **F-V08-CR-MEDIUM Snowflake count separation**: split the
    `_policy_inventory_findings` sub-check's coverage tracking
    into TWO `CoverageCount` entries (one per evidence source —
    `snowflake-masking-policy` + `snowflake-row-access-policy`)
    rather than mixing the two source counts under a single
    `snowflake-policy` bucket. Manifest reflects distinct coverage
    per evidence source. Orchestration loop normalizes both
    single-CoverageCount and list-of-CoverageCount returns from
    sub-checks.
  - **F-V08-CR-MEDIUM Snowflake quoted-identifier hardening**: new
    `_quote_snowflake_identifier()` static helper that escapes
    literal `"` per Snowflake's documented convention (double-up
    the quote — `my"db` → `"my""db"`). Replaces the unescaped
    f-string `f'"{db}".INFORMATION_SCHEMA.MASKING_POLICIES'`
    constructs in both masking + row-access query paths. Defensive
    hardening — Snowflake's published convention disallows `"` in
    identifiers, but operator-controlled inputs in third-party-
    managed accounts make the escape worth the one-line cost.
    4 new unit tests covering simple / single-quote / multi-quote
    / alphanumeric-passthrough cases.
  - **F-V08-CR-MEDIUM Databricks PermissionDenied typed catch**:
    replaced the `if "permission" in str(e).lower()` message-string
    heuristic in `_pat_inventory_findings` with a typed catch on
    `databricks.sdk.errors.PermissionDenied` +
    `databricks.sdk.errors.Unauthenticated`. Falls back to the
    message-string heuristic only when the typed-error module is
    unavailable (older databricks-sdk < 0.20). Stable across SDK
    upgrades; no longer mis-classifies localized error messages.
  - **F-V08-CR-MEDIUM Power BI 1MB byte-cap guard**: `push_rows()`
    now bisects batches whose serialized JSON exceeds Power BI's
    documented 1 MB request-body limit (using a 950 KB headroom
    threshold for the JSON envelope + multibyte expansion). Wide-
    schema customers (50+ string columns × 10K rows ≈ 2 MB)
    previously hit the byte cap with a 4xx; now they get split
    into sub-batches that each fit. Single-row exceedance raises a
    clear `PowerBIPublishError` so the operator can investigate.
    4 new unit tests covering small-batch single-post / wide-batch
    bisection / oversized-row error / empty-rows short-circuit.
  - **PR #18 Meridian gap diff workflow fix**: the actions/cache
    bump from v4.3.0 to v5.0.5 (along with checkout + setup-
    buildx + build-push + github-script bumps) tightened cache-
    key scoping; PR runs can no longer always restore the main-
    branch cache. The `Seed baseline on cache miss` step was
    previously gated on `github.event_name == 'push'`, so PR
    runs after a cache-key bump (or when the cache is otherwise
    missing) failed at the diff step with `File '/tmp/base.json'
    does not exist`. Dropped the event-name gate; the seed now
    fires on ANY cache miss, producing a clean no-regression diff
    for the first PR after a key bump (and recording the seeded
    baseline into the cache on push events).
- **v0.7.9 P0.4 Continuous-review HIGH findings** (5 inline-fixes
  + 2 added tests). Surfaced by the first /pre-release-review
  Continuous-variant pass on the v0.7.9 cycle, mid-flight after
  the P0.4 quartet + P0.5 OSCAL TPRM emit + P0.2 second slice
  landed.
  - **H-1 stuck-cursor guard** in Vanta + Drata `_paginate`. If the
    upstream API returns `hasNextPage: true` with the same
    `endCursor`/`nextPageToken` twice consecutively, the loop now
    breaks instead of running to the `max_vendors=2000` hard cap.
  - **H-2 explicit-key payload-priority** in Drata + SecurityScorecard
    pagination. The previous `data.get("data") or data.get("results")
    or []` chain mis-handled a legitimate `{"data": []}` empty-page
    response by falling through to other keys (because `[]` is
    falsy). Switched to explicit `if "data" in data and isinstance(
    data["data"], list)` precedence so an empty page is treated
    as a real response.
  - **H-3 monotonic-increase guard** in SecurityScorecard
    `_paginate_portfolio`. When the API reports more pages but our
    running output didn't grow this iteration, the loop stops
    instead of relying solely on the hard cap.
  - **H-5 column-write order** in `generate_from_byo_template` for
    SIG / SIG-Lite. Real-world Shared Assessments templates often
    put instruction text in column B and intend column C as the
    vendor response cell. The function now prefers column C when
    present + empty, falling back to column B only when C is
    absent or already populated.
  - **F-V09-S1 BitSight scheme guard (CWE-319)**. The cross-host
    pagination guard previously checked `parsed.netloc` but not
    `parsed.scheme`. A malicious upstream `next` URL of
    `http://api.bitsighttech.com/...` (HTTPS→HTTP downgrade) would
    have caused httpx to send the configured `Authorization: Basic
    <base64(token:)>` header over cleartext HTTP. The guard now
    refuses scheme downgrades alongside cross-host URLs.
  - **H-4 test gap closures**: new tests for (a)
    `parse_completed_questionnaire` JSON path with `vendor_id=None`
    in the prefill block (CLI surfaces a clear correlation error),
    (b) SIG BYO partial-label-match case (function silently skips
    non-matching rows instead of failing the whole operation).

### Changed

- **Dockerfile python base 3.12-slim → 3.14-slim** (PR #14, commit
  `5ff87ff`; Dependabot docker-group bump). Container-build CI
  validates new base post-bump.

### Docs

- **GOVERNANCE.md**, **CONTRIBUTING.md** coding-standards paragraph
  + stale-string fix, **SECURITY.md** Supported Versions table
  refresh (v0.7.2→v0.7.8), and **docs/openssf-best-practices-badge.md**
  — OpenSSF Silver-tier preparatory work (commit `6f862eb`).
- **README.md** OpenSSF Best Practices badge embed for project 12724
  (commit `77382f3`).
- **docs/v0.7.9-plan.md** carry-over section: rolled v0.7.8
  Step 5.A 11 deferred findings into v0.7.9 scope; dropped the
  now-shipped container-build trap note (commit `9b92e1e`).

### CI

- **container-build PyPI-propagation race fix**: added a Wait-for-
  PyPI step that polls the registry for the just-published wheel
  before kicking off the container build smoke test, plus dropped
  the fragile head-commit skip guard. Closes the v0.7.5-era trap
  that re-fired during v0.7.8 ship (commit `cd03675`).

### Added

- **TPRM DD-questionnaire P0.2 second slice** (v0.7.9 — completes
  the questionnaire round-trip workflow).
  - **XLSX output format**. New `--output-format xlsx` flag on
    `evidentia tprm dd-questionnaire generate` produces a multi-
    sheet Excel workbook (Sheet 1 = vendor metadata; one sheet per
    question domain). Gated behind a new optional `[xlsx]` extra:
    `pip install 'evidentia-core[xlsx]'` (openpyxl ~3 MB pure-
    Python). The collector raises a clear actionable
    `XlsxNotInstalledError` if openpyxl is missing.
  - **Ingest CLI + parser**. New `evidentia tprm dd-questionnaire
    ingest --questionnaire <path> [--vendor-id <id>]` command +
    `parse_completed_questionnaire()` engine function. Auto-
    detects format from the file extension (.json / .csv / .xlsx)
    + correlates back to a vendor inventory record via the
    questionnaire's embedded vendor_id (or explicit `--vendor-id`
    override). Returns a `CompletedQuestionnaire` carrying the
    per-question response map keyed by question.id; CLI prints
    table or JSON. Persistence to `Vendor.evidence_refs[]`
    deferred to a follow-up release once the audit-chain-of-
    custody Sigstore-signing wiring lands.
  - **SIG / SIG-Lite BYO XLSX template**. New `--from-template
    <path>` flag on `evidentia tprm dd-questionnaire generate`
    accepts an operator-supplied Shared Assessments licensed SIG
    XLSX. Evidentia opens the workbook, locates the standard
    "Vendor Information" / "Company Information" sheet via
    fuzzy name matching, and pre-fills vendor metadata into the
    documented label cells (Company Name / Vendor Type /
    Criticality Tier / Primary Contact / Contract Start Date /
    Region etc.). The SIG question content stays UNTOUCHED —
    Shared Assessments' license terms forbid redistribution, so
    Evidentia only writes to vendor-metadata cells. Returns
    pre-filled XLSX bytes; clear error messages when the
    workbook layout can't be recognized or no metadata rows
    matched.
  - **CAIQ-Full questionnaire**. New `caiq-full` format value
    with ~50 representative questions across all 17 CSA control
    domains (vs caiq-lite's ~25). Same CC BY 4.0 attribution
    string. Operators wanting the authoritative full 245-
    question CAIQ should download from CSA + use the BYO
    `--from-template` path once that surface lands for SIG-style
    XLSX templates.
  - **All four deliverables ship together** as one cohesive
    P0.2 second slice. New `evidentia-core[xlsx]` optional dep
    pulls `openpyxl>=3.1`. 15 new unit tests in
    `tests/unit/test_tprm_questionnaire.py` covering XLSX
    render + multi-sheet structure, JSON / CSV / XLSX ingest
    round-trip, SIG BYO pre-fill happy path, BYO error paths
    (non-BYO format / missing template / unrecognizable layout),
    + caiq-full domain coverage + CSA attribution.
- **OSCAL TPRM vendor-inventory emit** (v0.7.9 P0.5). Extends
  `evidentia_core.oscal.exporter.gap_report_to_oscal_ar` (and
  the `evidentia_core.gap_analyzer.export_report` driver) with
  a new optional `vendor_inventory: list[Vendor] | None`
  parameter. When supplied, each TPRM vendor lands in TWO
  surfaces of the OSCAL Assessment Results document:
  (1) `metadata.parties[]` as a `type=organization` party
  (standard OSCAL discovery surface — trestle-conformant tools
  can navigate vendors via the OSCAL party model) carrying
  Evidentia-namespaced props for criticality_tier /
  regulatory_classification / contract_start_date /
  contract_end_date / next_review_due / region /
  residual_risk_score / fourth_party_count / vendor_type;
  (2) `back-matter.resources[]` as a tamper-evident vendor
  record with canonical-JSON `base64.value` + SHA-256
  `rlinks[].hashes[]` (same integrity model as the v0.7.0
  finding-resource embedding — vendor-record tampering is
  detected by the existing
  `evidentia_core.oscal.verify.verify_ar_file` chain). The
  vendor's party UUID and back-matter resource UUID both equal
  `Vendor.id` so cross-references resolve. New `--vendor-inventory
  <path>` CLI flag on `evidentia gap analyze --format oscal-ar`
  accepting a JSON-array file (as produced by `evidentia tprm
  vendor list --json`). Top-level `metadata.props` gains an
  Evidentia-namespaced `vendor-inventory-count` property for
  quick auditor discovery. Closes the v0.7.9 P0 TPRM module
  loop: vendors flow from inventory → DD-questionnaire →
  concentration-report → vendor-risk-collector findings →
  OSCAL AR artifact, all in a single Sigstore-signable
  evidence bundle. Audit trail satisfies OCC Bulletin 2013-29
  + FRB SR 13-19 + FFIEC IT Examination Handbook Outsourcing
  booklet inventory expectations. 9 new unit tests covering
  parties+back-matter dual-encoding, UUID consistency, prop
  population, integrity-hash determinism, canonical-JSON
  round-trip, vendor-count metadata, no-vendor-no-noise, and
  vendor+finding coexistence.
- **SecurityScorecard portfolio collector** (v0.7.9 P0.4 fourth
  slice — completes the v0.7.9 P0.4 vendor-risk-collector quartet).
  New `evidentia collect securityscorecard [--portfolio-id <id>]`
  CLI command + `POST /api/collectors/securityscorecard/collect`
  REST endpoint. Read-only adapter pulling SSC portfolio companies
  via the SecurityScorecard API
  (`/portfolios/{portfolio_id}/companies`), surfacing each
  portfolio company as an INFORMATIONAL `company-inventory`
  SecurityFinding (NIST 800-53 SR-2 / SR-3 / SR-6 + OCC Bulletin
  2013-29 §III.A + FRB SR 13-19 §II + FFIEC IT Examination Handbook
  Outsourcing booklet §II) plus an additional MEDIUM-severity
  `company-low-score` finding when the score falls below the
  operator-configured threshold (default 70, the C/D grade
  boundary; range 0-100). Low-score mappings: RA-3 + CA-7 + OCC
  §III.A.4 + SR 13-19 §II.D. Portfolio resolution: explicit
  `--portfolio-id` flag OR auto-resolution by listing portfolios
  + picking the first available. Auth: `SECURITYSCORECARD_API_TOKEN`
  env var passed as `Authorization: Token <value>` (distinct from
  BitSight's HTTP Basic and Vanta/Drata's Bearer). Page+per_page
  pagination via response's `page_count` field. 13 unit tests with
  mocked httpx covering happy path, portfolio auto-resolution,
  configurable score threshold, unscored companies, page-based
  pagination, max-companies ceiling, 401 → SSCAuthError, empty
  portfolio handling, network failure → manifest-level error
  capture. First-slice scope is portfolio inventory + summary
  score; subsequent slices add per-company factor scores
  (Application Security, DNS Health, Endpoint Security, Hacker
  Chatter, IP Reputation, Network Security, Patching Cadence,
  Social Engineering) + historical grade trends.
- **BitSight portfolio collector** (v0.7.9 P0.4 third slice).
  New `evidentia collect bitsight` CLI command + `POST
  /api/collectors/bitsight/collect` REST endpoint. Read-only adapter
  pulling the operator's BitSight Security Ratings portfolio via
  the BitSight API (`/portfolio`), surfacing each portfolio company
  as an INFORMATIONAL `company-inventory` SecurityFinding (NIST
  800-53 SR-2 / SR-3 / SR-6 + OCC Bulletin 2013-29 §III.A + FRB
  SR 13-19 §II + FFIEC IT Examination Handbook Outsourcing booklet
  §II) plus an additional MEDIUM-severity `company-low-rating`
  finding when the company's BitSight rating falls below the
  operator-configured threshold (default 700, BitSight's "Basic"
  boundary; range 250-900). Low-rating mappings: RA-3 + CA-7 +
  OCC §III.A.4 + SR 13-19 §II.D. Auth: `BITSIGHT_API_TOKEN` env
  var; the collector wraps the token in HTTP Basic auth
  (token:empty-password) internally — the token never appears in
  URLs. Defensive cross-host pagination guard: refuses to follow
  `next` URLs pointing off-host. 13 unit tests with mocked httpx
  covering happy path, low-rating threshold emission (configurable),
  unrated companies, pagination via absolute `next` URLs, cross-host
  refusal, max-companies ceiling, 401/403 → BitSightAuthError,
  network failure. First-slice scope is portfolio inventory + summary
  rating; subsequent slices add per-factor scores + historical
  rating trends.
- **Drata vendor-inventory collector** (v0.7.9 P0.4 second slice).
  New `evidentia collect drata` CLI command + `POST
  /api/collectors/drata/collect` REST endpoint. Read-only adapter
  pulling the operator's Drata-managed vendor inventory via the
  Drata Public API (`/public/v1/vendors`), surfacing each vendor
  as a `vendor-inventory` SecurityFinding (NIST 800-53 SR-2 /
  SR-3 / SR-6 + OCC Bulletin 2013-29 §III.A + FRB SR 13-19 §II +
  FFIEC IT Handbook Outsourcing booklet §II) plus an additional
  `vendor-high-risk` finding whenever the underlying record carries
  a HIGH or CRITICAL risk-level flag (RA-3 + OCC §III.A.4 + SR
  13-19 §II.D). Auth: `DRATA_API_TOKEN` env var (Drata Personal
  API token), read-only vendor scope; the token NEVER flows
  through CLI args or request bodies. Uses Drata's documented
  `nextPageToken` cursor-based pagination with a 2000-vendor
  default ceiling (overridable via `--max-vendors`). Defensive
  high-risk detection across six field-shape variants:
  `riskLevel`, `risk_level`, `riskTier`, `risk_tier`, nested
  `riskAssessment.{level,tier,severity}`, plus numeric
  `inherentRisk`/`residualRisk` on Drata's documented 1-5 / 1-25
  scales. 13 unit tests with mocked httpx covering happy path,
  pagination, max-vendors ceiling, six high-risk field-shape
  variants, 401/403 → DrataAuthError, network failure → manifest-
  level error capture. First-slice scope is vendor inventory only;
  subsequent slices add control-test pulls + ongoing-monitoring
  posture per the v0.7.9 P0.4 plan.
- **Vanta vendor-inventory collector** (v0.7.9 P0.4 first slice).
  New `evidentia collect vanta` CLI command + `POST
  /api/collectors/vanta/collect` REST endpoint. Read-only
  adapter pulling the operator's Vanta-managed vendor inventory
  via the Vanta Public API (`/v1/vendors`), surfacing each
  vendor as a `vanta-vendor-inventory` SecurityFinding (NIST
  800-53 SR-2 / SR-3 / SR-6 + OCC Bulletin 2013-29 §III.A +
  FRB SR 13-19 §II + FFIEC IT Handbook Outsourcing booklet
  §II) plus an additional `vanta-vendor-high-risk` finding
  whenever the underlying record carries a HIGH or CRITICAL
  risk-tier flag (RA-3 + OCC §III.A.4 + SR 13-19 §II.D).
  Auth: VANTA_API_TOKEN env var (Personal Access Token or
  OAuth 2.0 client-credentials access token), scoped to
  `vendors:read`; the token NEVER flows through CLI args or
  request bodies. Lazy-import design: imports cleanly even
  when the optional `httpx` extra resolves at runtime; uses
  cursor-based pagination with a 2000-vendor default ceiling
  (overridable via `--max-vendors`). 13 unit tests with
  mocked httpx covering happy path, pagination, max-vendors
  ceiling, four high-risk field-shape variants (riskTier,
  risk_tier, riskLevel/risk_level, nested riskAssessment),
  401/403 → VantaAuthError, network failure → manifest-level
  error, empty inventory → empty findings. First slice scope
  is vendor inventory only; subsequent slices will add
  control-test pulls + ongoing-monitoring posture per the
  v0.7.9 P0.4 plan.
- **TPRM due-diligence questionnaire generator** (v0.7.9 P0.2).
  New `evidentia tprm dd-questionnaire generate --vendor-id <id>
  --format ... --output-format json|csv --output <path>` CLI +
  `POST /api/tprm/vendors/{id}/dd-questionnaire?format=...` REST
  endpoint. Pre-fills vendor metadata (name / type / criticality
  tier / contract dates / region / regulatory classification /
  4th-party disclosures) so the receiving vendor sees only
  control questions, not blank metadata templates. Two formats
  ship with packaged content: **`evidentia-generic`** (Apache-2.0
  Evidentia-original ~20-question baseline across FFIEC vendor-
  management domains: governance, access control, data handling,
  incident response, business continuity, 4th-party risk,
  personnel, insurance, compliance) and **`caiq-lite`**
  (representative ~25-question subset of the CSA Consensus
  Assessments Initiative Questionnaire v4.0.3, CC BY 4.0 with
  required attribution; covers all 17 CAIQ control domains).
  **`sig` / `sig-lite` are stubs** — Shared Assessments paywalls
  the question content; future versions will support
  `--from-template <licensed-xlsx>` BYO ingestion. Output
  formats: **JSON** (full Pydantic model dump) + **CSV** (flat;
  vendor-prefill header section + question rows + blank
  vendor_response column). XLSX deferred (would require
  openpyxl extra; CSV covers spreadsheet-pivot use case). Engine
  + types live in the new module
  `evidentia_core.tprm.questionnaire`. 24 unit tests + 7 CLI
  integration + 6 REST integration. The vendor `ingest`
  command (responses flow back into Evidentia for tracking) is
  deferred to a follow-up sub-slice.

- **TPRM concentration-risk reporting** (v0.7.9 P0.3). New
  `evidentia tprm concentration-report` CLI + `GET /api/tprm/
  concentration` REST endpoint aggregate the v0.7.9 P0.1 vendor
  inventory across configurable dimensions to surface
  concentration risk per FFIEC + OCC Bulletin 2013-29 + FRB SR
  13-19 expectations. Six supported dimensions: `region`,
  `cloud-provider` (combines direct cloud-provider vendors AND
  4th-party cloud-provider disclosures), `4th-party`,
  `service-category`, `criticality-tier`,
  `regulatory-classification`. Optional `--threshold <pct>` flag
  flags any per-value share meeting-or-exceeding the threshold
  (e.g., 30% to surface "9 of 12 vendors run on AWS"). Three
  output formats: HTML (single-file with sortable tables; no
  external deps), JSON (REST + scripted), CSV (spreadsheet
  pivot). Adds `region` field to the `Vendor` model
  (free-text geo / cloud-region label; nullable for legacy
  imports). Engine + types live in
  `evidentia_core.tprm.concentration` (new sub-namespace
  `evidentia_core.tprm` per the v0.7.9-plan). 20 unit tests +
  6 CLI integration + 6 REST integration.

- **Defense-in-depth security headers** on the FastAPI server via
  the new `SecurityHeadersMiddleware`
  (`evidentia_api.security_headers`). When enabled, every response
  carries `Content-Security-Policy` (locks resource loads to same-
  origin; `frame-ancestors 'none'`), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: strict-origin-when-cross-origin`,
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`,
  and `Permissions-Policy` denying camera / microphone /
  geolocation / payment / USB / FLoC. New `--security-headers /
  --no-security-headers` flag on `evidentia serve`; default is
  auto — ON when binding to non-loopback (operator opted into
  network exposure), OFF when binding to `127.0.0.1` /
  `localhost` / `::1` (dev-loop parity). Operators behind a
  TLS-terminating reverse proxy that already injects these
  headers can pass `--no-security-headers` to suppress
  duplicates. Closes v0.7.8 Step 5.A deferred F-V08-DAST-2 LOW
  finding (CWE-693 Protection Mechanism Failure).

Foundation for the v0.7.9 industry-overlay release. The first
slice of `evidentia tprm` lands the data + storage + CLI + REST
primitives that subsequent v0.7.9 sub-slices (DD-questionnaire
generator, concentration-risk reporting, vendor-risk collectors,
OSCAL TPRM emit) build on:

- **TPRM Pydantic models** (`evidentia_core.models.tprm`):
  `Vendor`, `FourthParty`, `EvidenceRef` plus three supporting
  enums — `VendorType` (saas / subservice_org / contractor /
  data_processor / cloud_provider / open_source), `CriticalityTier`
  (critical / high / medium / low), and `RegulatoryClassification`
  (custody / clearing / model / data_processor /
  critical_third_party). Aligned to FFIEC Vendor Management +
  NIST 800-161 SCRM categories + OCC Bulletin 2013-29 / FRB SR
  13-19. The `model` regulatory flag cross-links to the v0.7.9
  P0.6 Model Risk Management module under the active SR 26-02 +
  OCC Bulletin 2026-13a guidance.
- **`Vendor.compute_next_review_due`** — pure-function helper
  that maps criticality tier → DD-review cadence (critical/high
  → annual; medium → biennial; low → triennial) with
  calendar-aware month arithmetic (year roll + last-day clamp
  for Feb 29 leap → Feb 28 non-leap on annual roll).
- **`vendor_store` JSON-file persistence** — one file per
  vendor named `<vendor_id>.json` under a platformdirs-backed
  user-dir directory. `EVIDENTIA_VENDOR_STORE_DIR` env var
  override. CRUD surface: `save_vendor`, `load_vendor_by_id`,
  `list_vendors` (sorted by criticality → name),
  `delete_vendor`. ID-shape validation rejects non-UUID inputs
  (path-traversal segments, empty strings, etc.) with
  `InvalidVendorIdError`; resolved file path passes through
  `validate_within` for belt-and-suspenders boundary
  enforcement.
- **`evidentia tprm vendor add/list/show/edit/delete` CLI**
  with hybrid input UX: atomic-field flags for the common case
  (`--name`, `--type`, `--criticality-tier`, etc.) +
  `--from-yaml <path>` for complex adds with nested fields
  (4th-parties, evidence-refs). `edit` also supports
  `--editor` to open the current YAML in `$EDITOR`. `delete`
  prompts by default with `--yes` to bypass. Output: rich
  table by default, `--json` for machine-readable.
- **REST router** at `/api/tprm/vendors`: `GET` (with
  skip/limit pagination + criticality_tier/type filters),
  `POST` (201 on create), `GET/PUT/DELETE /{vendor_id}`, plus
  a `GET /{vendor_id}/next-review-due` cadence-preview helper.
  Error normalization preserves the v0.7.8 F-V08-DAST-3 fix
  (manual `HTTPException` uses 400, not 422, for runtime
  body-content errors so the `{detail: string}` response shape
  matches OpenAPI declaration).

48 new unit + integration tests (1305 → 1353); mypy strict
clean across 142 source files; ruff clean.

The full v0.7.9 plan (TPRM module + Model Risk Management
overlay + 7 new bundled catalogs + risk-governance primitives
+ audit chain-of-custody + WORM backends) lives in
`docs/v0.7.9-plan.md`. Estimated ship: 8.5–10.5 weeks after
v0.7.8 ship date.

## [0.7.8] - 2026-05-03

**The cloud data-warehouse + BI integrations release.** Brings
two long-anticipated capability areas into Evidentia: read-only
evidence collection from cloud data warehouses (Databricks +
Snowflake) and the first **output integrations to enterprise BI
platforms** (Tableau + Power BI). Positions Evidentia as the OSS
evidence feed beneath enterprise risk-officer + audit-committee
dashboards.

### Added

- **Databricks evidence collector**
  (`evidentia-collectors[databricks]`). Read-only adapter
  surfacing Personal Access Token inventory + lifecycle
  (long-lived, never-expires findings), cluster compliance
  (runtime version, libraries, init scripts), service-principal
  inventory + active/inactive status, and secret-scope inventory
  (Databricks-backed vs Azure Key Vault-backed) — all mapped to
  NIST 800-53 controls AC-2 / AC-2(3) / AC-2(11) / AC-3 / CM-2 /
  CM-3 / CM-8 / IA-5 / IA-5(1) / SC-12 / SI-2. Auth via the
  Databricks SDK's unified-auth resolver (PAT, OAuth M2M, Azure
  AD, AWS IAM, `.databrickscfg`). Ships 7 documented BLIND_SPOTS
  + 27 unit tests with full mock coverage. CLI: `evidentia
  collect databricks --workspace-url ...`. REST: `POST
  /api/collectors/databricks/collect`.
- **Snowflake evidence collector**
  (`evidentia-collectors[snowflake]`). Read-only adapter
  surfacing LOGIN_HISTORY (per-user inventory + per-failed-login
  row over a 90-day window), USERS inventory + MFA enforcement +
  disabled-account + never-logged-in findings, GRANTS_TO_USERS
  inventory + privileged-role grants (ACCOUNTADMIN /
  SECURITYADMIN / ORGADMIN), network-policy inventory + account-
  level baseline check, masking + row-access policy inventory
  per database, and operator-attested key-rotation status — all
  mapped to NIST controls AC-2 / AC-2(3) / AC-3 / AC-3(7) / AC-6
  / AC-6(7) / AC-7 / AU-2 / AU-3 / IA-2(1) / IA-2(2) / IR-4 /
  SC-7 / SC-7(5) / SC-12 / SC-28. Auth via password (env-var
  sourced) or key-pair (preferred for production — Snowflake is
  deprecating password auth). Ships 7 documented BLIND_SPOTS +
  29 unit tests + 4 API smoke tests. CLI: `evidentia collect
  snowflake --account ... --user ... --password-env ...`. REST:
  `POST /api/collectors/snowflake/collect`.
- **Tableau publish integration**
  (`evidentia-integrations[tableau]`). First substantive output
  integration since Jira (v0.5.0). Publishes gap inventory + risk
  register + collection-run audit trail to a Tableau Server /
  Tableau Cloud site as **CSV-based data sources** ready for
  refreshable risk-officer dashboards. Three datasets:
  `evidentia-gaps` (22 columns mirroring ControlGap), `evidentia-
  risks` (NIST SP 800-30 shape with AI-provenance fields surfaced
  from GenerationContext), `evidentia-collection-runs`
  (CollectionContext audit trail). Auth via Personal Access Token
  read from `TABLEAU_PAT_NAME` + `TABLEAU_PAT_SECRET` env vars
  (the integration NEVER accepts the PAT secret as a CLI flag or
  in a request body — only the env-var names). Ships 22 unit
  tests + 3 API smoke tests. CLI: `evidentia integrations tableau
  publish --gaps report.json --server-url ...`. REST: `POST
  /api/integrations/tableau/publish/{report_key}`.
- **Power BI publish integration**
  (`evidentia-integrations[powerbi]`). Pushes the same three
  datasets to a Power BI workspace as **Push Datasets** via the
  Power BI REST API + Azure AD service-principal OAuth2 (MSAL
  Python). Full-refresh semantics by default (clear-then-push).
  10,000-row batching per Power BI's documented limit. Schema-
  declared dataset creation auto-detects existing datasets by
  name and reuses IDs (idempotent re-runs). Auth via service
  principal with `Dataset.ReadWrite.All`; client secret read
  from `POWERBI_CLIENT_SECRET` env var server-side; never in
  request bodies. Ships 29 row-builder + schema unit tests + 15
  mocked-MSAL/httpx client tests + 4 API smoke tests. CLI:
  `evidentia integrations powerbi publish --gaps report.json
  --workspace-id ... --tenant-id ... --client-id ...`. REST:
  `POST /api/integrations/powerbi/publish/{report_key}`.
- **`docs/cloud-dw-collectors.md`** — comprehensive walkthrough
  for the Databricks + Snowflake collectors. Install, auth modes,
  required principal privileges (with the recommended hardened
  Snowflake setup SQL), every evidence source mapped to NIST
  controls, CLI/REST examples, programmatic-use snippets,
  BLIND_SPOTS tables, end-to-end pattern, future-work roadmap.
- **`docs/bi-integrations.md`** — comprehensive walkthrough for
  the Tableau + Power BI integrations. Includes the three-dataset
  schema tables, full audit-cycle workflow showing both
  integrations side-by-side, dashboard tips for Tableau and
  Power BI, troubleshooting playbook for common auth errors.
- **`examples/meridian-fintech-v2-with-bi/README.md`** — companion
  end-to-end demo to `examples/meridian-fintech-v2/`. Walks
  through cloud-DW evidence collection → gap analysis → AI risk
  generation → publish to BOTH Tableau AND Power BI →
  refresh-cadence recommendations.

### Changed

- **`evidentia-collectors`**: new `[databricks]` extra (pulls in
  `databricks-sdk>=0.30`) and `[snowflake]` extra (pulls in
  `snowflake-connector-python>=3.10`). Both included in the
  umbrella `[all]` extra alongside the existing AWS / GitHub /
  Okta / SQL family adapters.
- **`evidentia-integrations`**: new `[tableau]` extra
  (`tableauserverclient>=0.30` — pure-Python; no native deps)
  and `[powerbi]` extra (`msal>=1.31`; httpx is already a base
  dep). Both included in the umbrella `[all]` extra alongside
  Jira + ServiceNow.
- **`/api/collectors/status`**: now reports Databricks and
  Snowflake `installed` + auth-configured status flags
  alongside the existing AWS / GitHub / Okta / SQL family
  entries. The status endpoint NEVER returns secret values —
  only `<env_var>_configured: bool` indicators.
- **`evidentia integrations`**: new `tableau` and `powerbi`
  Typer subcommand groups alongside the existing `jira` and
  `servicenow` groups.

### Fixed

Pre-tag review batch fixes (v0.7.8 Step 5.A — see
`docs/security-review-v0.7.8.md` for the canonical 5th deliverable
with CVSS / CWE / EPSS columns):

- **Removed unbacked `[azure]` + `[gcp]` extras** from
  `evidentia-collectors`. These were declared from v0.5.0 onward
  without any implementing collector module — running
  `pip install 'evidentia-collectors[azure]'` would install Azure
  SDKs but no functional collector to import. The package
  description, keywords, and umbrella `[all]` extra are aligned
  with what actually ships. Azure + GCP remain on the forward
  architectural roadmap; the extras will return alongside the
  implementing modules. (F-V08-1)
- **DFAH + DSE arXiv expansions corrected** in
  `docs/v0.8.0-plan.md`: arXiv 2601.15322 is *Determinism-
  Faithfulness Assurance Harness* (not "Decision-Faithfulness
  Assessment"); arXiv 2406.11251 is *Document Screenshot
  Embedding* (not "Document Structure Embeddings"). Both papers
  verified to exist; substantive content unchanged. (F-V08-2)
- **`GET /api/frameworks/{framework_id}/controls/{control_id}`**
  now returns 404 (was 500) when the framework_id is unknown.
  The route handler's exception catch widened to include
  `ValueError` so manifest-resolution failures normalize to a
  client-friendly 404. Regression test added. (F-V08-DAST-1)
- **17 manual `HTTPException(status_code=422, detail="...")`
  sites converted to 400** across gaps + collectors + integrations
  + init_wizard + risks routers. 422 in OpenAPI declares
  `detail: array<ValidationError>` (the FastAPI auto-validation
  shape); manual 422s with `detail: string` violated the schema.
  18 corresponding tests updated. (F-V08-DAST-3)
- **Snowflake LOGIN_HISTORY query gains a defensive `LIMIT`**
  (default 10,000; new `login_history_max_rows` constructor
  argument). On a busy 90-day window the unbounded query could
  return 10K+ rows + emit a SecurityFinding per failed-login,
  bloating reports. (F-V08-CR-H1)
- **Snowflake `_policy_inventory_findings` opens a fresh cursor
  per per-DB query** (was reusing one cursor across SHOW
  DATABASES + every per-DB MASKING_POLICIES + every per-DB
  ROW_ACCESS_POLICIES query — cursor-state poisoning on
  permission-denied was making subsequent per-DB queries
  silently fail on most drivers). (F-V08-CR-H2)
- **Power BI `clear_table` now swallows 4xx + raises only on
  5xx**. First-publish flow on a freshly-created Push Dataset
  could return 404 from the rows-delete endpoint before
  v0.7.8's first publish; the pre-fix path raised
  `PowerBIPublishError` even though the post-condition
  ("no rows in the table") was already satisfied. (F-V08-CR-H3)
- **Databricks coverage construction O(4N) → O(N)** with
  single-pass dict accumulator; renamed misnamed
  `_cached_workspace_id` (held a URL, not an ID) to
  `_cached_workspace_url`; removed dead `active_finding_count`
  computation. (F-V08-CR-MEDIUM batch)

### Notes

- **CSV-only Tableau publish in v0.7.8**. `.hyper` extract
  publish (which would require the heavyweight
  `tableauhyperapi` native binary, ~100 MB) is documented as a
  v0.7.9+ enhancement under a separate `[tableau-hyper]` extra.
- **Push Datasets only for Power BI in v0.7.8**. Power BI
  Premium / Fabric capacity (full Tabular Model storage) is
  documented as a future enhancement; Push Datasets fits the
  compliance-dashboard use case cleanly and works on the
  standard Power BI Pro license (no Premium add-on required).
- **Some Databricks + Snowflake evidence sources DEFERRED to
  v0.7.9+**: Databricks workspace audit logs + table/column
  lineage (need SQL Warehouse plumbing); Databricks workspace
  network policies (need Account API auth path); Snowflake
  ACCESS_HISTORY lineage (large rowcount; pagination + sampling
  design needed); Snowflake failed-login spike-detection
  heuristic (separate from inventory). All deferred items are
  documented in `docs/v0.7.8-plan.md` and surfaced as explicit
  BLIND_SPOTS in each adapter.

**1259 tests passing** + 12 environmental skips (was 1100 at
v0.7.7 ship; +159 new tests covering Databricks + Snowflake +
Tableau + Power BI + new API surfaces + Step 5.A regression tests);
mypy strict clean across 138 source files; ruff lint clean.

### Carry-forward (unchanged from v0.7.7)

PyPI artifacts (6 wheels + 6 sdists), CycloneDX SBOM, PEP 740
attestations, SLSA L3 build provenance, Sigstore keyless signing,
container-image publish to ghcr.io with cosign verification, the
v0.7.7 SQL adapter family + ServiceNow integration, all v0.7.x
features carry forward.

## [0.7.7.1] - 2026-05-02

**Same-day Dockerfile-pin hot-fix for v0.7.7.** The `release.yml`
`publish-container` job ships an image tagged `:v0.7.7` that is
correctly built but installs `evidentia[gui]==0.7.6` inside —
because the Dockerfile pin is a hardcoded literal that
`bump_version.py` did not include in its sweep until this
release. Surfaced by the v0.7.7 pre-release-review Step 7.5
post-tag container smoke test.

Mirrors the v0.7.4 same-day Dockerfile-invocation hot-fix
pattern (different bug; same shape: ship → post-tag verify →
hot-fix → re-tag).

### Fixed

- **Dockerfile pin**: `evidentia[gui]==0.7.6` → `0.7.7.1`. Users
  who pulled `ghcr.io/allenfbyrd/evidentia:v0.7.7` got 0.7.6
  internally — no SQL collectors, no Okta, no ServiceNow, no
  Step 5.A security fixes. The `:v0.7.7.1` and `:latest` tags
  ship the correct binary.
- **`scripts/bump_version.py`** hardened to:
  - support 4-digit hot-fix versions (`X.Y.Z.W`) per the v0.7.4 +
    v0.7.7.1 precedent
  - sweep `Dockerfile` (in addition to `*.toml` + `*.json`) for
    the `evidentia[gui]==X.Y.Z` pin literal
  - use regex with negative-lookaheads instead of `str.replace`
    so the prefix-substring trap (`0.7.7` matching inside
    `0.7.7.1`) cannot recur

PyPI users on `pip install evidentia==0.7.7` are unaffected —
that wheel was correct. Only the container surface needed
remediation.

## [0.7.7] - 2026-05-02

**SQL family evidence collectors + Okta + ServiceNow + carry-forward
hardening.** First substantive new-collector release since v0.5.0.
Adds five read-only SQL adapters (PostgreSQL, MySQL/MariaDB,
SQLite, MS SQL Server, Oracle Database), a new Okta evidence
collector, and a ServiceNow output integration. All five SQL
adapters follow the v0.7.0 enterprise-grade collector pattern
(typed exceptions, CollectionContext, CollectionManifest, ECS
audit logging, BLIND_SPOTS, read-only principal probe).

The carry-forward CI hygiene from v0.7.6 lands cleanly: container-
build smoke test now skips on `chore(release):` commits (pre-empts
the PyPI propagation race during release-bump), advanced CodeQL
setup with custom config replaces the default setup, threat-model
publicly elevated to `docs/threat-model.md`, 5 v0.7.5 P0.7 alerts
dismissed.

### Added

- **PostgreSQL evidence collector** (`evidentia-collectors[sql-postgres]`):
  user + role inventory (`pg_roles` + `pg_authid`; AC-2),
  privilege grants (`INFORMATION_SCHEMA.TABLE_PRIVILEGES`,
  `pg_class.relacl`; AC-3, AC-6), audit log status
  (`pg_settings.log_*`, pgaudit; AU-2, AU-3), crypto config
  (`password_encryption`, TLS settings; SC-12), encryption posture
  (TLS-on-the-wire as proxy; SC-28 with documented BLIND_SPOT for
  filesystem-level), connection limits (`max_connections`; AC-3).
  16 unit tests + 3 Docker integration tests.
- **MySQL / MariaDB evidence collector**
  (`evidentia-collectors[sql-mysql]`): mirrors the Postgres surface
  using `mysql.user`, `INFORMATION_SCHEMA.USER_PRIVILEGES`,
  `general_log` / `audit_log_*`, `default_authentication_plugin`,
  InnoDB tablespace encryption + keyring plugin status. 13 unit
  tests. 3 BLIND_SPOTS documented (Community Edition audit gap,
  my.cnf filesystem access, cloud-managed variable visibility).
- **SQLite evidence collector** (`evidentia-collectors[sql-sqlite]`,
  empty extra — uses stdlib `sqlite3`): file-level + extension-
  level evidence — file ACL probe (UNIX mode bits; AC-3), write-
  privilege probe via `os.access` (AC-6), `PRAGMA journal_mode` +
  `synchronous` (durability; SC-28), `PRAGMA integrity_check(1)` +
  `foreign_key_check` (SI-7), encryption-extension probe
  (SEE / SQLCipher / WxSQLite3; SC-28). 16 unit tests using
  in-process `:memory:` databases.
- **MS SQL Server evidence collector**
  (`evidentia-collectors[sql-mssql]`, requires `pyodbc>=5.0` +
  Microsoft ODBC Driver 18 OS-level): `sys.server_principals` /
  `sys.database_principals` (AC-2), `sys.server_role_members` for
  sysadmin count (AC-6), `sys.server_audits` (AU-2),
  `sys.dm_database_encryption_keys` for TDE state (SC-28),
  `CONNECTIONPROPERTY` for TLS posture (SC-12). 20 unit tests.
- **Oracle Database evidence collector**
  (`evidentia-collectors[sql-oracle]`, uses `oracledb>=2.0` thin
  mode — no Oracle Client install required): `dba_users` (AC-2),
  `dba_role_privs` for DBA membership (AC-6), `dba_profiles` for
  password policy (IA-5), `AUDIT_UNIFIED_ENABLED_POLICIES`
  (12c+) or legacy `audit_trail` (AU-2),
  `v$encryption_wallet` + `dba_tablespaces.encrypted` for TDE
  (SC-28), `sqlnet.encryption_server` for in-transit (SC-12).
  23 unit tests. 4 BLIND_SPOTS documented (Advanced Security
  licensing, Unified vs Traditional audit, CDB/PDB context,
  sqlnet.ora client availability).
- **CLI `evidentia collect sql --adapter <name>`** routes to the
  per-adapter collector. Connection passwords MUST come from
  `EVIDENTIA_<ADAPTER>_PASSWORD` env vars per the secret-handling
  protocol — refused via CLI flag.
- **REST endpoints** `POST /api/collectors/sql/{postgres,mysql,sqlite,mssql,oracle}/collect`
  with corresponding `/api/collectors/status` extensions.
- **Okta evidence collector** (`evidentia-collectors[okta]`): MFA
  enrollment rate (sampled per-user `/api/v1/users/{id}/factors`;
  IA-2), inactive accounts (last_login > 90 days; AC-2(3)),
  privileged-account count (`/api/v1/iam/assignees/users`; AC-2,
  AC-6), password policy (`/api/v1/policies?type=PASSWORD`; IA-5),
  sign-on policies with adaptive MFA detection (AC-3). 20 unit
  tests. CLI: `evidentia collect okta --org-url ...` (token via
  `OKTA_API_TOKEN` env var). REST: `POST /api/collectors/okta/collect`.
- **ServiceNow output integration**
  (`evidentia-integrations[servicenow]`): push-only gap-to-record
  workflow via the Table API. Default target table `incident`
  with override to `sn_grc_issue` (GRC plugin) or custom GRC
  tables. Idempotent — `correlation_id = "evidentia-gap-<gap.id>"`
  detects existing records on re-push. 35 unit tests across
  mapper / client / sync. CLI: `evidentia integrations servicenow
  test` + `evidentia integrations servicenow push --gaps gaps.json`.
- **`docs/sql-collectors.md`** comprehensive walkthrough covering
  all 5 SQL adapters: common design, read-only principal
  verification table, secret handling, CLI + REST surface, NIST
  800-53 mapping summary table (9 controls × 5 adapters), per-
  adapter sections, troubleshooting guide.
- **`docs/threat-model.md`** publicly elevated from
  `.local/security-deep-pass-2026-Q3.md` with internal-detail
  scrub. Prereq for v0.8.0 minor per pre-release-review G5.

### Changed

- **CodeQL**: migrated from default setup to advanced workflow with
  custom config (`.github/codeql/codeql-config.yml`) +
  `.github/codeql/python-sanitizers/` pack scaffold. Sanitizer
  for `validate_within` deferred to v0.7.8+ (data-extension YAML
  + QL BarrierGuard subclass approaches both failed to fire; the
  3 false-positive `py/path-injection` alerts on `validate_within`
  were dismissed as part of the v0.7.5 P0.7 batch).
- **`.github/workflows/container-build.yml`**: `Build + smoke test`
  job skips when commit message starts with `chore(release):` —
  pre-empts the PyPI propagation race that briefly broke v0.7.5's
  first-fire publish-container.

### Fixed

- **mypy strict 0/0 across 123 source files** (was 2 pre-existing
  errors at v0.7.6 ship: `hatch_build.py:39` `BuildHookInterface`
  subclass + `jira/mapper.py:147` stale `type: ignore`).
- **F-001 / CWE-22**: SQLite REST + CLI surfaces now honor
  `EVIDENTIA_SQLITE_SAFE_ROOT` env var for path-traversal
  containment in multi-tenant deployments. Surfaced by the
  v0.7.7 pre-release-review Step 3 `/security-review` invocation.
- **F-002 / CWE-209**: connection-error wrappers in all 5 SQL
  adapters now report only the driver class name (e.g.,
  `(driver: OperationalError)`) instead of the full driver-side
  exception message — reduces accidental disclosure of
  connection-string internals to log streams.
- **F-003 / CWE-20**: SQLite `file:?mode=ro` URI now uses
  `urllib.parse.quote(path, safe="/")` before interpolation so
  paths containing `?`, `#`, or `%` cannot smuggle URI options.

EOF lifecycle: 1015 unit tests passing at v0.7.6 → 1103 at
v0.7.7 (88 SQL adapter unit tests + 20 Okta + 35 ServiceNow + 3
new SQLite REST safe_root tests + 8 mapping/aggregate test
extensions).

## [0.7.6] - 2026-05-01

**UI alpha.2 completion + carry-forward CI hygiene + perf benchmarks +
quickstart polish + accepted-findings doc.** This release closes
the alpha.2 GUI gap that's been outstanding since v0.4.0 (Gap
Analyze form / Gap Diff picker / Risk Generate streaming pages were
implemented but never routed in `App.tsx`), lands the 5-screenshot
walkthrough in `docs/gui/`, ships `docs/benchmarks.md` with
reproducible perf numbers, ships `docs/quickstart.md` (90-second
tutorial), and documents 5 accepted code-scanning false positives
in `docs/enterprise-grade-accepted-findings.md`.

Plus 3 carry-forward CI fixes from the v0.7.5 cycle: the PyPI
propagation race that briefly broke v0.7.5's first-tag publish-
container fire (now pre-empted by a Wait-for-PyPI step), the
composite-action-smoke `pip install` failure (uv-managed venvs
don't ship pip; switched to `uv pip install`), and the Meridian v2
baseline cache key that contained a stale legacy
`controlbridge_version` field from before the rename.

The v0.7.6 P1 Q2 `/security-review` deep pass walked 54 surfaces
across 5 tiers; **0 HIGH, 0 MEDIUM, 3 LOW (all design-choice or
intentional)**. v0.7.5 sanitization patterns confirmed clean at
every callsite.

### Added

- **U1 Gap Analyze form page** routed at `/gap/analyze` —
  interactive form with file upload + framework picker + per-run
  organization/system overrides; results render as a TanStack
  GapTable with critical/high/medium/low badges + coverage % +
  efficiency-opportunity counts.
- **U2 Gap Diff picker page** routed at `/gap/diff` — two-report
  selector from gap-store list with download-as-markdown +
  download-as-PR-comment buttons.
- **U3 Risk Generate streaming page** routed at `/risk/generate` —
  gap-id picker + LLM provider selector + SSE-streamed risk
  statements with per-gap progress indicators.
- **U4 5 web UI screenshots** captured at 1440×900 against
  `evidentia serve --dev` + reproducible Playwright capture recipe
  in `.local/capture_screenshots.py`. README §"Web UI flows"
  references all 5; `docs/gui/README.md` walkthrough updated to
  v0.7.6 alpha.2 wiring with embedded thumbnails.
- **B1 `docs/benchmarks.md`** (NEW, ~246 lines) — gap-analysis
  throughput across 4 sample inventories (5-13 ms median, 75-200
  reports/sec headroom on Ryzen-class hardware), NIST 800-53 Rev 5
  catalog load (138 ms median for 324 controls), web UI bundle
  (358 KB JS / 108 KB gzip / 22 KB CSS), test suite (977 tests in
  11.1 s). Hardware baseline + reproducibility recipe. Closes
  enterprise-grade M4 (performance benchmarks).
- **Q1 `docs/quickstart.md`** (NEW, ~165 lines) — 90-second
  tutorial: 5 commands from `pip install` to a verified OSCAL
  Assessment Results document. Cross-linked from README §Quick
  start.
- **GE5 `docs/enterprise-grade-accepted-findings.md`** (NEW,
  ~115 lines) — per-finding rationale for the 5 code-scanning HIGH
  alerts surfaced post-v0.7.5 push (3 CodeQL `py/path-injection`
  false positives on the `validate_within` sanitizer; 2 OpenSSF
  Scorecard accepts: `contents: write` for release-notes append +
  `==X.Y.Z` PyPI pin). Cross-linked from `docs/enterprise-grade.md`.
- **CI1 Wait-for-PyPI step** in the `publish-container` job of
  `release.yml`. Polls `pip index versions` until the new wheel
  appears (capped 5 min) + 20 s mirror catch-up sleep. Pre-empts
  the v0.7.5-trap PyPI propagation race that fired ~50 % of the
  time on first tag publish.

### Changed

- **App.tsx** routes 3 alpha.2 pages (`/gap/analyze`, `/gap/diff`,
  `/risk/generate`) instead of falling through to the 404 page.
  The page implementations have shipped since v0.4.x; the routing
  was the missing piece.
- **AppLayout sidebar** version-footer string bumped from
  `v0.4.1` to `v0.7.6 (alpha.2 wired)`.
- **CI2 `.github/workflows/action-smoke-test.yml`** switched from
  `python -m pip install -e packages/evidentia-core --no-deps`
  (failed with "No module named pip" because uv venvs lack pip) to
  `uv pip install -e packages/evidentia-core --no-deps`.
- **CI3 `.github/workflows/evidentia.yml`** Meridian baseline cache
  key bumped from `meridian-baseline-*` to
  `meridian-baseline-v0.7.6-*` to invalidate the stale snapshot
  that contained a legacy `controlbridge_version` field rejected by
  Pydantic strict-mode.
- **Dockerfile** pin `evidentia[gui]==0.7.5` → `evidentia[gui]==0.7.6`.
- All 6 `pyproject.toml` files bumped 0.7.5 → 0.7.6 atomically via
  `scripts/bump_version.py`. Inter-package pin range string
  (`>=0.7.0,<0.8.0`) unchanged — still inside the v0.7.x line.
- **`docs/v0.7.6-plan.md`** flipped status PLANNED → NEXT (now
  retro after this ship); marks Q1, Q2, U1-U4, B1, GE5, CI1-CI3
  all LANDED. P0.7 dismissals + P0.6 Dependabot batch + P1 R1
  Q3 quarterly resync remain ship-pending or carry-forward.
- **`docs/v0.8.0-plan.md`** gains a new §P0.5 "Identity +
  governance setup" covering GH1-GH5 (the GitHub Enterprise +
  Code Security + Secret Protection items deferred from v0.7.6
  P0.8) plus OR1 ORCID author-identifier registration. Deferred
  pairs with a forthcoming entity / governance setup.

### Deferred to v0.7.7+

- **P0.6 Dependabot batch** — PRs #11 (npm-runtime), #12
  (python-dev), #14 (docker python 3.12→3.14), #17 (github-actions
  re-bumped post-v0.7.5). Auto-merge disabled at repo level + PRs
  stale behind main; background routine
  `trig_01QJXnE5QHxdz3bNYs371pnM` (fires 2026-05-08T13:00 Z) handles
  the rebase + merge-recommendation cycle. PR #16 (npm-dev majors:
  tailwind 3→4 + ts 5→6 + eslint 9→10 + jsdom 25→29) deferred —
  needs targeted single-package PRs since the batched majors break
  the frontend build.
- **P0.7 dismissals** — 5 `gh api PATCH` commands to dismiss the
  accepted false-positive code-scanning alerts (#71, #72, #73, #74,
  #75) with rationale strings referencing
  `docs/enterprise-grade-accepted-findings.md`. Each dismissal is
  publish-authority gated; await explicit approval per
  CLAUDE.md.
- **P1 R1 quarterly research-resync** — Q3 2026 cadence
  (~July 2026); not yet due.

### Carry-forward (unchanged from v0.7.5)

PyPI artifacts (6 wheels + 6 sdists), CycloneDX SBOM, PEP 740
attestations, SLSA L3 build provenance attestation, Sigstore
keyless signing, ghcr.io container publish + cosign + SLSA L3
attestation against the image digest. All v0.7.5 features carry
forward unchanged.

**977 tests passing** + 9 environmental skips (unchanged from
v0.7.5; +6 vitest tests passing for evidentia-ui); mypy strict
clean (73 source files); ruff lint clean.

**Code-scanning alert delta vs v0.7.5**: 16 → 16 (5 new HIGH
documented as accepted; 5 dismissals queued for approval bring
the count to ≤11 once landed).

## [0.7.5] - 2026-05-01

**Container publish + critical security batch + quick-win polish.**
The headline ship: `ghcr.io/allenfbyrd/evidentia` with cosign keyless
OIDC signing + `actions/attest-build-provenance` SLSA L3 build
provenance against the image digest. Two independent verification
paths — `cosign verify` (PEP 740-equivalent for OCI) and
`gh attestation verify oci://...` (SLSA L3 path). Closes
enterprise-grade L1; the LOW score advances 1/5 → 2/5.

Plus 15 HIGH + 12 MEDIUM code-scanning alerts closed via the S1-S6
batch (path-injection containment, ReDoS fix, stack-trace exposure,
workflow permissions, Pinned-Dependencies triage, URL-substring
sanitization), a Dockerfile HEALTHCHECK false-positive fix
(`/health` → `/api/health`), a new `docs/troubleshooting.md` covering
common first-run issues, and an `evidentia oscal verify` UX clarity
fix that returns `PASS (no verification surface)` instead of FAIL on
metadata-only ARs.

### Added

- **C1-C3 ghcr.io container publish** in `release.yml` — new
  `publish-container` job, runs after `needs: publish-pypi`. Pushes
  `ghcr.io/allenfbyrd/evidentia:v0.7.5` AND `:latest` to the same
  digest. cosign keyless OIDC signs by digest; SLSA L3 build
  provenance attestation covers the same digest. Both verifiable via
  `cosign verify ghcr.io/allenfbyrd/evidentia:v0.7.5` and
  `gh attestation verify oci://ghcr.io/allenfbyrd/evidentia:v0.7.5
  -R allenfbyrd/evidentia`. The `publish-container` job runs in the
  new `ghcr` GitHub environment for OIDC scope binding. Append-body
  hook adds an Container image section to the GitHub Release notes.
  Design choice: implemented as a job in `release.yml` (Option A)
  rather than a separate `release-container.yml` (the v0.7.5-plan.md
  C1 description), for `needs: publish-pypi` deterministic ordering
  and a single-workflow-run audit narrative. The plan doc explicitly
  permitted either implementation.
- **C4 `docs/enterprise-grade.md` L1 status flip** — ⚠️ "not yet
  published" → ✅ "Published to `ghcr.io/allenfbyrd/evidentia` per
  release with cosign keyless OIDC signing + SLSA L3 build provenance
  attestation against the image digest". Score advances LOW: 1/5 →
  2/5. Container-image provenance bullet added to the supply-chain
  hardening narrative.
- **C2 `docs/sigstore-quickstart.md` extension** — three new
  top-level sections: "Verifying the published container image"
  (cosign keyless one-liner), "SLSA build provenance verification"
  (`gh attestation verify oci://...`), and "Pinning by digest for
  production deployment". Cross-link to the ghcr package page.
  Footer bumped to v0.7.5 cycle.
- **`docs/troubleshooting.md`** (Q3, NEW, ~220 lines) — common
  first-run issues with symptom/why/fix entries: PATH issues, Python
  version, missing `[gui]` extra, Sigstore TUF metadata fetch
  failures, the v0.7.4 `--version` subcommand recap, Docker uid 1000
  bind-mount perms, port 8000 conflicts, the v0.7.4-and-earlier
  HEALTHCHECK false-positive (cross-link to v0.7.5 Q2 fix), air-gap
  mode network-guard semantics. README §Quick start cross-links it.
- **`docs/release-checklist.md`** Step 5 + Step 9 image-verification
  gates — Step 5 acceptance: Dockerfile pin update + HEALTHCHECK
  `/api/health`; Step 9 acceptance: docker pull + cosign verify +
  gh attestation verify + tag/latest digest match.
- **R2 `evidentia oscal verify` `has_verification_surface` property** —
  `VerifyReport` now exposes whether any check actually ran (digest,
  GPG, or Sigstore). CLI distinguishes "PASS (no verification
  surface)" (yellow) from a meaningful PASS (green) and FAIL (red).
  JSON output (`--json`) exposes `has_verification_surface` for CI
  consumers.

### Fixed

- **S1 `py/path-injection`** — new
  `evidentia_core.security.paths.validate_within(path, safe_root)`
  helper: resolves a path and asserts `is_relative_to(safe_root)`,
  with explicit handling for symlink traversal, URL-encoded `..`,
  and absolute-path-injection inputs. Refactored 14 callsites in
  `evidentia_api/routers/{risks,integrations,gaps}.py`,
  `evidentia_api/app.py`, and
  `evidentia_core/gap_analyzer/inventory.py`. Closes 14 HIGH alerts.
- **S2 `py/polynomial-redos`** in
  `evidentia_core/models/catalog.py:42` — replaced polynomial-time
  alternation with a bounded character class + capped input length
  at the model-validation boundary. Closes 1 HIGH alert.
- **S3 `py/stack-trace-exposure`** in
  `evidentia_api/routers/integrations.py` (jira_status path) —
  errors now logged internally via `evidentia_core.audit.logger` and
  returned externally as generic 500s correlated by `request_id`.
  Closes 3 MEDIUM alerts.
- **Q2 Dockerfile HEALTHCHECK path** — corrected `/health` →
  `/api/health`. The `/health` request silently fell through to the
  SPA fallback handler and returned `index.html` with HTTP 200, a
  false-positive health pass even when the FastAPI app itself was
  broken. Affects every Dockerfile shipped since v0.7.3. Plus three
  regression tests in
  `tests/integration/test_api/test_basic_endpoints.py` covering
  exact response shape, content-type, and prefix path enforcement.
- **R2 `evidentia oscal verify` UX clarity** — a metadata-only AR
  with no embedded evidence + no signatures + `--require-signature`
  unset now returns `PASS (no verification surface)` with exit 0
  instead of the misleading `FAIL` it returned pre-v0.7.5. Pre-v0.7.5
  `overall_valid` consulted `digests_valid` which returned False on
  empty `digest_checks`, conflating "no surface" with "failed
  surface". Fix decouples the two: `overall_valid` now uses
  vacuous-truth semantics on empty surfaces while `digests_valid`
  retains False-when-empty for JSON-consumer back-compat. Two new
  regression tests.

### Changed

- **S4 Workflow permissions hygiene** in `.github/workflows/test.yml`
  — added explicit `permissions: contents: read` declarations for
  the test, lint, and typecheck jobs. Closes 4 MEDIUM
  `actions/missing-workflow-permissions` alerts.
- **S5 Pinned-Dependencies triage** — documented floating
  `apt-get install` package versions in `Dockerfile` with rationale
  for the floating intent (security patches + base-image-rebuild
  cadence); added Scorecard-suppression comment to
  `action-smoke-test.yml:63` for the intentional `pip install -e
  packages/evidentia-core` line. Closes 5 MEDIUM
  `Pinned-Dependencies` alerts.
- **S6 URL-substring sanitization** in
  `tests/unit/test_network_guard.py` — refactored test assertion
  from substring URL match to exact-string comparison via parsed-URL
  hostname checks. Test code only; not a runtime vuln. Closes 2 HIGH
  `URL-substring-sanitization` alerts in test code.
- **Dockerfile** pin: `evidentia[gui]==0.7.4` → `evidentia[gui]==0.7.5`.
- All 6 `pyproject.toml` files bumped 0.7.4 → 0.7.5 atomically via
  `scripts/bump_version.py`. Inter-package pin range string
  (`>=0.7.0,<0.8.0`) unchanged — still inside the v0.7.x line.

### Carry-forward (unchanged from v0.7.4)

PyPI artifacts (6 wheels + 6 sdists), CycloneDX SBOM, PEP 740
attestations, SLSA L3 build provenance attestation, Sigstore
keyless signing for evidence + now also for the container image.
All v0.7.4 features carry forward unchanged.

**977 tests passing** + 9 environmental skips (was 973+9 at v0.7.4
pre-batch; +2 Q2 health regression tests, +2 R2 oscal verify
regression tests); mypy strict clean; ruff lint clean.

**Code-scanning alert delta vs v0.7.4**: 37 → 15 (22 closed).
Remaining 15 are advisory Scorecard findings + a few pre-existing
findings to triage in v0.7.6.

### Deferred from v0.7.5 (carry-forward to v0.7.6)

- **Q1 OpenSSF Best Practices Badge filing** — Allen-driven; post-
  tag once the badge is awarded.
- **D1 Dependabot batch** — PRs #11 (npm-runtime), #12 (python-dev),
  #14 (docker python 3.12→3.14), #15 (github-actions) were rebased
  but not landed inside the v0.7.5 cycle (auto-merge disabled at
  repo level + PRs went stale behind main). PR #16 (npm-dev) closed
  with rationale (combined major bumps in tailwind/typescript/eslint
  break the frontend build; need targeted single-package PRs in
  v0.7.6).
- **R1 `docs/positioning-and-value.md` quarterly re-sync** — Q3
  2026 cadence target ~July 2026; today is 2026-04-30. Slipped to
  v0.7.6.

## [0.7.4] - 2026-04-29

**Same-day hot-fix release for v0.7.3.** Same-day patch correcting
three wrong CLI invocations that shipped in v0.7.3's container-image
work + an additional pre-existing wrong invocation in the composite
action's install step (latent since v0.7.0; never surfaced because
`.github/actions/gap-analysis/` was never externally consumed in
CI before v0.7.3 added the smoke-test workflow).

The Evidentia CLI registers `version` as a SUBCOMMAND (alongside
`init`, `doctor`, `serve`, `gap`, `catalog`, `risk`, `explain`,
`integrations`, `collect`, `oscal`) — not as a `--version` flag.
The Typer-driven CLI errors with "No such option: --version Did
you mean --verbose?" exit code 2 when invoked with the flag.
Similarly the framework-catalog subcommand is `evidentia catalog`
(not `evidentia frameworks`).

### Fixed

- **`Dockerfile` line 73**: `RUN evidentia --version` →
  `RUN evidentia version`. The image build was failing with exit
  code 2 in the v0.7.3 container-build.yml workflow on every push
  to main + every PR touching the Dockerfile. **Validated**:
  ran `docker build` locally during the v0.7.4 hot-fix cycle;
  build now produces the v0.7.4 image clean. The 3 failing
  container-build.yml runs from v0.7.3 push (run IDs `25142392128`
  on push-to-main + `25142414837` + `25142442386` on dependabot
  PRs) will succeed on next-trigger after this fix lands.
- **`.github/workflows/container-build.yml`**:
  `docker run --rm evidentia:smoke --version` →
  `docker run --rm evidentia:smoke version`;
  `evidentia frameworks list | head -10` →
  `evidentia catalog list | head -10`. Workflow comment header
  also updated to match the fixed invocations.
- **`.github/actions/gap-analysis/action.yml` line 107**:
  `evidentia --version` → `evidentia version`. Pre-existing bug
  in the composite action's install step — latent since v0.7.0
  but never exercised by any external consumer. Captured as part
  of the v0.7.4 sweep so future composite-action consumers don't
  hit it.
- **`.github/workflows/action-smoke-test.yml` line 64**:
  `.venv/bin/evidentia --version` → `.venv/bin/evidentia version`.
  Same root cause; same fix.
- **`.devcontainer/devcontainer.json` `postStartCommand`**:
  `evidentia --version` → `evidentia version`. The `|| echo ...`
  fallback was masking the failure but the line was still wrong.

### Changed

- **`docs/release-checklist.md` Step 5 — Test gate**: added a new
  "**Local Docker build**" line. Any release that touches the
  `Dockerfile` or `.github/workflows/container-build.yml` MUST
  build the image locally before tag (`docker build -t
  evidentia:rc .`) — the tag-triggered `release.yml` doesn't
  exercise the Dockerfile, and the PR-triggered
  `container-build.yml` only fires after push-to-main with
  Dockerfile changes. The v0.7.3 ship missed this because the
  Dockerfile was new in that release and no prior release-checklist
  entry covered it. v0.7.4 closes the gap.

### Carry-forward (unchanged from v0.7.3)

PyPI artifacts (6 wheels + 6 sdists), CycloneDX SBOM, PEP 740
attestations, SLSA L3 build provenance attestation, Sigstore
keyless signing, all v0.7.3 features (composite action SHA-pinning,
SLSA L3 release path, v0.8.0-plan, sigstore-quickstart,
pre-commit hooks, dev container, frontend dep CVE bumps) carry
forward unchanged.

**965 tests passing** + 8 environmental skips (matches v0.7.3
baseline); mypy strict clean (86 source files); ruff lint clean.

## [0.7.3] - 2026-04-29

**The composite action hardening + docs polish release.** Closes the
OpenSSF Scorecard "Pinned-Dependencies" check end-to-end (28
SHA-pinned `uses:` refs across the composite action + every workflow
file), adds a composite-action E2E smoke test that catches future
action.yml ↔ CLI drift, lands SLSA L3 build provenance via
`actions/attest-build-provenance@v2.4.0` (restoring
`gh attestation verify` as a working verifier alongside
`pypi-attestations verify pypi`), publishes the forward
[`docs/v0.8.0-plan.md`](docs/v0.8.0-plan.md) (the OSS-native AI
moat) + [`docs/sigstore-quickstart.md`](docs/sigstore-quickstart.md)
end-to-end walkthrough, lands `.pre-commit-config.yaml` +
`.devcontainer/devcontainer.json` (closing the two outstanding
promises in `docs/ide-setup.md`), and ships a non-publishing
container-image build workflow + `Dockerfile` (lightweight close
of enterprise-grade L1; full ghcr.io publishing gated to a future
release with cosign signing).

Also closes the v0.7.2-deferred frontend dev-tree CVE alerts —
coordinated `vite`/`vitest`/`@vitejs/plugin-react` bump past the
plugin-react peer-chain block; `npm audit` reports 0 vulnerabilities
in both production and full trees (was 7 moderate).

**965 tests passing** + 8 environmental skips on local Windows
(GnuPG entropy + Sigstore CI-OIDC; full pass on Linux CI per
v0.7.2 baseline); mypy strict clean (86 source files); ruff lint
clean.

This release also lands per-release follow-up items: A6 README
version-history truncation, A10 `CITATION.cff` (Citation File Format
1.2.0 metadata for the GitHub "Cite this repository" widget), B4
release-checklist refresh, A3 the frontend dev-stack CVE bumps. A2
release-note backfill for v0.7.0/v0.7.1, A4 local-only
pre-rewrite-backup ref cleanup, A5 stale-issue closure all
verified-complete during the v0.7.3 cycle. A1 `/security-review`
ran clean (zero HIGH/MEDIUM findings).

The DOC4 architecture-plan refresh adds a single "Updates since
v0.7.0" callout block to
[`Evidentia-Architecture-and-Implementation-Plan.md`](Evidentia-Architecture-and-Implementation-Plan.md)
covering v0.7.1 AI hardening + v0.7.2 supply-chain visibility +
v0.7.3 composite-action hardening + v0.8.0+ forward direction.
Document body unchanged.

### Added

- **`Dockerfile`** at repo root + **`.github/workflows/container-build.yml`**
  — repo-root container image build (audit-cleanup item B2,
  lightweight variant). Single-stage `python:3.12-slim` image
  installs `evidentia[gui]>=0.7,<0.8` from PyPI as a non-root user
  (uid 1000); runs `evidentia serve` on port 8000 by default;
  override `CMD` for any other CLI subcommand. Includes the gpg +
  ca-certificates + curl system deps so the air-gap GPG path
  works inside the image. The new workflow builds the image on
  every PR touching `Dockerfile` (and on push to `main`) and runs
  4 smoke tests: `evidentia --version`, `evidentia frameworks
  list`, OCI labels populated, non-root execution (uid 1000).
  Image is **not yet published** — the workflow does
  `push: false`, `load: true`. Publishing to
  `ghcr.io/allenfbyrd/evidentia` with cosign signing is gated to
  a future release that explicitly opts in. Closes the
  documentation half of enterprise-grade L1
  ([`docs/enterprise-grade.md`](docs/enterprise-grade.md))
  ("Not currently published" → "Repo-root Dockerfile + CI
  smoke-test, not yet published").
- **`.github/dependabot.yml`** — adds a `docker` ecosystem entry
  so Dependabot tracks the new `Dockerfile`'s `python:3.12-slim`
  base image. Same Monday 06:00 ET cadence and grouped-by-batch
  pattern as the existing uv / npm / github-actions ecosystems.
  `chore(docker)` commit prefix.
- **`packages/evidentia-ui/package.json`** + regenerated
  `package-lock.json` — coordinated frontend dev-stack bump
  (audit-cleanup item A3) closing the v0.7.2 deferred dev-tree
  Dependabot alerts. Bumps:
    - `vite` `^6.4.2` → `^8.0.10`
    - `vitest` `^2.1.3` → `^4.1.5`
    - `@vitejs/plugin-react` `^4.3.3` → `^6.0.1`
    - `@vitest/coverage-v8` `^2.1.3` → `^4.1.5`
    - `@vitest/ui` `^2.1.3` → `^4.1.5`

  v0.7.2 had pinned `vite` to `^6.4.2` because Dependabot's auto-PR
  proposed `vite@8.0.10` which broke the
  `@vitejs/plugin-react@^4.3.3` peer chain (plugin-react 4 supports
  vite 4-7, not 8). Bumping plugin-react to 6 resolves the peer
  chain and lets vite 7+ ship; bumping vitest to 4 closes the
  remaining 2 dev-tree moderate alerts (vitest's bundled
  vite/esbuild). Result: `npm audit` reports 0 vulnerabilities
  across both production and full trees. Validated via
  `npm run typecheck` (clean), `npm run build` (2.73s, 281 KB JS /
  22 KB CSS gzipped — in line with prior baseline), and
  `npm run test -- --run` (6/6 vitest tests passing under v4.1.5).
- **`CITATION.cff`** — Citation File Format 1.2.0 metadata at the
  repo root (audit-cleanup item A10). Renders as a "Cite this
  repository" widget on the GitHub repo sidebar; integrates with
  Zenodo when the user opts in to software-DOI minting. Documents
  the project title, sole author + email, abstract, repository URL,
  PyPI URL, version (0.7.2), date released, license, and the 13
  domain keywords (grc, oscal, nist-800-53, fedramp, cmmc, soc2,
  compliance-as-code, gap-analysis, risk-statements, sigstore,
  slsa, python). Updated at each release alongside the `version`
  bumps in the 7 pyproject.toml files.
- **`docs/release-checklist.md` Step 7** — added 4 new line items
  surfaced by the v0.7.2 post-audit hardening (audit-cleanup item
  B4): branch-protection-on-`main` verification, `pypi` environment
  branch policy verification (`custom_branch_policies: true` with
  both `main` and `v*` allowed for tag-triggered releases),
  Dependabot week-of-ship review, and SECURITY.md
  vulnerability-coordination-flow currency check. Closes the
  release-checklist refresh promised in the v0.7.2 audit findings.

- **`Evidentia-Architecture-and-Implementation-Plan.md`** — added
  an "Updates since v0.7.0" callout block at the top of the
  architecture plan (v0.7.3 P1 deliverable DOC4) covering: v0.7.1
  AI-features hardening (`GenerationContext`, 9 new `EventAction`
  entries, typed exception hierarchy, `with_retry_async`,
  audit-trail correlation, operator identity); v0.7.2 supply-chain
  visibility + IDE config + catalog-drift fix; v0.7.3
  composite-action hardening + SLSA L3 + pre-commit hooks + dev
  container; and a forward-direction pointer to v0.8.0+ (DFAH
  harness, PRT mode, MCP server, plugin-contract scaffolding) and
  v0.9.0 (federal-compliance reserved). Document body unchanged —
  the callout block carries the per-release deltas without
  rewriting the v0.7.0 baseline.
- **`.pre-commit-config.yaml`** + companion `.yamllint` +
  `.markdownlint.yaml` — pre-commit hook configuration (v0.7.3 P1
  deliverable DOC6). Activates the same quality gates as CI on
  every commit so contributors don't push CI-failing changes by
  accident. Hooks: ruff (check + format), mypy strict,
  markdownlint-cli2, prettier (UI), yamllint, end-of-file-fixer,
  trailing-whitespace, check-yaml, check-toml, check-json,
  check-merge-conflict, check-added-large-files. Both Cursor and
  VS Code pick up the hooks automatically once
  `pre-commit install` has been run. The promise in
  `docs/ide-setup.md` "Pre-commit hooks (planned for v0.7.x+)"
  flipped to "active since v0.7.3."
- **`.devcontainer/devcontainer.json`** — guaranteed-reproducible
  contributor environment (v0.7.3 P1 deliverable DOC7). Base image
  `mcr.microsoft.com/devcontainers/python:1-3.12` (matches the CI
  matrix Python version) layered with the dev-container features
  for Node 20, GitHub CLI, and uv (Astral). `postCreateCommand`
  runs `uv sync --all-packages --frozen` + installs pre-commit
  hooks. Forwards port 8000 for `evidentia serve`. Bakes the same
  VS Code extensions the version-controlled
  `.vscode/extensions.json` recommends so contributors get a
  fully-set-up editor on first open. The promise in
  `docs/ide-setup.md` "Dev container (planned, not yet enabled)"
  flipped to "active since v0.7.3."
- **`docs/ide-setup.md`** — pre-commit hooks + dev container
  sections rewritten from "planned" to "active since v0.7.3" with
  the concrete setup commands and full hook list.
- **`docs/sigstore-quickstart.md`** — five-minute end-to-end
  walkthrough for Sigstore signing + verifying OSCAL Assessment
  Results documents (v0.7.3 P1 deliverable DOC3). Covers: install
  with `[sigstore]` extra, why Sigstore for compliance evidence,
  signing in CI via the composite action's `emit-sigstore-bundle`
  flag, signing locally via OAuth browser fallback, opportunistic
  vs strict (`--require-signature` + `--expected-identity` +
  `--expected-issuer`) verification, common identity/issuer
  combinations table for GitHub Actions / GCP / AWS / local OAuth,
  air-gap fallback to GPG, and a troubleshooting matrix. Closes
  the v0.7.0 enterprise-grade documentation gap (the only Sigstore
  docs were the CLI `--help` text and action.yml inline comments).
- **`docs/v0.8.0-plan.md`** — forward-looking release plan for the
  v0.8.0 "OSS-native AI moat" minor (v0.7.3 P1 deliverable DOC2).
  Scopes the differentiation features sketched in
  [`positioning-and-value.md`](docs/positioning-and-value.md) §13.2
  into a single ~3-month minor: DFAH determinism harness
  (`evidentia eval`), Policy Reasoning Traces mode
  (`evidentia risk generate --emit-trace`), MCP server
  (`evidentia mcp serve`), and a stable plugin contract
  (`AuthProvider` / `StorageBackend` / `MarketplaceProvider`) for
  out-of-tree extension authors. P1 closes enterprise-grade
  follow-ups (mutation testing, property-based tests, Prometheus
  `/metrics`, reproducible builds, perf benchmarks doc, anti-tamper
  guidance doc). P2 carries optional / community items
  (DSE preview, evidentia-catalogs split, HF benchmark dataset).
- **`docs/ROADMAP.md`** — adds a v0.8.0 PLANNED section pointing
  at the new plan file, and a v0.9.0 RESERVED section for the
  federal-compliance capability work (POA&M, CONMON cycle
  calendar) informed by domain-expert input.
- **`.github/workflows/release.yml`** — SLSA L3 build provenance
  attestation step (v0.7.3 P0 S3) via
  `actions/attest-build-provenance@v2.4.0`. Generated after the
  build + CycloneDX SBOM steps so a single attestation covers the
  6 wheels + 6 sdists + the SBOM. Stored under the repo's
  Attestations endpoint and verifiable by consumers via
  `gh attestation verify dist/<wheel> -R allenfbyrd/evidentia`.
  This is the SLSA-path verifier; the PEP 740 PyPI path
  (`pypi-attestations verify pypi`) continues to work
  independently. Closes the H2 enterprise-grade item ("SLSA L2+
  reproducible builds + SBOM") and restores `gh attestation verify`
  as a working verifier alongside the PEP 740 path. Adds
  `attestations: write` to the publish-pypi job permissions.
- **`docs/release-checklist.md` Step 9** (DOC1) — split the
  post-release verification block into two clearly-labeled
  verifier paths: PEP 740 (`pypi-attestations verify pypi`) for
  per-file PyPI attestations, and SLSA L3
  (`gh attestation verify`) for the build-provenance attestation
  added by S3. Documents the predicate difference so future
  reviewers know which verifier handles which path.
- **`.github/workflows/action-smoke-test.yml`** — composite-action
  E2E smoke test (v0.7.3 P0 S2). Runs the consumer-facing
  `./.github/actions/gap-analysis` against the bundled Meridian
  fintech v2 sample inventory on every PR that touches the action
  surface, the underlying CLI, or the sample data. Catches the kind
  of action.yml ↔ CLI drift that surfaced as the
  `--bundle` vs `--sigstore-bundle` mismatch in v0.7.0 Step 4.
  Uses an editable install of the PR's `evidentia-core` so the
  action runs against the same-PR CLI source rather than the
  latest PyPI release. Validates that `gap-report.json` and
  `oscal-ar.json` land with the expected structure (`assessment-results`
  root key on the AR). Sigstore is intentionally off (covered by
  release.yml + S3); `fail-on-regression: false` because Meridian
  is a demo scenario.
- **`.github/actions/gap-analysis/action.yml`** — all four
  third-party actions SHA-pinned to specific 40-char commit SHAs
  with the pinned-version recorded in trailing comments
  (`@<sha> # vX.Y.Z`). Closes the OpenSSF Scorecard
  ["Pinned-Dependencies"](https://scorecard.dev/checks#pinned-dependencies)
  check for the composite action consumed by downstream audit
  pipelines: `actions/setup-python` v5.6.0,
  `actions/cache` v4.3.0,
  `marocchino/sticky-pull-request-comment` v2.9.4, and
  `actions/upload-artifact` v4.6.2. Dependabot's
  `github-actions` ecosystem (added in v0.7.2 post-audit hardening)
  opens grouped weekly PRs to advance the pins; review release
  notes per PR before merge. v0.7.3 P0 S1 per
  [`docs/v0.7.3-plan.md`](docs/v0.7.3-plan.md).
- **`.github/workflows/*.yml`** — same SHA-pinning treatment
  extended across every workflow file in the repo so the
  Scorecard score reflects end-to-end pinned dependencies, not
  just the externally-consumed composite action. Affected
  workflows: `catalog-refresh.yml`, `evidentia.yml`,
  `release.yml`, `scorecard.yml`, `test.yml`. Pinned actions:
  `actions/checkout` v4.3.1, `astral-sh/setup-uv` v3.2.4,
  `actions/github-script` v7.1.0, `actions/setup-node` v4.4.0,
  `softprops/action-gh-release` v2.6.2,
  `ossf/scorecard-action` v2.4.0,
  `github/codeql-action/upload-sarif` v3.35.2, plus the four
  also used by the composite action. Total: 28 pinned refs across
  6 files. The single remaining major-version-tag-pinned ref
  (`pypa/gh-action-pypi-publish@release/v1`) is the documented
  PyPA pattern for trusted-publisher OIDC publishes — the
  release branch is maintainer-controlled and Scorecard accepts
  it as a known-secure case.

- **`SECURITY.md`** — vulnerability disclosure policy at the repo
  root (rendered under the GitHub Security tab + linked from the
  "Report a vulnerability" affordance). Documents the GitHub
  Private Vulnerability Reporting flow (preferred channel) +
  email backup, required-info checklist for reports, SLA
  (3 business days initial / 10 business days triage), supported
  versions (single-supported-patch policy with explicit
  deprecation reasons for older patches that carry vulnerable
  transitive dep ranges), 90-day disclosure timeline with
  documented flexibility (shorter for upstream-fix-then-bump per
  v0.7.2 commit `8baa93d`, longer for architectural fixes by
  mutual agreement), in/out of scope (explicitly out: AWS
  canonical-example placeholders in test fixtures, Tier-C
  placeholder catalog text, third-party deps), supply-chain
  provenance verification command (`pypi-attestations verify
  pypi`).
- **`.github/dependabot.yml`** — weekly grouped version-update
  PRs across uv (Python — covers all 7 pyproject.toml files via
  uv.lock), npm (frontend), and github-actions ecosystems.
  Single Monday-06:00-ET batch (no daily drip), grouped by
  production/development split, per-ecosystem open-PR caps
  (5/5/3). Conventional-commit prefixes (`chore(deps)`,
  `chore(deps-dev)`, `chore(actions)`). Security update PRs
  remain ungrouped (groups scoped via `applies-to:
  version-updates`) so each advisory still gets its own PR with
  clear references, per the v0.7.2 supply-chain follow-up
  pattern.
- **README.md `## Security` section** — points at SECURITY.md +
  summarizes supply-chain provenance.
- **CONTRIBUTING.md `## Reporting security issues` section** —
  routes security reports to SECURITY.md; warns against using
  the bug-report template for vulnerabilities.

### Changed

- **GitHub repo settings (operational, not in source)** —
  branch protection on `main` (required status checks: pytest x
  3 OS + ruff + mypy + frontend; `enforce_admins: false`;
  `allow_force_pushes: false`; `allow_deletions: false`).
  Dependabot security updates + Dependabot malware alerts +
  automatic dependency submission enabled. CodeQL default-config
  analysis enabled. Secret-scanning non-provider patterns +
  validity checks deferred — currently unavailable on
  personal-account public repositories.
- **`README.md`** — version-history section truncated to last three
  releases (v0.7.2 / v0.7.1 / v0.7.0) with a pointer to
  `CHANGELOG.md` for full version history (audit-cleanup item A6).
  Removes 8 entries spanning v0.5.0 through v0.2.1 plus their
  in-section install snippets. Reduces the chronology from ~150
  lines to ~30.

## [0.7.2] - 2026-04-27

**The supply-chain polish + documentation refresh release.** Adds
`OpenSSF Scorecard` weekly workflow publishing to
`securityscorecards.dev` (S4 deliverable), version-controlled
Cursor + VS Code workspace configuration for testing/validation
inline (DOC6), and fixes the long-standing catalog-drift false
positive that opened daily as issues #1, #2, #3, and #4 between
2026-04-23 and 2026-04-26 (S0 — `yaml.safe_dump(width=200)` for
byte-stable manifest emit + `--ignore-all-space` belt-and-suspenders
guard in the catalog-refresh.yml workflow). Carries the
pre-release-review refinements pass (4 MEDIUM fixes for cross-platform
IDE config + doc accuracy + a stderr warning when the regen script
silently dropped malformed catalog files).

**965 tests passing** (8 environmental skips on local Windows for
GnuPG entropy + Sigstore CI-OIDC; full suite passes on Linux CI per
the v0.7.1 baseline). mypy clean against the CI gate
(`--strict-optional` over 86 source files); ruff lint clean.

This release also adds a `.local/` per-developer scratch directory
to `.gitignore` for working notes and drafts not ready to share. The
convention follows the existing `.vscode/` split: ignore by default;
un-ignore specific files only if they're meant to be shared. See
[`docs/ide-setup.md`](docs/ide-setup.md) for the contributor-facing
IDE walkthrough.

The v0.7.2 cycle ran the full `pre-release-review` SKILL.md flow
(Pre-tag variant, all 6 steps) on top of v0.7.1's ship; produced
[`docs/v0.7.3-plan.md`](docs/v0.7.3-plan.md) for the next release
(carries the v0.7.1-plan-originated S1+S2+S3 composite-action
hardening items that didn't make v0.7.2 + DOC2/DOC3/DOC5 docs
polish + DOC6 pre-commit hooks + DOC7 dev container).

### Added

- **`.github/workflows/scorecard.yml`** — OpenSSF Scorecard weekly
  workflow (Mondays 06:00 UTC + on push-to-main + workflow_dispatch).
  Publishes to `securityscorecards.dev` via OIDC; uploads SARIF to
  the GitHub Security tab. Permissions follow least-privilege
  (read-all at workflow level; per-job escalations explicit).
- **`.vscode/{settings,launch,tasks,extensions}.json`** — shared
  workspace config for VS Code + Cursor: pytest discovery + run-on-save,
  mypy strict inline, ruff format-on-save + auto-fix-on-save,
  coverage gutters, 7 debug launch configs (pytest current-file /
  full-suite / single-test, evidentia serve, gap analyze, explain,
  doctor), 16 pre-canned tasks (uv sync, pytest, mypy, ruff, build,
  twine check, pre-release gate composite, evidentia doctor, serve,
  + 4 frontend tasks).
- **`.cursorrules`** — Cursor AI guardrails encoding project
  conventions (typed exception hierarchy, audit logger, network
  guard, secret scrubber, commit-attribution, publishing-authority
  discipline). Inline-enforcement sister to CONTRIBUTING.md.
- **`.editorconfig`** — cross-editor consistency for any IDE that
  honors EditorConfig: utf-8, LF, trim trailing whitespace, final
  newline, 4-space indent for Python, 2-space for JS/TS/YAML, tab
  for Makefile, hands-off for `uv.lock` + `package-lock.json`.
- **`docs/ide-setup.md`** — contributor-facing walkthrough covering
  Cursor + VS Code paths from clone-to-test-feedback in one page.
  Tooling matrix, defined tasks, defined launch configs,
  Cursor-specific guidance, troubleshooting, planned pre-commit
  hooks + dev container.
- **`docs/v0.7.3-plan.md`** — forward-looking plan for the next
  release (composite action hardening + sample-data expansion).
- **`docs/positioning-and-value.md` §16 "Version history"** — new
  section capturing per-release skip-by-reuse decisions; first entry
  documents the v0.7.2 review-for-skip with all 5 skip criteria.
- **`.gitignore` `.local/`** — new per-developer scratch directory
  for working notes and drafts not ready to share. Convention
  follows the `.vscode/` split.

### Changed

- **`scripts/catalogs/regenerate_manifest.py`** — pinned
  `yaml.safe_dump(width=200)` so manifest emit is byte-stable across
  PyYAML versions and platform locales (closes false-positive issues
  #1-#4). Also: now emits `WARN: skipped malformed catalog file
  <path>: <repr>` to stderr on `(OSError, json.JSONDecodeError)`
  rather than silently dropping the catalog.
- **`packages/evidentia-core/src/evidentia_core/catalogs/data/frameworks.yaml`** —
  one-time canonical regen at the new `width=200` setting. 174 lines
  re-flowed; zero semantic changes.
- **`.github/workflows/catalog-refresh.yml`** — drift detection now
  uses `git diff --quiet --ignore-all-space` as belt-and-suspenders
  against future PyYAML word-wrap drift across versions.
- **`.vscode/settings.json`** — removed hardcoded
  `python.defaultInterpreterPath = "${workspaceFolder}/.venv/Scripts/python.exe"`
  which only worked on Windows. Python extension auto-discovers
  `.venv/` via `python.terminal.activateEnvironment` cross-platform.
- **`docs/positioning-and-value.md`** — minor refinements per the
  v0.7.2 pre-release-review Step 5.A: corrected stamp date 2026-04-25
  → 2026-04-24 to match git, re-phrased DORA Q1 2026 reference to
  past tense ("in force since Q1 2026") since the date has now passed.

### Supply-chain follow-up — disclosed CVEs

Dependabot surfaced 6 open advisories on the v0.7.2 push. Four
addressed in this release; two transitive vitest dev-deps deferred
to v0.7.3 with documented rationale.

- **`packages/evidentia-ai/pyproject.toml`** — `litellm` floor
  bumped from `>=1.83.0,<2.0` to `>=1.83.7,<2.0`. Resolves
  three open advisories that all affect LiteLLM's proxy server
  mode (Evidentia uses LiteLLM as a client library — `from litellm
  import completion` — so reachability is theoretical, but the
  visible-signal hygiene matters):
  - `GHSA-r75f-5x8p-qvmc` CRITICAL (CVSS 9.3) — SQL injection in
    proxy API key verification path.
  - `GHSA-xqmj-j6mv-4862` HIGH — server-side template injection
    in `/prompts/test` endpoint.
  - `GHSA-v4p8-mg3p-g94g` HIGH — authenticated command execution
    via MCP stdio test endpoints (`/mcp-rest/test/connection` +
    `/mcp-rest/test/tools/list`).
- **`packages/evidentia-api/pyproject.toml`** — `python-multipart`
  floor bumped from `>=0.0.9` to `>=0.0.26`. Resolves
  `GHSA-mj87-hwqh-73pj` / `CVE-2026-40347` MEDIUM — DoS via
  oversized multipart preamble or epilogue parsing. Reachable via
  FastAPI multipart endpoints under `evidentia serve`.
- **`packages/evidentia-ui/package.json`** — `vite` bumped from
  `^5.4.9` to `^6.4.2` (resolved at `6.4.2`). Pulls `esbuild` past
  `0.24.2` transitively (resolved at `0.25.12`). Resolves the
  direct-dep paths for `GHSA-4w7w-66w2-5vf9` / `CVE-2026-39365`
  (vite path traversal in optimized-deps `.map` handling) and
  `GHSA-67mh-4wv8-2f99` (esbuild dev-server CORS bypass).
  - **Choice rationale**: Dependabot's auto-PR proposed
    `vite@8.0.10`, which broke the `@vitejs/plugin-react@^4.3.3`
    peer chain (supports vite 4–7 but not 8). `6.4.2` is the
    smallest CVE-fix version that preserves peer compatibility
    with the existing React plugin. Coordinated bump of vite to
    7+ deferred to v0.7.3 alongside `@vitejs/plugin-react`
    upgrade.
  - **Vitest transitive vite/esbuild deferred**: vitest 2.1.9
    bundles its own vite 5.4.21 + esbuild 0.21.5 in its
    dependency tree. `npm audit --omit=dev` reports 0
    vulnerabilities (production tree is clean). Bumping the
    vitest tree to a vite-6-compatible version (vitest 3+)
    deferred to v0.7.3 with the broader frontend-stack-bump
    pass.

After the bump, `npm audit --omit=dev` reports zero
vulnerabilities. The 7 remaining moderate-severity advisories
are all dev-scope (vitest test runner) and never reach
production users.

## [0.7.1] - 2026-04-26

**The AI features hardening release.** Brings `evidentia-ai`
(`risk_statements/` + `explain/`) up to the v0.7.0 collector-pattern
enterprise grade — closing the v0.7.0 BLOCKER B3 carry-over for both
AI subsystems via the typed `EvidentiaAIError` hierarchy in
`evidentia_ai.exceptions`. Adds `GenerationContext` metadata on every
AI-generated artifact (sibling of `CollectionContext` in
`evidentia_core.audit.provenance`), 9 new `evidentia.ai.*`
`EventAction` entries for ECS-structured AI audit events, bounded
retry against the shared `LLM_TRANSIENT_EXCEPTIONS` set (LiteLLM
`RateLimitError` / `APIConnectionError` / `Timeout` /
`InternalServerError` / `ServiceUnavailableError` / `BadGatewayError`),
and `run_id`-correlated audit trails so SIEM operators can join AI
failures, retries, successes, and cache hits by namespace. Best-effort
operator identity is captured via the new
`evidentia_ai.client.get_operator_identity()` helper, closing the
NIST AU-3 "Identity" gap for AI-derived artifacts.

**973 tests collected** (965 passed + 8 environmental skips on local
Windows; the 8 skips are GnuPG entropy + Sigstore CI-OIDC-only and
pass on Linux CI per the v0.7.0 baseline). Net new tests for the
v0.7.1 P0 work ≈ 116 across `tests/unit/test_ai/`,
`tests/unit/test_audit/`, and `tests/unit/test_models/`. mypy strict
clean (98 source files); ruff lint clean.

**Shipped as P0-only by deliberate scope-narrowing decision** at ship
time. The P1 (supply-chain polish — SHA-pin composite action, action
E2E smoke test, SLSA L3 build provenance, OpenSSF Scorecard) and
P2/P3 (documentation polish + community-driven items) originally
scoped for v0.7.1 in
[`docs/v0.7.1-plan.md`](docs/v0.7.1-plan.md) **moved to**
[`docs/v0.7.2-plan.md`](docs/v0.7.2-plan.md) so v0.7.1 could land
focused on the BLOCKER B3 closure without scope creep. S5 ("Sigstore
verify warning log emission") was implemented as part of P0 and S6
("`PYPI_API_TOKEN` deletion verification") landed during v0.7.0
ship-day housekeeping (verified absent post-v0.7.1) — neither carries
to v0.7.2. See [`docs/v0.7.1-plan.md`](docs/v0.7.1-plan.md) (now
SHIPPED) for the line-item ship summary and
[`docs/v0.7.2-plan.md`](docs/v0.7.2-plan.md) for the forward plan.

### v0.7.1 detail — AI features hardening

#### Added

- **`GenerationContext`** Pydantic model in
  `evidentia_core.audit.provenance`, sibling to `CollectionContext`.
  Captures per-output AI provenance: `model`, `temperature`,
  `prompt_hash` (SHA-256 of system+user prompts via the new
  `compute_prompt_hash()` helper), `run_id` (ULID),
  `generated_at` (microsecond UTC), `attempts` (network-layer retry
  count), `instructor_max_retries` (validation-layer cap),
  `credential_identity` (best-effort operator label per NIST AU-3),
  `evidentia_version`.
- **9 new `EventAction` entries** under the `evidentia.ai.*` namespace:
  `AI_RISK_GENERATED`, `AI_RISK_FAILED`, `AI_RISK_RETRY`,
  `AI_RISK_BATCH_COMPLETED`, `AI_EXPLAIN_GENERATED`,
  `AI_EXPLAIN_FAILED`, `AI_EXPLAIN_RETRY`, `AI_EXPLAIN_CACHE_HIT`,
  `AI_EXPLAIN_BATCH_COMPLETED`. Documented in `docs/log-schema.md`.
- **`with_retry_async`** decorator + **`build_retrying`** /
  **`build_async_retrying`** factory functions in
  `evidentia_core.audit.retry`, supporting async callers and
  per-call attempt tracking.
- **`event_action`** kwarg on `with_retry`/`with_retry_async` (default
  `EventAction.COLLECT_RETRY` preserves pre-v0.7.1 collector
  behaviour); AI generators pass `AI_RISK_RETRY` /
  `AI_EXPLAIN_RETRY` so SIEM operators can filter retry storms by
  namespace.
- **`evidentia_ai.exceptions`** module with the typed exception
  hierarchy (`EvidentiaAIError`, `LLMUnavailableError`,
  `LLMValidationError`, `RiskStatementError`, `RiskGenerationFailed`).
- **`evidentia_ai.client.get_operator_identity()`** helper returning
  `$EVIDENTIA_AI_OPERATOR` if set, else best-effort
  `user@hostname`. Populates
  `GenerationContext.credential_identity`.
- Optional **`generation_context`** field on
  `evidentia_core.models.risk.RiskStatement` AND
  `evidentia_ai.explain.models.PlainEnglishExplanation` (default
  `None` for v0.7.x backward compat; will tighten to required in v0.8
  with a deprecation cycle).
- Shared **`LLM_TRANSIENT_EXCEPTIONS`** tuple in
  `evidentia_ai.exceptions` so `risk_statements/` and `explain/`
  retry on identical conditions (single source of truth).
- **`ExplainError`** + **`ExplainGenerationFailed`** in
  `evidentia_ai.exceptions` (sibling of the risk-specific hierarchy
  under the shared `EvidentiaAIError` base).

#### Changed

- `risk_statements/generator.py`: replaced stdlib `logging` with
  `evidentia_core.audit.get_logger`; wrapped LLM calls in bounded
  retry against the LiteLLM transient-exception set
  (`RateLimitError`, `APIConnectionError`, `Timeout`,
  `InternalServerError`, `ServiceUnavailableError`,
  `BadGatewayError`); replaced two `except Exception` BLOCKER B3
  sites with the typed exception hierarchy; emits structured events
  for every state transition with `run_id` correlation across success,
  failure, retry, and batch-summary events. Air-gap policy violations
  (`OfflineViolationError`) propagate unchanged.
- `explain/generator.py`: same hardening pattern as
  `risk_statements/generator.py` — structured logger, `@with_retry`
  via `build_retrying`, typed exception hierarchy
  (`ExplainError`/`ExplainGenerationFailed`), `GenerationContext`
  attached on cache miss (cache hits preserve whatever was cached),
  structured `AI_EXPLAIN_GENERATED`/`AI_EXPLAIN_FAILED`/`AI_EXPLAIN_RETRY`/
  `AI_EXPLAIN_CACHE_HIT` events with `run_id` correlation. Closes
  the v0.7.0 BLOCKER B3 carry-over for the explain subsystem.

#### Breaking changes

- **`evidentia_core.models.risk` module is no longer re-exported from
  the `evidentia_core.models` package root.** Callers must now use
  `from evidentia_core.models.risk import RiskStatement, RiskRegister, ...`
  directly. This mirrors the v0.7.0 exclusion of
  `evidentia_core.models.finding` and is required to break a circular
  import (`risk.py` now references `evidentia_core.audit.provenance`,
  which already imports from `models.common`). All in-tree callers
  already use the direct submodule path; downstream callers using
  `from evidentia_core.models import RiskStatement` must update their
  imports.

#### Deserialization compatibility note

- v0.7.0 readers will **reject** v0.7.1 `RiskStatement` JSON because
  `EvidentiaModel` sets `extra='forbid'` and the new
  `generation_context` field is unknown to v0.7.0. This is the same
  forward-compat property that v0.7.0 introduced when adding
  `collection_context` to `SecurityFinding`. Mixed-version
  deployments must upgrade `evidentia-core` to v0.7.1 on every
  reader before v0.7.1 writers go live. v0.7.1 readers accept v0.7.0
  payloads cleanly (the optional field defaults to `None`).

## [0.7.0] - 2026-04-25

**The enterprise-grade release.** Closes all 10 BLOCKER items in
[`docs/enterprise-grade.md`](docs/enterprise-grade.md). Adds Sigstore/Rekor
signing, CycloneDX SBOM on every release, PyPI Trusted Publishers (OIDC)
with PEP 740 attestations on every wheel + sdist, OSCAL Assessment Results
schema conformance via [`compliance-trestle`](https://github.com/oscal-compass/compliance-trestle),
AWS IAM Access Analyzer + GitHub Dependabot collectors with explicit
blind-spot disclosures embedded in the AR back-matter, ECS-8.11 / NIST-AU-3 /
OpenTelemetry structured logs, and a consolidated GitHub Action at
`.github/actions/gap-analysis/`. The 6 v0.5.1 `controlbridge-*`
deprecation shims are removed at this release per the public migration
contract documented since v0.6.0.

**857 tests passing (8 skipped).** Includes 3 new trestle conformance
tests (`tests/unit/test_oscal/test_trestle_conformance.py`) that
round-trip the AR through pydantic.v1 with `Extra.forbid`, catching
unknown-field bugs that NIST's JSON Schema misses, plus 8 new
Sigstore-verify integration tests added during the pre-tag review
cycle (`tests/unit/test_oscal/test_verify.py`) that mock the Sigstore
client to exercise bundle detection, custom paths, identity policies,
warning emission, and require_signature satisfaction by either GPG
or Sigstore.

### Pre-tag review cycle (Steps 1-5)

Before v0.7.0 was tagged, a comprehensive 6-step review was run
against `main` to validate the release end-to-end. Outputs:

- **`docs/positioning-and-value.md`** — exhaustive ~12k-word synthesis
  of Evidentia's competitive positioning, intellectual ancestry, AI
  posture, industry voices to follow/cite/pitch, and 12-month
  direction. Compiled from 7 parallel research streams (commercial
  GRC vendors, OSS GRC ecosystem, regulatory + M&A signals, academic
  foundations, AI/LLM tools in GRC, named industry voices, internal
  capability inventory).
- **`docs/capability-matrix.md`** — 5 risk tiers + 5 surface tiers,
  functional + code-review + adversarial smoke tests. Surfaced 18
  bugs across 5 categorized buckets (CRITICAL all fixed, HIGH
  deferred to v0.7.1, MEDIUM fixed in same review, LOW accepted).
- **`docs/v0.7.1-plan.md`** — forward-looking plan for the AI features
  hardening + supply-chain polish minor release. 6-8 week ship target.

Critical bugs fixed during the review:

- **Inter-package version pins** were stale at `>=0.6.0,<0.7.0`
  across 5 pyproject.toml files (would have made `pip install evidentia
  ==0.7.0` resolve `evidentia-core` at 0.6.0). All bumped to
  `>=0.7.0,<0.8.0`.
- **LiteLLM** dep range tightened from `>=1.50,<2.0` to
  `>=1.83.0,<2.0` to exclude the compromised 1.82.7 / 1.82.8 versions
  from the March 24, 2026 PyPI supply chain incident.
- **Sigstore CLI integration**: added `--sign-with-sigstore`,
  `--sigstore-bundle`, `--sigstore-identity-token` to `evidentia gap
  analyze` (the library API existed but the CLI flag was missing).
- **Sigstore verification**: `verify_ar_file` now detects
  `<path>.sigstore.json` bundles and verifies them alongside GPG
  `.asc` signatures. New CLI flags `--check-sigstore`,
  `--sigstore-bundle`, `--expected-identity`, `--expected-issuer`.
  `evidentia oscal verify` rich + JSON output extended.
- **Composite action.yml** flag rename `--bundle` -> `--sigstore-bundle`
  to match the new CLI surface (the old flag would have failed at
  runtime).
- **Secret scrubber** patterns expanded to cover Slack tokens,
  Stripe API keys, Google API keys, npm tokens (in addition to the
  existing AWS / GitHub / JWT / generic password= shapes).
- **`oscal/signing.py`** logger consistency: switched from stdlib
  `logging` to the v0.7.0 ECS-8.11 structured logger to match
  `oscal/sigstore.py`. Both signing paths now emit comparable
  `evidentia.sign.*` events for SIEM ingestion.
- **README documentation accuracy**: corrected REST endpoint count
  (18 -> 26 routes across 12 router modules), workspace sub-package
  count (4 -> 5), CLI command list (added `gap diff`, `explain`,
  `collect`, `integrations`, `oscal verify`, `serve`, global flags).

### Deferred to v0.7.1 (with documented design rationale)

Bringing `evidentia-ai` (`risk_statements/` + `explain/`) up to the
v0.7.0 collector-pattern enterprise grade requires 4 design decisions
that benefit from focused thought, not rushed inclusion in this
release. See `docs/v0.7.1-plan.md` for the scope: typed exception
hierarchy + `@with_retry` + new `GenerationContext` type + 7 new
`EventAction` enum entries + 250+ lines of mocked LLM tests for
`risk_statements/`.

### Supply-chain hardening (v0.7.0)

- **Build provenance**: GitHub Actions workflow with OIDC identity, no
  long-lived publishing tokens.
- **Signed publish**: PyPI Trusted Publisher (OIDC). The legacy
  `PYPI_API_TOKEN` is removed from GitHub secrets after first OIDC
  publish.
- **Per-artifact attestations**: PEP 740 Sigstore attestations on every
  wheel + sdist, signed with the GitHub Actions OIDC identity and
  logged to the Rekor public transparency log. Verifiable via
  `pip install pypi-attestations` + `pypi-attestations verify-pypi
  --repository allenfbyrd/evidentia <file>` or
  `gh attestation verify <file> -R allenfbyrd/evidentia`.
- **Software bill of materials**: CycloneDX 1.6 SBOM generated from
  `uv.lock`, attached to every GitHub Release alongside the wheels.
- **Schema conformance**: `compliance-trestle>=4.0` round-trip in CI.
- **Evidence integrity**: SHA-256 digests + GPG signatures (air-gap)
  or Sigstore bundles (online) on every Assessment Results document.

### Removed — controlbridge shim packages (per the public contract)

The 6 v0.5.1 `controlbridge-*` deprecation shims published in v0.6.0
are removed from the workspace at v0.7.0 per the public migration
contract documented in README.md, RENAMED.md, and CHANGELOG.md. The
v0.5.1 shim wheels remain on PyPI for installed users (manually yanked
at the v0.7.0 ship); future builds no longer produce shim wheels.

Removed:

- `packages/shim-controlbridge/`
- `packages/shim-controlbridge-core/`
- `packages/shim-controlbridge-collectors/`
- `packages/shim-controlbridge-ai/`
- `packages/shim-controlbridge-api/`
- `packages/shim-controlbridge-integrations/`
- `tests/unit/test_rename_shims.py`

`scripts/_create_shim_packages.py` is retained for historical reference
only with a deprecation header.

### Added — Composite GitHub Action consolidation

The legacy standalone `allenfbyrd/evidentia-action` repo is archived
in favor of a composite action at `.github/actions/gap-analysis/`.
External users invoke as:

```yaml
- uses: allenfbyrd/evidentia/.github/actions/gap-analysis@v0
  with:
    inventory: inventory.yaml
    frameworks: nist-800-53-rev5-moderate,soc2-tsc
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

Surface: install evidentia-core from PyPI -> run `evidentia gap analyze`
against the user's inventory -> restore base-branch baseline from
actions/cache (cache key includes `hashFiles(inventory)`) -> run
`evidentia gap diff` -> post sticky PR comment via
`marocchino/sticky-pull-request-comment@v2` -> gate merge on
regressions when `fail-on-regression: true`. Optional OSCAL AR JSON
output and Sigstore signing of the AR via the workflow's ambient OIDC
identity (requires `id-token: write`).

See [`.github/actions/gap-analysis/README.md`](.github/actions/gap-analysis/README.md)
for the full input/output surface, SHA-pinned variant for audit
pipelines, and migration guide from `evidentia-action@v1`.

### Added — Evidence chain of custody (v0.7.0 scope)

Originally planned for v0.6.0, displaced by the rename release. Every
OSCAL Assessment Results export can now carry cryptographic proof of its
evidence payload and an optional GPG signature of the document itself.

#### Exporter (`evidentia_core.oscal.exporter`)

`gap_report_to_oscal_ar(report, *, findings=None)` now accepts an optional
list of `SecurityFinding` objects. When supplied:

- Each finding is serialised to canonical JSON (sorted keys, no whitespace),
  SHA-256 digested, and embedded in `back-matter.resources[]` with
  base64-encoded content — making the AR self-contained for later
  verification with no external files required.
- The digest is stored in two places: the OSCAL-standard
  `rlinks[].hashes[]` field (`{algorithm: "SHA-256", value: "<hex>"}`)
  and an Evidentia-namespaced prop `evidence-digest` under
  `https://evidentia.dev/oscal` (value formatted as `sha256:<hex>`).
- Observations whose `control-id` prop matches a finding's `control_ids`
  get a `relevant-evidence[]` cross-reference to the resource UUID, and
  their `methods` flips from `["EXAMINE"]` to `["TEST"]` (automated
  finding, not manual examination).

Back-compat: omitting `findings=` produces the exact same AR shape as
pre-v0.7.0 — the `back-matter` block is only emitted when there are
resources to include.

#### Digest primitives (`evidentia_core.oscal.digest`)

- `digest_bytes` / `digest_file` / `digest_model` / `digest_json` — pure,
  deterministic SHA-256 helpers. `digest_model` uses Pydantic's
  `model_dump(mode="json")` plus `sort_keys=True` so two callers with
  the same input produce bit-for-bit identical hashes.
- `format_digest` / `parse_digest` — wrap and unwrap the
  `"sha256:<hex>"` OSCAL prop convention.
- `verify_bytes` / `verify_file` — compare a payload against an
  expected prop value.

#### GPG signing (`evidentia_core.oscal.signing`)

Subprocess-based wrapper around `gpg` (no new Python dependency):

- `sign_file(path, *, key_id, signature_path=None, gnupghome=None)` —
  produces an ASCII-armored detached signature at `<path>.asc` by default.
- `verify_file(path, *, signature_path=None, gnupghome=None)` — returns
  a `VerifyResult` with `valid`, `signer_key_id`, and
  `signer_fingerprint`. Signature *mismatches* return
  `valid=False` rather than raising — infrastructure errors (missing
  files, GnuPG not installed) raise `GPGError` subclasses so the two
  failure modes are distinguishable.
- `gpg_available()` — returns True iff the `gpg` binary is on PATH.
  Callers should probe this before adding sign/verify buttons in UI.

Uses `--batch`, `--pinentry-mode loopback`, `--local-user`, and
`--status-fd 1` so all invocations are non-interactive and emit
machine-readable status output. `GNUPGHOME` overrides let callers
point at a CI-scoped keyring without touching the operator's default
`~/.gnupg`.

#### Verification orchestrator (`evidentia_core.oscal.verify`)

`verify_ar_file(path, *, require_signature=False, ...)` ties the two
checks together:

1. Re-hash every embedded evidence resource and compare to stored digests.
2. If `<path>.asc` exists (or `require_signature=True` and it's missing),
   run the signature check.

Returns a `VerifyReport` with per-resource `digest_checks` and an
`overall_valid` boolean. Missing signature counts as `None` (not
checked) unless `require_signature=True`.

#### CLI

- `evidentia gap analyze` grows two flags:
  - `--findings <path>` — embed collector output in the AR with digests
  - `--sign-with-gpg <key-id>` — write a detached signature alongside
    the AR JSON
- New subcommand tree `evidentia oscal`:
  - `evidentia oscal verify <path>` — check digests + optional
    signature. Exits 0 on pass, 1 on fail. `--require-signature`,
    `--signature`, `--gnupghome`, and `--json` options.

#### Testing

- New test modules: `test_oscal/test_digest.py` (22 tests), `test_verify.py`
  (10 tests), `test_signing.py` (7 GPG round-trip tests). Signing tests
  skip gracefully via `@pytest.mark.skipif(not gpg_available())` so CI
  matrices without GnuPG still pass.
- `test_exporter.py` extended with 7 new tests pinning the v0.7.0
  evidence-embedding shape (back-matter resources, digest prop values,
  observation cross-references, method-flip behaviour).

### Changed

- Project-folder rename (development-only, not a user-visible change):
  the repository moved from `.../Claude Code/ControlBridge/` to
  `.../Claude Code/Evidentia/`. All imports, editable-install pointers,
  and bytecode caches refreshed accordingly. Bundled Vite SPA
  (`packages/evidentia-api/src/evidentia_api/static/`) rebuilt from the
  already-renamed source so the browser tab title matches the CLI.
- README status badge dropped "Phase 1 MVP" (stale since v0.2). README
  Roadmap section re-grouped into Shipped / Next / Later buckets.
  `docs/ROADMAP.md` bumped to v0.6.0 stamp; v0.5.1 reclassified as the
  deprecation-shim release; v0.6.0 reclassified as the rename release;
  Evidence chain of custody content moved to v0.7.0.

### Fixed

- Two pre-existing `mypy --strict` errors in
  `packages/evidentia-ai/src/evidentia_ai/client.py` — added `cast()`
  around `instructor.from_litellm()` so the declared `Instructor` /
  `AsyncInstructor` return types propagate under strict type-checking.

### Added — Enterprise-grade audit + compliance infrastructure (v0.7.0 scope)

Second v0.7.0 batch, targeting the enterprise-grade checklist (Big-4
audit firm, FedRAMP 3PAO adoption bar).

#### Audit module (`evidentia_core.audit`)

Four new modules power the enterprise-grade audit trail:

- `events.py` — curated `EventAction` catalog: 30 action values across
  collect / auth / config / sign / verify / manifest namespaces. Plus
  ECS enums (`EventCategory`, `EventType`, `EventOutcome`).
- `logger.py` — ECS 8.11 JSON logger with NIST SP 800-53 Rev 5 AU-3
  content coverage (what / when / where / source / outcome / identity)
  + OpenTelemetry trace correlation (`trace.id` = run_id). Secret
  scrubber for AWS access keys, GitHub tokens, JWTs, generic
  password/token patterns. Third-party log record fallback. Rich
  console (default) and JSON (opt-in) output modes.
- `retry.py` — `@with_retry` decorator built on tenacity with
  exponential backoff + jitter. Emits `evidentia.collect.retry`
  events on every attempt. Zero-backoff under `EVIDENTIA_TEST_MODE=1`.
- `provenance.py` — `CollectionContext` (per-finding provenance),
  `CollectionManifest` (per-run completeness attestation),
  `PaginationContext`, `CoverageCount`, `new_run_id()` (ULID).

CLI: global `--json-logs` flag switches all logging to ECS JSON for
SIEM ingestion. Works with Splunk / Elastic / Datadog / Sumo Logic /
Microsoft Sentinel without custom parsers.

New deps: `tenacity>=9.0`, `python-ulid>=3.0`. Both small.

#### OLIR (NIST relationship typing) on control mappings

`evidentia_core.models.common.OLIRRelationship` — all six values from
NIST OLIR Derived Relationship Mapping vocabulary (`equivalent-to`,
`equal-to`, `subset-of`, `superset-of`, `intersects-with`, `related-to`).

`ControlMapping` extended with `relationship` (default `RELATED_TO`)
and `justification` (default empty, max 1024 chars). Pre-v0.7.0
callers that construct `ControlMapping(framework, control_id)` continue
to work without changes.

`aws/mapping.py` — 27 Config rules and 25 Security Hub controls
classified with authoritative per-entry OLIR relationships + FSBP/CIS
citations. Security Hub entries use `SUBSET_OF` (per AWS's own
"Related requirements" field as the authoritative subset claim);
Config rules use a mix of `SUBSET_OF` and `INTERSECTS_WITH` per rule
semantics. Added `map_config_rule_to_control_mappings` and
`map_security_hub_control_to_control_mappings` functions.

#### SecurityFinding schema migration

`evidentia_core.models.finding.SecurityFinding`:

- `control_mappings: list[ControlMapping]` replaces
  `control_ids: list[str]`. A `@model_validator` accepts the old
  `control_ids=[...]` kwarg at construction and auto-converts to
  `RELATED_TO`-typed ControlMappings with "Pre-v0.7.0 mapping"
  justification. A `.control_ids` property preserves read compat.
- New `collection_context: CollectionContext` field; defaults to a
  synthetic `"legacy-pre-v0.7.0"` placeholder so pre-v0.7.0 callers
  keep working. Upgraded collectors pass real context.

`models/migrations/v0_6_to_v0_7.py` — read-only JSON migration helper
that detects legacy finding shapes and synthesizes v0.7.0 fields,
emitting a WARN-level log event for audit visibility.

#### Sigstore / Rekor signing

New `evidentia_core.oscal.sigstore` (opt-in via
`pip install 'evidentia-core[sigstore]'`):

- Keyless signing via Fulcio + Rekor — the bundle
  (`<artifact>.sigstore.json`) carries cert, signature, and Rekor
  inclusion proof in one file.
- Four typed error classes: `SigstoreNotAvailableError` (lib missing),
  `SigstoreAirGapError` (offline refusal), `SigstoreSigningError`,
  `SigstoreVerifyError`.
- Air-gap mode refuses Sigstore before any network IO and points
  operators at GPG for offline deployments.
- Additive to GPG, not replacement. Both can coexist on the same AR
  artifact for defence-in-depth.

`export_report()` grows `sign_with_sigstore=True` + optional
`sigstore_identity_token` to thread Sigstore signing through the
OSCAL AR export path.

#### Collector hardening (AWS Config + Security Hub + GitHub branch
protection)

- `aws/collector.py`: bare `except Exception` replaced with typed
  catches emitting discrete ECS events. `@with_retry` wraps the
  STS `GetCallerIdentity` call. New `collect_all_v2()` returns
  `(findings, manifest)`. Every SecurityFinding carries a real
  CollectionContext with the STS caller ARN + account:region.
  `collect_all()` keeps the v0.6 signature; adds `dry_run=True`.
  Security Hub findings with `Compliance.RelatedRequirements`
  referring to NIST 800-53 get promoted to `SUBSET_OF` mappings
  with justification citing AWS's native mapping.
- `github/collector.py`: 9 inline `control_ids=[...]` call sites
  migrated to OLIR-typed `ControlMapping` tables at module scope.
  Every finding carries a CollectionContext. New `collect_v2()`
  returns `(findings, manifest)` with coverage counts. `dry_run=True`
  flag added to `collect()`.

#### New collectors (v0.7.0 greenfield)

- **AWS IAM Access Analyzer**
  (`evidentia_collectors.aws.AccessAnalyzerCollector`) — supports
  ExternalAccess, UnusedIAMRole, UnusedIAMUser\*Credential,
  UnusedPermission, and Policy Validation finding types. Each type
  has a curated OLIR-typed mapping to AC-2 / AC-3 / AC-4 / AC-5 /
  AC-6 / AC-6(1) / IA-2 / IA-5(1) / SC-7 with authoritative
  justifications. **Five blind-spot disclosures** (KMS grant chains,
  S3 ACLs vs Block Public Access, service-linked role exclusion,
  unsupported resource types, finding-generation latency) are
  emitted as manifest warnings — the OSCAL exporter will promote
  them to back-matter `class="blind-spot"` resources in a future
  v0.7.x so auditors see the limits of coverage inline (Q7=Yes).
- **GitHub Dependabot alerts**
  (`evidentia_collectors.github.DependabotCollector`) — full state
  coverage (open / fixed / dismissed / auto_dismissed) with
  policy-driven dismissal handling (Tier 3): `no_bandwidth` and
  `tolerable_risk` default to ACTIVE (auditor-surfaced gaps);
  `fix_started`, `inaccurate`, `not_used` default to RESOLVED.
  Operators override via `DismissalVerdict` policy dict. Seven
  control mappings per alert (SI-2, SI-5, RA-5, SR-3, SR-11, plus
  SSDF PO.3 / PW.4 / RV.2 with GitHub Well-Architected as the
  authoritative citation source).

#### Structured logging schema (`docs/log-schema.md`)

New reference doc describing the ECS 8.11 + NIST AU-3 + OpenTelemetry
field conventions used by the audit logger. Includes the EventAction
catalog and example log records.

#### Enterprise-grade credibility checklist (`docs/enterprise-grade.md`)

30-item checklist synthesized from AWS Audit Manager, AWS Security Hub,
FedRAMP Rev 5, NIST SP 800-53 AU-3, SSAE 18, AICPA TSP, and GitHub
SSDF references. Each item tagged BLOCKER / HIGH / MEDIUM / LOW with
the Evidentia v0.7.0 implementation status.

#### CycloneDX SBOM on release (Q2=A)

Release workflow now generates a CycloneDX 1.6 JSON SBOM via
`cyclonedx-bom` and attaches it to the GitHub Release alongside the
wheel artifacts. Addresses checklist item H2 (SLSA L2+/SBOM).

#### Testing

Total suite: **862 passed, 8 skipped** (up from 657 baseline at
`e6dc94d`, +205 new tests). mypy clean across 96 source files.
ruff clean.

New test modules:

- `tests/unit/test_audit/` — 79 tests (events vocabulary, ECS
  record shape, retry semantics, provenance roundtrip).
- `tests/unit/test_models/test_olir_and_finding_schema.py` — 20
  tests (OLIR enum, ControlMapping backward compat, SecurityFinding
  control_ids kwarg shim, migration shim).
- `tests/unit/test_collectors/test_aws_olir_mappings.py` — 31 tests
  (every Config rule + every Security Hub control classified).
- `tests/unit/test_oscal/test_sigstore.py` — 10 tests (structural +
  CI-gated sign/verify integration per Q5=A).
- `tests/unit/test_collectors/test_access_analyzer.py` — 23 tests.
- `tests/unit/test_collectors/test_dependabot.py` — 34 tests.

## [0.6.0] - 2026-04-22

### Renamed from ControlBridge to Evidentia

This release is a **project rename** with no functional changes. Every
feature, CLI command, API route, and test from v0.5.0 works identically
under the new name. Only naming changes.

#### Why

The ControlBridge name collided with [controlbridge.ai](https://www.controlbridge.ai/),
a live commercial SOX 302/404 compliance platform for internal audit and
finance teams. The markets overlap directly (GRC / compliance automation,
CFO / audit-committee buyers), so continuing to use the identical name
created trademark, SEO, and buyer-confusion risks. v0.5.0 shipped days
ago with ~0 external users, so the remediation window is at its minimum.
See [RENAMED.md](RENAMED.md) for the full background.

#### What changed

- **PyPI package names:**
  - `controlbridge` → `evidentia`
  - `controlbridge-core` → `evidentia-core`
  - `controlbridge-ai` → `evidentia-ai`
  - `controlbridge-api` → `evidentia-api`
  - `controlbridge-collectors` → `evidentia-collectors`
  - `controlbridge-integrations` → `evidentia-integrations`
- **Python module names:** `controlbridge_*` → `evidentia_*` (same pattern).
- **CLI entry point:** `controlbridge` → `evidentia`. The `cb` short alias
  remains unchanged under the new `evidentia` package.
- **Frontend npm scope:** `@controlbridge/ui` → `@evidentia/ui`.
- **GitHub repositories:**
  - `allenfbyrd/controlbridge` → `allenfbyrd/evidentia`
  - `allenfbyrd/controlbridge-action` → `allenfbyrd/evidentia-action`
  - Both redirects are permanent (GitHub's built-in rename mechanism).
  - Old URLs printed on resumes, blog posts, and chat logs continue to work.
- **Config file name:** user-project `controlbridge.yaml` → `evidentia.yaml`.
  The bootstrap wizard + `evidentia init` generate the new name; the
  `.gitignore` keeps `controlbridge.yaml` ignored for migration compatibility.

#### Migration

Install the replacements:

```bash
pip install evidentia                    # CLI + library
pip install "evidentia[gui]"             # + web UI server
```

Rewrite imports:

```python
# before
from controlbridge_core.models.gap import Gap

# after
from evidentia_core.models.gap import Gap
```

If you can't migrate in one shot, the six old PyPI names stay installable
as **v0.5.1 transitional shims**. Each emits a `DeprecationWarning` on
import and forwards every attribute + submodule to the new `evidentia-*`
equivalents via `sys.modules` aliasing:

```bash
pip install controlbridge-core==0.5.1   # works; emits deprecation warning
```

Deep imports like `from controlbridge_core.models.common import EvidentiaModel`
continue to resolve to the same object as `from evidentia_core.models.common
import EvidentiaModel`. The CLI entry `controlbridge` remains available via
the shim and delegates to the new `evidentia` app.

**The shims will be yanked in v0.7.0** (~October 2026). Please migrate
within six months.

#### Added

- `packages/shim-controlbridge{,-core,-ai,-api,-collectors,-integrations}/`
  — six transitional re-export packages.
- `RENAMED.md` at repo root — canonical rename-rationale document indexed
  by Google for users searching "ControlBridge".
- `tests/unit/test_rename_shims.py` — 16 parametrised tests guarding the
  shims' DeprecationWarning + submodule-aliasing + CLI-entry-point
  behaviour until v0.7.0.
- `scripts/_rename_content.py`, `scripts/_bump_version.py`,
  `scripts/_create_shim_packages.py` — one-shot rename tooling, retained
  as historical reference for anyone auditing the rename diff.

#### Changed

- All 7 `pyproject.toml` files version-bumped `0.5.0` → `0.6.0`; inter-package
  dependency pins widened from `>=0.5.0,<0.6.0` to `>=0.6.0,<0.7.0`.
- All 7 workspace package directories renamed via `git mv`
  (history preserved).
- All 6 Python module directories (`src/controlbridge_*` → `src/evidentia_*`)
  renamed via `git mv`.
- 2,094 mechanical string replacements across 203 tracked files (lowercase,
  title-case, and uppercase variants of "controlbridge"/"ControlBridge"/
  "CONTROLBRIDGE").
- `uv.lock` + `packages/evidentia-ui/package-lock.json` regenerated from
  scratch.
- README.md gets a "Renamed from ControlBridge" banner at the very top
  so visitors arriving via GitHub's redirect understand continuity.

#### Shipped as

- 6 × `evidentia-*` wheels @ v0.6.0 (primary)
- 6 × `controlbridge-*` shim wheels @ v0.5.1 (transitional, removed v0.7.0)

## [0.5.0] - 2026-04-20

The **"Phase 2 integrations"** release. Evidentia finally wires the
long-advertised `evidentia-integrations` and `evidentia-collectors`
packages with real implementations: push gaps as Jira issues,
bidirectionally sync status, and auto-collect evidence from AWS +
GitHub. Maps every collected finding to NIST 800-53 control families.

Also extends strict mypy to the two formerly-empty shells and adds
boto3 + moto to dev deps so collector tests run out of the box.

### Added — Jira output integration

New: `pip install "evidentia-integrations"` (no extra needed — the
bundled implementation uses httpx directly rather than the heavyweight
`jira` SDK).

- **`evidentia_integrations.jira.JiraClient`** — httpx-based
  REST v3 client with `test_connection`, `create_issue`, `get_issue`,
  `list_transitions`, `transition_issue`. Secret-safe: API tokens flow
  only through HTTP basic-auth; never logged, never in response bodies.
- **`evidentia_integrations.jira.mapper`** — pure functions mapping
  ControlGap <-> Jira issue body + GapStatus <-> Jira workflow name.
  Forward mapping covers all five `GapStatus` enum values; reverse
  mapping covers the default Jira Cloud workflow plus common custom
  statuses (Blocked, In Review, Reopened, Won't Fix, WontFix, etc.).
- **`push_gap_to_jira`, `sync_gap_from_jira`** — gap-level helpers that
  combine client + mapper. Mutate `gap.jira_issue_key` on create;
  update `gap.status` + `gap.remediated_at` on sync. Return typed
  `JiraSyncOutcome` entries so CLI / API callers can render per-gap
  results without a second pass.
- **`push_open_gaps`, `sync_report`** — batch wrappers over a
  `GapAnalysisReport` with severity-filter + max-issues safety rail.
- **CLI**: `evidentia integrations jira {test,push,sync,status-map}`
- **REST API**:
  - `GET /api/integrations/jira/status` — connection probe (never returns token)
  - `GET /api/integrations/jira/status-map` — current mapping for UI
  - `POST /api/integrations/jira/push/{report_key}` — batch push
  - `POST /api/integrations/jira/sync/{report_key}` — batch sync

Credentials: `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_API_TOKEN`,
`JIRA_PROJECT_KEY`, `JIRA_ISSUE_TYPE` env vars.

### Added — AWS evidence collector

New: `pip install "evidentia-collectors[aws]"` (adds `boto3`).

- **`evidentia_collectors.aws.AwsCollector`** — orchestrator for
  Config + Security Hub with per-subsystem `collect_*` methods +
  `collect_all()`. Sub-collector failures are swallowed + logged so one
  bad service doesn't drop the other's findings.
- **AWS Config collector** — iterates `describe_compliance_by_config_rule`,
  then expands each non-compliant rule via
  `get_compliance_details_by_config_rule`. One SecurityFinding per
  non-compliant resource.
- **Security Hub collector** — batches `get_findings` with workflow/state
  filters. Prefers `Compliance.RelatedRequirements` for NIST 800-53 IDs
  when present (direct AWS attribution); falls back to the curated
  mapping table otherwise.
- **Control mapping** — `map_config_rule_to_controls` + `map_security_hub_control_to_controls`
  with 25+ rule/control entries covering AC/IA/SC/AU/CM/CP/SI families.
  Rule-name normalizer handles hyphenated + camelCase + underscored
  forms consistently.
- Credentials via standard boto3 chain (env / ~/.aws / instance profile).

### Added — GitHub evidence collector

New: ships in the base `evidentia-collectors` package — zero extra
deps needed (uses httpx directly; `[github]` extra remains for users
who want pygithub for custom workflows).

- **`evidentia_collectors.github.GitHubCollector`** — collects from
  a single repo: visibility, default-branch protection state, CODEOWNERS
  presence at any of three canonical paths.
- Emits findings for both compliance (PR review required, status checks
  configured, admins enforced, CODEOWNERS present — all INFORMATIONAL /
  RESOLVED) and non-compliance (unprotected default branch, missing
  CODEOWNERS, public repo — HIGH / MEDIUM / ACTIVE).
- Control mapping: SA-11 (developer security testing), CM-2/CM-3
  (baseline/change), AC-3/AC-6 (access enforcement), SI-2 (flaw
  remediation).
- Credential: `GITHUB_TOKEN` env var (personal access token or Actions
  workflow token). Public repos work unauthenticated.

### Added — collector CLI + REST API

- **CLI**: `evidentia collect {aws,github}` — writes findings as
  JSON to `--output` (default stdout) + prints a Rich summary table
  broken down by severity + source.
- **REST API**:
  - `GET /api/collectors/status` — which collectors are installed +
    whether `GITHUB_TOKEN` is set (never returns token value).
  - `POST /api/collectors/aws/collect` — run AWS collector with
    optional region/profile/subsystem flags.
  - `POST /api/collectors/github/collect` — run GitHub collector;
    request body: `{repo: "owner/repo"}`.

### Added — dev deps

- `boto3>=1.35` + `moto[all]>=5.0` in the workspace dev group so
  collector tests run without any extra install step.

### Changed

- **CI mypy target** extended from 3 packages to all 5 Python packages.
  `evidentia-integrations` and `evidentia-collectors` now
  enforce `--strict-optional` on every commit.
- **Roadmap**: v0.5.0 shipped Jira + AWS + GitHub. Okta / ServiceNow /
  Vanta / Drata shifted to v0.5.1. Evidence chain of custody still
  targets v0.6.0.

### Tests: 501 → **604 passing** (+103)

- +43 Jira mapper / client unit tests (httpx.MockTransport-backed)
- +14 Jira sync helper tests (fake JiraClient via MagicMock)
- +8 Jira REST-endpoint integration tests (TestClient)
- +22 AWS collector tests (MagicMock paginators + curated mapping)
- +12 GitHub collector tests (httpx.MockTransport)
- +4 collector REST-endpoint tests

Frontend test count unchanged (6 Vitest).

### Migration

None — v0.5.0 is a strict feature add. Inter-package pins bump from
`>=0.4.0,<0.5.0` to `>=0.5.0,<0.6.0` across every package; existing
v0.4.x installs need to upgrade all six packages in lockstep (which
`pip install --upgrade evidentia` does automatically).

## [0.4.1] - 2026-04-19

Completes the v0.4.0 "Accessible GRC" release — adds every interactive
page the v0.4.0-alpha.1 backend exposed over REST. Non-technical users
can now run gap analysis, diff reports, generate risks, and edit
configuration entirely in the browser without ever touching the CLI.

Also ships the reusable GitHub Action as a separately-published repo
(`allenfbyrd/evidentia-action@v1`) and fixes three mypy regressions
that slipped into `evidentia-api` routers on the alpha.1 release.

### Added — interactive web UI

- **Three-path onboarding wizard on Home page** (Zustand state machine):
  - "Try sample data" — guides through the Meridian v2 walkthrough
  - "Upload inventory" — drag-drop file picker, auto-detects format
  - "Start from scratch" — 4-question wizard (industry / hosting /
    data types / regulatory) -> POST /api/init/wizard -> previews
    all three generated YAMLs with copy-to-clipboard
- **Gap Analyze page** — framework multi-select (89 catalogs filterable),
  file upload OR server-side path, organization / system_name overrides,
  run button -> TanStack Table with sortable columns + global filter +
  severity/effort/priority badges.
- **Gap Diff page** — two-report picker from gap store, summary cards
  (opened / closed / severity↑ / severity↓ / unchanged), regression
  alert, filterable per-entry table. Matches the CLI's `gap diff`
  output exactly.
- **Risk Generate page** — SSE-streamed per-gap progress. POSTs to
  `/api/risk/generate` and reads the `text/event-stream` response via
  `ReadableStream` + `TextDecoder`, parsing each `data: {...}` frame
  into a progress row. Supports cancel mid-stream; fails cleanly on
  offline-mode violations.
- **Settings edit form** — validated PUT to `/api/config`. Writes
  `evidentia.yaml` server-side; CLI + GUI both pick up changes.
  LLM-provider and air-gap sections stay read-only (env-var sourced).

### Added — separate reusable GitHub Action

- New repo: [`allenfbyrd/evidentia-action`](https://github.com/allenfbyrd/evidentia-action)
  at v1.0.0 + floating `v1` pointer. One-line replacement for the
  80-line drop-in workflow template from v0.3.0:
  `uses: allenfbyrd/evidentia-action@v1`.
- Shipped from `scripts/evidentia-action-skeleton/` which remains
  as the authoritative source for the action's files; future changes
  propagate via `cp -r` + tag.

### Added — shadcn/ui primitives

- `input.tsx`, `label.tsx`, `textarea.tsx`, `switch.tsx`, `tabs.tsx`,
  `alert.tsx`, `progress.tsx` — Radix-based, matching shadcn New York
  preset. WCAG 2.1 AA via underlying Radix primitives.

### Added — Vitest coverage

- `src/lib/utils.test.ts` — `cn()` behavior (Tailwind merge, falsy
  filtering, object syntax)
- `src/lib/severity.test.ts` — severity-rank ordering + badge mapping

Frontend CI now runs 6 passing tests. Deeper component coverage
queued for v0.4.2.

### Fixed

- **Three mypy regressions in evidentia-api routers** (caught by
  the `typecheck` job on CI, not reproduced locally until now):
  - `routers/gaps.py`: `valid` helper missing a type annotation
  - `routers/risks.py`: passed `yaml.safe_load(...)` dict where
    `RiskStatementGenerator.generate_async` expected a typed
    `SystemContext` — now loads via `SystemContext.from_yaml(path)`
    and emits a clear SSE error if no context file is provided.
  - `routers/explain.py`: called non-existent `gen.explain(...)` —
    actual method is `generate(control, framework_id, refresh)`.

### Tests: 501 passing (unchanged)

Frontend: +6 Vitest tests. Backend: unchanged at 501 pytest (mypy
regressions were caught at CI-time, not via tests).

### Migration

None — v0.4.1 is a strict feature add on top of v0.4.0. Inter-package
pins stay at `>=0.4.0,<0.5.0`.

## [0.4.0-alpha.1] - 2026-04-19

The **"Accessible GRC"** release — Evidentia grows beyond the CLI.
Adds a FastAPI REST server, a React + shadcn/ui web UI (localhost-only,
WCAG 2.1 AA via Radix primitives), an air-gapped mode (`--offline`
flag + `doctor --check-air-gap` validator), and a new sixth workspace
package (`evidentia-api`). The web UI is installable via the new
`[gui]` extra: `pip install "evidentia[gui]"` then
`evidentia serve`.

This `alpha.1` ships the backend end-to-end + the read-only web UI
surface (Home / Dashboard / Frameworks / Settings). Interactive pages
(onboarding wizard, Gap Analyze form, Gap Diff picker, Risk Generate
streaming) land in `alpha.2`. The full `v0.4.0` release is gated on
Playwright E2E coverage and a fresh-venv smoke test on
Windows/macOS/Linux.

### Added

- **New workspace package `evidentia-api`** (`packages/evidentia-api/`)
  shipping a FastAPI app with 18 endpoints under `/api/*`. The `[gui]`
  optional extra on the meta-package pulls it in:
  `pip install "evidentia[gui]"`.
- **New CLI subcommand `evidentia serve`** — launches uvicorn serving
  both the REST API and the bundled React SPA from `127.0.0.1:8000`
  (localhost-only by default; `--host 0.0.0.0` emits a security warning).
  Flags: `--port`, `--host`, `--dev` (permissive CORS for Vite HMR),
  `--no-browser`, `--reload`.
- **Global `--offline` flag on every command.** Wires through to the new
  `evidentia_core.network_guard` module; when set, any attempted LLM
  or network call to a non-loopback / non-RFC-1918 host raises
  `OfflineViolationError` before network IO is issued. Works with Ollama
  (localhost:11434), vLLM, and custom OpenAI-compatible endpoints on
  private IPs.
- **`evidentia doctor --check-air-gap`** — per-subsystem posture
  report (LLM client, catalog loader, AI telemetry, gap store, web UI).
  Renders as a Rich table in the CLI and as JSON via
  `POST /api/doctor/check-air-gap`.
- **Web UI pages (v0.4.0-alpha.1 scope):**
  - `/` — Home / quick-nav cards to Frameworks, Dashboard, Settings
  - `/dashboard` — historical gap reports + top-line metrics
  - `/frameworks` — 82-framework browser with tier / category / free-text filters
  - `/frameworks/:id` — framework detail with full control list
  - `/settings` — config view + LLM-provider presence + air-gap posture
- **18 REST endpoints under `/api/*`:** health, version, config (GET/PUT),
  doctor (GET, `/check-air-gap`), llm-status (presence only — never
  returns key values), frameworks (list, detail, single-control), gaps
  (analyze, reports list, single-report, diff), risks (`/generate` SSE),
  explain (`/{framework}/{control_id}` SSE), init-wizard.
- **Shared `evidentia_core.init_wizard` module** — starter YAML
  generators + deterministic framework recommender. The CLI
  `evidentia init` and GUI `/api/init/wizard` endpoint now produce
  identical files from the same code path. Presets:
  `soc2-starter`, `nist-moderate-starter`, `hipaa-starter`,
  `cmmc-starter`, `empty`.
- **`evidentia_core.config`** moved from the CLI meta-package
  (`evidentia.config`) into `evidentia-core` so both the CLI
  and the API backend consume it without a circular dependency. A
  transparent re-export shim at the old location keeps existing
  `from evidentia.config import ...` imports working unchanged.
- **Hatchling build hook** (`packages/evidentia-api/hatch_build.py`)
  that drives `npm run build` in `packages/evidentia-ui/` and copies
  `dist/*` into the Python package's `static/` directory before wheel
  assembly. Set `EVIDENTIA_SKIP_FRONTEND_BUILD=1` to bypass for
  Python-only build matrices.
- **New workspace directory `packages/evidentia-ui/`** — Vite + React
  + TypeScript + shadcn/ui frontend. Not a Python workspace member;
  builds via `npm run build`. Stack: React 18, Vite 5, Tailwind CSS,
  shadcn/ui (Radix primitives), TanStack Query / Table / Virtual,
  React Router 6, Zustand, React Hook Form + Zod, Recharts.

### Changed

- **Roadmap shuffle (`docs/ROADMAP.md`):** GUI pulled forward from v0.6.0
  to v0.4.0; `--offline` flag pulled forward from v0.5.0 to v0.4.0;
  Phase 2 integrations (Jira, AWS, GitHub, Okta, ServiceNow, Vanta,
  Drata) shifted right to v0.5.0; evidence chain of custody (SHA-256 +
  GPG) shifted right to v0.6.0. See roadmap for the full shape.
- **`evidentia_ai.client.get_instructor_client`** now wraps
  `litellm.completion` / `acompletion` with an offline guard. When
  offline mode is on, cloud LLM calls raise
  `OfflineViolationError` before any network IO.
- **Meta-package `evidentia` deps:** removed `fastapi>=0.115`,
  `uvicorn[standard]>=0.30`, `python-multipart>=0.0.9` (moved to
  `evidentia-api` where they're actually used).
- **`evidentia init` defaults:** `--frameworks` now defaults to
  `nist-800-53-rev5-moderate,soc2-tsc` (was
  `nist-800-53-mod,soc2-tsc`); new `--preset` flag accepts the five
  wizard presets above; new `--organization` flag for headless use.
- **CI test workflow** (`.github/workflows/test.yml`): new `frontend-test`
  job runs TypeScript typecheck + Vite build on Node 20; existing mypy
  target list extended to include `evidentia-api`.
- **CI release workflow** (`.github/workflows/release.yml`): adds Node 20
  setup + SPA-bundled-in-wheel verification step before PyPI publish.

### Fixed

- **Windows cp1252 encoding** on `evidentia --help`: the
  pre-existing `--config` help string used `\u2192` (→) which crashed
  legacy Windows consoles. Replaced with ASCII `->`. Same class of fix
  as v0.3.1's `gap diff --format console` normalization.

### Tests: 392 → **501 passing** (+109)

- `+43` from `evidentia_core.network_guard` (host classifier, URL
  guard, LLM-model guard, offline-mode toggle + context manager).
- `+30` from `evidentia_core.init_wizard` (3 YAML generators + the
  framework recommender's decision tree).
- `+36` from `evidentia-api` FastAPI TestClient coverage (basic
  endpoints, frameworks browser, config read/write, init-wizard,
  gap analyze/reports/diff, SSE endpoint validation, OpenAPI schema).

### Migration

- **Library users importing `evidentia.config`**: no change needed
  (shim re-export). For new code, prefer the canonical
  `evidentia_core.config` import.
- **Users of `evidentia init`**: default framework list changed
  from the legacy 16-control NIST sample to the full Rev 5 Moderate
  baseline; supply `--frameworks nist-800-53-mod,soc2-tsc` to keep the
  old behavior.
- **CI consumers building from source**: install Node 20+ in the
  environment (or set `EVIDENTIA_SKIP_FRONTEND_BUILD=1` when Node
  is unavailable; the wheel will serve a dev-placeholder page in lieu
  of the SPA).

## [0.3.1] - 2026-04-19

Comprehensive examples + dogfooded GitHub Action + one latent-bug fix
surfaced by the new integration tests. No new features, no breaking
API changes; scope is "prove every v0.3.0 feature works end-to-end
against realistic data."

### Added — three realistic end-to-end scenarios

- **`examples/meridian-fintech-v2/`** — 48-control inventory against
  `nist-800-53-rev5-moderate` + `soc2-tsc` + `eu-gdpr`. Baseline
  (`my-controls.yaml`) + PR branch (`my-controls-pr.yaml`) engineered
  to produce every `gap diff` classification (opened + closed +
  severity_increased + severity_decreased + unchanged). Ships with
  pre-generated `snapshots/baseline.json` + `snapshots/pr-branch.json`
  + `snapshots/pr-diff.md` for zero-setup demo. Uses the v0.2.1
  `evidentia.yaml` schema (flat `frameworks:`, `llm.model`,
  `organization`, `system_name`). Mixes NIST-pub (`AC-2(1)`) and
  NIST-OSCAL (`ac-2.3`) ID conventions to exercise the normalizer.
  `user-catalog-demo/soc2-tsc-licensed.json` is a fake "licensed
  AICPA copy" fixture for the `catalog import` shadow-precedence
  demo.

- **`examples/acme-healthtech/`** — 34-control HIPAA-covered-entity
  scenario. Frameworks: `hipaa-security` + `hipaa-privacy` +
  `hipaa-breach` + `nist-800-53-rev5-moderate`. Showcases HIPAA's
  `164.308(a)(1)(i)` dotted-section ID style and multi-rule cross-
  framework efficiency where one control satisfies 3–4 frameworks.

- **`examples/dod-contractor/`** — 30-control CMMC Level 2 +
  NIST 800-171 Rev 2 scenario for DoD-contract workflows. Uses
  `CMMC.L2-3.1.1`-style prefixed IDs alongside plain `3.1.1`
  dotted IDs to exercise both conventions in one report. Includes
  a realistic DIBCAC-style gap (SIEM correlation missing).

- **`examples/WALKTHROUGH.md`** — tour document with exact command
  sequences for every v0.3.0 feature, keyed to each scenario.

- **`scripts/demo/generate_snapshot_pair.py`** — regeneration helper
  that rebuilds Meridian v2's `baseline.json` / `pr-branch.json` /
  `pr-diff.md` from the committed inventories. Use it after a
  NIST catalog refresh to keep the README's expected counts in sync.

- **`.github/workflows/evidentia.yml`** — Evidentia dog-
  fooding its own GitHub Action. On every PR touching the Meridian
  v2 inventory or the bundled catalogs, the workflow runs `gap
  analyze` + `gap diff` and posts the result as a PR comment;
  `--fail-on-regression` gates merging. Uses the local `uv sync`
  build so the action runs against whatever's on the PR branch,
  not the last-published PyPI wheel.

### Added — integration tests

- `tests/integration/test_examples/test_examples_smoke.py` — 8 cases
  covering each scenario's `gap analyze` pipeline, the Meridian v2
  `gap diff` every-classification regression guard, CSV inventory
  parse, and config-loader deprecation behavior (legacy meridian
  emits DeprecationWarning on its v0.1.x yaml schema; Meridian v2
  emits no warnings on the v0.2.1 schema).

### Fixed — `_is_open` gap-status filter on in-memory diff path

`evidentia_core.gap_diff._is_open()` used `str(gap.status)` to
compare against `GapStatus.OPEN.value`. On the JSON-roundtrip path
(CLI: `analyze` → save JSON → load JSON → `diff`), Pydantic
coerces the enum to its string value and the comparison works.
On the in-memory path (library users calling `compute_gap_diff()`
directly against freshly-computed `GapAnalysisReport`s with
`use_enum_values=True` active), `gap.status` is still a `GapStatus`
instance and `str(enum)` returns `"GapStatus.OPEN"` rather than
`"open"` — so `_is_open()` returned `False` for every gap and the
diff summary reported all zeros. The v0.3.1 fix normalizes via
`gap.status.value if isinstance(gap.status, GapStatus) else ...`
so both paths work identically. Flagged by the new Meridian v2
every-classification integration test — this bug never surfaced
in v0.3.0 because no test exercised the in-memory path.

### Fixed — Windows console Unicode handling in `gap diff` output

The v0.3.0 Rich console renderer used Unicode glyphs (`✗`, `✓`,
🆕, 📈) that crashed on Windows legacy consoles (cp1252 encoding):
`UnicodeEncodeError: 'charmap' codec can't encode character '\u2717'`.
v0.3.1 uses ASCII-only glyphs in the Rich path (`FAIL` /
`PASS` / section headers without emoji). The markdown and
github-annotation renderers keep their emoji — those target
UTF-8-clean surfaces (PR comments, Actions logs).

### Changed

- **Legacy `examples/meridian-fintech/`** gets a deprecation
  banner at the top of its README pointing at
  `examples/meridian-fintech-v2/`. No files deleted — all existing
  links still work.

### Tests: 384 → **392 passing** (+8)

New integration tests exercise the examples + config-loader
deprecation path end-to-end.

## [0.3.0] - 2026-04-17

The **"compliance-as-code" release.** Two user-facing feature areas plus
deprecation cleanup and a fully-strict mypy CI gate. No breaking API
changes to existing commands; new commands and a removed deprecated
enum.

### Added — PR-level compliance checking: `evidentia gap diff`

Compare two :class:`GapAnalysisReport` snapshots and classify each gap
into one of five states (opened, closed, severity_increased,
severity_decreased, unchanged). Drop-in for CI/CD pipelines: every pull
request can now run `evidentia gap diff --fail-on-regression` to
block merges that make the compliance posture worse.

- New module `evidentia_core.gap_diff` with `compute_gap_diff()`,
  `render_markdown()` (PR-comment-friendly), and
  `render_github_annotations()` (`::error::` / `::warning::` / `::notice::`
  lines that surface inline on the Actions Checks page).
- New models `GapDiff`, `GapDiffEntry`, `GapDiffSummary` (all Pydantic-
  validated and JSON-serializable).
- New CLI: `evidentia gap diff [--base PATH] [--head PATH]
  [--fail-on-regression] [--format console|json|markdown|github]
  [--output PATH]`. When `--base` / `--head` are omitted, auto-picks
  the two most-recent reports from the v0.2.1 gap store.
- **Control-ID normalization in diff**: a gap `AC-2(1)` in base and
  `ac-2.1` in head is correctly recognized as the same gap (uses the
  v0.2.1 normalizer, no false opened+closed pair).
- **Status-aware**: REMEDIATED / ACCEPTED / NOT_APPLICABLE gaps are
  excluded from the diff (they're not "open gaps" to regress on). An
  ACCEPTED gap in base that re-appears OPEN in head counts as a
  regression (acceptance was revoked).
- **GitHub Action scaffolding**: new `docs/github-action/README.md`
  (full setup guide) + `docs/github-action/workflow-example.yml`
  (drop-in `.github/workflows/evidentia.yml` template). The
  companion reusable action `allenfbyrd/evidentia-action` is
  scoped for v0.3.1.

### Added — Plain-English control explanations: `evidentia explain`

Translate authoritative-but-opaque framework control text into
actionable engineer-and-executive language. Every explanation is
cached on disk per (framework, control, model, temperature) tuple —
you pay the LLM cost once per lookup.

- New module `evidentia_ai.explain` with:
  - `PlainEnglishExplanation` Pydantic model (strict schema: plain
    English summary, why-it-matters paragraph, 3-8 what-to-do bullets,
    effort estimate, optional common-misconceptions paragraph).
  - `ExplanationGenerator` — Instructor-backed LLM pipeline on top of
    LiteLLM. Works with any LiteLLM-supported provider
    (OpenAI / Anthropic / Google / Ollama / etc).
  - Disk cache at `<platformdirs-cache>/evidentia/explanations/`
    keyed by SHA-256 of (framework, control, model, temperature).
    Override via `EVIDENTIA_EXPLAIN_CACHE_DIR`.
- New CLI: `evidentia explain control <id> [--framework FW]
  [--model MODEL] [--refresh] [--format panel|markdown|json]
  [--output PATH]`. Pre-flight check warns if no API-key env var
  matches the picked model (e.g., using `claude-*` without
  `ANTHROPIC_API_KEY`).
- Cache management: `evidentia explain cache where` (prints the
  cache directory), `evidentia explain cache clear` (wipes it).
- Reads defaults from `evidentia.yaml` using the v0.2.1 config
  loader (flag > env > yaml > built-in default).

### Changed

- **`FrameworkId` enum removed** from `evidentia_core.models.common`.
  Deprecated in v0.2.0 with a module-level `__getattr__` that emitted
  `DeprecationWarning`; v0.3.0 drops the enum and the getattr hook
  entirely. `ControlMapping.framework` has always been `str`; users
  who were relying on the enum value should use the plain string
  framework ID (e.g., `"nist-800-53-rev5"`) or
  `evidentia_core.catalogs.manifest.load_manifest()` for
  programmatic discovery.
- **mypy CI job flipped from advisory to strict.** v0.2.1 added
  `--strict-optional` as `continue-on-error: true` to avoid blocking
  releases on pre-existing annotation gaps; v0.3.0 fixed those 7
  gaps and dropped the `continue-on-error`. Enabled the
  `pydantic.mypy` plugin in `[tool.mypy]` so every
  `Model.model_validate*()` return type is correctly inferred.
  Added `types-PyYAML` and `pydantic` to the dev dependency group so
  mypy can find them.
- **`evidentia gap analyze`**: no behavior change, but the gap
  store write at the end of each run is now a required dependency
  of `gap diff`'s auto-picker. Unchanged from v0.2.1 users'
  perspective.

### Tests: 352 → **384** passing (+32 new)

- `tests/unit/test_gap_analyzer/test_gap_diff.py` — 16 cases covering
  every diff-status classification, control-ID normalization across
  notation styles, REMEDIATED/ACCEPTED status handling, sort order,
  and both Markdown / GitHub-annotation renderers.
- `tests/unit/test_ai/test_explain.py` — 19 cases covering the
  explanation cache (key determinism, model/temperature sensitivity,
  corruption handling), `ExplanationGenerator` behavior (cache hit
  skips LLM, refresh bypasses cache, echo-field defensive override),
  and the `PlainEnglishExplanation` schema's strict-validation edges.
- `tests/unit/test_models/test_framework_id_deprecation.py` — removed
  (the deprecation path and the enum are both gone).

### Infrastructure / hygiene

- Inter-package dependency pins bumped from `>=0.2.0,<0.3.0` to
  `>=0.3.0,<0.4.0` across all 5 packages.
- `scripts/catalogs/` generator scripts unchanged — v0.2.1 NIST
  bundling is stable.

### Known follow-ups (tracked in `docs/ROADMAP.md`)

- **Reusable `allenfbyrd/evidentia-action`** — the full GitHub
  Action wrapper. v0.3.0 ships the CLI; v0.3.1 will add the one-line
  `uses:` wrapper so users don't need the 80-line workflow in
  `docs/github-action/workflow-example.yml`.
- **PyPI Trusted Publisher (OIDC) migration** — still pending PyPI-
  side UI configuration. v0.3.0 continues using the API token.

## [0.2.1] - 2026-04-16

Correctness and integrity release. Follow-up to the v0.2.0 Phase 1.5
big-bang: fixes bugs an external code audit surfaced, bundles the full
NIST SP 800-53 Rev 5 catalog (1,196 controls + 4 resolved baselines),
adds 221 new tests, and lights up a working `evidentia.yaml`
project-config loader. No breaking API changes — all additions are
either additive (new CLI flags, new config keys) or transparent
(richer data, better defaults).

See `docs/ROADMAP.md` for the v0.3.0+ plan.

### Added

- **Full NIST SP 800-53 Rev 5 catalog** bundled verbatim from the CC0
  `usnistgov/oscal-content` repository at pinned tag `v1.4.0`. Ships as
  `nist-800-53-rev5.json` (1,196 controls across 20 families, including
  all enhancements) plus 4 resolved baseline catalogs:

  | Framework ID                    | Controls (inc. enhancements) | Use case                     |
  |---------------------------------|------------------------------|------------------------------|
  | `nist-800-53-rev5-low`          | 149                          | Low-impact FISMA systems     |
  | `nist-800-53-rev5-moderate`     | 287                          | Most federal / FedRAMP Mod   |
  | `nist-800-53-rev5-high`         | 370                          | High-impact FISMA / FedRAMP High |
  | `nist-800-53-rev5-privacy`      | 102                          | Privacy overlay              |

  Resolution uses the OSCAL profile resolver shipped in v0.2.0 (plus
  the fragment-href back-matter fix described under **Fixed** below).
  New script `scripts/catalogs/fetch_nist_oscal.py` regenerates these
  at release time against a pinned upstream tag.

- **FedRAMP baselines (`fedramp-rev5-low/moderate/high/li-saas`)** now
  carry real NIST 800-53 control text. v0.2.0 shipped these as
  pointer-only catalogs where every description was literally
  "See nist-800-53-rev5 catalog for full control text". v0.2.1 resolves
  each FedRAMP control ID against the bundled NIST catalog and
  substitutes real titles + descriptions (1,008 control descriptions
  replaced; zero unresolved).

- **Hybrid effort estimator** (`GapAnalyzer._estimate_effort`). v0.2.0
  used only a structural complexity score derived from
  `len(enhancements) + len(assessment_objectives)`, which was zero for
  every bundled catalog except the new NIST OSCAL one — meaning every
  gap scored `LOW` and the priority formula silently collapsed to
  `severity × (1 + 0.2 × cross_fw_count)`. The replacement is a
  three-layer cascade: structural score → keyword presence in the
  description → description-length fallback. See
  `docs/architecture/effort-estimation.md` for keyword lists and
  scoring rationale.

- **`evidentia.yaml` project-config loader** (`evidentia/config.py`).
  `evidentia init` has generated this file since v0.1.0 but no
  subcommand read it. v0.2.1 walks CWD → parents looking for the first
  `evidentia.yaml`, validates a strict schema, and applies values
  via precedence: **CLI flag > env var > yaml > built-in default**.
  Honored keys for v0.2.1:

  - `organization` / `system_name` — auto-populates inventory metadata
  - `frameworks:` — default set for `gap analyze`; CLI `--frameworks`
    replaces (does not union)
  - `llm.model` / `llm.temperature` — defaults for `risk generate`;
    overridden by env `EVIDENTIA_LLM_MODEL` / `EVIDENTIA_LLM_TEMPERATURE`

  Legacy v0.2.0 keys (`storage:`, `logging:`, nested `frameworks.default:`)
  are accepted without validation errors; `frameworks.default` triggers
  a deprecation warning pointing at the flattened v0.2.1 shape.
  `${ENV_VAR}` interpolation is supported in any string value.

- **Persistent gap report store** (`evidentia_core/gap_store.py`).
  Every `gap analyze` run writes a canonical snapshot to
  `<platformdirs>/evidentia/gap_store/<hash>.json`. `risk generate
  --gap-id GAP-…` (without `--gaps`) now loads the most-recent report
  from the store automatically. Override location via
  `EVIDENTIA_GAP_STORE_DIR`.

- **`--organization` / `--system-name` CLI flags on `gap analyze`**.
  Override inventory metadata for CSV-sourced runs (which previously
  hardcoded `"Unknown Organization (from CSV)"`) or when the inventory
  file's org name doesn't match the report recipient.

- **Placeholder-catalog warning**. Running `gap analyze` against a
  Tier-C stub catalog (e.g., `soc2-tsc`) now emits a prominent
  `UserWarning` telling users the control text isn't authoritative and
  pointing them at `evidentia catalog import` to load their
  licensed copy.

- **mypy CI job** (`.github/workflows/test.yml`). Runs `mypy --strict-optional`
  against `packages/evidentia-core/src` and
  `packages/evidentia/src`. Advisory-only for v0.2.1 (`continue-on-error`)
  because the existing v0.1.x codebase has some untyped helpers; will be
  tightened in v0.3.0.

- **221 new tests, bringing total from 131 → 352 passing**. New suites:

  - `tests/unit/test_gap_analyzer/test_effort_estimator.py` — 44 cases
    covering structural layer, all keyword substitutions, length fallback,
    regression guard for the v0.2.0 "everything is LOW" bug.
  - `tests/unit/test_gap_analyzer/test_priority_math.py` — 85 cases
    parameterized over every severity × effort × cross-fw-count
    combination, asserting priority matches the documented formula
    exactly.
  - `tests/unit/test_gap_analyzer/test_gap_store.py` — 14 cases for
    the persistent gap-store facility (directory resolution
    precedence, hash-key determinism, roundtrip integrity, latest-by-mtime
    lookup).
  - `tests/unit/test_oscal/test_profile_resolver.py` — 12 cases for
    OSCAL profile resolution edge cases (relative paths, `file://` URIs,
    fragment-href back-matter lookup, JSON-rlink preference,
    include/exclude filters, override IDs, missing-import errors).
  - `tests/unit/test_oscal/test_exporter.py` — 5 cases pinning the
    shape of OSCAL Assessment Results exports.
  - `tests/unit/test_config.py` — 24 cases for the new
    `evidentia.yaml` loader (schema validation, precedence chain,
    legacy-shape warnings, env-var interpolation).
  - `tests/unit/test_models/test_control_id_normalization.py` — 20
    cases covering the NIST-publication style (`AC-2(1)(a)`) vs.
    NIST-OSCAL style (`ac-2.1.a`) normalization added to support the
    bundled NIST catalog.
  - `tests/integration/test_cli/test_catalog_cli.py` — 12 cases for
    the v0.2.0 CLI subcommands (`import`, `where`, `license-info`,
    `remove`, `list --tier`, `list --category`, shadow-resolution,
    duplicate-import behavior, `doctor`, `version`) that previously had
    zero coverage.

- **`docs/ROADMAP.md`** — forward plan for v0.3.0 through v0.6.0+ with
  scope-locked priorities (compliance-as-code diff, plain-English
  explanations, Phase 2 integrations, air-gapped mode, evidence chain
  of custody, etc.).

- **`docs/architecture/effort-estimation.md`** — design doc for the new
  hybrid estimator so future reviewers don't re-derive the keyword
  lists from code.

### Fixed

- **OSCAL profile resolver — back-matter fragment href resolution.**
  v0.2.0's resolver rejected `href: "#<uuid>"` references (raising
  `ProfileResolutionError: Fragment-only hrefs not yet supported`),
  which meant every real-world OSCAL profile (including every NIST
  baseline) couldn't be resolved. v0.2.1 looks up the UUID in the
  profile's `back-matter.resources[].uuid`, walks the first JSON-media
  `rlinks[].href`, and follows it. Falls back to the first non-empty
  rlink when no JSON-flagged entry exists.

- **Dual control-ID convention support.** NIST publications render
  enhancement IDs as `AC-2(1)(a)`; NIST OSCAL renders them as
  `ac-2.1.a`. v0.2.0's `ControlCatalog.get_control()` was strict
  (did a `.upper()`-only lookup), so users typing one style against a
  catalog indexed in the other got `None`. v0.2.1 normalizes both via
  a new `_normalize_control_id()` helper: both
  `catalog.get_control("AC-2(1)(a)")` and
  `catalog.get_control("ac-2.1.a")` resolve to the same control.

- **`evidentia.yaml` is now actually read by subcommands** (see
  **Added** above).

- **`risk generate --gap-id` no longer unconditionally errors.** The
  new gap-store lookup resolves `--gap-id` against the last-saved
  report when `--gaps` is omitted. Provides a clear message
  ("Run `evidentia gap analyze ...` first") when no report exists.

- **CSV organization override.** v0.2.0 hardcoded
  `"Unknown Organization (from CSV)"` in the CSV inventory parser with
  no override path. The new `--organization` / `--system-name` CLI
  flags on `gap analyze` and the corresponding `evidentia.yaml`
  keys resolve this.

### Changed

- **`evidentia init` template** updates the generated
  `evidentia.yaml` to the v0.2.1 schema with commented-out examples
  of every honored key.

- **`litellm` version pin tightened** from `>=1.50` to `>=1.50,<2.0`
  (LiteLLM has historically broken minor-version APIs).

- **`nist-800-53-mod` (the 16-control v0.1.x sample)** kept intact for
  yaml-pin backward compatibility, but renamed in metadata to clearly
  flag it as deprecated and point at `nist-800-53-rev5-moderate` (the
  real 287-control baseline). Will be removed in v0.3.0.

- **Framework count** in `evidentia doctor` grows from 77 → 82 (5
  new NIST catalogs).

### Deferred / known follow-ups

- **PyPI Trusted Publisher (OIDC) migration** — release workflow
  continues to use `PYPI_API_TOKEN` for v0.2.1. Switching without
  configuring a Trusted Publisher on PyPI's admin panel first would
  break the release pipeline. Tracked in `docs/ROADMAP.md`.

- **Full `--strict` mypy** — the advisory-mode `--strict-optional` job
  added in v0.2.1 surfaces existing type-annotation gaps without
  blocking releases. v0.3.0 will clean those up and switch to
  strict-fail.

- **v0.2.0 release-workflow API token rotation** — the v0.2.0 commit
  that removed Claude co-authorship used `git filter-branch`; the
  resulting force-push to `main` has been well-tolerated by PyPI, but
  a future history-rewrite-heavy release should confirm PyPI token
  validity before tagging.

## [0.2.0] - 2026-04-16

**Phase 1.5 big-bang release — exhaustive framework expansion.** Follow-up
to the v0.1.1 legal remediation and v0.1.2 version-reporting truth-up.
Evidentia now ships ~77 bundled frameworks across four redistribution
tiers — a comprehensive GRC catalog library so common GRC workflows work
out of the box without digging.

### Added — Frameworks (77 total; up from 2)

**Tier A — US federal (verbatim public domain, 25 frameworks)**

- NIST family: 800-171 Rev 2 (110 controls), 800-171 Rev 3 (90), 800-172
  enhanced CUI protections (33), Cybersecurity Framework 2.0 (106
  subcategories), AI RMF 1.0 (72), Privacy Framework 1.0 (94), Secure
  Software Development Framework (SSDF) 800-218 (42)
- FedRAMP Rev 5: Low / Moderate / High / LI-SaaS baselines (pointer
  catalogs; full resolution via OSCAL profile resolver)
- CMMC 2.0: Levels 1 / 2 / 3
- HIPAA: Security Rule (45 CFR § 164 Subpart C), Privacy Rule (Subpart E),
  Breach Notification Rule (Subpart D)
- US regulatory: GLBA Safeguards Rule, NY DFS 23 NYCRR 500, NERC CIP v7,
  FDA 21 CFR Part 11, IRS Publication 1075, CMS ARS 5.1, FBI CJIS Security
  Policy v6.0, CISA Cross-Sector Cybersecurity Performance Goals
- Plus the existing 16-control `nist-800-53-mod` sample

**Tier A — International (6 frameworks)**

- UK: NCSC Cyber Assessment Framework 3.2, Cyber Essentials
- Australia: Essential Eight, Information Security Manual (ISM)
- Canada: ITSG-33
- New Zealand: NZISM 3.7

**Tier D — Statutory obligations (21 frameworks; government edicts — not
copyrightable)**

- EU: GDPR, AI Act (Regulation 2024/1689), NIS2 Directive, DORA
- UK: Data Protection Act 2018
- Canada: PIPEDA
- US state privacy laws (15): California CCPA/CPRA, Virginia VCDPA,
  Colorado CPA, Connecticut CTDPA, Utah UCPA, Texas TDPSA, Oregon OCPA,
  Delaware DPDPA, Montana MCDPA, Iowa ICDPA, Florida FDBR, Tennessee TIPA,
  New Hampshire NHPA, Maryland MODPA, Minnesota MNCDPA

**Tier C — Licensed stubs (20 frameworks; copyrighted control text not
bundled — structural numbering + license URLs for user import)**

- ISO/IEC family: 27001:2022 (93 Annex A controls), 27002:2022, 27017:2015,
  27018:2019, 27701:2019, 42001:2023 (AI), 22301:2019 (BC)
- PCI DSS v4.0.1
- HITRUST CSF v11
- COBIT 2019
- SWIFT CSCF v2024
- CIS Controls v8.1 + 5 CIS Benchmarks (AWS, Azure, GCP, Kubernetes, RHEL 9)
- Secure Controls Framework (SCF) 2024
- IEC 62443 (industrial/OT security)
- SOC 2 TSC (retained from v0.1.1)

**Tier B — Threat and vulnerability catalogs (4 frameworks)**

- MITRE ATT&CK Enterprise (41 high-use techniques/sub-techniques across
  all 14 tactics)
- MITRE CWE (Top 25 weaknesses for 2024)
- MITRE CAPEC (10-pattern sample)
- CISA Known Exploited Vulnerabilities (8-CVE sample of notable entries
  including Log4Shell, MOVEit, EternalBlue)

### Added — Architecture foundation

- **Manifest-driven registry**: `data/frameworks.yaml` replaces the three
  v0.1.x parallel sources of truth (`FRAMEWORK_METADATA` dict,
  `framework_files` dict, `FrameworkId` enum). Adding a framework = drop
  JSON + one YAML edit. Regenerate via
  `scripts/catalogs/regenerate_manifest.py`.
- **`ControlCatalog` model expansion**: new optional fields `guidance`,
  `objective`, `examples`, `control_class`, `ordering`, `family_hierarchy`,
  `category`. All additive — existing v0.1.x JSONs continue to parse under
  `extra="forbid"`.
- **Recursive enhancement flattener**: fixes NIST 800-53 Rev 5 3-level ID
  lookup like `AC-2(1)(a)` that v0.1.x silently lost. `catalog.get_control`
  now walks the full enhancement tree.
- **`TechniqueCatalog`, `VulnerabilityCatalog`, `ObligationCatalog` models**
  for non-control catalog types. See `evidentia_core/models/threat.py`
  and `evidentia_core/models/obligation.py`.
- **OSCAL profile resolver** (`evidentia_core/oscal/profile.py`):
  supports `include-controls`, `exclude-controls`, `set-parameter`,
  `alter.add`, `merge`. Enables user-supplied OSCAL profile JSONs via
  `evidentia catalog import --profile profile.json --catalog source.json`.
- **User-import facility**: new CLI commands `catalog import`, `catalog
  where`, `catalog license-info`, `catalog remove`, and `catalog list
  --tier <A|B|C|D> --category <control|technique|vulnerability|obligation>`.
  User-imported catalogs shadow bundled ones of the same ID (via
  `platformdirs`-resolved user directory, overridable by
  `EVIDENTIA_CATALOG_DIR`). A licensed ISO 27001 copy imported by a
  customer replaces the Tier-C stub transparently for all `catalog show` /
  `gap analyze` calls.
- **Tier-partitioned catalog directory layout**: `data/us-federal/`,
  `data/international/`, `data/state-privacy/`, `data/stubs/`,
  `data/threats/`, `data/mappings/`.

### Added — Crosswalks (6 total)

- NIST CSF 2.0 → NIST 800-53 (36 mappings, derived from NIST OLIR)
- FedRAMP Moderate → CMMC Level 2 (32 mappings, from DoD CMMC Assessment
  Guide correlations)
- NIST 800-53 → HIPAA Security Rule (20 mappings, from HHS OCR guidance)
- Virginia VCDPA → California CCPA/CPRA (13 subject-rights mappings)
- ISO/IEC 27001:2022 → NIST 800-53 (23 conceptual parity mappings)
- Existing `nist-800-53-rev5_to_soc2-tsc` crosswalk (17 mappings, retained
  from v0.1.1 with sanitized titles)

### Added — Testing

- 80 new unit tests bringing total from 22 → **131 tests passing**:
  parametric smoke test per bundled framework (77 cases), tier invariants
  (Tier-C must be placeholder, Tier-A must not), OSCAL model validation,
  manifest loader, user-dir resolution, `FrameworkId` deprecation gating,
  recursive enhancement flattener.

### Changed

- `FrameworkId` enum (in `evidentia_core.models.common`) is deprecated
  — emits `DeprecationWarning` on import. Use manifest-driven string IDs
  instead. Will be removed in v0.3.0.
- `evidentia catalog list` now filters by `--tier` / `--category` /
  `--bundled-only` / `--user-only` and shows tier + category columns.
- `evidentia catalog show <fw> <ctrl>` renders
  `[Licensed — see <license_url>]` for Tier-C placeholder controls instead
  of the raw placeholder text.
- `platformdirs>=4.3` added as a `evidentia-core` runtime dependency
  (for user-catalog directory resolution).

### Infrastructure

- `scripts/catalogs/` now hosts compact Python generators (one per
  framework family) plus `regenerate_manifest.py` so `frameworks.yaml` is
  built from what's actually on disk.
- v0.2.1 roadmap: upstream fetch adapters (`scripts/catalogs/upstream/`)
  and GitHub Actions cron workflow (`.github/workflows/catalog-refresh.yml`)
  for auto-detecting upstream drift and opening tracking issues.

## [0.1.2] - 2026-04-16

Version-reporting truth-up patch. Follow-up to v0.1.1. No functional
changes — the installed packages already reported their real versions
to package managers (`pip show`, PyPI metadata); this patch fixes the
version strings that Evidentia itself prints and embeds in
exported artifacts.

### Fixed

- `evidentia version` CLI output reported `"0.1.0"` regardless of
  which version was actually installed, because every package's
  `__version__` was a hardcoded string literal. All five `__init__.py`
  modules now resolve `__version__` from `importlib.metadata` at
  import time — the reported version always matches the installed
  wheel and will never drift again.
- `GapReport.evidentia_version`, `RiskRegister.evidentia_version`,
  and `EvidenceBundle.evidentia_version` all defaulted to `"0.1.0"`.
  They now use a `default_factory` that resolves the live
  `evidentia-core` version, so exported audit artifacts accurately
  record the version that produced them.

### Added

- `evidentia_core.models.common.current_version()` helper that
  returns the installed `evidentia-core` version, used as the
  `default_factory` for all report-stamp fields.

## [0.1.1] - 2026-04-16

Legal remediation + registry truth-up patch. No API breakage — all changes
are additive optional fields on existing models. The **v0.2.0 big-bang
Phase 1.5 release** (exhaustive framework expansion to ~50 frameworks
across four redistribution tiers, plus `evidentia catalog import`
for user-supplied licensed content, plus GitHub Actions refresh CI)
follows this patch.

### Fixed

- **SOC 2 TSC catalog replaced with Tier-C stub.** The v0.1.0 bundled
  `soc2-tsc.json` contained 12 paraphrased AICPA criteria whose titles
  closely mirrored the copyrighted AICPA Trust Services Criteria 2017
  text and embedded references to COSO Internal Control Integrated
  Framework principles. That content is removed. The stub ships 61
  criteria (CC1.1–CC9.2, A1.1–A1.3, C1.1–C1.2, P1.1–P8.1, PI1.1–PI1.5)
  with generic titles ("Common Criteria 6.1" rather than AICPA's full
  phrasing), `placeholder: true` on every entry, and a `license_url`
  pointing to the AICPA download page. `evidentia catalog show
  soc2-tsc CC6.1` now renders `[Licensed content — see license_url for
  authoritative text.]` rather than a paraphrase. v0.2.0 will add
  `evidentia catalog import` so users can load their own licensed
  copy without touching the installed package.
- **Bundled `nist-800-53-rev5_to_soc2-tsc.json` crosswalk** had the same
  AICPA-paraphrase exposure in `target_control_title` fields; those are
  now the generic stub titles matching the stub catalog. The 17
  source↔target mappings themselves are unchanged — the mapping concept
  (e.g., NIST AC-2 relates to SOC 2 CC6.1) is factual and uncopyrightable.
- **Registry no longer advertises 7 framework IDs with no backing data.**
  `FRAMEWORK_METADATA` in v0.1.0 listed 9 frameworks (`nist-800-53-rev5`,
  `nist-800-53-mod`, `nist-800-53-high`, `nist-csf-2.0`, `soc2-tsc`,
  `iso27001-2022`, `cis-controls-v8`, `cmmc-2-level2`, `pci-dss-4`) but
  only 2 had catalog JSON on disk. `evidentia catalog list` produced
  7 "loaded: no" rows — misleading for a GRC tool whose users need to
  trust stated coverage. `FRAMEWORK_METADATA`, the `framework_files`
  dispatch in `loader.py`, and the `FrameworkId` enum are all trimmed
  to the 2 backed frameworks (`nist-800-53-mod`, `soc2-tsc`). `doctor`
  output now reports 2 frameworks, matching reality.
- **README "9 registered frameworks" claim corrected** to "2 bundled"
  with an explicit Tier-A/Tier-C explanation and a pointer to the v0.2.0
  roadmap.

### Added

- Optional fields on `CatalogControl`: `tier` (`"A"` through `"D"`),
  `license_required`, `license_url`, `placeholder`. All default to safe
  values; existing catalog JSONs continue to parse under `extra="forbid"`.
- Optional fields on `ControlCatalog`: same four plus `license_terms`
  (human-readable description of licensing constraints).
- New test `test_load_bundled_soc2_catalog_is_licensed_stub` locks in
  the Tier-C stub shape so a future accidental re-add of paraphrased
  AICPA content trips the test suite.

### Changed

- `FrameworkId` enum in `evidentia_core.models.common` trimmed to
  `NIST_800_53_MOD` and `SOC2_TSC`. Callers using free-form `str`
  framework IDs (via `ControlMapping.framework`) are unaffected. The
  enum itself will be deprecated in v0.2.0 in favor of a
  manifest-driven registry and removed in v0.3.0.

## [0.1.0] - 2026-04-16

Initial release: **Phase 1 MVP** — a working, tested, end-to-end gap analyzer
with AI risk statement generation. Evidentia is an open-source,
Python-first GRC platform that treats compliance as a software problem:
composable libraries, structured data, open standards (OSCAL), and AI only
where language understanding is the bottleneck.

### Added

- **uv workspace monorepo** with 5 packages: `evidentia-core`,
  `evidentia-ai`, `evidentia-collectors`, `evidentia-integrations`,
  and the `evidentia` CLI meta-package
- **Pydantic v2 data models** for controls, catalogs, gaps, risks, evidence,
  and findings
- **OSCAL catalog loader and crosswalk engine** with 9 registered frameworks
  and bundled NIST 800-53 Moderate + SOC 2 TSC catalogs
- **Multi-format inventory parser** supporting YAML, CSV (with fuzzy header
  matching), OSCAL component-definition, and CISO Assistant export formats
- **Gap analyzer** with severity calculation, effort-weighted priority
  scoring, and cross-framework efficiency analysis
- **Four report exporters**: JSON, CSV, Markdown, OSCAL Assessment Results
- **AI Risk Statement Generator** (NIST SP 800-30 Rev 1) using LiteLLM +
  Instructor for provider-agnostic structured LLM output
- **Typer + Rich CLI**: `init`, `catalog` (list/show/crosswalk), `gap analyze`,
  `risk generate`, `doctor`, `version`
- **End-to-end walkthrough sample** (Meridian Financial fintech scenario)
  exercising every feature with 20 controls across two frameworks
- **22 passing pytest tests** covering models, catalogs, crosswalks,
  multi-format parsing, gap scoring, and all four exporters
- **GitHub Actions CI** (pytest matrix on ubuntu/windows/macos + ruff lint)
- **Code of Conduct** (Contributor Covenant v2.1 by reference),
  `CONTRIBUTING.md`, and issue templates

### Known limitations (intentional Phase 1 scope)

- Evidence collectors for AWS, GitHub, Okta, Azure, GCP — planned for Phase 2
- Jira and ServiceNow push integrations — planned for Phase 2
- LLM-based evidence validation — planned for Phase 3
- FastAPI REST server and web UI — planned for Phase 4
- Production-sized OSCAL catalogs: the bundled NIST 800-53 Moderate catalog
  has 16 hand-curated controls for demonstration, not the full ~323 from the
  NIST OSCAL content repo — planned for Phase 1.5

[Unreleased]: https://github.com/allenfbyrd/evidentia/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/allenfbyrd/evidentia/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/allenfbyrd/evidentia/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/allenfbyrd/evidentia/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/allenfbyrd/evidentia/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/allenfbyrd/evidentia/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/allenfbyrd/evidentia/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/allenfbyrd/evidentia/releases/tag/v0.1.0
