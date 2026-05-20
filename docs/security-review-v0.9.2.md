# Security review — v0.9.2 (2026-05-16) — backfill

> **Backfill notice**: this artifact was written retrospectively during v0.9.8 P1.10 (2026-05-19). The original v0.9.2 cycle did not produce a contemporaneous review file. This backfill summarizes the cycle's scope + retrospective compliance posture so the `docs/security-review-v0.9.*.md` trail is complete. Findings are drawn from the v0.9.3 review's "prior-cycle context" notes + the `evidentia_v0_9_2_shipped` memory entry; per-finding CVSS / CWE / EPSS scoring is omitted because the original `/security-review` invocations were not preserved.

## Summary

- **Cycle theme**: CONMON REST + LLM-assisted second rater + federal-compliance calibration corpus + federal-SI walk-through scenarios. First post-org-migration feature ship.
- **Tag**: `v0.9.2` (2026-05-16).
- **Findings**: 0 CRITICAL / 0 HIGH / 0 MEDIUM unfixed; LOW + INFO findings retrospectively classified per v0.9.3's reference back to "prior-cycle context".
- **Compliance posture**: **PROCEED-CLEAN** — **17th consecutive** of the v0.7.x → v0.8.x → v0.9.x line.
  - NIST SSDF PW.5 / PW.8: satisfied (2-rater calibration adds independent corroboration)
  - ISO 27001:2022 Annex A 8.27 (secure system architecture): met
  - SOC 2 Type II CC7.1: met
  - CISA Secure by Design Pledge: maintained
  - OpenSSF Best Practices Silver: maintained

## What shipped

Per ROADMAP `v0.9.2` section + the `evidentia_v0_9_2_shipped` memory entry:

1. **CONMON REST router** — 4 endpoints under `/api/conmon/`:
   - `GET /api/conmon/` (list cadences with optional `framework=` filter)
   - `GET /api/conmon/{slug}` (single cadence lookup)
   - `POST /api/conmon/next` (compute next-due from anchor)
   - `POST /api/conmon/check` (state-file → attention buckets)
   - 17 integration tests against the new endpoints. Auth-gated via the v0.8.1 `AuthProviderMiddleware`; routes inherit the same allowlist semantics as the rest of `/api/*`.
2. **LLM-assisted second rater** — `scripts/llm_rater.py` (temperature-0 deterministic labeling against the calibration corpus) + `--rule llm` mode in `scripts/compute_inter_rater_kappa.py`. JSONL sidecar persistence so the rater's labels are reproducible + auditable.
3. **Federal-compliance calibration corpus** — `tests/data/dfah-calibration/corpus_federal.jsonl` (24 entries; FedRAMP ConMon + POA&M + NIST 800-53 CA-7). Total corpus expanded to **147 entries** (was 123 at v0.8.6).
4. **Federal-SI walk-through scenarios** — FS-1 through FS-10 in `docs/capability-matrix.md`, each with persona / goal / surfaces-exercised / expected-outcome. Scenarios were drafted in v0.9.2 + executed post-walk-through in v0.9.4 + v0.9.8.
5. **GHCR public-flip** — first ship-day flip of the new-org GHCR package from default-private to public, surfaced at Step 7 (manual operator action; documented in the release-checklist as a v0.9.x-line item).

## /security-review invocations

Per the v4 skill spec, the v0.9.2 cycle ran the standard 3 mandatory invocations:

1. **Step 3 entry (diff `v0.9.1..claude/v0.9.2-dev`)** — scope: 28 files; ~3,200 LOC delta. CONMON REST router (new public surface) + LLM-rater script (new operator tool) + federal corpus + walk-through scenarios.
2. **Step 4 entry (per-subsystem)** — AI features (`scripts/llm_rater.py`, calibration corpus integrity) + CONMON surfaces (new REST router + REST + library boundary checks).
3. **Step 6.C entry (pre-push 16-row gate)** — all 16 rows pass; 17th consecutive PROCEED-CLEAN.

Findings (retrospective, drawn from v0.9.3's "prior-cycle context"):

- **F-V92-LOW-1** — CONMON REST list endpoint had no rate limit (LOW; CWE-770 partial). Accepted with rationale: the v0.8.1 `AuthProviderMiddleware` enforces authentication on all `/api/*` paths, so abuse requires a valid token. Token-bucket rate-limiting shipped v0.9.4 P1.3 closed this in the `/api/ai-gov/` surface; CONMON REST inherits the same defensive posture from v0.9.4's middleware.
- **F-V92-Q3** (INFO) — GHCR package default-private-on-creation requires a manual public flip at first push under a new GitHub org. Operator runbook entry added to `docs/release-checklist.md` v0.9.2 anchor.

## /code-review auto-fires

Two trigger conditions hit:

1. **First-time-pattern import** — LLM-rater script imports `litellm` for the first time outside `evidentia_ai/`. Reviewed; no findings.
2. **New REST endpoint surface** — 4 CONMON endpoints. Reviewed for auth-gating, input validation, response shape; no findings.

## Step 7 post-tag verification

- PEP 740 attestations: 7/7 packages valid under `Polycentric-Labs` workflow identity
- cosign SLSA Provenance v1: signed; verification against new GHCR path successful
- osv-scanner: 1 LOW (paramiko CVE-2026-44405 carry-forward; upstream-unpatched)
- docker run smoke: `docker run ghcr.io/polycentric-labs/evidentia:v0.9.2` returned the expected banner + 89 framework catalogs
- Pin-trap validation: 17th consecutive pass
- Auto-populate from CHANGELOG: 17th consecutive pass
- GHCR public-flip: completed day-of (manual; recorded in this review's Step 7 narrative)

## Carry-forwards into v0.9.3

- **paramiko CVE-2026-44405 LOW** (ongoing).
- **GHCR public-flip release-checklist item** — anchored in `docs/release-checklist.md`.
- **API-stability.md DRAFT** — authored in v0.9.3 P5 against the v0.9.2 surface baseline.

## Distinction from contemporaneous reviews

Backfilled-but-detailed scope:

1. **Per-subsystem findings preserved** via v0.9.3's "prior-cycle context" cross-references (which were authored contemporaneously and consistently mention v0.9.2 as the immediate predecessor).
2. **Auto-fire records reconstructed** from the CHANGELOG `[0.9.2]` block + the `evidentia_v0_9_2_shipped` memory entry. Detail level lower than v0.9.3+ contemporaneous reviews.
3. **Compliance counts** documented per the historical chain (16th → 17th); reflects the consecutive-PROCEED-CLEAN cadence rather than a contemporaneous re-derivation.

## Cross-references

- [`docs/security-review-v0.9.1.md`](security-review-v0.9.1.md) — preceding backfill (org migration)
- [`docs/security-review-v0.9.3.md`](security-review-v0.9.3.md) — first contemporaneous review of the v0.9.x federal-compliance-feature line
- [`docs/ROADMAP.md`](ROADMAP.md) §v0.9.2 — cycle-scope narrative
- [`docs/capability-matrix.md`](capability-matrix.md) — FS-1 through FS-10 scenario rows
- `~/.claude/projects/<evidentia-hash>/memory/evidentia_v0_9_2_shipped.md` — private ship record
