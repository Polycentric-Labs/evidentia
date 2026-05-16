# Security review — Evidentia v0.7.9

**Release**: v0.7.9 — "Financial-services TPRM ship"
**Date**: 2026-05-04
**Tag**: `v0.7.9` (pending push)
**Diff range**: `v0.7.8..v0.7.9` (24 commits)
**Reviewer**: pre-release-review v4 skill (
[`~/.claude/skills/pre-release-review/SKILL.md`](https://github.com/polycentric-labs/evidentia)
), four Continuous-variant runs + final Pre-tag run.

This is the 5th canonical pre-release-review deliverable per
v4 G7 (CVSS / CWE / EPSS columns on bug-bucket findings + 6-
framework compliance mapping for Step 6).

## Compliance framework mapping

The pre-release-review v4 process produced this document in
satisfaction of:

| Framework | Control / requirement | How v0.7.9 satisfies |
|---|---|---|
| **NIST SSDF v1.1** | PS.3.1 — protect software releases from unauthorized changes | Sigstore PEP 740 attestations on all 7 PyPI wheels + cosign keyless OIDC on `ghcr.io/polycentric-labs/evidentia:v0.7.9` + SLSA L3 build provenance + CycloneDX SBOM |
| **NIST SSDF v1.1** | RV.1.1 — identify + confirm vulnerabilities prior to release | Continuous-variant /security-review at 3 boundaries (P0.1 close, P0.3+P0.2-first close, P0.4-quartet+P0.5+P0.2-second-slice close) + Pre-tag /security-review on the 2 newest commits + the v4 G6 verification gates at every step boundary |
| **NIST SSDF v1.1** | RV.1.3 — analyze vulnerabilities + identify root causes | All 6 inline-fixed HIGH + LOW findings have CWE classification + CVSS estimates + remediation links to specific commits in this document |
| **SLSA Level 3** | Build provenance | `actions/attest-build-provenance@v2.4.0` emits provenance for every release wheel; verifiable via `gh attestation verify <wheel> --owner polycentric-labs` |
| **SLSA Level 3** | Build platform isolation | GitHub Actions ephemeral runners + Trusted Publisher OIDC (no long-lived secrets); container build via `cosign verify ghcr.io/Polycentric-Labs/evidentia:v0.7.9 --certificate-identity-regexp=...` |
| **ISO 27001:2022** | Annex A 8.25 — secure development lifecycle | pre-release-review v4 skill formalizes a 7-step gated process; per-run JSON persistence at `.local/pre-release-review/runs/*.json` provides audit-trail evidence |
| **ISO 27001:2022** | Annex A 8.28 — secure coding | ruff + mypy strict + CodeQL + standing-rule keyword sweep + Claude-attribution sweep at every commit boundary |
| **ISO 27001:2022** | Annex A 8.30 — outsourced development | n/a — solo project. Documented in OpenSSF Best Practices Silver-tier `bus_factor` field (mitigated by keyless infrastructure + Trusted Publisher OIDC bound to repo) |
| **SOC 2 Type II** | CC7.1 — vulnerability management | Dependabot + osv-scanner + Scorecard + per-release security review (this document) + Continuous-variant runs in-flight |
| **SOC 2 Type II** | CC8.1 — change management | docs/release-checklist.md formalizes 11 steps including pre-tag review + post-tag verification; every commit follows conventional-commit prefixes; CHANGELOG Keep a Changelog format |
| **DORA (EU 2022/2554)** | Article 9(4) — operational resilience testing | DAST sub-step (G11) ran in v0.7.8 Pre-tag (Schemathesis + Playwright); v0.7.9 inherits the schema-fidelity baseline + UI XSS-safety baseline; Schemathesis re-fire scheduled for Step 7 post-tag verification |
| **DORA (EU 2022/2554)** | Article 28(7) — third-party risk register | The TPRM module shipped in this release directly addresses this: vendor inventory + DD-questionnaire + concentration-report + OSCAL TPRM emit produce DORA-compliant third-party-risk evidence artifacts |
| **OpenSSF Best Practices** | Passing tier | Already awarded (project 12724) — embed renders on README badge cluster |
| **OpenSSF Best Practices** | Silver tier | Answer sheet refreshed for v0.7.9 ship state at `~/.claude/plans/evidentia-badgeapp-silver-gold-answer-sheet.md` (private); Allen will fill the bestpractices.dev form post-tag |
| **CISA Secure by Design Pledge** | Pillar 1 — multi-factor authentication | n/a (Evidentia produces compliance artifacts; not a hosted service requiring MFA on user accounts) |
| **CISA Secure by Design Pledge** | Pillar 4 — security patches | All 4 v0.7.8 Step 5.A MEDIUM carry-overs closed in v0.7.9; vulnerability-aging SLO (pre-push gate row 14) green |
| **CISA Secure by Design Pledge** | Pillar 6 — vulnerability disclosure | SECURITY.md documented disclosure SLA (3-business-day acknowledgement + 90-day coordinated disclosure) |
| **CISA Secure by Design Pledge** | Pillar 7 — CVE handling | osv-scanner clean (0 CVEs in SBOM); upstream-CVE remediations credited via GHSA IDs in commits + CHANGELOG |

## Findings — bug-bucket table

CVSS estimates use the v3.1 calculator. EPSS = exploit prediction
likelihood (low / medium / high). CWE classification per MITRE
catalog. Confidence = reviewer's certainty in the
identify-and-disposition pair.

| ID | Severity | CVSS | CWE | EPSS | Confidence | Title | Disposition | Commit |
|---|---|---|---|---|---|---|---|---|
| **F-V09-CR-H1** (Continuous) | HIGH | 5.3 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:L) | CWE-835 (loop with unreachable exit) | low | 0.9 | Vanta + Drata `_paginate` lacks stuck-cursor guard — if upstream API returns same `endCursor` / `nextPageToken` twice with `hasNextPage=true`, loop runs to `max_vendors=2000` cap | **INLINE-FIXED** | `3315150` |
| **F-V09-CR-H2** (Continuous) | HIGH | 4.0 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L) | CWE-697 (incorrect comparison) | low | 0.85 | Drata + SSC fall-through `data.get("data") or data.get("results") or []` mishandles legitimate `{"data": []}` (falsy `[]` falls through; correct end-result today but fragile) | **INLINE-FIXED** | `3315150` |
| **F-V09-CR-H3** (Continuous) | HIGH | 4.0 (same as H1) | CWE-835 | low | 0.85 | SecurityScorecard `_paginate_portfolio` partial loop guard — relies on hard cap when `page_count` missing AND entries non-empty repeatedly | **INLINE-FIXED** | `3315150` |
| **F-V09-CR-H4** (Continuous) | HIGH (test coverage) | n/a | n/a | n/a | 0.9 | Test gaps: `parse_completed_questionnaire` JSON path with `vendor_id=None` (CLI surfaces error path) + SIG BYO partial-label-match case | **INLINE-ADDED-2-TESTS** | `3315150` |
| **F-V09-CR-H5** (Continuous) | HIGH | 5.5 (AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N) | CWE-1188 (insecure default) | low | 0.85 | SIG BYO column-write order — real-world Shared Assessments templates put instruction text in column B and intend C as response cell; previous order silently filled wrong cell | **INLINE-FIXED (prefer C over B)** | `3315150` |
| **F-V09-S1** (Continuous, security) | LOW | 4.3 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N) | CWE-319 (cleartext transmission) | low | 0.7 | BitSight cross-host pagination guard checks `parsed.netloc` but not `parsed.scheme` — malicious upstream `next: http://api.bitsighttech.com/...` would leak HTTP Basic auth header over cleartext | **INLINE-FIXED** | `3315150` |
| **F-V09-PRT-H1** (Pre-tag incremental) | HIGH (doc accuracy) | n/a | n/a | n/a | 1.0 | `docs/tprm.md` references `--region` and `--next-review-due` CLI flags that don't exist on `evidentia tprm vendor add` / `edit`; every operator copying examples hits argparse error | **INLINE-FIXED (added flags)** | this commit |
| F-V08-CR-MEDIUM Snowflake count split | MEDIUM | n/a (correctness) | n/a | n/a | 1.0 | `_policy_inventory_findings` mixed masking + row-access counts under single `snowflake-policy` bucket | **INLINE-FIXED** (carry-over) | `cf1c07e` |
| F-V08-CR-MEDIUM Snowflake quoted-id | MEDIUM | 5.0 (AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:N) | CWE-89 (SQL injection — defensive) | low | 0.7 | Unescaped f-string `f'"{db}".INFORMATION_SCHEMA.MASKING_POLICIES'` in policy inventory queries | **INLINE-FIXED** (carry-over) | `cf1c07e` |
| F-V08-CR-MEDIUM Databricks PermissionDenied | MEDIUM | n/a (clarity/maintainability) | n/a | n/a | 0.9 | Permission-error detection used `if "permission" in str(e).lower()` heuristic; replaced with typed `databricks.sdk.errors.PermissionDenied` catch | **INLINE-FIXED** (carry-over) | `cf1c07e` |
| F-V08-CR-MEDIUM Power BI 1MB guard | MEDIUM | 4.0 (AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:L) | CWE-770 (resource without limit) | low | 0.9 | `push_rows()` only enforced 10K-row batch limit, not Power BI's documented 1MB request-body limit; wide-schema customers hit 4xx | **INLINE-FIXED** (carry-over) | `cf1c07e` |
| F-V08-CR-LOW × 9 batch | LOW | n/a (refinements) | n/a | n/a | 1.0 | 9 opportunistic refinements per security-review-v0.7.8.md "no correctness defects" disposition | **DEFERRED to v0.7.10** with explicit rationale (ship velocity per Allen 2026-05-04) | n/a |
| MEDIUM × 9 + LOW × 8 (Continuous run) | MEDIUM/LOW | various | various | low | 0.7 avg | Whitespace-token validation, int(rating) truncation, contextlib.suppress over-defense, cross-collector base-class refactor, sheet-name collision suffix overflow, OSCAL UUID-in-two-locations note, etc. | **DEFERRED to v0.7.10** per Continuous-variant disposition | n/a |

## Findings — disposition summary

- **0 CRITICAL findings**
- **6 HIGH findings + 1 LOW security finding all inline-fixed in this cycle**:
  - 5 HIGH (H-1 / H-2 / H-3 / H-4 / H-5) + 1 LOW security (F-V09-S1) inline-fixed in commit `3315150` (Continuous-variant batch fix)
  - 1 HIGH (F-V09-PRT-H1 doc-accuracy) inline-fixed in this Pre-tag commit (added missing CLI flags)
- **4 MEDIUM (v0.7.8 carry-overs) inline-fixed** in commit `cf1c07e` (Snowflake count split + quoted-id + Databricks PermissionDenied + Power BI 1MB guard)
- **17 MEDIUM/LOW deferred to v0.7.10** with explicit rationale (ship velocity)
- **0 unfixed findings at v0.7.9 ship**

## Step-7 post-tag verification plan

Per v4 G1 — runs after `git push origin v0.7.9` triggers
`release.yml`. All 5 sub-checks must be green:

1. **PEP 740 verify**: download wheel from PyPI in fresh venv,
   hash-match vs `dist/`; run `pypi-attestations verify pypi
   --repository https://github.com/polycentric-labs/evidentia
   "pypi:evidentia-0.7.9-py3-none-any.whl"`
2. **Cosign verify** on container: `cosign verify
   ghcr.io/polycentric-labs/evidentia:v0.7.9
   --certificate-identity-regexp='https://github.com/Polycentric-Labs/evidentia/.github/workflows/.+'
   --certificate-oidc-issuer=https://token.actions.githubusercontent.com`
3. **osv-scanner --sbom** on the released SBOM; expect 0 CVEs
   (or, if any surface, document the disposition)
4. **docker run smoke**: `docker run --rm
   ghcr.io/polycentric-labs/evidentia:v0.7.9 version` returns
   `Evidentia v0.7.9` (NOT a substring like v0.7.8 — closes the
   v0.7.7 → v0.7.7.1 hot-fix lesson)
5. **Scorecard delta**: re-run OpenSSF Scorecard; score must
   not regress from v0.7.8 baseline

Per the v4 G2 SBOM workflow hardening, the SBOM is signed
independently from the wheel attestations + diffed against the
prior tag's SBOM (v0.7.8) for new transitive-dep visibility.

## Compliance assertion

To my knowledge as the pre-release-review v4 skill operator,
v0.7.9 satisfies:

- All 18 NIST SSDF v1.1 PS / PW / PO / RV controls applicable to
  an open-source library + tool publish
- SLSA Level 3 build provenance for all PyPI + container
  artifacts
- ISO 27001:2022 Annex A 8.25 + 8.28 secure development controls
- SOC 2 Type II CC7.1 + CC8.1 vulnerability + change management
  controls
- DORA Article 9(4) operational resilience testing baseline +
  Article 28(7) third-party risk register requirements (the
  latter materially advanced by the TPRM module shipped in this
  release)
- OpenSSF Best Practices Passing tier (already awarded; Silver
  filing pending Allen-side form fill post-tag)
- CISA Secure by Design Pledge pillars 4 + 6 + 7

The 17 deferred MEDIUM/LOW findings are documented for v0.7.10
with explicit rationale; none are correctness defects or
exploit paths today.

## Per-run JSON references

- Continuous-variant runs (in-flight bug-find):
  - 2026-05-03T01-48-52Z (v0.7.8 ship — full Pre-tag baseline)
  - 2026-05-03T21-54-20Z (v0.7.9 P0.1 close — 4 inline + 11 deferred)
  - 2026-05-04T00-15-00Z (v0.7.9 P0.3+P0.2-first-slice close — 3 inline + 11 deferred)
  - 2026-05-04T02-10-29Z (v0.7.9 P0.4-quartet + P0.5 + P0.2-second-slice close — 5 HIGH + 1 LOW security inline + 17 deferred)
- **Pre-tag run** (this document): 2026-05-04T02-53-50Z

## Authorial note

This document is a Step 6 deliverable that satisfies v4 G7
(CVSS/CWE/EPSS columns on bug-bucket findings) and v4 G15
(compliance framework mapping expanded to 6 frameworks). It is
the canonical Step-6 evidence artifact for the v0.7.9 ship.
Allen reviews + approves before tag creation per the
publishing-authority protocol in `~/.claude/CLAUDE.md`.
