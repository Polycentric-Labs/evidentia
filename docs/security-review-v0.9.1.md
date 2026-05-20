# Security review — v0.9.1 (2026-05-15) — backfill

> **Backfill notice**: this artifact was written retrospectively during v0.9.8 P1.10 (2026-05-19). The original v0.9.1 cycle did not produce a contemporaneous review file — the cycle was consumed by the GitHub-organization migration from `allenfbyrd/evidentia` to `Polycentric-Labs/evidentia`, with no application-code changes shipped. This backfill summarizes the cycle's actual scope + retrospective compliance posture so the docs trail under `docs/security-review-v0.9.*.md` is complete.
>
> **Distinction from contemporaneous reviews**: this file does NOT carry per-finding CVSS / CWE / EPSS scoring because the cycle did not surface any new findings (no application-code diff). Findings columns are present in the v0.9.3 onward reviews where pre-release-review v4 + the `/code-review` + `/security-review` builtins were authored against actual code change.

## Summary

- **Cycle theme**: GitHub-organization migration (`allenfbyrd/evidentia` → `Polycentric-Labs/evidentia`); no feature code.
- **Tag**: `v0.9.1` (2026-05-15).
- **Application-code findings**: 0 (no application diff — only repo metadata changes).
- **Supply-chain posture**: maintained — PyPI Trusted Publisher OIDC routing migrated to the new org, cosign + PEP 740 attestations re-verified against the new ghcr.io path.
- **Compliance posture**: **PROCEED-CLEAN** — **16th consecutive** of the v0.7.x → v0.8.x → v0.9.x line.
  - NIST SSDF PW.5 (review for vulnerabilities): N/A (no diff)
  - NIST SSDF PO.5 (organize repository): satisfied (migration completed cleanly)
  - ISO 27001:2022 Annex A 5.10 (acceptable use of assets): satisfied
  - SOC 2 Type II CC8.1 (change management): satisfied (org transfer documented)
  - CISA Secure by Design Pledge: maintained
  - OpenSSF Best Practices Silver: maintained

## What shipped

Org-migration deliverables, per the v0.9.1 ROADMAP entry and the
`evidentia_org_migration` memory entry:

1. **Repository transfer** — `allenfbyrd/evidentia` → `Polycentric-Labs/evidentia`. Public (Apache-2.0). Branch protection rules + secrets re-established under the new org.
2. **Sibling private repo provisioning** — `Polycentric-Labs/evidentia-pro` created as a placeholder for the v1.1+ commercial tier (still empty at this cycle's ship; v0.9.8 P1.10 backfill notes that the private repo's first real content arrives post-v1.0).
3. **`allenfbyrd/evidentia-action` decision** — intentionally NOT migrated (archived public, separate concern).
4. **GHCR path migration** — `ghcr.io/allenfbyrd/evidentia` → `ghcr.io/polycentric-labs/evidentia`. The first ship-day push surfaced the v0.9.2 P-V92-Q3 "GHCR new-package private-by-default" gate (covered in `docs/security-review-v0.9.2.md`).
5. **PyPI Trusted Publisher OIDC re-routing** — workflow-file path updated; first publish under the new org succeeded.

## /security-review invocations

The v4 skill's mandatory `/security-review` invocations were NOT run for v0.9.1 because the cycle had no application-code diff to scope against. The skill's spec covers this case: when the diff is exclusively repo-metadata, the review batch reduces to a supply-chain verification step (PEP 740 + cosign + Trusted Publisher OIDC routing), which IS recorded in the v0.9.1 release pipeline run logs.

## Step 7 post-tag verification

- PEP 740 attestations: 7/7 packages signed under the new org's workflow identity
- cosign SLSA Provenance v1: signed against the new GHCR path
- osv-scanner: 0 NEW issues (paramiko LOW carry-forward from v0.9.0)
- docker run smoke: `docker run ghcr.io/polycentric-labs/evidentia:v0.9.1` resolved cleanly
- Pin-trap validation: pass (continuation of the v0.8.x trap series)
- Auto-populate from CHANGELOG: pass (release-pipeline G16)

## Carry-forwards into v0.9.2

- **GHCR public-flip release-checklist item** (surfaced day-of in the v0.9.2 review).
- **paramiko CVE-2026-44405 LOW** (upstream-unpatched; ongoing carry-forward through v0.9.8).
- **API-stability.md DRAFT** — first authored in v0.9.3 P5 (after v0.9.2 SHIPPED 2026-05-16) per the contemporaneous reviews.

## Distinction from contemporaneous reviews

This backfill differs from the v0.9.3+ pre-release-review v4 cycle artifacts in three ways:

1. **No per-finding scoring tables**: there were no findings to score. The contemporaneous reviews tabulate CVSS / CWE / EPSS per finding; this backfill records the empty set.
2. **No `/code-review` auto-fire records**: the auto-fire triggers (first-time-pattern imports, new security-module methods, etc.) require an application-code diff. The v0.9.1 org migration had none.
3. **Compliance counts updated mid-cycle**: pre-release-review v4 was introduced during v0.7.5 and stabilized by v0.7.16; the consecutive-PROCEED-CLEAN count documented here (16th) reflects the historical chain rather than a contemporaneous re-derivation.

## Cross-references

- [`docs/v0.9.0-shipped.md`](v0.9.0-shipped.md) — the preceding ship (federal-compliance theme)
- [`docs/security-review-v0.9.0.md`](security-review-v0.9.0.md) — the last contemporaneous review before this backfill
- [`docs/security-review-v0.9.2.md`](security-review-v0.9.2.md) — the next contemporaneous-but-also-backfilled review (post-org-migration feature ship)
- [`docs/ROADMAP.md`](ROADMAP.md) §v0.9.1 — cycle-scope narrative
- `~/.claude/projects/<evidentia-hash>/memory/evidentia_org_migration.md` — private memory entry documenting the migration decisions
