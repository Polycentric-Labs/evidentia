# Security review — v0.10.7

> **Status**: in-cycle artifact for the v0.10.7 ship — the security-review
> write-up that was deferred at ship time (Step 7.G ship-doc landed in
> internal memory; this public companion was carried to the v0.10.8 docs
> close-out, where it was authored from the `[0.10.7]` CHANGELOG block +
> [`docs/v0.10.7-plan.md`](v0.10.7-plan.md)).
>
> **Theme**: web console (GUI v2) visual refresh + gap-report export +
> the last hygiene / automation-debt / wiki-fill / doc-accuracy cycle on
> the v0.10.x line before the v0.11 federal-compliance theme.
>
> **Structure note**: this document follows the structure + voice of
> [`docs/security-review-v0.10.4.md`](security-review-v0.10.4.md) (the
> last in-repo review at authoring time). The v0.10.5 + v0.10.6 reviews
> had no in-repo doc either; all three
> ([v0.10.5](security-review-v0.10.5.md) +
> [v0.10.6](security-review-v0.10.6.md) + this one) were backfilled
> together during the v0.10.8 docs close-out.
>
> **Sourcing discipline**: the cycle narrative is drawn from the
> `CHANGELOG.md` `[0.10.7]` block, `docs/v0.10.7-plan.md`, and the
> committed hook / script source. The ship-time facts not derivable from
> those sources (container digest, tag SHA, finding counts, Step 7 numeric
> results, streak position) were **verified + filled 2026-06-03 during the
> v0.10.8 Wave-1 close-out** from the per-run audit JSON
> (`.local/pre-release-review/runs/2026-05-31T01-55-11Z-v0.10.7.json`). A
> few plan-derived expectations were corrected against that JSON (the
> review was right-sized to a single pass; Scorecard was not re-run at
> ship).

## Cycle scope

v0.10.7 is the seventh patch on the v0.10.x line, tagged 2026-05-30 (the
`[0.10.7]` CHANGELOG date). Per the `docs/v0.10.7-plan.md` lock-in
(2026-05-27, "do it all" wiki directive), the cycle delivered a web-UI +
hardening + automation-debt + documentation pass:

1. **Web console — GUI v2 visual refresh.** A presentation-only design
   pass: federal-blue interactive primary on a warm off-white workspace
   with deep-navy brand chrome, the CLI-matched severity palette preserved
   verbatim, self-hosted IBM Plex Sans/Mono + favicons / PWA manifest /
   Open-Graph assets (air-gap clean, no CDN), a wired light/dark toggle
   with a no-flash inline theme script, and every route + the onboarding
   flow restyled. All API / SSE / Zustand wiring, the OpenAPI type
   contract, severity hues, and accessibility preserved; live-validated
   across all 8 routes with zero console errors.
2. **Web console — gap-report export/download.** The Gap Analyze results
   expose a one-click export to all 8 report formats (`json`, `oscal-ar`,
   `sarif`, `ocsf`, `ocsf-detection`, `cyclonedx-vex`, `csv`, `markdown`)
   wired to the real `POST /api/gap/export` blob download, plus an
   OpenAPI → TypeScript type-generation step and a CI type-parity
   drift-gate so the typed frontend client cannot silently diverge from
   the API schema.
3. **v0.10.6 code-quality reviewer backlog (Groups A + D).** OSPS
   crosswalk regeneration (`gen_osps_crosswalks.py` deterministic
   rebuild + a single-source upstream-SHA constant module), `translate_url()`
   extraction into a tested module, a GitHub OSPS collector DRY pass
   (`_unknown_finding()` factory), an asymmetric-error fix in
   `_file_present_at_any` (5xx now surfaces UNKNOWN, not FAIL), and the
   two v0.10.6 Step 7.D Scorecard alerts (#123 pin-pinning + #124
   token-permission scoping) closed.
4. **Blocking pre-push gate (Layer 2)** — a hand-rolled `.githooks/pre-push`
   orchestrator (consistent with the existing `.githooks/commit-msg`, no
   `core.hooksPath` conflict) running, by ship time, 9 blocking checks:
   action-pin syntax, secret-pattern scan, CHANGELOG-presence-on-version-bump,
   docs-health `--strict`, workflow-perms `--strict`, `uv.lock`
   third-party pin-drift, OSPS-crosswalk drift, version-consistency
   (the never-skip version-anchor guard), and the commit-signature gate
   that closes F-V107-1 (see Findings ledger). Bypass logging to a
   gitignored JSONL log.
5. **`audit_workflow_permissions.py` promoted to a blocking CI gate**
   (`--strict` + a `# JUSTIFIED:` annotation parser + `--json` output;
   the new `verify-workflow-perms.yml` workflow runs it on every PR +
   push; 3 workflows carry JUSTIFIED annotations).
6. **In-repo wiki content fill (~47 pages)** — auto-generated
   canonical-doc mirrors + reference pages (CLI / MCP tools /
   configuration / catalogs / crosswalks) + 7 per-package API pages, plus
   hand-authored, triple-validated concept / guide / compliance pages and
   an FAQ. Generators wired into `sync-wiki.yml`.
7. **Two real product bug fixes** — TPRM + governance CLI enum-field
   rendering (the Pydantic `use_enum_values` `.value`-on-`str` crash),
   and `poam milestone` commands accepting a unique milestone-id prefix.
8. **Doc-wide CLI-example accuracy sweep** — fixed the `gap analyze`
   examples in `README.md`, both quickstarts, and the air-gapped guide to
   the real surface, and corrected the federal-SI walkthrough's Step-8
   CLI. Surfaced two multi-cycle naming/usage drifts (§12.5 CIMD
   terminology; §12.6 `gap analyze` example drift).
9. **Repo-hygiene + version-tracking hardening (Phase E)** — a
   declarative `scripts/version_tracked_files.yaml` manifest driving both
   the bumper and the new `check_version_consistency.py` gate, a frontend
   version-literal guard, `openapi.json` tracked as a version-anchor, a
   stale-`CITATION.cff` fix, README "Recent Releases" auto-generation, and
   a capitalized-subject commit convention enforced by `.githooks/commit-msg`.

Reported cycle health at ship (from the `[0.10.7]` CHANGELOG block):
**3863 tests pass / 14 skipped; mypy strict 0/0 across 272 source files;
ruff clean.** Workspace ships **8 PyPI packages**, unchanged from v0.10.6
(no new packages this cycle, so no LL-V105-1 partial-publish recurrence
risk).

## Review structure

The `/security-review` + `/code-review` review passes for this cycle ran
under `superpowers:subagent-driven-development` (per-phase
implementer → spec-compliance reviewer → code-quality reviewer →
fix-loop), direct-on-`main` per Evidentia's standing direct-push pattern.

| Pass | Scope | Verdict |
|---|---|---|
| `/security-review` (right-sized to a single pre-tag pass) | The v0.10.7 diff (`v0.10.6..HEAD`, 32 commits): GUI v2 presentation pass + export surface + the hardening/automation scripts + wiki generators | **PROCEED-CLEAN — 0 findings**. One Agent-dispatch pass (right-sized from the usual 3 by user direction — low surface: GUI is presentation-only and live-validated, the only logic deltas are two enum-render fixes + tooling/CI/docs). Traced the export endpoint + CLI fixes + poam + the client download; grepped every `.tsx` for unsafe React HTML-injection sinks (0 matches — no XSS). |
| `/code-review` (on the new server-side logic) | `gaps.py` export endpoint + `schemas.py` `GapExportRequest` + the tprm/governance enum-render fix + poam milestone-prefix resolution | **SOUND — 0 findings** (0 CRITICAL / 0 HIGH / 0 MEDIUM / 0 LOW; 41/41 relevant tests pass). The v0.10.7-plan §12 corrections-log captures the accuracy drifts caught + fixed in-cycle. |
| Doc-accuracy sweep (D6.B) | Every `evidentia ...` example across README + `docs/**/*.md` + wiki | Two multi-cycle drifts found + fixed (§12.5 CIMD terminology; §12.6 `gap analyze` examples). The corrected `gap analyze` proven to run end-to-end against the newly-bundled inventory (exit 0, 277 findings per §12.7). |

> **0-finding bar**: the cycle is recorded as a **0-finding ship** — no
> CRITICAL / HIGH / MEDIUM code-security finding reached the tag (the
> per-run JSON's `step_4` records 0/0/0/0). The two items in the JSON's
> `post_push_findings` array are **F-V107-1** (INFO — an *infrastructure*
> gap in the push path, not a code vulnerability; closed in-cycle by the
> new pre-push signing gate) and **F-V107-2** (LOW — the already-accepted
> `tuf` 6.0.0 carry, GHSA-qp9x-wp8f-qgjj). See the Findings ledger.

## F-V107-1 — unsigned commits admitted via the admin-bypass path

The single SECURITY-class finding this cycle is **F-V107-1**, an
infrastructure / process gap rather than a code defect, documented in the
committed remediation source
(`scripts/pre_push/check_commit_signatures.py`):

**The gap.** Branch protection on `main` requires verified signatures,
but the deliberate `enforce_admins=False` direct-push pattern lets an
admin *bypass* that rule. At the v0.10.7 push, three commits reached
`main` unsigned — `eedde81`, `5f44982`, `458a94c` (the Phase-E
version-tracking commits) — and were only flagged by GitHub *after the
fact*. No local gate caught the unsigned commits before they left the
machine.

**The remediation (landed in-cycle).** A new pre-push check —
**`.githooks/pre-push` check #9, `scripts/pre_push/check_commit_signatures.py`** —
asserts that every commit in the push range carries a signature, BEFORE
it leaves the machine, so the admin-bypass path cannot silently admit an
unsigned commit again. The decision rule blocks on `git log %G?` of:

- `N` — no signature at all (the exact failure mode that slipped through)
- `B` — a bad / forged signature

and PASSes on:

- `G` — good, verified signature
- `U` — good signature whose signer is not in the *local* allowed-signers
  file (the commit IS signed; GitHub verifies the registered key)
- `E` — signature unverifiable locally (e.g. no allowed-signers configured)

so a fresh clone without `gpg.ssh.allowedSignersFile` set does not
spuriously fail on otherwise-signed commits. The check is range-aware
(`RANGE_BASE..RANGE_TIP`), with the standard `origin/main`-or-tip-only
fallback for a brand-new branch.

**Defense-in-depth posture.** The local pre-push check is the
machine-side defense. The server-side complement — a required-signatures
ruleset on `main` with `enforce_admins=true` — is the v0.10.8 release
gate (B1/G2 in `docs/v0.10.8-plan.md`), which closes F-V107-1 server-side
while the local check stays as defense-in-depth. As of this write-up
(verified 2026-06-03, mid-v0.10.8) that server-side ruleset is **not yet
applied** — B1/G2 remains a pending Tier-4 gate later in the v0.10.8 cycle.

## Pre-push gate breakdown (9-check Layer-2 table)

The blocking pre-push gate as it stood at v0.10.7 ship (from
`.githooks/pre-push`). All checks run before the hook exits, so the
operator sees every failure at once:

| # | Check | Behavior |
|---|---|---|
| 1 | `check_action_pins` (action-pin syntax via pinact) | BLOCK; SKIP-with-nag if `pinact` missing |
| 2 | `check_secrets` (secret-pattern scan) | BLOCK; never prints the secret value |
| 3 | `check_changelog_present` (CHANGELOG block on version bump) | BLOCK |
| 4 | `check_docs_health` (`check_docs_health.py --strict`) | BLOCK on FAIL |
| 5 | `check_workflow_perms` (`audit_workflow_permissions.py --strict`) | BLOCK on FAIL |
| 6 | `check_uv_lock_pin_drift` (third-party pin drift on workspace bump) | BLOCK |
| 7 | `check_osps_crosswalk_drift` (OSPS regen `--check`) | BLOCK; range-gated to OSPS-file pushes |
| 8 | `check_version_consistency` (never-skip version-anchor coverage) | BLOCK; always runs |
| 9 | `check_commit_signatures` (every push-range commit signed) | BLOCK on `%G?` N/B — **closes F-V107-1** |

Bypass is logged: `EVIDENTIA_ALLOW_PRE_PUSH_BYPASS=1` plus a required
non-empty `EVIDENTIA_PRE_PUSH_BYPASS_REASON` (or an interactive `/dev/tty`
prompt) appends a JSONL row to `.local/hooks/pre-push-bypass.log`
(gitignored). Bypass is refused if non-interactive and no reason env var
is set.

## Step 7 — post-tag verification

Per the v0.10.7-plan Step 7 contract (Tasks A–G). Results below are filled
from the per-run JSON (`release.yml` run `26700606160`, conclusion
**success**; verified 2026-06-03):

| Step | Check | Result |
|---|---|---|
| 7.A | PEP 740 attestation sweep | **PASS** — PyPI integrity API 200; sampled `evidentia` + `evidentia-core` + `evidentia-mcp` (all 8 packages published at 0.10.7) |
| 7.B | Container smoke (`docker run … --version`) | **PASS** — "Evidentia v0.10.7 / Python 3.14.5" |
| 7.C | osv-scanner on published SBOM | **PASS** — 0 issues / 183 packages |
| 7.D | Scorecard delta | CI-scheduled, **not re-run at ship**; the two v0.10.6 alerts (#123 pin-pinning + #124 token-permission scoping) were addressed in-cycle (Cycle-scope item 3); prior baseline ~6.5 |
| 7.E | Fresh-venv install | **PASS** — `uvx` py3.12 → `evidentia 0.10.7` installs + imports |
| 7.F | cosign verify keyless OIDC + SLSA Provenance v1 | **PASS** — exit 0 |
| 7.G | Memory ship-doc + lessons-learned + CHANGELOG cross-check | Recorded (ship-memory) |

**Step 7 verdict**: **PROCEED-CLEAN** — `release.yml` run `26700606160`
succeeded; the per-run JSON estimates this the **~20th consecutive
PROCEED-CLEAN** of the v0.7.x → v0.10.x line (v0.10.4 was the 17th; v0.10.5
+ v0.10.6 shipped between).

## Findings ledger

### SECURITY-class item (closed in-cycle)

| ID | Class | Description | Disposition |
|---|---|---|---|
| F-V107-1 | Infrastructure / process | Unsigned commits (`eedde81` / `5f44982` / `458a94c`) reached `main` via the `enforce_admins=False` admin-bypass path; only flagged by GitHub after the fact | **Closed in-cycle** by the new pre-push signing gate (`.githooks/pre-push` #9 + `scripts/pre_push/check_commit_signatures.py`); server-side required-signatures ruleset is the v0.10.8 follow-up |

### Accepted supply-chain carry (osv allowlist)

| ID | Severity | Description | Disposition |
|---|---|---|---|
| GHSA-qp9x-wp8f-qgjj | MEDIUM (CVSS 4.0) | `tuf` 6.0.0 platform-dependent delegation-path matching; disclosed 2026-05-28. Fix (tuf 7.0.0) upstream-blocked — sigstore 4.2.0 pins `tuf~=6.0`. `tuf` reaches Evidentia only transitively via sigstore's keyless trust-root fetch; no operator-controlled tuf delegation surface, so the weakness is not reachable. | Accepted in `osv-scanner.toml` with `ignoreUntil = 2026-11-29`; **removal trigger**: drop the entry + bump tuf to >=7.0.0 as soon as sigstore ships tuf-7 support (tracked v0.10.8) |

### §12 corrections-log accuracy drifts (caught + fixed in-cycle)

These are accuracy corrections (not security findings) surfaced by the
documentation verify-everything pass, recorded in
`docs/v0.10.7-plan.md` §12:

| Ref | Description | Fix |
|---|---|---|
| §12.5 | "CIMD" was mislabeled "Cryptographic Integrity Manifest Document"; it is "Client ID Metadata Document" (OAuth Dynamic Client Registration, RFC 7591) and does not sign anything. The real tool-output signing is the separate `SignedToolOutput` (Sigstore keyless) mechanism. | Corrected in `evidence-integrity.md`, `architecture.md`, `api-stability.md` + the regenerated wiki mirror; broader scrub of 4 active non-wiki docs queued for v0.10.8 |
| §12.6 | The README + quickstart `gap analyze` examples never matched the real CLI (`--framework` vs `--frameworks`; `--evidence-dir <dir>` vs `--inventory <file>` — a conceptual error; missing required `--output`; `oscal` vs `oscal-ar`). | Fixed doc-wide; a runnable bundled inventory added so the corrected examples execute |

## Aggregate cycle metrics

| Metric | v0.10.7 |
|---|---|
| Tests | 3863 pass / 14 skip (per CHANGELOG `[0.10.7]`) |
| mypy strict | 0 issues / 272 source files |
| ruff | clean |
| PyPI packages | 8 (unchanged from v0.10.6; no new packages) |
| SECURITY-class findings | 1 infrastructure (F-V107-1), closed in-cycle |
| Code security findings carried to ship | 0 |
| Accepted supply-chain carries | 1 (GHSA-qp9x-wp8f-qgjj, tuf 6.0.0) |
| Tag | `v0.10.7`, 2026-05-30 |
| Tag SHA | `01e643c15b572b21e19eb3a3be822b8fa966bc8a` |
| Tag object SHA | `6585937503e105ad68c73b91cac069eae5e31682` |
| Container digest | `sha256:4555eeb877e51d472646c1d17681f7df114a5b4819d1d29ab1f9f560cf1f72bb` |
| `release.yml` run | `26700606160` (conclusion: success) |
| Consecutive PROCEED-CLEAN streak | ~20th (per-run JSON estimate) |
| **Overall verdict** | **PROCEED-CLEAN (0-finding ship)** — ~20th consecutive |

## Cross-references

- CHANGELOG block: [CHANGELOG.md §[0.10.7]](../CHANGELOG.md)
- Plan: [docs/v0.10.7-plan.md](v0.10.7-plan.md) (§4 execution sequence + §12 corrections-log)
- Forward direction: [docs/v0.10.8-plan.md](v0.10.8-plan.md) (B1/G2 server-side required-signatures ruleset closing F-V107-1)
- Pre-push gate: [docs/pre-push-gate.md](pre-push-gate.md) (the 3-layer architecture; L2 is the blocking layer)
- Remediation source: `.githooks/pre-push` (check #9) + `scripts/pre_push/check_commit_signatures.py`
- Per-run JSON (audit trail): `.local/pre-release-review/runs/2026-05-31T01-55-11Z-v0.10.7.json`

---

*Authored during the v0.10.8 docs close-out (Phase F) from the
`CHANGELOG.md` `[0.10.7]` block + `docs/v0.10.7-plan.md` + committed hook /
script source; the ship-time facts were verified + filled 2026-06-03 from
the per-run audit JSON
(`.local/pre-release-review/runs/2026-05-31T01-55-11Z-v0.10.7.json`).
Reviewer of record: Allen Byrd `<allenfbyrd>`.*
