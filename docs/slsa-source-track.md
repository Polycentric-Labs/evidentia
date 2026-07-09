# SLSA Source Track posture

This document is an **honest self-assessment** of Evidentia's source-control
integrity against the [SLSA](https://slsa.dev) **Source Track**, and a claim of
the level the project **genuinely meets today**. It maps each Source Track
requirement to verifiable evidence in this repository's GitHub configuration,
and states — precisely — the controls that are **not** met and the gap to the
next level. Every project-specific claim below is verifiable with the commands
in [How to verify](#how-to-verify); nothing is asserted that cannot be checked
against the live repo.

> **Bottom line.** Evidentia **enforces the SLSA Source Level 3 technical
> controls** (Continuous Technical Controls): continuous, technically-enforced,
> signed branch and tag protection with retained history and no bypass actors —
> all independently verifiable via the rulesets API. One honest caveat: GitHub
> does not emit standardized SLSA Source *attestation artifacts* (VSAs), so this
> is a **controls-enforced** claim, not a formal-attestation claim (disclosed
> throughout). It does **not** meet **Source Level 4** (Two-Party Review),
> because the project has a single maintainer and GitHub cannot let an author
> approve their own pull request — so two-trusted-person review is structurally
> unattainable until a second trusted maintainer joins. The L4 gap is a
> deliberate, honestly-disclosed ceiling, not an oversight.

## What the SLSA Source Track is

SLSA (Supply-chain Levels for Software Artifacts) has **two tracks**: the
**Build Track** (integrity of how artifacts are built) and the **Source
Track** (integrity of the source / version-control process — authoring,
reviewing, and managing source code *before* a tagged commit reaches a
builder). The two are independent: a project earns a level on each track
separately.

**Spec version this assessment targets.** The current SLSA specification is
**v1.2**, **Approved**. SLSA **v1.2** (announced November 2025) promoted the
Source Track from *experimental* to *approved* and reorganized the source
levels around history and continuous enforcement. The Build Track had been
stabilized earlier in **SLSA v1.1** (approved **April 2025**), which was
largely a clarity refresh. This document assesses Evidentia against the **v1.2
Source Track**; it does not restate Evidentia's Build Track posture (PEP 740
attestations, cosign keyless container signatures, SLSA build provenance),
which is covered in `SECURITY.md` and [`docs/verification.md`](verification.md).

> Note on Source Track terminology: SLSA generates **Verification Summary
> Attestations (VSAs)** and **Source Provenance Attestations** through a Source
> Control System (SCS). GitHub does not (yet) emit standardized SLSA Source VSAs
> for arbitrary repositories. This assessment therefore maps each Source Track
> requirement to the **technical control GitHub enforces** (rulesets, signature
> verification, history protection) as the evidence, and flags the
> attestation-emission requirements that depend on SCS tooling Evidentia does
> not control. See [What we cannot self-attest](#what-we-cannot-self-attest).

## The Source Track levels (SLSA v1.2)

| Level | Name | Focus |
|-------|------|-------|
| **Source L1** | Version Controlled | Source is in a VCS with immutable, uniquely-identifiable revisions and change-display tooling. |
| **Source L2** | History & Provenance | Branch history is continuous, immutable, and retained; tags cannot be moved or deleted; changes to named references are recorded; provenance is produced contemporaneously. |
| **Source L3** | Continuous Technical Controls | The organization enforces customized technical controls on specific named references, continuously, with the controls recorded in contemporaneous attestations; continuity is tracked from a start revision and re-established after any lapse. |
| **Source L4** | Two-Party Review | Changes to protected branches must be agreed to by **two or more trusted persons** (uploader + reviewer, or two reviewers), via an informed review covering security-relevant properties. |

(Source: SLSA v1.2 Source requirements,
<https://slsa.dev/spec/v1.2/source-requirements>.)

## Evidentia's source controls (ground truth)

All facts below were read from the live GitHub configuration of
`Polycentric-Labs/evidentia`. Three rulesets govern the source:

1. **Org default-branch baseline** (ruleset `16831409`,
   `polycentric-labs-default-branch-baseline`, Organization-level, **active**)
   — applies to the default branch of **all** repos in the org. Rules:
   `deletion`, `non_fast_forward`, `required_signatures`. `bypass_actors: []`.

2. **`main` PR flow** (ruleset `18097115`,
   *"main — PR flow (required checks + merge queue)"*, Repository-level,
   **active**) — targets the default branch. Rules: `pull_request`
   (allowed merge methods: `squash`), `required_status_checks`
   (**21** required checks), `merge_queue` (SQUASH), `required_linear_history`,
   `required_signatures`, `non_fast_forward`. `bypass_actors: []`,
   `current_user_can_bypass: never`.

3. **Release-tag protection** (ruleset `18175057`,
   *"Protect release tags (v\*)"*, Repository-level, **active**) — targets
   `refs/tags/v*`. Rules: `deletion`, `non_fast_forward`,
   `required_signatures`. `bypass_actors: []`, `current_user_can_bypass:
   never`.

Supporting facts:

- **Signed commits.** `commit.gpgsign=true` with `gpg.format=ssh` locally, and
  `required_signatures` is enforced server-side on both the default branch
  (two rulesets) and release tags. The current `main` HEAD commit verifies on
  GitHub (`verification.verified = true`, `reason = valid`) — merge-queue squash
  commits are GitHub-signed.
- **No force-push / no deletion.** `non_fast_forward` + `deletion` rules on
  both the default branch and `v*` tags; `required_linear_history` on `main`.
- **No bypass.** Every ruleset has an **empty** `bypass_actors` list; the
  repo rulesets additionally report `current_user_can_bypass: never`. A direct
  `git push origin main` fails — changes must go through a PR + the merge queue.
- **Release model.** Tag-driven: `git tag -s vX.Y.Z && git push origin vX.Y.Z`
  fires `release.yml`. Tags are signed and protected from move/delete by
  ruleset `18175057`.
- **Project shape.** 8 `evidentia-*` Python packages published to PyPI
  (`evidentia`, `-ai`, `-api`, `-collectors`, `-core`, `-eval`, `-integrations`,
  `-mcp`), plus `evidentia-ui` (a TypeScript/Vite/React UI served by the API,
  not a PyPI wheel). Apache-2.0. Single maintainer (Allen Byrd / Polycentric
  Labs).

## Requirement-by-requirement assessment

### Source L1 — Version Controlled · **MET**

| Requirement | Evidence | Status |
|-------------|----------|--------|
| Source in a VCS with a stable locator | Public Git repo `github.com/Polycentric-Labs/evidentia` | ✅ |
| Revisions immutable + uniquely identifiable | Git content-addressed commit SHAs | ✅ |
| Tooling to display changes between revisions | GitHub diff / `git diff` / PR review UI | ✅ |
| Identity management to authenticate actors | GitHub accounts; signed commits attribute revisions | ✅ |

**L1 is fully met.**

### Source L2 — History & Provenance · **MET**

| Requirement | Evidence | Status |
|-------------|----------|--------|
| History is continuous, immutable, retained | `non_fast_forward` + `deletion` protection on `main` (org baseline + repo ruleset) and `required_linear_history` | ✅ |
| Tags cannot be moved or deleted | Tag ruleset `18175057`: `deletion` + `non_fast_forward` on `refs/tags/v*` | ✅ |
| Changes to named references recorded (who/when) | GitHub records every push/merge to `main` and every tag in the ref/activity log; merge-queue squash commits are attributed | ✅ |
| Access control on history enforced | Rulesets active org-wide and repo-level; empty bypass | ✅ |
| Branch updates preserve ancestry | `required_linear_history` + `non_fast_forward` | ✅ |
| Source Provenance Attestation produced contemporaneously | GitHub's signed merge commits + ref activity log serve as the contemporaneous record; **standardized SLSA Source VSA emission is not available** — see caveat | ⚠️ partial (see below) |

**L2 is met in substance.** The history-integrity, tag-immutability, and
recorded-reference-change requirements are technically enforced and verifiable.
The only soft spot is the *form* of the attestation: SLSA L2 envisions a Source
Provenance Attestation emitted by the SCS. GitHub does not emit standardized
SLSA Source VSAs for this repo; the equivalent evidence is GitHub's
cryptographically-signed commit record and immutable ref-activity log. We claim
L2 on the strength of the enforced controls and contemporaneous record, and
flag the formal-VSA gap honestly in
[What we cannot self-attest](#what-we-cannot-self-attest).

### Source L3 — Continuous Technical Controls · **MET**

| Requirement | Evidence | Status |
|-------------|----------|--------|
| Org enforces customized technical controls on specific named refs | Repo ruleset `18097115` on `main`: PR-required, 21 required status checks, merge queue, signed commits, linear history; tag ruleset `18175057` on `v*` | ✅ |
| Controls enforced **continuously** (no lapse) | Rulesets are `enforcement: active`; org baseline active since 2026-05-25; bypass lists empty — there is no actor who can silently disable enforcement for a single change | ✅ |
| Controls documented (their meaning) | This document + [`docs/scorecard-posture.md`](scorecard-posture.md) + `SECURITY.md` define the enforced controls and their intent | ✅ |
| Continuity tracked from a start revision | Org baseline ruleset `created_at` 2026-05-25; repo PR-flow ruleset `created_at` 2026-06-24; tag ruleset `created_at` 2026-06-26 — each establishes a continuity start point | ✅ |

**L3 is met.** Evidentia enforces a customized, documented set of technical
controls on its protected `main` and `v*` references, continuously and without
bypass. The required-status-checks gate (21 contexts including CodeQL SAST,
cross-platform pytest, ruff, mypy, OSV/SBOM scan, gitleaks secret-scan, OpenAPI
+ CLI↔GUI drift gates, and workflow-permission audit) is itself part of the
enforced control surface.

> Honest caveat on L3's attestation clause: SLSA L3 also expects the enforced
> controls to be **recorded in contemporaneously-produced attestations** with
> `ORG_SOURCE_`-prefixed properties emitted by the SCS. GitHub's ruleset model
> does not emit those standardized source attestations today. We rely on the
> enforced-control evidence (queryable live via the rulesets API) plus this
> documented control inventory. This is the same SCS-tooling limitation noted at
> L2 and is disclosed, not glossed.

### Source L4 — Two-Party Review · **NOT MET** (this is the ceiling)

| Requirement | Reality | Status |
|-------------|---------|--------|
| Changes to protected branches agreed to by **two or more trusted persons** | **Single maintainer.** The `main` ruleset requires a PR (`pull_request` rule), but `required_approving_review_count` is **0** — because GitHub does not permit an author to approve their own PR, a non-zero requirement on a solo project would deadlock every merge. There is no second trusted person to review. | ❌ |
| Uploader and reviewer are different trusted persons (or two reviewers) | Not satisfiable with one maintainer | ❌ |
| Informed review covering security-relevant properties | Partially substituted by automated gates (21 required checks incl. CodeQL SAST) + a mandatory `/pre-release-review` before every tag, but these are **automated controls, not a second human reviewer** | ⚠️ substitute only |

**L4 is not met, and we do not claim it.** The honest gap is **two-person
review**. Evidentia is a single-maintainer project; GitHub structurally blocks
self-approval, so the "two trusted persons" requirement cannot be satisfied no
matter how the ruleset is configured. The PR-flow ruleset enforces the *process*
(every change is a PR through the merge queue, with 21 required checks and an
empty bypass list), but the *human* two-party-review control at the heart of L4
is absent. We surface this rather than papering over it with automated-gate
substitutes.

## Honest summary of the claim

| Level | Name | Status |
|-------|------|--------|
| Source L1 | Version Controlled | **MET** |
| Source L2 | History & Provenance | **MET** (formal SCS-emitted VSA not available; enforced-control + signed-history evidence substitutes — disclosed) |
| Source L3 | Continuous Technical Controls | **MET** (formal SCS source attestation not available; live rulesets + this inventory substitute — disclosed) |
| **Source L4** | **Two-Party Review** | **NOT MET — solo maintainer; self-approval is impossible on GitHub** |

**Claimed: the SLSA Source Level 3 _technical controls_ are enforced and
independently verifiable**, with the L2/L3 attestation-*format* caveats
disclosed above (the enforced controls themselves are real and queryable; only
the standardized SCS-emitted attestation artifacts are unavailable from GitHub
today). This is deliberately a controls-enforced claim, **not** a formal SLSA
Source VSA claim.

## Gap to the next level (L3 → L4)

The single blocker is **two trusted-person review**. To reach Source L4:

1. **Add a second trusted maintainer** to `Polycentric-Labs`. This is the
   structural prerequisite — without a second human, L4 is unreachable.
2. **Set `required_approving_review_count` to ≥ 1** on the `main` ruleset
   (`18097115`) once a second reviewer exists, so each PR is approved by a
   trusted person who is not the author. Optionally enable
   `require_last_push_approval` and a CODEOWNERS file (none exists today) to
   bind review to the relevant code areas.
3. **Keep the informed-review bar**: reviews should cover security-relevant
   properties of the change (the spec's "informed review"), with re-review when
   the final revision changes during review.
4. **Trusted-robot exceptions** (e.g. Dependabot) remain permissible under L4
   and need not be human-reviewed, consistent with the spec.

Until a second trusted maintainer exists, **Source Level 3 is the honest
ceiling**, and Evidentia claims exactly that — no more.

## What we cannot self-attest

To keep this assessment honest, these items are **not** claimed as fully
satisfied and are flagged for a reviewer:

- **Standardized SLSA Source VSAs / Source Provenance Attestations.** GitHub
  does not emit machine-readable SLSA Source-track attestations (with
  `ORG_SOURCE_` properties) for this repo. The L2/L3 evidence here is the
  **enforced technical control** (queryable via the rulesets API) plus
  signed-commit and ref-activity records — strong evidence of the control, but
  not the spec's envisioned attestation *artifact*. A formal SLSA Source VSA
  would require SCS tooling Evidentia does not control.
- **Two-person review (L4).** Not met (solo maintainer) — stated plainly above.

## How to verify

All of the following are read-only and reproducible by anyone with `gh` (no
special permissions needed for public ruleset metadata):

```bash
# 1. Org default-branch baseline (signed commits + no force-push/delete, org-wide)
gh api orgs/Polycentric-Labs/rulesets/16831409

# 2. main PR-flow ruleset: PR required, 21 status checks, merge queue,
#    signed commits, linear history, EMPTY bypass_actors, can_bypass=never
gh api repos/Polycentric-Labs/evidentia/rulesets/18097115

#    Count the required status checks (expect 21):
gh api repos/Polycentric-Labs/evidentia/rulesets/18097115 \
  --jq '.rules[] | select(.type=="required_status_checks")
        | .parameters.required_status_checks | length'

# 3. Release-tag protection on refs/tags/v*: deletion + non_fast_forward +
#    required_signatures, EMPTY bypass_actors
gh api repos/Polycentric-Labs/evidentia/rulesets/18175057

# 4. Confirm main HEAD commit is signature-verified by GitHub
gh api repos/Polycentric-Labs/evidentia/commits/main \
  --jq '.commit.verification | {verified, reason}'

# 5. Local signing config
git config --get commit.gpgsign   # -> true
git config --get gpg.format       # -> ssh
```

Expected results (as of this writing): ruleset 16831409 has rules
`deletion` + `non_fast_forward` + `required_signatures` with empty
`bypass_actors`; ruleset 18097115 reports 21 required status checks, an empty
`bypass_actors`, and `current_user_can_bypass: "never"`; ruleset 18175057
protects `refs/tags/v*` with `deletion` + `non_fast_forward` +
`required_signatures`; and `main`'s HEAD verifies (`verified: true`,
`reason: "valid"`).

## References

- SLSA v1.2 specification — <https://slsa.dev/spec/v1.2/>
- SLSA v1.2 Source requirements (Source Track levels) —
  <https://slsa.dev/spec/v1.2/source-requirements>
- Announcing SLSA v1.2 (Source Track promoted to Approved, November 2025) —
  <https://slsa.dev/blog/2025/11/announce-slsa-v1.2>
- SLSA v1.1 is now Approved (Build Track, April 2025) —
  <https://slsa.dev/blog/2025/04/slsa-v1.1>
- Evidentia OpenSSF Scorecard posture — [`docs/scorecard-posture.md`](scorecard-posture.md)
- Evidentia verification guide — [`docs/verification.md`](verification.md)
