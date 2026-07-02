# Release rollback / yank / recovery runbook

> Consolidated decision procedure for recovering from a bad Evidentia
> release. This runbook is the single home for guidance that was
> previously scattered across [`release-checklist.md`](../release-checklist.md)
> (Step 8 re-trigger notes, Step 10 yank note), the per-release
> `security-review-*.md` "standard ladder" / "rollback path" text, and
> the `release.yml` workflow comments.
>
> **Read the one-line invariant first.** Evidentia releases are
> tag-driven and immutable by design: **a published `v*` tag is never
> moved or deleted** (the server now refuses to, see §1), and a bad
> release is recovered by **yanking on PyPI + shipping a new patch** —
> never by deleting an artifact or rewriting history. A version pinned
> with `==X.Y.Z` keeps installing after a yank, so the yank protects new
> consumers without breaking pinned deployments.

---

## 0. Scope and the model this runbook protects

Evidentia ships from a single tag push: `git tag -s vX.Y.Z && git push
origin vX.Y.Z` fires [`release.yml`](../../.github/workflows/release.yml),
which builds and validates **every** artifact — the 8 `evidentia-*`
wheels + sdists, the CycloneDX SBOM, and the container image (built
**from the locally-built wheels**, not from the package index) — and
smoke-tests the image **before** the irreversible PyPI publish. Only
after `build` succeeds does `publish-pypi` upload to PyPI, then
`publish-container` pushes + cosign-signs the byte-identical image to
GHCR and creates the GitHub Release last.

That ordering (adopted in v0.10.14 after the v0.10.12 packages-only
release) means **most failures are caught before anything is published**
— a base-image regression, a failing smoke test, or a red gate fails
`build` and `publish-pypi` never runs. This runbook covers the harder
case: a release that *did* publish and then turned out to be bad.

What "bad" means here:

- A functional defect users hit (broken import, wrong output, crash).
- A security issue in Evidentia's own code (see §6 for the GHSA path).
- A supply-chain / dependency problem in the resolved tree.
- A broken or incomplete artifact set (e.g. wheels published but the
  container failed — the literal v0.10.12 → v0.10.13 case).

What this runbook is **not**: it is not the place to "undo" a release by
deleting it. PyPI deletion and tag deletion are off the table by policy
**and** by server enforcement (§1). Recovery is always *forward*.

---

## 1. The invariant is now server-enforced (not just a convention)

"Never move or delete a published tag" used to be a discipline you had
to remember. As of **2026-06-26** it is enforced by GitHub on the
canonical repo, so an accidental `git push --force` or `gh release
delete` against a `v*` tag is refused at the server:

1. **A tag ruleset blocks tag deletion, force-updates, and unsigned
   tags.** The repository ruleset **"Protect release tags (v\*)"**
   (`enforcement: active`, `target: tag`) applies to `refs/tags/v*` and
   carries three rules: `deletion`, `non_fast_forward`, and
   `required_signatures`. A `v*` tag therefore cannot be deleted, cannot
   be moved to a new commit (no non-fast-forward update), and must be
   signed.
   *Verify:* `gh api repos/Polycentric-Labs/evidentia/rulesets/18175057
   --jq '{name, enforcement, rules: [.rules[].type]}'` →
   `non_fast_forward` / `deletion` / `required_signatures`.

2. **GitHub Immutable Releases is enabled.** Published GitHub Releases
   (and their attached assets — SBOM, SLSA provenance bundle) cannot be
   altered or re-pointed after creation.
   *Verify:* `gh api
   repos/Polycentric-Labs/evidentia/immutable-releases` →
   `{"enabled":true,...}`.

**Consequence for this runbook:** the v0.10.3-era "move-tag re-fire"
recovery (delete the remote tag, re-create it on a fixed commit,
re-push) is now **impossible** on `v*` tags — and that is the intended
state. The only correct recovery for a published-but-bad release is to
**ship a new patch tag**. The decision tree below never asks you to
delete or move a tag.

> The `release.yml` concurrency comment still references the historical
> "move-tag re-fire" pattern as the reason `cancel-in-progress: false`.
> The `cancel-in-progress: false` setting is still correct (a re-pushed
> *new patch* tag should queue behind an in-flight run, not cancel it);
> the move-tag framing in that comment predates the tag ruleset.

---

## 2. Why "yank", not "delete" — PEP 592, verified

The recovery ladder leans on PyPI **yank**, which is a deliberately
weaker action than deletion. From **PEP 592 ("Adding Yank Support to the
Simple API")**:

- **Yank is not delete.** "Yanking a file allows authors to effectively
  delete a file, without breaking things for people who have pinned to
  exactly a specific version." The file stays hosted.
- **A pinned `==X.Y.Z` install still resolves a yanked release.** Per the
  installer specification, "Yanked files are always ignored, unless they
  are the only file that matches a version specifier that 'pins' to an
  exact version using either `==` (without any modifiers that make it a
  range, such as `.*`)." So `pip install evidentia==X.Y.Z` and a
  hash-pinned lockfile entry keep working after the yank.
- **Non-pinned installs skip it.** "An installer MUST ignore yanked
  releases, if the selection constraints can be satisfied with a
  non-yanked version." A bare `pip install evidentia` or a range
  specifier resolves to the next good version automatically.
- **That is exactly the motivation.** PEP 592 frames yank as the way out
  of the delete catch-22: deleting "will break users who have followed
  best practices and pinned to a specific version," whereas yank stops
  *new* inadvertent installs without breaking pinned consumers.

**Provenance survives a yank.** Because the artifact bytes are
preserved, every signature and attestation bound to them stays valid: a
yanked wheel's PEP 740 / Sigstore attestation still verifies, its entry
in the Rekor transparency log is unchanged, and its SLSA build
provenance still resolves. Yank changes a release's *availability
status*, not its bytes — so it never invalidates the supply-chain chain
this project spends so much effort producing.

> **One-line dry-run reminder.** Before yanking, sanity-check that you
> are not about to break a pinned consumer: a yank leaves
> `pip install evidentia==<bad-version>` working *on purpose*. If your
> goal is to make that exact pin fail, yank is the wrong tool — there
> is no policy-compatible tool for that (deletion is barred), and the
> answer is to ship a fixed patch and advise upgrading.

---

## 3. Decision tree

```
A bad release vX.Y.Z is live (published to PyPI / GHCR / Releases).
│
├─ Q1. Is it a SECURITY issue in Evidentia's own code?
│      ├─ YES → run the security track:
│      │         · open/After-the-fact draft a GHSA (§6)
│      │         · yank the affected PyPI artifacts (§4)
│      │         · ship a fixed patch vX.Y.Z+1 (§4)
│      │         · publish the GHSA after the fix is on PyPI (§6)
│      └─ NO  → continue.
│
├─ Q2. What is broken, and how bad?
│      ├─ Functional defect users hit at runtime
│      │     → STANDARD LADDER (§4): yank + ship a new patch.
│      ├─ Bad/incompatible dependency in the resolved tree
│      │     → STANDARD LADDER (§4): yank + ship a new patch with the pin fixed.
│      ├─ Container only (wheels are fine) — the v0.10.12→v0.10.13 case
│      │     → CONTAINER ROLLBACK (§5): do NOT yank the good wheels;
│      │       fix the Dockerfile/base and ship a new patch; GHCR steps in §5.
│      └─ Cosmetic only (CHANGELOG typo, wrong release-note text)
│            → no yank. Correct the source in a normal PR; if the published
│              Release body is wrong, note that GitHub Immutable Releases
│              (§1) bars editing it — carry the correction in the next
│              release's notes + CHANGELOG instead.
│
├─ Q3. NEVER, regardless of branch above:
│      ├─ move or delete the vX.Y.Z tag        (barred by §1; impossible)
│      ├─ delete the PyPI files                (policy: yank, never delete)
│      └─ auto-yank on a smoke-test failure    (see the note below)
│
└─ Q4. Capture evidence (§7) and communicate (§8) on every real rollback.
```

### The standard ladder, in one place

For a published-but-bad release, the canonical recovery — the "standard
ladder" the `security-review-*.md` docs reference — is:

1. **Tell users to pin to the last good version:**
   `pip install evidentia==X.Y.Z-1` (the prior patch). This is the
   immediate user-facing mitigation and needs no maintainer action.
2. **Yank the bad version's artifacts on PyPI** (§4). Yank ≠ delete;
   cosign + Rekor signatures stay valid; pinned installs of the bad
   version still resolve (§2).
3. **For a container-only fault, delete/repoint the bad GHCR tag** (§5).
4. **Ship a new patch `vX.Y.Z+1`** that fixes the defect, through the
   normal PR → merge-queue → `git tag -s` flow.
5. **Correct the CHANGELOG** (and open a GHSA if security, §6).

This is forward-only by construction: every step either changes
availability metadata (yank, GHCR tag) or adds a new release. Nothing is
rewritten.

### Why there is no auto-yank-on-smoke

`release.yml` smoke-tests the container in the `build` job **before**
`publish-pypi` runs. A failing smoke test therefore fails `build`, and
the irreversible PyPI publish never happens — there is nothing to yank.
By the time a release reaches PyPI it has already passed the smoke test.
A yank is consequently always a **deliberate, human** decision made
*after* publish in response to a real defect, never an automated
reaction wired into the pipeline. Do not add an auto-yank step; it would
fire only on conditions that cannot occur (a published-but-smoke-failed
release) and would risk yanking a good release on a flaky check.

### The nothing-published case: ghost tags (the atomic gate fired)

The best failure this runbook covers is the one with **zero public
blast radius**: the tag was pushed, `release.yml` fired, and the run
failed *before* the irreversible publish — the validate-before-publish
design working as intended (observed live: v0.10.14 failed in build
validation, v0.10.15 failed pre-upload; neither put a byte on PyPI or
GHCR).

What remains is a **ghost tag**: a signed, immutable tag whose version
slot is consumed but which published nothing. Recovery:

1. **Verify nothing actually published** before anything else:
   `pip index versions evidentia` / the PyPI JSON API (the version must
   be absent), `docker manifest inspect ghcr.io/...:v<X.Y.Z>` (must
   404), and `gh release view v<X.Y.Z>` (must not exist).
2. **Do not try to delete or move the tag.** The `Protect release tags
   (v*)` ruleset (deletion + non-fast-forward blocked, empty bypass
   list) makes the tag permanent *by design* — the append-only tag
   history is the provenance property being protected, and a burned
   patch number is its accepted, cheap cost. Do not weaken the ruleset
   to "clean up."
3. **Root-cause on a branch, then re-release as the next patch
   number** — normal PR flow, then a fresh tag. If the release workflow
   itself changed, run the first-live-run audit (engineering-practices
   lesson 8) before the new tag: publish jobs are unreachable in PR CI,
   so re-tagging is their next first execution.
4. **Record the ghost honestly**: the shipped release's CHANGELOG block
   names the ghost tag(s) and why the gate stopped them (see the
   0.10.16 entry) — a burned number with a one-line explanation reads
   as the safety system working; an unexplained gap reads as history
   editing.

---

## 4. PyPI yank + ship-a-patch (the standard ladder, detailed)

**When:** a functional or dependency defect has reached PyPI and you want
to stop new non-pinned installs from resolving the bad version.

### 4.1 Yank the affected artifacts

Yank is performed in the **PyPI web UI** per project, per version — there
is no first-party `pip`/`twine` yank command, and no API token is needed
(yank is an account-owner action, not a publish action, so it does not
go through the OIDC Trusted Publisher path):

1. For **each** affected package, go to
   `https://pypi.org/manage/project/<package>/releases/` (the 8 packages:
   `evidentia`, `evidentia-core`, `evidentia-ai`, `evidentia-collectors`,
   `evidentia-integrations`, `evidentia-api`, `evidentia-mcp`, and
   `evidentia-eval`).
2. Select release **X.Y.Z** → **Options** → **Yank** → supply a short
   public reason (it shows in the API and to anyone who installs the
   pinned version). Keep it factual, e.g. *"Yanked: container base
   regression; use X.Y.Z+1"* or *"Yanked: <CVE/GHSA-id>; fixed in
   X.Y.Z+1."*
3. Yank **the whole version set** that shipped together, so a range
   resolver doesn't pick a half-yanked release. If the defect is in one
   package only, yank at minimum that package; prefer yanking the matched
   version across all 8 so the inter-package pins stay coherent.

> **Reversible.** Yank is reversible (un-yank in the same UI) if you
> later determine the release was fine. Deletion is not — which is the
> other reason the ladder never deletes.

### 4.2 Verify the yank took effect

```bash
# The release's "yanked" flag is visible in the JSON API.
curl -s https://pypi.org/pypi/evidentia/X.Y.Z/json | python -c \
  "import sys,json; d=json.load(sys.stdin); \
   print('yanked:', any(f.get('yanked') for f in d['urls']))"

# Pinned install STILL works (expected — this is the PEP 592 contract):
python -m venv /tmp/yank-check && /tmp/yank-check/bin/pip install \
  "evidentia==X.Y.Z"          # resolves the yanked version: OK

# Non-pinned install SKIPS the yanked version (resolves to the good one):
python -m venv /tmp/range-check && /tmp/range-check/bin/pip install \
  "evidentia"                  # must NOT resolve X.Y.Z
```

### 4.3 Ship the fixed patch

Fix the defect on a branch and release `vX.Y.Z+1` through the normal
flow (see [`release-checklist.md`](../release-checklist.md) Step 8):

```bash
git checkout -b fix/vX.Y.Z+1
# ... fix + bump (scripts/bump_version.py --to X.Y.Z+1) + CHANGELOG ...
git push origin fix/vX.Y.Z+1
gh pr create --base main --head fix/vX.Y.Z+1 --title "..." --body "..."
gh pr merge <PR#> --squash --auto        # merge queue re-tests + squash-merges
# after it lands on main, tag (Tier-4 — get explicit approval first):
git tag -s vX.Y.Z+1 -m "Release vX.Y.Z+1 — <one-line summary>"
git push origin vX.Y.Z+1                  # fires release.yml
gh run watch
```

The v0.10.12 → **v0.10.13** cycle is the worked example of this ladder's
container variant (§5): wheels were fine, the container failed, and the
fix shipped as a forward patch — no yank of the good wheels, no tag
rewrite.

---

## 5. Container (GHCR) rollback

**When:** the wheels are good but the container image is broken or must
be withdrawn (e.g. a base-image regression, as in v0.10.12 where the
`python:3.14-slim` base broke the `litellm` resolve and the container
build failed *after* the PyPI publish).

Key facts about the GHCR surface:

- The image is published to `ghcr.io/polycentric-labs/evidentia` under
  two tags pushed at the same digest: `:vX.Y.Z` and `:latest`.
- It is **cosign-signed (keyless OIDC)** and carries a **SLSA build
  provenance** attestation on the digest.

### 5.1 Repoint `:latest` to the last good image (fastest mitigation)

If a freshly-pushed `:latest` is bad, the quickest user-facing fix is to
make `:latest` resolve to the previous good digest again. The durable
fix is to ship a new patch (which re-pushes `:latest` at the new good
digest); until then, consumers pulling `:vX.Y.Z-1` explicitly are
unaffected.

### 5.2 Delete the bad GHCR tag (when withdrawal is required)

Unlike git tags and PyPI files, a GHCR image version *can* be deleted —
GHCR is a registry, not the immutable release surface. Deleting the bad
image version withdraws it cleanly. These calls hit the GitHub "package
versions for a package owned by an organization" REST API, so the `gh`
token needs `read:packages` (to list) and `delete:packages` (to delete)
scope:

```bash
# List container versions (id + tags) to find the bad one:
gh api "orgs/Polycentric-Labs/packages/container/evidentia/versions" \
  --jq '.[] | {id, tags: .metadata.container.tags}'

# Delete the specific bad version by id (Tier-4 — get approval first):
gh api -X DELETE \
  "orgs/Polycentric-Labs/packages/container/evidentia/versions/<VERSION_ID>"
```

> Deleting a GHCR image version is a public-surface mutation (Tier-4):
> surface the exact `gh api -X DELETE …` command and get explicit
> approval before running it, per the publishing-authority protocol.
> Prefer repointing `:latest` + shipping a forward patch over deletion
> unless the bad image must be actively withdrawn (e.g. it ships a
> vulnerable layer).

### 5.3 Ship the fixed-container patch

Fix the Dockerfile / base / pin and ship `vX.Y.Z+1` exactly as in §4.3.
Because `release.yml` now builds the container **from the local wheels
and smoke-tests it before publish** (the v0.10.14 atomic-release
change), a re-broken container fails `build` and blocks the PyPI publish
of the patch — so you cannot accidentally re-create a wheels-only
release while fixing one.

---

## 6. Security track — GHSA + coordinated disclosure

If the bad release is a **security** issue in Evidentia's own code, run
the standard ladder (§4) **and** the disclosure flow from
[`SECURITY.md`](../../SECURITY.md):

1. **Draft a GitHub Security Advisory** at
   `https://github.com/Polycentric-Labs/evidentia/security/advisories/new`
   (private draft). Request a CVE through the GHSA flow if warranted.
2. **Fix + ship the patch** (§4.3). Per `SECURITY.md`, the supported
   version is always the latest patch — there are no pre-1.0 backports,
   so the fix ships as `vX.Y.Z+1` and older patches are deprecated.
3. **Yank the vulnerable artifacts** (§4.1) with a reason referencing the
   GHSA/CVE id once assigned.
4. **Publish the GHSA** *after* the fix is live on PyPI (the `SECURITY.md`
   pattern: "After fix lands and is published to PyPI, the GitHub
   Security Advisory is published"). Credit the reporter unless they
   opted out.
5. **Disclosure window:** 90 days from report to public disclosure by
   default, shorter when an upstream fix only needs a pin bump (the
   v0.7.2 same-day pattern), longer by mutual agreement.

A verification failure on a *published* artifact (cosign / PEP 740 /
`gh attestation verify` fails where it previously passed) is itself a
security incident, not a routine rollback — treat it as Q1=YES and
investigate before yanking, since a yank does not change artifact bytes
and would not "fix" a provenance compromise.

---

## 7. Evidence capture

Every real rollback is a change event and gets a paper trail (this is a
GRC tool — the rollback itself should be auditable):

- **The trigger.** The failing `release.yml` run id + the failed job/step
  (`gh run view <run-id>`), or the user report / advisory that surfaced
  the defect.
- **The decision.** Which ladder branch (§3) and why — note it in the
  release tracking issue and in the next release's
  `security-review-*.md` / CHANGELOG.
- **The yank.** Package(s) + version yanked, the public reason string,
  and the timestamp. The `curl …/json` yanked-flag check from §4.2 is a
  good before/after artifact.
- **The GHCR action.** The deleted version id or the repointed
  `:latest` digest, plus the `gh api` command run.
- **The fix.** The patch PR + the `vX.Y.Z+1` tag/run that resolved it.
- **Provenance note.** Record that the yanked artifacts' signatures /
  Rekor entries remain valid (yank preserved the bytes) — so an auditor
  reading the trail later understands the supply-chain chain was never
  broken.

For a security rollback, the GHSA *is* the canonical evidence record;
link the tracking issue and the fixing PR from it.

---

## 8. User communications

Match the channel to the severity:

- **CHANGELOG (always).** The fixing patch's `[X.Y.Z+1]` block states
  plainly what was wrong, that the prior version was yanked, and the
  upgrade action. The v0.10.13 CHANGELOG entry is the model: it names
  the regression, the root cause, and the fix without blame.
- **GitHub Release notes (the new patch).** `release.yml` builds the body
  from the CHANGELOG block, so a clear CHANGELOG entry produces clear
  release notes automatically. (The *bad* release's notes can't be edited
  — Immutable Releases, §1 — so the correction lives in the new release.)
- **Yank reason string (PyPI).** Short, points at the fixed version;
  visible to anyone installing the pinned bad version.
- **GHSA (security only, §6).** The coordinated-disclosure surface;
  publish after the fix is on PyPI.
- **Pin-to-last-good guidance.** For an actively-harmful release, the
  immediate user message is `pip install evidentia==X.Y.Z-1` (or
  `docker pull …:vX.Y.Z-1`) while the patch is prepared — this needs no
  maintainer action and is the fastest mitigation.

---

## 9. Quick reference

| Situation | Action | Never |
|---|---|---|
| Bad release on PyPI | Yank affected versions (§4.1) + ship patch (§4.3) | Delete PyPI files; move/delete the tag |
| Container broken, wheels fine | Repoint `:latest` / delete bad GHCR version (§5) + patch | Yank the good wheels |
| Security defect in our code | GHSA draft → patch → yank → publish GHSA (§6) | Publish the GHSA before the fix is on PyPI |
| Cosmetic Release-notes error | Correct in next release's notes + CHANGELOG | Try to edit the published Release (barred, §1) |
| Smoke test fails at release | Nothing to roll back — `build` failed pre-publish | Add auto-yank on smoke (§3) |
| Pinned consumer of bad version | They keep working by design (PEP 592, §2) | Expect yank to break their pin |

**Invariants:** tags are immutable and signature-required (§1) ·
Immutable Releases is on (§1) · yank ≠ delete and preserves provenance
(§2) · recovery is always *forward* (a new patch), never a rewrite.

---

## References

- [`release.yml`](../../.github/workflows/release.yml) — the atomic
  tag-driven flow (build-and-validate-all-artifacts-before-publish;
  container from local wheels; pre-publish smoke).
- [`release-checklist.md`](../release-checklist.md) — Step 8 (tag/push +
  re-trigger notes), Step 10 (yank note).
- [`SECURITY.md`](../../SECURITY.md) — vulnerability reporting, supported
  versions (single supported patch), 90-day disclosure window.
- [`engineering-practices.md`](../engineering-practices.md) — the
  safeguard-stack narrative the atomic-release change belongs to.
- [PEP 592 — Adding Yank Support to the Simple API](https://peps.python.org/pep-0592/)
  — the normative basis for yank ≠ delete and the pinned-install
  contract.
- [Google SRE Workbook, Chapter 16 — Canarying Releases](https://sre.google/workbook/canarying-releases/)
  — release-engineering context (smaller self-contained artifacts make
  rollback cheaper; deployments should be automated; staged rollout
  detects defects fast). The Workbook has no dedicated rollback chapter;
  the rollback procedure here is Evidentia-specific.
