# Engineering practices

Evidentia is supply-chain and compliance infrastructure. A tool that asks
other teams to prove their software is built, tested, and shipped with
integrity has to hold itself to that same bar — visibly, and in the open.

This document describes how Evidentia is engineered: the safeguards that gate
every change, and the candid story of the failures that put each one there.
The organizing idea:

> **Quality is mechanical, not remembered.** A release that depends on someone
> remembering to run the tests, bump every version, or scan for secrets will
> eventually ship the one where they forgot. Every check below is enforced by
> machinery — a required CI gate, a ruleset, a hook — not by discipline.

Three principles run through all of it:

- **Fail closed.** A gate that cannot run is a *failure*, not a skip. A
  chronically-red or silently-dead check is worse than no check at all — it
  becomes noise that hides real signal. (This rule came from a specific
  failure; see *Lessons*, below.)
- **One definition, no drift.** The same check runs in the local pre-push hook,
  in pull-request CI, and at the merge queue — from a single shared
  implementation, so the three surfaces cannot disagree.
- **Verify, don't assert.** Documented commands and factual claims are executed
  against the live tool, not trusted because they were true once.

This document is the **single home** for Evidentia's engineering + security
practices: a new safeguard, finding-handling rule, or dependency policy extends
the relevant section below rather than starting a parallel document.

---

## The development & release flow

**Pull-request flow with a merge queue.** Every change to `main` — code, docs,
and releases alike — goes through a pull request. A repository ruleset requires
a pull request before merging, requires the full set of status checks to pass,
and has an **empty bypass list**: no one, including the repository
administrator, can push directly to `main`. This is deliberate. The earlier
direct-push model let an administrator's push bypass the required checks, which
meant the full cross-platform matrix only ran *after* a change had already
landed — exactly the wrong time to discover a break. Moving the gate in front
of `main` closes that window.

A **merge queue** re-tests the *prospective* merge (the target branch plus the
pull request, plus anything ahead of it in the queue) so that two individually
green pull requests cannot combine to break `main`. Merges are squash-only,
which is the one merge method compatible with both required signed commits and
a required linear history — a merge commit breaks linearity, and a rebase
produces commits the platform cannot sign. Every workflow that produces a
required check also runs on the merge-queue event, or the queue would stall
waiting for a result that never arrives.

**A pre-release review before every tag.** Releases are tag-driven, and each
tag is preceded by a structured pre-release review: a checklist-and-skill
discipline that walks the version bumps, the changelog, the documentation
consistency sweep, the dependency posture, and the external service state
before the irreversible publish. The review *checks that the automatic gates
exist* — it does not replace them.

**Atomic releases.** The release pipeline builds and validates **every**
artifact — the wheels, the SBOM, and the container image — *before* it
publishes anything. The container is built from the locally-built wheels, not
from the package index, and is smoke-tested in place; only then are the wheels
published, and only then is the validated image pushed and signed. A
container-build failure now blocks the publish entirely, rather than leaving a
half-finished release where the packages shipped but the image did not.

---

## Supply-chain integrity

Evidentia's releases are designed to be independently verifiable end to end:

- **SLSA build provenance** is generated for the wheels, the SBOM, and the
  container image, and is verifiable with `gh attestation verify`.
- **Sigstore / cosign keyless signing.** Python distributions carry PEP 740
  index-hosted attestations; the container image is signed by digest with
  cosign's keyless OIDC flow and logged to the public Rekor transparency log.
- **A CycloneDX SBOM** is produced for, and attached to, every release.
- **PEP 770 per-wheel SBOMs.** Every published wheel embeds its own CycloneDX
  SBOM in `.dist-info/sboms/`, so `pip install` materializes it downstream —
  the release-asset SBOM describes the release; these travel with each package.
  The `evidentia-api` wheel carries a second document covering the bundled
  React SPA's npm closure (CycloneDX 1.5, npm's native emitter, alongside the
  1.6 python document — PEP 770 permits mixed documents). Generation is
  deterministic by construction (UUIDv5 serial numbers, `SOURCE_DATE_EPOCH`
  timestamps, sorted keys) because the release's reproducible-build gate
  byte-compares a double build; a release-time gate fails the run if any
  wheel is missing its SBOM, while local builds skip cleanly without one.
- **PyPI publishing uses an OIDC Trusted Publisher** — short-lived, workflow-
  scoped credentials minted per run. There are no long-lived API tokens to
  leak or rotate.
- **Everything is pinned.** Python dependencies install under
  `pip --require-hashes`; third-party GitHub Actions are pinned to full commit
  SHAs; the container base image is pinned by digest. A floating reference is
  treated as a defect. The container is a multi-stage build: a `python:3.13-slim`
  builder resolves the hash-pinned closure into a venv, and a distroless
  `dhi.io/python:3.13` (Docker Hardened Images) runtime carries only that venv as
  nonroot uid 65532 — no shell, package manager, `curl`, or `gpg` binary. Both base
  images are digest-pinned.
- **Release pipelines regenerate, never reuse.** The container's hash-pinned
  closure is regenerated from scratch inside the release run, against the exact
  wheels the run just built — an existing resolution output is never trusted
  (`pip-compile` silently reuses a prior output file's pins and hashes; see
  lesson 8), and the committed copy of that file is a lagging preview for
  inspection, never an input to a release. The publish path also runs
  **cache-free**: a PR-writable Actions cache read inside an artifact-producing
  job is a cache-poisoning vector, so the release builds every layer and
  toolchain from source-of-truth references. A release build must also use a
  version distinct from every published one: if artifacts are built at a
  version that already exists on the index, the resolver sources dependency
  metadata from the *index*, not the freshly-built local wheels, so a
  newly-added core dependency silently vanishes from the pinned closure —
  which is why a same-version committed hash file is structurally infeasible
  before publication.
- **Vulnerability scanning** runs `osv-scanner` against the resolved dependency
  closure — including the container's independently-resolved closure — on every
  pull request, surfacing transitive and disputed advisories the standard alert
  feed suppresses. Each requirements/lock artifact represents exactly one
  dependency closure — the container's closure is not the published package's
  closure — so expected drift between them is not a defect to "fix";
  regeneration consumes the committed input file (never overwriting it, which
  would drop manually-added security floors) and asserts the expected pins are
  present afterward.
- **Dependency updates are automated with guardrails.** Dependabot proposes
  weekly, grouped, cooldown-delayed version updates (a freshly-published release
  is held a few days, so a yanked or hot-fixed bad release is superseded before it
  is proposed); breaking-prone framework packages are isolated into their own
  reviewable PR; per-ecosystem open-PR caps bound the queue; and security
  advisories are never grouped — each rides its own PR. Patch updates in the
  lower-risk ecosystems (Python and npm) auto-merge once the full required-check
  suite is green (narrow, fail-closed; see lesson #1); majors, minors, container
  and Actions updates, and security updates always get human review, because CI
  verifies correctness, not the *intent* of a possibly-poisoned dependency.

These are also the signals OpenSSF Scorecard scores, which the project tracks
publicly.

---

## Continuous security assurance

- **Continuous fuzzing.** Atheris harnesses run under ClusterFuzzLite on every
  relevant pull request and on a scheduled batch, exercising the parsing and
  catalog-loading surfaces with coverage-guided inputs.
- **Static analysis.** CodeQL runs in an advanced configuration with a custom
  sanitizer model that teaches the path-traversal queries about the project's
  validation helpers, so they report real findings rather than known-safe ones.
  (The model is extended as new validators land — see the roadmap's engineering
  follow-ups.) **zizmor** statically audits the workflows themselves — full-commit-
  SHA action pins that resolve to the right commit, least-privilege permissions,
  no template injection, no cache poisoning, no credential persistence — online,
  on every PR and the merge queue, as a required check.
- **Findings are handled, not accumulated.** Every security gate that *runs* is a
  *required* check — no advisory-only scanners left to rot. A code-scanning
  finding is either fixed in the PR or dismissed with a written, primary-source-
  grounded reason; systemic false positives are encoded in committed config (a
  CodeQL query filter or sanitizer-model entry), never one-off clicks. High alerts
  carry a tight triage SLA toward a zero-open-High goal, and open code-scanning +
  Dependabot alerts are reviewed before a change is called done.
- **Published artifacts are re-scanned for day-N advisories.** The release-time
  and per-pull-request scans only catch what was *known at release*. A scheduled
  rescan re-runs the same pinned scanner against the **already-published**
  release — both the PyPI dependency closure and the container image — so a CVE
  disclosed in a frozen transitive dependency, or in the container's base image,
  *after* a release does not stay invisible until the next one. The container
  rides a general-purpose OS base whose packages steadily accrue advisories the
  project cannot fix; failing the rescan on *every* such advisory would pin it
  permanently red on unfixable distro CVEs — the chronically-red-gate failure
  again (see *Lessons*, below). So the container rescan gates on **fixability**:
  it fails only when a detected advisory has an applicable upstream fix ("a fix is
  now available — rebuild the image"), while unfixable base-OS advisories are
  **notify-only** — rendered in full to the run summary for visibility, but not
  failing the run. The scanner has no native fixable gate (it exits non-zero on
  any advisory), so the fixable/notify split is a committed, unit-tested policy
  step that parses the scanner's JSON and matches each *applicable* fix to the
  detected package, not to any release that merely shares the CVE. Time-bound
  exceptions live in the one committed allowlist (a single definition, applied by
  the scanner itself); reducing the base-OS surface *itself* is now done: the
  image rides the distroless `dhi.io/python:3.13` base (no shell/curl/apt/perl/gpg
  — an RCE is trapped in the Python process, with fewer commodity second-stage
  tools), and a scheduled **freshness sentinel** opens a tracking issue when the
  base digest drifts or the published image ages past 90 days, so the day-N clock
  is reset by an ordinary rebuild-and-release rather than left to the rescan
  alone. The honest limit stands: this is post-exploitation attack-surface
  reduction, not a CVE-count win (the distroless base still carries unfixable
  advisories) — and removing `curl` is not egress denial (Python
  `socket`/`urllib` remain).
- **Secret scanning.** A pinned gitleaks binary scans the full history on every
  push and pull request, complementing a local pre-push secret scan. Systemic
  secret-scanner false positives are encoded the same way — as value-precise
  allowlist regexes in committed config, matched against the flagged secret
  *value*, never as a path allowlist over source directories — and verified
  locally before landing.
- **Defensive guards in the code itself.** Network-egress paths enforce a
  public-host SSRF guard that fires *before* any optional driver import, so the
  security property holds even with zero optional extras installed — a property
  that is itself verified by a dedicated CI job.
- **One machine-readable API error contract, documented per operation.** Every
  deliberate 4xx/5xx the REST layer raises carries the structured
  `{"detail": {"error": "<snake_case_key>", ..., "message": "<human text>"}}`
  payload — a single stable key vocabulary (registry + `api_error()` /
  `error_responses()` helpers in `evidentia_api.errors`) instead of ad-hoc
  bare strings, and every operation's deliberately-raised statuses are declared
  in its OpenAPI `responses`. Two properties fall out: DAST (schemathesis) can
  hold the API to its own published contract — an undocumented status or a
  malformed error body is a finding, not noise — and clients (the web console's
  shared `extractApiErrorMessage()` included) dispatch on `error` keys rather
  than parsing prose. The v0.7.8 F-V08-DAST-3 *status* normalization (manual
  body-content errors → 400; Pydantic request-validation → 422 array) is
  unchanged — the manual-vs-automatic discrimination survives as object vs
  array. Convention set 2026-07-06; contract terms in
  `docs/api-stability.md` §6.

### Air-gap DSSE signing architecture

Evidentia ships a binary-free, air-gap-native signing path that works inside
distroless and minimal-base containers without a `gpg` binary or network access.
It complements — and in constrained environments replaces — the GPG and Sigstore
signing paths.

**Implementation.** `evidentia_core.oscal.keysign` produces DSSE envelopes
(Dead Simple Signing Envelope, per the
[secure-systems-lab/dsse](https://github.com/secure-systems-lab/dsse) spec)
carrying an in-toto Statement v1 payload. The statement binds the artifact's
canonical-JSON SHA-256 digest to the signing key. The signature algorithm is
auto-detected from the operator-supplied key: **Ed25519** (recommended —
constant-time, compact signature) or **RSA-PSS-SHA-256** (for operators whose
deployment requires RSA). The `cryptography` library (PyPI) is the only
dependency; no subprocess, no network.

**Trust model.** The operator pins the expected public key via `--verify-key
<pubkey.pem>`. Verification is fail-closed: if the DSSE file is absent, the
envelope is malformed, or the signature does not verify against the pinned key,
the `evidentia oscal verify` command exits non-zero. The `keyId` field in the
envelope is a hint (the SHA-256 of the public key's DER-encoded SubjectPublicKeyInfo)
— it is informational, not an authority decision. The decision is made by
`--verify-key`: only the pinned key can make the verification pass.

**What a passing verify actually asserts.** A passing DSSE leg means: the
operator-supplied key signed over this exact canonical-JSON content. It does
**not** assert the artifact's filename, the directory it lives in, or the
recency of the signing event. `signedAt` in the predicate is signer-asserted
wall-clock time — not a trusted timestamp. Key-based DSSE has no revocation or
expiry channel — trust is pinned-key-scoped. `subject.name` carries the
artifact filename at sign time and is non-authoritative: a renamed file whose
content is unchanged still verifies.

**Normative verify sequence.** `verify_oscal_file` enforces this order:
1. Parse and load the DSSE envelope.
2. Derive the signing algorithm from the **pinned key only** (not from the
   envelope header).
3. Verify the DSSE Pre-Authentication Encoding (PAE) signature.
4. Check `payloadType` is `application/vnd.in-toto+json`.
5. Check `_type` / `predicateType` in the decoded statement.
6. Cross-check the envelope's `predicate.algorithm` against the pinned key's
   expected algorithm — a mismatch (e.g., `ed25519` key presented against an
   `rsa-pss-sha256` envelope) fails closed.
7. Recompute the artifact's canonical-JSON SHA-256 and compare against the
   `subject[].digest.sha256` — a content change (even a byte flip in the OSCAL
   body) fails here.

**FIPS note.** DSSE + Ed25519/RSA-PSS is a signature *format*, not a
crypto-module validation. The stock `cryptography` Python wheel bundles its own
OpenSSL and is **not FIPS-validated**. Deployments requiring FIPS must use a
FIPS-validated cryptographic module and approved configuration (e.g., a
FIPS-OpenSSL base image); see the roadmap engineering follow-ups for the P3
FIPS-base migration.

---

## Research rigor

High-stakes technical decisions — a release-safety redesign, a competitive or
standards claim, a "does this already exist" question — are validated with a
multi-model, hard-skeptic research method rather than a single lookup. Several
independent models investigate in parallel; every proper noun (an advisory ID,
a version, a repository, a standard) is web-confirmed against a primary source
before it is treated as fact; and conclusions are adversarially checked before
they drive a change. The atomic-release design in this document, for example,
was pressure-tested by the multi-model review described above, which caught two
real defects before any of it reached the release pipeline.

---

## Documentation discipline

- **Docs are verified against the tool.** Before a documentation set ships,
  every command in it is run in a fresh sandbox against the real CLI and its
  output is diffed against the doc; a genuine product bug or a false claim is
  escalated to a human, never papered over by editing the doc.
- **In-repo docs are the source of truth.** Runbooks, the release checklist,
  the threat model, and the positioning material live in the repository, are
  reviewed in pull requests, and are guarded by automated consistency checks:
  the version is consistent across every source, capability counts match the
  code, and cross-document links resolve.
- **Doc moves are airtight.** Because GitHub does not redirect moved document
  paths, any doc cited by a frozen external surface (an immutable release
  body, a per-version package README, a tool config pointer) 404s the instant
  it moves; before a reorganization, frozen-cited paths are enumerated, left
  as stub redirects with an index map, and the citing gates are updated
  atomically in the move commit. Link-resolution checks sweep config-embedded
  and workflow-embedded doc pointers, not only tracked Markdown, since a
  phantom pointer shipped in code reaches the package index as a live 404.

---

## Lessons that shaped the system

Every safeguard above exists because something failed. Naming the failure
classes plainly is part of the discipline — a post-mortem that stays abstract
does not prevent the next incident.

**1. A base-image regression slipped in through an unreviewed dependency
bump.** An automated dependency update advanced the container's base image
across a major Python version. The AI stack constrains itself to the older
interpreter, so on the new base the resolver could only reach a
vulnerability-bearing version of one dependency and the patched pin became
uninstallable — and the container build failed. *Root cause:* a
security-sensitive, deliberately-chosen pin was reverted by a change that
merged on green CI without a human reading it. *Prevention:* the **broad**
auto-merge policy (patch **and minor**, every ecosystem) was removed; the base
image is pinned by digest with a guard comment; and the container smoke test
(see below) now catches an incompatible base bump at pull-request time.
Auto-merge was later **reinstated in a deliberately narrow form** — patch-only,
Python and npm ecosystems only, excluding majors, minors, the container
(`docker`) and `github-actions` ecosystems, the breaking-prone frameworks
group, and **all security updates** — firing only after the full required-check
suite is green, behind the release-age cooldown and the merge queue, via a
workflow that never executes pull-request code. The incident was a *minor*
`docker` bump under the broad policy with a silently-dead gate (lesson #2); the
narrow policy excludes that class twice over, and every major or security change
still gets a human. The narrow policy was settled by a multi-model,
primary-source research pass before it shipped.

**2. The gate that should have caught it had silently died.** The container
smoke test had been exiting early on a version-extraction step for several
releases — a brittle text match against a perennially-stale generated file — so
it never reached the build step. A chronically-red gate had become background
noise, and it masked the regression above. *The lesson, stated as a rule:* a
perpetually-failing or un-runnable check is worse than no check, because it
trains everyone to ignore a red signal. *Prevention:* the smoke test now reads
the version from the published index (self-correcting, with no dependency on a
stale committed file); it is a required check on every pull request; and a
written flake-resistance policy treats a skipped or dead gate as a failure to
be fixed, not tolerated.

**3. Timing-dependent tests flaked the CI.** Two tests asserted on wall-clock
behavior — one compared two timestamps taken microseconds apart against a
platform whose clock granularity is coarser than that gap, and one imposed a
fixed millisecond deadline on a property-based test. Both failed
non-deterministically. *Prevention:* a flake-resistance policy bans wall-clock
timing assertions outright — anchor timestamps deterministically in the past,
inject or freeze clocks, and disable hard deadlines in CI profiles.

**4. A container failure left a packages-only release.** Because the container
was built *after* the package publish, a build failure produced a release where
the packages were live on the index but the image was missing. *Prevention:*
the atomic-release reorder described above — all artifacts build and validate
before anything publishes, and the container is built from the local wheels so
it has no dependency on index propagation.

**5. Failures came in layers.** Several incidents shared a shape: each fix
*unmasked* the next, because nothing exercised the full path before a change
landed on `main`. *The meta-lesson:* the absence of a pre-merge full-matrix
gate let problems queue up and surface one at a time, post-merge. *Prevention:*
the pull-request flow and merge queue — the complete CI matrix now gates every
change *before* it reaches `main`, so "it shipped" means "the full matrix
proved it green first," not "we found out afterward."

**6. A dependency group-update bundled breaking migrations with routine
bumps.** A grouped version-update pull request raised more than a dozen routine
bumps together with two *breaking* major migrations — one that collapsed an
API's separate input/output schema components (which renamed the generated
client types), and one where a CLI library vendored its own copy of its parser
dependency (changing a test-visible class hierarchy and the test runner's stderr
handling). The breakage surfaced only in CI, tangled in with the safe bumps, so
it was hard to isolate. *Root cause:* a major version — an architectural change —
was treated as a routine bump and grouped with them. *Prevention:* majors are
isolated for separate, explicit review. The update bot groups minor and patch
updates but raises each major as its own pull request (Renovate's
`separateMajorMinor` + `separateMultipleMajor`, or a Dependabot group restricted
to minor/patch so majors raise individually); a release-age cooldown (Renovate
`minimumReleaseAge` / Dependabot `cooldown`) keeps day-one releases out of the
queue; and a deliberate upper-bound version cap (e.g. `>=2.9,<2.13`) holds a
known-breaking major out of dependency resolution until a dedicated migration
pull request adopts it — so a major migration is always reviewed on its own,
never ridden in on a routine batch.

**7. A local gate disagreed with CI.** The local pre-push gate ran the test
suite against a virtual environment built *without* the optional dependency
extras that CI installs, so a set of tests that import optional drivers failed
locally with an import error while passing in CI — a false signal in the exact
direction that erodes trust in a gate. *Root cause:* the local and CI
environments were built by different commands, so they could drift.
*Prevention:* both build their environment from one source of truth — the
lockfile, synced with identical flags *including the optional extras*
(`uv sync --all-extras --frozen`) — ideally behind a single task definition (a
`nox`/`tox` session or a one-command bootstrap) that both the pre-push hook and
the CI job invoke, with a `uv lock --check` gate keeping the lockfile itself
honest, so "passes locally" and "passes in CI" cannot mean two different things.

**8. A release pipeline's publish jobs failed on their first live run — twice.**
The atomic-release restructure moved publishing into jobs that *cannot execute in
pull-request CI* — so the first release tag after the change was also their first
execution, on an irreversible trigger. Two consecutive tags failed inside that
never-exercised surface: first a hash mismatch (the release's dependency
resolution *reused* a committed preview file's pins and hashes — `pip-compile`
silently reuses an existing output file — and that preview carried
locally-built wheel hashes at the same version, which cannot match the CI-built
wheels because wheel builds are not byte-reproducible across platforms), then an
exit-127 (a verification step invoked a tool the job never installs). Both times
the validate-before-publish gate stopped the run with **nothing published** — the
two burned tags remain as signed, immutable, unpublished "ghost" tags, which is
the accepted cost of an append-only tag ruleset, not a defect. *Root cause:* code
that only runs on an irreversible trigger was reviewed by diff but never executed
or simulated. *Prevention:* a **first-live-run audit** whenever the release
workflow changes — walk every post-build step in execution order and verify each
shell command's tool is installed *in that job* (or runner-preinstalled), each
pinned action's inputs and outputs against the action's schema *at the pinned
commit*, artifact names and paths across the job graph, that environment
deployment policies admit tag refs, and that the publish path runs cache-free
and regenerates every resolution artifact from scratch rather than trusting a
committed preview. The tool-availability leg of that audit is now mechanized: a
strict CI check (`scripts/check_workflow_tools.py`) fails any job that invokes
a tool its own steps never install.

**9. Assurance jobs were green while verifying nothing.** Two post-publish
assurance workflows installed package *extras that do not exist* — `pip` emits a
warning for an unknown extra and exits 0 — so for weeks the scheduled
published-closure rescan scanned an incomplete dependency closure, missing the
API server package entirely. The same latent bug sat in the post-publish smoke
workflow's "verify every published package resolves" step — but that step turned
out *never to have run at all*: the smoke workflow triggers on the Release
event, and a Release created by the release workflow's default `GITHUB_TOKEN`
never fires other workflows (GitHub's anti-recursion rule) — a structurally dead
trigger that looked wired, with zero runs in the workflow's lifetime. *Root
cause:* gates were trusted for their exit codes and their wiring, not for
observed behavior. *Prevention:* **assert coverage, not exit codes** — an
assurance step carries a post-condition that proves its claim (import checks,
`pip show` per expected package, names validated against the package manifest);
and **a gate is not real until it has been observed firing** — a workflow whose
trigger has never produced a run is a dead gate (the never-fired generalization
of lesson 2's silently-died gate), detectable mechanically from the workflow-runs
API. That detection now runs weekly: the workflow-liveness sentinel flags
structurally dead trigger events and automatic triggers that have never
produced a run (`scripts/check_workflow_liveness.py`), and the same strict CI
check that guards tool availability validates install-spec extras against the
package manifests.

**10. An open-ended version bound let the resolver explore an impossible
world.** The project declared its Python floor with no upper bound, while a
transitive AI-stack dependency capped a core library well below the newest
Python. That combination is not merely cosmetic: the dependency updater runs a
*universal* resolver that solves across every Python version the bound admits,
so it explored future interpreter versions where the transitive cap became
mathematically unsatisfiable — and every updater run then failed with
"requirements unsatisfiable." The visible symptom was oblique: the build stayed
green, but *every* open dependency pull request silently stopped rebasing, so
none could ever pick up a newly-required status check — a whole class of
updates wedged behind a resolver error nobody was watching. The guardrail that
should have caught the underlying base-image drift earlier was itself dead: an
ignore rule written to block *major* base-image bumps assumed a `3.13 → 3.14`
step was a major change, but the updater classifies it as *minor* (the leading
component stays `3`), so the rule never matched the class it was written to
stop — the same incident, one layer up. *Root cause:* a version bound was
treated as honesty metadata rather than a load-bearing input to resolution, and
a guardrail's matching semantics were never checked against how the tool
actually classifies the change it was meant to catch — a rule that looks
protective but can never fire. *Prevention:* **declare the true supported
ceiling** — cap the floor's upper bound to the tightest transitive cap the
project actually inherits, with a comment stating *why* and the *condition
that removes it*; in a workspace where members intersect, a single root cap
prunes the unsatisfiable resolver fork *during* resolution, unblocking the
updater immediately. Use a plain comparator, never a compatible-release
operator, which the updater's dependency graph cannot parse. And because a cap
set on someone else's constraint should not become permanent by neglect, pair
it with a scheduled watcher (`scripts/check_python_ceiling.py` in
`python-ceiling-watch.yml`) that reads the blocking package's published
metadata, evaluates it with real version-set containment rather than brittle
string matching, and opens a single tracking issue proposing the lift when the
ecosystem is ready — while the lift itself stays human-gated behind a real lock
trial, because an upstream relaxing its own bound is necessary but not
sufficient when other transitive gates remain. The same audit applies to every
ignore/ceiling rule in the dependency-update config: state the exact class it
is meant to catch, and verify that class against the tool's actual
classification of the change, not an assumption about what "major" means.

---

## How it composes

None of this is exotic — it is the standard high-assurance open-source playbook
(required checks before merge, signed and provenanced releases, continuous
fuzzing and scanning, verified docs). What makes it hold is applying it
consistently and keeping it honest: every failure becomes a gate, and a gate
that cannot be trusted is fixed or removed, never ignored.
