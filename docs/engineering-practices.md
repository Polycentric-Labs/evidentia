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
- **PyPI publishing uses an OIDC Trusted Publisher** — short-lived, workflow-
  scoped credentials minted per run. There are no long-lived API tokens to
  leak or rotate.
- **Everything is pinned.** Python dependencies install under
  `pip --require-hashes`; third-party GitHub Actions are pinned to full commit
  SHAs; the container base image is pinned by digest. A floating reference is
  treated as a defect.
- **Vulnerability scanning** runs `osv-scanner` against the resolved dependency
  closure — including the container's independently-resolved closure — on every
  pull request, surfacing transitive and disputed advisories the standard alert
  feed suppresses.
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
- **Secret scanning.** A pinned gitleaks binary scans the full history on every
  push and pull request, complementing a local pre-push secret scan.
- **Defensive guards in the code itself.** Network-egress paths enforce a
  public-host SSRF guard that fires *before* any optional driver import, so the
  security property holds even with zero optional extras installed — a property
  that is itself verified by a dedicated CI job.

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

---

## How it composes

None of this is exotic — it is the standard high-assurance open-source playbook
(required checks before merge, signed and provenanced releases, continuous
fuzzing and scanning, verified docs). What makes it hold is applying it
consistently and keeping it honest: every failure becomes a gate, and a gate
that cannot be trusted is fixed or removed, never ignored.
