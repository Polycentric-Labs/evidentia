# Evidentia access-continuity plan

> **Status**: in effect. Reviewed at every release per
> [`docs/release-checklist.md`](release-checklist.md) Step 5 +
> on a quarterly cadence regardless of release activity.
>
> **OpenSSF Best Practices Badge**: this document is the URL
> referenced by the Silver-tier `access_continuity` criterion.
> See also [`GOVERNANCE.md`](../GOVERNANCE.md) §"Continuity and
> bus factor" for the higher-level governance framing.

## Why this document exists

Evidentia is currently a single-maintainer project (Allen Byrd).
The OpenSSF Best Practices Silver-tier `access_continuity`
criterion requires:

> The project MUST be able to continue with minimal interruption
> if any one person dies, is incapacitated, or is otherwise
> unable or unwilling to continue support of the project. In
> particular, the project MUST be able to create and close
> issues, accept proposed changes, and release versions of
> software, within a week of confirmation of the loss of support
> from any one individual.

This document is the concrete plan that satisfies that criterion.
It is a public artifact so a successor can find it by searching
the repo, and so that an OpenSSF auditor can verify it exists.

## Operational SLA

If the maintainer becomes unable to continue support — death,
incapacitation, prolonged absence, or voluntary withdrawal — the
project commits to **resuming normal operations within 7 calendar
days of confirmation** of the loss of support, where "normal
operations" means:

1. **Create and close GitHub issues** on `polycentric-labs/evidentia`
   (triage backlog; respond to security reports filed via the
   private vulnerability-reporting channel).
2. **Accept proposed changes** (review and merge incoming PRs;
   reject ones that don't meet quality standards; ship docs
   updates).
3. **Release versions of software** — cut a tag, run the release
   pipeline, publish to PyPI + GHCR, attach SBOM + sign with
   Sigstore + cosign keyless OIDC.

## Why keyless infrastructure makes this viable

Evidentia's release infrastructure was deliberately designed so
that **no offline private signing keys exist** that could be lost
with the maintainer:

- **PyPI publishing**: via OIDC Trusted Publisher binding
  (`polycentric-labs/evidentia` repo + `release.yml` workflow + `pypi`
  environment). Any maintainer with repo write access can run the
  release workflow + publish to PyPI. **No long-lived API token
  exists** to be lost.
- **PEP 740 attestations**: emitted by Sigstore keyless OIDC.
  Identity is proven by the GitHub Actions OIDC token at sign
  time, not by an offline key. **No private key to lose**.
- **SLSA L3 build provenance**: emitted by
  `actions/attest-build-provenance` using the same OIDC chain.
  **No private key to lose**.
- **Container signing (cosign keyless)**: same OIDC pattern. The
  cosign-sign step in `publish-container.yml` consumes the
  workflow's ambient OIDC identity. **No private key to lose**.
- **Container registry (GHCR)**: push access derives from
  `GITHUB_TOKEN` (workflow-scoped, ephemeral). **No long-lived
  registry credential**.

The single-point-of-failure is therefore narrowed to **GitHub
account access** + **PyPI account access** + **DNS / domain
registrar access** if any web surface is added in the future.
Each of those has a documented external recovery procedure.

## Recovery procedure

The successor (named below) follows these steps in order. Each
step has a documented external recovery path that does not
require any secret transfer from the original maintainer.

### Step 1 — Confirm loss of support

The successor confirms the maintainer is unable to continue.
Acceptable forms of confirmation:

- Death certificate or equivalent legal record.
- Hospital / clinical confirmation of long-term incapacitation.
- 30+ consecutive days of zero project activity (commits, issue
  responses, PR reviews) with no out-of-office message and no
  response to email + the project's documented contact channels.
- Voluntary written withdrawal from the maintainer.

The 7-day SLA above starts from the moment confirmation is
established.

### Step 2 — GitHub repo + organization access

Two paths in priority order:

**Path 2a (preferred): account-recovery via GitHub Support.**

The successor contacts GitHub Support
([`https://support.github.com`](https://support.github.com)) with:

- The successor's identity verification.
- Documentation of the loss of support (Step 1).
- Reference to this document
  (`https://github.com/polycentric-labs/evidentia/blob/main/docs/access-continuity.md`)
  as a public, version-controlled declaration of the continuity
  plan.
- Reference to GitHub's
  [Deceased User Policy](https://docs.github.com/en/site-policy/other-site-policies/github-deceased-user-policy)
  if the loss-of-support reason is death.

GitHub's documented procedure transfers ownership of the
`polycentric-labs/evidentia` repo (or a fork) to the successor's
account. Typical turnaround: 2-7 business days based on
publicly-documented support response times.

**Path 2b (fallback): fork + redirect.**

If GitHub Support transfer is delayed, the successor can:

1. Fork `polycentric-labs/evidentia` to `<successor-account>/evidentia`.
2. Update PyPI Trusted Publisher entries (Step 3) to point at
   the fork.
3. Open an issue on the original repo declaring the fork as the
   continuation, with a link.
4. Maintain the fork as the canonical repo until the original
   transfers (or indefinitely if it doesn't).

Apache 2.0 license permits this without the original maintainer's
permission.

### Step 3 — PyPI project-owner role transfer

PyPI projects are owned by individual accounts. The
`evidentia` / `evidentia-core` / `evidentia-collectors` /
`evidentia-ai` / `evidentia-api` / `evidentia-integrations` /
`@evidentia/ui` packages are owned by the maintainer's PyPI
account.

The successor follows PyPI's
[project-owner-role transfer procedure](https://docs.pypi.org/project_management/#transferring-a-project-to-a-new-owner)
by opening a support ticket at
[`https://pypi.org/help/`](https://pypi.org/help/) with:

- The successor's PyPI account name.
- Documentation of the loss of support (Step 1).
- Reference to this document.

PyPI's documented turnaround: support ticket queue, typically
1-5 business days.

After transfer, the successor updates the Trusted Publisher
binding under the project's
[publishing-management UI](https://pypi.org/manage/account/publishing/)
to point at the new GitHub repo (if Step 2 went via Path 2b) or
to refresh the binding under the new owner account.

### Step 4 — GHCR (GitHub Container Registry) access

GHCR is part of the GitHub repo's package set. Repo-write access
(established in Step 2) automatically grants push access to
`ghcr.io/polycentric-labs/evidentia` (or
`ghcr.io/<successor-account>/evidentia` on the fork path).

No separate transfer step required. The cosign keyless OIDC
chain re-binds automatically to the new repo's workflow OIDC
token.

### Step 5 — DNS / domain registrar (future)

There is currently **no project-controlled DNS surface**. When
one is added (e.g., `evidentia.dev` for documentation hosting),
this document will be updated with the registrar + a domain-
transfer procedure pointer.

The maintainer's emergency contact (below) is instructed to
release any future domain-registrar credentials only to the
named successor following Step 1 confirmation.

### Step 6 — First release post-transfer

Once Steps 2 + 3 complete, the successor cuts a continuity
release (`v0.X.Y+1` patch) by:

1. Verifying repo write access works (`git push origin main`).
2. Verifying the Trusted Publisher OIDC binding works
   (`uv run scripts/bump_version.py --to 0.X.Y+1`; commit; tag;
   push tag; `release.yml` fires).
3. Confirming PEP 740 + cosign signatures emit cleanly.
4. Filing an issue on the repo declaring the continuity
   transition complete.

Step-by-step commands documented in
[`docs/release-checklist.md`](release-checklist.md).

## Named successor + emergency contact

For privacy reasons, the named successor and emergency contact
are documented **outside this public file** in:

1. **The maintainer's encrypted password manager** (Bitwarden /
   1Password / equivalent) under an entry titled
   "Evidentia continuity — emergency access". The entry contains:
   - Named successor identity + contact info.
   - GitHub account-recovery codes (so the successor doesn't
     have to wait for a support ticket if they can recover the
     account directly).
   - PyPI account-recovery codes (same).
   - This document's URL as the public reference.
2. **The maintainer's emergency contact** (designated trusted
   person — spouse, lawyer, or executor) is granted "emergency
   access" / "trusted access" in the password manager + has been
   given a written procedure pointing them at this document.
3. **The maintainer's will / estate documents** (if applicable)
   include a paragraph naming the successor + referencing this
   document for the operational procedure.

This satisfies the OpenSSF Silver criterion's
"providing keys in a lockbox and a will providing any needed
legal rights" pattern.

The named-successor identity is intentionally kept out of the
public repo to (a) avoid making them a target for social-
engineering attempts to "claim the project" prematurely, and
(b) preserve the maintainer's flexibility to update the
designation as relationships change. The OpenSSF criterion
text doesn't require public disclosure of the successor — it
requires that the project MUST be able to continue, which this
document plus the private-side designation jointly accomplish.

An OpenSSF auditor or successor seeking to verify the private-
side designation exists can:

- Contact the maintainer directly (see
  [`SECURITY.md`](../SECURITY.md) for the disclosure channel) for
  in-person / video confirmation.
- Verify by inspection that the maintainer's password manager
  and emergency-contact designation are operational.

## What stays the same after transfer

- **Apache 2.0 license** (unchanged; license is on the code, not
  the maintainer).
- **Public process**: every operational procedure — release
  workflow, security disclosure, threat model, capability matrix,
  per-release plans — is documented in the repo. A successor
  doesn't need to interview the original maintainer to take
  over.
- **Standard infrastructure**: GitHub for source + issues +
  GHCR, PyPI for Python distribution. All standard, recoverable
  platforms with documented account-recovery + project-owner-
  transfer procedures.
- **Code of Conduct + governance + contribution policy** —
  inherits unchanged. The successor is bound by the same public
  policies the original was.

## What may change after transfer

- The successor is not bound to keep the BDFL governance model.
  They MAY restructure to a steering group, multi-maintainer
  consensus, or LLC ownership at their discretion. They MUST
  update [`GOVERNANCE.md`](../GOVERNANCE.md) in the same PR that
  makes the change.
- The successor MAY rename the project (subject to license terms)
  or maintain it under a different GitHub account / organization.
- The successor MAY decline to continue — Apache 2.0 explicitly
  permits abandoning the project. In that case, the project's
  most recent release artifacts remain on PyPI (per PyPI's
  retention policy) and the GitHub repo can be archived. Any
  downstream consumer can fork and continue independently.

## Plan maintenance

### When the maintainer's situation changes

The maintainer updates this document via PR when:

- The named successor changes (update the password-manager
  entry; this doc's pointer text is unchanged).
- The emergency-contact designation changes.
- The will / estate documents change in a way that affects this
  plan.
- A new infrastructure surface is added (e.g., DNS registrar) —
  add a new step to the recovery procedure.
- An LLC or other organizational entity is formed — update §"Why
  keyless infrastructure makes this viable" + the named-successor
  section to reflect the entity's role.

### When a second maintainer joins

When a second maintainer is onboarded:

- The bus factor goes from 1 to 2.
- This plan still applies for the case of "any one person being
  unable to continue" — both maintainers are individually
  covered.
- The emergency-contact designation pattern carries over for
  each maintainer (each maintainer designates their own emergency
  contact + named successor for their share of access).
- This document is updated to enumerate the second maintainer's
  access set + their continuity arrangements.

### Quarterly review

Per [`docs/release-checklist.md`](release-checklist.md) Step 11
quarterly cadence work:

- The maintainer verifies the password-manager entry is current.
- The maintainer verifies the emergency contact still has
  emergency access.
- The maintainer verifies the named successor is still willing
  to take on the role.
- Any drift triggers an update to this document.

---

*Created 2026-05-04 for v0.7.9 P0.6 OpenSSF Silver-tier prep.
Satisfies the `access_continuity` MUST criterion. Companion to
[`GOVERNANCE.md`](../GOVERNANCE.md) §"Continuity and bus factor"
+ [`docs/assurance-case.md`](assurance-case.md). Reviewed at
every release per release-checklist.md Step 5; full review on a
quarterly cadence regardless of release activity.*
