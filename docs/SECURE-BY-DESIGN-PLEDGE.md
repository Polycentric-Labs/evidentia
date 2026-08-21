# CISA Secure by Design Pledge — Alignment Statement (Evidentia)

> **As of 2026-06-26** (UTC), [Polycentric-Labs/evidentia](https://github.com/Polycentric-Labs/evidentia)
> publishes this voluntary **alignment** statement against the seven goals of
> CISA's [Secure by Design Pledge](https://www.cisa.gov/securebydesign/pledge).
> This is **not** a formal signatory claim, and it is a self-assessment — no
> third-party audit has been conducted. See **Scope & honesty** at the end for
> exactly what this document is and is not.

## What this is — and what it is not

CISA launched the **Secure by Design Pledge** at the **RSA Conference in May
2024**. It is a **voluntary** pledge whose intended audience is **software
manufacturers**, and it focuses on a manufacturer's **enterprise software
products and services**. Signatories publicly commit to demonstrate measurable
progress against seven goals, each within **one year** of signing.

Evidentia is a **solo-maintainer, Apache-2.0 open-source Python project**
(a GRC / compliance-as-code tool — a `uv` monorepo of 8 `evidentia-*` PyPI
packages plus a React UI; single maintainer Allen Byrd / Polycentric Labs).
It is **not** a corporate "software manufacturer" shipping an enterprise SaaS
fleet, and it has **not signed** the pledge. Many of the pledge's metrics
(fleet-wide MFA adoption, customer patch-installation rates, evidence of
intrusions into a hosted service) presuppose a *vendor operating software on
customers' behalf* — a shape Evidentia does not have.

So this document is an **aspirational mapping**: for each of the seven goals it
states the goal, maps it to Evidentia's *actual, verified* engineering practice
with file-level evidence, and notes — plainly — where alignment is only partial
or where the goal does not cleanly apply to a downloadable library. Every
project-specific claim below was checked against the repository at the date
above; anything that could not be verified is flagged rather than asserted.

> The pledge goals are paraphrased below from CISA's published pledge text.
> For the authoritative wording, consult the
> [CISA Secure by Design Pledge](https://www.cisa.gov/securebydesign/pledge)
> directly — that page is the source of truth, not this document.

---

## Goal 1 — Multi-factor authentication

**The goal (CISA):** Within one year of signing, demonstrate actions that
measurably increase the use of multi-factor authentication across the
manufacturer's products.

**How Evidentia aligns.** Evidentia ships **no authentication system of its
own** — it is a library, CLI, and a *locally-run* REST/web console an operator
hosts on their own infrastructure, not a multi-tenant product with end-user
accounts. The relevant MFA surface is therefore the **development and release
supply chain**, and there MFA *is* enforced:

- The **GitHub organization `Polycentric-Labs` requires two-factor
  authentication** for all members. Verified via the GitHub API:
  `gh api orgs/Polycentric-Labs` returns `"two_factor_requirement_enabled":
  true`.
- Releases are **tag-driven and OIDC-signed** — wheels and sdists carry
  **PEP 740 attestations** signed via the GitHub Actions OIDC identity
  (Sigstore + Rekor), so publication authority is bound to the CI identity
  rather than a long-lived, password-only PyPI token. (See `SECURITY.md`
  → "Supply-chain provenance" and `docs/verification.md`.)

**Gap note.** This is **org-level account 2FA** for the maintainer and CI
identity — it is *not* application-level MFA in a shipped product, because
Evidentia has no shipped product login to protect. The pledge's intent
(end-users protected by MFA) does not map onto a downloadable tool; the honest
analogue is "the accounts that can publish Evidentia are 2FA-gated," which is
true and verified, and nothing more is claimed.

---

## Goal 2 — Default passwords

**The goal (CISA):** Within one year of signing, demonstrate measurable
progress toward reducing default passwords across the manufacturer's products.

**How Evidentia aligns.** **Not applicable in the strong sense: Evidentia ships
no default credentials.** There is no bundled admin account, no seeded
password, and no "first-run" credential anywhere in the installable packages.
The local REST API / web console is unauthenticated-by-design for
single-operator localhost use and is documented as such — it does not create a
default login that an operator must remember to change.

Where the codebase *mentions* credentials, it is consuming the operator's own:

- Collectors read credentials the operator supplies via **environment
  variables** (e.g. the API's collector router exposes a read-only
  `default_password_env_configured` boolean that reports *whether the operator
  has set their own DB-password env var* — it neither stores nor ships a
  password). Evidence: `packages/evidentia-api/src/evidentia_api/routers/collectors.py`.
- Cloud-WORM retention uses the cloud SDK's **Application Default Credentials**
  chain — the platform's own auth, not an Evidentia-shipped secret. Evidence:
  `packages/evidentia-core/src/evidentia_core/retention/worm_gcs.py`.
- "Default password" strings elsewhere are **framework control text** in the
  bundled catalogs (e.g. CISA CPG "Changing Default Passwords",
  NIST 800-53 control prose) — content Evidentia *measures compliance against*,
  not credentials it uses.

**Gap note.** None material. The goal is essentially satisfied by construction:
there is nothing to reduce because nothing default-credentialed is shipped.

---

## Goal 3 — Reducing entire classes of vulnerability

**The goal (CISA):** Within one year of signing, demonstrate actions that
enable a significant, measurable reduction in the prevalence of one or more
entire classes of vulnerability across the manufacturer's products.

**How Evidentia aligns.** This is the goal where the project invests most
heavily, favoring *class-eliminating* controls over per-instance fixes wherever
the tooling allows (and saying so honestly where it does not yet):

- **Static analysis — CodeQL `security-extended` + a Models-as-Data barrier
  extension.** The advanced CodeQL setup runs the `security-extended` query
  suite across Python, JavaScript/TypeScript, and GitHub Actions. It ships a
  Models-as-Data `barrierModel` extension
  (`.github/codeql/path-injection-barriers.model.yml`, loaded via the config's
  `dataExtensions:` key) declaring `evidentia_core.security.paths.validate_within`
  and `resolve_catalog_path` as `py/path-injection` barriers. **Honest scope:**
  the stock `py/path-injection` query does not yet consume Models-as-Data
  `barrierModel` (it uses the QL `PathInjection::Sanitizer` classes), so the
  extension is a forward-looking hook and this specific CWE-22 false-positive
  class is currently **dismissal-managed** (per-instance dismissals with written
  reasons, e.g. `#170`/`#171`) rather than eliminated at the analysis layer. The
  earlier project-authored `.qll` sanitizer pack was removed in v0.10.17 — it
  never loaded (the `packs:` config key takes only published registry specs, and
  an external library pack cannot inject a barrier into a stock query). Evidence:
  `.github/workflows/codeql.yml`, `.github/codeql/codeql-config.yml`,
  `.github/codeql/path-injection-barriers.model.yml`.
- **SSRF guard (CWE-918), secure-by-default + anti-DNS-rebinding.** A single
  reusable outbound-request chokepoint (`enforce_public_host`) refuses any host
  that resolves to a private / loopback / link-local / reserved address,
  **fails closed** on unresolvable hosts, and **pins the resolved public IPs**
  so a low-TTL attacker DNS record cannot rebind to `169.254.169.254` or an
  internal host at connection time. `block_private` defaults to `True`; the
  opt-out is an explicit `--allow-private-ips` flag. Evidence:
  `packages/evidentia-core/src/evidentia_core/network_guard.py`.
- **Continuous fuzzing — ClusterFuzzLite + Atheris.** Coverage-guided fuzz
  harnesses run on every PR (`cflite-pr`) and in batch (`cflite-batch`) against
  the parser surfaces (catalog import, OSCAL profile/verify, OCSF ingest, gap
  report, TPRM questionnaire). Evidence: `.clusterfuzzlite/`, `tests/fuzz/`,
  `.github/workflows/cflite-pr.yml`, `.github/workflows/cflite-batch.yml`.
- **Malformed-input robustness suite (parser-class invariant).** Hypothesis
  property tests encode the same invariant the fuzz harnesses enforce — *a
  parser fed arbitrary input may raise only its declared exception types* —
  and run cross-platform under plain `pytest` (the harnesses are Linux/CI-only).
  This converts "unexpected-exception-on-bad-input" from a per-bug whack-a-mole
  into a *class*-level property. Evidence:
  `tests/fuzz/test_parser_robustness.py`, `tests/property/`.
- **Strict typing.** `mypy` runs with the Pydantic plugin and
  `disallow_untyped_defs = true` project-wide (`pyproject.toml` `[tool.mypy]`),
  and the local/CI gate invokes it with `--strict-optional` across all eight
  source packages (`CLAUDE.md` gate list) — eliminating large classes of
  `None`/type-confusion defects before runtime.
- **Per-release threat model.** `docs/threat-model.md` walks the external-input
  surfaces each release and maps each to a CWE (the doc references CWE-22, -918,
  -502, -400, -770, -295, -319, -345, -362, and others). Its last full
  deep-pass (2026-05-01) recorded **0 HIGH, 0 MEDIUM, 3 LOW** open findings.

**Gap note.** "Measurable reduction *across products*" presumes a product
fleet with telemetry. Evidentia's evidence is the *presence and CI-enforcement*
of these class-level controls and the threat-model trend, not a longitudinal
vulnerability-density metric across a customer base — there is no customer base
to measure. The controls are real and gated in CI; the quantified-reduction
framing is the part that does not transfer to a single open-source tool.

---

## Goal 4 — Security patches

**The goal (CISA):** Within one year of signing, demonstrate actions that
measurably increase the installation of security patches by customers.

**How Evidentia aligns.** Evidentia cannot push updates to a user's machine
(it is `pip install`'d / pulled as a container), so "increase installation by
customers" is bounded by what a library author controls: **shipping patches
fast, signed, and discoverable, with a clear support policy.**

- **Tag-driven release pipeline.** A signed tag (`git tag -s vX.Y.Z`) fires
  `release.yml`, which builds, signs (PEP 740 + Sigstore), generates the SBOM,
  and publishes to PyPI + GHCR — so a fix becomes an installable, verifiable
  release with minimal latency. Evidence: `.github/workflows/release.yml`,
  `docs/release-checklist.md`.
- **Dependabot across every ecosystem.** Automated dependency-update PRs for
  `uv`, `npm`, `github-actions`, and `docker` (`.github/dependabot.yml`), so
  upstream fixes flow into a new Evidentia patch quickly.
- **`osv-scanner` supply-chain gate.** A single shared entry point
  (`scripts/run_osv_scan.py`) generates the CycloneDX SBOM and scans it with
  `osv-scanner` — run identically by CI (`test.yml`) and pre-tag by the release
  checklist, reporting transitive *and* disputed advisories that Dependabot's
  alert view can suppress. Evidence: `scripts/run_osv_scan.py`,
  `.github/workflows/test.yml`, `osv-scanner.toml`.
- **Documented support / EOL policy.** `EOL.md` defines a **single-supported-
  patch** policy pre-1.0 (the latest patch is the only supported version; no
  backports), transitioning to "latest patch of each supported minor" after
  v1.0, plus a cessation-comms policy (OSPS-DO-05). `SECURITY.md` mirrors the
  supported-versions table. This tells operators exactly which version carries
  the fixes — the discoverability half of "install the patch."

**Gap note.** A downloadable tool **cannot force installation** — there is no
auto-update channel and no install-rate telemetry, so the "measurably increase
installation" metric is genuinely out of reach. Alignment here is "fast, signed,
clearly-supported patches that are easy to find and verify," not a patch-uptake
number.

---

## Goal 5 — Vulnerability disclosure policy

**The goal (CISA):** Publish a vulnerability disclosure policy (VDP) that
authorizes good-faith security testing by members of the public and commits to
not recommend or pursue legal action against good-faith researchers.

**How Evidentia aligns — fully.** This goal maps cleanly and is met:

- **`SECURITY.md`** publishes the policy: two private reporting channels
  (preferred **GitHub Private Vulnerability Reporting**, email backup), a
  **safe-harbor** section using CISA/FTC sample VDP language (no legal action,
  CFAA authorization, DMCA waiver for good-faith research), explicit
  **SLAs** (acknowledgment within 3 business days; triage within 10), a
  **90-day coordinated-disclosure** window, and a defined in-scope/out-of-scope
  surface.
- **`.well-known/security.txt`** (RFC 9116) advertises the contact, the
  advisory-intake URL, an encryption key, the canonical location, and a
  `Policy:` pointer to `SECURITY.md`. Evidence:
  `.well-known/security.txt` (with `Expires: 2027-05-26`).

**Gap note.** None. This is the most direct fit of the seven.

---

## Goal 6 — CVEs (transparency in vulnerability reporting)

**The goal (CISA):** Within one year of signing, demonstrate transparency in
vulnerability reporting — issue CVEs in a timely manner for at least all
critical/high-impact vulnerabilities that require customer action or show
evidence of active exploitation, and include accurate CWE (and CPE) fields in
every CVE record.

**How Evidentia aligns.**

- **CVE issuance is process-ready via GitHub-as-CNA.** GitHub is a CVE
  Numbering Authority for any repository; a maintainer can request a CVE ID
  through a repository security advisory and GitHub publishes it on advisory
  release. Evidentia's `SECURITY.md` routes reports through **GitHub Private
  Vulnerability Reporting**, which includes "optional CVE assignment," and the
  disclosure timeline states a CVE "is requested" after a fix is published.
  The path to *issue* a CVE is therefore in place and documented.
- **CWE transparency is already practiced.** Every release ships a
  `docs/releases/reviews/security-review-vX.Y.Z.md` (37 such files at the date above, from
  v0.7.7 through v0.10.12), and `docs/threat-model.md` carries explicit CWE
  identifiers per surface (CWE-22, -918, -502, -400, -770, -295, -319, -345,
  -362, and more). So the "accurate CWE in the record" discipline is already
  exercised in the public security documentation.

**Gap note (honest).** **No CVE has been issued for Evidentia to date** —
verified: `gh api repos/Polycentric-Labs/evidentia/security-advisories`
returns an empty list (length 0). That reflects that no qualifying vulnerability
**in Evidentia's own code** has been disclosed, not a gap in willingness or
machinery. Upstream-dependency advisories are handled by bumping pins and
shipping a patch (see `SECURITY.md` scope) rather than by Evidentia issuing a
CVE for someone else's code. The CPE half of the goal is not applicable until a
first CVE exists. The honest statement is: *the process is ready and the CWE
discipline is live; the issuance track record is empty because there has been
nothing to issue.*

---

## Goal 7 — Evidence of intrusions

**The goal (CISA):** Within one year of signing, demonstrate a measurable
increase in customers' ability to gather evidence of cybersecurity intrusions
affecting the manufacturer's products (e.g., via logging).

**How Evidentia aligns.** Evidentia does not operate a hosted service, so it
cannot detect intrusions *into* a Polycentric-Labs-run platform — there is
none. What it *does* ship is operator-facing **audit-grade logging and
tamper-evident evidence** that an operator can use to detect tampering with
their own compliance evidence:

- **Curated structured-audit event vocabulary** mapped to NIST 800-53 AU-3
  (Content of Audit Records) and ECS categorization — a stable
  `evidentia.<namespace>.<verb>` action registry so SIEM correlation survives
  across releases. Evidence:
  `packages/evidentia-core/src/evidentia_core/audit/events.py`,
  `docs/log-schema.md`.
- **Append-only / WORM evidence store.** The evidence store enforces
  append-only semantics at the application layer (refuses to overwrite
  `v<N>.json`), with an **optional cloud-WORM mirror** (S3 Object Lock / Azure
  Immutable Blob / GCS Bucket Lock) for regulator-grade chain-of-custody
  (FedRAMP AU-9/AU-11, HIPAA §164.312(b), SOX §404). Evidence:
  `packages/evidentia-core/src/evidentia_core/evidence_store.py`,
  `evidence_store_worm.py`, `audit/provenance.py`,
  `docs/audit-chain-of-custody.md`, `docs/evidence-integrity.md`.
- **Cryptographic provenance** on outputs (Sigstore/Rekor signing of OSCAL
  Assessment Results; signed MCP output envelopes / CIMD) so an operator can
  detect after-the-fact alteration of an evidence artifact. Evidence:
  `SECURITY.md` → "Supply-chain provenance," `docs/evidence-integrity.md`.

**Gap note (honest).** Because Evidentia runs **on the operator's own
infrastructure and ships no hosted service**, it cannot itself meet the goal's
"intrusions affecting the manufacturer's products" framing — there is no
manufacturer-run product to be intruded upon, and no telemetry flows back to
Polycentric Labs. The alignment is one level removed: Evidentia *gives its
operators* the logging and tamper-evidence primitives the goal is about, for
*their* environment. The "measurable increase" metric is theirs to observe, not
the maintainer's.

---

## Scope & honesty

- **This is a voluntary alignment statement, not a signatory claim.** Evidentia
  has **not** signed the CISA Secure by Design Pledge and is not listed as a
  signatory. Nothing here should be read as implying CISA endorsement or
  participation.
- **It is a self-assessment.** No third-party audit, attestation, or review of
  this mapping has been performed. Claims are the maintainer's, grounded in the
  cited files.
- **Evidentia is not a "software manufacturer" in the pledge's sense.** It is a
  solo-maintainer, Apache-2.0, downloadable open-source tool. Several pledge
  metrics presuppose a vendor operating enterprise software on customers'
  behalf (fleet-wide MFA adoption, customer patch-installation rates,
  intrusion telemetry from a hosted service); those do not transfer, and this
  document says so per goal rather than papering over the mismatch.
- **Honest scorecard.** Cleanly met: **Goal 2** (no default credentials) and
  **Goal 5** (published VDP + safe harbor). Strongly aligned by construction:
  **Goal 3** (class-level controls — CodeQL + sanitizers, fuzzing, SSRF guard,
  robustness suite, strict typing). Partially aligned / out-of-shape for a
  downloadable tool: **Goal 1** (org/CI 2FA, not product MFA), **Goal 4** (fast
  signed patches, but no install-rate lever), **Goal 6** (issuance ready + CWE
  discipline live, but **zero CVEs issued to date**), **Goal 7** (operator-side
  logging/WORM, but no hosted service to instrument).
- **Accuracy commitment.** Every project-specific claim above was verified
  against the repository and the GitHub API on **2026-06-26**. If any claim
  drifts out of date (counts, support status, the empty-CVE state, the 2FA
  setting), the cited file or `gh api` call is the source of truth — this
  document is a snapshot.

For the authoritative pledge text, see CISA's
[Secure by Design Pledge](https://www.cisa.gov/securebydesign/pledge). For
Evidentia's broader security posture, see
[`SECURITY.md`](../SECURITY.md), [`docs/threat-model.md`](threat-model.md),
[`docs/engineering-practices.md`](engineering-practices.md), and
[`OSPS-CONFORMANCE.md`](OSPS-CONFORMANCE.md).
