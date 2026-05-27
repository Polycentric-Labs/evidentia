# Security policy

Thanks for taking the time to report a security concern. Evidentia
takes its supply-chain posture seriously — see the per-release
hardening in [`docs/enterprise-grade.md`](docs/enterprise-grade.md)
and the supply-chain provenance section of every release on
[GitHub Releases](https://github.com/polycentric-labs/evidentia/releases).

## Reporting a vulnerability

**Please do not open a public GitHub issue for security concerns.**

Two private channels:

1. **Preferred — GitHub Private Vulnerability Reporting**:
   <https://github.com/polycentric-labs/evidentia/security/advisories/new>.
   This routes through GitHub's coordinated-disclosure flow (private
   discussion thread, advisory drafting, optional CVE assignment).
2. **Backup — email**: `allen@allenfbyrd.com` with subject
   `[SECURITY] Evidentia <one-line summary>`. Please use this only
   if GitHub Private Vulnerability Reporting is unavailable.

Please include:

- Affected version(s) (`pip show evidentia` output is fine).
- Reproduction steps or a proof-of-concept (minimal is fine —
  willingness to engage matters more than polish).
- Your assessment of impact (data exposed, code execution,
  authentication bypass, etc.).
- Any suggested mitigation if you have one.
- Whether you'd like credit in the advisory (default: yes, with
  the name/handle you specify; no, if you prefer anonymous).

Initial acknowledgment within **3 business days**. Triage assessment
within **10 business days**. See **Disclosure timeline** below for
the full coordination window.

## Safe harbor

Evidentia commits to the following safe-harbor terms for good-faith security
researchers (CISA / FTC sample VDP language):

- We will not initiate legal action against researchers who comply with this policy.
- We consider security research conducted under this policy to be authorized
  conduct under the Computer Fraud and Abuse Act and similar laws.
- We waive any DMCA claims against you for circumventing technological
  measures to perform research under this policy.
- We will work with you to understand and resolve issues quickly.
- We will recognize your contribution if you are the first to report the
  issue and we make a code or configuration change.

In return, we ask that you:

- Make good-faith effort to avoid privacy violations, destruction of data,
  and interruption of service.
- Only use exploits to the extent necessary to confirm a vulnerability.
- Do not exfiltrate data, pivot to other systems, or use the vulnerability
  to access additional systems.
- Provide a reasonable amount of time for us to respond before public disclosure.

## Supported versions

Evidentia is pre-1.0 and ships from a **single supported patch
release**, not a minor-line. The latest patch is the only version
guaranteed to be free of disclosed advisories — older patches in the
same minor are deprecated as soon as a successor ships, even if the
deprecation reason is "carries pinned dep ranges that allow
installation of upstream-vulnerable transitive versions" rather than
a vulnerability in Evidentia's own code.

| Version | Status | Reason |
|---------|--------|--------|
| **`0.10.6`** | ✅ **Supported** | Latest patch. OSS first-mover artifacts (OSPS Baseline catalog + OSCAL + OSPS-CONFORMANCE.md) + 5 OSPS crosswalks + GitHub OSPS collector extension. 0 CVEs at ship per `docs/security-review-v0.10.6.md`. |
| `0.10.5` and earlier | ❌ Deprecated | Pre-v1.0 single-supported-patch policy; upgrade to `0.10.6`. |
| Legacy `controlbridge*` packages | ❌ Yanked from PyPI | Every version of every legacy package was yanked at the v0.6.0 rename. Upgrade path documented in [`RENAMED.md`](RENAMED.md). |

**Read this strictly**: an older patch — even one shipped less than
24 hours before its successor — is deprecated the moment a successor
ships if disclosed advisories make the older patch's resolved
dependency tree exploitable. Pre-1.0, there are no backports. The
single supported patch is always the answer.

Once `v1.0` ships, the supported-version policy will tighten to
explicit semver guarantees (latest patch of each supported minor).

## Disclosure timeline

Standard coordinated-disclosure window: **90 days from initial report
to public disclosure**. The window can shorten or lengthen by mutual
agreement — for example:

- **Shorter**: if the upstream library has already published a fix
  and we just need to bump our pin, we can ship + disclose within
  days. The v0.7.2 supply-chain follow-up
  ([commit 8baa93d](https://github.com/polycentric-labs/evidentia/commit/8baa93d))
  is the canonical pattern: 4 disclosed advisories in upstream
  packages → bumped pins → shipped + documented within hours of
  internal alerts firing.
- **Longer**: if the fix requires architectural changes, we'll
  request a window extension in the private discussion thread and
  agree on a target date.

After fix lands and is published to PyPI, the GitHub Security
Advisory is published and (if applicable) a CVE is requested.
Reporters are credited unless they opt out.

## Scope

In scope:

- Code in this repository (`packages/evidentia*/src/...`,
  `packages/evidentia-ui/src/...`, `scripts/...`).
- Build + release infrastructure (`.github/workflows/*.yml`).
- Distribution surface (PyPI packages `evidentia`, `evidentia-core`,
  `evidentia-collectors`, `evidentia-ai`, `evidentia-api`,
  `evidentia-integrations`).
- The composite GitHub Action
  (`.github/actions/gap-analysis/action.yml`).
- The bundled framework catalogs and crosswalk mappings
  (`packages/evidentia-core/src/evidentia_core/catalogs/data/`)
  insofar as a maliciously-crafted catalog could cause harm at
  load time.

Out of scope:

- **Vulnerabilities in third-party dependencies**. Report those to
  the upstream maintainer. Once a fix is published upstream, our
  Dependabot configuration
  ([`.github/dependabot.yml`](.github/dependabot.yml)) opens an
  auto-PR within the next weekly cycle, or sooner for critical
  advisories. Recent example:
  [PR #8](https://github.com/polycentric-labs/evidentia/pull/8) closed
  4 upstream advisories within hours of disclosure.
- **AWS canonical-example placeholders** in test files
  (`AKIAIOSFODNN7EXAMPLE`, `ASIAIOSFODNN7EXAMPLE` —
  [AWS-published](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html)
  literals that are never valid credentials). These are
  intentional test fixtures for the secret-scrubber's own unit
  tests.
- **Tier-C placeholder catalog text** (catalogs with the
  `placeholder: true` flag). Authoritative control text for these
  frameworks is copyrighted and not bundled; the placeholder text
  is intentionally non-authoritative. Use
  `evidentia catalog import` to load your licensed copy.
- **Findings against unsupported versions** (see Supported versions
  table above). If a vulnerability exists in an older patch but not
  in the current supported patch, the remediation is to upgrade.
- **Self-XSS, social engineering, or attacks requiring physical
  access to the user's machine.**
- **Theoretical issues without a reproducible exploit path**
  (e.g., "function X uses crypto algorithm Y which has theoretical
  weaknesses").

If you're unsure whether something is in scope, report it anyway.
We'd rather triage and decline than miss a real issue.

## Supply-chain provenance

Every Evidentia release ships with cryptographic provenance:

- **PEP 740 attestations** on every wheel + sdist, signed via the
  GitHub Actions OIDC identity (Sigstore + Rekor public
  transparency log).
- **CycloneDX 1.6 SBOM** generated from `uv.lock`, attached to
  every GitHub Release.
- **Sigstore/Rekor signing** of every OSCAL Assessment Results
  document (or GPG `.asc` signatures in air-gap mode).

Verify a release wheel:

```bash
pip install pypi-attestations
pypi-attestations verify pypi \
  --repository https://github.com/polycentric-labs/evidentia \
  "pypi:evidentia-0.10.6-py3-none-any.whl"
```

If verification fails, **stop and report immediately** via the
private channels above — a verification failure on a published
artifact is itself a security incident.

## Acknowledgments

Coordinated security reports — once disclosed and fixed — are
credited in the corresponding release notes and in the GitHub
Security Advisory. A future `SECURITY-HALL-OF-FAME.md`-style page is
planned for the post-v1.0 line; for now, recognition is
in-release-only.

Thank you in advance for helping keep Evidentia and its users safe.
