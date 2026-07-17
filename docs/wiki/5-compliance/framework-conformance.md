# Framework conformance

There are two different "conformance" questions about Evidentia, and
they are easy to confuse:

1. **Which frameworks does Evidentia ship catalogs for?** — that is the
   [Catalog inventory](catalog-inventory.md) (96 catalogs Evidentia
   helps *you* assess against).
2. **Which standards does Evidentia itself conform to, as a software
   project?** — that is *this* page.

This page covers the second question. Everything below is a
**self-assessment**: Evidentia has not undergone a third-party audit.
Where a claim is independently checkable (a public badge, a CI gate),
the link is provided so you can verify it yourself.

## OpenSSF OSPS Baseline — self-attested Maturity 2

Evidentia publishes a per-control conformance attestation against the
**OpenSSF Open Source Project Security Baseline v2026.02.19** at
[`OSPS-CONFORMANCE.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/OSPS-CONFORMANCE.md)
(repo root).

**The attested claim is Maturity 2, with partial Maturity 3.** As of the
2026-05-27 walk:

| Maturity | PASS / Total | Conformance |
|---|---|---|
| Maturity 1 | 24 / 24 | 100% |
| Maturity 2 | 39 / 41 | 95% |
| Maturity 3 | 55 / 62 | 89% |

The walk covers **64 active assessment-requirements** across 41
top-level controls (1 requirement, `OSPS-BR-01.02`, is `Retired`
upstream and excluded). The aggregate verdict is **57 PASS / 7
HONEST_GAP / 0 FAIL** — **zero FAIL verdicts**; every non-PASS is
documented as an HONEST_GAP with a concrete resolution path.

### The honest gaps (why Maturity 3 is partial)

Four of the seven gaps are **structurally unreachable for a
single-maintainer project** — they require ≥2 unassociated contributors
(two-person review, formal permission-grant review, etc.) and are tied
to the SOC 2 Type I segregation-of-duties milestone in
[`v1.0-transition.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/v1.0-transition.md).
The other three (CI/CD least-privilege audit, VEX emission, an
`osv-scanner` PR-blocking gate) have scoped resolution paths on the
v0.10.7 / v0.11.x roadmap. The full gap table is in the conformance
document itself.

### What makes the claim honest

A GitHub Actions gate,
[`verify-osps-conformance.yml`](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/verify-osps-conformance.yml),
re-validates **every claimed-PASS evidence link** in the conformance
document on every push to `main`, on every pull request, and on a weekly
cron. Each evidence link is translated to its GitHub REST API endpoint
and probed for HTTP 200; any 404 fails the workflow. So the attestation
cannot silently rot as the codebase evolves — a renamed or deleted
evidence file breaks CI.

For the full walkthrough of the OSPS Baseline catalogs, crosswalks, and
the 16 GitHub conformance-check collector helpers, see the
[OSPS Baseline mapping](osps-baseline-mapping.md) showcase page. To fork
this self-attestation pattern for your own project, see
[Guides → OSPS self-assessment](../2-guides/osps-self-assessment.md).

> **First-mover note.** At the time of publication (2026-05-27), a
> `gh api search/code "filename:OSPS-CONFORMANCE.md"` query returned
> `total_count: 0`. Evidentia is, to its knowledge, the first public
> open-source project to ship a machine-readable per-control OSPS
> Baseline conformance attestation paired with a re-validating CI gate.

## OpenSSF Best Practices Badge — Silver

Evidentia holds the **OpenSSF Best Practices Badge at the Silver tier**
(project [#12724](https://www.bestpractices.dev/projects/12724)). The
badge is rendered live in the
[README](https://github.com/Polycentric-Labs/evidentia#readme); click it
to see the per-criterion answers.

**Gold is structurally blocked, and the project says so plainly.** The
Gold tier requires "at least two unassociated significant contributors"
and a "bus factor of 2 or more" — both absolute MUSTs at
[bestpractices.dev](https://www.bestpractices.dev/en/criteria/2) with no
exception path. Evidentia is a single-maintainer project, so Gold is
acknowledged as unreachable until the contributor threshold is met; the
roadmap ties that to the same organizational milestone as the SOC 2
Type I program rather than promising a date.

## OpenSSF Scorecard

Evidentia runs the **OpenSSF Scorecard** weekly (and on push to `main`)
via [`scorecard.yml`](https://github.com/Polycentric-Labs/evidentia/blob/main/.github/workflows/scorecard.yml),
publishing to [scorecard.dev](https://scorecard.dev/viewer/?uri=github.com/Polycentric-Labs/evidentia).
It surfaces ~20 supply-chain checks (Pinned-Dependencies,
Branch-Protection, Code-Review, SBOM, Signed-Releases, etc.). The score
is a live, third-party-computed signal — the badge in the README links
to the current viewer.

## Supply-chain attestations (per release)

Evidentia's release pipeline produces, on every tagged release, a set of
positive supply-chain attestations that map cleanly onto procurement
frameworks:

| Attestation | Standard alignment |
|---|---|
| **PEP 740** attestations on every wheel + sdist | Sigstore-signed, Rekor-logged |
| **Sigstore / cosign** SLSA Provenance v1 on the container | SLSA Build L3 |
| **CycloneDX 1.7 SBOM** attached to each GitHub Release | NIST SP 800-218 PS.3 / SR controls |
| **OpenSSF Scorecard 6.5+** | Supply-chain hygiene baseline |

Consumer-side recipes to verify each of these yourself are in
[Project → Verification](../6-project/verification.md). Per the project's
standing posture, Evidentia has **not** mapped these into a vendor
questionnaire on this public page beyond the alignment column above;
[`positioning-and-value.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/positioning-and-value.md)
§10.4 carries the procurement-ready framing.

## What Evidentia does NOT claim

To keep this page honest:

- **No third-party audit.** The OSPS Baseline conformance is a
  self-assessment. A SOC 2 Type I examination for the maintaining entity
  is referenced as *in progress* in `v1.0-transition.md` with no
  committed delivery date — it is not a current attestation.
- **No NIST 800-53 "compliant" claim.** Evidentia ships NIST 800-53
  catalogs and maps its own release pipeline to specific SSDF / 800-53
  controls in its per-release security reviews, but it does not claim a
  formal 800-53 authorization or ATO.
- **No OpenSSF Gold.** Blocked by the two-contributor MUST (above).

## See also

- [`OSPS-CONFORMANCE.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/OSPS-CONFORMANCE.md)
  — the full per-control self-attestation (repo root).
- [OSPS Baseline mapping](osps-baseline-mapping.md) — the catalogs,
  crosswalks, and conformance-check collectors behind the claim.
- [Guides → OSPS self-assessment](../2-guides/osps-self-assessment.md) —
  how to fork the pattern.
- [Project → Verification](../6-project/verification.md) — verify the
  supply-chain attestations yourself.
- [Project → Security](../6-project/security.md) — vulnerability
  disclosure + signing policy.
