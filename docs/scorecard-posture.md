# OpenSSF Scorecard posture

This document explains Evidentia's [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/Polycentric-Labs/evidentia)
score, check by check. The aggregate (**5.7** as of 2026-06-17, Scorecard
v5.3.0) is held down almost entirely by checks that are either **transient
artifacts** of the project's recent org migration, **structural consequences**
of a deliberate solo-maintainer direct-push workflow, or **small fixes already
applied and awaiting the next weekly re-scan** — not by sloppy supply-chain
hygiene. The substantive supply-chain checks (SAST, Pinned-Dependencies,
Dependency-Update-Tool, Security-Policy, License, Packaging, Dangerous-Workflow,
Binary-Artifacts) all score 9–10.

## Checks scoring 9–10 (no concern)

SAST (CodeQL) · Security-Policy · Dependency-Update-Tool (Dependabot) ·
License (Apache-2.0) · Packaging · Dangerous-Workflow · Binary-Artifacts ·
CII-Best-Practices (Silver) · Pinned-Dependencies (9) · Vulnerabilities (9).
These represent the real, controllable supply-chain surface, and they are in
good shape.

## Low / zero checks — what each means and our disposition

### Maintained — 0 · transient (recovers ~2026-08)
**Measures:** recent commit/release/issue activity. **Why low:** Scorecard
hard-zeros any repo created within the last 90 days. This repo's GitHub
creation date is the **org-migration date** (`allenfbyrd/evidentia` →
`Polycentric-Labs/evidentia`, mid-May 2026), not the project's true age — it
has shipped continuously since 2024. **Disposition:** ages out automatically
once the 90-day window from migration closes (~August 2026); no action.

### Signed-Releases — 0 · transient + one applied fix
**Measures:** cryptographic signatures / provenance attached to release
artifacts. **Why low:** Scorecard scanned v0.10.6–v0.10.10 and inspects the
**GitHub Release assets**, which carried only the CycloneDX SBOM. Evidentia
**does** sign every release — PEP 740 attestations on every wheel/sdist
(Sigstore + Rekor), cosign keyless container signatures, and SLSA build
provenance — but those artifacts live on **PyPI / the OCI registry / Rekor**,
which this check does not inspect. **Disposition:** the signing is real and
verifiable today (see SECURITY.md → supply-chain provenance, and
[`docs/verification.md`](verification.md)). To make the check *see* it, the
release workflow additionally attaches the SLSA provenance (`.intoto.jsonl`) /
cosign bundle as Release assets; the score climbs as the 5-release window rolls
forward.

### Token-Permissions — 0 → fixed (pending re-scan)
**Measures:** least-privilege GitHub Actions token scopes. **Why low:** one
workflow (`dependabot-automerge.yml`) declared `contents: write` at the
**top level**; Scorecard near-binary-caps the check on any top-level non-read
write. The other write grants (`release.yml`, `sync-wiki.yml`) were already
**job-scoped and justified**. **Disposition:** fixed — the
dependabot-automerge permissions are now job-scoped with a top-level
`contents: read` default (matching the pattern already used by sync-wiki.yml).
Expected 0 → 9–10 at the next weekly scan.

### Vulnerabilities — 9 → fixed (pending re-scan)
**Measures:** open known vulnerabilities. **Why low:** one transitive
**build-time** npm devDependency in the UI — `brace-expansion`
(GHSA-jxxr-4gwj-5jf2 / CVE-2026-45149, a ReDoS) pulled via the OpenAPI tooling.
It is **not in the shipped Python wheels** and not in any runtime path.
**Disposition:** fixed via an `overrides` pin + regenerated lockfile; low
urgency (build-tool DoS only).

### Pinned-Dependencies — 9 → fixed (pending re-scan)
**Measures:** dependencies pinned by hash. **Why low:** exactly one unpinned
item — a `pip install "pyyaml>=6.0"` *range* in `docker/Dockerfile.demo` (the
demo image, not the shipped wheel; the base image is already `@sha256`-pinned).
**Disposition:** pinned to an exact version. Aggregate impact is small (9 is
already high); done for cleanliness.

### Code-Review — 0 · by-design (solo maintainer)
**Measures:** human approving review before merge. **Why low:** Evidentia ships
via **direct-push-to-main** with a tag-driven release (`enforce_admins=false`);
the push is itself the human release gate, and a solo direct-push flow
structurally produces zero merged-and-approved PRs. **Disposition:** by-design.
Substitute controls: CodeQL SAST (10), required status checks, signed commits,
and a mandatory `/pre-release-review` gate before every tag.

### Branch-Protection — 3 · by-design (+ a visibility lever)
**Measures:** maximal branch-protection. **Why low:** the PR-centric
requirements (required approvers, CODEOWNERS review, PRs-required) are
incompatible with the direct-push design above. The non-PR protections **are**
on: deletion disabled, force-push disabled, required status checks,
admin-included. **Disposition:** by-design for the PR requirements; expressing
the active protections as a public Repo Ruleset lets Scorecard fully credit the
controls already in place.

### Contributors — 3 · by-design (early-stage)
**Measures:** contributors from multiple organizations (bus-factor). **Why
low:** a single-org solo project. **Disposition:** by-design; rises organically
with external contributors. No artificial action.

### Fuzzing — 0 · by-design (candidate for v1.0)
**Measures:** continuous fuzzing integration. **Why low:** no fuzz harness yet.
Evidentia's attack surface is structured-data parsing (OSCAL/YAML/JSON
catalogs, OCSF findings) rather than raw byte-stream parsing; the project uses
mutation testing (`mutmut`) today. **Disposition:** intentional gap with a named
v1.0 candidate (ClusterFuzzLite against the catalog loader + OCSF ingestion
paths).

### CI-Tests — N/A (−1) · by-design
Excluded from the aggregate. Reported "no pull request found" because of the
direct-push flow — tests **do** run on every push and are required status
checks; Scorecard cannot see them through the PR lens.

## Summary

The fixable items (Token-Permissions, Pinned-Dependencies, Vulnerabilities, plus
attaching provenance assets for Signed-Releases) are small and have been
addressed in the current cycle; the score reflects them after the next weekly
Scorecard scan. The remaining low checks are the honest, intentional cost of a
solo-maintainer direct-push project and a recent org migration — understood and
either temporary or deliberately accepted, with mitigating controls named above.
