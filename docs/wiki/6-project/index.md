# 6. Project

Project meta: roadmap, changelog, API stability, versioning, governance, security, contributing, EOL, verification, FAQ.

## Pages in this section

- **[Roadmap](roadmap.md)** — mirror of [`ROADMAP.md`](../../ROADMAP.md) (the canonical source-of-truth).

- **[Changelog](changelog.md)** — mirror of [`CHANGELOG.md`](../../../CHANGELOG.md).

- **[API stability](api-stability.md)** — NORMATIVE; mirror of [`docs/api-stability.md`](../../api-stability.md). Frozen-surface contract for v0.9.7+.

- **[Deprecation policy](deprecation-policy.md)** — mirror of [`docs/deprecation-calendar.md`](../../deprecation-calendar.md).

- **[Versioning](versioning.md)** — SemVer 2.0.0 conventions; pre-1.0 minor-vs-patch heuristics; v1.0 transition criteria.

- **[Governance](governance.md)** — mirror of [`GOVERNANCE.md`](../../../GOVERNANCE.md).

- **[Security](security.md)** — mirror of [`SECURITY.md`](../../../SECURITY.md).

- **[Contributing](contributing.md)** — mirror of [`CONTRIBUTING.md`](../../../CONTRIBUTING.md).

- **[EOL](eol.md)** — mirror of [`EOL.md`](../../../EOL.md). Version support windows + cessation-comms policy.

- **[Verification](verification.md)** — mirror of [`docs/verification.md`](../../verification.md). Consumer-side recipes for PEP 740 + cosign + osv-scanner + SLSA Provenance v1.

- **[FAQ](faq.md)** — NEW; frequent operator questions (e.g., "how do I handle a catalog with custom controls?", "what does CIMD give me that just signing the file doesn't?", "can I run Evidentia offline?", "what's the difference between OCSF Compliance and Detection Findings?").

## How to use this section

This is the "anything that's not user-facing usage but a project-level meta-fact" section. The FAQ is the right place to look first for operational questions; the rest are mirrors of canonical artifacts at the repo root or in `docs/`.

> **Stub status:** as of v0.10.7, the 9 mirror pages (roadmap, changelog, api-stability, deprecation-policy, governance, security, contributing, eol, verification) are live generated mirrors, produced by `scripts/wiki/sync_mirrors.py` and regenerated in CI by `.github/workflows/sync-wiki.yml`; each carries an auto-generated banner plus the canonical repo-root body with absolute-blob-URL links back to the source. Only `versioning.md` and `faq.md` remain stubs — `faq.md` is waiting for its first batch of operator questions.
