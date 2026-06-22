# 6. Project

Project meta: roadmap, changelog, API stability, versioning, governance, security, contributing, EOL, verification, FAQ.

## Pages in this section

- **[Roadmap](roadmap.md)** — mirror of [`ROADMAP.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/ROADMAP.md) (the canonical source-of-truth).

- **[Changelog](changelog.md)** — mirror of [`CHANGELOG.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/CHANGELOG.md).

- **[API stability](api-stability.md)** — NORMATIVE; mirror of [`docs/api-stability.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/api-stability.md). Frozen-surface contract for v0.9.7+.

- **[Deprecation policy](deprecation-policy.md)** — mirror of [`docs/deprecation-calendar.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/deprecation-calendar.md).

- **[Versioning](versioning.md)** — SemVer 2.0.0 conventions; pre-1.0 minor-vs-patch heuristics; v1.0 transition criteria.

- **[Governance](governance.md)** — mirror of [`GOVERNANCE.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/GOVERNANCE.md).

- **[Security](security.md)** — mirror of [`SECURITY.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/SECURITY.md).

- **[Contributing](contributing.md)** — mirror of [`CONTRIBUTING.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/CONTRIBUTING.md).

- **[EOL](eol.md)** — mirror of [`EOL.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/EOL.md). Version support windows + cessation-comms policy.

- **[Verification](verification.md)** — mirror of [`docs/verification.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/verification.md). Consumer-side recipes for PEP 740 + cosign + osv-scanner + SLSA Provenance v1.

- **[FAQ](faq.md)** — NEW; frequent operator questions (e.g., "how do I handle a catalog with custom controls?", "what does CIMD give me that just signing the file doesn't?", "can I run Evidentia offline?", "what's the difference between OCSF Compliance and Detection Findings?").

## How to use this section

This is the "anything that's not user-facing usage but a project-level meta-fact" section. The FAQ is the right place to look first for operational questions; the rest are mirrors of canonical artifacts at the repo root or in `docs/`.

All eleven pages above are live. The 9 mirror pages (roadmap, changelog, api-stability, deprecation-policy, governance, security, contributing, eol, verification) are generated mirrors, produced by `scripts/wiki/sync_mirrors.py` and regenerated in CI by `.github/workflows/sync-wiki.yml`; each carries an auto-generated banner plus the canonical repo-root body with absolute-blob-URL links back to the source. `versioning.md` and `faq.md` are hand-authored against `docs/api-stability.md` + the ROADMAP and the in-repo source surfaces respectively.
