# 5. Compliance

The compliance-tool differentiator section. What catalogs Evidentia ships, what conformance Evidentia itself claims, how to browse + use the framework crosswalks, and how to contribute a catalog.

## Pages in this section

- **[Catalog inventory](catalog-inventory.md)** — 92 framework catalogs by region/standard family + version pin + last-update date + maintainer.

- **[Framework conformance](framework-conformance.md)** — standards Evidentia ITSELF conforms to (OSPS Baseline, NIST 800-53 self-assessment, OpenSSF Best Practices Silver, etc.).

- **[Crosswalk index](crosswalk-index.md)** — browse + filter all 13 crosswalks.

- **[OSPS Baseline mapping](osps-baseline-mapping.md)** — OSPS Baseline v2026.02.19 walkthrough + Evidentia's conformance status per assessment-requirement + the 5 OSPS crosswalks + the 16 GitHub OSPS collector helpers.

- **[OCSF mapping](ocsf-mapping.md)** — NORMATIVE `SecurityFinding` ↔ OCSF field map (v0.10.0 + v0.10.5 ingestion + detection).

- **[Gemara mapping](gemara-mapping.md)** — NORMATIVE Evidentia ↔ OpenSSF Gemara taxonomy alignment (Catalogs / Logs / Documents / Entities / Collections).

- **[Financial-sector overlay](financial-sector-overlay.md)** — composition pattern for federally-supervised banks, broker-dealers, insurers, credit unions (OCC + FRB + FDIC + NCUA + FFIEC + state insurance + SR 11-7 / SR 26-02 + OCC Bulletin 2026-13a).

- **[Contributing a catalog](contributing-a-catalog.md)** — 3-file PR recipe + YAML-vs-JSON comparison + required schema + tier conventions.

## How to use this section

This section is the answer to "does Evidentia cover [framework X]?" + "how do I use Evidentia's mapping outputs in [audit / compliance / SIEM workflow]?" The OSPS Baseline mapping page is the showcase of the v0.10.6 first-mover work.

> **Stub status:** as of v0.10.7, `osps-baseline-mapping.md` remains the fully-detailed showcase page, and the 4 mirror pages (`ocsf-mapping`, `gemara-mapping`, `financial-sector-overlay`, `contributing-a-catalog`) are now live generated mirrors of their `docs/<file>.md` sources, produced by `scripts/wiki/sync_mirrors.py` and regenerated in CI by `.github/workflows/sync-wiki.yml`. The remaining stubs are `catalog-inventory.md`, `framework-conformance.md`, and `crosswalk-index.md`.
