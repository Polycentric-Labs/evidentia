# 5. Compliance

Use this section to check what catalogs Evidentia bundles, what its own
conformance evidence supports, and how crosswalks and catalog imports work.

## Pages in this section

- **[Catalog inventory](catalog-inventory.md)**: framework families, redistribution tiers and the text actually bundled.
- **[Catalog currency](catalog-currency.md)**: dated source checks, historical catalogs, ID changes and applicability limits.
- **[Framework conformance](framework-conformance.md)**: Evidentia's own standards claims and supporting evidence.
- **[Crosswalk index](crosswalk-index.md)**: bundled mappings and their source and target families.
- **[OSPS Baseline mapping](osps-baseline-mapping.md)**: the upstream assessment requirements, bundled mappings and GitHub collector checks.
- **[OCSF mapping](ocsf-mapping.md)**: the normative `SecurityFinding` field map, ingestion and detection behavior.
- **[Gemara mapping](gemara-mapping.md)**: Evidentia's alignment with the OpenSSF Gemara taxonomy.
- **[Financial-sector overlay](financial-sector-overlay.md)**: catalog composition for banks, broker-dealers, insurers and credit unions.
- **[Contributing a catalog](contributing-a-catalog.md)**: the catalog schema, redistribution rules and required validation.

## Keeping these pages current

The catalog inventory, framework conformance and crosswalk index are maintained
against the repository's data and evidence. The catalog inventory includes a
generated count table. OCSF, Gemara, financial-sector overlay, catalog currency
and catalog contribution pages are generated mirrors of their canonical
`docs/` sources. `scripts/wiki/sync_mirrors.py` refreshes those mirrors, and the
wiki synchronization workflow publishes them after the required checks pass.
