# Vendored FedRAMP CR26 JSON Schemas

These are the JSON Schemas (draft 2020-12) that `evidentia conmon ksi` validates
its emitted **Security Decision Record (SDR)** documents against, vendored from
[`FedRAMP/schemas`](https://github.com/FedRAMP/schemas) so validation works
offline / air-gapped. Exact upstream pins (commit, blob SHAs, sha256 hashes,
the `$schemaVersion` baseline for all 11 CR26 schemas) live in
[`UPSTREAM.json`](UPSTREAM.json) — that file is the single source of truth for
both the `fedramp-schema-watch` drift sentinel and the
`scripts/catalogs/gen_fedramp_ksi.py` catalog generator.

## Files

| File | Upstream fidelity |
|------|-------------------|
| `fedramp-security-decision-record-schema-2026-06-24.json` | **One documented local delta** (below) |
| `fedramp-common-definitions-schema-2026-06-24.json` | Byte-identical to upstream |

## The local delta (drop when upstream fixes it)

As published, every cross-document `$ref` in the CR26 schema set places the
JSON Pointer in the URI **path** (`...json/$defs/x`) instead of the **fragment**
(`...json#/$defs/x`), so no conforming JSON Schema 2020-12 validator can
resolve them (upstream [issue #3](https://github.com/FedRAMP/schemas/issues/3),
fix [PR #4](https://github.com/FedRAMP/schemas/pull/4) — unmerged at vendor
time). The vendored SDR schema carries exactly **one** such rewrite. When the
upstream fix merges, re-vendor byte-identical and clear the `local_delta` note
in `UPSTREAM.json`. The `fedramp-schema-watch` sentinel flags upstream movement
on these files, so the merge will surface on its own.

## Re-sync procedure

1. Fetch the current files from `FedRAMP/schemas@main`; note the commit SHA.
2. Diff against these copies; review the CHANGELOG / `$schemaVersion` bumps.
3. Re-apply (or drop, per above) the `$ref` fragment fix; update the schemas,
   `UPSTREAM.json` pins, and — if the KSI catalog content moved — re-run
   `scripts/catalogs/gen_fedramp_ksi.py` + `scripts/catalogs/regenerate_manifest.py`.
4. Run the emitter round-trip tests (`tests/unit/test_fedramp/`).

The `2026-06-24` date in the filenames identifies the CR26 ruleset; upstream
policy (their README) is that a future ruleset (CR27) cuts NEW dated files and
leaves these frozen, so a new dated set appearing upstream is a MAJOR drift
signal, not an in-place edit.
