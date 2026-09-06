# Vendored FedRAMP CR26 JSON Schemas

These are the JSON Schemas (draft 2020-12) that `evidentia conmon ksi` validates
its emitted **Security Decision Record (SDR)** documents against, vendored from
[`FedRAMP/schemas`](https://github.com/FedRAMP/schemas) so validation works
offline / air-gapped. Exact upstream pins (commit, blob SHAs, sha256 hashes,
the `$schemaVersion` baseline for all 11 CR26 schemas) live in
[`UPSTREAM.json`](UPSTREAM.json) — that file is the single source of truth for
the `fedramp-schema-watch` drift sentinel and both catalog generators
(`scripts/catalogs/gen_fedramp_ksi.py` for the KSI catalog,
`scripts/catalogs/gen_fedramp_frr.py` for the provider-facing
Requirements catalog; the FRR generator reuses the KSI generator's fetch
and sha256 check so the two cannot disagree about the dataset).

## Files

| File | Upstream fidelity |
|------|-------------------|
| `fedramp-security-decision-record-schema-2026-06-24.json` | Byte-identical to upstream (re-vendored 2026-09-06 at schema 1.1.1) |
| `fedramp-common-definitions-schema-2026-06-24.json` | Byte-identical to upstream (re-vendored 2026-09-06 at schema 0.3.0) |

Both copies are verifiable against upstream by git blob SHA: `git
hash-object <file>` must equal the `blob_sha` recorded in `UPSTREAM.json`.

## History: the `$ref` local delta (2026-07-18 → 2026-08-21, now retired)

As published, every cross-document `$ref` in the CR26 schema set placed the
JSON Pointer in the URI **path** (`...json/$defs/x`) instead of the **fragment**
(`...json#/$defs/x`), so no conforming JSON Schema 2020-12 validator could
resolve them. Evidentia carried a single documented rewrite of that ref in the
vendored SDR schema from the 2026-07-18 re-vendor onward, so `conmon ksi`
could validate offline while the defect stood upstream.

Upstream fixed it on 2026-08-11 ([issue
#11](https://github.com/FedRAMP/schemas/issues/11) → [PR
#15](https://github.com/FedRAMP/schemas/pull/15), "Fix unresolvable
cross-schema $refs (path form → URI fragment)"). The 2026-08-21 re-vendor
picked up that commit, confirmed the upstream ref is now byte-for-byte what
the local delta had been, and retired the delta: the vendored SDR schema is
byte-identical to upstream again and `UPSTREAM.json` records `local_delta:
null` for both files. The `fedramp-schema-watch` sentinel surfaced the merge
exactly as designed.

## History: the 2026-09-06 re-vendor (SDR metadata modelled upstream)

Upstream issue #20 ("Add metadata fields to the SDR schema", per SDR-CSO-MTD)
landed on 2026-09-01 as SDR schema 1.1.0: an optional top-level `metadata`
object with required `version`, `lastUpdated` and `updateSource`. Evidentia's
emitter had carried a rule-required `metadata` block since v0.11 as a
schema-permitted additional property, with the third key spelled `source`. The
re-vendor renamed the emitted key to `updateSource` in the same change, so the
block validates under the new shape; the operator-facing status-file field is
still `source`. Common-definitions 0.3.0 (optional `painReductionEvents`, a
`Remediated` final disposition, a citation fix) does not touch the one `$ref`
the SDR schema takes from it. `FedRAMP/rules` did not move.

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
