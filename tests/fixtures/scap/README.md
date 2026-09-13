# Synthetic SCAP fixtures

These four newly authored XML documents exercise the admitted XCCDF 1.2 and OVAL
5.8, 5.11.2 and 5.12.3 core-result profiles. Host, user and observation labels are
synthetic. The files contain no captured scanner output or operational credentials.

The adjacent expected JSON files contain complete hand-derived native graphs and
assessment projections. The XCCDF and OVAL 5.8 expectations also contain four
separately verified artifact cases: unlinked native completion, a CA-7 cadence
association, caller-declared completion and API-authenticated completion. Each case
records every stable artifact field, its content hash, the compact identity-frame
hash and the finding identity. Import-time and run metadata are deliberately
outside these stable expectations.

The source-index.json ledger binds each XML file and expected JSON file by byte
count and SHA-256. Unit tests normalize checkout CRLF to LF only when reading these
synthetic fixtures. The collector does not normalize operational source bytes.

The fixtures test native observations and disclosed completion provenance. They do
not establish authenticity, complete scanner population coverage, full XML Schema
conformance, platform-specific OVAL validity or a compliance conclusion. Comments,
processing instructions, ordering and uninterpreted content remain in the native
graph. OVAL generator timestamps do not qualify assessment completion.

Expected values must be reviewed independently of the implementation under test.
Do not replace these files with collector output to resolve a failed comparison.
