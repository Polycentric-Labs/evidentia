# Import SCAP results

Evidentia imports a local XCCDF or OVAL results document and returns its native observations, the selected assessment, completion provenance and artifact availability. Use the CLI, the SCAP tab in Collect, or the raw XML API. Importing does not run a scanner or save evidence automatically.

## Choose an explicit source profile

| Profile | Accepted results source |
| --- | --- |
| `xccdf-1.2-results` | XCCDF 1.2 Benchmark with a selected TestResult occurrence, or a standalone TestResult with its required benchmark reference |
| `oval-5.8-core-results` | OVAL 5.8 core results |
| `oval-5.11.2-core-results` | OVAL 5.11.2 core results |
| `oval-5.12.3-core-results` | OVAL 5.12.3 core results |

The profile and zero-based assessment index are required. Select the profile from the export's actual format and version. An exporter name alone does not establish compatibility. An ARF wrapper, STIG checklist, or another XML format is not accepted merely because it came from a SCAP tool.

The native graph preserves ordered elements, attributes, namespace declarations, comments, processing instructions and decoded text. XML newline processing still applies; the graph is not a byte-for-byte archive. The source binding records the SHA-256 and byte count of the exact input. Keep the original XML separately when those original bytes are needed.

The result preserves unselected source context and explains which assessment was selected. Source URLs, schema locations, fixes, XPath-like text and embedded signatures remain inert. The importer does not fetch references, execute instructions, verify source signatures, claim full XML Schema or platform-specific OVAL validation, or infer compliance from a native outcome.

## CLI

Install the collectors package with its `scan` extra when XML support is absent. The public Python contracts remain importable without that optional support.

Import one XCCDF result:

```powershell
evidentia collect scap --file results.xml --source-profile xccdf-1.2-results --assessment-index 0 --output scap-result.json
```

Omit `--output` to write one complete JSON document to stdout. Use `--output-view artifact` to request only the evidence artifact. A successful full result may have `evidence_artifact: null`; that is still exit 0. Requesting an unavailable artifact is exit 2 and leaves the output target unopened.

Inputs and the optional assertion sidecar must be stable local regular files. Standard input, remote shares, devices, links, reparse points, changing files and input/output aliases are refused. The importer reads finite snapshots and validates the complete result before publishing it. A file output is prepared in an owned sibling and replaced only after final checks. A failure before replacement leaves the existing target unchanged.

Stdout and filesystem operations can fail or block after final admission. Such failures are reported; there is no automatic retry or promise that partially delivered stdout can be recalled. Diagnostics use stderr. Configured CLI read-role denial remains exit 77.

## Completion and OVAL assertions

XCCDF native completion is eligible only when its declared time and source conditions qualify. Missing, future, unresolved or otherwise ineligible completion remains visible in the full result and prevents an artifact. OVAL generator timestamps describe generation and do not establish assessment completion.

For OVAL, an operator can supply a separate completion assertion. Its six required fields are:

- `schema_version`: `scap-completion-assertion-v1`.
- `source_sha256`: the exact XML input's SHA-256.
- `source_profile`: the selected OVAL profile.
- `assessment_index`: the selected occurrence.
- `completed_at`: an eligible UTC timestamp ending in `Z`, with a four-digit year and at most six fractional digits.
- `reference`: a nonblank reference for the assertion.

Duplicate or extra keys, mismatched source/selection, future completion, invalid native types and assertions on XCCDF are refused. The JSON sidecar is at most 2,048 bytes. A local caller must also give its own label:

```powershell
evidentia collect scap --file oval-results.xml --source-profile oval-5.12.3-core-results --assessment-index 0 --completion-assertion completion.json --asserted-by "Local operator" --output scap-result.json
```

The CLI records that label as caller-declared provenance. The API obtains its assertion actor from the configured authentication provider and authenticated principal. An actor or completion assertion does not establish source authenticity or assessment truth. For CLI imports, optional sidecar reading, source reading, parsing, validation and publication all use the original import deadline and import-time anchor.

## Console and API

In **Collect > SCAP**, choose the profile, assessment index and local XML file. An optional cadence association and OVAL assertion are explicit actions. The console sends the exact captured file bytes. It validates the entire response and its repeated source, native, assessment and artifact fields before replacing the last good result. Source strings are displayed as escaped text.

Full-result download remains available when the artifact is null. Artifact download requires a validated non-null artifact. Demo scenarios use synthetic fixtures and are identified as such. They do not demonstrate a live scanner assessment.

`POST /api/collectors/scap/collect` requires a configured authentication provider and read authorization before reading the body. It accepts `Content-Type: application/xml` with identity encoding. Required query fields are `source_profile` and `assessment_index`; `cadence_slug` is optional. Unknown or duplicate fields and a noncanonical decimal index are refused.

The optional `X-Evidentia-SCAP-Completion-Assertion` header carries the same six-key assertion as ASCII JSON, at most 2,048 bytes. Escape non-ASCII reference characters in JSON. A client cannot supply the actor. The API starts its import deadline and UTC anchor after media, query, assertion-header and actor-provenance admission, before consuming the body. The endpoint returns the complete result with HTTP 200; it has no artifact-only mode or implicit save operation. Authentication errors retain the API's existing 401/403 behavior.

## Results, cadence and persistence

A `scap-collection-v1` result includes the exact source binding, full native graph, selected assessment, one summary finding, manifest, completion, nullable evidence artifact, artifact-availability reasons, cadence and diagnostics. The source's individual outcomes remain in the assessment; the summary does not convert them into a compliance conclusion.

An optional `--cadence-slug` associates an existing cadence definition. Import time is not substituted for assessment completion. Unresolved completion and unavailable artifacts remain separate from cadence status. Association does not schedule future collection.

Artifact identity and content hashing are stable for unchanged source, selection, completion provenance and cadence association. Import/run metadata can change without creating a fresh stable artifact identity. Saving is a separate action through the existing evidence-save command or `POST /api/evidence`, with the required write authorization. Saving the same version-1 artifact again encounters the existing append-only refusal, including HTTP 409 at the API. The collector does not silently assign another version.

## Finite import limits and errors

The raw source limit is 8 MiB, the full result limit is 16 MiB, and nesting is at most 64 levels. Further limits bound XML tokens, decoded source text, nodes, attributes, namespaces, systems, outcomes and timestamps. A file below 8 MiB can still exceed one of those limits. Native and assessment JSON are bounded independently at 5 MiB and 2 MiB.

Each import has a real 60-second budget with a 10-second publication reserve. Complex input or a slow host can exceed the budget. A deadline failure does not produce a successful partial result. Limits remain fixed across the CLI, Python and API surfaces.

Errors use fixed messages without parser exceptions, source values, local paths or stack traces. Invalid options, malformed/unsafe XML, unsupported profiles, source/result limits and unavailable artifacts use CLI exit 2. Missing or broken support, deadline expiry and publication failures use exit 1. At the API, option errors use 422, malformed/unsafe input uses 400, size limits use 413, media errors use 415, unavailable support/deadlines use 503, and internal/publication failures use 500. Missing optional support is distinguished from a broken installed dependency.

The [synthetic fixture ledger](../tests/fixtures/scap/README.md) describes the hand-derived expectations used for source and artifact correspondence. Synthetic checks do not establish an operational export's authenticity, completeness or compliance.
