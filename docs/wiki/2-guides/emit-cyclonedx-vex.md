# Export control-gap observations as CycloneDX

`evidentia gap analyze --format=cyclonedx-vex` exports a gap report using
CycloneDX 1.6 by default. Select 1.7 explicitly when needed. Both versions use
the same supported fields and retain each gap's source values.

These exports describe control-gap lifecycle observations. The `analysis`
object contains only `detail`; it does not assert vulnerability impact,
component applicability, vulnerable-code presence or exploitability. Accepting
a control risk, marking a control not applicable, or remediating a control gap
does not establish any of those software conclusions.

## Before you start

Install Evidentia and prepare a control inventory as described in
[Run a gap analysis](run-gap-analysis.md). Exporting needs no additional
CycloneDX tool or network access. Check the selected schema version and your
consumer's handling of gap observations before using the file in another
system. Schema validation alone does not establish VEX applicability or
interoperability with a particular consumer.

## Export the default version

The following commands write CycloneDX 1.6 JSON to `gap-vex.cdx.json`.

**Bash**

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-mod \
  --format=cyclonedx-vex \
  --output=gap-vex.cdx.json
```

**PowerShell**

```powershell
evidentia gap analyze `
  --inventory=my-controls.yaml `
  --frameworks=nist-800-53-mod `
  --format=cyclonedx-vex `
  --output=gap-vex.cdx.json
```

You can also pass `--vex-spec-version=1.6` explicitly. Omitting the option
retains the 1.6 default.

## Select CycloneDX 1.7

**Bash**

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-mod \
  --format=cyclonedx-vex \
  --vex-spec-version=1.7 \
  --output=gap-vex-1.7.cdx.json
```

**PowerShell**

```powershell
evidentia gap analyze `
  --inventory=my-controls.yaml `
  --frameworks=nist-800-53-mod `
  --format=cyclonedx-vex `
  --vex-spec-version=1.7 `
  --output=gap-vex-1.7.cdx.json
```

Only the exact values `1.6` and `1.7` are accepted. An invalid value or an
explicit version used with another export format exits with status 2 before
inventory loading, analysis, output, report saving or signing. The CLI's input
path checks can run before this option check.

## API and console

The gap export API accepts the optional JSON member `vex_spec_version` for
`format: "cyclonedx-vex"`. Omission selects 1.6; explicit `"1.6"` and `"1.7"`
select those versions. Invalid typed values, `null` and unknown request members
produce HTTP 422. An explicitly supplied valid version with another format
produces HTTP 400 after the existing format and report-source checks, before
loading a stored report or creating an export file. A successful VEX response
retains the `application/vnd.cyclonedx+json` content type and `.vex.cdx.json`
download suffix.

In the console, choose **CycloneDX VEX**, then use **CycloneDX version**. The
selector starts at 1.6. A download captures the chosen format and version; both
selectors and the export button stay disabled while it runs. Static demo mode
reports that VEX export is unavailable instead of downloading native report
JSON under a VEX filename. Other demo export formats retain their existing
behavior.

## Output compatibility

Each control gap still produces one `vulnerability` entry with its existing
identifier, source, severity, description, recommendation and source properties.
The lifecycle details remain literal observations. The export does not add
`analysis.state`, `analysis.justification`, `analysis.response` or an `affects`
relationship inferred from those observations.

The serial number is a deterministic UUID URN derived from the report ID and
the original analysis timestamp representation. Re-exporting that report in
either version retains the serial. It is not a content digest, and a different
offset representation can produce a different serial for the same instant.
This reuse deliberately differs from the publisher's recommendation for a
fresh serial per BOM. Consumers must not treat the serial as proof of identical
content.

Tool metadata uses `publisher`. The metadata timestamp is the report's analysis
instant normalized to UTC with six fractional digits, not the time of export.
Naive timestamps, undefined offsets and UTC conversion outside the supported
calendar range are refused without substituting the current time. These
corrections apply to new exports in both versions. Previously written files
are not rewritten.

For the full option list, see the [CLI reference](../4-reference/cli.md).
Other export workflows are covered in [Emit SARIF](emit-sarif.md) and
[Emit OCSF Detection](emit-ocsf-detection.md).
