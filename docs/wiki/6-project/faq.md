# FAQ

Frequent operator questions with accurate, source-backed answers. Each
answer links to the guide or concept page that covers the topic in
depth.

## What is a control inventory, and what format does it take?

A **control inventory** describes what your organization actually does
today ("what do we have?"). The gap analyzer compares it against a
framework catalog ("what does the framework require?") and reports the
gaps. It is **not** an evidence directory — `--inventory` takes a single
YAML, CSV, or JSON file.

The minimal shape is an `organization` string plus a `controls[]` list,
where each control has an `id` (matching framework control IDs like
`AC-2`, `SC-13`, `CC6.1`), an optional `title`, a `status` (one of
`implemented` / `partially_implemented` / `planned` / `not_implemented`
/ `not_applicable`), and optional `implementation_notes` + `owner`.

A ready-to-run starter template ships **inside** the installed package
so a fresh `pip install evidentia` can run the quickstart with zero
setup. Locate it from Python:

```python
from importlib.resources import files
path = files("evidentia.examples") / "sample-inventory.yaml"
```

Then run a gap analysis against a bundled framework:

```bash
evidentia gap analyze \
    --inventory <path-to-sample-inventory.yaml> \
    --frameworks nist-800-53-rev5-moderate \
    --output gap-report.json
```

The sample's control IDs are all drawn from the bundled
`nist-800-53-rev5-moderate` catalog, so it produces a meaningful report
out of the box. See [Guides → Run gap analysis](../2-guides/run-gap-analysis.md)
for the full walkthrough.

## What does CIMD give me that signing the file doesn't?

This is a common confusion, so to be precise: **CIMD and signing are two
different mechanisms that solve two different problems.**

- **CIMD (Client ID Metadata Document)** is an **OAuth client-scope
  gating** layer for the MCP server, per the OAuth Dynamic Client
  Registration spec (RFC 7591). It lets you register multiple MCP clients
  (e.g. `claude-desktop`, `readonly-agent`) each with a `scope` field
  that **allowlists which tools that client may call**, and it logs the
  calling `client_id` in the audit trail. CIMD is **NOT authentication
  and NOT a signature** — a client connecting without transport auth can
  claim any `client_id`, so operators deploying CIMD must *also* wire
  transport auth. CIMD answers "*which* tools may *this* client invoke?"

- **Signing** is a cryptographic integrity + provenance mechanism. MCP
  tool output is signed via the **`SignedToolOutput`** envelope
  (Sigstore-keyless), and OSCAL documents are signed with **GPG** detached
  signatures (the air-gap path) or Sigstore/cosign (the online path).
  Signing answers "*did this output really come from Evidentia, and has
  it been tampered with?*"

So CIMD gives you per-client tool authorization + an audit trail of who
called what; signing the file gives you tamper-evidence + provenance.
They compose, but neither substitutes for the other. See
[Concepts → Evidence integrity](../3-concepts/evidence-integrity.md) for
the signing chain and
[Guides → Sign and verify evidence](../2-guides/sign-and-verify-evidence.md)
for the recipes.

## Can I run Evidentia offline / air-gapped?

Yes — this is a first-class design goal. Evidentia's gap arithmetic runs
on-device; the only optional outbound calls are LLM API requests. The
global **`--offline`** flag fails closed on any non-local network call
(every LLM / network call consults the `network_guard` module, which
raises before any network IO fires for non-loopback / non-RFC-1918
targets), and `evidentia doctor --check-air-gap` validates your posture.

For installing without PyPI reach, use the offline wheelhouse pattern
and the GPG-only signing fallback (for enclaves that cannot reach
Sigstore's Fulcio/Rekor). See
[Guides → Air-gapped install](../2-guides/air-gapped-install.md).

## What's the difference between an OCSF Compliance Finding and a Detection Finding?

They are two different OCSF classes for two different purposes:

- **Compliance Finding** (`class_uid` **2003**) is the semantically
  correct class for compliance-posture results — "control X is
  satisfied / not satisfied". This is what `evidentia gap analyze
  --format ocsf` emits, and what `finding_from_ocsf` ingests.
- **Detection Finding** (`class_uid` **2004**) is what security scanners
  like Prowler and AWS Security Hub emit — security *detections*, not
  compliance posture. Evidentia ingests these via
  `finding_from_ocsf_detection` and can emit them with
  `evidentia gap analyze --format ocsf-detection` for SIEM ingestion
  (Splunk / Elastic / Sentinel / Datadog read 2004 natively).

So: emit **2003** when your consumer wants compliance posture; ingest
**2004** when pulling from a scanner; emit **2004** when feeding a SIEM.
See [Compliance → OCSF mapping](../5-compliance/ocsf-mapping.md) for the
NORMATIVE field map and [Guides → Ingest OCSF](../2-guides/ingest-ocsf.md)
/ [Guides → Emit OCSF Detection](../2-guides/emit-ocsf-detection.md).

## How do I add a custom framework / catalog?

Open a 3-file PR: add a catalog file (YAML or JSON — the loader
auto-detects by extension) under the appropriate `data/<region>/`
directory, run `python scripts/catalogs/regenerate_manifest.py` to
update the auto-generated `frameworks.yaml` manifest, and stage both.
The required schema (`framework_id`, `tier`, `category`, `families`,
`controls[]`, plus the Tier-C `placeholder` / `license_required` /
`license_url` fields for copyrighted frameworks) is documented in
[Compliance → Contributing a catalog](../5-compliance/contributing-a-catalog.md).

If the framework's control text is copyrighted (ISO, CIS, PCI DSS,
etc.), ship it as a **Tier-C placeholder** — control IDs + neutral
titles only, with a `license_url` — and let operators import their
licensed copy with `evidentia catalog import`. See the
[Catalog inventory](../5-compliance/catalog-inventory.md) for the tier
conventions.

## Why isn't there a `collect osps` command?

Because the OSPS conformance checks are exposed as a **library surface**,
not a CLI collector verb. The `collect` command group covers the
SaaS / cloud / database collectors (`aws`, `github`, `okta`, `sql`,
`databricks`, `snowflake`, `vanta`, `drata`, `bitsight`,
`securityscorecard`, `ocsf`, `convert`) — there is intentionally no
`evidentia collect osps`.

Instead, the ~16 OSPS conformance checks live as
`populate_osps_*(client, owner, repo)` helper functions in
`evidentia_collectors.github.osps`. Each returns one `SecurityFinding`
with a `compliance_status` mapped from a GitHub REST API observation. You
drive them from a small script (the
[OSPS Baseline mapping](../5-compliance/osps-baseline-mapping.md) +
[Guides → OSPS self-assessment](../2-guides/osps-self-assessment.md)
pages show the pattern). They were shipped as library helpers because
they are most useful composed into a project's own conformance-attestation
tooling — exactly how Evidentia's own
[`OSPS-CONFORMANCE.md`](https://github.com/Polycentric-Labs/evidentia/blob/main/OSPS-CONFORMANCE.md)
+ `verify-osps-conformance.yml` CI gate uses them.

## How do I verify a release I downloaded?

Every tagged release ships PEP 740 attestations on the wheels + sdist
(Sigstore-signed, Rekor-logged), a cosign SLSA Provenance v1 attestation
on the container, and a CycloneDX 1.6 SBOM attached to the GitHub
Release. Consumer-side recipes for `pip`/`pypi-attestations`, `cosign`,
`osv-scanner`, and SLSA provenance verification are in
[Project → Verification](../6-project/verification.md). The supply-chain
attestations Evidentia itself produces are summarized on
[Compliance → Framework conformance](../5-compliance/framework-conformance.md).

## Is Evidentia audited / certified?

No third-party audit has been conducted. Evidentia's OpenSSF OSPS
Baseline conformance (Maturity 2, with partial Maturity 3) is a
**self-assessment** backed by a re-validating CI gate; it holds the
OpenSSF Best Practices Badge at **Silver** and runs OpenSSF Scorecard
weekly. See [Framework conformance](../5-compliance/framework-conformance.md)
for exactly what is and is not claimed.

## See also

- [Guides](../2-guides/index.md) — task-oriented how-tos for every surface above.
- [Concepts](../3-concepts/index.md) — the "why" behind the data model + engines.
- [Reference](../4-reference/index.md) — CLI verbs, MCP tools, config, catalog +
  crosswalk tables.
