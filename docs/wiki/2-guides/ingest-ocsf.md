# Ingest third-party OCSF findings

`evidentia collect ocsf` reads OCSF-formatted findings produced by other tools —
Prowler, AWS Security Hub, and anything else that emits OCSF — and converts them
into Evidentia `SecurityFinding` objects. Those findings can then feed a gap
analysis (via `gap analyze --findings`) or land in your evidence pipeline
alongside Evidentia's own collectors.

This is the ingest direction of Evidentia's OCSF support. The emit direction
(turning a gap report *into* OCSF) is covered in
[Emit OCSF Detection](emit-ocsf-detection.md).

## Prerequisites

- The optional OCSF extra: `pip install 'evidentia-core[ocsf]'`. Without it the
  command exits with a hint to install it.
- An OCSF JSON file or HTTPS endpoint. Evidentia accepts both the OCSF
  **Compliance Finding** class (`class_uid` 2003 — what Evidentia itself emits)
  and the **Detection Finding** class (`class_uid` 2004 — what Prowler and AWS
  Security Hub emit). The input may be a single OCSF object or a JSON array.

## Step 1 — Ingest from a file

The simplest, safest path is to write the third-party output to disk first, then
ingest it:

```bash
prowler aws --output-formats json-ocsf --output-filename prowler-ocsf.json
evidentia collect ocsf --input=prowler-ocsf.json --output=findings.json
```

`--input` (`-i`) takes a local path or an `https://` URL; `--output` (`-o`)
defaults to stdout. You will see a severity summary table and a by-source
breakdown, then the converted `SecurityFinding` array at `--output`.

## Step 2 (optional) — Ingest from a URL

If the OCSF document is served over HTTPS, you can ingest it directly:

```bash
evidentia collect ocsf --input=https://findings.internal.example.com/prowler.json \
  --output=findings.json
```

URL mode is HTTPS-only, follows no redirects, and is bounded by two caps you can
tune:

- `--url-timeout` — connect/read timeout in seconds (default `10`).
- `--url-max-bytes` — response body cap in bytes (default 50 MB).

### The `--block-private-ips` SSRF guard

By default, URL mode refuses any URL that resolves to a private, loopback,
link-local, multicast, or reserved IP range *before* it opens the connection
(added in v0.10.2). This closes a server-side request forgery surface: without
it, a hostile or mistyped URL could coax Evidentia into fetching a cloud
instance-metadata endpoint (for example `169.254.169.254`, the AWS / GCP / Azure
IAM-credential vector) or an internal-only service.

The flag is `--block-private-ips` (default, on) with an opt-out of
`--allow-private-ips`. Only relax it for a deliberately internal endpoint you
trust:

```bash
# Trusted on-cluster receiver — opt out of the private-IP block explicitly.
evidentia collect ocsf \
  --input=https://findings.svc.cluster.local/ocsf.json \
  --allow-private-ips \
  --output=findings.json
```

When in doubt, prefer file mode — fetch the document with your own tooling and
ingest the file.

## The trust-unmapped contract

OCSF carries an `unmapped` block for fields that do not fit the standard schema.
Evidentia treats third-party `unmapped` content as **untrusted**: ingested OCSF
input never controls Evidentia-native fields through that block (the v0.10.1
trust boundary). This means a foreign tool cannot, for instance, smuggle a
forged compliance verdict or control mapping into your evidence by stuffing it
into `unmapped[evidentia]`. The mapping is one-way and defensive — what you get
out is a clean `SecurityFinding` shaped by Evidentia's own mapper, not whatever
the upstream tool asserted.

## Step 3 — Use the ingested findings

The converted `findings.json` is an ordinary `SecurityFinding` array. Fold it
into an OSCAL Assessment Results document the same way you would any collector
output:

```bash
evidentia gap analyze \
  --inventory=my-controls.yaml \
  --frameworks=nist-800-53-rev5-mod \
  --findings=findings.json \
  --format=oscal-ar \
  --output=assessment-results.json
```

(Recall that `--findings` is only consumed by `--format oscal-ar`.)

## What's next

- **Round-trip the other way**: `evidentia collect convert --format ocsf` turns
  Evidentia findings back into OCSF Compliance Findings (see the
  [CLI reference](../4-reference/cli.md)).
- **Emit a gap report as OCSF for a SIEM**: [Emit OCSF Detection](emit-ocsf-detection.md).
- **The OCSF field map**: [Compliance → OCSF mapping](../5-compliance/ocsf-mapping.md).

## Got stuck?

- "OCSF ingestion needs the optional ocsf extra": run
  `pip install 'evidentia-core[ocsf]'`.
- A URL is rejected before connecting: it resolved to a private/reserved range —
  this is the SSRF guard. Use file mode, or `--allow-private-ips` if the target
  is genuinely trusted and internal.
- Ingest fails to parse: confirm the file is OCSF `class_uid` 2003 or 2004 and is
  valid JSON (a single object or an array).
