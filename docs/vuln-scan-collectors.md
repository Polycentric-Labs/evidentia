# Vulnerability-scan collectors

> *Status: Nessus ships in v0.13 (V13-05 first half). Greenbone follows in a
> later batch of the same item.*

File-ingest collectors for vulnerability-scanner exports. Unlike the
credentialed collectors (AWS, Okta, the SQL adapters, …), these read an
already-produced scan report — a file on disk or an in-memory XML string —
and never make an outbound network call. Per the
[cadence-assertion-layer design](designs/cadence-assertion-layer-design.md)
section 2.6, a file-import collector does not raise the README's
credentialed-collector count (see `scripts/check_doc_counts.py`'s
`_NON_COLLECTOR_INGEST`); it is an importer, not an evidence-collection
agent.

## Nessus (`collect nessus`)

Parses a Nessus v2 (`.nessus`) scan-export XML document — the file Nessus
Essentials, Nessus Professional, and Tenable.sc all write on export — into
one `SecurityFinding` per `(host, plugin, port, protocol)` `ReportItem`,
plus a `CollectionManifest` and one scan-report `EvidenceArtifact`.

### What the ingest reads

| Nessus v2 element | Read as |
|---|---|
| `<NessusClientData_v2>` | Required root element |
| `<Report name="...">` | Scan/report name (`CollectionContext.source_system_id`, `EvidenceArtifact.metadata.report_name`) |
| `<ReportHost name="...">` | One host |
| `<HostProperties><tag name="host-ip">` | The host's IP (`resource_id`, falls back to the `ReportHost` name) |
| `<HostProperties><tag name="HOST_START">` / `HOST_END">` | Scan start/end per host (ctime-style text, e.g. `"Tue Sep  1 10:22:31 2026"`); `HOST_END` is the finding's `collected_at` |
| `<ReportItem port protocol svc_name severity pluginID pluginName pluginFamily>` | One finding per item |
| `<synopsis>` + `<description>` | Joined into `SecurityFinding.description` |
| `<solution>` | `SecurityFinding.remediation` |
| `<risk_factor>`, `<cve>` (repeatable), `<cvss3_base_score>`, `<plugin_output>` (trimmed) | `raw_data` |

### Finding mapping

| `SecurityFinding` field | Value |
|---|---|
| `source_system` | `"nessus"` |
| `source_finding_id` | `f"{report_name}:{host_name}:{pluginID}:{port}/{protocol}"` — the model derives the deterministic `id` from `source_system` + this string (see [collector-idempotency-audit.md](collector-idempotency-audit.md) section 4); the collector never sets `id` directly |
| `title` | `f"{pluginName} on {host_name}:{port}/{protocol}"` |
| `severity` | From the numeric `severity` attribute: `0` informational, `1` low, `2` medium, `3` high, `4` critical (out-of-range values clamp to the nearest end) |
| `compliance_status` | Left at its default (`unknown`) — a vulnerability observation is not a pass/fail control check |
| `resource_type` / `resource_id` | `"host"` / the host's IP (or its `ReportHost` name when no `host-ip` tag is present) |
| `control_mappings` | `nist-800-53-rev5` `RA-5` (vulnerability scan output) + `SI-2` (flaw remediation input), both `subset-of` |
| `collection_context.collected_at`, `first_observed`, `last_observed` | The finding's host's `HOST_END`; falls back to the collection time (with a manifest warning) when the tag is absent or unparseable |

### The evidence artifact + `conmon series`

Each ingest also builds one `EvidenceArtifact` (`evidence_type` test result,
`source_system="nessus"`, `metadata.cadence_slug` from `--cadence-slug` /
`cadence_slug` or the bundled default `fedramp-conmon-scans`) summarizing
the scan (hosts scanned, findings by severity, scan start/end, run id) and
carrying the same two control mappings. Persisting it is the caller's
choice — the CLI saves it by default (`--no-save-evidence` to skip); the
API's `save_evidence` body field defaults to `true`.

Once saved, `evidentia conmon series <slug> --evidence-store <dir>` reads
every artifact whose `metadata.cadence_slug` matches and asserts a dated
series against a window — see
[conmon-runbook.md](conmon-runbook.md#cadence-evidence-series) for the full
verdict vocabulary. A gap-free series is evidence of cadence and nothing
more.

### Blind spots

```sh
python -c "from evidentia_collectors.nessus import BLIND_SPOTS; \
    import json; print(json.dumps(BLIND_SPOTS, indent=2))"
```

- **Unauthenticated scans see less than credentialed ones.** A scan run
  without host credentials relies on network-visible banners and
  responses; it cannot enumerate installed packages, local patch levels,
  or configuration files the way a credentialed scan can. The export
  carries no marker distinguishing which mode produced it.
- **Hosts outside the scan targets are absent.** The export contains
  exactly the hosts the scan policy targeted; an under-scoped target list
  is invisible to this ingest.
- **Plugin-feed age is not in the export.** Nessus v2 XML does not carry
  the plugin feed's publish or sync date — a scan against a stale feed
  looks identical, on the wire, to a scan against a current one.
- **A partial scan still produces a report.** A scan that times out or is
  manually stopped still exports whatever it collected before the
  interruption. The manifest's `is_complete` flag reflects only whether
  every host in *this* export has a parseable `HOST_END`, not whether the
  scan covered everything the policy intended.

### Security notes

- XML is parsed with `defusedxml` (`defusedxml.ElementTree.fromstring`),
  so a DOCTYPE with an `<!ENTITY` declaration or an external (SYSTEM /
  PUBLIC) reference is refused before any element is read — closing XXE
  and entity-expansion (billion-laughs) attacks from an untrusted export.
- Input is capped at 50 MB, mirroring the OCSF ingest's own cap
  (`evidentia_collectors.ocsf.collector`).
- The API endpoint takes no path and no URL — only inline XML text in the
  request body. The server never reads a client-named file; a Nessus
  export reaches the server the same way an OCSF inline-`content` payload
  does.
- Requires the optional `scan` extra:
  `pip install 'evidentia-collectors[scan]'`.

### CLI / API / console surfaces

- CLI: `evidentia collect nessus --file scan.nessus [--cadence-slug SLUG]
  [--evidence-store DIR] [--no-save-evidence]
  [--plugin-output-max-chars N] [--output FILE]`.
- API: `POST /api/collectors/nessus/collect` — body
  `{"content": "<xml text>", "cadence_slug"?, "save_evidence"?,
  "plugin_output_max_chars"?}`; returns
  `{"findings": [...], "manifest": {...}, "evidence": {"lineage_id", "saved", "collected_at"}}`.
- Console: the `/collect` page's "Nessus scan (.nessus XML)" tab — a
  textarea for the XML, an optional cadence-slug field, and a
  save-evidence toggle. Local-only, like the OCSF tab's inline-content
  mode — not gated behind API authentication.

## Related documents

[conmon-runbook.md](conmon-runbook.md) (cadence evidence series),
[cadence-assertion-layer-design.md](designs/cadence-assertion-layer-design.md)
section 2.6 (the design this implements),
[collector-idempotency-audit.md](collector-idempotency-audit.md) section 4
(the deterministic-id contract),
[evidence-integrity.md](evidence-integrity.md),
[sql-collectors.md](sql-collectors.md) (the credentialed-collector
convention this ingest deliberately does not carry — no auth, no network).
