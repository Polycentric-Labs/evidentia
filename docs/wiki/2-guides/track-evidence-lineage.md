# Track evidence-artifact lineage

Evidence in Evidentia lives in a **WORM (write-once-read-many)** store: once an
artifact version is persisted it is **immutable**, and "editing" means appending
a *new version* to the same lineage chain. The store keeps one directory per
lineage and one JSON file per version (`v1.json`, `v2.json`, …) — saving a new
version never overwrites an existing one. That gives an auditor a tamper-evident
*history* of how a piece of evidence changed over time, not just its latest
state.

This guide covers the **lineage** surface: how to save a fresh artifact, append
a new version, and walk a chain to inspect any version — from both the
`evidentia evidence` CLI and the **Evidence** web console screen. It is the
companion to [Sign and verify evidence](sign-and-verify-evidence.md), which
covers the *cryptographic* attestations (GPG / Sigstore signatures). This page
deliberately does **not** repeat the signing material — see that guide for it.

## Prerequisites

- An evidence-store directory. By default Evidentia resolves it from
  `--store-dir` → the `EVIDENTIA_EVIDENCE_STORE_DIR` environment variable → a
  per-platform default directory. No setup is required to start — the first
  `save` creates the store.
- A YAML or JSON file describing the artifact, validated against the
  `EvidenceArtifact` schema (the `save` command takes a file path, not flags).

## The lineage model

A lineage chain has three identity fields that thread the versions together:

- **`version`** — the sequence number within the chain. The first version is
  `1` (the default); each subsequent edit is `N+1`.
- **`lineage_id`** — the UUID of the chain. For the **first** version you leave
  this unset: the artifact *is* the lineage root, and its own `id` serves as the
  implicit lineage id. Every later version sets `lineage_id` to that root id.
- **`predecessor_id`** — the `id` of the prior version. `None` for the root;
  the previous version's `id` for every version after it.

```
v1  (id=A, lineage_id=unset → A, predecessor_id=none)
   └─> v2  (id=B, lineage_id=A, predecessor_id=A)
         └─> v3  (id=C, lineage_id=A, predecessor_id=B)
```

You never construct the v2/v3 identity fields by hand — the model's
`new_version()` factory does it for you (it mints a fresh `id`, copies the
lineage root forward, and points `predecessor_id` at the version you called it
on). The store enforces append-only on top: re-saving a version that already
exists on disk is refused.

The four **required** fields on every artifact are `title`, `evidence_type`,
`source_system`, and `collected_by`. Everything else carries a sensible default.
The valid `evidence_type` values are: `configuration`, `log`, `screenshot`,
`policy_document`, `audit_report`, `api_response`, `test_result`,
`attestation`, `repository_metadata`, `identity_data`.

## Step 1 — Save a new lineage root

Write the artifact to a YAML (or JSON) file. For a brand-new chain, leave
`lineage_id` and `predecessor_id` unset and keep `version: 1` (the default):

```yaml
# evidence-v1.yaml — a new lineage root
title: "MFA enforced on the admin console"
evidence_type: configuration
source_system: okta
collected_by: jane.doe@example.com
description: "Okta admin policy requires MFA for all administrators."
tags:
  - soc2
  - access-control
content:
  policy: require-mfa
  scope: admins
```

Persist it:

```bash
evidentia evidence save evidence-v1.yaml
```

The human-readable output reports the new artifact's `id`, its
`lineage_id` (which, for a root, equals the `id`), and `version` (`1`). **Copy
the lineage id** — it is how you address the chain from now on, since the store
has no global "list everything" command. For machine-readable output (to
capture the lineage id in a script), add `--json`:

```bash
evidentia evidence save evidence-v1.yaml --json
```

## Step 2 — Walk the lineage history

Pass the lineage id (the root's `id`, or any version's
`effective_lineage_id`) to `history` to list every persisted version with its
timestamps:

```bash
evidentia evidence history 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e
```

A well-formed but unknown lineage id returns an empty chain rather than an
error. Add `--json` for a structured list you can pipe into other tooling:

**Bash / Linux / macOS**

```bash
evidentia evidence history 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e --json \
  | jq '.[].version'
```

**PowerShell (Windows)**

```powershell
evidentia evidence history 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e --json `
  | ConvertFrom-Json | ForEach-Object { $_.version }
```

## Step 3 — Inspect one specific version

`show` renders a single version of a chain. The `--version` / `-V` flag is
**required** and must be `>= 1`:

```bash
evidentia evidence show 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e --version 1
```

Add `--json` to emit the full artifact model (the complete `model_dump`),
including the `content`, `content_hash`, and `control_mappings`:

```bash
evidentia evidence show 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e --version 1 --json
```

## Step 4 — Append a new version

When the underlying evidence changes — a refreshed export, an updated policy
snapshot — you do not edit the existing version. You append `v2`. Write a new
file whose identity fields point back at the chain: set `lineage_id` to the
root's id, `predecessor_id` to the prior version's `id`, and `version` to the
next number:

```yaml
# evidence-v2.yaml — a new version in an existing chain
title: "MFA enforced on the admin console"
evidence_type: configuration
source_system: okta
collected_by: jane.doe@example.com
description: "Re-collected after the Q3 admin-group expansion."
version: 2
lineage_id: 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e
predecessor_id: 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e
content:
  policy: require-mfa
  scope: admins-and-break-glass
```

```bash
evidentia evidence save evidence-v2.yaml
```

`history` now shows two versions. If you re-save a version number that already
exists on disk, the store refuses it with a WORM-violation error that names the
**next available version** — bump `version` to that number and re-save.

## Step 5 — (Optional) point at a non-default store

By default the store lives at `$EVIDENTIA_EVIDENCE_STORE_DIR` or a per-platform
default. To work against an explicit directory for one command, pass
`--store-dir` (accepted by `save` and `history`). To set it for a whole session,
export the environment variable:

**Bash / Linux / macOS**

```bash
export EVIDENTIA_EVIDENCE_STORE_DIR=./audit-2026-evidence
evidentia evidence history 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e
```

**PowerShell (Windows)**

```powershell
$env:EVIDENTIA_EVIDENCE_STORE_DIR = ".\audit-2026-evidence"
evidentia evidence history 8f14e45f-ceea-467d-9f8b-2a1c0b7c4d3e
```

## Track lineage in the web console

The same store is browsable from the **Evidence** screen. Start the server with
`evidentia serve` (it needs the `[gui]` extra — see
[Serve the local web UI](serve-the-web-ui.md)), then open **Evidence** in the
sidebar under **Govern** (route `/evidence`).

Because the store is addressed by lineage and has no global list, the screen
works in two halves:

1. **Save evidence (top card).** Fill in the four required fields — **Title**,
   **Source system**, **Collected by**, and a one-click **Evidence type** pill
   row — plus optional **Description**, comma-separated **Tags**, and an optional
   **Lineage id**. Leave **Lineage id** blank to start a fresh chain; set it to
   append a new version to an existing one. Click **Save evidence**; on success
   a green panel reports the new **Artifact id**, **Lineage id**, and
   **Version**. The save form posts to `POST /api/evidence`.
2. **Lineage history (lower section).** Type a lineage id into the **Lineage
   id** box and click **Load history**. The screen calls
   `GET /api/evidence/{lineage_id}/history` and renders one card per version
   (version badge, evidence-type badge, title, who collected it, and when).
   Click a version card to open an in-place **detail panel** — it shows the
   description, source system, collected-by, content hash (SHA-256), the lineage
   id, and any tags. Click **Close** to dismiss it.

A few console behaviours worth knowing:

- **WORM collision.** If you save a version that already exists in a lineage,
  the form returns a red **"Version already exists"** alert that names the next
  available version (the 409 carries a `next_version` hint). Bump the version
  and re-save.
- **Unknown vs. malformed id.** A *well-formed* lineage id with no versions
  shows an empty-state message; a *malformed* id returns a 404, surfaced as
  "No evidence lineage found for that id."
- **No filesystem path is shown.** The REST surface deliberately omits the
  on-disk store path from the save response — the browser only ever sees
  `artifact_id` / `lineage_id` / `version`, never the server's filesystem
  layout. Inspect a version's content from the CLI (`evidence show … --json`)
  when you need the full payload.

> **Heads up — finding a lineage id in the console.** The store has no
> "list all evidence" endpoint by design, so the console (like the CLI) needs a
> lineage id to look anything up. Capture the lineage id from the **Save
> evidence** success panel when you create a chain, or from the
> `evidentia evidence save … --json` output, and keep it with the rest of your
> audit record.

## What's next

- **Sign the evidence you save**: [Sign and verify evidence](sign-and-verify-evidence.md)
  adds GPG / Sigstore signatures and explains the cloud-WORM (S3 Object Lock /
  Azure / GCS) backends for hardware-enforced immutability.
- **The design behind the store**: [Concepts → Evidence integrity](../3-concepts/evidence-integrity.md)
  — the append-only model and its threat-model boundaries.
- **The artifact schema**: [Concepts → Data model](../3-concepts/data-model.md)
  documents every `EvidenceArtifact` field.
- **Who can save vs. read**: [Concepts → RBAC and multi-tenancy](../3-concepts/rbac-and-multi-tenancy.md)
  — `save` is a `write` verb; `history` / `show` are `read` verbs (RBAC only
  bites when a policy file is configured).

## Got stuck?

- **"Version already exists" / WORM violation on save** — the store is
  append-only; that version number is already on disk. The error names the next
  available version — set `version` to it and re-save.
- **`history` returns nothing** — a well-formed but unknown lineage id returns
  an empty chain (not an error). Re-check the id against the `save` output; the
  store has no global list to fall back on.
- **`show` errors about `--version`** — `--version` / `-V` is required and must
  be `>= 1`. Run `history` first to see which versions exist.
- **Validation error on `save`** — the file must validate against the
  `EvidenceArtifact` schema; a bare/empty file errors. Confirm the four required
  fields (`title`, `evidence_type`, `source_system`, `collected_by`) are present
  and `evidence_type` is one of the allowed values.
- **Console can't reach the store** — confirm the backend is running
  (`evidentia serve`) and that you launched it against the same
  `EVIDENTIA_EVIDENCE_STORE_DIR` your CLI uses.
