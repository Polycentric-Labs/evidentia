# Observe release publication cadence

Use **Collect > Release cadence** or `evidentia collect release-cadence` to observe public GitHub releases. Use **CONMON > Release series** or `evidentia conmon release-series` to evaluate recorded publication spacing in a local evidence store.

These results describe upstream publications. They do not show that a system installed a patch, remediated a vulnerability or satisfied a compliance obligation.

## Observe a public repository

Polling needs the `evidentia-collectors` package and no GitHub credential. Install the normal collectors extra if it is absent:

```bash
pip install 'evidentia[collectors]'
```

Choose the repository owner and name separately. Replace the example values with the public repository you intend to observe:

```bash
evidentia collect release-cadence \
  --owner example --repository application \
  --channel full_releases
```

The command writes the full canonical JSON result to stdout. It has no `--output` or findings-only format option. A shell redirect can retain the bytes:

```bash
evidentia collect release-cadence \
  --owner example --repository application \
  --channel full_releases > release-poll.json
```

Check the exit status and JSON states before using the file. Shell redirection may create an empty or incomplete file when the command or output stream fails; stdout is not an atomic file destination.

| Channel | Initial publication selection |
|---|---|
| `full_releases` | Published, non-draft releases that are not prereleases |
| `all_published` | Published, non-draft releases including prereleases |

A selected release also needs a supported `published_at` instant no later than the completed traversal. Absent, invalid, unsupported and future publication times remain visible. Retrieval time never fills in missing publication time.

Owner and repository grammar is intentionally narrow: no full URL, path separator, enterprise host or repository name ending in `.git`. The source profile is fixed to `github-public-releases-2026-03-10`. It sends unauthenticated requests to `api.github.com` with GitHub API version `2026-03-10`; it does not use `GITHUB_TOKEN`.

## Inspect the full result

Start with `collection_state`, `terminal_reason`, `pages`, `rows`, `events` and `persistence`.

- `complete` means the admitted pages reached a validated terminal page within the fixed limits. It does not establish a historically exhaustive or transactionally consistent repository snapshot.
- `partial` or `unavailable` preserves admitted evidence and fixed refusal reasons. Rows from a rejected page are not admitted. Incomplete traversal cannot save records.
- Rows retain literal selected fields, absent/null distinctions, page/record positions and publication-time classification. Identical duplicate rows share an event; unequal duplicates become explicit conflicts.
- Events show the current-to-parent comparison, known source changes and whether those changes block either channel.
- Persistence outcomes describe each publication/observation slot, whether a save was called, and what local readback established. A successful HTTP response alone is not a persistence-success assertion.

The API result retains page hashes and selected native facts, not full release descriptions, assets or downloaded binaries. URLs, tags and markup are displayed as inert source text.

## Save only when requested

The default `persist=false` poll does not open the evidence store. Saving requires the CLI flag, the request boolean or the console's explicit persistence checkbox, plus write permission:

```bash
evidentia collect release-cadence \
  --owner example --repository application \
  --channel full_releases --persist \
  --evidence-store ./release-evidence
```

The local store base is chosen by `--evidence-store`, then `EVIDENTIA_EVIDENCE_STORE_DIR`, then the platform's Evidentia data directory. Tenant policy chooses the exact `tenants/{tenant}` child from the authenticated/local identity or configured default. API and browser requests cannot supply the store path or a tenant override.

A first eligible release creates one stable version-one publication record. Its time is the source publication instant. Repeated identical source facts reuse validated stored evidence. Changed facts can create a separate source-observation record with a retrieval clock and an explicit parent-publication reference. Such observations do not create extra cadence events. Existing records are never overwritten, silently repaired or automatically versioned.

Use an operator-owned local filesystem. Discovery refuses unreadable or changed entries, symlinks/reparse points, malformed release records, unsafe Windows path spellings and unsupported storage. It checks the inventory twice; it does not claim to freeze the filesystem against all concurrent replacements.

Local outcomes include `created`, `already_saved`, `existing_different_facts`, `present_after_uncertain_save`, `not_applicable`, `not_attempted`, `failed`, `indeterminate` and `conflict`. Read the accompanying call, local-state, reason and verification fields. Mirrors are reported as `unobserved`; local success is not a remote durability receipt.

If the original deadline expires after a save was entered and a full result cannot be returned, the fixed error says:

> The release deadline expired after a save was attempted. Persistence may have occurred. Inspect local records before retrying.

This is `persistence_outcome_unavailable` (HTTP 500; CLI exit 1). Do not infer that nothing was written or blindly repeat the request. Cancellation, disconnect or stdout failure also cannot undo completed local writes.

## Evaluate recorded publications offline

Series evaluation uses Core, so it needs no poll collector or provider credential. It reads the chosen local store and makes no network calls or writes:

```bash
evidentia conmon release-series \
  --owner example --repository application \
  --channel full_releases \
  --window-start 2026-01-01T00:00:00Z \
  --window-end 2026-02-01T00:00:00Z \
  --interval-days 14 --tolerance-days 1 \
  --evidence-store ./release-evidence
```

Both window endpoints are required UTC strings ending in uppercase `Z`, with zero through six fractional digits. The window must increase, span at most 36,600 days, and cannot end in the future relative to evaluation. Interval is 1 through 3,660 days; tolerance is 0 through 3,660.

Events exactly on the start or end are included. With two or more eligible events, gaps include the window start to first event, every adjacent pair, and last event to window end. Exact equality with the allowed interval plus tolerance passes; one microsecond beyond it fails.

| State | Meaning |
|---|---|
| `continuous` | Every measured gap fits the requested policy |
| `gapped` | At least one measured gap exceeds the allowed duration |
| `insufficient` | Fewer than two eligible in-window publication events; no gap rows |
| `conflict` | Retained source observations contain a material cadence conflict |
| `unavailable` | Complete qualifying store discovery could not be established |

Changing a tag or description does not itself create another publication. Material changes to publication time, qualification, node identity or draft status block a clean series; prerelease changes also matter to `full_releases`. The full result preserves the supporting records, event relations and fixed reasons.

`conmon release-series` is separate from the YAML state file used by `conmon status` and the `conmon watch` daemon. It does not schedule polling or mark a regulatory cadence complete.

## API and console

The API operations are:

- `POST /api/collect/release-cadence`
- `POST /api/conmon/release-series`

Both require configured API authentication and read permission. Poll persistence additionally requires write permission. An absent/malformed policy or changed authority refuses the operation. These requirements apply even though the upstream GitHub requests use no credentials.

Use `Content-Type: application/json`. Bodies are closed JSON objects with no extra fields, duplicate keys, query parameters or tenant/store override headers. The fixed profile and schema version are required:

```json
{
  "schema_version": "release-poll-request-v1",
  "source_profile": "github-public-releases-2026-03-10",
  "owner": "example",
  "repository": "application",
  "channel": "full_releases",
  "persist": false
}
```

A series request carries the same owner, repository, profile and channel, with these exact remaining fields:

```json
{
  "schema_version": "release-series-request-v1",
  "source_profile": "github-public-releases-2026-03-10",
  "owner": "example",
  "repository": "application",
  "channel": "full_releases",
  "window_start": "2026-01-01T00:00:00Z",
  "window_end": "2026-02-01T00:00:00Z",
  "interval_days": 14,
  "tolerance_days": 1
}
```

The console uses these operations, verifies the full bounded result and offers an exact full-JSON download. Saving a download does not persist evidence. Tables are paginated without dropping rows from the download. A failed replacement keeps the last accepted result while the same authentication owns it; authentication loss clears it. Editing inputs, cancellation or unmount prevents an old request from publishing as the new result. Cancelling the browser request is not a server-side rollback.

Explicit demo mode uses labeled synthetic examples. It neither contacts GitHub nor writes the evidence store.

## Limits and failures

One cooperative 60-second deadline covers the invocation. There are no automatic retries or new budgets for persistence/readback. Polling reserves 15 seconds before effects and series discovery reserves 5 seconds for completion. Synchronous system calls cannot be forcibly interrupted by these checks.

The fixed source ceiling is 10 pages of at most 100 rows (1,000 row occurrences), 4 MiB raw and decoded per page, and 16 MiB each across the invocation. Canonical selected facts are limited to 16 KiB per occurrence and 8 MiB total; the complete result is at most 16 MiB. Request JSON is at most 4 KiB. Local discovery permits at most 1,024 qualifying release records across its two passes, with 2,048 charged release reads and 64 MiB total observed store bytes. Limits reject excesses rather than truncate a successful result.

CLI exit 0 means a complete poll with persistence complete or not requested, or a valid series state of `continuous`, `gapped` or `insufficient`. A gapped series is an evaluated result, not a command failure. Partial/unavailable/conflicting operations and support/output failures exit 1; invalid CLI requests exit 2; permission denial exits 77. Inspect the JSON state rather than using exit 0 as a compliance signal.

API refusals distinguish invalid request (422), request/result size (413), media type (415), unavailable support/authority (503) and broken support/operation failure (500), alongside the existing authentication responses. Provider failures use fixed reasons in the full poll result where it can be produced; upstream response bodies are not reflected as error text.

See the [design and exact limits](https://github.com/Polycentric-Labs/evidentia/blob/main/docs/designs/release-cadence-collector-design.md) and the [CLI reference](../4-reference/cli.md).
