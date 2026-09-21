# Release publication cadence

## Scope and meaning

The release-cadence feature observes a public GitHub repository's release metadata and evaluates spacing between recorded publication events. It does not inspect deployed software, installed versions, vulnerability remediation or compliance. A release can exist upstream without any downstream system installing it.

The two operations share a closed Core contract:

| Operation | CLI | API | Console |
|---|---|---|---|
| Observe public releases | `collect release-cadence` | `POST /api/collect/release-cadence` | Collect > Release cadence |
| Evaluate local publication history | `conmon release-series` | `POST /api/conmon/release-series` | CONMON > Release series |

Polling defaults to no persistence. Series evaluation reads the selected local store without network calls or writes. Neither operation schedules future work or starts a daemon. No new MCP tool is introduced.

## Source profile and transport

The only admitted profile is `github-public-releases-2026-03-10`. It fixes the source host to `api.github.com`, the GitHub API version to `2026-03-10`, and the path to `/repos/{owner}/{repository}/releases?per_page=100&page={n}`. Owner and repository are separately validated; their lowercase forms identify the repository. Repository URLs, enterprise hosts, private repositories, credentials and caller-selected transport headers are outside this profile. The poller does not read a GitHub token.

Transport uses the existing public-destination and owned-connection controls. Redirects are refused. Only a validated next-page Link relation for the same repository and consecutive page number can advance traversal. Duplicate or unsupported Link forms refuse traversal; no guessed pagination, retries or rate-limit sleeps fill the gap. Identity and gzip bodies are bounded while streaming, with separate raw and decoded accounting.

A page is admitted only after its entire body, JSON structure, selected rows and pagination metadata pass validation. A rejected page contributes delivery counters and a fixed reason, but none of its rows enter the admitted projection. Previously admitted pages remain visible. `complete` means the bounded request reached an admitted terminal page; it is not a guarantee that GitHub returned every historical publication or that the repository was unchanged during the request.

## Native facts, presence and time

Each admitted release retains these selected fields:

`id`, `node_id`, `url`, `html_url`, `tag_name`, `target_commitish`, `name`, `draft`, `prerelease`, `immutable`, `created_at`, `published_at`, `updated_at`.

The optional `immutable` and `updated_at` fields preserve absence. Supported nullable fields preserve explicit null. Other source fields, including asset contents, release bodies and author objects, are not projected. Page hashes bind the bounded source bytes; the result is not a complete copy of the provider response.

`published_at` supplies publication time. Its literal remains separate from normalized UTC with six fractional digits. Accepted source syntax permits timezone offsets and up to six fractional digits. Invalid calendars, year zero, leap seconds, excessive precision, unsupported syntax and UTC overflow retain explicit classifications. Neither `created_at`, `updated_at` nor retrieval time substitutes for an unqualified publication time.

Drafts never create initial publication evidence. `full_releases` excludes prereleases; `all_published` admits them. Initial publication eligibility also requires a qualified publication instant no later than the actual completed traversal. For partial traversal, time eligibility is unestablished even where the reasons list is empty.

## Identity and source changes

The stable event key contains the identity version, source host, canonical owner, canonical repository and numeric release ID. Its UUIDv5 identity does not depend on tag spelling or retrieval time. The result separately binds the selected-facts digest and every row's page/record occurrence.

Identical duplicate selected facts remain separate row occurrences and share one event. Unequal selected facts for the same event are an explicit within-run conflict. They are not resolved by selecting the first, last or newest-looking row.

A first eligible publication creates a version-one `release_publication` artifact with `collected_at` equal to source publication time. Later identical observations reuse a verified publication without changing its first-observation provenance. Changed selected facts can create a distinct version-one `release_source_observation`, whose clock is retrieval time and whose content binds the original publication. Both record kinds are self-rooted evidence lineages; the observation's explicit content relation is not a Core predecessor-version mutation.

The exact fact digest also determines observation identity. Reimporting an already stored fact state can reuse that observation after validation. There is no automatic new version, overwrite, repair, migration or deletion. A matching UUID alone is insufficient: full record contents, hash domains, source key and parent relation must agree.

## Local store and persistence

Store selection uses an explicit CLI/Python override, then `EVIDENTIA_EVIDENCE_STORE_DIR`, then the platform's Evidentia data directory. Under tenant policy, the captured exact tenant selects `tenants/{tenant}` beneath that base. API callers cannot select a filesystem root or tenant in the request, query or override headers.

Strict discovery enumerates twice, reads canonical record files through descriptors, and compares the complete observed inventory. Unreadable entries, reparse points or symlinks, unsafe names, physical identity changes, invalid release records, missing parents and finite-limit excesses refuse completeness. Unrelated valid Core records do not become release events. These checks observe an operator-owned local filesystem; they do not promise protection against every hostile replacement between checks.

The version-one writer owns a unique temporary file and publishes a complete destination without replacement. A collision triggers exact readback, not overwrite. The result records save-call state, local state and verified record references separately. A call that raised can still leave a complete file, which is reported as `present_after_uncertain_save` only after qualifying readback. Mirror state remains `unobserved`; a local result makes no remote-mirror durability claim.

A complete traversal and complete preparation are required before writes. The first save needs at least 15 seconds remaining on the original clock. Once effects begin, failures retain observed outcomes and stop further work as required. A no-call `reuse_publication` slot does not claim that this run saved or reread its parent.

## Result and deadline boundaries

All ingress is native, bounded and closed. Request/model ingress rejects mutable aliases, subclasses and callbacks as authority. Raw-page testing ingress alone permits acyclic aliases, detaching and charging every occurrence. Cycles refuse at both boundaries. Canonical snapshots remain authoritative across builders and final verification; mutable output copies cannot authorize changed bytes.

| Bound | Value |
|---|---:|
| Request JSON | 4,096 bytes |
| Pages / rows per page / total row occurrences | 10 / 100 / 1,000 |
| Raw and decoded response, each per page | 4,194,304 bytes |
| Raw and decoded response, each per invocation | 16,777,216 bytes |
| Canonical selected facts per occurrence / aggregate | 16,384 / 8,388,608 bytes |
| JSON depth / values per page | 64 / 131,072 |
| Complete serialized result | 16,777,216 bytes |
| Canonical release artifact / stored release file | 65,536 / 131,072 bytes |
| Root entries / total lineage children / canonical files per discovery pass | 4,096 / 16,384 / 8,192 |
| Qualifying release reads across both passes | 2,048, permitting at most 1,024 qualifying records |
| Aggregate observed store bytes | 67,108,864 bytes |
| Original invocation deadline | 60 seconds |

Selected-facts and complete-result limits count canonical JSON bytes with ASCII escaping; native Unicode is preserved rather than normalized or trimmed. Store counts charge observed occurrences, including both reads, rather than just unique objects.

The original cooperative clock covers request admission, traversal/discovery, validation and output admission. Polling reserves 15 seconds for subsequent work; series discovery reserves 5. There is no reset deadline for save, readback, cleanup or publication. Synchronous OS operations cannot be forcibly preempted by this clock, and disconnect/cancellation does not roll back completed writes.

If an operation-owned save was actually entered and the original deadline expires before a full validated result can be returned, the API uses the pre-encoded `persistence_outcome_unavailable` error (HTTP 500). The CLI prints the same fixed message and exits 1. It states that persistence may have occurred and requires inspection before retry. It is not a fabricated complete result or a pre-admission failure. Ordinary cancellation remains cancellation.

## Offline series semantics

`evaluate_release_series` groups verified local publication and observation records by stable event identity. Material changes to node ID, publication instant, publication qualification or draft status cause source conflict. Prerelease changes also conflict for `full_releases`. Equivalent publication literals and non-cadence metadata changes remain distinguishable without adding events.

The requested window has explicit UTC endpoints, includes events exactly on either endpoint, and cannot end after evaluation begins. The window spans at most 36,600 days. Interval is 1 through 3,660 days; tolerance is 0 through 3,660 days. Arithmetic uses exact integer microseconds and 86,400 seconds per day.

Fewer than two eligible in-window events produces `insufficient` with no gap rows. With at least two, the result checks the leading window boundary, every adjacent event pair and the trailing boundary. A gap exceeds policy only when its duration is strictly greater than interval plus tolerance. Equality passes. Multiple source observations do not increase event count.

The states are `continuous`, `gapped`, `insufficient`, `conflict` and `unavailable`. A `continuous` result describes only the recorded upstream-publication series in that explicit window.

## Surfaces and validation scope

API operations require the configured authentication provider and a bound, unchanged RBAC policy. Both require read permission; persistence additionally requires write permission. The CLI keeps its existing read-denial exit 77. Series support belongs to Core and remains available when the optional poll collector is absent; missing and broken poll support remain different refusals.

The console snapshots the request before awaiting, validates the complete bounded response, and rejects stale publication after selection, cancellation or authentication ownership changes. Failed replacement under the same owner retains the last good result. Source values render as inert text. Full downloads retain the accepted response bytes; they do not save evidence. Demo responses are explicitly synthetic and never contact GitHub or persist.

Offline validation covers source/time/identity rules, atomic publication, discovery, actual API and CLI boundaries, complete console graphs, finite resource boundaries and instrumented Windows capacity. These are not live-provider interoperability, cross-platform execution or downstream patch-installation claims. See the [operator guide](../wiki/2-guides/release-cadence.md).
