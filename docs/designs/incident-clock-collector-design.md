# Incident clock collector

The incident clock collector observes two configured workflow events on one selected incident. It preserves source literals and occurrence identities, then computes exact elapsed seconds only when the selected visible source is complete and both event instants are valid and ordered.

A workflow label records the organization's declared mapping. Creation, acknowledgement, resolution and notification events retain their operational source meanings. The collector does not establish a human determination, a regulatory deadline, service entitlement or the correctness of an organization's workflow configuration.

## Selection and authorization

The public surface is one `collect incident-clock` command, one `POST /api/collectors/incident-clock` operation named `collect_incident_clock`, and one incident clock tab in Collect. The CLI accepts `--provider`, `--request-file`, optional `--profiles-file` and optional `--output`.

A request selects a provider, profile alias, record ID and clock alias. Jira and PagerDuty allow explicit native occurrences. PagerDuty requires a nonempty `since`/`until` interval no longer than 366 days. Requests cannot supply origins, credentials, HTTP headers, source queries or workflow definitions.

The trusted profile store declares allowed records, clocks, credential references and API principal grants. A separate `allow_local_cli` grant applies only to the local command. API authentication and read RBAC precede body and profile I/O. CLI read RBAC precedes input, profile and output path metadata access. Missing, malformed, inaccessible and unauthorized profiles share one refusal before credential resolution.

Authorization issues an immutable in-process selection. Requests, profile fields and nested models reject coercion, extra fields and custom objects. The selected configuration digest binds the permitted origin and workflow mapping without publishing a credential reference.

## Provider contracts

| Provider | Selected source | Identity and interpretation |
| --- | --- | --- |
| ServiceNow | Current `sn_si_incident` record through Table API v2 | Exact lower-case `sys_id`; two distinct configured raw UTC date columns; display values and reference links excluded. |
| Jira Cloud | Numeric issue ID and visible changelog traversal within limits | Exact returned ID; history ID and item index identify occurrences; selected field IDs and native `from`/`to` values determine matching. |
| PagerDuty | Selected incident and log entries in the explicit interval | Exact incident ID on every entry; retain event ID, type and timestamp. |

ServiceNow field omission can result from ACLs or an invalid configured column. Missing cells remain missing. Current date fields do not reconstruct field history. SIR availability and the instance dictionary must be established by the organization.

Jira uses an existing authorized OAuth application. The client first reads accessible resources at the fixed Atlassian API origin and requires the selected cloud ID with `read:jira-work`. IDs shared by different resource types do not alone create ambiguity. Conflicting relevant grants are refused; other sites are excluded from the projection. App registration, consent, token exchange and renewal remain deployment prerequisites outside collection.

Jira issue creation is source context. The request sets `fields=created`, `fieldsByKeys=false`, `updateHistory=false` and `failFast=true`. The dedicated oldest-first changelog endpoint preserves every relevant item, including selected-field transitions that match neither side. Unknown item identity prevents complete matching.

PagerDuty sends its versioned JSON Accept header and supported token authorization format. It requests `total=true`, `time_zone=UTC` and `is_overview=false`. All 17 event types in the pinned contract are retained. An observed interval and visible traversal do not establish a publisher retention guarantee.

## Owned transport and admission

One session owns credentials, GET traversal, budgets, response receipts and admitted snapshots. Adapters receive traversal methods and immutable page facts. They cannot supply completeness flags or read counts as authority. The collector binds the adapter result to its own issued session authority and validates the original result bytes.

Only fixed endpoint templates are allowed. TLS uses certifi, certificate and hostname verification, TLS 1.2 or later and disabled key logging. The transport does not use ambient proxies, custom trust, client certificates, redirects, cookies, retries or content decompression. Credential material is rechecked immediately before the selected GET header is sent.

DNS uses an owned isolated CPython worker with a minimal non-secret environment. The parent validates every answer, rejects mixed public/private sets and pins approved addresses before connecting to a numeric address. Process and reader cleanup have separate bounded grace periods. Cancellation is preserved after owned cleanup.

Each response has finite body, decrypted-wire and framing budgets. The reader accepts one final HTTP/1.0 or HTTP/1.1 response with valid Content-Length or chunked framing. Conflicting lengths, ambiguous framing, informational responses, unsupported encodings and oversized control data are refused. Non-200 responses close before error-body reads.

A complete identity body retains its SHA-256 when JSON, source validation or a final deadline check rejects it. Incomplete bodies never receive whole-body hashes. Counters include observed bytes and the single overflow sentinel where applicable. A decoded outer container is counted before source-page rejection: 10001 rows remain 10001. Unreceived, incomplete, JSON-refused or uncountable bodies have null record counts.

The whole page must pass identity, field, pagination and projection checks before any event is admitted. Repeated identities, conflicting content, changing totals, repeated or skipped cursors, contradictory terminal flags and empty nonterminal pages are refused. Later rejected pages leave prior admitted pages intact.

## Clock and publication

Timestamp parsing preserves the literal and an exact integer coefficient with decimal scale. Unsupported syntax, excessive precision and invalid calendar values are refused without floating-point rounding. Event instants remain separate from local retrieval and collection wall clocks. Monotonic time governs deadlines; wall-clock adjustments are visible and never clamped.

Multiple unqualified matching occurrences are ambiguous. Explicit occurrences must still match the trusted definition. The collector does not skip a null, empty or unsupported selected timestamp to choose another occurrence. Reversed instants have no elapsed value.

Incomplete traversal produces provisional candidate lists, null selected instants and an `incomplete_source` clock. Every admitted literal remains in the projection. Diagnostics retain the first observed timestamp problem of each kind per side, with its source-read reference, within the finite budget.

The immutable run authority binds request, definition, installed collector and core versions, run ID, wall clocks, credential-validity status, record, events, reads and diagnostics. The factory derives every result, finding, context and manifest field from that snapshot. Inherited fields are required and narrowed. Legacy defaults, extra keys, copied unissued results and altered nested values are refused.

Exactly one informational finding is emitted when the selected record is admitted. Its compliance status is unknown. The finding contains a bounded summary; the full source projection and read receipts remain in the result. Coverage describes the one selected incident only.

## Budgets

| Resource | Limit |
| --- | ---: |
| Request / profile file | 16 KiB / 64 KiB |
| Profiles / grants per profile / records per profile / clocks per profile | 32 / 64 / 128 / 16 |
| History pages / total requests / projected events | 100 / 102 / 10000 |
| Page size / Jira items per history | 100 / 256 |
| One body / cumulative bodies | 1 MiB / 8 MiB |
| One decrypted response / cumulative decrypted responses | 1.125 MiB / 10 MiB |
| Status or header line | 8 KiB |
| Status, headers and trailers / chunk framing | 64 KiB / 64 KiB |
| Header and trailer fields | 100 |
| JSON depth / source JSON nodes | 32 / 100000 |
| Native string / timestamp literal | 64 KiB / 2048 UTF-8 bytes |
| Canonical record and event projection | 12 MiB |
| Reserved terminal envelope / full result | 4 MiB / 16 MiB |
| Source reads / diagnostics | 102 / 64 |
| Run useful work | 60 seconds |
| DNS / connect / TLS / read idle | 5 / 5 / 5 / 10 seconds, capped by remaining work time |
| Additional DNS process / reader cleanup grace | 1 / 1 seconds |

The session leaves ten seconds of the original run budget for sealing and publication. This does not extend the sixty-second deadline. A run that cannot finish validation and publication in time fails without fabricating a partial result. Each candidate whole-page projection is serialized against 12 MiB before admission. Final serialization checks the complete 16 MiB cap; source data is never dropped to fit.

## Surface outcomes and output

Complete sources return HTTP 200 and CLI exit 0, including unresolved or reversed clocks. Incomplete and unavailable source results return HTTP 200 and CLI exit 1. The full validated JSON is published before a nonzero exit. Invalid internal output returns a static collector failure without a substitute result.

The CLI reads bounded regular files through identity checks and refuses symlinks, reparse points, multiple hard links, input/output aliases and changed inputs. Output reservation protects both the request and selected profile file. An existing destination is replaced only after the owned sibling is written, flushed, synchronized and read back. Changed destinations or reservations are refused. Without an output path, original result bytes go to stdout and human diagnostics go to stderr.

Genuine optional-package absence is unavailable before request or profile I/O. Broken installed dependencies fail startup or the command rather than becoming optional absence. API and console publication preserve the original validated result bytes and keep source completeness separate from clock state.

## Source and fixture provenance

The [fixture index](../../tests/fixtures/incident_clock/source-index.json) binds nine authored synthetic responses by byte count and SHA-256. They demonstrate selected behavior and do not establish live provider compatibility, permissions, entitlements or organization workflow correctness.

Reviewed references are the [Jira OpenAPI snapshot](https://dac-static.atlassian.com/cloud/jira/platform/swagger-v3.v3.json?_v=1.8516.108), [PagerDuty schema at commit 2326e6b9](https://github.com/PagerDuty/api-schema/blob/2326e6b9f4737ca7f383214e1cd9d783c81fd2c6/reference/REST/openapiv3.json), and [ServiceNow Xanadu Table API documentation](https://www.servicenow.com/docs/r/xanadu/api-reference/rest-apis/c_TableAPI.html). The index records source hashes and versions. Live provider assessment and organization-specific validation require separate authority.
