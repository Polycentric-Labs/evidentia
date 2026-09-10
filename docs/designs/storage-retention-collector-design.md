# Storage retention collector design

Status: storage milestone implemented for the v0.13 candidate. The Python collector, CLI, API and
console share the bounded request and full result contracts. Acceptance uses authored synthetic
provider responses and local integration tests. Live-provider acceptance remains unverified.

The first milestone observes configuration on explicitly selected S3 general-purpose buckets, Azure
Blob containers with their account and service context, and GCS live buckets. It does not enumerate
accounts, buckets, objects or versions, read object metadata or bodies, test deletion, or change retention,
locks or holds. Later Vault, Splunk and Elastic work remains outside this milestone. The existing
Entra/M365 collector already supplies M365 retention-label configuration evidence.

## Scope and request contract

`StorageRetentionCollectRequest` is a strict provider-discriminated root model. Its JSON is the branch
object, without a `root` wrapper. Each request selects one provider, an operator-defined `scope_label`,
and 1 through 20 targets in input order. Duplicate canonical identities reject before credential access.
The request accepts no credentials, credential-reference names, arbitrary endpoints, object keys,
extra query parameters or increased limits.

| Provider | Target fields | Canonical identity |
| --- | --- | --- |
| `s3` | `bucket`, `region`, optional `expected_owner` | `s3:{region}:{bucket}` |
| `azure` | `subscription_id`, `resource_group`, `account`, `container` | `azure:` plus the lowercase complete ARM container path |
| `gcs` | `bucket` | `gcs:{bucket}` |

Names use the explicit ASCII subsets in the shared contracts. S3 uses the frozen 34-region commercial
allowlist and excludes directory buckets, access-point aliases, IP-form names and reserved forms.
Azure subscription UUID text normalizes to lowercase hyphenated form; accepted resource-group spelling
is preserved while canonical ARM comparison is ASCII case-insensitive. GCS accepts the bounded dotted
name subset, at most 222 characters and at most 63 per component. These are supported input subsets,
not assertions that a caller can create or owns a resource.

`scope_label` is 1 through 64 ASCII characters: an initial alphanumeric followed by alphanumerics,
underscores, periods or hyphens. Whitespace is not stripped. Schema, native validation, JSON validation,
defaults, serialization and copied models must agree on these constraints.

## Fixed methods and field projectors

All methods are GET with an empty body. The common layer constructs URLs from validated targets;
callers cannot replace their host, path, query or cloud partition. Let `A` denote
`/subscriptions/{subscription_id}/resourceGroups/{encoded_resource_group}/providers/Microsoft.Storage/storageAccounts/{account}`.
Azure path segments are encoded once.

| Component, in execution order | Fixed URL | Primary method reference |
| --- | --- | --- |
| `s3-object-lock` | `https://s3.{region}.amazonaws.com/{bucket}?object-lock` | [GetObjectLockConfiguration](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html) |
| `s3-versioning` | `https://s3.{region}.amazonaws.com/{bucket}?versioning` | [GetBucketVersioning](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html) |
| `azure-account` | `https://management.azure.com{A}?api-version=2026-04-01` | [Storage Accounts: Get Properties](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2026-04-01) |
| `azure-blob-service` | `https://management.azure.com{A}/blobServices/default?api-version=2026-04-01` | [Blob Services: Get Service Properties](https://learn.microsoft.com/en-us/rest/api/storagerp/blob-services/get-service-properties?view=rest-storagerp-2026-04-01) |
| `azure-container` | `https://management.azure.com{A}/blobServices/default/containers/{container}?api-version=2026-04-01` | [Blob Containers: Get](https://learn.microsoft.com/en-us/rest/api/storagerp/blob-containers/get?view=rest-storagerp-2026-04-01) |
| `gcs-bucket` | `https://storage.googleapis.com/storage/v1/b/{bucket}?projection=noAcl` | [Buckets: get](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get) |

Regional S3 path-style addressing is an intentional bounded choice. A region mismatch never authorizes
redirect following or a different endpoint. AWS documents the path-style form and its future deprecation
intent; a provider change requires review. [S3 addressing](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html)

Domain projectors select only the approved fields. S3 retains lock enablement, default mode and
native Days or Years, and versioning/MFA-delete state. Azure retains exact source IDs, account HNS and
immutability defaults, service versioning, and container policy/hold/enablement details; user identifiers,
tenant identifiers and update history are excluded. GCS retains exact bucket name, metageneration,
retention policy, versioning and object-retention enablement. Its quoted integer values remain strings.
[Bucket resource](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets)

Missing, explicit null, known absence and unsupported values are distinct. A wrong type, envelope,
identity or duplicate field invalidates the entire component. Structurally valid unknown values or
missing required detail may produce a partial projection with a fixed diagnostic. Domain tests cover
these distinctions separately from credential, transport, collection and application tests.

Only the exact valid S3 XML error `ObjectLockConfigurationNotFoundError` with HTTP 404 on the lock
component can represent absent lock configuration. Other 404 and authorization failures cannot.
An empty successful versioning configuration represents never-enabled versioning; absent MFA-delete
state remains absent. [S3 errors](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html)

S3 XML accepts the documented namespace or no namespace, rejects duplicate known fields, and maps the
wire member `MfaDelete` to the projection member `MFADelete`. Days and Years remain native integers;
they are never converted into each other. Nonpositive durations and unknown mode/state values retain
their literal value in partial evidence. A default rule with both duration units rejects.

Azure validates each response's full ARM identity against the selected account, default blob service
or container. Account defaults, service versioning and container policy/hold observations remain
separate. HNS or disabled service versioning does not erase a container policy. Current legal-hold
tags and append-write flags are retained; user, tenant and update-history metadata is excluded.
Conflicting policy/hold detail produces partial evidence without inferring effective object protection.

GCS validates the exact selected bucket name and retains quoted metageneration and retentionPeriod
values as strings, including leading zeroes. Omitted optional configuration stays omitted. Present
objects with missing or null required detail are partial. Valid source timestamp strings retain their
offsets and fractional spelling; unsupported detail is never replaced with an invented default.

## Shared module responsibilities

The public module directory is `evidentia_collectors.retention`. Shared boundaries live in
`_contracts.py`, `_parsing.py`, `_credentials.py`, `_aws_signing.py` and `_client.py`; `aws.py`,
`azure.py` and `gcs.py` implement the field projectors. `StorageRetentionCollector.collect_v2` runs
the finite plan and returns the full result. Its compatibility `collect` method returns findings only.
Each run owns a fresh read session; closure and final budget checks precede result admission.

`StorageReadSession` freezes a validated request as bytes and derives the finite target/component plan.
Its request property returns a new validated model. Reads must follow that plan exactly. A selected target
is detached from the caller before retries, and a separate validated target is supplied to the projector.
Caller or projector mutation cannot retarget a later request.

The callback interface is `ComponentProjector(ComponentResponse, StorageTarget) -> ProjectedComponent`.
`ComponentResponse` contains the component ID, safe status, bounded parsed body and optional transport
ETag. A projector returns selected fields, API version, native scope and allowed source-detail diagnostics.
It cannot provide attempt counts, clocks, manifests, findings or a completion verdict.

`ProjectedComponent` stores canonical bytes and returns detached fields. The factory validates its type,
contents and size before admission, computes the projection digest, and revalidates copied or constructed
models before serialization. Admission is atomic: malformed candidate evidence cannot leave part of that
component in the result. Previously admitted components remain available.

## Credentials, signing and send ordering

Only the selected provider's fixed references are read: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`
and optional `AWS_SESSION_TOKEN`; `STORAGE_RETENTION_AZURE_ACCESS_TOKEN`; or
`STORAGE_RETENTION_GCS_ACCESS_TOKEN`. Trusted Python callers may inject the typed credential provider.
HTTP request data cannot select it. There is no default SDK chain, profile/file lookup, OAuth acquisition,
STS/SSO discovery, identity inference or refresh.

Credential resolution is lazy and at most once per run, after request validation and the first generated
URL/offline/public-address checks. Credential objects are detached, immutable and redacted in repr.
Access/secret values are limited to 2048 printable ASCII characters without whitespace; bearer/session
tokens to 16384. A supplied expiry is normalized to UTC; null means unknown. Material and expiry are
rechecked for each attempt, including after slow client construction or signing.

The S3 adapter accepts only the same two fixed GET routes and frozen region list. It requires botocore
1.43.89 in both distribution metadata and the imported module. A mismatch yields `signing_unsupported`.
Each attempt creates fresh explicit SDK credentials, request, signing timestamp and `S3SigV4Auth` object.
The reviewed helper sequence delegates request preparation, canonicalization, string-to-sign, signature
and header injection to botocore without calling its logging `add_auth` orchestration. It does not copy
cryptographic algorithms or use an SDK endpoint client for transport.
[Signature Version 4 process](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html)

The exact botocore boundary is deliberate because the orchestration uses private SDK helpers. Any version
change requires helper-source review, normal SDK request parity and DEBUG record-factory/filter/handler
checks. The retention extra uses botocore==1.43.89 and defusedxml>=0.7.1. Missing top-level optional dependencies remain distinct from broken transitive imports.

For every attempt, the common layer checks generated URL bytes, GET, empty body, Host and preserved
signed headers. It calls `network_guard.check_url`, `enforce_public_host` and same-thread
`pin_resolved_host`, including for injected synthetic transports. The default owned HTTPTransport keeps TLS verification enabled. The client uses HTTP/1.1,
no environment proxy inheritance, no automatic retries and no redirect following. Caller clients,
auth, hooks, cookies and trace extensions are not accepted. Fresh requests avoid ambient client state.

Immediately before send, the initial observation-clock callback runs, credentials and expiry are
revalidated, and the monotonic budget is recomputed. Connect/pool timeouts are at most 5 seconds and
read/write timeouts at most 20 seconds, each capped by the remaining budget. Expiry or exhausted time at
that point causes no additional attempt or outbound request.

The sole response hook belongs to the session. It records safe status, wraps response closure, rejects
every 3xx before HTTPX processes Location into a redirect request, and latches 401 credential rejection.
The hook is removed and cookies are cleared in cleanup. HTTPX documents that response hooks run before
body-reading decisions; the earlier-than-redirect boundary is separately covered by local malformed-Location
regressions. [HTTPX response hooks](https://www.python-httpx.org/advanced/event-hooks/)

ETag metadata is optional. If present, exactly one header field is accepted, preserved literally, and
checked for nonempty ASCII text without control characters and a 1024-character limit. Multiple ETag
fields reject, including identical duplicates; they are not joined into invented metadata. This is a
bounded transport metadata check, not a complete entity-tag grammar check. Source-body metadata remains
subject to its domain projector. Independent Azure reads and their ETags do not form an atomic snapshot.

## Bounds, parsing, retry and cleanup

| Boundary | Fixed ceiling |
| --- | --- |
| Raw request | 65536 bytes |
| Each response body | 1048576 raw bytes and 1048576 decoded bytes |
| Entire run, including retry/failure bytes read | 16777216 raw bytes and 16777216 decoded bytes |
| One canonical projection, excluding its digest field | 16384 bytes |
| Aggregate canonical projections | 1048576 bytes |
| Final serialized result | 4194304 bytes |
| Operational run budget | 120 seconds |
| Attempts per component | 3 |
| JSON containers/nodes | Depth 32; 10000 nodes, counting keys and values |
| XML elements | Depth 16; 10000 elements |

Raw and decoded counts are charged before chunks are retained. Only identity encoding or one bounded
gzip member is accepted. Unsupported/stacked encodings, concatenated/trailing members, truncation and
over-expansion reject. A redirect or 401 is refused before body reading; counts describe bytes actually
read, not an assumed full response length. A run can record the offending bytes that caused a refusal.

JSON requires native UTF-8 bytes without a BOM. A grammar scan bounds depth/nodes before decoder tree
allocation. Duplicate decoded keys, nonfinite numbers and unpaired surrogates reject. Integers preserve
exact value and native type up to 128 decimal digits excluding sign. Float tokens must satisfy
`Decimal(original_token) == Decimal(str(parsed_float))`; 0.1 and signed zero pass, while precision loss,
nonzero underflow and excessive exponents reject. Native finite floats remain authoritative. This preserves
logical values and integer/float identity, not original token spelling. Request and projection models enforce
their object shapes separately. GCS quoted integers are not converted to float.

Canonical JSON uses sorted keys, compact separators, UTF-8, `ensure_ascii=False` and `allow_nan=False`.
The native-tree validator rejects subclasses, cycles and coercible non-JSON values and returns detached
copies. The common canonical helper's ceiling is 1 MiB; the full result has its separate 4 MiB limit.

XML supports UTF-8 only, with an optional UTF-8 BOM. Other declared encodings and UTF-16/32 reject;
original bytes are not transcoded. A namespace-disabled defusedxml SAX pass counts prospective expanded
names using scoped URI lengths before the namespace-aware tree parser runs. Retained expanded names,
attribute values and text together are limited to 1 MiB. Both passes forbid DTDs, entities and external
references. ElementTree handles normal XML text and attribute normalization; the parser performs no
permissive boolean/integer coercion. The checks bound input, structure and logical content, not total
process memory. defusedxml is imported only on the XML path.

Retry is limited to HTTP 408/429/500/502/503/504 and connect/read timeouts. Default waits are 1 then
2 seconds. Retry-After accepts bounded delta seconds and the three HTTP-date forms, at most 30 seconds
and within the remaining run budget. Malformed metadata rejects; a valid excessive wait ends the run
without retrying early. Invalid payloads, identities, destinations, redirects and other 4xx do not retry.
A 401 stops later credential use. The exact reviewed S3 token-rejection code/status pairs also latch;
resource-specific 403/404 do not invalidate unrelated targets.

The session checks time around guards, resolution, signing, sends, reads, waits and projection admission.
Synchronous DNS, provider callbacks and OS cleanup are not necessarily preemptible; 120 seconds is an
operational budget, not a guaranteed wall-clock cutoff. Response and owned client closure run on success
and failure. Cleanup failure preserves admitted evidence while preventing a complete result.

Ordinary HTTPX/httpcore/cookie logs are suppressed within the operation's context across send/read/close,
while other-thread logs remain available. The code changes no global logger level or method and installs
no signing logger filter. This does not isolate credentials from arbitrary instrumentation already running
inside the process. Diagnostics use closed codes and safe HTTP status, never source error text or repr.

## Evidence and completion semantics

Every result uses `storage-retention-collection/v1` and declares `observation_scope=configuration`,
`coverage_scope=selected_resources`, `identity_basis=operator-declared`, and literal false for
`object_enforcement_assessed`, `recordset_completeness_assessed` and `authenticated_identity_verified`.
Numeric zero is not accepted in place of those booleans. `expected_owner` is a signed expectation, not an
independent identity discovery. Deployment IAM and authenticated application authorization remain
responsible for access; a scope label or resource ID is not an ownership or tenant-isolation claim.

Collection clocks serialize in UTC with exactly six fractional digits. Source timestamp strings remain
literal in selected fields. A projection records API/projection versions, native scope, selected fields,
optional ETag/metageneration and a factory-created canonical SHA256. The digest binds that logical
projection; it is not a hash of a full provider response or proof of a simultaneous observation.

| Status | Component | Resource and overall result |
| --- | --- | --- |
| `complete` | Admitted projection, no diagnostic | Every required component/resource complete; no terminal run diagnostic |
| `partial` | Admitted projection with an allowed diagnostic | Some admitted evidence and at least one incomplete part or terminal diagnostic |
| `unavailable` | No admitted projection; fixed diagnostic required | No admitted evidence |

All requested targets remain present, including those not attempted after refusal or budget exhaustion.
Attempted components have bounded counters and an observation interval; unattempted components have
zero counters and null clocks/status/projection. The factory checks exact target/component order,
identities, counts, status and digest consistency, including constructed/copied evidence.

One informational active `SecurityFinding` is created per resource with admitted evidence. Its
compliance status is unknown, `resolved_at` is null and control mappings are empty. IDs depend on the
provider/resource/kind, not observation time or scope label. CollectionContext contains nonempty selected
filters, `credential_identity=operator-configured:identity-unverified` and null pagination context.
The manifest derives requested/attempted resources, planned/attempted/completed components and finding
counts. Serialization treats warnings as errors and returns a detached revalidated result.

## Application boundaries

`evidentia collect retention --request-file request.json --output result.json` reads a named regular
JSON file after the configured read-role check. Omitting `--output` writes the full result to stdout.
Stdin, reparse/symlink paths, multiple hard links and request/output aliases are refused. A unique sibling
file is reserved before collection; serialization, readback and destination checks precede atomic
replacement. An editor may replace the request file after it was read, but the original parsed selection
still binds the result and the current request path cannot become the output. These checks do not claim
protection from a hostile filesystem change between the final check and replacement.

The CLI exits 0 for complete evidence, 1 for partial/unavailable evidence or collection/output failure,
2 for invalid input and 77 for role denial. Partial and unavailable results retain all requested
resources and diagnostics in the JSON output. Missing S3 support is distinguished from a broken
transitive import using the originally selected provider, even if a collector mutates its input.

`POST /api/collectors/retention/collect` requires configured API authentication and read RBAC before
reading the request body. It accepts JSON within the actual streamed 65536-byte ceiling; a Content-Length
header cannot authorize more bytes. It returns the full result with HTTP 200 for every valid collection
status, 400 for invalid input, 413 for excess bytes, 415 for unsupported media, 503 for absent optional
support and sanitized 500 errors for invalid results or unexpected failures. Provider work runs in the
worker thread pool. Result provider, scope label and ordered targets must match a detached request
snapshot after the collector closes.

The Collect page's Storage retention tab validates the same input subsets, rechecks authentication,
and shows resource/component status, safe diagnostics, counts and source limits. Native source fields
and the full JSON download retain the API response text, avoiding JavaScript number rounding in evidence
exports. Structured browser summaries are not a replacement for Python result and digest validation.
Demo mode is explicitly synthetic and never calls a provider. The status endpoint reports configuration
presence separately from live acceptance and authenticated identity, both of which remain false.

## Fixture provenance and acceptance limits

The [source ledger](../../tests/fixtures/retention/source-index.json) indexes 24 authored synthetic HTTP
response fixtures, eight per provider, with hashes of their actual bytes and the six primary method
references. No file is labeled a recorded provider response. Inline test scenarios cover additional
malformed, conflicting, missing, unauthorized and interrupted responses. Separate console fixtures are
full synthetic collection results, not provider recordings.

Local acceptance exercises the real parsing, guarding, projection, collection and application paths
through injected transports without cloud calls. Neither documentation review nor local tests establish
live-provider fidelity, tenant acceptance, credential identity, legal retention sufficiency or object
enforcement. Existing WORM and retention-metadata execution remains unchanged. A locked or enabled
configuration remains an observation with unknown compliance status. Vault, Splunk and Elastic
remain subsequent V13-04 work. M365 label configuration is supplied by the Entra/M365 collector;
label application and item enforcement remain unassessed.
