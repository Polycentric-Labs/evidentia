# Enterprise retention collector design

The shared foundation implements strict requests and full results, trusted profile authorization, bounded JSON, source correspondence, and an owned read session for selected Google Vault, Splunk Enterprise, and Elasticsearch ILM configuration. The namespace currently exports models only. Provider projectors, the full collector, and enterprise API, CLI, and console actions are planned integration work.

This scope observes configuration for explicitly selected resources. It does not discover all resources, read held records, events or documents, test deletion, change policies, establish record-set completeness, or assess legal compliance. Provider account and resource ownership remain unverified. The existing [Entra/M365 collector](entra-m365-collector-design.md) supplies retention-label configuration through its separate delegated credential contract; it is not a fourth enterprise branch.

## Requests and profiles

`EnterpriseRetentionCollectRequest` is a strict provider-discriminated root model. Its wire JSON is the branch object, with required `provider`, `profile_alias`, `scope_label`, and `targets`. A request has 1 through 20 unique targets in input order. Extra fields, scalar coercion, invalid copied/constructed models, duplicate targets, and unsupported selectors reject. Use the bounded bytes parser or explicit model validation; a generic Pydantic `TypeAdapter` is not the authoritative JSON ingress.

| Provider | Selected target and supported ASCII subset |
| --- | --- |
| `google-vault` | `matter_id`: `[A-Za-z0-9_-]{1,128}`. |
| `splunk-enterprise` | `index`: `[A-Za-z0-9_][A-Za-z0-9_-]{0,79}`; reject `_new`, `_reload`, and `_all` without case sensitivity. |
| `elastic-ilm` | `index`: `[a-z0-9.][a-z0-9_.-]{0,254}`; reject `.` and `..`. Select concrete indexes only; no wildcard, alias, data-stream, remote-cluster or all-index expansion. |
| Discovered Elastic policy | `[A-Za-z0-9_.-]{1,255}`; reject `.`, `..`, and case-insensitive `_all`. The name must originate in an admitted raw explain response. |

Aliases and scope labels contain 1 through 64 ASCII characters, beginning with an alphanumeric character and then allowing alphanumerics, underscore, dot and hyphen. These are supported subsets, not complete vendor naming grammars. Labels describe operator selection; they do not authenticate a cloud tenant. Requests contain no origin, credential/reference, header, CA, CIDR, proxy or raised-limit option.

A trusted `ProfileRegistry` contains up to 32 unique profiles. Each profile fixes an alias, provider, HTTPS origin with explicit port, credential reference, address policy, optional detached CA bytes, exact API-principal allowlist, and local CLI grant. Vault's origin is fixed to `https://vault.googleapis.com:443`. Splunk and Elastic origins permit no userinfo, path, query, fragment, ambiguous encoding, trailing-dot hostname or scoped address.

The strict registry file uses `schema_version=enterprise-retention-profiles/v1` and a `profiles` list. Each profile's `address_policy` requires `mode` and a `cidrs` list. `api_principals` defaults to an empty list and `allow_local_cli` to `false`; neither grants access by default. Principal entries are exact nonblank strings, at most 1,024 UTF-8 bytes each and 128 unique values per profile. Matching preserves case, spaces and authenticated suffixes.

`load_profile_registry` reads a named regular JSON file through bounded descriptors, with link/reparse, device/alternate-stream and file-identity checks. An optional CA file is a bounded PEM-only snapshot; relative CA references resolve against the registry parent. Owned clients receive a newly constructed verified SSL context, never a caller-owned mutable context. This boundary trusts the operator's process and configuration; it does not isolate a hostile operating-system user.

`authorize_api_profile` requires an exact allowed principal. `authorize_cli_profile` requires the explicit local grant. Unknown, wrong-provider and unauthorized aliases share the fixed `profile_unavailable` result. These helpers do not replace the future entry points' authentication and read-role checks. API principal authorization does not enable CLI access, and CLI identity or tenant labels are operator assertions. The bundled local-token provider's shared `local-operator` principal cannot distinguish individual token holders.

## Provider permissions and credentials

Local profile permission and provider permission are separate. A provider refusal cannot identify which license, role, scope or resource grant is absent.

| Provider | Credential and permission boundary |
| --- | --- |
| Vault | A preminted Bearer OAuth token with `https://www.googleapis.com/auth/ediscovery.readonly`, applicable Vault licensing and privileges, and access to the selected matter. One universal least-privilege role is not claimed to expose every `FULL_HOLD` field. See [authorization](https://developers.google.com/workspace/vault/auth) and [Vault privileges](https://knowledge.workspace.google.com/admin/vault/set-up-vault-privileges). |
| Splunk Enterprise | A preminted Bearer token for a restricted account able to read the selected index. The `indexes_list_all` requirement depends on instance authorization and all-index listing; it is not a universal requirement for this leaf read. See the [10.4 index endpoint](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.4/introspection-endpoints/introspection-endpoint-descriptions) and [token authentication](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/authenticate-into-the-splunk-platform-with-tokens/use-authentication-tokens). |
| Elasticsearch ILM | A preminted API key constrained by its actual privileges: index `view_index_metadata` for [explain](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-explain-lifecycle), and cluster `read_ilm` for [policy](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-get-lifecycle) and [status](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-get-status). `manage_ilm` is not required by this reader. |

The default resolver reads only the selected `ENTERPRISE_RETENTION_[A-Z0-9_]{1,48}_TOKEN` reference, once per run after destination approval. It performs no login, token acquisition, refresh, SDK credential discovery, JWT identity inference or fallback. Trusted Python integrations may inject the same typed resolver.

Runtime credential material contains 1 through 16,384 printable ASCII bytes without whitespace or a supplied authorization scheme. It is excluded from representations and serialization. An optional aware expiry is checked before use and immediately before send; environment resolution leaves unknown expiry as `None`. Vault and Splunk use `Bearer`; Elastic uses `ApiKey`. A 401 latches credential refusal for the remaining run. A 403 or 404 affects its own read and is never evidence of an absent configuration.

## Six fixed reads

All source operations are GETs. Only HTTP 200 admits a provider source envelope. The API contract below does not assert the connected server's version.

| Read kind | Fixed path and query | Contract and primary reference |
| --- | --- | --- |
| `vault-matter` | `/v1/matters/{matter_id}?view=BASIC` | Vault v1 [matter get](https://developers.google.com/workspace/vault/reference/rest/v1/matters/get). |
| `vault-holds` | `/v1/matters/{matter_id}/holds?view=FULL_HOLD&pageSize=100`, with one encoded `pageToken` only for continuation | Vault v1 [holds list](https://developers.google.com/workspace/vault/reference/rest/v1/matters.holds/list). |
| `splunk-index` | `/services/data/indexes/{index}?output_mode=json&summarize=false` | Documented [Splunk Enterprise 10.4](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.4/introspection-endpoints/introspection-endpoint-descriptions) leaf; no collection pagination. |
| `elastic-explain` | `/{index}/_ilm/explain?only_managed=false&only_errors=false` | Elastic Stack [explain lifecycle](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-explain-lifecycle). |
| `elastic-policy` | `/_ilm/policy/{policy}` | Elastic Stack [get lifecycle](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-get-lifecycle), only after raw relationship admission. |
| `elastic-status` | `/_ilm/status` | Elastic Stack [get status](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-ilm-get-status), once per run. |

Vault discovery revision `20260827` has no retention-rule resource. This limits the implementation to matters and holds; it does not imply that Vault lacks retention rules. Default/custom retention rules and held-record coverage always remain unassessed. The [Vault v1 discovery document](https://vault.googleapis.com/$discovery/rest?version=v1) and [guide](https://developers.google.com/workspace/vault/guides) define the referenced API surface.

Splunk Cloud parity is not established. Elastic targets the documented versioned Stack ILM surface; [Serverless ILM is unsupported](https://www.elastic.co/docs/manage-data/lifecycle/index-lifecycle-management), with no data-stream lifecycle fallback or server-version probe. Extra response identity keys and actual alias expansion reject.

## Finite source selection

The correspondence engine has 33 source roots and 13 selected shapes. Fields retain exact native JSON types and absent/null distinctions. Coverage uses only the declared roots with `absent`, `null`, `known` or `unknown`; interpretation is `known` or `limited`. Missing optional detail and correctly typed future values do not by themselves make enumeration partial. Wrong declared scalar/container types invalidate the whole candidate page.

| Source | Retained fields and shape |
| --- | --- |
| Vault matter | Required exact `matterId`; optional string/null `state`. Known states are `OPEN`, `CLOSED`, `DELETED`; other strings are unknown. Matter name, description, permissions and region are excluded. |
| Vault hold | Required nonblank `holdId`, at most 1,024 UTF-8 bytes; optional string/null `name`, `corpus`, `updateTime`; optional null/list `accounts`, null/object `orgUnit`, and null/object `query`. |
| Splunk entry | Required exact `name`; selected content becomes `datatype`, `disabled`, `frozenTimePeriodInSecs`, `maxTotalDataSizeMB`, `coldToFrozenDirState`, and `coldToFrozenScriptState`. |
| Elastic explain | Required exact string `index` and strict boolean `managed`; optional string/null `policy`, `phase`, `action`, `step`, `failed_step`; five optional nonnegative integer/null millisecond fields; optional object/null `phase_execution`. |
| Elastic current policy | Optional nonnegative integer/null `version`, string/integer/null `modified_date`, and object/null `policy` with selected `phases`. A negative integer `modified_date` remains literal; no conversion is inferred. |
| Elastic service | Optional string/null `operation_mode`; known `RUNNING`, `STOPPING`, `STOPPED`, otherwise unknown. |

A Vault account retains required `accountId` and optional string/null `holdTime`; an organizational unit retains required `orgUnitId` and optional string/null `holdTime`. Account email and personal-name fields are excluded at those declared locations. List order and duplicate accounts remain literal. The documented account/organizational-unit mutual exclusion is an interpretation constraint: contradictory returned scope data is retained with limited interpretation, without inferring a union or a valid scope. See the [hold schema](https://developers.google.com/workspace/vault/reference/rest/v1/matters.holds).

Known Vault query branches are object/null. Drive shared/team-drive flags and the chat room flag are boolean/null; mail/groups time and terms leaves are string/null; Voice covered data is a list of strings or null. Calendar/Gemini and future bounded query content remain literal with appropriate interpretation limits. Exclusions are location-specific. Explicit query, phase and action subtrees are not recursively scrubbed by key name or content.

Splunk `disabled` retains boolean, integer, string, finite float or null. Known values are booleans, integers 0/1, and strings `"0"`/`"1"`; float 0.0 is not coerced. Time/size settings retain integer, string, finite float or null, with known nonnegative integers and ASCII digit strings. Booleans reject. Raw archive paths/scripts are excluded; the derived state is exactly `absent`, `null`, `empty` or `nonempty`, and coverage keeps the original source field names. Time settings do not guarantee minimum retention, and a nonempty archive setting does not prove execution or durability.

The five explain times are `index_creation_date_millis`, `lifecycle_date_millis`, `phase_time_millis`, `action_time_millis`, and `step_time_millis`. Running `phase_execution` retains its policy, nonnegative integer/null version and modified-date milliseconds, and bounded phase definition separately from the current policy. Phase entries may be object or null; `min_age` is string/null and `actions` is object/null, with bounded action subtrees preserved. Outer unselected `_meta` and `in_use_by` are excluded at their declared locations. A running/current policy difference is not by itself an error or retention verdict; see [phase update behavior](https://www.elastic.co/docs/troubleshoot/elasticsearch/index-lifecycle-management-errors). `ERROR` and `STOPPED` can be valid source states.

## Source authority and atomic admission

`EnterpriseReadSession` receives a detached request, an `AuthorizedProfile`, an owned transport factory and injected clocks/sleep/run-ID functions. Construction performs no credential resolution, DNS or socket work. Its initial ledger contains explicit unattempted slots: matter then holds per Vault target, one Splunk leaf per target, or one Elastic status followed by explains in target order. Newly admitted distinct policies append in first-discovery order.

Raw envelope validation precedes the projector. A matter must match `matterId`; each hold occurrence retains its original ordinal and literal ID; Splunk must have exactly one matching entry and an object content field; Elastic must have exactly one requested index/policy key and exact embedded index/managed values. Splunk `ERROR` messages refuse even if a callback omits them; `WARN` and unknown message types produce fixed warnings. Message text is never retained.

The callback receives detached `ParsedResponse` and `ReadSubject` views and returns an immutable `ProjectedPage` of records. It controls no URL, token, clock, counter, credential or finding. Every original occurrence must appear once, in the same order and with the same ordinal, identity, selected native values and coverage. Raw tokens and policy relationships are private session authority. The complete candidate is checked for correspondence, budgets, factory validity and capacity before any observation, duplicate state, token history or policy slot commits. A final monotonic check after candidate validation prevents a late page from committing and preserves earlier evidence.

Vault requires admitted matter identity before holds. An absent or empty holds list can be complete; null is invalid. Absent or empty continuation ends enumeration; nonempty source tokens are opaque bounded query values. Repeated tokens refuse the current page before commit. Identical selected projections coalesce after raw occurrence accounting. Conflicting identities are quarantined and removed, unrelated observations remain, and later occurrences cannot resurrect a quarantined identity. A refused later page preserves earlier facts.

Elastic reads status before explains. Only literal raw `managed=True` with a supported policy name admits a policy key. A false value means `not_applicable`; missing/null/empty/unsupported policy detail is `unresolved`. A known relationship is `resolved` even if its policy GET fails. Status and policy outcomes, including failures, are cached once per run. Immutable `ReadHandle` values expose only `read_id`; foreign, copied or reconstructed handles cannot authorize a follow-up. This is a trusted-callback programming boundary, not isolation from arbitrary interpreter code.

## Destination and transport boundary

Each attempt first applies the existing offline/URL guard, then performs one native hostname resolution. Every raw answer must have a valid family, shape, configured port and unscoped canonical address. Empty, malformed, mixed or disallowed answer sets refuse before credential resolution. The initial lookup uses ASCII hostname bytes to bypass any outer string-host pin; subsequent checks and connection resolution use the approved string-host pin.

Private profiles require canonical CIDRs wholly within `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or `fc00::/7`. Public profiles use an explicit conservative public subset; optional CIDRs must be public across their whole range, not just at endpoints. Public IPv6 lies within `2000::/3` excluding `2001::/23`, `2001:db8::/32`, `2002::/16` and `3fff::/20`. Public IPv4 CIDRs must overlap none of `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4` or `240.0.0.0/4`. Globally reachable exceptions inside excluded ranges are not supported. Mapped/scoped addresses and the explicit metadata addresses `fd00:ec2::254` and `fd20:ce::254` always refuse. This is not an exhaustive metadata-service inventory.

The entire admitted set is pinned around the unchanged public guard, credential resolution and synchronous send. The public guard must return the same set. Private permission never disables the global offline guard. Retries resolve and validate again. Owned HTTP/1 transports disable keepalive, environment proxies, ambient authentication, cookies, automatic retries and redirects. A fresh request carries only fixed headers and the selected authorization. A response hook refuses 3xx before `Location` parsing. Verified CA context applies to the transport itself.

Responses, clients and transports close on every exit. A close failure is recorded separately; already valid source evidence is preserved and later source work stops. Ordinary HTTP/cookie logging uses the reviewed context-local boundary. Arbitrary malicious logging instrumentation in the process is outside the guarantee.

## Exact values, limits and results

JSON rejects duplicate decoded keys, invalid UTF-8, BOMs, unpaired surrogates, nonfinite values, unsupported native objects and lossy numeric tokens. Integers have at most 128 decimal digits excluding sign. Finite float tokens must survive the defined decimal round trip; signed zero is retained. Native integer, float and string types remain distinct. Source timestamps keep their literal offsets and fractions; the conservative calendar recognizer handles seconds 00 through 59. Leap-second strings remain literal unknown detail. No source date conversion, sorting or inferred expiry is performed.

Collection clocks are aware UTC and serialize with exactly six fractional digits and `Z`. `canonical_projection_sha256` hashes compact sorted UTF-8 JSON containing projection version, fixed method ID, native scope, literal source identity and selected fields. It is a logical projection digest, not a hash of an unretained original response. Finding summaries bind ordered projection-digest lists; they do not copy every observation body.

| Boundary | Local limit |
| --- | --- |
| Request or profile JSON | 65,536 raw UTF-8 bytes; up to 20 targets or 32 profiles. |
| Trusted CA snapshot | 1,048,576 bytes, PEM-only. |
| One provider response | 1,048,576 encoded bytes and 1,048,576 decoded bytes. |
| Entire run | 16,777,216 encoded and decoded bytes, independently, including failed attempts. |
| JSON document | Root container depth 1; maximum depth 16 and 10,000 nodes including keys and values. |
| Observations | 65,536 bytes each; 2,097,152 bytes in aggregate. |
| Complete result | 4,194,304 UTF-8 bytes; aggregate validation has separate depth/node accounting. |
| Vault holds | 20 received pages and 2,000 occurrences per run; tokens at most 4,096 UTF-8 bytes. |
| Fan-out and attempts | 20 distinct policies; 100 attempts per run, at most three per logical page/leaf. |
| Deadline and timeouts | 120 monotonic seconds; connect/pool at most 5, read/write at most 20, clipped to fresh remaining time. |

Only HTTP 408/429/500/502/503/504 and the exact transport failures `ConnectTimeout`, `ReadTimeout`, `ConnectError`, and `ReadError` are retryable before complete admission. Delays are 1 then 2 seconds. Supported `Retry-After` values must fit within 10 seconds and the remaining budget; invalid or excessive values end that read. Unsafe destinations, malformed bodies, schema/identity failures, redirects and other 4xx do not retry. DNS, TLS and close work may not be preemptible, so the deadline is an operational budget rather than a hard wall-clock return promise.

`EnterpriseRetentionCollectResult` contains every selected resource, unique source reads, observations, findings, diagnostics, field coverage and a cross-checked manifest. Responses count every status; pages count fully received strict-JSON success envelopes before projection; records count original root occurrences even when a member later fails. Admitted counts describe only surviving committed evidence. Duplicate occurrences and quarantined identity groups have separate counters. Shared reads contribute once to manifest totals.

Complete means exhaustive successful reads for the selected configuration scope. A read with no admitted page is unavailable; retained pages plus unfinished enumeration, conflicts or a terminal fault are partial. A resource requires all its reads and required policy relationship. Overall partial requires selected-target evidence; shared service status alone does not turn an unavailable collection into partial. Unknown optional detail limits interpretation without changing enumeration completeness. Run/cleanup faults prevent complete status. All targets remain represented, including unattempted ones.

The factory creates one informational active finding for each resource with selected-target evidence, with unknown compliance, no resolution date and fresh empty control mappings. `raw_data` contains selected target, read references/digests, coverage and states. It cannot replace the full result. Forty fixed diagnostic codes have finite scope bindings, fixed order and deduplication. A safe HTTP status is retained only when unambiguous; no source error text, arbitrary headers, tokens or private origin enters diagnostics. Final native/JSON validation rechecks identity, relationships, counters, clocks, coverage, digests and finding context. Publication is validated and serialized before the final deadline check. If time expires during that work, the session rebuilds a partial or unavailable result with the fixed deadline diagnostic and the already captured finish time; it does not sample UTC again.

A request-specific `CapacityPlan` reserves all future metadata, including the maximum policy/read/finding slots and terminal diagnostics, before source work. There are at most 20 resources and 20 findings; the unique-read limits are 40 for Vault, 20 for Splunk, and 41 for Elastic (one status, 20 explains and 20 policies). Candidate pages are checked before commit. With 20 longest targets and maximum-length aliases/scopes, measured conservative reservations are:

| Provider | Metadata bytes | Metadata plus maximum observations and placement bytes |
| --- | ---: | ---: |
| Vault | 395,288 | 2,494,460 |
| Splunk | 225,763 | 2,322,935 |
| Elastic | 575,466 | 2,672,659 |

The 2 MiB observation ceiling plus these finite reservations is below the 4 MiB result cap. Synthetic acceptance separately checks an exact 2,097,152-byte observation total, one-byte refusal and internal result test ceilings. It does not invent a reachable production 4 MiB case. Capacity refusal stops new work and preserves a valid full partial/unavailable result with prior facts. The oracle and `publication_bytes()` use compact sorted UTF-8 JSON with `ensure_ascii=False` and `allow_nan=False`; API/CLI byte parity awaits their integration tests.

## Packaging, fixture provenance and remaining integration

The foundation uses existing core, HTTPX, Pydantic and standard-library facilities. Base enterprise imports do not require S3 signing or XML extras. It reuses unchanged bounded storage JSON/body helpers through enterprise limits; it does not reuse the storage run session or alter its retry policy. There is no new dependency, SDK transport or optional enterprise credential chain.

The [fixture source ledger](../../tests/fixtures/enterprise_retention/source-index.json) describes the two authored synthetic source-field corpora and their raw byte hashes. Positive cases and negative mutation recipes are expected data, not provider recordings. Future Vault, Splunk and Elastic leaf fixtures are listed as planned until actually authored and reviewed. Local synthetic tests can establish contract behavior and intercepted transport boundaries; they do not establish live licensing, permissions, tenant identity, TLS interoperability, deployment compatibility or an atomic provider snapshot.

The planned full collector will compose the three provider projectors through this session. Planned API, CLI and console integration must enforce authentication/read role before input work, separate profile authorization, exact request/result binding, sanitized errors and full-result publication. Only exact absence of the collectors package or enterprise feature may count as optional absence; broken internal/transitive imports remain installation failures. These enterprise entry points are not exposed by the model-only foundation. Existing M365 label collection remains documented in the [collector guide](../wiki/2-guides/run-collectors.md) and [Entra/M365 design](entra-m365-collector-design.md), with its nine-capability envelope and label-only `full_surface_complete=False` unchanged.
