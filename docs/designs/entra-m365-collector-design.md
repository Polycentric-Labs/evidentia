# Entra ID and Microsoft 365 evidence collector

This design defines bounded identity, device, retention, DLP configuration, and Defender event evidence. Typed contracts, a Graph reader, admission accounting, authored mappings, and fixture provenance form the shared foundation. Domain readers and the public collector, CLI, API, and console entry points remain planned until integration. The runtime behavior below is their integration contract.

The collector reads eight commercial Microsoft Graph v1.0 collections and one supplied DLP export. It uses the existing HTTP client, network guard, findings, collection context, and manifest models. Token acquisition or refresh, a Microsoft SDK, PowerShell execution, new persistence, and automatic evidence-store or signer writes are outside this design.

Results always contain these nine capabilities in this order. Graph requests use GET at `https://graph.microsoft.com` and exactly the relative routes shown. Only the selected fields are retained.

| Capability | Route or input | Exact retained fields | Evidence boundary |
| --- | --- | --- | --- |
| [conditional-access](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0) | `/v1.0/identity/conditionalAccess/policies` | `id`, `state`, `conditions`, `grantControls`, `sessionControls` | Policy configuration, including disabled and report-only states; effective MFA and resolved identity/application coverage are not established. |
| [authentication-registration](https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0) | `/v1.0/reports/authenticationMethods/userRegistrationDetails` | `id`, `isMfaRegistered`, `isMfaCapable`, `methodsRegistered`, `lastUpdatedDateTime` | Registration and capability counts over observed records. The method excludes disabled users. |
| [sign-ins](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0) | `/v1.0/auditLogs/signIns` | `id`, `createdDateTime`, `conditionalAccessStatus`, `authenticationRequirement`, `status.errorCode`, `appliedConditionalAccessPolicies` | In-window events within source availability. Missing/null applied-policy detail makes the capability partial; authenticationRequirement has the v1.0 limitation below. |
| [directory-roles](https://learn.microsoft.com/en-us/graph/api/directoryrole-list?view=graph-rest-1.0) | `/v1.0/directoryRoles` | `id`, `roleTemplateId`, `displayName` | Activated roles only, without assignments, membership, or PIM eligibility. One page; continuation is invalid. |
| [managed-devices](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0) | `/v1.0/deviceManagement/managedDevices` | `id`, `complianceState`, `managementState`, `lastSyncDateTime` | Observed Intune device states; neither an Evidentia compliance verdict nor proof of complete enrollment. |
| [retention-labels](https://learn.microsoft.com/en-us/graph/api/security-labelsroot-list-retentionlabel?view=graph-rest-1.0) | `/v1.0/security/labels/retentionLabels` | `id`, `displayName`, `retentionTrigger`, `retentionDuration`, `behaviorDuringRetentionPeriod`, `actionAfterRetentionPeriod` | Label configuration, without item-application, record-set scope, or immutability claims. |
| dlp-export | Supplied evidentia-dlp-v1 or explicitly selected scubagear-provider-v1 JSON | Seven policy and seven rule fields defined below | Exported configuration; no Graph call or PowerShell execution. |
| [defender-alerts](https://learn.microsoft.com/en-us/graph/api/security-list-alerts_v2?view=graph-rest-1.0) | `/v1.0/security/alerts_v2` | `id`, `incidentId`, `severity`, `status`, `createdDateTime`, `lastUpdateDateTime`, `resolvedDateTime`, `serviceSource`, `detectionSource` | Available alert metadata; protection deployment and response completion are not established. |
| [defender-incidents](https://learn.microsoft.com/en-us/graph/api/security-list-incidents?view=graph-rest-1.0) | `/v1.0/security/incidents` | `id`, `severity`, `status`, `createdDateTime`, `lastUpdateDateTime` | Available incident metadata, distinct from alerts and protection configuration. |

All eight methods support delegated work or school accounts. Seven also support application access; retention labels require delegated access. Personal Microsoft accounts are unsupported. Permissions and delegated-user roles are separate requirements. The linked list methods supply the access facts below.

| Capability | Least-privileged Graph permission | Delegated-user qualification |
| --- | --- | --- |
| Conditional Access | Policy.Read.All | When acting on another user: Global Secure Access Administrator, Security Reader, or Security Administrator for standard properties; Global Reader and Conditional Access Administrator are also listed. A supported custom role is an alternative. |
| Authentication registration | AuditLog.Read.All | Reports Reader, Security Reader, Security Administrator, or Global Reader; or a supported custom role. |
| Sign-ins | AuditLog.Read.All | Global Reader, Reports Reader, Security Administrator, Security Operator, or Security Reader; or a supported custom role. |
| Directory roles | RoleManagement.Read.Directory | A role from the method's supported list, which includes Directory Readers and User, or a custom role granting the operation. |
| Managed devices | DeviceManagementManagedDevices.Read.All | The list-method page names no delegated role; service RBAC may still apply. |
| Retention labels | RecordsManagement.Read.All, delegated only | The list-method page names no delegated role; service RBAC may still apply. |
| Defender alerts | SecurityAlert.Read.All | Security Reader, Global Reader, Security Operator, or Security Administrator; or a supported custom role. |
| Defender incidents | SecurityIncident.Read.All | Security Reader, Global Reader, Security Operator, or Security Administrator; or a supported custom role. |

Higher-privileged alternatives documented by the methods are not needed by this read design. Directory roles also accepts RoleManagement.ReadWrite.Directory, Directory.Read.All, or Directory.ReadWrite.All; device, retention, alert, and incident methods list their corresponding read/write permissions. Applied Conditional Access details in sign-ins additionally require Policy.Read.All, Policy.Read.ConditionalAccess, or Policy.ReadWrite.ConditionalAccess. A delegated user also needs Global Reader, Security Administrator, Security Reader, or Conditional Access Administrator for that detail. An omitted property remains unavailable detail. [Sign-in permissions](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0#permissions)

Conditional Access feature use requires Entra ID P1; Microsoft 365 Business Premium also provides access. Risk-based policies require Entra ID Protection/P2, and integrated services have their own licensing. These are feature prerequisites, not an inferred authorization test for a GET. [Conditional Access licensing](https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview#license-requirements)

Authentication Methods Activity requires P1 or P2 for Usage and insights. Its broader role list differs from the registration method's table, and its reports exclude disabled and recently soft-deleted users and can lag changes. The aggregate denominator is observed records. Unspecified group wording in the method is not used to infer tenant-wide authority. [Authentication Methods Activity](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity#permissions-and-licenses)

Downloading sign-in logs through Graph requires P1 or P2 and remains subject to source retention. The method describes interactive and successful federated sign-ins; it does not justify a claim of every sign-in type or complete requested-window history. [Sign-in resource](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0)

Intune Graph access requires an active Intune tenant license. Directory-role, retention-label, and Defender list-method pages do not state a universal license SKU; service licensing or RBAC can still restrict access. Sentinel events require onboarding to the Defender portal. Token presence, a successful response, or an unexplained 403 cannot precisely establish or diagnose permission, role, or license entitlement. [Intune requirements](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0), [Defender source availability](https://learn.microsoft.com/en-us/graph/api/resources/security-alert?view=graph-rest-1.0)

Identity is operator-declared. tenant_label is a nonsecret alias matching `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`, without trimming; it is not a verified Microsoft tenant ID. The seven primary Graph capabilities use ENTRA_M365_ACCESS_TOKEN. Only retention uses ENTRA_M365_RETENTION_ACCESS_TOKEN. ENTRA_M365_AUTH_MODE declares application or delegated for the primary token, defaulting to application. Retention is declared delegated; DLP has no auth mode. Tokens are neither decoded to infer identity nor logged. CollectionContext uses `entra-m365:operator-label:<tenant_label>` as source_system_id and the same unverified credential basis reported by the capability.

Configuration is resolved only for requested capabilities. DLP-only needs neither token; retention-only does not resolve primary configuration. Empty or invalid primary mode produces configuration_invalid without fallback. An unavailable primary capability refused before configuration resolution can retain null mode with a fixed guard, budget, configuration, or internal diagnostic. Complete/partial primary observations require a known mode, and a known 401/403 cannot claim unresolved mode. A primary-token 401 suppresses later reuse; a 403 leaves unrelated capabilities eligible. Retention never falls back to the primary token.

The planned request has exactly these fields. Duplicate/unknown keys and invalid types fail before credential lookup or collection. Numeric booleans, strings, coercion, and format guessing are rejected.

| Field | Contract |
| --- | --- |
| `tenant_label` | Required alias defined above. |
| `capabilities` | Defaults to all nine; otherwise a nonempty array of distinct exact names, executed in canonical order. |
| `lookback_days` | Strict integer 1 through 30, default 30, for sign-ins, alerts, and incidents. |
| `max_items` | Strict integer 1 through 10,000, default 10,000, per capability; DLP policies and rules share it. |
| `max_pages` | Strict integer 1 through 100, default 100; directory roles and DLP remain one page. |
| `dlp_content` | Optional UTF-8 JSON text, at most 4,194,304 encoded bytes, only when DLP is requested; never a URL or server path. |
| `dlp_format` | evidentia-dlp-v1 by default or explicit scubagear-provider-v1. An explicitly supplied format requires content. |

First-page parameters are empty except for sign-ins, which sends only a createdDateTime ge START and createdDateTime le END $filter. END is the captured UTC run start; START is END minus lookback_days. That same inclusive window filters all three event capabilities locally. Alerts and incidents are enumerated within the configured bounds. The design adds no $select, $top, $orderby, expansion, delta query, batch request, per-resource subrequest, alternate version, or cloud selector.

IDs and nullable foreign IDs are literal nonblank strings of at most 512 code points. Other strings have a 2,048-code-point limit; scalar enums have 128. Each projected record is limited to 16 JSON nesting levels and 32,768 UTF-8 JSON bytes. Policy objects and retentionDuration are nullable objects; methodsRegistered is a nullable string array; appliedConditionalAccessPolicies is a nullable object array. Registration flags are nullable strict booleans. status is nullable, but a present status.errorCode must be a non-null strict integer. Missing, null, false, and zero remain distinct. Invalid selected shapes or bounds invalidate the entire page without truncation.

Enum membership is exact and case-sensitive. Unknown bounded literals survive; unknown and unknownFutureValue count as unknown. methodsRegistered is an open string collection. An unknown enum alone does not imply incomplete enumeration. Three source distinctions matter:

- signIn.authenticationRequirement is absent from the v1.0 resource and reviewed v1.0 metadata. It remains optional, with no known-value set; any observed string is unknown. This design cannot promise v1.0 authentication-stage evidence and makes no beta request. [Sign-in definition](https://learn.microsoft.com/en-us/graph/api/resources/signin?view=graph-rest-1.0)
- managedDevice.managementState appears in v1.0 metadata and its list example despite omission from the resource property table. It remains managementState. [Management-state enum](https://learn.microsoft.com/en-us/graph/api/resources/intune-devices-managementstate?view=graph-rest-1.0)
- actionAfterRetentionPeriod=relabel and serviceSource=microsoftInsiderRiskManagement are known in the reviewed v1.0 metadata beyond their documentation tables. They are metadata-backed additions, with no route/header expansion. [Pinned Microsoft metadata](https://raw.githubusercontent.com/microsoftgraph/msgraph-metadata/0d13ff1c5e4c8e5e3acc8200de615dfb36233395/schemas/v1.0-Prod.csdl), [retention definition](https://learn.microsoft.com/en-us/graph/api/resources/security-retentionlabel?view=graph-rest-1.0), [security enums](https://learn.microsoft.com/en-us/graph/api/resources/enums-security?view=graph-rest-1.0#servicesource-values)

Some detectionSource and incidentStatus members require Prefer: include-unknown-enum-members for delivery. This design adds no such header. A known-value table does not promise delivery, and a returned unknownFutureValue stays unknown. [Detection-source delivery](https://learn.microsoft.com/en-us/graph/api/resources/security-detectionsource?view=graph-rest-1.0), [incident status](https://learn.microsoft.com/en-us/graph/api/resources/security-incident?view=graph-rest-1.0#incidentstatus-values)

Pages are strict UTF-8 JSON objects with required value arrays. Duplicate keys, non-JSON constants, nonfinite numbers, and excessive depth are invalid even in discarded fields. Integer tokens have an explicit 4,300-digit bound independent of the process integer-string setting. Selected integers have absolute value at most 9,007,199,254,740,991; selected float tokens must round-trip through JSON without changing their decimal value.

Exact source timestamps use the ASCII profile `YYYY-MM-DD[Tt]HH:MM:SS[.DIGITS]([Zz]|[+-]HH:MM)`, bounded to 2,048 characters. Calendar years are 0001 through 9999, seconds 00 through 59, and offset hours/minutes at most 23/59. Numeric epochs, naive values, whitespace, leap seconds, invalid calendars, and UTC underflow/overflow are rejected. Literal spelling, every fractional digit, and trailing zeroes remain in selected source data. UTC normalization and comparisons preserve that precision without float, datetime-fraction, or JavaScript Date rounding. Collection-clock boundaries have six fractional digits; query and returned requested-window text agree.

Observed extrema are exact nullable UTC strings over final admitted, unique, unconflicted, in-window events. They are both null for empty sets and non-event capabilities. Equal instants retain the longest supplied precision independently of response order. Older records remain scanned but outside matched_filter; future events are excluded with a warning. Optional update, sync, resolution, and export timestamps use the same parser. Source ages are exact nonnegative decimal strings; future values have null age. No arbitrary stale-device or MFA-risk threshold is added.

Core resolved_at is populated only when source precision is exactly representable at microsecond resolution. Otherwise it remains null with timestamp_precision_unrepresentable and the exact source value retained. This warning does not make enumeration partial or change a source-reported resolved status. Core first_observed and last_observed use the collection clock. API and UI retain exact source strings.

These are Evidentia limits, not Microsoft service guarantees:

| Boundary | Limit |
| --- | --- |
| Execution | Serial GET; at most three attempts per page. |
| Client timeout | Connect/pool 5 seconds and read/write 20 seconds, reduced to remaining elapsed time. |
| Elapsed time | 60 seconds per capability, 300 seconds per run, checked before requests, chunks, and sleeps. |
| Page body | 4,194,304 raw bytes and 4,194,304 decoded bytes; JSON depth 32; at most 10,000 value records. |
| Aggregate responses | 33,554,432 decoded bytes per capability and 134,217,728 per run, including consumed failed/retried bodies. |
| Admitted records | 40,000 per run, plus the per-capability request cap. Quarantined identities retain slots. |
| URL | 16,384 UTF-8 bytes; exact registered HTTPS origin, port, path, and version. |
| Retry sleep | 1 then 2 seconds without Retry-After; a valid server delay must be at most 10 seconds and within both elapsed budgets. |

An in-flight blocking read can finish after its elapsed budget by at most its previously assigned timeout; this is not a hard interruption guarantee. Retry only connection/timeouts and HTTP 429, 500, 502, 503, or 504. Invalid/excessive Retry-After, other 4xx, unsafe destinations, source errors, and size limits stop that read. Past valid HTTP dates mean zero delay. Fixed codes and numeric HTTP status replace raw transport errors or bodies; cancellation never becomes success.

Destination checks precede credential attachment, including with injected clients. Production uses public-address validation and DNS pinning, disables environment proxies and HTTP/2, and refuses redirects per request. Continuations must preserve the registered endpoint. Unsafe authority syntax, control characters, backslashes, malformed escapes, encoded authority/path delimiters, normalization tricks, and excluded operation selectors are refused. Accepted opaque query values, including encoded values such as %26, remain unchanged, with no first-page parameter merge. Repeated/alternating URL loops stop before another request. Missing/null nextLink is terminal; empty/non-string nextLink is invalid.

Absent/identity encoding or one bounded gzip stream is accepted. Stacked/unsupported encodings, trailing gzip data, and concatenated members are rejected, with decoded bounds enforced during decompression. Responses and owned clients close on every path; caller-owned clients remain open. Transport log suppression stays local and does not disable audit events.

Admission validates the entire page and continuation before changing records, slots, conflicts, or diagnostics. Rejected pages retain only actual attempt/byte accounting. Exact projected repeats coalesce and increment duplicate_records. A new conflicting variant quarantines every occurrence of that identity, records one conflict, and makes the capability partial. Repeated known variants still count as duplicates; no variant restores an identity or its slot. Discarded fields do not create conflicts. Even at the item cap, the remaining validated page is checked for conflicts affecting already admitted identities.

A terminal page ending exactly at the cap may complete. Unadmitted records or continuation at a page/item cap stop enumeration as partial. Further attempts/admission are refused after a terminal or stopping condition. Unresolved continuation cannot yield complete state. Final counters, filtering, future/detail diagnostics, and extrema use surviving identities; failed final validation cannot mutate derived counts. Owned snapshots detach requests, records, and capability data from caller mutation.

DLP input has exactly schema_version, source, policies, and rules. schema_version is integer 1. Both arrays are required and may be empty, with at most 10,000 records each before combined admission limits. source has exactly kind, producer, producer_version, captured_at, parent_sha256, source_uri, and sanitization. Kind is operator-export, recorded-provider-projection, or authored-synthetic; sanitization is operator-declared, publisher-attested, or synthetic. These are supplied provenance statements, not authenticated attestations; source_uri is never fetched.

| DLP record | Exact required fields and types |
| --- | --- |
| Policy | Guid and Name: nonblank strings up to 512; Mode, DistributionStatus, Workload: strings up to 128 or null; Enabled and IsValid: strict booleans or null. |
| Rule | Guid: nonblank string up to 512; Policy and ParentPolicyName: nonblank strings up to 512 or null; Mode and Workload: strings up to 128 or null; Disabled and IsValid: strict booleans or null. |

The explicit ScubaGear adapter reads only dlp_compliance_policies and dlp_compliance_rules, selects these fields, and computes the raw input parent hash. It does not use dlp_policies, detect formats, execute provider text, or promise every ScubaGear release is compatible. Missing selected keys or wrong types are input errors before any Graph request. Structurally valid repeated identities remain available for coalescing/quarantine.

Policy/rule identities stay distinct even with equal Guid strings. Admission processes policies before rules. A non-null rule.Policy joins only a surviving policy.Guid; a present ParentPolicyName must agree with that same policy.Name. Missing, unmatched, quarantined, or disagreeing references remain unresolved and make DLP partial. Name, Id, or Identity is never an alternate join. Unadmitted rules cannot enter findings.

A policy is disabled for Disable with Enabled=false, test for TestWithNotifications or TestWithoutNotifications with Enabled=true, or configured_enforce for Enable with Enabled=true. Contradictory known flags and false/null IsValid produce unknown state and partial evidence. A new vendor mode remains unknown. Rule configured_enforce requires an enforcing resolved parent, Mode=Enforce, Disabled=false, and IsValid=true. Disabled=true and disabled/test parents retain their limitations. DistributionStatus stays separate: Pending remains pending, including configured_enforce policies. These classifications do not establish applied protection, content matching, workload completeness, or compliance.

The result contains schema_version entra-m365-collection/v1, status, requested_capabilities, full_surface_complete, provenance, findings, manifest, and all nine capability records. Provenance has exactly tenant_label, identity_basis=operator-declared, authenticated_identity_verified=false, and graph_cloud=commercial. No constant release-test/live-tenant claim appears in runtime output. Credential basis is unverified:primary-token, unverified:retention-token, unverified:dlp-export, or null for not-requested capabilities.

| Capability state | Meaning |
| --- | --- |
| complete | Requested enumeration and mandatory evidence finished within bounds, including a successful empty page/export. |
| partial | An accepted page/export exists, but enumeration, a limit, mandatory detail, or interpretation/join requirements failed. |
| unavailable | No accepted page or usable export exists, including budget refusal before start. |
| not_requested | Omitted by the caller; no read occurred. |

Each capability has name, state, credential_basis, declared_auth_mode, scanned, matched_filter, collected, duplicate_records, pages_completed, requests_attempted, started_at, finished_at, requested_window_start, requested_window_end, observed_first, observed_last, field_coverage, and diagnostics. Counts are strict nonnegative integers. Unstarted timestamps are null; requested event windows remain present even when unavailable, and non-event windows are null. Diagnostics use unique code/status pairs and positive aggregated counts. Future timestamps, unrepresentable core timestamp precision, and source retention are warnings compatible with complete enumeration; internal failure is not.

scanned counts validated records on accepted pages before filtering/deduplication; matched_filter counts final unique unconflicted in-scope records; collected counts findings. Field coverage distinguishes absent, null, known, and unknown. Each Graph field sums to matched_filter. DLP uses `policies.<field>` and `rules.<field>`, with separate kind denominators; the policies.Guid and rules.Guid denominators sum to matched_filter. Policy-only fields are not absent on rules. Rejected pages add no record counts.

The shared factory owns selected records in `raw_data.source`. Domain interpretation belongs in `raw_data.observation`. Registration emits observation only: independent registered/capable counts, method counts, and the observed denominator. Other findings use admitted records. All findings share one run ID and stable identities derived from source_system entra-m365 and source_finding_id `<tenant_label>:<suffix>`; the window and run ID do not alter that identity.

Result JSON revalidation checks finding cardinality, DLP policy-specific coverage, exact source event extrema, and raw nested collection-clock precision before core parsing can round it. Each final in-scope Graph record outside registration requires one finding; nonempty registration requires one aggregate. Every admitted DLP policy requires its own policy finding, so an unresolved rule cannot substitute for policy coverage. Static metadata, mappings, scope, credential basis, and counters are rechecked. Literal source keys survive without core whitespace normalization; findings and mappings remain detached across issuance, completion, and result construction.

These NIST 800-53 Rev 5 mappings are authored evidence relationships. Every row is intersects-with except the unresolved DLP rule's related-to relationship. None represents equivalence or a compliance determination.

| Finding rule | Unit and suffix | Control references |
| --- | --- | --- |
| `conditional-access-policy` | One policy; `conditional-access:<id>` | AC-3, IA-2 |
| `authentication-registration-summary` | One aggregate when records exist; `authentication-registration:summary` | IA-2, IA-5 |
| `sign-in-observation` | One in-window event; `sign-ins:<id>` | AU-6, SI-4 |
| `directory-role-inventory` | One activated role; `directory-roles:<id>` | AC-2, AC-6 |
| `managed-device-state` | One device; `managed-devices:<id>` | CM-8, CA-7 |
| `retention-label-configuration` | One label; `retention-labels:<id>` | SI-12 |
| `dlp-policy-configuration` | One policy with admitted selected rule observations; `dlp-export:policy:<Guid>` | AC-4, SI-4 |
| `dlp-unresolved-rule` | One unresolved parent rule; `dlp-export:unresolved-rule:<Guid>` | AC-4, related-to |
| `defender-alert-observation` | One in-window alert; `defender-alerts:<id>` | SI-4, IR-5 |
| `defender-incident-observation` | One in-window incident; `defender-incidents:<id>` | IR-4, IR-5 |

All compliance_status values are UNKNOWN. Non-Defender findings are informational and active. Defender informational/low/medium/high retain their severity; other values map to informational with literal source values retained. Only exact source status resolved sets a resolved finding. Source strings remain escaped data. Excluded top-level user principal names, IP addresses, user/device names, raw descriptions, and unrelated provider fields are not persisted. Retained policy conditions can contain identifying scope values; the selected evidence is not an anonymization guarantee.

Manifest is_complete is true exactly when every requested capability is complete, with no errors. Otherwise static capability/code text describes incompleteness. coverage_counts has one entry per requested capability; total_findings equals both findings length and summed collected counts. Only complete empty capabilities enter empty_categories. Overall status is complete for a complete requested scope, partial when an incomplete run has any accepted page/export, and unavailable otherwise. Manifest warnings retain source-scope, retention, and unknown-data limitations. full_surface_complete requires all nine requested and complete; it does not imply tenant-wide compliance.

Planned Python exports from evidentia_collectors.entra_m365 are EntraM365Collector, EntraM365CollectRequest, EntraM365CollectResult, EntraM365CapabilityResult, EntraM365Diagnostic, and EntraM365InputError. New callers use collect_v2(request) to preserve completeness; collect(request) follows the findings-only Python convention. COLLECTOR_ID is entra-m365-scan, SOURCE_SYSTEM is entra-m365, and console status uses entra-m365.

The planned CLI is `evidentia collect entra-m365`, with `--tenant-label`, repeatable --capability, --lookback-days, --max-items, --max-pages, optional --dlp-export PATH, --dlp-format, and --output PATH. Local input uses the cumulative byte bound and is never evaluated. Input/output identity, symlink/hard-link aliases, and output feasibility are checked before collection. Invalid input or serialization preserves existing bytes. A valid partial result is written atomically before exit 1; complete is exit 0 and invalid input is exit 2. Output failure exits 1 without claiming a save; existing read-role denial remains exit 77. Without an output file, stdout is JSON only and notices use stderr.

The planned `POST /api/collectors/entra-m365/collect` uses the collector-owned result model, application/json, and a cumulative 8,388,608-byte body limit before decoding, independent of Content-Length. Overflow is 413; unsupported content type is 415; other input errors use sanitized 400 invalid_body/invalid_field envelopes. Unknown attacker-controlled keys cannot appear in error field paths. Callers cannot supply token values, credential files/profiles, environment names, or auth mode.

Existing authentication and read RBAC apply to the endpoint and CLI leaf. A Graph request without a configured AuthProvider returns 403 auth_not_configured before token lookup/egress; the console disables that action. DLP-only local ingestion retains the existing no-provider posture while honoring configured RBAC. Authorization uses the authenticated principal, never the tenant alias. Well-formed completed attempts return HTTP 200 even when partial/all-unavailable. Unexpected failure without a safe result is 500 collector_failed.

With the optional collector absent, the API keeps the path, applies auth/RBAC, and returns 503 feature_unavailable without parsing collection content or reading tokens. Its OpenAPI advertises no success response. Only absence of the optional package or feature module qualifies; broken installed modules and unrelated missing dependencies are not treated as optional absence. Full installations use the authoritative success schema, without a duplicate or loose wire model.

The planned console form has a capability selector, nonsecret alias, bounded options, and optional local DLP upload, with no token/environment-name input. It renders all nine states, counts, exact windows, declared identity, and the full-surface flag even when findings is empty. Partial/unavailable results remain prominent. Installed, configured, and live-validated status are distinct; import success or stale health cannot establish tenant access. Demo partial/all-unavailable responses are labeled synthetic.

Fixture acceptance distinguishes authored-synthetic Graph transports, documentation examples, and a recorded-provider DLP projection. Synthetic Graph fixtures specify method, route, query, status, permitted synthetic headers, body, and pagination. They do not claim a capture date, valid credential, permission grant, or license. They support deterministic contract tests, not live-service acceptance.

The recorded DLP fixture selects fields from a [pinned CISA ScubaGear artifact](https://github.com/cisagov/ScubaGear/blob/274ce8ec984af2d0d062b5a4e09e8c59461ca24a/PowerShell/ScubaGear/Sample-Reports/ProviderSettingsExport.json), under [CC0](https://github.com/cisagov/ScubaGear/blob/274ce8ec984af2d0d062b5a4e09e8c59461ca24a/LICENSE). It preserves 11 policies, 15 rules, source order, and all 182 selected values and scalar types. Every policy DistributionStatus is Pending. Every rule Mode is Enforce, but two rules have Disabled=true; neither value overrides a disabled/test parent. A complete configuration inventory can coexist with pending distribution.

[CISA's publisher account](https://github.com/cisagov/ScubaGear/pull/2136) describes test-tenant generation and sanitization. This is publisher-attested provenance, not independent certification of complete redaction. No full export, AdvancedRule text, notification recipients, or unrelated tenant metadata is retained. Report metadata identifies ScubaGear 1.8.0 and May 4, 2026; exact acquisition time is not established, so `source.captured_at` remains null. This is selected recorded provider output, not a Graph HTTP recording. Fixture provenance retains the source pin, license, parent raw hash, projection hash, and transformation statement.

Integration acceptance must exercise every route, state, permission refusal, field shape, exact timestamp, pagination/conflict path, byte/time/item cap, retry/destination guard, DLP join/flag contradiction, manifest invariant, and CLI/API/UI round trip. Tests must preserve partial and empty evidence, suppress sensitive errors, and prove output-file safety with synthetic transports and isolated files. No ambient tenant, credentials, catalog, evidence store, or signer can influence tests. Live-tenant acceptance has not been performed; fixture results do not supply it.
