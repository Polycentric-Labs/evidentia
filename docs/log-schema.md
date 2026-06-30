# Evidentia structured log schema (v0.7.0+)

Evidentia emits machine-readable audit logs conforming to three
authorities:

- **Elastic Common Schema (ECS) 8.11** — the de-facto SIEM interchange
  format. Splunk, Elastic, Datadog, Sumo Logic, and Microsoft Sentinel
  ingest ECS without custom parsers.
- **NIST SP 800-53 Rev 5 AU-3** (Content of Audit Records) — the
  federal audit-content requirement: *what, when, where, source,
  outcome, identity*.
- **OpenTelemetry Logs Data Model v1.31** — correlation fields
  (`trace.id`, `span.id`) for cross-referencing logs, metrics, and
  traces.

## Two output modes

| Mode | Trigger | Use case |
|---|---|---|
| **Rich console** (default) | No flag | Interactive CLI runs |
| **ECS JSON** | `--json-logs` CLI flag or `evidentia_core.audit.enable_json_logs()` | SIEM ingestion, CI, long-term log storage |

Both modes emit the same events; only the encoding differs.

## Example record

```json
{
  "@timestamp": "2026-04-24T14:28:36.123Z",
  "ecs": {"version": "8.11"},
  "log": {
    "level": "info",
    "logger": "evidentia.collectors.aws.access_analyzer"
  },
  "message": "Retrieved 42 Access Analyzer findings from us-east-1",

  "event": {
    "kind": "event",
    "category": ["configuration", "iam"],
    "type": ["info"],
    "action": "evidentia.collect.finding_retrieved",
    "outcome": "success",
    "id": "01HXYZ7K8N2M3P4Q5R6S7T8U9V",
    "start": "2026-04-24T14:28:36.123Z",
    "end": "2026-04-24T14:28:36.265Z",
    "duration": 142000000,
    "dataset": "evidentia.audit"
  },

  "service": {
    "name": "evidentia",
    "version": "0.7.2",
    "type": "grc"
  },

  "host": {
    "hostname": "collector-01.example.com"
  },

  "trace": {"id": "01KPXRYJVQ0BNNHTC8TC3GXC2V"},
  "span": {"id": "5f6e7d8c9b0a1b2c"},

  "user": {
    "id": "arn:aws:iam::123456789012:role/grc-read-only-collector",
    "domain": "aws"
  },

  "cloud": {
    "provider": "aws",
    "account": {"id": "123456789012"},
    "region": "us-east-1"
  },

  "evidentia": {
    "run_id": "01KPXRYJVQ0BNNHTC8TC3GXC2V",
    "collector": {"id": "aws-access-analyzer", "version": "0.7.1"},
    "analyzer_arn": "arn:aws:access-analyzer:us-east-1:…:analyzer/grc",
    "findings_count": 42
  }
}
```

## NIST AU-3 field mapping

| AU-3 requirement | Evidentia fields |
|---|---|
| **What** | `event.action` + `event.category` |
| **When** | `@timestamp` + `event.start` + `event.end` |
| **Where** | `host.*` + `cloud.*` |
| **Source** | `service.name` + `log.logger` |
| **Outcome** | `event.outcome` (success / failure / unknown) |
| **Identity** | `user.id` + `user.domain` |

## Event catalog

Every `event.action` value is drawn from a curated enum
(`evidentia_core.audit.events.EventAction`). Unknown actions are
accepted but tagged with a warning, so the vocabulary can grow
without breaking consumers.

### `evidentia.collect.*` — collection lifecycle

| Action | When emitted |
|---|---|
| `evidentia.collect.started` | Collector begins a run |
| `evidentia.collect.finding_retrieved` | Each finding pulled from source |
| `evidentia.collect.finding_skipped` | Finding filtered out |
| `evidentia.collect.page_fetched` | Pagination page loaded |
| `evidentia.collect.retry` | Retry attempt after transient failure |
| `evidentia.collect.completed` | Run finished cleanly |
| `evidentia.collect.failed` | Run finished with unrecoverable error |
| `evidentia.collect.aborted` | Operator or safety-cap terminated run |

### `evidentia.auth.*` — credential events

| Action | When emitted |
|---|---|
| `evidentia.auth.credential_resolved` | Principal identified from SDK chain |
| `evidentia.auth.credential_refresh` | Token renewed mid-run |
| `evidentia.auth.credential_failed` | Auth lookup failed (falls back to placeholder) |

### `evidentia.config.*` — configuration events

| Action | When emitted |
|---|---|
| `evidentia.config.loaded` | `evidentia.yaml` parsed |
| `evidentia.config.resolved` | Precedence chain applied (CLI > env > yaml > default) |
| `evidentia.config.override_applied` | Operator-supplied override took effect |
| `evidentia.config.invalid` | Config validation failed |

### `evidentia.sign.*` / `evidentia.verify.*` — signing lifecycle

| Action | When emitted |
|---|---|
| `evidentia.sign.gpg_signed` | GPG signature produced |
| `evidentia.sign.key_signed` | DSSE envelope produced via cryptography-native Ed25519/RSA-PSS path (`--sign-with-key`) |
| `evidentia.sign.sigstore_signed` | Sigstore bundle produced |
| `evidentia.sign.sigstore_skipped_airgap` | Sigstore refused in air-gap mode |
| `evidentia.sign.signing_failed` | Signing raised an error |
| `evidentia.verify.started` | Verification run begins |
| `evidentia.verify.digest_passed` / `digest_failed` | Per-resource digest check |
| `evidentia.verify.signature_passed` / `signature_failed` | Signature check |
| `evidentia.verify.completed` | Verification done |

### `evidentia.manifest.*` — completeness attestation

| Action | When emitted |
|---|---|
| `evidentia.manifest.generated` | CollectionManifest written |
| `evidentia.manifest.empty_set_attested` | Scanned category returned zero findings (explicit empty-set claim per B5) |
| `evidentia.manifest.incomplete` | Run marked `is_complete=False` |

### `evidentia.ai.*` — AI generation events (v0.7.1)

Emitted by `evidentia-ai` when an LLM produces a risk statement or
plain-English control explanation. The namespace is distinct from
`evidentia.collect.*` because these outputs are **generated** rather
than **collected** — an auditor querying provenance needs to tell the
two paths apart.

| Action | When emitted |
|---|---|
| `evidentia.ai.risk_generated` | Risk statement returned successfully (one event per gap, also for each item in a batch) |
| `evidentia.ai.risk_failed` | Risk-statement generation raised an unrecoverable exception after all retries |
| `evidentia.ai.risk_retry` | `@with_retry` fired a network-layer retry against the LLM endpoint |
| `evidentia.ai.risk_batch_completed` | Risk-statement batch finished. `outcome=success` when `succeeded==total`, `outcome=unknown` when partial. `evidentia.succeeded` / `total` / `failed` are integer counts. |
| `evidentia.ai.explain_generated` | Plain-English explanation returned successfully on a cache miss |
| `evidentia.ai.explain_failed` | Explanation generation raised an unrecoverable exception after all retries |
| `evidentia.ai.explain_retry` | `@with_retry` fired a network-layer retry on an explain call |
| `evidentia.ai.explain_cache_hit` | Cached explanation returned without invoking the LLM (no `GenerationContext` is minted; the cached one is preserved) |
| `evidentia.ai.explain_batch_completed` | Explanation batch finished (same `outcome` + counts semantics as `risk_batch_completed`) |

Every successful `evidentia.ai.*_generated` event corresponds to an
output object carrying a `GenerationContext` provenance block — see
the next section.

### `evidentia.mcp.*` — MCP tool authorization (v0.8.6 P1)

Fired by `evidentia_mcp.scope.enforce_cimd_scope` once per tool
call routed through the CIMD-enforcement gate. AUTHORIZED + DENIED
are mutually exclusive per call; both carry the calling
`client_id` + the requested `tool_name` + the registered scope
allowlist so an auditor can reconstruct the gate's decision
without re-running the request.

| Action | When emitted |
|---|---|
| `evidentia.mcp.tool_authorized` | Tool dispatch passed the CIMD gate (registered `client_id` + scope contains tool); call delegated to FastMCP `call_tool` |
| `evidentia.mcp.tool_denied` | Tool dispatch failed the CIMD gate (ambiguous client_id, unregistered client_id, or scope does not contain tool); MCP client receives `McpError` code -32602 |

Both events carry the following evidentia-extension fields:

| Field | Type | Purpose |
|---|---|---|
| `evidentia.run_id` | `str` (32-char hex) | Per-call UUID4; distinct from DFAH `run_id`. Lets auditors correlate the authorize/deny decision with downstream tool-execution events when AUTHORIZED proceeds. |
| `evidentia.client_id` | `str \| null` | Resolved client_id (precedence: `Context.client_id` → `default_client_id` → `null`). When `null`, the call denied with ambiguous-caller policy. |
| `evidentia.tool_name` | `str` | The MCP tool name the client requested (e.g., `gap_analyze`, `list_frameworks`). |
| `evidentia.scope_allowlist` | `str \| null` | Space-separated tool allowlist from the matched CIMDDocument (or `null` if client_id was unresolved/unregistered). |

When the MCP server is built without a CIMDRegistry attached
(the v0.8.5 default), the gate passes all calls through and these
events do NOT fire — absence of the events is itself an audit
signal that the operator did not opt into per-tool gating.

**Threat model**: CIMD is NOT authentication. The audit-trail
records what `client_id` the gate observed; transport-level
authentication (reverse-proxy mTLS, bearer tokens, UID-based
trust for stdio) is the prerequisite for using CIMD as an AuthZ
control. See `evidentia_mcp.scope` module docstring +
`docs/threat-model.md` for the full posture.

### `evidentia.poam.*` — Plan-of-Action-and-Milestones lifecycle (v0.9.0 P1)

Fired by the POA&M store + CLI/REST/OSCAL surfaces (P2) on every
state transition that an auditor would expect to see in the audit
trail. The vocabulary matches the FedRAMP POA&M Template Completion
Guide v3.0 + NIST SP 800-53A Rev 5 Appendix F lifecycle states.

| Action | When emitted |
|---|---|
| `evidentia.poam.created` | A POA&M item lands in the store for the first time (typically via `evidentia poam create --from-gap-report <path>` in v0.9.0 P2). |
| `evidentia.poam.updated` | A persisted edit to a POA&M item that ISN'T a state transition (description fix, evidence_ref edit, tag addition). |
| `evidentia.poam.milestone_reached` | A single milestone's status transitions to COMPLETED. Distinct from `closed` because a multi-milestone POA&M can have several milestones reach completion before the overall POA&M is verified. |
| `evidentia.poam.overdue` | Fired on operator-set status=OVERDUE transitions only (e.g., `milestone update --status overdue`). Derived overdue (target_date < today + status in {PLANNED, IN_PROGRESS}) surfaces in `poam calendar` output + dashboard widgets but does NOT emit per-cycle audit events — operators who need an audit record per surfaced derived-overdue must explicitly transition status via the milestone-update verb. Keeps the audit log low-noise. |
| `evidentia.poam.closed` | The LAST open milestone on a POA&M transitions to COMPLETED, OR the operator marks `ControlGap.status = REMEDIATED`. |
| `evidentia.poam.verified` | An auditor (or operator on auditor's behalf with provenance) confirms a closed POA&M. Terminal — no further events on the same POA&M unless a NEW gap is filed referencing it. |

Common evidentia-extension fields across the family:

| Field | Type | Purpose |
|---|---|---|
| `evidentia.poam_id` | `str` (UUID) | `ControlGap.id` of the POA&M item being acted on. |
| `evidentia.control_id` | `str` | The framework + control_id pair (e.g., `nist-800-53-rev5:AC-2`) for cross-reference to the underlying gap. |
| `evidentia.milestone_id` | `str` (UUID) \| absent | Present on `milestone_reached`; identifies the specific milestone whose state changed. |
| `evidentia.prior_state` | `POAMState` value \| absent | Present on `updated` + `closed` + `verified` + `milestone_reached`; the state BEFORE the transition. |
| `evidentia.new_state` | `POAMState` value \| absent | Present alongside `prior_state`; the state AFTER the transition. |

State-transition validity is enforced by
`evidentia_core.poam.state.is_valid_transition` — backward
transitions (e.g., `COMPLETED → IN_PROGRESS`) are programmatically
forbidden. An operator who needs to re-open work files a NEW
milestone with a fresh `target_date`; the audit trail captures the
re-open as a NEW `created` event, never an `updated` rewind.

`overdue` events fire ONLY on operator-set status=OVERDUE
transitions (via the `milestone update --status overdue` verb).
Derived overdue (target_date < today + status in {PLANNED,
IN_PROGRESS}) is surfaced in `poam calendar` CLI / `GET
/api/poam/calendar` output + dashboard widgets but does NOT emit
per-cycle audit records. This keeps the audit log low-noise:
operators who need a per-surfaced-overdue record must explicitly
transition the milestone state. The CONMON cycle calendar (below)
takes the OPPOSITE choice — `evidentia.conmon.cycle_overdue` fires
per surfaced cycle from the `conmon check` query path because the
CONMON cadences represent organization-wide assessment events
rather than per-record state.

### `evidentia.conmon.*` — Continuous Monitoring cycle calendar (v0.9.0 P3)

Fired by the CONMON CLI query path (REST surface deferred to
v0.9.1 if walk-through identifies operator demand) when an
operator query identifies a due or overdue cycle. The cadence library
(`evidentia_core.conmon.calendar`) is pure-function; audit emit
happens at the query layer, not in the library, so a given cycle
can be "due" multiple times in a row without multiplying audit
records — operators only emit when they actively query the
calendar.

| Action | When emitted |
|---|---|
| `evidentia.conmon.cycle_due` | A CONMON cycle is within the operator-configured due-soon window (default 14 days). |
| `evidentia.conmon.cycle_overdue` | A CONMON cycle's next-due date is in the past relative to the query date. Auditor-visible signal that the organization is behind on its monitoring obligations. |

Both events carry the following evidentia-extension fields:

| Field | Type | Purpose |
|---|---|---|
| `evidentia.cadence_slug` | `str` | The `ConmonCadence.slug` identifying the cycle (e.g., `nist-800-53-rev5-ca7`, `fedramp-conmon-annual`). Stable across releases. |
| `evidentia.framework` | `str` | The framework identifier (e.g., `nist-800-53-rev5`, `fedramp-rev5-mod`, `cmmc-v2`). |
| `evidentia.activity` | `str` | The activity within the framework (e.g., `continuous-monitoring`, `poam-update`, `security-assessment`). |
| `evidentia.last_completed` | `str` (ISO-8601 date) | The anchor date the next-due was computed from. |
| `evidentia.next_due` | `str` (ISO-8601 date) | The computed next-due date. |
| `evidentia.days_until_due` | `int` | Days from query date to next-due; negative for overdue. |

**Current cycles** (`next_due > today + window_days`) do NOT emit
events. The absence of an event is itself an auditor signal: no
attention needed for that cycle this query.

Cadence-slug stability is the audit-trail integrity property — an
auditor reviewing six months of CONMON events can rely on the slug
to consistently identify the cycle even as the bundled cadence
catalog grows. Slug changes require a new entry alongside the old
(append-only), never a rename.

## `GenerationContext` — AI output provenance

Every artifact emitted by `evidentia-ai` (currently `RiskStatement`
and `PlainEnglishExplanation`) carries an optional
`GenerationContext` block with the same role that
`CollectionContext` plays for collected findings.

| Field | Type | Purpose |
|---|---|---|
| `model` | `str` | LiteLLM model identifier exactly as passed to the LLM call (e.g., `claude-sonnet-4`, `openrouter/anthropic/claude-sonnet-4`). |
| `temperature` | `float` (0.0–2.0) | Sampling temperature pinned for reproduction. |
| `prompt_hash` | `str` (64-char SHA-256 hex) | Hash of `system_prompt + "\n---\n" + user_prompt` via `evidentia_core.audit.compute_prompt_hash`. Lets an auditor prove byte-equivalence of prompts across runs. |
| `run_id` | `str` (26-char ULID) | Defaults to a fresh ULID per call. Batch callers mint one via `new_run_id()` and thread it through every output to enable batch reconstruction. |
| `generated_at` | ISO 8601 datetime | UTC microsecond timestamp of the validated LLM response. |
| `attempts` | `int` (≥1) | Total network-layer attempts before success (1 = first try; >1 = `@with_retry` fired N-1 retries). |
| `instructor_max_retries` | `int` (≥0) | The configured Instructor validation-retry cap (independent of `attempts`; counts JSON-shape retries, not network retries). |
| `credential_identity` | `str \| null` | Best-effort operator/principal label that authorized the LLM call. Mirrors `CollectionContext.credential_identity`; satisfies NIST AU-3 "Identity". Populated from `$EVIDENTIA_AI_OPERATOR` if set, else `user@hostname`. NEVER the API key itself. |
| `evidentia_version` | `str` | Version of evidentia-core orchestrating the generation. |

## Secret scrubbing

Before emission, `message` strings pass through a regex-based scrubber
that redacts:

- AWS access key IDs (`AKIA*`, `ASIA*`, 20 chars total)
- GitHub tokens (`ghp_*`, `gho_*`, `ghu_*`, `ghs_*`, `ghr_*` + 36 chars)
- Generic `password=`, `token=`, `api_key=`, `secret=`, `credential=` shapes ≥8 chars
- JWTs (three base64url segments separated by dots)

Matched strings are replaced with `[REDACTED]`.

### Filesystem path disclosure caveat (v0.9.4 P1.4 F-V93-S9)

The scrubber redacts secret-like strings but does NOT scrub
operator-supplied filesystem paths. Several lifecycle events emit
absolute paths as structured-field values, which can leak deployment-
environment topology to a SIEM operator (or an attacker who exfiltrates
SIEM data).

Audit events carrying paths:

- `evidentia.conmon.daemon_started` / `daemon_stopped` — payload
  includes `state_file=<absolute path>` (operator-supplied via
  `--state-file`).
- `evidentia.conmon.cycle_marked_completed` — message text references
  the state-file path.
- `evidentia.config.loaded` — emits the resolved config-file path.
- `evidentia.collect.*` — collectors that write evidence to disk emit
  the output path in event payloads.

On typical Linux daemon deployments, paths like
`/etc/evidentia/state.yaml` are benign topology disclosure. For
environments where the path itself is sensitive (operator username in
`/home/<sensitive-username>/evidentia/`, customer-tenant ID in
`/var/lib/evidentia/<tenant-id>/`), operators SHOULD scrub paths
before SIEM ingestion:

- Logstash / Vector / fluent-bit: add a path-redaction transform
  using a regex like `s|/home/[^/]+/|/home/[REDACTED]/|g`
- ECS log shipper: configure `path_pattern` redaction in the indexer

This is intentional design — auditors investigating a specific event
often need the exact path. The opt-in scrub belongs at the SIEM
ingestion layer where operators control the trust boundary, not in
the daemon's emission layer.

The base scrubber stays at the message-string layer:
collectors are responsible for keeping secrets out of
structured field values (not logged as strings).

## Trace correlation

A collection run begins with `new_run_id()` (26-char ULID). That
run_id flows into every emitted event's `trace.id` via
`log.scope(trace_id=run_id)`. Operators querying SIEM by `trace.id`
retrieve every event from that run, across retries and sub-collectors,
in chronological order (ULID's 48-bit timestamp prefix makes them
sortable even when `@timestamp` resolution collides).

## Configuration

```bash
# CLI flag (one-shot)
evidentia --json-logs collect aws

# Python API
from evidentia_core.audit import enable_json_logs
enable_json_logs(stream=sys.stderr)
```

JSON logs emit to `stderr` by default so they don't contaminate stdout
(which CLI commands use for primary output).

## Test mode

Set `EVIDENTIA_TEST_MODE=1` to zero out retry backoff — used by the
test suite to keep `@with_retry` tests fast. Production should never
set this.
