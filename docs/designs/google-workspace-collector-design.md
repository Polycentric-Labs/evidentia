# Design: the Google Workspace collector (V13-03)

Status: built in batch 7, 2026-09-06. Scope item V13-03 of
[the v0.13 plan](../releases/plans/v0.13-plan.md): "Okta extension plus a Google
Workspace collector". The Google Workspace collector is the new surface; section
5 below covers what "extend the Okta leaf" meant for the other half of the item.

## 1. The auth decision

The collector reads a **pre-minted OAuth 2.0 access token** from
`GOOGLE_WORKSPACE_ACCESS_TOKEN` and sends it as `Authorization: Bearer <token>`.
It never mints or refreshes a token itself. This keeps the batch's new dependency
surface at zero (the same `httpx`-based `BaseSaaSCollector` shape every other SaaS
collector already uses) and matches how an operator would hand the collector a
short-lived credential for a scheduled run.

**Deferred**: a service-account domain-wide-delegation flow, where the collector
would mint and automatically refresh its own token from a service-account key,
is a later, optional extra. It removes the roughly one-hour token-lifetime blind
spot (section 4) for long-running enumerations but adds a new credential shape
(a JSON key file, plus the domain-wide delegation admin console setup) that is
out of scope for this batch.

## 2. The two endpoints

Both live under the Admin SDK, `https://admin.googleapis.com` by default:

- **Directory API**, `GET /admin/directory/v1/users`: user inventory, admin
  roles (`isAdmin`, `isDelegatedAdmin`), and 2-Step Verification status
  (`isEnrolledIn2Sv`, `isEnforcedIn2Sv`). Paginated with `maxResults` (500) and
  `pageToken`; a `fields` mask keeps the response to the eleven fields the
  collector reads. Scope: `https://www.googleapis.com/auth/admin.directory.user.readonly`.
- **Reports API**, `GET /admin/reports/v1/activity/users/all/applications/login`,
  for login activity over a configurable look-back window
  (`--login-window-days`, default 30, range 0-180; 0 skips this endpoint
  entirely). Paginated with `maxResults` (1000) and `pageToken`. Scope:
  `https://www.googleapis.com/auth/admin.reports.audit.readonly`, requested only
  when the window is greater than 0.

Every page fetch is wrapped in a bounded retry (`build_retrying` with a
`retry_predicate`, from the shared core change earlier in this batch), retrying
429 and the transient 5xx class, never auth errors or other 4xx. The Directory
pull is fatal on failure (there is no run without a user list); the Reports pull
is non-fatal: its failure is recorded in the manifest and the Directory
findings still ship.

## 3. The six findings

Every finding carries `source_system="google-workspace"`, a
`resource_type="GoogleWorkspace::Customer"`, and authored `control_mappings`
(never the discarding `control_ids` shim) against `nist-800-53-rev5`.

| Finding | Emitted | Severity | Mappings |
|---|---|---|---|
| user inventory | always | informational | AC-2 |
| inactive accounts | only when count > 0 | high (>50) / medium | AC-2 |
| admin accounts | always | high (>10 super admins) / medium (>5) / informational | AC-2, AC-6 |
| admin 2-Step Verification | always | high if any active super admin lacks 2SV, else informational | IA-2, AC-6 |
| tenant-wide 2-Step Verification enrollment | always | high (<0.80) / medium (<0.95) / informational | IA-2 |
| login activity | only when the Reports pull ran and succeeded | medium if any suspicious event, else informational | AU-6, AC-7, SI-4 |

"Active" means not suspended and not archived. "Never signed in" means
`lastLoginTime` is missing or before 1971 (Google's epoch sentinel). "Inactive"
judges a never-signed-in user on `creationTime` alone, not their sentinel
`lastLoginTime`, so a recently created user who has not yet signed in does not
count as inactive.

## 4. Blind spots

Four, documented on the collector and surfaced in `evidentia doctor` style
disclosure:

- **`EVIDENTIA-GOOGLE-WORKSPACE-TOKEN-LIFETIME`**: the pre-minted token has no
  refresh path; a long enumeration against a very large tenant can outlive it.
- **`EVIDENTIA-GOOGLE-WORKSPACE-2SV-METHOD`**: 2-Step Verification is reported
  as enrolled/enforced booleans, not the method (security key, prompt, SMS).
- **`EVIDENTIA-GOOGLE-WORKSPACE-REPORTS-RETENTION`**: login activity is bounded
  by Google's roughly 180-day retention; a longer window or a missing Reports
  scope yields an incomplete manifest, not an error.
- **`EVIDENTIA-GOOGLE-WORKSPACE-ENUMERATION-CAP`**: `--max-users` and
  `--max-login-events` truncate very large tenants; the affected finding
  records `truncated`.

## 5. What "extend the Okta leaf" meant in this batch

No CLI, API or console surface changed for Okta. Four internal changes to
`packages/evidentia_collectors/okta/collector.py`:

1. Every finding's `control_ids=[...]` becomes `control_mappings=list(<MAPPINGS>)`,
   so the authored OLIR relationship and justification ship instead of being
   discarded. A finding's deterministic id is unaffected (it derives only from
   `source_system` and `source_finding_id`).
2. `OktaQueryError` gains a `status_code` kwarg; a new `_request`/`_request_once`
   pair (used by both `_api_get` and `_list_all_users`) wraps every GET in the
   same bounded retry the Google Workspace collector uses, retrying 429 and the
   transient 5xx class.
3. The manifest's coverage counts move from a hardcoded `okta-org` 1/1/1 row to
   four real per-resource-type rows: `okta-user`, `okta-admin-assignment`,
   `okta-mfa-sample`, `okta-policy`.
4. The user-inventory finding's `raw_data` gains `status_counts`: every distinct
   Okta status seen among the enumerated users, not just the three named in the
   finding's title.

## 6. Deferred

- **Okta groups and app assignments** are not enumerated. The v0.13 plan scoped
  this item as an *extension* of the existing Okta leaf, not a rebuild of its
  evidence surface; groups and app assignments are a candidate for a future
  batch.
- **Duo is excluded from v0.13.** Its Admin API is available on paid tiers
  only, so there is no free CI test path (per the v0.13 plan's V13-03 body).

## 7. Related documents

[api-stability.md](../api-stability.md),
[collector-idempotency-audit.md](../collector-idempotency-audit.md),
[cli-gui-parity.yaml](../cli-gui-parity.yaml),
[wiki/2-guides/run-collectors.md](../wiki/2-guides/run-collectors.md).
