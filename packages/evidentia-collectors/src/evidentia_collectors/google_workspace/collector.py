"""Google Workspace evidence collector, main module (v0.13 batch 7).

Read-only collector against the Google Workspace Admin SDK: the
Directory API (user inventory, admin roles, 2-Step Verification
status) and the Reports API (login activity). Emits NIST-mapped
SecurityFinding objects covering account inventory, inactive
accounts, admin accounts, super admin 2SV enrollment, tenant-wide
2SV enrollment, and login activity.

Mirrors the Vanta collector's BaseSaaSCollector subclass shape (typed
error hierarchy, manifest, blind spots) and the Okta collector's
finding shapes and sub-check loop. See
``evidentia_collectors.google_workspace.__init__`` for the
public-surface walkthrough and credential handling.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any

from evidentia_core.audit import (
    CollectionContext,
    CollectionManifest,
    CoverageCount,
    EventAction,
    EventCategory,
    EventOutcome,
    EventType,
    build_retrying,
    get_logger,
    new_run_id,
)
from evidentia_core.models.common import (
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import (
    ComplianceStatus,
    FindingStatus,
    SecurityFinding,
)
from evidentia_core.plugins.collectors import (
    BaseSaaSCollector,
    SaaSAuthError,
    SaaSCollectorError,
    SaaSConnectionError,
    SaaSQueryError,
)

from evidentia_collectors.google_workspace.mapping import (
    ADMIN_2SV_MAPPINGS,
    ADMIN_ACCOUNT_MAPPINGS,
    INACTIVE_ACCOUNT_MAPPINGS,
    LOGIN_ACTIVITY_MAPPINGS,
    TWO_SV_ENROLLMENT_MAPPINGS,
    USER_INVENTORY_MAPPINGS,
)

if TYPE_CHECKING:
    import httpx


_log = get_logger("evidentia.collectors.google_workspace")

COLLECTOR_ID = "google-workspace-scan"
SOURCE_SYSTEM = "google-workspace"

# The token this collector reads is a pre-minted OAuth 2.0 access token
# (about one hour of life); the collector never mints or refreshes one.
TOKEN_ENV_VAR = "GOOGLE_WORKSPACE_ACCESS_TOKEN"

DEFAULT_BASE_URL = "https://admin.googleapis.com"
DEFAULT_CUSTOMER = "my_customer"

# Inactive-account threshold per AC-2(3): default 90 days.
DEFAULT_INACTIVE_THRESHOLD_DAYS = 90

# Hard cap on Directory user enumeration.
DEFAULT_MAX_USERS = 10_000

# Reports API login-activity look-back window, in days. 0 means "do not
# call the Reports API at all" (see the login_window_days constructor arg).
DEFAULT_LOGIN_WINDOW_DAYS = 30

# Hard cap on Reports API login-event enumeration.
DEFAULT_MAX_LOGIN_EVENTS = 10_000

# HTTP statuses a bounded retry should retry: rate limiting (429) and the
# transient 5xx class. Auth errors (401/403) and other 4xx never retry.
RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})

# The Directory API `fields` mask (developers.google.com, fetched
# 2026-09-06): keeps the response to exactly the fields this collector
# reads, which also keeps quota usage down on large tenants.
_DIRECTORY_FIELDS = (
    "nextPageToken,users(id,primaryEmail,suspended,suspensionReason,"
    "archived,isAdmin,isDelegatedAdmin,isEnrolledIn2Sv,isEnforcedIn2Sv,"
    "lastLoginTime,creationTime,orgUnitPath)"
)

_DIRECTORY_PATH = "/admin/directory/v1/users"
_REPORTS_LOGIN_PATH = "/admin/reports/v1/activity/users/all/applications/login"

# Reports API login event names the collector treats as suspicious. Every
# event name seen is counted in `by_event`; this subset drives severity.
_SUSPICIOUS_EVENT_NAMES = frozenset(
    {
        "suspicious_login",
        "suspicious_login_less_secure_app",
        "suspicious_programmatic_login",
        "account_disabled_password_leak",
        "account_disabled_hijacked",
        "user_signed_out_due_to_suspicious_session_cookie",
    }
)


# ── Typed exception hierarchy ──────────────────────────────────────


class GoogleWorkspaceCollectorError(SaaSCollectorError):
    """Base class for all Google Workspace collector failures."""


class GoogleWorkspaceAuthError(GoogleWorkspaceCollectorError, SaaSAuthError):
    """Authentication or authorization failure: HTTP 401 or 403 from the API.

    Distinguished from query errors so callers can surface a clear
    'check your GOOGLE_WORKSPACE_ACCESS_TOKEN' message rather than a
    generic 'something went wrong' message.
    """


class GoogleWorkspaceConnectionError(GoogleWorkspaceCollectorError, SaaSConnectionError):
    """Network, TLS or timeout failure reaching admin.googleapis.com."""


class GoogleWorkspaceQueryError(GoogleWorkspaceCollectorError, SaaSQueryError):
    """A specific API call failed (permission denied, rate limit, or a
    malformed response). The Directory pull treats this as fatal (there
    is no run without a user list); the Reports pull treats this as
    non-fatal and records it in the manifest instead.
    """


def _is_retryable(exc: BaseException) -> bool:
    """Retry predicate for the bounded-retry wrapper around every GET.

    Retries a connection failure outright, and a query failure only when
    its carried HTTP status is in :data:`RETRYABLE_STATUS_CODES` (429 and
    the transient 5xx class). Everything else, including auth errors and
    other 4xx responses, is not retried.
    """
    if isinstance(exc, GoogleWorkspaceConnectionError):
        return True
    if isinstance(exc, GoogleWorkspaceQueryError):
        return exc.status_code in RETRYABLE_STATUS_CODES
    return False


# ── BLIND_SPOTS list ────────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-GOOGLE-WORKSPACE-TOKEN-LIFETIME",
        "title": "Pre-minted access token has no refresh path",
        "description": (
            "The collector takes a pre-minted OAuth 2.0 access token (about "
            "one hour of life) and does not mint or refresh one itself. A "
            "long enumeration against a very large tenant can outlive the "
            "token's lifetime and end as a partial run; a service-account "
            "domain-wide-delegation flow that mints and refreshes its own "
            "token is a later, optional extra."
        ),
    },
    {
        "id": "EVIDENTIA-GOOGLE-WORKSPACE-2SV-METHOD",
        "title": "2-Step Verification method strength is not enumerated",
        "description": (
            "The Directory API reports 2-Step Verification enrollment and "
            "enforcement as booleans, not the method in use (security key, "
            "prompt, SMS, backup codes). A tenant can show a high enrollment "
            "rate while relying on a weaker method; judging method strength "
            "needs out-of-band evidence."
        ),
    },
    {
        "id": "EVIDENTIA-GOOGLE-WORKSPACE-REPORTS-RETENTION",
        "title": "Login activity is bounded by Google's retention window",
        "description": (
            "The Reports API's login activity feed covers about 180 days. A "
            "requested window longer than the tenant's actual retention, or "
            "a token missing the Reports readonly scope, yields no "
            "login-activity finding and an incomplete manifest rather than "
            "an error: absence of the finding is not evidence of a clean "
            "login history."
        ),
    },
    {
        "id": "EVIDENTIA-GOOGLE-WORKSPACE-ENUMERATION-CAP",
        "title": "Directory and Reports enumeration are capped",
        "description": (
            "max_users and max_login_events truncate very large tenants at "
            "an operator-configured ceiling; the user-inventory and "
            "login-activity findings both record `truncated` so a reviewer "
            "can tell a capped run from a complete one."
        ),
    },
]


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse an RFC 3339 Google timestamp; unparseable values are skipped.

    Returns ``None`` for a missing, non-string, or unparseable value
    rather than raising: an unparseable timestamp is skipped, never
    counted toward a finding.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _is_active(user: dict[str, Any]) -> bool:
    """Return True when the account is active: not suspended, not archived."""
    return not user.get("suspended", False) and not user.get("archived", False)


def _never_signed_in(user: dict[str, Any]) -> bool:
    """Return True when the account has never signed in.

    Missing lastLoginTime, or a lastLoginTime year before 1971, both mean
    never signed in: Google's sentinel for the never-signed-in case is
    the 1970-01-01 epoch timestamp.
    """
    last_login = _parse_timestamp(user.get("lastLoginTime"))
    return last_login is None or last_login.year < 1971


def _is_inactive(user: dict[str, Any], threshold: datetime) -> bool:
    """Return True when an active account is inactive against the threshold.

    Inactive means active, and either (never signed in, with a
    creationTime older than the threshold) or (has signed in before, with
    a lastLoginTime older than the threshold). A user who never signed in
    is judged on creationTime alone, not on their sentinel lastLoginTime,
    so a recently created user who has not yet signed in does not count
    as inactive.
    """
    if not _is_active(user):
        return False
    if _never_signed_in(user):
        created = _parse_timestamp(user.get("creationTime"))
        return created is not None and created < threshold
    last_login = _parse_timestamp(user.get("lastLoginTime"))
    return last_login is not None and last_login < threshold


def _sample_emails(users: list[dict[str, Any]]) -> list[str]:
    """Sorted, capped sample of primaryEmail values for a raw_data sample_* key."""
    emails = sorted(str(email) for u in users if (email := u.get("primaryEmail")))
    return emails[:25]


# ── Collector ────────────────────────────────────────────────────────


class GoogleWorkspaceCollector(BaseSaaSCollector):
    """Google Workspace Directory + Reports evidence collector.

    Args:
        api_token: A pre-minted OAuth 2.0 access token carrying the
            Directory readonly and Reports readonly scopes. Sourced
            from the ``GOOGLE_WORKSPACE_ACCESS_TOKEN`` env var per the
            secret-handling protocol; never accepted as a CLI flag.
        base_url: API base URL. Default ``https://admin.googleapis.com``.
        client: Optional pre-configured ``httpx.Client``. When
            provided, the collector does not close it on exit
            (caller-owned).
        block_private_ips: SSRF guard, default-on.
        customer: The Directory customer id. Default ``my_customer``
            (Google's literal alias for the caller's own tenant).
        inactive_threshold_days: Days since last activity that mark an
            active account inactive. Default 90.
        max_users: Hard cap on Directory user enumeration. Default 10000.
        login_window_days: How many days back the Reports API login
            activity pull covers. 0 skips the Reports API entirely.
            Default 30; valid range [0, 180].
        max_login_events: Hard cap on Reports API login-event
            enumeration. Default 10000.
        now: The single clock for this run (drives the inactivity
            threshold and the Reports API ``startTime``). Defaults to
            the real current time; tests freeze it for determinism.

    Raises:
        GoogleWorkspaceAuthError: missing API token at construction time.
        ValueError: an out-of-range constructor argument.
    """

    COLLECTOR_ID = COLLECTOR_ID
    DEFAULT_BASE_URL = DEFAULT_BASE_URL
    TOKEN_ENV_VAR = TOKEN_ENV_VAR
    AUTH_ERROR_CLASS = GoogleWorkspaceAuthError
    CONNECTION_ERROR_CLASS = GoogleWorkspaceConnectionError
    QUERY_ERROR_CLASS = GoogleWorkspaceQueryError

    def __init__(
        self,
        *,
        api_token: str | None = None,
        base_url: str | None = None,
        client: httpx.Client | None = None,
        block_private_ips: bool = True,
        customer: str = DEFAULT_CUSTOMER,
        inactive_threshold_days: int = DEFAULT_INACTIVE_THRESHOLD_DAYS,
        max_users: int = DEFAULT_MAX_USERS,
        login_window_days: int = DEFAULT_LOGIN_WINDOW_DAYS,
        max_login_events: int = DEFAULT_MAX_LOGIN_EVENTS,
        now: datetime | None = None,
    ) -> None:
        super().__init__(
            api_token=api_token,
            base_url=base_url,
            client=client,
            block_private_ips=block_private_ips,
        )
        customer = customer.strip()
        if not customer:
            raise ValueError("customer must be a non-empty string.")
        if inactive_threshold_days < 1:
            raise ValueError("inactive_threshold_days must be >= 1.")
        if max_users < 1:
            raise ValueError("max_users must be >= 1.")
        if not 0 <= login_window_days <= 180:
            raise ValueError("login_window_days must be in [0, 180].")
        if max_login_events < 1:
            raise ValueError("max_login_events must be >= 1.")
        self._customer = customer
        self._inactive_threshold_days = inactive_threshold_days
        self._max_users = max_users
        self._login_window_days = login_window_days
        self._max_login_events = max_login_events
        self._now = now if now is not None else utc_now()
        # Per-run scan counts, populated by the sub-checks below and read
        # by collect_v2 to build the manifest's coverage_counts.
        self._last_directory_scanned = 0
        self._last_login_scanned = 0

    # ── HTTP ────────────────────────────────────────────────────────

    def _get_retrying(self, path: str, **params: Any) -> dict[str, Any]:
        """A single GET wrapped in the bounded retry (429 and transient 5xx)."""
        retrying = build_retrying(
            function_name="google_workspace_get",
            retry_predicate=_is_retryable,
        )
        for attempt in retrying:
            with attempt:
                return self._get(path, **params)
        raise RuntimeError("unreachable")  # pragma: no cover

    def test_connection(self) -> dict[str, Any]:
        try:
            self._get(
                _DIRECTORY_PATH,
                customer=self._customer,
                maxResults=1,
                fields=_DIRECTORY_FIELDS,
            )
        except GoogleWorkspaceQueryError as e:
            raise GoogleWorkspaceConnectionError(
                f"Could not query the Directory API for customer {self._customer!r}: {e}"
            ) from e
        return {"customer": self._customer, "reachable": True}

    def _fetch_directory_users(self) -> tuple[list[dict[str, Any]], bool]:
        """Paginate the Directory API's users.list until exhausted or max_users."""
        users: list[dict[str, Any]] = []
        page_token: str | None = None
        page_index = 0
        while len(users) < self._max_users:
            params: dict[str, Any] = {
                "customer": self._customer,
                "maxResults": 500,
                "orderBy": "email",
                "fields": _DIRECTORY_FIELDS,
            }
            if page_token:
                params["pageToken"] = page_token
            data = self._get_retrying(_DIRECTORY_PATH, **params)
            page_index += 1
            page_users = data.get("users") or []
            _log.info(
                action=EventAction.COLLECT_PAGE_FETCHED,
                message=(f"Google Workspace Directory page {page_index} fetched: {len(page_users)} user(s)"),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={
                    "resource": "google-workspace-user",
                    "page": page_index,
                    "count": len(page_users),
                },
            )
            users.extend(page_users)
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            if next_token == page_token:
                # Stuck-token guard (the sibling SaaS collectors carry the
                # same defense): a page that hands back the token it was
                # fetched with would loop forever. Stop, and report the
                # enumeration as truncated since completeness is unknown.
                _log.warning(
                    action=EventAction.COLLECT_ABORTED,
                    outcome=EventOutcome.FAILURE,
                    message="Google Workspace Directory pagination returned a repeated pageToken; stopping",
                    evidentia={"resource": "google-workspace-user", "page": page_index},
                )
                return users[: self._max_users], True
            page_token = next_token
        truncated = len(users) > self._max_users or (len(users) >= self._max_users and bool(page_token))
        return users[: self._max_users], truncated

    def _fetch_login_events(self) -> tuple[list[dict[str, Any]], bool]:
        """Paginate the Reports API's login activity feed."""
        start_time = (self._now - timedelta(days=self._login_window_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        events: list[dict[str, Any]] = []
        page_token: str | None = None
        page_index = 0
        while len(events) < self._max_login_events:
            params: dict[str, Any] = {"startTime": start_time, "maxResults": 1000}
            if page_token:
                params["pageToken"] = page_token
            data = self._get_retrying(_REPORTS_LOGIN_PATH, **params)
            page_index += 1
            page_items = data.get("items") or []
            _log.info(
                action=EventAction.COLLECT_PAGE_FETCHED,
                message=(f"Google Workspace Reports page {page_index} fetched: {len(page_items)} event(s)"),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={
                    "resource": "google-workspace-login-event",
                    "page": page_index,
                    "count": len(page_items),
                },
            )
            events.extend(page_items)
            next_token = data.get("nextPageToken")
            if not next_token:
                break
            if next_token == page_token:
                _log.warning(
                    action=EventAction.COLLECT_ABORTED,
                    outcome=EventOutcome.FAILURE,
                    message="Google Workspace Reports pagination returned a repeated pageToken; stopping",
                    evidentia={"resource": "google-workspace-login-event", "page": page_index},
                )
                return events[: self._max_login_events], True
            page_token = next_token
        truncated = len(events) > self._max_login_events or (len(events) >= self._max_login_events and bool(page_token))
        return events[: self._max_login_events], truncated

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="Google Workspace dry-run, no API calls made",
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={"dry_run": True},
            )
            return []
        findings, _manifest = self.collect_v2()
        return findings

    def collect_v2(self) -> tuple[list[SecurityFinding], CollectionManifest]:
        run_id = new_run_id()
        started_at = utc_now()

        try:
            self.test_connection()
        except GoogleWorkspaceCollectorError:
            raise
        except Exception as e:
            raise GoogleWorkspaceConnectionError(
                f"Could not establish or probe the Google Workspace connection: {e}"
            ) from e

        context = CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"google-workspace-access-token:{self._customer}",
            source_system_id=f"google-workspace:{self._customer}",
            filter_applied={
                "customer": self._customer,
                "login_window_days": str(self._login_window_days),
            },
        )
        errors: list[str] = []
        findings: list[SecurityFinding] = []
        empty_categories: list[str] = []
        reports_ran = False

        with _log.scope(
            trace_id=run_id,
            user={"id": context.credential_identity},
            evidentia={
                "run_id": run_id,
                "collector": {"id": COLLECTOR_ID, "version": current_version()},
                "customer": self._customer,
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(f"Google Workspace collection starting for customer {self._customer}"),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            try:
                findings.extend(self._directory_findings(context))
            except GoogleWorkspaceAuthError:
                _log.warning(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message="Google Workspace authentication failed",
                    evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
                )
                raise
            except GoogleWorkspaceCollectorError as e:
                _log.error(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=f"Google Workspace Directory pull failed: {e}",
                    error={"type": type(e).__name__, "message": str(e)},
                )
                raise

            if self._login_window_days > 0:
                try:
                    findings.extend(self._login_activity_findings(context))
                    reports_ran = True
                except GoogleWorkspaceCollectorError as e:
                    errors.append(f"login-activity: {e}")
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Google Workspace Reports pull failed: {e}",
                        error={"type": type(e).__name__, "message": str(e)},
                    )
            else:
                empty_categories.append("login_events")

            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=(EventOutcome.SUCCESS if not errors else EventOutcome.FAILURE),
                message=(f"Google Workspace collection completed: {len(findings)} finding(s)"),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.END],
                evidentia={
                    "findings_count": len(findings),
                    "errors_count": len(errors),
                },
            )

        coverage_counts = [
            CoverageCount(
                resource_type="google-workspace-user",
                scanned=self._last_directory_scanned,
                matched_filter=self._last_directory_scanned,
                collected=self._last_directory_scanned,
            ),
        ]
        if reports_ran:
            coverage_counts.append(
                CoverageCount(
                    resource_type="google-workspace-login-event",
                    scanned=self._last_login_scanned,
                    matched_filter=self._last_login_scanned,
                    collected=self._last_login_scanned,
                )
            )

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=started_at,
            collection_finished_at=utc_now(),
            source_system_ids=[context.source_system_id],
            filters_applied=dict(context.filter_applied),
            coverage_counts=coverage_counts,
            total_findings=len(findings),
            is_complete=not errors,
            incomplete_reason="; ".join(errors) if errors else None,
            empty_categories=empty_categories,
            errors=errors,
        )
        return findings, manifest

    # ── Sub-checks ──────────────────────────────────────────────────

    def _directory_findings(self, context: CollectionContext) -> list[SecurityFinding]:
        """Fetch the Directory users once and derive the five Directory findings."""
        users, truncated = self._fetch_directory_users()
        self._last_directory_scanned = len(users)
        findings: list[SecurityFinding] = [
            self._user_inventory_finding(users, truncated, context),
        ]
        findings.extend(self._inactive_accounts_finding(users, context))
        findings.append(self._admin_accounts_finding(users, context))
        findings.append(self._admin_2sv_finding(users, context))
        findings.append(self._two_sv_enrollment_finding(users, context))
        return findings

    def _login_activity_findings(self, context: CollectionContext) -> list[SecurityFinding]:
        """Fetch Reports login events and derive the login-activity finding.

        Only called (by collect_v2) when login_window_days > 0. Any
        GoogleWorkspaceCollectorError raised here (including a 403 from a
        token missing the Reports scope) is caught by the caller and
        treated as non-fatal.
        """
        events, truncated = self._fetch_login_events()
        self._last_login_scanned = len(events)
        return [self._login_activity_finding(events, truncated, context)]

    def _user_inventory_finding(
        self,
        users: list[dict[str, Any]],
        truncated: bool,
        context: CollectionContext,
    ) -> SecurityFinding:
        active = [u for u in users if _is_active(u)]
        suspended = [u for u in users if u.get("suspended")]
        archived = [u for u in users if u.get("archived")]
        super_admins = [u for u in users if u.get("isAdmin")]
        delegated_admins = [u for u in users if u.get("isDelegatedAdmin")]
        never_signed_in = [u for u in users if _never_signed_in(u)]

        return SecurityFinding(
            title=(
                f"Google Workspace user inventory: {len(users)} total, "
                f"{len(active)} active, {len(suspended)} suspended, "
                f"{len(archived)} archived"
            ),
            description=(
                f"The Directory API's users.list returned {len(users)} "
                f"account(s) for customer {self._customer} (capped at "
                f"{self._max_users}), including {len(super_admins)} super "
                f"admin(s) and {len(delegated_admins)} delegated admin(s). "
                "AC-2 evidence: review the active list against the "
                "intended principals, and confirm suspended or archived "
                "accounts carry no live application access."
            ),
            severity=Severity.INFORMATIONAL,
            status=FindingStatus.ACTIVE,
            compliance_status=ComplianceStatus.UNKNOWN,
            source_system=SOURCE_SYSTEM,
            source_finding_id=f"user-inventory:{context.source_system_id}",
            resource_type="GoogleWorkspace::Customer",
            resource_id=str(context.source_system_id),
            control_mappings=list(USER_INVENTORY_MAPPINGS),
            collection_context=context,
            raw_data={
                "total": len(users),
                "active": len(active),
                "suspended": len(suspended),
                "archived": len(archived),
                "super_admins": len(super_admins),
                "delegated_admins": len(delegated_admins),
                "never_signed_in": len(never_signed_in),
                "max_users": self._max_users,
                "truncated": truncated,
            },
        )

    def _inactive_accounts_finding(
        self, users: list[dict[str, Any]], context: CollectionContext
    ) -> list[SecurityFinding]:
        threshold = self._now - timedelta(days=self._inactive_threshold_days)
        inactive = [u for u in users if _is_inactive(u, threshold)]
        if not inactive:
            return []
        count = len(inactive)
        return [
            SecurityFinding(
                title=(
                    f"Google Workspace inactive accounts: {count} active "
                    f"account(s) inactive past {self._inactive_threshold_days} "
                    "days"
                ),
                description=(
                    f"{count} active account(s) for customer {self._customer} "
                    f"have not signed in, or have never signed in and were "
                    f"created, more than {self._inactive_threshold_days} days "
                    "ago. AC-2(3) Account Management (disable inactive "
                    "accounts): review each account for continued need and "
                    "disable or remove it if none exists."
                ),
                severity=Severity.HIGH if count > 50 else Severity.MEDIUM,
                status=FindingStatus.ACTIVE,
                compliance_status=ComplianceStatus.WARNING,
                source_system=SOURCE_SYSTEM,
                source_finding_id=f"inactive-accounts:{context.source_system_id}",
                resource_type="GoogleWorkspace::Customer",
                resource_id=str(context.source_system_id),
                control_mappings=list(INACTIVE_ACCOUNT_MAPPINGS),
                collection_context=context,
                raw_data={
                    "count": count,
                    "threshold_days": self._inactive_threshold_days,
                    "sample_inactive": _sample_emails(inactive),
                },
            )
        ]

    def _admin_accounts_finding(self, users: list[dict[str, Any]], context: CollectionContext) -> SecurityFinding:
        super_admins = [u for u in users if u.get("isAdmin")]
        delegated_admins = [u for u in users if u.get("isDelegatedAdmin")]
        n_super = len(super_admins)
        n_delegated = len(delegated_admins)
        if n_super > 10:
            severity = Severity.HIGH
        elif n_super > 5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.INFORMATIONAL
        compliance = ComplianceStatus.WARNING if n_super > 5 else ComplianceStatus.UNKNOWN

        return SecurityFinding(
            title=(f"Google Workspace admin accounts: {n_super} super admin(s), {n_delegated} delegated admin(s)"),
            description=(
                f"{n_super} account(s) carry isAdmin (super admin) and "
                f"{n_delegated} carry isDelegatedAdmin for customer "
                f"{self._customer}. AC-6 Least Privilege: the super admin "
                "count should stay minimal; AC-2 evidence: each admin "
                "assignment should trace to a documented business need."
            ),
            severity=severity,
            status=FindingStatus.ACTIVE,
            compliance_status=compliance,
            source_system=SOURCE_SYSTEM,
            source_finding_id=f"admin-accounts:{context.source_system_id}",
            resource_type="GoogleWorkspace::Customer",
            resource_id=str(context.source_system_id),
            control_mappings=list(ADMIN_ACCOUNT_MAPPINGS),
            collection_context=context,
            raw_data={
                "super_admins": n_super,
                "delegated_admins": n_delegated,
                "sample_super_admins": _sample_emails(super_admins),
                "sample_delegated_admins": _sample_emails(delegated_admins),
            },
        )

    def _admin_2sv_finding(self, users: list[dict[str, Any]], context: CollectionContext) -> SecurityFinding:
        active_super_admins = [u for u in users if u.get("isAdmin") and _is_active(u)]
        without_2sv = [u for u in active_super_admins if not u.get("isEnrolledIn2Sv")]
        not_enforced = [u for u in active_super_admins if not u.get("isEnforcedIn2Sv")]
        any_without = len(without_2sv) > 0

        return SecurityFinding(
            title=(
                f"Google Workspace super admin 2-Step Verification: "
                f"{len(without_2sv)} of {len(active_super_admins)} active "
                "super admin(s) not enrolled"
            ),
            description=(
                f"{len(without_2sv)} of {len(active_super_admins)} active "
                f"super admin account(s) for customer {self._customer} do "
                f"not have isEnrolledIn2Sv set; {len(not_enforced)} do not "
                "have isEnforcedIn2Sv set. IA-2 requires multi-factor "
                "authentication for privileged accounts; an unenrolled "
                "super admin is the highest-value target in the tenant and "
                "should be remediated first."
            ),
            severity=Severity.HIGH if any_without else Severity.INFORMATIONAL,
            status=(FindingStatus.ACTIVE if any_without else FindingStatus.RESOLVED),
            compliance_status=(ComplianceStatus.FAIL if any_without else ComplianceStatus.PASS),
            source_system=SOURCE_SYSTEM,
            source_finding_id=f"admin-2sv:{context.source_system_id}",
            resource_type="GoogleWorkspace::Customer",
            resource_id=str(context.source_system_id),
            control_mappings=list(ADMIN_2SV_MAPPINGS),
            collection_context=context,
            raw_data={
                "super_admins": len(active_super_admins),
                "super_admins_without_2sv": len(without_2sv),
                "super_admins_not_enforced": len(not_enforced),
                "sample_without_2sv": _sample_emails(without_2sv),
            },
        )

    def _two_sv_enrollment_finding(self, users: list[dict[str, Any]], context: CollectionContext) -> SecurityFinding:
        active = [u for u in users if _is_active(u)]
        enrolled = [u for u in active if u.get("isEnrolledIn2Sv")]
        enforced = [u for u in active if u.get("isEnforcedIn2Sv")]
        n_active = len(active)

        enrollment_rate: float | None
        enforcement_rate: float | None
        if n_active == 0:
            enrollment_rate = None
            enforcement_rate = None
            severity = Severity.INFORMATIONAL
            status = FindingStatus.RESOLVED
            compliance = ComplianceStatus.UNKNOWN
        else:
            enrollment_rate = round(len(enrolled) / n_active, 4)
            enforcement_rate = round(len(enforced) / n_active, 4)
            if enrollment_rate < 0.80:
                severity = Severity.HIGH
            elif enrollment_rate < 0.95:
                severity = Severity.MEDIUM
            else:
                severity = Severity.INFORMATIONAL
            status = FindingStatus.ACTIVE if enrollment_rate < 0.95 else FindingStatus.RESOLVED
            compliance = ComplianceStatus.PASS if enrollment_rate >= 0.95 else ComplianceStatus.FAIL
        pct = f"{enrollment_rate * 100:.1f}%" if enrollment_rate is not None else "n/a"

        return SecurityFinding(
            title=(f"Google Workspace 2-Step Verification enrollment: {len(enrolled)}/{n_active} active users ({pct})"),
            description=(
                f"{len(enrolled)} of {n_active} active account(s) for "
                f"customer {self._customer} have isEnrolledIn2Sv set ({pct}); "
                f"{len(enforced)} have isEnforcedIn2Sv set. IA-2 requires "
                "multi-factor authentication; an enrollment rate below 95% "
                "indicates partial coverage and warrants operator follow-up."
            ),
            severity=severity,
            status=status,
            compliance_status=compliance,
            source_system=SOURCE_SYSTEM,
            source_finding_id=f"2sv-enrollment:{context.source_system_id}",
            resource_type="GoogleWorkspace::Customer",
            resource_id=str(context.source_system_id),
            control_mappings=list(TWO_SV_ENROLLMENT_MAPPINGS),
            collection_context=context,
            raw_data={
                "active_users": n_active,
                "enrolled": len(enrolled),
                "enforced": len(enforced),
                "enrollment_rate": enrollment_rate,
                "enforcement_rate": enforcement_rate,
            },
        )

    def _login_activity_finding(
        self,
        events: list[dict[str, Any]],
        truncated: bool,
        context: CollectionContext,
    ) -> SecurityFinding:
        by_event: dict[str, int] = {}
        actors: set[str] = set()
        login_failures = 0
        suspicious = 0
        for item in events:
            actor_email = (item.get("actor") or {}).get("email")
            if actor_email:
                actors.add(actor_email)
            for event in item.get("events") or []:
                name = event.get("name")
                if not name:
                    continue
                by_event[name] = by_event.get(name, 0) + 1
                if name == "login_failure":
                    login_failures += 1
                if name in _SUSPICIOUS_EVENT_NAMES:
                    suspicious += 1

        start_time = (self._now - timedelta(days=self._login_window_days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        severity = Severity.MEDIUM if suspicious > 0 else Severity.INFORMATIONAL
        status = FindingStatus.ACTIVE if suspicious > 0 else FindingStatus.RESOLVED
        compliance = ComplianceStatus.WARNING if suspicious > 0 else ComplianceStatus.UNKNOWN

        return SecurityFinding(
            title=(
                f"Google Workspace login activity: {len(events)} event(s) "
                f"over {self._login_window_days} days, {suspicious} suspicious"
            ),
            description=(
                f"The Reports API's login activity feed returned "
                f"{len(events)} event(s) for customer {self._customer} since "
                f"{start_time} (capped at {self._max_login_events}), "
                f"covering {len(actors)} distinct actor(s) and "
                f"{login_failures} failed login(s). AU-6 evidence: "
                f"{suspicious} event(s) matched the suspicious-activity set "
                "and should be reviewed first."
            ),
            severity=severity,
            status=status,
            compliance_status=compliance,
            source_system=SOURCE_SYSTEM,
            source_finding_id=f"login-activity:{context.source_system_id}",
            resource_type="GoogleWorkspace::Customer",
            resource_id=str(context.source_system_id),
            control_mappings=list(LOGIN_ACTIVITY_MAPPINGS),
            collection_context=context,
            raw_data={
                "window_days": self._login_window_days,
                "start_time": start_time,
                "events_scanned": len(events),
                "distinct_actors": len(actors),
                "by_event": dict(sorted(by_event.items())),
                "suspicious": suspicious,
                "login_failures": login_failures,
                "max_login_events": self._max_login_events,
                "truncated": truncated,
            },
        )
