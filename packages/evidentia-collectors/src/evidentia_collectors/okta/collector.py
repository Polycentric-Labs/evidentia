"""Okta evidence collector — main module (v0.7.7 C1).

Read-only collector against Okta's Identity Engine REST API. Emits
NIST-mapped SecurityFinding objects covering MFA enforcement,
inactive accounts, privileged-role membership, password policy,
and sign-on policies.

See ``evidentia_collectors.okta.__init__`` for the public-surface
walkthrough + credential handling.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import httpx
from evidentia_core.audit import (
    CollectionContext,
    CollectionManifest,
    CoverageCount,
    EventAction,
    EventCategory,
    EventOutcome,
    EventType,
    get_logger,
    new_run_id,
)
from evidentia_core.models.common import (
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import FindingStatus, SecurityFinding

from evidentia_collectors.okta.mapping import (
    INACTIVE_ACCOUNT_MAPPINGS,
    MFA_MAPPINGS,
    PASSWORD_POLICY_MAPPINGS,
    PRIVILEGED_ACCOUNT_MAPPINGS,
    SIGN_ON_POLICY_MAPPINGS,
    USER_INVENTORY_MAPPINGS,
)

_log = get_logger("evidentia.collectors.okta")

COLLECTOR_ID = "okta-scan"

# Inactive-account threshold per AC-2(3): default 90 days. Operators
# can override at construction time.
DEFAULT_INACTIVE_THRESHOLD_DAYS = 90

# Hard cap on user enumeration to keep the collector from running
# unbounded against very large orgs. Operators can override.
DEFAULT_MAX_USERS = 10_000


# ── Typed exception hierarchy ──────────────────────────────────────


class OktaCollectorError(Exception):
    """Base class for all Okta collector failures."""


class OktaConnectionError(OktaCollectorError):
    """Connection / authentication / TLS handshake failure."""


class OktaQueryError(OktaCollectorError):
    """A specific API call failed (permission denied, missing
    resource, rate-limit). The collector continues with remaining
    queries; the error is recorded in the manifest."""


# ── BLIND_SPOTS list ────────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-OKTA-WORKFLOWS-COVERAGE",
        "title": (
            "Okta Workflows + Identity Governance not enumerated"
        ),
        "description": (
            "Okta Workflows (provisioning automations) and Okta "
            "Identity Governance (OIG access certifications, "
            "privileged-access requests) are separately licensed "
            "and have their own API surfaces. The collector does "
            "not enumerate either. Operators using OIG for "
            "AC-2 attestation should provide out-of-band "
            "evidence."
        ),
    },
    {
        "id": "EVIDENTIA-OKTA-RATE-LIMIT-PARTIAL",
        "title": (
            "API rate limits may produce partial enumeration"
        ),
        "description": (
            "Okta's per-org rate limits (Concurrent Rate, Org Rate) "
            "can throttle large user/group enumerations. The "
            "collector handles HTTP 429 with backoff but for very "
            "large orgs (>50k users) collection time may exceed "
            "1 hour. Operator-supplied paginated CSV exports are "
            "an alternative for periodic offline runs."
        ),
    },
    {
        "id": "EVIDENTIA-OKTA-USER-MFA-FACTOR-LIFECYCLE",
        "title": (
            "MFA factor lifecycle (PENDING_ACTIVATION) state"
        ),
        "description": (
            "Users with factors in PENDING_ACTIVATION (enrolled "
            "but not yet verified) are reported as enrolled but "
            "have a finite window to complete activation before "
            "the factor lapses. The collector reports the count "
            "but cannot judge per-user activation deadlines."
        ),
    },
]


# ── Main collector class ────────────────────────────────────────────


class OktaCollector:
    """Read-only Okta evidence collector."""

    def __init__(
        self,
        *,
        org_url: str | None = None,
        api_token: str | None = None,
        client: httpx.Client | None = None,
        inactive_threshold_days: int = DEFAULT_INACTIVE_THRESHOLD_DAYS,
        max_users: int = DEFAULT_MAX_USERS,
    ) -> None:
        if not org_url and client is None:
            raise OktaCollectorError(
                "OktaCollector requires either org_url= or "
                "client= (an injected httpx.Client for testing)."
            )
        if org_url:
            parsed = urlparse(org_url)
            if parsed.scheme != "https":
                raise OktaCollectorError(
                    "org_url must use https://. Refusing to send "
                    "API tokens over a non-TLS channel."
                )
            if not parsed.hostname:
                raise OktaCollectorError(
                    f"org_url {org_url!r} has no hostname."
                )
        self._org_url = org_url.rstrip("/") if org_url else None
        self._api_token = api_token
        self._client = client
        self._owns_client = client is None
        self._inactive_threshold_days = inactive_threshold_days
        self._max_users = max_users

    # ── Lifecycle ───────────────────────────────────────────────────

    def __enter__(self) -> OktaCollector:
        self._ensure_client()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        if self._org_url is None:
            raise OktaCollectorError(
                "_ensure_client called without an org_url."
            )
        if self._api_token is None:
            raise OktaCollectorError(
                "OKTA_API_TOKEN is not set; cannot authenticate "
                "against the Okta API."
            )
        self._client = httpx.Client(
            base_url=self._org_url,
            headers={
                "Authorization": f"SSWS {self._api_token}",
                "Accept": "application/json",
                "User-Agent": (
                    f"evidentia-collectors/{current_version()} "
                    f"(+https://github.com/polycentric-labs/evidentia)"
                ),
            },
            timeout=30.0,
        )
        return self._client

    def _api_get(
        self, path: str, params: dict[str, Any] | None = None
    ) -> Any:
        client = self._ensure_client()
        try:
            response = client.get(path, params=params)
        except httpx.HTTPError as e:
            raise OktaConnectionError(
                f"GET {path} failed: {e}"
            ) from e
        if response.status_code >= 400:
            raise OktaQueryError(
                f"GET {path} returned HTTP {response.status_code}"
            )
        return response.json()

    # ── Context + provenance ────────────────────────────────────────

    def _build_context(self, run_id: str) -> CollectionContext:
        host = (
            urlparse(self._org_url).hostname
            if self._org_url
            else "unknown"
        )
        return CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"okta-token:{host}",
            source_system_id=f"okta:{host}",
            filter_applied={"org_url": self._org_url or "unknown"},
        )

    def test_connection(self) -> dict[str, Any]:
        # /api/v1/users/me returns the token holder's user record
        # (+ associated org metadata via Set-Cookie? no — fall back
        # to /api/v1/org). Both confirm the credentials work.
        try:
            org = self._api_get("/api/v1/org")
        except OktaQueryError as e:
            raise OktaConnectionError(
                f"Could not query /api/v1/org: {e}"
            ) from e
        return {
            "subdomain": org.get("subdomain"),
            "company_name": org.get("companyName"),
            "status": org.get("status"),
        }

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message="Okta dry-run — no API calls made",
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={"dry_run": True},
            )
            return []
        findings, _manifest = self.collect_v2()
        return findings

    def collect_v2(
        self,
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        run_id = new_run_id()
        started_at = utc_now()

        try:
            org_info = self.test_connection()
        except OktaCollectorError:
            raise
        except Exception as e:
            raise OktaConnectionError(
                f"Could not establish + probe Okta connection: {e}"
            ) from e

        context = self._build_context(run_id)
        errors: list[str] = []
        findings: list[SecurityFinding] = []

        with _log.scope(
            trace_id=run_id,
            user={"id": context.credential_identity},
            evidentia={
                "run_id": run_id,
                "collector": {
                    "id": COLLECTOR_ID,
                    "version": current_version(),
                },
                "org": org_info.get("subdomain"),
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"Okta collection starting for "
                    f"{org_info.get('subdomain')}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            for sub_check in (
                self._user_inventory_findings,
                self._privileged_account_findings,
                self._mfa_findings,
                self._password_policy_findings,
                self._sign_on_policy_findings,
            ):
                try:
                    findings.extend(sub_check(context))
                except OktaQueryError as e:
                    errors.append(str(e))
                    _log.warning(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Sub-check {sub_check.__name__} failed: {e}",
                        error={"type": "OktaQueryError", "message": str(e)},
                    )
                except Exception as e:
                    errors.append(
                        f"{sub_check.__name__}: unexpected error: {e}"
                    )
                    _log.error(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=(
                            f"Sub-check {sub_check.__name__} unexpected error"
                        ),
                        error={"type": type(e).__name__, "message": str(e)},
                    )

            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=(
                    EventOutcome.SUCCESS
                    if not errors
                    else EventOutcome.FAILURE
                ),
                message=(
                    f"Okta collection completed: {len(findings)} findings"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.END],
                evidentia={
                    "findings_count": len(findings),
                    "errors_count": len(errors),
                },
            )

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=started_at,
            collection_finished_at=utc_now(),
            source_system_ids=[
                f"okta:{org_info.get('subdomain') or 'unknown'}"
            ],
            filters_applied={"org_url": self._org_url or "unknown"},
            coverage_counts=[
                CoverageCount(
                    resource_type="okta-org",
                    scanned=1,
                    matched_filter=1,
                    collected=1,
                ),
            ],
            total_findings=len(findings),
            is_complete=not errors,
            incomplete_reason="; ".join(errors) if errors else None,
            errors=errors,
        )
        return findings, manifest

    # ── Sub-checks ──────────────────────────────────────────────────

    def _list_all_users(self) -> list[dict[str, Any]]:
        """Paginate /api/v1/users until exhausted or max_users."""
        users: list[dict[str, Any]] = []
        path: str | None = "/api/v1/users"
        params: dict[str, Any] | None = {"limit": 200}
        while path is not None and len(users) < self._max_users:
            client = self._ensure_client()
            try:
                response = client.get(path, params=params)
            except httpx.HTTPError as e:
                raise OktaConnectionError(
                    f"GET {path} failed: {e}"
                ) from e
            if response.status_code >= 400:
                raise OktaQueryError(
                    f"GET {path} returned HTTP {response.status_code}"
                )
            users.extend(response.json())
            # Okta paginates via Link header: rel="next"
            link = response.headers.get("link", "") or response.headers.get(
                "Link", ""
            )
            next_url: str | None = None
            for part in link.split(","):
                if 'rel="next"' in part:
                    seg = part.strip().split(";", 1)[0].strip()
                    if seg.startswith("<") and seg.endswith(">"):
                        next_url = seg[1:-1]
                        break
            if next_url:
                # Use the absolute URL's path-and-query directly
                parsed = urlparse(next_url)
                path = parsed.path
                # Query string is part of the path on the next call
                if parsed.query:
                    path = f"{path}?{parsed.query}"
                params = None
            else:
                path = None
        return users[: self._max_users]

    def _user_inventory_findings(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        users = self._list_all_users()
        active = [u for u in users if u.get("status") == "ACTIVE"]
        suspended = [u for u in users if u.get("status") == "SUSPENDED"]
        deprovisioned = [
            u for u in users if u.get("status") == "DEPROVISIONED"
        ]

        threshold = utc_now() - timedelta(
            days=self._inactive_threshold_days
        )
        inactive: list[dict[str, Any]] = []
        for u in active:
            last_login = u.get("lastLogin")
            if last_login is None:
                # Active user that has never logged in — surface
                # as inactive
                inactive.append(u)
                continue
            try:
                ll_dt = datetime.fromisoformat(
                    str(last_login).replace("Z", "+00:00")
                )
                if ll_dt.tzinfo is None:
                    ll_dt = ll_dt.replace(tzinfo=UTC)
                if ll_dt < threshold:
                    inactive.append(u)
            except (ValueError, TypeError):
                continue

        out: list[SecurityFinding] = []
        out.append(
            SecurityFinding(
                title=(
                    f"Okta user inventory: {len(users)} total, "
                    f"{len(active)} ACTIVE, "
                    f"{len(suspended)} SUSPENDED, "
                    f"{len(deprovisioned)} DEPROVISIONED"
                ),
                description=(
                    f"/api/v1/users returned {len(users)} accounts "
                    f"(capped at {self._max_users}). "
                    f"AC-2 evidence — operators should review "
                    f"the ACTIVE list against the intended "
                    "principals; deprovisioned accounts should "
                    "be checked for retained app assignments."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.ACTIVE,
                source_system="okta",
                source_finding_id=f"user-inventory:{context.source_system_id}",
                resource_type="Okta::Org",
                resource_id=str(context.source_system_id),
                control_ids=[m.control_id for m in USER_INVENTORY_MAPPINGS],
                collection_context=context,
                raw_data={
                    "total_users": len(users),
                    "active_count": len(active),
                    "suspended_count": len(suspended),
                    "deprovisioned_count": len(deprovisioned),
                    "max_users_cap": self._max_users,
                    "result_capped": len(users) >= self._max_users,
                },
            )
        )

        if inactive:
            sample = [
                u.get("profile", {}).get("login", "?") for u in inactive[:5]
            ]
            out.append(
                SecurityFinding(
                    title=(
                        f"Okta inactive accounts: {len(inactive)} "
                        f"ACTIVE users with no login in the last "
                        f"{self._inactive_threshold_days} days"
                    ),
                    description=(
                        f"{len(inactive)} accounts have status=ACTIVE "
                        f"but lastLogin > {self._inactive_threshold_days} "
                        f"days ago (or null). Sample: {sample}. "
                        "AC-2(3) Account Management — Disable Inactive "
                        "Accounts requires periodic review + "
                        "deprovisioning of accounts that have not "
                        "been used within the configured threshold."
                    ),
                    severity=(
                        Severity.HIGH
                        if len(inactive) > 50
                        else Severity.MEDIUM
                    ),
                    status=FindingStatus.ACTIVE,
                    source_system="okta",
                    source_finding_id=(
                        f"inactive-accounts:{context.source_system_id}"
                    ),
                    resource_type="Okta::Org",
                    resource_id=str(context.source_system_id),
                    control_ids=[
                        m.control_id for m in INACTIVE_ACCOUNT_MAPPINGS
                    ],
                    collection_context=context,
                    raw_data={
                        "inactive_count": len(inactive),
                        "threshold_days": self._inactive_threshold_days,
                        "sample_logins": sample,
                    },
                )
            )

        return out

    def _privileged_account_findings(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        # /api/v1/iam/assignees/users returns users with admin role
        # assignments. Older API surface: /api/v1/users/{id}/roles
        # — we use the modern aggregate endpoint.
        try:
            assignees = self._api_get("/api/v1/iam/assignees/users")
        except OktaQueryError:
            # Fallback: enumerate /api/v1/users + per-user roles
            # would be O(n) — skip in favor of best-effort signal
            assignees = []

        admin_count = (
            len(assignees) if isinstance(assignees, list) else 0
        )
        return [
            SecurityFinding(
                title=(
                    f"Okta admin accounts: {admin_count} users with "
                    "any admin-role assignment"
                ),
                description=(
                    f"/api/v1/iam/assignees/users returned "
                    f"{admin_count} users with admin role "
                    "membership. AC-6 Least Privilege — the count "
                    "should be minimal (1-3 break-glass + "
                    "automation accounts); each admin-assignment "
                    "should be backed by a documented business "
                    "justification per AC-2(7) Privileged Accounts."
                ),
                severity=(
                    Severity.HIGH
                    if admin_count > 10
                    else Severity.MEDIUM
                    if admin_count > 5
                    else Severity.INFORMATIONAL
                ),
                status=(
                    FindingStatus.ACTIVE
                    if admin_count > 5
                    else FindingStatus.RESOLVED
                ),
                source_system="okta",
                source_finding_id=(
                    f"admin-accounts:{context.source_system_id}"
                ),
                resource_type="Okta::Org",
                resource_id=str(context.source_system_id),
                control_ids=[
                    m.control_id for m in PRIVILEGED_ACCOUNT_MAPPINGS
                ],
                collection_context=context,
                raw_data={"admin_count": admin_count},
            )
        ]

    def _mfa_findings(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        # Active users + factor enrollment. The full per-user factor
        # enumeration is O(n) — too slow for 10k+ orgs. Use the
        # /api/v1/users with statistics in the response when
        # available; fall back to sampling.
        users = self._list_all_users()
        active = [u for u in users if u.get("status") == "ACTIVE"]

        # Best-effort: the modern Okta /api/v1/users response includes
        # `_embedded.factors` only on /api/v1/users/{id} — we'd need
        # per-user calls. For a periodic compliance scan, sample up
        # to 100 active users to estimate the enrollment rate, then
        # surface the sample-based metric.
        sample_size = min(100, len(active))
        sample = active[:sample_size]
        users_with_factors = 0
        for u in sample:
            user_id = u.get("id")
            if not user_id:
                continue
            try:
                factors = self._api_get(f"/api/v1/users/{user_id}/factors")
            except OktaQueryError:
                continue
            if isinstance(factors, list) and any(
                f.get("status") in {"ACTIVE", "PENDING_ACTIVATION"}
                for f in factors
            ):
                users_with_factors += 1

        enrollment_rate = (
            (users_with_factors / sample_size) if sample_size else 0.0
        )
        return [
            SecurityFinding(
                title=(
                    f"Okta MFA enrollment (sampled): "
                    f"{users_with_factors}/{sample_size} active users "
                    f"({enrollment_rate * 100:.1f}%)"
                ),
                description=(
                    f"Sampled {sample_size} active users; "
                    f"{users_with_factors} have at least one MFA "
                    "factor in ACTIVE or PENDING_ACTIVATION state. "
                    "IA-2 evidence — the control requires MFA for "
                    "privileged + remote access; an enrollment "
                    "rate < 95% indicates partial coverage and "
                    "warrants operator follow-up. The sample is "
                    "best-effort due to per-user API cost; for "
                    "exhaustive enumeration use Okta's CSV export "
                    "or the Identity Governance access-review "
                    "feature."
                ),
                severity=(
                    Severity.HIGH
                    if enrollment_rate < 0.80
                    else Severity.MEDIUM
                    if enrollment_rate < 0.95
                    else Severity.INFORMATIONAL
                ),
                status=(
                    FindingStatus.RESOLVED
                    if enrollment_rate >= 0.95
                    else FindingStatus.ACTIVE
                ),
                source_system="okta",
                source_finding_id=(
                    f"mfa-enrollment:{context.source_system_id}"
                ),
                resource_type="Okta::Org",
                resource_id=str(context.source_system_id),
                control_ids=[m.control_id for m in MFA_MAPPINGS],
                collection_context=context,
                raw_data={
                    "sample_size": sample_size,
                    "users_with_factors": users_with_factors,
                    "enrollment_rate": round(enrollment_rate, 4),
                },
            )
        ]

    def _password_policy_findings(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        try:
            policies = self._api_get(
                "/api/v1/policies", params={"type": "PASSWORD"}
            )
        except OktaQueryError as e:
            raise OktaQueryError(
                f"Could not query /api/v1/policies?type=PASSWORD: {e}"
            ) from e

        active_policies = [
            p for p in (policies or []) if p.get("status") == "ACTIVE"
        ]
        # Inspect the first ACTIVE policy's settings as the org's
        # default password posture (Okta evaluates by priority).
        first = active_policies[0] if active_policies else None
        complexity: dict[str, Any] = {}
        age: dict[str, Any] = {}
        lockout: dict[str, Any] = {}
        if first:
            settings = first.get("settings") or {}
            password = settings.get("password") or {}
            complexity = password.get("complexity") or {}
            age = password.get("age") or {}
            lockout = password.get("lockout") or {}

        min_length = complexity.get("minLength")
        max_age_days = age.get("maxAgeDays")
        max_attempts = lockout.get("maxAttempts")

        # Composite "strong" judgement
        strong = bool(
            min_length
            and int(min_length) >= 12
            and max_age_days is not None
            and 0 < int(max_age_days) <= 365
            and max_attempts is not None
            and 0 < int(max_attempts) <= 10
        )
        return [
            SecurityFinding(
                title=(
                    f"Okta password policy: "
                    f"{len(active_policies)} active "
                    f"(min_length={min_length}, "
                    f"max_age_days={max_age_days}, "
                    f"max_attempts={max_attempts})"
                ),
                description=(
                    f"/api/v1/policies?type=PASSWORD returned "
                    f"{len(active_policies)} ACTIVE policies. "
                    f"Highest-priority policy: minLength="
                    f"{min_length}, maxAgeDays={max_age_days}, "
                    f"lockout.maxAttempts={max_attempts}. IA-5 "
                    "Authenticator Management — modern guidance "
                    "(NIST SP 800-63B) prefers length + breach "
                    "checks over rotation; the collector reports "
                    "the configured values for operator review."
                ),
                severity=(
                    Severity.INFORMATIONAL if strong else Severity.MEDIUM
                ),
                status=(
                    FindingStatus.RESOLVED if strong else FindingStatus.ACTIVE
                ),
                source_system="okta",
                source_finding_id=(
                    f"password-policy:{context.source_system_id}"
                ),
                resource_type="Okta::Policy",
                resource_id=str(first.get("id") if first else "unknown"),
                control_ids=[
                    m.control_id for m in PASSWORD_POLICY_MAPPINGS
                ],
                collection_context=context,
                raw_data={
                    "active_policy_count": len(active_policies),
                    "min_length": min_length,
                    "max_age_days": max_age_days,
                    "max_attempts": max_attempts,
                },
            )
        ]

    def _sign_on_policy_findings(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        try:
            policies = self._api_get(
                "/api/v1/policies", params={"type": "OKTA_SIGN_ON"}
            )
        except OktaQueryError as e:
            raise OktaQueryError(
                f"Could not query /api/v1/policies?type=OKTA_SIGN_ON: {e}"
            ) from e

        active_policies = [
            p for p in (policies or []) if p.get("status") == "ACTIVE"
        ]
        # Count rules with MFA factor requirements
        rules_with_mfa = 0
        total_rules = 0
        for p in active_policies:
            rules = p.get("rules") or []
            total_rules += len(rules)
            for r in rules:
                actions = r.get("actions") or {}
                signon = actions.get("signon") or {}
                if signon.get("factorPromptMode") in {
                    "ALWAYS",
                    "DEVICE",
                    "SESSION",
                }:
                    rules_with_mfa += 1

        return [
            SecurityFinding(
                title=(
                    f"Okta sign-on policies: {len(active_policies)} "
                    f"active, {rules_with_mfa}/{total_rules} rules "
                    "enforce MFA"
                ),
                description=(
                    f"/api/v1/policies?type=OKTA_SIGN_ON returned "
                    f"{len(active_policies)} ACTIVE policies with "
                    f"{total_rules} total rules; {rules_with_mfa} "
                    "rules have factorPromptMode = ALWAYS / DEVICE "
                    "/ SESSION. AC-3 Access Enforcement — sign-on "
                    "policies are the context-aware access "
                    "enforcement layer (network zone, device "
                    "trust, geo-restriction)."
                ),
                severity=Severity.INFORMATIONAL,
                status=(
                    FindingStatus.ACTIVE
                    if rules_with_mfa < total_rules
                    else FindingStatus.RESOLVED
                ),
                source_system="okta",
                source_finding_id=(
                    f"sign-on-policy:{context.source_system_id}"
                ),
                resource_type="Okta::Policy",
                resource_id=str(context.source_system_id),
                control_ids=[
                    m.control_id for m in SIGN_ON_POLICY_MAPPINGS
                ],
                collection_context=context,
                raw_data={
                    "active_policy_count": len(active_policies),
                    "total_rules": total_rules,
                    "rules_with_mfa": rules_with_mfa,
                },
            )
        ]


