"""BitSight evidence collector — main module (v0.7.9 P0.4 third slice).

Read-only collector pulling a BitSight Security Ratings portfolio +
per-company ratings via the BitSight API
(https://api.bitsighttech.com) and emitting NIST 800-53 + OCC 2013-29
+ FRB SR 13-19 + FFIEC IT Examination Handbook Outsourcing booklet
mapped SecurityFinding objects.

Auth: BitSight uses HTTP Basic with the API token as username +
empty password. The collector constructs the
``Authorization: Basic <base64(token:)>`` header internally; the
token never appears in URLs or query params.

Pagination: BitSight returns paginated portfolio listings with
``next`` URL field on the response — when set, it's a fully-qualified
URL; the collector follows it as-is until exhaustion or hard cap.

Severity mapping: a "low rating" is a BitSight rating below the
operator-configured threshold (default 700, BitSight's "Basic"
boundary between B and C grades). The collector emits a single
MEDIUM-severity finding per low-rated company. Operators wanting
finer-grained tier-aware severity can post-process the findings
list externally.

v0.7.9 P0.4 third slice ships portfolio inventory + low-rating
flag emit. Subsequent slices add per-company factor scores +
historical rating data.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from evidentia_core.audit import (
    CollectionContext,
    CollectionManifest,
    CoverageCount,
    EventAction,
    EventOutcome,
    get_logger,
    new_run_id,
)
from evidentia_core.models.common import (
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import FindingStatus, SecurityFinding
from evidentia_core.plugins.collectors import (
    BaseSaaSCollector,
    SaaSAuthError,
    SaaSCollectorError,
    SaaSConnectionError,
    SaaSQueryError,
)

from evidentia_collectors.bitsight.mapping import (
    LOW_RATING_MAPPINGS,
    PORTFOLIO_INVENTORY_MAPPINGS,
)

if TYPE_CHECKING:
    import httpx


_log = get_logger("evidentia.collectors.bitsight")

COLLECTOR_ID = "bitsight-scan"

# BitSight API base. Override for staging / dev tenants.
DEFAULT_BASE_URL = "https://api.bitsighttech.com"

# BitSight portfolio endpoint. The portfolio is the operator's
# subscribed company list — companies BitSight is rating on the
# operator's behalf.
DEFAULT_PORTFOLIO_PATH = "/portfolio"

# BitSight ratings span 250-900. The "Basic" boundary at 700 is the
# canonical reasonable default operators use to flag "needs review."
# Operators can override per-call.
DEFAULT_LOW_RATING_THRESHOLD = 700

# Hard cap on portfolio enumeration. BitSight portfolios typically
# carry <500 companies; the cap protects against unbounded
# pagination if cursor logic encounters a malformed response.
DEFAULT_MAX_COMPANIES = 2000

DEFAULT_TIMEOUT_SECONDS = 30.0


# ── Typed exception hierarchy ──────────────────────────────────────


# v0.8.0 P0.4 / M-4: BitSightCollectorError now subclasses
# SaaSCollectorError + the three typed errors multi-inherit from
# their generic SaaS* counterparts, preserving the existing
# `pytest.raises(BitSightAuthError)` test semantics + adding the
# generic-class-hierarchy behavior so `pytest.raises(SaaSAuthError)`
# also matches.


class BitSightCollectorError(SaaSCollectorError):
    """Base class for all BitSight collector failures."""


class BitSightAuthError(BitSightCollectorError, SaaSAuthError):
    """Auth failure — 401 / 403 from the API."""


class BitSightConnectionError(BitSightCollectorError, SaaSConnectionError):
    """Network / TLS / timeout failure."""


class BitSightQueryError(BitSightCollectorError, SaaSQueryError):
    """A specific API call failed (4xx / 5xx other than auth, or a
    malformed response)."""


# ── BLIND_SPOTS list ───────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-BITSIGHT-FACTOR-SCORES-DEFERRED",
        "title": "Per-company factor scores not yet collected",
        "description": (
            "BitSight provides per-company factor scores (Botnet "
            "Infections, Spam Propagation, Malware Servers, Patching "
            "Cadence, etc.) via /v1/companies/{guid}/findings, but "
            "the v0.7.9 P0.4 third slice ships portfolio + summary "
            "rating only. Per-factor pull lands in a follow-up slice."
        ),
    },
    {
        "id": "EVIDENTIA-BITSIGHT-HISTORICAL-RATINGS",
        "title": "Historical rating trends not yet collected",
        "description": (
            "BitSight exposes historical ratings via /v1/companies/"
            "{guid}/ratings, useful for trend-detection (rating "
            "regressions over a 90-day window). The v0.7.9 P0.4 "
            "third slice surfaces only the current rating snapshot."
        ),
    },
    {
        "id": "EVIDENTIA-BITSIGHT-FIELD-SHAPE-DEFENSIVE",
        "title": "Company JSON shape parsed defensively",
        "description": (
            "The collector extracts well-known ``guid`` + ``name`` "
            "+ ``rating`` fields explicitly; everything else flows "
            "through to the SecurityFinding's ``raw_data`` field. "
            "If BitSight's API renames or restructures fields, the "
            "collector keeps producing portfolio evidence but "
            "low-rating-flag detection may not trigger until the "
            "parser is updated."
        ),
    },
    {
        "id": "EVIDENTIA-BITSIGHT-PAID-API-DEPENDENCY",
        "title": "Live testing requires paid BitSight API access",
        "description": (
            "BitSight is a commercial security-ratings provider; "
            "the API requires a paid relationship. CI uses mocked-"
            "httpx tests for collector verification. Operators "
            "must have a BitSight Enterprise subscription + API "
            "token to use this collector."
        ),
    },
]


# ── Collector ──────────────────────────────────────────────────────


class BitSightCollector(BaseSaaSCollector):
    """BitSight portfolio collector.

    Args:
        api_token: BitSight API token. Sourced from the
            ``BITSIGHT_API_TOKEN`` env var per the secret-handling
            protocol — never log or echo the token value. The
            collector encodes ``token:`` (HTTP Basic auth, empty
            password) into the request header.
        base_url: API base URL. Default
            ``https://api.bitsighttech.com``.
        max_companies: Hard cap on portfolio enumeration.
        low_rating_threshold: Companies with a rating BELOW this
            threshold get an additional MEDIUM-severity finding.
            Default 700 (BitSight's "Basic" boundary).
        timeout_seconds: HTTP connect + read timeout per request.
        client: Optional pre-configured ``httpx.Client``. When
            provided, NOT auto-closed on exit (caller-owned).

    Raises:
        BitSightAuthError: missing API token at construction time.
    """

    # v0.8.0 P0.4 / M-4: Drive BaseSaaSCollector behavior via class
    # attributes. The base handles auth-token validation, httpx
    # client lifecycle (__enter__/__exit__/_ensure_client), and
    # GET + auth/connection/query error normalization (_get).
    # BitSightCollector overrides _auth_header() for HTTP Basic and
    # adds BitSight-specific portfolio pagination + per-company
    # finding projection below.
    COLLECTOR_ID = "bitsight-scan"
    DEFAULT_BASE_URL = "https://api.bitsighttech.com"
    TOKEN_ENV_VAR = "BITSIGHT_API_TOKEN"
    DEFAULT_TIMEOUT_SECONDS = 30.0
    AUTH_ERROR_CLASS = BitSightAuthError
    CONNECTION_ERROR_CLASS = BitSightConnectionError
    QUERY_ERROR_CLASS = BitSightQueryError

    def __init__(
        self,
        *,
        api_token: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        max_companies: int = DEFAULT_MAX_COMPANIES,
        low_rating_threshold: int = DEFAULT_LOW_RATING_THRESHOLD,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        super().__init__(
            api_token=api_token,
            base_url=base_url,
            timeout_seconds=timeout_seconds,
            client=client,
        )
        self._max_companies = max_companies
        self._low_rating_threshold = low_rating_threshold

    def _auth_header(self) -> str:
        """BitSight uses HTTP Basic with token as username, empty password.

        Constructed manually rather than via httpx's BasicAuth
        helper to keep the token-handling pattern symmetric with
        the header-driven default (Bearer) — and so the token never
        materializes in a separate auth-object that downstream
        code might log.
        """
        # _api_token is non-None at this point; the base raises
        # AUTH_ERROR_CLASS in __init__ otherwise. v0.8.1 F-V08-
        # CR-8: explicit check instead of ``assert`` so the
        # invariant survives PYTHONOPTIMIZE=1 / -O deployments.
        if self._api_token is None:  # pragma: no cover - defensive
            raise self.AUTH_ERROR_CLASS(
                f"{type(self).__name__}: missing api_token"
            )
        encoded = base64.b64encode(
            f"{self._api_token}:".encode("ascii")
        ).decode("ascii")
        return f"Basic {encoded}"

    def _paginate_portfolio(self) -> list[dict[str, Any]]:
        """Walk the portfolio paginated response.

        BitSight returns ``{"results": [...], "next": "<url>" | null,
        "previous": <url> | null, "count": N}``. Follow ``next`` until
        null or hard cap.
        """
        out: list[dict[str, Any]] = []
        next_url: str | None = DEFAULT_PORTFOLIO_PATH
        while next_url:
            data = self._get(next_url)
            results = data.get("results", [])
            if not isinstance(results, list):
                raise BitSightQueryError(
                    f"BitSight API: expected `results` to be a list "
                    f"on GET {next_url}; got {type(results).__name__}"
                )
            out.extend(r for r in results if isinstance(r, dict))
            if len(out) >= self._max_companies:
                out = out[: self._max_companies]
                break
            raw_next = data.get("next")
            if not raw_next or not isinstance(raw_next, str):
                break
            # BitSight returns absolute URLs in `next`. We accept the
            # absolute form when it's same-host as the base, OR strip
            # to the path-portion to keep the request scoped to our
            # configured base_url (defensive against host-spoofing
            # in a malformed response).
            parsed = urlparse(raw_next)
            base_parsed = urlparse(self._base_url)
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                # Defensive: don't follow cross-host pagination links.
                # v0.7.11 P3 closure of v0.7.9 M-5: emit a structured
                # warning so the silent break is observable in audit
                # logs + collection manifest.
                _log.warning(
                    action=EventAction.COLLECT_ABORTED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        "BitSight cross-host pagination link refused; "
                        "stopping enumeration early."
                    ),
                    evidentia={
                        "collector_id": COLLECTOR_ID,
                        "reason": "cross_host_next_url",
                        "next_netloc": parsed.netloc,
                        "base_netloc": base_parsed.netloc,
                        "results_collected": len(out),
                    },
                )
                break
            # v0.7.9 P0.4 Continuous F-V09-S1 (CWE-319): also refuse
            # scheme-downgrade. A malicious upstream returning an
            # http://api.bitsighttech.com/... `next` URL would
            # otherwise leak the Authorization: Basic header over
            # cleartext HTTP. Keep us on the same scheme as the
            # configured base_url.
            if (
                parsed.scheme
                and base_parsed.scheme
                and parsed.scheme != base_parsed.scheme
            ):
                _log.warning(
                    action=EventAction.COLLECT_ABORTED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        "BitSight scheme-downgrade pagination link "
                        "refused; stopping enumeration early."
                    ),
                    evidentia={
                        "collector_id": COLLECTOR_ID,
                        "reason": "scheme_downgrade_next_url",
                        "next_scheme": parsed.scheme,
                        "base_scheme": base_parsed.scheme,
                        "results_collected": len(out),
                    },
                )
                break
            next_url = (
                raw_next
                if parsed.netloc
                else parsed.path
                + (f"?{parsed.query}" if parsed.query else "")
            )
        return out

    # ── public collect API ─────────────────────────────────────────

    def collect(self) -> list[SecurityFinding]:
        findings, _manifest = self.collect_v2()
        return findings

    def collect_v2(
        self,
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        run_id = new_run_id()
        context = CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity="bitsight-api-token",
            source_system_id="bitsight",
        )
        _log.info(
            action=EventAction.COLLECT_STARTED,
            outcome=EventOutcome.UNKNOWN,
            message="BitSight collection started",
            evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
        )
        findings: list[SecurityFinding] = []
        errors: list[str] = []
        scanned = 0
        try:
            companies = self._paginate_portfolio()
            scanned = len(companies)
            for c in companies:
                findings.extend(self._company_to_findings(c, context))
        except BitSightAuthError:
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message="BitSight authentication failed",
                evidentia={
                    "run_id": run_id,
                    "collector_id": COLLECTOR_ID,
                },
            )
            raise
        except (BitSightConnectionError, BitSightQueryError) as exc:
            errors.append(f"portfolio: {exc}")
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message=f"BitSight portfolio collection failed: {exc!r}",
                evidentia={
                    "run_id": run_id,
                    "collector_id": COLLECTOR_ID,
                },
                error={
                    "type": type(exc).__name__,
                    "message": str(exc),
                },
            )

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=context.collected_at,
            collection_finished_at=utc_now(),
            source_system_ids=["bitsight"],
            filters_applied={
                "max_companies": str(self._max_companies),
                "low_rating_threshold": str(self._low_rating_threshold),
            },
            coverage_counts=[
                CoverageCount(
                    resource_type="bitsight-company",
                    scanned=scanned,
                    matched_filter=scanned,
                    collected=scanned,
                ),
            ],
            total_findings=len(findings),
            is_complete=not errors,
            incomplete_reason=("; ".join(errors) if errors else None),
            empty_categories=[
                "factor_scores",  # P0.4 follow-up slice
                "historical_ratings",  # P0.4 follow-up slice
            ],
            errors=errors,
        )

        # v0.7.12 P3 closure of v0.7.9 M-3: drop over-defensive
        # contextlib.suppress wrapping on the audit logger.
        _log.info(
            action=EventAction.COLLECT_COMPLETED,
            outcome=(
                EventOutcome.SUCCESS if not errors
                else EventOutcome.UNKNOWN
            ),
            message=(
                f"BitSight collection finished: {len(findings)} "
                f"finding(s) across {scanned} company(s)"
            ),
            evidentia={
                "run_id": run_id,
                "collector_id": COLLECTOR_ID,
                "company_count": scanned,
                "finding_count": len(findings),
            },
        )

        return findings, manifest

    # ── per-company mapping ────────────────────────────────────────

    def _company_to_findings(
        self,
        company: dict[str, Any],
        context: CollectionContext,
    ) -> list[SecurityFinding]:
        guid = str(
            company.get("guid")
            or company.get("id")
            or "unknown"
        )
        name = str(
            company.get("name")
            or company.get("companyName")
            or "unknown"
        )
        rating = company.get("rating")
        # v0.7.10 P3 closure of v0.7.9 M-2: round() not int() so a
        # floating-point rating like 749.6 doesn't trunc to 749 and
        # silently fall under a 750 low-rating threshold.
        # v0.7.12 P3 closure of v0.7.9 L-8: BitSight occasionally
        # returns rating as a JSON-string (e.g., ``"750"``) rather
        # than a number. Without coercion that gets treated as
        # unrated, silently dropping a low-rating finding. Try
        # int(str)/float(str) coercion before declaring unrated.
        rating_int: int | None
        if isinstance(rating, (int, float)):
            rating_int = round(rating)
        elif isinstance(rating, str) and rating.strip():
            try:
                rating_int = round(float(rating.strip()))
            except (ValueError, TypeError):
                rating_int = None
        else:
            rating_int = None
        rating_str = (
            str(rating_int) if rating_int is not None else "unrated"
        )
        out: list[SecurityFinding] = [
            SecurityFinding(
                title=(
                    f"BitSight portfolio company: {name} "
                    f"(rating: {rating_str})"
                ),
                description=(
                    f"Company {name!r} (BitSight guid: {guid}) is "
                    f"present in the operator's BitSight portfolio. "
                    f"Current rating: {rating_str} (BitSight scale: "
                    "250-900). The full BitSight payload is "
                    "preserved in this finding's raw_data field "
                    "for cross-tool correlation; see the v0.7.9 "
                    "P0.1 evidentia tprm vendor surface for the "
                    "curated TPRM inventory."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.RESOLVED,
                source_system="bitsight",
                source_finding_id=f"company-inventory:{guid}",
                resource_type="bitsight-company",
                resource_id=guid,
                collection_context=context,
                control_mappings=PORTFOLIO_INVENTORY_MAPPINGS,
                raw_data={"bitsight_company_record": company},
            )
        ]
        if (
            rating_int is not None
            and rating_int < self._low_rating_threshold
        ):
            out.append(
                SecurityFinding(
                    title=(
                        f"BitSight low rating: {name} "
                        f"({rating_int} < {self._low_rating_threshold})"
                    ),
                    description=(
                        f"Company {name!r} (BitSight guid: {guid}) "
                        f"carries a BitSight rating of {rating_int}, "
                        f"below the configured threshold of "
                        f"{self._low_rating_threshold}. BitSight's "
                        "scale is 250-900 with grades A (740-900), "
                        "B (670-739), C (600-669), D (530-599), "
                        "F (<530). Recommended action: review "
                        "BitSight's per-factor breakdown + confirm "
                        "ongoing-monitoring cadence in the v0.7.9 "
                        "P0.1 evidentia tprm vendor record + "
                        "consider whether contractual remediation "
                        "is warranted per OCC 2013-29 §III.A.4."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.ACTIVE,
                    source_system="bitsight",
                    source_finding_id=f"company-low-rating:{guid}",
                    resource_type="bitsight-company",
                    resource_id=guid,
                    collection_context=context,
                    control_mappings=LOW_RATING_MAPPINGS,
                    raw_data={"bitsight_company_record": company},
                )
            )
        return out
