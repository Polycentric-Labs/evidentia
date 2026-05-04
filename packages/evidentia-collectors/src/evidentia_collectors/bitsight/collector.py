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
import contextlib
from typing import Any
from urllib.parse import urlparse

import httpx
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

from evidentia_collectors.bitsight.mapping import (
    LOW_RATING_MAPPINGS,
    PORTFOLIO_INVENTORY_MAPPINGS,
)

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


class BitSightCollectorError(Exception):
    """Base class for all BitSight collector failures."""


class BitSightAuthError(BitSightCollectorError):
    """Auth failure — 401 / 403 from the API."""


class BitSightConnectionError(BitSightCollectorError):
    """Network / TLS / timeout failure."""


class BitSightQueryError(BitSightCollectorError):
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


class BitSightCollector:
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
        # v0.7.10 P3 closure of v0.7.9 M-1: whitespace-only tokens.
        if api_token is not None:
            api_token = api_token.strip() or None
        if not api_token and client is None:
            raise BitSightAuthError(
                "BitSightCollector requires either an api_token or a "
                "pre-configured httpx.Client. The token is sourced "
                "from the BITSIGHT_API_TOKEN env var per the secret-"
                "handling protocol."
            )
        self._api_token = api_token
        self._base_url = base_url.rstrip("/")
        self._max_companies = max_companies
        self._low_rating_threshold = low_rating_threshold
        self._timeout_seconds = timeout_seconds
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> BitSightCollector:
        return self

    def __exit__(self, *exc: object) -> None:
        if self._owns_client and self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        if self._api_token is None:
            raise BitSightAuthError("missing api_token")
        # BitSight uses HTTP Basic with the token as username + empty
        # password. We construct the header manually because httpx's
        # auth=BasicAuth(...) helper would also work but constructing
        # the header keeps the token-handling pattern symmetric with
        # Vanta + Drata (header-driven, not auth-helper-driven).
        encoded = base64.b64encode(
            f"{self._api_token}:".encode("ascii")
        ).decode("ascii")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Basic {encoded}",
                "Accept": "application/json",
                "User-Agent": (
                    f"evidentia-collectors/{current_version()} "
                    "(BitSightCollector; "
                    "https://github.com/allenfbyrd/evidentia)"
                ),
            },
            timeout=self._timeout_seconds,
        )
        return self._client

    # ── HTTP plumbing ──────────────────────────────────────────────

    def _get(self, path_or_url: str, **params: Any) -> dict[str, Any]:
        """GET + JSON-decode + auth/connection error normalization.

        Accepts either a relative path (e.g. ``/portfolio``) or an
        absolute URL (e.g. the ``next`` field from a paginated
        response). When given an absolute URL on the same host as
        the configured base, the ``next``-following honors the
        cursor BitSight already encoded server-side.
        """
        client = self._ensure_client()
        try:
            resp = client.get(path_or_url, params=params)
        except httpx.TimeoutException as exc:
            raise BitSightConnectionError(
                f"BitSight API timeout after {self._timeout_seconds}s "
                f"on GET {path_or_url}"
            ) from exc
        except httpx.HTTPError as exc:
            raise BitSightConnectionError(
                f"BitSight API connection failure on GET "
                f"{path_or_url}: {type(exc).__name__}"
            ) from exc
        if resp.status_code in (401, 403):
            raise BitSightAuthError(
                f"BitSight API auth failure on GET {path_or_url}: "
                f"HTTP {resp.status_code}. Verify "
                "BITSIGHT_API_TOKEN scope + expiration."
            )
        if resp.status_code >= 400:
            raise BitSightQueryError(
                f"BitSight API error on GET {path_or_url}: "
                f"HTTP {resp.status_code}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise BitSightQueryError(
                f"BitSight API returned non-JSON response on GET "
                f"{path_or_url}"
            ) from exc
        if not isinstance(data, dict):
            raise BitSightQueryError(
                f"BitSight API returned non-object JSON on GET "
                f"{path_or_url}: {type(data).__name__}"
            )
        return data

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
        rating_int = (
            round(rating) if isinstance(rating, (int, float)) else None
        )
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
