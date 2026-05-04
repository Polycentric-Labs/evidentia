"""SecurityScorecard evidence collector — main module
(v0.7.9 P0.4 fourth slice).

Read-only collector pulling SecurityScorecard portfolio companies
+ per-company score via the SecurityScorecard API
(https://api.securityscorecard.io) and emitting NIST 800-53 + OCC
2013-29 + FRB SR 13-19 + FFIEC IT Handbook Outsourcing booklet
mapped SecurityFinding objects.

Auth: SSC uses ``Authorization: Token <api_token>`` headers
(distinct from BitSight's HTTP Basic + Vanta/Drata's Bearer).
The token is sourced from ``SECURITYSCORECARD_API_TOKEN`` env
var per the secret-handling protocol; it never appears in URLs.

Pagination: SSC uses page+per_page query-param pagination with
``total_count`` + ``page_count`` in the response. The collector
walks pages until exhaustion or hard cap.

Severity mapping: a "low score" is an SSC numeric score below
the operator-configured threshold (default 70 — boundary between
C and D grades). The collector emits a single MEDIUM-severity
finding per low-scored company.

v0.7.9 P0.4 fourth slice ships portfolio inventory + low-score
flag emit. Subsequent slices add per-company factor scores +
historical grade trends.
"""

from __future__ import annotations

import contextlib
import re
from typing import Any

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

from evidentia_collectors.securityscorecard.mapping import (
    LOW_SCORE_MAPPINGS,
    PORTFOLIO_INVENTORY_MAPPINGS,
)

_log = get_logger("evidentia.collectors.securityscorecard")

COLLECTOR_ID = "securityscorecard-scan"

DEFAULT_BASE_URL = "https://api.securityscorecard.io"

# SSC scores 0-100. The C/D boundary at 70 is a reasonable
# default; operators commonly require B (80+) for tier-1
# vendors but accept C (70+) for lower-tier.
DEFAULT_LOW_SCORE_THRESHOLD = 70

# Hard cap on portfolio enumeration.
DEFAULT_MAX_COMPANIES = 2000

# Per-page count for paginated endpoints.
DEFAULT_PAGE_SIZE = 100

DEFAULT_TIMEOUT_SECONDS = 30.0


# ── Typed exception hierarchy ──────────────────────────────────────


class SecurityScorecardCollectorError(Exception):
    """Base class for all SecurityScorecard collector failures."""


class SecurityScorecardAuthError(SecurityScorecardCollectorError):
    """Auth failure — 401 / 403 from the API."""


class SecurityScorecardConnectionError(SecurityScorecardCollectorError):
    """Network / TLS / timeout failure."""


class SecurityScorecardQueryError(SecurityScorecardCollectorError):
    """A specific API call failed (4xx / 5xx other than auth, or a
    malformed response)."""


class SecurityScorecardInvalidPortfolioIdError(SecurityScorecardCollectorError):
    """Raised when a candidate portfolio_id contains characters that
    could path-traverse the SSC API URL.

    Closes v0.7.12 P0.6 / CodeQL alert #92 (`py/partial-ssrf`,
    CRITICAL): a `portfolio_id` value containing path-traversal
    segments (``..``, ``/``, etc.) flowed from the REST request body
    into ``f"/portfolios/{portfolio_id}/companies"`` at
    ``_paginate_portfolio``, which httpx then resolved against the
    SSC base URL — letting an attacker rewrite the request path.

    The validation predicate (``_PORTFOLIO_ID_RE``) accepts only
    ``[A-Za-z0-9_-]{1,128}``, which covers the MongoDB ObjectId
    24-char hex form SSC actually issues plus a defensive allowance
    for vendor-hyphenated variants. Anything else (``..``, ``/``,
    ``\\``, spaces, empty strings, leading/trailing slashes, query
    strings, fragments) trips this exception.
    """


# v0.7.12 P0.6 / CodeQL #92 closure: SSC portfolio_id allow-list.
# SSC issues 24-char MongoDB-ObjectId-style hex strings; the broader
# ``[A-Za-z0-9_-]`` character class is a defensive allowance for any
# vendor-hyphenated variants without admitting path-traversal chars.
_PORTFOLIO_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _validate_portfolio_id_shape(portfolio_id: str) -> None:
    """Reject SSC portfolio IDs that aren't shape-safe for URL interpolation.

    See :class:`SecurityScorecardInvalidPortfolioIdError` for the
    full rationale. Raises that exception on any value that does
    not match :data:`_PORTFOLIO_ID_RE`.
    """
    if not isinstance(portfolio_id, str) or not _PORTFOLIO_ID_RE.fullmatch(
        portfolio_id
    ):
        raise SecurityScorecardInvalidPortfolioIdError(
            "Invalid SecurityScorecard portfolio_id format "
            "(expected [A-Za-z0-9_-]{1,128}; got "
            f"{portfolio_id!r})"
        )


# ── BLIND_SPOTS list ───────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-SECURITYSCORECARD-FACTOR-SCORES-DEFERRED",
        "title": "Per-company factor scores not yet collected",
        "description": (
            "SecurityScorecard provides per-company factor scores "
            "(Application Security, DNS Health, Endpoint Security, "
            "Hacker Chatter, IP Reputation, Network Security, "
            "Patching Cadence, Social Engineering, etc.) via "
            "/companies/{domain}/factors, but the v0.7.9 P0.4 "
            "fourth slice ships portfolio + summary score only. "
            "Per-factor pull lands in a follow-up slice."
        ),
    },
    {
        "id": "EVIDENTIA-SECURITYSCORECARD-HISTORICAL-GRADES",
        "title": "Historical grade trends not yet collected",
        "description": (
            "SSC exposes historical grades via /companies/{domain}/"
            "history/score. The v0.7.9 P0.4 fourth slice surfaces "
            "only the current grade snapshot."
        ),
    },
    {
        "id": "EVIDENTIA-SECURITYSCORECARD-FIELD-SHAPE-DEFENSIVE",
        "title": "Company JSON shape parsed defensively",
        "description": (
            "The collector extracts well-known ``domain`` + ``name``"
            " + ``score`` + ``grade`` fields; everything else flows "
            "through to raw_data. If SSC's API renames or "
            "restructures fields, the collector keeps producing "
            "portfolio evidence but low-score-flag detection may "
            "not trigger until the parser is updated."
        ),
    },
    {
        "id": "EVIDENTIA-SECURITYSCORECARD-PAID-API-DEPENDENCY",
        "title": "Live testing requires paid SSC API access",
        "description": (
            "SecurityScorecard is a commercial security-ratings "
            "provider; the API requires a paid relationship. CI "
            "uses mocked-httpx tests for collector verification. "
            "Operators must have an SSC subscription + API token "
            "to use this collector."
        ),
    },
]


# ── Collector ──────────────────────────────────────────────────────


class SecurityScorecardCollector:
    """SecurityScorecard portfolio collector.

    Args:
        api_token: SSC API token. Sourced from the
            ``SECURITYSCORECARD_API_TOKEN`` env var per the
            secret-handling protocol.
        portfolio_id: Optional portfolio identifier. When set,
            the collector pulls only this portfolio's companies.
            When None, the collector lists portfolios first and
            pulls from the first available portfolio.
        base_url: API base URL.
        max_companies: Hard cap on portfolio enumeration.
        low_score_threshold: SSC score below which to emit a
            low-score finding. Default 70 (C/D boundary).
        timeout_seconds: HTTP connect + read timeout per request.
        client: Optional pre-configured ``httpx.Client``.

    Raises:
        SecurityScorecardAuthError: missing API token at construction.
    """

    def __init__(
        self,
        *,
        api_token: str | None = None,
        portfolio_id: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        max_companies: int = DEFAULT_MAX_COMPANIES,
        low_score_threshold: int = DEFAULT_LOW_SCORE_THRESHOLD,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        # v0.7.10 P3 closure of v0.7.9 M-1: whitespace-only tokens.
        if api_token is not None:
            api_token = api_token.strip() or None
        if not api_token and client is None:
            raise SecurityScorecardAuthError(
                "SecurityScorecardCollector requires either an "
                "api_token or a pre-configured httpx.Client. The "
                "token is sourced from the "
                "SECURITYSCORECARD_API_TOKEN env var per the "
                "secret-handling protocol."
            )
        # v0.7.12 P0.6 / CodeQL #92 closure: validate portfolio_id
        # at the trust boundary so any path-traversal attempt is
        # rejected before the URL composition at
        # `_paginate_portfolio`.
        if portfolio_id is not None:
            _validate_portfolio_id_shape(portfolio_id)
        self._api_token = api_token
        self._portfolio_id = portfolio_id
        self._base_url = base_url.rstrip("/")
        self._max_companies = max_companies
        self._low_score_threshold = low_score_threshold
        self._timeout_seconds = timeout_seconds
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> SecurityScorecardCollector:
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
            raise SecurityScorecardAuthError("missing api_token")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Token {self._api_token}",
                "Accept": "application/json",
                "User-Agent": (
                    f"evidentia-collectors/{current_version()} "
                    "(SecurityScorecardCollector; "
                    "https://github.com/allenfbyrd/evidentia)"
                ),
            },
            timeout=self._timeout_seconds,
        )
        return self._client

    # ── HTTP plumbing ──────────────────────────────────────────────

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        client = self._ensure_client()
        try:
            resp = client.get(path, params=params)
        except httpx.TimeoutException as exc:
            raise SecurityScorecardConnectionError(
                f"SecurityScorecard API timeout after "
                f"{self._timeout_seconds}s on GET {path}"
            ) from exc
        except httpx.HTTPError as exc:
            raise SecurityScorecardConnectionError(
                f"SecurityScorecard API connection failure on GET "
                f"{path}: {type(exc).__name__}"
            ) from exc
        if resp.status_code in (401, 403):
            raise SecurityScorecardAuthError(
                f"SecurityScorecard API auth failure on GET "
                f"{path}: HTTP {resp.status_code}. Verify "
                "SECURITYSCORECARD_API_TOKEN scope + expiration."
            )
        if resp.status_code >= 400:
            raise SecurityScorecardQueryError(
                f"SecurityScorecard API error on GET {path}: "
                f"HTTP {resp.status_code}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise SecurityScorecardQueryError(
                f"SecurityScorecard API returned non-JSON response "
                f"on GET {path}"
            ) from exc
        if not isinstance(data, dict):
            raise SecurityScorecardQueryError(
                f"SecurityScorecard API returned non-object JSON on "
                f"GET {path}: {type(data).__name__}"
            )
        return data

    def _resolve_portfolio_id(self) -> str:
        """Return the configured portfolio_id, or list portfolios
        and pick the first available."""
        if self._portfolio_id:
            return self._portfolio_id
        data = self._get("/portfolios")
        entries = data.get("entries", []) or data.get("portfolios", [])
        if not isinstance(entries, list) or not entries:
            raise SecurityScorecardQueryError(
                "SecurityScorecard /portfolios returned no "
                "portfolios. Either supply a portfolio_id "
                "explicitly or create a portfolio in the SSC UI."
            )
        first = entries[0]
        if not isinstance(first, dict):
            raise SecurityScorecardQueryError(
                "SecurityScorecard /portfolios returned malformed "
                "entries."
            )
        portfolio_id = first.get("id")
        if not isinstance(portfolio_id, str):
            raise SecurityScorecardQueryError(
                "SecurityScorecard portfolio entry is missing a "
                "string `id` field."
            )
        # v0.7.12 P0.6 / CodeQL #92 closure: defense-in-depth.
        # Even if the SSC API itself returns a malformed/malicious
        # portfolio_id, reject it before it's composed into the
        # `/portfolios/{portfolio_id}/companies` URL.
        _validate_portfolio_id_shape(portfolio_id)
        # v0.7.11 P3 closure of v0.7.9 M-6: emit a warning so
        # operators with multiple SSC portfolios know an arbitrary
        # one was selected. Pass --portfolio-id explicitly to
        # control the choice deterministically.
        if len(entries) > 1:
            _log.warning(
                action=EventAction.COLLECT_PAGE_FETCHED,
                outcome=EventOutcome.SUCCESS,
                message=(
                    f"SecurityScorecard portfolio_id not specified; "
                    f"auto-selected first of {len(entries)} portfolios. "
                    f"Pass --portfolio-id (CLI) or portfolio_id=... "
                    f"(library) to choose deterministically."
                ),
                evidentia={
                    "collector_id": COLLECTOR_ID,
                    "selected_portfolio_id": portfolio_id,
                    "selected_portfolio_name": first.get("name"),
                    "total_portfolios": len(entries),
                },
            )
        return portfolio_id

    def _paginate_portfolio(
        self, portfolio_id: str
    ) -> list[dict[str, Any]]:
        """Walk the portfolio companies endpoint via page+per_page."""
        out: list[dict[str, Any]] = []
        page = 1
        prev_count = 0
        while True:
            data = self._get(
                f"/portfolios/{portfolio_id}/companies",
                page=page,
                per_page=DEFAULT_PAGE_SIZE,
            )
            # v0.7.9 P0.4 Continuous H-2: explicit-key priority order
            # rather than `or`-fall-through. Falsy `[]` (legitimate
            # empty page) shouldn't fall through to alternative keys.
            if "entries" in data and isinstance(data["entries"], list):
                entries: list[Any] = data["entries"]
            elif "companies" in data and isinstance(data["companies"], list):
                entries = data["companies"]
            else:
                raise SecurityScorecardQueryError(
                    f"SecurityScorecard /portfolios/{portfolio_id}/"
                    f"companies: expected `entries` or `companies` "
                    f"to be a list; neither was present or non-list."
                )
            out.extend(e for e in entries if isinstance(e, dict))
            if len(out) >= self._max_companies:
                out = out[: self._max_companies]
                break
            # SSC pagination: total_count + page_count fields tell us
            # whether more pages exist. Default break if metadata
            # missing.
            page_count = data.get("page_count")
            if not isinstance(page_count, int) or page >= page_count:
                break
            # Defensive: if the response carried zero entries, stop
            # to avoid infinite loop on malformed metadata.
            if not entries:
                break
            # v0.7.9 P0.4 Continuous H-3: monotonic-increase guard.
            # If the API reports more pages but our running output
            # didn't grow this iteration, something's stuck — stop.
            if len(out) <= prev_count:
                break
            prev_count = len(out)
            page += 1
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
            credential_identity="securityscorecard-api-token",
            source_system_id="securityscorecard",
        )
        _log.info(
            action=EventAction.COLLECT_STARTED,
            outcome=EventOutcome.UNKNOWN,
            message="SecurityScorecard collection started",
            evidentia={
                "run_id": run_id,
                "collector_id": COLLECTOR_ID,
            },
        )
        findings: list[SecurityFinding] = []
        errors: list[str] = []
        scanned = 0
        portfolio_id: str | None = None
        try:
            portfolio_id = self._resolve_portfolio_id()
            companies = self._paginate_portfolio(portfolio_id)
            scanned = len(companies)
            for c in companies:
                findings.extend(self._company_to_findings(c, context))
        except SecurityScorecardAuthError:
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message="SecurityScorecard authentication failed",
                evidentia={
                    "run_id": run_id,
                    "collector_id": COLLECTOR_ID,
                },
            )
            raise
        except (
            SecurityScorecardConnectionError,
            SecurityScorecardQueryError,
        ) as exc:
            errors.append(f"portfolio: {exc}")
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message=(
                    f"SecurityScorecard portfolio collection "
                    f"failed: {exc!r}"
                ),
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
            source_system_ids=["securityscorecard"],
            filters_applied={
                "max_companies": str(self._max_companies),
                "low_score_threshold": str(self._low_score_threshold),
                "portfolio_id": portfolio_id or "(unresolved)",
            },
            coverage_counts=[
                CoverageCount(
                    resource_type="securityscorecard-company",
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
                "historical_grades",  # P0.4 follow-up slice
            ],
            errors=errors,
        )

        with contextlib.suppress(Exception):
            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=(
                    EventOutcome.SUCCESS if not errors
                    else EventOutcome.UNKNOWN
                ),
                message=(
                    f"SecurityScorecard collection finished: "
                    f"{len(findings)} finding(s) across "
                    f"{scanned} company(s)"
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
        domain = str(
            company.get("domain")
            or company.get("hostname")
            or company.get("id")
            or "unknown"
        )
        name = str(
            company.get("name")
            or company.get("companyName")
            or domain
        )
        score = company.get("score")
        # v0.7.10 P3 closure of v0.7.9 M-2: round() not int() so a
        # floating-point score like 69.6 doesn't trunc to 69 and
        # silently slip under a 70 low-score threshold.
        score_int = (
            round(score) if isinstance(score, (int, float)) else None
        )
        grade = company.get("grade")
        grade_str = str(grade) if grade else "ungraded"
        score_str = (
            str(score_int) if score_int is not None else "unscored"
        )
        out: list[SecurityFinding] = [
            SecurityFinding(
                title=(
                    f"SecurityScorecard portfolio company: {name} "
                    f"(score: {score_str}, grade: {grade_str})"
                ),
                description=(
                    f"Company {name!r} (SSC domain: {domain}) is "
                    f"present in the operator's SecurityScorecard "
                    f"portfolio. Current score: {score_str} "
                    f"(SSC scale: 0-100, grade: {grade_str}). The "
                    "full SSC payload is preserved in this finding's "
                    "raw_data field for cross-tool correlation; see "
                    "the v0.7.9 P0.1 evidentia tprm vendor surface "
                    "for the curated TPRM inventory."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.RESOLVED,
                source_system="securityscorecard",
                source_finding_id=f"company-inventory:{domain}",
                resource_type="securityscorecard-company",
                resource_id=domain,
                collection_context=context,
                control_mappings=PORTFOLIO_INVENTORY_MAPPINGS,
                raw_data={"securityscorecard_company_record": company},
            )
        ]
        if (
            score_int is not None
            and score_int < self._low_score_threshold
        ):
            out.append(
                SecurityFinding(
                    title=(
                        f"SecurityScorecard low score: {name} "
                        f"({score_int} < {self._low_score_threshold})"
                    ),
                    description=(
                        f"Company {name!r} (SSC domain: {domain}) "
                        f"carries a SecurityScorecard score of "
                        f"{score_int} (grade {grade_str}), below "
                        f"the configured threshold of "
                        f"{self._low_score_threshold}. SSC's scale "
                        "is 0-100 with grades A (90+), B (80-89), "
                        "C (70-79), D (60-69), F (<60). Recommended "
                        "action: review SSC's per-factor breakdown "
                        "+ confirm ongoing-monitoring cadence in "
                        "the v0.7.9 P0.1 evidentia tprm vendor "
                        "record + consider whether contractual "
                        "remediation is warranted per OCC 2013-29 "
                        "§III.A.4."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.ACTIVE,
                    source_system="securityscorecard",
                    source_finding_id=f"company-low-score:{domain}",
                    resource_type="securityscorecard-company",
                    resource_id=domain,
                    collection_context=context,
                    control_mappings=LOW_SCORE_MAPPINGS,
                    raw_data={
                        "securityscorecard_company_record": company,
                    },
                )
            )
        return out
