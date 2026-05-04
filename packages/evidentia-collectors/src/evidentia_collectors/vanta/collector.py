"""Vanta evidence collector — main module (v0.7.9 P0.4 first slice).

Read-only collector that pulls a Vanta-managed vendor inventory via
the Vanta Public API (https://api.vanta.com) and emits NIST 800-53
+ OCC 2013-29 + FRB SR 13-19 + FFIEC Vendor Management mapped
SecurityFinding objects. See `evidentia_collectors.vanta.__init__`
for the public-surface walkthrough + credential handling protocol.

Mirrors the v0.7.7 Okta + v0.7.8 Snowflake collector pattern:

- Typed exception hierarchy (``VantaCollectorError`` /
  ``VantaAuthError`` / ``VantaConnectionError`` / ``VantaQueryError``)
- ``CollectionContext`` threaded through every emitted finding
- ``CollectionManifest`` returned by ``collect_v2()`` for completeness
  attestation
- ECS-structured audit logging via
  ``evidentia_core.audit.get_logger("evidentia.collectors.vanta")``
- Explicit ``BLIND_SPOTS`` list documenting coverage gaps
- httpx-based REST client (no Vanta SDK dep — ``httpx>=0.27`` is
  already a base dep of evidentia-collectors)

v0.7.9 P0.4 first slice ships the foundational scaffolding + ONE
complete evidence source (Vanta vendor inventory). Subsequent
slices in the v0.7.9 cycle will add Vanta control-test evidence,
ongoing-monitoring posture changes, and the other 3 vendor-risk
collectors (Drata / BitSight / SecurityScorecard) following the
same pattern.

Defensive parsing: Vanta's Public API field shapes are documented at
https://developer.vanta.com/ but field names + nesting can vary by
API version. The collector treats every JSON field other than
``id`` + ``name`` as Optional, passes the full per-vendor JSON dict
through to the SecurityFinding's ``metadata`` field unchanged so
operators get the full Vanta payload + the collector keeps working
even if the API adds or renames fields.
"""

from __future__ import annotations

import contextlib
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

from evidentia_collectors.vanta.mapping import (
    VENDOR_HIGH_RISK_MAPPINGS,
    VENDOR_INVENTORY_MAPPINGS,
)

_log = get_logger("evidentia.collectors.vanta")

COLLECTOR_ID = "vanta-scan"

# Default Vanta Public API base URL. Override via the ``base_url``
# constructor argument for staging / dev tenants.
DEFAULT_BASE_URL = "https://api.vanta.com"

# Hard cap on vendor enumeration. Vanta orgs typically have <500
# vendors; the cap protects against accidental unbounded
# pagination if the cursor-loop logic encounters a malformed
# response. Operators with >2000 vendors should override.
DEFAULT_MAX_VENDORS = 2000

# Per-page count for paginated endpoints. Vanta's documented
# upper-bound is 100; the collector requests this to minimize
# request count.
DEFAULT_PAGE_SIZE = 100

# Connect + read timeout (seconds). Vanta's API is generally fast;
# 30s default leaves headroom for slow regions without making
# transient failures hang.
DEFAULT_TIMEOUT_SECONDS = 30.0


# ── Typed exception hierarchy ──────────────────────────────────────


class VantaCollectorError(Exception):
    """Base class for all Vanta collector failures."""


class VantaAuthError(VantaCollectorError):
    """Authentication / authorization failure — 401 / 403 from the API.

    Distinguished from query errors so callers can surface a clear
    'check your VANTA_API_TOKEN' message rather than a generic
    'something went wrong' message.
    """


class VantaConnectionError(VantaCollectorError):
    """Network / TLS / timeout failure — could not reach api.vanta.com."""


class VantaQueryError(VantaCollectorError):
    """A specific API call failed (4xx / 5xx other than auth, or a
    malformed response). Surfaced inside ``collect_v2`` and recorded
    in the manifest's ``errors`` list rather than failing the whole
    collection — partial evidence is more useful than no evidence.
    """


# ── BLIND_SPOTS list ───────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-VANTA-CONTROL-TESTS-DEFERRED",
        "title": (
            "Vanta control test results not yet collected"
        ),
        "description": (
            "Vanta's per-control test evidence (the SOC-2-readiness "
            "signal that drives most operators' Vanta usage) is "
            "exposed via /v1/controls + /v1/control-tests but is NOT "
            "enumerated in the v0.7.9 P0.4 first slice. The collector "
            "ships vendor-inventory only; control test pull-in lands "
            "in a follow-up slice."
        ),
    },
    {
        "id": "EVIDENTIA-VANTA-OAUTH-CLIENT-CREDENTIALS",
        "title": (
            "OAuth 2.0 client-credentials flow not yet implemented"
        ),
        "description": (
            "The collector authenticates via static Bearer token "
            "(Personal Access Token or pre-acquired OAuth access "
            "token). The full OAuth 2.0 client-credentials grant "
            "(token exchange + automatic refresh) lands in a "
            "follow-up slice. Operators using OAuth today should "
            "supply a pre-acquired access token via the env var."
        ),
    },
    {
        "id": "EVIDENTIA-VANTA-WEBHOOK-EVENTS",
        "title": (
            "Vanta webhook event ingestion not implemented"
        ),
        "description": (
            "Vanta supports webhook subscriptions for vendor + control "
            "state changes (push model). The collector is pull-only "
            "in v0.7.9 P0.4 first slice. Webhook ingestion would be "
            "a separate v0.8.x feature once the API surface for "
            "receiving + verifying webhook signatures lands in "
            "evidentia-api."
        ),
    },
    {
        "id": "EVIDENTIA-VANTA-FIELD-SHAPE-DEFENSIVE",
        "title": (
            "Vendor JSON shape parsed defensively"
        ),
        "description": (
            "The collector extracts only the well-known ``id`` + "
            "``name`` fields explicitly; everything else is "
            "passed through to the SecurityFinding's ``metadata`` "
            "field as-is. If Vanta's API renames or restructures "
            "fields, the collector keeps producing inventory "
            "evidence but specific field-derived signals (e.g., "
            "Vanta's risk-tier flag → high-risk-finding upgrade) "
            "may not trigger until the parser is updated."
        ),
    },
]


# ── Collector ──────────────────────────────────────────────────────


class VantaCollector:
    """Vanta vendor-inventory collector.

    Args:
        api_token: Vanta API token. Either a Personal Access Token
            (developer / scripting use) or an OAuth 2.0 access
            token pre-acquired via client-credentials grant. Both
            pass ``Authorization: Bearer <token>``. Sourced from
            the ``VANTA_API_TOKEN`` env var per the secret-handling
            protocol — never log or echo the token value.
        base_url: API base URL. Default
            ``https://api.vanta.com``. Override for staging /
            dev tenants.
        max_vendors: Hard cap on vendor enumeration; defaults to
            :data:`DEFAULT_MAX_VENDORS`. Operators with very large
            inventories should override; operators wanting a
            preview run can set this lower.
        timeout_seconds: HTTP connect + read timeout per request.
            Default :data:`DEFAULT_TIMEOUT_SECONDS`.
        client: Optional pre-configured ``httpx.Client``. When
            provided, the collector does NOT close it on exit
            (caller-owned). When None, the collector creates +
            owns its own client.

    Raises:
        VantaAuthError: missing API token at construction time.
    """

    def __init__(
        self,
        *,
        api_token: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        max_vendors: int = DEFAULT_MAX_VENDORS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        client: httpx.Client | None = None,
    ) -> None:
        if not api_token and client is None:
            raise VantaAuthError(
                "VantaCollector requires either an api_token or a "
                "pre-configured httpx.Client. The token is sourced "
                "from the VANTA_API_TOKEN env var per the secret-"
                "handling protocol."
            )
        self._api_token = api_token
        self._base_url = base_url.rstrip("/")
        self._max_vendors = max_vendors
        self._timeout_seconds = timeout_seconds
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> VantaCollector:
        return self

    def __exit__(self, *exc: object) -> None:
        if self._owns_client and self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        # Caller-owned construction: build an httpx.Client with the
        # bearer token + base URL. The token never appears in logs
        # because we use httpx's auth-header injection, not a URL
        # query parameter.
        if self._api_token is None:  # defensive — checked in __init__
            raise VantaAuthError("missing api_token")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_token}",
                "Accept": "application/json",
                "User-Agent": (
                    f"evidentia-collectors/{current_version()} "
                    "(VantaCollector; https://github.com/allenfbyrd/evidentia)"
                ),
            },
            timeout=self._timeout_seconds,
        )
        return self._client

    # ── HTTP plumbing ──────────────────────────────────────────────

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        """GET + JSON-decode + auth/connection error normalization."""
        client = self._ensure_client()
        try:
            resp = client.get(path, params=params)
        except httpx.TimeoutException as exc:
            raise VantaConnectionError(
                f"Vanta API timeout after {self._timeout_seconds}s "
                f"on GET {path}"
            ) from exc
        except httpx.HTTPError as exc:
            # Network / TLS / DNS / connection-refused etc.
            raise VantaConnectionError(
                f"Vanta API connection failure on GET {path}: "
                f"{type(exc).__name__}"
            ) from exc
        if resp.status_code in (401, 403):
            raise VantaAuthError(
                f"Vanta API auth failure on GET {path}: "
                f"HTTP {resp.status_code}. Verify VANTA_API_TOKEN "
                "scope + expiration."
            )
        if resp.status_code >= 400:
            raise VantaQueryError(
                f"Vanta API error on GET {path}: "
                f"HTTP {resp.status_code}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise VantaQueryError(
                f"Vanta API returned non-JSON response on GET {path}"
            ) from exc
        if not isinstance(data, dict):
            raise VantaQueryError(
                f"Vanta API returned non-object JSON on GET {path}: "
                f"{type(data).__name__}"
            )
        return data

    def _paginate(
        self, path: str, **params: Any
    ) -> list[dict[str, Any]]:
        """Pull a paginated endpoint to its natural end (or hard cap).

        Vanta uses cursor-based pagination — responses carry a
        ``page_info`` object with ``has_next_page`` + ``end_cursor``.
        We follow ``end_cursor`` until either the API runs out OR
        the hard cap is hit.

        Defensive: missing pagination metadata is treated as
        end-of-results rather than an error.
        """
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        page_count = 0
        while True:
            page_count += 1
            page_params = dict(params)
            page_params.setdefault("pageSize", DEFAULT_PAGE_SIZE)
            if cursor:
                page_params["cursor"] = cursor
            data = self._get(path, **page_params)
            results = data.get("results", [])
            if not isinstance(results, list):
                raise VantaQueryError(
                    f"Vanta API: expected `results` to be a list on "
                    f"GET {path}; got {type(results).__name__}"
                )
            out.extend(r for r in results if isinstance(r, dict))
            if len(out) >= self._max_vendors:
                # Hard cap reached; truncate + stop.
                out = out[: self._max_vendors]
                break
            page_info = data.get("pageInfo") or data.get("page_info") or {}
            if not isinstance(page_info, dict):
                break
            has_next = bool(
                page_info.get("hasNextPage")
                or page_info.get("has_next_page")
            )
            if not has_next:
                break
            next_cursor = (
                page_info.get("endCursor")
                or page_info.get("end_cursor")
            )
            if not next_cursor or not isinstance(next_cursor, str):
                # No usable cursor → stop. Safer than infinite loop.
                break
            cursor = next_cursor
        return out

    # ── public collect API ─────────────────────────────────────────

    def collect(self) -> list[SecurityFinding]:
        """Legacy single-return collect. Use :meth:`collect_v2` for
        the manifest-aware contract."""
        findings, _manifest = self.collect_v2()
        return findings

    def collect_v2(
        self,
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        """Pull Vanta vendor inventory + emit NIST/OCC-mapped findings.

        Returns:
            ``(findings, manifest)`` — findings is the SecurityFinding
            list; manifest carries CollectionContext + per-source
            coverage counts + any non-fatal errors.
        """
        run_id = new_run_id()
        context = CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity="vanta-api-token",
            source_system_id="vanta",
        )
        _log.info(
            action=EventAction.COLLECT_STARTED,
            outcome=EventOutcome.UNKNOWN,
            message="Vanta collection started",
            evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
        )
        findings: list[SecurityFinding] = []
        errors: list[str] = []
        scanned = 0
        try:
            vendors = self._paginate("/v1/vendors")
            scanned = len(vendors)
            for v in vendors:
                findings.extend(
                    self._vendor_to_findings(v, context)
                )
        except VantaAuthError:
            # Auth failures are fatal — no point continuing.
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message="Vanta authentication failed",
                evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
            )
            raise
        except (VantaConnectionError, VantaQueryError) as exc:
            errors.append(f"vendors: {exc}")
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message=f"Vanta vendor collection failed: {exc!r}",
                evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
                error={"type": type(exc).__name__, "message": str(exc)},
            )

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=context.collected_at,
            collection_finished_at=utc_now(),
            source_system_ids=["vanta"],
            filters_applied={"max_vendors": str(self._max_vendors)},
            coverage_counts=[
                CoverageCount(
                    resource_type="vanta-vendor",
                    scanned=scanned,
                    matched_filter=scanned,
                    collected=scanned,
                ),
            ],
            total_findings=len(findings),
            is_complete=not errors,
            incomplete_reason=("; ".join(errors) if errors else None),
            empty_categories=[
                "control_tests",  # P0.4 follow-up slice
                "ongoing_monitoring_events",  # P0.4 follow-up slice
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
                    f"Vanta collection finished: {len(findings)} "
                    f"finding(s) across {scanned} vendor(s)"
                ),
                evidentia={
                    "run_id": run_id,
                    "collector_id": COLLECTOR_ID,
                    "vendor_count": scanned,
                    "finding_count": len(findings),
                },
            )

        return findings, manifest

    # ── per-vendor mapping ─────────────────────────────────────────

    def _vendor_to_findings(
        self, vendor: dict[str, Any], context: CollectionContext
    ) -> list[SecurityFinding]:
        """Project a Vanta vendor JSON dict into one or more findings.

        Always emits an inventory finding (RESOLVED + INFORMATIONAL
        — it's evidence-of-collection, not a gap). When Vanta has
        flagged the vendor as high-risk, emits an additional ACTIVE
        finding at MEDIUM severity calling for operator review.
        """
        # Defensive extraction — id + name are well-known; everything
        # else flows through to metadata.
        vendor_id = str(vendor.get("id") or vendor.get("vendorId") or "unknown")
        vendor_name = str(
            vendor.get("name")
            or vendor.get("displayName")
            or vendor.get("vendorName")
            or "unknown"
        )
        out: list[SecurityFinding] = [
            SecurityFinding(
                title=f"Vanta vendor inventoried: {vendor_name}",
                description=(
                    f"Vendor {vendor_name!r} (Vanta id: {vendor_id}) "
                    "is present in the operator's Vanta vendor "
                    "register. The full Vanta payload is preserved "
                    "in this finding's metadata for cross-tool "
                    "correlation; see the v0.7.9 P0.1 evidentia "
                    "tprm vendor surface for the curated TPRM "
                    "inventory."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.RESOLVED,
                source_system="vanta",
                source_finding_id=f"vendor-inventory:{vendor_id}",
                resource_type="vanta-vendor",
                resource_id=vendor_id,
                collection_context=context,
                control_mappings=VENDOR_INVENTORY_MAPPINGS,
                raw_data={"vanta_vendor_record": vendor},
            )
        ]
        # If Vanta tags the vendor as high-risk via any of the
        # documented or de-facto field names, emit an additional
        # finding so operators get a discrete review prompt rather
        # than burying the signal in the inventory metadata.
        if self._is_high_risk(vendor):
            out.append(
                SecurityFinding(
                    title=(
                        f"Vanta-flagged high-risk vendor: {vendor_name}"
                    ),
                    description=(
                        f"Vendor {vendor_name!r} (Vanta id: "
                        f"{vendor_id}) carries a HIGH or CRITICAL "
                        "risk-tier flag in the operator's Vanta "
                        "register. Recommended action: review "
                        "Vanta's underlying assessment + confirm "
                        "ongoing-monitoring cadence in the v0.7.9 "
                        "P0.1 evidentia tprm vendor record + "
                        "consider whether contractual remediation "
                        "is warranted per OCC 2013-29 §III.A.4."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.ACTIVE,
                    source_system="vanta",
                    source_finding_id=(
                        f"vendor-high-risk:{vendor_id}"
                    ),
                    resource_type="vanta-vendor",
                    resource_id=vendor_id,
                    collection_context=context,
                    control_mappings=VENDOR_HIGH_RISK_MAPPINGS,
                    raw_data={"vanta_vendor_record": vendor},
                )
            )
        return out

    @staticmethod
    def _is_high_risk(vendor: dict[str, Any]) -> bool:
        """Best-effort high-risk detection across documented + de-facto
        Vanta vendor-record field shapes.

        Defensive: returns False on any unrecognised shape rather
        than raising. Operators relying on the high-risk signal
        should verify against their Vanta UI; the BLIND_SPOTS list
        documents the field-shape uncertainty.
        """
        # Walk a small set of likely field names — Vanta's API
        # publication has used `riskTier`, `risk_tier`, `riskLevel`,
        # `risk_level` across published versions; we accept any of
        # them.
        for key in ("riskTier", "risk_tier", "riskLevel", "risk_level"):
            value = vendor.get(key)
            if isinstance(value, str) and value.upper() in ("HIGH", "CRITICAL"):
                return True
        # Some Vanta exports nest risk under a `riskAssessment` block.
        risk_assessment = vendor.get("riskAssessment") or vendor.get("risk_assessment")
        if isinstance(risk_assessment, dict):
            for key in ("tier", "level", "severity"):
                value = risk_assessment.get(key)
                if isinstance(value, str) and value.upper() in (
                    "HIGH", "CRITICAL"
                ):
                    return True
        return False
