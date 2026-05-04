"""Drata evidence collector — main module (v0.7.9 P0.4 second slice).

Read-only collector that pulls a Drata-managed vendor inventory via
the Drata Public API and emits NIST 800-53 + OCC 2013-29 + FRB
SR 13-19 + FFIEC Vendor Management mapped SecurityFinding objects.
See `evidentia_collectors.drata.__init__` for the public-surface
walkthrough + credential handling protocol.

Mirrors the v0.7.9 P0.4 first-slice Vanta collector pattern
(typed exception hierarchy, ECS-structured logging, BLIND_SPOTS
list, defensive field-shape parsing). Drata's vendor-inventory
surface lives at ``/public/v1/vendors`` (vs Vanta's ``/v1/vendors``)
but the cursor-based pagination + bearer-token auth contract is
shape-compatible.

v0.7.9 P0.4 second slice ships vendor-inventory only. Subsequent
slices add Drata control-test pulls + ongoing-monitoring posture
+ webhook ingestion.
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

from evidentia_collectors.drata.mapping import (
    VENDOR_HIGH_RISK_MAPPINGS,
    VENDOR_INVENTORY_MAPPINGS,
)

_log = get_logger("evidentia.collectors.drata")

COLLECTOR_ID = "drata-scan"

# Default Drata Public API base URL. Drata exposes its public
# surface at https://public-api.drata.com (sub-domain split from
# the dashboard).
DEFAULT_BASE_URL = "https://public-api.drata.com"

# Hard cap on vendor enumeration. Drata orgs typically have <500
# vendors; the cap protects against accidental unbounded
# pagination if the cursor-loop logic encounters a malformed
# response.
DEFAULT_MAX_VENDORS = 2000

# Per-page count for paginated endpoints. Drata's documented
# upper-bound is 100; the collector requests this to minimize
# request count.
DEFAULT_PAGE_SIZE = 100

# Connect + read timeout (seconds).
DEFAULT_TIMEOUT_SECONDS = 30.0


# ── Typed exception hierarchy ──────────────────────────────────────


class DrataCollectorError(Exception):
    """Base class for all Drata collector failures."""


class DrataAuthError(DrataCollectorError):
    """Authentication / authorization failure — 401 / 403 from the API."""


class DrataConnectionError(DrataCollectorError):
    """Network / TLS / timeout failure — could not reach the Drata API."""


class DrataQueryError(DrataCollectorError):
    """A specific API call failed (4xx / 5xx other than auth, or a
    malformed response). Surfaced inside ``collect_v2`` and recorded
    in the manifest's ``errors`` list rather than failing the whole
    collection.
    """


# ── BLIND_SPOTS list ───────────────────────────────────────────────

BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "EVIDENTIA-DRATA-CONTROL-TESTS-DEFERRED",
        "title": (
            "Drata control test results not yet collected"
        ),
        "description": (
            "Drata's per-control test evidence (the SOC-2 / ISO-27001 "
            "readiness signal that drives most operators' Drata usage) "
            "is exposed via /public/v1/controls but is NOT enumerated "
            "in the v0.7.9 P0.4 second slice. The collector ships "
            "vendor-inventory only; control test pull-in lands in a "
            "follow-up slice."
        ),
    },
    {
        "id": "EVIDENTIA-DRATA-OAUTH-CLIENT-CREDENTIALS",
        "title": (
            "OAuth 2.0 client-credentials flow not yet implemented"
        ),
        "description": (
            "The collector authenticates via static Bearer token "
            "(Personal API token). The full OAuth 2.0 client-"
            "credentials grant (token exchange + automatic refresh) "
            "lands in a follow-up slice. Operators using OAuth today "
            "should supply a pre-acquired access token via the env var."
        ),
    },
    {
        "id": "EVIDENTIA-DRATA-WEBHOOK-EVENTS",
        "title": (
            "Drata webhook event ingestion not implemented"
        ),
        "description": (
            "Drata supports webhook subscriptions for vendor + control "
            "state changes (push model). The collector is pull-only "
            "in v0.7.9 P0.4 second slice. Webhook ingestion would be "
            "a separate v0.8.x feature once the API surface for "
            "receiving + verifying webhook signatures lands in "
            "evidentia-api."
        ),
    },
    {
        "id": "EVIDENTIA-DRATA-FIELD-SHAPE-DEFENSIVE",
        "title": (
            "Vendor JSON shape parsed defensively"
        ),
        "description": (
            "The collector extracts only the well-known ``id`` + "
            "``name`` fields explicitly; everything else is "
            "passed through to the SecurityFinding's ``raw_data`` "
            "field as-is. If Drata's API renames or restructures "
            "fields, the collector keeps producing inventory "
            "evidence but specific field-derived signals (e.g., "
            "Drata's risk-level flag → high-risk-finding upgrade) "
            "may not trigger until the parser is updated."
        ),
    },
]


# ── Collector ──────────────────────────────────────────────────────


class DrataCollector:
    """Drata vendor-inventory collector.

    Args:
        api_token: Drata Personal API token. Sourced from the
            ``DRATA_API_TOKEN`` env var per the secret-handling
            protocol — never log or echo the token value.
        base_url: API base URL. Default
            ``https://public-api.drata.com``. Override for staging /
            dev tenants.
        max_vendors: Hard cap on vendor enumeration; defaults to
            :data:`DEFAULT_MAX_VENDORS`.
        timeout_seconds: HTTP connect + read timeout per request.
        client: Optional pre-configured ``httpx.Client``. When
            provided, the collector does NOT close it on exit
            (caller-owned). When None, the collector creates +
            owns its own client.

    Raises:
        DrataAuthError: missing API token at construction time.
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
            raise DrataAuthError(
                "DrataCollector requires either an api_token or a "
                "pre-configured httpx.Client. The token is sourced "
                "from the DRATA_API_TOKEN env var per the secret-"
                "handling protocol."
            )
        self._api_token = api_token
        self._base_url = base_url.rstrip("/")
        self._max_vendors = max_vendors
        self._timeout_seconds = timeout_seconds
        self._client = client
        self._owns_client = client is None

    def __enter__(self) -> DrataCollector:
        return self

    def __exit__(self, *exc: object) -> None:
        if self._owns_client and self._client is not None:
            with contextlib.suppress(Exception):
                self._client.close()
            self._client = None

    def _ensure_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        if self._api_token is None:  # defensive — checked in __init__
            raise DrataAuthError("missing api_token")
        self._client = httpx.Client(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_token}",
                "Accept": "application/json",
                "User-Agent": (
                    f"evidentia-collectors/{current_version()} "
                    "(DrataCollector; https://github.com/allenfbyrd/evidentia)"
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
            raise DrataConnectionError(
                f"Drata API timeout after {self._timeout_seconds}s "
                f"on GET {path}"
            ) from exc
        except httpx.HTTPError as exc:
            raise DrataConnectionError(
                f"Drata API connection failure on GET {path}: "
                f"{type(exc).__name__}"
            ) from exc
        if resp.status_code in (401, 403):
            raise DrataAuthError(
                f"Drata API auth failure on GET {path}: "
                f"HTTP {resp.status_code}. Verify DRATA_API_TOKEN "
                "scope + expiration."
            )
        if resp.status_code >= 400:
            raise DrataQueryError(
                f"Drata API error on GET {path}: "
                f"HTTP {resp.status_code}"
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise DrataQueryError(
                f"Drata API returned non-JSON response on GET {path}"
            ) from exc
        if not isinstance(data, dict):
            raise DrataQueryError(
                f"Drata API returned non-object JSON on GET {path}: "
                f"{type(data).__name__}"
            )
        return data

    def _paginate(
        self, path: str, **params: Any
    ) -> list[dict[str, Any]]:
        """Pull a paginated endpoint to its natural end (or hard cap).

        Drata uses cursor-based pagination — responses carry a
        ``nextPageToken`` field at the top level (not nested in a
        page-info object like Vanta). We follow the cursor until
        either the API runs out OR the hard cap is hit.

        Defensive: missing pagination metadata is treated as
        end-of-results rather than an error. Also accepts
        Vanta-style ``pageInfo`` shape as a fallback for forward
        compatibility if Drata adopts the same convention.
        """
        out: list[dict[str, Any]] = []
        cursor: str | None = None
        while True:
            page_params = dict(params)
            page_params.setdefault("pageSize", DEFAULT_PAGE_SIZE)
            if cursor:
                page_params["pageToken"] = cursor
            data = self._get(path, **page_params)
            results = (
                data.get("data")
                or data.get("results")
                or data.get("vendors")
                or []
            )
            if not isinstance(results, list):
                raise DrataQueryError(
                    f"Drata API: expected list payload on GET {path}; "
                    f"got {type(results).__name__}"
                )
            out.extend(r for r in results if isinstance(r, dict))
            if len(out) >= self._max_vendors:
                out = out[: self._max_vendors]
                break
            # Drata top-level cursor field
            next_cursor = (
                data.get("nextPageToken")
                or data.get("next_page_token")
            )
            # Fallback to Vanta-style nested pageInfo for forward
            # compatibility (no harm if Drata never emits it).
            if not next_cursor:
                page_info = (
                    data.get("pageInfo")
                    or data.get("page_info")
                    or {}
                )
                if isinstance(page_info, dict):
                    next_cursor = (
                        page_info.get("endCursor")
                        or page_info.get("end_cursor")
                    )
            if not next_cursor or not isinstance(next_cursor, str):
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
        """Pull Drata vendor inventory + emit NIST/OCC-mapped findings."""
        run_id = new_run_id()
        context = CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity="drata-api-token",
            source_system_id="drata",
        )
        _log.info(
            action=EventAction.COLLECT_STARTED,
            outcome=EventOutcome.UNKNOWN,
            message="Drata collection started",
            evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
        )
        findings: list[SecurityFinding] = []
        errors: list[str] = []
        scanned = 0
        try:
            vendors = self._paginate("/public/v1/vendors")
            scanned = len(vendors)
            for v in vendors:
                findings.extend(
                    self._vendor_to_findings(v, context)
                )
        except DrataAuthError:
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message="Drata authentication failed",
                evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
            )
            raise
        except (DrataConnectionError, DrataQueryError) as exc:
            errors.append(f"vendors: {exc}")
            _log.warning(
                action=EventAction.COLLECT_FAILED,
                outcome=EventOutcome.FAILURE,
                message=f"Drata vendor collection failed: {exc!r}",
                evidentia={"run_id": run_id, "collector_id": COLLECTOR_ID},
                error={"type": type(exc).__name__, "message": str(exc)},
            )

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=context.collected_at,
            collection_finished_at=utc_now(),
            source_system_ids=["drata"],
            filters_applied={"max_vendors": str(self._max_vendors)},
            coverage_counts=[
                CoverageCount(
                    resource_type="drata-vendor",
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
                    f"Drata collection finished: {len(findings)} "
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
        """Project a Drata vendor JSON dict into one or more findings.

        Always emits an inventory finding (RESOLVED + INFORMATIONAL —
        evidence-of-collection, not a gap). When Drata has flagged the
        vendor as high-risk, emits an additional ACTIVE finding at
        MEDIUM severity calling for operator review.
        """
        vendor_id = str(
            vendor.get("id")
            or vendor.get("vendorId")
            or vendor.get("uuid")
            or "unknown"
        )
        vendor_name = str(
            vendor.get("name")
            or vendor.get("displayName")
            or vendor.get("vendorName")
            or "unknown"
        )
        out: list[SecurityFinding] = [
            SecurityFinding(
                title=f"Drata vendor inventoried: {vendor_name}",
                description=(
                    f"Vendor {vendor_name!r} (Drata id: {vendor_id}) "
                    "is present in the operator's Drata vendor "
                    "register. The full Drata payload is preserved "
                    "in this finding's raw_data field for cross-tool "
                    "correlation; see the v0.7.9 P0.1 evidentia "
                    "tprm vendor surface for the curated TPRM "
                    "inventory."
                ),
                severity=Severity.INFORMATIONAL,
                status=FindingStatus.RESOLVED,
                source_system="drata",
                source_finding_id=f"vendor-inventory:{vendor_id}",
                resource_type="drata-vendor",
                resource_id=vendor_id,
                collection_context=context,
                control_mappings=VENDOR_INVENTORY_MAPPINGS,
                raw_data={"drata_vendor_record": vendor},
            )
        ]
        if self._is_high_risk(vendor):
            out.append(
                SecurityFinding(
                    title=(
                        f"Drata-flagged high-risk vendor: {vendor_name}"
                    ),
                    description=(
                        f"Vendor {vendor_name!r} (Drata id: "
                        f"{vendor_id}) carries a HIGH or CRITICAL "
                        "risk-level flag in the operator's Drata "
                        "register. Recommended action: review "
                        "Drata's underlying assessment + confirm "
                        "ongoing-monitoring cadence in the v0.7.9 "
                        "P0.1 evidentia tprm vendor record + "
                        "consider whether contractual remediation "
                        "is warranted per OCC 2013-29 §III.A.4."
                    ),
                    severity=Severity.MEDIUM,
                    status=FindingStatus.ACTIVE,
                    source_system="drata",
                    source_finding_id=(
                        f"vendor-high-risk:{vendor_id}"
                    ),
                    resource_type="drata-vendor",
                    resource_id=vendor_id,
                    collection_context=context,
                    control_mappings=VENDOR_HIGH_RISK_MAPPINGS,
                    raw_data={"drata_vendor_record": vendor},
                )
            )
        return out

    @staticmethod
    def _is_high_risk(vendor: dict[str, Any]) -> bool:
        """Best-effort high-risk detection across documented + de-facto
        Drata vendor-record field shapes.

        Defensive: returns False on any unrecognised shape rather
        than raising. Operators relying on the high-risk signal
        should verify against their Drata UI; the BLIND_SPOTS list
        documents the field-shape uncertainty.
        """
        # Drata's API has used `riskLevel` + `risk_level` in published
        # versions; older releases used `riskTier`. Accept any.
        for key in (
            "riskLevel",
            "risk_level",
            "riskTier",
            "risk_tier",
        ):
            value = vendor.get(key)
            if isinstance(value, str) and value.upper() in ("HIGH", "CRITICAL"):
                return True
        # Some Drata exports nest risk under a `riskAssessment` block.
        risk_assessment = (
            vendor.get("riskAssessment")
            or vendor.get("risk_assessment")
        )
        if isinstance(risk_assessment, dict):
            for key in ("level", "tier", "severity"):
                value = risk_assessment.get(key)
                if isinstance(value, str) and value.upper() in (
                    "HIGH",
                    "CRITICAL",
                ):
                    return True
        # Drata also sometimes uses `inherentRisk` or `residualRisk`
        # numeric fields on a 1-5 / 1-25 scale; treat 4+ on a 5-scale
        # OR 16+ on a 25-scale as HIGH.
        for key in ("inherentRisk", "residualRisk"):
            value = vendor.get(key)
            if isinstance(value, int) and (
                (value >= 4 and value <= 5)  # 1-5 scale
                or (value >= 16 and value <= 25)  # 1-25 scale
            ):
                return True
        return False
