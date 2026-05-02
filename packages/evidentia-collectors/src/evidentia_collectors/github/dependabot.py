"""GitHub Dependabot alerts collector (v0.7.0).

Collects vulnerability findings from GitHub Dependabot alerts and maps
them to NIST SP 800-218 SSDF practices (PO.3, PW.4, RV.2) and
NIST SP 800-53 Rev 5 controls (SI-2, SI-5, RA-5, SR-3, SR-11).

Authoritative mapping sources (Q3=A spot-check):

- GitHub Well-Architected: Implementing the NIST SSDF with GitHub
  (https://wellarchitected.github.com/library/scenarios/nist-ssdf-implementation/)
  — authoritative per GitHub for PO.3 / PW.4 / RV.2 classifications.
- NIST SP 800-218 SSDF v1.1 — practice definitions (PW.4 reuse well-
  secured software, RV.2 assess/prioritize/remediate).
- NIST SP 800-53 Rev 5 — SI-2 (Flaw Remediation), RA-5 (Vulnerability
  Monitoring and Scanning), SR-3/SR-11 (supply chain).
- FedRAMP Rev 5 Continuous Monitoring vulnerability-scanning
  requirements (30/90/180-day SLAs per severity).

**Dismissal policy (Tier 3 = policy-driven).** Dependabot's
``dismissed_reason`` values have different audit interpretations:

- ``fix_started``       → treat as resolved (partial positive)
- ``inaccurate``        → treat as resolved (VEX-like false positive)
- ``no_bandwidth``      → treat as open (auditor concern: unremediated)
- ``not_used``          → treat as resolved (VEX-like unreachable)
- ``tolerable_risk``    → treat as open (risk acceptance → POA&M)

Operators can override any of these in ``evidentia.yaml``:

.. code-block:: yaml

    dependabot:
      dismissal_policy:
        fix_started: treat_as_resolved
        inaccurate: treat_as_resolved
        no_bandwidth: treat_as_open      # auditor-default
        not_used: treat_as_resolved
        tolerable_risk: treat_as_open    # auditor-default

The default policy is biased toward surfacing-to-auditor for the two
ambiguous cases (``no_bandwidth`` and ``tolerable_risk``) — safer
default for compliance posture.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

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
    with_retry,
)
from evidentia_core.models.common import (
    ControlMapping,
    OLIRRelationship,
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import FindingStatus, SecurityFinding

from evidentia_collectors.github.client import (
    GitHubApiError,
    GitHubClient,
)

_log = get_logger("evidentia.collectors.github.dependabot")

COLLECTOR_ID = "github-dependabot"


# ═════════════════════════════════════════════════════════════════════════
# Dismissal policy (Tier 3)
# ═════════════════════════════════════════════════════════════════════════


class DismissalVerdict(str, Enum):
    """How a dismissed Dependabot alert should be treated in evidence.

    ``TREAT_AS_RESOLVED`` → status=RESOLVED in SecurityFinding (the
    alert counts as a closed gap for audit purposes).

    ``TREAT_AS_OPEN`` → status=ACTIVE in SecurityFinding (the alert is
    presented to the auditor as an unremediated risk requiring POA&M
    tracking). Used for ``no_bandwidth`` and ``tolerable_risk``
    dismissals by default — a FedRAMP 3PAO treats explicit risk
    acceptance as a gap, not a resolution.
    """

    TREAT_AS_RESOLVED = "treat_as_resolved"
    TREAT_AS_OPEN = "treat_as_open"


#: Default dismissal policy per Tier 3 research. Operators can
#: override individual entries in ``evidentia.yaml``.
DEFAULT_DISMISSAL_POLICY: dict[str, DismissalVerdict] = {
    "fix_started": DismissalVerdict.TREAT_AS_RESOLVED,
    "inaccurate": DismissalVerdict.TREAT_AS_RESOLVED,
    "no_bandwidth": DismissalVerdict.TREAT_AS_OPEN,
    "not_used": DismissalVerdict.TREAT_AS_RESOLVED,
    "tolerable_risk": DismissalVerdict.TREAT_AS_OPEN,
}


# ═════════════════════════════════════════════════════════════════════════
# OLIR-typed control mappings
# ═════════════════════════════════════════════════════════════════════════


def _mapping(
    control_id: str,
    relationship: OLIRRelationship,
    justification: str,
    framework: str = "nist-800-53-rev5",
) -> ControlMapping:
    return ControlMapping(
        framework=framework,
        control_id=control_id,
        relationship=relationship,
        justification=justification,
    )


#: Core vulnerability-remediation mappings — apply to every
#: Dependabot alert regardless of state.
_CORE_MAPPINGS: list[ControlMapping] = [
    _mapping(
        "SI-2",
        OLIRRelationship.SUBSET_OF,
        "SI-2 Flaw Remediation — Dependabot alerts directly evidence "
        "known flaws in third-party dependencies that must be "
        "remediated per the NIST 800-53 Rev 5 SI-2 requirement. "
        "GitHub's 'Implementing the NIST SSDF with GitHub' Well-"
        "Architected guide names Dependabot as the primary RV.2 "
        "mechanism, and RV.2 in turn cross-walks to SI-2.",
    ),
    _mapping(
        "SI-5",
        OLIRRelationship.INTERSECTS_WITH,
        "SI-5 Security Alerts, Advisories, and Directives — Dependabot "
        "surfaces GHSA / CVE advisories. Intersects SI-5 which also "
        "covers directives from US-CERT, vendor advisories, etc.",
    ),
    _mapping(
        "RA-5",
        OLIRRelationship.SUBSET_OF,
        "RA-5 Vulnerability Monitoring and Scanning — Dependabot "
        "provides continuous dependency vulnerability monitoring per "
        "RA-5's scanning requirement. FedRAMP Rev 5 Continuous "
        "Monitoring explicitly accepts SCA/dependency scanning under "
        "RA-5.",
    ),
    _mapping(
        "SR-3",
        OLIRRelationship.SUBSET_OF,
        "SR-3 Supply Chain Controls and Processes — Dependabot "
        "alerts are the primary supply-chain vulnerability signal; "
        "directly evidences the SR-3 requirement to identify "
        "supply-chain-introduced risks.",
    ),
    _mapping(
        "SR-11",
        OLIRRelationship.INTERSECTS_WITH,
        "SR-11 Component Authenticity — Dependabot identifies known-"
        "vulnerable components; intersects SR-11's authenticity "
        "verification scope (though SR-11 also covers tampered / "
        "counterfeit components which Dependabot does not).",
    ),
    _mapping(
        "PO.3",
        OLIRRelationship.SUBSET_OF,
        "PO.3 Implement Supporting Toolchains — GitHub's SSDF guide "
        "lists Dependabot alerts and security updates as a required "
        "PO.3 toolchain element for organizations adopting the SSDF.",
        framework="nist-sp-800-218-ssdf",
    ),
    _mapping(
        "PW.4",
        OLIRRelationship.SUBSET_OF,
        "PW.4 Reuse Existing, Well-Secured Software — Dependabot "
        "alerts directly evidence PW.4 by identifying dependencies "
        "that are no longer well-secured (have known CVEs). GitHub's "
        "SSDF guide names Dependabot as the primary PW.4 mechanism.",
        framework="nist-sp-800-218-ssdf",
    ),
    _mapping(
        "RV.2",
        OLIRRelationship.SUBSET_OF,
        "RV.2 Assess, Prioritize, and Remediate Vulnerabilities — "
        "GitHub's SSDF guide explicitly classifies 'Dependabot "
        "security updates' as the primary RV.2 implementation.",
        framework="nist-sp-800-218-ssdf",
    ),
]


# ═════════════════════════════════════════════════════════════════════════
# Collector
# ═════════════════════════════════════════════════════════════════════════


class DependabotCollectorError(Exception):
    """Collector-level failures (missing token, missing repo, etc)."""


class DependabotCollector:
    """GitHub Dependabot alerts collector.

    Enumerates active + dismissed + fixed + auto_dismissed alerts.
    Applies the dismissal policy (Tier 3) to reclassify ambiguous
    dismissals as ``ACTIVE`` (``tolerable_risk``, ``no_bandwidth``
    by default) or ``RESOLVED``.
    """

    def __init__(
        self,
        *,
        owner: str,
        repo: str,
        token: str | None = None,
        client: GitHubClient | None = None,
        dismissal_policy: dict[str, DismissalVerdict] | None = None,
    ) -> None:
        if not owner or not repo:
            raise DependabotCollectorError(
                "DependabotCollector requires non-empty owner + repo."
            )
        self.owner = owner
        self.repo = repo
        self._client = client or GitHubClient(token=token)
        self._owns_client = client is None
        self.dismissal_policy = {
            **DEFAULT_DISMISSAL_POLICY,
            **(dismissal_policy or {}),
        }

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> DependabotCollector:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    # ── API calls ────────────────────────────────────────────────────

    @with_retry(max_attempts=3, retry_on=(ConnectionError, TimeoutError))
    def _fetch_alerts(
        self,
        *,
        state: str | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> list[dict[str, Any]]:
        """Retryable wrapper around the Dependabot alerts REST API.

        GitHub's Dependabot REST API returns the full list of alerts
        for a repo at ``/repos/{owner}/{repo}/dependabot/alerts``. We
        use per_page pagination (max 100 per GitHub's API).
        """
        params: dict[str, Any] = {"per_page": per_page, "page": page}
        if state:
            params["state"] = state
        response = self._client.request(
            "GET",
            f"/repos/{self.owner}/{self.repo}/dependabot/alerts",
            params=params,
        )
        if not isinstance(response, list):
            return []
        return [item for item in response if isinstance(item, dict)]

    # ── orchestration ────────────────────────────────────────────────

    def collect(
        self,
        *,
        include_dismissed: bool = True,
        include_auto_dismissed: bool = True,
        dry_run: bool = False,
    ) -> list[SecurityFinding]:
        """Return findings; backward-compat-style API."""
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"Dependabot dry-run for {self.slug} — would enumerate "
                    "open + fixed + dismissed alerts"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={
                    "dry_run": True,
                    "repo": self.slug,
                    "include_dismissed": include_dismissed,
                    "include_auto_dismissed": include_auto_dismissed,
                },
            )
            return []
        findings, _manifest = self.collect_v2(
            include_dismissed=include_dismissed,
            include_auto_dismissed=include_auto_dismissed,
        )
        return findings

    def collect_v2(
        self,
        *,
        include_dismissed: bool = True,
        include_auto_dismissed: bool = True,
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        """Enterprise-grade orchestrator.

        Returns ``(findings, manifest)`` with coverage counts per
        state (open, fixed, dismissed, auto_dismissed), dismissal-
        policy-driven reclassification, and complete provenance.
        """
        run_id = new_run_id()
        started_at = utc_now()
        source_system_id = f"github:{self.slug}"
        context = CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"github-token:scope:{self.slug}",
            source_system_id=source_system_id,
            filter_applied={
                "repo": self.slug,
                "include_dismissed": include_dismissed,
                "include_auto_dismissed": include_auto_dismissed,
                "dismissal_policy": {
                    k: v.value for k, v in self.dismissal_policy.items()
                },
            },
        )

        findings: list[SecurityFinding] = []
        errors: list[str] = []
        counts_by_state: dict[str, int] = {
            "open": 0,
            "fixed": 0,
            "dismissed": 0,
            "auto_dismissed": 0,
        }

        with _log.scope(
            trace_id=run_id,
            user={"id": context.credential_identity, "domain": "github.com"},
            evidentia={
                "run_id": run_id,
                "collector": {
                    "id": COLLECTOR_ID,
                    "version": current_version(),
                },
                "repo": self.slug,
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"Dependabot collection starting for {self.slug}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            try:
                all_alerts = self._fetch_all_pages()
                for alert in all_alerts:
                    state = str(alert.get("state") or "").lower()
                    counts_by_state[state] = counts_by_state.get(
                        state, 0
                    ) + 1

                    # Apply inclusion filters.
                    if state == "dismissed" and not include_dismissed:
                        continue
                    if (
                        state == "auto_dismissed"
                        and not include_auto_dismissed
                    ):
                        continue

                    findings.append(
                        self._alert_to_finding(alert, context)
                    )
            except GitHubApiError as e:
                errors.append(f"dependabot: GitHubApiError: {e}")
                _log.error(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=f"Dependabot API call failed: {e}",
                    error={"type": "GitHubApiError", "message": str(e)},
                )
            except (ConnectionError, TimeoutError) as e:
                errors.append(f"dependabot: transient: {e}")
                _log.error(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=f"Dependabot transient error: {e}",
                    error={"type": type(e).__name__, "message": str(e)},
                )
            except Exception as e:
                errors.append(
                    f"dependabot: {type(e).__name__}: {e}"
                )
                _log.error(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=f"Dependabot collector failed: {e}",
                    error={"type": type(e).__name__, "message": str(e)},
                )

            empty_categories: list[str] = []
            if not findings and not errors:
                empty_categories.append("github-dependabot-alerts")
                _log.info(
                    action=EventAction.MANIFEST_EMPTY_SET_ATTESTED,
                    message=(
                        "Dependabot: zero alerts (attested empty)"
                    ),
                )

            manifest = CollectionManifest(
                run_id=run_id,
                collector_id=COLLECTOR_ID,
                collector_version=current_version(),
                collection_started_at=started_at,
                collection_finished_at=utc_now(),
                source_system_ids=[source_system_id],
                filters_applied={
                    "repo": self.slug,
                    "include_dismissed": include_dismissed,
                    "include_auto_dismissed": include_auto_dismissed,
                },
                coverage_counts=[
                    CoverageCount(
                        resource_type=f"github-dependabot-alert-{state}",
                        scanned=count,
                        matched_filter=count,
                        collected=sum(
                            1
                            for f in findings
                            if (f.raw_data or {}).get("state") == state
                        ),
                    )
                    for state, count in counts_by_state.items()
                    if count > 0
                ],
                total_findings=len(findings),
                is_complete=not errors,
                incomplete_reason=(
                    "; ".join(errors) if errors else None
                ),
                empty_categories=empty_categories,
                errors=errors,
            )

            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=EventOutcome.SUCCESS
                if not errors
                else EventOutcome.FAILURE,
                message=(
                    f"Dependabot completed: {len(findings)} findings "
                    f"({counts_by_state})"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.END],
                evidentia={
                    "findings_count": len(findings),
                    "counts_by_state": counts_by_state,
                },
            )

        return findings, manifest

    def _fetch_all_pages(self) -> list[dict[str, Any]]:
        """Fetch every alert across all pages."""
        all_alerts: list[dict[str, Any]] = []
        page = 1
        while True:
            alerts = self._fetch_alerts(page=page, per_page=100)
            if not alerts:
                break
            all_alerts.extend(alerts)
            if len(alerts) < 100:
                break
            page += 1
            # Hard cap at 100 pages (10,000 alerts) as a safety net.
            if page > 100:
                _log.warning(
                    action=EventAction.COLLECT_ABORTED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        "Dependabot pagination hit 100-page safety cap "
                        "(10k alerts). Some alerts may not be collected."
                    ),
                )
                break
        return all_alerts

    # ── alert → finding ──────────────────────────────────────────────

    def _alert_to_finding(
        self, alert: dict[str, Any], context: CollectionContext
    ) -> SecurityFinding:
        """Convert a Dependabot alert JSON to a SecurityFinding.

        Applies the dismissal policy to reclassify ambiguous
        dismissals as ACTIVE or RESOLVED per the operator's configured
        verdicts.
        """
        state = str(alert.get("state") or "open").lower()
        dismissed_reason = (
            str(alert.get("dismissed_reason"))
            if alert.get("dismissed_reason")
            else None
        )

        # Dismissal-policy classification. Open/fixed/auto_dismissed
        # map directly to ACTIVE/RESOLVED; 'dismissed' depends on the
        # reason and the operator's policy (Tier 3).
        if state == "open":
            status = FindingStatus.ACTIVE
        elif state == "fixed":
            status = FindingStatus.RESOLVED
        elif state == "auto_dismissed":
            # GitHub's auto-dismissal typically means package removed
            # or repo archived — functionally resolved.
            status = FindingStatus.RESOLVED
        elif state == "dismissed" and dismissed_reason:
            verdict = self.dismissal_policy.get(
                dismissed_reason, DismissalVerdict.TREAT_AS_OPEN
            )
            status = (
                FindingStatus.ACTIVE
                if verdict == DismissalVerdict.TREAT_AS_OPEN
                else FindingStatus.RESOLVED
            )
        else:
            # Unknown state → ACTIVE (safer default for audit).
            status = FindingStatus.ACTIVE

        advisory = alert.get("security_advisory") or {}
        vulnerability = alert.get("security_vulnerability") or {}
        ghsa_id = str(advisory.get("ghsa_id") or "")
        cve_id = str(advisory.get("cve_id") or "") if advisory.get("cve_id") else None
        cvss = (advisory.get("cvss_severities") or {}).get("cvss_v3") or {}
        cvss_score = cvss.get("score")

        severity = _severity_from_advisory(advisory, vulnerability)

        package = (vulnerability.get("package") or {})
        pkg_name = str(package.get("name") or "")
        pkg_ecosystem = str(package.get("ecosystem") or "")

        title_parts = [ghsa_id or cve_id or f"Dependabot alert #{alert.get('number')}"]
        if pkg_name:
            title_parts.append(pkg_name)
        title = " / ".join(title_parts)[:200]

        description_parts = [
            str(advisory.get("summary") or "")[:500],
        ]
        if pkg_ecosystem and pkg_name:
            description_parts.append(
                f"Package: {pkg_ecosystem}/{pkg_name}"
            )
        if cvss_score is not None:
            description_parts.append(f"CVSS v3 base: {cvss_score}")
        if cve_id:
            description_parts.append(f"CVE: {cve_id}")
        if state == "dismissed" and dismissed_reason:
            description_parts.append(
                f"Dismissal reason: {dismissed_reason}"
            )
        description = "\n".join(description_parts)[:2000]

        return SecurityFinding(
            title=title,
            description=description,
            severity=severity,
            status=status,
            source_system="github-dependabot",
            source_finding_id=str(alert.get("number") or ""),
            resource_type="GitHub::Dependabot::Alert",
            resource_id=f"{self.slug}#{alert.get('number')}",
            control_mappings=list(_CORE_MAPPINGS),
            collection_context=context,
            raw_data=alert,
            first_observed=_to_datetime(alert.get("created_at")),
            last_observed=_to_datetime(alert.get("updated_at"))
            or _to_datetime(alert.get("created_at")),
            resolved_at=(
                _to_datetime(alert.get("fixed_at"))
                or _to_datetime(alert.get("dismissed_at"))
                or _to_datetime(alert.get("auto_dismissed_at"))
            ),
        )


# ── helpers ──────────────────────────────────────────────────────────────


def _severity_from_advisory(
    advisory: dict[str, Any], vulnerability: dict[str, Any]
) -> Severity:
    """Compute severity from the GitHub-advisory severity label.

    Dependabot alerts use (critical, high, medium, low). We map
    directly. CVSS v3 score is included in raw_data for reviewers
    who want to requalify.
    """
    label = str(
        advisory.get("severity") or vulnerability.get("severity") or "medium"
    ).lower()
    lookup = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,  # older advisories use "moderate"
        "low": Severity.LOW,
    }
    return lookup.get(label, Severity.MEDIUM)


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
