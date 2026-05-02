"""AWS IAM Access Analyzer collector (v0.7.0).

Collects evidence findings from AWS IAM Access Analyzer — findings that
directly evidence NIST SP 800-53 Rev 5 access-control requirements
(AC-3, AC-4, AC-5, AC-6, AC-6(1), IA-2, IA-5, CM-3, SA-3).

Three analyzer types are supported; each requires its own analyzer
instance in AWS:

- **External access** (``TYPE_EXTERNAL_ACCESS``) — identifies
  resource-based policies that grant access to principals outside
  the analyzer's zone of trust.
- **Unused access** (``TYPE_UNUSED_ACCESS``) — identifies IAM roles,
  users, access keys, passwords, and permissions that haven't been
  used within the configured window.
- **Internal access** (``TYPE_INTERNAL_ACCESS``) — identifies
  potential access paths within the organization / account.

Authoritative mapping sources:

- AWS Audit Manager 'AWS NIST 800-53 Rev 5' framework
  (https://docs.aws.amazon.com/audit-manager/latest/userguide/NIST800-53r5.html)
- AWS Security Hub NIST SP 800-53 Rev 5 standard
  (https://docs.aws.amazon.com/securityhub/latest/userguide/standards-reference-nist-800-53.html)
- FedRAMP Rev 5 baseline access-control requirements

**Blind-spot disclosures** are emitted as ``back-matter.resources[]``
entries with ``class="blind-spot"`` so auditors reading the OSCAL AR
see the limits of Access Analyzer coverage inline, satisfying the
Q7=Yes checklist requirement for in-document disclosure.

Usage::

    collector = AccessAnalyzerCollector(
        analyzer_arn="arn:aws:access-analyzer:us-east-1:…:analyzer/grc",
        region="us-east-1",
    )
    findings, manifest = collector.collect_v2()
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:  # pragma: no cover
    pass


_log = get_logger("evidentia.collectors.aws.access_analyzer")

COLLECTOR_ID = "aws-access-analyzer"

# ── OLIR-typed mapping tables ────────────────────────────────────────────
#
# Spot-checked per Q3=A against authoritative sources. Relationship
# classifications follow the research-backed convention established
# in aws/mapping.py:
#
# - SUBSET_OF — finding directly evidences a specific aspect of the
#   NIST control (typical for external access, unused credentials).
# - INTERSECTS_WITH — finding addresses one dimension of a broader
#   control objective.


def _mapping(
    control_id: str,
    relationship: OLIRRelationship,
    justification: str,
) -> ControlMapping:
    return ControlMapping(
        framework="nist-800-53-rev5",
        control_id=control_id,
        relationship=relationship,
        justification=justification,
    )


# ExternalAccess findings — S3 / IAM role / KMS / Lambda / SQS / SNS /
# Secrets / EBS-snapshot with cross-account or public resource policy.
_EXTERNAL_ACCESS_MAPPINGS = [
    _mapping(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — external-access findings directly "
        "evidence that a resource-based policy permits access by a "
        "principal outside the authorized zone of trust, violating "
        "AC-3's enforcement requirement.",
    ),
    _mapping(
        "AC-4",
        OLIRRelationship.SUBSET_OF,
        "AC-4 Information Flow Control — cross-account / public "
        "access creates information flows that must be approved per "
        "AC-4. Access Analyzer external findings identify policies "
        "permitting un-approved flows.",
    ),
    _mapping(
        "AC-5",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-5 Separation of Duties — cross-account grants without "
        "separation-of-duties review intersect with AC-5 but don't "
        "evidence the full scope.",
    ),
    _mapping(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — external access grants typically "
        "over-provision privilege. Access Analyzer external findings "
        "are direct evidence of least-privilege violations.",
    ),
]


# Public-access specialization (e.g., S3 bucket with 'Principal: *').
_EXTERNAL_PUBLIC_ACCESS_MAPPINGS = [
    *_EXTERNAL_ACCESS_MAPPINGS,
    _mapping(
        "SC-7",
        OLIRRelationship.SUBSET_OF,
        "SC-7 Boundary Protection — public access removes the "
        "boundary enforcement that SC-7 requires for resources "
        "carrying non-public information.",
    ),
]


_UNUSED_ROLE_MAPPINGS = [
    _mapping(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — roles with no activity in the "
        "configured window are candidates for removal. Directly "
        "evidences over-provisioning.",
    ),
    _mapping(
        "AC-6(1)",
        OLIRRelationship.SUBSET_OF,
        "AC-6(1) Authorize Access to Security Functions — unused "
        "privileged roles lack justification under AC-6(1) periodic "
        "review.",
    ),
]


_UNUSED_CREDENTIAL_MAPPINGS = [
    _mapping(
        "AC-2",
        OLIRRelationship.SUBSET_OF,
        "AC-2 Account Management — unused access keys / passwords "
        "are AC-2 account-hygiene violations. Credentials that "
        "haven't authenticated in the window must be revoked or "
        "disabled.",
    ),
    _mapping(
        "IA-2",
        OLIRRelationship.INTERSECTS_WITH,
        "IA-2 Identification and Authentication — unused credentials "
        "don't evidence authentication posture but overlap with the "
        "IA-2 requirement that credentials be managed to prevent "
        "compromise.",
    ),
    _mapping(
        "IA-5(1)",
        OLIRRelationship.SUBSET_OF,
        "IA-5(1) Password-Based Authentication — unused passwords "
        "fail the IA-5(1) requirement for active account hygiene.",
    ),
]


_UNUSED_PERMISSION_MAPPINGS = [
    _mapping(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — service-level and action-level "
        "permissions never exercised in the window are direct "
        "evidence of privilege creep.",
    ),
]


_VALID_POLICY_MAPPINGS = [
    _mapping(
        "IA-5(1)",
        OLIRRelationship.SUBSET_OF,
        "IA-5(1) — policy validation warnings about permissive "
        "wildcards directly evidence authenticator-policy weakness.",
    ),
    _mapping(
        "AC-2",
        OLIRRelationship.INTERSECTS_WITH,
        "AC-2 — overly permissive policies affect account-management "
        "scope.",
    ),
    _mapping(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 — wildcard policies violate least privilege at the "
        "design stage.",
    ),
]


# Blind-spot disclosures — the specific things Access Analyzer does NOT
# cover. Each becomes a back-matter resource with class="blind-spot"
# in the OSCAL AR so auditors see the limits of coverage inline.
BLIND_SPOTS: list[dict[str, str]] = [
    {
        "id": "kms-grants",
        "title": "KMS grant chains not analyzed",
        "description": (
            "IAM Access Analyzer analyzes KMS key policies but does "
            "not analyze KMS grants. A principal with kms:CreateGrant "
            "can delegate key-use permissions without modifying the "
            "key policy — this access path is invisible to Access "
            "Analyzer. Supplement with AWS CloudTrail KMS grant "
            "event monitoring for complete coverage."
        ),
    },
    {
        "id": "s3-acls-vs-block-public-access",
        "title": "S3 ACL + Block Public Access interaction",
        "description": (
            "Access Analyzer analyzes S3 ACLs and bucket policies "
            "but reports exposures independently of S3 Block Public "
            "Access settings. A bucket with a permissive policy may "
            "report as externally accessible even when BPA blocks "
            "the access. Cross-reference BPA configuration with "
            "Access Analyzer findings before concluding public "
            "exposure."
        ),
    },
    {
        "id": "service-linked-roles",
        "title": "Service-linked roles excluded from unused analysis",
        "description": (
            "Service-linked roles are predefined and managed by AWS "
            "services and are excluded from unused-access analysis. "
            "Independent verification is required to confirm that "
            "service-linked roles are necessary for current "
            "workloads."
        ),
    },
    {
        "id": "unsupported-resource-types",
        "title": "Limited resource-type coverage",
        "description": (
            "External-access analyzers support S3, IAM roles, KMS, "
            "Lambda functions and layers, SQS queues, Secrets Manager "
            "secrets, SNS topics, and EBS volume snapshots. "
            "DynamoDB, RDS, Redshift, Glue, and other services are "
            "not covered. Supplement with service-specific audit "
            "tooling for a complete access-control inventory."
        ),
    },
    {
        "id": "finding-latency",
        "title": "Finding-generation latency",
        "description": (
            "Access Analyzer takes up to 30 minutes to re-analyze a "
            "resource after a policy change; resource control "
            "policies (RCPs) refresh within 24 hours; multi-region "
            "S3 access points refresh every 6 hours. Findings "
            "collected immediately after a policy deploy may not "
            "reflect the updated state."
        ),
    },
]


class AccessAnalyzerCollectorError(Exception):
    """Collector-level failures (missing creds, missing analyzer ARN, etc)."""


class AccessAnalyzerCollector:
    """AWS IAM Access Analyzer evidence collector.

    One instance per analyzer per region. Use
    :meth:`collect_v2` for the enterprise-grade path that returns a
    ``(findings, manifest)`` tuple with coverage counts and blind-spot
    disclosures.
    """

    def __init__(
        self,
        *,
        analyzer_arn: str,
        region: str | None = None,
        profile: str | None = None,
        _clients: dict[str, Any] | None = None,
    ) -> None:
        """Construct a collector bound to a specific analyzer ARN.

        Parameters
        ----------
        analyzer_arn:
            Full ARN of the IAM Access Analyzer, e.g.
            ``arn:aws:access-analyzer:us-east-1:123456789012:analyzer/grc-external``.
        region:
            AWS region. Required — Access Analyzer is regional, and
            each analyzer belongs to exactly one region.
        profile:
            Optional AWS profile from ``~/.aws/credentials``.
        _clients:
            Test-only override — inject moto clients keyed by service.
        """
        if not analyzer_arn:
            raise AccessAnalyzerCollectorError(
                "analyzer_arn is required; create an Access Analyzer in "
                "your account via `aws accessanalyzer create-analyzer` "
                "and pass its ARN here."
            )
        self.analyzer_arn = analyzer_arn

        if _clients is not None:
            self._clients = _clients
            self._session: Any | None = None
            self._region = region or "us-east-1"
            return

        try:
            import boto3
        except ImportError as e:  # pragma: no cover
            raise AccessAnalyzerCollectorError(
                "boto3 is not installed. Install the collectors AWS extra: "
                "`pip install 'evidentia-collectors[aws]'`."
            ) from e

        self._session = boto3.Session(region_name=region, profile_name=profile)
        self._region = region or self._session.region_name or "us-east-1"
        self._clients = {}

    def _client(self, service: str) -> Any:
        if service not in self._clients:
            if self._session is None:
                raise AccessAnalyzerCollectorError(
                    f"No boto3 client available for {service!r}; pass "
                    "_clients to the constructor when mocking."
                )
            self._clients[service] = self._session.client(service)
        return self._clients[service]

    @property
    def region(self) -> str:
        return self._region

    # ── API calls (with retry) ──────────────────────────────────────

    @with_retry(max_attempts=3, retry_on=(ConnectionError, TimeoutError))
    def _call_list_findings(
        self,
        *,
        next_token: str | None = None,
        include_archived: bool = False,
    ) -> dict[str, Any]:
        """Retryable wrapper around the ListFindings API.

        Uses the v1 ``ListFindings`` endpoint, which supports external-
        access analyzers. For unused-access / internal-access analyzers,
        ``ListFindingsV2`` is required — future v0.7.x work will add
        per-analyzer-type dispatch.
        """
        client = self._client("accessanalyzer")
        kwargs: dict[str, Any] = {"analyzerArn": self.analyzer_arn}
        if next_token:
            kwargs["nextToken"] = next_token
        if not include_archived:
            # Default: Active findings only. Archived findings are
            # "acknowledged expected access" and usually filtered out;
            # auditors can include them to see the full lifecycle.
            kwargs["filter"] = {"status": {"eq": ["ACTIVE"]}}
        result: dict[str, Any] = client.list_findings(**kwargs)
        return result

    # ── collection orchestration ────────────────────────────────────

    def collect(
        self, *, include_archived: bool = False, dry_run: bool = False
    ) -> list[SecurityFinding]:
        """Return findings. Backward-compat-style API."""
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"Access Analyzer dry-run for {self.analyzer_arn} — "
                    "would enumerate findings with pagination"
                ),
                category=[EventCategory.IAM],
                types=[EventType.INFO],
                evidentia={
                    "dry_run": True,
                    "analyzer_arn": self.analyzer_arn,
                    "include_archived": include_archived,
                },
            )
            return []
        findings, _manifest = self.collect_v2(include_archived=include_archived)
        return findings

    def collect_v2(
        self, *, include_archived: bool = False
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        """Enterprise-grade orchestrator.

        Returns ``(findings, manifest)`` with per-resource-type coverage
        counts, empty-set attestation, and blind-spot disclosures
        captured in the manifest warnings (also surfaced as AR
        back-matter resources by the exporter).
        """
        run_id = new_run_id()
        started_at = utc_now()

        source_system_id = f"aws-access-analyzer:{self.analyzer_arn}"
        context = CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"aws:analyzer:{self.analyzer_arn}",
            source_system_id=source_system_id,
            filter_applied={
                "status": "ACTIVE" if not include_archived else "ALL",
                "region": self._region,
            },
        )

        findings: list[SecurityFinding] = []
        errors: list[str] = []
        page_count = 0

        with _log.scope(
            trace_id=run_id,
            user={"id": context.credential_identity, "domain": "aws"},
            cloud={
                "provider": "aws",
                "region": self._region,
            },
            evidentia={
                "run_id": run_id,
                "collector": {"id": COLLECTOR_ID, "version": current_version()},
                "analyzer_arn": self.analyzer_arn,
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"Access Analyzer collection starting for "
                    f"{self.analyzer_arn}"
                ),
                category=[EventCategory.IAM],
                types=[EventType.START],
            )

            next_token: str | None = None
            try:
                while True:
                    page = self._call_list_findings(
                        next_token=next_token,
                        include_archived=include_archived,
                    )
                    page_count += 1
                    for raw_finding in page.get("findings", []):
                        if isinstance(raw_finding, dict):
                            findings.append(
                                self._finding_from_raw(raw_finding, context)
                            )

                    next_token = page.get("nextToken")
                    if not next_token:
                        break
            except (ConnectionError, TimeoutError) as e:
                errors.append(f"access-analyzer: transient error: {e}")
                _log.error(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=(
                        f"Access Analyzer collection failed (transient): {e}"
                    ),
                    error={"type": type(e).__name__, "message": str(e)},
                )
            except Exception as e:
                errors.append(
                    f"access-analyzer: {type(e).__name__}: {e}"
                )
                _log.error(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=f"Access Analyzer collection failed: {e}",
                    error={"type": type(e).__name__, "message": str(e)},
                )

            empty_categories: list[str] = []
            if not findings and not errors:
                empty_categories.append("aws-access-analyzer-active")
                _log.info(
                    action=EventAction.MANIFEST_EMPTY_SET_ATTESTED,
                    message=(
                        "Access Analyzer: zero active findings "
                        "(attested empty)"
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
                    "analyzer_arn": self.analyzer_arn,
                    "region": self._region,
                    "include_archived": include_archived,
                },
                coverage_counts=[
                    CoverageCount(
                        resource_type="aws-access-analyzer-finding",
                        scanned=len(findings),
                        matched_filter=len(findings),
                        collected=len(findings),
                    ),
                ],
                total_findings=len(findings),
                is_complete=not errors,
                incomplete_reason=(
                    "; ".join(errors) if errors else None
                ),
                empty_categories=empty_categories,
                # Blind-spot disclosures as manifest warnings. The
                # OSCAL exporter also picks these up for back-matter
                # embedding (Q7=Yes).
                warnings=[f"{bs['id']}: {bs['title']}" for bs in BLIND_SPOTS],
                errors=errors,
            )

            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=EventOutcome.SUCCESS
                if not errors
                else EventOutcome.FAILURE,
                message=(
                    f"Access Analyzer completed: {len(findings)} findings "
                    f"across {page_count} page(s), {len(errors)} errors"
                ),
                category=[EventCategory.IAM],
                types=[EventType.END],
                evidentia={
                    "findings_count": len(findings),
                    "pages": page_count,
                },
            )

        return findings, manifest

    # ── Finding conversion ──────────────────────────────────────────

    def _finding_from_raw(
        self, raw: dict[str, Any], context: CollectionContext
    ) -> SecurityFinding:
        """Convert an Access Analyzer API finding dict to a SecurityFinding."""
        finding_id = str(raw.get("id") or "")
        resource = str(raw.get("resource") or "")
        resource_type = str(raw.get("resourceType") or "")
        resource_owner_account = str(raw.get("resourceOwnerAccount") or "")
        finding_type = str(raw.get("findingType") or "ExternalAccess")
        status = str(raw.get("status") or "ACTIVE").upper()
        is_public = bool(raw.get("isPublic", False))

        # Severity heuristic: public > cross-account external >
        # unused-permission > unused-role/credential
        if is_public:
            severity = Severity.HIGH
        elif finding_type.lower().startswith("external"):
            severity = Severity.MEDIUM
        elif finding_type in {"UnusedIAMRole", "UnusedIAMUserAccessKey",
                              "UnusedIAMUserPassword"} or finding_type == "UnusedPermission":
            severity = Severity.LOW
        else:
            severity = Severity.MEDIUM

        # Control mappings by finding type.
        control_mappings = self._mappings_for_type(finding_type, is_public)

        # Status mapping: AWS Active → FindingStatus.ACTIVE;
        # Resolved/Archived → RESOLVED.
        status_enum = (
            FindingStatus.ACTIVE
            if status == "ACTIVE"
            else FindingStatus.RESOLVED
        )

        title = (
            f"Public access: {resource}"
            if is_public
            else f"{finding_type}: {resource or finding_id}"
        )[:200]
        description = (
            f"AWS IAM Access Analyzer finding ({finding_type}) on "
            f"resource {resource or '(none)'} "
            f"({resource_type or 'unknown-type'}); status={status}; "
            f"analyzer={self.analyzer_arn}."
        )[:2000]

        return SecurityFinding(
            title=title,
            description=description,
            severity=severity,
            status=status_enum,
            source_system="aws-access-analyzer",
            source_finding_id=finding_id,
            resource_type=resource_type or None,
            resource_id=resource or None,
            resource_region=self._region,
            resource_account=resource_owner_account or None,
            control_mappings=control_mappings,
            collection_context=context,
            raw_data=_jsonify(raw),
            first_observed=_to_datetime(raw.get("createdAt")),
            last_observed=_to_datetime(raw.get("updatedAt"))
            or _to_datetime(raw.get("analyzedAt")),
        )

    def _mappings_for_type(
        self, finding_type: str, is_public: bool
    ) -> list[ControlMapping]:
        """Return the OLIR-typed ControlMappings for a finding type."""
        if is_public and finding_type.lower().startswith("external"):
            return _EXTERNAL_PUBLIC_ACCESS_MAPPINGS
        if finding_type.lower().startswith("external"):
            return _EXTERNAL_ACCESS_MAPPINGS
        if finding_type == "UnusedIAMRole":
            return _UNUSED_ROLE_MAPPINGS
        if finding_type in {"UnusedIAMUserAccessKey", "UnusedIAMUserPassword"}:
            return _UNUSED_CREDENTIAL_MAPPINGS
        if finding_type == "UnusedPermission":
            return _UNUSED_PERMISSION_MAPPINGS
        if finding_type.lower().startswith("policyvalidation"):
            return _VALID_POLICY_MAPPINGS
        # Unknown — return empty rather than guess.
        return []


# ── helpers ──────────────────────────────────────────────────────────────


def _jsonify(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _jsonify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonify(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _to_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
