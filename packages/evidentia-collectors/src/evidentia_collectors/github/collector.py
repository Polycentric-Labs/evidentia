"""GitHub evidence collector.

Assembles :class:`SecurityFinding` instances from three observations:
branch protection, CODEOWNERS presence, and repository visibility.

v0.7.0 enterprise-grade refactor:

- Every inline control mapping converted to an OLIR-typed
  :class:`ControlMapping` with per-entry justification.
- Every emitted :class:`SecurityFinding` carries a
  :class:`CollectionContext`.
- ``collect_v2`` returns ``(findings, manifest)`` for completeness
  attestation. Pre-v0.7.0 ``collect() -> list[SecurityFinding]``
  preserved for backward compat, plus a new ``dry_run=True`` flag.
- Structured log events at ``evidentia.collect.*`` for audit trail.
"""

from __future__ import annotations

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
)
from evidentia_core.models.common import (
    ControlMapping,
    OLIRRelationship,
    Severity,
    current_version,
    utc_now,
)
from evidentia_core.models.finding import (
    ComplianceStatus,
    FindingStatus,
    SecurityFinding,
)

from evidentia_collectors.github.client import (
    GitHubApiError,
    GitHubClient,
)

_log = get_logger("evidentia.collectors.github")

COLLECTOR_ID = "github-repo-scan"


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


# OLIR-typed control mapping tables. Each rule's classification is
# spot-checked against NIST SP 800-53 Rev 5 control families and the
# specific GitHub feature's security role.

_VISIBILITY_MAPPINGS = [
    _mapping(
        "AC-3",
        OLIRRelationship.INTERSECTS_WITH,
        "Repository visibility (private vs public) is one axis of "
        "AC-3 Access Enforcement — intersects with AC-3 but doesn't "
        "subsume it.",
    ),
    _mapping(
        "AC-6",
        OLIRRelationship.INTERSECTS_WITH,
        "Private visibility constrains who can read source — one "
        "aspect of AC-6 Least Privilege.",
    ),
]

_BRANCH_UNPROTECTED_MAPPINGS = [
    _mapping(
        "SA-11",
        OLIRRelationship.SUBSET_OF,
        "SA-11 Developer Security Testing — branch protection is the "
        "gate that forces review; missing it = SA-11 gap.",
    ),
    _mapping(
        "CM-2",
        OLIRRelationship.INTERSECTS_WITH,
        "CM-2 Baseline Configuration — protected branches are the "
        "baseline; unprotected branch means no enforced baseline.",
    ),
    _mapping(
        "CM-3",
        OLIRRelationship.SUBSET_OF,
        "CM-3 Configuration Change Control — unprotected branch "
        "bypasses change-control review entirely.",
    ),
    _mapping(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — protection rules ARE the "
        "enforcement; without them, any write-access principal can "
        "push directly.",
    ),
]

_BRANCH_READ_ERROR_MAPPINGS = [
    _mapping(
        "SA-11",
        OLIRRelationship.RELATED_TO,
        "Unable to verify branch protection posture — SA-11 evidence "
        "indeterminate.",
    ),
    _mapping(
        "CM-3",
        OLIRRelationship.RELATED_TO,
        "Configuration Change Control verification failed — "
        "audit-review should treat as 'unknown state'.",
    ),
]

_PR_REVIEW_MAPPINGS = [
    _mapping(
        "SA-11",
        OLIRRelationship.SUBSET_OF,
        "SA-11 Developer Security Testing — required PR review is a "
        "concrete implementation of peer review before merge.",
    ),
    _mapping(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — PR review gate ensures only "
        "approved changes land on the protected branch.",
    ),
]

_STATUS_CHECK_MAPPINGS = [
    _mapping(
        "SA-11",
        OLIRRelationship.SUBSET_OF,
        "SA-11 — required status checks enforce automated test/SAST/"
        "dependency-scan gates before merge.",
    ),
    _mapping(
        "SI-2",
        OLIRRelationship.INTERSECTS_WITH,
        "SI-2 Flaw Remediation — status checks often include "
        "vulnerability scans; blocking merge on failures enforces "
        "timely remediation.",
    ),
]

_ENFORCE_ADMINS_MAPPINGS = [
    _mapping(
        "AC-6",
        OLIRRelationship.SUBSET_OF,
        "AC-6 Least Privilege — enforce_admins=true means admin "
        "privileges don't include 'skip review'.",
    ),
    _mapping(
        "CM-3",
        OLIRRelationship.SUBSET_OF,
        "CM-3 Configuration Change Control — closes the admin-bypass "
        "loophole that defeats CM-3.",
    ),
]

_CODEOWNERS_MAPPINGS = [
    _mapping(
        "SA-11",
        OLIRRelationship.SUBSET_OF,
        "SA-11 Developer Security Testing — CODEOWNERS enforces "
        "reviewer selection.",
    ),
    _mapping(
        "AC-3",
        OLIRRelationship.SUBSET_OF,
        "AC-3 Access Enforcement — CODEOWNERS constrains who can "
        "approve changes to specific file paths.",
    ),
]


class GitHubCollectorError(Exception):
    """Raised for collector-level failures — missing token, missing repo, etc."""


class GitHubCollector:
    """Collect evidence findings from a single GitHub repository."""

    def __init__(
        self,
        *,
        owner: str,
        repo: str,
        token: str | None = None,
        client: GitHubClient | None = None,
    ) -> None:
        if not owner or not repo:
            raise GitHubCollectorError(
                "GitHubCollector requires non-empty owner + repo."
            )
        self.owner = owner
        self.repo = repo
        self._client = client or GitHubClient(token=token)
        self._owns_client = client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> GitHubCollector:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"

    def _build_context(self, run_id: str) -> CollectionContext:
        """Build a CollectionContext for this run."""
        return CollectionContext(
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=f"github-token:scope:{self.slug}",
            source_system_id=f"github:{self.slug}",
            filter_applied={"repo": self.slug},
        )

    # ── High-level orchestration ────────────────────────────────────

    def collect(self, *, dry_run: bool = False) -> list[SecurityFinding]:
        """Run every sub-check and return the merged findings list.

        Backward-compatible v0.6 API. v0.7.0 callers wanting the
        completeness manifest should use :meth:`collect_v2`.

        v0.7.0 adds ``dry_run=True`` to preview scope without API calls.
        """
        if dry_run:
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"GitHub dry-run for {self.slug} — would collect: "
                    "visibility, branch protection, CODEOWNERS"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.INFO],
                evidentia={"dry_run": True, "repo": self.slug},
            )
            return []
        findings, _manifest = self.collect_v2()
        return findings

    def collect_v2(
        self,
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        """Enterprise-grade v0.7.0 orchestrator."""
        run_id = new_run_id()
        started_at = utc_now()
        context = self._build_context(run_id)

        errors: list[str] = []
        findings: list[SecurityFinding] = []

        with _log.scope(
            trace_id=run_id,
            user={
                "id": context.credential_identity,
                "domain": "github.com",
            },
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
                message=f"GitHub collection starting for {self.slug}",
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            try:
                repo_meta = self._client.get_repo(self.owner, self.repo)
            except GitHubApiError as e:
                _log.error(
                    action=EventAction.COLLECT_FAILED,
                    outcome=EventOutcome.FAILURE,
                    message=f"Could not read repo {self.slug}: {e}",
                    error={"type": "GitHubApiError", "message": str(e)},
                )
                raise GitHubCollectorError(
                    f"Could not read repo {self.slug}: {e}"
                ) from e

            findings.extend(self._visibility_finding(repo_meta, context))
            findings.extend(
                self._branch_protection_findings(repo_meta, context)
            )
            findings.extend(self._codeowners_finding(context))

            _log.info(
                action=EventAction.COLLECT_COMPLETED,
                outcome=EventOutcome.SUCCESS
                if not errors
                else EventOutcome.FAILURE,
                message=(
                    f"GitHub collection completed: {len(findings)} findings"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.END],
                evidentia={"findings_count": len(findings)},
            )

        manifest = CollectionManifest(
            run_id=run_id,
            collector_id=COLLECTOR_ID,
            collector_version=current_version(),
            collection_started_at=started_at,
            collection_finished_at=utc_now(),
            source_system_ids=[f"github:{self.slug}"],
            filters_applied={"repo": self.slug},
            coverage_counts=[
                CoverageCount(
                    resource_type="github-repository",
                    scanned=1,
                    matched_filter=1,
                    collected=1,
                ),
                CoverageCount(
                    resource_type="github-branch-protection",
                    scanned=1,
                    matched_filter=1,
                    collected=sum(
                        1
                        for f in findings
                        if f.resource_type == "GitHub::Branch"
                    ),
                ),
            ],
            total_findings=len(findings),
            is_complete=not errors,
            incomplete_reason="; ".join(errors) if errors else None,
            errors=errors,
        )
        return findings, manifest

    # ── Sub-checks ──────────────────────────────────────────────────

    def _visibility_finding(
        self, repo_meta: dict[str, Any], context: CollectionContext
    ) -> list[SecurityFinding]:
        is_private = bool(repo_meta.get("private", False))
        visibility = str(repo_meta.get("visibility", "unknown"))

        if is_private:
            return [
                SecurityFinding(
                    title=f"GitHub repo {self.slug} is private",
                    description=(
                        f"Repository {self.slug} visibility is {visibility!r}. "
                        "Source code is not publicly accessible."
                    ),
                    severity=Severity.INFORMATIONAL,
                    status=FindingStatus.RESOLVED,
                    # v0.10.0: a private repo satisfies the visibility
                    # access-control posture this finding evidences.
                    compliance_status=ComplianceStatus.PASS,
                    source_system="github",
                    source_finding_id=f"{self.slug}:visibility",
                    resource_type="GitHub::Repository",
                    resource_id=self.slug,
                    control_mappings=_VISIBILITY_MAPPINGS,
                    collection_context=context,
                    raw_data={"visibility": visibility, "private": is_private},
                )
            ]
        return [
            SecurityFinding(
                title=f"GitHub repo {self.slug} is public",
                description=(
                    f"Repository {self.slug} is publicly visible. "
                    "Verify this matches the organization's open-source "
                    "policy."
                ),
                severity=Severity.MEDIUM,
                status=FindingStatus.ACTIVE,
                # v0.10.0: a public repo is not a hard failure, but
                # warrants review against the org's open-source policy.
                compliance_status=ComplianceStatus.WARNING,
                source_system="github",
                source_finding_id=f"{self.slug}:visibility",
                resource_type="GitHub::Repository",
                resource_id=self.slug,
                control_mappings=_VISIBILITY_MAPPINGS,
                collection_context=context,
                raw_data={"visibility": visibility, "private": is_private},
            )
        ]

    def _branch_protection_findings(
        self, repo_meta: dict[str, Any], context: CollectionContext
    ) -> list[SecurityFinding]:
        default_branch = str(repo_meta.get("default_branch") or "main")
        try:
            protection = self._client.get_branch_protection(
                self.owner, self.repo, default_branch
            )
        except GitHubApiError as e:
            return [
                SecurityFinding(
                    title=f"Could not read branch protection for {self.slug}@{default_branch}",
                    description=str(e),
                    severity=Severity.LOW,
                    status=FindingStatus.ACTIVE,
                    # v0.10.0: branch-protection state could not be read
                    # — the check result is indeterminate, not failed.
                    compliance_status=ComplianceStatus.UNKNOWN,
                    source_system="github",
                    source_finding_id=f"{self.slug}:{default_branch}:protection-error",
                    resource_type="GitHub::Branch",
                    resource_id=f"{self.slug}:{default_branch}",
                    control_mappings=_BRANCH_READ_ERROR_MAPPINGS,
                    collection_context=context,
                )
            ]

        if protection is None:
            return [
                SecurityFinding(
                    title=(
                        f"Default branch {default_branch!r} in {self.slug} "
                        "has no branch protection"
                    ),
                    description=(
                        "Branch protection is not enabled on the default "
                        "branch. Anyone with write access can push directly "
                        "bypassing PR review."
                    ),
                    severity=Severity.HIGH,
                    status=FindingStatus.ACTIVE,
                    # v0.10.0: no branch protection on the default branch
                    # is a failed access-enforcement / change-control check.
                    compliance_status=ComplianceStatus.FAIL,
                    source_system="github",
                    source_finding_id=f"{self.slug}:{default_branch}:unprotected",
                    resource_type="GitHub::Branch",
                    resource_id=f"{self.slug}:{default_branch}",
                    control_mappings=_BRANCH_UNPROTECTED_MAPPINGS,
                    collection_context=context,
                )
            ]

        findings: list[SecurityFinding] = []

        pr_review = (protection.get("required_pull_request_reviews") or {})
        reviewers = int(pr_review.get("required_approving_review_count", 0))
        findings.append(
            _finding(
                slug=self.slug,
                branch=default_branch,
                rule="pr_review",
                title=f"PR review required on {default_branch!r}"
                if reviewers > 0
                else f"PR review NOT required on {default_branch!r}",
                description=(
                    f"{reviewers} approving review(s) required before merge."
                    if reviewers > 0
                    else "No approving reviews required."
                ),
                severity=Severity.INFORMATIONAL if reviewers > 0 else Severity.HIGH,
                status=FindingStatus.RESOLVED if reviewers > 0 else FindingStatus.ACTIVE,
                compliance_status=ComplianceStatus.PASS
                if reviewers > 0
                else ComplianceStatus.FAIL,
                control_mappings=_PR_REVIEW_MAPPINGS,
                collection_context=context,
                raw=pr_review,
            )
        )

        status_checks = (protection.get("required_status_checks") or {})
        contexts = status_checks.get("contexts") or []
        findings.append(
            _finding(
                slug=self.slug,
                branch=default_branch,
                rule="status_checks",
                title=f"Status checks required on {default_branch!r}"
                if contexts
                else f"No required status checks on {default_branch!r}",
                description=(
                    f"{len(contexts)} required check(s): {', '.join(contexts[:5])}"
                    f"{'...' if len(contexts) > 5 else ''}"
                    if contexts
                    else "No required status checks. CI can be bypassed."
                ),
                severity=Severity.INFORMATIONAL if contexts else Severity.MEDIUM,
                status=FindingStatus.RESOLVED if contexts else FindingStatus.ACTIVE,
                compliance_status=ComplianceStatus.PASS
                if contexts
                else ComplianceStatus.FAIL,
                control_mappings=_STATUS_CHECK_MAPPINGS,
                collection_context=context,
                raw=status_checks,
            )
        )

        enforce_admins = bool(
            (protection.get("enforce_admins") or {}).get("enabled", False)
        )
        findings.append(
            _finding(
                slug=self.slug,
                branch=default_branch,
                rule="enforce_admins",
                title="Admin bypass "
                + ("disabled" if enforce_admins else "allowed")
                + f" on {default_branch!r}",
                description=(
                    "Admins cannot bypass branch protection."
                    if enforce_admins
                    else "Admins can bypass branch protection rules."
                ),
                severity=Severity.INFORMATIONAL if enforce_admins else Severity.MEDIUM,
                status=FindingStatus.RESOLVED if enforce_admins else FindingStatus.ACTIVE,
                compliance_status=ComplianceStatus.PASS
                if enforce_admins
                else ComplianceStatus.FAIL,
                control_mappings=_ENFORCE_ADMINS_MAPPINGS,
                collection_context=context,
                raw={"enforce_admins": enforce_admins},
            )
        )

        return findings

    def _codeowners_finding(
        self, context: CollectionContext
    ) -> list[SecurityFinding]:
        for path in (".github/CODEOWNERS", "docs/CODEOWNERS", "CODEOWNERS"):
            try:
                content = self._client.get_contents(self.owner, self.repo, path)
            except GitHubApiError:
                continue
            if content is not None:
                return [
                    SecurityFinding(
                        title=f"CODEOWNERS present in {self.slug}",
                        description=(
                            f"Code review ownership defined at {path!r}."
                        ),
                        severity=Severity.INFORMATIONAL,
                        status=FindingStatus.RESOLVED,
                        # v0.10.0: a present CODEOWNERS file satisfies
                        # the reviewer-ownership check.
                        compliance_status=ComplianceStatus.PASS,
                        source_system="github",
                        source_finding_id=f"{self.slug}:codeowners",
                        resource_type="GitHub::Repository",
                        resource_id=self.slug,
                        control_mappings=_CODEOWNERS_MAPPINGS,
                        collection_context=context,
                        raw_data={"path": path},
                    )
                ]
        return [
            SecurityFinding(
                title=f"CODEOWNERS missing in {self.slug}",
                description=(
                    "No CODEOWNERS file found. Code review ownership is "
                    "implicit rather than enforced."
                ),
                severity=Severity.MEDIUM,
                status=FindingStatus.ACTIVE,
                # v0.10.0: a missing CODEOWNERS file is a failed
                # reviewer-ownership check.
                compliance_status=ComplianceStatus.FAIL,
                source_system="github",
                source_finding_id=f"{self.slug}:codeowners-missing",
                resource_type="GitHub::Repository",
                resource_id=self.slug,
                control_mappings=_CODEOWNERS_MAPPINGS,
                collection_context=context,
            )
        ]


def _finding(
    *,
    slug: str,
    branch: str,
    rule: str,
    title: str,
    description: str,
    severity: Severity,
    status: FindingStatus,
    compliance_status: ComplianceStatus,
    control_mappings: list[ControlMapping],
    collection_context: CollectionContext,
    raw: Any,
) -> SecurityFinding:
    return SecurityFinding(
        title=title[:200],
        description=description[:2000],
        severity=severity,
        status=status,
        compliance_status=compliance_status,
        source_system="github",
        source_finding_id=f"{slug}:{branch}:{rule}",
        resource_type="GitHub::Branch",
        resource_id=f"{slug}:{branch}",
        control_mappings=control_mappings,
        collection_context=collection_context,
        raw_data=raw,
    )
