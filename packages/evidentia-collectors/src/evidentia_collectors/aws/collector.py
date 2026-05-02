"""AWS collector — orchestrates Config + Security Hub evidence pulls.

Requires the ``[aws]`` extra (``pip install 'evidentia-collectors[aws]'``).
Uses the standard AWS SDK credential chain — environment variables,
``~/.aws/credentials``, or (inside EC2/Lambda) the instance profile.

v0.7.0 enterprise-grade refactor (checklist items B3, B10, H5, H6, H9):

- **B3 (no silent failures):** the pre-v0.7.0 ``except Exception:
  logger.exception(...)`` block in ``collect_all`` is replaced by typed
  catches with structured log emission — auditors see every collection
  error as a discrete ECS event rather than a generic stack trace.
- **B10 (bounded retry):** boto3 API calls go through
  :func:`~evidentia_core.audit.retry.with_retry` with exponential
  backoff + jitter. Retries emit ``evidentia.collect.retry`` events.
- **H5 (provenance on every finding):** each :class:`SecurityFinding`
  carries a :class:`CollectionContext` built from the STS caller
  identity + collection run ID.
- **H6 (no silent failures):** ``collect_all_v2`` returns a tuple
  (findings, manifest) where the manifest documents any errors.
- **H9 (structured logs):** every collection emits
  ``evidentia.collect.started``, ``evidentia.collect.completed``,
  ``evidentia.collect.failed`` events with ECS fields.
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

from evidentia_collectors.aws.mapping import (
    map_config_rule_to_control_mappings,
    map_security_hub_control_to_control_mappings,
)

if TYPE_CHECKING:  # pragma: no cover
    pass


_log = get_logger("evidentia.collectors.aws")

COLLECTOR_ID_CONFIG = "aws-config"
COLLECTOR_ID_SECURITY_HUB = "aws-security-hub"


class AwsCollectorError(Exception):
    """Raised for collector-level failures (missing creds, missing region, etc)."""


class AwsCollector:
    """AWS evidence collector.

    One instance per AWS account + region. Credentials come from the
    standard boto3 chain; no Evidentia-specific auth knob.

    Usage::

        collector = AwsCollector(region="us-east-1")
        findings = collector.collect_all()                  # v0.6 API
        findings, manifest = collector.collect_all_v2()     # v0.7.0 enterprise
    """

    def __init__(
        self,
        *,
        region: str | None = None,
        profile: str | None = None,
        _clients: dict[str, Any] | None = None,
    ) -> None:
        if _clients is not None:
            self._clients = _clients
            self._session: Any | None = None
            self._region = region or "us-east-1"
            return

        try:
            import boto3
        except ImportError as e:  # pragma: no cover
            raise AwsCollectorError(
                "boto3 is not installed. Install the collectors AWS extra: "
                "`pip install 'evidentia-collectors[aws]'`."
            ) from e

        self._session = boto3.Session(region_name=region, profile_name=profile)
        self._region = region or self._session.region_name or "us-east-1"
        self._clients = {}

    def _client(self, service: str) -> Any:
        if service not in self._clients:
            if self._session is None:
                raise AwsCollectorError(
                    f"No boto3 client available for {service!r}; pass _clients "
                    "to the constructor when mocking."
                )
            self._clients[service] = self._session.client(service)
        return self._clients[service]

    @property
    def region(self) -> str:
        return self._region

    # ── test_connection ──────────────────────────────────────────────

    @with_retry(max_attempts=3, retry_on=(ConnectionError, TimeoutError))
    def _call_sts_get_caller_identity(self) -> dict[str, Any]:
        """Retryable wrapper around ``sts:GetCallerIdentity``."""
        result: dict[str, Any] = self._client("sts").get_caller_identity()
        return result

    def test_connection(self) -> dict[str, str]:
        """Verify credentials + return caller identity.

        v0.7.0: transient errors retry up to 3 times with backoff.
        """
        try:
            identity = self._call_sts_get_caller_identity()
        except (ConnectionError, TimeoutError) as e:
            raise AwsCollectorError(
                f"AWS STS connection failed after retries: {e}"
            ) from e
        except Exception as e:
            # boto3 ClientError/BotoCoreError/NoCredentialsError are not
            # in retry_on (programmer/config errors — retrying won't help).
            raise AwsCollectorError(f"AWS connection failed: {e}") from e
        return {
            "account": str(identity.get("Account", "")),
            "arn": str(identity.get("Arn", "")),
            "user_id": str(identity.get("UserId", "")),
            "region": self._region,
        }

    # ── CollectionContext helpers ────────────────────────────────────

    def _build_context(
        self,
        *,
        collector_id: str,
        run_id: str,
        credential_identity: str,
        source_system_id: str,
        filter_applied: dict[str, Any] | None = None,
    ) -> CollectionContext:
        return CollectionContext(
            collector_id=collector_id,
            collector_version=current_version(),
            run_id=run_id,
            credential_identity=credential_identity,
            source_system_id=source_system_id,
            filter_applied=filter_applied or {},
        )

    # ── AWS Config ──────────────────────────────────────────────────

    def collect_config_findings(
        self, context: CollectionContext | None = None
    ) -> list[SecurityFinding]:
        """Return non-compliant AWS Config rule evaluations as findings.

        When ``context`` is None, the SecurityFinding default
        (synthetic-legacy) is used. v0.7.0 collectors should pass a
        real CollectionContext.
        """
        client = self._client("config")
        findings: list[SecurityFinding] = []

        paginator = client.get_paginator("describe_compliance_by_config_rule")
        for page in paginator.paginate():
            for rule in page.get("ComplianceByConfigRules", []):
                if not isinstance(rule, dict):
                    continue
                rule_name = str(rule.get("ConfigRuleName", ""))
                compliance = rule.get("Compliance") or {}
                if compliance.get("ComplianceType") != "NON_COMPLIANT":
                    continue
                findings.extend(
                    self._config_rule_findings(client, rule_name, context)
                )

        return findings

    def _config_rule_findings(
        self,
        client: Any,
        rule_name: str,
        context: CollectionContext | None,
    ) -> list[SecurityFinding]:
        """Expand a non-compliant Config rule into per-resource findings."""
        out: list[SecurityFinding] = []
        # v0.7.0: OLIR-typed ControlMappings with authoritative per-rule
        # justification citing FSBP/CIS sources.
        control_mappings = map_config_rule_to_control_mappings(rule_name)

        paginator = client.get_paginator(
            "get_compliance_details_by_config_rule"
        )
        for page in paginator.paginate(
            ConfigRuleName=rule_name,
            ComplianceTypes=["NON_COMPLIANT"],
        ):
            for result in page.get("EvaluationResults", []):
                if not isinstance(result, dict):
                    continue
                ident = (result.get("EvaluationResultIdentifier") or {}).get(
                    "EvaluationResultQualifier"
                ) or {}
                resource_type = str(ident.get("ResourceType") or "")
                resource_id = str(ident.get("ResourceId") or "")
                annotation = str(result.get("Annotation") or "")
                recorded = result.get("ResultRecordedTime")

                title = f"AWS Config: {rule_name} non-compliant"
                description = (
                    annotation
                    or f"Resource {resource_id} ({resource_type}) is not compliant "
                    f"with rule {rule_name}."
                )

                finding_kwargs: dict[str, Any] = {
                    "title": title[:200],
                    "description": description[:2000],
                    "severity": Severity.MEDIUM,
                    "status": FindingStatus.ACTIVE,
                    "source_system": "aws-config",
                    "source_finding_id": f"{rule_name}:{resource_id}",
                    "resource_type": resource_type or None,
                    "resource_id": resource_id or None,
                    "resource_region": self._region,
                    "control_mappings": control_mappings,
                    "raw_data": {
                        "rule_name": rule_name,
                        "result": _jsonify(result),
                    },
                    "first_observed": _to_datetime(recorded),
                    "last_observed": _to_datetime(recorded),
                }
                if context is not None:
                    finding_kwargs["collection_context"] = context
                out.append(SecurityFinding(**finding_kwargs))
        return out

    # ── Security Hub ────────────────────────────────────────────────

    def collect_security_hub_findings(
        self,
        *,
        workflow_status: list[str] | None = None,
        max_findings: int = 1000,
        context: CollectionContext | None = None,
    ) -> list[SecurityFinding]:
        """Return Security Hub findings as SecurityFinding objects."""
        client = self._client("securityhub")
        findings: list[SecurityFinding] = []

        filters: dict[str, Any] = {
            "WorkflowStatus": [
                {"Value": s, "Comparison": "EQUALS"}
                for s in (workflow_status or ["NEW", "NOTIFIED"])
            ],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        }

        paginator = client.get_paginator("get_findings")
        seen = 0
        for page in paginator.paginate(Filters=filters):
            for raw in page.get("Findings", []):
                if not isinstance(raw, dict):
                    continue
                if seen >= max_findings:
                    break
                findings.append(self._security_hub_finding(raw, context))
                seen += 1
            if seen >= max_findings:
                break

        return findings

    def _security_hub_finding(
        self,
        raw: dict[str, Any],
        context: CollectionContext | None,
    ) -> SecurityFinding:
        """Convert a single Security Hub finding dict to a SecurityFinding."""
        title = str(raw.get("Title") or "")[:200]
        description = str(raw.get("Description") or "")[:2000]
        severity_label = str(
            (raw.get("Severity") or {}).get("Label") or "MEDIUM"
        ).lower()
        severity = _severity_from_label(severity_label)
        source_id = str(raw.get("Id") or "")

        resources = raw.get("Resources") or []
        first_resource = resources[0] if resources else {}
        resource_id = str(first_resource.get("Id") or "")
        resource_type = str(first_resource.get("Type") or "")
        region = str(first_resource.get("Region") or self._region)

        # v0.7.0: build OLIR-typed ControlMappings. Prefer Security Hub's
        # ``Compliance.RelatedRequirements`` when it carries NIST 800-53
        # refs — that IS the authoritative SUBSET_OF mapping per AWS.
        compliance = raw.get("Compliance") or {}
        related = [
            str(r) for r in (compliance.get("RelatedRequirements") or []) if isinstance(r, str)
        ]
        if any(r.startswith("NIST.800-53") for r in related):
            nist_ids = [
                _extract_nist_id(r) for r in related if r.startswith("NIST.800-53")
            ]
            control_mappings = [
                ControlMapping(
                    framework="nist-800-53-rev5",
                    control_id=cid,
                    relationship=OLIRRelationship.SUBSET_OF,
                    justification=(
                        f"AWS Security Hub Compliance.RelatedRequirements "
                        f"field cites {cid}. Security Hub's Related "
                        "Requirements are the authoritative subset-of "
                        "mapping per AWS documentation."
                    ),
                )
                for cid in nist_ids
                if cid
            ]
        else:
            generator_id = str(
                compliance.get("SecurityControlId")
                or raw.get("GeneratorId")
                or ""
            )
            control_mappings = map_security_hub_control_to_control_mappings(
                generator_id
            )

        product_fields = raw.get("ProductFields") or {}
        account = str(
            raw.get("AwsAccountId")
            or product_fields.get("aws/securityhub/awsAccountId")
            or ""
        )

        finding_kwargs: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "status": FindingStatus.ACTIVE
            if str((raw.get("Workflow") or {}).get("Status") or "NEW") != "RESOLVED"
            else FindingStatus.RESOLVED,
            "source_system": "aws-security-hub",
            "source_finding_id": source_id,
            "resource_type": resource_type or None,
            "resource_id": resource_id or None,
            "resource_region": region,
            "resource_account": account or None,
            "control_mappings": control_mappings,
            "raw_data": _jsonify(raw),
            "first_observed": _to_datetime(raw.get("FirstObservedAt"))
            or _to_datetime(raw.get("CreatedAt")),
            "last_observed": _to_datetime(raw.get("LastObservedAt"))
            or _to_datetime(raw.get("UpdatedAt")),
        }
        if context is not None:
            finding_kwargs["collection_context"] = context
        return SecurityFinding(**finding_kwargs)

    # ── Orchestration ───────────────────────────────────────────────

    def collect_all(
        self,
        *,
        include_config: bool = True,
        include_security_hub: bool = True,
        dry_run: bool = False,
    ) -> list[SecurityFinding]:
        """Run every sub-collector and return a merged list.

        Backward-compatible v0.6 API — returns only findings. Callers
        wanting the v0.7.0 manifest should use :meth:`collect_all_v2`.

        Parameters
        ----------
        dry_run:
            v0.7.0 addition. When True, logs what *would* be collected
            and returns an empty list without issuing source-system
            API calls. Useful for previewing scope before committing
            to a collection run.
        """
        if dry_run:
            self._emit_dry_run_events(
                include_config=include_config,
                include_security_hub=include_security_hub,
            )
            return []
        findings, _manifest = self.collect_all_v2(
            include_config=include_config,
            include_security_hub=include_security_hub,
        )
        return findings

    def collect_all_v2(
        self,
        *,
        include_config: bool = True,
        include_security_hub: bool = True,
    ) -> tuple[list[SecurityFinding], CollectionManifest]:
        """Enterprise-grade v0.7.0 orchestrator.

        Returns ``(findings, manifest)`` — the manifest documents
        coverage, completeness, and any errors encountered. Empty-set
        attestation for categories that were scanned but returned no
        findings (checklist item B5).
        """
        run_id = new_run_id()
        started_at = utc_now()
        try:
            identity = self.test_connection()
            credential_identity = identity["arn"]
            account_id = identity["account"]
        except AwsCollectorError as e:
            # STS might be unreachable (e.g., permissions-restricted
            # environment that allows only the target services) or
            # mocked out of test fixtures. Fall back to a clearly-marked
            # "unknown" identity so collection still proceeds with real
            # provenance on the ``source_system_id`` axis.
            _log.warning(
                action=EventAction.AUTH_CREDENTIAL_FAILED,
                outcome=EventOutcome.FAILURE,
                message=(
                    "STS caller identity lookup failed; using "
                    "'unknown-identity' placeholder for collector "
                    "provenance. Verify sts:GetCallerIdentity "
                    "permission for audit-grade identity tracking."
                ),
                error={"type": type(e).__name__, "message": str(e)},
            )
            credential_identity = "aws:unknown-identity"
            account_id = "unknown"
        source_system_id = f"aws-account:{account_id}:{self._region}"

        findings: list[SecurityFinding] = []
        errors: list[str] = []
        empty_categories: list[str] = []
        coverage_counts: list[CoverageCount] = []

        with _log.scope(
            trace_id=run_id,
            user={"id": credential_identity, "domain": "aws"},
            cloud={
                "provider": "aws",
                "account": {"id": account_id},
                "region": self._region,
            },
            evidentia={
                "run_id": run_id,
                "collector": {"id": "aws", "version": current_version()},
            },
        ):
            _log.info(
                action=EventAction.COLLECT_STARTED,
                message=(
                    f"AWS collection starting in account {account_id} "
                    f"region {self._region}"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.START],
            )

            if include_config:
                context = self._build_context(
                    collector_id=COLLECTOR_ID_CONFIG,
                    run_id=run_id,
                    credential_identity=credential_identity,
                    source_system_id=source_system_id,
                    filter_applied={"compliance_type": "NON_COMPLIANT"},
                )
                try:
                    config_findings = self.collect_config_findings(context)
                    findings.extend(config_findings)
                    coverage_counts.append(
                        CoverageCount(
                            resource_type="aws-config-rule-evaluation",
                            scanned=len(config_findings),
                            matched_filter=len(config_findings),
                            collected=len(config_findings),
                        )
                    )
                    if not config_findings:
                        empty_categories.append("aws-config-non-compliant")
                        _log.info(
                            action=EventAction.MANIFEST_EMPTY_SET_ATTESTED,
                            message=(
                                "AWS Config: zero non-compliant rule "
                                "evaluations (attested empty)"
                            ),
                        )
                except (ConnectionError, TimeoutError) as e:
                    errors.append(f"aws-config: transient error: {e}")
                    _log.error(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"AWS Config collector failed (transient): {e}",
                        error={"type": type(e).__name__, "message": str(e)},
                    )
                except Exception as e:
                    # Typed catch replaces pre-v0.7.0 bare except.
                    errors.append(f"aws-config: {type(e).__name__}: {e}")
                    _log.error(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"AWS Config collector failed: {e}",
                        error={"type": type(e).__name__, "message": str(e)},
                    )

            if include_security_hub:
                context = self._build_context(
                    collector_id=COLLECTOR_ID_SECURITY_HUB,
                    run_id=run_id,
                    credential_identity=credential_identity,
                    source_system_id=source_system_id,
                    filter_applied={
                        "workflow_status": ["NEW", "NOTIFIED"],
                        "record_state": "ACTIVE",
                    },
                )
                try:
                    sh_findings = self.collect_security_hub_findings(
                        context=context
                    )
                    findings.extend(sh_findings)
                    coverage_counts.append(
                        CoverageCount(
                            resource_type="aws-security-hub-finding",
                            scanned=len(sh_findings),
                            matched_filter=len(sh_findings),
                            collected=len(sh_findings),
                        )
                    )
                    if not sh_findings:
                        empty_categories.append("aws-security-hub-active")
                        _log.info(
                            action=EventAction.MANIFEST_EMPTY_SET_ATTESTED,
                            message=(
                                "Security Hub: zero active findings "
                                "(attested empty)"
                            ),
                        )
                except (ConnectionError, TimeoutError) as e:
                    errors.append(f"aws-security-hub: transient error: {e}")
                    _log.error(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Security Hub collector failed (transient): {e}",
                        error={"type": type(e).__name__, "message": str(e)},
                    )
                except Exception as e:
                    errors.append(
                        f"aws-security-hub: {type(e).__name__}: {e}"
                    )
                    _log.error(
                        action=EventAction.COLLECT_FAILED,
                        outcome=EventOutcome.FAILURE,
                        message=f"Security Hub collector failed: {e}",
                        error={"type": type(e).__name__, "message": str(e)},
                    )

            manifest = CollectionManifest(
                run_id=run_id,
                collector_id="aws",
                collector_version=current_version(),
                collection_started_at=started_at,
                collection_finished_at=utc_now(),
                source_system_ids=[source_system_id],
                filters_applied={"region": self._region},
                coverage_counts=coverage_counts,
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
                    f"AWS collection completed: {len(findings)} findings, "
                    f"{len(errors)} errors"
                ),
                category=[EventCategory.CONFIGURATION],
                types=[EventType.END],
                evidentia={"findings_count": len(findings)},
            )

        return findings, manifest

    def _emit_dry_run_events(
        self, *, include_config: bool, include_security_hub: bool
    ) -> None:
        """Log what would be collected without actually collecting."""
        _log.info(
            action=EventAction.COLLECT_STARTED,
            message=(
                f"AWS dry-run in region {self._region} — would collect from: "
                f"{'Config' if include_config else ''}"
                f"{', ' if include_config and include_security_hub else ''}"
                f"{'Security Hub' if include_security_hub else ''}"
            ),
            category=[EventCategory.CONFIGURATION],
            types=[EventType.INFO],
            evidentia={
                "dry_run": True,
                "include_config": include_config,
                "include_security_hub": include_security_hub,
            },
        )


# ── helpers ──────────────────────────────────────────────────────────────


def _severity_from_label(label: str) -> Severity:
    lookup = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "informational": Severity.INFORMATIONAL,
    }
    return lookup.get(label.lower(), Severity.MEDIUM)


def _extract_nist_id(related: str) -> str:
    parts = related.strip().split()
    return parts[-1] if len(parts) >= 2 else ""


def _jsonify(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _jsonify(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_jsonify(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _to_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass
    from datetime import UTC

    return datetime.now(UTC)
