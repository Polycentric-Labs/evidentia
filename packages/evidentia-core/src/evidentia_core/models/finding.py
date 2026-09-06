"""Security finding model for collector outputs.

Collectors produce findings (raw security observations from systems).
Findings are then transformed into OSCAL Assessment Results documents
with explicit control mappings.

v0.7.0 schema upgrade:

- ``control_ids: list[str]`` is replaced by ``control_mappings:
  list[ControlMapping]`` with OLIR relationship typing + justification
  on every mapping. The old ``control_ids`` kwarg is still accepted on
  construction for backward compatibility (auto-converted via
  ``@model_validator``); a read-only ``.control_ids`` property returns
  the plain IDs for callers that only need them.
- ``collection_context: CollectionContext`` is a new field capturing
  per-finding provenance. Defaults to a synthetic-legacy context so
  pre-v0.7.0 construction sites keep working; upgraded collectors
  (v0.7.0+) pass real context.

v0.10.0 schema upgrade (OCSF alignment):

- ``compliance_status: ComplianceStatus`` records the pass/fail
  result of the checked control, mirroring the OCSF Compliance
  Finding ``compliance.status`` field. Defaults to ``UNKNOWN`` so
  pre-v0.10.0 construction sites (and collectors not yet migrated)
  keep working without asserting a result.
- ``remediation: str | None`` carries optional remediation guidance,
  mapping to the OCSF Compliance Finding ``remediation.desc`` field.

Both fields are additive and optional — v0.7.x / v0.8.x / v0.9.x
serialized findings re-parse cleanly. See ``docs/releases/plans/v0.10.0-plan.md``
for the OCSF mapping design.

See :mod:`evidentia_core.audit.provenance` for the CollectionContext
model and :class:`~evidentia_core.models.common.OLIRRelationship` for
the relationship vocabulary.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from pydantic import Field, model_validator

from evidentia_core.audit.provenance import CollectionContext, new_run_id
from evidentia_core.models.common import (
    ControlMapping,
    EvidentiaModel,
    OLIRRelationship,
    Severity,
    current_version,
    deterministic_finding_id,
    new_id,
    utc_now,
)


class FindingStatus(str, Enum):
    """Status of a security finding."""

    ACTIVE = "active"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class ComplianceStatus(str, Enum):
    """Compliance/posture result of the check a finding represents.

    Distinct from :class:`FindingStatus`, which is the finding's
    lifecycle state (active / resolved / suppressed).
    ``ComplianceStatus`` answers a different question — did the checked
    control pass or fail? — and mirrors the OCSF Compliance Finding
    ``compliance.status`` field. Added v0.10.0 for OCSF alignment.
    """

    PASS = "pass"
    """The control or check passed; the resource is compliant."""

    FAIL = "fail"
    """The control or check failed; the resource is non-compliant."""

    WARNING = "warning"
    """A non-fatal concern, short of an outright failure."""

    NOT_APPLICABLE = "not_applicable"
    """The control or check does not apply to the evaluated resource."""

    UNKNOWN = "unknown"
    """Result not determined — the default for findings from collectors
    not yet migrated to set the status explicitly, and for
    informational / inventory findings that do not represent a check."""


def _synthetic_legacy_context() -> CollectionContext:
    """Synthesize a CollectionContext for pre-v0.7.0 construction sites.

    Marks every field with the placeholder ``"legacy-pre-v0.7.0"`` so
    audit-reviewers can tell the difference between real provenance
    (populated by a v0.7.0+ collector) and this synthetic placeholder.
    """
    return CollectionContext(
        collector_id="legacy-pre-v0.7.0",
        collector_version="unknown",
        run_id=new_run_id(),
        credential_identity="legacy-pre-v0.7.0",
        source_system_id="legacy-pre-v0.7.0",
        filter_applied={"_legacy": True},
        evidentia_version=current_version(),
    )


class SecurityFinding(EvidentiaModel):
    """A security finding from an evidence collector.

    Findings are the raw output of collectors — they represent a single
    observation about a system's security posture.

    v0.7.0 schema (see module docstring for migration notes):

    - ``control_mappings`` replaces ``control_ids`` (backward-compat
      via :meth:`_migrate_control_ids_kwarg`).
    - ``collection_context`` required but defaults to a synthetic
      placeholder for pre-v0.7.0 construction sites.
    """

    id: str = Field(default_factory=new_id)
    title: str
    description: str
    severity: Severity
    status: FindingStatus = Field(default=FindingStatus.ACTIVE)
    # v0.10.0 (OCSF alignment): compliance/posture result + remediation.
    compliance_status: ComplianceStatus = Field(
        default=ComplianceStatus.UNKNOWN,
        description=(
            "Pass/fail result of the control or check this finding "
            "represents. Distinct from `status` (the active/resolved "
            "lifecycle state). Mirrors the OCSF Compliance Finding "
            "`compliance.status` field. Defaults to UNKNOWN: collectors "
            "migrated in v0.10.0+ set this explicitly; pre-v0.10.0 "
            "construction sites and not-yet-migrated collectors leave it "
            "UNKNOWN rather than asserting a result. Most collectors "
            "gather non-compliant items, but the vendor-risk collectors "
            "also emit informational inventory findings, so UNKNOWN — "
            "not FAIL — is the safe default."
        ),
    )
    remediation: str | None = Field(
        default=None,
        description=(
            "Optional human-readable remediation guidance. Maps to the "
            "OCSF Compliance Finding `remediation.desc` field. Populated "
            "by collectors where the source system supplies remediation "
            "text (e.g. AWS Security Hub Remediation.Recommendation); "
            "None when unavailable."
        ),
    )
    source_system: str = Field(description="E.g. 'aws-security-hub', 'github'")
    source_finding_id: str | None = Field(
        default=None,
        description="Original finding ID in the source system",
    )
    resource_type: str | None = Field(
        default=None,
        description="E.g. 'AWS::S3::Bucket', 'GitHub::Repository'",
    )
    resource_id: str | None = Field(
        default=None,
        description="Resource identifier in the source system",
    )
    resource_region: str | None = Field(default=None)
    resource_account: str | None = Field(default=None)
    # v0.7.0: control mappings now carry OLIR relationship + justification.
    control_mappings: list[ControlMapping] = Field(
        default_factory=list,
        description=(
            "NIST 800-53 (or other framework) controls this finding relates "
            "to. v0.7.0 adds OLIR relationship typing + justification "
            "per mapping. Pre-v0.7.0 callers passing ``control_ids=[...]`` "
            "as keyword arg are auto-converted via the schema's "
            "``@model_validator``."
        ),
    )
    # v0.7.0: per-finding provenance — who, what, when, where, how.
    collection_context: CollectionContext = Field(
        default_factory=_synthetic_legacy_context,
        description=(
            "Per-finding collection provenance (collector id/version, "
            "run_id, credential identity, source instance, filters, "
            "pagination). v0.7.0+ collectors MUST pass a real "
            "CollectionContext; the default synthesizes a "
            "'legacy-pre-v0.7.0' placeholder for older construction sites."
        ),
    )
    raw_data: Any | None = Field(
        default=None,
        description="Original finding data from the source system",
    )
    first_observed: datetime = Field(default_factory=utc_now)
    last_observed: datetime = Field(default_factory=utc_now)
    resolved_at: datetime | None = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def _derive_deterministic_id(cls, data: Any) -> Any:
        """Derive a deterministic ``id`` from natural keys when possible.

        Added v0.10.5 Phase 10 (idempotency hardening for the v1.0 API
        freeze). When the caller did NOT supply ``id=...`` explicitly
        AND both ``source_system`` and ``source_finding_id`` are present
        in the construction kwargs, derive ``id`` via
        :func:`~evidentia_core.models.common.deterministic_finding_id`.

        Effect: two ``collect()`` calls against an unchanged source
        produce findings whose ``id`` values are identical. The same
        OSCAL Assessment Results document re-emitted from a re-run is
        bit-stable on the identity axis (timestamps still vary).

        Backward-compat:

        - Explicit ``id=`` always wins — operators and ingest paths that
          set ``id`` directly are unaffected. This includes the OCSF
          Detection Finding ingest path that sets ``id=info.uid`` from
          third-party input.
        - When ``source_finding_id`` is None / empty, no derivation runs
          and the ``default_factory=new_id`` random UUID v4 is used.
          This preserves the behaviour of the synthetic-legacy code
          path in ``_synthetic_legacy_context`` and the migration
          helper in ``models/migrations/v0_6_legacy.py``.

        Trust boundary: this validator is identity-derivation only. It
        does NOT validate that ``source_finding_id`` is non-malicious —
        a hostile collector could deterministically derive an ID that
        collides with another collector's finding by spoofing both
        ``source_system`` and ``source_finding_id``. The UUID5 namespace
        + the NUL-byte separator make accidental collisions impossible;
        intentional collisions require lying about both natural keys,
        which is a trust-boundary issue handled upstream by the
        collector authentication + provenance pipeline (see
        ``CollectionContext.credential_identity``).

        See: ``docs/collector-idempotency-audit.md`` §4 for the full
        contract.
        """
        if not isinstance(data, dict):
            return data
        # Explicit id wins — covers OCSF round-trip + ingest paths.
        if data.get("id"):
            return data
        source_system = data.get("source_system")
        source_finding_id = data.get("source_finding_id")
        if (
            isinstance(source_system, str)
            and source_system.strip()
            and isinstance(source_finding_id, str)
            and source_finding_id.strip()
        ):
            data["id"] = deterministic_finding_id(source_system, source_finding_id)
        return data

    @model_validator(mode="before")
    @classmethod
    def _migrate_control_ids_kwarg(cls, data: Any) -> Any:
        """Accept ``control_ids=[...]`` as a pre-v0.7.0 compat shortcut."""
        if not isinstance(data, dict):
            return data
        if "control_ids" not in data:
            return data

        legacy_ids = data.pop("control_ids")
        if not isinstance(legacy_ids, list):
            return data

        synthesized = [
            ControlMapping(
                framework="nist-800-53-rev5",
                control_id=str(control_id),
                relationship=OLIRRelationship.RELATED_TO,
                justification=(
                    "Pre-v0.7.0 mapping (auto-converted from control_ids "
                    "kwarg). Relationship unclassified; auditors should "
                    "treat this as a legacy mapping."
                ),
            )
            for control_id in legacy_ids
        ]
        existing = data.get("control_mappings") or []
        explicit_keys = {
            (
                m.framework if hasattr(m, "framework") else m.get("framework"),
                m.control_id if hasattr(m, "control_id") else m.get("control_id"),
            )
            for m in existing
        }
        merged = list(existing) + [m for m in synthesized if (m.framework, m.control_id) not in explicit_keys]
        data["control_mappings"] = merged
        return data

    @property
    def control_ids(self) -> list[str]:
        """Read-only view returning just the control IDs as strings."""
        return [m.control_id for m in self.control_mappings]

    if TYPE_CHECKING:
        # Typed init shim so mypy accepts legacy ``control_ids=[...]``
        # kwargs at the v0.6-era call sites. Runtime handled by
        # ``_migrate_control_ids_kwarg`` above. Removed in Commit 4
        # when all call sites switch to ``control_mappings=[...]``.
        def __init__(
            self,
            *,
            control_ids: list[str] | None = None,
            **kwargs: Any,
        ) -> None: ...


# v0.10.1 rename — ``Finding`` is the new canonical class name,
# aligned with the OCSF "Finding" terminology (Compliance Finding,
# Detection Finding). ``SecurityFinding`` is retained as a
# backward-compatible alias for ≥ 1 minor cycle per the deprecation
# policy in ``docs/api-stability.md``. Both names refer to the same
# class — call sites can use either, JSON serialization is identical,
# isinstance() checks against either name succeed. See
# ``docs/deprecation-calendar.md`` for the removal timeline.
Finding = SecurityFinding
