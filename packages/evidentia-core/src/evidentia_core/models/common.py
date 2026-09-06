"""Shared types, enums, and base classes used across all Evidentia models."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4, uuid5

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


def utc_now() -> datetime:
    """Return current UTC time with timezone info."""
    return datetime.now(UTC)


def new_id() -> str:
    """Generate a new UUID v4 string."""
    return str(uuid4())


# v0.10.5 Phase 10: deterministic finding-ID derivation namespace.
#
# Generated once via ``uuid.uuid5(uuid.NAMESPACE_DNS, "finding.evidentia.dev")``
# and pinned forever. Rotating this UUID would re-key every
# ``SecurityFinding.id`` ever produced and break every cached OSCAL
# Assessment Results document, OCSF round-trip, and historical evidence
# archive. The namespace constant must NEVER change post-v0.10.5; if a
# future major-version bump introduces an incompatible identity scheme,
# add a SECOND namespace constant rather than mutating this one.
#
# Cited in:
# - ``docs/collector-idempotency-audit.md`` §4 (the derivation contract).
# - ``docs/api-stability.md`` §"Frozen surfaces" (the identity guarantee).
NAMESPACE_EVIDENTIA_FINDING: UUID = UUID("c81bcb44-9b41-5b18-9f10-72b3b9b4d3d6")


def deterministic_finding_id(source_system: str, source_finding_id: str) -> str:
    """Return a deterministic UUID5 string derived from natural keys.

    Two calls with identical ``(source_system, source_finding_id)``
    arguments produce byte-identical output, so re-running a collector
    against an unchanged source yields the same
    :attr:`~evidentia_core.models.finding.SecurityFinding.id` for every
    logical finding. Added v0.10.5 Phase 10; see
    :doc:`docs/collector-idempotency-audit </collector-idempotency-audit>`
    for the per-collector design rationale.

    The payload separator is a NUL byte — illegal in either argument
    (`source_system` is a short identifier like ``"aws-config"``;
    ``source_finding_id`` is constructed from natural API IDs that
    never contain NUL). This guarantees no collision between e.g.
    ``("aws", "config:bucket")`` and ``("aws-config", "bucket")``.

    Args:
        source_system: Stable collector identifier (e.g. ``"aws-config"``,
            ``"github"``, ``"okta"``). MUST be non-empty.
        source_finding_id: The collector's natural per-finding key
            (e.g. ``f"{rule_name}:{resource_id}"``, ``f"{slug}:{branch}:{rule}"``,
            a native source UID like a GitHub alert number). MUST be non-empty.

    Returns:
        The canonical-string form of a UUID v5 (e.g.
        ``"a3b2c1d0-...".``). Matches the format of :func:`new_id` for
        drop-in compatibility everywhere ``SecurityFinding.id`` is
        consumed.

    Raises:
        ValueError: if either argument is empty / whitespace-only.

    Example:
        >>> deterministic_finding_id("aws-config", "s3-public-read:bucket-one")
        '... a stable UUID v5 string ...'
    """
    if not source_system or not source_system.strip():
        raise ValueError("source_system must be a non-empty string")
    if not source_finding_id or not source_finding_id.strip():
        raise ValueError("source_finding_id must be a non-empty string")
    payload = f"{source_system}\x00{source_finding_id}"
    return str(uuid5(NAMESPACE_EVIDENTIA_FINDING, payload))


def current_version() -> str:
    """Return the installed evidentia-core version.

    Used as a ``default_factory`` on report-stamp fields
    (``GapReport.evidentia_version`` etc.) so exported artifacts
    accurately record the version that produced them. Resolves via
    ``importlib.metadata`` — always matches the installed wheel.
    """
    from evidentia_core import __version__

    return __version__


def enum_value(v: object) -> str:
    """Return ``.value`` if v is a real enum, else cast to str.

    Defensive helper for the :class:`EvidentiaModel`
    ``use_enum_values=True`` duality: Pydantic-deserialized enum
    fields round-trip as their raw string values after
    :meth:`BaseModel.model_validate_json`, but freshly-constructed
    Pydantic models carry the real enum instance at field-access
    time. The ``hasattr(v, "value")`` check covers both shapes —
    callers can pass either form without distinguishing.

    Introduced in v0.9.0 P5 (single-source-of-truth extraction;
    deduplicates triplicated copies in ``cli/poam.py`` +
    ``routers/poam.py`` + ``oscal/poam_exporter.py``). Earlier
    inline duplicates in ``oscal/exporter.py`` use the same
    pattern and can migrate to this helper in a future cleanup.
    """
    return v.value if hasattr(v, "value") else str(v)


# "At least one character that survives ``str.strip()``." EvidentiaModel sets
# ``str_strip_whitespace=True``, so a whitespace-only value passes a bare
# ``min_length=1`` in the PUBLISHED schema but fails post-strip validation at
# runtime, which schemathesis (correctly) reports as RejectedPositiveData. The
# 2026-07-06 fix used ``\S``; the 2026-09-03 DAST run showed that is not enough:
# regex engines disagree on whether U+00A0 and its relatives are whitespace,
# while Python's strip removes every code point listed here (the 2026-09-06 run
# generated a lone U+0085). Spelling the set out makes the published schema and
# the runtime agree in every engine (JSON Schema patterns are ECMA-262 searches,
# so the class is deliberately unanchored). Keep in sync with ``str.isspace()``.
NON_BLANK_PATTERN = r"[^\s\x1c-\x1f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]"

# The one string type to use for any free-text field that must not be blank. It
# publishes ``minLength: 1`` AND the pattern above, so a schema-driven client (or
# fuzzer) can never produce a value the stripping runtime then rejects. Combine
# with ``Field(max_length=..., description=...)`` as usual.
NonBlankStr = Annotated[str, StringConstraints(min_length=1, pattern=NON_BLANK_PATTERN)]


class EvidentiaModel(BaseModel):
    """Base model for all Evidentia objects.

    Provides consistent serialization settings:
    - Enums serialize to their string values
    - Datetimes serialize to ISO 8601
    - Extra fields are forbidden (strict schema)
    - Whitespace is stripped from strings on input
    """

    model_config = ConfigDict(
        use_enum_values=True,
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
    )


class Severity(str, Enum):
    """Universal severity levels used across gaps, risks, and findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


# v0.3.0: ``FrameworkId`` enum REMOVED per the v0.2.0 deprecation notice.
# v0.1.x shipped a 2-value enum (NIST_800_53_MOD + SOC2_TSC); v0.2.0 kept it
# behind a DeprecationWarning-emitting module ``__getattr__``; v0.3.0 drops
# it entirely. Use plain string framework IDs — ``ControlMapping.framework``
# has always been ``str``, so no caller was type-dependent on the enum.
# For the canonical list of bundled framework IDs, use
# ``evidentia_core.catalogs.manifest.load_manifest()``.


class OLIRRelationship(str, Enum):
    """NIST OLIR (Online Informative References) relationship types.

    Added in v0.7.0 to support enterprise-grade mapping claims. Rather
    than bare ``framework+control_id`` pairs, every :class:`ControlMapping`
    now declares the strength and direction of the relationship between
    the mapped evidence and the named control.

    Values match the NIST OLIR Derived Relationship Mapping (DRM)
    vocabulary at https://csrc.nist.gov/projects/olir/derived-relationship-mapping.
    An auditor reading evidence can tell the difference between
    "this finding fully evidences AC-6" (``SUBSET_OF``) and
    "this finding is loosely related to AC-6" (``RELATED_TO``).
    """

    EQUIVALENT_TO = "equivalent-to"
    """Evidence and control address the same objective via the same
    method. Functionally identical with identical outcomes."""

    EQUAL_TO = "equal-to"
    """Evidence and control are word-for-word identical. Rare between
    separate frameworks; common when mapping translations / re-issues."""

    SUBSET_OF = "subset-of"
    """Evidence is narrower than the control — addresses one specific
    aspect. The usual relationship between an automated finding and a
    NIST family control (e.g., 'S3 bucket is public' subset-of AC-3
    Access Enforcement)."""

    SUPERSET_OF = "superset-of"
    """Evidence is broader than the control. Uncommon in automated
    findings; typical for framework-to-framework crosswalks."""

    INTERSECTS_WITH = "intersects-with"
    """Evidence and control overlap but neither fully contains the
    other. Used when a finding partially evidences a control but also
    addresses things outside that control."""

    RELATED_TO = "related-to"
    """Weakest relationship: evidence and control share a topic but
    the mapping strength is unclassified. Default for pre-v0.7.0
    mappings that haven't been re-classified yet."""


class ControlMapping(EvidentiaModel):
    """Maps an entity (evidence, risk, gap) to a specific framework control.

    v0.7.0 extended the model with OLIR relationship typing and
    justification. Pre-v0.7.0 callers that constructed
    ``ControlMapping(framework=..., control_id=...)`` without the new
    fields continue to work — defaults (``relationship=RELATED_TO``,
    ``justification=""``) are supplied automatically. Collectors and
    mapping tables upgraded in v0.7.0 set explicit stronger relationships.
    """

    framework: str = Field(description="Framework identifier, e.g. 'nist-800-53-rev5', 'soc2-tsc'")
    control_id: str = Field(description="Control identifier within the framework, e.g. 'AC-2', 'CC6.1'")
    control_title: str | None = Field(
        default=None,
        description="Human-readable control title",
    )
    relationship: OLIRRelationship = Field(
        default=OLIRRelationship.RELATED_TO,
        description=(
            "NIST OLIR relationship type. v0.7.0+ mappings should declare "
            "the strongest honest relationship (typically ``SUBSET_OF`` "
            "for automated findings against family controls). Default "
            "``RELATED_TO`` preserves pre-v0.7.0 behaviour."
        ),
    )
    justification: str = Field(
        default="",
        max_length=1024,
        description=(
            "Free-text rationale for the mapping, typically citing the "
            "authoritative source (AWS Security Hub 'Related requirements', "
            "AWS Audit Manager framework entry, NIST OLIR submission, "
            "FedRAMP baseline appendix). Empty string = 'legacy mapping'."
        ),
    )

    def __str__(self) -> str:
        return f"{self.framework}:{self.control_id}"
