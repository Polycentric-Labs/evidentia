"""Per-finding and per-run provenance metadata (v0.7.0+).

Implements checklist items H5 (collector metadata on every finding),
H10 (pagination continuation tokens preserved as evidence), and B5
(completeness attestation). Designed to satisfy:

- NIST SP 800-53 Rev 5 AU-2(d) / AU-3 / AU-6(4) — audit records must
  identify the user, process, resource, outcome, and timing of each
  evidence-generating action.
- ISAE 3402 / SSAE 18 AT-C 320 — auditors expect to trace every piece
  of evidence back to the collecting process, credential, and scope.
- FedRAMP CA-7 (Continuous Monitoring) — evidence collection scope
  must be documented and verifiable on demand.

Public classes:

- :class:`CollectionContext` is embedded on every finding. Redundant
  across findings from the same run, but stays with each finding if
  the payload is split, filtered, or re-exported. Chain-of-custody
  survives transformations.
- :class:`CollectionManifest` is one-per-run, attached to the OSCAL AR
  document's ``metadata.props`` and written as an optional sibling
  file. Captures coverage, filters, record counts, and — crucially —
  explicit empty-set attestations so a reviewer can distinguish
  "no findings" from "collection never ran" or "collection crashed".
- :class:`GenerationContext` (v0.7.1) is the AI-output sibling of
  :class:`CollectionContext`. Risk statements and plain-English control
  explanations are *generated* (not collected from a source system) and
  carry distinct provenance — model, temperature, prompt hash, retry
  count — so an auditor can reproduce or challenge an AI-derived claim.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any

import ulid
from pydantic import Field

from evidentia_core.models.common import EvidentiaModel, current_version, utc_now


def new_run_id() -> str:
    """Generate a fresh collection-run identifier as a ULID string.

    ULID (Universally Unique Lexicographically Sortable Identifier) is
    a 128-bit identifier with a 48-bit timestamp prefix. For audit logs
    that's the property that matters: run_ids sort chronologically by
    their value alone, so ``ORDER BY run_id`` in a log store returns
    collections in the order they started, even across clock-skew
    boundaries or rotation breaks where ``@timestamp`` gets messy.
    """
    return str(ulid.ULID())


class PaginationContext(EvidentiaModel):
    """Pagination state at the moment of finding retrieval.

    Preserving the pagination context lets an auditor prove collection
    completeness (checklist H10). If a collector returned 42 findings
    across 3 pages with no continuation token, the evidence trail shows
    the operator didn't silently stop at the first page.
    """

    page_size: int | None = Field(
        default=None,
        description="Number of records requested per API page",
    )
    page_number: int | None = Field(
        default=None,
        description="1-indexed position of the page this finding appeared in",
    )
    total_pages: int | None = Field(
        default=None,
        description=(
            "Total pages in the result set when computable from API response; "
            "None for cursor-based pagination where total is unknown"
        ),
    )
    continuation_token: str | None = Field(
        default=None,
        description=(
            "Opaque API continuation/next token if pagination was not "
            "fully drained at collection time; None on the final page"
        ),
    )
    is_complete: bool = Field(
        default=True,
        description=(
            "False if collection was truncated (rate limit, time budget "
            "exhausted, explicit limit). Forces CollectionManifest to "
            "mark the run 'incomplete' for auditor visibility."
        ),
    )


class CollectionContext(EvidentiaModel):
    """Per-finding provenance block — who/what/when/where/how.

    Every :class:`~evidentia_core.models.finding.SecurityFinding` in
    v0.7.0+ carries one of these. All six NIST AU-3 content requirements
    are expressed across the SecurityFinding + CollectionContext pair:

    =====================  ==========================================
    AU-3 requirement       Field(s)
    =====================  ==========================================
    Type of event           ``SecurityFinding.title``, ``severity``
    When event occurred     ``collected_at`` (microsecond UTC)
    Where event occurred    ``source_system_id`` + ``filter_applied``
    Source of event         ``collector_id`` + ``collector_version``
    Outcome of event        ``SecurityFinding.status``
    Identity                ``credential_identity``
    =====================  ==========================================
    """

    collector_id: str = Field(
        description=(
            "Stable collector identifier; used for filtering and SIEM "
            "alerting. Examples: 'aws-config', 'aws-security-hub', "
            "'aws-access-analyzer', 'github-branch-protection', "
            "'github-dependabot'."
        ),
    )
    collector_version: str = Field(
        description=(
            "Semver of the evidentia-collectors package that produced "
            "this finding. Resolved from importlib.metadata at collection "
            "time so it always matches the installed wheel."
        ),
    )
    run_id: str = Field(
        description=(
            "ULID of the collection run. Identical across every finding "
            "emitted by the same ``collect`` invocation; also equals the "
            "CollectionManifest.run_id so the two can be joined."
        ),
    )
    collected_at: datetime = Field(
        default_factory=utc_now,
        description=(
            "Exact UTC timestamp when the finding was retrieved from the "
            "source API. Auditor-grade precision (microseconds)."
        ),
    )
    credential_identity: str = Field(
        description=(
            "Authenticated principal that produced the finding. "
            "Format varies by source: AWS IAM ARN, GitHub app installation "
            "id, token subject, service-account email, etc. NOT the secret "
            "itself — the identity that the secret authenticates."
        ),
    )
    source_system_id: str = Field(
        description=(
            "Source system instance identifier. Examples: "
            "'aws-account:123456789012:us-east-1', "
            "'github:org/repo', 'github:enterprise/acme'."
        ),
    )
    filter_applied: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Filter / query parameters used during collection. Auditors "
            "use this to verify the reported scope. Empty dict means "
            "'no filter — full enumeration' (which is itself a claim)."
        ),
    )
    pagination_context: PaginationContext | None = Field(
        default=None,
        description=(
            "Pagination state if the source API requires it. None when "
            "the source API returns the full set in a single response."
        ),
    )
    evidentia_version: str = Field(
        default_factory=current_version,
        description=(
            "Version of evidentia-core orchestrating the collection. "
            "Paired with collector_version, lets auditors verify the "
            "exact release that produced the evidence."
        ),
    )


def compute_prompt_hash(system_prompt: str, user_prompt: str) -> str:
    """Return a deterministic SHA-256 of the prompt pair driving an LLM call.

    Used as :attr:`GenerationContext.prompt_hash` so an auditor can prove
    two AI outputs were generated from byte-identical prompts (or detect
    when a prompt was subtly altered between runs). The hash is over the
    UTF-8 encoding of ``system_prompt + "\\n---\\n" + user_prompt`` — the
    separator is fixed so no caller-side concatenation choice can collide
    pairs that were actually distinct.

    Returns the lowercase hex digest (64 chars).
    """
    payload = f"{system_prompt}\n---\n{user_prompt}".encode()
    return hashlib.sha256(payload).hexdigest()


class GenerationContext(EvidentiaModel):
    """Per-output provenance for AI-generated artifacts (v0.7.1).

    Sibling of :class:`CollectionContext`, but for outputs that are
    *generated* by an LLM rather than *collected* from a source system.
    Risk statements (`evidentia-ai.risk_statements`) and plain-English
    control explanations (`evidentia-ai.explain`) attach one of these
    to every output so an auditor or reviewer can:

    1. Reproduce the call (``model`` + ``temperature`` + ``prompt_hash``).
    2. Distinguish a clean first-attempt success from a flaky-network
       success-after-retry (``attempts`` vs ``instructor_max_retries``).
    3. Group outputs from a single batch (``run_id``).
    4. Pin the artifact to the exact release that produced it
       (``evidentia_version``).

    Fields deliberately mirror :class:`CollectionContext` field naming
    where the semantics align (``run_id``, ``evidentia_version``) so
    downstream tooling that joins on those keys works identically for
    collected and generated artifacts.
    """

    model: str = Field(
        description=(
            "LiteLLM model identifier passed to the underlying LLM call. "
            "Examples: 'claude-sonnet-4', 'gpt-4o', "
            "'openrouter/anthropic/claude-sonnet-4'. The exact string an "
            "auditor would re-pass to LiteLLM to reproduce the call."
        ),
    )
    temperature: float = Field(
        ge=0.0,
        le=2.0,
        description=(
            "Sampling temperature used for the LLM call. Pinned in the "
            "context because two outputs from the same model+prompt at "
            "different temperatures are NOT equivalent for audit reproduction."
        ),
    )
    prompt_hash: str = Field(
        min_length=64,
        max_length=64,
        description=(
            "SHA-256 hex digest of the (system_prompt, user_prompt) pair "
            "driving this generation. Computed via "
            ":func:`compute_prompt_hash` so the separator is fixed. "
            "Lets an auditor prove byte-equivalence of prompts across runs."
        ),
    )
    run_id: str = Field(
        default_factory=lambda: str(ulid.ULID()),
        description=(
            "ULID identifying the generation run. Defaults to a fresh "
            "ULID per call so single-shot generations get a unique id; "
            "callers wrapping a batch should mint one ``run_id`` via "
            ":func:`new_run_id` and pass it down to every output so the "
            "batch can be reconstructed from the audit log."
        ),
    )
    generated_at: datetime = Field(
        default_factory=utc_now,
        description=(
            "Exact UTC timestamp when the LLM call returned a validated "
            "response (microsecond precision). Mirrors "
            ":attr:`CollectionContext.collected_at` semantics."
        ),
    )
    attempts: int = Field(
        default=1,
        ge=1,
        description=(
            "Total network-layer attempts made before this output succeeded. "
            "1 = first try succeeded; >1 = ``@with_retry`` fired N-1 retries. "
            "Distinct from ``instructor_max_retries`` which counts validation-"
            "layer retries (LLM returned non-conforming JSON)."
        ),
    )
    instructor_max_retries: int = Field(
        default=3,
        ge=0,
        description=(
            "The Instructor ``max_retries`` cap configured for this call. "
            "Echoed into the context (rather than only the actual retry "
            "count) so an auditor reviewing a failed-batch postmortem can "
            "see the configured tolerance, not just what happened to fire."
        ),
    )
    credential_identity: str | None = Field(
        default=None,
        description=(
            "Best-effort identifier of the operator/principal that "
            "authorized the LLM call. Mirrors :attr:`CollectionContext."
            "credential_identity` so AI artifacts satisfy NIST SP 800-53 "
            "Rev 5 AU-3 ('Identity') the same way collected findings do. "
            "Populated by callers from the ``EVIDENTIA_AI_OPERATOR`` env "
            "var when set, falling back to ``user@hostname`` from the OS. "
            "NEVER the API key itself \u2014 always a label or principal "
            "identifier that the secret authenticates."
        ),
    )
    evidentia_version: str = Field(
        default_factory=current_version,
        description=(
            "Version of evidentia-core orchestrating the generation. "
            "Paired with ``model``, lets an auditor identify the exact "
            "(orchestrator, model) pair that produced the artifact."
        ),
    )


class CoverageCount(EvidentiaModel):
    """One resource-type's scan/match/collect counts within a run."""

    resource_type: str = Field(
        description=(
            "Source-system resource category. Examples: 'aws-iam-role', 'aws-iam-user', 'github-dependabot-alert'."
        ),
    )
    scanned: int = Field(ge=0, description="Total resources enumerated (before filtering)")
    matched_filter: int = Field(ge=0, description="Resources passing the collector's filter criteria")
    collected: int = Field(
        ge=0,
        description=(
            "Findings actually produced from this resource type. May be < "
            "matched_filter if some matched resources yielded no findings."
        ),
    )


class CollectionManifest(EvidentiaModel):
    """Per-run manifest attesting to collection scope and completeness.

    Implements checklist item B5 (completeness attestation). One
    manifest per collection run is attached to the OSCAL Assessment
    Results document's ``metadata.props`` and optionally written as a
    sibling ``<output>.manifest.json`` for standalone inspection.

    The manifest is signed using the same signing pipeline as the AR
    itself. A verified manifest establishes:

    1. Which source systems were scanned.
    2. Which filters were applied.
    3. How many resources of each type were examined.
    4. Whether any categories were intentionally empty.
    5. Whether any errors truncated collection (``is_complete=False``).
    """

    run_id: str = Field(
        description=(
            "ULID matching CollectionContext.run_id on every finding "
            "produced by this run. Join key for findings↔manifest."
        ),
    )
    collector_id: str
    collector_version: str
    collection_started_at: datetime = Field(
        description="UTC timestamp when the collector began this run",
    )
    collection_finished_at: datetime | None = Field(
        default=None,
        description=("UTC timestamp when the collector finished. None while still in progress."),
    )
    source_system_ids: list[str] = Field(
        default_factory=list,
        description="All source_system_ids covered in this run",
    )
    filters_applied: dict[str, Any] = Field(
        default_factory=dict,
        description=("Run-level filters. Empty dict means 'no filter'."),
    )
    coverage_counts: list[CoverageCount] = Field(
        default_factory=list,
        description="Per-resource-type scan/match/collect counts",
    )
    total_findings: int = Field(default=0, ge=0, description="Sum of findings emitted from this run")
    is_complete: bool = Field(
        default=True,
        description=(
            "False if any collection error, truncation, or pagination "
            "abort occurred. Auditors treat incomplete runs as evidence "
            "gaps."
        ),
    )
    incomplete_reason: str | None = Field(
        default=None,
        description=("Human-readable reason the run didn't complete. MUST be populated when ``is_complete=False``."),
    )
    empty_categories: list[str] = Field(
        default_factory=list,
        description=(
            "Resource types explicitly scanned but yielding zero "
            "findings. Per checklist B5: an auditor cannot distinguish "
            "'no findings' (legitimate) from 'collector skipped' "
            "(evidence gap) without this explicit attestation."
        ),
    )
    warnings: list[str] = Field(
        default_factory=list,
        description=(
            "Non-fatal issues encountered during collection — rate-limit "
            "backoffs, skipped resources, blind-spot disclosures."
        ),
    )
    errors: list[str] = Field(
        default_factory=list,
        description=(
            "Fatal errors that caused specific resources to be skipped "
            "but didn't abort the run. Non-empty plus is_complete=True "
            "means 'partial success'."
        ),
    )
    evidentia_version: str = Field(
        default_factory=current_version,
        description="Version of evidentia-core that wrote this manifest",
    )
