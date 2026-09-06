# Data model

Evidentia's data model is a set of [Pydantic](https://docs.pydantic.dev/) v2 models that flow through the whole pipeline: a collector emits a `SecurityFinding`, the gap analyzer produces `ControlGap` records, the crosswalk engine reads `CrosswalkDefinition` files, and every output emitter serializes one of these shapes. This page explains the load-bearing models, which fields are frozen versus additive (the [api-stability](../6-project/api-stability.md) contract), and the small set of design rules that hold across all of them.

If you only read one thing: the models are **strict** (`extra="forbid"`), **frozen-but-extensible** (you can add optional fields in a minor release; you cannot rename or remove a field without a major bump), and **enum-valued on serialize** (enums round-trip as their string values).

## The base model

Every Evidentia model subclasses `EvidentiaModel` (`packages/evidentia-core/src/evidentia_core/models/common.py`), which fixes four serialization rules in one place:

```python
class EvidentiaModel(BaseModel):
    model_config = ConfigDict(
        use_enum_values=True,  # enums serialize to their .value string
        extra="forbid",  # unknown fields raise at parse time
        str_strip_whitespace=True,  # leading/trailing whitespace stripped on input
        populate_by_name=True,  # field aliases AND names both accepted
    )
```

Two consequences are worth internalizing because they show up everywhere downstream:

- **`use_enum_values=True`** means a freshly-constructed model carries the real enum instance at field-access time, but a model that round-tripped through `model_validate_json()` carries the raw string. The `enum_value()` helper in `common.py` papers over the duality (`v.value if hasattr(v, "value") else str(v)`), and several models coerce strings back to enums in their own accessors (`RBACPolicy.role_for`, for example). When you read a model field, do not assume it is the enum — assume it might be the string.
- **`extra="forbid"`** is what makes "add an optional field" a safe, backward-compatible change: a v0.9.x serialized document re-parses cleanly under v0.10.x because the new field has a default, and an *unknown* field is rejected loudly rather than silently dropped.

## SecurityFinding (and its `Finding` alias)

`SecurityFinding` (`models/finding.py`) is the raw output of an evidence collector — one observation about a system's posture. Verified fields:

| Field | Type | Notes |
|---|---|---|
| `id` | `str` | UUID; `default_factory=new_id` (random UUID v4) **unless** the deterministic-id validator fires (see below). |
| `title` | `str` | Required. |
| `description` | `str` | Required. |
| `severity` | `Severity` | Required. `critical` / `high` / `medium` / `low` / `informational`. |
| `status` | `FindingStatus` | Lifecycle state. Default `ACTIVE`. `active` / `resolved` / `suppressed`. |
| `compliance_status` | `ComplianceStatus` | **v0.10.0 (OCSF alignment).** Pass/fail of the *check*. Default `UNKNOWN`. |
| `remediation` | `str \| None` | **v0.10.0.** Optional remediation prose; maps to OCSF `remediation.desc`. |
| `source_system` | `str` | Required, e.g. `"aws-security-hub"`, `"github"`. |
| `source_finding_id` | `str \| None` | Original ID in the source system. |
| `resource_type` / `resource_id` / `resource_region` / `resource_account` | `str \| None` | Resource provenance. |
| `control_mappings` | `list[ControlMapping]` | OLIR-typed mappings. Default empty. |
| `collection_context` | `CollectionContext` | Per-finding provenance; default is a synthetic-legacy placeholder. |
| `raw_data` | `Any \| None` | Original source payload. |
| `first_observed` / `last_observed` | `datetime` | Default `utc_now`. |
| `resolved_at` | `datetime \| None` | Set when resolved. |

`status` and `compliance_status` answer **different questions** and the model docstring is emphatic about it: `status` is the finding's lifecycle (is it active, resolved, or suppressed?); `compliance_status` is the verdict of the control the finding represents (did the check pass or fail?). They are deliberately distinct enums.

### The deterministic-id contract (v0.10.5 Phase 10)

`SecurityFinding` carries a `@model_validator(mode="before")` named `_derive_deterministic_id`. When the caller does **not** pass `id=` explicitly **and** both `source_system` and `source_finding_id` are present and non-empty, the `id` is derived as:

```python
id = uuid5(NAMESPACE_EVIDENTIA_FINDING, f"{source_system}\x00{source_finding_id}")
```

The namespace UUID is pinned forever in `common.py`:

```python
NAMESPACE_EVIDENTIA_FINDING = UUID("c81bcb44-9b41-5b18-9f10-72b3b9b4d3d6")
```

The effect is **idempotency**: two `collect()` runs against an unchanged source produce findings with byte-identical `id` values, so a re-emitted OSCAL Assessment Results document is bit-stable on the identity axis. Explicit `id=` always wins (covers the OCSF ingest path that sets `id=info.uid`), and when `source_finding_id` is missing the random-UUID `default_factory` is used. The separator is a NUL byte — illegal in either argument — so `("aws", "config:bucket")` can never collide with `("aws-config", "bucket")`.

This is identity-derivation only, **not** a trust boundary: a hostile collector could deterministically collide IDs by lying about both natural keys. That is handled upstream by collector authentication, not here.

### The `Finding` alias

`finding.py` ends with `Finding = SecurityFinding`. The v0.10.1 rename made `Finding` the canonical name (aligned with OCSF's "Finding" terminology) while keeping `SecurityFinding` as a backward-compatible alias. **Both names refer to the exact same class** — `isinstance` checks against either succeed, JSON serialization is identical. The `SecurityFinding` alias is retained for at least one minor cycle per the deprecation policy; its earliest removal is v1.0.0.

### ComplianceStatus and FindingStatus enums

`ComplianceStatus` (5 members) mirrors the OCSF Compliance Finding `compliance.status` field:

| Member | Value | Meaning |
|---|---|---|
| `PASS` | `pass` | Control passed; resource compliant. |
| `FAIL` | `fail` | Control failed; resource non-compliant. |
| `WARNING` | `warning` | Non-fatal concern, short of failure. |
| `NOT_APPLICABLE` | `not_applicable` | Control does not apply. |
| `UNKNOWN` | `unknown` | Result not determined — the default. |

`UNKNOWN` (not `FAIL`) is the deliberate default: most collectors gather non-compliant items, but the vendor-risk collectors also emit informational inventory findings, so asserting `FAIL` by default would be wrong.

`FindingStatus` (3 members): `ACTIVE` / `RESOLVED` / `SUPPRESSED`.

## ControlGap

`ControlGap` (`models/gap.py`) is the gap analyzer's primary output unit — a framework requirement the organization has not fully implemented. Its fields group into framework-requirement data (`framework`, `control_id`, `control_title`, `control_description`, `control_family`), gap details (`gap_severity: GapSeverity`, `implementation_status: str`, `gap_description`, `status: GapStatus`), cross-framework analysis (`equivalent_controls_in_inventory`, `cross_framework_value`), remediation (`remediation_guidance`, `implementation_effort: ImplementationEffort`, `priority_score`), ticket tracking (`jira_issue_key`, `servicenow_ticket_id`), and lifecycle stamps (`created_at`, `remediated_at`, `assigned_to`, `tags`).

The supporting enums verified in `gap.py`:

- `GapSeverity` — `critical` / `high` / `medium` / `low` / `informational`.
- `ImplementationEffort` — `low` / `medium` / `high` / `very_high`.
- `GapStatus` — `open` / `in_progress` / `remediated` / `accepted` / `not_applicable`.

### POA&M milestones

`ControlGap.poam_milestones: list[Milestone]` (default empty, added v0.9.0) carries the remediation timeline. A `Milestone` has `id`, `target_date: date`, `description`, `status: POAMState`, `evidence_ref`, `created_at`/`updated_at`, plus the v0.9.5 collaboration fields `owner` and `reviewer` (both `str | None`, kept separate so the two-eyes principle is enforceable at the data layer).

`POAMState` is a five-member lifecycle enum aligned to the FedRAMP POA&M Template Completion Guide v3.0 + NIST SP 800-53A Rev 5 Appendix F: `PLANNED` → `IN_PROGRESS` → `COMPLETED` → `VERIFIED`, plus the off-axis `OVERDUE`. Transitions are forward-only and enforced by `evidentia_core.poam.state.is_valid_transition` — `VERIFIED` is terminal (re-opening requires a *new* milestone, never mutating the verified record, for audit-trail integrity). `OVERDUE` is a derived attention signal computed at query time against a reference date.

The wrapping report is `GapAnalysisReport` (also in `gap.py`): summary counts (`total_gaps`, `critical_gaps` … `informational_gaps`, `coverage_percentage`), the `gaps: list[ControlGap]`, `efficiency_opportunities: list[EfficiencyOpportunity]` (controls that satisfy 3+ frameworks), and a `prioritized_roadmap`.

## ControlMapping and the OLIR relationship vocabulary

`ControlMapping` (`models/common.py`) attaches a finding (or risk, or gap) to a specific framework control with a *typed* relationship. The v0.7.0 schema upgrade replaced bare `framework+control_id` pairs with NIST OLIR relationship typing + a justification string:

- `framework: str`, `control_id: str`, `control_title: str | None`.
- `relationship: OLIRRelationship` — default `RELATED_TO`.
- `justification: str` — default `""`; cite the authoritative source (an empty string means "legacy mapping").

`OLIRRelationship` (6 members, matching the NIST OLIR Derived Relationship Mapping vocabulary): `EQUIVALENT_TO`, `EQUAL_TO`, `SUBSET_OF`, `SUPERSET_OF`, `INTERSECTS_WITH`, `RELATED_TO`. The point is auditor honesty — `SUBSET_OF` ("this finding evidences one specific aspect of AC-3") says something materially different from `RELATED_TO` ("shares a topic, strength unclassified"). Automated findings against family controls are typically `SUBSET_OF`.

`SecurityFinding` accepts a legacy `control_ids=[...]` keyword for pre-v0.7.0 call sites: a `@model_validator` auto-converts each ID into a `ControlMapping` with `framework="nist-800-53-rev5"`, `relationship=RELATED_TO`, and a "legacy mapping" justification. The read-only `.control_ids` property returns just the IDs for callers that only need them.

## OCSF mapping types

Evidentia interoperates with the [Open Cybersecurity Schema Framework](https://schema.ocsf.io/) through `evidentia_core.ocsf` (`packages/evidentia-core/src/evidentia_core/ocsf/finding_mapping.py`). This module is the **only** place that imports `py-ocsf-models` (installed via the optional `[ocsf]` extra), so the default install stays slim and the core `SecurityFinding` model is insulated from OCSF schema churn — the import is lazy, surfacing `OCSFMappingError` only when a mapping function is actually called.

Public surface (re-exported from `evidentia_core.ocsf.__init__`):

- `finding_to_ocsf(finding) -> dict` — converts a `SecurityFinding` to an OCSF **Compliance Finding** (`class_uid` 2003). The complete Evidentia finding is stashed under the OCSF-standard `unmapped["evidentia"]` field, so the round-trip is lossless: `finding_from_ocsf(finding_to_ocsf(f)) == f` holds for Evidentia-produced findings (OCSF's native fields cannot express OLIR-typed mappings or `CollectionContext`).
- `finding_from_ocsf(ocsf_dict, *, trust_unmapped=True) -> SecurityFinding` — the reverse. `trust_unmapped` defaults `True` for internal round-trips; **ingestion of third-party OCSF you do not cryptographically verify should pass `trust_unmapped=False`** (a forged `unmapped` block could otherwise control the reconstructed finding). This parameter was added in v0.10.1 to close finding F-V100-L1 (a CWE-345 proxy).
- `finding_from_ocsf_detection(ocsf_dict, *, trust_unmapped=False) -> SecurityFinding` — for OCSF **Detection Finding** (`class_uid` 2004), the class Prowler and AWS Security Hub emit. Detection Findings have no native `compliance` object, so `compliance_status` is synthesized from `severity_id` (CRITICAL/HIGH/MEDIUM/FATAL → `FAIL`, LOW → `WARNING`, INFORMATIONAL/UNKNOWN/OTHER → `UNKNOWN`) and `control_mappings` starts empty for downstream enrichment. `trust_unmapped` defaults `False` here because the typical source is third-party.
- `OCSFMappingError` — raised when the `[ocsf]` extra is absent or input fails OCSF validation.

The severity and status crosswalk tables live in `finding_mapping.py` as module constants (e.g. `_SEVERITY_TO_OCSF`, `_COMPLIANCE_STATUS_TO_OCSF`). OCSF has no "not applicable" compliance value, so `NOT_APPLICABLE` maps to OCSF `Other` (99) and round-trips losslessly only via the `unmapped` block.

## The EventAction enum

Not a "data" model in the schema sense, but `EventAction` (`evidentia_core.audit.events`) is a frozen, **append-only** vocabulary that the audit subsystem emits on every structured-log event. Names follow `evidentia.<namespace>.<verb>` so SIEM operators can filter by prefix (`event.action:evidentia.collect.*`). The enum carries 82 members across namespaces such as `COLLECT_*`, `AUTH_*`, `CONFIG_*`, `SIGN_*` (e.g. `SIGN_GPG_SIGNED`, `SIGN_SIGSTORE_SIGNED`), `VERIFY_*`, `MANIFEST_*`, `AI_*`, `POAM_*`, `CONMON_*`, `EVIDENCE_*`, `RBAC_*`, and `RETENTION_*`. Existing values are never removed or renamed; new values arrive in minor releases. This is what lets a query written against a v0.7.0 audit log stay meaningful against a v0.10.x one.

## What's frozen versus additive

The rule, formalized in [api-stability.md](../6-project/api-stability.md): exported model classes have **stable field names and types**. Adding an optional field (with a default) is a minor-bump change; renaming, removing, or retyping an existing field is a major-bump trigger requiring a deprecation cycle. The `compliance_status` + `remediation` fields (v0.10.0), the `Milestone.owner`/`reviewer` fields (v0.9.5), and the deterministic-id derivation (v0.10.5) are all examples of additive evolution that left older serialized documents parseable. JSON field *ordering* is explicitly not guaranteed.

## Related reading

- [Architecture](architecture.md) — where these models sit in the 9-package data flow.
- [Catalog engine](catalog-engine.md) — the `CatalogControl` / `ControlCatalog` models and how they load.
- [Crosswalk engine](crosswalk-engine.md) — the `CrosswalkDefinition` / `FrameworkMapping` models.
- [Frozen surfaces and stability](frozen-surfaces-and-stability.md) — the full public-API contract.
- [`api-stability.md`](../6-project/api-stability.md) — NORMATIVE frozen-surface table + revision history.
- [`ocsf-mapping.md`](../5-compliance/ocsf-mapping.md) — the normative OCSF field map.
