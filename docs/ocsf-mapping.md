# OCSF Compliance Finding mapping

> **Status**: NORMATIVE as of v0.10.0 (2026-05-22). Documents the
> bidirectional mapping between Evidentia's native `SecurityFinding`
> model and the OCSF **Compliance Finding** class.
>
> **Canonical location**: `docs/ocsf-mapping.md`
> **Cross-references**: [v0.10.0-plan.md](v0.10.0-plan.md),
> [integration-survey.md](integration-survey.md),
> [api-stability.md](api-stability.md)

---

## 1. Why OCSF

The [Open Cybersecurity Schema Framework](https://schema.ocsf.io) is
the emerging vendor-neutral schema for security findings. Mapping
Evidentia findings to and from OCSF makes downstream integrations
cheap rather than bespoke: any OCSF-aware consumer (SIEMs, AWS
Security Lake, Datadog, RegScale ingestion) can read Evidentia output
through one adapter, and — once the v0.10.1 ingestion collector lands
— any OCSF-emitting tool can be read *into* Evidentia the same way.

Evidentia keeps its **own** Pydantic finding model. OCSF is an
*interchange* format at the boundary, not the internal representation.
The native model retains Evidentia's enrichment over OCSF — OLIR-typed
control mappings and `CollectionContext` provenance — which the OCSF
`compliance` object cannot natively express.

## 2. Target class and version

| Item | Value |
|---|---|
| OCSF class | **Compliance Finding** |
| `class_uid` | `2003` |
| `category_uid` | `2` (Findings) |
| OCSF schema (current) | 1.8.0 (released 2026-03-18) |
| `py-ocsf-models` version pinned | `>=0.9.0,<0.10.0` |
| OCSF schema modelled by that library | 1.5.0 |

The Compliance Finding class is **stable across OCSF 1.1+**, so the
1.5.0-vs-1.8.0 gap is a version-label detail, not a functional one.
The generic `security_finding` class was deprecated in OCSF 1.1;
Compliance Finding is the semantically correct class for
control-pass/fail findings.

**Note on Prowler / AWS Security Hub.** Prowler emits the OCSF
**Detection Finding** class, not Compliance Finding. The v0.10.0
`finding_from_ocsf` direction targets Compliance Finding; the deferred
v0.10.1 OCSF-ingestion collector adds a Detection Finding path.

## 3. The `py-ocsf-models` dependency

The OCSF representation comes from
[`py-ocsf-models`](https://github.com/prowler-cloud/py-ocsf-models)
(Apache-2.0, Pydantic, maintained by the Prowler team). It is an
**optional** dependency, installed via the `ocsf` extra:

```bash
pip install 'evidentia-core[ocsf]'
```

`evidentia_core.ocsf.finding_mapping` is the **only** module that
imports it. The core `evidentia_core.models.finding` model never does,
so:

- the default install stays slim (`py-ocsf-models` pulls in
  `cryptography` and other transitive dependencies);
- the core `SecurityFinding` model is insulated from OCSF schema churn
  — only the mapping layer moves on an OCSF version bump.

Calling `finding_to_ocsf` / `finding_from_ocsf` without the extra
installed raises `OCSFMappingError` with an actionable install hint.

## 4. Field mapping — `SecurityFinding` → OCSF

`finding_to_ocsf(finding)` produces a JSON-ready `dict` conforming to
the OCSF Compliance Finding class.

| `SecurityFinding` field | OCSF Compliance Finding location |
|---|---|
| `id` | `finding_info.uid` |
| `title` | `finding_info.title` |
| `description` | `finding_info.desc`, `compliance.desc`, `message` |
| `severity` | `severity_id` (+ `severity` string) |
| `status` (`FindingStatus`) | `status_id` |
| `compliance_status` (`ComplianceStatus`) | `compliance.status_id` |
| `remediation` | `remediation.desc` (omitted when `None`) |
| `source_system` | `finding_info.data_sources[]` |
| `resource_type` | `resources[].type` |
| `resource_id` | `resources[].uid` |
| `resource_region` | `resources[].region` |
| `control_mappings[].framework` | `compliance.standards[]` (deduplicated, sorted) |
| `control_mappings[].control_id` | `compliance.requirements[]` |
| `first_observed` | `finding_info.first_seen_time_dt`, `time`, `time_dt` |
| `last_observed` | `finding_info.last_seen_time_dt` |
| *(whole finding)* | `unmapped["evidentia"]` — see §6 |

**OCSF envelope fields** (`class_uid`, `category_uid`, `class_name`,
`category_name`, `activity_id`, `type_uid`, `metadata.product`) are
**computed by the mapping layer**, not stored on `SecurityFinding`.
`metadata.product` is fixed to Evidentia (`name`, `vendor_name`
"Polycentric Labs", `version`).

**Fields with no native OCSF home** — `source_finding_id`,
`resource_account`, `resolved_at`, `collection_context`, `raw_data`,
and the OLIR `relationship` + `justification` on each control mapping —
are not lost: they ride in the `unmapped["evidentia"]` block (§6).

### 4.1 Enum value mappings

**Severity** → OCSF `severity_id`:

| `Severity` | `severity_id` |
|---|---|
| `CRITICAL` | 5 |
| `HIGH` | 4 |
| `MEDIUM` | 3 |
| `LOW` | 2 |
| `INFORMATIONAL` | 1 |

Inbound OCSF `severity_id` values with no Evidentia equivalent
(`0` Unknown, `6` Fatal, `99` Other) fall back to `MEDIUM`.

**ComplianceStatus** → OCSF `compliance.status_id`:

| `ComplianceStatus` | `status_id` | OCSF name |
|---|---|---|
| `PASS` | 1 | Pass |
| `WARNING` | 2 | Warning |
| `FAIL` | 3 | Fail |
| `UNKNOWN` | 0 | Unknown |
| `NOT_APPLICABLE` | 99 | Other |

OCSF has no "not applicable" compliance value, so `NOT_APPLICABLE`
maps to `Other` (99). The exact Evidentia value still round-trips
losslessly via the `unmapped` block.

**FindingStatus** → OCSF `status_id`:

| `FindingStatus` | `status_id` | OCSF name |
|---|---|---|
| `ACTIVE` | 1 | New |
| `RESOLVED` | 4 | Resolved |
| `SUPPRESSED` | 3 | Suppressed |

## 5. Field mapping — OCSF → `SecurityFinding`

`finding_from_ocsf(ocsf_dict, *, trust_unmapped=True)` is the inverse.
It first validates the input as an OCSF Compliance Finding
(`OCSFMappingError` on failure), then takes one of two paths:

1. **Evidentia-produced input** (`trust_unmapped=True`, default) — the
   `dict` carries an `unmapped["evidentia"]` block; the original
   `SecurityFinding` is reconstructed *exactly* from it (see §6).
2. **Third-party input** — no `unmapped["evidentia"]` block **OR**
   `trust_unmapped=False`. The finding is rebuilt **best-effort** from
   native OCSF fields: `finding_info` → id/title/description,
   `severity_id` → severity, `compliance.status_id` → compliance_status,
   `compliance.standards` + `compliance.requirements` → control mappings
   (with an `OLIRRelationship.RELATED_TO` default and a justification
   noting the OCSF provenance), `remediation.desc` → remediation.

### 5.1 `trust_unmapped=False` — the third-party ingestion path (v0.10.1)

A valid-but-malicious OCSF producer could craft an
`unmapped["evidentia"]` block to control the reconstructed
`SecurityFinding` — id / title / source_system / control_mappings all
attacker-chosen. Pydantic still re-validates the model so corrupted
blocks fail safely, but the residual identity / attribution-forgery
risk is real (CWE-345 *Insufficient Verification of Data
Authenticity*, proxy).

The v0.10.1 OCSF-ingestion collector passes `trust_unmapped=False`
when reading third-party input whose origin it does not verify; the
block is then ignored entirely and the finding is rebuilt from
native OCSF fields only. Operators integrating
`finding_from_ocsf` into their own ingestion pipelines should adopt
the same pattern unless they verify the OCSF doc's origin
cryptographically (Sigstore bundle, signed envelope, trusted SaaS
source allowlist).

This parameter closes pre-release-review finding **F-V100-L1**
identified during the v0.10.0 ship.

## 6. Round-trip fidelity

The mapping guarantees:

```python
finding_from_ocsf(finding_to_ocsf(f)) == f
```

holds **exactly** for any Evidentia-produced finding.

OCSF's `compliance` object cannot express Evidentia's OLIR-typed
control mappings (relationship + justification) or its
`CollectionContext` provenance. Rather than drop them, `finding_to_ocsf`
stashes the *complete* finding — `finding.model_dump(mode="json")` —
under the OCSF-standard `unmapped` field, namespaced as
`unmapped["evidentia"]`. `finding_from_ocsf` restores from that block
when present.

This is a deliberate design choice: the native OCSF fields make the
finding readable by *any* OCSF consumer, while the `unmapped` block
makes the round trip lossless for Evidentia-to-Evidentia flows. A
third-party OCSF consumer simply ignores `unmapped["evidentia"]`.

## 7. API

```python
from evidentia_core.ocsf import (
    finding_to_ocsf,              # SecurityFinding -> OCSF Compliance Finding dict
    finding_from_ocsf,            # OCSF Compliance Finding dict -> SecurityFinding
    finding_from_ocsf_detection,  # v0.10.1: OCSF Detection Finding dict -> SecurityFinding
    OCSFMappingError,             # raised when the `ocsf` extra is absent or input is invalid
)
```

All three mapping functions are pure — no I/O, no global state.
`finding_to_ocsf` returns a JSON-ready `dict` (serialize however);
`finding_from_ocsf` and `finding_from_ocsf_detection` accept dicts
parsed from JSON.

v0.10.1 also ships an **ingestion collector** that wraps these for
file + URL input:

```python
from evidentia_collectors.ocsf import (
    collect_ocsf_file,   # path-or-Path  -> list[SecurityFinding]
    collect_ocsf_url,    # https:// URL  -> list[SecurityFinding]
    OCSFIngestError,     # malformed JSON / unsupported class_uid / URL policy
)
```

Or use the CLI: `evidentia collect ocsf --input <file-or-url>
[--output findings.json]`. URL mode is HTTPS-only with no redirects,
a 10s connect/read timeout, and a 50 MB body cap — see the
collector module's docstring for the rationale.

## 7.A. Detection Finding mapping (v0.10.1)

OCSF **Detection Finding** (`class_uid` 2004) is what Prowler and
AWS Security Hub emit — *not* Compliance Finding. The
`finding_from_ocsf_detection(ocsf_dict, *, trust_unmapped=False)`
function handles it.

The key delta vs. Compliance Finding: **Detection Finding has no
native `compliance` object**, so `compliance_status` and
`control_mappings` cannot be read from the OCSF doc directly.
The conversion:

| `SecurityFinding` field | Source on Detection Finding |
|---|---|
| `id` | `finding_info.uid` |
| `title` | `finding_info.title` |
| `description` | `finding_info.desc` ∥ `message` ∥ `finding_info.title` |
| `severity` | `severity_id` (same mapping as Compliance Finding) |
| `status` | `status_id` (same `FindingStatus` mapping) |
| `compliance_status` | **synthesized from `severity_id`** — see table below |
| `remediation` | `remediation.desc` |
| `source_system` | `metadata.product.name` (fallback `"ocsf-detection-import"`) |
| `resource_type` / `_id` / `_region` | `resources[0]` |
| `first_observed` / `last_observed` | `finding_info.first_seen_time_dt` / `last_seen_time_dt` |
| `control_mappings` | **empty** — downstream collectors enrich based on detector-ruleset knowledge |

**Synthesized `compliance_status` from `severity_id`** (the v0.10.1
heuristic in `_DETECTION_SEVERITY_TO_COMPLIANCE`):

| `severity_id` | OCSF name | → `compliance_status` |
|---|---|---|
| 5 | Critical | `FAIL` |
| 4 | High | `FAIL` |
| 3 | Medium | `FAIL` |
| 2 | Low | `WARNING` |
| 1 | Informational | `UNKNOWN` |
| 0 | Unknown | `UNKNOWN` |
| 6 | Fatal | `FAIL` |
| 99 | Other | `UNKNOWN` |

Rationale: a detection finding represents an observed problem, so
non-informational severities map to a non-passing compliance state.
INFORMATIONAL is treated as `UNKNOWN` because the source is publishing
context, not a check result.

**Default `trust_unmapped=False`** for Detection Finding — the typical
input source (Prowler, AWS Security Hub) is third-party and not
Evidentia-produced. Operators who produce their own Detection Finding
round-trip artifacts can flip to `True` for lossless reconstruction.

## 8. Deferred to v0.10.1+

- The third-party **OCSF-ingestion collector** that wires
  `finding_from_ocsf` to a file/API reader (Prowler, AWS Security Hub).
  Requires a **Detection Finding** path — that is the class Prowler
  emits.
- Migrating the remaining ~11 collectors to populate `compliance_status`
  and `remediation` explicitly (the 3 pilot collectors — AWS, GitHub,
  Postgres — do so in v0.10.0).
- An optional `evidentia collect --format ocsf` output mode.
