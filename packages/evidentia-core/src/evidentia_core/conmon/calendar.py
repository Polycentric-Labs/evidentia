"""CONMON cycle-calendar core (v0.9.0 P3).

Pure-function library defining the canonical assessment + reporting
cadences for the major federal-compliance frameworks. Operators
consult this via :func:`next_due` to plan their CONMON workflow;
the v0.9.0 P2-adjacent ``evidentia conmon`` CLI wires the queries
into operator-facing surfaces.

Month arithmetic follows the same calendar-aware + last-day-clamping
pattern as :meth:`evidentia_core.models.tprm.Vendor.compute_next_review_due`
(stdlib-only; no dateutil dep). 2025-01-31 + 1 month → 2025-02-28
(not an invalid date); 2025-01-31 + 3 months → 2025-04-30 (clamped).

Frequency vocabulary:

- ``monthly``    — 1 month (NIST 800-53 CA-7 monthly cycles)
- ``quarterly``  — 3 months
- ``annual``     — 12 months
- ``biennial``   — 24 months
- ``triennial``  — 36 months

Operators can extend the cadence registry at runtime via
:func:`register_cadence` for organization-specific frameworks +
internal review cycles. The bundled cadences are immutable
templates; runtime registration shadows them per-process.
"""

from __future__ import annotations

import calendar as stdlib_calendar
import warnings
from datetime import date, timedelta
from enum import Enum

from pydantic import Field

from evidentia_core.models.common import EvidentiaModel, NonBlankStr


class CadenceFrequency(str, Enum):
    """Canonical cycle-frequency vocabulary."""

    MONTHLY = "monthly"
    """1 month between cycles."""

    QUARTERLY = "quarterly"
    """3 months between cycles."""

    ANNUAL = "annual"
    """12 months between cycles."""

    BIENNIAL = "biennial"
    """24 months between cycles."""

    TRIENNIAL = "triennial"
    """36 months between cycles."""


CONMON_FREQUENCIES: dict[CadenceFrequency, int] = {
    CadenceFrequency.MONTHLY: 1,
    CadenceFrequency.QUARTERLY: 3,
    CadenceFrequency.ANNUAL: 12,
    CadenceFrequency.BIENNIAL: 24,
    CadenceFrequency.TRIENNIAL: 36,
}
"""Mapping of cadence frequency → month delta. Stable across releases."""


class CycleAttentionState(str, Enum):
    """Attention bucket the calendar query path returns.

    Mirrors the v0.9.0 P1 POA&M attention-state shape so operator
    UIs can surface CONMON + POA&M signals through the same widgets.
    """

    CURRENT = "current"
    """Cycle is far enough in the future to need no attention."""

    DUE_SOON = "due_soon"
    """Cycle is due within the operator-configured window (default 14 days)."""

    OVERDUE = "overdue"
    """Cycle's next-due date has passed without a recorded completion."""


class ConmonCadence(EvidentiaModel):
    """Canonical assessment cycle for a framework + activity pairing.

    Each cadence ties a unique slug (``framework-activity`` form)
    to a frequency + human-readable description + the regulatory
    citation that establishes it. Operators query the registry by
    slug; the slug is stable across releases (additions are append-
    only; semantic changes require a new slug).
    """

    slug: NonBlankStr = Field(
        max_length=128,
        description=(
            "Unique cadence identifier (``framework-activity`` form, "
            "kebab-case). Stable across releases — used as the lookup "
            "key + audit-trail prop value."
        ),
    )
    framework: NonBlankStr = Field(
        max_length=128,
        description=(
            "Framework identifier (matches the gap-analyzer + catalog "
            "convention: ``nist-800-53-rev5`` / ``fedramp-rev5-mod`` "
            "/ ``cmmc-v2`` / ``dod-rmf`` / ``occ-2026-13`` / etc.)."
        ),
    )
    activity: NonBlankStr = Field(
        max_length=128,
        description=(
            "Activity within the framework (e.g., ``continuous-monitoring``"
            ", ``poam-update``, ``security-assessment``, ``model-risk-"
            "review``)."
        ),
    )
    frequency: CadenceFrequency = Field(
        description="How often the cycle repeats.",
    )
    description: NonBlankStr = Field(
        max_length=1024,
        description=(
            "Human-readable description of what the cycle covers + "
            "what operator deliverable closes it."
        ),
    )
    citation: str | None = Field(
        default=None,
        max_length=512,
        description=(
            "Regulatory or policy citation establishing the cadence "
            "(e.g., 'NIST SP 800-53 Rev 5 CA-7' / 'FedRAMP ConMon "
            "Strategy & Guide v3.0 §3.3')."
        ),
    )


# ── bundled cadence catalog ────────────────────────────────────────


BUNDLED_CADENCES: list[ConmonCadence] = [
    ConmonCadence(
        slug="nist-800-53-rev5-ca7",
        framework="nist-800-53-rev5",
        activity="continuous-monitoring",
        frequency=CadenceFrequency.MONTHLY,
        description=(
            "NIST 800-53 CA-7 Continuous Monitoring — monthly review "
            "of control effectiveness, configuration changes, and "
            "vulnerability scan output."
        ),
        citation="NIST SP 800-53 Rev 5 CA-7 (Continuous Monitoring)",
    ),
    ConmonCadence(
        slug="fedramp-conmon-poam",
        framework="fedramp-rev5-mod",
        activity="poam-update",
        frequency=CadenceFrequency.MONTHLY,
        description=(
            "FedRAMP Continuous Monitoring — monthly Plan-of-Action-"
            "and-Milestones (POA&M) update submitted to the AO. "
            "Includes status changes on open items + new findings."
        ),
        citation="FedRAMP ConMon Strategy & Guide v3.0 §3.4",
    ),
    ConmonCadence(
        slug="fedramp-conmon-scans",
        framework="fedramp-rev5-mod",
        activity="vulnerability-scans",
        frequency=CadenceFrequency.MONTHLY,
        description=(
            "FedRAMP Continuous Monitoring — monthly vulnerability "
            "scan output (operating system, web app, database) "
            "submitted alongside the POA&M update."
        ),
        citation="FedRAMP ConMon Strategy & Guide v3.0 §3.3",
    ),
    ConmonCadence(
        slug="fedramp-conmon-annual",
        framework="fedramp-rev5-mod",
        activity="security-assessment",
        frequency=CadenceFrequency.ANNUAL,
        description=(
            "FedRAMP Continuous Monitoring — annual security "
            "assessment by an accredited 3PAO. Produces a refreshed "
            "Security Assessment Report (SAR) + updated SSP."
        ),
        citation="FedRAMP ConMon Strategy & Guide v3.0 §4",
    ),
    ConmonCadence(
        slug="cmmc-l2-triennial",
        framework="cmmc-v2",
        activity="reassessment",
        frequency=CadenceFrequency.TRIENNIAL,
        description=(
            "CMMC Level 2 triennial reassessment by an authorized "
            "C3PAO. Required to maintain DoD contractor eligibility "
            "for CUI-handling contracts."
        ),
        citation="DoD CMMC 2.0 Program Rule (48 CFR Part 204)",
    ),
    ConmonCadence(
        slug="dod-rmf-annual",
        framework="dod-rmf",
        activity="control-assessment",
        frequency=CadenceFrequency.ANNUAL,
        description=(
            "DoD Risk Management Framework annual control "
            "assessment. Subset of controls assessed each cycle "
            "per the system-specific RMF strategy."
        ),
        citation="DoDI 8510.01 §3.5.b",
    ),
    ConmonCadence(
        slug="occ-2026-13-model-risk",
        framework="occ-2026-13",
        activity="model-risk-review",
        frequency=CadenceFrequency.ANNUAL,
        description=(
            "OCC Bulletin 2026-13 + FRB SR 26-2 annual model-"
            "risk review. Validation of model inventory, "
            "documentation, ongoing-performance-monitoring + "
            "effective-challenge evidence. Excludes generative + "
            "agentic AI per the April 2026 scope clarification."
        ),
        citation="OCC Bulletin 2026-13 (April 2026); FRB SR 26-2",
    ),
]
"""Bundled CONMON cadences shipped with v0.9.0 P3."""


_REGISTRY: dict[str, ConmonCadence] = {c.slug: c for c in BUNDLED_CADENCES}


DEPRECATED_SLUG_ALIASES: dict[str, str] = {
    # v0.13 designator correction: the OCC bulletin is 2026-13 (no "a"
    # suffix), so the bundled model-risk cadence slug was renamed. Old
    # operator state files keep working through this read-time alias.
    # See docs/deprecation-calendar.md (target removal v1.0.0).
    "occ-2026-13a-model-risk": "occ-2026-13-model-risk",
}
"""Deprecated cadence slugs, old form -> canonical. Consulted by every
state-file reader so a state file written before a rename keeps satisfying
the renamed cadence."""


def migrate_deprecated_slugs[V](state: dict[str, V]) -> dict[str, V]:
    """Translate deprecated cadence-slug keys to their canonical form.

    Emits a :class:`DeprecationWarning` per deprecated key found. When both
    the old and the new key are present, the new key's value wins and the
    old key is dropped, so a half-migrated state file can never regress a
    newer completion date. Mutates and returns ``state``.
    """
    for old, new in DEPRECATED_SLUG_ALIASES.items():
        if old not in state:
            continue
        warnings.warn(
            f"conmon state key {old!r} is deprecated; rename it to {new!r} "
            "(see docs/deprecation-calendar.md - scheduled for removal in "
            "v1.0.0)",
            DeprecationWarning,
            stacklevel=2,
        )
        value = state.pop(old)
        state.setdefault(new, value)
    return state


# ── public helpers ─────────────────────────────────────────────────


def list_cadences(framework: str | None = None) -> list[ConmonCadence]:
    """Return the registered cadences, optionally filtered by framework.

    The returned list is sorted by (framework, activity, slug) for
    deterministic CLI output. Operator-registered cadences via
    :func:`register_cadence` are included alongside bundled ones.
    """
    cadences = list(_REGISTRY.values())
    if framework is not None:
        cadences = [c for c in cadences if c.framework == framework]
    cadences.sort(key=lambda c: (c.framework, c.activity, c.slug))
    return cadences


def get_cadence(slug: str) -> ConmonCadence | None:
    """Look up a cadence by slug; return None for unknown slugs."""
    return _REGISTRY.get(slug)


def register_cadence(cadence: ConmonCadence) -> None:
    """Register an operator-supplied cadence at runtime.

    The cadence shadows any bundled cadence with the same slug.
    Process-local: a new ``evidentia`` invocation starts with only
    the bundled set. Operators who need durable extensions ship a
    plugin entry point in the v0.8.0 P0.4 plugin-contract surface
    (deferred extensible-cadence wiring to v0.9.1 if needed).
    """
    _REGISTRY[cadence.slug] = cadence


def next_due(slug: str, last_completed: date) -> date:
    """Compute the next-due date for a registered cadence.

    Raises ``KeyError`` for unknown slugs (operator should
    :func:`get_cadence` first OR register a custom cadence).

    Month arithmetic is calendar-aware: rolls year correctly, clamps
    day to the last valid day of the target month. Same pattern as
    :meth:`evidentia_core.models.tprm.Vendor.compute_next_review_due`.
    """
    cadence = _REGISTRY.get(slug)
    if cadence is None:
        raise KeyError(
            f"Unknown CONMON cadence slug {slug!r}; "
            f"available: {sorted(_REGISTRY.keys())}"
        )
    cadence_months = CONMON_FREQUENCIES[CadenceFrequency(cadence.frequency)]
    new_month = last_completed.month + cadence_months
    new_year = last_completed.year + (new_month - 1) // 12
    new_month = ((new_month - 1) % 12) + 1
    last_day_of_target_month = stdlib_calendar.monthrange(new_year, new_month)[1]
    new_day = min(last_completed.day, last_day_of_target_month)
    return date(new_year, new_month, new_day)


def derive_status(
    next_due_date: date,
    today: date,
    window_days: int = 14,
) -> CycleAttentionState:
    """Bucket a pending cycle into current / due-soon / overdue.

    Mirrors :func:`evidentia_core.poam.milestone.derive_attention_state`
    semantics so operator UIs can render CONMON + POA&M signals
    through the same attention widgets.

    Rules:

      - ``next_due_date < today``    → OVERDUE
      - ``today <= next_due_date <= today + window_days`` → DUE_SOON
      - ``next_due_date > today + window_days`` → CURRENT

    Negative ``window_days`` raises :class:`ValueError` — overdue
    queries should call :func:`derive_status` with a small positive
    window + filter the result by state, not negate the window.
    """
    if window_days < 0:
        raise ValueError(
            "window_days must be >= 0; for overdue-only queries, "
            "filter derive_status's output by CycleAttentionState.OVERDUE."
        )
    if next_due_date < today:
        return CycleAttentionState.OVERDUE
    horizon = today + timedelta(days=window_days)
    if next_due_date <= horizon:
        return CycleAttentionState.DUE_SOON
    return CycleAttentionState.CURRENT


__all__: list[str] = [
    "BUNDLED_CADENCES",
    "CONMON_FREQUENCIES",
    "CadenceFrequency",
    "ConmonCadence",
    "CycleAttentionState",
    "derive_status",
    "get_cadence",
    "list_cadences",
    "next_due",
    "register_cadence",
]
