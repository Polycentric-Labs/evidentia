"""Continuous Monitoring (CONMON) cycle-calendar primitives (v0.9.0 P3 + v0.9.3 P1).

Read-only library for surfacing assessment + reporting cycles per
the major federal-compliance frameworks. Operators consume this via:

- :func:`evidentia_core.conmon.calendar.next_due` — compute the next
  cycle's due date from a framework + last-completed-cycle anchor
- :func:`evidentia_core.conmon.calendar.list_cadences` — enumerate
  the bundled cadence rules
- :func:`evidentia_core.conmon.calendar.derive_status` — bucket a
  pending cycle into ``due_soon`` / ``overdue`` / ``current`` at
  query time against a reference date
- :func:`evidentia_core.conmon.daemon.run_daemon` (v0.9.3 P1.1) —
  long-running poll loop with operator-supplied callbacks for
  due-soon / overdue cycles. Wired into the CLI via
  ``evidentia conmon watch --poll``.

The `evidentia conmon` CLI (v0.9.0 P2-adjacent; ships in the same
release cycle) wires these primitives into the operator workflow.
The CONMON live-trigger daemon (event-driven, vs the v0.9.3 poll
mode) remains reserved for v1.0.

Bundled cadences (v0.9.0 P3 baseline; operator-extensible via
:func:`register_cadence`):

- ``nist-800-53-rev5-ca7``      — monthly (NIST 800-53 CA-7
  Continuous Monitoring)
- ``fedramp-conmon-poam``       — monthly POA&M updates
- ``fedramp-conmon-scans``      — monthly vulnerability scans
- ``fedramp-conmon-annual``     — annual SAR
- ``cmmc-l2-triennial``         — triennial reassessment
- ``dod-rmf-annual``            — annual control assessment
- ``occ-2026-13-model-risk``    — annual model-risk review
- ``pci-dss-11-6-1-weekly``: weekly (PCI DSS v4.0.1 11.6.1), v0.13
- ``nerc-cip-007-r2-patch-evaluation``: every 35 days (NERC CIP-007-6 R2), v0.13
- ``irs-pub-1345-weekly-asv-scan``: weekly ASV scan (IRS Pub 1345), v0.13
- ``glba-314-4-d-semiannual-vulnerability-assessment``: semiannual, v0.13
- ``glba-314-4-d-annual-penetration-test``: annual (16 CFR 314.4(d)(2)(i)), v0.13

The v0.13 cadence evidence series (:mod:`evidentia_core.conmon.series`) reads
the evidence store and judges a dated series continuous, gapped, insufficient
or unknown; see docs/designs/cadence-assertion-layer-design.md.

Pure functions; no I/O; no persistence side-effects. Audit-trail
emit (``EventAction.CONMON_CYCLE_DUE`` /
``EventAction.CONMON_CYCLE_OVERDUE``) happens at the CLI
layer when queries identify due/overdue cycles — not in this
library, which only computes the dates.
"""

from __future__ import annotations

from evidentia_core.conmon.alerting import (
    DEFAULT_SUPPRESSION_HOURS,
    AlertChannel,
    AlertDeduper,
    make_alert_handler,
    resolve_secret,
)
from evidentia_core.conmon.calendar import (
    BUNDLED_CADENCES,
    CONMON_FREQUENCIES,
    CONMON_FREQUENCY_DAYS,
    DEPRECATED_SLUG_ALIASES,
    CadenceFrequency,
    ConmonCadence,
    CycleAttentionState,
    derive_status,
    get_cadence,
    interval_days_for,
    list_cadences,
    migrate_deprecated_slugs,
    next_due,
    register_cadence,
)
from evidentia_core.conmon.daemon import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    MIN_POLL_INTERVAL_SECONDS,
    CycleHandler,
    CycleObservation,
    DaemonConfig,
    PollResult,
    load_state_file,
    mark_completed,
    poll_once,
    run_daemon,
    save_state_file,
)
from evidentia_core.conmon.health import (
    FrameworkHealth,
    HealthReport,
    compute_health,
    health_from_state_file,
)
from evidentia_core.conmon.series import (
    CADENCE_SLUG_METADATA_KEY,
    CADENCE_SOURCE_SYSTEM,
    CadenceSeries,
    SeriesGap,
    SeriesObservation,
    SeriesVerdict,
    allowed_gap_days,
    assert_series,
    default_tolerance_days,
    default_window,
    series_to_finding,
)

__all__ = [
    "BUNDLED_CADENCES",
    "CADENCE_SLUG_METADATA_KEY",
    "CADENCE_SOURCE_SYSTEM",
    "CONMON_FREQUENCIES",
    "CONMON_FREQUENCY_DAYS",
    "DEFAULT_POLL_INTERVAL_SECONDS",
    "DEFAULT_SUPPRESSION_HOURS",
    "DEPRECATED_SLUG_ALIASES",
    "MIN_POLL_INTERVAL_SECONDS",
    "AlertChannel",
    "AlertDeduper",
    "CadenceFrequency",
    "CadenceSeries",
    "ConmonCadence",
    "CycleAttentionState",
    "CycleHandler",
    "CycleObservation",
    "DaemonConfig",
    "FrameworkHealth",
    "HealthReport",
    "PollResult",
    "SeriesGap",
    "SeriesObservation",
    "SeriesVerdict",
    "allowed_gap_days",
    "assert_series",
    "compute_health",
    "default_tolerance_days",
    "default_window",
    "derive_status",
    "get_cadence",
    "health_from_state_file",
    "interval_days_for",
    "list_cadences",
    "load_state_file",
    "make_alert_handler",
    "mark_completed",
    "migrate_deprecated_slugs",
    "next_due",
    "poll_once",
    "register_cadence",
    "resolve_secret",
    "run_daemon",
    "save_state_file",
    "series_to_finding",
]
