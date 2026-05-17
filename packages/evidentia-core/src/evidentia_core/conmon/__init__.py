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
- ``occ-2026-13a-model-risk``   — annual model-risk review

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
    CadenceFrequency,
    ConmonCadence,
    CycleAttentionState,
    derive_status,
    get_cadence,
    list_cadences,
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

__all__ = [
    "BUNDLED_CADENCES",
    "CONMON_FREQUENCIES",
    "DEFAULT_POLL_INTERVAL_SECONDS",
    "DEFAULT_SUPPRESSION_HOURS",
    "MIN_POLL_INTERVAL_SECONDS",
    "AlertChannel",
    "AlertDeduper",
    "CadenceFrequency",
    "ConmonCadence",
    "CycleAttentionState",
    "CycleHandler",
    "CycleObservation",
    "DaemonConfig",
    "FrameworkHealth",
    "HealthReport",
    "PollResult",
    "compute_health",
    "derive_status",
    "get_cadence",
    "health_from_state_file",
    "list_cadences",
    "load_state_file",
    "make_alert_handler",
    "mark_completed",
    "next_due",
    "poll_once",
    "register_cadence",
    "resolve_secret",
    "run_daemon",
    "save_state_file",
]
