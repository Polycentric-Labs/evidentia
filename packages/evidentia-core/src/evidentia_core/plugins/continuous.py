"""Continuous evidence-source plugin contract (v0.9.3 P1.4).

Protocol for plugins that poll external systems (cloud APIs, SIEM
feeds, ticketing status, security scanners) and feed the results
into the CONMON daemon's audit-event stream.

Design constraints:

- **Read-only**: continuous sources surface evidence; they never
  mutate the external system.
- **Synchronous poll**: callers invoke ``poll()`` on a cadence;
  the implementation blocks until results are gathered. Async I/O
  inside the implementation is fine, but the public Protocol is
  synchronous to keep the v0.9.3 P1.1 daemon's loop simple.
- **Health probe**: ``health_check()`` returns a quick "is the
  source reachable + credentialed?" signal so operators can verify
  config before scheduling polls.
- **Failure-tolerant**: per-source failures must raise; the
  CONMON daemon's wrapper (TBD v0.9.4) catches + logs and keeps
  the rest of the schedule running.

Future v0.9.4 wires this Protocol into ``evidentia conmon watch
--continuous --plugin <name>``. v0.9.3 P1.4 ships only the
Protocol + reference impl; production wrappers around the v0.7.x
SaaS/cloud collectors are deferred to v0.9.4 once the daemon
integration shape is locked.

Reference implementation:

- :class:`NoopContinuousSource` — minimal demo + test fixture.
  Production plugins wrap their actual external client (httpx,
  boto3, etc.) and implement ``poll()`` to return a list of
  evidence records.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, runtime_checkable


@dataclass(frozen=True)
class EvidenceRecord:
    """One unit of evidence surfaced by a continuous source.

    Intentionally minimal: source name + timestamp + opaque payload.
    Concrete plugin authors define the payload shape per their
    domain (CloudTrail event, Snyk finding, Splunk alert, etc.).
    Downstream consumers (audit log, alerting, dashboards) treat
    the payload as JSON-serializable opaque data.
    """

    source: str
    """Stable identifier for the source plugin (matches
    :attr:`ContinuousEvidenceSource.name`)."""

    cadence_slug: str
    """The CONMON cadence this evidence supports. Operators wire
    the source-to-cadence mapping at plugin config time; the
    plugin echoes it in each record so the audit trail can join
    evidence back to the schedule."""

    observed_at: datetime
    """When the source produced this record (NOT when Evidentia
    polled). UTC; ISO-8601 serializable."""

    payload: dict[str, Any]
    """Source-defined payload. Plugin authors document the schema
    in their plugin's README/docstring; Evidentia treats it as
    opaque JSON-serializable data."""


@runtime_checkable
class ContinuousEvidenceSource(Protocol):
    """Continuous evidence-source plugin contract.

    Implementations live in operator code or in
    ``evidentia_integrations.continuous.*`` for first-party
    reference impls. Discovered via the ``evidentia.plugins``
    entry-point group; opt-in per :func:`discover_plugins`.

    Implementations MUST be re-entrant: the v0.9.4 daemon may
    invoke ``poll()`` concurrently across multiple schedule
    instances. Implementations holding mutable state must guard it.
    """

    name: str
    """Stable plugin identifier. Matches the entry-point name
    operators reference via ``--plugin <name>`` (v0.9.4)."""

    cadence_slug: str
    """The CONMON cadence this source supports. Set at construction
    time by the operator config; the daemon uses this to associate
    poll results with the correct cycle."""

    def poll(self) -> list[EvidenceRecord]:
        """Poll the external system + return new evidence records.

        Implementations may apply server-side filtering (e.g.,
        "only records since last poll") to keep the result set
        bounded. Implementations MUST NOT block indefinitely;
        operators rely on poll cadence for liveness signals.

        Raises:
            Exception: Any transport/auth/parse error. The v0.9.4
                daemon catches + logs + continues; the
                implementation should NOT retry internally (the
                daemon's poll interval IS the retry).
        """
        ...

    def health_check(self) -> bool:
        """Quick reachability + credential check.

        Returns True if the source is reachable + credentials are
        valid + the configured cadence_slug exists. Used by
        operator config validation (``evidentia conmon watch
        --continuous --plugin <name> --validate`` v0.9.4) to fail
        fast before scheduling a broken plugin.

        Implementations should keep this fast (under 5s); a slow
        health check defeats its purpose. Concretely: hit a cheap
        endpoint (e.g., the API's ``/whoami`` or equivalent), not
        a full data-fetch.
        """
        ...


# ── reference implementation ──────────────────────────────────────


class NoopContinuousSource:
    """Minimal :class:`ContinuousEvidenceSource` for testing + docs.

    Returns an empty list on every poll; always reports healthy.
    Useful as:

    - A test fixture so the v0.9.4 daemon-integration tests can
      exercise the wiring without external dependencies.
    - A template for plugin authors: copy this class, replace the
      poll/health-check bodies with your actual implementation.
    """

    def __init__(self, name: str = "noop", cadence_slug: str = "noop") -> None:
        self.name = name
        self.cadence_slug = cadence_slug
        self._poll_count = 0

    def poll(self) -> list[EvidenceRecord]:
        self._poll_count += 1
        return []

    def health_check(self) -> bool:
        return True

    @property
    def poll_count(self) -> int:
        """Test helper: how many times ``poll()`` has been called."""
        return self._poll_count
