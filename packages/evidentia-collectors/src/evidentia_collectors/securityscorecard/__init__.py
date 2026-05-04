"""SecurityScorecard evidence collector for Evidentia
(v0.7.9 P0.4 fourth slice).

Read-only collector that pulls a SecurityScorecard portfolio via
the SecurityScorecard API (https://api.securityscorecard.io) and
emits NIST 800-53 + OCC Bulletin 2013-29 + FRB SR 13-19 + FFIEC IT
Examination Handbook Outsourcing booklet mapped SecurityFinding
objects.

SecurityScorecard is a continuous-rating provider (sister to
BitSight). Operators import vendor companies INTO their SSC
portfolios; SSC grades each company's external security posture
on a 0-100 score with letter grades:

- A: 90-100 (Excellent)
- B: 80-89 (Good)
- C: 70-79 (Average)
- D: 60-69 (Below average)
- F: <60 (Poor)

Public surface::

    from evidentia_collectors.securityscorecard import SecurityScorecardCollector

    with SecurityScorecardCollector(
        api_token=os.environ["SECURITYSCORECARD_API_TOKEN"],
        portfolio_id="<portfolio-id>",  # optional
    ) as c:
        findings, manifest = c.collect_v2()

The API token is sourced from the ``SECURITYSCORECARD_API_TOKEN``
env var per the secret-handling protocol — SSC uses
``Authorization: Token <api_token>`` headers. The token never
appears in URLs or query params.

This module ships in v0.7.9 P0.4 fourth slice (the final P0.4
slice in v0.7.9). Follow-up slices will add per-company factor
scores + historical-grade trends.

No new pyproject extra is needed — the only runtime dep is
``httpx>=0.27`` which is already a base dependency of
``evidentia-collectors``.

Typed exceptions:

- :class:`SecurityScorecardCollectorError` — base
- :class:`SecurityScorecardAuthError` — 401 / 403 / token rejection
- :class:`SecurityScorecardConnectionError` — network failure
- :class:`SecurityScorecardQueryError` — per-endpoint failure
"""

from __future__ import annotations

from evidentia_collectors.securityscorecard.collector import (
    SecurityScorecardAuthError,
    SecurityScorecardCollector,
    SecurityScorecardCollectorError,
    SecurityScorecardConnectionError,
    SecurityScorecardQueryError,
)

__all__ = [
    "SecurityScorecardAuthError",
    "SecurityScorecardCollector",
    "SecurityScorecardCollectorError",
    "SecurityScorecardConnectionError",
    "SecurityScorecardQueryError",
]
