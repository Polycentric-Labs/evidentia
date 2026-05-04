"""Vanta evidence collector for Evidentia (v0.7.9 P0.4 first slice).

Read-only collector that pulls a Vanta-managed vendor inventory via
the Vanta Public API and emits NIST 800-53 + OCC Bulletin 2013-29 +
FRB SR 13-19 + FFIEC Vendor Management mapped SecurityFinding
objects. Designed for the operator pattern where:

- Vanta is the system-of-record for SOC 2 readiness + vendor risk
  metadata (control tests, ongoing-monitoring posture)
- Evidentia is the system-of-record for the broader GRC narrative
  (gap analysis, OSCAL artifacts, AI risk statements,
  cross-framework crosswalks, the v0.7.9 TPRM module)

The collector pulls Vanta's vendor inventory + risk attributes into
Evidentia's evidence chain so the same vendor surfaces in both
tools. Operators running periodic v0.7.9 P0.3 concentration-risk
reports get Vanta-disclosed 4th-party data alongside their
manually-curated inventory.

Public surface::

    from evidentia_collectors.vanta import VantaCollector

    with VantaCollector(api_token=os.environ["VANTA_API_TOKEN"]) as c:
        findings, manifest = c.collect_v2()

Or the legacy ``collect()`` shortcut returning just findings::

    findings = VantaCollector(api_token="...").collect()

The API token is sourced from the ``VANTA_API_TOKEN`` env var per
the secret-handling protocol — Vanta supports both Personal Access
Tokens (developer / scripting use; recommended for first
deployment) and OAuth 2.0 client credentials for production
machine-to-machine use. Both pass ``Authorization: Bearer <token>``
headers; the collector accepts either.

Token scope: read-only access to ``vendors:read`` (the only scope
this collector exercises in the first slice). Operators
provisioning a new token for Evidentia should restrict to that
scope; never share a token with broader scopes than needed.

This module ships in v0.7.9 P0.4 first slice; subsequent slices
will add the remaining P0.4 collectors (Drata / BitSight /
SecurityScorecard) following the same pattern, and additional
Vanta endpoints (control tests, ongoing-monitoring posture).

No new pyproject extra is needed — the only runtime dep is
``httpx>=0.27`` which is already a base dependency of
``evidentia-collectors``. The collector imports cleanly from
``evidentia_collectors.vanta`` whenever the package is installed.

Typed exceptions (importable for caller-side ``except`` discipline):

- :class:`VantaCollectorError` — base; superclass of all the below
- :class:`VantaAuthError` — 401 / 403 / token rejection
- :class:`VantaConnectionError` — network / TLS / timeout
- :class:`VantaQueryError` — per-endpoint failure (4xx / 5xx) that
  doesn't fit the auth bucket; raised within ``collect_v2`` and
  surfaced in the manifest's ``errors`` list rather than failing
  the whole collection
"""

from __future__ import annotations

from evidentia_collectors.vanta.collector import (
    VantaAuthError,
    VantaCollector,
    VantaCollectorError,
    VantaConnectionError,
    VantaQueryError,
)

__all__ = [
    "VantaAuthError",
    "VantaCollector",
    "VantaCollectorError",
    "VantaConnectionError",
    "VantaQueryError",
]
