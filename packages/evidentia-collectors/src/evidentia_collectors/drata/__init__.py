"""Drata evidence collector for Evidentia (v0.7.9 P0.4 second slice).

Read-only collector that pulls a Drata-managed vendor inventory via
the Drata Public API (https://developers.drata.com) and emits
NIST 800-53 + OCC Bulletin 2013-29 + FRB SR 13-19 + FFIEC Vendor
Management mapped SecurityFinding objects. Mirrors the v0.7.9 P0.4
first-slice Vanta collector pattern.

Public surface::

    from evidentia_collectors.drata import DrataCollector

    with DrataCollector(api_token=os.environ["DRATA_API_TOKEN"]) as c:
        findings, manifest = c.collect_v2()

Or the legacy ``collect()`` shortcut returning just findings::

    findings = DrataCollector(api_token="...").collect()

The API token is sourced from the ``DRATA_API_TOKEN`` env var per
the secret-handling protocol — Drata uses Personal API tokens
that pass ``Authorization: Bearer <token>`` headers.

Token scope: read-only access to the vendor inventory surface (the
only endpoints this collector exercises in the first slice).

This module ships in v0.7.9 P0.4 second slice; subsequent slices
add Drata control-test pulls + ongoing-monitoring posture +
similar BitSight + SecurityScorecard collectors.

No new pyproject extra is needed — the only runtime dep is
``httpx>=0.27`` which is already a base dependency of
``evidentia-collectors``.

Typed exceptions (importable for caller-side ``except`` discipline):

- :class:`DrataCollectorError` — base; superclass of all the below
- :class:`DrataAuthError` — 401 / 403 / token rejection
- :class:`DrataConnectionError` — network / TLS / timeout
- :class:`DrataQueryError` — per-endpoint failure (4xx / 5xx) that
  doesn't fit the auth bucket; raised within ``collect_v2`` and
  surfaced in the manifest's ``errors`` list rather than failing
  the whole collection
"""

from __future__ import annotations

from evidentia_collectors.drata.collector import (
    DrataAuthError,
    DrataCollector,
    DrataCollectorError,
    DrataConnectionError,
    DrataQueryError,
)

__all__ = [
    "DrataAuthError",
    "DrataCollector",
    "DrataCollectorError",
    "DrataConnectionError",
    "DrataQueryError",
]
