"""Tableau Server / Cloud output integration (v0.7.8 P1.1).

Publishes Evidentia compliance data — gap inventory + risk register +
collection-run audit trail — to a Tableau site as a CSV-based data
source. Risk officers + audit committees can then build refreshable
dashboards on top of the published data sources.

Public surface (imports from ``evidentia_integrations.tableau``):

- :class:`TableauClient` — pure-Python wrapper around the Tableau
  REST API via the official ``tableauserverclient`` library. Handles
  PAT-based auth + site selection + project lookup.
- :class:`TableauConfig` — typed configuration (server URL, site name,
  project name, auth-token-env-var name). Credentials never travel
  inside the config object.
- :class:`TableauApiError`, :class:`TableauAuthError`,
  :class:`TableauPublishError` — typed exception hierarchy.
- :func:`build_gap_dataset_csv` / :func:`build_risk_dataset_csv` /
  :func:`build_collection_run_dataset_csv` — pure functions producing
  CSV bytes from Evidentia models. Easy to unit-test without a live
  Tableau server.
- :func:`publish_report` — high-level orchestration: build the CSVs,
  authenticate to Tableau, publish all three datasets to the
  configured site/project. Returns a :class:`TableauPublishResult`.

v0.7.8 ships **CSV-datasource publish** (the broadly-supported
Tableau format). ``.hyper`` extracts (which would require the
heavyweight ``tableauhyperapi`` native binary) are documented as a
v0.7.9+ enhancement under a separate ``[tableau-hyper]`` extra.

Auth modes supported:

- **Personal Access Token (PAT)** — token name + secret read from
  env vars (``TABLEAU_PAT_NAME`` + ``TABLEAU_PAT_SECRET``). Simple
  for CI + dev.
- **Username + password** — supported by the underlying SDK but
  NOT exposed via this integration; password auth is being
  deprecated by Tableau Cloud and this integration is forward-
  compatible only.

Per ``~/.claude/CLAUDE.md`` secret-handling protocol:

- The integration NEVER accepts a token in code at the CLI surface.
  The CLI surface (``evidentia integrations tableau publish``)
  reads token name + secret from env vars + forwards to the
  publisher.
- The token secret NEVER appears in API request bodies — only the
  env-var name does.
"""

from evidentia_integrations.tableau.client import (
    TableauApiError,
    TableauAuthError,
    TableauClient,
    TableauPublishError,
)
from evidentia_integrations.tableau.config import TableauConfig
from evidentia_integrations.tableau.extract import (
    build_collection_run_dataset_csv,
    build_gap_dataset_csv,
    build_risk_dataset_csv,
)
from evidentia_integrations.tableau.publish import (
    TableauPublishResult,
    publish_report,
)

__all__ = [
    "TableauApiError",
    "TableauAuthError",
    "TableauClient",
    "TableauConfig",
    "TableauPublishError",
    "TableauPublishResult",
    "build_collection_run_dataset_csv",
    "build_gap_dataset_csv",
    "build_risk_dataset_csv",
    "publish_report",
]
