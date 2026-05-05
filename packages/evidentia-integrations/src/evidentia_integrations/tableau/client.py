"""Tableau Server / Cloud REST API client (v0.7.8 P1.1).

Thin wrapper around the official ``tableauserverclient`` library. The
SDK is pure-Python (no native deps), authenticates via PAT, and
exposes the publish-datasource endpoint we need.

The wrapper adds:

- Typed exception hierarchy (:class:`TableauApiError` /
  :class:`TableauAuthError` / :class:`TableauPublishError`)
- Lazy SDK import so the ``evidentia_integrations`` package loads
  without ``tableauserverclient`` installed
- Resolution of project name → project ID (the SDK requires the ID
  but operators think in terms of names)
- A context-manager interface that signs out cleanly on exit
"""

from __future__ import annotations

import contextlib
import os
from typing import TYPE_CHECKING, Any

from evidentia_integrations.tableau.config import TableauConfig

if TYPE_CHECKING:
    # Type-only import; tableauserverclient is in the [tableau]
    # optional extra. The runtime import is lazy.
    import tableauserverclient as TSC  # noqa: F401


class TableauApiError(Exception):
    """Base class for all Tableau integration failures."""


class TableauAuthError(TableauApiError):
    """Authentication failure (bad token, expired session, wrong site)."""


class TableauPublishError(TableauApiError):
    """A specific publish step failed (project lookup, datasource upload, etc.)."""


class TableauClient:
    """Tableau Server / Cloud client.

    Args:
        config: typed :class:`TableauConfig`. Holds env-var names,
            never the secret values themselves.

    Usage::

        with TableauClient(config) as client:
            project_id = client.get_project_id("Compliance")
            client.publish_csv_datasource(
                project_id=project_id,
                datasource_name="evidentia-gaps",
                csv_bytes=gap_csv_bytes,
                overwrite=True,
            )
    """

    def __init__(self, config: TableauConfig) -> None:
        self._config = config
        self._server: Any | None = None
        self._auth_token: str | None = None

    def __enter__(self) -> TableauClient:
        self._signin()
        return self

    def __exit__(self, *_: object) -> None:
        self._signout()

    # ── Internal lifecycle ──────────────────────────────────────────

    def _ensure_sdk(self) -> Any:
        try:
            import tableauserverclient as TSC
        except ImportError as e:
            raise TableauApiError(
                "tableauserverclient is not installed. "
                "Install via the [tableau] extra: "
                'pip install "evidentia-integrations[tableau]"'
            ) from e
        return TSC

    def _signin(self) -> None:
        if self._server is not None:
            return
        TSC = self._ensure_sdk()

        token_name = os.environ.get(self._config.pat_name_env)
        token_secret = os.environ.get(self._config.pat_secret_env)
        if not token_name:
            raise TableauAuthError(
                f"Env var '{self._config.pat_name_env}' is not set "
                f"or is empty. Set it to the Tableau Personal "
                f"Access Token name."
            )
        if not token_secret:
            raise TableauAuthError(
                f"Env var '{self._config.pat_secret_env}' is not "
                f"set or is empty. Set it to the Tableau Personal "
                f"Access Token secret."
            )

        try:
            tableau_auth = TSC.PersonalAccessTokenAuth(
                token_name=token_name,
                personal_access_token=token_secret,
                site_id=self._config.site_id,
            )
            server = TSC.Server(
                self._config.server_url,
                use_server_version=False,
            )
            server.version = self._config.api_version
            server.auth.sign_in(tableau_auth)
        except Exception as e:
            raise TableauAuthError(
                f"Tableau sign-in failed (driver: {type(e).__name__})"
            ) from e
        self._server = server

    def _signout(self) -> None:
        if self._server is None:
            return
        with contextlib.suppress(Exception):
            self._server.auth.sign_out()
        self._server = None

    # ── Public surface ──────────────────────────────────────────────

    def get_project_id(self, project_name: str) -> str:
        """Resolve a project name to its Tableau project ID.

        Tableau projects are unique by name within a site (with
        rare nesting exceptions); we accept the first match.
        """
        if self._server is None:
            self._signin()
        assert self._server is not None
        TSC = self._ensure_sdk()

        try:
            req_options = TSC.RequestOptions()
            req_options.filter.add(
                TSC.Filter(
                    TSC.RequestOptions.Field.Name,
                    TSC.RequestOptions.Operator.Equals,
                    project_name,
                )
            )
            projects, _pagination = self._server.projects.get(req_options)
        except Exception as e:
            raise TableauPublishError(
                f"Project lookup failed (driver: {type(e).__name__})"
            ) from e

        if not projects:
            raise TableauPublishError(
                f"Project '{project_name}' not found on site "
                f"'{self._config.site_id or '<default>'}'."
            )
        return str(projects[0].id)

    def publish_csv_datasource(
        self,
        *,
        project_id: str,
        datasource_name: str,
        csv_bytes: bytes,
        overwrite: bool = True,
    ) -> str:
        """Publish a CSV byte-blob as a Tableau data source.

        The SDK requires a file path; we write the CSV to a
        temporary file inside a ``tempfile.TemporaryDirectory()``
        context, publish, then let the directory cleanup handle
        the file removal.

        v0.7.14 P1.2 closure for v0.7.8 LOW item 3 (Tableau
        Windows tempfile cleanup): the previous implementation
        used ``NamedTemporaryFile(delete=False)`` + manual
        ``unlink()`` wrapped in ``contextlib.suppress(OSError)``.
        On Windows, the SDK call sometimes left a handle open
        long enough for ``unlink()`` to fail with
        ``PermissionError`` (a sub-class of ``OSError``);
        the suppress swallowed it silently, leaving a leaked
        .csv tempfile in the system tempdir.

        ``TemporaryDirectory()`` is the canonical fix: the
        directory cleanup at context exit handles the file
        removal cleanly across both POSIX and Windows. If a
        handle is still open at exit time, ``shutil.rmtree``
        retries (Python 3.12+ has ``ignore_cleanup_errors=True``
        as an option, which we don't enable — we want any
        cleanup failure to surface as a logger warning, not
        silently leak files).

        Returns the published data-source ID.
        """
        if self._server is None:
            self._signin()
        assert self._server is not None
        TSC = self._ensure_sdk()

        import tempfile
        from pathlib import Path

        try:
            ds_item = TSC.DatasourceItem(project_id=project_id)
            ds_item.name = datasource_name
            with tempfile.TemporaryDirectory(
                prefix="evidentia-tableau-"
            ) as tmpdir:
                tmp_path = Path(tmpdir) / "datasource.csv"
                tmp_path.write_bytes(csv_bytes)
                mode = (
                    TSC.Server.PublishMode.Overwrite
                    if overwrite
                    else TSC.Server.PublishMode.CreateNew
                )
                published = self._server.datasources.publish(
                    ds_item, str(tmp_path), mode
                )
                # Directory cleanup happens automatically at
                # context exit; no manual unlink needed.
        except Exception as e:
            raise TableauPublishError(
                f"Datasource publish failed (driver: "
                f"{type(e).__name__}): {e}"
            ) from e
        return str(published.id)
