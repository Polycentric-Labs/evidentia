"""Power BI REST API client (v0.7.8 P1.2).

Pure-Python client over httpx (already a base dep) + MSAL Python
for the Azure AD service-principal OAuth2 flow.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import httpx

from evidentia_integrations.powerbi.config import PowerBIConfig

if TYPE_CHECKING:
    # Type-only import; msal is in the [powerbi] optional extra.
    import msal  # noqa: F401


class PowerBIApiError(Exception):
    """Base class for all Power BI integration failures."""


class PowerBIAuthError(PowerBIApiError):
    """OAuth2 client-credentials flow failed (bad client secret,
    wrong tenant, missing service-principal permission, etc.)."""


class PowerBIPublishError(PowerBIApiError):
    """A specific publish step failed (dataset creation, row push,
    workspace ID lookup, etc.)."""


class PowerBIClient:
    """Power BI client.

    Args:
        config: typed :class:`PowerBIConfig`. Holds workspace +
            tenant + client identifiers + the env-var name where
            the client secret lives.
        http_timeout: httpx request timeout in seconds. Power BI
            REST endpoints are usually fast (< 1s) but row-push
            can take longer for large batches.

    Usage::

        with PowerBIClient(config) as client:
            dataset_id = client.ensure_dataset(
                dataset_name="evidentia-gaps",
                schema=GAP_DATASET_SCHEMA,
            )
            client.push_rows(
                dataset_id=dataset_id,
                table_name="gaps",
                rows=row_list,
            )
    """

    def __init__(
        self,
        config: PowerBIConfig,
        *,
        http_timeout: float = 30.0,
    ) -> None:
        self._config = config
        self._timeout = http_timeout
        self._access_token: str | None = None
        self._http: httpx.Client | None = None

    def __enter__(self) -> PowerBIClient:
        self._signin()
        return self

    def __exit__(self, *_: object) -> None:
        self._close()

    # ── Internal lifecycle ──────────────────────────────────────────

    def _ensure_msal(self) -> Any:
        try:
            import msal
        except ImportError as e:
            raise PowerBIApiError(
                'msal is not installed. Install via the [powerbi] extra: pip install "evidentia-integrations[powerbi]"'
            ) from e
        return msal

    def _signin(self) -> None:
        if self._access_token is not None:
            return

        client_secret = os.environ.get(self._config.client_secret_env)
        if not client_secret:
            raise PowerBIAuthError(
                f"Env var '{self._config.client_secret_env}' is "
                f"not set or is empty. Set it to the Azure AD "
                f"service-principal client secret."
            )

        msal = self._ensure_msal()
        try:
            authority = f"{self._config.authority_url.rstrip('/')}/{self._config.tenant_id}"
            app = msal.ConfidentialClientApplication(
                client_id=self._config.client_id,
                client_credential=client_secret,
                authority=authority,
            )
            result = app.acquire_token_for_client(scopes=[self._config.api_scope])
        except Exception as e:
            raise PowerBIAuthError(f"MSAL token acquisition failed (driver: {type(e).__name__})") from e

        if not isinstance(result, dict) or "access_token" not in result:
            err = result.get("error_description") if isinstance(result, dict) else "unknown"
            raise PowerBIAuthError(
                f"Power BI access token not granted. "
                f"Verify the service principal has "
                f"Dataset.ReadWrite.All on the workspace. "
                f"Detail: {err}"
            )
        self._access_token = str(result["access_token"])
        self._http = httpx.Client(
            base_url=self._config.api_base_url.rstrip("/"),
            timeout=self._timeout,
            headers={
                "Authorization": f"Bearer {self._access_token}",
                "Content-Type": "application/json",
            },
        )

    def _close(self) -> None:
        if self._http is not None:
            self._http.close()
            self._http = None
        self._access_token = None

    # ── Public surface ──────────────────────────────────────────────

    def list_datasets(self) -> list[dict[str, Any]]:
        """Enumerate all datasets in the configured workspace."""
        if self._http is None:
            self._signin()
        assert self._http is not None
        try:
            r = self._http.get(f"/groups/{self._config.workspace_id}/datasets")
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise PowerBIPublishError(f"List datasets failed: {type(e).__name__}: {e}") from e
        result = r.json()
        value = result.get("value", [])
        if not isinstance(value, list):
            return []
        return list(value)

    def find_dataset_by_name(self, name: str) -> dict[str, Any] | None:
        """Return the first dataset matching `name` exactly, or None."""
        for ds in self.list_datasets():
            if ds.get("name") == name:
                return ds
        return None

    def create_dataset(
        self,
        *,
        dataset_name: str,
        table_name: str,
        schema: list[dict[str, str]],
    ) -> str:
        """Create a Push Dataset with a single table.

        Args:
            dataset_name: human-readable name (Power BI lookup
                key).
            table_name: name for the single table within the
                dataset (Power BI Push Datasets typically have
                one table per dataset).
            schema: list of {name, dataType} dicts per column.

        Returns the new dataset ID.
        """
        if self._http is None:
            self._signin()
        assert self._http is not None
        body = {
            "name": dataset_name,
            "defaultMode": "Push",
            "tables": [{"name": table_name, "columns": schema}],
        }
        try:
            r = self._http.post(
                f"/groups/{self._config.workspace_id}/datasets",
                json=body,
            )
            r.raise_for_status()
        except httpx.HTTPError as e:
            raise PowerBIPublishError(f"Create dataset '{dataset_name}' failed: {type(e).__name__}: {e}") from e
        result = r.json()
        ds_id = result.get("id")
        if not ds_id:
            raise PowerBIPublishError(f"Power BI did not return a dataset ID for '{dataset_name}'.")
        return str(ds_id)

    def ensure_dataset(
        self,
        *,
        dataset_name: str,
        table_name: str,
        schema: list[dict[str, str]],
    ) -> str:
        """Look up an existing Push Dataset by name; create if missing."""
        existing = self.find_dataset_by_name(dataset_name)
        if existing is not None and "id" in existing:
            return str(existing["id"])
        return self.create_dataset(
            dataset_name=dataset_name,
            table_name=table_name,
            schema=schema,
        )

    def clear_table(self, *, dataset_id: str, table_name: str) -> None:
        """Delete all rows from a Push Dataset table.

        Power BI Push Datasets retain rows until explicitly cleared
        (or until the FIFO row limit is hit). For periodic full-
        refresh use cases (the typical compliance-dashboard
        pattern) we clear before pushing.

        F-V08-CR-H3 — first-publish flows on a freshly-created Push
        Dataset can return 404 (table doesn't yet contain rows the
        endpoint can identify) or other 4xx variants from some
        Power BI deployment regions. These are benign — the desired
        post-condition (no rows in the table) is already true. We
        swallow 4xx and let the caller proceed to push_rows. Real
        problems (5xx, network errors) still surface as
        PowerBIPublishError.
        """
        if self._http is None:
            self._signin()
        assert self._http is not None
        try:
            r = self._http.delete(f"/groups/{self._config.workspace_id}/datasets/{dataset_id}/tables/{table_name}/rows")
        except httpx.HTTPError as e:
            # Network-level failure (timeout, connection refused, etc.)
            raise PowerBIPublishError(f"Clear table '{table_name}' failed: {type(e).__name__}: {e}") from e
        if r.status_code == 404 or 400 <= r.status_code < 500:
            # Benign — see docstring. Proceed silently; the caller's
            # subsequent push_rows call will validate the table is
            # actually pushable.
            return
        if r.status_code >= 500:
            raise PowerBIPublishError(f"Clear table '{table_name}' failed: HTTP {r.status_code} {r.reason_phrase}")

    def push_rows(
        self,
        *,
        dataset_id: str,
        table_name: str,
        rows: list[dict[str, Any]],
    ) -> None:
        """Push rows to a Push Dataset table.

        Power BI's documented limits for a single push request are
        BOTH (a) max 10,000 rows AND (b) max 1 MB request body. This
        method splits on the row-count cap, then sub-splits any batch
        whose serialized JSON exceeds 1 MB so wide-schema customers
        (e.g., 50+ string columns × 10,000 rows) don't hit the byte
        cap with a 4xx. Closes v0.7.8 deferred F-V08-CR-MEDIUM Power
        BI 1MB guard.
        """
        if self._http is None:
            self._signin()
        assert self._http is not None

        if not rows:
            return

        row_batch_size = 10_000
        # 1 MB is the documented Power BI limit. We use 950 KB to
        # leave headroom for the JSON envelope (`{"rows": [...]}`)
        # + multibyte character expansion.
        max_batch_bytes = 950 * 1024

        def _serialize_batch(batch: list[dict[str, Any]]) -> bytes:
            return json.dumps({"rows": batch}).encode("utf-8")

        def _post(batch: list[dict[str, Any]], offset: int) -> None:
            assert self._http is not None
            try:
                r = self._http.post(
                    f"/groups/{self._config.workspace_id}/datasets/{dataset_id}/tables/{table_name}/rows",
                    json={"rows": batch},
                )
                r.raise_for_status()
            except httpx.HTTPError as e:
                raise PowerBIPublishError(
                    f"Push rows to '{table_name}' failed (batch starting at row {offset}): {type(e).__name__}: {e}"
                ) from e

        for batch_start in range(0, len(rows), row_batch_size):
            batch = rows[batch_start : batch_start + row_batch_size]
            payload = _serialize_batch(batch)
            if len(payload) <= max_batch_bytes:
                _post(batch, batch_start)
                continue
            # Wide-schema fallback: bisect the batch until each chunk
            # fits the 1 MB window. log2(10_000) ≈ 14, so worst case
            # we do 14 levels of bisection — bounded and predictable.
            stack: list[tuple[list[dict[str, Any]], int]] = [(batch, batch_start)]
            while stack:
                chunk, offset = stack.pop()
                chunk_payload = _serialize_batch(chunk)
                if len(chunk_payload) <= max_batch_bytes:
                    _post(chunk, offset)
                    continue
                if len(chunk) <= 1:
                    # A single row exceeds 1 MB on its own — Power BI
                    # cannot accept it. Surface a clear error so the
                    # operator can investigate.
                    raise PowerBIPublishError(
                        f"Single row at offset {offset} exceeds "
                        f"Power BI's 1 MB push-dataset limit "
                        f"(serialized size: {len(chunk_payload)} "
                        "bytes). Reduce the row's field sizes or "
                        "drop the offending field from the dataset."
                    )
                mid = len(chunk) // 2
                # Push order matches input order: process left first,
                # so push left LAST onto the stack (LIFO).
                stack.append((chunk[mid:], offset + mid))
                stack.append((chunk[:mid], offset))
