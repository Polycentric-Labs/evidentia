"""httpx-based ServiceNow Table API client.

We use ``httpx`` directly rather than the optional ``pysnc`` SDK to
keep the dependency footprint small. The Table API surface we need
— create record, get record, query — is well within REST reach.

**Secret handling.** The ``password`` from :class:`ServiceNowConfig`
is sent as HTTP basic-auth's password field, never logged, never
returned in any method's output. Exceptions carry the HTTP status
code + ServiceNow's ``error.message`` field but never echo
outbound headers.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import httpx
from pydantic import BaseModel, ConfigDict, Field

from evidentia_integrations.servicenow.config import ServiceNowConfig

logger = logging.getLogger(__name__)


class ServiceNowApiError(Exception):
    """Raised when the Table API returns a non-2xx response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        error_message: str | None = None,
        body_excerpt: str | None = None,
    ) -> None:
        self.status_code = status_code
        self.error_message = error_message
        self.body_excerpt = body_excerpt
        detail = f"[HTTP {status_code}] {message}"
        if error_message:
            detail += f" -- {error_message}"
        super().__init__(detail)


class ServiceNowRecord(BaseModel):
    """Typed ServiceNow Table-API record — narrowed."""

    model_config = ConfigDict(extra="allow")

    sys_id: str = Field(description="Internal record sys_id.")
    number: str = Field(description="Display-friendly record number, e.g. INC0010001.")
    short_description: str = Field(description="Record short description.")
    state: str = Field(default="", description="Workflow state code or name.")
    url: str = Field(description="Browser URL for the record.")


class ServiceNowClient:
    """Thin ServiceNow Table-API client.

    Usage::

        cfg = ServiceNowConfig.from_env()
        with ServiceNowClient(cfg) as client:
            record = client.create_record(fields={...})
            client.test_connection()
    """

    def __init__(
        self,
        config: ServiceNowConfig,
        *,
        http: httpx.Client | None = None,
    ) -> None:
        self._config = config
        basic = base64.b64encode(f"{config.user}:{config.password}".encode()).decode("ascii")
        self._http = http or httpx.Client(
            base_url=config.instance_url,
            headers={
                "Authorization": f"Basic {basic}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            timeout=config.timeout_seconds,
        )

    @property
    def config(self) -> ServiceNowConfig:
        return self._config

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ServiceNowClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ── Low-level request ───────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        try:
            response = self._http.request(method, path, json=json, params=params)
        except httpx.HTTPError as e:
            raise ServiceNowApiError(f"ServiceNow request failed: {e}", status_code=0) from e

        if response.status_code == 204:
            return {}

        try:
            body = response.json()
        except ValueError:
            body = None

        if not 200 <= response.status_code < 300:
            error_message: str | None = None
            if isinstance(body, dict):
                err = body.get("error")
                if isinstance(err, dict):
                    error_message = str(err.get("message") or err.get("detail") or "")
            excerpt = response.text[:200] + ("..." if len(response.text) > 200 else "") if not error_message else None
            raise ServiceNowApiError(
                f"{method.upper()} {path}",
                status_code=response.status_code,
                error_message=error_message,
                body_excerpt=excerpt,
            )

        return body if isinstance(body, dict) else {}

    # ── High-level operations ───────────────────────────────────────

    def test_connection(self) -> dict[str, str]:
        """Verify credentials + table access.

        Probes the configured table with a 1-row query — confirms
        both that the credentials work and that the principal has
        read access to the target table.
        """
        body = self._request(
            "GET",
            f"/api/now/table/{self._config.table_name}",
            params={"sysparm_limit": "1", "sysparm_fields": "sys_id"},
        )
        return {
            "instance_url": self._config.instance_url,
            "table_name": self._config.table_name,
            "user": self._config.user,
            "result_count": str(len(body.get("result", []) or [])),
        }

    def create_record(self, *, fields: dict[str, Any]) -> ServiceNowRecord:
        """Create a record in the configured table."""
        body = self._request(
            "POST",
            f"/api/now/table/{self._config.table_name}",
            json=fields,
        )
        result = body.get("result") or {}
        if not isinstance(result, dict):
            raise ServiceNowApiError(
                "ServiceNow create returned no record",
                status_code=200,
            )
        sys_id = str(result.get("sys_id") or "")
        number = str(result.get("number") or "")
        url = f"{self._config.instance_url}/nav_to.do?uri={self._config.table_name}.do?sys_id={sys_id}"
        return ServiceNowRecord(
            sys_id=sys_id,
            number=number,
            short_description=str(result.get("short_description") or ""),
            state=str(result.get("state") or ""),
            url=url,
        )

    def get_record(self, sys_id: str) -> ServiceNowRecord:
        body = self._request(
            "GET",
            f"/api/now/table/{self._config.table_name}/{sys_id}",
        )
        result = body.get("result") or {}
        if not isinstance(result, dict):
            raise ServiceNowApiError(
                f"ServiceNow get returned no record for {sys_id}",
                status_code=200,
            )
        url = f"{self._config.instance_url}/nav_to.do?uri={self._config.table_name}.do?sys_id={sys_id}"
        return ServiceNowRecord(
            sys_id=str(result.get("sys_id") or sys_id),
            number=str(result.get("number") or ""),
            short_description=str(result.get("short_description") or ""),
            state=str(result.get("state") or ""),
            url=url,
        )

    def find_existing_by_correlation(self, *, correlation_id: str) -> ServiceNowRecord | None:
        """Look up a previously-created record by correlation_id.

        Used to make `push_open_gaps` idempotent — re-pushing the
        same gap report should update existing records rather than
        creating duplicates.
        """
        body = self._request(
            "GET",
            f"/api/now/table/{self._config.table_name}",
            params={
                "sysparm_query": f"correlation_id={correlation_id}",
                "sysparm_limit": "1",
                "sysparm_fields": "sys_id,number,short_description,state",
            },
        )
        results = body.get("result") or []
        if not results:
            return None
        first = results[0] if isinstance(results, list) else None
        if not isinstance(first, dict):
            return None
        sys_id = str(first.get("sys_id") or "")
        url = f"{self._config.instance_url}/nav_to.do?uri={self._config.table_name}.do?sys_id={sys_id}"
        return ServiceNowRecord(
            sys_id=sys_id,
            number=str(first.get("number") or ""),
            short_description=str(first.get("short_description") or ""),
            state=str(first.get("state") or ""),
            url=url,
        )
