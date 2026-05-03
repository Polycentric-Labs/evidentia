"""Unit tests for evidentia_integrations.powerbi.client (v0.7.8 P1.2).

Mocks MSAL token-acquisition + httpx HTTP layer — no live Power BI
account or Azure AD tenant required.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
from evidentia_integrations.powerbi.client import (
    PowerBIApiError,
    PowerBIAuthError,
    PowerBIClient,
    PowerBIPublishError,
)
from evidentia_integrations.powerbi.config import PowerBIConfig


def _config() -> PowerBIConfig:
    return PowerBIConfig(
        workspace_id="11111111-1111-1111-1111-111111111111",
        tenant_id="22222222-2222-2222-2222-222222222222",
        client_id="33333333-3333-3333-3333-333333333333",
    )


def _patch_msal_success() -> Any:
    """Return a patcher that makes MSAL return a fake access token."""
    fake_msal = MagicMock()
    app = MagicMock()
    app.acquire_token_for_client.return_value = {
        "access_token": "FAKE-TOKEN-FOR-TESTING-ONLY"
    }
    fake_msal.ConfidentialClientApplication.return_value = app
    return fake_msal


def _build_client_with_secret(
    monkeypatch: pytest.MonkeyPatch,
    *,
    fake_msal: Any | None = None,
    secret: str = "FAKE-CLIENT-SECRET",
) -> PowerBIClient:
    monkeypatch.setenv("POWERBI_CLIENT_SECRET", secret)
    client = PowerBIClient(_config())
    if fake_msal is not None:
        # Inject the mocked MSAL into the lazy-import path.
        client._ensure_msal = lambda: fake_msal  # type: ignore[method-assign]
    return client


# ── TestAuth ───────────────────────────────────────────────────────


class TestAuth:
    def test_missing_secret_raises_auth_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("POWERBI_CLIENT_SECRET", raising=False)
        client = PowerBIClient(_config())
        with pytest.raises(PowerBIAuthError) as exc_info:
            client._signin()
        assert "POWERBI_CLIENT_SECRET" in str(exc_info.value)

    def test_msal_failure_raises_auth_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # MSAL raises during token acquisition.
        fake_msal = MagicMock()
        fake_msal.ConfidentialClientApplication.side_effect = (
            RuntimeError("simulated MSAL failure")
        )
        client = _build_client_with_secret(
            monkeypatch, fake_msal=fake_msal
        )
        with pytest.raises(PowerBIAuthError) as exc_info:
            client._signin()
        assert "MSAL" in str(exc_info.value)

    def test_no_access_token_raises_auth_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # MSAL returns a dict without 'access_token'.
        fake_msal = MagicMock()
        app = MagicMock()
        app.acquire_token_for_client.return_value = {
            "error_description": "AADSTS500011 — service principal "
            "not found"
        }
        fake_msal.ConfidentialClientApplication.return_value = app
        client = _build_client_with_secret(
            monkeypatch, fake_msal=fake_msal
        )
        with pytest.raises(PowerBIAuthError) as exc_info:
            client._signin()
        assert "access token not granted" in str(exc_info.value)

    def test_signin_success_sets_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _build_client_with_secret(
            monkeypatch, fake_msal=_patch_msal_success()
        )
        client._signin()
        assert client._access_token == "FAKE-TOKEN-FOR-TESTING-ONLY"
        assert client._http is not None


class TestImportError:
    def test_msal_not_installed_raises_typed_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without msal installed, _ensure_msal raises a typed
        PowerBIApiError pointing at the [powerbi] extra."""
        import sys

        saved = sys.modules.get("msal")
        sys.modules["msal"] = None  # type: ignore[assignment]
        try:
            monkeypatch.setenv("POWERBI_CLIENT_SECRET", "x")
            client = PowerBIClient(_config())
            with pytest.raises(PowerBIApiError) as exc_info:
                client._signin()
            assert "[powerbi]" in str(exc_info.value)
        finally:
            if saved is None:
                sys.modules.pop("msal", None)
            else:
                sys.modules["msal"] = saved


# ── TestRESTHelpers ────────────────────────────────────────────────


class TestRESTHelpers:
    def _signed_in(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> PowerBIClient:
        client = _build_client_with_secret(
            monkeypatch, fake_msal=_patch_msal_success()
        )
        client._signin()
        return client

    def test_list_datasets(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = {
            "value": [
                {"id": "ds1", "name": "evidentia-gaps"},
                {"id": "ds2", "name": "evidentia-risks"},
            ]
        }
        with patch.object(
            client._http, "get", return_value=response
        ) as mock_get:
            datasets = client.list_datasets()
            mock_get.assert_called_once_with(
                f"/groups/{client._config.workspace_id}/datasets"
            )
        assert len(datasets) == 2
        assert datasets[0]["name"] == "evidentia-gaps"

    def test_find_dataset_by_name_match(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = {
            "value": [
                {"id": "ds1", "name": "evidentia-gaps"},
            ]
        }
        with patch.object(
            client._http, "get", return_value=response
        ):
            ds = client.find_dataset_by_name("evidentia-gaps")
        assert ds is not None
        assert ds["id"] == "ds1"

    def test_find_dataset_by_name_no_match(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = {
            "value": [
                {"id": "ds1", "name": "other-dataset"},
            ]
        }
        with patch.object(
            client._http, "get", return_value=response
        ):
            ds = client.find_dataset_by_name("evidentia-gaps")
        assert ds is None

    def test_create_dataset_returns_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.raise_for_status = MagicMock()
        response.json.return_value = {"id": "new-ds-id"}
        with patch.object(
            client._http, "post", return_value=response
        ) as mock_post:
            ds_id = client.create_dataset(
                dataset_name="evidentia-gaps",
                table_name="gaps",
                schema=[{"name": "x", "dataType": "String"}],
            )
            assert ds_id == "new-ds-id"
            mock_post.assert_called_once()

    def test_clear_table_calls_delete(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.status_code = 200  # Power BI returns 200 OK on success
        with patch.object(
            client._http, "delete", return_value=response
        ) as mock_delete:
            client.clear_table(
                dataset_id="ds-x", table_name="gaps"
            )
            mock_delete.assert_called_once()

    def test_clear_table_swallows_404_on_fresh_dataset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """F-V08-CR-H3 — first-publish flow on a brand-new Push
        Dataset can return 404 because the table has no rows the
        endpoint can identify. clear_table must swallow this so
        the subsequent push_rows call proceeds."""
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.status_code = 404
        response.reason_phrase = "Not Found"
        with patch.object(
            client._http, "delete", return_value=response
        ):
            # Should NOT raise PowerBIPublishError
            client.clear_table(
                dataset_id="ds-fresh", table_name="gaps"
            )

    def test_clear_table_raises_on_5xx(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """5xx is a real backend failure; surface to caller."""
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.status_code = 503
        response.reason_phrase = "Service Unavailable"
        with (
            patch.object(client._http, "delete", return_value=response),
            pytest.raises(PowerBIPublishError),
        ):
            client.clear_table(
                dataset_id="ds-x", table_name="gaps"
            )

    def test_push_rows_chunks_at_10k(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        response = MagicMock()
        response.raise_for_status = MagicMock()
        # 25,000 rows → 3 batches (10k + 10k + 5k).
        rows = [{"x": i} for i in range(25_000)]
        with patch.object(
            client._http, "post", return_value=response
        ) as mock_post:
            client.push_rows(
                dataset_id="ds-x",
                table_name="gaps",
                rows=rows,
            )
            assert mock_post.call_count == 3

    def test_push_rows_empty_no_call(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        with patch.object(
            client._http, "post"
        ) as mock_post:
            client.push_rows(
                dataset_id="ds-x", table_name="gaps", rows=[]
            )
            mock_post.assert_not_called()

    def test_http_error_wrapped_as_publish_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = self._signed_in(monkeypatch)
        with patch.object(
            client._http,
            "get",
            side_effect=httpx.HTTPError("simulated"),
        ), pytest.raises(PowerBIPublishError):
            client.list_datasets()


# ── TestEnsureDataset ──────────────────────────────────────────────


class TestEnsureDataset:
    def test_returns_existing_dataset_id(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _build_client_with_secret(
            monkeypatch, fake_msal=_patch_msal_success()
        )
        client._signin()

        # First call: list returns one matching dataset.
        list_response = MagicMock()
        list_response.raise_for_status = MagicMock()
        list_response.json.return_value = {
            "value": [{"id": "existing-id", "name": "evidentia-gaps"}]
        }
        with patch.object(
            client._http, "get", return_value=list_response
        ):
            ds_id = client.ensure_dataset(
                dataset_name="evidentia-gaps",
                table_name="gaps",
                schema=[],
            )
        assert ds_id == "existing-id"

    def test_creates_when_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        client = _build_client_with_secret(
            monkeypatch, fake_msal=_patch_msal_success()
        )
        client._signin()

        list_response = MagicMock()
        list_response.raise_for_status = MagicMock()
        list_response.json.return_value = {"value": []}

        create_response = MagicMock()
        create_response.raise_for_status = MagicMock()
        create_response.json.return_value = {"id": "new-id"}

        with (
            patch.object(
                client._http, "get", return_value=list_response
            ),
            patch.object(
                client._http, "post", return_value=create_response
            ),
        ):
            ds_id = client.ensure_dataset(
                dataset_name="evidentia-gaps",
                table_name="gaps",
                schema=[{"name": "x", "dataType": "String"}],
            )
        assert ds_id == "new-id"
