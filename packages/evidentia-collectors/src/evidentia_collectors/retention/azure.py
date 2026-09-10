"""Selected Azure account, service and container retention configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from ._client import ClientFault, ComponentResponse, StorageReadSession
from ._contracts import (
    AzureTarget,
    ComponentId,
    ProjectedComponent,
    StorageRetentionComponentResult,
    StorageRetentionDiagnostic,
    StorageTarget,
    target_identity,
)
from ._parsing import JsonObject, JsonValue

_API_VERSION = "2026-04-01"
_DETAIL_CODES = Literal["missing_source_detail", "unsupported_source_value"]
_SCOPES: dict[ComponentId, str] = {
    "azure-account": "Microsoft.Storage/storageAccounts",
    "azure-blob-service": "Microsoft.Storage/storageAccounts/blobServices",
    "azure-container": "Microsoft.Storage/storageAccounts/blobServices/containers",
}


@dataclass
class _Fields:
    """Copy selected native fields while retaining unknown and omitted states."""

    diagnostics: set[_DETAIL_CODES] = field(default_factory=set)

    def missing(self) -> None:
        self.diagnostics.add("missing_source_detail")

    def unsupported(self) -> None:
        self.diagnostics.add("unsupported_source_value")

    def boolean(self, source: JsonObject, output: JsonObject, name: str, *, required: bool = False) -> bool | None:
        if name not in source:
            if required:
                self.missing()
            return None
        value = source[name]
        if value is None:
            output[name] = None
            self.missing()
            return None
        if type(value) is not bool:
            raise ClientFault("invalid_response")
        output[name] = value
        return value

    def text(
        self,
        source: JsonObject,
        output: JsonObject,
        name: str,
        *,
        required: bool = False,
        maximum: int = 128,
        known: frozenset[str] | None = None,
    ) -> str | None:
        if name not in source:
            if required:
                self.missing()
            return None
        value = source[name]
        if value is None:
            output[name] = None
            self.missing()
            return None
        if type(value) is not str or len(value) > maximum:
            raise ClientFault("invalid_response")
        output[name] = value
        if not value.strip():
            self.missing()
        if known is not None and value not in known:
            self.unsupported()
        return value

    def days(self, source: JsonObject, output: JsonObject, *, required: bool, maximum: int) -> None:
        name = "immutabilityPeriodSinceCreationInDays"
        if name not in source:
            if required:
                self.missing()
            return
        value = source[name]
        if value is None:
            output[name] = None
            self.missing()
        elif type(value) is not int or not 1 <= value <= maximum:
            raise ClientFault("invalid_response")
        else:
            output[name] = value

    def object(
        self, source: JsonObject, output: JsonObject, name: str, *, required: bool = False
    ) -> tuple[JsonObject, JsonObject] | None:
        if name not in source:
            if required:
                self.missing()
            return None
        value = source[name]
        if value is None:
            output[name] = None
            self.missing()
            return None
        if type(value) is not dict:
            raise ClientFault("invalid_response")
        child: JsonObject = {}
        output[name] = child
        return value, child

    def projection(self, response: ComponentResponse, fields: JsonObject) -> ProjectedComponent:
        return ProjectedComponent(
            api_version=_API_VERSION,
            native_scope=_SCOPES[response.component_id],
            fields=fields,
            diagnostics=tuple(StorageRetentionDiagnostic(code=code) for code in sorted(self.diagnostics)),
            source_etag=response.source_etag,
        )


def _envelope(
    response: ComponentResponse, target: StorageTarget, component: ComponentId
) -> tuple[JsonObject, JsonObject, JsonObject]:
    if response.component_id != component or type(target) is not AzureTarget:
        raise ClientFault("endpoint_mismatch")
    try:
        target = AzureTarget.model_validate(target)
    except ValueError:
        raise ClientFault("endpoint_mismatch") from None
    body = response.body
    if type(response.http_status) is not int or response.http_status != 200 or type(body) is not dict:
        raise ClientFault("invalid_response")
    properties = body.get("properties")
    original_id = body.get("id")
    if "error" in body or type(properties) is not dict or type(original_id) is not str:
        raise ClientFault("invalid_response")
    expected_id = target_identity(target).removeprefix("azure:")
    if component == "azure-account":
        expected_id = expected_id.rsplit("/blobservices/", 1)[0]
    elif component == "azure-blob-service":
        expected_id = expected_id.rsplit("/containers/", 1)[0]
    if not original_id.isascii() or len(original_id) > 512 or original_id.lower() != expected_id:
        raise ClientFault("source_identity_mismatch")
    output: JsonObject = {}
    fields: JsonObject = {"id": original_id, "properties": output}
    return properties, output, fields


def _policy(view: _Fields, source: JsonObject, output: JsonObject, *, account: bool) -> None:
    states = frozenset({"Disabled", "Unlocked", "Locked"} if account else {"Unlocked", "Locked"})
    state = view.text(source, output, "state", required=True, known=states)
    view.days(source, output, required=state != "Disabled", maximum=146_000 if account else 2**31 - 1)
    append = view.boolean(source, output, "allowProtectedAppendWrites")
    if not account:
        append_all = view.boolean(source, output, "allowProtectedAppendWritesAll")
        if append is True and append_all is True:
            view.unsupported()


def _project_account(response: ComponentResponse, target: StorageTarget) -> ProjectedComponent:
    source, output, fields = _envelope(response, target, "azure-account")
    view = _Fields()
    view.boolean(source, output, "isHnsEnabled", required=True)
    immutable = view.object(source, output, "immutableStorageWithVersioning", required=True)
    if immutable is not None:
        native, selected = immutable
        enabled = view.boolean(native, selected, "enabled", required=True)
        policy = view.object(native, selected, "immutabilityPolicy", required=enabled is True)
        if policy is not None:
            _policy(view, *policy, account=True)
    return view.projection(response, fields)


def _project_service(response: ComponentResponse, target: StorageTarget) -> ProjectedComponent:
    source, output, fields = _envelope(response, target, "azure-blob-service")
    view = _Fields()
    view.boolean(source, output, "isVersioningEnabled", required=True)
    return view.projection(response, fields)


def _tags(view: _Fields, source: JsonObject, output: JsonObject) -> bool | None:
    if "tags" not in source:
        view.missing()
        return None
    tags = source["tags"]
    if tags is None:
        output["tags"] = None
        view.missing()
        return None
    if type(tags) is not list:
        raise ClientFault("invalid_response")
    selected: list[JsonValue] = []
    values: list[str] = []
    for entry in tags:
        if type(entry) is not dict:
            raise ClientFault("invalid_response")
        kept: JsonObject = {}
        value = view.text(entry, kept, "tag", required=True, maximum=1024)
        selected.append(kept)
        if value is not None and value.strip():
            values.append(value)
    output["tags"] = selected
    if len(set(values)) != len(values):
        view.unsupported()
    return bool(values) if len(values) == len(tags) else None


def _hold(view: _Fields, source: JsonObject, output: JsonObject, has_hold: bool | None) -> None:
    embedded = view.boolean(source, output, "hasLegalHold", required=True)
    has_tags = _tags(view, source, output)
    known = [value for value in (has_hold, embedded, has_tags) if value is not None]
    if len(set(known)) > 1:
        view.unsupported()
    # Retain the append exception, excluding history timestamps and actor details.
    history = view.object(source, output, "protectedAppendWritesHistory")
    if history is not None:
        native, selected = history
        view.boolean(native, selected, "allowProtectedAppendWritesAll", required=True)


def _project_container(response: ComponentResponse, target: StorageTarget) -> ProjectedComponent:
    source, output, fields = _envelope(response, target, "azure-container")
    view = _Fields()
    has_policy = view.boolean(source, output, "hasImmutabilityPolicy", required=True)
    has_hold = view.boolean(source, output, "hasLegalHold", required=True)
    policy = view.object(source, output, "immutabilityPolicy", required=has_policy is True)
    if policy is not None:
        native, selected = policy
        if has_policy is False:
            view.unsupported()
        view.text(native, selected, "etag", maximum=1024)
        properties = view.object(native, selected, "properties", required=True)
        if properties is not None:
            _policy(view, *properties, account=False)
    immutable = view.object(source, output, "immutableStorageWithVersioning", required=True)
    if immutable is not None:
        native, selected = immutable
        view.boolean(native, selected, "enabled", required=True)
        view.text(native, selected, "migrationState", known=frozenset({"InProgress", "Completed"}))
        # Source precision and offset remain literal; no object retention is inferred.
        view.text(native, selected, "timeStamp")
    hold = view.object(source, output, "legalHold", required=has_hold is True)
    if hold is not None:
        _hold(view, *hold, has_hold)
    return view.projection(response, fields)


def read_azure(target: AzureTarget, session: StorageReadSession) -> list[StorageRetentionComponentResult]:
    """Read the three selected ARM resources without a fallback or object request."""
    if type(target) is not AzureTarget:
        raise ClientFault("endpoint_mismatch")
    try:
        selected = AzureTarget.model_validate(target)
    except ValueError:
        raise ClientFault("endpoint_mismatch") from None
    return [
        session.read_component("azure-account", selected, _project_account),
        session.read_component("azure-blob-service", selected, _project_service),
        session.read_component("azure-container", selected, _project_container),
    ]
