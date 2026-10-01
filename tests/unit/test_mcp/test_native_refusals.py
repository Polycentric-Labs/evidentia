"""Native tool refusals retain fixed codes without classifying exception text."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from evidentia_core.models import open_corpora as native
from evidentia_mcp.cimd import CIMDDocument, CIMDRegistry
from evidentia_mcp.server import build_server
from mcp.server.mcpserver.exceptions import ToolError, UnexpectedToolError
from pydantic import ValidationError
from pydantic_core import PydanticSerializationError


@pytest.fixture
def native_server():
    registry = CIMDRegistry(
        clients={
            "native-reader": CIMDDocument(
                client_id="native-reader", client_name="Synthetic native reader", scope="get_catalog_native"
            )
        }
    )
    return build_server(cimd_registry=registry, default_client_id="native-reader")


def _invoke(server):
    return asyncio.run(server.call_tool("get_catalog_native", {"framework_id": "au-ism", "bundle_sha256": "0" * 64}))


@pytest.mark.parametrize(
    "code",
    [
        "native_source_invalid",
        "native_source_unavailable",
        "catalog_generation_changed",
        "processing_deadline_exceeded",
    ],
)
@pytest.mark.parametrize("target", ["direct", "_preflight", "native_value"])
def test_native_tool_preserves_typed_serializer_refusal(native_server, monkeypatch, code, target):
    from evidentia_core.catalogs.registry import FrameworkRegistry

    model = native.NativeReadRequest.model_validate({"framework_id": "au-ism", "bundle_sha256": "0" * 64})

    def refuse(*args, **kwargs):
        raise native.NativeSourceError(code)

    class Bundle:
        bundle_sha256 = "0" * 64

        def model_dump(self, **kwargs):
            if target == "direct":
                refuse()
            with monkeypatch.context() as patch:
                patch.setattr(native, target, refuse)
                return model.model_dump(mode="json")

    monkeypatch.setattr(FrameworkRegistry, "get_catalog", lambda *args: SimpleNamespace(native_source=Bundle()))
    before = native._ACTIVE_BUDGET.get()
    with pytest.raises(ToolError) as caught:
        _invoke(native_server)
    assert not isinstance(caught.value, UnexpectedToolError)
    assert str(caught.value) == f"Error executing tool get_catalog_native: {code}"
    assert native._ACTIVE_BUDGET.get() is before


@pytest.mark.parametrize(
    "kind",
    ["text", "value_error", "context", "deep_cause", "validation", "multiple", "mutated", "subclass"],
)
def test_native_tool_does_not_normalize_unknown_errors(native_server, monkeypatch, kind):
    from evidentia_core.catalogs.registry import FrameworkRegistry

    error = PydanticSerializationError("synthetic-private-detail processing_deadline_exceeded")
    if kind == "value_error":
        error.__cause__ = ValueError("processing_deadline_exceeded")
    elif kind == "context":
        error.__context__ = native.NativeSourceError("processing_deadline_exceeded")
    elif kind == "deep_cause":
        error.__cause__ = RuntimeError("synthetic-private-detail")
        error.__cause__.__cause__ = native.NativeSourceError("processing_deadline_exceeded")
    elif kind in {"validation", "multiple"}:
        validation = ValidationError.from_exception_data(
            "Synthetic",
            [
                {"type": "value_error", "loc": (name,), "input": None, "ctx": {"error": native.NativeSourceError()}}
                for name in (["one"] if kind == "validation" else ["one", "two"])
            ],
        )
        if kind == "validation":
            error = validation
        else:
            error.__cause__ = validation
    elif kind == "mutated":
        error.__cause__ = native.NativeSourceError()
        error.__cause__.code = "synthetic-private-detail"
    elif kind == "subclass":

        class RefusalSubclass(native.NativeSourceError):
            pass

        error.__cause__ = RefusalSubclass()

    class Bundle:
        bundle_sha256 = "0" * 64

        def model_dump(self, **kwargs):
            raise error

    monkeypatch.setattr(FrameworkRegistry, "get_catalog", lambda *args: SimpleNamespace(native_source=Bundle()))
    before = native._ACTIVE_BUDGET.get()
    with pytest.raises(UnexpectedToolError) as caught:
        _invoke(native_server)
    assert caught.value.__cause__ is error
    assert native._ACTIVE_BUDGET.get() is before


@pytest.mark.parametrize("kind", ["missing", "none", "integer", "boolean", "list", "dict", "object", "str_subclass"])
@pytest.mark.parametrize("target", ["direct", "_preflight", "native_value"])
def test_native_tool_does_not_normalize_malformed_codes(native_server, monkeypatch, kind, target):
    from evidentia_core.catalogs.registry import FrameworkRegistry

    class CodeSubclass(str):
        pass

    error = native.NativeSourceError("processing_deadline_exceeded")
    if kind == "missing":
        del error.code
    else:
        error.code = {
            "none": None,
            "integer": 1,
            "boolean": True,
            "list": ["processing_deadline_exceeded"],
            "dict": {"code": "processing_deadline_exceeded"},
            "object": object(),
            "str_subclass": CodeSubclass("processing_deadline_exceeded"),
        }[kind]
    model = native.NativeReadRequest.model_validate({"framework_id": "au-ism", "bundle_sha256": "0" * 64})

    def refuse(*args, **kwargs):
        raise error

    class Bundle:
        bundle_sha256 = "0" * 64

        def model_dump(self, **kwargs):
            if target == "direct":
                refuse()
            with monkeypatch.context() as patch:
                patch.setattr(native, target, refuse)
                return model.model_dump(mode="json")

    monkeypatch.setattr(FrameworkRegistry, "get_catalog", lambda *args: SimpleNamespace(native_source=Bundle()))
    before = native._ACTIVE_BUDGET.get()
    with pytest.raises(UnexpectedToolError) as caught:
        _invoke(native_server)
    if target == "direct":
        assert caught.value.__cause__ is error
    else:
        assert type(caught.value.__cause__) is PydanticSerializationError
    assert native._ACTIVE_BUDGET.get() is before
