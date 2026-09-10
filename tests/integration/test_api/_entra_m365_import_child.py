"""Import-isolated optional feature checks; no environment installation changes."""

from __future__ import annotations

import asyncio
import importlib.abc
import importlib.util
import json
import sys
from collections.abc import Sequence
from importlib.machinery import ModuleSpec
from pathlib import Path
from types import ModuleType

import pytest
from _entra_m365_asgi import AUTH, Provider, app, deliver, isolate
from _entra_m365_llm_isolation import isolate_unused_llm
from fastapi import FastAPI

llm = isolate_unused_llm()

MODE = sys.argv[1]
DIRECTORY = Path(sys.argv[2]).resolve()
DIRECTORY.mkdir(parents=True, exist_ok=True)
NAMES = {
    "parent": "evidentia_collectors",
    "feature": "evidentia_collectors.entra_m365",
    "internal": "evidentia_collectors.entra_m365._contracts",
}


class BrokenLoader(importlib.abc.Loader):
    def create_module(self, spec: ModuleSpec) -> ModuleType | None:
        return None

    def exec_module(self, module: ModuleType) -> None:
        if MODE == "transitive":
            raise ModuleNotFoundError("synthetic dependency failure", name="synthetic_transitive_dependency")
        if MODE == "symbol":
            return
        raise SyntaxError("synthetic broken feature")


class Block(importlib.abc.MetaPathFinder):
    def find_spec(
        self, fullname: str, path: Sequence[str] | None, target: ModuleType | None = None
    ) -> ModuleSpec | None:
        if MODE in NAMES and fullname == NAMES[MODE]:
            raise ModuleNotFoundError("synthetic optional-import probe", name=fullname)
        if MODE in ("transitive", "symbol", "syntax") and fullname == "evidentia_collectors.entra_m365":
            return importlib.util.spec_from_loader(fullname, BrokenLoader(), is_package=True)
        return None


async def check_absence(application: FastAPI) -> None:
    operation = application.openapi()["paths"]["/api/collectors/entra-m365/collect"]["post"]
    assert "200" not in operation["responses"]
    assert operation["responses"]["503"]["content"]["application/json"]["schema"]["$ref"].endswith("/ErrorEnvelope")
    assert "requestBody" not in operation
    status, body, consumed = await deliver(application, [b"UNREAD_BODY"], headers=[])
    assert status == 503 and body["detail"]["error"] == "feature_unavailable" and consumed == 0
    from evidentia_core.rbac import RBACPolicy, Role, TenantRBACPolicy

    denied = app(
        provider=Provider("reviewer@@denied"),
        policy=TenantRBACPolicy(tenants={"denied": RBACPolicy(default_role=Role.DENY)}),
    )
    status, body, consumed = await deliver(denied, [b"UNREAD_BODY"], headers=[(b"authorization", AUTH)])
    assert status == 403 and body["detail"]["error"] == "rbac_denied" and consumed == 0
    status, body, consumed = await deliver(denied, [b"UNREAD_BODY"], headers=[])
    assert status == 401 and consumed == 0


with pytest.MonkeyPatch.context() as patch:
    isolate(patch, DIRECTORY)
    sys.meta_path.insert(0, Block())
    try:
        application = app()
    except (ModuleNotFoundError, ImportError, SyntaxError) as error:
        assert MODE in ("internal", "transitive", "symbol", "syntax"), (MODE, type(error).__name__)
        expected = {
            "internal": "ModuleNotFoundError",
            "transitive": "ModuleNotFoundError",
            "symbol": "ImportError",
            "syntax": "SyntaxError",
        }[MODE]
        assert type(error).__name__ == expected
        print(
            json.dumps(
                {
                    "mode": MODE,
                    "llm_calls": llm.calls,
                    "startup": "rejected",
                    "exception": expected,
                    "module": getattr(error, "name", None),
                }
            )
        )
    else:
        assert MODE in ("parent", "feature")
        # The event loop's local socket pair is initialized before the request guard.
        patch.undo()
        with asyncio.Runner() as runner:
            runner.get_loop()
            isolate(patch, DIRECTORY)
            runner.run(check_absence(application))
        print(
            json.dumps(
                {
                    "mode": MODE,
                    "llm_calls": llm.calls,
                    "startup": "available-error-only",
                    "statuses": [503, 403, 401],
                    "body_reads": 0,
                    "success_schema": False,
                }
            )
        )

llm.assert_unused()
