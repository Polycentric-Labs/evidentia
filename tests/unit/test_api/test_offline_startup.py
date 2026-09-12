"""Boot the API in an empty offline home without importing the AI client."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_api_startup_and_model_status_need_no_tokenizer_cache(tmp_path: Path) -> None:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"}
    }
    for name in ("home", "cache", "temp", "roaming", "local"):
        (tmp_path / name).mkdir()
    environment.update(
        {
            "HOME": str(tmp_path / "home"),
            "USERPROFILE": str(tmp_path / "home"),
            "APPDATA": str(tmp_path / "roaming"),
            "LOCALAPPDATA": str(tmp_path / "local"),
            "TEMP": str(tmp_path / "temp"),
            "TMP": str(tmp_path / "temp"),
            "TIKTOKEN_CACHE_DIR": str(tmp_path / "cache"),
            "EVIDENTIA_API_OFFLINE": "1",
            "LITELLM_LOCAL_MODEL_COST_MAP": "true",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    program = """
import asyncio
import os
import sys
from pathlib import Path

loop = asyncio.new_event_loop()
operations = []
def audit(event, args):
    if event in {"socket.connect", "socket.connect_ex", "socket.getaddrinfo", "socket.bind", "urllib.Request", "http.client.connect", "subprocess.Popen", "os.system"}:
        operations.append(event)
        raise AssertionError("offline_startup_attempted_io")
sys.addaudithook(audit)

from evidentia_api.app import create_app
from evidentia_api.routers.llm_status import llm_status
from evidentia_collectors.enterprise_retention._profiles import ProfileRegistry
from evidentia_core.plugins.auth import AuthProvider, AuthResult
from httpx import ASGITransport, AsyncClient

class LocalAuth(AuthProvider):
    def authenticate(self, *, authorization_header):
        return AuthResult(authenticated=False)
    def name(self):
        return "offline-startup-test"

app = create_app(offline=True, auth_provider=LocalAuth(), enterprise_retention_profiles=ProfileRegistry(), trust_proxy_headers=False)
assert app.openapi()["openapi"]
assert not any(name in sys.modules for name in ("evidentia_ai.client", "litellm", "instructor", "tiktoken"))

async def exercise():
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
            assert (await client.get("/api/health")).status_code == 200
    for configured, expected in [(None, "gpt-4o"), ("ollama/synthetic", "ollama/synthetic"), ("", "")]:
        if configured is None:
            os.environ.pop("EVIDENTIA_LLM_MODEL", None)
        else:
            os.environ["EVIDENTIA_LLM_MODEL"] = configured
        status = await llm_status()
        assert status.configured_model == expected
        assert status.providers["ollama"].configured == bool(configured and configured.startswith("ollama/"))
        assert all(not status.providers[name].configured for name in ("openai", "anthropic", "google", "azure_openai"))
try:
    loop.run_until_complete(exercise())
finally:
    loop.close()
assert not any(name in sys.modules for name in ("evidentia_ai.client", "litellm", "instructor", "tiktoken"))
assert not list(Path(os.environ["TIKTOKEN_CACHE_DIR"]).iterdir())
assert not operations
"""
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", program],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        check=False,
        timeout=60,
    )
    (tmp_path / "startup.stdout").write_bytes(result.stdout)
    (tmp_path / "startup.stderr").write_bytes(result.stderr)
    assert result.returncode == 0, "Offline API startup failed; subprocess output is preserved"
