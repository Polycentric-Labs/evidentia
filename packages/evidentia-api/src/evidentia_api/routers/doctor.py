"""Doctor + air-gap validator router.

Mirrors the ``evidentia doctor`` CLI output for browser consumption,
plus the ``--check-air-gap`` validator as a POST endpoint (so GUI users
can run the check explicitly from the Settings page).
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

from evidentia_core.config import load_config
from evidentia_core.network_guard import (
    LOCAL_LLM_PREFIXES,
    is_loopback_or_private,
)
from fastapi import APIRouter

from evidentia_api.schemas import AirGapCheck, AirGapCheckResponse

router = APIRouter()


@router.get("/doctor")
async def doctor() -> dict[str, object]:
    """Return a diagnostic summary of the Evidentia installation.

    Structurally similar to the CLI ``doctor`` table output, but as JSON
    so the GUI can render badges + severity coloring per-subsystem.
    """
    py_version = ".".join(str(v) for v in sys.version_info[:3])
    subsystems: list[dict[str, str]] = [{"name": "Python", "status": "ok", "detail": py_version}]

    for pkg in (
        "evidentia_core",
        "evidentia_ai",
        "evidentia_collectors",
        "evidentia_integrations",
        "evidentia_api",
    ):
        try:
            __import__(pkg)
            subsystems.append({"name": pkg, "status": "ok", "detail": "installed"})
        except ImportError as e:
            subsystems.append({"name": pkg, "status": "missing", "detail": str(e)})

    # Catalogs + crosswalks
    try:
        from evidentia_core.catalogs.registry import FrameworkRegistry

        registry = FrameworkRegistry.get_instance()
        frameworks = registry.list_frameworks()
        crosswalk = registry.crosswalk
        subsystems.append(
            {
                "name": "OSCAL catalogs",
                "status": "ok",
                "detail": f"{len(frameworks)} frameworks registered",
            }
        )
        subsystems.append(
            {
                "name": "Crosswalks",
                "status": "ok",
                "detail": f"{len(crosswalk.available_frameworks)} frameworks mapped",
            }
        )
    except Exception as e:  # pragma: no cover — defensive
        subsystems.append({"name": "OSCAL catalogs", "status": "fail", "detail": str(e)})

    # LLM provider detection (no key values returned; just presence)
    llm_keys = {
        "OPENAI_API_KEY": "OpenAI",
        "ANTHROPIC_API_KEY": "Anthropic",
        "GOOGLE_API_KEY": "Google",
        "AZURE_OPENAI_API_KEY": "Azure OpenAI",
    }
    detected = [name for env, name in llm_keys.items() if os.environ.get(env)]
    subsystems.append(
        {
            "name": "LLM provider",
            "status": "ok" if detected else "warn",
            "detail": (
                ", ".join(detected) if detected else "No API key detected — set OPENAI_API_KEY, ANTHROPIC_API_KEY, etc."
            ),
        }
    )

    return {"subsystems": subsystems}


@router.post("/doctor/check-air-gap", response_model=AirGapCheckResponse)
async def check_air_gap() -> AirGapCheckResponse:
    """Audit every subsystem's offline posture without running any network IO.

    Returns a per-subsystem status report matching the CLI's
    ``doctor --check-air-gap`` table output.
    """
    checks: list[AirGapCheck] = []
    any_leaks = False

    cfg = load_config()
    model = os.environ.get("EVIDENTIA_LLM_MODEL") or (cfg.llm.model if cfg.llm else None) or "gpt-4o"
    api_base = os.environ.get("EVIDENTIA_LLM_API_BASE") or os.environ.get("OPENAI_API_BASE")

    # Subsystem: LLM client
    if any(model.lower().startswith(p) for p in LOCAL_LLM_PREFIXES):
        checks.append(
            AirGapCheck(
                subsystem="llm_client",
                status="ok",
                detail=f"model={model} (local prefix)",
            )
        )
    elif api_base:
        host = urlparse(api_base).hostname or ""
        if is_loopback_or_private(host):
            checks.append(
                AirGapCheck(
                    subsystem="llm_client",
                    status="ok",
                    detail=f"api_base={api_base} on loopback/RFC-1918",
                )
            )
        else:
            any_leaks = True
            checks.append(
                AirGapCheck(
                    subsystem="llm_client",
                    status="would_leak",
                    detail=(
                        f"api_base={api_base} is not loopback/RFC-1918. "
                        "Switch to Ollama or a local OpenAI-compatible endpoint."
                    ),
                )
            )
    else:
        any_leaks = True
        checks.append(
            AirGapCheck(
                subsystem="llm_client",
                status="would_leak",
                detail=(
                    f"model={model} is a cloud LLM and no local api_base is set. "
                    "Set EVIDENTIA_LLM_MODEL=ollama/llama3 or similar."
                ),
            )
        )

    # Subsystem: catalog loader (v0.4.0 has no URL-based catalog import yet)
    checks.append(
        AirGapCheck(
            subsystem="catalog_loader",
            status="ok",
            detail="v0.4.0 loads only from bundled + user-dir catalogs (no URL fetch)",
        )
    )

    # Subsystem: AI telemetry
    checks.append(
        AirGapCheck(
            subsystem="ai_telemetry",
            status="ok",
            detail="LiteLLM + Instructor do not emit telemetry",
        )
    )

    # Subsystem: gap store
    checks.append(
        AirGapCheck(
            subsystem="gap_store",
            status="ok",
            detail="platformdirs user-data (local filesystem only)",
        )
    )

    # Subsystem: web UI bind
    checks.append(
        AirGapCheck(
            subsystem="web_ui",
            status="ok",
            detail="`evidentia serve` binds to 127.0.0.1 by default",
        )
    )

    return AirGapCheckResponse(air_gapped=not any_leaks, checks=checks)
