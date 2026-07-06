"""Init-wizard router — GUI "Start from scratch" onboarding path.

Wraps :mod:`evidentia_core.init_wizard` for browser use. ``POST /init/wizard``
generates three starter YAMLs + a recommended framework list for the browser to
preview; ``POST /init/commit`` (v0.10.12) writes those same files to the
server's working directory once the user confirms.
"""

from __future__ import annotations

from pathlib import Path

from evidentia_core.init_wizard import (
    _PRESET_CONTROLS,
    generate_evidentia_yaml,
    generate_my_controls_yaml,
    generate_system_context_yaml,
    recommend_frameworks,
)
from fastapi import APIRouter

from evidentia_api.errors import api_error, error_responses
from evidentia_api.schemas import (
    InitWizardCommitRequest,
    InitWizardCommitResponse,
    InitWizardRequest,
    InitWizardResponse,
)

router = APIRouter()

# The fixed starter files the wizard produces. A closed set of filenames means a
# browser request can never steer the commit write to an arbitrary path.
_STARTER_FILES = ("evidentia.yaml", "my-controls.yaml", "system-context.yaml")


def _generate(payload: InitWizardRequest) -> tuple[dict[str, str], list[str]]:
    """Generate the three starter YAMLs + recommended frameworks.

    Shared by the preview (``/init/wizard``) and commit (``/init/commit``)
    paths so a committed file is byte-identical to what the browser previewed.
    Raises a 400 ``api_error`` (``error: unknown_preset``) on an invalid
    ``preset``.
    """
    recommended = recommend_frameworks(
        industry=payload.industry,
        hosting=payload.hosting,
        data_classification=payload.data_classification,
        regulatory_requirements=payload.regulatory_requirements,
    )

    try:
        my_controls_yaml = generate_my_controls_yaml(
            preset=payload.preset,  # type: ignore[arg-type]
            organization=payload.organization,
        )
    except ValueError as e:
        # 400 (not 422) — runtime input-validation after Pydantic body
        # parsing succeeded (the F-V08-DAST-3 status normalization is
        # unchanged). The detail is the structured object from
        # evidentia_api.errors, following the unknown_<field> pattern.
        raise api_error(
            400,
            "unknown_preset",
            str(e),
            preset=payload.preset,
            valid=sorted(_PRESET_CONTROLS),
        ) from e

    files = {
        "evidentia.yaml": generate_evidentia_yaml(
            organization=payload.organization,
            frameworks=recommended,
            system_name=payload.system_name,
        ),
        "my-controls.yaml": my_controls_yaml,
        "system-context.yaml": generate_system_context_yaml(
            organization=payload.organization,
            system_name=payload.system_name or "Your System",
            data_classification=payload.data_classification,
            hosting=payload.hosting or "(cloud provider + region)",
            regulatory_requirements=payload.regulatory_requirements,
        ),
    }
    return files, recommended


@router.post(
    "/init/wizard",
    response_model=InitWizardResponse,
    responses=error_responses(
        {
            400: (
                "Unknown ``preset`` (``error: unknown_preset``); "
                "``detail`` carries ``preset`` + ``valid``."
            ),
        }
    ),
)
async def init_wizard(payload: InitWizardRequest) -> InitWizardResponse:
    """Generate starter YAMLs from lightweight onboarding context.

    Returns three pre-filled files + a recommended framework list. The client
    previews them in the wizard UI; writing to disk is the separate
    ``/init/commit`` call.
    """
    files, recommended = _generate(payload)
    return InitWizardResponse(
        evidentia_yaml=files["evidentia.yaml"],
        my_controls_yaml=files["my-controls.yaml"],
        system_context_yaml=files["system-context.yaml"],
        recommended_frameworks=recommended,
    )


@router.post(
    "/init/commit",
    response_model=InitWizardCommitResponse,
    responses=error_responses(
        {
            400: (
                "Unknown ``preset`` (``error: unknown_preset``); "
                "``detail`` carries ``preset`` + ``valid``."
            ),
        }
    ),
)
async def init_commit(
    payload: InitWizardCommitRequest,
) -> InitWizardCommitResponse:
    """Write the generated starter files to the SERVER's working directory.

    Mirrors ``evidentia init``: the three YAMLs are regenerated server-side from
    the onboarding answers (the request NEVER carries file content), then
    written to the directory the server was launched from. The filenames are a
    closed set — there is no client-controlled path, so the write cannot be
    steered elsewhere (no traversal). Existing files are SKIPPED unless
    ``overwrite`` is true (mirrors the CLI's ``--force``), so the wizard cannot
    silently clobber an existing project. This is a local-store mutation under
    the same host-owner trust model as ``evidentia init`` — the security-posture
    banner surfaces when the API is unauthenticated.
    """
    files, _ = _generate(payload)

    directory = Path.cwd()
    created: list[str] = []
    skipped: list[str] = []
    for filename in _STARTER_FILES:
        target = directory / filename
        if target.exists() and not payload.overwrite:
            skipped.append(filename)
            continue
        target.write_text(files[filename], encoding="utf-8")
        created.append(filename)
    (directory / ".evidentia").mkdir(exist_ok=True)

    return InitWizardCommitResponse(
        created=created, skipped=skipped, directory=str(directory)
    )
