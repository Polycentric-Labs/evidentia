"""Persistent Effective Challenge log store (v0.7.10 P1.5 G2).

JSON-file-per-record persistence mirroring the v0.7.10 P0.6.1
:mod:`evidentia_core.model_risk_store` pattern adapted for the
:class:`evidentia_core.governance.effective_challenge.EffectiveChallenge`
schema.

Storage location precedence:
    1. Explicit ``override`` argument
    2. ``EVIDENTIA_CHALLENGE_STORE_DIR`` environment variable
    3. Platform default via ``platformdirs.user_data_dir``
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from uuid import UUID

from platformdirs import user_data_dir

from evidentia_core.governance.effective_challenge import EffectiveChallenge
from evidentia_core.models.common import utc_now
from evidentia_core.security.paths import (
    PathTraversalError,
    validate_within,
)

logger = logging.getLogger(__name__)

CHALLENGE_STORE_ENV_VAR = "EVIDENTIA_CHALLENGE_STORE_DIR"


class InvalidChallengeIdError(ValueError):
    """Raised when a candidate challenge ID isn't a valid UUID string."""


def _validate_id_shape(challenge_id: str) -> None:
    if not isinstance(challenge_id, str) or not challenge_id:
        raise InvalidChallengeIdError(
            f"Invalid challenge ID: empty or non-string: {challenge_id!r}"
        )
    try:
        UUID(challenge_id)
    except (ValueError, AttributeError, TypeError) as e:
        raise InvalidChallengeIdError(
            f"Invalid challenge ID: not a UUID-shaped string: "
            f"{challenge_id!r} ({type(e).__name__}: {e})"
        ) from e


def get_challenge_store_dir(override: Path | None = None) -> Path:
    """Resolve the effective-challenge store directory."""
    if override is not None:
        return Path(override).expanduser().resolve()
    env = os.environ.get(CHALLENGE_STORE_ENV_VAR)
    if env:
        # v0.7.12 P3 cosmetic harmonization: match vendor_store +
        # model_risk_store pattern. expanduser() resolves ``~/`` in
        # operator-supplied paths; resolve() collapses ``..`` segments
        # before any downstream validate_within() call sees them.
        return Path(env).expanduser().resolve()
    return Path(user_data_dir("evidentia", appauthor=False)) / "challenge_store"


def save_challenge(
    challenge: EffectiveChallenge, *, override: Path | None = None
) -> Path:
    """Persist a challenge record. Atomic via os.replace.

    ID shape is validated up-front via :func:`_validate_id_shape`,
    then the constructed path is independently validated to be
    within the store directory via
    :func:`evidentia_core.security.paths.validate_within` —
    belt-and-suspenders barrier matching the v0.7.9 vendor_store +
    v0.7.10 P0.6.1 model_risk_store patterns. v0.7.10 P3 closure
    of v0.7.10 security-review F-V10-S1.
    """
    _validate_id_shape(challenge.id)
    store_dir = get_challenge_store_dir(override)
    store_dir.mkdir(parents=True, exist_ok=True)

    refreshed = challenge.model_copy(update={"updated_at": utc_now()})
    payload = refreshed.model_dump_json(indent=2)

    candidate = store_dir / f"{challenge.id}.json"
    try:
        out_path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidChallengeIdError(
            f"Invalid challenge ID: path-traversal violation: {challenge.id!r}"
        ) from e
    tmp_path = store_dir / f"{challenge.id}.json.tmp"
    tmp_path.write_text(payload, encoding="utf-8")
    os.replace(tmp_path, out_path)
    logger.debug("saved challenge %s to %s", challenge.id, out_path)
    return out_path


def load_challenge_by_id(
    challenge_id: str, *, override: Path | None = None
) -> EffectiveChallenge | None:
    """Load a challenge by ID. Returns None for well-formed-unknown IDs."""
    _validate_id_shape(challenge_id)
    store_dir = get_challenge_store_dir(override)
    candidate = store_dir / f"{challenge_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidChallengeIdError(
            f"Invalid challenge ID: path-traversal violation: {challenge_id!r}"
        ) from e
    if not path.exists():
        return None
    return EffectiveChallenge.model_validate_json(path.read_text(encoding="utf-8"))


def list_challenges(
    *, override: Path | None = None
) -> list[EffectiveChallenge]:
    """List all challenges sorted by challenge_date DESC then id."""
    store_dir = get_challenge_store_dir(override)
    if not store_dir.exists():
        return []
    challenges: list[EffectiveChallenge] = []
    for path in store_dir.glob("*.json"):
        if path.name.endswith(".tmp"):
            continue
        try:
            challenges.append(
                EffectiveChallenge.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
            )
        except Exception as e:
            logger.warning("Skipping malformed challenge file %s: %s", path, e)
            continue
    # Sort by challenge_date DESC (newest first), then id for stability
    challenges.sort(key=lambda c: (-c.challenge_date.toordinal(), c.id))
    return challenges


def delete_challenge(
    challenge_id: str, *, override: Path | None = None
) -> bool:
    """Delete a challenge by ID. Returns True if removed."""
    _validate_id_shape(challenge_id)
    store_dir = get_challenge_store_dir(override)
    candidate = store_dir / f"{challenge_id}.json"
    try:
        path = validate_within(candidate, store_dir)
    except PathTraversalError as e:
        raise InvalidChallengeIdError(
            f"Invalid challenge ID: path-traversal violation: {challenge_id!r}"
        ) from e
    if not path.exists():
        return False
    path.unlink()
    return True
