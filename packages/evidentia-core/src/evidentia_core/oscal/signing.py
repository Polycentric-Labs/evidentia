"""GPG detached-signature support for OSCAL Assessment Results (v0.7.0).

Thin wrapper around the ``gpg`` binary (GnuPG 2.x) via ``subprocess`` —
no new Python dependency. Produces ASCII-armored detached signatures
(``.asc``) so the signed artifact can travel through email, Slack, or
any text-only channel without binary mangling.

Why subprocess instead of a library
------------------------------------

- **Portable.** GnuPG is a universal install; the Python wrappers
  (``python-gnupg``, ``python-pgp``) would add a dep that's strictly
  weaker than invoking the battle-tested binary.
- **Air-gap friendly.** No network calls, no surprise telemetry. The
  same ``gpg`` binary is what auditors already trust.
- **Fidelity.** GnuPG's CLI is the authoritative reference for the
  OpenPGP protocol. We get every KDF and cipher negotiation the binary
  supports, for free.

If the caller's environment doesn't have GnuPG installed,
:func:`sign_file` raises :class:`GPGNotAvailableError`. Callers should
catch this and either fail the export (if signing was explicitly
requested) or emit an unsigned bundle (if signing is optional).
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from evidentia_core.audit.events import EventAction, EventOutcome
from evidentia_core.audit.logger import get_logger

# v0.7.0 Step-5 review: switched from stdlib logging to the ECS-8.11
# structured logger used throughout v0.7.0 for SIEM-friendly audit
# trail consistency (matches oscal/sigstore.py's logger setup so the
# two signing paths emit comparable `evidentia.sign.*` events).
_log = get_logger("evidentia.oscal.signing")
# Retained for non-event debug lines that don't fit the EventAction
# vocabulary (e.g., subprocess command construction).
logger = logging.getLogger(__name__)


class GPGError(Exception):
    """Base class for GPG subprocess failures."""


class GPGNotAvailableError(GPGError):
    """Raised when the ``gpg`` binary is not on PATH."""


class GPGSigningError(GPGError):
    """Raised when the ``gpg --detach-sign`` invocation fails."""


class GPGVerifyError(GPGError):
    """Raised when a verification invocation fails unexpectedly.

    A *signature mismatch* is NOT an exception — it's a False in
    :attr:`VerifyResult.valid`. This exception is reserved for infrastructure
    errors: missing signature file, malformed artifact, GnuPG crash.
    """


@dataclass(frozen=True)
class VerifyResult:
    """Outcome of a signature verification.

    ``valid`` is the yes/no answer auditors actually care about.
    ``signer_key_id`` / ``signer_fingerprint`` are populated on success
    so the audit record can note *who* signed — even a valid signature
    is meaningless without identifying the signer.
    """

    valid: bool
    signer_key_id: str | None = None
    signer_fingerprint: str | None = None
    stderr: str = ""


def gpg_available() -> bool:
    """Return True iff the ``gpg`` binary is discoverable on PATH."""
    return shutil.which("gpg") is not None


def sign_file(
    artifact_path: str | Path,
    *,
    key_id: str,
    signature_path: str | Path | None = None,
    gnupghome: str | Path | None = None,
) -> Path:
    """Produce an ASCII-armored detached GPG signature of ``artifact_path``.

    Parameters
    ----------
    artifact_path:
        The file to sign (typically an OSCAL AR JSON document).
    key_id:
        GPG key identifier — key ID, fingerprint, or UID substring. Passed
        verbatim to ``gpg --local-user``; GnuPG resolves it against the
        active keyring. Omitting this is intentional-error: unambiguous
        signer identity is the whole point of the feature.
    signature_path:
        Where to write the ``.asc`` sig. Defaults to
        ``<artifact_path>.asc`` — the OpenPGP convention for ASCII-armored
        detached sigs.
    gnupghome:
        Optional ``GNUPGHOME`` override — point GnuPG at a custom keyring
        directory. Useful in tests (ephemeral tmpdir keyring) and in
        pipelines where the operator's ``~/.gnupg`` isn't appropriate.

    Returns
    -------
    The ``Path`` of the written signature file.

    Raises
    ------
    GPGNotAvailableError
        If ``gpg`` is not on PATH.
    GPGSigningError
        If ``gpg --detach-sign`` returns a non-zero exit code.
    """
    if not gpg_available():
        raise GPGNotAvailableError(
            "`gpg` binary not found on PATH. Install GnuPG (https://gnupg.org/) to sign OSCAL AR exports."
        )

    artifact = Path(artifact_path).resolve()
    if not artifact.is_file():
        raise GPGSigningError(f"Artifact not found: {artifact}")

    sig_path = Path(signature_path) if signature_path else artifact.with_suffix(artifact.suffix + ".asc")

    # ``--batch --yes`` prevents interactive prompts so this function is
    # safe to call from CI. ``--detach-sign --armor`` produces the ASCII
    # detached form. ``--local-user`` selects the signing key even when
    # the keyring has multiple.
    cmd = [
        "gpg",
        "--batch",
        "--yes",
        "--armor",
        "--detach-sign",
        "--local-user",
        key_id,
        "--output",
        str(sig_path),
        str(artifact),
    ]
    env = _gnupghome_env(gnupghome)
    logger.debug("gpg sign cmd: %s (GNUPGHOME=%s)", " ".join(cmd), env.get("GNUPGHOME"))

    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, env=env or None)
    except FileNotFoundError as e:  # pragma: no cover — gpg_available() checked
        raise GPGNotAvailableError(str(e)) from e

    if result.returncode != 0:
        _log.warning(
            action=EventAction.SIGN_FAILED,
            outcome=EventOutcome.FAILURE,
            message=f"GPG signing failed for {artifact.name}",
            error={"type": "GPGSigningError", "exit_code": result.returncode},
            evidentia={
                "artifact_path": str(artifact),
                "key_id": key_id,
                "stderr": result.stderr.strip()[:500],  # truncate for log size
            },
        )
        raise GPGSigningError(f"gpg --detach-sign failed (exit {result.returncode}): {result.stderr.strip()}")

    _log.info(
        action=EventAction.SIGN_GPG_SIGNED,
        outcome=EventOutcome.SUCCESS,
        message=f"GPG detached signature written for {artifact.name}",
        evidentia={
            "artifact_path": str(artifact),
            "signature_path": str(sig_path),
            "key_id": key_id,
        },
    )
    return sig_path


def verify_file(
    artifact_path: str | Path,
    *,
    signature_path: str | Path | None = None,
    gnupghome: str | Path | None = None,
) -> VerifyResult:
    """Verify a detached GPG signature against its artifact.

    Returns a :class:`VerifyResult` with ``valid=True/False``. Signature
    mismatches return False rather than raising — the caller decides
    what to do about a broken chain of custody.

    Parameters
    ----------
    artifact_path:
        The file whose signature is being checked.
    signature_path:
        Path to the ``.asc`` signature. Defaults to ``<artifact_path>.asc``.
    gnupghome:
        Optional ``GNUPGHOME`` override — lets callers verify against a
        specific keyring without touching the operator's default one.

    Raises
    ------
    GPGNotAvailableError
        If ``gpg`` is not on PATH.
    GPGVerifyError
        If the artifact or signature file is missing.
    """
    if not gpg_available():
        raise GPGNotAvailableError(
            "`gpg` binary not found on PATH. Install GnuPG (https://gnupg.org/) to verify signed OSCAL AR exports."
        )

    artifact = Path(artifact_path).resolve()
    if not artifact.is_file():
        raise GPGVerifyError(f"Artifact not found: {artifact}")

    sig_path = Path(signature_path) if signature_path else artifact.with_suffix(artifact.suffix + ".asc")
    if not sig_path.is_file():
        raise GPGVerifyError(f"Signature not found: {sig_path}")

    # ``--status-fd 1`` emits machine-readable status lines (``[GNUPG:] ...``)
    # to stdout. We parse these to extract signer identity on a GOODSIG.
    cmd = [
        "gpg",
        "--batch",
        "--status-fd",
        "1",
        "--verify",
        str(sig_path),
        str(artifact),
    ]
    env = _gnupghome_env(gnupghome)
    logger.debug("gpg verify cmd: %s", " ".join(cmd))

    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, env=env or None)
    except FileNotFoundError as e:  # pragma: no cover — gpg_available() checked
        raise GPGNotAvailableError(str(e)) from e

    key_id, fingerprint = _parse_status_lines(result.stdout)
    valid = result.returncode == 0 and "GOODSIG" in result.stdout

    if valid:
        _log.info(
            action=EventAction.VERIFY_SIGNATURE_PASSED,
            outcome=EventOutcome.SUCCESS,
            message=f"GPG signature valid for {artifact.name}",
            evidentia={
                "artifact_path": str(artifact),
                "signature_path": str(sig_path),
                "signer_key_id": key_id,
                "signer_fingerprint": fingerprint,
            },
        )
    else:
        _log.warning(
            action=EventAction.VERIFY_SIGNATURE_FAILED,
            outcome=EventOutcome.FAILURE,
            message=f"GPG signature invalid for {artifact.name}",
            evidentia={
                "artifact_path": str(artifact),
                "signature_path": str(sig_path),
                "stderr": result.stderr.strip()[:500],
            },
        )

    return VerifyResult(
        valid=valid,
        signer_key_id=key_id,
        signer_fingerprint=fingerprint,
        stderr=result.stderr.strip(),
    )


def _parse_status_lines(stdout: str) -> tuple[str | None, str | None]:
    """Extract signer key-id and fingerprint from ``gpg --status-fd 1`` output.

    Relevant status codes (see ``doc/DETAILS`` in the GnuPG source):

    - ``GOODSIG <keyid> <uid>`` — issued on successful verification
    - ``VALIDSIG <fingerprint> <creation> <timestamp> ... <primary-fp>``
      — more detail, including the full fingerprint
    """
    key_id: str | None = None
    fingerprint: str | None = None
    for line in stdout.splitlines():
        if not line.startswith("[GNUPG:] "):
            continue
        tokens = line[len("[GNUPG:] ") :].split()
        if not tokens:
            continue
        if tokens[0] == "GOODSIG" and len(tokens) >= 2:
            key_id = tokens[1]
        elif tokens[0] == "VALIDSIG" and len(tokens) >= 2:
            fingerprint = tokens[1]
    return key_id, fingerprint


def _gnupghome_env(gnupghome: str | Path | None) -> dict[str, str]:
    """Build an env-dict that sets GNUPGHOME when the caller requested it.

    Returns an empty dict when ``gnupghome`` is None — callers should
    pass ``env=None`` to :func:`subprocess.run` in that case so GnuPG
    inherits the default environment (including ``~/.gnupg``).
    """
    if gnupghome is None:
        return {}
    import os

    merged = dict(os.environ)
    merged["GNUPGHOME"] = str(Path(gnupghome).resolve())
    return merged
