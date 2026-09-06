"""`evidentia traceability` — emit a signed Control↔Threat Traceability Matrix.

Promotes the threat→control→evidence view into a first-class capability: it
emits the matrix as a Sigstore-signable OSCAL **profile** (the 2026-06-17
representation decision — NOT Assessment Results, which is a semantic abuse, and
NOT the OSCAL ``mapping`` model, which is control↔control only). The profile
imports a control catalog and annotates each control with a ``link
rel="mitigates"`` to the threats it covers; threats live in integrity-hashed
``back-matter.resources[]``. Sign with ``--sign-with-gpg`` /
``--sign-with-sigstore`` (the existing OSCAL signing path) and verify with
``evidentia oscal verify``.

v0.10.11 ships this signed-OSCAL slice. OWASP Threat-Dragon ingest, the MITRE
CTID Mappings-Explorer crosswalk, and a CycloneDX representation are the v0.11
build.

Input (``--input``, JSON or YAML) is a ``TraceabilityMatrix``::

    title: "Control-to-Threat Traceability: Acme"
    catalog_href: "nist-800-53-rev5-moderate.json"
    framework_id: "nist-800-53-rev5-moderate"
    crosswalk_source: "self-attested"   # or "mitre-ctid-mappings-explorer"
    mappings:
      - control_id: "AC-2"
        threat_id: "T1078"
        threat_framework: "mitre-attack"
        threat_name: "Valid Accounts"
        relationship: "mitigates"
        coverage: "partial"
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer
import yaml
from evidentia_core.models.traceability import TraceabilityMatrix
from evidentia_core.oscal.signing import sign_file as gpg_sign_file
from evidentia_core.oscal.sigstore import sign_file as sigstore_sign_file
from evidentia_core.oscal.traceability_exporter import (
    traceability_matrix_to_oscal_profile,
)
from rich.console import Console

app = typer.Typer(
    no_args_is_help=True,
    help="Control↔Threat traceability matrix (signed OSCAL profile).",
)
console = Console()


@app.command("emit")
def emit(
    input_path: Path = typer.Option(
        ...,
        "--input",
        "-i",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "Traceability matrix input (JSON or YAML): title, catalog_href, framework_id, crosswalk_source, mappings[]."
        ),
    ),
    output: Path = typer.Option(
        ...,
        "--output",
        "-o",
        help="Where to write the emitted OSCAL profile JSON.",
    ),
    sign_with_gpg: str | None = typer.Option(
        None,
        "--sign-with-gpg",
        help=(
            "GPG key id/fingerprint to detached-sign the emitted profile "
            "(writes <output>.asc). The air-gap signing path."
        ),
    ),
    sign_with_sigstore: bool = typer.Option(
        False,
        "--sign-with-sigstore",
        help=(
            "Sigstore keyless-sign the emitted profile (writes "
            "<output>.sigstore.json). Requires network + an OIDC credential."
        ),
    ),
    sigstore_identity_token: str | None = typer.Option(
        None,
        "--sigstore-identity-token",
        help="Explicit OIDC token for Sigstore signing (else auto-detected).",
    ),
    sign_with_key: Path | None = typer.Option(
        None,
        "--sign-with-key",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "PEM/PKCS#8 private key (Ed25519 or RSA) to DSSE-sign the emitted "
            "profile to <output>.dsse.json — air-gap-clean (no gpg binary). "
            "Encrypted keys: $EVIDENTIA_SIGNING_KEY_PASSPHRASE."
        ),
    ),
) -> None:
    """Emit the Control↔Threat Traceability Matrix as a signable OSCAL profile."""
    try:
        raw: Any = yaml.safe_load(input_path.read_text(encoding="utf-8"))
        matrix = TraceabilityMatrix.model_validate(raw)
    except yaml.YAMLError as e:
        console.print(f"[red]Invalid traceability matrix input (YAML parse):[/red] {e}")
        raise typer.Exit(code=2) from e
    except Exception as e:
        console.print(f"[red]Invalid traceability matrix input:[/red] {e}")
        raise typer.Exit(code=2) from e

    if not matrix.mappings:
        console.print("[red]The matrix has no mappings — nothing to emit.[/red]")
        raise typer.Exit(code=2)

    profile = traceability_matrix_to_oscal_profile(matrix)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    console.print(
        f"[green]Wrote OSCAL profile:[/green] {output}  "
        f"({len(matrix.mappings)} mappings across "
        f"{len(matrix.control_ids)} controls)"
    )

    signed = False
    if sign_with_gpg:
        try:
            sig = gpg_sign_file(output, key_id=sign_with_gpg)
        except Exception as e:
            console.print(f"[red]GPG signing failed:[/red] {e}")
            raise typer.Exit(code=1) from e
        console.print(f"[green]GPG signature:[/green] {sig}")
        signed = True

    if sign_with_sigstore:
        try:
            bundle = sigstore_sign_file(output, identity_token=sigstore_identity_token)
        except Exception as e:
            console.print(f"[red]Sigstore signing failed:[/red] {e}")
            raise typer.Exit(code=1) from e
        console.print(f"[green]Sigstore bundle:[/green] {bundle}")
        signed = True

    if sign_with_key:
        from evidentia_core.oscal.keysign import sign_oscal_file

        try:
            dsse_out = sign_oscal_file(output, key_path=sign_with_key)
        except Exception as e:
            console.print(f"[red]DSSE signing failed:[/red] {e}")
            raise typer.Exit(code=1) from e
        console.print(f"[green]DSSE envelope:[/green] {dsse_out}")
        signed = True

    if signed:
        if sign_with_key and not sign_with_gpg and not sign_with_sigstore:
            console.print(
                f"[dim]Verify with:[/dim] evidentia oscal verify {output} --verify-key <pubkey.pem> --require-signature"
            )
        else:
            console.print(f"[dim]Verify with:[/dim] evidentia oscal verify {output} --require-signature")
