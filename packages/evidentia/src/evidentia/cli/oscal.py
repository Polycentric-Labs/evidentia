"""`evidentia oscal` — OSCAL integrity tooling (v0.7.0).

Today this namespace exposes one verb:

- ``evidentia oscal verify <path>`` — check SHA-256 digests of every
  embedded evidence resource in an OSCAL AR document, and verify any
  detached GPG signature (``.asc``) and/or Sigstore bundle
  (``.sigstore.json``) found alongside it.

The evidence-embedding + signing side of the story lives under
``evidentia gap analyze --findings ... --sign-with-gpg <key-id>``
and/or ``--sign-with-sigstore``. Verification is separated so
auditors who didn't produce the AR can still run the check with just
the JSON + signature artifacts.
"""

from __future__ import annotations

from pathlib import Path

import typer
from evidentia_core.oscal.verify import DigestCheck, VerifyReport, verify_ar_file
from rich.console import Console
from rich.table import Table

app = typer.Typer(
    no_args_is_help=True,
    help="OSCAL integrity + signature tooling.",
)
console = Console()


@app.command("verify")
def verify(
    path: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the OSCAL Assessment Results JSON file to verify.",
    ),
    require_signature: bool = typer.Option(
        False,
        "--require-signature",
        help=(
            "Fail verification if no detached GPG signature is found next "
            "to the AR file. Default behaviour is opportunistic — verify "
            "the sig if present, pass on digests alone if absent."
        ),
    ),
    signature: Path | None = typer.Option(
        None,
        "--signature",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=("Custom signature file path. Defaults to <path>.asc next to the AR file."),
    ),
    gnupghome: Path | None = typer.Option(
        None,
        "--gnupghome",
        exists=True,
        file_okay=False,
        dir_okay=True,
        help=(
            "Override GNUPGHOME for signature verification. Useful when "
            "verifying against a specific keyring rather than the "
            "operator's default ~/.gnupg."
        ),
    ),
    check_sigstore: bool = typer.Option(
        True,
        "--check-sigstore/--no-check-sigstore",
        help=(
            "Verify a Sigstore bundle (<path>.sigstore.json) if present. "
            "Default True. Use --no-check-sigstore to skip Sigstore checks "
            "entirely (e.g., for air-gap-only verification)."
        ),
    ),
    sigstore_bundle: Path | None = typer.Option(
        None,
        "--sigstore-bundle",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=("Custom Sigstore bundle path. Defaults to <path>.sigstore.json next to the AR file."),
    ),
    verify_key: Path | None = typer.Option(
        None,
        "--verify-key",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help=(
            "PEM public key (Ed25519 or RSA) pinning the expected DSSE signer. "
            "Required to verify a <path>.dsse.json envelope; without it a "
            "present envelope fails closed."
        ),
    ),
    dsse_bundle: Path | None = typer.Option(
        None,
        "--dsse-bundle",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Custom DSSE envelope path. Defaults to <path>.dsse.json.",
    ),
    expected_identity: str | None = typer.Option(
        None,
        "--expected-identity",
        help=(
            "Expected Sigstore signer identity (email or OIDC subject). "
            "When omitted along with --expected-issuer, the verifier "
            "accepts ANY signer (UnsafeNoOp policy) and emits a warning. "
            "Both-or-neither with --expected-issuer (cosign model); "
            "supplying exactly one fails verification. Production audit "
            "pipelines should always set both."
        ),
    ),
    expected_issuer: str | None = typer.Option(
        None,
        "--expected-issuer",
        help=(
            "Expected Sigstore identity issuer URL "
            "(e.g., 'https://token.actions.githubusercontent.com' for "
            "GitHub Actions OIDC). Both-or-neither with "
            "--expected-identity (cosign model)."
        ),
    ),
    json_output: bool = typer.Option(
        False,
        "--json",
        help=(
            "Emit the verification report as machine-readable JSON to stdout. "
            "Exit code reflects overall pass/fail regardless of output mode."
        ),
    ),
) -> None:
    """Verify digests + optional GPG and/or Sigstore signatures of an OSCAL AR document.

    Exits 0 on successful verification, 1 otherwise. Useful in CI
    pipelines that pull a signed AR from storage and need to fail the
    job if the chain of custody is broken.

    Both GPG (``.asc``) and Sigstore (``.sigstore.json``) signatures are
    checked when present. With ``--require-signature``, EITHER one
    satisfies the requirement.
    """
    report = verify_ar_file(
        path,
        require_signature=require_signature,
        signature_path=signature,
        gnupghome=gnupghome,
        check_sigstore=check_sigstore,
        sigstore_bundle_path=sigstore_bundle,
        expected_sigstore_identity=expected_identity,
        expected_sigstore_issuer=expected_issuer,
        verify_key_path=verify_key,
        dsse_bundle_path=dsse_bundle,
    )

    if json_output:
        _emit_json(report)
    else:
        _render_rich(report)

    raise typer.Exit(code=0 if report.overall_valid else 1)


def _render_rich(report: VerifyReport) -> None:
    """Human-readable summary of the verification outcome."""
    if not report.overall_valid:
        status_line = "[red]FAIL[/red]"
    elif not report.has_verification_surface:
        # v0.7.5 R2 — distinguishes "no embedded evidence + no signature
        # + --require-signature unset" from a meaningful PASS. Pre-v0.7.5
        # this case returned an unqualified FAIL.
        status_line = "[yellow]PASS[/yellow] (no verification surface)"
    else:
        status_line = "[green]PASS[/green]"
    console.print(f"[bold]{report.ar_path}[/bold] — {status_line}")

    if report.errors:
        console.print("[red]Errors:[/red]")
        for err in report.errors:
            console.print(f"  - {err}")

    if report.warnings:
        console.print("[yellow]Warnings:[/yellow]")
        for warn in report.warnings:
            console.print(f"  - {warn}")

    if report.digest_checks:
        _render_digest_table(report.digest_checks)
    else:
        console.print("[dim]No embedded evidence resources (digests skipped).[/dim]")

    # GPG signature
    if report.signature_valid is not None:
        sig_status = "[green]valid[/green]" if report.signature_valid else "[red]INVALID[/red]"
        console.print(f"GPG signature: {sig_status}")
        if report.signature_signer:
            console.print(f"  Signer key id: [cyan]{report.signature_signer}[/cyan]")
        if report.signature_fingerprint:
            console.print(f"  Fingerprint:   [cyan]{report.signature_fingerprint}[/cyan]")
    else:
        console.print("[dim]No GPG signature checked.[/dim]")

    # Sigstore signature
    if report.sigstore_signature_valid is not None:
        ss_status = "[green]valid[/green]" if report.sigstore_signature_valid else "[red]INVALID[/red]"
        console.print(f"Sigstore signature: {ss_status}")
        if report.sigstore_signer_identity:
            console.print(f"  Signer identity: [cyan]{report.sigstore_signer_identity}[/cyan]")
        if report.sigstore_signer_issuer:
            console.print(f"  Issuer:          [cyan]{report.sigstore_signer_issuer}[/cyan]")
        if report.sigstore_rekor_log_index is not None:
            console.print(f"  Rekor log index: [cyan]{report.sigstore_rekor_log_index}[/cyan]")
    else:
        console.print("[dim]No Sigstore signature checked.[/dim]")

    # DSSE signature
    if report.dsse_signature_valid is not None:
        ds_status = "[green]valid[/green]" if report.dsse_signature_valid else "[red]INVALID[/red]"
        console.print(f"DSSE signature: {ds_status}")
        if report.dsse_signer_key_id:
            console.print(f"  Signer key id: [cyan]{report.dsse_signer_key_id}[/cyan]")
        if report.dsse_algorithm:
            console.print(f"  Algorithm:     [cyan]{report.dsse_algorithm}[/cyan]")
    else:
        console.print("[dim]No DSSE signature checked.[/dim]")


def _render_digest_table(checks: list[DigestCheck]) -> None:
    """Tabulate per-resource digest outcomes."""
    total = len(checks)
    passed = sum(1 for c in checks if c.valid)
    table = Table(
        title=f"Evidence digests — {passed}/{total} valid",
        show_lines=False,
    )
    table.add_column("Status", style="bold")
    table.add_column("Resource UUID", style="dim")
    table.add_column("Title")
    for c in checks:
        marker = "[green]OK[/green]" if c.valid else "[red]FAIL[/red]"
        table.add_row(marker, c.resource_uuid[:8], c.title or "(untitled)")
    console.print(table)


def _emit_json(report: VerifyReport) -> None:
    """Serialize the VerifyReport as JSON for scripting / CI consumption."""

    payload = {
        "ar_path": str(report.ar_path),
        "overall_valid": report.overall_valid,
        "has_verification_surface": report.has_verification_surface,
        "digests_valid": report.digests_valid,
        "signature_valid": report.signature_valid,
        "signature_signer": report.signature_signer,
        "signature_fingerprint": report.signature_fingerprint,
        "sigstore_signature_valid": report.sigstore_signature_valid,
        "sigstore_signer_identity": report.sigstore_signer_identity,
        "sigstore_signer_issuer": report.sigstore_signer_issuer,
        "sigstore_rekor_log_index": report.sigstore_rekor_log_index,
        "dsse_signature_valid": report.dsse_signature_valid,
        "dsse_signer_key_id": report.dsse_signer_key_id,
        "dsse_algorithm": report.dsse_algorithm,
        "errors": report.errors,
        "warnings": report.warnings,
        "digest_checks": [
            {
                "resource_uuid": c.resource_uuid,
                "title": c.title,
                "expected_digest": c.expected_digest,
                "actual_digest": c.actual_digest,
                "valid": c.valid,
            }
            for c in report.digest_checks
        ],
    }
    console.print_json(data=payload)
