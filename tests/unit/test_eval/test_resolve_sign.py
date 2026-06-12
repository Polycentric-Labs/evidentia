"""Unit tests for ``_resolve_sign`` OIDC graceful degrade (v0.10.9 A).

The product fix behind the v0.10.8 test fix (F-V108-CI1):
``evidentia eval … --output`` auto-signed whenever
``GITHUB_ACTIONS == "true"`` and sigstore was importable, but never
checked OIDC-token *obtainability* — so the CLI crashed with
``SigstoreSigningError`` in any CI job lacking ``id-token: write``
(exactly the release gate job's permission set). GitHub sets BOTH
``ACTIONS_ID_TOKEN_REQUEST_TOKEN`` and ``ACTIONS_ID_TOKEN_REQUEST_URL``
iff the job has that permission, so the auto-detect branch now
additionally requires both.

Covers the tri-state (``--sign`` / ``--no-sign`` / auto-detect) ×
token-presence matrix:

1. :class:`TestAutoDetect` — sign_flag=None. Signs only when CI +
   sigstore + BOTH token env vars; degrades to unsigned output with
   a stderr warning when CI is detected but the token env vars are
   absent (the release-gate shape).
2. :class:`TestExplicitSign` — sign_flag=True keeps attempt-and-raise
   semantics regardless of token presence (honest failure beats
   silent degrade when the operator demanded signing).
3. :class:`TestExplicitNoSign` — sign_flag=False suppresses signing
   even in full-credential CI.
4. :class:`TestStubSmokeGracefulDegrade` — CLI-level regression for
   the exact F-V108-CI1 shape: ``stub-smoke --output`` in tokenless
   CI exits 0 and writes unsigned JSON instead of crashing.

None of these require the sigstore package — ``sigstore_available``
is monkeypatched at its source module (``_resolve_sign`` imports it
lazily, so the patch lands).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from evidentia.cli.eval import _resolve_sign
from evidentia.cli.eval import app as eval_cli_app
from typer.testing import CliRunner

# Stable fragment of the degrade warning — asserted on instead of the
# full sentence so wording polish doesn't churn the tests.
_WARNING_FRAGMENT = "CI detected but no OIDC token"


@pytest.fixture(autouse=True)
def _clear_signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start every case from a signing-neutral environment.

    Mirrors the v0.10.8 ``_isolate_from_ci_autosign`` hermeticity
    fixture in ``test_harness.py`` but also clears the OIDC token
    request vars — each case below sets exactly the env shape it
    exercises, wherever the suite runs (dev box or CI).
    """
    for var in (
        "GITHUB_ACTIONS",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
    ):
        monkeypatch.delenv(var, raising=False)


def _set_ci_env(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: bool = False,
    url: bool = False,
) -> None:
    """Simulate a GitHub Actions job with optional OIDC token vars."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    if token:
        monkeypatch.setenv(
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "test-oidc-token"
        )
    if url:
        monkeypatch.setenv(
            "ACTIONS_ID_TOKEN_REQUEST_URL",
            "https://oidc.invalid/token",
        )


def _stub_sigstore(
    monkeypatch: pytest.MonkeyPatch, available: bool
) -> None:
    """Patch sigstore importability without requiring the package."""
    monkeypatch.setattr(
        "evidentia_core.oscal.sigstore.sigstore_available",
        lambda: available,
    )


# ── 1. Auto-detect (sign_flag=None) × token presence ─────────────


class TestAutoDetect:
    def test_no_output_returns_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """No output target → nothing to sign, even in full CI."""
        _set_ci_env(monkeypatch, token=True, url=True)
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(None, None) is False
        assert _WARNING_FRAGMENT not in capsys.readouterr().err

    def test_outside_ci_returns_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Local run (GITHUB_ACTIONS unset) → unsigned, no warning."""
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(None, Path("out.json")) is False
        assert _WARNING_FRAGMENT not in capsys.readouterr().err

    def test_ci_with_both_tokens_signs(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Full release context (CI + sigstore + both vars) → sign."""
        _set_ci_env(monkeypatch, token=True, url=True)
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(None, Path("out.json")) is True
        assert _WARNING_FRAGMENT not in capsys.readouterr().err

    def test_ci_without_tokens_degrades_with_warning(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """The F-V108-CI1 shape: CI + sigstore but no ``id-token:
        write`` → unsigned output + stderr warning, not a crash."""
        _set_ci_env(monkeypatch)
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(None, Path("out.json")) is False
        err = capsys.readouterr().err
        assert _WARNING_FRAGMENT in err
        # v0.10.9 polish: the remedy is ordered grant-the-permission-
        # first (the durable fix), then --sign (the override).
        assert "grant `id-token: write`" in err

    def test_ci_with_only_request_token_degrades(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Half-set env (URL var missing) is not obtainable."""
        _set_ci_env(monkeypatch, token=True)
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(None, Path("out.json")) is False
        assert _WARNING_FRAGMENT in capsys.readouterr().err

    def test_ci_with_only_request_url_degrades(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Half-set env (token var missing) is not obtainable."""
        _set_ci_env(monkeypatch, url=True)
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(None, Path("out.json")) is False
        assert _WARNING_FRAGMENT in capsys.readouterr().err

    def test_ci_without_sigstore_degrades_silently(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """No ``[sigstore]`` extra → the pre-existing silent degrade;
        the OIDC warning presupposes sigstore is importable."""
        _set_ci_env(monkeypatch)
        _stub_sigstore(monkeypatch, available=False)
        assert _resolve_sign(None, Path("out.json")) is False
        assert _WARNING_FRAGMENT not in capsys.readouterr().err

    def test_ci_with_tokens_but_no_sigstore_returns_false(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Tokens alone don't help when sigstore isn't importable."""
        _set_ci_env(monkeypatch, token=True, url=True)
        _stub_sigstore(monkeypatch, available=False)
        assert _resolve_sign(None, Path("out.json")) is False
        assert _WARNING_FRAGMENT not in capsys.readouterr().err


# ── 2. Explicit --sign (sign_flag=True) ──────────────────────────


class TestExplicitSign:
    def test_explicit_sign_wins_without_tokens(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Explicit ``--sign`` keeps attempt-and-raise semantics —
        resolve True (and no degrade warning) even with no OIDC
        token vars; the downstream signer raises honestly."""
        _set_ci_env(monkeypatch)
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(True, Path("out.json")) is True
        assert _WARNING_FRAGMENT not in capsys.readouterr().err

    def test_explicit_sign_outside_ci_wins(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``--sign`` doesn't depend on the CI auto-detect at all."""
        _stub_sigstore(monkeypatch, available=False)
        assert _resolve_sign(True, Path("out.json")) is True

    def test_explicit_sign_without_output_is_noop(self) -> None:
        """Documented behavior: ``--sign`` without ``--output`` is a
        no-op (nothing to sign)."""
        assert _resolve_sign(True, None) is False


# ── 3. Explicit --no-sign (sign_flag=False) ──────────────────────


class TestExplicitNoSign:
    def test_explicit_no_sign_wins_in_full_ci(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """``--no-sign`` suppresses signing even when every auto-
        detect precondition (CI + sigstore + tokens) holds."""
        _set_ci_env(monkeypatch, token=True, url=True)
        _stub_sigstore(monkeypatch, available=True)
        assert _resolve_sign(False, Path("out.json")) is False
        assert _WARNING_FRAGMENT not in capsys.readouterr().err


# ── 4. CLI-level regression for the release-gate shape ───────────


class TestStubSmokeGracefulDegrade:
    def test_stub_smoke_writes_unsigned_output_in_tokenless_ci(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        """``stub-smoke --output`` in tokenless CI (the release gate
        job's exact permission set) exits 0 and writes the unsigned
        JSON instead of crashing with SigstoreSigningError."""
        _set_ci_env(monkeypatch)
        _stub_sigstore(monkeypatch, available=True)
        out_path = tmp_path / "result.json"
        runner = CliRunner()
        result = runner.invoke(
            eval_cli_app,
            [
                "stub-smoke",
                "--samples-per-prompt",
                "2",
                "--output",
                str(out_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert out_path.exists()
        loaded = json.loads(out_path.read_text(encoding="utf-8"))
        assert "run_id" in loaded
        # No Sigstore bundle was produced — unsigned degrade.
        assert not (
            tmp_path / "result.json.sigstore.json"
        ).exists()
        # The degrade warning surfaced (CliRunner mixes stderr
        # into .output on click < 8.2).
        assert _WARNING_FRAGMENT in result.output
