"""Argv-allowlist runner for the Tier-1 public demo (constrained CLI).

This module is the *only* executable the Tier-1 demo profile exposes (see
``docker/Dockerfile.demo``). It enforces condition 1 of the demo threat model
(``docs/demo-suite-design.md`` §5): no raw shell, no ``-c``/``-m``, no
user-controlled env, no free-form flags — only a fixed set of network-free,
fixture-only ``evidentia`` argv vectors.

Three public helpers:

``is_allowed(argv)``
    Exact, token-for-token match of the FULL argv against the allowlist
    loaded from ``allowlist.yaml``. The single placeholder token ``$OUT`` in
    a vector matches only the runner's fixed scratch-output filename
    (:data:`OUTPUT_NAME`) — a caller-supplied output path can never satisfy
    it. Anything else (extra flags, off-allowlist verbs, ``-c``) is refused.

``scrub_env(env)``
    Returns a brand-new env dict containing only an allowlisted essentials
    set (:data:`ALLOWED_ENV_KEYS`) plus the forced ``EVIDENTIA_API_OFFLINE=1``.
    Every credential-shaped variable (API keys, cloud secrets, tokens) is
    dropped because it never appears in the allowlist.

``run(argv)``
    Refuses (exit 2 + a message) when ``not is_allowed(argv)``; otherwise
    execs ``evidentia --offline <argv>`` with the scrubbed env, the global
    ``--offline`` flag forced on, ``$OUT`` rewritten to a private temp file,
    and ``shell=False``. No ``/bin/sh``, no ``shell=True``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from importlib.resources import files
from pathlib import Path

import yaml

# The single fixed scratch-output filename. Allowlist vectors carrying the
# ``$OUT`` placeholder accept *only* this token in the user-facing argv; the
# runner rewrites it to a path under a private tmpdir before exec. A
# caller-supplied ``--output /etc/passwd`` therefore never matches.
OUTPUT_NAME = "demo-output.json"

# The placeholder token used in ``allowlist.yaml`` for the fixed output target.
_OUT_PLACEHOLDER = "$OUT"

# The minimal env an allowlisted ``evidentia`` invocation needs to run. Every
# other variable in the inherited environment — notably any credential — is
# dropped by :func:`scrub_env`. ``EVIDENTIA_API_OFFLINE`` is force-set on top.
ALLOWED_ENV_KEYS: frozenset[str] = frozenset(
    {"PATH", "HOME", "LANG", "PYTHONIOENCODING", "TERM"}
)


def _load_vectors() -> list[list[str]]:
    """Load the allowed argv vectors from the bundled ``allowlist.yaml``.

    Resolved via ``importlib.resources`` so it works from an installed wheel,
    not just a source checkout.
    """
    raw = (files("evidentia.demo") / "allowlist.yaml").read_text(
        encoding="utf-8"
    )
    data = yaml.safe_load(raw)
    vectors = data.get("vectors", []) if isinstance(data, dict) else []
    # Normalize to ``list[list[str]]`` and reject any malformed entry up front
    # so a typo in the YAML fails loudly rather than silently widening the
    # allowlist.
    parsed: list[list[str]] = []
    for vec in vectors:
        if not isinstance(vec, list) or not all(
            isinstance(tok, str) for tok in vec
        ):
            raise ValueError(f"malformed allowlist vector: {vec!r}")
        parsed.append([str(tok) for tok in vec])
    return parsed


# Loaded once at import time — the allowlist is static package data.
_ALLOWED_VECTORS: list[list[str]] = _load_vectors()


def _vector_matches(vector: list[str], argv: list[str]) -> bool:
    """Exact token-for-token match of one allowlist vector against ``argv``.

    Lengths must be identical and every token must be equal, with the sole
    exception that a ``$OUT`` placeholder token in the vector matches only the
    fixed :data:`OUTPUT_NAME` literal in ``argv``.
    """
    if len(vector) != len(argv):
        return False
    for want, got in zip(vector, argv, strict=True):
        if want == _OUT_PLACEHOLDER:
            if got != OUTPUT_NAME:
                return False
        elif want != got:
            return False
    return True


def is_allowed(argv: list[str]) -> bool:
    """Return ``True`` iff ``argv`` exactly matches an allowlist vector.

    Matching is full-argv and token-for-token; there is no prefix matching,
    no free-form arguments, and no wildcards. Raw-shell escapes (``-c``,
    ``-m``), excluded verbs (``collect*``, ``mcp serve``, ``eval``,
    ``risk generate``, ``explain``, …), and any off-allowlist flag therefore
    all return ``False``.
    """
    return any(_vector_matches(vec, argv) for vec in _ALLOWED_VECTORS)


def scrub_env(env: dict[str, str]) -> dict[str, str]:
    """Return a minimal, credential-free env with offline mode forced on.

    Only keys in :data:`ALLOWED_ENV_KEYS` survive from ``env``; everything
    else (API keys, cloud secrets, tokens, anything user-controlled) is
    dropped. ``EVIDENTIA_API_OFFLINE=1`` is then force-set so the
    unauthenticated API, collector token-exfil paths, and LLM-cost paths all
    fail closed even if a verb were somehow coerced into reaching them.
    """
    scrubbed = {k: v for k, v in env.items() if k in ALLOWED_ENV_KEYS}
    scrubbed["EVIDENTIA_API_OFFLINE"] = "1"
    return scrubbed


def _resolve_output(argv: list[str], scratch_dir: Path) -> list[str]:
    """Rewrite the fixed ``$OUT`` output token to a private temp path.

    Allowlisted vectors carry :data:`OUTPUT_NAME` verbatim in the user argv;
    at exec time it is mapped into ``scratch_dir`` so the demo never writes to
    a caller-chosen location.
    """
    out_path = str(scratch_dir / OUTPUT_NAME)
    return [out_path if tok == OUTPUT_NAME else tok for tok in argv]


def run(argv: list[str], env: dict[str, str] | None = None) -> int:
    """Execute an allowlisted ``evidentia`` argv air-gapped, or refuse it.

    Refuses with exit code 2 (and a stderr message) when ``argv`` is not on
    the allowlist. Otherwise execs ``evidentia --offline <argv>`` with the
    scrubbed env, the ``$OUT`` token rewritten into a private scratch dir, and
    ``shell=False`` — no ``/bin/sh``, no ``shell=True``, no ``-c``/``-m``.

    Returns the subprocess's exit code (or 2 on refusal). ``env`` defaults to
    the current process environment; it is always passed through
    :func:`scrub_env` first, so credentials cannot leak in via a caller.
    """
    if not is_allowed(argv):
        sys.stderr.write(
            "evidentia-demo: refused — argv is not on the demo allowlist. "
            "The public demo only runs a fixed set of network-free, "
            "fixture-only commands.\n"
        )
        return 2

    source_env = os.environ if env is None else env
    scrubbed = scrub_env(dict(source_env))

    with tempfile.TemporaryDirectory(prefix="evidentia-demo-") as scratch:
        resolved = _resolve_output(argv, Path(scratch))
        # The global ``--offline`` flag is a root-callback option, so it must
        # precede the subcommand: ``evidentia --offline <verb> ...``.
        # Fixed argv (allowlisted vector + forced --offline), scrubbed env,
        # shell=False — no shell interpolation, no user-controlled command.
        completed = subprocess.run(
            ["evidentia", "--offline", *resolved],
            env=scrubbed,
            shell=False,
            check=False,
        )
    return completed.returncode
