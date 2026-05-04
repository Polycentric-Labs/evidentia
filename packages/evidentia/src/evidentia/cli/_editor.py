"""Editor-resolution helper for ``--editor`` CLI flags (v0.7.11 P3).

Closes v0.7.10 F-V10-S2 (LOW; CWE-78 risk amplifier): both
``evidentia model-risk model edit --editor`` and ``evidentia tprm
vendor edit --editor`` previously read ``$EDITOR`` and passed the
value directly to ``subprocess.run`` argv-list. This is safe
against shell-metachar injection (no ``shell=True``), but an
attacker who controls ``$EDITOR`` can launch any binary on the
operator's ``PATH`` when the operator triggers ``--editor``.

The pre-condition (env-var write access) already implies code-
execution potential, but defense-in-depth is cheap. This helper
defaults to a small allowlist of common editors; operators with
non-standard editors set ``EVIDENTIA_EDITOR_ALLOW_ANY=1`` to opt
out of the allowlist check.

Public surface:

  - :func:`resolve_editor_or_exit` — parses ``$EDITOR`` (or the
    explicit ``editor`` arg), resolves the first token via
    :func:`shutil.which`, applies the allowlist (unless opted
    out), and returns the resolved argv list ready for
    ``subprocess.run``. On any failure, prints a clear error +
    raises :class:`typer.Exit(code=1)`.
"""

from __future__ import annotations

import os
import shlex
import shutil

import typer
from rich.console import Console

# Allowlist of editor binaries we permit by default. Covers the
# common cross-platform set: terminal editors (vi/vim/nvim/nano/
# emacs/micro/pico) + GUI editors with CLI launchers (code/subl/
# notepad). Allowlist matching is on the basename of the resolved
# absolute path, NOT on the raw ``$EDITOR`` string — so symlinks
# (e.g. ``/usr/local/bin/editor`` -> ``/usr/bin/vim``) are handled
# correctly.
_DEFAULT_EDITOR_ALLOWLIST = frozenset({
    "vi",
    "vim",
    "vim.basic",  # debian/ubuntu wrapper
    "vim.tiny",
    "nvim",
    "nano",
    "emacs",
    "micro",
    "pico",
    "code",
    "code-insiders",
    "subl",
    "atom",
    "gedit",
    "kate",
    "notepad",
    "notepad.exe",
})

_OPT_OUT_ENV = "EVIDENTIA_EDITOR_ALLOW_ANY"

_console = Console()


def resolve_editor_or_exit(
    *,
    default: str = "vi",
    allowlist: frozenset[str] | None = None,
) -> list[str]:
    """Resolve ``$EDITOR`` to a safe argv list or exit cleanly.

    Returns the argv list ready for ``subprocess.run`` — i.e.,
    ``[<resolved-binary>, *<rest-of-tokens>]`` where the binary
    has been ``shutil.which`` resolved + allowlist-checked.

    The split-on-whitespace handles common patterns like
    ``EDITOR='code -w'`` or ``EDITOR='vim -u NONE'``.

    Parameters
    ----------
    default
        Editor command to use when ``$EDITOR`` is unset. Default
        ``"vi"`` matches the historical Unix convention.
    allowlist
        Override the default allowlist. Pass ``frozenset({"vi"})``
        for the strictest case, or pre-add a custom binary basename.

    Raises
    ------
    typer.Exit
        Code 1, with a clear stderr message, on any of:
        - empty/whitespace-only ``$EDITOR``
        - first token not on PATH (``shutil.which`` returns None)
        - resolved basename not in the allowlist + opt-out env
          var not set
    """
    raw = os.environ.get("EDITOR", default)
    raw = raw.strip()
    if not raw:
        _console.print(
            "[red]Error:[/red] $EDITOR is empty or whitespace-only. "
            "Set $EDITOR to a valid editor command (e.g. 'vim') "
            "and retry."
        )
        raise typer.Exit(code=1)

    # shlex.split handles whitespace + simple quoting; safer than
    # str.split for quoted args like EDITOR='vim "-u NONE"'.
    try:
        parts = shlex.split(raw)
    except ValueError as e:
        _console.print(
            f"[red]Error:[/red] $EDITOR={raw!r} could not be parsed: {e}"
        )
        raise typer.Exit(code=1) from e

    if not parts:
        _console.print(
            "[red]Error:[/red] $EDITOR parsed to empty argv. "
            "Set $EDITOR to a valid editor command (e.g. 'vim')."
        )
        raise typer.Exit(code=1)

    head = parts[0]
    resolved = shutil.which(head)
    if resolved is None:
        _console.print(
            f"[red]Error:[/red] Editor {head!r} not found on $PATH. "
            f"Install it or set $EDITOR to an editor that is."
        )
        raise typer.Exit(code=1)

    if os.environ.get(_OPT_OUT_ENV) != "1":
        check_set = allowlist if allowlist is not None else _DEFAULT_EDITOR_ALLOWLIST
        # Compare on the resolved-path basename (handles symlinks
        # like /usr/local/bin/editor -> /usr/bin/vim).
        basename = os.path.basename(resolved).lower()
        if basename not in check_set:
            _console.print(
                f"[red]Error:[/red] Editor {head!r} (resolved to "
                f"{resolved}) is not in Evidentia's editor allowlist. "
                f"Allowed: {sorted(check_set)}.\n"
                f"To use a non-standard editor, set "
                f"{_OPT_OUT_ENV}=1 to opt out of the allowlist check "
                f"(only do this if you trust the binary)."
            )
            raise typer.Exit(code=1)

    # Replace head with the resolved absolute path; preserve any
    # additional argv tokens.
    return [resolved, *parts[1:]]
