#!/usr/bin/env python3
"""Generate the Tier-0 asciinema cast of the Meridian v2 CLI sequence.

Part of the public demo suite (``docs/demo-suite-design.md`` §4). Records
the **real** ``evidentia`` gap-analysis runbook against the bundled
``examples/meridian-fintech-v2/`` inventory and emits a self-hosted
`asciicast v2 <https://docs.asciinema.org/manual/asciicast/v2/>`_ file —
no asciinema.org dependency (air-gap-on-brand). The committed artifact
lives at ``packages/evidentia-ui/public/demo.cast`` and is embedded on the
demo page + README.

THE SEQUENCE (frozen/stable CLI verbs)
======================================

    evidentia doctor
    evidentia catalog list --tier A
    evidentia gap analyze --inventory <inv> \
        --frameworks nist-800-53-rev5-moderate,soc2-tsc --output report.json
    evidentia gap analyze --inventory <inv> \
        --frameworks nist-800-53-rev5-moderate,soc2-tsc \
        --output ar.oscal.json --format oscal-ar
    evidentia oscal verify ar.oscal.json

Each command is run with ``PYTHONIOENCODING=utf-8``, ``FORCE_COLOR=1`` and
``COLUMNS=100`` so Rich renders the same wide, colored tables an operator
sees on a terminal, and its merged stdout+stderr bytes are captured.

DETERMINISM
===========

The cast carries **no wall-clock timestamps** — the event clock is a
counter that advances by a fixed per-character keystroke delay and a fixed
inter-command pause, so re-running the generator against an unchanged CLI
produces a byte-stable timeline. (The captured *output* still reflects the
live tool; that is the point — re-run after a catalog refresh and commit
the refreshed cast.)

Usage::

    uv run --no-sync python scripts/demo/gen_cast.py packages/evidentia-ui/public/demo.cast
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger("gen_cast")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SCENARIO_DIR = REPO_ROOT / "examples" / "meridian-fintech-v2"
# Repo-relative so it renders cleanly in the typed prompt AND resolves under
# ``cwd=REPO_ROOT`` (an absolute path would leak the operator's home dir).
INVENTORY = "examples/meridian-fintech-v2/my-controls.yaml"

# asciicast v2 header geometry (must match the player on the demo page).
WIDTH = 100
HEIGHT = 30
TITLE = "Evidentia — gap analysis on a fintech inventory"

# Deterministic timeline knobs (seconds).
KEYSTROKE_DELAY = 0.04  # ~40ms/char typed-prompt animation
PROMPT_PAUSE = 0.4      # beat after the prompt is typed, before output
COMMAND_PAUSE = 1.0     # pause between commands

# Throwaway output paths kept inside the scenario's temp area so the demo
# run never litters the repo. They are recreated each command.
REPORT_OUT = "demo-report.json"
OSCAL_OUT = "demo-ar.oscal.json"

# The allowlisted Meridian-v2 sequence. Each entry is the argv passed to the
# ``evidentia`` console script (the leading "evidentia" is added by the
# runner). Output targets are placed under the OS temp dir at run time.
COMMANDS: list[list[str]] = [
    ["doctor"],
    ["catalog", "list", "--tier", "A"],
    [
        "gap", "analyze",
        "--inventory", INVENTORY,
        "--frameworks", "nist-800-53-rev5-moderate,soc2-tsc",
        "--output", "{report}",
    ],
    [
        "gap", "analyze",
        "--inventory", INVENTORY,
        "--frameworks", "nist-800-53-rev5-moderate,soc2-tsc",
        "--output", "{oscal}",
        "--format", "oscal-ar",
    ],
    ["oscal", "verify", "{oscal}"],
]


def _display_command(argv: list[str]) -> str:
    """Render an argv as the typed prompt string (no temp-dir noise)."""
    parts = ["evidentia"]
    for tok in argv:
        if tok == "{report}":
            parts.append(REPORT_OUT)
        elif tok == "{oscal}":
            parts.append(OSCAL_OUT)
        else:
            parts.append(tok)
    return " ".join(parts)


# Volatile machine-specific fragments the CLI echoes verbatim. They carry
# the operator's home directory (PII), a per-run random hash, and a
# wall-clock log-timestamp prefix — all normalized to stable demo tokens
# before reaching the committed cast so it is reproducible AND home-path-free.
_GAP_STORE_RE = re.compile(
    r"[A-Za-z]:[\\/].*?[\\/]gap_store[\\/][0-9a-fA-F]+\.json"
    r"|/.*?/gap_store/[0-9a-fA-F]+\.json"
)
# Leading log timestamp: "2026-06-15 18:33:34,396 " -> a fixed token so the
# interleaved INFO log lines don't change the cast byte-for-byte each run.
_LOG_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} ")


def redact_output(text: str, tmp_dir: Path) -> str:
    """Normalize volatile/PII fragments to stable demo tokens.

    - scratch-output paths collapse to their bare filenames;
    - the per-run gap-store snapshot path collapses to a fixed placeholder;
    - the repo root collapses to ``.`` (absolute paths would leak ``$HOME``);
    - wall-clock log-timestamp prefixes collapse to a fixed token.
    """
    text = text.replace(str(tmp_dir / REPORT_OUT), REPORT_OUT)
    text = text.replace(str(tmp_dir / OSCAL_OUT), OSCAL_OUT)
    text = text.replace(tmp_dir.as_posix() + "/" + REPORT_OUT, REPORT_OUT)
    text = text.replace(tmp_dir.as_posix() + "/" + OSCAL_OUT, OSCAL_OUT)
    text = _GAP_STORE_RE.sub("<gap-store>/<snapshot>.json", text)
    # Strip the repo-root prefix in both native and POSIX spellings so
    # echoes like "Loading inventory from <root>/examples/..." stay relative.
    text = text.replace(str(REPO_ROOT) + os.sep, "")
    text = text.replace(REPO_ROOT.as_posix() + "/", "")
    text = _LOG_TS_RE.sub("[demo] ", text)
    return text


def run_command(argv: list[str], tmp_dir: Path) -> bytes:
    """Run ``evidentia <argv>`` and return its merged stdout+stderr bytes.

    The environment forces UTF-8, Rich color, and a 100-column width so the
    captured frames match the cast geometry. Output-file placeholders are
    resolved into ``tmp_dir``; volatile/PII paths in the captured output are
    redacted to stable tokens via :func:`redact_output`.
    """
    resolved: list[str] = []
    for tok in argv:
        if tok == "{report}":
            resolved.append(str(tmp_dir / REPORT_OUT))
        elif tok == "{oscal}":
            resolved.append(str(tmp_dir / OSCAL_OUT))
        else:
            resolved.append(tok)

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["FORCE_COLOR"] = "1"
    env["COLUMNS"] = str(WIDTH)
    env["LINES"] = str(HEIGHT)

    logger.info("exec: evidentia %s", " ".join(resolved))
    result = subprocess.run(
        ["evidentia", *resolved],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if result.returncode != 0:
        sys.stderr.buffer.write(result.stdout)
        raise SystemExit(
            f"Command failed ({result.returncode}): evidentia {' '.join(resolved)}"
        )
    redacted = redact_output(
        result.stdout.decode("utf-8", errors="replace"), tmp_dir
    )
    return redacted.encode("utf-8")


def _header() -> dict[str, object]:
    return {"version": 2, "width": WIDTH, "height": HEIGHT, "title": TITLE}


def build_events(
    commands: list[list[str]],
    runner: Callable[[list[str]], bytes],
) -> list[list[object]]:
    """Build the ``[t, "o", data]`` event stream for the command list.

    ``runner`` returns the raw output bytes for a given argv; it is injected
    so tests can stub the CLI. Timestamps are deterministic — a counter that
    advances by ``KEYSTROKE_DELAY`` per typed character, ``PROMPT_PAUSE``
    after the prompt, the command's output as one frame, and
    ``COMMAND_PAUSE`` between commands.
    """
    events: list[list[object]] = []
    t = 0.0
    for argv in commands:
        prompt = _display_command(argv)
        # Animate the prompt one character at a time: "$ <cmd>".
        events.append([round(t, 6), "o", "$ "])
        for ch in prompt:
            t += KEYSTROKE_DELAY
            events.append([round(t, 6), "o", ch])
        # Newline + a beat before the output renders.
        t += KEYSTROKE_DELAY
        events.append([round(t, 6), "o", "\r\n"])
        t += PROMPT_PAUSE

        output = runner(argv).decode("utf-8", errors="replace")
        events.append([round(t, 6), "o", output])

        t += COMMAND_PAUSE
    return events


def render_cast(events: list[list[object]]) -> str:
    """Serialize header + events to an asciicast v2 JSON-lines string."""
    lines = [json.dumps(_header(), ensure_ascii=False)]
    lines.extend(json.dumps(ev, ensure_ascii=False) for ev in events)
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        sys.stderr.write(
            "usage: gen_cast.py <output.cast>\n"
            "  e.g. scripts/demo/gen_cast.py "
            "packages/evidentia-ui/public/demo.cast\n"
        )
        return 2
    out_path = Path(args[0])

    import shutil
    import tempfile

    # A FIXED (not mkdtemp-random) scratch dir so the captured output paths
    # — which the CLI echoes verbatim ("Report exported: <path>") — are
    # stable across runs, keeping the committed cast byte-reproducible.
    tmp_dir = Path(tempfile.gettempdir()) / "evidentia-democast"
    if tmp_dir.exists():
        shutil.rmtree(tmp_dir)
    tmp_dir.mkdir(parents=True)
    try:
        events = build_events(
            COMMANDS, lambda a: run_command(a, tmp_dir)
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    cast = render_cast(events)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(cast, encoding="utf-8", newline="\n")
    logger.info(
        "Wrote %s (%d events, %d bytes)",
        out_path,
        len(events),
        len(cast.encode("utf-8")),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
