"""Publish one offline SCAP import under its original file and clock authority."""

from __future__ import annotations

import sys
from importlib.util import find_spec
from pathlib import Path
from typing import Never

import typer


def _exit(message: str, code: int) -> Never:
    typer.echo(message, err=True)
    raise typer.Exit(code)


def _proven_absent(error: ModuleNotFoundError) -> bool:
    if error.name not in {"evidentia_collectors", "evidentia_collectors.scap"}:
        return False
    try:
        return find_spec(error.name) is None
    except Exception:
        return False


def run_scap(
    *,
    source: Path,
    source_profile: str,
    assessment_index: int,
    cadence_slug: str | None = None,
    completion_assertion: Path | None = None,
    asserted_by: str | None = None,
    output: Path | None = None,
    output_view: str = "result",
) -> None:
    """Read guarded local inputs and publish exact bytes without saving evidence."""
    try:
        from evidentia_collectors.scap import _files, collector
        from evidentia_collectors.scap._json import load_json
        from evidentia_collectors.scap._limits import CLAIM_LIMIT, ScapFailure
    except ModuleNotFoundError as error:
        _exit("The SCAP collector is unavailable." if _proven_absent(error) else "SCAP import support failed.", 1)
    except Exception:
        _exit("SCAP import support failed.", 1)

    source_raw = claim_raw = b""
    try:
        prepared = collector._prepare_import()
        prepared.budget.check()
        if type(output_view) is not str or output_view not in {"result", "artifact"}:
            raise ScapFailure("invalid_request")
        if (completion_assertion is None) != (asserted_by is None):
            raise ScapFailure("invalid_request")
        source_path, claim_path, output_path = _files.check_paths(source, completion_assertion, output)
        prepared.budget.check()
        claim = None
        if claim_path is not None:
            claim_raw = _files.read_claim(claim_path, prepared.budget)
            prepared.budget.check()
            try:
                claim = load_json(claim_raw, CLAIM_LIMIT)
            except ScapFailure as error:
                code: str = error.code
                if code == "processing_deadline_exceeded":
                    raise
                prepared.budget.check()
                raise ScapFailure("completion_assertion_invalid") from None
            prepared.budget.check()
        operation = prepared.begin(
            source_profile=source_profile,
            assessment_index=assessment_index,
            cadence_slug=cadence_slug,
            completion_assertion=claim,
            actor=collector._caller_actor(claim, asserted_by),
        )
        source_raw = _files.read_source(source_path, operation.budget)
        accepted = operation.consume(source_raw)
        source_raw = claim_raw = b""
        wire = accepted.output_bytes(output_view)
        _files.check_paths(source_path, claim_path, output_path)
        if output_path is not None:
            _files.publish_file(output_path, wire, accepted.budget)
        else:
            try:
                stream = sys.stdout.buffer
            except Exception:
                raise ScapFailure("publication_failed") from None
            _files.publish_stdout(stream, wire, accepted.budget)
    except ScapFailure as error:
        _exit(error.message, error.cli_exit)
    except Exception:
        failure = ScapFailure()
        _exit(failure.message, failure.cli_exit)
    finally:
        source_raw = claim_raw = b""
