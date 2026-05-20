"""Publish the Evidentia GRC LLM faithfulness eval suite to the HF Hub (v0.9.8 P1.9).

Promotes the in-repo DFAH calibration corpus
(`tests/data/dfah-calibration/corpus*.jsonl`) to a published Hugging
Face dataset under `Polycentric-Labs/evidentia-grc-eval`.

Two-phase by design — the secret-handling + publishing-authority
protocols mean the actual upload is gated:

  Phase 1 (no token, no network):
      uv run python scripts/publish_hf_eval.py --dry-run

  validates every corpus file's schema, rebuilds `corpus-all.jsonl`
  from the subsets, assembles the upload set, and prints exactly what
  WOULD be pushed. Safe to run anytime; this is what CI + tests exercise.

  Phase 2 (operator-run, requires HF_TOKEN):
      HF_TOKEN=<token> uv run python scripts/publish_hf_eval.py

  performs the actual upload. The token is read ONLY from the
  ``HF_TOKEN`` environment variable — never a CLI argument — so it
  does not land in shell history or process listings. Creating /
  updating a public dataset repo is a publishing action; the operator
  runs this step deliberately.

The script is operational tooling under ``scripts/`` — not part of any
package's importable API surface (per ``docs/api-stability.md``).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# ── Configuration ──────────────────────────────────────────────────

DEFAULT_REPO_ID = "Polycentric-Labs/evidentia-grc-eval"

CALIBRATION_DIR = Path("tests/data/dfah-calibration")

# (corpus filename, HF config_name). Order matters only for the
# corpus-all.jsonl concatenation determinism.
CORPUS_SUBSETS: list[tuple[str, str]] = [
    ("corpus.jsonl", "base"),
    ("corpus_nist.jsonl", "nist-800-53"),
    ("corpus_ffiec.jsonl", "ffiec"),
    ("corpus_iso27001.jsonl", "iso-27001"),
    ("corpus_federal.jsonl", "federal"),
    ("corpus_fedramp_high.jsonl", "fedramp-rev5-high"),
    ("corpus_cmmc_l2.jsonl", "cmmc-l2"),
]

#: Combined-corpus filename (built from CORPUS_SUBSETS).
CORPUS_ALL_FILENAME = "corpus-all.jsonl"

#: The dataset-card source. Uploaded to the HF repo as ``README.md``.
DATASET_CARD_FILENAME = "hf-dataset-card.md"

#: Valid ``category`` values per the corpus schema.
VALID_CATEGORIES = frozenset(
    {"verbatim", "paraphrase", "semi-related", "hallucination"}
)


class CorpusValidationError(Exception):
    """Raised when a corpus file fails schema validation."""


# ── Schema validation ──────────────────────────────────────────────


def validate_corpus_entry(entry: object, *, source: str, line_no: int) -> None:
    """Validate one corpus entry against the DFAH schema.

    Schema (per ``tests/data/dfah-calibration/README.md``):

    - ``id``: non-empty string
    - ``category``: one of :data:`VALID_CATEGORIES`
    - ``claim``: non-empty string
    - ``source_clauses``: non-empty list of strings
    - ``faithful``: bool
    - ``framework``: optional string (absent on the framework-agnostic
      base subset)

    Raises:
        CorpusValidationError: On any schema violation, with the source
            file + line number so operators can locate the bad entry.
    """
    where = f"{source}:{line_no}"
    if not isinstance(entry, dict):
        raise CorpusValidationError(
            f"{where}: entry is not a JSON object"
        )
    for field in ("id", "claim"):
        value = entry.get(field)
        if not isinstance(value, str) or not value:
            raise CorpusValidationError(
                f"{where}: {field!r} must be a non-empty string"
            )
    category = entry.get("category")
    if category not in VALID_CATEGORIES:
        raise CorpusValidationError(
            f"{where}: category {category!r} not in {sorted(VALID_CATEGORIES)}"
        )
    clauses = entry.get("source_clauses")
    if not isinstance(clauses, list) or not clauses:
        raise CorpusValidationError(
            f"{where}: 'source_clauses' must be a non-empty list"
        )
    if not all(isinstance(c, str) and c for c in clauses):
        raise CorpusValidationError(
            f"{where}: every source_clause must be a non-empty string"
        )
    if not isinstance(entry.get("faithful"), bool):
        raise CorpusValidationError(
            f"{where}: 'faithful' must be a boolean"
        )
    # framework is optional, but if present must be a non-empty string.
    framework = entry.get("framework")
    if framework is not None and (
        not isinstance(framework, str) or not framework
    ):
        raise CorpusValidationError(
            f"{where}: 'framework' (when present) must be a non-empty string"
        )


def validate_corpus_file(path: Path) -> list[str]:
    """Validate every entry in a JSONL corpus file.

    Args:
        path: Path to a ``corpus*.jsonl`` file.

    Returns:
        The file's raw lines (stripped of trailing newline) — so callers
        can reuse them for the combined-corpus concatenation without a
        second read.

    Raises:
        FileNotFoundError: ``path`` does not exist.
        CorpusValidationError: Any line is not valid JSON OR any entry
            fails the schema check.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Corpus file not found: {path}")
    lines: list[str] = []
    for line_no, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = raw_line.strip()
        if not stripped:
            continue  # tolerate blank lines
        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise CorpusValidationError(
                f"{path.name}:{line_no}: invalid JSON: {exc}"
            ) from exc
        validate_corpus_entry(entry, source=path.name, line_no=line_no)
        lines.append(stripped)
    if not lines:
        raise CorpusValidationError(
            f"{path.name}: contains no entries"
        )
    return lines


# ── Assemble ───────────────────────────────────────────────────────


def build_corpus_all(calibration_dir: Path) -> tuple[Path, int]:
    """Rebuild ``corpus-all.jsonl`` by concatenating every subset.

    Keeps the combined ``all`` config in sync with the per-framework
    subsets — running this before every publish means the Hub's
    ``all`` config can never drift from the subsets it aggregates.

    Args:
        calibration_dir: The ``tests/data/dfah-calibration`` directory.

    Returns:
        ``(path, entry_count)`` — the written combined-corpus path +
        the total number of entries.

    Raises:
        CorpusValidationError / FileNotFoundError: Propagated from
            :func:`validate_corpus_file`.
    """
    combined: list[str] = []
    for filename, _config in CORPUS_SUBSETS:
        combined.extend(validate_corpus_file(calibration_dir / filename))
    out_path = calibration_dir / CORPUS_ALL_FILENAME
    out_path.write_text("\n".join(combined) + "\n", encoding="utf-8")
    return out_path, len(combined)


def assemble_upload_set(calibration_dir: Path) -> dict[str, Path]:
    """Build the repo-path → local-path map for the HF upload.

    Side effect: rebuilds ``corpus-all.jsonl`` (via
    :func:`build_corpus_all`) so the assembled set is always current.

    Returns:
        A dict mapping each file's path-in-repo to its local path.
        The dataset card maps to ``README.md`` (HF's dataset-card
        convention); every corpus file keeps its name.

    Raises:
        FileNotFoundError: The dataset card is missing.
        CorpusValidationError: Any corpus file fails validation.
    """
    build_corpus_all(calibration_dir)

    upload: dict[str, Path] = {}
    # Dataset card → README.md at the repo root.
    card = calibration_dir / DATASET_CARD_FILENAME
    if not card.is_file():
        raise FileNotFoundError(f"Dataset card not found: {card}")
    upload["README.md"] = card
    # Every subset + the combined corpus, by their own names.
    for filename, _config in CORPUS_SUBSETS:
        upload[filename] = calibration_dir / filename
    upload[CORPUS_ALL_FILENAME] = calibration_dir / CORPUS_ALL_FILENAME
    return upload


# ── Publish ────────────────────────────────────────────────────────


def publish(
    repo_id: str,
    upload_set: dict[str, Path],
    *,
    token: str,
    private: bool,
) -> None:
    """Upload the assembled set to the HF Hub dataset repo.

    Args:
        repo_id: The target dataset repo (e.g.
            ``Polycentric-Labs/evidentia-grc-eval``).
        upload_set: Output of :func:`assemble_upload_set`.
        token: HF write token. Read by :func:`main` from the
            ``HF_TOKEN`` env var — never a CLI argument.
        private: Whether to create the repo private. Datasets are
            public by default (the eval suite is meant to be used).

    Raises:
        RuntimeError: When ``huggingface_hub`` is not importable.
    """
    try:
        from huggingface_hub import HfApi
    except ImportError as exc:  # pragma: no cover - env-dependent
        raise RuntimeError(
            "huggingface_hub is not installed. Install it with "
            "`uv pip install huggingface_hub` before running the "
            "publish step. (The --dry-run path does NOT need it.)"
        ) from exc

    api = HfApi(token=token)
    api.create_repo(
        repo_id=repo_id,
        repo_type="dataset",
        exist_ok=True,
        private=private,
    )
    for path_in_repo, local_path in sorted(upload_set.items()):
        api.upload_file(
            path_or_fileobj=str(local_path),
            path_in_repo=path_in_repo,
            repo_id=repo_id,
            repo_type="dataset",
        )
        print(f"  uploaded {local_path.name} -> {path_in_repo}")


# ── CLI ────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Returns a process exit code (0 = success, non-zero = failure) so
    the function is unit-testable without a SystemExit.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Publish the Evidentia GRC LLM faithfulness eval suite to "
            "the Hugging Face Hub. Run with --dry-run first (no token "
            "needed); the real upload reads HF_TOKEN from the env."
        )
    )
    parser.add_argument(
        "--repo-id",
        default=DEFAULT_REPO_ID,
        help=f"Target HF dataset repo (default: {DEFAULT_REPO_ID}).",
    )
    parser.add_argument(
        "--calibration-dir",
        type=Path,
        default=CALIBRATION_DIR,
        help=(
            "Directory holding the corpus*.jsonl files + the dataset "
            f"card (default: {CALIBRATION_DIR})."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Validate + assemble + print the upload plan WITHOUT "
            "touching the network or needing HF_TOKEN."
        ),
    )
    parser.add_argument(
        "--private",
        action="store_true",
        help=(
            "Create the dataset repo private. Default is public — the "
            "eval suite is meant to be downloadable."
        ),
    )
    args = parser.parse_args(argv)

    calibration_dir: Path = args.calibration_dir
    try:
        upload_set = assemble_upload_set(calibration_dir)
    except (FileNotFoundError, CorpusValidationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    combined_path = calibration_dir / CORPUS_ALL_FILENAME
    total_entries = len(
        combined_path.read_text(encoding="utf-8").splitlines()
    )
    print(
        f"Assembled {len(upload_set)} files for {args.repo_id!r} "
        f"({total_entries} total corpus entries):"
    )
    for path_in_repo in sorted(upload_set):
        print(f"  {path_in_repo}")

    if args.dry_run:
        print(
            "\n--dry-run: nothing uploaded. Re-run without --dry-run "
            "(with HF_TOKEN set) to publish."
        )
        return 0

    import os

    token = os.environ.get("HF_TOKEN")
    if not token:
        print(
            "ERROR: HF_TOKEN environment variable is not set. The "
            "publish step needs a Hugging Face write token. Set it in "
            "your shell (do NOT pass it as a CLI flag), then re-run. "
            "Use --dry-run to validate without a token.",
            file=sys.stderr,
        )
        return 1

    print(f"\nPublishing to https://huggingface.co/datasets/{args.repo_id} ...")
    try:
        publish(
            args.repo_id,
            upload_set,
            token=token,
            private=args.private,
        )
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print("Publish complete.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
