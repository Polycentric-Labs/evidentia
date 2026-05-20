"""Self-tests for ``scripts/publish_hf_eval.py`` (v0.9.8 P1.9).

The publish script promotes the in-repo DFAH calibration corpus to a
Hugging Face dataset. These tests pin:

1. The corpus-entry schema validator (catches malformed entries).
2. The combined-corpus rebuild (``corpus-all.jsonl``).
3. The upload-set assembly.
4. The CLI ``main()`` — dry-run path (no token, no network) + the
   missing-token guard on the real-publish path.
5. A mocked-``HfApi`` publish happy path (no real upload).

The actual HF upload is NOT exercised — it needs a write token + the
network. The ``--dry-run`` path is the contract these tests lock.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Load the script as a module — ``scripts/`` is not a package.
_SCRIPT_PATH = (
    Path(__file__).parent.parent.parent / "scripts" / "publish_hf_eval.py"
)
_spec = importlib.util.spec_from_file_location(
    "publish_hf_eval", _SCRIPT_PATH
)
assert _spec is not None
assert _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
sys.modules["publish_hf_eval"] = _mod
_spec.loader.exec_module(_mod)

CorpusValidationError = _mod.CorpusValidationError
validate_corpus_entry = _mod.validate_corpus_entry
validate_corpus_file = _mod.validate_corpus_file
build_corpus_all = _mod.build_corpus_all
assemble_upload_set = _mod.assemble_upload_set
publish = _mod.publish
main = _mod.main
CORPUS_SUBSETS = _mod.CORPUS_SUBSETS
DATASET_CARD_FILENAME = _mod.DATASET_CARD_FILENAME

_REPO_ROOT = Path(__file__).parent.parent.parent
_REAL_CALIBRATION_DIR = _REPO_ROOT / "tests" / "data" / "dfah-calibration"


# ── Helpers ────────────────────────────────────────────────────────


def _valid_entry(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "id": "x-001",
        "category": "verbatim",
        "framework": "nist-800-53",
        "claim": "A claim sentence.",
        "source_clauses": ["A source clause."],
        "faithful": True,
    }
    base.update(overrides)
    return base


def _write_corpus(path: Path, entries: list[dict[str, object]]) -> None:
    path.write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n",
        encoding="utf-8",
    )


# ── 1. Schema validation ───────────────────────────────────────────


class TestValidateCorpusEntry:
    def test_valid_entry_accepted(self) -> None:
        validate_corpus_entry(_valid_entry(), source="t", line_no=1)

    def test_entry_without_framework_accepted(self) -> None:
        """The framework-agnostic base subset omits ``framework``."""
        entry = _valid_entry()
        del entry["framework"]
        validate_corpus_entry(entry, source="t", line_no=1)

    def test_non_dict_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="not a JSON object"):
            validate_corpus_entry(["not", "a", "dict"], source="t", line_no=1)

    def test_empty_id_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="'id'"):
            validate_corpus_entry(
                _valid_entry(id=""), source="t", line_no=1
            )

    def test_bad_category_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="category"):
            validate_corpus_entry(
                _valid_entry(category="bogus"), source="t", line_no=1
            )

    def test_non_list_source_clauses_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="source_clauses"):
            validate_corpus_entry(
                _valid_entry(source_clauses="not-a-list"),
                source="t",
                line_no=1,
            )

    def test_empty_source_clauses_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="source_clauses"):
            validate_corpus_entry(
                _valid_entry(source_clauses=[]), source="t", line_no=1
            )

    def test_non_string_source_clause_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="source_clause"):
            validate_corpus_entry(
                _valid_entry(source_clauses=["ok", 123]),
                source="t",
                line_no=1,
            )

    def test_non_bool_faithful_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="faithful"):
            validate_corpus_entry(
                _valid_entry(faithful="yes"), source="t", line_no=1
            )

    def test_bad_framework_type_rejected(self) -> None:
        with pytest.raises(CorpusValidationError, match="framework"):
            validate_corpus_entry(
                _valid_entry(framework=42), source="t", line_no=1
            )


class TestValidateCorpusFile:
    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            validate_corpus_file(tmp_path / "nope.jsonl")

    def test_invalid_json_line_raises(self, tmp_path: Path) -> None:
        corpus = tmp_path / "bad.jsonl"
        corpus.write_text('{"id": "x-001"\nnot json\n', encoding="utf-8")
        with pytest.raises(CorpusValidationError, match="invalid JSON"):
            validate_corpus_file(corpus)

    def test_empty_file_raises(self, tmp_path: Path) -> None:
        corpus = tmp_path / "empty.jsonl"
        corpus.write_text("\n  \n", encoding="utf-8")
        with pytest.raises(CorpusValidationError, match="no entries"):
            validate_corpus_file(corpus)

    def test_valid_file_returns_lines(self, tmp_path: Path) -> None:
        corpus = tmp_path / "ok.jsonl"
        _write_corpus(corpus, [_valid_entry(id="x-001"), _valid_entry(id="x-002")])
        lines = validate_corpus_file(corpus)
        assert len(lines) == 2

    def test_blank_lines_tolerated(self, tmp_path: Path) -> None:
        corpus = tmp_path / "ok.jsonl"
        corpus.write_text(
            json.dumps(_valid_entry()) + "\n\n", encoding="utf-8"
        )
        assert len(validate_corpus_file(corpus)) == 1


# ── 2. Real corpus integration ─────────────────────────────────────


class TestRealCorpus:
    """The 7 real subset files must all pass validation."""

    @pytest.mark.parametrize(
        "filename", [f for f, _ in CORPUS_SUBSETS]
    )
    def test_real_subset_validates(self, filename: str) -> None:
        lines = validate_corpus_file(_REAL_CALIBRATION_DIR / filename)
        # Every per-framework subset is 24 entries; base is 51.
        expected = 51 if filename == "corpus.jsonl" else 24
        assert len(lines) == expected

    def test_build_corpus_all_totals_195(self, tmp_path: Path) -> None:
        """Combined corpus = 51 + 24*6 = 195 entries.

        Built into a temp dir copy so the test does not mutate the
        repo's committed ``corpus-all.jsonl``.
        """
        import shutil

        for filename, _ in CORPUS_SUBSETS:
            shutil.copy(
                _REAL_CALIBRATION_DIR / filename, tmp_path / filename
            )
        out_path, count = build_corpus_all(tmp_path)
        assert count == 195
        assert out_path.name == "corpus-all.jsonl"
        assert (
            len(out_path.read_text(encoding="utf-8").splitlines()) == 195
        )

    def test_new_subsets_present(self) -> None:
        """v0.9.8 P1.9 adds FedRAMP Rev 5 High + CMMC L2 subsets."""
        configs = {config for _, config in CORPUS_SUBSETS}
        assert "fedramp-rev5-high" in configs
        assert "cmmc-l2" in configs


# ── 3. Upload-set assembly ─────────────────────────────────────────


class TestAssembleUploadSet:
    def _seed_calibration_dir(self, tmp_path: Path) -> Path:
        """Copy the real corpus + card into a temp dir."""
        import shutil

        for filename, _ in CORPUS_SUBSETS:
            shutil.copy(
                _REAL_CALIBRATION_DIR / filename, tmp_path / filename
            )
        shutil.copy(
            _REAL_CALIBRATION_DIR / DATASET_CARD_FILENAME,
            tmp_path / DATASET_CARD_FILENAME,
        )
        return tmp_path

    def test_assemble_maps_card_to_readme(self, tmp_path: Path) -> None:
        seeded = self._seed_calibration_dir(tmp_path)
        upload = assemble_upload_set(seeded)
        assert "README.md" in upload
        assert upload["README.md"].name == DATASET_CARD_FILENAME

    def test_assemble_includes_all_subsets_and_combined(
        self, tmp_path: Path
    ) -> None:
        seeded = self._seed_calibration_dir(tmp_path)
        upload = assemble_upload_set(seeded)
        for filename, _ in CORPUS_SUBSETS:
            assert filename in upload
        assert "corpus-all.jsonl" in upload
        # README + 7 subsets + corpus-all = 9 files.
        assert len(upload) == 9

    def test_assemble_missing_card_raises(self, tmp_path: Path) -> None:
        import shutil

        # Seed corpus files but NOT the dataset card.
        for filename, _ in CORPUS_SUBSETS:
            shutil.copy(
                _REAL_CALIBRATION_DIR / filename, tmp_path / filename
            )
        with pytest.raises(FileNotFoundError, match="Dataset card"):
            assemble_upload_set(tmp_path)


# ── 4. CLI main() ──────────────────────────────────────────────────


class TestMainDryRun:
    def test_dry_run_returns_zero(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """--dry-run against the real corpus exits 0 without a token."""
        monkeypatch.delenv("HF_TOKEN", raising=False)
        rc = main(
            [
                "--dry-run",
                "--calibration-dir",
                str(_REAL_CALIBRATION_DIR),
            ]
        )
        assert rc == 0

    def test_non_dry_run_without_token_returns_one(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Real-publish path with no HF_TOKEN → exit 1, no upload."""
        monkeypatch.delenv("HF_TOKEN", raising=False)
        rc = main(
            ["--calibration-dir", str(_REAL_CALIBRATION_DIR)]
        )
        assert rc == 1

    def test_bad_calibration_dir_returns_one(
        self, tmp_path: Path
    ) -> None:
        """Missing corpus files → exit 1 with a clear error."""
        rc = main(["--dry-run", "--calibration-dir", str(tmp_path)])
        assert rc == 1


class TestMainPublishPath:
    def test_publish_invoked_with_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With HF_TOKEN set, main() calls publish() — HfApi mocked."""
        monkeypatch.setenv("HF_TOKEN", "fake-write-token")

        captured: dict[str, object] = {}

        def _fake_publish(
            repo_id: str,
            upload_set: dict[str, Path],
            *,
            token: str,
            private: bool,
        ) -> None:
            captured["repo_id"] = repo_id
            captured["token"] = token
            captured["private"] = private
            captured["file_count"] = len(upload_set)

        monkeypatch.setattr(_mod, "publish", _fake_publish)
        rc = main(
            ["--calibration-dir", str(_REAL_CALIBRATION_DIR)]
        )
        assert rc == 0
        assert captured["repo_id"] == "Polycentric-Labs/evidentia-grc-eval"
        assert captured["token"] == "fake-write-token"
        assert captured["private"] is False
        assert captured["file_count"] == 9


class TestPublishFunction:
    def test_publish_calls_hf_api(self) -> None:
        """publish() drives HfApi create_repo + upload_file per file."""
        fake_api = MagicMock(name="HfApi-instance")
        fake_hf_module = MagicMock()
        fake_hf_module.HfApi.return_value = fake_api

        upload_set = {
            "README.md": Path("/tmp/card.md"),
            "corpus.jsonl": Path("/tmp/corpus.jsonl"),
        }
        with patch.dict(
            sys.modules, {"huggingface_hub": fake_hf_module}
        ):
            publish(
                "Polycentric-Labs/evidentia-grc-eval",
                upload_set,
                token="fake-token",
                private=False,
            )
        # Repo created once as a dataset.
        fake_api.create_repo.assert_called_once()
        _, kwargs = fake_api.create_repo.call_args
        assert kwargs["repo_type"] == "dataset"
        assert kwargs["exist_ok"] is True
        # One upload_file call per file in the set.
        assert fake_api.upload_file.call_count == 2

    def test_publish_raises_without_huggingface_hub(self) -> None:
        """A missing huggingface_hub surfaces a clear RuntimeError."""
        # Simulate the import failing.
        with (
            patch.dict(sys.modules, {"huggingface_hub": None}),
            pytest.raises(RuntimeError, match="huggingface_hub"),
        ):
            publish(
                "x/y",
                {"README.md": Path("/tmp/card.md")},
                token="t",
                private=False,
            )
