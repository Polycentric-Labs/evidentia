# Fuzzing harnesses (`tests/fuzz/`)

Coverage-guided fuzzing of Evidentia's untrusted-input parsers, plus a
cross-platform Hypothesis complement.

The approach is **atheris harnesses → ClusterFuzzLite in CI → OSS-Fuzz
later** (the same harnesses graduate). ClusterFuzzLite is the
OpenSSF-Scorecard-credited "Fuzzing" vehicle; bare atheris-in-CI is not.

## What runs where

| Layer | Files | Runs on | How |
| --- | --- | --- | --- |
| **atheris harnesses** | `fuzz_*.py` | **Linux/CI only** | ClusterFuzzLite (`.clusterfuzzlite/`) |
| **Hypothesis property tests** | `test_parser_robustness.py` | **everywhere** | `uv run pytest tests/fuzz/` |

atheris has **no Windows wheel** — the `fuzz_*.py` harnesses do not
import or run on Windows. They are syntactically valid Python and are
exercised in CI by ClusterFuzzLite. The Hypothesis tests encode the same
invariant and run cross-platform under plain pytest.

## Harnesses → target parse entry points

Each harness feeds fuzz bytes into one untrusted-input parser and catches
**only** that parser's *declared* exceptions; any other exception type
escaping is a finding.

| Harness | Surface | Source entry point |
| --- | --- | --- |
| `fuzz_catalog_import.py` | `catalog import` (JSON/YAML) | `evidentia_core.catalogs.loader._load_catalog_data` + `load_oscal_catalog` / `load_evidentia_catalog` / `load_non_control_catalog` |
| `fuzz_oscal_profile.py` | OSCAL profile load/resolve | `evidentia_core.oscal.profile._load_oscal_json` + `resolve_profile` |
| `fuzz_oscal_verify.py` | `oscal verify` (AR digests) | `evidentia_core.oscal.verify.verify_digests` |
| `fuzz_ocsf_ingest.py` | `collect ocsf` ingest | `evidentia_collectors.ocsf.collector._convert_ocsf_payload` (→ `finding_from_ocsf` / `finding_from_ocsf_detection`) |
| `fuzz_gap_report.py` | gap-store report loader | `evidentia_core.models.gap.GapAnalysisReport.model_validate_json` |
| `fuzz_tprm_questionnaire.py` | TPRM completed-DDQ ingest | `evidentia_core.tprm.questionnaire.parse_completed_questionnaire` (JSON + CSV sub-parsers) |

> **SARIF note.** Evidentia *emits* SARIF (`gap analyze --format sarif`)
> but has **no SARIF ingest/round-trip parser**, so there is no untrusted
> SARIF parse surface to harness. If a SARIF ingestion collector is added
> later, add a `fuzz_sarif_ingest.py` harness next to these.

## Seed corpora

`corpus/<surface>/` holds minimal valid seed documents that bootstrap
coverage. `build.sh` zips each into `<harness>_seed_corpus.zip` (the
OSS-Fuzz / ClusterFuzzLite auto-unpack convention).

## Run the Hypothesis tests locally

```bash
export PYTHONIOENCODING=utf-8          # Windows cp1252 guard
uv run pytest tests/fuzz/ -q
# wider local search:
HYPOTHESIS_PROFILE=dev uv run pytest tests/fuzz/ -q
```

## Run a single atheris harness locally (Linux only)

```bash
uv pip install atheris
python tests/fuzz/fuzz_catalog_import.py tests/fuzz/corpus/catalog_import/
# bounded run:
python tests/fuzz/fuzz_catalog_import.py -max_total_time=60 tests/fuzz/corpus/catalog_import/
```

## CI

- `.github/workflows/cflite-pr.yml` — PR `code-change` mode (300 s).
- `.github/workflows/cflite-batch.yml` — scheduled `batch` mode (1800 s).

Both are independent of the tag-driven release pipeline (`release.yml`);
fuzzing never gates a release. Corpus/coverage persistence across runs is
optional (a separate storage repo + `PERSONAL_ACCESS_TOKEN`); see the
`cflite-pr.yml` header to enable it.

## Adding a harness

1. Write `fuzz_<surface>.py` following the existing shape
   (`with atheris.instrument_imports(): import <module>`; a
   `TestOneInput(data)` that catches only declared exceptions).
2. Add a `corpus/<surface>/` seed dir.
3. Add a matching `test_<surface>` property test to
   `test_parser_robustness.py`.
4. `build.sh` auto-discovers `fuzz_*.py` — no edit needed.
