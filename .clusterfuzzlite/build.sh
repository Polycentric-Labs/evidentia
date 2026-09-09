#!/bin/bash -eu
# ClusterFuzzLite / OSS-Fuzz build script for Evidentia's atheris harnesses.
#
# Installs the Evidentia packages the harnesses import, then compiles each
# tests/fuzz/fuzz_*.py harness into a self-contained fuzzer with
# `compile_python_fuzzer` (provided by the OSS-Fuzz Python base image —
# it wraps PyInstaller + atheris and emits an $OUT/<name> executable).
#
# Ref: https://google.github.io/clusterfuzzlite/build-integration/python-lang/

# ── Install the harnessed packages ───────────────────────────────────────
# pip-install (not uv) so the OSS-Fuzz build env resolves cleanly. The
# harnesses import evidentia_core (catalogs/oscal/ocsf/gap/tprm),
# evidentia_collectors (ocsf collector), pydantic, pyyaml, and — for the
# OCSF mapping path — the optional [ocsf] extra (py-ocsf-models).
# --ignore-requires-python: the base image ships Python 3.11, but the workspace
# declares requires-python >=3.12 as a runtime floor. Harness-reached modules
# must remain importable on 3.11; the preflight below checks each one before
# packaging. atheris is built against the base interpreter, so do not replace
# it independently of the fuzzing toolchain.
pip3 install --ignore-requires-python \
  "$SRC/evidentia/packages/evidentia-core[ocsf]" \
  "$SRC/evidentia/packages/evidentia-collectors"

# ── Compile each harness ─────────────────────────────────────────────────
# $PYFUZZ_DIR holds the harnesses + the shared _harness_util.py. Building
# from that directory keeps the `from _harness_util import to_text` import
# resolvable (PyInstaller bundles sibling modules on the build path).
PYFUZZ_DIR="$SRC/evidentia/tests/fuzz"
cd "$PYFUZZ_DIR"

for harness in fuzz_*.py; do
  name="${harness%.py}"
  # Import the actual harness before freezing it. PyInstaller can omit a module
  # with unsupported syntax and report only a missing module at startup.
  # The alternate run name leaves the harness main function uncalled.
  python3 -c "import runpy, sys; runpy.run_path(sys.argv[1], run_name='__fuzz_build_import__')" \
    "$PYFUZZ_DIR/$harness"
  # --add-data bundles the shared _harness_util.py into each fuzzer. The
  # harnesses do `from _harness_util import to_text`, but compile_python_fuzzer
  # runs PyInstaller from a temp copy of the script, so the sibling module is
  # not on the analysis path and was NOT bundled — every fuzzer then crashed at
  # startup with `ModuleNotFoundError: No module named '_harness_util'`.
  # Shipping it as data at the bundle root (extracted onto sys.path at runtime)
  # makes the import resolve in the frozen fuzzer.
  # --collect-data bundles every non-Python DATA file of the harnessed
  # packages (the catalog YAMLs in evidentia_core/catalogs/data, OSCAL/OCSF
  # data, etc.). PyInstaller bundles modules, not package data, by default —
  # so the catalog/oscal harnesses crashed with
  # FileNotFoundError: .../evidentia_core/catalogs/data/frameworks.yaml.
  compile_python_fuzzer "$PYFUZZ_DIR/$harness" \
    --add-data "$PYFUZZ_DIR/_harness_util.py:." \
    --collect-data evidentia_core \
    --collect-data evidentia_collectors

  # Map harness file -> seed-corpus subdir (drop the fuzz_ prefix).
  corpus_subdir="${name#fuzz_}"
  if [ -d "$PYFUZZ_DIR/corpus/$corpus_subdir" ]; then
    # OSS-Fuzz / ClusterFuzzLite convention: <fuzzer>_seed_corpus.zip
    # placed next to the fuzzer in $OUT is auto-unpacked as the seed corpus.
    zip -j "$OUT/${name}_seed_corpus.zip" \
      "$PYFUZZ_DIR/corpus/$corpus_subdir"/* >/dev/null
  fi
done
