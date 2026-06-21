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
pip3 install \
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
  compile_python_fuzzer "$PYFUZZ_DIR/$harness"

  # Map harness file -> seed-corpus subdir (drop the fuzz_ prefix).
  corpus_subdir="${name#fuzz_}"
  if [ -d "$PYFUZZ_DIR/corpus/$corpus_subdir" ]; then
    # OSS-Fuzz / ClusterFuzzLite convention: <fuzzer>_seed_corpus.zip
    # placed next to the fuzzer in $OUT is auto-unpacked as the seed corpus.
    zip -j "$OUT/${name}_seed_corpus.zip" \
      "$PYFUZZ_DIR/corpus/$corpus_subdir"/* >/dev/null
  fi
done
