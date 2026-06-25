# ClusterFuzzLite build image for Evidentia's atheris fuzz harnesses.
#
# Based on the OSS-Fuzz Python base-builder, which ships clang +
# atheris + the `compile_python_fuzzer` helper used by build.sh. The
# SAME image + harnesses graduate to OSS-Fuzz later (the OSS-Fuzz
# project Dockerfile is this file with a `git clone` instead of COPY).
#
# Ref: https://google.github.io/clusterfuzzlite/build-integration/python-lang/
FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:bb4b09f7376cd0f2188344e8b293428b8d2ee54c81b596fa0ef1cd7f8b29d1a1

# Digest-pinned (OpenSSF Scorecard Pinned-Dependencies). base-builder-python
# ships Python 3.11; Evidentia declares requires-python >=3.12, so build.sh
# installs with --ignore-requires-python (every harness-reached module imports
# clean on 3.11 — the only 3.12-syntax files, plugins/storage/*, are unreached
# by the six harnesses). atheris is compiled against the base's 3.11, so we
# deliberately do NOT swap the interpreter. Bump this digest on a cadence —
# OSS-Fuzz rebuilds the base frequently and a stale pin drifts behind the
# toolchain CFLite expects.

# Copy the whole repo into $SRC/evidentia (ClusterFuzzLite mounts the
# checkout here at build time).
COPY . $SRC/evidentia
WORKDIR $SRC/evidentia
COPY .clusterfuzzlite/build.sh $SRC/build.sh
