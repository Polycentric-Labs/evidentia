# ClusterFuzzLite build image for Evidentia's atheris fuzz harnesses.
#
# Based on the OSS-Fuzz Python base-builder, which ships clang +
# atheris + the `compile_python_fuzzer` helper used by build.sh. The
# SAME image + harnesses graduate to OSS-Fuzz later (the OSS-Fuzz
# project Dockerfile is this file with a `git clone` instead of COPY).
#
# Ref: https://google.github.io/clusterfuzzlite/build-integration/python-lang/
FROM gcr.io/oss-fuzz-base/base-builder-python

# Evidentia targets Python 3.12 (root pyproject: requires-python >=3.12).
# base-builder-python provides a recent Python + pip; the harnesses only
# rely on stdlib + the project packages + pydantic, so no extra apt deps
# are required.

# Copy the whole repo into $SRC/evidentia (ClusterFuzzLite mounts the
# checkout here at build time).
COPY . $SRC/evidentia
WORKDIR $SRC/evidentia
COPY .clusterfuzzlite/build.sh $SRC/build.sh
