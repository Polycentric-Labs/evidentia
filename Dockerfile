# Evidentia container image (v0.7.3 P2 B2; multi-stage as of v0.10.14).
#
# Debian-slim Python 3.13 image. Installs evidentia + the bundled web UI
# (`[gui]` extra) as a non-root user and runs `evidentia serve` on port
# 8000 by default; override via `docker run` arguments to use the CLI
# subcommands instead.
#
# Build (operator, from PyPI):
#   docker build -t evidentia:dev .
#
# Run the web UI:
#   docker run --rm -p 8000:8000 evidentia:dev
#
# Run a CLI command:
#   docker run --rm -v "$PWD":/work -w /work evidentia:dev gap analyze \
#       --inventory my-controls.yaml \
#       --frameworks nist-800-53-rev5-moderate \
#       --output report.json
#
# CI builds the image on every PR touching the Dockerfile (smoke test
# only — not published) per `.github/workflows/container-build.yml`.
# Publishing to `ghcr.io/polycentric-labs/evidentia` happens in
# release.yml at tag time.

# ---------------------------------------------------------------------------
# INSTALL_SOURCE — selects how evidentia is installed into the image:
#
#   pypi  (DEFAULT) — hash-pinned install of evidentia[gui]==X.Y.Z from PyPI.
#                     This is the path an operator's `docker build .` and the
#                     container-build.yml PR smoke test use, and the path
#                     OpenSSF Scorecard's Pinned-Dependencies check scans.
#   local           — hash-pinned install from the wheels in docker/wheels/.
#                     release.yml's `build` job copies the just-built dist/*.whl
#                     into docker/wheels/, regenerates docker/requirements.txt
#                     against those local wheels (+ PyPI transitives, all
#                     hashed), and builds with `--build-arg INSTALL_SOURCE=local`
#                     so the RELEASED image is validated from the EXACT wheels
#                     BEFORE they are published to PyPI. This is the atomic-
#                     release fix (v0.10.14): it kills both the post-publish
#                     container-build-failure class (v0.10.12 shipped PyPI-only
#                     when the container build failed AFTER publish) and the
#                     evidentia-eval PyPI-propagation race (the image no longer
#                     waits on / resolves the just-published version from PyPI).
#
# WHY MULTI-STAGE: BuildKit only builds the stages in the selected final
# image's dependency graph. In pypi mode the final image is FROM deps-pypi, so
# the deps-local stage — and its `COPY docker/wheels/` — is NEVER evaluated. A
# clean checkout therefore needs NO docker/wheels/ directory at all, and the
# `.gitignore` `wheels/` rule that would otherwise swallow a committed wheels
# dir is a non-issue. (An earlier single-`COPY` design would have failed every
# clean-clone `docker build .` because docker/wheels/ does not exist on disk.)
# ---------------------------------------------------------------------------
ARG INSTALL_SOURCE=pypi

# ---- base: OS packages + non-root user, shared by both install paths -------
# Python 3.13 (NOT 3.14): the AI stack (litellm) declares requires-python
# <3.14, so a 3.14 base caps the resolver at litellm 1.83.7 — the only
# 3.14-installable release, and the one carrying CVE-2026-40217 (HIGH); the fix
# and every later patch require <3.14. On 3.13 the container resolves the same
# CVE-clean set the library's uv.lock pins (litellm 1.88.1, aiohttp 3.14.x,
# python-dotenv 1.2.2).
FROM python:3.13-slim@sha256:c33f0bc4364a6881bed1ec0cc2665e6c53c87a43e774aaeab88e6f17af105e4f AS base

# System dependencies kept minimal:
# - ca-certificates for HTTPS (PyPI, OSCAL catalog mirrors, Sigstore)
# - curl for the HEALTHCHECK below
# - gpg for the optional GPG-signed evidence path (air-gap)
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gpg \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (uid 1000 — the conventional first non-system user).
# `--create-home` so pip's --user install has a home directory to land in;
# mkdir of common output paths so volume mounts attach cleanly.
RUN useradd --create-home --uid 1000 --shell /bin/bash evidentia \
    && mkdir -p /home/evidentia/.evidentia \
                /home/evidentia/evidence \
                /home/evidentia/reports \
                /home/evidentia/risks \
    && chown -R evidentia:evidentia /home/evidentia

USER evidentia
WORKDIR /home/evidentia

# Put the user-installed `evidentia` entrypoint on PATH + friendlier Python
# defaults. Set in `base` so both deps stages + the final image inherit them.
ENV PATH="/home/evidentia/.local/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# ---- deps-pypi (DEFAULT): hash-pinned install from PyPI --------------------
# The `[gui]` extra pulls in evidentia-api so `evidentia serve` works out of
# the box. docker/requirements.txt is the hash-pinned closure; container-build.yml
# regenerates it against PyPI's just-published wheels before its smoke build,
# and release.yml regenerates it from local wheels for the deps-local path. The
# committed file ships as preview state operators can inspect.
#
# Closes the recurring Scorecard PinnedDependencies false-positive cycle
# structurally: `--require-hashes` means every byte installed is pinned.
FROM base AS deps-pypi
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --user --require-hashes -r /tmp/requirements.txt

# ---- deps-local: hash-pinned install from the locally-built wheels ---------
# release.yml's `build` job populates docker/wheels/ with the just-built
# dist/*.whl and regenerates docker/requirements.txt with
# `pip-compile --generate-hashes --find-links docker/wheels` so the evidentia-*
# hashes are the LOCAL wheel bytes while transitive third-party deps resolve +
# hash from PyPI. `--require-hashes --find-links /tmp/wheels` then installs the
# evidentia wheels from the local dir (hash-matched) and the transitives from
# PyPI (hash-matched). `--find-links` is passed on the install command line, NOT
# emitted into requirements.txt (pip-compile runs with --no-emit-find-links), so
# the requirements file carries no machine-specific path.
FROM base AS deps-local
COPY docker/requirements.txt /tmp/requirements.txt
COPY docker/wheels/ /tmp/wheels/
RUN pip install --no-cache-dir --user --require-hashes --find-links /tmp/wheels -r /tmp/requirements.txt

# ---- final: select the install path by build-arg, add runtime config -------
FROM deps-${INSTALL_SOURCE} AS final

# Validate the install at build time so a broken image fails fast.
# Note: `evidentia version` is a SUBCOMMAND (not a `--version` flag) — the
# Typer-driven CLI registers `version` alongside `init`, `doctor`, `serve`,
# `gap`, `catalog`, `risk`, `explain`, `integrations`, `collect`, `oscal`.
# Using `--version` here errors with "No such option: --version".
RUN evidentia version

# Default web-UI port matches the FastAPI server's default.
EXPOSE 8000

# Health check: hit the FastAPI server's /api/health endpoint. Honors both the
# default port (8000) and the typical CMD override pattern. Note: must be
# /api/health (not /health) — the health router is mounted under the /api prefix
# in evidentia_api.app:create_app. A bare /health request silently falls through
# to the SPA fallback handler and returns index.html with 200 (a false-positive
# health pass). The regression test for this path lives in
# tests/integration/test_api/test_basic_endpoints.py::TestHealth.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

# Default command starts the web UI. Override with any other evidentia
# subcommand:
#   docker run --rm evidentia:dev gap analyze --inventory ...
ENTRYPOINT ["evidentia"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]

# OCI image labels for downstream registries + tooling.
LABEL org.opencontainers.image.title="Evidentia"
LABEL org.opencontainers.image.description="Open-source GRC infrastructure: OSCAL-native gap analysis, AI risk-statement generation, Sigstore-signed evidence. 82 frameworks bundled."
LABEL org.opencontainers.image.source="https://github.com/polycentric-labs/evidentia"
LABEL org.opencontainers.image.url="https://github.com/polycentric-labs/evidentia"
LABEL org.opencontainers.image.documentation="https://github.com/polycentric-labs/evidentia/blob/main/README.md"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="polycentric-labs"
