# Evidentia container image (v0.7.3 P2 B2).
#
# Single-stage Debian-slim Python 3.12 image. Installs evidentia +
# the bundled web UI (`[gui]` extra) from PyPI as a non-root user.
# Runs `evidentia serve` on port 8000 by default; override via
# `docker run` arguments to use the CLI subcommands instead.
#
# Build:
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
# CI builds the image on every PR touching the Dockerfile (smoke
# test only — not published) per `.github/workflows/container-build.yml`.
# Publishing to `ghcr.io/polycentric-labs/evidentia` is gated to a future
# release that explicitly opts in.

FROM python:3.14-slim@sha256:c845af9399020c7e562969a13689e929074a10fd057acd1b1fad06a2fb068e97

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
# `--create-home` so pip's --user install has a home directory to
# land in; mkdir of common output paths so volume mounts attach
# cleanly.
RUN useradd --create-home --uid 1000 --shell /bin/bash evidentia \
    && mkdir -p /home/evidentia/.evidentia \
                /home/evidentia/evidence \
                /home/evidentia/reports \
                /home/evidentia/risks \
    && chown -R evidentia:evidentia /home/evidentia

USER evidentia
WORKDIR /home/evidentia

# Install evidentia from PyPI in the user site so we don't fight
# the system Python. The `[gui]` extra pulls in evidentia-api so
# `evidentia serve` works out of the box; ~50 MB extra for the
# bundled SPA + FastAPI deps.
#
# v0.8.4 G4 Path 2 ACTIVATED: hash-pinned install via
# `pip install --require-hashes -r /tmp/requirements.txt`. The
# `docker/requirements.txt` file is REGENERATED at release-time
# by release.yml's "Regenerate hash-pinned requirements.txt
# against PyPI" step, which runs AFTER Wait-for-PyPI-propagation
# but BEFORE this docker build. The release-time regeneration:
#
#   1. Overwrites docker/requirements.in to pin
#      evidentia[gui]==<version> for the just-published release.
#   2. Runs pip-compile --generate-hashes --no-emit-find-links
#      against PyPI's just-published wheels, computing SHA256
#      hashes FROM PyPI's actual bytes.
#   3. The docker build then runs `pip install --require-hashes`
#      against the freshly-regenerated requirements.txt; pip
#      downloads the same PyPI bytes + verifies the hashes match.
#
# Path 2 doesn't have the v0.8.3 Path 1 cross-platform
# reproducibility issue (Windows local vs Linux CI build wheel
# bytes diverged) because both pip-compile + pip install run in
# the same Linux runner against the same PyPI bytes. Hashes
# match by construction.
#
# The committed `docker/requirements.txt` ships as preview state
# (operators can inspect it pre-tag). The release-time
# regenerated file is what actually gets baked into the
# container; the committed file is overwritten ephemerally
# inside the workflow filesystem.
#
# Closes the recurring Scorecard PinnedDependencies false-
# positive cycle (alerts #100 → #116 across v0.7.12 → v0.8.3.1)
# structurally + permanently. Future releases get
# PinnedDependencies score 10/10 without per-cycle dismissals.
COPY docker/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir --user --require-hashes -r /tmp/requirements.txt

# Put the user-installed `evidentia` entrypoint on PATH.
ENV PATH="/home/evidentia/.local/bin:${PATH}"

# Cosmetic: friendlier Python defaults inside the container.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Default web-UI port matches the FastAPI server's default.
EXPOSE 8000

# Validate the install at build time so a broken image fails fast.
# Note: `evidentia version` is a SUBCOMMAND (not a `--version` flag) —
# the Typer-driven CLI registers `version` alongside `init`, `doctor`,
# `serve`, `gap`, `catalog`, `risk`, `explain`, `integrations`,
# `collect`, `oscal`. Using `--version` here errors with "No such
# option: --version Did you mean --verbose?".
RUN evidentia version

# Health check: hit the FastAPI server's /api/health endpoint. Honors
# both the default port (8000) and the typical CMD override pattern.
# Note: must be /api/health (not /health) — the health router is mounted
# under the /api prefix in evidentia_api.app:create_app. A bare /health
# request silently falls through to the SPA fallback handler and
# returns index.html with 200 (a false-positive health pass). The
# regression test for this path lives in
# tests/integration/test_api/test_basic_endpoints.py::TestHealth.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -fsS http://localhost:8000/api/health || exit 1

# Default command starts the web UI. Override with any other
# evidentia subcommand:
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
