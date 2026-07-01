# Evidentia container image — multi-stage: python:3.13-slim builder ->
# dhi.io/python:3.13 (Docker Hardened Images) distroless runtime.
#
# The runtime is shell-free, curl-free, gpg-free and runs as nonroot uid 65532.
# Air-gap evidence signing uses the binary-free DSSE path (evidentia_core.oscal
# .keysign); Sigstore is online-only; the gpg-EMIT code path fails closed
# (GPGNotAvailableError) since no gpg binary is present. Honest framing: the win
# is post-exploitation attack-surface reduction + a green fixable-rescan gate,
# NOT raw CVE-count.
#
# INSTALL_SOURCE selects the install path (pypi default / local for release.yml);
# see docs/dockerfile-pinning.md. BuildKit only builds stages in the final
# image's graph, so the pypi path never evaluates docker/wheels/.
ARG INSTALL_SOURCE=pypi

# ---- base-builder: slim + venv + install toolchain (has a shell) ------------
FROM python:3.13-slim@sha256:c33f0bc4364a6881bed1ec0cc2665e6c53c87a43e774aaeab88e6f17af105e4f AS base-builder
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
# Output-dir skeleton COPYed into the distroless runtime (an EMPTY dir does not
# survive COPY, so each carries a .keep placeholder).
RUN mkdir -p /build/home/.evidentia /build/home/evidence /build/home/reports /build/home/risks \
    && touch /build/home/.evidentia/.keep /build/home/evidence/.keep \
             /build/home/reports/.keep /build/home/risks/.keep

# ---- deps-pypi (DEFAULT): hash-pinned install from PyPI ----------------------
FROM base-builder AS deps-pypi
COPY docker/requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt

# ---- deps-local: hash-pinned install from locally-built wheels ---------------
FROM base-builder AS deps-local
COPY docker/requirements.txt /tmp/requirements.txt
COPY docker/wheels/ /tmp/wheels/
RUN /opt/venv/bin/pip install --no-cache-dir --require-hashes --find-links /tmp/wheels -r /tmp/requirements.txt

# ---- venv-fix: repoint the venv at DHI's interpreter (/opt/python/bin) -------
# DHI ships python at /opt/python/bin/python (NOT the slim /usr/local/bin/python).
# Console-script shebangs reference /opt/venv/bin/python (the venv symlink), so
# repointing that symlink + pyvenv.cfg is sufficient. (Exact commands proven in
# the Task-2 spike.)
FROM deps-${INSTALL_SOURCE} AS venv-fix
RUN set -eux; \
    rm -f /opt/venv/bin/python /opt/venv/bin/python3 /opt/venv/bin/python3.13; \
    ln -s /opt/python/bin/python /opt/venv/bin/python; \
    ln -s /opt/python/bin/python /opt/venv/bin/python3; \
    ln -s /opt/python/bin/python /opt/venv/bin/python3.13; \
    sed -i \
      -e 's|^home = .*|home = /opt/python/bin|' \
      -e 's|^executable = .*|executable = /opt/python/bin/python|' \
      -e 's|^base-prefix = .*|base-prefix = /opt/python|' \
      -e 's|^base-exec-prefix = .*|base-exec-prefix = /opt/python|' \
      -e 's|^base-executable = .*|base-executable = /opt/python/bin/python|' \
      /opt/venv/pyvenv.cfg

# ---- final: distroless DHI runtime, nonroot uid 65532 -----------------------
FROM dhi.io/python:3.13@sha256:f97073bcfd7f380ad2479fc49371709a345763b10687b5bb4b61bbc9a318bfd9 AS final
COPY --from=venv-fix --chown=65532:65532 /opt/venv /opt/venv
COPY --from=venv-fix --chown=65532:65532 /build/home/ /home/nonroot/
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /home/nonroot
USER 65532

# Build-time validation — EXEC-FORM (no /bin/sh on distroless).
RUN ["/opt/venv/bin/evidentia", "version"]

EXPOSE 8000

# Python healthcheck (no curl on distroless). Must hit /api/health (NOT /health —
# a bare /health falls through to the SPA fallback and 200s falsely; regression
# test: tests/integration/test_api/test_basic_endpoints.py::TestHealth).
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health', timeout=5).status == 200 else 1)"]

ENTRYPOINT ["/opt/venv/bin/evidentia"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]

LABEL org.opencontainers.image.title="Evidentia"
LABEL org.opencontainers.image.description="Open-source GRC infrastructure: OSCAL-native gap analysis, AI risk-statement generation, Sigstore-signed evidence. 82 frameworks bundled."
LABEL org.opencontainers.image.source="https://github.com/polycentric-labs/evidentia"
LABEL org.opencontainers.image.url="https://github.com/polycentric-labs/evidentia"
LABEL org.opencontainers.image.documentation="https://github.com/polycentric-labs/evidentia/blob/main/README.md"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="polycentric-labs"
