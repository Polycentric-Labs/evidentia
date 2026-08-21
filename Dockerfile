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
FROM python:3.13-slim@sha256:ffb752e139c0a19692a43af8d8523b274222dd68eebad5d583b45c2201c6e30a AS base-builder
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

# ---- venv-fix: repoint the venv at DHI's interpreter (/usr/bin) --------------
# DHI ships python at /usr/bin/python with the stdlib at /usr/lib/python3.13
# (NOT the slim /usr/local/bin/python). LAYOUT CHANGE (2026-07): DHI bases
# built through June 2026 carried python under /opt/python/bin; the current
# digests (observed 1842a6b9…, built 2026-07-08) moved it to the standard
# system paths and /opt/python no longer exists — CI-probe-verified via a
# rootfs listing on this exact pinned digest, after the build-time validation
# below failed with `exec /opt/venv/bin/evidentia: no such file or directory`
# (a shebang pointing at the vanished interpreter). Console-script shebangs
# reference /opt/venv/bin/python (the venv symlink), so repointing that
# symlink + pyvenv.cfg is sufficient.
FROM deps-${INSTALL_SOURCE} AS venv-fix
RUN set -eux; \
    rm -f /opt/venv/bin/python /opt/venv/bin/python3 /opt/venv/bin/python3.13; \
    ln -s /usr/bin/python /opt/venv/bin/python; \
    ln -s /usr/bin/python /opt/venv/bin/python3; \
    ln -s /usr/bin/python /opt/venv/bin/python3.13; \
    sed -i \
      -e 's|^home = .*|home = /usr/bin|' \
      -e 's|^executable = .*|executable = /usr/bin/python|' \
      -e 's|^base-prefix = .*|base-prefix = /usr|' \
      -e 's|^base-exec-prefix = .*|base-exec-prefix = /usr|' \
      -e 's|^base-executable = .*|base-executable = /usr/bin/python|' \
      /opt/venv/pyvenv.cfg

# ---- final: distroless DHI runtime, nonroot uid 65532 -----------------------
# Digest bumped 2026-08-20 (v0.12), closing issue #248. The base-freshness
# sentinel reported the pin drifted on 2026-08-18, and post-publish-rescan
# had been failing three consecutive weeks on 7 FIXABLE util-linux
# advisories in the published v0.11.2 image (DEBIAN-CVE-2025-14104,
# -2026-13595, -2026-27456, -2026-53612/-53613/-53614/-53615) — i.e. an
# upstream fix existed and only a rebuild could take it. Reachability is
# low (distroless: no shell, no apt, the Python process never invokes
# these binaries), but SECURITY.md § Supported versions promises the
# latest patch carries no disclosed advisories, so it does not get to sit.
# See docs/releases/reviews/safeguards-resweep-2026-Q3.md § 2.2.
FROM dhi.io/python:3.13@sha256:e512071462b6f002ac3d6f4d31bdf7d20fe6ffce3b5ce4f684b5e50d14dba217 AS final
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
