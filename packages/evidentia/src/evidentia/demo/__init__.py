"""Tier-1 constrained-runner for the public demo suite.

Part of the three-tier demo suite (``docs/demo-suite-design.md`` §5). The
public Tier-1 demo lets anonymous users drive the *real* ``evidentia`` CLI
in an ephemeral container — but only through this argv-allowlist runner,
never a raw shell.

The runner enforces the threat-model's first non-negotiable condition: the
only executable reachable in the demo profile is :func:`run`, which validates
``argv`` against a fixed allowlist of network-free, fixture-only verbs
(:func:`is_allowed`), scrubs the environment to a tiny essentials set with
forced offline mode (:func:`scrub_env`), and execs ``evidentia --offline
<argv>`` with no shell, no ``-c``/``-m``, and no user-controlled env.

The remaining four conditions (default-deny egress, empty-credential startup
assertion, resource caps + read-only rootfs + TTL, and building FROM the
cosign-verified signed release digest) are the *host's* responsibility and are
documented as the run contract in ``docker/Dockerfile.demo``.

The allowed argv vectors live alongside this module in ``allowlist.yaml`` and
are resolved at runtime via ``importlib.resources``.
"""

from __future__ import annotations
