"""Evidentia plugin contracts (v0.8.0 P0.4).

Four extension surfaces for out-of-tree authors to ship custom
implementations without forking core:

- ``AuthProvider`` (auth) — pluggable authentication backends for
  ``evidentia serve`` (token files, OAuth, mTLS, etc.)
- ``StorageBackend`` (storage) — pluggable persistence for gap
  reports, collector findings, and audit-relevant records
  (filesystem, S3, IPFS, etc.)
- ``MarketplaceProvider`` (marketplace) — pluggable OSCAL catalog
  providers (local directory, community CDN mirror, IBM
  compliance-trestle registry, organization-private registries)
- ``BaseSaaSCollector`` (collectors) — common SaaS-collector
  scaffolding (auth + httpx client + pagination + error-
  translation) for the v0.7.9 vendor-risk collectors (Vanta /
  Drata / BitSight / SecurityScorecard) and any future SaaS
  collectors. Closes the v0.7.13-cycle M-4 follow-up.

Each contract is an ``abc.ABC`` with abstractmethods that
implementers must provide. The contracts ship with at least
one OSS reference implementation per type (see the ``local_*``
or ``file_backend`` modules under each contract package) so
authors have a working shape to copy.

Discovery is via the ``evidentia.plugins`` entry-point group
in ``importlib.metadata.entry_points``. See ``docs/extending.md``
for the canonical author guide.

The contracts are designed for OSS-justified personas:

- **Community catalog providers** — someone hosts an OSCAL
  catalog mirror (a local-language catalog set, a community
  CDN, etc.) and wants Evidentia users to fetch from it
- **SI partners** — an SI delivery contract needs a private
  storage backend specific to a federal customer's environment
  (e.g., on-prem NFS, AWS GovCloud S3, etc.)
- **Extension authors** — someone maintains an out-of-tree
  collector for a niche cloud and wants the same audit-trail
  + error-translation conventions Evidentia's bundled
  collectors use

The contracts do NOT depend on any commercial-tier vocabulary.
They are designed for OSS-only consumption.
"""

from __future__ import annotations

from evidentia_core.plugins.auth import AuthProvider
from evidentia_core.plugins.collectors import BaseSaaSCollector
from evidentia_core.plugins.marketplace import MarketplaceProvider
from evidentia_core.plugins.storage import StorageBackend

__all__ = [
    "AuthProvider",
    "BaseSaaSCollector",
    "MarketplaceProvider",
    "StorageBackend",
]


def discover_plugins(
    group: str = "evidentia.plugins",
    *,
    of_type: type | None = None,
) -> dict[str, object]:
    """Discover registered plugins via ``importlib.metadata``.

    Args:
        group: The entry-point group to query. Defaults to
            ``evidentia.plugins`` per the Evidentia convention.
        of_type: Optional ABC class to narrow the result. When
            supplied, only entry points whose loaded value is a
            subclass of ``of_type`` are returned. Useful for
            filtering by plugin contract without each caller
            re-implementing the ``isinstance + issubclass``
            check (v0.8.1 F-V08-CR-11 ergonomics fix).

    Returns:
        Mapping of entry-point name → loaded plugin object.
        When ``of_type`` is supplied, the values are guaranteed
        to be subclasses of that type.

    Example:
        Out-of-tree plugin authors register their plugin in their
        package's ``pyproject.toml``::

            [project.entry-points."evidentia.plugins"]
            my-storage = "my_package.my_storage:MyStorageBackend"

        At runtime, Evidentia loads them via::

            from evidentia_core.plugins import (
                discover_plugins,
                StorageBackend,
            )

            # v0.8.0 verbose pattern:
            for name, plugin in discover_plugins().items():
                if isinstance(plugin, type) and issubclass(plugin, StorageBackend):
                    register_storage_backend(name, plugin)

            # v0.8.1+ narrowed pattern:
            for name, cls in discover_plugins(of_type=StorageBackend).items():
                register_storage_backend(name, cls)

    The default behavior is opt-in (callers explicitly invoke
    ``discover_plugins()``); Evidentia's default runtime does
    not auto-discover plugins. This keeps the trust posture
    explicit: operators choose to enable third-party plugins.
    """
    from importlib.metadata import entry_points

    eps = entry_points(group=group)
    loaded = {ep.name: ep.load() for ep in eps}
    if of_type is None:
        return loaded
    # Narrow to subclasses of of_type. Defensive: tolerate
    # entries that aren't classes (factory functions etc.) by
    # silently skipping them — caller asked for "subclasses
    # of X" so non-class entries don't satisfy the request.
    return {
        name: cls
        for name, cls in loaded.items()
        if isinstance(cls, type) and issubclass(cls, of_type)
    }
