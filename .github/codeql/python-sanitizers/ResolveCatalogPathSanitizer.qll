/**
 * Custom sanitizer for `evidentia_core.catalogs.user_dir.resolve_catalog_path`.
 *
 * `resolve_catalog_path(framework_id, ...)` maps a framework id to an on-disk
 * catalog path and returns `(path, entry, source)`. For the user-dir branch it
 * resolves the candidate and asserts `resolved.is_relative_to(user_dir)` (a
 * CWE-22 containment guard) before returning the RESOLVED path; the bundled
 * branch returns a path derived from the trusted package manifest. The
 * framework id is only ever used as a dict KEY for the manifest lookup, never
 * concatenated raw into the returned path. The returned path is therefore
 * already containment-checked / trusted, so any flow OUT of this call is safe
 * for `py/path-injection`.
 *
 * This is the query-level fix for alert #164 (`py/path-injection` at
 * `evidentia_core/catalogs/loader.py` `_load_catalog_data` → `read_text`): the
 * loader's path comes from `resolve_catalog_path` via
 * `load_catalog` / `load_any_catalog`, so modeling this call's return as a
 * barrier clears that finding at the analysis layer rather than by per-instance
 * dismissal. It composes with the runtime change that now RETURNS the
 * `is_relative_to`-checked `resolved` path (so CodeQL's built-in guard
 * recognition also sees the barrier).
 *
 * Mirrors `ValidateWithinSanitizer.qll`. v0.10.x engineering follow-up.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.PathInjectionCustomizations
import semmle.python.ApiGraphs

/**
 * The data-flow node for a call to
 * `evidentia_core.catalogs.user_dir.resolve_catalog_path(...)`. Resolved across
 * modules via the API graph (the loader + the API/CLI routers all import it).
 */
private DataFlow::Node resolveCatalogPathCall() {
  result =
    API::moduleImport("evidentia_core")
        .getMember("catalogs")
        .getMember("user_dir")
        .getMember("resolve_catalog_path")
        .getACall()
}

/**
 * Sanitizer for `py/path-injection`: the value returned by
 * `resolve_catalog_path` is a containment-checked / trusted-manifest path.
 */
class ResolveCatalogPathSanitizer extends PathInjection::Sanitizer {
  ResolveCatalogPathSanitizer() { this = resolveCatalogPathCall() }
}
