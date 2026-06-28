/**
 * Custom sanitizer for `evidentia_api.routers.catalog._validate_framework_id`.
 *
 * `_validate_framework_id(framework_id)` rejects any id that is not a kebab-case
 * token matching `^[a-z0-9][a-z0-9._-]{0,127}$` and contains no `..`, then
 * RETURNS the validated id. Callers reassign
 * (`framework_id = _validate_framework_id(framework_id)`), so the validated
 * value — not the raw request value — flows into the
 * `user_dir / f"{framework_id}.json"` write path. A returned-value validator is
 * a sanitizing transform CodeQL can model, mirroring
 * `validate_within` / `ValidateWithinSanitizer`.
 *
 * Modeling note (honest): `_validate_framework_id` is module-private and is
 * called intra-module (within `catalog.py`), so for those callsites CodeQL's
 * *intra-procedural* analysis is what recognizes the barrier — it reads the
 * regex + `..` rejection directly on the value the function returns. This API-
 * graph entry additionally models any *cross-module* use (e.g. a test importing
 * the helper) and documents the contract in committed config (the
 * "encode systemic false positives in config, never one-off clicks" rule).
 * The companion `ResolveCatalogPathSanitizer` covers the read-back / loader
 * path (alert #164), where the value comes from the user manifest.
 *
 * v0.10.x engineering follow-up.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.PathInjectionCustomizations
import semmle.python.ApiGraphs

/**
 * The data-flow node for a call to
 * `evidentia_api.routers.catalog._validate_framework_id(...)`.
 */
private DataFlow::Node validateFrameworkIdCall() {
  result =
    API::moduleImport("evidentia_api")
        .getMember("routers")
        .getMember("catalog")
        .getMember("_validate_framework_id")
        .getACall()
}

/**
 * Sanitizer for `py/path-injection`: the value returned by
 * `_validate_framework_id` is a shape-validated framework id that cannot
 * contain path separators or `..`.
 */
class FrameworkIdSanitizer extends PathInjection::Sanitizer {
  FrameworkIdSanitizer() { this = validateFrameworkIdCall() }
}
