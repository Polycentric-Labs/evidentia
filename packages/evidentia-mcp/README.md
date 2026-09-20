# evidentia-mcp

Model Context Protocol server for Evidentia. It exposes 15 tools for catalog reads, gap analysis, continuous monitoring, local evidence ingestion and artifact verification.

## Quick start

```bash
pip install evidentia[mcp]
evidentia mcp doctor
evidentia mcp serve
```

The default transport is stdio. HTTP and SSE are also supported. For bind settings, client configuration and scope registries, see [MCP client setup](../../docs/wiki/2-guides/mcp-client-setup.md).

## Tool surface

| Tool | Purpose |
|---|---|
| `list_frameworks` | List catalog metadata |
| `get_control` | Read one catalog control |
| `gap_analyze` | Analyze a local inventory |
| `gap_diff` | Compare gap reports |
| `conmon_list_cadences` | List continuous-monitoring cadences |
| `conmon_next_due` | Calculate a cadence due date |
| `conmon_check_state` | Read cadence state |
| `conmon_health` | Report cadence health |
| `gap_analyze_sarif` | Emit gap results as SARIF |
| `collect_ocsf` | Ingest a local OCSF file |
| `tprm_vendor_list` | List local vendor records |
| `poam_list` | List local POA&M records |
| `verify_signed_artifact` | Verify an Evidentia signed artifact |
| `conmon_series` | Read a cadence evidence series |
| `get_catalog_native` | Read a validated native catalog bundle at an exact digest |

The [generated tool reference](../../docs/wiki/4-reference/mcp-tools.md) records signatures. Existing tool names and schemas retain the [append-only contract](../../docs/api-stability.md#mcp-tool-contract).

## Scope and source handling

`get_catalog_native` requires a configured CIMD registry and an explicit literal grant for that tool. Missing registries and wildcard grants do not authorize it. Its only arguments are `framework_id` and `bundle_sha256`; it cannot import, download or accept a source path. A stale digest returns a fixed tool error. Default registry migration does not add the new grant.

The existing fourteen tools keep their established no-registry behavior. With a registry, identity and scope checks run before handlers and signing. CIMD scope metadata is not client authentication; use the documented authenticated transport boundary for remote access. File-taking tools remain restricted by `--allow-root`.

Optional signed outputs bind the delivered payload under the existing envelope. Check the signature and the documented envelope limits before trusting an output. Credentials are not accepted in tool arguments.

## License

Apache-2.0. See the workspace root LICENSE file. Native source documents retain their own notices and terms.
