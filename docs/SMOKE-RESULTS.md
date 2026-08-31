# External smoke results

External server smokes are optional and environment-dependent. This file
records what was actually attempted for the compatibility-lab revision; it is
not a claim about those servers' protocol behavior.

## 2026-08-30

The final `check stdio` command was attempted against all requested targets
with npm forced offline because registry network access was unavailable:

```bash
env npm_config_offline=true python3 mcp_probe.py check stdio --protocol-version 2025-11-25 --timeout 5 -- npx -y @modelcontextprotocol/server-everything
env npm_config_offline=true python3 mcp_probe.py check stdio --protocol-version 2025-11-25 --timeout 5 -- npx -y @modelcontextprotocol/server-memory
env npm_config_offline=true python3 mcp_probe.py check stdio --protocol-version 2025-11-25 --timeout 5 -- npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-probe-smoke-filesystem
env npm_config_offline=true python3 mcp_probe.py check stdio --protocol-version 2025-11-25 --timeout 5 --env NOTION_TOKEN=dummy -- npx -y @notionhq/notion-mcp-server
```

All four commands exited `3` because npm exited before an MCP response. Direct
offline package checks established the environmental cause:

| Target | npm result |
| --- | --- |
| `@modelcontextprotocol/server-everything` | `ENOTCACHED`; missing cached `https://registry.npmjs.org/jszip` response |
| `@modelcontextprotocol/server-memory` | `ENOTCACHED`; package metadata not cached |
| `@modelcontextprotocol/server-filesystem` | `ENOTCACHED`; package metadata not cached |
| `@notionhq/notion-mcp-server` | `ENOTCACHED`; package metadata not cached |

No external MCP server process reached initialization, so there is no external
compatibility result to report. The local offline stdio and HTTP fixtures did
complete the full verification gate.
