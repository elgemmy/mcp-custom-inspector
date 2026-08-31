# Memory

The Memory server is useful for testing structured tool calls. Use a dedicated
temporary graph file so an active test does not modify a real knowledge graph.

The npm commands below track the package name. Pin an exact package version for
a repeatable CI job.

Run safe compatibility checks:

```bash
python3 mcp_probe.py check stdio \
  --protocol-version 2025-06-18 \
  --env MEMORY_FILE_PATH=/tmp/mcp-probe-memory.jsonl \
  -- npx -y @modelcontextprotocol/server-memory
```

Create an entity and then read the graph. These manual raw requests are explicit
active operations and will modify the temporary file:

```bash
python3 mcp_probe.py stdio \
  --protocol-version 2025-06-18 \
  --raw '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"create_entities","arguments":{"entities":[{"name":"MCP_Probe","entityType":"tool","observations":["Used to inspect raw MCP server responses"]}]}}}' \
  --raw '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_graph","arguments":{}}}' \
  --verbose \
  --env MEMORY_FILE_PATH=/tmp/mcp-probe-memory.jsonl \
  -- npx -y @modelcontextprotocol/server-memory
```
