# Memory

The Memory server is useful for testing structured tool calls.

Discover tools, resources, and prompts:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --discover --verbose --env MEMORY_FILE_PATH=/tmp/mcp-probe-memory.jsonl -- npx -y @modelcontextprotocol/server-memory
```

Create an entity and then read the graph:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --raw '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"create_entities","arguments":{"entities":[{"name":"MCP_Probe","entityType":"tool","observations":["Used to inspect raw MCP server responses"]}]}}}' --raw '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"read_graph","arguments":{}}}' --verbose --env MEMORY_FILE_PATH=/tmp/mcp-probe-memory.jsonl -- npx -y @modelcontextprotocol/server-memory
```
