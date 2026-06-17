# Filesystem

The Filesystem server is useful for testing practical local tools against a safe temporary directory.

Prepare a safe test directory:

```bash
mkdir -p /tmp/mcp-probe-fs
printf 'hello from mcp probe
' > /tmp/mcp-probe-fs/hello.txt
```

Discover tools, resources, and prompts:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --discover --verbose -- npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-probe-fs
```

Call real filesystem tools:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --raw '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"list_allowed_directories","arguments":{}}}' --raw '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/tmp/mcp-probe-fs/hello.txt"}}}' --verbose -- npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-probe-fs
```
