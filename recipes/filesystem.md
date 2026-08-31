# Filesystem

The Filesystem server is useful for testing practical local tools. Give it a
dedicated temporary directory; do not point an experimental tool call at a
working tree or personal directory.

Prepare a safe test directory:

```bash
mkdir -p /tmp/mcp-probe-fs
printf 'hello from mcp probe
' > /tmp/mcp-probe-fs/hello.txt
```

Run non-mutating discovery and protocol checks:

```bash
python3 mcp_probe.py check stdio \
  --protocol-version 2025-06-18 \
  --transcript /tmp/filesystem.ndjson \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-probe-fs
```

Call selected tools manually. `--raw` is an explicit active operation: inspect
the method, arguments, and allowed directory before running it.

```bash
python3 mcp_probe.py stdio \
  --protocol-version 2025-06-18 \
  --raw '{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"list_allowed_directories","arguments":{}}}' \
  --raw '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"/tmp/mcp-probe-fs/hello.txt"}}}' \
  --verbose \
  -- npx -y @modelcontextprotocol/server-filesystem /tmp/mcp-probe-fs
```
