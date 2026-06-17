# Everything

The Everything server is a good smoke test because it exposes tools, resources, and prompts.

Discover server capabilities:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --discover --verbose -- npx -y @modelcontextprotocol/server-everything
```

Test missing `protocolVersion`:

```bash
python3 mcp_probe.py stdio --init-file examples/init-missing-protocol-version.json --no-initialized --verbose -- npx -y @modelcontextprotocol/server-everything
```
