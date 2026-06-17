# Generic MCP Servers

For npm-based stdio servers:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --discover --verbose -- npx -y package-name
```

For Streamable HTTP endpoints:

```bash
python3 mcp_probe.py http --url http://127.0.0.1:3000/mcp --init-file examples/init-valid.json --discover --verbose
```

Add server-specific environment variables with repeated `--env KEY=value` flags for stdio servers, or repeated `--header 'Name: Value'` flags for HTTP endpoints.
