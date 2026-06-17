# Generic MCP Servers

For npm-based servers:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --discover \
  --log transcripts/server-discovery.jsonl \
  --verbose \
  -- npx -y package-name
```

For Docker-based servers:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --discover \
  --log transcripts/server-discovery.jsonl \
  --verbose \
  -- docker run -i --rm image-name
```

For Streamable HTTP endpoints:

```bash
python3 mcp_probe.py http \
  --url http://127.0.0.1:3000/mcp \
  --init-file examples/init-valid.json \
  --discover \
  --log transcripts/http-server.jsonl \
  --verbose
```

Add server-specific environment variables with repeated `--env KEY=value` flags for stdio servers, or repeated `--header 'Name: Value'` flags for HTTP endpoints.
