# GitHub

The official GitHub MCP server is commonly run through Docker.

Valid initialize:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --no-initialized \
  --verbose \
  --env GITHUB_PERSONAL_ACCESS_TOKEN=dummy \
  -- docker run -i --rm ghcr.io/github/github-mcp-server
```

Missing `protocolVersion`:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-missing-protocol-version.json \
  --no-initialized \
  --verbose \
  --env GITHUB_PERSONAL_ACCESS_TOKEN=dummy \
  -- docker run -i --rm ghcr.io/github/github-mcp-server
```

If you want to inspect real GitHub tools, use a real token and add `--discover` after the server initializes.
