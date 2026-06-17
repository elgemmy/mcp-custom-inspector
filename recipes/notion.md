# Notion

The Notion server can be tested through npm.

Valid initialize:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --no-initialized \
  --log transcripts/notion-with-version.jsonl \
  --verbose \
  --env NOTION_TOKEN=dummy \
  -- npx -y @notionhq/notion-mcp-server
```

Missing `protocolVersion`:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-missing-protocol-version.json \
  --no-initialized \
  --log transcripts/notion-without-version.jsonl \
  --verbose \
  --env NOTION_TOKEN=dummy \
  -- npx -y @notionhq/notion-mcp-server
```

This only tests the local MCP handshake. It should not call the Notion API unless you continue past initialization and invoke tools.
