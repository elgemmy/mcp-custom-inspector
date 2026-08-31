# Notion

The Notion server can be launched through npm. The commands below use a dummy
token and send only protocol initialization; they do not invoke a tool. The
third-party server may still validate credentials during startup or
initialization, so these are not Notion API safety guarantees.

The npm commands below track the package name. Pin an exact package version for
a repeatable CI job.

Valid initialize with the initialized notification deliberately omitted:

```bash
python3 mcp_probe.py stdio \
  --protocol-version 2025-06-18 \
  --no-initialized \
  --verbose \
  --env NOTION_TOKEN=dummy \
  -- npx -y @notionhq/notion-mcp-server
```

Missing `protocolVersion`:

```bash
python3 mcp_probe.py stdio \
  --protocol-version 2025-06-18 \
  --init-file examples/init-missing-protocol-version.json \
  --no-initialized \
  --verbose \
  --env NOTION_TOKEN=dummy \
  -- npx -y @notionhq/notion-mcp-server
```

Do not put a real token in a recipe, transcript, report, shell-history example,
or committed environment file. If you deliberately perform a live test, supply
credentials only at run time. These commands intentionally invoke no MCP tool.
