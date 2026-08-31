# Notion

The Notion server can be launched through npm. The commands below use a dummy
token and stop at protocol initialization; they are not API tests.

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
credentials only at run time. Probe will not call the Notion API unless you
continue past initialization and invoke an operation that does so.
