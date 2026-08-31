# Everything

The Everything server is a useful optional smoke target because it exposes
tools, resources, and prompts. Installing or running it requires Node and npm;
it is not part of the offline verification suite.

Inspect a known legacy profile:

```bash
python3 mcp_probe.py stdio \
  --protocol-version 2025-06-18 \
  --discover \
  --verbose \
  -- npx -y @modelcontextprotocol/server-everything
```

Run safe checks and retain redacted evidence:

```bash
python3 mcp_probe.py check stdio \
  --protocol-version 2025-06-18 \
  --transcript /tmp/everything.ndjson \
  --report /tmp/everything-report.json \
  -- npx -y @modelcontextprotocol/server-everything
```

Compare lifecycle eras without assuming the server supports all of them:

```bash
python3 mcp_probe.py matrix stdio \
  --version 2025-06-18 \
  --version 2025-11-25 \
  --version 2026-07-28 \
  -- npx -y @modelcontextprotocol/server-everything
```

Send a custom initialize message with the required `protocolVersion` omitted:

```bash
python3 mcp_probe.py stdio \
  --protocol-version 2025-06-18 \
  --init-file examples/init-missing-protocol-version.json \
  --no-initialized \
  --verbose \
  -- npx -y @modelcontextprotocol/server-everything
```

The compatibility suite never invokes the Everything server's tools. Use a
manual `--raw` request or an explicitly permitted scenario if a tool call is
actually part of the experiment.
