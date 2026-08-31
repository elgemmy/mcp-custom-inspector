# Generic MCP servers

Inspect a stdio server using an explicit dated profile:

```bash
python3 mcp_probe.py stdio \
  --protocol-version 2025-06-18 \
  --discover \
  -- python3 path/to/server.py
```

Run the safe compatibility suite. This discovers primitives but does not call
tools:

```bash
python3 mcp_probe.py check stdio \
  --protocol-version 2025-06-18 \
  --transcript /tmp/mcp-probe.ndjson \
  --report /tmp/mcp-probe-report.json \
  -- python3 path/to/server.py
```

Compare the same server under selected protocol profiles. Matrix mode launches a
fresh server process for each profile:

```bash
python3 mcp_probe.py matrix stdio \
  --version 2025-06-18 \
  --version 2025-11-25 \
  --version 2026-07-28 \
  --output markdown \
  -- python3 path/to/server.py
```

For a Streamable HTTP endpoint:

```bash
python3 mcp_probe.py check http \
  --url http://127.0.0.1:3000/mcp \
  --protocol-version 2025-11-25 \
  --output json
```

Replay a captured stdio interaction after changing the server. Keep the source
and replay evidence in different files:

```bash
python3 mcp_probe.py replay stdio \
  --from /tmp/mcp-probe.ndjson \
  --protocol-version 2025-06-18 \
  --transcript /tmp/mcp-probe-replay.ndjson \
  -- python3 path/to/fixed_server.py
```

Run the repository's basic declarative scenario against a compatible legacy
server:

```bash
python3 mcp_probe.py scenario stdio \
  --file examples/scenario-discovery.json \
  --protocol-version 2025-06-18 \
  -- python3 path/to/server.py
```

Add server-specific environment variables with repeated `--env KEY=value`
flags for stdio servers, or request headers with repeated
`--header 'Name: Value'` flags for HTTP endpoints. Put all Probe options before
the stdio `--` separator. Credential values are redacted from diagnostics and
saved evidence, but should still be supplied at run time rather than committed.

For modern MCP, select `--protocol-version 2026-07-28`. Probe then uses
`server/discover` and per-request metadata instead of the legacy
initialize/initialized lifecycle.
