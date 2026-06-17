# MCP Probe

A tiny MCP client for sending custom JSON-RPC requests to MCP servers and logging the exact responses.

The official MCP Inspector is excellent for normal interactive testing, but it does not expose full control over the `initialize` payload. This tool is for protocol-level checks, demos, and compatibility evidence.

It is intentionally small: one Python script, no third-party Python dependencies.

## What It Does

- Launches stdio MCP servers, such as npm or Docker based servers.
- Sends a custom `initialize` request from a JSON file or inline JSON.
- Optionally sends `notifications/initialized`.
- Sends raw JSON-RPC objects with `--raw`.
- Can run simple discovery calls: `tools/list`, `resources/list`, and `prompts/list`.
- Logs every send/receive event as JSONL for evidence.
- Includes basic Streamable HTTP probing for HTTP MCP endpoints.

This is not built on top of MCP Inspector. It is a small MCP client/probe.

## Quick Start

Run from this repository:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --no-initialized \
  --log transcripts/notion-with-version.jsonl \
  --verbose \
  --env NOTION_TOKEN=dummy \
  -- npx -y @notionhq/notion-mcp-server
```

Then run the same server with a deliberately invalid initialize payload:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-missing-protocol-version.json \
  --no-initialized \
  --log transcripts/notion-without-version.jsonl \
  --verbose \
  --env NOTION_TOKEN=dummy \
  -- npx -y @notionhq/notion-mcp-server
```

Compare the transcripts:

```bash
cat transcripts/notion-with-version.jsonl
cat transcripts/notion-without-version.jsonl
```

The first run should show a successful `initialize` response with a `result`. The second run should show a JSON-RPC `error` response if the server enforces the required `protocolVersion`.

## Example Payloads

- `examples/init-valid.json`: minimal valid initialize params.
- `examples/init-missing-protocol-version.json`: initialize params missing `protocolVersion`.
- `examples/init-custom-client-capabilities.json`: example with non-empty client capabilities.

`--init-file` accepts either an initialize params object:

```json
{
  "protocolVersion": "2025-06-18",
  "capabilities": {},
  "clientInfo": {
    "name": "mcp-compat-probe",
    "version": "0.1.0"
  }
}
```

Or a full JSON-RPC initialize request object:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "initialize",
  "params": {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {
      "name": "mcp-compat-probe",
      "version": "0.1.0"
    }
  }
}
```

## Common Usage

List tools, resources, and prompts after initialization:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --discover \
  --log transcripts/server-discovery.jsonl \
  --verbose \
  -- npx -y package-name
```

Send a raw JSON-RPC request:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --raw '{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}' \
  --log transcripts/raw-tools-list.jsonl \
  --verbose \
  -- npx -y package-name
```

Open a small interactive prompt after initialization:

```bash
python3 mcp_probe.py stdio \
  --init-file examples/init-valid.json \
  --interactive \
  -- npx -y package-name
```

Inside interactive mode:

```text
mcp> tools/list {}
mcp> resources/list {}
mcp> raw {"jsonrpc":"2.0","id":10,"method":"prompts/list","params":{}}
mcp> quit
```

## HTTP Endpoint Example

For Streamable HTTP servers:

```bash
python3 mcp_probe.py http \
  --url http://127.0.0.1:3000/mcp \
  --init-file examples/init-valid.json \
  --discover \
  --header 'Authorization: Bearer YOUR_TOKEN' \
  --log transcripts/http-server.jsonl \
  --verbose
```

## Asking an Agent for a Command

This repo works well with coding agents. Ask the agent for a command like:

```text
Generate an mcp_probe.py command that launches the GitHub MCP server and sends examples/init-missing-protocol-version.json as the initialize payload. Include any required env vars as --env placeholders and write logs under transcripts/.
```

Then review the generated command before running it, especially any tokens or shell arguments.

## Notes

- `transcripts/*.jsonl` is gitignored by default because logs may contain local paths, tokens, server output, or tool responses.
- Use dummy tokens when only testing the MCP handshake.
- Use real tokens only when you intentionally want to inspect authenticated tools or resources.
