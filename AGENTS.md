# Agent Guide

This repo is a small MCP probe for sending controlled JSON-RPC requests to MCP servers. Keep it simple and command-oriented.

## Project Shape

- `mcp_probe.py` is the single Python CLI entry point.
- `examples/` contains reusable initialize payloads.
- `recipes/` contains hand-run examples for tested local flows.
- There is no package manager setup and no third-party Python dependency list.

Keep the tool lean: prefer printed output, tested npm/local recipes, and small explicit helpers unless the user explicitly asks for more.

## Core Commands

Check the CLI:

```bash
python3 mcp_probe.py --help
python3 mcp_probe.py stdio --help
python3 mcp_probe.py http --help
```

Run a syntax check after editing Python:

```bash
python3 -m py_compile mcp_probe.py
```

Run a basic npm stdio discovery smoke test:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --discover --verbose -- npx -y @modelcontextprotocol/server-everything
```

Test a missing `protocolVersion` initialize payload:

```bash
python3 mcp_probe.py stdio --init-file examples/init-missing-protocol-version.json --no-initialized --verbose -- npx -y @modelcontextprotocol/server-everything
```

Test Notion initialize behavior without calling real Notion tools:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --no-initialized --verbose --env NOTION_TOKEN=dummy -- npx -y @notionhq/notion-mcp-server
```

Call a tool with a raw JSON-RPC request:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --raw '{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}' --verbose -- npx -y package-name
```

## Command Generation Rules

When generating commands for users:

- Put all `mcp_probe.py` flags before the final `--`.
- Put the MCP server command after the final `--`.
- Prefer one-line commands to avoid shell continuation mistakes.
- Use `--verbose` when the user wants raw send/receive visibility.
- Use dummy tokens for handshake-only tests.
- Use real tokens only when the user intentionally wants authenticated tool/resource inspection.
- Keep raw JSON-RPC objects valid JSON, usually single-quoted at the shell level.

Good shape:

```bash
python3 mcp_probe.py stdio --init-file examples/init-valid.json --discover --verbose -- npx -y package-name
```

Bad shape:

```bash
python3 mcp_probe.py stdio -- npx -y package-name --discover
```

## Tested Local Recipes

Prefer these examples when asked for runnable flows:

- `recipes/notion.md`: initialize compatibility check against Notion.
- `recipes/everything.md`: discovery against the MCP Everything test server.
- `recipes/memory.md`: discovery and structured tool calls.
- `recipes/filesystem.md`: safe local filesystem tool calls.
- `recipes/generic.md`: generic npm stdio and HTTP templates.

## Editing Guidance

- Keep `mcp_probe.py` dependency-free and standard-library only.
- Use small explicit JSON-RPC helpers rather than broad abstractions.
- Add new payload examples under `examples/` when they represent reusable scenarios.
- Add or update a recipe when a new server flow is tested by hand.
- Do not commit real API tokens, bearer tokens, private endpoints, or sensitive response data.

## Commit Style

Use short imperative commit subjects, for example:

```text
Add filesystem recipe
Simplify initialize handling
```
