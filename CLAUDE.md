# Agent guide

MCP Probe is a standard-library-only raw-wire MCP compatibility laboratory.
Keep it command-oriented, deterministic, transparent, and safe by default. It
complements the official Inspector and Conformance suite; do not turn it into a
web UI, SDK wrapper, LLM tool, or full schema validator.

## Project shape

- `mcp_probe.py` is the stable primary entry point.
- `mcp_probe_core/` contains small explicit modules for protocol profiles,
  transports, lifecycle sessions, redaction, transcripts, reports, checks,
  scenarios, replay, matrix behavior, and CLI parsing.
- `tests/fixtures/mcp_fixture.py` is the configurable real stdio/HTTP fixture.
- `tests/` uses only `unittest`; integration tests cross subprocess pipes and
  loopback HTTP sockets.
- `examples/`, `recipes/`, and `docs/` contain reviewed user-facing inputs and
  commands. Never add credentials or private responses.

Do not add third-party Python dependencies or packaging ceremony. Preserve
exact decoded JSON-RPC and malformed-wire escape hatches; high-level helpers
must never make them inaccessible.

## Required verification

Run the complete offline gate after a change:

```bash
python3 scripts/verify.py
```

The underlying test command is:

```bash
python3 -m unittest discover -s tests -v
```

Also inspect command help when changing CLI behavior:

```bash
python3 mcp_probe.py --help
python3 mcp_probe.py stdio --help
python3 mcp_probe.py http --help
python3 mcp_probe.py check stdio --help
python3 mcp_probe.py matrix stdio --help
python3 mcp_probe.py scenario stdio --help
python3 mcp_probe.py replay stdio --help
```

External npm servers are optional smoke targets and must not become an offline
test dependency.

## Behavioral contracts

- Protocol profiles are explicit dated revisions. Do not apply one era's
  lifecycle, headers, or request semantics to another.
- Raw traffic and compatibility evidence must be recorded before normalization.
- Redaction occurs before every persistent or diagnostic sink. Treat
  authorization, cookies, API keys, session IDs, `Mcp-Param-*`, credential-like
  JSON keys, URLs, command arguments, and environment values conservatively.
- Built-in checks are non-destructive and never call tools. Scenario/replay
  `tools/call` actions require an exact literal allow-list.
- Findings use registered stable codes, an explicit normative/heuristic/
  operational basis, and transcript evidence whenever an interaction exists.
- Preserve exit codes: 0 clean, 1 compatibility failure, 2 configuration or
  unsafe action, 3 transport/startup failure, 4 internal error, 130 interrupt.
- Cleanup must be idempotent and reliable after success, crash, timeout,
  configuration errors, and Ctrl-C. Do not leave subprocess groups behind.
- Reports and transcripts must never expose secret values or overwrite an input
  file through a path collision.

## Command shape

Put Probe flags before the final `--`, and put a stdio server command after it:

```bash
python3 mcp_probe.py check stdio --protocol-version 2025-11-25 --output json -- python3 server.py
```

For HTTP, use the nested transport leaf:

```bash
python3 mcp_probe.py check http --url http://127.0.0.1:3000/mcp --protocol-version 2026-07-28
```

Use dummy tokens for handshake-only smoke tests. Never infer that a tool is
safe from its name, and never automatically invoke every discovered tool.
