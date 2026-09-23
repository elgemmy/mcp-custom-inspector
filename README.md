# MCP Probe

MCP Probe runs a *path* (an ordered list of JSON-RPC messages, well-formed or not) against an MCP server, records the transcript, and lets you diff two transcripts. You or your agent compose the path; the probe executes and reports.

## Why it exists

The [official MCP Inspector](https://github.com/modelcontextprotocol/inspector) provides a guided client for well-formed requests. MCP Probe sends the messages you wrote, including deliberately broken JSON-RPC, so you can see how a server responds. Happy paths and failure paths use the same mechanism.

## Quick start

These paths use the Everything example server and need Node/npm for that server:

```bash
python3 mcp_probe.py run paths/handshake-valid.json
python3 mcp_probe.py run paths/handshake-missing-protocol-version.json
python3 mcp_probe.py diff runs/handshake-valid-*.jsonl runs/handshake-missing-protocol-version-*.jsonl
```

Both runs should exit 0: the first expects a result, the second an error. Diff exits 2 and reports one differing step. After repeated runs, replace the two globs with the exact `transcript` paths printed in the summaries.

## Path format

```json
{
  "name": "missing-protocol-version",
  "server": {"stdio": ["npx", "-y", "@modelcontextprotocol/server-everything"]},
  "handshake": false,
  "timeout": 15,
  "steps": [
    {
      "send": {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
          "capabilities": {},
          "clientInfo": {"name": "mcp-probe", "version": "0.2.0"}
        }
      },
      "expect": "error"
    }
  ]
}
```

Raw `send` accepts any JSON value. The other step shape, `{"method":"tools/list","params":{}}`, supplies JSON-RPC framing and an ID; `notify:true` omits the ID. Optional expectations are exactly `result`, `error`, `none`, and `timeout`. No expectation means record only. Use `wait:true` to observe silence after a notification; `none` and `timeout` both match a timeout. An `expect` object (`outcome`, `result_contains`, `note`) is recorded for a trace reader and never checked.

Automatic handshake is the default unless a step sends initialize. Set `handshake:false` to send only your written sequence, or supply an initialize-params object. A server block can also contain `http` and `headers`. See [SPEC.md](SPEC.md) for the durable format and semantics.

`run --bearer-env NAME` sends a bearer token read from an environment variable, keeping it off the command line. `run --trace PATH` appends a flushed JSONL event per run start, step, and run end, with each call classified as `success`, `tool_error`, `protocol_error`, or `transport_error`; see SPEC.md.

Summaries are JSON on stdout, progress is on stderr, and transcripts stay in gitignored `runs/`. Diff compares step outcomes, HTTP statuses, errors, result keys, and the server exit code. Text output counts differing steps; `--json` lists changed fields. Exit codes are 0 for success, 1 for input/startup errors, 2 for mismatches/differences, and 3 for an aborted run.

## Ad-hoc mode

Explore before writing a path; the existing commands remain available:
```bash
python3 mcp_probe.py stdio --discover --verbose -- npx -y @modelcontextprotocol/server-everything
python3 mcp_probe.py http --url http://127.0.0.1:3000/mcp --discover
```
Use `--raw`, `--init-file`, or stdio `--interactive` for one-off experiments.

## Using it with an agent

The [MCP Probe usage skill](.agents/skills/mcp-probe/SKILL.md) explains how to compose paths, choose failure cases, run target overrides, and read the evidence. Claude Code uses the relative symlink under `.claude/skills/`.

Example prompt: “Write a path that checks whether this server survives a request with no jsonrpc field and can still list tools afterwards.”

The ten files in `paths/` are reusable examples and the verification suite. The skill also shows how to run the missing-version path against Notion with a dummy token; initialize payloads for ad-hoc use remain in `examples/`.

For a worked example against a real server, see [Odoo helpdesk tools over MCP](examples/odoo-helpdesk/README.md).

## Scope and non-goals

One server, an ordered path, exact JSON sends, optional outcome expectations, local transcripts, and a shallow diff. `login` fetches an OAuth token for servers that use dynamic client registration. The client answers server requests minimally and masks supplied env values and auth-like headers in run artifacts. Arbitrary response data can still be private; never commit credentials or unmasked transcripts.

OAuth stops at `login`, which prints an access token; there is no token storage or refresh. There is no test-case generator, assertion language, MCP Apps, tasks, subscriptions, sampling or elicitation workflow, conformance grading, compatibility matrix, replay engine, redaction framework, multi-server orchestration, web UI, or PyPI package. Raw arrays can be sent, but batch responses are not parsed. Full result comparisons belong to the agent or `jq`.

## Requirements

Python 3.10+; standard library only. There is no package setup or Python dependency installation. The target server supplies its own runtime requirements. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for development and verification.

## License

[MIT](LICENSE), copyright 2026 Ahmed Gamal.
