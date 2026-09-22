---
name: mcp-probe
description: Compose, run, and compare MCP Probe paths to test how an MCP server responds to well-formed and malformed JSON-RPC. Use when the user wants to check a server's protocol behaviour, reproduce a handshake or tool-call issue, or compare two servers or builds.
---

# MCP Probe

Run commands from the repository root. Use the single `mcp_probe.py` entry point.

## Discover or compose

Use ad-hoc mode when you do not yet know the server's tools:

```bash
python3 mcp_probe.py stdio --discover --verbose -- npx -y @modelcontextprotocol/server-everything
```

Keep all probe flags before the final `--`; the server command follows it.
Use `--raw` for a one-off exact JSON-RPC object, `--init-file` for a custom handshake,
or `--interactive` to explore. Move a repeatable experiment into a path.

## Path essentials

A JSON object has `name`, `server`, and `steps`; `description` is optional.
`name` becomes the transcript filename: use kebab-case (letters, digits, `.`, `_`, `-`).
`server` is either `{"stdio":["command","arg"],"env":{"TOKEN":"dummy"}}`
or `{"http":"http://127.0.0.1:3000/mcp","headers":{}}`.
`timeout` is per step, defaults to 15 seconds, and may be overridden on the CLI.

`handshake` defaults to `"auto"`: prepend initialize/initialized only if no step
sends initialize. Use `false` for an exact sequence, including broken or omitted
initialization. An object supplies initialize params and is followed by initialized.

Exactly two step shapes:

- `{"send": <any JSON value>}` sends that value unchanged, including invalid JSON-RPC.
- `{"method":"tools/list","params":{}}` adds jsonrpc and an unused ID.
  Add `"notify":true` to omit the ID.

Optional `label` is echoed in the summary. `wait` overrides waiting: by default,
objects with an ID wait for that response; everything else is an unawaited send.
For a non-object payload, `wait:true` observes the next message.
An optional `expect` accepts only `result`, `error`, `none`, or `timeout`.
`none` and `timeout` both match silence; set `wait:true` on notifications when testing silence.
Without `expect`, the outcome is recorded without an assertion.
There are no variables, references, loops, conditions, or additional assertions.
If you need a URI from discovery, read that run and write a second path with the literal URI.

## Turn intent into steps

| Intent | Path shape |
| --- | --- |
| Does it reject X? | One broken request with `expect:error` |
| What happens if X? | One step with no expectation |
| Does it survive X? | Broken step, then `tools/list` with `expect:result` |
| Is build B the same as A? | One path, two target overrides, one diff |

Failure patterns to choose from:

- Missing required field; wrong type.
- Unknown method; unknown protocol version.
- Request before initialize; duplicate initialized notification.
- Missing jsonrpc field; non-object payload with `wait:true`.
- Oversized string argument; unknown tool name; empty tool arguments.

## Run and compare

```bash
python3 mcp_probe.py run paths/discover.json
python3 mcp_probe.py run paths/discover.json --server-cmd -- python3 /path/to/build-a.py
python3 mcp_probe.py run paths/discover.json --server-cmd -- python3 /path/to/build-b.py
python3 mcp_probe.py diff RUN_A.jsonl RUN_B.jsonl
```

Capture the exit code explicitly (`python3 mcp_probe.py run ...; echo "rc=$?"`) and
report the number you saw, never one inferred from the summary.
Use the actual `transcript` paths from the summaries. Place run flags before
`--server-cmd --`; everything after it belongs to the server.
`--url`, repeated `--env K=V`, and repeated `--header 'N: V'` override the target.
`--out DIR` changes the transcript directory; `--quiet` suppresses step lines.
Stdout is a single JSON summary; progress goes to stderr.

The original Notion handshake experiment uses the same missing-version path:

```bash
python3 mcp_probe.py run paths/handshake-missing-protocol-version.json --env NOTION_TOKEN=dummy --server-cmd -- npx -y @notionhq/notion-mcp-server
```

## Read the result

Check `ok`, then each step's `outcome` and `error.code`.
Outcomes are `result`, `error`, `timeout`, `closed`, and `sent`.
HTTP also supplies `http_status`; a bodyless HTTP error need not be a JSON-RPC error.
`result_keys` lists top-level result keys; the full result is in the transcript.
Open only the transcript events needed for the relevant step and quote those lines
back to the user rather than paraphrasing protocol evidence.
The final `{"summary":...}` transcript record lets diff work without a separate summary file.

Exit codes: 0 expectations matched, 1 invalid input/startup failure,
2 expectation mismatch or differing runs, 3 aborted transport/server failure.
An absent expectation does not turn an aborted run into a successful run.
Text diff groups changes by step; `--json` lists individual changed fields.
It compares outcomes, HTTP statuses, errors, result keys, and server exit codes.
It ignores IDs, timings, transcript paths, and full result bodies.

## Safety and saving paths

Use dummy tokens for handshake tests. Never run write-capable tools against real
accounts without saying so and checking that the action is within the user's request.
Transcripts under `runs/` are local and gitignored. Env values and auth-like headers
are masked, but arbitrary response content can still be private.
Save new paths under `paths/` only when reusable and token-free; otherwise use a
named scratch file and tell the user where it is. Never commit real credentials.
