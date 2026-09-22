# MCP Probe: Core Reference

## 1. What MCP Probe is

A small MCP client that sends exactly the JSON-RPC messages you tell it to, in the order you tell it to, over stdio or Streamable HTTP, and records exactly what came back.

One sentence for the README and the talk:

> MCP Probe runs a *path* (an ordered list of JSON-RPC messages, well-formed or not) against an MCP server, records the transcript, and lets you diff two transcripts. You or your agent compose the path; the probe executes and reports.

The official MCP Inspector (v2, 2026) is an excellent client for well-formed requests: it builds `tools/call` from a schema, handles OAuth, renders MCP Apps, and its CLI is scriptable. What it does not do, by design, is let you put an arbitrary or deliberately broken message on the wire and watch the server's reaction. That is the whole of MCP Probe's job. Happy paths and failure paths are the same mechanism here: a path is just messages, and a message is whatever JSON you wrote.

Agent-first means: the tool has a stable file format in, a stable JSON summary out, and a skill that tells an agent how to turn "check that the server rejects a missing protocolVersion" into a path file, a run, and a reading of the result. The agent generates; the tool executes and compares. The tool never guesses cases on your behalf.

## 2. Scope

In scope (the core):

- Execute a path file against one server over stdio or Streamable HTTP.
- Verbatim sends: what is in the file is what goes on the wire, including malformed JSON-RPC.
- A sugar step for well-formed requests so common paths stay short.
- Record a JSONL transcript per run and print a JSON summary per step.
- Optional per-step expectations (result / error / none / timeout) that flip the exit code.
- Diff two transcripts, aligned by step, ignoring volatile fields.
- Keep the existing ad-hoc mode (`stdio` / `http` subcommands with `--discover`, `--raw`, `--interactive`) unchanged. It is already tested and useful for poking around before writing a path.
- Mask secrets (env values, auth-ish headers) in transcripts and summaries.

Out of scope (write these in the README so nobody, human or agent, drifts back into them):

- Generating test cases from tool schemas. The agent does this using the skill, from `tools/list` output. If a generator ever exists it is a separate script, not part of the probe.
- An assertion language beyond the four outcome expectations. Deeper checks are the agent's job reading the summary, or `jq` on the transcript.
- OAuth, MCP Apps, tasks, subscriptions, sampling, elicitation UI. Server-initiated requests are answered minimally (see 6.4) and logged, nothing more.
- Conformance grading, compatibility matrices, replay engines, redaction frameworks, multi-server orchestration, a web UI, a package on PyPI.
- JSON-RPC batching (removed in 2025-06-18). If you want to test a server's reaction to a batch, put a raw array in a step; the probe will send it and record whatever comes back, but it will not parse batch responses.
- Third-party Python dependencies. Standard library only, Python 3.10+.
- Splitting `mcp_probe.py` into a package. One file until it passes roughly 1,200 lines, and even then only into two or three modules.

## 5. Path file format

```json
{
  "name": "notion-handshake-missing-protocol-version",
  "description": "Server should reject initialize without protocolVersion",
  "server": {
    "stdio": ["npx", "-y", "@notionhq/notion-mcp-server"],
    "env": {"NOTION_TOKEN": "dummy"}
  },
  "handshake": false,
  "timeout": 15,
  "steps": [
    {
      "send": {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"capabilities": {}, "clientInfo": {"name": "mcp-probe", "version": "0.2.0"}}
      },
      "expect": "error"
    }
  ]
}
```

Fields:

- `name` (required): used for the transcript file name and diff headers.
- `description` (optional).
- `server` (required unless overridden on the CLI): exactly one of
  - `{"stdio": [argv...], "env": {...}}`
  - `{"http": "http://127.0.0.1:3000/mcp", "headers": {...}}`
- `handshake` (optional, default `"auto"`):
  - `"auto"`: if no step sends `initialize`, the probe prepends the standard `initialize` (with `LATEST_PROTOCOL_VERSION`, empty capabilities, probe clientInfo) and `notifications/initialized` before step 1. These prepended messages appear in the transcript but are not numbered steps.
  - `false`: send nothing you did not write. Required for testing "call before initialize", broken initialize, or skipping `initialized`.
  - An object: used as the `initialize` params (same shape as today's `--init-file`), followed by `notifications/initialized`.
- `timeout` (optional, seconds, default 15): per-step wait.
- `steps` (required): list of step objects.

Step shapes, exactly two:

1. **Raw step**: `{"send": <any JSON value>}`. Sent verbatim. If `send` is an object with an `id`, the probe waits for the response with that id. If it has no `id`, it is treated as a notification and nothing is awaited. If it is not an object (an array, a string, a number), it is sent as-is and nothing is awaited unless `"wait": true`, in which case the probe waits `timeout` seconds and records whatever arrives.
2. **Sugar step**: `{"method": "tools/call", "params": {...}}`. Expanded into a well-formed request with an auto-assigned id. `"notify": true` makes it a notification. This keeps the ninety percent of paths that are well-formed short, and keeps ids out of the author's way when ids are not the thing under test.

Optional on any step:

- `expect`: one of `"result"`, `"error"`, `"none"`, `"timeout"`. `"none"` means "I sent something and expect no message back within the timeout" and is the same thing as `"timeout"` from the wire's point of view; both names are accepted because one reads naturally for notifications and the other for hangs. When `expect` is set and the outcome differs, the step is marked `ok: false` and the run exits 2. When `expect` is absent, the step is always `ok: true` and you are just recording.
- `wait`: `true` / `false` to override the id-based default. Expectations do not change that default; use `wait: true` when testing notification silence.
- `label`: free text, echoed in the summary so a diff reads well.

There are no variables, references to earlier results, loops, or conditionals. If a step needs a value from an earlier response (a resource URI from `resources/list`, say), the agent runs a discovery path first, reads the summary, and writes the second path. Two runs are cheaper than a template language.

Validation: the probe validates the path shape before starting the server and exits 1 with a one-line reason on any problem. It does not validate the content of `send`; that is the point.

## 6. Run semantics

6.1 Start: launch the stdio process or prepare the HTTP session. For HTTP, `Mcp-Session-Id` and negotiated `MCP-Protocol-Version` are tracked as today.

6.2 Handshake: per `handshake` above.

6.3 Steps run strictly in order. For each step: send, then wait according to the rules in section 5, then classify the outcome:

- `result`: a response with the matching id and a `result` member.
- `error`: a response with the matching id and an `error` member. `error.code` and `error.message` are lifted into the summary.
- `timeout`: nothing with that id arrived within `timeout`.
- `closed`: the server exited or closed the pipe before answering. The stderr tail (last 20 lines, already captured) is attached.
- `sent`: a notification or unawaited raw send that completed without waiting.
- `http:<status>` is attached as a separate field for HTTP runs, alongside the JSON-RPC outcome, because a 4xx with an empty body is a real and common failure shape.

6.4 Server-initiated requests: `ping` gets `{}`, `roots/list` gets `{"roots": []}`, anything else gets `-32601`. Each is recorded as `server-request` and `auto-response` transcript events and counted in the summary's `server_requests` list. No configuration.

6.5 Unmatched messages: responses with unknown ids and notifications from the server are recorded in the transcript and counted in the summary as `unsolicited`. They never fail a run.

6.6 Shutdown: close stdin, wait, SIGTERM, kill, as today. The summary records `server_exit_code` when known.

6.7 Secrets: values of `env` in the path or `--env`, and values of headers whose name matches `authorization`, `cookie`, `proxy-authorization`, or ends with `-token` / `-key` / `-secret` (case-insensitive), are replaced with `"***"` in the transcript and summary. The path file is never rewritten. This is one small function, not a subsystem; it exists so a transcript can go on a slide.

## 7. Transcript and summary

Transcript record (unchanged shape from today's verbose logger, now also written to file):

```json
{"ts":"2026-09-22T20:14:03.117+00:00","direction":"send","transport":"stdio","step":1,"payload":{...}}
{"ts":"...","direction":"recv","transport":"stdio","step":1,"payload":{...}}
{"ts":"...","direction":"stderr","transport":"stdio","payload":"..."}
```

Directions: `send`, `recv`, `recv-invalid` (non-JSON line from the server, kept as text), `stderr`, `server-request`, `auto-response`. HTTP records also carry `status` and masked `headers`. `step` is present on records that belong to a numbered step; handshake records carry `"step": 0`.

Summary (stdout, one object):

```json
{
  "name": "notion-handshake-missing-protocol-version",
  "transport": "stdio",
  "server": {"stdio": ["npx","-y","@notionhq/notion-mcp-server"], "env": {"NOTION_TOKEN": "***"}},
  "started": "2026-09-22T20:14:02.900+00:00",
  "elapsed_ms": 1312,
  "transcript": "runs/notion-handshake-missing-protocol-version-20260922T201402Z.jsonl",
  "steps": [
    {
      "n": 1,
      "label": null,
      "method": "initialize",
      "id": 1,
      "outcome": "error",
      "error": {"code": -32603, "message": "[ { \"expected\": \"string\", ... } ]"},
      "result_keys": null,
      "elapsed_ms": 1098,
      "expect": "error",
      "ok": true
    }
  ],
  "server_requests": [],
  "unsolicited": 0,
  "server_exit_code": 0,
  "ok": true
}
```

Each transcript ends with a `{"summary": {...}}` record containing this same masked summary. It records non-wire facts such as timeouts and shutdown status so `diff` does not need a separate summary file. Wire-event directions remain the six listed above.

`result_keys` is the sorted top-level key list of `result` when the outcome is `result`; the full result lives in the transcript. `method` is lifted from the sent message when it is an object with a `method`, otherwise `null`. That is enough for an agent to decide what to look at next without the summary becoming the transcript.

## 8. diff

`diff A.jsonl B.jsonl` reads the two embedded summaries from the transcripts (so the summary does not have to be saved separately) and compares step by step:

- Aligned by step number. A step present in one run only is reported as `only-in-A` / `only-in-B`.
- Compared fields: `outcome`, `http_status`, `error.code`, `error.message`, `result_keys`, and `server_exit_code` at run level.
- Ignored: timestamps, elapsed times, ids (unless both sides sent the same message and the ids differ, which is noise), transcript paths.
- Output: a text table with one line per differing step and a final `identical` / `N differences` line counting differing steps (plus a run-level difference if the exit code changed); `--json` gives `[{"step": 2, "field": "outcome", "a": "result", "b": "error"}, ...]`. Exit 0 if identical, 2 if different, 1 on usage error.

This is deliberately shallow. Comparing full result bodies belongs to `jq` or the agent, and deep-diffing JSON in a way that is not noisy is a project of its own.

## 9. Exit codes

- `0`: run completed and every step with an `expect` matched (or no expectations were set); `diff` found no differences.
- `1`: usage error, invalid path file, unreadable transcript, server failed to start.
- `2`: run completed but at least one expectation did not match; `diff` found differences.
- `3`: run aborted mid-way because the server closed or the transport failed on a step that expected to keep going. The summary is still printed with the steps that ran.

An agent branches on these; a human reads stderr.
