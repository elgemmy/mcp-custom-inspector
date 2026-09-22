# MCP Probe: Scoped Core Spec

Status: proposed, one-night scope
Target: `mcp_probe.py` on `main` (657 lines, stdlib only). The `feat/compatibility-lab` branch is not the base.

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

## 3. Concepts

- **Path**: a JSON file describing one server target and an ordered list of steps. It is the unit you compose. Reviewing a path is reviewing the exact protocol sequence that will be sent.
- **Step**: one message to send, plus how to wait for it and optionally what outcome you expect.
- **Run**: one execution of a path against a server. Produces a transcript and a summary.
- **Transcript**: JSONL, one record per wire event (send, recv, recv-invalid, stderr, server-request, auto-response). Already what `--verbose` prints today; now it also goes to a file.
- **Summary**: one JSON object on stdout with per-step outcomes. This is what an agent reads.
- **Diff**: a comparison of two summaries (or the summaries embedded in two transcripts), aligned by step index.

## 4. CLI surface

```
python3 mcp_probe.py run  PATH.json [--out DIR] [--server-cmd -- CMD...] [--url URL] [--env K=V]... [--header 'N: V']... [--timeout S] [--quiet]
python3 mcp_probe.py diff RUN_A.jsonl RUN_B.jsonl [--json]
python3 mcp_probe.py stdio ...   (unchanged)
python3 mcp_probe.py http  ...   (unchanged)
```

`run`:
- `--out` defaults to `runs/`. Transcript file name: `<path name>-<UTC timestamp>.jsonl`. The summary's `transcript` field holds the file path so an agent can find it.
- `--server-cmd`, `--url`, `--env`, `--header` override the path's `server` block. This is how one path file runs against two builds of the same server (local vs published, branch A vs branch B) for a diff.
- Summary goes to stdout as a single JSON object. Human-readable step lines go to stderr unless `--quiet`. Keeping stdout pure JSON is what makes `| jq` and agent parsing reliable.

`diff`:
- Text table by default, `--json` for a machine-readable list of differences.

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
- `wait`: `true` / `false` to override the id-based default.
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

`result_keys` is the sorted top-level key list of `result` when the outcome is `result`; the full result lives in the transcript. `method` is lifted from the sent message when it is an object with a `method`, otherwise `null`. That is enough for an agent to decide what to look at next without the summary becoming the transcript.

## 8. diff

`diff A.jsonl B.jsonl` rebuilds the two step summaries from the transcripts (so the summary does not have to be saved separately) and compares step by step:

- Aligned by step number. A step present in one run only is reported as `only-in-A` / `only-in-B`.
- Compared fields: `outcome`, `http_status`, `error.code`, `error.message`, `result_keys`, and `server_exit_code` at run level.
- Ignored: timestamps, elapsed times, ids (unless both sides sent the same message and the ids differ, which is noise), transcript paths.
- Output: a text table with one line per differing step and a final `identical` / `N differences` line; `--json` gives `[{"step": 2, "field": "outcome", "a": "result", "b": "error"}, ...]`. Exit 0 if identical, 2 if different, 1 on usage error.

This is deliberately shallow. Comparing full result bodies belongs to `jq` or the agent, and deep-diffing JSON in a way that is not noisy is a project of its own.

## 9. Exit codes

- `0`: run completed and every step with an `expect` matched (or no expectations were set); `diff` found no differences.
- `1`: usage error, invalid path file, unreadable transcript, server failed to start.
- `2`: run completed but at least one expectation did not match; `diff` found differences.
- `3`: run aborted mid-way because the server closed or the transport failed on a step that expected to keep going. The summary is still printed with the steps that ran.

An agent branches on these; a human reads stderr.

## 10. Repository layout after the night

```
mcp_probe.py              the tool (stdlib, ~900 lines after run/diff)
paths/                    curated, runnable path files (see 10.1)
examples/                 initialize payloads for ad-hoc mode (unchanged)
runs/                     transcripts, gitignored except .gitkeep
.agents/skills/mcp-probe/SKILL.md      usage skill (Codex and other .agents readers)
.claude/skills/mcp-probe  -> symlink to ../../.agents/skills/mcp-probe   (Claude Code)
AGENTS.md                 for agents developing the tool
CLAUDE.md                 single line: @AGENTS.md
README.md
CONTRIBUTING.md
LICENSE                   MIT
SPEC.md                   this document, trimmed to the parts that stay true
```

Removed: `recipes/` (its content becomes path files plus two README paragraphs), `transcripts/` (renamed to `runs/`), `__pycache__` was never meant to be there.

10.1 Curated paths, all runnable against `@modelcontextprotocol/server-everything` with no token unless stated:

- `handshake-valid.json`: initialize with all fields, expect result.
- `handshake-missing-protocol-version.json`: expect error. Second variant targets Notion with a dummy token, since that was the original motivating case.
- `handshake-unknown-protocol-version.json`: `"protocolVersion": "1999-01-01"`, record only.
- `call-before-initialize.json`: `handshake: false`, `tools/list` first, record only.
- `discover.json`: auto handshake, `tools/list`, `resources/list`, `prompts/list`, all expect result.
- `unknown-method.json`: `foo/bar`, expect error.
- `tool-call-missing-required-arg.json`: `tools/call` on `echo` with `{}`, record only (servers differ on `-32602` vs `isError`, which is the interesting bit).
- `malformed-json-rpc.json`: raw send of `{"id": 5, "method": "tools/list"}` with no `jsonrpc` field, `wait: true`, record only.
- `notification-then-request.json`: `notifications/initialized` sent twice, then `tools/list`, expect result.

Nine files, each under 30 lines. They double as the test suite (section 12) and as the demo material.

10.2 AGENTS.md (developer-facing). Contents, in this order: what the project is in three sentences; the scope list from section 2 verbatim (in and out); the layout; how to verify a change (`py_compile`, run `paths/discover.json` and `paths/handshake-missing-protocol-version.json` against the everything server, run `diff` on two runs); editing rules (stdlib only, 3.10+, one file, small explicit helpers, no batch parsing, never commit tokens or unmasked transcripts); commit style. Explicitly: "If a change adds more than ~150 lines to `mcp_probe.py`, stop and ask whether it belongs in a separate script or not at all."

10.3 CLAUDE.md: exactly `@AGENTS.md`. Claude Code expands the import; no duplication to drift.

10.4 The usage skill, `.agents/skills/mcp-probe/SKILL.md`. Frontmatter: name `mcp-probe`, description "Compose, run, and compare MCP Probe paths to test how an MCP server responds to well-formed and malformed JSON-RPC. Use when the user wants to check a server's protocol behaviour, reproduce a handshake or tool-call issue, or compare two servers or builds." Body:

- When to use ad-hoc mode (`stdio --discover`) versus writing a path: discover first if you do not know the server's tools.
- The path format, compressed to the essentials (server block, handshake, the two step shapes, expect values).
- How to turn an intent into steps. A short table: "does it reject X" becomes one step with `expect: error`; "what happens if" becomes a step with no expect; "does it survive" becomes the malformed step followed by a well-formed `tools/list` with `expect: result`; "is build B the same as A" becomes one path, two runs with `--server-cmd` overrides, one diff.
- Failure-path patterns worth reaching for, as a list the agent can pick from: missing required field, wrong type, unknown method, unknown protocol version, request before initialize, duplicate `initialized`, missing `jsonrpc`, non-object payload, oversized string argument, unknown tool name, tool call with empty args. This is the "generation" the user asked about: it lives in the skill as a checklist, not in the tool as code.
- How to read the summary: check `ok`, then per step `outcome` and `error.code`; open the transcript only for the steps that need it; quote transcript lines back to the user rather than paraphrasing.
- Safety: dummy tokens for handshake tests; never run write-capable tools against real accounts without saying so; transcripts under `runs/` are local and gitignored.
- Where to save new paths: `paths/` only if reusable and token-free; otherwise a scratch file the agent names and mentions.

Under 120 lines. The skill is the only place usage instructions live; README links to it for agent use.

10.5 README. Sections: the one-sentence description; why it exists (the Inspector sends well-formed requests; this sends yours); quick start (three commands: run a valid handshake, run the broken one, diff them); the path format with one full example; ad-hoc mode in five lines; using it with an agent (point at the skill, one example prompt); scope and non-goals (section 2, shortened); requirements; license. Under 150 lines.

10.6 CONTRIBUTING.md. Ten lines: open an issue before a feature; PRs under 300 lines of diff; stdlib only; every new behaviour gets a path file under `paths/` that demonstrates it; no new subcommands without updating the skill and README; run the verification commands from AGENTS.md.

10.7 LICENSE: MIT, your name, 2026.

## 11. The Codex branch

Close the PR. Keep the branch for a week as reference, then delete it. Two ideas from it survive in spirit: the action-list scenario format (here: paths, with two step shapes instead of ten action types) and the "no variables, no branches" principle. Nothing from the branch is merged as code; the 27k lines are the cost of asking for hardening without a scope guard, and section 2 plus the AGENTS.md line about 150-line changes is the guard.

Before starting, commit the currently uncommitted diff on `main` (stderr tail, clearer JSON errors, safer shutdown) as its own commit: "Harden error reporting and shutdown". It is good work and it is independent of the night's plan.

## 12. Night plan, in order

Each item is one commit. Sizes are lines of change in `mcp_probe.py` unless noted.

1. Commit the pending hardening diff. (0 new)
2. Docs skeleton: `CLAUDE.md` becomes `@AGENTS.md`; rewrite `AGENTS.md` per 10.2; add `LICENSE`, `CONTRIBUTING.md`; rename `transcripts/` to `runs/` and update `.gitignore`. (docs only)
3. Transcript-to-file writer: extend `Logger` with an optional file sink and `step` field. Masking function for env and headers applied at the sink. (~60)
4. Path loader and validator, handshake resolution, step expansion (sugar to raw). (~90)
5. `run` subcommand reusing `StdioMcpProbe` / `HttpMcpProbe`: execute steps, classify outcomes, build summary, exit codes. (~120)
6. Nine curated paths under `paths/`, verified by running each against the everything server. (json only)
7. `diff` subcommand. (~80)
8. Skill file and symlink. (docs only)
9. README rewrite; delete `recipes/`. (docs only)
10. Bump `LATEST_PROTOCOL_VERSION` to `2025-11-25`; the 2026-07-28 era is not chased. (1 line)
11. Trim this SPEC.md to sections 1, 2, 5, 6, 7, 8, 9 as the durable reference; the plan sections go.

Total new code: roughly 350 lines. If step 5 alone passes 150 lines, that is the signal to simplify the outcome model, not to split the file.

Verification is the curated paths: after step 7, `run` on every file in `paths/` exits as its `expect` fields predict, and `diff` between `handshake-valid` and `handshake-missing-protocol-version` runs reports exactly one difference on step 1. There is no pytest suite in the core; the paths are the tests, and they are also the docs and the demo.

## 13. Talk demo (two minutes)

1. `python3 mcp_probe.py stdio --discover -- npx -y @modelcontextprotocol/server-everything`, to show it is a normal client.
2. `cat paths/handshake-missing-protocol-version.json`, to show the path is the exact wire sequence and readable in one screen.
3. `python3 mcp_probe.py run paths/handshake-valid.json` then `run paths/handshake-missing-protocol-version.json`, showing the two summaries.
4. `python3 mcp_probe.py diff runs/handshake-valid-*.jsonl runs/handshake-missing-*.jsonl`, one line of difference.
5. Ask the agent in the terminal: "write a path that checks whether this server survives a request with no jsonrpc field and can still list tools afterwards", let it produce and run it. That is the agent-first claim, demonstrated rather than described.

## 14. Decisions and why

- **Single file, stdlib.** The tool's value is that anyone can read the whole thing and trust what goes on the wire. A package with fifteen modules cannot be reviewed on a slide.
- **JSON paths, not YAML or a DSL.** Stdlib parses JSON; agents write JSON reliably; the file is the literal payload, so there is no translation step to doubt.
- **Two step shapes only.** Raw covers every failure case by construction. Sugar covers the well-formed majority. A third shape is where the DSL starts.
- **The agent generates, the tool executes.** A schema-driven fuzzer would be a real feature, but it is a second tool with its own scope creep. Putting the failure-pattern checklist in the skill gets most of the value for zero code and keeps the human in the loop on what is being sent.
- **Expectations are four words, not a language.** `result / error / none / timeout` is enough to make a run pass or fail in CI and to make a diff meaningful. Anything finer is a `jq` expression against the transcript.
- **Shallow diff.** Outcome and error code are what change between servers and builds. Deep JSON diffs drown that signal in ordering and timestamp noise.
- **Ad-hoc mode stays.** It works, it is tested, and it is how you find out what to put in a path.
- **Summary on stdout, prose on stderr.** The one convention that makes a CLI agent-friendly without any other work.
