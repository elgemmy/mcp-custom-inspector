# MCP Probe

MCP Probe is a raw-wire MCP compatibility and debugging laboratory. It is a
small, command-oriented Python client for exact protocol experiments,
especially against stdio servers.

The core uses only the Python 3.11+ standard library. It has no MCP SDK, web
UI, Node runtime, JSON Schema package, or LLM dependency. That is intentional:
messages remain visible, deterministic, scriptable, and reproducible.

| Use | Best tool |
| --- | --- |
| Polished interactive MCP exploration, OAuth, and Apps | Official [MCP Inspector](https://github.com/modelcontextprotocol/inspector) |
| Canonical executable coverage of normative requirements | Official [MCP Conformance](https://github.com/modelcontextprotocol/conformance) |
| Exact messages, lifecycle mutations, stdio faults, transcripts, replay, and dated-version comparisons | MCP Probe |

MCP Probe complements the official tools; it does not calculate a conformance
percentage or replace either one. See [compatibility scope](docs/COMPATIBILITY-SCOPE.md).

## Quick start

Run the offline fixture through the safe compatibility suite:

```bash
python3 mcp_probe.py check stdio --protocol-version 2025-06-18 -- python3 tests/fixtures/mcp_fixture.py stdio --profile stdio-good-legacy
```

The result names every `PASS`, `FAIL`, `WARN`, and `SKIP`, with stable finding
codes and references such as `event:8` when a transcript is enabled. Built-in
checks perform discovery but never call a server tool.

Run all repository-local verification without network access:

```bash
python3 scripts/verify.py
```

## Ordinary inspection

The original low-level inspection commands remain available. Launch a stdio
server, initialize it, discover primitives, and show redacted traffic:

```bash
python3 mcp_probe.py stdio --protocol-version 2025-06-18 --discover --verbose -- python3 path/to/server.py
```

Supply a completely custom initialize payload and deliberately omit the
initialized notification:

```bash
python3 mcp_probe.py stdio --protocol-version 2025-06-18 --init-file examples/init-missing-protocol-version.json --no-initialized --verbose -- python3 path/to/server.py
```

Send an exact decoded JSON-RPC object:

```bash
python3 mcp_probe.py stdio --protocol-version 2025-06-18 --raw '{"jsonrpc":"2.0","id":"probe-99","method":"tools/list","params":{}}' -- python3 path/to/server.py
```

Open the small stdio REPL with `--interactive`. Inside it:

```text
mcp> tools/list {}
mcp> notify notifications/cancelled '{"requestId":10,"reason":"experiment"}'
mcp> raw {"jsonrpc":"2.0","id":10,"method":"probe/unknown","params":{}}
mcp> quit
```

Ordinary inspection treats a JSON-RPC error response as observed protocol data
and normally exits 0. Use `check` or `scenario` when pass/fail semantics and CI
exit codes matter.

## Compatibility checks and JSON reports

Run the non-destructive suite and save both a report and its evidence:

```bash
python3 mcp_probe.py check stdio --protocol-version 2025-11-25 --output json --report /tmp/mcp-report.json --transcript /tmp/mcp-trace.ndjson -- python3 path/to/server.py
```

The JSON report includes the redacted target, requested and negotiated version,
server information, capabilities, discovered primitives, findings, timings,
transport/process errors, transcript event count, and overall result. Markdown
output is also available with `--output markdown`. There is deliberately no
numerical quality score.

Stable process exit categories are:

| Exit | Meaning |
| ---: | --- |
| `0` | No failed compatibility finding; warnings/skips may remain |
| `1` | Compatibility or scenario assertion failure |
| `2` | Invalid configuration/scenario or blocked unsafe action |
| `3` | Startup or transport failure prevented required execution |
| `4` | Internal MCP Probe error |
| `130` | Interrupted (Ctrl-C, SIGTERM, or SIGHUP) |

This supports a tight agent/CI loop: run Probe, inspect finding evidence, fix
the server, and rerun the same command. A minimal CI step needs only Python and
the server under test:

```yaml
- name: Verify MCP compatibility
  run: python3 mcp_probe.py check stdio --protocol-version 2025-11-25 --output json --report mcp-report.json -- python3 server.py
```

## Protocol version matrix

Each process/session in a matrix run is isolated. Stdio defaults to all five
supported revisions; HTTP defaults to the Streamable HTTP revisions:

```bash
python3 mcp_probe.py matrix stdio --output markdown -- python3 path/to/server.py
```

Choose an explicit subset by repeating `--version`:

```bash
python3 mcp_probe.py matrix stdio --version 2025-11-25 --version 2026-07-28 --output json -- python3 path/to/server.py
```

Supported profiles are `2024-11-05`, `2025-03-26`, `2025-06-18`,
`2025-11-25`, and `2026-07-28`. The first four use stateful
initialize/initialized lifecycle behavior. `2026-07-28` uses stateless
per-request metadata and `server/discover`. The deprecated pre-Streamable
HTTP+SSE transport for `2024-11-05` is not implemented.

## Transcripts and replay

Every command can write a redacted NDJSON transcript:

```bash
python3 mcp_probe.py stdio --protocol-version 2025-06-18 --discover --transcript /tmp/original.ndjson -- python3 path/to/server.py
```

After fixing the server, replay only the captured client-originated actions.
Replay preserves IDs, notifications, ordering, lifecycle messages, and valid
raw framing; it does not silently add initialization:

```bash
python3 mcp_probe.py replay stdio --from /tmp/original.ndjson --transcript /tmp/replay.ndjson -- python3 path/to/fixed-server.py
```

Captured credentials and session IDs are never restored. Configure fresh
destination credentials explicitly. A captured `tools/call` is blocked unless
its exact literal name is repeated with `--allow-tool NAME`. Timing replay is
off by default and bounded when `--preserve-timing` is selected. See
[transcripts and replay](docs/TRANSCRIPTS.md).

## Declarative scenarios

Scenarios are strict JSON action lists, not a programming language. They can
connect, send requests/notifications/exact objects, inject malformed wire
input, expect results/errors/timeouts/server requests/close, make small JSON
Pointer assertions, follow discovery pages, and disconnect:

```bash
python3 mcp_probe.py scenario stdio --file examples/scenario-discovery.json --protocol-version 2025-06-18 --transcript /tmp/scenario.ndjson -- python3 path/to/server.py
```

Use scenarios for invalid request objects, lifecycle ordering, duplicate
initialization, unusual IDs, malformed lines/bodies, or precise regression
reproduction. An explicit tool call additionally needs `--allow-tool` with its
exact name. See the complete [scenario format](docs/SCENARIOS.md).

## Streamable HTTP

Inspect a modern endpoint:

```bash
python3 mcp_probe.py http --url http://127.0.0.1:3000/mcp --protocol-version 2026-07-28 --discover --header 'Authorization: Bearer YOUR_TOKEN' --verbose
```

The supported subset covers JSON and SSE responses, multiple SSE events,
protocol/method headers, legacy optional session propagation and termination,
empty successful responses, error statuses, malformed bodies, content types,
timeouts, and redacted authentication headers. It does not implement OAuth or
legacy HTTP+SSE. Redirects are deliberately not followed, so credentials and
session headers are not forwarded to another endpoint. For legacy Streamable
HTTP, Probe surfaces an expired-session `404` but does not automatically
reinitialize and retry the operation. SSE handling is request-scoped: Probe
does not keep an independent long-lived GET/listening stream, and events that
arrive after the correlated POST response are not guaranteed to be retained.
Probe decodes only absent or `identity` response Content-Encoding. Other
encodings remain opaque evidence and fail the required exchange. It also
rejects ambiguous response framing, unsupported transfer codings, and
incomplete declared bodies.

## Safety and redaction

- Automated checks call list/discovery methods only; they never infer that a
  tool is safe from its name.
- Automated lifecycle establishment rejects nested `tools/call`-like data in
  custom initialization and client capability metadata.
- Scenario and replay tool calls require an exact allow-list. Ordinary `--raw`
  remains an intentionally explicit wire interface—review the object yourself.
- Authorization, cookies, API keys/tokens, session IDs, `Mcp-Param-*` argument
  headers, credential-like object keys, URL user information, sensitive query
  values, and secret environment assignments are redacted before verbose
  output, reports, and transcripts.
- Redaction is name-based, not a proof that arbitrary application data is safe
  to share. Never commit real credentials or private server responses.
- Stdio children run in a managed process group and are cleaned up after normal
  completion, timeout, crash, configuration failure, and interruption.
- On POSIX, catchable `SIGTERM` and `SIGHUP` follow the same cleanup path as
  Ctrl-C. `SIGKILL` cannot be intercepted; Windows cleanup is limited to the
  direct child because POSIX process-group signaling is unavailable there.
- Wire input, queues, batches, SSE streams, pagination, structured JSON, and
  retained evidence have deterministic resource caps. Crossing one is an
  operational/configuration failure, never a clean compatibility pass. Exact
  limits are listed in the [compatibility scope](docs/COMPATIBILITY-SCOPE.md)
  and [transcript documentation](docs/TRANSCRIPTS.md).

## External smoke targets

The offline suite does not need npm. Optional commands for the Everything,
Memory, Filesystem, and Notion servers are maintained under [recipes](recipes/).
They use dummy credentials for handshake-only Notion probing and never commit
server output. Package/network availability is environmental, so external
smokes are not part of the local quality gate. See the latest
[recorded smoke attempts](docs/SMOKE-RESULTS.md). The npm examples intentionally
track the package names; pin exact package versions in a repeatable CI job.

## Repository map

- `mcp_probe.py`: stable primary entry point.
- `mcp_probe_core/`: small explicit protocol, transport, scenario, replay,
  checking, transcript, redaction, and reporting modules.
- `tests/fixtures/mcp_fixture.py`: configurable stdio and loopback HTTP fixture.
- `tests/`: standard-library unit and real-boundary integration tests.
- `examples/`: initialize payloads and scenarios.
- `recipes/`: optional real-server commands.
- `docs/BASELINE.md`: behavior and defects recorded before this revision.

Useful command references:

```bash
python3 mcp_probe.py --help
python3 mcp_probe.py stdio --help
python3 mcp_probe.py check stdio --help
python3 mcp_probe.py matrix http --help
python3 mcp_probe.py scenario stdio --help
python3 mcp_probe.py replay stdio --help
```
