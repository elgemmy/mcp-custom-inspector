# Declarative scenarios

A scenario is a strict JSON action list for a small, deterministic protocol
experiment. It can establish a session, send high-level or exact messages,
inject malformed wire input, assert the observed outcome, discover paginated
primitives, and disconnect. It is intentionally not a programming language:
there are no variables, substitutions, imports, branches, loops, expressions,
or executable hooks.

Run one over stdio:

```bash
python3 mcp_probe.py scenario stdio \
  --file examples/scenario-discovery.json \
  --protocol-version 2025-06-18 \
  --transcript /tmp/scenario.ndjson \
  -- python3 path/to/server.py
```

For Streamable HTTP, replace `stdio -- SERVER` with
`http --url http://127.0.0.1:3000/mcp`. Transport-specific actions are noted
below.

## Minimal format

The top-level object must contain the exact schema identifier, a non-empty
name, and at least one action:

```json
{
  "schema": "mcp-probe.scenario/v1",
  "name": "legacy discovery and unknown method",
  "description": "Negotiate, inspect tools, then verify JSON-RPC method-not-found.",
  "timeout": 5,
  "actions": [
    {"action": "connect", "establish": true},
    {
      "action": "expect",
      "kind": "result",
      "assertions": [
        {"path": "/result/protocolVersion", "type": "string"}
      ]
    },
    {"action": "request", "method": "tools/list", "params": {}},
    {
      "action": "expect",
      "kind": "result",
      "assertions": [
        {"path": "/result/tools", "type": "array"}
      ]
    },
    {"action": "request", "method": "probe/unknown", "params": {}},
    {"action": "expect", "kind": "error", "code": -32601},
    {"action": "disconnect"}
  ]
}
```

The optional top-level `description` is text. `timeout` is the default timeout
for actions, in seconds; it defaults to `5`, must be positive, and cannot exceed
`3600`. CLI `--timeout` overrides that scenario default, and an action-level
`timeout` is most specific. Files are UTF-8 JSON and limited to 1 MiB. Duplicate
object keys, unknown fields, and wrong JSON types are rejected before the target
starts.

All structured JSON paths reject duplicate object keys and non-finite numbers,
and are limited to depth 100 and 100,000 decoded nodes. These are Probe safety
limits rather than MCP assertions.

`autoRespondServerRequests` defaults to `true`, which enables Probe's small
legacy client handler for `ping`, advertised `roots/list`, malformed-request
`-32600`, not-initialized `-32002`, and unsupported-method `-32601` responses.
Set it to `false` when a legacy scenario must inspect a server request before
choosing, delaying, or omitting the exact client response. In that mode, use an
`exact` action with the server's request ID to send the response; Probe will not
send a canned response first. In `2026-07-28`, server-to-client requests and
client JSON-RPC responses are forbidden; Probe records the request as a failure
and does not reply regardless of this setting.

## Actions

| Action | Fields and behavior |
| --- | --- |
| `start` or `connect` | Optional first action only. `establish` defaults to `false`; when true, it runs initialize/initialized for a legacy profile or `server/discover` for the modern profile. The transport starts implicitly even when this action is omitted. |
| `request` | Requires `method`; optional object `params`. Probe assigns an ID, waits for its correlated response, and adds required 2026-07-28 request metadata when that profile is selected. |
| `notification` | Requires `method`; optional object `params`. `wait` defaults to `false`; use it when the next expectation concerns an immediate stdio observation. |
| `exact` | Requires object `message`. Probe does not add metadata, replace its ID, normalize its fields, or correlate a stdio response by ID. `wait` defaults to `false`; a following expectation consumes the next response in actual arrival order. With `wait: true`, the action eagerly receives and stores a response for that expectation. |
| `malformed` | Requires string `data`. Sends deliberately malformed or unusual wire input using the transport-specific fields below. `wait` defaults to `true`. |
| `expect` | Requires `kind`: `result`, `error`, `timeout`, `serverRequest`, or `close`. It evaluates the immediately preceding observable action. |
| `discover` | Requires `primitive`: `tools`, `resources`, `resourceTemplates`, `prompts`, or `all`. `maxPages` defaults to `100` and must be from `1` through `1000`. Cursors are followed safely. |
| `disconnect` or `terminate` | Optional final action only. Without it, Probe performs an implicit cleanup. Both names perform the same managed shutdown. |

A scenario may contain at most one `start`/`connect`, and it must be first. A
`disconnect`/`terminate` must be last, and an `expect` cannot be first.
Consecutive expectations are allowed: they can consume interleaved server
requests and responses or multiple exact-request responses in observed arrival
order. Attach field assertions to the expectation for the value they inspect.

### Expectations and assertions

`result` expects a JSON-RPC result, while `error` expects a JSON-RPC error. An
error expectation may add integer `code`. `serverRequest` may add `method` to
match a particular server-to-client method. `timeout` and `close` distinguish a
silent wait from stdio EOF/process exit.

An expectation may contain `assertions`. Each assertion has a JSON Pointer in
`path` (the empty string means the root) and exactly one operator:

| Operator | Value |
| --- | --- |
| `equals` | Any JSON value; exact decoded-value comparison |
| `exists` | Boolean |
| `type` | `null`, `boolean`, `integer`, `number`, `string`, `object`, or `array` |
| `length` | Non-negative integer; applies to strings, arrays, and objects |

JSON Pointer escaping follows RFC 6901: `~0` denotes `~` and `~1` denotes `/`.
Assertions run only after the enclosing expectation matches. Each produces its
own `SCENARIO_ASSERTION` finding and evidence reference.

## Exact and malformed input

`exact` sends a decoded JSON object as written. It is the appropriate action for
unusual IDs, incorrect JSON-RPC versions, missing fields, lifecycle order
violations, and notifications that a high-level helper might otherwise
normalize.

For stdio, `malformed.data` is UTF-8 text by default. Set `encoding` to
`base64` to provide arbitrary bytes and use `appendNewline` (default `true`) to
control MCP's line delimiter:

```json
{
  "action": "malformed",
  "encoding": "utf8",
  "data": "{not-json",
  "appendNewline": true,
  "wait": true
}
```

For HTTP, `malformed` sends the string or decoded bytes as the POST body.
`contentType` defaults to `application/json`; optional `headers` is an object of
string names and values. Header names must be RFC field-name tokens; CR/LF and
case-insensitive duplicates are rejected. `appendNewline` has no HTTP effect.
Response status, body, parsing issues, and decoded events remain available as
evidence.

Strict JSON malformed bodies can hide an active `tools/call` from a simple
allow-list check (for example through another character encoding or a
permissive server parser). Probe therefore blocks opaque malformed wire by
default. Add `--allow-opaque-wire` only after reviewing the target and exact
bytes; the report records `SAFETY_OPAQUE_WIRE_OPT_IN`. Strictly decoded JSON
tool calls still require the exact `--allow-tool NAME` independently.
Transport-level headers participate in this decision: a configured non-identity
`Content-Encoding` or non-JSON effective Content-Type makes an HTTP raw action
opaque even when the action itself says `application/json`.

A malformed input experiment may itself violate a client's transport
obligation. Record the observed robustness result, but do not label every
disconnect or parse error from that experiment a normative server violation.

An HTTP `close` expectation is reported as `SKIP`: the current Streamable HTTP
probe observes request/response exchanges, not a stable application-level
socket whose closure has portable meaning.

## Active tool safety

Discovery and the built-in compatibility suite never invoke tools. Any scenario
`request`, `notification`, `exact`, or valid decoded raw body that targets
`tools/call` must provide a literal string `params.name`, then allow that exact
tool name on the command line:

```bash
python3 mcp_probe.py scenario stdio \
  --file examples/scenario-tool-call.json \
  --protocol-version 2025-06-18 \
  --allow-tool fixture_echo \
  -- python3 tests/fixtures/mcp_fixture.py stdio --profile stdio-good-legacy
```

Repeat `--allow-tool NAME` for additional explicitly reviewed tools. Probe does
not infer safety from a name, generate arguments, or execute every discovered
tool. A missing or non-literal name and a missing allow-list entry are
`CONFIG_UNSAFE_ACTION` configuration errors: nothing is sent. An authorized
call produces a `SAFETY_ACTIVE_TOOL_OPT_IN` pass finding, and active steps are
marked `active: true` in the report. Ambiguous malformed text that resembles
`tools/call` is blocked even with an allow-list because Probe cannot verify an
exact target name. Raw ordinary inspection remains an intentionally explicit
wire-control interface; review any `tools/call` payload before sending it.
Automated `connect`/`establish` also rejects custom initialize data or client
capabilities that contain a nested or normalized `tools/call`-like value; put
an authorized call in its own explicit scenario action instead.

## Results and exit behavior

Scenario steps, expectations, assertions, disconnect behavior, and errors are
emitted through the same text, Markdown, or JSON reporting model as built-in
checks. Use `--output json` for stdout JSON and `--report PATH` to retain a JSON
report alongside `--transcript PATH` evidence. A failed expectation or
assertion exits with the compatibility-failure code; invalid scenario syntax or
an unapproved active tool exits with the configuration code; startup and
transport failures remain distinct.
