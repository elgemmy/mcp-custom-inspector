# Protocol transcripts

MCP Probe transcripts are append-only NDJSON evidence streams. Each non-empty
line is one JSON object with schema identifier
`mcp-probe.transcript.event/v1`. NDJSON keeps a partial run readable when a
server crashes or the probe is interrupted and lets agents process large traces
one event at a time.

Use `--transcript PATH` on an inspection, compatibility check, matrix,
scenario, or replay run. The file is securely created or truncated at the start
of that run.

## Event model

Every event has these stable fields:

| Field | Meaning |
| --- | --- |
| `schema` | `mcp-probe.transcript.event/v1` |
| `seq` | Contiguous, 1-based integer sequence within the run |
| `time` | UTC timestamp for human correlation |
| `elapsedMs` | Relative monotonic time from recorder creation |
| `direction` | Such as `client_to_server`, `server_to_client`, `server_stderr`, or `probe` |
| `transport` | `stdio` or `http` |
| `classification` | JSON-RPC request, response, notification, raw wire, transport event, or parse/error event |

Applicable events also include `id`, `method`, decoded `payload`, displayed
`raw` data, `httpStatus`, relevant HTTP `headers`, a sanitized `url`, error
text, SSE metadata, timeout information, or subprocess exit and cleanup data.
Optional fields are omitted rather than set to `null`.

Compatibility report evidence uses `event:N` to identify event number `N`.
Some report entries add a JSON Pointer into that event's decoded payload. The
sequence number, rather than the wall-clock timestamp, is the stable join key.

Example shape (values abbreviated):

```json
{"schema":"mcp-probe.transcript.event/v1","seq":4,"time":"2026-08-30T12:00:00.000+00:00","elapsedMs":8.417,"direction":"server_to_client","transport":"stdio","classification":"response","id":1,"payload":{"jsonrpc":"2.0","id":1,"result":{}}}
```

## Storage and limits

Probe retains at most 10,000 transcript events and 64 MiB of encoded evidence
per run, in memory and on disk. Crossing either cap writes one `capture_limit`
marker when space permits, becomes a transport failure (exit `3` for laboratory
commands), and can never produce an overall clean pass.

The transcript loader accepts at most 64 MiB, 10,000 physical lines, and 64 MiB
for any one line. It requires strict UTF-8 JSON and contiguous event sequence
numbers starting at 1. Structured values also use the global depth-100 and
100,000-node JSON parser limits.

On POSIX, transcript outputs are mode `0600`. Probe refuses a transcript target
that is a symlink, hard link, FIFO, device, or other non-regular file. JSON
reports use private atomic replacement and likewise reject linked or special
targets. Parent-directory permissions remain the caller's responsibility.
Transcript and report paths cannot be `-`, cannot name the same file, and cannot
alias an input such as a replay transcript, scenario, initialize payload, or
`--raw @file` source.

## Redaction policy

Redaction happens before an event reaches the in-memory event list, verbose
diagnostic output, or the transcript file. Probe redacts recognized credential
headers (including authorization, cookies, API keys, access tokens, MCP session
identifiers, and mirrored MCP argument headers), recursively masks values whose
object keys look credential-bearing, removes URL user information, masks
sensitive URL query values, and masks recognizable secret environment
assignments. Reports list stdio environment variable names, not their values.

The replacement marker is the literal string `[REDACTED]`. Replay never
recovers a redacted value and must not reuse credentials from the source trace.
Supply any credentials required by the new target through that replay command's
explicit `--env` or `--header` options.

Redaction is conservative name-based protection, not a proof that arbitrary
application data is non-sensitive. A token placed under an innocent field name,
or private resource/tool content returned by a server, may remain visible.
Review a transcript before sharing or committing it. Real credentials and
private server output do not belong in repository examples.

## Fidelity and diagnostics

Decoded JSON payloads preserve the observed structure and non-redacted values.
`raw` records the displayed wire text when available. For non-UTF-8 bytes Probe
records replacement text, the byte length, and that exact bytes were not
captured; it does not pretend the transcript is a byte-for-byte packet capture.
HTTP events can retain observed request and response headers, but recognized
credentials and MCP session values are replaced before persistence.

Timeout, unexpected EOF, invalid JSON, invalid UTF-8, stderr, HTTP status,
content-type/body parsing, session, child-exit, and cleanup events remain in the
same sequence as protocol traffic. This is what lets a finding point to the
interaction that caused it instead of emitting an unsupported opinion.

## Replay semantics

Replay reads schema-valid transcript events and resends the client-originated
protocol interaction in sequence against a new compatible target. It preserves
request IDs, notifications, exact decoded JSON messages, lifecycle ordering,
and protocol-version metadata. Exact timing is off by default; optional timing
preservation uses relative delays, not real-time scheduling guarantees. Enable
it with `--preserve-timing`; `--max-delay` and `--max-total-delay` bound how
long captured pauses can delay a replay (defaults: one second per pause and 30
seconds total). `--timing-scale` multiplies each captured delay before those
safety caps are applied.

```bash
python3 mcp_probe.py replay stdio \
  --from /tmp/original.ndjson \
  --protocol-version 2025-06-18 \
  --transcript /tmp/replay.ndjson \
  -- python3 path/to/fixed_server.py
```

The source and destination transcript paths must be different. Replay does not
perform a new automatic establishment exchange: initialize, initialized, or
modern discovery/metadata are sent only if they were client events in the
source. When `--protocol-version` is omitted, Probe infers the first captured
initialize or modern per-request version; an explicit value keeps the expected
era visible. The selected HTTP profile must match the replay plan.

Source and target transports must match. For stdio, each captured
server-to-client message becomes an ordered receive checkpoint. For HTTP, each
captured POST defines a response window. Replay compares classification,
JSON-RPC ID and ID type, method, result-versus-error shape, error code, and HTTP
status where present; it deliberately does not require a server-specific result
payload to be byte-for-byte identical. Transport metadata that cannot safely or
meaningfully transfer is rebuilt for the destination. `REPLAY_EVENT`,
`REPLAY_RESPONSE_MATCH`, and `REPLAY_COMPLETE` findings make those comparisons
machine-readable. For newly captured raw-wire events, replay also preserves the
stdio newline choice. Older v1 events without that field default to appending a
newline. An event marked `exactBytesRecorded: false` is rejected because
replacement text cannot faithfully reproduce the bytes.

HTTP raw replay reuses only the captured Content-Type media-type token; it drops
parameters and derives every other header afresh. Captured authorization,
cookies, sessions, and MCP headers are ignored. A malformed HTTP body is
compared through its recorded `invalid_body` checkpoint rather than treated as
a decoded JSON-RPC message.

Captured authorization, cookies, API keys, session identifiers, and other
redacted data are never recovered or silently resent. A `[REDACTED]` payload
value stays redacted, and destination credentials come only from that replay
command's explicit configuration. HTTP session identifiers belong to the
destination session and are not portable. A captured `tools/call` is blocked
unless the replay command explicitly allows its exact tool name.

A transcript is useful evidence, but it is not always a runnable scenario.
Malformed byte sequences that were not captured exactly, a server's asynchronous
timing, server-originated requests, and transport closure can be inherently
target-specific. Use a
[scenario](SCENARIOS.md) when the expected outcome matters more than mirroring a
previous response.
