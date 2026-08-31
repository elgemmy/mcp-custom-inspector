# MCP Probe compatibility scope

MCP Probe is a dependency-free, command-oriented MCP client and compatibility
laboratory. It exposes the wire: callers can choose a protocol revision, supply
an exact initialization message, omit lifecycle messages, send unusual or
malformed input, save evidence, and repeat the same interaction. Its automated
checks are deterministic and non-destructive by default.

MCP Probe is deliberately not a production MCP client, a web application, an
OAuth client, a fuzzer, or a complete implementation of every MCP feature. It
does not assign a quality score and it does not claim formal conformance.

## Relationship to the official tools

Use the [official MCP Inspector](https://github.com/modelcontextprotocol/inspector)
for a polished interactive client. Inspector already provides web, CLI, and TUI
interfaces; stdio, Streamable HTTP, and legacy SSE transports; OAuth; protocol
era handling; pagination; traffic export; and schema diagnostics. MCP Probe's
distinct purpose is deterministic low-level experimentation: exact and malformed
messages, lifecycle mutations, dated-version comparisons, deep stdio failure
tests, redacted evidence, scenarios, and replay from a standard-library Python
program.

Use the [official MCP Conformance project](https://github.com/modelcontextprotocol/conformance)
for canonical, version-tagged conformance scenarios and formal requirement
coverage. MCP Probe complements it with direct stdio subprocess testing,
user-authored negative scenarios, raw-wire fault isolation, replay, and
differential testing across revisions. A Probe `PASS` means only that the named
checks executed in that report passed.

The specification, not this document or either tool, is authoritative. This
revision is based on the official dated specifications and schemas under
[modelcontextprotocol.io/specification](https://modelcontextprotocol.io/specification/2026-07-28).

## Supported protocol profiles

MCP Probe treats each dated revision as an explicit profile. It never silently
maps one profile onto another.

| Protocol revision | Lifecycle used by Probe | Transport scope |
| --- | --- | --- |
| `2024-11-05` | `initialize`, then `notifications/initialized` | stdio; legacy HTTP+SSE is deliberately unsupported |
| `2025-03-26` | `initialize`, then `notifications/initialized` | stdio and Streamable HTTP, including optional session behavior |
| `2025-06-18` | `initialize`, then `notifications/initialized` | stdio and Streamable HTTP with the negotiated protocol-version header |
| `2025-11-25` | `initialize`, then `notifications/initialized` | stdio and Streamable HTTP with the negotiated protocol-version header |
| `2026-07-28` | stateless per-request metadata and `server/discover`; no initialize exchange | stdio and POST-only Streamable HTTP; no MCP sessions, server-to-client JSON-RPC requests, or client JSON-RPC responses |

The current profile is `2026-07-28`. See the official
[versioning rules](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
[changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog),
[stdio transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio),
[Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
and [`server/discover`](https://modelcontextprotocol.io/specification/2026-07-28/server/discover).

## How to interpret findings

Every automated finding has a stable code, a status (`PASS`, `FAIL`, `WARN`, or
`SKIP`), and a basis. Findings caused by an observed protocol interaction carry
an evidence reference into the transcript; a configuration-level `SKIP` may
have no wire event to reference.

- `normative` checks implement a specific requirement from the selected dated
  specification. They are intentionally narrow: Probe does not generalize a
  rule from one revision to another.
- `heuristic` checks identify reproducibility, interoperability, or portability
  risks that are not by themselves specification violations. Cursor loops and
  limited tool-schema portability warnings are examples.
- `operational` checks describe execution and transport behavior, such as a
  timeout, malformed wire output, child exit, HTTP failure, or cleanup result.

The built-in suite treats revision-specific lifecycle and negotiation shapes,
advertised capability versus list behavior, JSON-RPC response envelopes and
IDs, unknown-method and notification behavior, list/cursor field types,
applicable server-to-client request rules, transport headers/status/content,
and narrowly defined MCP tool-schema shapes as normative. Repeated cursors,
failure to terminate pagination within a configured bound, and schema
portability observations that are not invalid for that dated revision are
heuristic. Process startup, timeouts, stderr/stdout parsing, HTTP I/O, and
cleanup are operational. The `basis` on each finding is the machine-readable
authority for that particular result.

Its default wire actions are bounded: establish the selected era, list tools,
resources, resource templates, and prompts with pagination, request an unknown
method, and send an unknown notification. It never sends `tools/call`.

A skipped check is not a pass. A transport or configuration error may prevent
normative checks from running. Read the finding explanation and its evidence;
do not infer broad conformance from the overall status alone.

## Deliberate limits

- Automated discovery does not call tools. An ordinary raw request is itself an
  explicit wire action; scenarios and replay additionally require an exact
  tool-name allow-list before sending a captured `tools/call`.
- Tool-schema inspection performs a small set of structural rules. It is not a
  complete JSON Schema validator and does not duplicate Inspector's portability
  linter.
- Probe implements only the client-side server requests needed for targeted
  legacy protocol experiments. It handles `ping`, advertised `roots/list`, and
  explicit JSON-RPC errors for early, malformed, or unsupported requests; it is
  not a production sampling, elicitation, or roots client. Under `2026-07-28`,
  a server-to-client request is itself forbidden: Probe records the failure and
  sends no JSON-RPC response.
- The `2025-03-26` profile accepts bounded, non-empty structured JSON-RPC
  batches over stdio and HTTP JSON/SSE. Probe records the envelope and each
  item, correlates individual responses, and groups replies to batched legacy
  server requests. The safe built-in suite does not synthesize a batch, so
  `JSONRPC_BATCH_SUPPORT` is `SKIP` unless a batch is observed. `2025-06-18`
  and later profiles reject batching.
- Legacy HTTP+SSE from `2024-11-05`, OAuth flows, every historical transport,
  full resumability, and exhaustive content-semantic validation are outside the
  supported scope.
- Legacy Streamable HTTP propagates an established session ID and tests session
  termination (`2xx` or `405`). Probe does not automatically reinitialize and
  retry after an expired-session `404`, including the recovery required by the
  `2025-11-25` specification; it exposes that exchange as a transport or
  compatibility failure.
- Streamable HTTP SSE parsing is request-scoped. Probe does not open an
  independent long-lived GET/listening stream and does not guarantee capture of
  events that arrive after the correlated POST response. Full resumability is
  outside the supported subset.
- HTTP response bodies, including session termination responses, are decoded
  only when Content-Encoding is absent or `identity`. Other encodings remain
  opaque evidence and fail the exchange. Duplicate critical singleton headers,
  Content-Length with Transfer-Encoding, unsupported transfer codings, and
  incomplete declared bodies are rejected as ambiguous or incomplete framing.
- The safe built-in suite does not inject method-specific invalid parameters,
  malformed request objects, duplicate initialization, or logging-level
  changes. Those require an explicit scenario so the exact input and expected
  outcome are reviewable.
- Cancellation, progress, sampling, elicitation, and other client-side feature
  semantics are not exhaustively exercised. In legacy profiles,
  target-originated requests are handled and recorded only within Probe's
  documented client subset. The modern profile records any such request as a
  violation without replying.
- Deliberately malformed stdio input can also violate the client's framing
  obligations. Robustness observations from such tests are not automatically
  classified as normative server failures.
- External npm servers are optional smoke targets. The offline verification
  suite uses only local stdio and HTTP fixtures.

## Deterministic resource bounds

These are Probe safety limits, not protocol limits. A hard-cap breach is an
operational or configuration failure and cannot produce an overall clean pass.

- One stdio frame or inbound HTTP/SSE body: 8 MiB.
- One structured JSON-RPC batch: 1,000 members.
- Retained stdio input: 1,000 entries and 16 MiB.
- One SSE response: 1,000 events, 10,000 lines, 100 parse issues, and an 8 MiB
  maximum line/event-data field.
- Pagination: 100 pages by default, configurable through 1,000, with 100,000
  collected items and 64 MiB of cumulative decoded items per session.
- Strict decoded JSON: maximum depth 100 and 100,000 nodes. A scenario file is
  additionally limited to 1 MiB; CLI JSON arguments/files are limited to 8 MiB.
- Transcript capture and loading: 10,000 events/physical lines and 64 MiB total;
  see [transcript storage and limits](TRANSCRIPTS.md#storage-and-limits).
