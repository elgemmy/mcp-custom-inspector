# Pre-revision baseline

This records the behavior observed at `main` commit `effb2c8` before the
compatibility-lab work began. It is a regression reference, not a list of
current limitations.

## Commands run

The following succeeded with exit status 0:

```sh
python3 mcp_probe.py --help
python3 mcp_probe.py stdio --help
python3 mcp_probe.py http --help
python3 -m py_compile mcp_probe.py
```

There was no `tests/` directory, so the requested unittest discovery command
could not run a repository-local suite. A local line-oriented Python fixture
accepted a fully replaced initialize object, confirming that custom initialize
payloads and omission of `notifications/initialized` worked.

The Everything-server smoke attempt was environmental rather than a product
result. Network execution was blocked before npm could run. A forced offline
retry failed with npm `ENOTCACHED` for `https://registry.npmjs.org/jszip`, so no
external server was exercised during the baseline.

## Original defects reproduced or established by inspection

- JSON-RPC initialization errors did not affect the process exit status;
  discovery and `notifications/initialized` could still follow a failed
  initialize response.
- A stdio child crash or early EOF was normally reported only after the full
  response timeout. The child exit code and causal ordering were lost.
- A non-object JSON value such as `42` on stdout could raise `TypeError` inside
  the reader path. Malformed JSON output was printed in verbose mode but was not
  retained as structured evidence.
- Response IDs were not correlated for HTTP. Multi-event SSE handling could
  choose the wrong message as the initialize response.
- Several configuration and startup errors escaped as Python tracebacks,
  including a missing executable, a missing initialize file, and refused HTTP
  connections.
- HTTP debug output could expose `Authorization`, cookies, API-key headers,
  MCP session identifiers, and secret-bearing URLs. The removed historical
  transcript logger also persisted request headers without a central redaction
  boundary.
- Stdio cleanup targeted only the direct child and did not make a process-group
  cleanup guarantee. Crash, timeout, and interrupt paths had no automated
  orphan-process tests.
- JSON-RPC IDs were stored directly as dictionary keys: unhashable custom IDs
  could crash the probe, and Python equality could conflate unusual IDs.
- HTTP parsing silently discarded malformed or non-object messages and read SSE
  responses until EOF without a bounded event-stream model.
- Protocol behavior assumed the `2025-06-18` stateful lifecycle. There was no
  explicit model for earlier revisions, `2025-11-25`, or the stateless
  `2026-07-28` lifecycle.
- Discovery did not follow pagination or compare behavior with advertised
  capabilities. There was no stable finding model or CI-distinguishable exit
  code contract.

The useful baseline behavior remains part of the product contract: direct
stdio process launch, exact decoded JSON-RPC objects, custom initialization,
optional initialized notification, raw traffic visibility, primitive
discovery, basic HTTP probing, recipes, and the small REPL.
