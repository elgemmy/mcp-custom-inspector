# Agent Guide

MCP Probe is a small MCP client for sending controlled JSON-RPC messages.
It runs paths, records transcripts, and compares outcomes over stdio or Streamable HTTP.
Keep it a single-file, standard-library tool that agents and people can read.

## Scope

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

## Layout

- `mcp_probe.py`: the Python 3.10+ CLI.
- `paths/`: nine curated paths, also the verification suite.
- `examples/`: initialize payloads for ad-hoc mode.
- `runs/`: local transcripts, ignored except `.gitkeep`.
- `.agents/skills/mcp-probe/SKILL.md`: usage instructions.
- `.claude/skills/mcp-probe`: relative symlink to that skill.
- `AGENTS.md` / `CLAUDE.md`: developer guide and its import.
- `README.md`, `CONTRIBUTING.md`, `LICENSE`, `SPEC.md`: project references.

## Verify a change

Run `python3 -m py_compile mcp_probe.py`.
Run `python3 mcp_probe.py run paths/discover.json` and `python3 mcp_probe.py run paths/handshake-missing-protocol-version.json` against the Everything server; both should exit 0.
Run all nine curated paths before a PR and check their expectations.
Run `python3 mcp_probe.py run paths/handshake-valid.json`, then `python3 mcp_probe.py diff VALID.jsonl MISSING.jsonl` using the transcript paths from the summaries; expect exit 2 and one differing step.
The paths are the tests. Do not add pytest, `tests/`, or `scripts/`.

## Editing rules

- Standard library only; Python 3.10+; keep `mcp_probe.py` one file.
- Prefer small explicit helpers and preserve the existing ad-hoc commands.
- Do not parse JSON-RPC batches; raw array sends remain possible.
- Never commit tokens or unmasked transcripts.
- If a change adds more than ~150 lines to `mcp_probe.py`, stop and ask whether it belongs in a separate script or not at all.

## Commit style

Use short imperative subjects, such as `Add path runner` or `Simplify transcript diff`.
