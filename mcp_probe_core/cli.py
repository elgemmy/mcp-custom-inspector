"""Command-line interface for MCP Probe.

The parser deliberately keeps the original ``stdio`` and ``http`` commands at
the top level.  New laboratory commands use one additional noun, for example
``check stdio -- SERVER``.  Protocol implementation modules are imported lazily
so the raw inspection path remains small and so user/configuration failures can
be translated to stable process exit codes at one boundary.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import signal
import shlex
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit

from .errors import (
    EXIT_CONFIGURATION_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_OK,
    EXIT_TRANSPORT_FAILURE,
    ConfigurationError,
    HttpExchangeError,
    ProbeError,
    TransportError,
)
from .io_safety import InputLimitError, read_utf8_limited
from .protocol import (
    LATEST_PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    profile_for,
    strict_json_loads,
)
from .redaction import (
    contains_redaction,
    known_secrets_from_command,
    redact_headers,
    redact_raw,
    redact_text,
    redact_value,
)
from .safety import find_active_tool_calls
from .session import McpSession, RpcOutcome, SessionConfig
from .transcript import EventRecorder, pretty_json
from .transports import HttpExchange, HttpTransport, StdioTransport


JsonObject = dict[str, Any]
OUTPUT_FORMATS = ("text", "json", "markdown")
_HTTP_FIELD_NAME = re.compile(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+\Z")
MAX_CLI_JSON_BYTES = 8 * 1024 * 1024


@dataclass
class _Runtime:
    recorder: EventRecorder
    session: McpSession


class _ProbeArgumentParser(argparse.ArgumentParser):
    """Argparse with errors that use MCP Probe's configuration exit code."""

    known_secrets: tuple[str, ...] = ()

    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(
            EXIT_CONFIGURATION_ERROR,
            f"{self.prog}: error: {redact_text(message, self.known_secrets)}\n",
        )


def _read_json(text: str, *, label: str) -> Any:
    try:
        if text.startswith("@"):
            path = Path(text[1:])
            text = read_utf8_limited(
                path,
                max_bytes=MAX_CLI_JSON_BYTES,
                label=label,
            )
        elif len(text.encode("utf-8")) > MAX_CLI_JSON_BYTES:
            raise InputLimitError(
                f"{label} exceeds the {MAX_CLI_JSON_BYTES}-byte safety limit"
            )
        return strict_json_loads(text)
    except (OSError, UnicodeError, InputLimitError) as exc:
        raise ConfigurationError(f"Could not read {label}: {exc}") from exc
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigurationError(f"Invalid JSON for {label}: {exc}") from exc


def _load_initialize(args: argparse.Namespace) -> JsonObject | None:
    init_file = getattr(args, "init_file", None)
    init_json = getattr(args, "init_json", None)
    if init_file and init_json:
        raise ConfigurationError("Use either --init-file or --init-json, not both.")
    supplied: Any = None
    if init_file:
        supplied = _read_json(f"@{init_file}", label="--init-file")
    elif init_json:
        supplied = _read_json(init_json, label="--init-json")
    if supplied is None:
        return None
    if not isinstance(supplied, dict):
        raise ConfigurationError("Initialize params must be a JSON object.")
    if supplied.get("method") is not None:
        if supplied.get("method") != "initialize":
            raise ConfigurationError(
                "A full --init-json/--init-file payload must use method "
                "'initialize'. Use --raw or a scenario exact action for other "
                "protocol messages."
            )
        message = supplied
    else:
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": supplied,
        }
    if find_active_tool_calls(message):
        raise ConfigurationError(
            "Initialize configuration contains a nested tools/call-like object. "
            "Automated lifecycle establishment is non-destructive; use an exact "
            "scenario action with --allow-tool for an explicitly authorized call."
        )
    return message


def _load_capabilities(value: str | None) -> JsonObject:
    if value is None:
        return {}
    capabilities = _read_json(value, label="--client-capabilities")
    if not isinstance(capabilities, dict):
        raise ConfigurationError("--client-capabilities must be a JSON object.")
    if find_active_tool_calls(capabilities):
        raise ConfigurationError(
            "Client capabilities contain a nested tools/call-like object. "
            "Automated lifecycle metadata must remain non-destructive."
        )
    return capabilities


def _parse_key_values(values: Sequence[str] | None, flag: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values or ():
        if "=" not in item:
            raise ConfigurationError(f"{flag} expects KEY=VALUE.")
        key, value = item.split("=", 1)
        if not key:
            raise ConfigurationError(f"{flag} requires a non-empty key.")
        if "\0" in key or "\0" in value:
            raise ConfigurationError(f"{flag} names and values must not contain NUL.")
        result[key] = value
    return result


def _parse_headers(values: Sequence[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    normalized_names: set[str] = set()
    for item in values or ():
        if "\r" in item or "\n" in item:
            raise ConfigurationError("--header names and values must not contain CR or LF.")
        if ":" not in item:
            raise ConfigurationError("--header expects 'Name: Value'.")
        key, value = item.split(":", 1)
        key = key.strip()
        if not key:
            raise ConfigurationError("--header requires a non-empty header name.")
        if _HTTP_FIELD_NAME.fullmatch(key) is None:
            raise ConfigurationError(
                "--header name contains characters outside the HTTP field-name grammar."
            )
        normalized = key.lower()
        if normalized in normalized_names:
            raise ConfigurationError(
                "--header contains a duplicate case-insensitive header name."
            )
        normalized_names.add(normalized)
        result[key] = value.strip()
    return result


def _server_command(args: argparse.Namespace) -> list[str]:
    command = list(getattr(args, "command", ()) or ())
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise ConfigurationError(
            "Missing server command. Put it after --, for example: -- python3 server.py"
        )
    return command


def _session_config(args: argparse.Namespace, version: str | None = None) -> SessionConfig:
    selected = version or args.protocol_version
    profile_for(selected)
    return SessionConfig(
        protocol_version=selected,
        client_info={
            "name": getattr(args, "client_name", "mcp-probe"),
            "version": getattr(args, "client_version", "0.2.0"),
        },
        client_capabilities=_load_capabilities(
            getattr(args, "client_capabilities", None)
        ),
        initialize_message=_load_initialize(args),
        send_initialized=not getattr(args, "no_initialized", False),
    )


def _runtime(
    args: argparse.Namespace,
    *,
    version: str | None = None,
    recorder: EventRecorder | None = None,
) -> _Runtime:
    config = _session_config(args, version)
    active_recorder = recorder or EventRecorder(args.transcript, args.verbose)
    transport_name = args.transport
    try:
        if transport_name == "stdio":
            transport = StdioTransport(
                _server_command(args),
                _parse_key_values(args.env, "--env"),
                active_recorder,
            )
        elif transport_name == "http":
            headers = _parse_headers(args.header)
            if not config.profile.streamable_http:
                raise ConfigurationError(
                    f"Protocol {config.protocol_version} predates Streamable HTTP; "
                    "MCP Probe does not implement deprecated HTTP+SSE."
                )
            if args.include_protocol_header_on_initialize:
                if not any(
                    name.lower() == "mcp-protocol-version" for name in headers
                ):
                    headers["MCP-Protocol-Version"] = config.protocol_version
            transport = HttpTransport(
                args.url,
                headers,
                active_recorder,
                config.profile,
            )
        else:  # parser invariant; retained as a defensive configuration error
            raise ConfigurationError(f"Unknown transport: {transport_name!r}.")
    except Exception:
        if recorder is None:
            active_recorder.close()
        raise
    return _Runtime(active_recorder, McpSession(transport, config, active_recorder))


def _safe_http(exchange: HttpExchange, recorder: EventRecorder) -> JsonObject:
    return {
        "status": exchange.status,
        "headers": recorder.redact_headers(exchange.headers),
        "messages": [recorder.redact_value(message.payload) for message in exchange.messages],
        "raw": recorder.redact_raw(exchange.body),
        "parseIssues": [recorder.redact_text(issue) for issue in exchange.parse_issues],
        "timedOut": exchange.timed_out,
        "bodyComplete": exchange.body_complete,
    }


def _safe_outcome(value: Any, recorder: EventRecorder) -> Any:
    if isinstance(value, RpcOutcome):
        if value.http_exchange is not None:
            return _safe_http(value.http_exchange, recorder)
        return recorder.redact_value(value.response.payload)
    if isinstance(value, HttpExchange):
        return _safe_http(value, recorder)
    return recorder.redact_value(value)


def _failed_http_value(
    error: HttpExchangeError, recorder: EventRecorder
) -> JsonObject:
    value = _safe_http(error.exchange, recorder)
    value["error"] = {
        "code": error.finding_code,
        "message": recorder.redact_text(str(error)),
    }
    return value


def _emit_inspection(
    records: list[tuple[str, Any]], output: str, recorder: EventRecorder
) -> None:
    if output == "json":
        document = {
            "schema": "mcp-probe.inspection/v1",
            "records": [
                {"label": recorder.redact_text(label), "value": recorder.redact_value(value)}
                for label, value in records
            ],
        }
        print(json.dumps(document, ensure_ascii=False, indent=2))
        return
    if output == "markdown":
        print("# MCP Probe inspection")
        for label, value in records:
            print(f"\n## {recorder.redact_text(label)}\n")
            print("```json")
            print(pretty_json(recorder.redact_value(value)))
            print("```")
        return
    for label, value in records:
        print(f"\n== {recorder.redact_text(label)} ==")
        print(pretty_json(recorder.redact_value(value)))


def _inspection_document(records: list[tuple[str, Any]], runtime: _Runtime) -> JsonObject:
    return {
        "schema": "mcp-probe.inspection/v1",
        "target": _inspection_target(runtime),
        "protocol": {
            "requestedVersion": runtime.session.requested_version,
            "negotiatedVersion": runtime.session.negotiated_version,
            "era": runtime.session.profile.era,
        },
        "server": {
            "serverInfo": runtime.recorder.redact_value(runtime.session.server_info),
            "capabilities": runtime.recorder.redact_value(runtime.session.capabilities),
        },
        "records": [
            {
                "label": runtime.recorder.redact_text(label),
                "value": runtime.recorder.redact_value(value),
            }
            for label, value in records
        ],
        "transcript": {
            "path": str(runtime.recorder.path) if runtime.recorder.path else None,
            "eventCount": len(runtime.recorder.events),
            "redacted": True,
        },
    }


def _inspection_target(runtime: _Runtime) -> JsonObject:
    """Build a redacted target without applying secrets to control keys."""

    transport = runtime.session.transport
    if isinstance(transport, StdioTransport):
        return {
            "transport": "stdio",
            "command": runtime.recorder.redact_command(transport.command),
            "environmentKeys": sorted(transport.env),
        }
    return {
        "transport": "http",
        "url": runtime.recorder.redact_url(transport.url),
        "headerNames": sorted(transport.extra_headers),
    }


def _write_json_file(path: str, value: Any) -> None:
    from .report import write_report

    write_report(path, value)


def run_inspection(args: argparse.Namespace) -> int:
    runtime = _runtime(args)
    records: list[tuple[str, Any]] = []
    inspection_closed = False
    try:
        lifecycle_label = (
            "server/discover"
            if runtime.session.profile.modern
            and not args.init_file
            and not args.init_json
            else "initialize"
        )
        try:
            established = runtime.session.establish(args.timeout)
        except HttpExchangeError as exc:
            records.append(
                (lifecycle_label, _failed_http_value(exc, runtime.recorder))
            )
            runtime.session.close()
            inspection_closed = True
            if args.report:
                _write_json_file(
                    args.report, _inspection_document(records, runtime)
                )
            _emit_inspection(records, args.output, runtime.recorder)
            return EXIT_TRANSPORT_FAILURE
        except TransportError as exc:
            transport_code = (
                "TRANSPORT_HTTP_IO"
                if isinstance(runtime.session.transport, HttpTransport)
                else "TRANSPORT_STDIO_EOF"
            )
            if isinstance(runtime.session.transport, StdioTransport):
                print(
                    f"mcp-probe: {runtime.recorder.redact_text(str(exc))}",
                    file=sys.stderr,
                )
            records.append(
                (
                    lifecycle_label,
                    {
                        "error": {
                            "code": transport_code,
                            "message": runtime.recorder.redact_text(str(exc)),
                        },
                        "evidence": runtime.recorder.last_reference(),
                    },
                )
            )
            try:
                runtime.session.close()
            except TransportError as cleanup_exc:
                records.append(
                    (
                        "cleanup",
                        {
                            "error": {
                                "code": transport_code,
                                "message": runtime.recorder.redact_text(
                                    str(cleanup_exc)
                                ),
                            },
                            "evidence": runtime.recorder.last_reference(),
                        },
                    )
                )
            inspection_closed = True
            if args.report:
                _write_json_file(
                    args.report, _inspection_document(records, runtime)
                )
            _emit_inspection(records, args.output, runtime.recorder)
            return EXIT_TRANSPORT_FAILURE
        if established.http_exchange is not None:
            init_value: Any = _safe_http(established.http_exchange, runtime.recorder)
        else:
            init_value = runtime.recorder.redact_value(established.response.payload)
        records.append((lifecycle_label, init_value))

        if args.discover and established.success:
            for method in ("tools/list", "resources/list", "prompts/list"):
                try:
                    records.append(
                        (
                            method,
                            _safe_outcome(
                                runtime.session.rpc(method, {}, args.timeout),
                                runtime.recorder,
                            ),
                        )
                    )
                except HttpExchangeError as exc:
                    records.append(
                        (method, _failed_http_value(exc, runtime.recorder))
                    )
                except ProbeError as exc:
                    records.append(
                        (method, {"error": runtime.recorder.redact_text(str(exc))})
                    )
        elif args.discover:
            for method in ("tools/list", "resources/list", "prompts/list"):
                records.append(
                    (
                        method,
                        {
                            "skipped": True,
                            "reason": "lifecycle establishment did not succeed",
                        },
                    )
                )

        for raw in args.raw or ():
            message = _read_json(raw, label="--raw")
            if not isinstance(message, dict):
                raise ConfigurationError("--raw must be a JSON-RPC object.")
            label = f"raw {message.get('method') or message.get('id')}"
            try:
                outcome = runtime.session.send_raw_object(message, args.timeout)
            except HttpExchangeError as exc:
                records.append((label, _failed_http_value(exc, runtime.recorder)))
                runtime.session.close()
                inspection_closed = True
                if args.report:
                    _write_json_file(
                        args.report, _inspection_document(records, runtime)
                    )
                _emit_inspection(records, args.output, runtime.recorder)
                return exc.exit_code
            except ProbeError as exc:
                records.append(
                    (
                        label,
                        {
                            "error": {
                                "code": type(exc).__name__,
                                "message": runtime.recorder.redact_text(str(exc)),
                            }
                        },
                    )
                )
                runtime.session.close()
                inspection_closed = True
                if args.report:
                    _write_json_file(
                        args.report, _inspection_document(records, runtime)
                    )
                _emit_inspection(records, args.output, runtime.recorder)
                return exc.exit_code
            records.append((label, _safe_outcome(outcome, runtime.recorder)))

        if args.interactive:
            if args.transport != "stdio":
                raise ConfigurationError("--interactive is only available for stdio.")
            _emit_inspection(records, args.output, runtime.recorder)
            _interactive(runtime.session, args.timeout)
        runtime.session.close()
        inspection_closed = True
        if args.report:
            _write_json_file(args.report, _inspection_document(records, runtime))
        if not args.interactive:
            _emit_inspection(records, args.output, runtime.recorder)
        return EXIT_OK
    finally:
        if not inspection_closed:
            runtime.session.close()
        runtime.recorder.close()


def _interactive(session: McpSession, timeout: float) -> None:
    print("\nInteractive mode. Commands:")
    print("  method [json-params]    send a JSON-RPC request")
    print("  notify method [params]  send a JSON-RPC notification")
    print("  raw {json}              send an exact JSON object")
    print("  quit")
    while True:
        try:
            line = input("mcp> ").strip()
        except EOFError:
            return
        if not line:
            continue
        if line in {"quit", "exit"}:
            return
        try:
            if line.startswith("raw "):
                message = _read_json(line[4:], label="interactive raw input")
                if not isinstance(message, dict):
                    raise ValueError("raw input must be a JSON object")
                outcome = session.send_raw_object(message, timeout)
                if "id" in message:
                    _emit_inspection(
                        [
                            (
                                f"raw id={message['id']}",
                                _safe_outcome(outcome, session.recorder),
                            )
                        ],
                        "text",
                        session.recorder,
                    )
            elif line.startswith("notify "):
                parts = shlex.split(line)
                if len(parts) < 2:
                    print("usage: notify method [json-params]")
                    continue
                params = (
                    _read_json(parts[2], label="interactive notification params")
                    if len(parts) > 2
                    else None
                )
                message: JsonObject = {"jsonrpc": "2.0", "method": parts[1]}
                if params is not None:
                    message["params"] = params
                session.send_notification(message, timeout)
            else:
                parts = shlex.split(line)
                params = (
                    _read_json(parts[1], label="interactive request params")
                    if len(parts) > 1
                    else {}
                )
                outcome = session.rpc(parts[0], params, timeout)
                _emit_inspection(
                    [(parts[0], _safe_outcome(outcome, session.recorder))],
                    "text",
                    session.recorder,
                )
        except (ProbeError, ValueError, json.JSONDecodeError) as exc:
            print(f"error: {session.recorder.redact_text(str(exc))}", file=sys.stderr)


def _emit_report(report: Any, args: argparse.Namespace) -> int:
    from .report import write_report

    if hasattr(report, "render"):
        rendered = report.render(args.output)
        exit_code = int(report.exit_code)
    elif isinstance(report, dict):
        rendered = json.dumps(redact_value(report), ensure_ascii=False, indent=2) + "\n"
        exit_code = int(report.get("exitCode", EXIT_OK))
    else:
        raise TypeError("Laboratory runner returned an unsupported report object.")
    if args.report:
        write_report(args.report, report)
    sys.stdout.write(rendered)
    return exit_code


def _report_from_result(
    result: Any,
    runtime: _Runtime,
    *,
    report_type: str,
    duration_ms: float | None = None,
    operation: dict[str, Any] | None = None,
    started_at: str,
) -> Any:
    """Wrap scenario/replay result records in the stable report envelope."""
    from .report import CompatibilityReport

    findings = tuple(getattr(result, "findings", ()))
    errors = tuple(getattr(result, "errors", ()))
    measured_duration = (
        duration_ms if duration_ms is not None else getattr(result, "duration_ms", None)
    )
    requested_version = getattr(
        result, "protocol_version", runtime.session.requested_version
    )
    negotiated_version = getattr(
        result, "negotiated_version", runtime.session.negotiated_version
    )
    return CompatibilityReport(
        report_type=report_type,
        target=runtime.session.target_description(),
        started_at=started_at,
        duration_ms=measured_duration,
        requested_version=requested_version,
        negotiated_version=negotiated_version,
        era=runtime.session.profile.era,
        server_info=runtime.session.server_info or None,
        capabilities=runtime.session.capabilities or None,
        discovery=runtime.session.discovered,
        findings=findings,
        errors=errors,
        transcript={
            "path": str(runtime.recorder.path) if runtime.recorder.path else None,
            "eventCount": len(runtime.recorder.events),
            "redacted": True,
        },
        scenario=operation if report_type == "scenario" else None,
        replay=operation if report_type == "replay" else None,
        known_secrets=runtime.recorder.known_secrets,
    )


def run_check_command(args: argparse.Namespace) -> int:
    from .checks import run_check

    runtime = _runtime(args)
    check_finished = False
    try:
        report = run_check(
            runtime.session,
            timeout=args.timeout,
            max_pages=args.max_pages,
            close=True,
        )
        check_finished = True
        return _emit_report(report, args)
    finally:
        if not check_finished:
            runtime.session.close()
        runtime.recorder.close()


def run_matrix_command(args: argparse.Namespace) -> int:
    from .matrix import default_matrix_versions, validate_matrix_versions
    from .report import CompatibilityReport

    requested = args.version or default_matrix_versions(args.transport)
    versions = list(validate_matrix_versions(requested, transport=args.transport))

    # One recorder keeps evidence references unique across all matrix runs.
    recorder = EventRecorder(args.transcript, args.verbose)
    started_at = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
    started = time.monotonic()
    run_reports: list[dict[str, Any]] = []
    target: dict[str, Any] | None = None
    try:
        from .checks import run_check

        for version in versions:
            runtime = _runtime(args, version=version, recorder=recorder)
            if target is None:
                target = runtime.session.target_description()
            check_finished = False
            try:
                report = run_check(
                    runtime.session,
                    timeout=args.timeout,
                    max_pages=args.max_pages,
                    close=True,
                )
                check_finished = True
                run_reports.append(report.to_dict())
            finally:
                if not check_finished:
                    runtime.session.close()
        assert target is not None
        matrix = CompatibilityReport(
            report_type="matrix",
            target=target,
            started_at=started_at,
            duration_ms=(time.monotonic() - started) * 1000,
            transcript={
                "path": str(recorder.path) if recorder.path else None,
                "eventCount": len(recorder.events),
                "redacted": True,
            },
            matrix={"versions": versions, "runs": run_reports},
            known_secrets=recorder.known_secrets,
        )
        return _emit_report(matrix, args)
    finally:
        recorder.close()


def run_scenario_command(args: argparse.Namespace) -> int:
    from .scenario import load_scenario, run_scenario

    started_at = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
    scenario = load_scenario(args.file)
    runtime = _runtime(args)
    scenario_finished = False
    try:
        result = run_scenario(
            runtime.session,
            scenario,
            timeout=args.timeout,
            allow_tools=set(args.allow_tool or ()),
            allow_opaque_wire=args.allow_opaque_wire,
        )
        scenario_finished = True
        report = _report_from_result(
            result,
            runtime,
            report_type="scenario",
            operation={
                "schema": scenario.schema,
                "name": scenario.name,
                "description": scenario.description,
                "source": str(Path(args.file)),
                "actionCount": len(scenario.actions),
                "completedActions": result.completed_actions,
                "disconnected": result.disconnected,
                "opaqueWireAllowed": args.allow_opaque_wire,
            },
            started_at=started_at,
        )
        return _emit_report(report, args)
    finally:
        if not scenario_finished:
            runtime.session.close()
        runtime.recorder.close()


def run_replay_command(args: argparse.Namespace) -> int:
    from .replay import (
        ReplayOptions,
        ReplayResult,
        ensure_distinct_transcript_paths,
        load_replay_plan,
        replay_plan,
    )

    started_at = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
    started = time.monotonic()
    ensure_distinct_transcript_paths(args.from_path, args.transcript)
    initial_options = ReplayOptions(
        timeout=args.timeout,
        protocol_version=args.protocol_version,
        preserve_timing=args.preserve_timing,
        timing_scale=args.timing_scale,
        max_delay_seconds=args.max_delay,
        max_total_delay_seconds=args.max_total_delay,
        allow_tools=tuple(args.allow_tool or ()),
        allow_opaque_wire=args.allow_opaque_wire,
    )
    # Validate and infer the era before opening the target or the output
    # transcript.  Replay adds no lifecycle messages of its own.
    plan = load_replay_plan(args.from_path, initial_options)
    selected_version = args.protocol_version or plan.protocol_version or LATEST_PROTOCOL_VERSION
    runtime = _runtime(args, version=selected_version)
    replay_closed = False
    try:
        options = ReplayOptions(
            timeout=args.timeout,
            protocol_version=selected_version,
            preserve_timing=args.preserve_timing,
            timing_scale=args.timing_scale,
            max_delay_seconds=args.max_delay,
            max_total_delay_seconds=args.max_total_delay,
            allow_tools=tuple(args.allow_tool or ()),
            allow_opaque_wire=args.allow_opaque_wire,
        )
        result: ReplayResult | None = None
        try:
            result = replay_plan(
                plan,
                runtime.session.transport,
                runtime.recorder,
                options,
            )
        except TransportError as exc:
            result = _replay_transport_failure_result(
                plan,
                runtime,
                selected_version,
                exc,
                phase="execution",
            )
        # Replay owns no lifecycle cleanup.  Capture target shutdown evidence
        # before freezing the report while leaving the recorder open to emit it.
        try:
            cleanup = runtime.session.close()
        except TransportError as exc:
            result = _replay_transport_failure_result(
                plan,
                runtime,
                selected_version,
                exc,
                phase="cleanup",
                prior=result,
            )
        else:
            result = _apply_replay_cleanup(result, cleanup, runtime.recorder)
        replay_closed = True
        report = _report_from_result(
            result,
            runtime,
            report_type="replay",
            duration_ms=(time.monotonic() - started) * 1000,
            operation={
                "source": plan.source,
                **{
                    key: value
                    for key, value in result.to_dict().items()
                    if key != "findings"
                },
            },
            started_at=started_at,
        )
        return _emit_report(report, args)
    finally:
        if not replay_closed:
            runtime.session.close()
        runtime.recorder.close()


def _replay_transport_failure_result(
    plan: Any,
    runtime: _Runtime,
    protocol_version: str,
    exc: TransportError,
    *,
    phase: str,
    prior: Any | None = None,
) -> Any:
    """Convert target I/O failures into the same stable replay report model."""

    from .errors import ProbeTimeout, ProcessExited
    from .replay import ReplayResult
    from .report import EvidenceRef, Finding, RunError

    transport = runtime.session.transport
    is_http = isinstance(transport, HttpTransport)
    if isinstance(exc, ProbeTimeout):
        code = "TRANSPORT_HTTP_TIMEOUT" if is_http else "TRANSPORT_STDIO_TIMEOUT"
    elif isinstance(exc, ProcessExited):
        code = (
            "TRANSPORT_STDIO_CHILD_EXIT"
            if getattr(transport, "returncode", None) not in {None, 0}
            else "TRANSPORT_STDIO_EOF"
        )
    elif is_http:
        observed_response = any(
            event.get("direction") == "server_to_client"
            and event.get("transport") == "http"
            for event in runtime.recorder.events
        )
        code = (
            "TRANSPORT_HTTP_IO"
            if observed_response or phase == "cleanup"
            else "TRANSPORT_HTTP_CONNECT"
        )
    else:
        code = (
            "TRANSPORT_STDIO_STARTUP"
            if getattr(transport, "process", None) is None and phase == "execution"
            else "TRANSPORT_STDIO_EOF"
        )

    evidence_name = runtime.recorder.last_reference()
    evidence = (EvidenceRef(evidence_name),) if evidence_name is not None else ()
    phase_label = "target cleanup" if phase == "cleanup" else "target execution"
    error = RunError(
        code=code,
        kind="transport",
        summary=f"Replay {phase_label} failed.",
        details=str(exc),
        evidence=evidence,
    )
    failure = Finding(
        code="REPLAY_COMPLETE",
        status="FAIL",
        category="replay",
        basis="operational",
        summary=f"Replay could not complete because {phase_label} failed.",
        details=str(exc),
        expected={"completed": True, "transportFailure": None},
        actual={
            "completed": (
                False
                if phase == "execution"
                else bool(getattr(prior, "completed", False))
            ),
            "transportFailure": code,
            "exception": type(exc).__name__,
        },
        evidence=evidence,
    )

    if prior is not None:
        findings = tuple(
            failure if finding.code == "REPLAY_COMPLETE" else finding
            for finding in prior.findings
        )
        if not any(finding.code == "REPLAY_COMPLETE" for finding in prior.findings):
            findings += (failure,)
        return replace(
            prior,
            completed=prior.completed if phase == "cleanup" else False,
            matches_source=False,
            findings=findings,
            errors=prior.errors + (error,),
        )

    sent_actions = sum(
        event.get("direction") == "client_to_server"
        and event.get("transport") == plan.source_transport
        for event in runtime.recorder.events
    )
    received_messages = sum(
        event.get("direction") == "server_to_client"
        and event.get("transport") == plan.source_transport
        for event in runtime.recorder.events
    )
    return ReplayResult(
        source_transport=plan.source_transport,
        target_transport="http" if is_http else "stdio",
        protocol_version=protocol_version,
        negotiated_version=runtime.session.negotiated_version,
        source_event_count=len(plan.events),
        planned_actions=plan.client_event_count,
        sent_actions=sent_actions,
        received_messages=received_messages,
        completed=False,
        matches_source=False,
        credentials_reused=False,
        redactions_applied=contains_redaction(runtime.recorder.events),
        active_tools=plan.active_tools,
        opaque_wire_event_count=plan.opaque_wire_event_count,
        findings=(failure,),
        errors=(error,),
        evidence=(evidence_name,) if evidence_name is not None else (),
    )


def _apply_replay_cleanup(result: Any, cleanup: Any, recorder: EventRecorder) -> Any:
    """Make abnormal target cleanup and trailing traffic visible in replay reports."""

    from .report import EvidenceRef, Finding, RunError
    from .transports import CleanupResult

    if isinstance(cleanup, int) and not isinstance(cleanup, bool):
        replay_complete_sequences = [
            event["seq"]
            for event in recorder.events
            if event.get("classification") == "replay_complete"
            and isinstance(event.get("seq"), int)
        ]
        replay_complete_sequence = (
            replay_complete_sequences[-1] if replay_complete_sequences else None
        )
        explicit_termination = any(
            event.get("classification") == "session_terminated"
            and event.get("httpStatus") == cleanup
            and isinstance(event.get("seq"), int)
            and replay_complete_sequence is not None
            and event["seq"] < replay_complete_sequence
            for event in recorder.events
        )
        if explicit_termination:
            # The DELETE was a captured replay action. Its status was already
            # compared with the source; close() merely returns the cached
            # result and must not reinterpret a reproduced 4xx/5xx as a new
            # automatic-cleanup transport failure.
            return result
        if 200 <= cleanup < 300 or cleanup == 405:
            return result
        evidence_name = recorder.last_reference()
        evidence = (EvidenceRef(evidence_name),) if evidence_name is not None else ()
        details = f"HTTP session termination returned status {cleanup}."
        failure = Finding(
            code="REPLAY_COMPLETE" if result.matches_source else "HTTP_SESSION_TERMINATION",
            status="FAIL",
            category="replay" if result.matches_source else "transport",
            basis="operational",
            summary="Replay protocol traffic completed, but HTTP session cleanup failed.",
            details=details,
            expected={"cleanupStatus": "2xx or 405"},
            actual={"cleanupStatus": cleanup},
            evidence=evidence,
        )
        findings = (
            tuple(
                failure if finding.code == "REPLAY_COMPLETE" else finding
                for finding in result.findings
            )
            if result.matches_source
            else result.findings + (failure,)
        )
        return replace(
            result,
            matches_source=False,
            findings=findings,
            errors=result.errors
            + (
                RunError(
                    code="TRANSPORT_HTTP_IO",
                    kind="transport",
                    summary="Replay HTTP session cleanup failed.",
                    details=details,
                    evidence=evidence,
                ),
            ),
        )
    if not isinstance(cleanup, CleanupResult):
        return result

    complete_sequences = [
        event.get("seq")
        for event in recorder.events
        if event.get("classification") == "replay_complete"
        and isinstance(event.get("seq"), int)
    ]
    completed_sequence = complete_sequences[-1] if complete_sequences else None
    trailing = [
        event
        for event in recorder.events
        if completed_sequence is not None
        and event.get("direction") == "server_to_client"
        and isinstance(event.get("seq"), int)
        and event["seq"] > completed_sequence
    ]
    status: str | None = None
    details: str | None = None
    error_summary: str | None = None
    if cleanup.killed:
        status = "FAIL"
        details = (
            "The stdio child ignored stdin closure and SIGTERM, so MCP Probe "
            "used SIGKILL during replay cleanup."
        )
        error_summary = "Replay target required forced process termination."
    elif cleanup.terminated:
        status = "WARN"
        details = (
            "The stdio child did not exit after stdin closed; MCP Probe sent "
            "SIGTERM to prevent an orphan process."
        )
    elif cleanup.graceful and cleanup.returncode not in {None, 0}:
        status = "FAIL"
        details = (
            f"The stdio child returned exit status {cleanup.returncode} after "
            "the replay interaction."
        )
        error_summary = "Replay target exited with a non-zero status."
    if status is None and not trailing:
        return result

    if trailing and status is None:
        status = "FAIL"
        details = (
            f"The stdio target emitted {len(trailing)} protocol message(s) after "
            "the replay had reached its captured endpoint."
        )
        error_summary = None

    evidence_names = [f"event:{event['seq']}" for event in trailing]
    evidence_name = recorder.last_reference()
    if evidence_name is not None and evidence_name not in evidence_names:
        evidence_names.append(evidence_name)
    evidence = tuple(EvidenceRef(item) for item in evidence_names)
    cleanup_finding = Finding(
        code="REPLAY_COMPLETE" if result.matches_source else "STDIO_CLEANUP",
        status=status,
        category="replay" if result.matches_source else "transport",
        basis="operational",
        summary=(
            "Replay traffic matched, but target cleanup required SIGTERM."
            if status == "WARN" and result.matches_source
            else (
                "Replay protocol traffic completed, but target cleanup failed."
                if result.matches_source
                else "Replay target cleanup was not graceful after an earlier failure."
            )
        ),
        details=details,
        expected={
            "sentActions": result.planned_actions,
            "completed": True,
            "responseComparisons": "all match",
            "cleanup": "graceful exit 0",
        },
        actual={
            "protocolMatch": result.matches_source,
            "cleanupExitCode": cleanup.returncode,
            "terminated": cleanup.terminated,
            "killed": cleanup.killed,
            "trailingMessages": len(trailing),
        },
        evidence=evidence,
    )
    if result.matches_source:
        findings = tuple(
            cleanup_finding if finding.code == "REPLAY_COMPLETE" else finding
            for finding in result.findings
        )
    else:
        findings = result.findings + (cleanup_finding,)
    errors = result.errors
    if error_summary is not None:
        errors = errors + (
            RunError(
                code="TRANSPORT_STDIO_CHILD_EXIT",
                kind="transport",
                summary=error_summary,
                details=details,
                evidence=evidence,
            ),
        )
    return replace(
        result,
        matches_source=result.matches_source if status == "WARN" else False,
        received_messages=result.received_messages + len(trailing),
        evidence=result.evidence
        + tuple(item for item in evidence_names if item not in result.evidence),
        findings=findings,
        errors=errors,
    )


def _add_protocol_args(
    parser: argparse.ArgumentParser,
    *,
    default_version: str | None = LATEST_PROTOCOL_VERSION,
    include_client: bool = True,
    include_version: bool = True,
    include_initialize_payload: bool = True,
    scenario_timeout: bool = False,
) -> None:
    if include_version:
        parser.add_argument(
            "--protocol-version",
            default=default_version,
            help=(
                "Dated MCP protocol profile (inferred from transcript metadata when "
                f"present; otherwise defaults to {LATEST_PROTOCOL_VERSION})."
                if default_version is None
                else f"Dated MCP protocol profile (default: {default_version})."
            ),
        )
    if include_client:
        parser.add_argument("--client-name", default="mcp-probe")
        parser.add_argument("--client-version", default="0.2.0")
        parser.add_argument(
            "--client-capabilities",
            help="JSON object for client capabilities. Defaults to {}.",
        )
        if include_initialize_payload:
            parser.add_argument(
                "--init-json",
                help="Initialize params or a full JSON-RPC initialize request.",
            )
            parser.add_argument(
                "--init-file",
                help="File containing initialize params or a full initialize request.",
            )
        parser.add_argument(
            "--no-initialized",
            action="store_true",
            help="Do not send notifications/initialized in legacy protocol eras.",
        )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None if scenario_timeout else 15.0,
        help=(
            "Override the scenario file's default operation timeout."
            if scenario_timeout
            else "Per-operation timeout in seconds (default: 15)."
        ),
    )
    parser.add_argument(
        "--transcript",
        metavar="PATH",
        help=(
            "Write a private redacted NDJSON transcript "
            "(maximum 10,000 events / 64 MiB)."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print redacted send/receive events to stderr.",
    )


def _add_transport_args(parser: argparse.ArgumentParser, transport: str) -> None:
    parser.set_defaults(transport=transport)
    if transport == "stdio":
        parser.add_argument(
            "--env", action="append", help="Server environment variable, KEY=VALUE."
        )
        parser.add_argument(
            "command", nargs=argparse.REMAINDER, help="Server command after --."
        )
    else:
        parser.add_argument(
            "--url", required=True, help="Streamable HTTP MCP endpoint URL."
        )
        parser.add_argument(
            "--header",
            action="append",
            help="Extra request header, for example 'Authorization: Bearer ...'.",
        )
        parser.add_argument(
            "--include-protocol-header-on-initialize",
            action="store_true",
            help="Send MCP-Protocol-Version on legacy initialize as an experiment.",
        )


def _add_output_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--output", choices=OUTPUT_FORMATS, default="text")
    parser.add_argument(
        "--report",
        metavar="PATH",
        help="Also write a private machine-readable JSON report file.",
    )


def _add_inspection_parser(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser], transport: str
) -> None:
    parser = subparsers.add_parser(
        transport,
        help=(
            "Launch and inspect a stdio MCP server."
            if transport == "stdio"
            else "Inspect a Streamable HTTP MCP endpoint."
        ),
    )
    _add_protocol_args(parser)
    _add_output_args(parser)
    parser.add_argument(
        "--raw",
        action="append",
        help="Exact JSON-RPC object to send; use @file.json to load a file.",
    )
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Call tools/list, resources/list, and prompts/list.",
    )
    if transport == "stdio":
        parser.add_argument(
            "--interactive", action="store_true", help="Open the small stdio REPL."
        )
    else:
        parser.set_defaults(interactive=False)
    _add_transport_args(parser, transport)
    parser.set_defaults(func=run_inspection)


def _add_laboratory_leaf(
    parent: argparse._SubParsersAction[argparse.ArgumentParser],
    command: str,
    transport: str,
    func: Callable[[argparse.Namespace], int],
) -> None:
    parser = parent.add_parser(transport, help=f"Run {command} over {transport}.")
    _add_protocol_args(
        parser,
        default_version=None if command == "replay" else LATEST_PROTOCOL_VERSION,
        include_client=command != "replay",
        include_version=command != "matrix",
        include_initialize_payload=command != "matrix",
        scenario_timeout=command == "scenario",
    )
    _add_output_args(parser)
    if command in {"check", "matrix"}:
        parser.add_argument(
            "--max-pages",
            type=int,
            default=100,
            help="Pagination safety limit per primitive (default: 100; range: 1-1000).",
        )
    if command == "matrix":
        parser.add_argument(
            "--version",
            action="append",
            choices=SUPPORTED_PROTOCOL_VERSIONS,
            help="Version to test; repeat to choose an explicit matrix.",
        )
    if command == "scenario":
        # An omitted CLI timeout lets the scenario's top-level timeout apply;
        # individual action timeouts remain most specific.
        parser.add_argument("--file", required=True, help="Scenario JSON file.")
        parser.add_argument(
            "--allow-tool",
            action="append",
            help="Explicitly permit one tools/call target; repeat as needed.",
        )
        parser.add_argument(
            "--allow-opaque-wire",
            action="store_true",
            help=(
                "Permit malformed/non-UTF-8/transformed wire input that cannot be "
                "inspected for hidden tools/call actions."
            ),
        )
    if command == "replay":
        parser.add_argument(
            "--from", dest="from_path", required=True, help="Transcript NDJSON to replay."
        )
        parser.add_argument(
            "--preserve-timing",
            action="store_true",
            help="Approximate delays between recorded client events.",
        )
        parser.add_argument(
            "--max-delay",
            type=float,
            default=1.0,
            help="Maximum delay between replayed events (default: 1 second).",
        )
        parser.add_argument(
            "--max-total-delay",
            type=float,
            default=30.0,
            help="Maximum total replay delay (default: 30 seconds).",
        )
        parser.add_argument(
            "--timing-scale",
            type=float,
            default=1.0,
            help="Multiplier for captured delays before applying safety bounds.",
        )
        parser.add_argument(
            "--allow-tool",
            action="append",
            help="Explicitly permit a captured tools/call target; repeat as needed.",
        )
        parser.add_argument(
            "--allow-opaque-wire",
            action="store_true",
            help=(
                "Permit raw transcript events which are not strict JSON and cannot "
                "be inspected for hidden tools/call actions."
            ),
        )
    _add_transport_args(parser, transport)
    parser.set_defaults(func=func)


def build_parser() -> argparse.ArgumentParser:
    parser = _ProbeArgumentParser(
        description="Raw-wire MCP compatibility and debugging laboratory."
    )
    subparsers = parser.add_subparsers(dest="mode", required=True)
    _add_inspection_parser(subparsers, "stdio")
    _add_inspection_parser(subparsers, "http")

    commands: tuple[tuple[str, Callable[[argparse.Namespace], int], str], ...] = (
        ("check", run_check_command, "Run deterministic compatibility checks."),
        ("matrix", run_matrix_command, "Compare behavior across dated protocol profiles."),
        ("scenario", run_scenario_command, "Run a declarative protocol scenario."),
        ("replay", run_replay_command, "Replay client-originated transcript events."),
    )
    for name, func, help_text in commands:
        command_parser = subparsers.add_parser(name, help=help_text)
        transports = command_parser.add_subparsers(dest="transport", required=True)
        _add_laboratory_leaf(transports, name, "stdio", func)
        _add_laboratory_leaf(transports, name, "http", func)
    return parser


def _same_path(first: str, second: str) -> bool:
    first_path = Path(first).expanduser()
    second_path = Path(second).expanduser()
    if first_path.resolve() == second_path.resolve():
        return True
    try:
        return first_path.exists() and second_path.exists() and os.path.samefile(
            first_path, second_path
        )
    except OSError:
        return False


def _validate_http_url(value: str) -> None:
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ConfigurationError("--url must not contain whitespace or control characters.")
    try:
        parsed = urlsplit(value)
        # Accessing port also validates malformed bracket and port syntax.
        parsed.port
    except ValueError as exc:
        raise ConfigurationError("--url is not a valid HTTP endpoint URL.") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ConfigurationError("--url must be an absolute http:// or https:// URL.")


def _validate_io_paths(args: argparse.Namespace) -> None:
    outputs = [
        (flag, value)
        for flag, value in (
            ("--transcript", getattr(args, "transcript", None)),
            ("--report", getattr(args, "report", None)),
        )
        if value
    ]
    for flag, value in outputs:
        if value == "-":
            raise ConfigurationError(
                f"{flag} requires a file path; use --output json for stdout."
            )
    for index, (first_flag, first_path) in enumerate(outputs):
        for second_flag, second_path in outputs[index + 1 :]:
            if _same_path(first_path, second_path):
                raise ConfigurationError(
                    f"{first_flag} and {second_flag} must be different paths."
                )

    inputs: list[tuple[str, str]] = []
    for flag, attribute in (
        ("--from", "from_path"),
        ("--file", "file"),
        ("--init-file", "init_file"),
    ):
        value = getattr(args, attribute, None)
        if value:
            inputs.append((flag, value))
    for raw in getattr(args, "raw", None) or ():
        if raw.startswith("@") and len(raw) > 1:
            inputs.append(("--raw @file", raw[1:]))

    for input_flag, input_path in inputs:
        for output_flag, output_path in outputs:
            if _same_path(input_path, output_path):
                raise ConfigurationError(
                    f"{input_flag} input and {output_flag} output must be different paths."
                )


def _validate_args(args: argparse.Namespace) -> None:
    if args.timeout is not None and (
        isinstance(args.timeout, bool)
        or not isinstance(args.timeout, (int, float))
        or not math.isfinite(args.timeout)
        or args.timeout <= 0
    ):
        raise ConfigurationError("--timeout must be greater than zero.")
    if hasattr(args, "max_pages"):
        from .checks import MAX_CHECK_PAGES

        if (
            isinstance(args.max_pages, bool)
            or not isinstance(args.max_pages, int)
            or not 1 <= args.max_pages <= MAX_CHECK_PAGES
        ):
            raise ConfigurationError(
                f"--max-pages must be an integer from 1 to {MAX_CHECK_PAGES}."
            )
    for name in ("timing_scale", "max_delay", "max_total_delay"):
        if hasattr(args, name) and getattr(args, name) < 0:
            raise ConfigurationError(f"--{name.replace('_', '-')} must be non-negative.")
    if getattr(args, "mode", None) == "matrix" and (
        getattr(args, "init_file", None) or getattr(args, "init_json", None)
    ):
        raise ConfigurationError(
            "Matrix mode does not accept a fixed custom initialize payload; "
            "use ordinary inspection or a scenario for exact lifecycle experiments."
        )
    if args.transport == "stdio":
        _server_command(args)
        _parse_key_values(getattr(args, "env", None), "--env")
    elif args.transport == "http":
        _validate_http_url(args.url)
        _parse_headers(getattr(args, "header", None))
        selected_version = getattr(args, "protocol_version", None)
        if selected_version is not None and not profile_for(selected_version).streamable_http:
            raise ConfigurationError(
                f"Protocol {selected_version} predates Streamable HTTP; "
                "MCP Probe does not implement deprecated HTTP+SSE."
            )
    if getattr(args, "interactive", False) and args.output != "text":
        raise ConfigurationError("--interactive requires --output text.")
    _validate_io_paths(args)


@contextmanager
def _termination_signals_as_interrupts():
    """Route catchable process-termination signals through normal cleanup."""

    if threading.current_thread() is not threading.main_thread():
        yield
        return
    installed: list[tuple[int, Any]] = []

    def interrupt(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    try:
        for name in ("SIGTERM", "SIGHUP"):
            signum = getattr(signal, name, None)
            if signum is None:
                continue
            try:
                previous = signal.signal(signum, interrupt)
            except (OSError, RuntimeError, ValueError):
                continue
            installed.append((signum, previous))
        yield
    finally:
        for signum, previous in reversed(installed):
            try:
                signal.signal(signum, previous)
            except (OSError, RuntimeError, ValueError):
                pass


def _set_parser_known_secrets(
    parser: argparse.ArgumentParser, known_secrets: tuple[str, ...]
) -> None:
    """Install pre-parse credentials on every parser which may emit an error."""

    if isinstance(parser, _ProbeArgumentParser):
        parser.known_secrets = known_secrets
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for child in action.choices.values():
                _set_parser_known_secrets(child, known_secrets)


def main(argv: list[str] | None = None) -> int:
    raw_arguments = list(sys.argv[1:] if argv is None else argv)
    known_secrets = tuple(known_secrets_from_command(raw_arguments))
    parser = build_parser()
    _set_parser_known_secrets(parser, known_secrets)
    try:
        with _termination_signals_as_interrupts():
            args = parser.parse_args(raw_arguments)
            _validate_args(args)
            return int(args.func(args) or EXIT_OK)
    except KeyboardInterrupt:
        print("mcp-probe: interrupted", file=sys.stderr)
        return 130
    except ProbeError as exc:
        print(
            f"mcp-probe: {redact_text(str(exc), known_secrets)}", file=sys.stderr
        )
        return int(exc.exit_code)
    except (OSError, json.JSONDecodeError) as exc:
        print(
            f"mcp-probe: {redact_text(str(exc), known_secrets)}", file=sys.stderr
        )
        return EXIT_CONFIGURATION_ERROR
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else EXIT_CONFIGURATION_ERROR
    except Exception as exc:  # final CLI boundary: never expose a traceback by default
        print(
            f"mcp-probe: internal error: {redact_text(str(exc), known_secrets)}",
            file=sys.stderr,
        )
        return EXIT_INTERNAL_ERROR


__all__ = ["build_parser", "main"]
