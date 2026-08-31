#!/usr/bin/env python3
"""Configurable, dependency-free MCP fixture server.

The fixture can be imported by unittest modules or executed as a real child
process.  It deliberately keeps protocol behavior small and predictable; its
profiles introduce one fault at a time.

Stdio examples::

    python3 tests/fixtures/mcp_fixture.py stdio --profile stdio-good-legacy
    python3 tests/fixtures/mcp_fixture.py stdio --profile stdio-malformed-output

HTTP examples::

    python3 tests/fixtures/mcp_fixture.py http --profile http-json --port 0

The HTTP subprocess prints one JSON readiness record containing its URL. Tests
that need to inspect received requests can instead use ``running_http_fixture``.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator


JsonObject = dict[str, Any]

DEFAULT_PROTOCOL_VERSION = "2025-06-18"

STDIO_PROFILES = (
    "stdio-good-legacy",
    "stdio-good-modern",
    "stdio-malformed-output",
    "stdio-delayed-response",
    "stdio-crash",
    "stdio-mismatched-id",
    "stdio-server-request",
    "stdio-capability-mismatch",
    "stdio-pagination",
    "stdio-invalid-response",
    "stdio-partial-output",
    "stdio-non-utf8",
    "stdio-out-of-order",
    "stdio-notification-response",
)

HTTP_PROFILES = (
    "http-json",
    "http-malformed-body",
    "http-sse",
    "http-sse-multi",
    "http-session",
    "http-delayed-response",
    "http-error",
    "http-empty",
    "http-wrong-content-type",
)

ALL_PROFILES = STDIO_PROFILES + HTTP_PROFILES


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def default_capabilities() -> JsonObject:
    return {
        "tools": {"listChanged": False},
        "resources": {"subscribe": False, "listChanged": False},
        "prompts": {"listChanged": False},
    }


def fixture_tool(name: str) -> JsonObject:
    return {
        "name": name,
        "description": f"Deterministic fixture tool {name}",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "additionalProperties": False,
        },
    }


@dataclass(slots=True)
class FixtureConfig:
    profile: str
    protocol_version: str | None = None
    delay: float = 0.20
    chunk_delay: float = 0.02
    crash_exit_code: int = 17
    mismatch_offset: int = 1000
    capability_mismatch_mode: str = "unadvertised"
    pagination_mode: str = "normal"
    http_error_status: int = 503
    empty_status: int = 202
    session_id: str = "fixture-session-id"
    require_protocol_header: bool = False
    stderr_line: str | None = None

    def __post_init__(self) -> None:
        if self.profile not in ALL_PROFILES:
            raise ValueError(f"Unknown fixture profile: {self.profile}")
        if self.delay < 0 or self.chunk_delay < 0:
            raise ValueError("Fixture delays must be non-negative")
        if self.pagination_mode not in {"normal", "repeat", "loop", "malformed"}:
            raise ValueError(f"Unknown pagination mode: {self.pagination_mode}")
        if self.capability_mismatch_mode not in {"unadvertised", "unimplemented"}:
            raise ValueError(
                f"Unknown capability mismatch mode: {self.capability_mismatch_mode}"
            )
        if not 100 <= self.http_error_status <= 599:
            raise ValueError("HTTP error status must be between 100 and 599")
        if not 100 <= self.empty_status <= 599:
            raise ValueError("Empty HTTP status must be between 100 and 599")


@dataclass
class FixtureState:
    """Observable mutable state shared by the fixture adapters."""

    initialized: bool = False
    received_initialized_notification: bool = False
    terminated: bool = False
    received_messages: list[Any] = field(default_factory=list)
    received_http: list[JsonObject] = field(default_factory=list)
    server_request_responses: list[JsonObject] = field(default_factory=list)
    pending_initialize: JsonObject | None = None
    pending_out_of_order: list[JsonObject] = field(default_factory=list)
    fault_emitted: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record_message(self, message: Any) -> None:
        with self.lock:
            self.received_messages.append(message)

    def record_http(self, record: JsonObject) -> None:
        with self.lock:
            self.received_http.append(record)


class FixtureEngine:
    """Small deterministic MCP message engine used by both transports."""

    SERVER_REQUEST_ID = "fixture-roots-request"

    def __init__(self, config: FixtureConfig, state: FixtureState | None = None) -> None:
        self.config = config
        self.state = state or FixtureState()

    @property
    def requires_initialized_notification(self) -> bool:
        return self.config.profile == "stdio-good-legacy"

    def handle(self, message: Any) -> list[JsonObject]:
        self.state.record_message(message)
        if not isinstance(message, dict):
            return [self._error(None, -32600, "Invalid Request")]

        method = message.get("method")
        if isinstance(method, str):
            if "id" not in message:
                self._handle_notification(method)
                if self.config.profile == "stdio-notification-response":
                    return [self._result(None, {})]
                return []
            return self._handle_request(message)

        if "id" in message and ("result" in message or "error" in message):
            return self._handle_client_response(message)

        return [self._error(message.get("id"), -32600, "Invalid Request")]

    def _handle_notification(self, method: str) -> None:
        if method == "notifications/initialized":
            self.state.received_initialized_notification = True

    def _handle_request(self, message: JsonObject) -> list[JsonObject]:
        method = str(message["method"])
        request_id = message.get("id")

        if method == "initialize":
            self.state.initialized = True
            response = self._initialize_response(message)
            if self.config.profile == "stdio-server-request":
                self.state.pending_initialize = response
                return [
                    {
                        "jsonrpc": "2.0",
                        "id": self.SERVER_REQUEST_ID,
                        "method": "roots/list",
                        "params": {},
                    }
                ]
            return [response]

        if not self.state.initialized and self.requires_initialized_notification:
            return [self._error(request_id, -32002, "Server not initialized")]
        if self.requires_initialized_notification and not self.state.received_initialized_notification:
            return [self._error(request_id, -32002, "Initialized notification required")]

        if method == "ping":
            return [self._result(request_id, {})]
        if method == "tools/list":
            if (
                self.config.profile == "stdio-capability-mismatch"
                and self.config.capability_mismatch_mode == "unimplemented"
            ):
                return [self._error(request_id, -32601, "Method not found: tools/list")]
            return [self._result(request_id, self._tools_page(message.get("params")))]
        if method == "tools/call":
            params = message.get("params") if isinstance(message.get("params"), dict) else {}
            name = params.get("name")
            arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
            if not isinstance(name, str) or not name.startswith("fixture_"):
                return [self._error(request_id, -32602, "Unknown fixture tool")]
            return [
                self._result(
                    request_id,
                    {
                        "content": [
                            {
                                "type": "text",
                                "text": compact_json({"name": name, "arguments": arguments}),
                            }
                        ],
                        "isError": False,
                    },
                )
            ]
        if method == "resources/list":
            return [self._result(request_id, {"resources": []})]
        if method == "prompts/list":
            return [self._result(request_id, {"prompts": []})]

        return [self._error(request_id, -32601, f"Method not found: {method}")]

    def _handle_client_response(self, message: JsonObject) -> list[JsonObject]:
        if message.get("id") == self.SERVER_REQUEST_ID and self.state.pending_initialize is not None:
            self.state.server_request_responses.append(message)
            response = self.state.pending_initialize
            self.state.pending_initialize = None
            return [response]
        return []

    def _initialize_response(self, request: JsonObject) -> JsonObject:
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        requested_version = params.get("protocolVersion")
        protocol_version = self.config.protocol_version or (
            requested_version if isinstance(requested_version, str) else DEFAULT_PROTOCOL_VERSION
        )
        capabilities = default_capabilities()
        if (
            self.config.profile == "stdio-capability-mismatch"
            and self.config.capability_mismatch_mode == "unadvertised"
        ):
            capabilities = {}
        response = self._result(
            request.get("id"),
            {
                "protocolVersion": protocol_version,
                "capabilities": capabilities,
                "serverInfo": {"name": self.config.profile, "version": "1.0.0"},
            },
        )

        if self.config.profile == "stdio-mismatched-id":
            response["id"] = self._mismatched_id(request.get("id"))
        elif self.config.profile == "stdio-invalid-response":
            response["jsonrpc"] = "1.0"
            response["error"] = {"code": -32000, "message": "result and error together"}
        return response

    def _tools_page(self, params: Any) -> JsonObject:
        cursor = params.get("cursor") if isinstance(params, dict) else None
        if self.config.profile != "stdio-pagination":
            return {"tools": [fixture_tool("fixture_echo")]}

        if cursor is None:
            next_cursor: Any = "page-2"
            if self.config.pagination_mode == "malformed":
                next_cursor = {"not": "a string"}
            return {"tools": [fixture_tool("fixture_page_one")], "nextCursor": next_cursor}

        if cursor == "page-2":
            page: JsonObject = {"tools": [fixture_tool("fixture_page_two")]}
            if self.config.pagination_mode == "repeat":
                page["nextCursor"] = "page-2"
            elif self.config.pagination_mode == "loop":
                page["nextCursor"] = "page-1"
            return page

        if cursor == "page-1" and self.config.pagination_mode == "loop":
            return {"tools": [fixture_tool("fixture_page_one_again")], "nextCursor": "page-2"}
        return {"tools": []}

    def _mismatched_id(self, request_id: Any) -> Any:
        if isinstance(request_id, int) and not isinstance(request_id, bool):
            return request_id + self.config.mismatch_offset
        return "fixture-mismatched-id"

    @staticmethod
    def _result(request_id: Any, result: JsonObject) -> JsonObject:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> JsonObject:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }


def stdio_fixture_command(profile: str = "stdio-good-legacy", *extra_args: str) -> list[str]:
    """Return a command suitable for launching this module as a stdio server."""

    if profile not in STDIO_PROFILES:
        raise ValueError(f"Not a stdio fixture profile: {profile}")
    return [sys.executable, str(Path(__file__).resolve()), "stdio", "--profile", profile, *extra_args]


def _write_stdout_bytes(data: bytes) -> None:
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def _write_stderr(text: str) -> None:
    sys.stderr.buffer.write(text.encode("utf-8", errors="replace") + b"\n")
    sys.stderr.buffer.flush()


def _emit_stdio_response(engine: FixtureEngine, response: JsonObject) -> None:
    config = engine.config
    state = engine.state
    encoded = compact_json(response).encode("utf-8") + b"\n"

    if config.profile == "stdio-delayed-response":
        time.sleep(config.delay)

    if config.profile == "stdio-malformed-output" and not state.fault_emitted:
        state.fault_emitted = True
        _write_stdout_bytes(b"this is not json-rpc\n")
    elif config.profile == "stdio-non-utf8" and not state.fault_emitted:
        state.fault_emitted = True
        _write_stdout_bytes(b"\xff\xfebroken-utf8\n")

    if config.profile == "stdio-partial-output":
        first = max(1, len(encoded) // 3)
        second = max(first + 1, (len(encoded) * 2) // 3)
        for chunk in (encoded[:first], encoded[first:second], encoded[second:]):
            _write_stdout_bytes(chunk)
            if config.chunk_delay:
                time.sleep(config.chunk_delay)
        return

    _write_stdout_bytes(encoded)


def run_stdio_fixture(config: FixtureConfig) -> int:
    if config.profile not in STDIO_PROFILES:
        raise ValueError(f"Not a stdio profile: {config.profile}")

    engine = FixtureEngine(config)
    if config.stderr_line:
        _write_stderr(config.stderr_line)

    for raw_line in sys.stdin.buffer:
        if config.profile == "stdio-crash":
            os._exit(config.crash_exit_code)

        try:
            text = raw_line.decode("utf-8")
            message = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError):
            _emit_stdio_response(engine, FixtureEngine._error(None, -32700, "Parse error"))
            continue

        responses = engine.handle(message)
        if (
            config.profile == "stdio-out-of-order"
            and isinstance(message, dict)
            and message.get("method") != "initialize"
            and "id" in message
        ):
            engine.state.pending_out_of_order.extend(responses)
            if len(engine.state.pending_out_of_order) >= 2:
                for response in reversed(engine.state.pending_out_of_order):
                    _emit_stdio_response(engine, response)
                engine.state.pending_out_of_order.clear()
            continue

        for response in responses:
            _emit_stdio_response(engine, response)
    return 0


class FixtureHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: FixtureConfig) -> None:
        if config.profile not in HTTP_PROFILES:
            raise ValueError(f"Not an HTTP profile: {config.profile}")
        self.config = config
        self.state = FixtureState()
        self.engine = FixtureEngine(config, self.state)
        super().__init__(address, FixtureHttpHandler)


class FixtureHttpHandler(BaseHTTPRequestHandler):
    server: FixtureHttpServer
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *args: Any) -> None:
        del args

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = self._read_body()
        headers = {key.lower(): value for key, value in self.headers.items()}
        self.server.state.record_http(
            {
                "method": "POST",
                "path": self.path,
                "headers": headers,
                "body": body.decode("utf-8", errors="replace"),
            }
        )

        try:
            message = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_bytes(400, b"malformed request body", "text/plain")
            return

        if self.server.config.profile == "http-session":
            if not self._validate_session(message):
                return
            if not self._validate_protocol_header(message):
                return

        if self.server.config.profile == "http-malformed-body":
            self._send_bytes(200, b'{"jsonrpc":"2.0",broken', "application/json")
            return
        if self.server.config.profile == "http-delayed-response":
            time.sleep(self.server.config.delay)
        if self.server.config.profile == "http-error":
            request_id = message.get("id") if isinstance(message, dict) else None
            payload = FixtureEngine._error(request_id, -32000, "Fixture HTTP failure")
            self._send_json(self.server.config.http_error_status, payload)
            return
        if self.server.config.profile == "http-empty":
            self._send_bytes(self.server.config.empty_status, b"", None)
            return

        responses = self.server.engine.handle(message)
        if self.server.config.profile == "http-session" and self._is_initialize(message):
            extra_headers = {"Mcp-Session-Id": self.server.config.session_id}
        else:
            extra_headers = None

        if not responses:
            self._send_bytes(202, b"", None, extra_headers)
            return

        profile = self.server.config.profile
        if profile in {"http-sse", "http-sse-multi"}:
            messages = responses
            if profile == "http-sse-multi":
                messages = [
                    {
                        "jsonrpc": "2.0",
                        "method": "notifications/message",
                        "params": {"level": "info", "data": "fixture event"},
                    },
                    *responses,
                ]
            self._send_bytes(200, self._encode_sse(messages), "text/event-stream", extra_headers)
            return

        content_type = "text/plain" if profile == "http-wrong-content-type" else "application/json"
        self._send_bytes(
            200,
            compact_json(responses[0]).encode("utf-8"),
            content_type,
            extra_headers,
        )

    def do_DELETE(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        headers = {key.lower(): value for key, value in self.headers.items()}
        self.server.state.record_http(
            {"method": "DELETE", "path": self.path, "headers": headers, "body": ""}
        )
        if self.server.config.profile != "http-session":
            self._send_bytes(405, b"", None)
            return
        if self.headers.get("Mcp-Session-Id") != self.server.config.session_id:
            self._send_bytes(404, b"unknown session", "text/plain")
            return
        self.server.state.terminated = True
        self._send_bytes(204, b"", None)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self._send_bytes(405, b"", None, {"Allow": "POST, DELETE"})

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = max(0, int(raw_length))
        except ValueError:
            length = 0
        return self.rfile.read(length)

    def _validate_session(self, message: Any) -> bool:
        if self._is_initialize(message):
            return True
        if self.server.state.terminated:
            self._send_bytes(404, b"terminated session", "text/plain")
            return False
        if self.headers.get("Mcp-Session-Id") != self.server.config.session_id:
            self._send_bytes(404, b"unknown session", "text/plain")
            return False
        return True

    def _validate_protocol_header(self, message: Any) -> bool:
        if self._is_initialize(message) or not self.server.config.require_protocol_header:
            return True
        if not self.headers.get("MCP-Protocol-Version"):
            self._send_bytes(400, b"missing MCP-Protocol-Version", "text/plain")
            return False
        return True

    @staticmethod
    def _is_initialize(message: Any) -> bool:
        return isinstance(message, dict) and message.get("method") == "initialize"

    @staticmethod
    def _encode_sse(messages: list[JsonObject]) -> bytes:
        chunks = [f"event: message\ndata: {compact_json(message)}\n\n" for message in messages]
        return "".join(chunks).encode("utf-8")

    def _send_json(self, status: int, payload: JsonObject) -> None:
        self._send_bytes(status, compact_json(payload).encode("utf-8"), "application/json")

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        content_type: str | None,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        if content_type:
            self.send_header("Content-Type", content_type)
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            try:
                self.wfile.write(body)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass


@dataclass(slots=True)
class RunningHttpFixture:
    server: FixtureHttpServer
    thread: threading.Thread

    @property
    def url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/mcp"

    @property
    def state(self) -> FixtureState:
        return self.server.state


@contextlib.contextmanager
def running_http_fixture(
    profile: str = "http-json", host: str = "127.0.0.1", **config_overrides: Any
) -> Iterator[RunningHttpFixture]:
    """Run a loopback fixture across a real TCP boundary for a unittest."""

    config = FixtureConfig(profile=profile, **config_overrides)
    server = FixtureHttpServer((host, 0), config)
    thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.05),
        name="mcp-fixture-http",
        daemon=True,
    )
    thread.start()
    running = RunningHttpFixture(server=server, thread=thread)
    try:
        yield running
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _config_from_args(args: argparse.Namespace) -> FixtureConfig:
    return FixtureConfig(
        profile=args.profile,
        protocol_version=args.protocol_version,
        delay=args.delay,
        chunk_delay=args.chunk_delay,
        crash_exit_code=args.crash_exit_code,
        mismatch_offset=args.mismatch_offset,
        capability_mismatch_mode=args.capability_mismatch_mode,
        pagination_mode=args.pagination_mode,
        http_error_status=args.http_error_status,
        empty_status=args.empty_status,
        session_id=args.session_id,
        require_protocol_header=args.require_protocol_header,
        stderr_line=args.stderr_line,
    )


def _add_config_args(parser: argparse.ArgumentParser, profiles: tuple[str, ...]) -> None:
    parser.add_argument("--profile", choices=profiles, required=True)
    parser.add_argument("--protocol-version")
    parser.add_argument("--delay", type=float, default=0.20)
    parser.add_argument("--chunk-delay", type=float, default=0.02)
    parser.add_argument("--crash-exit-code", type=int, default=17)
    parser.add_argument("--mismatch-offset", type=int, default=1000)
    parser.add_argument(
        "--capability-mismatch-mode",
        choices=["unadvertised", "unimplemented"],
        default="unadvertised",
    )
    parser.add_argument(
        "--pagination-mode",
        choices=["normal", "repeat", "loop", "malformed"],
        default="normal",
    )
    parser.add_argument("--http-error-status", type=int, default=503)
    parser.add_argument("--empty-status", type=int, default=202)
    parser.add_argument("--session-id", default="fixture-session-id")
    parser.add_argument("--require-protocol-header", action="store_true")
    parser.add_argument("--stderr-line")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run a deterministic local MCP fixture server")
    subparsers = parser.add_subparsers(dest="transport", required=True)

    stdio = subparsers.add_parser("stdio")
    _add_config_args(stdio, STDIO_PROFILES)

    http = subparsers.add_parser("http")
    _add_config_args(http, HTTP_PROFILES)
    http.add_argument("--host", default="127.0.0.1")
    http.add_argument("--port", type=int, default=0)
    http.add_argument("--ready-file")
    return parser


def run_http_subprocess(args: argparse.Namespace, config: FixtureConfig) -> int:
    server = FixtureHttpServer((args.host, args.port), config)
    host, port = server.server_address[:2]
    readiness = compact_json({"url": f"http://{host}:{port}/mcp", "pid": os.getpid()})
    if args.ready_file:
        ready_path = Path(args.ready_file)
        ready_path.parent.mkdir(parents=True, exist_ok=True)
        ready_path.write_text(readiness + "\n", encoding="utf-8")
    else:
        print(readiness, flush=True)

    def stop(_signum: int, _frame: Any) -> None:
        raise KeyboardInterrupt

    previous_term = signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever(poll_interval=0.10)
    except KeyboardInterrupt:
        return 0
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = _config_from_args(args)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    if args.transport == "stdio":
        return run_stdio_fixture(config)
    return run_http_subprocess(args, config)


if __name__ == "__main__":
    raise SystemExit(main())
