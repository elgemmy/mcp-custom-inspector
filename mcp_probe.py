#!/usr/bin/env python3
"""
Small MCP server probe with controllable JSON-RPC payloads.

Examples:
  python mcp_probe.py stdio --discover -- npx -y @modelcontextprotocol/server-everything

  python mcp_probe.py stdio \
    --init-file init_params.json \
    --raw '{"jsonrpc":"2.0","id":99,"method":"tools/list","params":{}}' \
    -- npx -y @modelcontextprotocol/server-github

  python mcp_probe.py http \
    --url http://127.0.0.1:3000/mcp \
    --discover \
    --header 'Authorization: Bearer ...'
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import queue
import shlex
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


LATEST_PROTOCOL_VERSION = "2025-06-18"


Json = dict[str, Any]


def now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)


def load_json_arg(value: str) -> Any:
    if value.startswith("@"):
        return json.loads(Path(value[1:]).read_text(encoding="utf-8"))
    return json.loads(value)


def load_json_file_or_inline(file_value: str | None, json_value: str | None) -> Any | None:
    if file_value and json_value:
        raise SystemExit("Use either --init-file or --init-json, not both.")
    if file_value:
        return json.loads(Path(file_value).read_text(encoding="utf-8"))
    if json_value:
        return json.loads(json_value)
    return None


def parse_key_value(values: list[str] | None, flag_name: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values or []:
        if "=" not in item:
            raise SystemExit(f"{flag_name} expects KEY=VALUE, got: {item!r}")
        key, value = item.split("=", 1)
        parsed[key] = value
    return parsed


def parse_header(values: list[str] | None) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values or []:
        if ":" not in item:
            raise SystemExit(f"--header expects 'Name: Value', got: {item!r}")
        key, value = item.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


class Logger:
    def __init__(self, path: str | None, verbose: bool) -> None:
        self.verbose = verbose
        self._lock = threading.Lock()
        self._file = None
        if path:
            log_path = Path(path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._file = log_path.open("a", encoding="utf-8")

    def close(self) -> None:
        if self._file:
            self._file.close()

    def event(self, direction: str, transport: str, payload: Any, **meta: Any) -> None:
        record = {
            "ts": now_iso(),
            "direction": direction,
            "transport": transport,
            "payload": payload,
            **{k: v for k, v in meta.items() if v is not None},
        }
        line = compact_json(record)
        with self._lock:
            if self._file:
                self._file.write(line + "\n")
                self._file.flush()
            if self.verbose:
                prefix = f"[{record['ts']}] {direction.upper()} {transport}"
                if direction == "stderr":
                    print(f"{prefix}: {payload}", file=sys.stderr)
                else:
                    print(f"{prefix}:\n{pretty_json(payload)}", file=sys.stderr)


def default_initialize_params(args: argparse.Namespace) -> Json:
    capabilities = load_json_arg(args.client_capabilities) if args.client_capabilities else {}
    return {
        "protocolVersion": args.protocol_version,
        "capabilities": capabilities,
        "clientInfo": {
            "name": args.client_name,
            "version": args.client_version,
        },
    }


def initialize_request(args: argparse.Namespace, request_id: int = 1) -> Json:
    supplied = load_json_file_or_inline(args.init_file, args.init_json)
    if isinstance(supplied, dict) and supplied.get("method"):
        return supplied
    params = supplied if supplied is not None else default_initialize_params(args)
    if not isinstance(params, dict):
        raise SystemExit("Initialize params must be a JSON object.")
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": params,
    }


def initialized_notification() -> Json:
    return {"jsonrpc": "2.0", "method": "notifications/initialized"}


def request(method: str, request_id: int, params: Json | None = None) -> Json:
    msg: Json = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def method_of(message: Any) -> str | None:
    return message.get("method") if isinstance(message, dict) else None


def id_of(message: Any) -> Any:
    return message.get("id") if isinstance(message, dict) else None


class StdioMcpProbe:
    def __init__(self, command: list[str], env: dict[str, str], logger: Logger) -> None:
        if not command:
            raise SystemExit("stdio mode requires a server command after --")
        self.command = command
        self.env = env
        self.logger = logger
        self._responses: dict[Any, Json] = {}
        self._messages: queue.Queue[Json] = queue.Queue()
        self._closed = threading.Event()
        self._proc: subprocess.Popen[str] | None = None
        self._next_id = 2

    def start(self) -> None:
        full_env = os.environ.copy()
        full_env.update(self.env)
        self._proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env=full_env,
        )
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()

    def close(self) -> None:
        self._closed.set()
        proc = self._proc
        if not proc:
            return
        if proc.stdin:
            try:
                proc.stdin.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)

    def _read_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        for raw_line in self._proc.stdout:
            line = raw_line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except json.JSONDecodeError as exc:
                self.logger.event("recv-invalid", "stdio", line, error=str(exc))
                continue
            self.logger.event("recv", "stdio", message)
            self._messages.put(message)
        self._closed.set()

    def _read_stderr(self) -> None:
        assert self._proc and self._proc.stderr
        for line in self._proc.stderr:
            self.logger.event("stderr", "stdio", line.rstrip("\n"))

    def send(self, message: Json) -> None:
        assert self._proc and self._proc.stdin
        payload = compact_json(message)
        self.logger.event("send", "stdio", message)
        self._proc.stdin.write(payload + "\n")
        self._proc.stdin.flush()

    def next_id(self) -> int:
        current = self._next_id
        self._next_id += 1
        return current

    def wait_for_response(self, request_id: Any, timeout: float) -> Json:
        if request_id in self._responses:
            return self._responses.pop(request_id)
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for response id={request_id!r}")
            try:
                message = self._messages.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError(f"Timed out waiting for response id={request_id!r}") from exc
            if "id" in message and ("result" in message or "error" in message):
                if message["id"] == request_id:
                    return message
                self._responses[message["id"]] = message
                continue
            self._handle_server_message(message)

    def _handle_server_message(self, message: Json) -> None:
        if "id" not in message or "method" not in message:
            return
        method = str(message["method"])
        response_msg: Json
        if method in {"ping"}:
            response_msg = {"jsonrpc": "2.0", "id": message["id"], "result": {}}
        elif method == "roots/list":
            response_msg = {"jsonrpc": "2.0", "id": message["id"], "result": {"roots": []}}
        else:
            response_msg = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "error": {
                    "code": -32601,
                    "message": f"Probe does not implement client method: {method}",
                },
            }
        self.send(response_msg)

    def rpc(self, method: str, params: Json | None, timeout: float) -> Json:
        msg = request(method, self.next_id(), params)
        self.send(msg)
        return self.wait_for_response(msg["id"], timeout)


@dataclass
class HttpResponse:
    status: int
    headers: dict[str, str]
    messages: list[Json]
    raw_body: str


class HttpMcpProbe:
    def __init__(self, url: str, headers: dict[str, str], logger: Logger) -> None:
        self.url = url
        self.extra_headers = headers
        self.logger = logger
        self.session_id: str | None = None
        self.protocol_version: str | None = None
        self._next_id = 2

    def next_id(self) -> int:
        current = self._next_id
        self._next_id += 1
        return current

    def send(self, message: Json, timeout: float, include_protocol_header: bool = True) -> HttpResponse:
        body = compact_json(message).encode("utf-8")
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **self.extra_headers,
        }
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if include_protocol_header and self.protocol_version:
            headers["MCP-Protocol-Version"] = self.protocol_version

        self.logger.event("send", "http", message, url=self.url, headers=headers)
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = resp.status
                resp_headers = {k: v for k, v in resp.headers.items()}
                raw_body = resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = exc.code
            resp_headers = {k: v for k, v in exc.headers.items()}
            raw_body = exc.read().decode("utf-8", errors="replace")

        if "Mcp-Session-Id" in resp_headers:
            self.session_id = resp_headers["Mcp-Session-Id"]

        messages = parse_http_body(raw_body, resp_headers.get("Content-Type", ""))
        for msg in messages:
            self.logger.event("recv", "http", msg, status=status, headers=resp_headers)
        if not messages:
            self.logger.event("recv", "http", raw_body, status=status, headers=resp_headers)
        return HttpResponse(status, resp_headers, messages, raw_body)

    def rpc(self, method: str, params: Json | None, timeout: float) -> HttpResponse:
        return self.send(request(method, self.next_id(), params), timeout)


def parse_http_body(raw_body: str, content_type: str) -> list[Json]:
    if not raw_body.strip():
        return []
    if "text/event-stream" in content_type:
        return parse_sse(raw_body)
    try:
        parsed = json.loads(raw_body)
    except json.JSONDecodeError:
        return []
    return [parsed] if isinstance(parsed, dict) else []


def parse_sse(raw_body: str) -> list[Json]:
    messages: list[Json] = []
    data_lines: list[str] = []

    def flush() -> None:
        if not data_lines:
            return
        data = "\n".join(data_lines)
        data_lines.clear()
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            return
        if isinstance(parsed, dict):
            messages.append(parsed)

    for line in raw_body.splitlines():
        if not line:
            flush()
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    flush()
    return messages


def print_response(label: str, message: Any) -> None:
    print(f"\n== {label} ==")
    print(pretty_json(message))


def negotiated_protocol_version(init_response: Json, fallback: str) -> str:
    result = init_response.get("result") if isinstance(init_response, dict) else None
    if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
        return result["protocolVersion"]
    return fallback


def discover_stdio(probe: StdioMcpProbe, args: argparse.Namespace) -> None:
    for method in ["tools/list", "resources/list", "prompts/list"]:
        try:
            response = probe.rpc(method, {}, args.timeout)
        except TimeoutError as exc:
            print_response(method, {"error": str(exc)})
            continue
        print_response(method, response)


def discover_http(probe: HttpMcpProbe, args: argparse.Namespace) -> None:
    for method in ["tools/list", "resources/list", "prompts/list"]:
        response = probe.rpc(method, {}, args.timeout)
        print_response(method, {"status": response.status, "messages": response.messages, "raw": response.raw_body})


def run_stdio(args: argparse.Namespace) -> int:
    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("Missing server command. Put it after --, for example: -- npx -y package-name")

    logger = Logger(args.log, args.verbose)
    probe = StdioMcpProbe(command, parse_key_value(args.env, "--env"), logger)
    try:
        probe.start()
        init = initialize_request(args)
        probe.send(init)
        init_response = probe.wait_for_response(init.get("id"), args.timeout)
        print_response("initialize", init_response)
        if not args.no_initialized:
            probe.send(initialized_notification())

        if args.discover:
            discover_stdio(probe, args)

        for raw in args.raw or []:
            message = load_json_arg(raw)
            if not isinstance(message, dict):
                raise SystemExit("--raw must be a JSON-RPC object.")
            probe.send(message)
            if "id" in message:
                print_response(f"raw id={message['id']}", probe.wait_for_response(message["id"], args.timeout))

        if args.interactive:
            interactive_stdio(probe, args.timeout)
        return 0
    finally:
        probe.close()
        logger.close()


def interactive_stdio(probe: StdioMcpProbe, timeout: float) -> None:
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
                msg = json.loads(line[4:])
                probe.send(msg)
                if isinstance(msg, dict) and "id" in msg:
                    print_response(f"raw id={msg['id']}", probe.wait_for_response(msg["id"], timeout))
            elif line.startswith("notify "):
                parts = shlex.split(line)
                if len(parts) < 2:
                    print("usage: notify method [json-params]")
                    continue
                params = json.loads(parts[2]) if len(parts) > 2 else None
                msg: Json = {"jsonrpc": "2.0", "method": parts[1]}
                if params is not None:
                    msg["params"] = params
                probe.send(msg)
            else:
                parts = shlex.split(line)
                params = json.loads(parts[1]) if len(parts) > 1 else {}
                response = probe.rpc(parts[0], params, timeout)
                print_response(parts[0], response)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)


def run_http(args: argparse.Namespace) -> int:
    logger = Logger(args.log, args.verbose)
    probe = HttpMcpProbe(args.url, parse_header(args.header), logger)
    try:
        init = initialize_request(args)
        init_response = probe.send(init, args.timeout, include_protocol_header=args.include_protocol_header_on_initialize)
        print_response("initialize", {
            "status": init_response.status,
            "headers": init_response.headers,
            "messages": init_response.messages,
            "raw": init_response.raw_body,
        })

        if init_response.messages:
            probe.protocol_version = negotiated_protocol_version(init_response.messages[-1], args.protocol_version)
        else:
            probe.protocol_version = args.protocol_version

        if not args.no_initialized:
            probe.send(initialized_notification(), args.timeout)

        if args.discover:
            discover_http(probe, args)

        for raw in args.raw or []:
            message = load_json_arg(raw)
            if not isinstance(message, dict):
                raise SystemExit("--raw must be a JSON-RPC object.")
            response = probe.send(message, args.timeout)
            print_response(f"raw {method_of(message) or id_of(message)}", {
                "status": response.status,
                "headers": response.headers,
                "messages": response.messages,
                "raw": response.raw_body,
            })
        return 0
    finally:
        logger.close()


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--protocol-version", default=LATEST_PROTOCOL_VERSION)
    parser.add_argument("--client-name", default="mcp-probe")
    parser.add_argument("--client-version", default="0.1.0")
    parser.add_argument(
        "--client-capabilities",
        help="JSON object for initialize.params.capabilities. Defaults to {}.",
    )
    parser.add_argument(
        "--init-json",
        help="Initialize params object, or a full JSON-RPC initialize request object.",
    )
    parser.add_argument(
        "--init-file",
        help="Path to initialize params JSON, or a full JSON-RPC initialize request JSON.",
    )
    parser.add_argument("--raw", action="append", help="Exact JSON-RPC object to send. Use @file.json to load a file.")
    parser.add_argument("--discover", action="store_true", help="After initialize, call tools/list, resources/list, prompts/list.")
    parser.add_argument("--no-initialized", action="store_true", help="Do not send notifications/initialized after initialize.")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--log", help="Append JSONL transcript to this file.")
    parser.add_argument("--verbose", action="store_true", help="Print every send/receive event to stderr.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Probe MCP servers with controllable JSON-RPC messages.")
    sub = parser.add_subparsers(dest="mode", required=True)

    stdio = sub.add_parser("stdio", help="Launch and inspect a stdio MCP server.")
    add_common_args(stdio)
    stdio.add_argument("--env", action="append", help="Extra environment variable for the server, KEY=VALUE.")
    stdio.add_argument("--interactive", action="store_true", help="Open a small REPL after scripted requests.")
    stdio.add_argument("command", nargs=argparse.REMAINDER, help="Server command after --")
    stdio.set_defaults(func=run_stdio)

    http = sub.add_parser("http", help="Inspect a Streamable HTTP MCP endpoint.")
    add_common_args(http)
    http.add_argument("--url", required=True, help="MCP endpoint URL, for example http://localhost:3000/mcp")
    http.add_argument("--header", action="append", help="Extra HTTP header, for example 'Authorization: Bearer ...'.")
    http.add_argument(
        "--include-protocol-header-on-initialize",
        action="store_true",
        help="Also send MCP-Protocol-Version on the initialize request.",
    )
    http.set_defaults(func=run_http)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
