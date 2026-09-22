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
from collections import deque
import datetime as dt
import json
import os
import queue
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
from typing import Any


LATEST_PROTOCOL_VERSION = "2025-06-18"


Json = dict[str, Any]


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)


def parse_json_text(value: str, label: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{label} contains invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


def load_json_file(path_value: str, label: str) -> Any:
    try:
        text = Path(path_value).read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"Could not read {label} {path_value!r}: {exc.strerror or exc}") from exc
    return parse_json_text(text, f"{label} {path_value!r}")


def load_json_arg(value: str, label: str = "JSON argument") -> Any:
    if value.startswith("@"):
        path_value = value[1:]
        if not path_value:
            raise SystemExit(f"{label} @file path is empty.")
        return load_json_file(path_value, label)
    return parse_json_text(value, label)


def load_json_file_or_inline(file_value: str | None, json_value: str | None) -> Any | None:
    if file_value and json_value:
        raise SystemExit("Use either --init-file or --init-json, not both.")
    if file_value:
        return load_json_file(file_value, "--init-file")
    if json_value:
        return parse_json_text(json_value, "--init-json")
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


def mask_secrets(value: Any, secrets: list[str]) -> Any:
    if isinstance(value, dict):
        return {k: "***" if k.lower() in {"authorization", "cookie", "proxy-authorization"}
                or k.lower().endswith(("-token", "-key", "-secret"))
                else mask_secrets(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_secrets(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in sorted(set(secrets), key=len, reverse=True):
            if secret:
                value = value.replace(secret, "***")
    return value


class Logger:
    def __init__(self, verbose: bool, sink: Any = None, secrets: list[str] | None = None) -> None:
        self.verbose = verbose
        self.sink = sink
        self.secrets = secrets or []
        self.step: int | None = None
        self._lock = threading.Lock()

    def event(self, direction: str, transport: str, payload: Any, **meta: Any) -> None:
        if not self.verbose and self.sink is None:
            return
        record = {
            "ts": now_iso(),
            "direction": direction,
            "transport": transport,
            "payload": payload,
            **({"step": self.step} if self.step is not None else {}),
            **{k: v for k, v in meta.items() if v is not None},
        }
        if self.sink is not None:
            record = mask_secrets(record, self.secrets)
            payload = record["payload"]
        prefix = f"[{record['ts']}] {direction.upper()} {transport}"
        with self._lock:
            if self.sink is not None:
                self.sink.write(compact_json(record) + "\n")
                self.sink.flush()
            if not self.verbose:
                return
            if direction == "stderr":
                print(f"{prefix}: {payload}", file=sys.stderr)
            else:
                print(f"{prefix}:\n{pretty_json(payload)}", file=sys.stderr)

    def summary(self, value: Json) -> Json:
        masked = mask_secrets(value, self.secrets)
        with self._lock:
            self.sink.write(compact_json({"summary": masked}) + "\n")
            self.sink.flush()
        return masked


def default_initialize_params(args: argparse.Namespace) -> Json:
    capabilities = load_json_arg(args.client_capabilities, "--client-capabilities") if args.client_capabilities else {}
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
        self._stderr_tail: deque[str] = deque(maxlen=20)

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
            try:
                proc.send_signal(signal.SIGTERM)
            except OSError:
                return
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except OSError:
                    return
        except OSError:
            return

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
            text = line.rstrip("\n")
            self._stderr_tail.append(text)
            self.logger.event("stderr", "stdio", text)

    def send(self, message: Json) -> None:
        assert self._proc and self._proc.stdin
        payload = compact_json(message)
        self.logger.event("send", "stdio", message)
        try:
            self._proc.stdin.write(payload + "\n")
            self._proc.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise ConnectionError("Server closed its input before the probe could send a message.") from exc

    def next_id(self) -> int:
        current = self._next_id
        self._next_id += 1
        return current

    def wait_for_response(self, request_id: Any, timeout: float) -> Json:
        if request_id in self._responses:
            return self._responses.pop(request_id)
        deadline = time.monotonic() + timeout
        while True:
            if self._closed.is_set() and self._messages.empty():
                raise ConnectionError(self._server_exit_message(request_id))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for response id={request_id!r}")
            try:
                message = self._messages.get(timeout=min(remaining, 0.1))
            except queue.Empty as exc:
                if self._closed.is_set():
                    raise ConnectionError(self._server_exit_message(request_id)) from exc
                continue
            if "id" in message and ("result" in message or "error" in message):
                if message["id"] == request_id:
                    return message
                self._responses[message["id"]] = message
                continue
            self._handle_server_message(message)

    def _server_exit_message(self, request_id: Any) -> str:
        proc = self._proc
        returncode = proc.poll() if proc else None
        suffix = f" Server exit code: {returncode}." if returncode is not None else ""
        stderr = "\n".join(self._stderr_tail)
        if stderr:
            return f"Server exited before responding to id={request_id!r}.{suffix}\nServer stderr tail:\n{stderr}"
        return f"Server exited before responding to id={request_id!r}.{suffix}"

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

    logger = Logger(args.verbose)
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
            message = load_json_arg(raw, "--raw")
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
                rest = line[len("notify "):].strip()
                if not rest:
                    print("usage: notify method [json-params]")
                    continue
                method, _, params_text = rest.partition(" ")
                params = json.loads(params_text) if params_text.strip() else None
                msg: Json = {"jsonrpc": "2.0", "method": method}
                if params is not None:
                    msg["params"] = params
                probe.send(msg)
            else:
                method, _, params_text = line.partition(" ")
                params = json.loads(params_text) if params_text.strip() else {}
                response = probe.rpc(method, params, timeout)
                print_response(method, response)
        except Exception as exc:
            print(f"error: {exc}", file=sys.stderr)


def run_http(args: argparse.Namespace) -> int:
    logger = Logger(args.verbose)
    probe = HttpMcpProbe(args.url, parse_header(args.header), logger)
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
        message = load_json_arg(raw, "--raw")
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


def load_path(args: argparse.Namespace) -> tuple[Json, list[tuple[int, Json, Any]], list[str]]:
    path = load_json_file(args.path, "path")
    def require(condition: bool, reason: str) -> None:
        if not condition:
            raise SystemExit(f"Invalid path: {reason}")

    require(isinstance(path, dict), "expected an object")
    require(not set(path) - {"name", "description", "server", "handshake", "timeout", "steps"}, "unknown field")
    name = path.get("name")
    require(isinstance(name, str) and bool(name) and name not in {".", ".."}
            and "/" not in name and "\\" not in name, "name must be a nonempty filename")
    require("description" not in path or isinstance(path["description"], str), "description must be text")
    server = path.get("server", {})
    require(isinstance(server, dict), "server must be an object")
    server = dict(server)
    require(not set(server) - {"stdio", "http", "env", "headers"}, "unknown server field")
    require(not (args.server_cmd is not None and args.url is not None), "choose --server-cmd or --url")
    if args.server_cmd is not None:
        server.pop("http", None)
        server["stdio"] = args.server_cmd
    if args.url is not None:
        server.pop("stdio", None)
        server["http"] = args.url
    require(("stdio" in server) != ("http" in server), "choose exactly one stdio or http target")
    if "stdio" in server:
        command = server["stdio"]
        require(isinstance(command, list) and bool(command)
                and all(isinstance(part, str) and part for part in command), "stdio must be a nonempty argv list")
    else:
        url = server["http"]
        require(isinstance(url, str) and url.startswith(("http://", "https://")), "http must be an HTTP URL")
    secrets = []
    for key, overrides in (("env", parse_key_value(args.env, "--env")), ("headers", parse_header(args.header))):
        values = server.get(key, {})
        require(isinstance(values, dict) and all(isinstance(v, str) for v in values.values()), f"{key} must map names to strings")
        for mapping in (values, overrides):
            secrets.extend(v for k, v in mapping.items() if key == "env" or mask_secrets({k: v}, [])[k] == "***")
        if key == "headers":
            values = {k: v for k, v in values.items() if k.lower() not in {h.lower() for h in overrides}}
        if values or overrides:
            server[key] = {**values, **overrides}
    path["server"] = server
    timeout = args.timeout if args.timeout is not None else path.get("timeout", 15)
    require(type(timeout) in (int, float) and 0 < timeout < float("inf"), "timeout must be positive and finite")
    path["timeout"] = timeout
    handshake = path.get("handshake", "auto")
    require(handshake is False or handshake == "auto" or isinstance(handshake, dict), "invalid handshake")
    steps = path.get("steps")
    require(isinstance(steps, list), "steps must be a list")
    for n, step in enumerate(steps, 1):
        require(isinstance(step, dict), f"step {n} must be an object")
        raw = "send" in step
        allowed = {"send"} if raw else {"method", "params", "notify"}
        require(not set(step) - allowed - {"expect", "wait", "label"}, f"unknown field in step {n}")
        if not raw:
            require(isinstance(step.get("method"), str) and bool(step["method"]), f"step {n} needs a method")
            require(isinstance(step.get("params", {}), dict), f"step {n} params must be an object")
        for key in ("wait", "notify"):
            require(key not in step or type(step[key]) is bool, f"step {n} {key} must be boolean")
        require("expect" not in step or step["expect"] in ("result", "error", "none", "timeout"), f"step {n} has invalid expect")
        require("label" not in step or isinstance(step["label"], str), f"step {n} label must be text")
    used_ids = [id_of(s["send"]) for s in steps if "send" in s]
    next_id = 1
    expanded = []
    for n, step in enumerate(steps, 1):
        if "send" in step:
            message = step["send"]
        else:
            while next_id in used_ids:
                next_id += 1
            message = request(step["method"], next_id, step.get("params", {}))
            next_id += 1
            if step.get("notify"):
                message.pop("id")
        expanded.append((n, step, message))
    if isinstance(handshake, dict) or (handshake == "auto" and not any(method_of(m) == "initialize" for _, _, m in expanded)):
        while next_id in used_ids:
            next_id += 1
        params = handshake if isinstance(handshake, dict) else {
            "protocolVersion": LATEST_PROTOCOL_VERSION, "capabilities": {},
            "clientInfo": {"name": "mcp-probe", "version": "0.2.0"},
        }
        expanded[0:0] = [(0, {}, request("initialize", next_id, params)), (0, {}, initialized_notification())]
    return path, expanded, secrets


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
    try:
        return int(args.func(args) or 0)
    except SystemExit:
        raise
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    except urllib.error.URLError as exc:
        print(f"HTTP error: {exc.reason}", file=sys.stderr)
        return 1
    except TimeoutError as exc:
        print(f"Timeout: {exc}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"File not found: {exc.filename or exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}", file=sys.stderr)
        return 1
    except (BrokenPipeError, ConnectionError) as exc:
        print(f"Connection error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"OS error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
