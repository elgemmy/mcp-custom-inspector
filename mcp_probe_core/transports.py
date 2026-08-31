"""Raw stdio and Streamable HTTP transports with evidence capture."""

from __future__ import annotations

import http.client
import json
import os
import queue
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .errors import ProbeTimeout, ProcessExited, TransportError
from .protocol import (
    JsonObject,
    ProtocolProfile,
    classify_message,
    make_notification,
    make_request,
    message_id,
    modern_http_headers,
)
from .redaction import redact_command, redact_text, redact_url
from .transcript import EventRecorder, compact_json


DEFAULT_MAX_MESSAGE_BYTES = 8 * 1024 * 1024


@dataclass
class InboundMessage:
    payload: Any
    raw: str
    classification: str
    evidence: str
    http_status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    sse_event: str | None = None
    sse_id: str | None = None
    handled: bool = False


@dataclass
class CleanupResult:
    returncode: int | None
    graceful: bool
    terminated: bool
    killed: bool


@dataclass
class HttpExchange:
    status: int
    headers: dict[str, str]
    body: str
    messages: list[InboundMessage]
    parse_issues: list[str]
    timed_out: bool = False


@dataclass
class HttpRpcResult:
    response: InboundMessage
    exchange: HttpExchange


def _rpc_key(value: Any) -> tuple[str, str | int] | None:
    if type(value) is int:
        return ("int", value)
    if isinstance(value, str):
        return ("str", value)
    return None


def header_value(headers: dict[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


class StdioTransport:
    """Newline-framed MCP over a managed subprocess."""

    def __init__(
        self,
        command: list[str],
        env: dict[str, str],
        recorder: EventRecorder,
        *,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        shutdown_timeout: float = 2.0,
    ) -> None:
        if not command:
            raise TransportError("stdio transport requires a server command.")
        self.command = list(command)
        self.env = dict(env)
        self.recorder = recorder
        self.max_message_bytes = max_message_bytes
        self.shutdown_timeout = shutdown_timeout
        self.server_request_handler: Callable[[InboundMessage], JsonObject | None] | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._incoming: queue.Queue[InboundMessage] = queue.Queue()
        self._pending: dict[tuple[str, str | int], list[InboundMessage]] = {}
        self._notifications: queue.Queue[InboundMessage] = queue.Queue()
        self._server_requests: queue.Queue[InboundMessage] = queue.Queue()
        self._server_request_evidence: set[str] = set()
        self._invalid: queue.Queue[InboundMessage] = queue.Queue()
        self._invalid_evidence: set[str] = set()
        self._stdout_eof = threading.Event()
        self._closing = threading.Event()
        self._threads: list[threading.Thread] = []
        self._next_id = 1
        self._used_ids: set[tuple[str, str | int]] = set()
        self._outstanding: dict[tuple[str, str | int], str] = {}
        self._write_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._cleanup_result: CleanupResult | None = None

    @property
    def process(self) -> subprocess.Popen[bytes] | None:
        return self._proc

    @property
    def returncode(self) -> int | None:
        return self._proc.poll() if self._proc else None

    def start(self) -> None:
        if self._proc is not None:
            return
        full_env = os.environ.copy()
        full_env.update(self.env)
        try:
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=0,
                env=full_env,
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            self.recorder.record(
                "probe",
                "stdio",
                classification="startup_error",
                error=str(exc),
                command=redact_command(self.command),
                environmentKeys=sorted(self.env),
            )
            raise TransportError(f"Could not start stdio server: {exc}") from exc
        self.recorder.record(
            "probe",
            "stdio",
            classification="process_start",
            command=redact_command(self.command),
            environmentKeys=sorted(self.env),
            pid=self._proc.pid,
        )
        self._threads = [
            threading.Thread(target=self._read_stdout, name="mcp-probe-stdout", daemon=True),
            threading.Thread(target=self._read_stderr, name="mcp-probe-stderr", daemon=True),
            threading.Thread(target=self._watch_process, name="mcp-probe-wait", daemon=True),
        ]
        for thread in self._threads:
            thread.start()

    def _read_stdout(self) -> None:
        assert self._proc is not None and self._proc.stdout is not None
        stream = self._proc.stdout
        try:
            while not self._closing.is_set():
                raw = stream.readline(self.max_message_bytes + 1)
                if not raw:
                    break
                if len(raw) > self.max_message_bytes:
                    if not raw.endswith(b"\n"):
                        while raw and not raw.endswith(b"\n"):
                            raw = stream.readline(self.max_message_bytes + 1)
                    evidence = self.recorder.record(
                        "server_to_client",
                        "stdio",
                        classification="message_too_large",
                        error=f"stdout message exceeded {self.max_message_bytes} bytes",
                    )
                    message = InboundMessage(None, "", "message_too_large", evidence)
                    self._observe_invalid(message)
                    self._incoming.put(message)
                    continue
                wire = raw[:-1] if raw.endswith(b"\n") else raw
                if wire.endswith(b"\r"):
                    wire = wire[:-1]
                if not wire:
                    continue
                try:
                    text = wire.decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    replacement = wire.decode("utf-8", errors="replace")
                    evidence = self.recorder.record(
                        "server_to_client",
                        "stdio",
                        classification="invalid_utf8",
                        raw=replacement,
                        error=str(exc),
                        byteLength=len(wire),
                    )
                    message = InboundMessage(None, replacement, "invalid_utf8", evidence)
                    self._observe_invalid(message)
                    self._incoming.put(message)
                    continue
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as exc:
                    evidence = self.recorder.record(
                        "server_to_client",
                        "stdio",
                        classification="invalid_json",
                        raw=text,
                        error=str(exc),
                    )
                    message = InboundMessage(None, text, "invalid_json", evidence)
                    self._observe_invalid(message)
                    self._incoming.put(message)
                    continue
                classification = classify_message(payload)
                evidence = self.recorder.record(
                    "server_to_client",
                    "stdio",
                    payload=payload,
                    raw=text,
                    classification=classification,
                )
                message = InboundMessage(payload, text, classification, evidence)
                if classification == "invalid":
                    self._observe_invalid(message)
                elif classification == "request":
                    self._service_server_request(message)
                self._incoming.put(message)
        except (OSError, ValueError) as exc:
            if not self._closing.is_set():
                self.recorder.record(
                    "probe", "stdio", classification="stdout_error", error=str(exc)
                )
        finally:
            self._stdout_eof.set()
            self.recorder.record("probe", "stdio", classification="stdout_eof")

    def _read_stderr(self) -> None:
        assert self._proc is not None and self._proc.stderr is not None
        stream = self._proc.stderr
        try:
            while not self._closing.is_set():
                raw = stream.readline(self.max_message_bytes + 1)
                if not raw:
                    break
                text = raw.rstrip(b"\r\n").decode("utf-8", errors="replace")
                self.recorder.record(
                    "server_stderr", "stdio", classification="stderr", raw=text
                )
        except (OSError, ValueError) as exc:
            if not self._closing.is_set():
                self.recorder.record(
                    "probe", "stdio", classification="stderr_error", error=str(exc)
                )

    def _watch_process(self) -> None:
        assert self._proc is not None
        returncode = self._proc.wait()
        self.recorder.record(
            "probe", "stdio", classification="process_exit", exitCode=returncode
        )

    def reserve_id(self, value: Any) -> None:
        key = _rpc_key(value)
        if key is not None:
            self._used_ids.add(key)

    def next_id(self) -> int:
        while ("int", self._next_id) in self._used_ids:
            self._next_id += 1
        value = self._next_id
        self._next_id += 1
        self._used_ids.add(("int", value))
        return value

    def send_message(self, message: Any) -> str:
        if self._proc is None or self._proc.stdin is None:
            raise TransportError("stdio server has not been started.")
        wire = compact_json(message)
        if isinstance(message, dict) and "id" in message:
            self.reserve_id(message.get("id"))
            key = _rpc_key(message.get("id"))
            if key and isinstance(message.get("method"), str):
                self._outstanding[key] = message["method"]
        evidence = self.recorder.record(
            "client_to_server",
            "stdio",
            payload=message,
            raw=wire,
            classification=classify_message(message),
        )
        data = wire.encode("utf-8") + b"\n"
        try:
            with self._write_lock:
                self._proc.stdin.write(data)
                self._proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            self.recorder.record(
                "probe", "stdio", classification="write_error", error=str(exc)
            )
            raise TransportError(f"Could not write to stdio server: {exc}") from exc
        return evidence

    def send_wire(self, data: str | bytes, *, append_newline: bool = True) -> str:
        if self._proc is None or self._proc.stdin is None:
            raise TransportError("stdio server has not been started.")
        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        display = raw_bytes.decode("utf-8", errors="replace")
        evidence = self.recorder.record(
            "client_to_server",
            "stdio",
            classification="raw_wire",
            raw=display,
            byteLength=len(raw_bytes),
            exactBytesRecorded=isinstance(data, str),
            appendNewline=append_newline,
        )
        wire = raw_bytes + (b"\n" if append_newline else b"")
        try:
            with self._write_lock:
                self._proc.stdin.write(wire)
                self._proc.stdin.flush()
        except (BrokenPipeError, OSError, ValueError) as exc:
            self.recorder.record(
                "probe", "stdio", classification="write_error", error=str(exc)
            )
            raise TransportError(f"Could not write raw stdio bytes: {exc}") from exc
        return evidence

    def receive(self, timeout: float) -> InboundMessage:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeTimeout("Timed out waiting for a stdio message.")
            try:
                return self._incoming.get(timeout=min(remaining, 0.1))
            except queue.Empty:
                if self._stdout_eof.is_set() and self._incoming.empty():
                    returncode = self.returncode
                    detail = f" (exit {returncode})" if returncode is not None else ""
                    raise ProcessExited(f"stdio server closed stdout{detail}.")

    def wait_for_response(
        self,
        request_id: str | int,
        timeout: float,
        *,
        cancel_on_timeout: bool = True,
    ) -> InboundMessage:
        wanted = _rpc_key(request_id)
        if wanted is None:
            raise TransportError("Cannot correlate a response to a non-string/non-integer request ID.")
        waiting = self._pending.get(wanted)
        if waiting:
            message = waiting.pop(0)
            if not waiting:
                self._pending.pop(wanted, None)
            self._outstanding.pop(wanted, None)
            return message
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.recorder.record(
                    "probe",
                    "stdio",
                    classification="timeout",
                    requestId=request_id,
                    timeoutSeconds=timeout,
                )
                method = self._outstanding.get(wanted)
                if cancel_on_timeout and method and method != "initialize":
                    try:
                        self.send_message(
                            make_notification(
                                "notifications/cancelled",
                                {"requestId": request_id, "reason": "MCP Probe timeout"},
                            )
                        )
                    except TransportError:
                        pass
                raise ProbeTimeout(f"Timed out waiting for response id={request_id!r}.")
            try:
                inbound = self.receive(min(remaining, 0.25))
            except ProbeTimeout:
                continue
            if inbound.classification == "response" and isinstance(inbound.payload, dict):
                key = _rpc_key(inbound.payload.get("id"))
                if key is None:
                    self._observe_invalid(inbound)
                    continue
                if key == wanted:
                    self._outstanding.pop(wanted, None)
                    return inbound
                self._pending.setdefault(key, []).append(inbound)
                continue
            if inbound.classification == "request":
                self._service_server_request(inbound)
                continue
            if inbound.classification == "notification":
                self._notifications.put(inbound)
                continue
            self._observe_invalid(inbound)

    def rpc(self, method: str, params: JsonObject | None, timeout: float) -> InboundMessage:
        request_id = self.next_id()
        self.send_message(make_request(method, request_id, params))
        return self.wait_for_response(request_id, timeout)

    def observed_server_requests(self) -> list[InboundMessage]:
        return _drain_queue(self._server_requests)

    def observed_notifications(self) -> list[InboundMessage]:
        return _drain_queue(self._notifications)

    def observed_invalid_messages(self) -> list[InboundMessage]:
        return _drain_queue(self._invalid)

    def _service_server_request(self, message: InboundMessage) -> None:
        if message.evidence not in self._server_request_evidence:
            self._server_request_evidence.add(message.evidence)
            self._server_requests.put(message)
        if message.handled or not self.server_request_handler:
            return
        # Mark first so a response wait cannot race the reader into replying a
        # second time to the same server request.
        message.handled = True
        response = self.server_request_handler(message)
        if response is not None:
            self.send_message(response)

    def _observe_invalid(self, message: InboundMessage) -> None:
        if message.evidence in self._invalid_evidence:
            return
        self._invalid_evidence.add(message.evidence)
        self._invalid.put(message)

    def close(self) -> CleanupResult:
        with self._close_lock:
            return self._close_once()

    def _close_once(self) -> CleanupResult:
        if self._cleanup_result is not None:
            return self._cleanup_result
        proc = self._proc
        if proc is None:
            self._cleanup_result = CleanupResult(None, True, False, False)
            return self._cleanup_result
        self._closing.set()
        graceful = False
        terminated = False
        killed = False
        if proc.stdin is not None:
            try:
                proc.stdin.close()
            except OSError:
                pass
        try:
            proc.wait(timeout=self.shutdown_timeout)
            graceful = True
        except subprocess.TimeoutExpired:
            terminated = True
            self.recorder.record("probe", "stdio", classification="process_terminate")
            self._signal_process_group(signal.SIGTERM)
            try:
                proc.wait(timeout=self.shutdown_timeout)
            except subprocess.TimeoutExpired:
                killed = True
                self.recorder.record("probe", "stdio", classification="process_kill")
                self._signal_process_group(signal.SIGKILL if os.name == "posix" else None)
                try:
                    proc.wait(timeout=self.shutdown_timeout)
                except subprocess.TimeoutExpired:
                    self.recorder.record(
                        "probe",
                        "stdio",
                        classification="cleanup_error",
                        error="process did not exit after forced termination",
                    )
        descendant_terminated, descendant_killed = self._cleanup_descendant_group()
        terminated = terminated or descendant_terminated
        killed = killed or descendant_killed
        for stream in (proc.stdout, proc.stderr):
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=0.5)
        result = CleanupResult(proc.poll(), graceful, terminated, killed)
        self.recorder.record(
            "probe",
            "stdio",
            classification="process_cleanup",
            exitCode=result.returncode,
            graceful=graceful,
            terminated=terminated,
            killed=killed,
        )
        self._cleanup_result = result
        return result

    def _signal_process_group(self, sig: int | None) -> bool:
        proc = self._proc
        if proc is None:
            return False
        try:
            if os.name == "posix" and sig is not None:
                os.killpg(proc.pid, sig)
            elif proc.poll() is not None:
                return False
            elif sig == signal.SIGTERM:
                proc.terminate()
            else:
                proc.kill()
        except (OSError, ProcessLookupError):
            return False
        return True

    def _cleanup_descendant_group(self) -> tuple[bool, bool]:
        """Terminate descendants even when the process-group leader exited first."""

        if os.name != "posix" or self._proc is None:
            return False, False
        try:
            os.killpg(self._proc.pid, 0)
        except (OSError, ProcessLookupError):
            return False, False
        self.recorder.record(
            "probe", "stdio", classification="process_group_terminate"
        )
        terminated = self._signal_process_group(signal.SIGTERM)
        if not terminated:
            return False, False
        time.sleep(min(self.shutdown_timeout, 0.05))
        try:
            os.killpg(self._proc.pid, 0)
        except (OSError, ProcessLookupError):
            return True, False
        self.recorder.record("probe", "stdio", classification="process_group_kill")
        return True, self._signal_process_group(signal.SIGKILL)


class HttpTransport:
    """Synchronous request-scoped Streamable HTTP subset."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str],
        recorder: EventRecorder,
        profile: ProtocolProfile,
        *,
        max_body_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ) -> None:
        if not profile.streamable_http:
            raise TransportError(
                f"Protocol {profile.version} uses deprecated HTTP+SSE, not Streamable HTTP."
            )
        self.url = url
        self.extra_headers = dict(headers)
        self.recorder = recorder
        self.profile = profile
        self.max_body_bytes = max_body_bytes
        self.session_id: str | None = None
        self.protocol_version = profile.version
        self.initialized = False
        self.server_request_handler: Callable[[InboundMessage], JsonObject | None] | None = None
        self._next_id = 1
        self._used_ids: set[tuple[str, str | int]] = set()
        self._session_lock = threading.RLock()
        self._termination_result: int | None = None
        self.recorder.record(
            "probe", "http", classification="transport_ready", url=self.url
        )

    def reserve_id(self, value: Any) -> None:
        key = _rpc_key(value)
        if key is not None:
            self._used_ids.add(key)

    def next_id(self) -> int:
        while ("int", self._next_id) in self._used_ids:
            self._next_id += 1
        value = self._next_id
        self._next_id += 1
        self._used_ids.add(("int", value))
        return value

    def send_message(
        self,
        message: Any,
        timeout: float,
        *,
        include_protocol_header_on_initialize: bool = False,
        derived_headers: dict[str, str] | None = None,
    ) -> HttpExchange:
        body = compact_json(message).encode("utf-8")
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **self.extra_headers,
        }
        method = message.get("method") if isinstance(message, dict) else None
        if self.profile.modern and isinstance(message, dict):
            headers.update(modern_http_headers(message, self.protocol_version))
        elif self.profile.protocol_header and (
            self.initialized or include_protocol_header_on_initialize
        ):
            headers["MCP-Protocol-Version"] = self.protocol_version
        if self.profile.http_sessions and self.session_id:
            headers["MCP-Session-Id"] = self.session_id
        if derived_headers:
            headers.update(derived_headers)
        if isinstance(message, dict) and "id" in message:
            self.reserve_id(message.get("id"))
        exchange = self._send_body(
            body,
            timeout,
            headers=headers,
            displayed_payload=message,
            classification=classify_message(message),
        )
        if method == "initialize" and exchange.messages:
            matching = _find_matching_response(exchange.messages, message.get("id"))
            if matching and isinstance(matching.payload, dict) and "result" in matching.payload:
                self.initialized = True
                session_id = header_value(exchange.headers, "MCP-Session-Id")
                if self.profile.http_sessions and session_id:
                    self.session_id = session_id
                    self._termination_result = None
                    self.recorder.record(
                        "probe",
                        "http",
                        classification="session_assigned",
                        headers={"MCP-Session-Id": session_id},
                    )
        return exchange

    def send_wire(
        self,
        body: str | bytes,
        timeout: float,
        *,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> HttpExchange:
        raw = body.encode("utf-8") if isinstance(body, str) else body
        request_headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": content_type,
            **self.extra_headers,
            **(headers or {}),
        }
        if self.profile.modern:
            request_headers.setdefault("MCP-Protocol-Version", self.protocol_version)
        elif self.profile.protocol_header and self.initialized:
            request_headers.setdefault("MCP-Protocol-Version", self.protocol_version)
        if self.profile.http_sessions and self.session_id:
            request_headers["MCP-Session-Id"] = self.session_id
        return self._send_body(
            raw,
            timeout,
            headers=request_headers,
            displayed_payload=None,
            raw_display=raw.decode("utf-8", errors="replace"),
            classification="raw_wire",
        )

    def _send_body(
        self,
        body: bytes,
        timeout: float,
        *,
        headers: dict[str, str],
        displayed_payload: Any,
        classification: str,
        raw_display: str | None = None,
    ) -> HttpExchange:
        self.recorder.record(
            "client_to_server",
            "http",
            payload=displayed_payload,
            raw=raw_display,
            classification=classification,
            headers=headers,
            url=self.url,
            byteLength=len(body),
            contentType=header_value(headers, "Content-Type"),
        )
        status: int
        response_headers: dict[str, str]
        response_body: bytes
        timed_out = False
        try:
            request = urllib.request.Request(
                self.url, data=body, headers=headers, method="POST"
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(response.status)
                response_headers = {key: value for key, value in response.headers.items()}
                response_body, timed_out = _read_http_body(
                    response, self.max_body_bytes
                )
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_headers = {key: value for key, value in exc.headers.items()}
            try:
                response_body, timed_out = _read_http_body(exc, self.max_body_bytes)
            finally:
                exc.close()
        except (socket.timeout, TimeoutError) as exc:
            self.recorder.record(
                "probe",
                "http",
                classification="timeout",
                url=self.url,
                error=str(exc),
                timeoutSeconds=timeout,
            )
            raise ProbeTimeout(
                f"HTTP request timed out for {redact_url(self.url)}."
            ) from None
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                self.recorder.record(
                    "probe",
                    "http",
                    classification="timeout",
                    url=self.url,
                    error=str(exc.reason),
                    timeoutSeconds=timeout,
                )
                raise ProbeTimeout(
                    f"HTTP request timed out for {redact_url(self.url)}."
                ) from None
            self.recorder.record(
                "probe",
                "http",
                classification="transport_error",
                url=self.url,
                error=str(exc),
            )
            raise TransportError(
                f"HTTP request failed for {redact_url(self.url)}: {redact_text(str(exc))}"
            ) from None
        except (OSError, ValueError, http.client.InvalidURL) as exc:
            self.recorder.record(
                "probe",
                "http",
                classification="transport_error",
                url=self.url,
                error=str(exc),
            )
            raise TransportError(
                f"HTTP request failed for {redact_url(self.url)}: {redact_text(str(exc))}"
            ) from None
        try:
            text = response_body.decode("utf-8", errors="strict")
            decode_issues: list[str] = []
        except UnicodeDecodeError as exc:
            text = response_body.decode("utf-8", errors="replace")
            decode_issues = [f"HTTP body is not valid UTF-8: {exc}"]
        self.recorder.record(
            "probe",
            "http",
            classification="http_response",
            status=status,
            headers=response_headers,
            url=self.url,
            byteLength=len(response_body),
            timedOut=timed_out,
        )
        content_type = header_value(response_headers, "Content-Type") or ""
        parsed, issues = parse_http_messages(text, content_type)
        issues = decode_issues + issues
        messages: list[InboundMessage] = []
        for payload, event_name, event_id, raw_event in parsed:
            message_class = classify_message(payload)
            evidence = self.recorder.record(
                "server_to_client",
                "http",
                payload=payload,
                raw=raw_event,
                classification=message_class,
                status=status,
                headers=response_headers,
                url=self.url,
                sseEvent=event_name,
                sseId=event_id,
            )
            messages.append(
                InboundMessage(
                    payload,
                    raw_event,
                    message_class,
                    evidence,
                    status,
                    response_headers,
                    event_name,
                    event_id,
                )
            )
        if not messages and text:
            self.recorder.record(
                "server_to_client",
                "http",
                raw=text,
                classification="invalid_body" if issues else "empty_message_set",
                status=status,
                headers=response_headers,
                url=self.url,
                parseIssues=issues,
            )
        for issue in issues:
            self.recorder.record(
                "probe",
                "http",
                classification="parse_issue",
                status=status,
                error=issue,
            )
        return HttpExchange(status, response_headers, text, messages, issues, timed_out)

    def rpc(
        self,
        method: str,
        params: JsonObject | None,
        timeout: float,
        *,
        message_transform: Callable[[JsonObject], JsonObject] | None = None,
        derived_headers: dict[str, str] | None = None,
    ) -> HttpRpcResult:
        request_id = self.next_id()
        message = make_request(method, request_id, params)
        if message_transform:
            message = message_transform(message)
        exchange = self.send_message(
            message, timeout, derived_headers=derived_headers
        )
        response = _find_matching_response(exchange.messages, request_id)
        for inbound in exchange.messages:
            if inbound.classification == "request":
                if self.server_request_handler:
                    reply = self.server_request_handler(inbound)
                    if reply is not None:
                        self.send_message(reply, timeout)
        if response is None:
            if exchange.timed_out:
                raise ProbeTimeout(
                    f"HTTP response stream timed out before response id={request_id!r}."
                )
            raise TransportError(
                f"HTTP response did not contain a response matching id={request_id!r}."
            )
        return HttpRpcResult(response, exchange)

    def terminate_session(self, timeout: float) -> int | None:
        with self._session_lock:
            return self._terminate_session_once(timeout)

    def _terminate_session_once(self, timeout: float) -> int | None:
        if not self.profile.http_sessions or not self.session_id:
            return self._termination_result
        headers = {
            "Accept": "application/json, text/event-stream",
            **self.extra_headers,
            "MCP-Session-Id": self.session_id,
        }
        if self.profile.protocol_header:
            headers["MCP-Protocol-Version"] = self.protocol_version
        self.recorder.record(
            "client_to_server",
            "http",
            classification="session_terminate",
            headers=headers,
            url=self.url,
        )
        try:
            request = urllib.request.Request(self.url, headers=headers, method="DELETE")
            with urllib.request.urlopen(request, timeout=timeout) as response:
                status = int(response.status)
                response_headers = {key: value for key, value in response.headers.items()}
                response.read(self.max_body_bytes + 1)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_headers = {key: value for key, value in exc.headers.items()}
            exc.close()
        except (
            urllib.error.URLError,
            socket.timeout,
            TimeoutError,
            OSError,
            ValueError,
            http.client.InvalidURL,
        ) as exc:
            self.recorder.record(
                "probe",
                "http",
                classification="session_termination_error",
                error=str(exc),
                url=self.url,
            )
            raise TransportError(
                f"Could not terminate HTTP session: {redact_text(str(exc))}"
            ) from None
        finally:
            self.session_id = None
        self.recorder.record(
            "server_to_client",
            "http",
            classification="session_terminated",
            status=status,
            headers=response_headers,
            url=self.url,
        )
        self._termination_result = status
        return status

    def close(self, timeout: float = 2.0) -> int | None:
        return self.terminate_session(timeout)


def _drain_queue(source: queue.Queue[InboundMessage]) -> list[InboundMessage]:
    values: list[InboundMessage] = []
    while True:
        try:
            values.append(source.get_nowait())
        except queue.Empty:
            return values


def _find_matching_response(
    messages: Iterable[InboundMessage], request_id: Any
) -> InboundMessage | None:
    wanted = _rpc_key(request_id)
    if wanted is None:
        return None
    for message in messages:
        if message.classification != "response" or not isinstance(message.payload, dict):
            continue
        if _rpc_key(message.payload.get("id")) == wanted:
            return message
    return None


def _read_http_body(response: Any, limit: int) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    timed_out = False
    while True:
        try:
            chunk = response.read(min(65536, limit + 1 - total))
        except (socket.timeout, TimeoutError):
            timed_out = True
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > limit:
            raise TransportError(f"HTTP response body exceeded {limit} bytes.")
    return b"".join(chunks), timed_out


def parse_http_messages(
    body: str, content_type: str
) -> tuple[list[tuple[Any, str | None, str | None, str]], list[str]]:
    if not body.strip():
        return [], []
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "text/event-stream":
        return parse_sse_messages(body)
    issues: list[str] = []
    if media_type != "application/json":
        issues.append(
            f"unexpected Content-Type {content_type!r}; expected application/json or text/event-stream"
        )
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        return [], [*issues, f"invalid JSON body: {exc}"]
    if not isinstance(payload, dict):
        issues.append("HTTP JSON response is not one JSON-RPC object")
    return [(payload, None, None, body)], issues


def parse_sse_messages(
    body: str,
) -> tuple[list[tuple[Any, str | None, str | None, str]], list[str]]:
    parsed: list[tuple[Any, str | None, str | None, str]] = []
    issues: list[str] = []
    data_lines: list[str] = []
    event_name: str | None = None
    event_id: str | None = None
    last_event_id: str | None = None

    def flush() -> None:
        nonlocal event_name, event_id, last_event_id
        if not data_lines:
            event_name = None
            event_id = None
            return
        data = "\n".join(data_lines)
        data_lines.clear()
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            issues.append(f"invalid SSE JSON data: {exc}")
        else:
            if not isinstance(payload, dict):
                issues.append("SSE data is not one JSON-RPC object")
            if event_id is not None:
                last_event_id = event_id
            parsed.append((payload, event_name, last_event_id, data))
        event_name = None
        event_id = None

    for line in body.splitlines():
        if line == "":
            flush()
            continue
        if line.startswith(":"):
            continue
        field_name, separator, value = line.partition(":")
        if not separator:
            value = ""
        elif value.startswith(" "):
            value = value[1:]
        if field_name == "data":
            data_lines.append(value)
        elif field_name == "event":
            event_name = value
        elif field_name == "id":
            if "\x00" in value:
                issues.append("SSE id contains a null character")
            else:
                event_id = value
        elif field_name == "retry":
            if value and not value.isdigit():
                issues.append("SSE retry value is not an integer")
    flush()
    return parsed, issues
