"""Raw stdio and Streamable HTTP transports with evidence capture."""

from __future__ import annotations

import http.client
import json
import os
import queue
import select
import signal
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable

from .errors import ConfigurationError, ProbeTimeout, ProcessExited, TransportError
from .protocol import (
    JsonObject,
    ProtocolProfile,
    classify_message,
    make_notification,
    make_request,
    message_id,
    modern_http_headers,
    strict_json_loads,
)
from .redaction import (
    known_secrets_from_command,
    known_secrets_from_headers,
    known_secrets_from_url,
    redact_command,
    redact_text,
    redact_url,
    sensitive_key,
)
from .transcript import EventRecorder, compact_json


DEFAULT_MAX_MESSAGE_BYTES = 8 * 1024 * 1024
DEFAULT_STDIO_WRITE_TIMEOUT = 2.0
MAX_BATCH_MESSAGES = 1000
MAX_BUFFERED_STDIO_MESSAGES = 1000
MAX_BUFFERED_STDIO_BYTES = 16 * 1024 * 1024
MAX_SSE_EVENTS = 1000
MAX_SSE_LINES = 10_000
MAX_SSE_ISSUES = 100
MAX_SSE_ID_BYTES = 4096
MAX_SSE_FIELD_BYTES = DEFAULT_MAX_MESSAGE_BYTES
MAX_HTTP_SERVER_REQUEST_DEPTH = 8
_HTTP_FIELD_NAME = "!#$%&'*+-.^_`|~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
_UNSAFE_USER_HTTP_FIELDS = {
    "connection",
    "content-length",
    "host",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def validate_http_headers(headers: dict[str, str]) -> None:
    """Reject names/values which cannot be represented as RFC HTTP fields."""

    lowered: set[str] = set()
    for name, value in headers.items():
        if not isinstance(name, str) or not name or any(
            character not in _HTTP_FIELD_NAME for character in name
        ):
            raise ConfigurationError(f"Invalid HTTP header name: {name!r}.")
        normalized = name.lower()
        if normalized in _UNSAFE_USER_HTTP_FIELDS:
            raise ConfigurationError(
                f"HTTP framing or hop-by-hop header {name!r} is not user-configurable."
            )
        if normalized in lowered:
            raise ConfigurationError(
                f"Duplicate case-insensitive HTTP header name: {name!r}."
            )
        lowered.add(normalized)
        if not isinstance(value, str) or any(
            not (
                character == "\t"
                or 0x20 <= ord(character) <= 0x7E
                or 0x80 <= ord(character) <= 0xFF
            )
            for character in value
        ):
            raise ConfigurationError(
                f"HTTP header {name!r} contains an invalid field value."
            )


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


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Expose redirects to the caller instead of forwarding sensitive headers."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


class _SseDecoder:
    """Incremental, deliberately small SSE event decoder for JSON-RPC data."""

    def __init__(self, *, max_event_bytes: int = DEFAULT_MAX_MESSAGE_BYTES) -> None:
        self.data_lines: list[str] = []
        self.event_name: str | None = None
        self.event_id: str | None = None
        self.last_event_id: str | None = None
        self.max_event_bytes = max_event_bytes
        self._data_bytes = 0
        self._lines = 0
        self._events = 0
        self._issues = 0

    def feed_line(
        self, line: str
    ) -> tuple[list[tuple[Any, str | None, str | None, str]], list[str]]:
        self._lines += 1
        if self._lines > MAX_SSE_LINES:
            raise TransportError(
                f"SSE response exceeded the {MAX_SSE_LINES}-line safety limit."
            )
        line_bytes = len(line.encode("utf-8"))
        if line_bytes > MAX_SSE_FIELD_BYTES:
            raise TransportError(
                f"SSE line exceeded the {MAX_SSE_FIELD_BYTES}-byte safety limit."
            )
        if line == "":
            return self._flush()
        if line.startswith(":"):
            return [], []
        field_name, separator, value = line.partition(":")
        if not separator:
            value = ""
        elif value.startswith(" "):
            value = value[1:]
        issues: list[str] = []
        if field_name == "data":
            added = len(value.encode("utf-8")) + (1 if self.data_lines else 0)
            self._data_bytes += added
            if self._data_bytes > self.max_event_bytes:
                raise TransportError(
                    f"SSE event data exceeded the {self.max_event_bytes}-byte safety limit."
                )
            self.data_lines.append(value)
        elif field_name == "event":
            if len(value.encode("utf-8")) > MAX_SSE_ID_BYTES:
                raise TransportError(
                    f"SSE event name exceeded the {MAX_SSE_ID_BYTES}-byte safety limit."
                )
            self.event_name = value
        elif field_name == "id":
            if len(value.encode("utf-8")) > MAX_SSE_ID_BYTES:
                raise TransportError(
                    f"SSE id exceeded the {MAX_SSE_ID_BYTES}-byte safety limit."
                )
            if "\x00" in value:
                issues.append(self._issue("SSE id contains a null character"))
            else:
                self.event_id = value
        elif field_name == "retry" and value and not value.isdigit():
            issues.append(self._issue("SSE retry value is not an integer"))
        return [], issues

    def finish(
        self,
    ) -> tuple[list[tuple[Any, str | None, str | None, str]], list[str]]:
        return self._flush()

    def _flush(
        self,
    ) -> tuple[list[tuple[Any, str | None, str | None, str]], list[str]]:
        if self.event_id is not None:
            self.last_event_id = self.event_id
        data = "\n".join(self.data_lines)
        had_data_field = bool(self.data_lines)
        event_name = self.event_name
        event_id = self.last_event_id
        self.data_lines.clear()
        self.event_name = None
        self.event_id = None
        self._data_bytes = 0
        # Empty data events are commonly used to prime a resumable SSE stream.
        # They are valid transport traffic, but do not contain a JSON-RPC message.
        if not had_data_field or not data.strip():
            return [], []
        self._events += 1
        if self._events > MAX_SSE_EVENTS:
            raise TransportError(
                f"SSE response exceeded the {MAX_SSE_EVENTS}-event safety limit."
            )
        try:
            payload = strict_json_loads(data)
        except (json.JSONDecodeError, ValueError) as exc:
            return [], [self._issue(f"invalid SSE JSON data: {exc}")]
        issues: list[str] = []
        return [(payload, event_name, event_id, data)], issues

    def _issue(self, message: str) -> str:
        self._issues += 1
        if self._issues > MAX_SSE_ISSUES:
            raise TransportError(
                f"SSE response exceeded the {MAX_SSE_ISSUES}-issue safety limit."
            )
        return message


def _rpc_key(value: Any) -> tuple[str, str | int] | None:
    if type(value) is int:
        return ("int", value)
    if isinstance(value, str):
        return ("str", value)
    return None


def _outbound_message_classification(
    value: Any, profile: ProtocolProfile | None
) -> str:
    if not isinstance(value, list):
        return classify_message(value)
    if (
        profile is not None
        and profile.batch_receive_required
        and 0 < len(value) <= MAX_BATCH_MESSAGES
    ):
        return "batch"
    return "invalid_batch"


def _is_invalid_request_error(
    request: InboundMessage, response: JsonObject
) -> bool:
    error = response.get("error")
    return (
        _rpc_key(message_id(request.payload)) is None
        and response.get("id") is None
        and isinstance(error, dict)
        and error.get("code") == -32600
    )


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
        profile: ProtocolProfile | None = None,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
        shutdown_timeout: float = 2.0,
        write_timeout: float = DEFAULT_STDIO_WRITE_TIMEOUT,
    ) -> None:
        if not command:
            raise TransportError("stdio transport requires a server command.")
        self.command = list(command)
        self.env = dict(env)
        self.recorder = recorder
        self.recorder.register_secrets(known_secrets_from_command(self.command))
        self.recorder.register_secrets(
            value for key, value in self.env.items() if sensitive_key(key)
        )
        self.recorder.register_secrets(
            value for key, value in os.environ.items() if sensitive_key(key)
        )
        self.max_message_bytes = max_message_bytes
        self.shutdown_timeout = shutdown_timeout
        self.write_timeout = write_timeout
        self.profile = profile
        self.server_request_handler: Callable[[InboundMessage], JsonObject | None] | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._incoming: queue.Queue[InboundMessage] = queue.Queue(
            maxsize=MAX_BUFFERED_STDIO_MESSAGES
        )
        self._pending: dict[tuple[str, str | int], list[InboundMessage]] = {}
        self._notifications: queue.Queue[InboundMessage] = queue.Queue(
            maxsize=MAX_BUFFERED_STDIO_MESSAGES
        )
        self._server_requests: queue.Queue[InboundMessage] = queue.Queue(
            maxsize=MAX_BUFFERED_STDIO_MESSAGES
        )
        self._server_request_evidence: set[str] = set()
        self._invalid: queue.Queue[InboundMessage] = queue.Queue(
            maxsize=MAX_BUFFERED_STDIO_MESSAGES
        )
        self._invalid_evidence: set[str] = set()
        self._stdout_eof = threading.Event()
        self._closing = threading.Event()
        self._threads: list[threading.Thread] = []
        self._next_id = 1
        self._used_ids: set[tuple[str, str | int]] = set()
        self._outstanding: dict[tuple[str, str | int], str] = {}
        self._write_lock = threading.Lock()
        self._close_lock = threading.Lock()
        self._buffer_lock = threading.Lock()
        self._buffered_messages = 0
        self._buffered_bytes = 0
        self._resource_failure: TransportError | None = None
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
                    if not self._publish_invalid(message):
                        break
                    continue
                if not raw.endswith(b"\n"):
                    display = raw.decode("utf-8", errors="replace")
                    evidence = self.recorder.record(
                        "server_to_client",
                        "stdio",
                        classification="missing_delimiter",
                        raw=display,
                        error="stdio message ended at EOF without a newline delimiter",
                    )
                    message = InboundMessage(None, display, "missing_delimiter", evidence)
                    self._publish_invalid(message)
                    break
                wire = raw[:-1] if raw.endswith(b"\n") else raw
                if wire.endswith(b"\r"):
                    wire = wire[:-1]
                if not wire:
                    evidence = self.recorder.record(
                        "server_to_client",
                        "stdio",
                        classification="blank_line",
                        raw="",
                        error="stdio emitted an empty non-message line",
                    )
                    message = InboundMessage(None, "", "blank_line", evidence)
                    if not self._publish_invalid(message):
                        break
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
                    if not self._publish_invalid(message):
                        break
                    continue
                try:
                    payload = strict_json_loads(text)
                except (json.JSONDecodeError, ValueError) as exc:
                    evidence = self.recorder.record(
                        "server_to_client",
                        "stdio",
                        classification="invalid_json",
                        raw=text,
                        error=str(exc),
                    )
                    message = InboundMessage(None, text, "invalid_json", evidence)
                    if not self._publish_invalid(message):
                        break
                    continue
                if not self._ingest_stdio_payload(payload, text):
                    break
        except (OSError, ValueError, TransportError) as exc:
            if not self._closing.is_set():
                if isinstance(exc, TransportError):
                    self._set_resource_failure(str(exc))
                else:
                    self.recorder.record(
                        "probe", "stdio", classification="stdout_error", error=str(exc)
                    )
        finally:
            self._stdout_eof.set()
            try:
                self.recorder.record("probe", "stdio", classification="stdout_eof")
            except TransportError as exc:
                self._set_resource_failure(str(exc))

    def _ingest_stdio_payload(self, payload: Any, raw: str) -> bool:
        if isinstance(payload, list):
            allowed = bool(self.profile and self.profile.batch_receive_required)
            valid_size = 0 < len(payload) <= MAX_BATCH_MESSAGES
            envelope_class = "batch" if allowed and valid_size else "invalid_batch"
            evidence = self.recorder.record(
                "server_to_client",
                "stdio",
                payload=payload,
                raw=raw,
                classification=envelope_class,
                batchSize=len(payload),
                batchAllowed=allowed,
            )
            if not allowed or not valid_size:
                too_large = allowed and len(payload) > MAX_BATCH_MESSAGES
                detail = (
                    f"JSON-RPC batch exceeds the {MAX_BATCH_MESSAGES}-message limit"
                    if too_large
                    else "JSON-RPC batch receive is not valid for this protocol profile"
                )
                message = InboundMessage(payload, raw, envelope_class, evidence)
                if too_large:
                    self._set_resource_failure(detail)
                    return False
                return self._publish_invalid(message)

            messages: list[InboundMessage] = []
            reply_pairs: list[tuple[InboundMessage, JsonObject]] = []
            for index, item in enumerate(payload):
                item_class = classify_message(item)
                item_raw = compact_json(item)
                item_evidence = self.recorder.record(
                    "server_to_client",
                    "stdio",
                    payload=item,
                    raw=item_raw,
                    classification=item_class,
                    batchEvidence=evidence,
                    batchIndex=index,
                )
                inbound = InboundMessage(item, item_raw, item_class, item_evidence)
                messages.append(inbound)
                if item_class == "request":
                    reply = self._prepare_server_request(inbound)
                    if reply is not None:
                        reply_pairs.append((inbound, reply))
                elif item_class == "invalid":
                    if not self._observe_invalid(inbound):
                        return False
            for inbound in messages:
                if not self._queue_put(self._incoming, inbound, "incoming messages"):
                    return False
            if reply_pairs:
                replies = [reply for _, reply in reply_pairs]
                self.send_message(replies)
                self.recorder.record(
                    "probe",
                    "stdio",
                    classification="server_request_response",
                    grouped=True,
                    requestIds=[message_id(item.payload) for item, _ in reply_pairs],
                    responseIds=[message_id(reply) for _, reply in reply_pairs],
                    idMatched=all(
                        _rpc_key(message_id(item.payload))
                        == _rpc_key(message_id(reply))
                        and _rpc_key(message_id(item.payload)) is not None
                        for item, reply in reply_pairs
                    ),
                    invalidRequestResponses=[
                        _is_invalid_request_error(item, reply)
                        for item, reply in reply_pairs
                    ],
                    sourceEvidence=[item.evidence for item, _ in reply_pairs],
                )
            return True

        classification = classify_message(payload)
        evidence = self.recorder.record(
            "server_to_client",
            "stdio",
            payload=payload,
            raw=raw,
            classification=classification,
        )
        message = InboundMessage(payload, raw, classification, evidence)
        if classification == "invalid":
            if not self._observe_invalid(message):
                return False
        elif classification == "request":
            self._service_server_request(message)
        return self._queue_put(self._incoming, message, "incoming messages")

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
        except (OSError, ValueError, TransportError) as exc:
            if not self._closing.is_set():
                if isinstance(exc, TransportError):
                    self._set_resource_failure(str(exc))
                else:
                    self.recorder.record(
                        "probe", "stdio", classification="stderr_error", error=str(exc)
                    )

    def _watch_process(self) -> None:
        assert self._proc is not None
        returncode = self._proc.wait()
        try:
            self.recorder.record(
                "probe", "stdio", classification="process_exit", exitCode=returncode
            )
        except TransportError as exc:
            self._set_resource_failure(str(exc))

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

    def send_message(self, message: Any, timeout: float | None = None) -> str:
        self.raise_if_failed()
        if self._proc is None or self._proc.stdin is None:
            raise TransportError("stdio server has not been started.")
        if isinstance(message, list) and len(message) > MAX_BATCH_MESSAGES:
            self.recorder.record(
                "probe",
                "stdio",
                classification="resource_limit",
                error=f"Outgoing JSON-RPC batch exceeds {MAX_BATCH_MESSAGES} messages.",
            )
            raise TransportError(
                f"Outgoing JSON-RPC batch exceeds {MAX_BATCH_MESSAGES} messages."
            )
        wire = compact_json(message)
        data = wire.encode("utf-8") + b"\n"
        if len(data) > self.max_message_bytes:
            self.recorder.record(
                "probe",
                "stdio",
                classification="outgoing_message_too_large",
                byteLength=len(data),
                maxBytes=self.max_message_bytes,
            )
            raise TransportError(
                f"Outgoing stdio message exceeded {self.max_message_bytes} bytes."
            )
        outbound_items = message if isinstance(message, list) else [message]
        for item in outbound_items:
            if isinstance(item, dict) and "id" in item:
                self.reserve_id(item.get("id"))
                key = _rpc_key(item.get("id"))
                if key and isinstance(item.get("method"), str):
                    self._outstanding[key] = item["method"]
        evidence = self.recorder.record(
            "client_to_server",
            "stdio",
            payload=message,
            raw=wire,
            classification=_outbound_message_classification(message, self.profile),
        )
        self._write_bytes(data, timeout, "stdio message")
        return evidence

    def send_wire(
        self,
        data: str | bytes,
        *,
        append_newline: bool = True,
        timeout: float | None = None,
    ) -> str:
        self.raise_if_failed()
        if self._proc is None or self._proc.stdin is None:
            raise TransportError("stdio server has not been started.")
        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        wire = raw_bytes + (b"\n" if append_newline else b"")
        if len(wire) > self.max_message_bytes:
            self.recorder.record(
                "probe",
                "stdio",
                classification="outgoing_message_too_large",
                byteLength=len(wire),
                maxBytes=self.max_message_bytes,
            )
            raise TransportError(
                f"Outgoing raw stdio data exceeded {self.max_message_bytes} bytes."
            )
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
        self._write_bytes(wire, timeout, "raw stdio data")
        return evidence

    def _write_bytes(
        self, data: bytes, timeout: float | None, description: str
    ) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None:
            raise TransportError("stdio server has not been started.")
        chosen_timeout = self.write_timeout if timeout is None else timeout
        if (
            isinstance(chosen_timeout, bool)
            or not isinstance(chosen_timeout, (int, float))
            or chosen_timeout <= 0
        ):
            raise ConfigurationError("stdio write timeout must be a positive number.")
        deadline = time.monotonic() + float(chosen_timeout)
        remaining = deadline - time.monotonic()
        if not self._write_lock.acquire(timeout=max(0.0, remaining)):
            self._abort_timed_out_write(description, float(chosen_timeout))
        try:
            if self._closing.is_set() or proc.poll() is not None:
                raise TransportError("stdio server is closing or has exited.")
            if os.name == "posix":
                self._write_posix(
                    proc.stdin.fileno(), data, deadline, float(chosen_timeout)
                )
            else:
                self._write_fallback(
                    proc.stdin, data, deadline, float(chosen_timeout)
                )
        except (BrokenPipeError, OSError, ValueError) as exc:
            self.recorder.record(
                "probe", "stdio", classification="write_error", error=str(exc)
            )
            raise TransportError(f"Could not write {description}: {exc}") from exc
        finally:
            self._write_lock.release()

    def _write_posix(
        self, descriptor: int, data: bytes, deadline: float, timeout: float
    ) -> None:
        os.set_blocking(descriptor, False)
        offset = 0
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._abort_timed_out_write("stdio data", timeout)
            try:
                _, writable, _ = select.select([], [descriptor], [], remaining)
            except InterruptedError:
                continue
            if not writable:
                self._abort_timed_out_write("stdio data", timeout)
            try:
                written = os.write(descriptor, data[offset:])
            except BlockingIOError:
                continue
            if written <= 0:
                raise BrokenPipeError("stdio write returned no progress")
            offset += written

    def _write_fallback(
        self, stream: Any, data: bytes, deadline: float, timeout: float
    ) -> None:
        completed = threading.Event()
        errors: list[BaseException] = []

        def write() -> None:
            try:
                stream.write(data)
                stream.flush()
            except Exception as exc:  # surfaced synchronously below
                errors.append(exc)
            finally:
                completed.set()

        worker = threading.Thread(
            target=write, name="mcp-probe-stdin-write", daemon=True
        )
        worker.start()
        if not completed.wait(max(0.0, deadline - time.monotonic())):
            self._abort_timed_out_write("stdio data", timeout)
        if errors:
            raise errors[0]

    def _abort_timed_out_write(self, description: str, timeout: float) -> None:
        self.recorder.record(
            "probe",
            "stdio",
            classification="write_timeout",
            error=f"Timed out writing {description}",
            timeoutSeconds=timeout,
        )
        proc = self._proc
        if proc is not None and proc.poll() is None:
            self._signal_process_group(signal.SIGTERM)
            try:
                proc.wait(timeout=min(self.shutdown_timeout, 0.25))
            except subprocess.TimeoutExpired:
                self._signal_process_group(
                    signal.SIGKILL if os.name == "posix" else None
                )
                try:
                    proc.wait(timeout=min(self.shutdown_timeout, 0.25))
                except subprocess.TimeoutExpired:
                    pass
        raise TransportError(f"Timed out writing {description} to stdio server.")

    def receive(self, timeout: float) -> InboundMessage:
        deadline = time.monotonic() + timeout
        while True:
            self.raise_if_failed()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProbeTimeout("Timed out waiting for a stdio message.")
            try:
                message = self._incoming.get(timeout=min(remaining, 0.1))
                self._release_buffer(message)
                return message
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
            self._release_buffer(message)
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
                method = self._outstanding.pop(wanted, None)
                if cancel_on_timeout and method and method != "initialize":
                    try:
                        self.send_message(
                            make_notification(
                                "notifications/cancelled",
                                {"requestId": request_id, "reason": "MCP Probe timeout"},
                            ),
                            timeout=min(self.write_timeout, 0.25),
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
                if key in self._outstanding:
                    if not self._retain_buffer(inbound, "pending responses"):
                        self.raise_if_failed()
                    self._pending.setdefault(key, []).append(inbound)
                else:
                    # An unsolicited response must never satisfy a request
                    # which happens to reuse that ID later.
                    self.recorder.record(
                        "probe",
                        "stdio",
                        classification="unexpected_response_id",
                        payload=inbound.payload,
                        responseEvidence=inbound.evidence,
                        expectedOutstandingIds=[key[1] for key in self._outstanding],
                    )
                    self._observe_invalid(inbound)
                continue
            if inbound.classification == "request":
                self._service_server_request(inbound)
                continue
            if inbound.classification == "notification":
                if not self._queue_put(
                    self._notifications, inbound, "observed notifications"
                ):
                    self.raise_if_failed()
                continue
            self._observe_invalid(inbound)

    def rpc(self, method: str, params: JsonObject | None, timeout: float) -> InboundMessage:
        request_id = self.next_id()
        self.send_message(make_request(method, request_id, params))
        return self.wait_for_response(request_id, timeout)

    def observed_server_requests(self) -> list[InboundMessage]:
        return self._drain_buffered_queue(self._server_requests)

    def observed_notifications(self) -> list[InboundMessage]:
        return self._drain_buffered_queue(self._notifications)

    def observed_invalid_messages(self) -> list[InboundMessage]:
        return self._drain_buffered_queue(self._invalid)

    def _service_server_request(self, message: InboundMessage) -> None:
        response = self._prepare_server_request(message)
        if response is None:
            return
        if self._closing.is_set():
            self.recorder.record(
                "probe",
                "stdio",
                classification="server_request_response_skipped",
                requestId=message_id(message.payload),
                error="transport is closing",
            )
            return
        try:
            self.send_message(response)
        except TransportError as exc:
            # The peer can close stdin after issuing a request, or close()
            # can race a handler already in flight. Preserve evidence
            # without leaking an unhandled daemon-thread traceback.
            self.recorder.record(
                "probe",
                "stdio",
                classification="server_request_response_error",
                requestId=message_id(message.payload),
                responseId=message_id(response),
                requestIdType=type(message.payload.get("id")).__name__,
                responseIdType=type(response.get("id")).__name__,
                sourceEvidence=message.evidence,
                error=str(exc),
            )
            return
        self.recorder.record(
            "probe",
            "stdio",
            classification="server_request_response",
            requestId=message_id(message.payload),
            responseId=message_id(response),
            requestIdType=type(message.payload.get("id")).__name__,
            responseIdType=type(response.get("id")).__name__,
            idMatched=(
                _rpc_key(message_id(message.payload))
                == _rpc_key(message_id(response))
                and _rpc_key(message_id(message.payload)) is not None
            ),
            invalidRequestResponse=_is_invalid_request_error(message, response),
            sourceEvidence=message.evidence,
        )

    def _prepare_server_request(self, message: InboundMessage) -> JsonObject | None:
        if message.evidence not in self._server_request_evidence:
            self._server_request_evidence.add(message.evidence)
            if not self._queue_put(
                self._server_requests, message, "observed server requests"
            ):
                return None
        if message.handled or not self.server_request_handler:
            return None
        # Mark first so a response wait cannot race the reader into replying a
        # second time to the same server request.
        message.handled = True
        try:
            response = self.server_request_handler(message)
        except Exception as exc:  # A handler must never tear down the reader thread.
            self.recorder.record(
                "probe",
                "stdio",
                classification="server_request_handler_error",
                requestId=message_id(message.payload),
                requestIdType=type(message.payload.get("id")).__name__,
                sourceEvidence=message.evidence,
                error=str(exc),
            )
            return None
        return response

    def _publish_invalid(self, message: InboundMessage) -> bool:
        return self._observe_invalid(message) and self._queue_put(
            self._incoming, message, "incoming messages"
        )

    def _observe_invalid(self, message: InboundMessage) -> bool:
        if message.evidence in self._invalid_evidence:
            return True
        self._invalid_evidence.add(message.evidence)
        return self._queue_put(self._invalid, message, "observed invalid messages")

    @staticmethod
    def _buffer_size(message: InboundMessage) -> int:
        return len(message.raw.encode("utf-8", errors="replace"))

    def _retain_buffer(self, message: InboundMessage, label: str) -> bool:
        size = self._buffer_size(message)
        reason: str | None = None
        with self._buffer_lock:
            if self._buffered_messages >= MAX_BUFFERED_STDIO_MESSAGES:
                reason = (
                    f"stdio {label} exceeded the "
                    f"{MAX_BUFFERED_STDIO_MESSAGES}-message safety limit"
                )
            elif self._buffered_bytes + size > MAX_BUFFERED_STDIO_BYTES:
                reason = (
                    f"stdio buffered data exceeded the "
                    f"{MAX_BUFFERED_STDIO_BYTES}-byte safety limit"
                )
            else:
                self._buffered_messages += 1
                self._buffered_bytes += size
                return True
        assert reason is not None
        self._set_resource_failure(reason)
        return False

    def _release_buffer(self, message: InboundMessage) -> None:
        size = self._buffer_size(message)
        with self._buffer_lock:
            self._buffered_messages = max(0, self._buffered_messages - 1)
            self._buffered_bytes = max(0, self._buffered_bytes - size)

    def _queue_put(
        self,
        target: queue.Queue[InboundMessage],
        message: InboundMessage,
        label: str,
    ) -> bool:
        if not self._retain_buffer(message, label):
            return False
        try:
            target.put_nowait(message)
        except queue.Full:
            self._release_buffer(message)
            self._set_resource_failure(
                f"stdio {label} exceeded the {MAX_BUFFERED_STDIO_MESSAGES}-message safety limit"
            )
            return False
        return True

    def _drain_buffered_queue(
        self, source: queue.Queue[InboundMessage]
    ) -> list[InboundMessage]:
        self.raise_if_failed()
        values: list[InboundMessage] = []
        while True:
            try:
                message = source.get_nowait()
            except queue.Empty:
                return values
            self._release_buffer(message)
            values.append(message)

    def _set_resource_failure(self, reason: str) -> None:
        with self._buffer_lock:
            if self._resource_failure is not None:
                return
            self._resource_failure = TransportError(reason)
        try:
            self.recorder.record(
                "probe",
                "stdio",
                classification="resource_limit",
                error=reason,
                maxBufferedMessages=MAX_BUFFERED_STDIO_MESSAGES,
                maxBufferedBytes=MAX_BUFFERED_STDIO_BYTES,
            )
        except TransportError:
            # A transcript capture limit can be the resource failure itself.
            pass

    def raise_if_failed(self) -> None:
        self.recorder.raise_if_truncated()
        with self._buffer_lock:
            failure = self._resource_failure
        if failure is not None:
            raise TransportError(str(failure))

    def close(self) -> CleanupResult:
        with self._close_lock:
            result = self._close_once()
        self.raise_if_failed()
        return result

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
            self._record_cleanup_event(classification="process_terminate")
            self._signal_process_group(signal.SIGTERM)
            try:
                proc.wait(timeout=self.shutdown_timeout)
            except subprocess.TimeoutExpired:
                killed = True
                self._record_cleanup_event(classification="process_kill")
                self._signal_process_group(signal.SIGKILL if os.name == "posix" else None)
                try:
                    proc.wait(timeout=self.shutdown_timeout)
                except subprocess.TimeoutExpired:
                    self._record_cleanup_event(
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
        self._record_cleanup_event(
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
        self._record_cleanup_event(classification="process_group_terminate")
        terminated = self._signal_process_group(signal.SIGTERM)
        if not terminated:
            return False, False
        time.sleep(min(self.shutdown_timeout, 0.05))
        try:
            os.killpg(self._proc.pid, 0)
        except (OSError, ProcessLookupError):
            return True, False
        self._record_cleanup_event(classification="process_group_kill")
        return True, self._signal_process_group(signal.SIGKILL)

    def _record_cleanup_event(self, *, classification: str, **metadata: Any) -> None:
        try:
            self.recorder.record(
                "probe", "stdio", classification=classification, **metadata
            )
        except TransportError as exc:
            self._set_resource_failure(str(exc))


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
        validate_http_headers(headers)
        self.extra_headers = dict(headers)
        self.recorder = recorder
        self.recorder.register_secrets(known_secrets_from_headers(self.extra_headers))
        self.recorder.register_secrets(known_secrets_from_url(self.url))
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
        # urllib follows redirects by default and carries caller-supplied headers
        # to the redirected request.  MCP headers can contain bearer credentials
        # or session identifiers, so redirects are always surfaced as 3xx.
        self._opener = urllib.request.build_opener(_NoRedirectHandler())
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

    def accept_session_id(
        self, session_id: str, *, source_evidence: str | None = None
    ) -> None:
        """Validate and adopt a server-minted session identifier exactly once."""

        if not self.profile.http_sessions:
            return
        if not _valid_session_id(session_id):
            self.recorder.record(
                "probe",
                "http",
                classification="invalid_session_id",
                error=(
                    "MCP-Session-Id must contain only visible ASCII "
                    "characters (0x21-0x7E)"
                ),
                sourceEvidence=source_evidence,
            )
            raise TransportError(
                "Server returned an invalid MCP-Session-Id; expected "
                "visible ASCII characters (0x21-0x7E)."
            )
        self.recorder.register_secrets((session_id,))
        self.session_id = session_id
        self._termination_result = None
        self.recorder.record(
            "probe",
            "http",
            classification="session_assigned",
            headers={"MCP-Session-Id": session_id},
            sourceEvidence=source_evidence,
        )

    def send_message(
        self,
        message: Any,
        timeout: float,
        *,
        include_protocol_header_on_initialize: bool = False,
        derived_headers: dict[str, str] | None = None,
        _server_request_depth: int = 0,
    ) -> HttpExchange:
        if isinstance(message, list) and len(message) > MAX_BATCH_MESSAGES:
            self.recorder.record(
                "probe",
                "http",
                classification="resource_limit",
                error=f"Outgoing JSON-RPC batch exceeds {MAX_BATCH_MESSAGES} messages.",
            )
            raise TransportError(
                f"Outgoing JSON-RPC batch exceeds {MAX_BATCH_MESSAGES} messages."
            )
        body = compact_json(message).encode("utf-8")
        if len(body) > self.max_body_bytes:
            self.recorder.record(
                "probe",
                "http",
                classification="outgoing_message_too_large",
                byteLength=len(body),
                maxBytes=self.max_body_bytes,
            )
            raise TransportError(
                f"Outgoing HTTP message exceeded {self.max_body_bytes} bytes."
            )
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
        outbound_items = message if isinstance(message, list) else [message]
        for item in outbound_items:
            if isinstance(item, dict) and "id" in item:
                self.reserve_id(item.get("id"))
        exchange = self._send_body(
            body,
            timeout,
            headers=headers,
            displayed_payload=message,
            classification=_outbound_message_classification(message, self.profile),
            server_request_depth=_server_request_depth,
        )
        if method == "initialize" and exchange.messages:
            matching = _find_matching_response(exchange.messages, message.get("id"))
            if matching and isinstance(matching.payload, dict) and "result" in matching.payload:
                session_id = header_value(exchange.headers, "MCP-Session-Id")
                if self.profile.http_sessions and session_id:
                    self.accept_session_id(
                        session_id, source_evidence=matching.evidence
                    )
                self.initialized = True
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
        if len(raw) > self.max_body_bytes:
            self.recorder.record(
                "probe",
                "http",
                classification="outgoing_message_too_large",
                byteLength=len(raw),
                maxBytes=self.max_body_bytes,
            )
            raise TransportError(
                f"Outgoing raw HTTP data exceeded {self.max_body_bytes} bytes."
            )
        exact_bytes_recorded = True
        if isinstance(body, str):
            raw_display = body
        else:
            try:
                raw_display = body.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raw_display = body.decode("utf-8", errors="replace")
                exact_bytes_recorded = False
        expected_response_id: Any = None
        if exact_bytes_recorded:
            try:
                raw_payload = strict_json_loads(raw_display)
            except (json.JSONDecodeError, ValueError):
                raw_payload = None
            if classify_message(raw_payload) == "request":
                expected_response_id = message_id(raw_payload)
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
            raw_display=raw_display,
            classification="raw_wire",
            exact_bytes_recorded=exact_bytes_recorded,
            expected_response_id=expected_response_id,
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
        exact_bytes_recorded: bool | None = None,
        expected_response_id: Any = None,
        server_request_depth: int = 0,
    ) -> HttpExchange:
        validate_http_headers(headers)
        self.recorder.register_secrets(known_secrets_from_headers(headers))
        if expected_response_id is None and classification == "request":
            expected_response_id = message_id(displayed_payload)
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
            exactBytesRecorded=exact_bytes_recorded,
        )
        status: int
        response_headers: dict[str, str]
        response_body: bytes
        messages: list[InboundMessage]
        issues: list[str]
        timed_out = False
        deadline = time.monotonic() + max(0.0, timeout)
        try:
            request = urllib.request.Request(
                self.url, data=body, headers=headers, method="POST"
            )
            with self._opener.open(
                request, timeout=_remaining_http_timeout(deadline)
            ) as response:
                status = int(response.status)
                response_headers = {key: value for key, value in response.headers.items()}
                self.recorder.register_secrets(
                    known_secrets_from_headers(response_headers)
                )
                response_body, messages, issues, timed_out = self._consume_response(
                    response,
                    status,
                    response_headers,
                    deadline,
                    expected_response_id,
                    server_request_depth,
                )
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_headers = {key: value for key, value in exc.headers.items()}
            self.recorder.register_secrets(
                known_secrets_from_headers(response_headers)
            )
            try:
                response_body, messages, issues, timed_out = self._consume_response(
                    exc,
                    status,
                    response_headers,
                    deadline,
                    expected_response_id,
                    server_request_depth,
                )
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
        content_type = header_value(response_headers, "Content-Type") or ""
        media_type = content_type.partition(";")[0].strip().lower()
        if media_type != "text/event-stream":
            parsed, parse_issues = parse_http_messages(
                text, content_type, profile=self.profile
            )
            issues.extend(parse_issues)
            for payload, event_name, event_id, raw_event in parsed:
                recorded, grouped = self._record_http_payload(
                    payload,
                    raw_event,
                    status,
                    response_headers,
                    event_name,
                    event_id,
                )
                messages.extend(recorded)
                self._service_http_server_requests(
                    recorded,
                    deadline,
                    server_request_depth,
                    grouped=grouped,
                )
        issues = decode_issues + issues
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
        unexpected_session_id = header_value(response_headers, "MCP-Session-Id")
        if unexpected_session_id and not self.profile.http_sessions:
            self.recorder.record(
                "probe",
                "http",
                classification="unexpected_session_id",
                headers={"MCP-Session-Id": unexpected_session_id},
                status=status,
                error=(
                    "Server returned MCP-Session-Id for a protocol profile "
                    "which does not use HTTP sessions."
                ),
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

    def _consume_response(
        self,
        response: Any,
        status: int,
        response_headers: dict[str, str],
        deadline: float,
        expected_response_id: Any,
        server_request_depth: int,
    ) -> tuple[bytes, list[InboundMessage], list[str], bool]:
        content_type = header_value(response_headers, "Content-Type") or ""
        media_type = content_type.partition(";")[0].strip().lower()
        if media_type == "text/event-stream":
            return self._read_sse_response(
                response,
                status,
                response_headers,
                deadline,
                expected_response_id,
                server_request_depth,
            )
        body, timed_out = _read_http_body(
            response, self.max_body_bytes, deadline
        )
        return body, [], [], timed_out

    def _read_sse_response(
        self,
        response: Any,
        status: int,
        response_headers: dict[str, str],
        deadline: float,
        expected_response_id: Any,
        server_request_depth: int,
    ) -> tuple[bytes, list[InboundMessage], list[str], bool]:
        decoder = _SseDecoder(max_event_bytes=self.max_body_bytes)
        body = bytearray()
        pending = bytearray()
        previous_was_cr = False
        messages: list[InboundMessage] = []
        issues: list[str] = []
        timed_out = False
        matched = False

        def add_issues(values: Iterable[str]) -> None:
            incoming = list(values)
            if len(issues) + len(incoming) > MAX_SSE_ISSUES:
                raise TransportError(
                    f"SSE response exceeded the {MAX_SSE_ISSUES}-issue safety limit."
                )
            issues.extend(incoming)

        def process_line(raw_line: bytes) -> None:
            nonlocal matched
            if raw_line.endswith(b"\r"):
                raw_line = raw_line[:-1]
            try:
                line = raw_line.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                add_issues([f"HTTP body is not valid UTF-8: {exc}"])
                line = raw_line.decode("utf-8", errors="replace")
            parsed, line_issues = decoder.feed_line(line)
            add_issues(line_issues)
            for payload, event_name, event_id, raw_event in parsed:
                recorded, grouped = self._record_http_payload(
                    payload,
                    raw_event,
                    status,
                    response_headers,
                    event_name,
                    event_id,
                )
                messages.extend(recorded)
                self._service_http_server_requests(
                    recorded,
                    deadline,
                    server_request_depth,
                    grouped=grouped,
                )
                if any(
                    inbound.classification == "response"
                    and _rpc_key(message_id(inbound.payload))
                    == _rpc_key(expected_response_id)
                    and _rpc_key(expected_response_id) is not None
                    for inbound in recorded
                ):
                    matched = True

        while not matched:
            try:
                chunk = _read_http_chunk(
                    response,
                    min(65536, self.max_body_bytes + 1 - len(body)),
                    deadline,
                )
            except (socket.timeout, TimeoutError):
                timed_out = True
                break
            if not chunk:
                if pending:
                    process_line(bytes(pending))
                    pending.clear()
                parsed, finish_issues = decoder.finish()
                add_issues(finish_issues)
                for payload, event_name, event_id, raw_event in parsed:
                    recorded, grouped = self._record_http_payload(
                        payload,
                        raw_event,
                        status,
                        response_headers,
                        event_name,
                        event_id,
                    )
                    messages.extend(recorded)
                    self._service_http_server_requests(
                        recorded,
                        deadline,
                        server_request_depth,
                        grouped=grouped,
                    )
                break
            for byte in chunk:
                if matched:
                    break
                body.append(byte)
                if len(body) > self.max_body_bytes:
                    raise TransportError(
                        f"HTTP response body exceeded {self.max_body_bytes} bytes."
                    )
                if byte == 0x0A:  # LF, or the second half of CRLF.
                    if previous_was_cr:
                        previous_was_cr = False
                        continue
                    process_line(bytes(pending))
                    pending.clear()
                    continue
                if byte == 0x0D:  # CR is also an SSE line terminator on its own.
                    process_line(bytes(pending))
                    pending.clear()
                    previous_was_cr = True
                    continue
                previous_was_cr = False
                pending.append(byte)
                if len(pending) > MAX_SSE_FIELD_BYTES:
                    raise TransportError(
                        f"SSE line exceeded the {MAX_SSE_FIELD_BYTES}-byte safety limit."
                    )
        return bytes(body), messages, issues, timed_out

    def _record_http_payload(
        self,
        payload: Any,
        raw_event: str,
        status: int,
        response_headers: dict[str, str],
        event_name: str | None,
        event_id: str | None,
    ) -> tuple[list[InboundMessage], bool]:
        if not isinstance(payload, list):
            return [
                self._record_http_message(
                    payload,
                    raw_event,
                    status,
                    response_headers,
                    event_name,
                    event_id,
                )
            ], False

        allowed = self.profile.batch_receive_required
        valid_size = 0 < len(payload) <= MAX_BATCH_MESSAGES
        envelope_class = "batch" if allowed and valid_size else "invalid_batch"
        envelope_evidence = self.recorder.record(
            "server_to_client",
            "http",
            payload=payload,
            raw=raw_event,
            classification=envelope_class,
            status=status,
            headers=response_headers,
            url=self.url,
            sseEvent=event_name,
            sseId=event_id,
            batchSize=len(payload),
            batchAllowed=allowed,
        )
        if allowed and len(payload) > MAX_BATCH_MESSAGES:
            self.recorder.record(
                "probe",
                "http",
                classification="resource_limit",
                error=f"JSON-RPC batch exceeds {MAX_BATCH_MESSAGES} messages.",
                sourceEvidence=envelope_evidence,
            )
            raise TransportError(
                f"JSON-RPC batch exceeds {MAX_BATCH_MESSAGES} messages."
            )
        if not allowed or not valid_size:
            return [
                InboundMessage(
                    payload,
                    raw_event,
                    "invalid_batch",
                    envelope_evidence,
                    status,
                    response_headers,
                    event_name,
                    event_id,
                )
            ], False

        messages: list[InboundMessage] = []
        for index, item in enumerate(payload):
            item_raw = compact_json(item)
            messages.append(
                self._record_http_message(
                    item,
                    item_raw,
                    status,
                    response_headers,
                    event_name,
                    event_id,
                    batch_evidence=envelope_evidence,
                    batch_index=index,
                )
            )
        return messages, True

    def _record_http_message(
        self,
        payload: Any,
        raw_event: str,
        status: int,
        response_headers: dict[str, str],
        event_name: str | None,
        event_id: str | None,
        *,
        batch_evidence: str | None = None,
        batch_index: int | None = None,
    ) -> InboundMessage:
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
            batchEvidence=batch_evidence,
            batchIndex=batch_index,
        )
        return InboundMessage(
            payload,
            raw_event,
            message_class,
            evidence,
            status,
            response_headers,
            event_name,
            event_id,
        )

    def _service_http_server_requests(
        self,
        messages: Iterable[InboundMessage],
        deadline: float,
        depth: int,
        *,
        grouped: bool,
    ) -> None:
        if self.server_request_handler is None:
            return
        pairs: list[tuple[InboundMessage, JsonObject]] = []
        for inbound in messages:
            if inbound.classification != "request" or inbound.handled:
                continue
            inbound.handled = True
            try:
                reply = self.server_request_handler(inbound)
            except Exception as exc:
                self.recorder.record(
                    "probe",
                    "http",
                    classification="server_request_handler_error",
                    requestId=message_id(inbound.payload),
                    error=str(exc),
                    sourceEvidence=inbound.evidence,
                )
                continue
            if reply is None:
                continue
            request_id = message_id(inbound.payload)
            reply_id = message_id(reply)
            error = reply.get("error") if isinstance(reply, dict) else None
            invalid_request_reply = (
                _rpc_key(request_id) is None
                and reply.get("id") is None
                and isinstance(error, dict)
                and error.get("code") == -32600
            )
            if not invalid_request_reply and (
                _rpc_key(request_id) is None
                or _rpc_key(reply_id) != _rpc_key(request_id)
            ):
                self.recorder.record(
                    "probe",
                    "http",
                    classification="server_request_response_correlation_error",
                    requestId=request_id,
                    responseId=reply_id,
                    requestIdType=type(inbound.payload.get("id")).__name__,
                    responseIdType=type(reply.get("id")).__name__,
                    sourceEvidence=inbound.evidence,
                )
                raise TransportError(
                    "HTTP server-request handler produced a response with a mismatched id."
                )
            pairs.append((inbound, reply))
        if not pairs:
            return
        if depth >= MAX_HTTP_SERVER_REQUEST_DEPTH:
            self.recorder.record(
                "probe",
                "http",
                classification="server_request_depth_limit",
                error=(
                    "Nested HTTP server requests exceeded the "
                    f"{MAX_HTTP_SERVER_REQUEST_DEPTH}-level safety limit."
                ),
                sourceEvidence=pairs[0][0].evidence,
            )
            raise TransportError(
                f"Nested HTTP server requests exceeded {MAX_HTTP_SERVER_REQUEST_DEPTH} levels."
            )
        reply_payload: Any = (
            [reply for _, reply in pairs] if grouped else pairs[0][1]
        )
        try:
            remaining = _remaining_http_timeout(deadline)
            exchange = self.send_message(
                reply_payload,
                remaining,
                _server_request_depth=depth + 1,
            )
        except (ProbeTimeout, TransportError) as exc:
            self.recorder.record(
                "probe",
                "http",
                classification="server_request_response_error",
                requestIds=[message_id(inbound.payload) for inbound, _ in pairs],
                responseIds=[message_id(reply) for _, reply in pairs],
                requestIdTypes=[
                    type(inbound.payload.get("id")).__name__ for inbound, _ in pairs
                ],
                responseIdTypes=[type(reply.get("id")).__name__ for _, reply in pairs],
                error=str(exc),
                sourceEvidence=[inbound.evidence for inbound, _ in pairs],
            )
            raise
        accepted = 200 <= exchange.status < 300
        for inbound, reply in pairs:
            self.recorder.record(
                "probe",
                "http",
                classification=(
                    "server_request_response"
                    if accepted
                    else "server_request_response_http_error"
                ),
                requestId=message_id(inbound.payload),
                responseId=message_id(reply),
                requestIdType=type(inbound.payload.get("id")).__name__,
                responseIdType=type(reply.get("id")).__name__,
                idMatched=(
                    _rpc_key(message_id(inbound.payload))
                    == _rpc_key(message_id(reply))
                    and _rpc_key(message_id(inbound.payload)) is not None
                ),
                invalidRequestResponse=(
                    _rpc_key(message_id(inbound.payload)) is None
                    and reply.get("id") is None
                    and isinstance(reply.get("error"), dict)
                    and reply["error"].get("code") == -32600
                ),
                httpStatus=exchange.status,
                sourceEvidence=inbound.evidence,
                nestedResponseEvidence=[item.evidence for item in exchange.messages],
            )
        if not accepted:
            raise TransportError(
                "HTTP server-request response POST returned "
                f"unexpected status {exchange.status}."
            )

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
        self._service_http_server_requests(
            exchange.messages,
            time.monotonic() + max(0.0, timeout),
            0,
            grouped=False,
        )
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
        validate_http_headers(headers)
        self.recorder.record(
            "client_to_server",
            "http",
            classification="session_terminate",
            headers=headers,
            url=self.url,
        )
        deadline = time.monotonic() + max(0.0, timeout)
        try:
            request = urllib.request.Request(self.url, headers=headers, method="DELETE")
            with self._opener.open(
                request, timeout=_remaining_http_timeout(deadline)
            ) as response:
                status = int(response.status)
                response_headers = {key: value for key, value in response.headers.items()}
                self.recorder.register_secrets(
                    known_secrets_from_headers(response_headers)
                )
                body, timed_out = _read_http_body(
                    response, self.max_body_bytes, deadline
                )
                if timed_out:
                    raise ProbeTimeout("HTTP session termination timed out.")
                if len(body) > self.max_body_bytes:
                    raise TransportError(
                        f"HTTP response body exceeded {self.max_body_bytes} bytes."
                    )
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_headers = {key: value for key, value in exc.headers.items()}
            self.recorder.register_secrets(
                known_secrets_from_headers(response_headers)
            )
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


def _valid_session_id(value: str) -> bool:
    return bool(value) and all(0x21 <= ord(character) <= 0x7E for character in value)


def _remaining_http_timeout(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout("HTTP operation exceeded its total deadline")
    return remaining


def _set_http_socket_timeout(response: Any, timeout: float) -> None:
    """Best-effort access to urllib's underlying socket for a total deadline."""

    candidates = [response]
    visited: set[int] = set()
    while candidates:
        candidate = candidates.pop(0)
        if candidate is None or id(candidate) in visited:
            continue
        visited.add(id(candidate))
        if isinstance(candidate, socket.socket):
            candidate.settimeout(timeout)
            return
        if len(visited) >= 12:
            return
        for attribute in ("fp", "raw", "_sock"):
            try:
                nested = getattr(candidate, attribute, None)
            except (OSError, ValueError):
                nested = None
            if nested is not None:
                candidates.append(nested)


def _read_http_chunk(response: Any, size: int, deadline: float) -> bytes:
    if size <= 0:
        return b""
    remaining = _remaining_http_timeout(deadline)
    _set_http_socket_timeout(response, remaining)
    reader = getattr(response, "read1", None)
    if not callable(reader):
        reader = response.read
    return reader(size)


def _read_http_body(
    response: Any, limit: int, deadline: float
) -> tuple[bytes, bool]:
    chunks: list[bytes] = []
    total = 0
    timed_out = False
    while True:
        try:
            chunk = _read_http_chunk(
                response, min(65536, limit + 1 - total), deadline
            )
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
    body: str,
    content_type: str,
    *,
    profile: ProtocolProfile | None = None,
) -> tuple[list[tuple[Any, str | None, str | None, str]], list[str]]:
    if len(body.encode("utf-8")) > DEFAULT_MAX_MESSAGE_BYTES:
        raise TransportError(
            f"HTTP body exceeded the {DEFAULT_MAX_MESSAGE_BYTES}-byte parse limit."
        )
    if not body.strip():
        return [], []
    media_type = content_type.partition(";")[0].strip().lower()
    if media_type == "text/event-stream":
        return parse_sse_messages(body, profile=profile)
    issues: list[str] = []
    if media_type != "application/json":
        issues.append(
            f"unexpected Content-Type {content_type!r}; expected application/json or text/event-stream"
        )
    try:
        payload = strict_json_loads(body)
    except (json.JSONDecodeError, ValueError) as exc:
        return [], [*issues, f"invalid JSON body: {exc}"]
    if isinstance(payload, list):
        if not (profile and profile.batch_receive_required):
            issues.append("JSON-RPC batch is not valid for this protocol profile")
        elif not payload:
            issues.append("JSON-RPC batch must not be empty")
        elif len(payload) > MAX_BATCH_MESSAGES:
            issues.append(
                f"JSON-RPC batch exceeds the {MAX_BATCH_MESSAGES}-message safety limit"
            )
    elif not isinstance(payload, dict):
        issues.append("HTTP JSON response is not one JSON-RPC object")
    return [(payload, None, None, body)], issues


def parse_sse_messages(
    body: str,
    *,
    profile: ProtocolProfile | None = None,
) -> tuple[list[tuple[Any, str | None, str | None, str]], list[str]]:
    if len(body.encode("utf-8")) > DEFAULT_MAX_MESSAGE_BYTES:
        raise TransportError(
            f"SSE body exceeded the {DEFAULT_MAX_MESSAGE_BYTES}-byte parse limit."
        )
    parsed: list[tuple[Any, str | None, str | None, str]] = []
    issues: list[str] = []
    decoder = _SseDecoder()
    for line in body.splitlines():
        events, line_issues = decoder.feed_line(line)
        parsed.extend(events)
        issues.extend(line_issues)
    events, finish_issues = decoder.finish()
    parsed.extend(events)
    issues.extend(finish_issues)
    for payload, _, _, _ in parsed:
        if isinstance(payload, list):
            if not (profile and profile.batch_receive_required):
                issues.append("JSON-RPC batch is not valid for this protocol profile")
            elif not payload:
                issues.append("JSON-RPC batch must not be empty")
            elif len(payload) > MAX_BATCH_MESSAGES:
                issues.append(
                    f"JSON-RPC batch exceeds the {MAX_BATCH_MESSAGES}-message safety limit"
                )
        elif not isinstance(payload, dict):
            issues.append("SSE data is not one JSON-RPC object")
        if len(issues) > MAX_SSE_ISSUES:
            raise TransportError(
                f"SSE response exceeded the {MAX_SSE_ISSUES}-issue safety limit."
            )
    return parsed, issues
