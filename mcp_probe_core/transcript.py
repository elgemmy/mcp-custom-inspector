"""Structured, redacted protocol event recording."""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .errors import ConfigurationError, TransportError
from .io_safety import InputLimitError, iter_utf8_lines_limited
from .protocol import classify_message, message_id, message_method, strict_json_loads
from .redaction import (
    expand_known_secrets,
    redact_command,
    redact_headers,
    redact_protocol_payload,
    redact_raw,
    redact_text,
    redact_url,
    redact_value,
)


TRANSCRIPT_EVENT_SCHEMA = "mcp-probe.transcript.event/v1"
MAX_TRANSCRIPT_EVENTS = 10_000
MAX_TRANSCRIPT_BYTES = 64 * 1024 * 1024
MAX_TRANSCRIPT_LINE_BYTES = MAX_TRANSCRIPT_BYTES
_CAPTURE_MARKER_RESERVE = 1024


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def pretty_json(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, indent=2, sort_keys=False, allow_nan=False
    )


class EventRecorder:
    """Collect evidence in memory and optionally write it as NDJSON."""

    def __init__(
        self,
        path: str | None = None,
        verbose: bool = False,
        *,
        max_events: int = MAX_TRANSCRIPT_EVENTS,
        max_capture_bytes: int = MAX_TRANSCRIPT_BYTES,
    ) -> None:
        if max_events < 2 or max_capture_bytes < _CAPTURE_MARKER_RESERVE * 2:
            raise ConfigurationError(
                "Transcript capture limits are too small to retain a limit marker."
            )
        self.path = Path(path) if path else None
        self.verbose = verbose
        self.events: list[dict[str, Any]] = []
        self._started_mono = time.monotonic()
        self._sequence = 0
        self._lock = threading.RLock()
        self._known_secrets: set[str] = set()
        self._max_events = max_events
        self._max_capture_bytes = max_capture_bytes
        self._captured_bytes = 0
        self._capture_failure: TransportError | None = None
        self._capture_marker_reference: str | None = None
        self._file = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if hasattr(os, "O_NONBLOCK"):
                flags |= os.O_NONBLOCK
            descriptor: int | None = None
            try:
                descriptor = os.open(self.path, flags, 0o600)
                file_status = os.fstat(descriptor)
                if not stat.S_ISREG(file_status.st_mode) or file_status.st_nlink != 1:
                    raise OSError(
                        "transcript target must be a regular file with one link"
                    )
                os.ftruncate(descriptor, 0)
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
                self._file = os.fdopen(
                    descriptor, "w", encoding="utf-8", newline="\n"
                )
                descriptor = None
            except OSError as exc:
                if descriptor is not None:
                    os.close(descriptor)
                raise ConfigurationError(
                    f"Could not create private transcript {self.path}: {exc}"
                ) from exc

    def close(self) -> None:
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None

    def register_secrets(self, values: Any) -> None:
        with self._lock:
            self._known_secrets.update(expand_known_secrets(values))

    @property
    def capture_truncated(self) -> bool:
        with self._lock:
            return self._capture_failure is not None

    def raise_if_truncated(self) -> None:
        with self._lock:
            failure = self._capture_failure
        if failure is not None:
            raise TransportError(str(failure))

    @property
    def known_secrets(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._known_secrets, key=lambda item: (-len(item), item)))

    def redact_value(self, value: Any, parent_key: str | None = None) -> Any:
        return redact_value(value, parent_key, known_secrets=self.known_secrets)

    def redact_protocol_payload(self, value: Any) -> Any:
        return redact_protocol_payload(value, known_secrets=self.known_secrets)

    def redact_text(self, value: str) -> str:
        return redact_text(value, self.known_secrets)

    def redact_raw(self, value: str) -> str:
        return redact_raw(value, self.known_secrets)

    def redact_headers(self, value: dict[str, Any] | None) -> dict[str, Any]:
        return redact_headers(value, self.known_secrets)

    def redact_url(self, value: str) -> str:
        return redact_url(value, self.known_secrets)

    def redact_command(self, value: list[str]) -> list[str]:
        return redact_command(value, self.known_secrets)

    def record(
        self,
        direction: str,
        transport: str,
        *,
        payload: Any = None,
        classification: str | None = None,
        raw: str | None = None,
        headers: dict[str, Any] | None = None,
        status: int | None = None,
        url: str | None = None,
        error: str | None = None,
        **metadata: Any,
    ) -> str:
        with self._lock:
            if self._capture_failure is not None:
                return self._capture_marker_reference or "event:0"
            self._sequence += 1
            seq = self._sequence
            safe_payload = (
                self.redact_protocol_payload(payload) if payload is not None else None
            )
            inferred_class = classification or (
                classify_message(payload) if payload is not None else "event"
            )
            record: dict[str, Any] = {
                "schema": TRANSCRIPT_EVENT_SCHEMA,
                "seq": seq,
                "time": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds"),
                "elapsedMs": round((time.monotonic() - self._started_mono) * 1000, 3),
                "direction": direction,
                "transport": transport,
                "classification": inferred_class,
            }
            # Derive denormalized fields from the already-redacted payload;
            # IDs and method strings can themselves contain credential URLs.
            rpc_id = message_id(safe_payload)
            method = message_method(safe_payload)
            if rpc_id is not None:
                record["id"] = rpc_id
            if method is not None:
                record["method"] = method
            if payload is not None:
                record["payload"] = safe_payload
            if raw is not None:
                record["raw"] = self.redact_raw(raw)
            if headers is not None:
                record["headers"] = self.redact_headers(headers)
            if status is not None:
                record["httpStatus"] = status
            if url is not None:
                record["url"] = self.redact_url(url)
            if error is not None:
                record["error"] = self.redact_text(error)
            for key, value in metadata.items():
                if value is not None:
                    # Metadata field names are fixed by MCP Probe call sites,
                    # not supplied by the peer.  A server-minted session ID
                    # may coincidentally equal one of them; keep the transcript
                    # schema stable while redacting the corresponding value.
                    record[key] = self.redact_value(value, key)
            encoded = compact_json(record) + "\n"
            if (
                len(self.events) + 1 >= self._max_events
                or self._captured_bytes
                + len(encoded.encode("utf-8"))
                + _CAPTURE_MARKER_RESERVE
                > self._max_capture_bytes
            ):
                return self._record_capture_limit(seq)
            self._append_record(record, encoded)
            if self.verbose:
                self._print(record)
            return f"event:{seq}"

    def _append_record(self, record: dict[str, Any], encoded: str) -> None:
        self.events.append(record)
        self._captured_bytes += len(encoded.encode("utf-8"))
        if self._file:
            self._file.write(encoded)
            self._file.flush()

    def _record_capture_limit(self, seq: int) -> str:
        message = (
            "Transcript capture exceeded its deterministic event or byte safety limit."
        )
        marker: dict[str, Any] = {
            "schema": TRANSCRIPT_EVENT_SCHEMA,
            "seq": seq,
            "time": dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds"),
            "elapsedMs": round((time.monotonic() - self._started_mono) * 1000, 3),
            "direction": "probe",
            "transport": "probe",
            "classification": "capture_limit",
            "error": message,
            "maxEvents": self._max_events,
            "maxBytes": self._max_capture_bytes,
            "droppedEvents": 1,
        }
        encoded = compact_json(marker) + "\n"
        if self._captured_bytes + len(encoded.encode("utf-8")) <= self._max_capture_bytes:
            self._append_record(marker, encoded)
            if self.verbose:
                self._print(marker)
        reference = f"event:{seq}"
        self._capture_marker_reference = reference
        self._capture_failure = TransportError(message)
        raise TransportError(message)

    def _print(self, record: dict[str, Any]) -> None:
        prefix = (
            f"[{record['time']}] #{record['seq']} "
            f"{record['direction'].upper()} {record['transport']} "
            f"{record['classification']}"
        )
        details = {key: value for key, value in record.items() if key not in {"schema", "time"}}
        print(f"{prefix}:\n{pretty_json(details)}", file=sys.stderr)

    def last_reference(self) -> str | None:
        return f"event:{self.events[-1]['seq']}" if self.events else None


def load_transcript(path: str | Path) -> list[dict[str, Any]]:
    transcript_path = Path(path)
    if not transcript_path.exists():
        raise ConfigurationError(f"Transcript not found: {transcript_path}")
    events: list[dict[str, Any]] = []
    try:
        lines = iter_utf8_lines_limited(
            transcript_path,
            max_bytes=MAX_TRANSCRIPT_BYTES,
            max_lines=MAX_TRANSCRIPT_EVENTS,
            max_line_bytes=MAX_TRANSCRIPT_LINE_BYTES,
            label="Transcript",
        )
        for line_number, line in lines:
            if not line.strip():
                continue
            try:
                event = strict_json_loads(line)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ConfigurationError(
                    f"Invalid transcript JSON on line {line_number}: {exc}"
                ) from exc
            if not isinstance(event, dict) or event.get("schema") != TRANSCRIPT_EVENT_SCHEMA:
                raise ConfigurationError(
                    f"Unsupported transcript event on line {line_number}; expected {TRANSCRIPT_EVENT_SCHEMA}."
                )
            if type(event.get("seq")) is not int or event["seq"] <= 0:
                raise ConfigurationError(f"Transcript event on line {line_number} has no integer seq.")
            expected_seq = len(events) + 1
            if event["seq"] != expected_seq:
                raise ConfigurationError(
                    f"Transcript event on line {line_number} has seq {event['seq']}; "
                    f"expected {expected_seq}."
                )
            for required in ("direction", "transport", "classification"):
                if not isinstance(event.get(required), str) or not event[required]:
                    raise ConfigurationError(
                        f"Transcript event on line {line_number} has no {required}."
                    )
            events.append(event)
    except (OSError, UnicodeError, InputLimitError) as exc:
        raise ConfigurationError(f"Could not read transcript {transcript_path}: {exc}") from exc
    if not events:
        raise ConfigurationError(f"Transcript is empty: {transcript_path}")
    return events
