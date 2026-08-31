"""Structured, redacted protocol event recording."""

from __future__ import annotations

import datetime as dt
import json
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .errors import ConfigurationError
from .protocol import classify_message, message_id, message_method
from .redaction import redact_headers, redact_raw, redact_text, redact_url, redact_value


TRANSCRIPT_EVENT_SCHEMA = "mcp-probe.transcript.event/v1"


def compact_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False)


class EventRecorder:
    """Collect evidence in memory and optionally write it as NDJSON."""

    def __init__(self, path: str | None = None, verbose: bool = False) -> None:
        self.path = Path(path) if path else None
        self.verbose = verbose
        self.events: list[dict[str, Any]] = []
        self._started_mono = time.monotonic()
        self._sequence = 0
        self._lock = threading.RLock()
        self._file = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._file = self.path.open("w", encoding="utf-8")

    def close(self) -> None:
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None

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
            self._sequence += 1
            seq = self._sequence
            safe_payload = redact_value(payload) if payload is not None else None
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
            rpc_id = message_id(payload)
            method = message_method(payload)
            if rpc_id is not None:
                record["id"] = rpc_id
            if method is not None:
                record["method"] = method
            if payload is not None:
                record["payload"] = safe_payload
            if raw is not None:
                record["raw"] = redact_raw(raw)
            if headers is not None:
                record["headers"] = redact_headers(headers)
            if status is not None:
                record["httpStatus"] = status
            if url is not None:
                record["url"] = redact_url(url)
            if error is not None:
                record["error"] = redact_text(error)
            for key, value in metadata.items():
                if value is not None:
                    record[key] = redact_value(value, key)
            self.events.append(record)
            if self._file:
                self._file.write(compact_json(record) + "\n")
                self._file.flush()
            if self.verbose:
                self._print(record)
            return f"event:{seq}"

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
    for line_number, line in enumerate(
        transcript_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
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
    if not events:
        raise ConfigurationError(f"Transcript is empty: {transcript_path}")
    return events
