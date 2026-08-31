"""Stable compatibility reports for humans, agents, and CI.

The JSON shape in this module is a public interface.  Finding and error codes
are deliberately registry-backed so callers cannot accidentally create a new
code for every server response.  All values pass through the shared redaction
helpers both when report objects are constructed and when they are rendered.
"""

from __future__ import annotations

import datetime as dt
import json
import math
import os
import re
import shlex
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .errors import (
    EXIT_COMPATIBILITY_FAILURE,
    EXIT_CONFIGURATION_ERROR,
    EXIT_INTERNAL_ERROR,
    EXIT_OK,
    EXIT_TRANSPORT_FAILURE,
    ConfigurationError,
)
from .redaction import (
    REDACTED,
    redact_command,
    redact_headers,
    redact_text,
    redact_url,
    redact_value,
)


REPORT_SCHEMA = "mcp-probe.report/v1"
REPORT_TYPES = ("inspection", "compatibility", "matrix", "scenario", "replay")
FINDING_STATUSES = ("PASS", "FAIL", "WARN", "SKIP")
OVERALL_STATUSES = ("PASS", "FAIL", "WARN", "SKIP", "ERROR")
FINDING_BASES = ("normative", "heuristic", "operational")
FINDING_CATEGORIES = (
    "negotiation",
    "lifecycle",
    "capability",
    "jsonrpc",
    "pagination",
    "client-request",
    "transport",
    "schema",
    "safety",
    "scenario",
    "replay",
)
ERROR_KINDS = ("configuration", "transport", "internal")

TOOL_NAME = "mcp-probe"
TOOL_VERSION = "0.2.0"


_FINDING_CODES_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "negotiation": (
        "NEGOTIATION_PROTOCOL_VERSION",
        "NEGOTIATION_SERVER_INFO",
        "NEGOTIATION_CAPABILITIES",
    ),
    "lifecycle": (
        "LIFECYCLE_INITIALIZE",
        "LIFECYCLE_INITIALIZED",
        "LIFECYCLE_ORDERING",
        "LIFECYCLE_DUPLICATE_INITIALIZE",
    ),
    "capability": (
        "CAPABILITY_TOOLS_LIST",
        "CAPABILITY_RESOURCES_LIST",
        "CAPABILITY_RESOURCE_TEMPLATES_LIST",
        "CAPABILITY_PROMPTS_LIST",
        "CAPABILITY_LOGGING",
        "CAPABILITY_ROOTS",
    ),
    "jsonrpc": (
        "JSONRPC_RESPONSE_SHAPE",
        "JSONRPC_RESPONSE_ID",
        "JSONRPC_VERSION",
        "JSONRPC_UNKNOWN_METHOD",
        "JSONRPC_INVALID_PARAMS",
        "JSONRPC_INVALID_REQUEST",
        "JSONRPC_NOTIFICATION_NO_RESPONSE",
    ),
    "pagination": (
        "PAGINATION_CURSOR_SHAPE",
        "PAGINATION_CURSOR_PROGRESS",
        "PAGINATION_CURSOR_LOOP",
    ),
    "client-request": (
        "CLIENT_REQUEST_PING",
        "CLIENT_REQUEST_ROOTS_LIST",
        "CLIENT_REQUEST_UNSUPPORTED",
    ),
    "transport": (
        "STDIO_INVALID_OUTPUT",
        "STDIO_UNEXPECTED_EOF",
        "STDIO_CHILD_EXIT",
        "STDIO_TIMEOUT",
        "STDIO_CLEANUP",
        "HTTP_STATUS",
        "HTTP_CONTENT_TYPE",
        "HTTP_BODY_SHAPE",
        "HTTP_SSE_PARSE",
        "HTTP_SESSION_ID",
        "HTTP_PROTOCOL_VERSION_HEADER",
        "HTTP_SESSION_TERMINATION",
        "HTTP_TIMEOUT",
    ),
    "schema": (
        "TOOL_SCHEMA_INPUT_PRESENT",
        "TOOL_SCHEMA_INPUT_OBJECT",
        "TOOL_SCHEMA_REQUIRED_SHAPE",
        "TOOL_SCHEMA_OUTPUT_OBJECT",
        "TOOL_NAME_UNIQUE",
        "TOOL_SCHEMA_PORTABILITY",
        "TOOL_LIST_NOT_ARRAY",
        "TOOL_DESCRIPTOR_NOT_OBJECT",
        "TOOL_NAME_MISSING",
        "TOOL_NAME_NOT_STRING",
        "TOOL_NAME_EMPTY",
        "TOOL_NAME_DUPLICATE",
        "TOOL_INPUT_SCHEMA_MISSING",
        "TOOL_INPUT_SCHEMA_NOT_OBJECT",
        "TOOL_INPUT_SCHEMA_TYPE_NOT_OBJECT",
        "TOOL_INPUT_SCHEMA_PROPERTIES_NOT_OBJECT",
        "TOOL_INPUT_SCHEMA_REQUIRED_NOT_ARRAY",
        "TOOL_INPUT_SCHEMA_REQUIRED_ENTRY_NOT_STRING",
        "TOOL_INPUT_SCHEMA_REQUIRED_DUPLICATE",
        "TOOL_INPUT_SCHEMA_REQUIRED_UNKNOWN",
        "TOOL_OUTPUT_SCHEMA_NOT_OBJECT",
        "TOOL_X_MCP_HEADER_MISPLACED",
        "TOOL_X_MCP_HEADER_NOT_STRING",
        "TOOL_X_MCP_HEADER_INVALID_NAME",
        "TOOL_X_MCP_HEADER_INVALID_TYPE",
        "TOOL_X_MCP_HEADER_DUPLICATE",
        "TOOL_SCHEMA_INSPECTION",
    ),
    "safety": ("SAFETY_ACTIVE_TOOL_OPT_IN",),
    "scenario": (
        "SCENARIO_STEP",
        "SCENARIO_EXPECTATION",
        "SCENARIO_ASSERTION",
        "SCENARIO_DISCONNECT",
    ),
    "replay": (
        "REPLAY_EVENT",
        "REPLAY_RESPONSE_MATCH",
        "REPLAY_COMPLETE",
    ),
}
FINDING_CODES = tuple(
    code for category in FINDING_CATEGORIES for code in _FINDING_CODES_BY_CATEGORY[category]
)
FINDING_CODE_CATEGORIES = MappingProxyType(
    {
        code: category
        for category, codes in _FINDING_CODES_BY_CATEGORY.items()
        for code in codes
    }
)

ERROR_CODES_BY_KIND: dict[str, tuple[str, ...]] = {
    "configuration": (
        "CONFIG_INVALID_ARGUMENT",
        "CONFIG_INVALID_JSON",
        "CONFIG_INVALID_SCENARIO",
        "CONFIG_UNSUPPORTED_VERSION",
        "CONFIG_UNSAFE_ACTION",
    ),
    "transport": (
        "TRANSPORT_STDIO_STARTUP",
        "TRANSPORT_STDIO_EOF",
        "TRANSPORT_STDIO_CHILD_EXIT",
        "TRANSPORT_STDIO_TIMEOUT",
        "TRANSPORT_HTTP_CONNECT",
        "TRANSPORT_HTTP_TIMEOUT",
        "TRANSPORT_HTTP_IO",
    ),
    "internal": ("INTERNAL_UNEXPECTED",),
}
ERROR_CODES = tuple(code for kind in ERROR_KINDS for code in ERROR_CODES_BY_KIND[kind])
ERROR_CODE_KINDS = MappingProxyType(
    {code: kind for kind, codes in ERROR_CODES_BY_KIND.items() for code in codes}
)

_CODE_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
_EVENT_RE = re.compile(r"^event:([1-9][0-9]*)$")
_COUNT_KEYS = ("pass", "fail", "warn", "skip")
_DISCOVERY_KEYS = ("tools", "resources", "resourceTemplates", "prompts")


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")


def _safe_text(value: str) -> str:
    return redact_text(value)


def _safe_json(value: Any, parent_key: str | None = None) -> Any:
    """Return redacted JSON-compatible data with deterministic container types."""
    redacted = redact_value(value, parent_key)
    if redacted is None or isinstance(redacted, (bool, int)):
        return redacted
    if isinstance(redacted, float):
        return redacted if math.isfinite(redacted) else str(redacted)
    if isinstance(redacted, str):
        return _safe_text(redacted)
    if isinstance(redacted, Mapping):
        return {
            str(key): _safe_json(item, str(key))
            for key, item in redacted.items()
        }
    if isinstance(redacted, (list, tuple)):
        return [_safe_json(item) for item in redacted]
    if isinstance(redacted, (set, frozenset)):
        return [_safe_json(item) for item in sorted(redacted, key=repr)]
    return _safe_text(str(redacted))


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _round_duration(value: float | int | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("durationMs must be a number or null.")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise ValueError("durationMs must be a finite non-negative number.")
    return round(number, 3)


@dataclass(frozen=True)
class EvidenceRef:
    """A stable pointer to one transcript event and, optionally, JSON Pointer data."""

    event: str
    pointer: str | None = None
    note: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event, str) or not _EVENT_RE.fullmatch(self.event):
            raise ValueError("Evidence event must have the form event:<positive integer>.")
        if self.pointer is not None:
            if not isinstance(self.pointer, str) or (
                self.pointer != "" and not self.pointer.startswith("/")
            ):
                raise ValueError("Evidence pointer must be a JSON Pointer or null.")
            object.__setattr__(self, "pointer", _safe_text(self.pointer))
        if self.note is not None:
            if not isinstance(self.note, str):
                raise ValueError("Evidence note must be a string or null.")
            object.__setattr__(self, "note", _safe_text(self.note))

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": self.event,
            "pointer": self.pointer,
            "note": self.note,
        }


def _coerce_evidence(value: EvidenceRef | Mapping[str, Any] | str) -> EvidenceRef:
    if isinstance(value, EvidenceRef):
        return value
    if isinstance(value, str):
        return EvidenceRef(event=value)
    if isinstance(value, Mapping):
        return EvidenceRef(
            event=value.get("event"),
            pointer=value.get("pointer"),
            note=value.get("note"),
        )
    raise ValueError("Evidence entries must be EvidenceRef, an object, or an event reference.")


def _coerce_evidence_list(
    values: Iterable[EvidenceRef | Mapping[str, Any] | str] | None,
) -> tuple[EvidenceRef, ...]:
    if values is None:
        return ()
    if isinstance(values, (str, bytes)):
        values = (values.decode(errors="replace") if isinstance(values, bytes) else values,)
    return tuple(_coerce_evidence(value) for value in values)


@dataclass(frozen=True)
class Finding:
    """One immutable, evidence-backed compatibility assertion result."""

    code: str
    status: str
    category: str
    basis: str
    summary: str
    details: str | None = None
    expected: Any = None
    actual: Any = None
    evidence: tuple[EvidenceRef, ...] = field(default_factory=tuple)
    duration_ms: float | None = None
    active: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not _CODE_RE.fullmatch(self.code):
            raise ValueError("Finding code must use stable AREA_SUBJECT uppercase form.")
        if self.code not in FINDING_CODE_CATEGORIES:
            raise ValueError(f"Unknown finding code: {self.code}")
        status = str(self.status).upper()
        if status not in FINDING_STATUSES:
            raise ValueError(f"Unknown finding status: {self.status!r}")
        if self.category not in FINDING_CATEGORIES:
            raise ValueError(f"Unknown finding category: {self.category!r}")
        expected_category = FINDING_CODE_CATEGORIES[self.code]
        if self.category != expected_category:
            raise ValueError(
                f"Finding {self.code} belongs to category {expected_category!r}, "
                f"not {self.category!r}."
            )
        if self.basis not in FINDING_BASES:
            raise ValueError(f"Unknown finding basis: {self.basis!r}")
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("Finding summary must be a non-empty string.")
        if self.details is not None and not isinstance(self.details, str):
            raise ValueError("Finding details must be a string or null.")
        if status == "SKIP" and (self.details is None or not self.details.strip()):
            raise ValueError("A SKIP finding must explain why in details.")
        if not isinstance(self.active, bool):
            raise ValueError("Finding active must be a boolean.")

        object.__setattr__(self, "status", status)
        object.__setattr__(self, "summary", _safe_text(self.summary.strip()))
        object.__setattr__(
            self,
            "details",
            _safe_text(self.details.strip()) if self.details is not None else None,
        )
        object.__setattr__(self, "expected", _freeze(_safe_json(self.expected)))
        object.__setattr__(self, "actual", _freeze(_safe_json(self.actual)))
        object.__setattr__(self, "evidence", _coerce_evidence_list(self.evidence))
        object.__setattr__(self, "duration_ms", _round_duration(self.duration_ms))

    def to_dict(self) -> dict[str, Any]:
        return _safe_json(
            {
                "code": self.code,
                "status": self.status,
                "category": self.category,
                "basis": self.basis,
                "summary": self.summary,
                "details": self.details,
                "expected": _thaw(self.expected),
                "actual": _thaw(self.actual),
                "evidence": [item.to_dict() for item in self.evidence],
                "durationMs": self.duration_ms,
                "active": self.active,
            }
        )


@dataclass(frozen=True)
class RunError:
    """A run-level failure which prevented or invalidated required execution."""

    code: str
    kind: str
    summary: str
    details: str | None = None
    evidence: tuple[EvidenceRef, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not isinstance(self.code, str) or not _CODE_RE.fullmatch(self.code):
            raise ValueError("Run error code must use stable AREA_SUBJECT uppercase form.")
        if self.code not in ERROR_CODE_KINDS:
            raise ValueError(f"Unknown run error code: {self.code}")
        if self.kind not in ERROR_KINDS:
            raise ValueError(f"Unknown run error kind: {self.kind!r}")
        expected_kind = ERROR_CODE_KINDS[self.code]
        if self.kind != expected_kind:
            raise ValueError(
                f"Run error {self.code} belongs to kind {expected_kind!r}, not {self.kind!r}."
            )
        if not isinstance(self.summary, str) or not self.summary.strip():
            raise ValueError("Run error summary must be a non-empty string.")
        if self.details is not None and not isinstance(self.details, str):
            raise ValueError("Run error details must be a string or null.")
        object.__setattr__(self, "summary", _safe_text(self.summary.strip()))
        object.__setattr__(
            self,
            "details",
            _safe_text(self.details.strip()) if self.details is not None else None,
        )
        object.__setattr__(self, "evidence", _coerce_evidence_list(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        return _safe_json(
            {
                "code": self.code,
                "kind": self.kind,
                "summary": self.summary,
                "details": self.details,
                "evidence": [item.to_dict() for item in self.evidence],
            }
        )


def stdio_target(
    command: Sequence[str], environment_keys: Iterable[str] = ()
) -> dict[str, Any]:
    if isinstance(command, (str, bytes)) or not command:
        raise ValueError("stdio target command must be a non-empty sequence of arguments.")
    safe_command = redact_command([str(item) for item in command])
    keys = sorted({str(key) for key in environment_keys})
    return {
        "transport": "stdio",
        "description": shlex.join(safe_command),
        "command": safe_command,
        "environmentKeys": keys,
    }


def http_target(url: str, headers: Mapping[str, Any] | None = None) -> dict[str, Any]:
    if not isinstance(url, str) or not url:
        raise ValueError("HTTP target URL must be a non-empty string.")
    safe_url = redact_url(url)
    return {
        "transport": "http",
        "description": safe_url,
        "url": safe_url,
        "headers": redact_headers(headers),
    }


def _normalize_target(target: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(target, Mapping):
        raise ValueError("Report target must be an object.")
    transport = target.get("transport")
    if transport == "stdio":
        command = target.get("command")
        if not isinstance(command, Sequence) or isinstance(command, (str, bytes)):
            raise ValueError("stdio report target requires a command array.")
        environment_keys = target.get("environmentKeys", ())
        if "env" in target and isinstance(target["env"], Mapping):
            environment_keys = tuple(environment_keys) + tuple(target["env"].keys())
        if "environment" in target and isinstance(target["environment"], Mapping):
            environment_keys = tuple(environment_keys) + tuple(target["environment"].keys())
        return stdio_target(command, environment_keys)
    if transport == "http":
        return http_target(str(target.get("url") or ""), target.get("headers"))
    raise ValueError("Report target transport must be 'stdio' or 'http'.")


def _normalize_discovery(discovery: Mapping[str, Any] | None) -> dict[str, list[Any]]:
    source = discovery or {}
    if not isinstance(source, Mapping):
        raise ValueError("Report discovery must be an object.")
    result: dict[str, list[Any]] = {}
    for key in _DISCOVERY_KEYS:
        items = source.get(key, [])
        if items is None:
            items = []
        if not isinstance(items, (list, tuple)):
            raise ValueError(f"discovery.{key} must be an array.")
        result[key] = [_safe_json(item) for item in items]
    return result


def _normalize_transcript(transcript: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if transcript is None:
        return None
    if not isinstance(transcript, Mapping):
        raise ValueError("Report transcript must be an object or null.")
    event_count = transcript.get("eventCount", 0)
    if isinstance(event_count, bool) or not isinstance(event_count, int) or event_count < 0:
        raise ValueError("transcript.eventCount must be a non-negative integer.")
    return {
        "schema": str(transcript.get("schema") or "mcp-probe.transcript.event/v1"),
        "path": _safe_text(str(transcript.get("path"))) if transcript.get("path") is not None else None,
        "eventCount": event_count,
        "redacted": bool(transcript.get("redacted", True)),
    }


def _finding_status(value: Finding | Mapping[str, Any]) -> str:
    return value.status if isinstance(value, Finding) else str(value.get("status", "")).upper()


def _error_kind(value: RunError | Mapping[str, Any]) -> str:
    return value.kind if isinstance(value, RunError) else str(value.get("kind", ""))


def aggregate_overall(
    findings: Iterable[Finding | Mapping[str, Any]],
    errors: Iterable[RunError | Mapping[str, Any]],
) -> dict[str, Any]:
    finding_list = tuple(findings)
    error_list = tuple(errors)
    counts = {key: 0 for key in _COUNT_KEYS}
    for finding in finding_list:
        status = _finding_status(finding)
        if status not in FINDING_STATUSES:
            raise ValueError(f"Cannot aggregate unknown finding status: {status!r}")
        counts[status.lower()] += 1

    if error_list:
        status = "ERROR"
    elif counts["fail"]:
        status = "FAIL"
    elif counts["warn"]:
        status = "WARN"
    elif counts["pass"]:
        status = "PASS"
    else:
        status = "SKIP"
    return {"status": status, "counts": counts, "errorCount": len(error_list)}


def derive_exit_code(
    findings: Iterable[Finding | Mapping[str, Any]] = (),
    errors: Iterable[RunError | Mapping[str, Any]] = (),
) -> int:
    finding_list = tuple(findings)
    error_list = tuple(errors)
    kinds = {_error_kind(error) for error in error_list}
    if "internal" in kinds:
        return EXIT_INTERNAL_ERROR
    if "configuration" in kinds:
        return EXIT_CONFIGURATION_ERROR
    if "transport" in kinds:
        return EXIT_TRANSPORT_FAILURE
    if any(_finding_status(finding) == "FAIL" for finding in finding_list):
        return EXIT_COMPATIBILITY_FAILURE
    return EXIT_OK


@dataclass(frozen=True, kw_only=True)
class CompatibilityReport:
    """A complete v1 MCP Probe report envelope."""

    target: Mapping[str, Any]
    report_type: str = "compatibility"
    started_at: str = field(default_factory=_now_iso)
    duration_ms: float | None = None
    requested_version: str | None = None
    negotiated_version: str | None = None
    era: str | None = None
    server_info: Mapping[str, Any] | None = None
    capabilities: Mapping[str, Any] | None = None
    discovery: Mapping[str, Any] | None = None
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    errors: tuple[RunError, ...] = field(default_factory=tuple)
    transcript: Mapping[str, Any] | None = None
    matrix: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.report_type not in REPORT_TYPES:
            raise ValueError(f"Unknown report type: {self.report_type!r}")
        if not isinstance(self.started_at, str) or not self.started_at:
            raise ValueError("startedAt must be a non-empty ISO timestamp string.")
        for field_name, value in (
            ("requestedVersion", self.requested_version),
            ("negotiatedVersion", self.negotiated_version),
            ("era", self.era),
        ):
            if value is not None and not isinstance(value, str):
                raise ValueError(f"protocol.{field_name} must be a string or null.")
        if self.server_info is not None and not isinstance(self.server_info, Mapping):
            raise ValueError("serverInfo must be an object or null.")
        if self.capabilities is not None and not isinstance(self.capabilities, Mapping):
            raise ValueError("capabilities must be an object or null.")
        findings = tuple(self.findings)
        errors = tuple(self.errors)
        if not all(isinstance(item, Finding) for item in findings):
            raise ValueError("Report findings must contain Finding objects.")
        if not all(isinstance(item, RunError) for item in errors):
            raise ValueError("Report errors must contain RunError objects.")
        if self.report_type == "matrix" and (findings or errors):
            raise ValueError("Matrix top-level findings and errors must remain empty.")

        object.__setattr__(self, "target", _freeze(_normalize_target(self.target)))
        object.__setattr__(self, "duration_ms", _round_duration(self.duration_ms))
        object.__setattr__(self, "started_at", _safe_text(self.started_at))
        object.__setattr__(self, "requested_version", _safe_json(self.requested_version))
        object.__setattr__(self, "negotiated_version", _safe_json(self.negotiated_version))
        object.__setattr__(self, "era", _safe_json(self.era))
        object.__setattr__(
            self,
            "server_info",
            _freeze(_safe_json(self.server_info)) if self.server_info is not None else None,
        )
        object.__setattr__(
            self,
            "capabilities",
            _freeze(_safe_json(self.capabilities)) if self.capabilities is not None else None,
        )
        object.__setattr__(self, "discovery", _freeze(_normalize_discovery(self.discovery)))
        object.__setattr__(self, "findings", findings)
        object.__setattr__(self, "errors", errors)
        object.__setattr__(
            self,
            "transcript",
            _freeze(_normalize_transcript(self.transcript)) if self.transcript is not None else None,
        )
        object.__setattr__(
            self,
            "matrix",
            _freeze(_safe_json(self.matrix)) if self.matrix is not None else None,
        )

    @property
    def overall(self) -> dict[str, Any]:
        if self.report_type == "matrix" and self.matrix is not None:
            return _aggregate_matrix(_thaw(self.matrix))
        return aggregate_overall(self.findings, self.errors)

    @property
    def exit_code(self) -> int:
        if self.report_type == "matrix" and self.matrix is not None:
            return _derive_matrix_exit_code(_thaw(self.matrix))
        return derive_exit_code(self.findings, self.errors)

    def to_dict(self) -> dict[str, Any]:
        report: dict[str, Any] = {
            "schema": REPORT_SCHEMA,
            "reportType": self.report_type,
            "tool": {"name": TOOL_NAME, "version": TOOL_VERSION},
            "run": {
                "startedAt": self.started_at,
                "durationMs": self.duration_ms,
                "exitCode": self.exit_code,
            },
            "target": _thaw(self.target),
            "protocol": {
                "requestedVersion": self.requested_version,
                "negotiatedVersion": self.negotiated_version,
                "era": self.era,
            },
            "server": {
                "serverInfo": _thaw(self.server_info),
                "capabilities": _thaw(self.capabilities),
            },
            "discovery": _thaw(self.discovery),
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
            "transcript": _thaw(self.transcript),
            "overall": self.overall,
        }
        if self.report_type == "matrix":
            report["matrix"] = _thaw(self.matrix) if self.matrix is not None else {
                "versions": [],
                "runs": [],
            }
        return _safe_json(report)

    def render(self, output_format: str = "text") -> str:
        if output_format == "text":
            return render_text(self)
        if output_format == "json":
            return render_json(self)
        if output_format in {"markdown", "md"}:
            return render_markdown(self)
        raise ValueError(f"Unknown report output format: {output_format!r}")


Report = CompatibilityReport


def _matrix_runs(matrix: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    runs = matrix.get("runs", [])
    if not isinstance(runs, list):
        raise ValueError("matrix.runs must be an array.")
    if not all(isinstance(run, Mapping) for run in runs):
        raise ValueError("Each matrix run must be an object.")
    return list(runs)


def _aggregate_matrix(matrix: Mapping[str, Any]) -> dict[str, Any]:
    counts = {key: 0 for key in _COUNT_KEYS}
    error_count = 0
    statuses: list[str] = []
    for run in _matrix_runs(matrix):
        overall = run.get("overall", {})
        if not isinstance(overall, Mapping):
            raise ValueError("Each matrix run requires an overall object.")
        status = str(overall.get("status", ""))
        if status not in OVERALL_STATUSES:
            raise ValueError(f"Unknown matrix run status: {status!r}")
        statuses.append(status)
        run_counts = overall.get("counts", {})
        if not isinstance(run_counts, Mapping):
            raise ValueError("Each matrix overall.counts value must be an object.")
        for key in _COUNT_KEYS:
            value = run_counts.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"Matrix count {key!r} must be a non-negative integer.")
            counts[key] += value
        value = overall.get("errorCount", 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError("Matrix errorCount must be a non-negative integer.")
        error_count += value

    if "ERROR" in statuses:
        status = "ERROR"
    elif "FAIL" in statuses:
        status = "FAIL"
    elif "WARN" in statuses:
        status = "WARN"
    elif "PASS" in statuses:
        status = "PASS"
    else:
        status = "SKIP"
    return {"status": status, "counts": counts, "errorCount": error_count}


def _derive_matrix_exit_code(matrix: Mapping[str, Any]) -> int:
    kinds: set[str] = set()
    has_fail = False
    for run in _matrix_runs(matrix):
        errors = run.get("errors", [])
        findings = run.get("findings", [])
        if not isinstance(errors, list) or not isinstance(findings, list):
            raise ValueError("Matrix run findings and errors must be arrays.")
        kinds.update(_error_kind(error) for error in errors if isinstance(error, Mapping))
        has_fail = has_fail or any(
            _finding_status(finding) == "FAIL"
            for finding in findings
            if isinstance(finding, Mapping)
        )
    if "internal" in kinds:
        return EXIT_INTERNAL_ERROR
    if "configuration" in kinds:
        return EXIT_CONFIGURATION_ERROR
    if "transport" in kinds:
        return EXIT_TRANSPORT_FAILURE
    return EXIT_COMPATIBILITY_FAILURE if has_fail else EXIT_OK


def _report_dict(report: CompatibilityReport | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(report, CompatibilityReport):
        return report.to_dict()
    if isinstance(report, Mapping):
        return _safe_json(report)
    raise TypeError("report must be a CompatibilityReport or mapping.")


def render_json(report: CompatibilityReport | Mapping[str, Any]) -> str:
    return json.dumps(
        _report_dict(report),
        ensure_ascii=False,
        indent=2,
        allow_nan=False,
    ) + "\n"


def _target_description(data: Mapping[str, Any]) -> str:
    target = data.get("target")
    if isinstance(target, Mapping):
        description = target.get("description")
        if isinstance(description, str):
            return description
    return "unknown"


def _protocol_value(data: Mapping[str, Any], key: str) -> str:
    protocol = data.get("protocol")
    if isinstance(protocol, Mapping) and protocol.get(key) is not None:
        return str(protocol[key])
    return "n/a"


def _event_refs(item: Mapping[str, Any]) -> str:
    evidence = item.get("evidence", [])
    if not isinstance(evidence, list):
        return ""
    refs = [str(entry.get("event")) for entry in evidence if isinstance(entry, Mapping)]
    return f" [{', '.join(refs)}]" if refs else ""


def render_text(report: CompatibilityReport | Mapping[str, Any]) -> str:
    data = _report_dict(report)
    overall = data.get("overall", {})
    counts = overall.get("counts", {}) if isinstance(overall, Mapping) else {}
    status = overall.get("status", "ERROR") if isinstance(overall, Mapping) else "ERROR"
    lines = [
        f"MCP Probe {data.get('reportType', 'report')}: {status}",
        f"Target: {_target_description(data)}",
        (
            "Protocol: requested "
            f"{_protocol_value(data, 'requestedVersion')}, negotiated "
            f"{_protocol_value(data, 'negotiatedVersion')}"
        ),
    ]
    server = data.get("server", {})
    if isinstance(server, Mapping) and server.get("serverInfo") is not None:
        lines.append(
            "Server: "
            + json.dumps(server["serverInfo"], ensure_ascii=False, separators=(",", ":"))
        )
    lines.append(
        "Summary: "
        + ", ".join(f"{key.upper()} {counts.get(key, 0)}" for key in _COUNT_KEYS)
        + f", ERRORS {overall.get('errorCount', 0) if isinstance(overall, Mapping) else 0}"
    )

    findings = data.get("findings", [])
    if findings:
        lines.append("Findings:")
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            lines.append(
                f"{finding.get('status')} {finding.get('code')}  "
                f"{finding.get('summary')}{_event_refs(finding)}"
            )
            if finding.get("status") in {"FAIL", "WARN", "SKIP"} and finding.get("details"):
                lines.append(f"  {finding['details']}")

    errors = data.get("errors", [])
    if errors:
        lines.append("Errors:")
        for error in errors:
            if not isinstance(error, Mapping):
                continue
            lines.append(
                f"ERROR {error.get('code')}  {error.get('summary')}{_event_refs(error)}"
            )
            if error.get("details"):
                lines.append(f"  {error['details']}")

    transcript = data.get("transcript")
    if isinstance(transcript, Mapping) and transcript.get("path"):
        lines.append(f"Transcript: {transcript['path']}")
    return "\n".join(lines) + "\n"


def _markdown_cell(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).replace("\\", "\\\\").replace("|", "\\|")
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", " ")


def render_markdown(report: CompatibilityReport | Mapping[str, Any]) -> str:
    data = _report_dict(report)
    overall = data.get("overall", {})
    counts = overall.get("counts", {}) if isinstance(overall, Mapping) else {}
    status = overall.get("status", "ERROR") if isinstance(overall, Mapping) else "ERROR"
    lines = [
        f"# MCP Probe {data.get('reportType', 'report')}: {status}",
        "",
        f"- Target: `{_markdown_cell(_target_description(data))}`",
        f"- Requested protocol: `{_markdown_cell(_protocol_value(data, 'requestedVersion'))}`",
        f"- Negotiated protocol: `{_markdown_cell(_protocol_value(data, 'negotiatedVersion'))}`",
        (
            "- Counts: "
            + ", ".join(f"{key.upper()} {counts.get(key, 0)}" for key in _COUNT_KEYS)
            + f", ERRORS {overall.get('errorCount', 0) if isinstance(overall, Mapping) else 0}"
        ),
        "",
        "## Findings",
        "",
        "| Status | Code | Basis | Summary | Evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in data.get("findings", []):
        if not isinstance(finding, Mapping):
            continue
        evidence = _event_refs(finding).strip().strip("[]")
        lines.append(
            "| "
            + " | ".join(
                _markdown_cell(value)
                for value in (
                    finding.get("status"),
                    finding.get("code"),
                    finding.get("basis"),
                    finding.get("summary"),
                    evidence,
                )
            )
            + " |"
        )

    lines.extend(["", "## Errors", ""])
    errors = data.get("errors", [])
    if errors:
        for error in errors:
            if isinstance(error, Mapping):
                lines.append(
                    f"- **{_markdown_cell(error.get('code'))}:** "
                    f"{_markdown_cell(error.get('summary'))}"
                )
    else:
        lines.append("None.")
    transcript = data.get("transcript")
    if isinstance(transcript, Mapping) and transcript.get("path"):
        lines.extend(["", f"Transcript: `{_markdown_cell(transcript['path'])}`"])
    return "\n".join(lines) + "\n"


def write_report(path: str | Path, report: CompatibilityReport | Mapping[str, Any]) -> None:
    report_path = Path(path)
    if str(report_path) == "-":
        raise ConfigurationError("write_report does not accept '-' as a stdout sentinel.")
    report_path.parent.mkdir(parents=True, exist_ok=True)
    content = render_json(report)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=report_path.parent,
            prefix=f".{report_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_name = handle.name
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, report_path)
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


__all__ = [
    "CompatibilityReport",
    "ERROR_CODES",
    "ERROR_KINDS",
    "EvidenceRef",
    "FINDING_BASES",
    "FINDING_CATEGORIES",
    "FINDING_CODES",
    "FINDING_STATUSES",
    "Finding",
    "OVERALL_STATUSES",
    "REPORT_SCHEMA",
    "REPORT_TYPES",
    "Report",
    "RunError",
    "aggregate_overall",
    "derive_exit_code",
    "http_target",
    "render_json",
    "render_markdown",
    "render_text",
    "stdio_target",
    "write_report",
]
