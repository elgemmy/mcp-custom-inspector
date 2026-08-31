"""Deterministic, credential-safe replay of MCP Probe transcripts.

Replay deliberately operates below :class:`McpSession`: it sends only actions
which were present in the source transcript.  In particular, it never inserts
``initialize``, ``notifications/initialized``, modern request metadata, or any
other lifecycle message.

Server-to-client events in a stdio transcript are receive checkpoints, not
data to inject.  HTTP is request scoped, so fresh responses are compared with
the source response window for each POST.  Comparisons are structural: message
classification, IDs, methods, response kind, JSON-RPC error code, and HTTP
status are compared while server-specific result payloads are left alone.
"""

from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from .errors import ConfigurationError, ProbeTimeout, ProcessExited, TransportError
from .protocol import (
    classify_message,
    message_method,
    modern_http_headers,
    profile_for,
    strict_json_loads,
)
from .redaction import (
    REDACTED,
    contains_redaction,
)
from .report import EvidenceRef, Finding, RunError
from .transcript import EventRecorder, compact_json, load_transcript
from .transports import (
    HttpExchange,
    HttpTransport,
    InboundMessage,
    StdioTransport,
    header_value,
)


_TRANSPORTS = {"stdio", "http"}
_CLIENT_DIRECTIONS = {"client_to_server"}
_SERVER_DIRECTIONS = {"server_to_client"}
_MESSAGE_CLASSES = {"request", "response", "notification", "invalid"}
_INBOUND_CLASSES = _MESSAGE_CLASSES | {
    "blank_line",
    "invalid_body",
    "invalid_json",
    "invalid_utf8",
    "message_too_large",
    "missing_delimiter",
}
_CLIENT_ACTION_CLASSES = _MESSAGE_CLASSES | {"batch", "raw_wire", "session_terminate"}
_MAX_REPLAY_BATCH_MESSAGES = 1_000

@dataclass(frozen=True, slots=True)
class ReplayOptions:
    """Bounds and protocol context for one replay.

    ``protocol_version`` chooses the transport era; it never rewrites a
    recorded payload.  When omitted, replay infers the first initialize or
    modern per-request version, falling back to the target transport profile.
    """

    timeout: float = 5.0
    protocol_version: str | None = None
    preserve_timing: bool = False
    timing_scale: float = 1.0
    max_delay_seconds: float = 1.0
    max_total_delay_seconds: float = 30.0
    max_events: int = 10_000
    allow_tools: tuple[str, ...] = ()
    allow_opaque_wire: bool = False

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
        ):
            raise ConfigurationError("Replay timeout must be a number.")
        if self.timeout <= 0:
            raise ConfigurationError("Replay timeout must be greater than zero.")
        if not isinstance(self.preserve_timing, bool):
            raise ConfigurationError("Replay preserve_timing must be a boolean.")
        for name, value in (
            ("timing_scale", self.timing_scale),
            ("max_delay_seconds", self.max_delay_seconds),
            ("max_total_delay_seconds", self.max_total_delay_seconds),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
            ):
                raise ConfigurationError(f"Replay {name} must be a number.")
            if value < 0:
                raise ConfigurationError(f"Replay {name} cannot be negative.")
        if isinstance(self.max_events, bool) or not isinstance(self.max_events, int):
            raise ConfigurationError("Replay max_events must be an integer.")
        if self.max_events <= 0:
            raise ConfigurationError("Replay max_events must be greater than zero.")
        if self.protocol_version is not None and (
            not isinstance(self.protocol_version, str) or not self.protocol_version
        ):
            raise ConfigurationError(
                "Replay protocol_version must be a non-empty string or null."
            )
        if isinstance(self.allow_tools, (str, bytes)) or not isinstance(
            self.allow_tools, (tuple, list, set, frozenset)
        ):
            raise ConfigurationError("Replay allow_tools must be a collection of tool names.")
        normalized_tools: list[str] = []
        for name in self.allow_tools:
            if not isinstance(name, str) or not name:
                raise ConfigurationError(
                    "Every replay allow_tools entry must be a non-empty string."
                )
            if name not in normalized_tools:
                normalized_tools.append(name)
        object.__setattr__(self, "allow_tools", tuple(normalized_tools))
        if not isinstance(self.allow_opaque_wire, bool):
            raise ConfigurationError("Replay allow_opaque_wire must be a boolean.")


@dataclass(frozen=True, slots=True)
class ReplayPlan:
    """Validated source events and metadata needed to construct a target."""

    source: str
    source_transport: str
    protocol_version: str | None
    events: tuple[Mapping[str, Any], ...]
    client_event_count: int
    active_tools: tuple[str, ...]
    opaque_wire_event_count: int = 0


@dataclass(frozen=True, slots=True)
class ReplayResult:
    """Stable replay outcome consumed directly by the CLI report builder."""

    source_transport: str
    target_transport: str
    protocol_version: str | None
    negotiated_version: str | None
    source_event_count: int
    planned_actions: int
    sent_actions: int
    received_messages: int
    completed: bool
    matches_source: bool
    credentials_reused: bool
    redactions_applied: bool
    active_tools: tuple[str, ...]
    opaque_wire_event_count: int
    findings: tuple[Finding, ...] = field(default_factory=tuple)
    errors: tuple[RunError, ...] = field(default_factory=tuple)
    evidence: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "sourceTransport": self.source_transport,
            "targetTransport": self.target_transport,
            "protocolVersion": self.protocol_version,
            "negotiatedVersion": self.negotiated_version,
            "sourceEventCount": self.source_event_count,
            "plannedActions": self.planned_actions,
            "sentActions": self.sent_actions,
            "receivedMessages": self.received_messages,
            "completed": self.completed,
            "matchesSource": self.matches_source,
            "credentialsReused": self.credentials_reused,
            "redactionsApplied": self.redactions_applied,
            "activeTools": list(self.active_tools),
            "opaqueWireEventCount": self.opaque_wire_event_count,
            "evidence": list(self.evidence),
            "findings": [finding.to_dict() for finding in self.findings],
        }


def load_replay_plan(
    path: str | Path, options: ReplayOptions | None = None
) -> ReplayPlan:
    """Load and validate a v1 NDJSON transcript without opening a target."""

    replay_options = options or ReplayOptions()
    events = load_transcript(path)
    if len(events) > replay_options.max_events:
        raise ConfigurationError(
            f"Transcript has {len(events)} events; replay limit is "
            f"{replay_options.max_events}."
        )
    _validate_event_sequence(events)

    actions = [event for event in events if _is_client_action(event)]
    if not actions:
        raise ConfigurationError("Transcript has no client-originated protocol actions to replay.")
    transports = {event.get("transport") for event in actions}
    if len(transports) != 1:
        raise ConfigurationError(
            "A replay transcript must use exactly one transport for client actions."
        )
    source_transport = next(iter(transports))
    if source_transport not in _TRANSPORTS:
        raise ConfigurationError(
            f"Unsupported replay source transport: {source_transport!r}."
        )
    _validate_replay_events(events, source_transport)
    active_tools, opaque_count = _validate_active_tool_actions(
        actions,
        replay_options.allow_tools,
        allow_opaque_wire=replay_options.allow_opaque_wire,
    )
    protocol_version = replay_options.protocol_version or _infer_protocol_version(actions)
    return ReplayPlan(
        source=str(Path(path)),
        source_transport=source_transport,
        protocol_version=protocol_version,
        events=tuple(events),
        client_event_count=len(actions),
        active_tools=active_tools,
        opaque_wire_event_count=opaque_count,
    )


def replay_transcript(
    path: str | Path,
    transport: StdioTransport | HttpTransport,
    recorder: EventRecorder,
    options: ReplayOptions | None = None,
) -> ReplayResult:
    """Load then replay one transcript against an already configured target.

    The caller owns transport cleanup.  Stdio is started here if necessary.
    Runtime connection/write failures continue to use the transport exceptions;
    a target message which differs from the captured interaction is represented
    as a deterministic ``FAIL`` finding instead.
    """

    replay_options = options or ReplayOptions()
    if recorder.path is not None:
        ensure_distinct_transcript_paths(path, recorder.path)
    plan = load_replay_plan(path, replay_options)
    return replay_plan(plan, transport, recorder, replay_options)


def replay_plan(
    plan: ReplayPlan,
    transport: StdioTransport | HttpTransport,
    recorder: EventRecorder,
    options: ReplayOptions | None = None,
) -> ReplayResult:
    """Execute a preloaded replay plan without adding lifecycle actions."""

    replay_options = options or ReplayOptions(protocol_version=plan.protocol_version)
    if recorder.path is not None:
        ensure_distinct_transcript_paths(plan.source, recorder.path)
    target_name = _target_transport_name(transport)
    if plan.source_transport != target_name:
        raise ConfigurationError(
            f"Transcript transport is {plan.source_transport!r}, but target transport "
            f"is {target_name!r}. Cross-transport replay is intentionally unsupported."
        )
    if (
        replay_options.protocol_version is not None
        and plan.protocol_version is not None
        and replay_options.protocol_version != plan.protocol_version
    ):
        raise ConfigurationError(
            "Replay options protocol version differs from the loaded replay plan."
        )
    runtime_active_tools, runtime_opaque_count = _validate_active_tool_actions(
        [event for event in plan.events if _is_client_action(event)],
        replay_options.allow_tools,
        allow_opaque_wire=replay_options.allow_opaque_wire,
    )
    if runtime_active_tools != plan.active_tools:
        raise ConfigurationError(
            "Replay plan active-tool metadata does not match its client actions."
        )
    if runtime_opaque_count != plan.opaque_wire_event_count:
        raise ConfigurationError(
            "Replay plan opaque-wire metadata does not match its client actions."
        )
    if isinstance(transport, HttpTransport):
        selected = replay_options.protocol_version or plan.protocol_version
        if selected is not None and selected != transport.profile.version:
            raise ConfigurationError(
                f"Replay protocol version {selected!r} does not match the HTTP "
                f"target profile {transport.profile.version!r}."
            )
    elif transport.process is not None:
        raise ConfigurationError(
            "Stdio replay requires a fresh, unstarted target transport so no "
            "automatic or earlier protocol traffic can contaminate the interaction."
        )

    # A transport may have been prepared through McpSession, which installs an
    # automatic server-request handler.  Replay must never let that handler add
    # a response absent from the captured client event stream.
    previous_handler = transport.server_request_handler
    transport.server_request_handler = None
    try:
        if isinstance(transport, StdioTransport):
            selected = replay_options.protocol_version or plan.protocol_version
            if selected is not None:
                # Stdio batch decoding is profile-sensitive (2025-03 receives
                # batches; 2025-06 and later reject them).  A fresh replay must
                # configure that era before the reader thread starts.
                transport.profile = profile_for(selected)
            transport.start()
            state = _replay_stdio(plan, transport, recorder, replay_options)
        else:
            state = _replay_http(plan, transport, recorder, replay_options)
    finally:
        transport.server_request_handler = previous_handler

    if plan.opaque_wire_event_count:
        state.findings.append(
            Finding(
                code="SAFETY_OPAQUE_WIRE_OPT_IN",
                status="PASS",
                category="safety",
                basis="operational",
                summary="Opaque transcript wire events were explicitly allowed for replay.",
                details=(
                    f"{plan.opaque_wire_event_count} raw event(s) could not be reduced "
                    "to strict JSON for active-tool inspection."
                ),
                evidence=tuple(EvidenceRef(item) for item in state.evidence),
                active=True,
            )
        )

    comparison_failures = any(finding.status == "FAIL" for finding in state.findings)
    matches = state.completed and not comparison_failures
    final_evidence = recorder.record(
        "probe",
        target_name,
        classification="replay_complete",
        sourceTransport=plan.source_transport,
        plannedActions=plan.client_event_count,
        sentActions=state.sent_actions,
        receivedMessages=state.received_messages,
        completed=state.completed,
        matchesSource=matches,
        credentialsReused=False,
        redactionsApplied=state.redactions_applied,
    )
    state.evidence.append(final_evidence)
    state.findings.append(
        Finding(
            code="REPLAY_COMPLETE",
            status="PASS" if matches else "FAIL",
            category="replay",
            basis="operational",
            summary=(
                "Replay completed and matched the captured protocol structure."
                if matches
                else "Replay did not match the captured protocol structure."
            ),
            details=(
                None
                if matches
                else (
                    f"Sent {state.sent_actions} of {plan.client_event_count} actions; "
                    f"completed={state.completed}."
                )
            ),
            expected={
                "sentActions": plan.client_event_count,
                "completed": True,
                "responseComparisons": "all match",
            },
            actual={
                "sentActions": state.sent_actions,
                "completed": state.completed,
                "responseComparisons": "mismatch" if comparison_failures else "all match",
            },
            evidence=(EvidenceRef(final_evidence),),
        )
    )
    return ReplayResult(
        source_transport=plan.source_transport,
        target_transport=target_name,
        protocol_version=replay_options.protocol_version or plan.protocol_version,
        negotiated_version=_replayed_negotiated_version(
            plan,
            recorder,
            (
                transport.protocol_version
                if isinstance(transport, HttpTransport)
                else replay_options.protocol_version or plan.protocol_version
            ),
        ),
        source_event_count=len(plan.events),
        planned_actions=plan.client_event_count,
        sent_actions=state.sent_actions,
        received_messages=state.received_messages,
        completed=state.completed,
        matches_source=matches,
        credentials_reused=False,
        redactions_applied=state.redactions_applied,
        active_tools=runtime_active_tools,
        opaque_wire_event_count=runtime_opaque_count,
        findings=tuple(state.findings),
        evidence=tuple(state.evidence),
    )


@dataclass
class _ReplayState:
    findings: list[Finding] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    sent_actions: int = 0
    received_messages: int = 0
    completed: bool = True
    redactions_applied: bool = False
    last_client_elapsed_ms: float | None = None
    total_delay_seconds: float = 0.0


def _replay_stdio(
    plan: ReplayPlan,
    transport: StdioTransport,
    recorder: EventRecorder,
    options: ReplayOptions,
) -> _ReplayState:
    state = _ReplayState()
    for event in plan.events:
        if _is_client_action(event):
            _apply_timing(event, state, options)
            evidence, redacted = _send_stdio_action(
                event, transport, options.timeout
            )
            state.sent_actions += 1
            state.redactions_applied = state.redactions_applied or redacted
            state.evidence.append(evidence)
            state.findings.append(_event_finding(event, evidence))
            continue
        if not _is_server_checkpoint(event, "stdio"):
            continue
        try:
            actual = transport.receive(options.timeout)
        except (ProbeTimeout, ProcessExited) as exc:
            evidence = recorder.record(
                "probe",
                "stdio",
                classification="replay_receive_failure",
                error=str(exc),
                sourceSeq=event["seq"],
            )
            state.evidence.append(evidence)
            state.findings.append(
                _response_finding(event, None, evidence, extra_difference=str(exc))
            )
            state.completed = False
            break
        state.received_messages += 1
        state.evidence.append(actual.evidence)
        state.findings.append(_response_finding(event, actual, actual.evidence))
    return state


def _replay_http(
    plan: ReplayPlan,
    transport: HttpTransport,
    recorder: EventRecorder,
    options: ReplayOptions,
) -> _ReplayState:
    del recorder  # the transport owns all HTTP evidence generation
    state = _ReplayState()
    windows = _http_action_windows(plan.events)
    for action, window in windows:
        _apply_timing(action, state, options)
        classification = action.get("classification")
        if classification == "session_terminate":
            event_count_before = len(transport.recorder.events)
            status = transport.terminate_session(options.timeout)
            action_sent = len(transport.recorder.events) > event_count_before
            if action_sent:
                evidence = transport.recorder.last_reference()
                assert evidence is not None
                state.sent_actions += 1
                state.findings.append(_event_finding(action, evidence))
            else:
                evidence = transport.recorder.record(
                    "probe",
                    "http",
                    classification="replay_action_unavailable",
                    error="target has no active HTTP session to terminate",
                    sourceSeq=action["seq"],
                )
                state.completed = False
                state.findings.append(
                    Finding(
                        code="REPLAY_EVENT",
                        status="FAIL",
                        category="replay",
                        basis="operational",
                        summary=f"Could not replay source event {action['seq']}.",
                        details="The target has no fresh HTTP session to terminate.",
                        expected={"classification": "session_terminate"},
                        actual=None,
                        evidence=(EvidenceRef(evidence),),
                    )
                )
            state.evidence.append(evidence)
            expected_status = _expected_http_status(window)
            if expected_status is not None or status is not None:
                state.findings.append(
                    _http_status_finding(action, expected_status, status, evidence)
                )
            continue

        exchange, evidence, redacted = _send_http_action(action, transport, options.timeout)
        state.sent_actions += 1
        state.redactions_applied = state.redactions_applied or redacted
        state.evidence.append(evidence)
        state.findings.append(_event_finding(action, evidence))
        expected_messages = [
            event for event in window if _is_server_checkpoint(event, "http")
        ]
        actual_messages = _recorded_http_messages(transport.recorder, evidence)
        state.received_messages += len(actual_messages)
        expected_status = _expected_http_status(window)
        status_evidence = (
            actual_messages[0].evidence if actual_messages else transport.recorder.last_reference()
        )
        assert status_evidence is not None
        if expected_status is not None:
            state.findings.append(
                _http_status_finding(action, expected_status, exchange.status, status_evidence)
            )
        count = max(len(expected_messages), len(actual_messages))
        for index in range(count):
            expected = expected_messages[index] if index < len(expected_messages) else None
            actual = actual_messages[index] if index < len(actual_messages) else None
            actual_evidence = actual.evidence if actual is not None else status_evidence
            state.evidence.append(actual_evidence)
            if expected is None:
                state.findings.append(
                    _unexpected_response_finding(actual, actual_evidence, action["seq"])
                )
            else:
                state.findings.append(
                    _response_finding(expected, actual, actual_evidence)
                )
    return state


def _send_stdio_action(
    event: Mapping[str, Any], transport: StdioTransport, timeout: float
) -> tuple[str, bool]:
    classification = event.get("classification")
    if classification == "session_terminate":
        raise ConfigurationError("session_terminate is not a valid stdio replay action.")
    if classification == "raw_wire":
        raw, redacted = _safe_raw_wire(event, transport.recorder)
        append_newline = event.get("appendNewline", True)
        if not isinstance(append_newline, bool):
            raise ConfigurationError(
                f"Raw stdio replay event {event.get('seq')} appendNewline must be boolean."
            )
        return (
            _stdio_send_wire(
                transport,
                raw,
                append_newline=append_newline,
                timeout=timeout,
            ),
            redacted,
        )
    payload, redacted = _safe_payload(event, transport.recorder)
    return _stdio_send_message(transport, payload, timeout), redacted


def _stdio_send_message(
    transport: StdioTransport, payload: Any, timeout: float
) -> str:
    return transport.send_message(payload, timeout=timeout)


def _stdio_send_wire(
    transport: StdioTransport,
    data: str | bytes,
    *,
    append_newline: bool,
    timeout: float,
) -> str:
    return transport.send_wire(
        data,
        append_newline=append_newline,
        timeout=timeout,
    )


def _send_http_action(
    event: Mapping[str, Any], transport: HttpTransport, timeout: float
) -> tuple[HttpExchange, str, bool]:
    classification = event.get("classification")
    outbound_payload: Any = None
    if classification == "raw_wire":
        raw, redacted = _safe_raw_wire(event, transport.recorder)
        try:
            outbound_payload = strict_json_loads(raw)
        except (json.JSONDecodeError, ValueError):
            outbound_payload = None
        derived_headers = None
        if transport.profile.modern and isinstance(outbound_payload, dict):
            derived_headers = modern_http_headers(
                outbound_payload, transport.protocol_version
            )
        exchange = transport.send_wire(
            raw,
            timeout,
            content_type=_source_content_type(event),
            headers=derived_headers,
        )
    else:
        payload, redacted = _safe_payload(event, transport.recorder)
        outbound_payload = payload
        exchange = transport.send_message(payload, timeout)
    _update_http_lifecycle(transport, outbound_payload, exchange)
    evidence = _client_evidence_for_exchange(transport.recorder, exchange)
    return exchange, evidence, redacted


def _update_http_lifecycle(
    transport: HttpTransport, outbound: Any, exchange: HttpExchange
) -> None:
    """Apply fresh initialize/session state without consulting source headers."""

    if not isinstance(outbound, dict) or outbound.get("method") != "initialize":
        return
    request_id = outbound.get("id")
    matching: InboundMessage | None = None
    for inbound in exchange.messages:
        if inbound.classification != "response" or not isinstance(inbound.payload, dict):
            continue
        candidate = inbound.payload.get("id")
        if type(candidate) is type(request_id) and candidate == request_id:
            matching = inbound
            break
    if matching is None or not isinstance(matching.payload.get("result"), dict):
        return
    selected = matching.payload["result"].get("protocolVersion")
    if not isinstance(selected, str):
        raise TransportError("Initialize response omitted a string protocolVersion.")
    try:
        selected_profile = profile_for(selected)
    except ConfigurationError as exc:
        raise TransportError(
            f"Initialize response selected unsupported protocol version {selected!r}."
        ) from exc
    if selected_profile.modern or not selected_profile.streamable_http:
        raise TransportError(
            f"Initialize response selected protocol version {selected!r}, which is not "
            "compatible with replay's legacy Streamable HTTP lifecycle."
        )
    transport.profile = selected_profile
    transport.protocol_version = selected
    if transport.profile.http_sessions and not transport.session_id:
        fresh_session = header_value(exchange.headers, "MCP-Session-Id")
        if fresh_session:
            transport.accept_session_id(
                fresh_session, source_evidence=matching.evidence
            )
    transport.initialized = True


def _client_evidence_for_exchange(
    recorder: EventRecorder, exchange: HttpExchange
) -> str:
    # The outgoing event precedes the response and is the nearest earlier
    # client_to_server record.  Scan backwards instead of trusting event counts.
    del exchange
    for event in reversed(recorder.events):
        if event.get("direction") == "client_to_server" and event.get("transport") == "http":
            return f"event:{event['seq']}"
    raise ConfigurationError("HTTP replay action produced no outgoing evidence event.")


def _recorded_http_messages(
    recorder: EventRecorder, client_evidence: str
) -> list[InboundMessage]:
    """Include invalid HTTP bodies which HttpExchange cannot decode as messages."""

    try:
        client_sequence = int(client_evidence.split(":", 1)[1])
    except (IndexError, ValueError) as exc:
        raise ConfigurationError("HTTP replay produced an invalid evidence reference.") from exc
    observed: list[InboundMessage] = []
    for event in recorder.events:
        if event.get("seq", 0) <= client_sequence:
            continue
        if event.get("direction") != "server_to_client" or event.get("transport") != "http":
            continue
        classification = event.get("classification")
        if classification not in _INBOUND_CLASSES:
            continue
        headers = event.get("headers")
        observed.append(
            InboundMessage(
                payload=event.get("payload"),
                raw=str(event.get("raw") or ""),
                classification=str(classification),
                evidence=f"event:{event['seq']}",
                http_status=(
                    event.get("httpStatus")
                    if isinstance(event.get("httpStatus"), int)
                    else None
                ),
                headers=(
                    {str(key): str(value) for key, value in headers.items()}
                    if isinstance(headers, Mapping)
                    else {}
                ),
                sse_event=(
                    str(event["sseEvent"]) if event.get("sseEvent") is not None else None
                ),
                sse_id=str(event["sseId"]) if event.get("sseId") is not None else None,
            )
        )
    return observed


def _safe_payload(
    event: Mapping[str, Any], recorder: EventRecorder
) -> tuple[Any, bool]:
    if "payload" not in event:
        raise ConfigurationError(
            f"Transcript event {event.get('seq')} has no payload to replay."
        )
    source = event["payload"]
    safe = recorder.redact_value(source)
    # Loading JSON already guarantees serializable types, but explicitly
    # validate to keep ReplayPlan callers honest.
    try:
        compact_json(safe)
    except (TypeError, ValueError) as exc:
        raise ConfigurationError(
            f"Transcript event {event.get('seq')} payload is not JSON serializable."
        ) from exc
    return safe, safe != source or contains_redaction(safe)


def _safe_raw_wire(
    event: Mapping[str, Any], recorder: EventRecorder
) -> tuple[str, bool]:
    raw = event.get("raw")
    if not isinstance(raw, str):
        raise ConfigurationError(
            f"Raw replay event {event.get('seq')} requires a string raw field."
        )
    safe = recorder.redact_raw(raw)
    return safe, safe != raw or REDACTED in safe


def _source_content_type(event: Mapping[str, Any]) -> str:
    """Copy only the safe media type, never arbitrary captured headers."""

    candidate = event.get("contentType")
    if candidate is None:
        headers = event.get("headers")
        if isinstance(headers, Mapping):
            for key, value in headers.items():
                if str(key).lower() == "content-type":
                    candidate = value
                    break
    if candidate is None:
        return "application/json"
    if not isinstance(candidate, str):
        raise ConfigurationError(
            f"Raw HTTP replay event {event.get('seq')} Content-Type must be a string."
        )
    # Header parameters may contain opaque user material.  The MCP transport
    # behavior depends on the media type, so preserve that token and rebuild
    # the remainder instead of forwarding captured parameter values.
    media_type = candidate.split(";", 1)[0].strip()
    if not re.fullmatch(r"[A-Za-z0-9!#$&^_.+-]+/[A-Za-z0-9!#$&^_.+-]+", media_type):
        raise ConfigurationError(
            f"Raw HTTP replay event {event.get('seq')} has an unsafe Content-Type."
        )
    return media_type


def _event_finding(event: Mapping[str, Any], evidence: str) -> Finding:
    payload = event.get("payload")
    if payload is None and event.get("classification") == "raw_wire":
        raw = event.get("raw")
        if isinstance(raw, str):
            try:
                payload = strict_json_loads(raw)
            except (json.JSONDecodeError, ValueError):
                payload = None
    active = bool(_find_tool_call_objects(payload))
    return Finding(
        code="REPLAY_EVENT",
        status="PASS",
        category="replay",
        basis="operational",
        summary=f"Replayed source event {event['seq']}.",
        actual=_event_signature(event),
        evidence=(EvidenceRef(evidence),),
        active=active,
    )


def _response_finding(
    expected: Mapping[str, Any],
    actual: InboundMessage | None,
    evidence: str,
    *,
    extra_difference: str | None = None,
) -> Finding:
    expected_signature = _event_signature(expected)
    actual_signature = _message_signature(actual) if actual is not None else None
    differences = _signature_differences(expected_signature, actual_signature)
    if extra_difference:
        differences.append(extra_difference)
    matched = not differences
    return Finding(
        code="REPLAY_RESPONSE_MATCH",
        status="PASS" if matched else "FAIL",
        category="replay",
        basis="operational",
        summary=(
            f"Target message matched source event {expected['seq']}."
            if matched
            else f"Target message differed from source event {expected['seq']}."
        ),
        details="; ".join(differences) if differences else None,
        expected=expected_signature,
        actual=actual_signature,
        evidence=(EvidenceRef(evidence),),
    )


def _unexpected_response_finding(
    actual: InboundMessage | None, evidence: str, action_seq: Any
) -> Finding:
    return Finding(
        code="REPLAY_RESPONSE_MATCH",
        status="FAIL",
        category="replay",
        basis="operational",
        summary=f"Target emitted an extra message after source event {action_seq}.",
        details="The captured HTTP exchange contained fewer protocol messages.",
        expected=None,
        actual=_message_signature(actual) if actual is not None else None,
        evidence=(EvidenceRef(evidence),),
    )


def _http_status_finding(
    action: Mapping[str, Any], expected: int | None, actual: int | None, evidence: str
) -> Finding:
    matched = expected == actual
    return Finding(
        code="REPLAY_RESPONSE_MATCH",
        status="PASS" if matched else "FAIL",
        category="replay",
        basis="operational",
        summary=(
            f"HTTP status matched after source event {action['seq']}."
            if matched
            else f"HTTP status differed after source event {action['seq']}."
        ),
        details=None if matched else f"Expected HTTP {expected}, received HTTP {actual}.",
        expected={"httpStatus": expected},
        actual={"httpStatus": actual},
        evidence=(EvidenceRef(evidence),),
    )


def _event_signature(event: Mapping[str, Any]) -> dict[str, Any]:
    payload = event.get("payload")
    signature: dict[str, Any] = {"classification": event.get("classification")}
    if isinstance(payload, dict):
        if "id" in payload:
            signature["id"] = payload.get("id")
            signature["idType"] = _json_id_type(payload.get("id"))
        method = message_method(payload)
        if method is not None:
            signature["method"] = method
        response_kind = _response_kind(payload)
        if response_kind is not None:
            signature["responseKind"] = response_kind
        error_code = _error_code(payload)
        if error_code is not None:
            signature["errorCode"] = error_code
    return signature


def _message_signature(message: InboundMessage | None) -> dict[str, Any] | None:
    if message is None:
        return None
    payload = message.payload
    signature: dict[str, Any] = {"classification": message.classification}
    if isinstance(payload, dict):
        if "id" in payload:
            signature["id"] = payload.get("id")
            signature["idType"] = _json_id_type(payload.get("id"))
        method = message_method(payload)
        if method is not None:
            signature["method"] = method
        response_kind = _response_kind(payload)
        if response_kind is not None:
            signature["responseKind"] = response_kind
        error_code = _error_code(payload)
        if error_code is not None:
            signature["errorCode"] = error_code
    return signature


def _signature_differences(
    expected: Mapping[str, Any], actual: Mapping[str, Any] | None
) -> list[str]:
    if actual is None:
        return ["target emitted no corresponding protocol message"]
    differences: list[str] = []
    for key in ("classification", "id", "idType", "method", "responseKind", "errorCode"):
        if expected.get(key) != actual.get(key):
            differences.append(
                f"{key} expected {expected.get(key)!r}, received {actual.get(key)!r}"
            )
    return differences


def _response_kind(payload: Mapping[str, Any]) -> str | None:
    has_result = "result" in payload
    has_error = "error" in payload
    if has_result and not has_error:
        return "result"
    if has_error and not has_result:
        return "error"
    if has_result and has_error:
        return "result_and_error"
    return None


def _error_code(payload: Mapping[str, Any]) -> Any:
    error = payload.get("error")
    return error.get("code") if isinstance(error, dict) else None


def _json_id_type(value: Any) -> str:
    if value is None:
        return "null"
    if type(value) is int:
        return "integer"
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool):
        return "boolean"
    return type(value).__name__


def _apply_timing(
    event: Mapping[str, Any], state: _ReplayState, options: ReplayOptions
) -> None:
    elapsed = event.get("elapsedMs")
    current = (
        float(elapsed)
        if isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool)
        else None
    )
    if not options.preserve_timing:
        state.last_client_elapsed_ms = current
        return
    if current is None:
        raise ConfigurationError(
            f"Transcript event {event.get('seq')} needs numeric elapsedMs for timed replay."
        )
    if current < 0:
        raise ConfigurationError(
            f"Transcript event {event.get('seq')} has negative elapsedMs."
        )
    previous = state.last_client_elapsed_ms
    state.last_client_elapsed_ms = current
    if previous is None:
        return
    if current < previous:
        raise ConfigurationError(
            f"Transcript event {event.get('seq')} has elapsedMs earlier than the "
            "previous client action."
        )
    source_delay = max(0.0, (current - previous) / 1000.0) * options.timing_scale
    remaining_total = max(
        0.0, options.max_total_delay_seconds - state.total_delay_seconds
    )
    delay = min(source_delay, options.max_delay_seconds, remaining_total)
    if delay > 0:
        time.sleep(delay)
        state.total_delay_seconds += delay


def _http_action_windows(
    events: Sequence[Mapping[str, Any]],
) -> list[tuple[Mapping[str, Any], tuple[Mapping[str, Any], ...]]]:
    windows: list[tuple[Mapping[str, Any], tuple[Mapping[str, Any], ...]]] = []
    action: Mapping[str, Any] | None = None
    following: list[Mapping[str, Any]] = []
    for event in events:
        if _is_client_action(event):
            if action is not None:
                windows.append((action, tuple(following)))
            action = event
            following = []
        elif action is not None:
            following.append(event)
    if action is not None:
        windows.append((action, tuple(following)))
    return windows


def _expected_http_status(events: Sequence[Mapping[str, Any]]) -> int | None:
    for event in events:
        status = event.get("httpStatus")
        if isinstance(status, int) and not isinstance(status, bool):
            return status
    return None


def _is_client_action(event: Mapping[str, Any]) -> bool:
    return (
        event.get("direction") in _CLIENT_DIRECTIONS
        and event.get("classification") in _CLIENT_ACTION_CLASSES
    )


def _is_server_checkpoint(event: Mapping[str, Any], transport: str) -> bool:
    return (
        event.get("direction") in _SERVER_DIRECTIONS
        and event.get("transport") == transport
        and event.get("classification") in _INBOUND_CLASSES
    )


def _validate_event_sequence(events: Sequence[Mapping[str, Any]]) -> None:
    previous = 0
    for line_number, event in enumerate(events, start=1):
        sequence = event.get("seq")
        if not isinstance(sequence, int) or isinstance(sequence, bool):
            raise ConfigurationError(
                f"Transcript event on logical line {line_number} has no integer seq."
            )
        if sequence <= previous:
            raise ConfigurationError(
                "Transcript event seq values must be strictly increasing."
            )
        previous = sequence


def _validate_replay_events(
    events: Sequence[Mapping[str, Any]], source_transport: str
) -> None:
    saw_client_action = False
    for event in events:
        direction = event.get("direction")
        classification = event.get("classification")
        if direction not in _CLIENT_DIRECTIONS | _SERVER_DIRECTIONS:
            continue
        if classification not in _CLIENT_ACTION_CLASSES | _INBOUND_CLASSES:
            continue
        if event.get("transport") != source_transport:
            raise ConfigurationError(
                f"Transcript event {event.get('seq')} mixes transport "
                f"{event.get('transport')!r} into a {source_transport!r} replay."
            )
        if direction in _CLIENT_DIRECTIONS:
            saw_client_action = True
            if classification == "session_terminate":
                if source_transport != "http":
                    raise ConfigurationError(
                        "session_terminate can only be replayed over HTTP."
                    )
            elif classification == "batch":
                payload = event.get("payload")
                if not isinstance(payload, list) or not payload:
                    raise ConfigurationError(
                        f"Batch replay event {event.get('seq')} requires a non-empty "
                        "JSON array payload."
                    )
                if len(payload) > _MAX_REPLAY_BATCH_MESSAGES:
                    raise ConfigurationError(
                        f"Batch replay event {event.get('seq')} has {len(payload)} "
                        f"items; replay limit is {_MAX_REPLAY_BATCH_MESSAGES}."
                    )
                if any(not isinstance(item, dict) for item in payload):
                    raise ConfigurationError(
                        f"Batch replay event {event.get('seq')} must contain only "
                        "JSON-RPC object members."
                    )
            elif classification == "raw_wire":
                if not isinstance(event.get("raw"), str):
                    raise ConfigurationError(
                        f"Raw replay event {event.get('seq')} requires a string raw field."
                    )
                if event.get("exactBytesRecorded") is False:
                    raise ConfigurationError(
                        f"Raw {source_transport} replay event {event.get('seq')} did not "
                        "capture exact bytes and cannot be replayed faithfully."
                    )
                if source_transport == "stdio":
                    append_newline = event.get("appendNewline", True)
                    if not isinstance(append_newline, bool):
                        raise ConfigurationError(
                            f"Raw stdio replay event {event.get('seq')} appendNewline "
                            "must be boolean."
                        )
                elif source_transport == "http":
                    _source_content_type(event)
            elif "payload" not in event:
                raise ConfigurationError(
                    f"Replay event {event.get('seq')} requires a payload."
                )
            elif classify_message(event.get("payload")) != classification:
                raise ConfigurationError(
                    f"Replay event {event.get('seq')} classification does not match "
                    "its decoded JSON-RPC payload."
                )
        elif (
            source_transport == "http"
            and classification in _INBOUND_CLASSES
            and not saw_client_action
        ):
            raise ConfigurationError(
                f"HTTP transcript event {event.get('seq')} has no preceding client action."
            )


def _validate_active_tool_actions(
    actions: Sequence[Mapping[str, Any]],
    allow_tools: Sequence[str],
    *,
    allow_opaque_wire: bool,
) -> tuple[tuple[str, ...], int]:
    """Require exact opt-in for every captured active tool invocation."""

    allowed = set(allow_tools)
    active: list[str] = []
    opaque_count = 0
    for event in actions:
        payload: Any
        if event.get("classification") == "raw_wire":
            raw = event.get("raw")
            assert isinstance(raw, str)  # validated by _validate_replay_events
            try:
                payload = strict_json_loads(raw)
            except (json.JSONDecodeError, ValueError):
                # An invalid raw object cannot execute as JSON-RPC, but block a
                # recognizable tools/call token anyway: malformed-wire replay
                # must never become an accidental active call after server-side
                # recovery or normalization.
                if _raw_resembles_tools_call(raw):
                    raise ConfigurationError(
                        f"Raw transcript event {event.get('seq')} resembles tools/call "
                        "but is not valid JSON, so an exact tool allow-list cannot be verified."
                    )
                if not allow_opaque_wire:
                    raise ConfigurationError(
                        f"Raw transcript event {event.get('seq')} is not strict JSON, so "
                        "MCP Probe cannot prove it is free of an active tools/call. Pass "
                        "--allow-opaque-wire only after reviewing the exact event and target."
                    )
                opaque_count += 1
                continue
        else:
            payload = event.get("payload")
        calls = _find_tool_call_objects(payload)
        for call in calls:
            params = call.get("params")
            name = params.get("name") if isinstance(params, Mapping) else None
            if not isinstance(name, str) or not name:
                raise ConfigurationError(
                    f"Transcript event {event.get('seq')} calls a tool without an exact "
                    "string name; replay cannot authorize it safely."
                )
            if name not in allowed:
                raise ConfigurationError(
                    f"Replay would actively call tool {name!r} from transcript event "
                    f"{event.get('seq')}. Explicitly allow that exact tool name to proceed."
                )
            if name not in active:
                active.append(name)
    return tuple(active), opaque_count


def _resembles_tools_call_method(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() == "tools/call"


def _find_tool_call_objects(value: Any) -> list[Mapping[str, Any]]:
    """Conservatively find active-tool-like objects, including nested batches."""

    found: list[Mapping[str, Any]] = []
    stack = [value]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            if _resembles_tools_call_method(current.get("method")):
                found.append(current)
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return found


_JSON_STRING_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"')


def _raw_resembles_tools_call(text: str) -> bool:
    """Recognize escaped/case/whitespace variants in malformed raw input."""

    tokens: list[tuple[int, int, str]] = []
    for match in _JSON_STRING_TOKEN.finditer(text):
        try:
            decoded = json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(decoded, str):
            tokens.append((match.start(), match.end(), decoded))
    for index, (_start, end, key) in enumerate(tokens):
        if key.strip().casefold() != "method":
            continue
        for value_start, _value_end, candidate in tokens[index + 1 :]:
            if ":" not in text[end:value_start]:
                continue
            if _resembles_tools_call_method(candidate):
                return True
            break
    return bool(
        re.search(
            r"(?is)['\"]\s*method\s*['\"]\s*:\s*['\"]\s*tools/call\s*['\"]",
            text,
        )
    )


def _infer_protocol_version(events: Sequence[Mapping[str, Any]]) -> str | None:
    for event in events:
        payload = event.get("payload")
        if payload is None and event.get("classification") == "raw_wire":
            raw = event.get("raw")
            if isinstance(raw, str):
                try:
                    payload = strict_json_loads(raw)
                except (json.JSONDecodeError, ValueError):
                    payload = None
        messages = payload if isinstance(payload, list) else [payload]
        for message in messages:
            if not isinstance(message, dict):
                continue
            params = message.get("params")
            if not isinstance(params, dict):
                continue
            if message.get("method") == "initialize":
                version = params.get("protocolVersion")
                if isinstance(version, str):
                    return version
            meta = params.get("_meta")
            if isinstance(meta, dict):
                version = meta.get("io.modelcontextprotocol/protocolVersion")
                if isinstance(version, str):
                    return version
    return None


def _replayed_negotiated_version(
    plan: ReplayPlan, recorder: EventRecorder, fallback: str | None
) -> str | None:
    initialize_id: Any = None
    found_initialize = False
    for event in plan.events:
        if not _is_client_action(event):
            continue
        payload = event.get("payload")
        if payload is None and event.get("classification") == "raw_wire":
            raw = event.get("raw")
            if isinstance(raw, str):
                try:
                    payload = strict_json_loads(raw)
                except (json.JSONDecodeError, ValueError):
                    payload = None
        if isinstance(payload, dict) and payload.get("method") == "initialize":
            initialize_id = payload.get("id")
            found_initialize = True
            break
    if not found_initialize:
        return fallback
    for event in recorder.events:
        if event.get("direction") != "server_to_client":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict):
            continue
        if (
            type(payload.get("id")) is not type(initialize_id)
            or payload.get("id") != initialize_id
        ):
            continue
        result = payload.get("result")
        version = result.get("protocolVersion") if isinstance(result, dict) else None
        if isinstance(version, str):
            return version
    return fallback


def _target_transport_name(transport: StdioTransport | HttpTransport) -> str:
    if isinstance(transport, StdioTransport):
        return "stdio"
    if isinstance(transport, HttpTransport):
        return "http"
    raise ConfigurationError(
        "Replay target must be a StdioTransport or HttpTransport instance."
    )


def ensure_distinct_transcript_paths(
    source: str | Path, destination: str | Path | None
) -> None:
    """Reject replay output which would overwrite its source transcript.

    CLI callers must invoke this *before* constructing the destination
    :class:`EventRecorder`, because its path is opened in truncate mode.
    ``replay_plan`` repeats the check as a defense in depth for API callers.
    """

    if destination is None:
        return
    source_path = Path(source).expanduser().resolve()
    destination_path = Path(destination).expanduser().resolve()
    if source_path == destination_path:
        raise ConfigurationError(
            "Replay source and destination transcript paths must be different; "
            "refusing to overwrite the captured interaction."
        )


__all__ = [
    "ReplayOptions",
    "ReplayPlan",
    "ReplayResult",
    "ensure_distinct_transcript_paths",
    "load_replay_plan",
    "replay_plan",
    "replay_transcript",
]
