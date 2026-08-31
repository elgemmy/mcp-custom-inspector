"""Small, deterministic JSON scenarios for protocol-level MCP experiments.

The scenario format is intentionally an action list, not a programming
language.  It has no variables, interpolation, branches, loops, imports, or
code execution.  A scenario can therefore be reviewed as the exact sequence
of protocol operations that MCP Probe will perform.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .errors import ConfigurationError, ProbeTimeout, ProcessExited, TransportError
from .protocol import make_notification
from .redaction import redact_value
from .report import EvidenceRef, Finding, RunError
from .session import McpSession, PaginationResult, RpcOutcome
from .transports import HttpExchange, HttpTransport, InboundMessage, StdioTransport


SCENARIO_SCHEMA = "mcp-probe.scenario/v1"
DEFAULT_SCENARIO_TIMEOUT = 5.0
MAX_SCENARIO_BYTES = 1024 * 1024

ACTION_TYPES = (
    "start",
    "connect",
    "request",
    "notification",
    "exact",
    "malformed",
    "expect",
    "discover",
    "disconnect",
    "terminate",
)
EXPECTATION_TYPES = ("result", "error", "timeout", "serverRequest", "close")
ASSERTION_TYPES = ("null", "boolean", "integer", "number", "string", "object", "array")
DISCOVERY_PRIMITIVES = ("tools", "resources", "resourceTemplates", "prompts", "all")

_MISSING = object()
_HTTP_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class ScenarioDefinition:
    name: str
    actions: tuple[dict[str, Any], ...]
    timeout: float = DEFAULT_SCENARIO_TIMEOUT
    description: str | None = None
    schema: str = SCENARIO_SCHEMA


@dataclass(frozen=True)
class ScenarioRunResult:
    scenario: ScenarioDefinition
    findings: tuple[Finding, ...]
    errors: tuple[RunError, ...]
    completed_actions: int
    disconnected: bool
    duration_ms: float
    values: tuple[Any, ...] = field(default_factory=tuple)


def load_scenario(path: str | Path) -> ScenarioDefinition:
    """Read and strictly validate one UTF-8 JSON scenario file."""

    scenario_path = Path(path)
    try:
        size = scenario_path.stat().st_size
    except OSError as exc:
        raise ConfigurationError(f"Could not read scenario {scenario_path}: {exc}") from exc
    if size > MAX_SCENARIO_BYTES:
        raise ConfigurationError(
            f"Scenario exceeds the {MAX_SCENARIO_BYTES}-byte safety limit: {scenario_path}"
        )
    try:
        text = scenario_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ConfigurationError(f"Could not read scenario {scenario_path}: {exc}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise ConfigurationError(f"Invalid scenario JSON in {scenario_path}: {exc}") from exc
    return parse_scenario(value)


def parse_scenario(value: Any) -> ScenarioDefinition:
    """Validate an already decoded scenario and return a defensive copy."""

    root = _require_object(value, "scenario")
    _only_keys(root, {"schema", "name", "description", "timeout", "actions"}, "scenario")
    if root.get("schema") != SCENARIO_SCHEMA:
        raise _invalid(
            f"scenario.schema must be {SCENARIO_SCHEMA!r}; got {root.get('schema')!r}."
        )
    name = root.get("name")
    if not isinstance(name, str) or not name.strip():
        raise _invalid("scenario.name must be a non-empty string.")
    description = root.get("description")
    if description is not None and not isinstance(description, str):
        raise _invalid("scenario.description must be a string or null.")
    timeout = _positive_number(root.get("timeout", DEFAULT_SCENARIO_TIMEOUT), "scenario.timeout")
    raw_actions = root.get("actions")
    if not isinstance(raw_actions, list) or not raw_actions:
        raise _invalid("scenario.actions must be a non-empty array.")

    actions: list[dict[str, Any]] = []
    seen_connect = False
    for index, raw_action in enumerate(raw_actions, start=1):
        action = _validate_action(raw_action, index)
        action_type = action["action"]
        if action_type in {"start", "connect"}:
            if seen_connect:
                raise _invalid("A scenario may contain at most one start/connect action.")
            if index != 1:
                raise _invalid("A start/connect action must be the first scenario action.")
            seen_connect = True
        if action_type in {"disconnect", "terminate"} and index != len(raw_actions):
            raise _invalid("A disconnect/terminate action must be the final scenario action.")
        if action_type == "expect" and index == 1:
            raise _invalid("An expect action must follow an observable protocol action.")
        actions.append(action)

    return ScenarioDefinition(
        name=name.strip(),
        description=description,
        timeout=timeout,
        actions=tuple(deepcopy(actions)),
    )


def run_scenario(
    session: McpSession,
    scenario: ScenarioDefinition,
    *,
    timeout: float | None = None,
    allow_tools: set[str] | frozenset[str] | tuple[str, ...] = (),
) -> ScenarioRunResult:
    """Execute a scenario, applying explicit active-tool authorization.

    Per-action timeouts take precedence over ``timeout``; the scenario's
    top-level timeout is the final fallback.
    """

    if not isinstance(scenario, ScenarioDefinition):
        raise ConfigurationError("run_scenario requires a validated ScenarioDefinition.")
    default_timeout = (
        _positive_number(timeout, "scenario CLI timeout")
        if timeout is not None
        else scenario.timeout
    )
    allowed = frozenset(allow_tools)
    if not all(isinstance(name, str) and name for name in allowed):
        raise ConfigurationError("Allowed tool names must be non-empty strings.")
    return ScenarioRunner(
        session,
        scenario,
        default_timeout=default_timeout,
        allow_tools=allowed,
    ).run()


class ScenarioRunner:
    """Execute validated actions synchronously against one MCP session."""

    def __init__(
        self,
        session: McpSession,
        scenario: ScenarioDefinition,
        *,
        default_timeout: float | None = None,
        allow_tools: frozenset[str] = frozenset(),
    ) -> None:
        self.session = session
        self.scenario = scenario
        self.default_timeout = default_timeout or scenario.timeout
        self.allow_tools = allow_tools
        self.findings: list[Finding] = []
        self.errors: list[RunError] = []
        self.values: list[Any] = []
        self.completed_actions = 0
        self.disconnected = False
        self.last_value: Any = None
        self.last_response: InboundMessage | None = None
        self.pending_http_responses: list[InboundMessage] = []
        self.last_exchange: HttpExchange | None = None
        self.last_fault: TransportError | None = None
        self.last_fault_evidence: str | None = None
        self.last_action: str | None = None
        self.awaiting_observation = False
        self.server_requests: list[InboundMessage] = []
        self.consumed_server_request_evidence: set[str] = set()

    def run(self) -> ScenarioRunResult:
        started = time.monotonic()
        try:
            # Connecting the transport is implicit.  An explicit start/connect
            # action remains useful when the scenario also wants an MCP-era
            # establishment exchange.
            self.session.start()
        except TransportError as exc:
            self._add_transport_error(exc, during_start=True)
            self._disconnect(implicit=True)
            return self._result(started)

        try:
            for index, action in enumerate(self.scenario.actions, start=1):
                if self.last_fault is not None and action["action"] != "expect":
                    self._add_transport_error(self.last_fault)
                    break
                self._execute(index, action)
                self.completed_actions = index
                if self.errors:
                    break
        except (ConfigurationError, ValueError, TypeError) as exc:
            self.errors.append(
                RunError(
                    code="CONFIG_INVALID_SCENARIO",
                    kind="configuration",
                    summary="Scenario execution configuration is invalid.",
                    details=str(exc),
                    evidence=_evidence(self.session.recorder.last_reference()),
                )
            )
        except TransportError as exc:
            self._add_transport_error(exc)
        except Exception as exc:  # pragma: no cover - defensive CLI boundary
            self.errors.append(
                RunError(
                    code="INTERNAL_UNEXPECTED",
                    kind="internal",
                    summary="Unexpected internal scenario runner error.",
                    details=f"{type(exc).__name__}: {exc}",
                    evidence=_evidence(self.session.recorder.last_reference()),
                )
            )
        finally:
            if self.last_fault is not None:
                self._add_transport_error(self.last_fault)
            if not self.disconnected:
                self._disconnect(implicit=True)
        return self._result(started)

    def _result(self, started: float) -> ScenarioRunResult:
        return ScenarioRunResult(
            scenario=self.scenario,
            findings=tuple(self.findings),
            errors=tuple(self.errors),
            completed_actions=self.completed_actions,
            disconnected=self.disconnected,
            duration_ms=round((time.monotonic() - started) * 1000, 3),
            values=tuple(deepcopy(self.values)),
        )

    def _execute(self, index: int, action: dict[str, Any]) -> None:
        action_type = action["action"]
        self.last_action = action_type
        if action_type in {"start", "connect"}:
            self._connect(index, action)
        elif action_type == "request":
            self._request(index, action)
        elif action_type == "notification":
            self._notification(index, action)
        elif action_type == "exact":
            self._exact(index, action)
        elif action_type == "malformed":
            self._malformed(index, action)
        elif action_type == "expect":
            self._expect(index, action)
        elif action_type == "discover":
            self._discover(index, action)
        elif action_type in {"disconnect", "terminate"}:
            self._disconnect(
                index=index, implicit=False, timeout=self._timeout(action)
            )
        else:  # validation makes this unreachable
            raise ConfigurationError(f"Unknown scenario action: {action_type}")

    def _connect(self, index: int, action: dict[str, Any]) -> None:
        evidence: tuple[EvidenceRef, ...] = ()
        if action["establish"]:
            try:
                outcome = self.session.establish(self._timeout(action))
            except TransportError as exc:
                self._capture_fault(exc)
            else:
                self.last_response = outcome.response
                self.last_exchange = outcome.http_exchange
                self.last_value = outcome.response.payload
                self._store_value(self.last_value)
                evidence = _evidence(*outcome.evidence)
        self._step_finding(
            index,
            "Connected to the target"
            + (" and ran MCP establishment" if action["establish"] else ""),
            evidence=evidence,
        )

    def _request(self, index: int, action: dict[str, Any]) -> None:
        self._clear_observation()
        if not self._authorize_tool_call(index, action["method"], action.get("params")):
            return
        try:
            outcome = self.session.rpc(
                action["method"], action.get("params"), self._timeout(action)
            )
        except TransportError as exc:
            self._capture_fault(exc)
            evidence = _evidence(self.last_fault_evidence)
        else:
            self._remember_rpc(outcome)
            evidence = _evidence(outcome.response.evidence)
        self._step_finding(
            index,
            f"Sent request {action['method']}",
            evidence=evidence,
            active=action["method"] == "tools/call",
        )

    def _notification(self, index: int, action: dict[str, Any]) -> None:
        self._clear_observation()
        if not self._authorize_tool_call(index, action["method"], action.get("params")):
            return
        message = make_notification(action["method"], action.get("params"))
        try:
            if isinstance(self.session.transport, HttpTransport):
                exchange = self.session.transport.send_message(
                    message, self._timeout(action)
                )
                self._remember_exchange(exchange)
                evidence_ref = (
                    exchange.messages[-1].evidence
                    if exchange.messages
                    else self.session.recorder.last_reference()
                )
            else:
                evidence_ref = self.session.send_notification(
                    message, self._timeout(action)
                )
                self.last_value = message
                self._store_value(message)
                self.awaiting_observation = action["wait"]
                if action["wait"]:
                    self._receive_stdio(self._timeout(action))
        except TransportError as exc:
            self._capture_fault(exc)
            evidence_ref = self.last_fault_evidence
        self._step_finding(
            index,
            f"Sent notification {action['method']}",
            evidence=_evidence(evidence_ref),
            active=action["method"] == "tools/call",
        )

    def _exact(self, index: int, action: dict[str, Any]) -> None:
        self._clear_observation()
        message = deepcopy(action["message"])
        method = message.get("method") if isinstance(message.get("method"), str) else None
        params = message.get("params") if isinstance(message.get("params"), dict) else None
        if not self._authorize_tool_call(index, method, params):
            return
        try:
            transport = self.session.transport
            if isinstance(transport, StdioTransport):
                evidence = transport.send_message(message)
                self.awaiting_observation = True
                if action["wait"]:
                    self._observe_response(self._timeout(action))
                    evidence = self._current_evidence() or evidence
            else:
                exchange = transport.send_message(message, self._timeout(action))
                self._remember_exchange(exchange)
                evidence = (
                    exchange.messages[-1].evidence
                    if exchange.messages
                    else self.session.recorder.last_reference()
                )
        except TransportError as exc:
            self._capture_fault(exc)
            evidence = self.last_fault_evidence
        self._step_finding(
            index,
            "Sent exact JSON-RPC object",
            evidence=_evidence(evidence),
            active=method == "tools/call",
        )

    def _malformed(self, index: int, action: dict[str, Any]) -> None:
        self._clear_observation()
        data: str | bytes
        if action["encoding"] == "base64":
            data = base64.b64decode(action["data"], validate=True)
        else:
            data = action["data"]
        if not self._authorize_raw_tool_call(index, data):
            return
        try:
            transport = self.session.transport
            if isinstance(transport, StdioTransport):
                evidence = transport.send_wire(data, append_newline=action["appendNewline"])
                if action["wait"]:
                    inbound = self._receive_stdio(self._timeout(action))
                    if inbound is not None:
                        evidence = inbound.evidence
                else:
                    self.awaiting_observation = True
            else:
                exchange = transport.send_wire(
                    data,
                    self._timeout(action),
                    content_type=action["contentType"],
                    headers=action["headers"],
                )
                self._remember_exchange(exchange)
                evidence = (
                    exchange.messages[-1].evidence
                    if exchange.messages
                    else self.session.recorder.last_reference()
                )
        except TransportError as exc:
            self._capture_fault(exc)
            evidence = self.last_fault_evidence
        self._step_finding(
            index,
            "Sent deliberately malformed wire input",
            evidence=_evidence(evidence),
        )

    def _expect(self, index: int, action: dict[str, Any]) -> None:
        kind = action["kind"]
        matched = False
        expected: Any = kind
        actual: Any = self._actual_summary()
        evidence_ref = self._current_evidence()

        if kind == "result":
            if (
                self.last_response is None
                and self.last_fault is None
                and isinstance(self.session.transport, StdioTransport)
            ):
                self._observe_response(self._timeout(action))
            payload = self.last_response.payload if self.last_response else None
            matched = isinstance(payload, dict) and "result" in payload and "error" not in payload
            actual = payload
            evidence_ref = self._current_evidence()
        elif kind == "error":
            if (
                self.last_response is None
                and self.last_fault is None
                and isinstance(self.session.transport, StdioTransport)
            ):
                self._observe_response(self._timeout(action))
            payload = self.last_response.payload if self.last_response else None
            matched = isinstance(payload, dict) and isinstance(payload.get("error"), dict)
            actual = payload
            evidence_ref = self._current_evidence()
            if matched and action.get("code") is not None:
                expected = {"errorCode": action["code"]}
                actual_code = payload["error"].get("code")
                actual = {"errorCode": actual_code}
                matched = type(actual_code) is int and actual_code == action["code"]
        elif kind == "timeout":
            if self.last_fault is None and self.awaiting_observation:
                self._observe_for_expectation(self._timeout(action))
            matched = isinstance(self.last_fault, ProbeTimeout)
            actual = type(self.last_fault).__name__ if self.last_fault else self._actual_summary()
            if matched:
                self.last_fault = None
                self.last_fault_evidence = None
        elif kind == "serverRequest":
            request = self._find_server_request(
                action.get("method"), self._timeout(action)
            )
            matched = request is not None
            expected = {"serverRequest": action.get("method") or "any"}
            actual = request.payload if request else self._actual_summary()
            if request:
                self.last_value = request.payload
                self._store_value(request.payload)
                evidence_ref = request.evidence
            elif isinstance(self.last_fault, ProbeTimeout):
                # A wait expiring here is the assertion result, not a run-level
                # transport failure.
                self.last_fault = None
                self.last_fault_evidence = None
        elif kind == "close":
            if self.last_fault is None:
                self._observe_close(self._timeout(action))
            matched = isinstance(self.last_fault, ProcessExited)
            actual = type(self.last_fault).__name__ if self.last_fault else self._actual_summary()
            if isinstance(self.session.transport, HttpTransport):
                self.findings.append(
                    Finding(
                        code="SCENARIO_EXPECTATION",
                        status="SKIP",
                        category="scenario",
                        basis="operational",
                        summary=(
                            f"Step {index}: HTTP connection-close expectation is not observable."
                        ),
                        details=(
                            "Streamable HTTP is request-scoped in this probe; socket "
                            "closure is not exposed as a protocol event."
                        ),
                        expected=expected,
                        actual=actual,
                        evidence=_evidence(evidence_ref),
                    )
                )
                self.awaiting_observation = False
                return
            if matched:
                self.last_fault = None
                self.last_fault_evidence = None
            elif isinstance(self.last_fault, ProbeTimeout):
                self.last_fault = None
                self.last_fault_evidence = None

        self.findings.append(
            Finding(
                code="SCENARIO_EXPECTATION",
                status="PASS" if matched else "FAIL",
                category="scenario",
                basis="operational",
                summary=(
                    f"Step {index}: expected {kind} "
                    + ("was observed." if matched else "was not observed.")
                ),
                details=None if matched else f"Observed: {actual!r}",
                expected=expected,
                actual=actual,
                evidence=_evidence(evidence_ref),
            )
        )
        if not matched and self.last_fault is not None:
            self._add_transport_error(self.last_fault)
        if matched and action["assertions"]:
            source = (
                self.last_response.payload
                if self.last_response is not None
                else self.last_value
            )
            self._evaluate_assertions(index, action["assertions"], source, evidence_ref)
        if matched and kind in {"result", "error"}:
            self.last_response = (
                self.pending_http_responses.pop(0)
                if self.pending_http_responses
                else None
            )
        self.awaiting_observation = False

    def _discover(self, index: int, action: dict[str, Any]) -> None:
        self._clear_observation()
        try:
            if action["primitive"] == "all":
                results = self.session.discover_all(
                    self._timeout(action), max_pages=action["maxPages"]
                )
                value = {name: _pagination_value(result) for name, result in results.items()}
                responses = [
                    response
                    for result in results.values()
                    for response in result.responses
                ]
            else:
                result = self.session.paginate(
                    action["primitive"],
                    self._timeout(action),
                    max_pages=action["maxPages"],
                )
                value = _pagination_value(result)
                responses = result.responses
        except TransportError as exc:
            self._capture_fault(exc)
            evidence = self.last_fault_evidence
        else:
            self.last_value = value
            self._store_value(value)
            if responses:
                self.last_response = responses[-1]
                evidence = responses[-1].evidence
            else:
                evidence = self.session.recorder.last_reference()
        self._step_finding(
            index,
            f"Discovered {action['primitive']}",
            evidence=_evidence(evidence),
        )

    def _disconnect(
        self,
        index: int = 0,
        *,
        implicit: bool,
        timeout: float | None = None,
    ) -> None:
        if self.disconnected:
            return
        evidence_before = self.session.recorder.last_reference()
        try:
            result = self.session.close(timeout or self.default_timeout)
        except TransportError as exc:
            self._add_transport_error(exc)
            status = "FAIL"
            details = str(exc)
        else:
            if isinstance(result, int) and not 200 <= result < 300:
                status = "FAIL"
                details = f"HTTP session termination returned status {result}."
            else:
                status = "PASS"
                details = None
            self.last_value = _serializable_cleanup(result)
            self._store_value(self.last_value)
        self.disconnected = True
        evidence_after = self.session.recorder.last_reference() or evidence_before
        label = "Implicitly disconnected from target" if implicit else "Disconnected from target"
        self.findings.append(
            Finding(
                code="SCENARIO_DISCONNECT",
                status=status,
                category="scenario",
                basis="operational",
                summary=(f"Step {index}: " if index else "") + label + ".",
                details=details,
                evidence=_evidence(evidence_after),
            )
        )

    def _receive_stdio(self, timeout: float) -> InboundMessage | None:
        assert isinstance(self.session.transport, StdioTransport)
        try:
            inbound = self.session.transport.receive(timeout)
        except TransportError as exc:
            self._capture_fault(exc)
            return None
        self._remember_inbound(inbound)
        return inbound

    def _observe_for_expectation(self, timeout: float) -> None:
        if isinstance(self.session.transport, StdioTransport):
            self._receive_stdio(timeout)

    def _observe_response(self, timeout: float) -> None:
        if not isinstance(self.session.transport, StdioTransport):
            return
        deadline = time.monotonic() + timeout
        while self.last_response is None and self.last_fault is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._capture_fault(ProbeTimeout("Timed out waiting for a scenario response."))
                return
            self._receive_stdio(remaining)

    def _observe_close(self, timeout: float) -> None:
        transport = self.session.transport
        if not isinstance(transport, StdioTransport):
            return
        if transport.returncode is not None:
            self._capture_fault(
                ProcessExited(f"stdio server exited with code {transport.returncode}.")
            )
            return
        self._receive_stdio(timeout)

    def _find_server_request(self, method: str | None, timeout: float) -> InboundMessage | None:
        candidates = list(self.server_requests)
        if isinstance(self.session.transport, StdioTransport):
            candidates.extend(self.session.transport.observed_server_requests())
        if self.last_exchange:
            candidates.extend(
                message
                for message in self.last_exchange.messages
                if message.classification == "request"
                and message.evidence not in self.consumed_server_request_evidence
            )
        candidates = [
            message
            for message in candidates
            if message.evidence not in self.consumed_server_request_evidence
        ]
        found = next((item for item in candidates if _method_matches(item, method)), None)
        if found is not None:
            self.consumed_server_request_evidence.add(found.evidence)
            self.server_requests = [item for item in candidates if item is not found]
            return found
        self.server_requests = candidates
        if not isinstance(self.session.transport, StdioTransport):
            return None
        try:
            inbound = self.session.transport.receive(timeout)
        except TransportError as exc:
            self._capture_fault(exc)
            return None
        self._remember_inbound(inbound)
        if inbound.classification == "request" and _method_matches(inbound, method):
            self.consumed_server_request_evidence.add(inbound.evidence)
            self.server_requests = [
                item for item in self.server_requests if item is not inbound
            ]
            return inbound
        return None

    def _remember_rpc(self, outcome: RpcOutcome) -> None:
        self.last_response = outcome.response
        self.pending_http_responses = []
        self.last_exchange = outcome.http_exchange
        self.last_value = outcome.response.payload
        self._store_value(self.last_value)

    def _remember_exchange(self, exchange: HttpExchange) -> None:
        self.last_exchange = exchange
        responses = [item for item in exchange.messages if item.classification == "response"]
        self.last_response = responses[0] if responses else None
        self.pending_http_responses = responses[1:]
        self.last_value = (
            self.last_response.payload if self.last_response else _exchange_value(exchange)
        )
        self._store_value(self.last_value)

    def _remember_inbound(self, inbound: InboundMessage) -> None:
        self.last_value = inbound.payload
        self._store_value(inbound.payload)
        if inbound.classification == "response":
            self.last_response = inbound
        elif inbound.classification == "request":
            self.server_requests.append(inbound)
            handler = self.session.transport.server_request_handler
            if handler:
                response = handler(inbound)
                if response is not None:
                    self.session.transport.send_message(response)

    def _evaluate_assertions(
        self,
        step: int,
        assertions: list[dict[str, Any]],
        source: Any,
        evidence_ref: str | None,
    ) -> None:
        for assertion in assertions:
            path = assertion["path"]
            actual = _resolve_pointer(source, path)
            operator = next(
                key
                for key in ("equals", "exists", "type", "length")
                if key in assertion
            )
            expected = assertion[operator]
            if operator == "equals":
                passed = actual is not _MISSING and _json_equal(actual, expected)
            elif operator == "exists":
                passed = (actual is not _MISSING) is expected
            elif operator == "type":
                passed = actual is not _MISSING and _has_json_type(actual, expected)
            else:
                passed = (
                    actual is not _MISSING
                    and isinstance(actual, (str, list, dict))
                    and len(actual) == expected
                )
            rendered_actual = "<missing>" if actual is _MISSING else actual
            self.findings.append(
                Finding(
                    code="SCENARIO_ASSERTION",
                    status="PASS" if passed else "FAIL",
                    category="scenario",
                    basis="operational",
                    summary=(
                        f"Step {step}: assertion {operator} at {path or '/'} "
                        + ("passed." if passed else "failed.")
                    ),
                    details=None if passed else f"Observed: {rendered_actual!r}",
                    expected={operator: expected},
                    actual=rendered_actual,
                    evidence=_evidence(evidence_ref),
                )
            )

    def _step_finding(
        self,
        index: int,
        summary: str,
        *,
        evidence: tuple[EvidenceRef, ...] = (),
        active: bool = False,
    ) -> None:
        self.findings.append(
            Finding(
                code="SCENARIO_STEP",
                status="PASS",
                category="scenario",
                basis="operational",
                summary=f"Step {index}: {summary}.",
                evidence=evidence,
                active=active,
            )
        )

    def _authorize_tool_call(
        self,
        index: int,
        method: str | None,
        params: Mapping[str, Any] | None,
    ) -> bool:
        if method != "tools/call":
            return True
        name = params.get("name") if isinstance(params, Mapping) else None
        if isinstance(name, str) and name in self.allow_tools:
            self.findings.append(
                Finding(
                    code="SAFETY_ACTIVE_TOOL_OPT_IN",
                    status="PASS",
                    category="safety",
                    basis="operational",
                    summary=f"Step {index}: active tool {name!r} was explicitly allowed.",
                    evidence=_evidence(self.session.recorder.last_reference()),
                    active=True,
                )
            )
            return True
        actual = name if isinstance(name, str) else "<non-literal or missing name>"
        self.errors.append(
            RunError(
                code="CONFIG_UNSAFE_ACTION",
                kind="configuration",
                summary="Scenario tool call was not explicitly allowed.",
                details=(
                    f"Step {index} targets {actual!r}. Pass --allow-tool with the exact "
                    "literal tool name before running this active action."
                ),
                evidence=_evidence(self.session.recorder.last_reference()),
            )
        )
        return False

    def _authorize_raw_tool_call(self, index: int, data: str | bytes) -> bool:
        try:
            text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
        except UnicodeDecodeError:
            text = data.decode("utf-8", errors="replace")
            parsed: Any = _MISSING
        else:
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = _MISSING

        objects = parsed if isinstance(parsed, list) else [parsed]
        calls = [
            item
            for item in objects
            if isinstance(item, dict) and item.get("method") == "tools/call"
        ]
        if calls:
            names = [
                item["params"].get("name")
                if isinstance(item.get("params"), dict)
                else None
                for item in calls
            ]
            invalid = next(
                (
                    name
                    for name in names
                    if not isinstance(name, str) or name not in self.allow_tools
                ),
                _MISSING,
            )
            if invalid is not _MISSING:
                params = {"name": invalid} if isinstance(invalid, str) else None
                return self._authorize_tool_call(index, "tools/call", params)
            for name in names:
                assert isinstance(name, str)
                self._authorize_tool_call(index, "tools/call", {"name": name})
            return True
        if re.search(r"(?i)[\"']method[\"']\s*:\s*[\"']tools/call", text):
            self.errors.append(
                RunError(
                    code="CONFIG_UNSAFE_ACTION",
                    kind="configuration",
                    summary="Raw wire action ambiguously resembles an active tool call.",
                    details=(
                        f"Step {index} cannot be reduced to top-level tool calls with exact "
                        "literal names, so MCP Probe cannot safely verify --allow-tool. "
                        "The action was not sent."
                    ),
                    evidence=_evidence(self.session.recorder.last_reference()),
                )
            )
            return False
        return True

    def _timeout(self, action: Mapping[str, Any]) -> float:
        value = action.get("timeout", self.default_timeout)
        return float(value)

    def _store_value(self, value: Any) -> None:
        self.values.append(deepcopy(redact_value(value)))

    def _capture_fault(self, exc: TransportError) -> None:
        self.last_fault = exc
        self.last_fault_evidence = self.session.recorder.last_reference()
        self.last_response = None
        self.pending_http_responses = []
        self.last_value = None

    def _add_transport_error(self, exc: TransportError, *, during_start: bool = False) -> None:
        transport = self.session.transport
        if isinstance(exc, ProbeTimeout):
            code = (
                "TRANSPORT_STDIO_TIMEOUT"
                if isinstance(transport, StdioTransport)
                else "TRANSPORT_HTTP_TIMEOUT"
            )
        elif isinstance(exc, ProcessExited):
            code = (
                "TRANSPORT_STDIO_CHILD_EXIT"
                if transport.returncode not in {None, 0}
                else "TRANSPORT_STDIO_EOF"
            )
        elif isinstance(transport, StdioTransport):
            code = "TRANSPORT_STDIO_STARTUP" if during_start else "TRANSPORT_STDIO_EOF"
        else:
            code = "TRANSPORT_HTTP_IO"
        self.errors.append(
            RunError(
                code=code,
                kind="transport",
                summary="Scenario transport operation failed.",
                details=str(exc),
                evidence=_evidence(
                    self.last_fault_evidence or self.session.recorder.last_reference()
                ),
            )
        )
        if exc is self.last_fault:
            self.last_fault = None
            self.last_fault_evidence = None

    def _clear_observation(self) -> None:
        self.last_response = None
        self.pending_http_responses = []
        self.last_exchange = None
        self.last_value = None
        self.last_fault = None
        self.last_fault_evidence = None
        self.awaiting_observation = False

    def _current_evidence(self) -> str | None:
        if self.last_response is not None:
            return self.last_response.evidence
        return self.last_fault_evidence or self.session.recorder.last_reference()

    def _actual_summary(self) -> Any:
        if self.last_fault is not None:
            return {"fault": type(self.last_fault).__name__, "message": str(self.last_fault)}
        if self.last_response is not None:
            return self.last_response.payload
        return self.last_value


def _validate_action(raw: Any, index: int) -> dict[str, Any]:
    context = f"scenario.actions[{index - 1}]"
    action = _require_object(raw, context)
    action_type = action.get("action")
    if action_type not in ACTION_TYPES:
        raise _invalid(f"{context}.action must be one of {', '.join(ACTION_TYPES)}.")
    value = deepcopy(action)

    if action_type in {"start", "connect"}:
        _only_keys(action, {"action", "establish", "timeout"}, context)
        value["establish"] = _boolean(action.get("establish", False), f"{context}.establish")
        _validate_timeout_field(value, action, context)
    elif action_type == "request":
        _only_keys(action, {"action", "method", "params", "timeout"}, context)
        value["method"] = _method(action.get("method"), f"{context}.method")
        if "params" in action:
            value["params"] = _require_object(action["params"], f"{context}.params")
        _validate_timeout_field(value, action, context)
    elif action_type == "notification":
        _only_keys(action, {"action", "method", "params", "timeout", "wait"}, context)
        value["method"] = _method(action.get("method"), f"{context}.method")
        if "params" in action:
            value["params"] = _require_object(action["params"], f"{context}.params")
        _validate_timeout_field(value, action, context)
        value["wait"] = _boolean(action.get("wait", False), f"{context}.wait")
    elif action_type == "exact":
        _only_keys(action, {"action", "message", "timeout", "wait"}, context)
        value["message"] = _require_object(action.get("message"), f"{context}.message")
        _validate_timeout_field(value, action, context)
        value["wait"] = _boolean(action.get("wait", False), f"{context}.wait")
    elif action_type == "malformed":
        _only_keys(
            action,
            {
                "action",
                "data",
                "encoding",
                "appendNewline",
                "contentType",
                "headers",
                "wait",
                "timeout",
            },
            context,
        )
        data = action.get("data")
        if not isinstance(data, str):
            raise _invalid(f"{context}.data must be a string.")
        encoding = action.get("encoding", "utf8")
        if encoding not in {"utf8", "base64"}:
            raise _invalid(f"{context}.encoding must be 'utf8' or 'base64'.")
        if encoding == "base64":
            try:
                base64.b64decode(data, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise _invalid(f"{context}.data is not valid base64: {exc}") from exc
        headers = _http_headers(action.get("headers", {}), f"{context}.headers")
        content_type = action.get("contentType", "application/json")
        if (
            not isinstance(content_type, str)
            or not content_type
            or "\r" in content_type
            or "\n" in content_type
        ):
            raise _invalid(f"{context}.contentType must be a non-empty string.")
        value.update(
            {
                "data": data,
                "encoding": encoding,
                "appendNewline": _boolean(
                    action.get("appendNewline", True), f"{context}.appendNewline"
                ),
                "contentType": content_type,
                "headers": headers,
                "wait": _boolean(action.get("wait", True), f"{context}.wait"),
            }
        )
        _validate_timeout_field(value, action, context)
    elif action_type == "expect":
        _only_keys(action, {"action", "kind", "code", "method", "assertions", "timeout"}, context)
        kind = action.get("kind")
        if kind not in EXPECTATION_TYPES:
            raise _invalid(f"{context}.kind must be one of {', '.join(EXPECTATION_TYPES)}.")
        if "code" in action and kind != "error":
            raise _invalid(f"{context}.code is only valid for an error expectation.")
        if "method" in action and kind != "serverRequest":
            raise _invalid(f"{context}.method is only valid for a serverRequest expectation.")
        if "code" in action and (type(action["code"]) is not int):
            raise _invalid(f"{context}.code must be an integer.")
        if "method" in action:
            value["method"] = _method(action["method"], f"{context}.method")
        raw_assertions = action.get("assertions", [])
        if not isinstance(raw_assertions, list):
            raise _invalid(f"{context}.assertions must be an array.")
        value["assertions"] = [
            _validate_assertion(item, f"{context}.assertions[{offset}]")
            for offset, item in enumerate(raw_assertions)
        ]
        value["kind"] = kind
        _validate_timeout_field(value, action, context)
    elif action_type == "discover":
        _only_keys(action, {"action", "primitive", "maxPages", "timeout"}, context)
        primitive = action.get("primitive")
        if primitive not in DISCOVERY_PRIMITIVES:
            raise _invalid(f"{context}.primitive must be one of {', '.join(DISCOVERY_PRIMITIVES)}.")
        max_pages = action.get("maxPages", 100)
        if type(max_pages) is not int or max_pages < 1 or max_pages > 1000:
            raise _invalid(f"{context}.maxPages must be an integer from 1 through 1000.")
        value.update(
            {
                "primitive": primitive,
                "maxPages": max_pages,
            }
        )
        _validate_timeout_field(value, action, context)
    else:
        _only_keys(action, {"action", "timeout"}, context)
        _validate_timeout_field(value, action, context)
    return value


def _validate_assertion(raw: Any, context: str) -> dict[str, Any]:
    assertion = _require_object(raw, context)
    _only_keys(assertion, {"path", "equals", "exists", "type", "length"}, context)
    path = assertion.get("path")
    if not isinstance(path, str) or (path and not path.startswith("/")):
        raise _invalid(f"{context}.path must be a JSON Pointer (or an empty string for the root).")
    operators = [key for key in ("equals", "exists", "type", "length") if key in assertion]
    if len(operators) != 1:
        raise _invalid(f"{context} must contain exactly one assertion operator.")
    operator = operators[0]
    if operator == "exists" and type(assertion[operator]) is not bool:
        raise _invalid(f"{context}.exists must be a boolean.")
    if operator == "type" and assertion[operator] not in ASSERTION_TYPES:
        raise _invalid(f"{context}.type must be one of {', '.join(ASSERTION_TYPES)}.")
    if operator == "length" and (type(assertion[operator]) is not int or assertion[operator] < 0):
        raise _invalid(f"{context}.length must be a non-negative integer.")
    if operator == "equals" and not _is_json_value(assertion[operator]):
        raise _invalid(f"{context}.equals must contain a finite JSON value.")
    # Validate escapes now so malformed pointers fail before a target is started.
    _decode_pointer(path, context)
    return deepcopy(assertion)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-standard JSON numeric constant {value!r}")


def _is_json_value(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _is_json_value(item)
            for key, item in value.items()
        )
    return False


def _require_object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _invalid(f"{context} must be an object.")
    if not all(isinstance(key, str) for key in value):
        raise _invalid(f"{context} field names must be strings.")
    return deepcopy(value)


def _only_keys(value: Mapping[str, Any], allowed: set[str], context: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise _invalid(f"{context} has unknown field(s): {', '.join(unknown)}.")


def _positive_number(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise _invalid(f"{context} must be a positive number.")
    number = float(value)
    if not math.isfinite(number) or number > 3600:
        raise _invalid(f"{context} must not exceed 3600 seconds.")
    return number


def _validate_timeout_field(
    destination: dict[str, Any],
    action: Mapping[str, Any],
    context: str,
) -> None:
    if "timeout" in action:
        destination["timeout"] = _positive_number(
            action["timeout"], f"{context}.timeout"
        )
    else:
        destination.pop("timeout", None)


def _boolean(value: Any, context: str) -> bool:
    if type(value) is not bool:
        raise _invalid(f"{context} must be a boolean.")
    return value


def _method(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise _invalid(f"{context} must be a non-empty string.")
    return value


def _http_headers(value: Any, context: str) -> dict[str, str]:
    mapping = _require_object(value, context)
    if not all(isinstance(key, str) and isinstance(item, str) for key, item in mapping.items()):
        raise _invalid(f"{context} values must all be strings.")
    lowered: set[str] = set()
    for key, item in mapping.items():
        if not _HTTP_HEADER_NAME.fullmatch(key):
            raise _invalid(f"{context} contains an invalid HTTP header name: {key!r}.")
        if "\r" in item or "\n" in item:
            raise _invalid(f"{context}.{key} must not contain CR or LF characters.")
        normalized = key.lower()
        if normalized in lowered:
            raise _invalid(
                f"{context} contains duplicate case-insensitive header name {key!r}."
            )
        lowered.add(normalized)
    return mapping


def _invalid(message: str) -> ConfigurationError:
    return ConfigurationError(message)


def _decode_pointer(path: str, context: str = "JSON Pointer") -> list[str]:
    if path == "":
        return []
    segments: list[str] = []
    for raw_segment in path[1:].split("/"):
        index = 0
        decoded = ""
        while index < len(raw_segment):
            char = raw_segment[index]
            if char != "~":
                decoded += char
                index += 1
                continue
            if index + 1 >= len(raw_segment) or raw_segment[index + 1] not in {"0", "1"}:
                raise _invalid(f"{context} contains an invalid JSON Pointer escape.")
            decoded += "~" if raw_segment[index + 1] == "0" else "/"
            index += 2
        segments.append(decoded)
    return segments


def _resolve_pointer(value: Any, path: str) -> Any:
    current = value
    for segment in _decode_pointer(path):
        if isinstance(current, dict):
            if segment not in current:
                return _MISSING
            current = current[segment]
        elif isinstance(current, list):
            if not segment.isdigit() or (len(segment) > 1 and segment.startswith("0")):
                return _MISSING
            offset = int(segment)
            if offset >= len(current):
                return _MISSING
            current = current[offset]
        else:
            return _MISSING
    return current


def _has_json_type(value: Any, expected: str) -> bool:
    if expected == "null":
        return value is None
    if expected == "boolean":
        return type(value) is bool
    if expected == "integer":
        return type(value) is int
    if expected == "number":
        return type(value) in {int, float}
    if expected == "string":
        return isinstance(value, str)
    if expected == "object":
        return isinstance(value, dict)
    return isinstance(value, list)


def _json_equal(left: Any, right: Any) -> bool:
    if type(left) is bool or type(right) is bool:
        return type(left) is type(right) and left == right
    if type(left) in {int, float} and type(right) in {int, float}:
        return left == right
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    return type(left) is type(right) and left == right


def _pagination_value(result: PaginationResult) -> dict[str, Any]:
    return {
        "primitive": result.primitive,
        "items": deepcopy(result.items),
        "pages": result.pages,
        "cursors": list(result.cursors),
        "complete": result.complete,
        "repeatedCursor": result.repeated_cursor,
        "malformedCursor": deepcopy(result.malformed_cursor),
        "pageLimitReached": result.page_limit_reached,
        "error": deepcopy(result.error_response.payload) if result.error_response else None,
    }


def _exchange_value(exchange: HttpExchange) -> dict[str, Any]:
    return {
        "httpStatus": exchange.status,
        "headers": deepcopy(exchange.headers),
        "body": exchange.body,
        "parseIssues": list(exchange.parse_issues),
        "timedOut": exchange.timed_out,
    }


def _serializable_cleanup(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool, list, dict)):
        return value
    if hasattr(value, "__dict__"):
        return deepcopy(value.__dict__)
    return str(value)


def _method_matches(inbound: InboundMessage, method: str | None) -> bool:
    if method is None:
        return True
    return isinstance(inbound.payload, dict) and inbound.payload.get("method") == method


def _evidence(*references: str | None) -> tuple[EvidenceRef, ...]:
    return tuple(EvidenceRef(event=reference) for reference in references if reference is not None)
