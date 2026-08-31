"""Deterministic, non-destructive MCP compatibility checks.

The checks in this module intentionally stay below an MCP SDK.  They exercise
only discovery and protocol behavior; they never invoke a discovered tool.
Each conclusion is backed by one or more transcript events.
"""

from __future__ import annotations

import datetime as dt
import math
import time
from dataclasses import dataclass
from typing import Any, Iterable

from .errors import ConfigurationError, ProbeTimeout, ProcessExited, TransportError
from .protocol import make_notification, profile_for, response_error_code
from .report import (
    FINDING_CODE_CATEGORIES,
    CompatibilityReport,
    EvidenceRef,
    Finding,
    RunError,
)
from .schema_inspection import SchemaIssue, inspect_tool_schemas
from .safety import find_active_tool_calls
from .session import McpSession, PaginationResult, SessionConfig
from .transports import CleanupResult, HttpExchange, HttpTransport, InboundMessage, StdioTransport
from .transcript import EventRecorder


_SEVERITY = {"SKIP": 0, "PASS": 1, "WARN": 2, "FAIL": 3}
MAX_CHECK_PAGES = 1_000
_INVALID_STDIO_CLASSES = {
    "invalid",
    "invalid_json",
    "invalid_utf8",
    "message_too_large",
    "blank_line",
    "missing_delimiter",
    "invalid_batch",
}


def _typed_rpc_key(value: Any) -> tuple[str, str | int | float] | None:
    if type(value) is int:
        return ("int", value)
    if isinstance(value, float) and math.isfinite(value):
        return ("float", value)
    if isinstance(value, str):
        return ("str", value)
    return None


def _finite_nonnegative_json_number(value: Any) -> bool:
    return (
        type(value) in {int, float}
        and math.isfinite(value)
        and value >= 0
    )


_CAPABILITY_BOOLEAN_FLAGS: dict[str, tuple[str, ...]] = {
    "tools": ("listChanged",),
    "resources": ("subscribe", "listChanged"),
    "prompts": ("listChanged",),
}
_KNOWN_CAPABILITY_DESCRIPTORS = frozenset(
    {*_CAPABILITY_BOOLEAN_FLAGS, "logging", "completions", "experimental", "tasks"}
)

_LIST_NOTIFICATION_CAPABILITIES: dict[str, tuple[str, str]] = {
    "notifications/tools/list_changed": ("tools", "CAPABILITY_TOOLS_LIST"),
    "notifications/resources/list_changed": (
        "resources",
        "CAPABILITY_RESOURCES_LIST",
    ),
    "notifications/resources/updated": (
        "resources",
        "CAPABILITY_RESOURCES_LIST",
    ),
    "notifications/prompts/list_changed": ("prompts", "CAPABILITY_PROMPTS_LIST"),
}


def _capability_shape_issues(capabilities: Any) -> list[dict[str, Any]]:
    if not isinstance(capabilities, dict):
        return [{"path": "/capabilities", "expected": "object", "actual": capabilities}]
    issues: list[dict[str, Any]] = []
    for name, descriptor in capabilities.items():
        if name not in _KNOWN_CAPABILITY_DESCRIPTORS:
            continue
        descriptor_path = f"/capabilities/{name}"
        if not isinstance(descriptor, dict):
            issues.append(
                {
                    "path": descriptor_path,
                    "expected": "object",
                    "actual": descriptor,
                }
            )
            continue
        for flag in _CAPABILITY_BOOLEAN_FLAGS.get(name, ()):
            if flag in descriptor and not isinstance(descriptor[flag], bool):
                issues.append(
                    {
                        "path": f"{descriptor_path}/{flag}",
                        "expected": "boolean",
                        "actual": descriptor[flag],
                    }
                )
    return issues


_PRIMITIVE_CHECKS: dict[str, tuple[str, str, str]] = {
    "tools": ("CAPABILITY_TOOLS_LIST", "tools", "tools/list"),
    "resources": ("CAPABILITY_RESOURCES_LIST", "resources", "resources/list"),
    "resourceTemplates": (
        "CAPABILITY_RESOURCE_TEMPLATES_LIST",
        "resources",
        "resources/templates/list",
    ),
    "prompts": ("CAPABILITY_PROMPTS_LIST", "prompts", "prompts/list"),
}


@dataclass(frozen=True, slots=True)
class CheckOptions:
    """Bounded settings for the built-in safe compatibility suite."""

    timeout: float = 10.0
    max_pages: int = 100
    notification_observation_window: float = 0.10
    close: bool = True

    def __post_init__(self) -> None:
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise ConfigurationError("Compatibility check timeout must be greater than zero.")
        if (
            isinstance(self.max_pages, bool)
            or not isinstance(self.max_pages, int)
            or not 1 <= self.max_pages <= MAX_CHECK_PAGES
        ):
            raise ConfigurationError(
                f"Compatibility max_pages must be an integer from 1 to {MAX_CHECK_PAGES}."
            )
        if (
            isinstance(self.notification_observation_window, bool)
            or not isinstance(self.notification_observation_window, (int, float))
            or not math.isfinite(self.notification_observation_window)
            or self.notification_observation_window < 0
        ):
            raise ConfigurationError(
                "Notification observation window must be zero or greater."
            )


def run_check(
    session: McpSession,
    *,
    timeout: float = 10.0,
    max_pages: int = 100,
    notification_observation_window: float = 0.10,
    close: bool = True,
) -> CompatibilityReport:
    """Run the safe built-in suite and return a stable compatibility report.

    Discovery methods may be called even when they are not advertised so the
    report can detect both sides of a capability mismatch.  ``tools/call`` and
    every other active primitive are deliberately absent.
    """

    if find_active_tool_calls(
        session.config.initialize_message
    ) or find_active_tool_calls(session.config.client_capabilities):
        raise ConfigurationError(
            "Compatibility checks cannot establish a session with active "
            "tools/call-like lifecycle data. Use an explicitly authorized "
            "scenario action for active tool testing."
        )
    options = CheckOptions(timeout, max_pages, notification_observation_window, close)
    return _CheckRun(session, options).execute()


def run_check_transport(
    transport: StdioTransport | HttpTransport,
    config: SessionConfig,
    recorder: EventRecorder,
    **options: Any,
) -> CompatibilityReport:
    """Convenience API for CLI and matrix callers that already built a transport."""

    return run_check(McpSession(transport, config, recorder), **options)


class _CheckRun:
    def __init__(self, session: McpSession, options: CheckOptions) -> None:
        self.session = session
        self.options = options
        self.recorder = session.recorder
        self.findings: list[Finding] = []
        self.errors: list[RunError] = []
        self.responses: list[InboundMessage] = []
        self.observed_requests: list[InboundMessage] = []
        self.pagination: dict[str, PaginationResult] = {}
        # Matrix runs deliberately share a recorder so the saved transcript has
        # one monotonic sequence. Findings, however, must only inspect evidence
        # produced by this run; otherwise an earlier version can contaminate a
        # later version's compatibility result.
        self._event_start = len(self.recorder.events)
        self._started_at = dt.datetime.now(dt.UTC).isoformat(timespec="milliseconds")
        self._started_mono = time.monotonic()
        self._operation_exception: Exception | None = None
        self._cleanup: CleanupResult | int | None = None
        self._probe_notification_seq: int | None = None

    def execute(self) -> CompatibilityReport:
        try:
            establish = self.session.establish(self.options.timeout)
            self.responses.append(establish.response)
            self._check_establishment(establish.success, establish.response)
            if establish.success:
                self._run_discovery()
                if self._operation_exception is None:
                    self._check_unknown_method()
                if self._operation_exception is None:
                    if self.session.profile.modern:
                        self._add(
                            "JSONRPC_NOTIFICATION_NO_RESPONSE",
                            "SKIP",
                            "The modern safe suite did not synthesize a client notification.",
                            details=(
                                "The 2026-07-28 core defines no client-to-server "
                                "notification exercised by this non-mutating suite; use a "
                                "scenario for extension or malformed-notification behavior."
                            ),
                        )
                    else:
                        self._check_notification_no_response()
        except (ConfigurationError, TransportError) as exc:
            self._operation_exception = exc
            self._diagnose_exception(exc)
        except Exception as exc:  # defensive API boundary; never hide internal failures
            self._operation_exception = exc
            self.errors.append(
                RunError(
                    code="INTERNAL_UNEXPECTED",
                    kind="internal",
                    summary="MCP Probe encountered an unexpected internal error.",
                    details=f"{type(exc).__name__}: {exc}",
                    evidence=self._last_evidence(),
                )
            )
        finally:
            if self.options.close:
                try:
                    self._cleanup = self.session.close(min(self.options.timeout, 2.0))
                except TransportError as exc:
                    if self._operation_exception is None:
                        self._operation_exception = exc
                    self._diagnose_close_exception(exc)

        self._collect_server_request_findings()
        self._add_notification_findings()
        self._validate_response_envelopes()
        self._add_transport_findings()
        self._add_batch_findings()
        self._add(
            "SAFETY_ACTIVE_TOOL_OPT_IN",
            "PASS",
            "Built-in compatibility checks did not invoke any server tool.",
            basis="operational",
            expected=False,
            actual=False,
        )
        return self._build_report()

    def _check_establishment(self, success: bool, response: InboundMessage) -> None:
        profile = self.session.profile
        payload = response.payload if isinstance(response.payload, dict) else {}
        result = payload.get("result") if isinstance(payload.get("result"), dict) else None
        evidence = (response.evidence,)

        if profile.modern:
            self._add(
                "LIFECYCLE_INITIALIZE",
                "SKIP",
                "Initialize is not part of the 2026-07-28 stateless lifecycle.",
                details="The check used server/discover with per-request metadata instead.",
                evidence=evidence,
            )
            self._add(
                "LIFECYCLE_INITIALIZED",
                "SKIP",
                "notifications/initialized is not part of the modern lifecycle.",
                details="The 2026-07-28 profile has no initialized notification.",
                evidence=evidence,
            )
        else:
            self._add(
                "LIFECYCLE_INITIALIZE",
                "PASS" if success else "FAIL",
                "Initialize completed successfully."
                if success
                else "Initialize did not return a successful result.",
                expected="JSON-RPC result",
                actual=payload.get("error", payload),
                evidence=evidence,
            )
            if success and self.session.config.send_initialized:
                initialized_event = self._find_client_method_event("notifications/initialized")
                self._add(
                    "LIFECYCLE_INITIALIZED",
                    "PASS" if initialized_event else "FAIL",
                    "notifications/initialized followed successful initialization."
                    if initialized_event
                    else "notifications/initialized was not observed after initialize.",
                    expected="notification after initialize result",
                    actual="sent" if initialized_event else "missing",
                    evidence=(self._event_ref(initialized_event),) if initialized_event else evidence,
                )
            elif success:
                self._add(
                    "LIFECYCLE_INITIALIZED",
                    "FAIL",
                    "The required initialized notification was deliberately omitted.",
                    details=(
                        "MCP Probe preserved the requested lifecycle mutation and reports "
                        "its normative compatibility consequence."
                    ),
                    expected="notifications/initialized after initialize result",
                    actual="omitted",
                    evidence=evidence,
                )

        self._add(
            "LIFECYCLE_ORDERING",
            "PASS" if success else "FAIL",
            "The configured lifecycle reached discovery in the required order."
            if success
            else "The configured lifecycle could not be established.",
            expected="successful establishment before discovery",
            actual="established" if success else "not established",
            evidence=evidence,
        )
        self._add(
            "LIFECYCLE_DUPLICATE_INITIALIZE",
            "SKIP",
            "Duplicate initialization was not injected by the safe default suite.",
            details="Use a scenario to record deliberately invalid duplicate lifecycle behavior.",
            evidence=evidence,
        )

        if result is None:
            self._add(
                "NEGOTIATION_PROTOCOL_VERSION",
                "FAIL",
                "Protocol negotiation did not produce a result object.",
                expected=self.session.requested_version,
                actual=payload.get("error", payload),
                evidence=evidence,
            )
            return

        if profile.modern:
            versions = result.get("supportedVersions")
            valid_versions = (
                isinstance(versions, list)
                and bool(versions)
                and all(isinstance(item, str) for item in versions)
            )
            includes_requested = valid_versions and self.session.requested_version in versions
            self._add(
                "NEGOTIATION_PROTOCOL_VERSION",
                "PASS" if includes_requested else "FAIL",
                "server/discover advertised the requested protocol version."
                if includes_requested
                else "server/discover did not advertise the requested protocol version.",
                expected={"contains": self.session.requested_version},
                actual=versions,
                evidence=(self._pointer(response, "/result/supportedVersions"),),
            )
            required = {
                "resultType": result.get("resultType") == "complete",
                "ttlMs": _finite_nonnegative_json_number(result.get("ttlMs")),
                "cacheScope": result.get("cacheScope") in {"public", "private"},
            }
            if not all(required.values()):
                self._add(
                    "JSONRPC_RESPONSE_SHAPE",
                    "FAIL",
                    "server/discover omitted or malformed required result fields.",
                    expected={key: True for key in required},
                    actual=required,
                    evidence=(self._pointer(response, "/result"),),
                )
        else:
            selected = result.get("protocolVersion")
            if not isinstance(selected, str) or not selected:
                status = "FAIL"
                summary = "initialize.result.protocolVersion is missing or not a string."
            else:
                try:
                    selected_profile = profile_for(selected)
                except ConfigurationError:
                    selected_profile = None
                transport_compatible = not (
                    isinstance(self.session.transport, HttpTransport)
                    and selected_profile is not None
                    and not selected_profile.streamable_http
                )
                compatible = (
                    selected_profile is not None
                    and not selected_profile.modern
                    and transport_compatible
                )
            if isinstance(selected, str) and selected == self.session.requested_version:
                status = "PASS"
                summary = "The server negotiated the requested protocol version."
            elif isinstance(selected, str) and compatible:
                status = "WARN"
                summary = "The server selected a different dated protocol version."
            else:
                status = "FAIL"
                summary = "The server selected an unsupported or lifecycle-incompatible version."
            self._add(
                "NEGOTIATION_PROTOCOL_VERSION",
                status,
                summary,
                expected=self.session.requested_version,
                actual=selected,
                evidence=(self._pointer(response, "/result/protocolVersion"),),
            )

        capabilities = result.get("capabilities")
        capability_issues = _capability_shape_issues(capabilities)
        self._add(
            "NEGOTIATION_CAPABILITIES",
            "PASS" if not capability_issues else "FAIL",
            "Server capabilities and their known descriptors have the required shapes."
            if not capability_issues
            else "Server capabilities contain a malformed descriptor or flag.",
            expected="object descriptors with boolean capability flags",
            actual=capability_issues or capabilities,
            evidence=(self._pointer(response, "/result/capabilities"),),
        )
        server_info = self.session.server_info
        valid_info = (
            isinstance(server_info, dict)
            and isinstance(server_info.get("name"), str)
            and isinstance(server_info.get("version"), str)
        )
        info_status = "PASS" if valid_info else ("WARN" if profile.modern else "FAIL")
        self._add(
            "NEGOTIATION_SERVER_INFO",
            info_status,
            "Server information includes string name and version."
            if valid_info
            else (
                "Modern server/discover did not include recommended server information."
                if profile.modern
                else "initialize.result.serverInfo is missing or malformed."
            ),
            basis="normative",
            expected={"name": "string", "version": "string"},
            actual=server_info,
            evidence=(
                self._pointer(
                    response,
                    "/result/_meta/io.modelcontextprotocol~1serverInfo"
                    if profile.modern
                    else "/result/serverInfo",
                ),
            ),
        )

    def _run_discovery(self) -> None:
        pagination_with_cursors: list[str] = []
        pagination_complete: list[str] = []
        malformed: list[tuple[str, Any, InboundMessage | None]] = []
        loops: list[tuple[str, str | None, InboundMessage | None]] = []

        for primitive, (code, capability_key, method) in _PRIMITIVE_CHECKS.items():
            advertised = capability_key in self.session.capabilities
            try:
                result = self.session.paginate(
                    primitive,
                    self.options.timeout,
                    max_pages=self.options.max_pages,
                )
            except TransportError as exc:
                self._operation_exception = exc
                self._diagnose_exception(exc)
                break
            self.pagination[primitive] = result
            self.responses.extend(result.responses)
            evidence = tuple(item.evidence for item in result.responses)
            error_code = (
                response_error_code(result.error_response.payload)
                if result.error_response is not None
                else None
            )
            valid_pages = bool(result.responses) and all(
                self._valid_list_page(item, primitive) for item in result.responses
            )

            if result.error_response is not None:
                if advertised:
                    status = "FAIL"
                    summary = f"{method} failed despite its advertised capability."
                elif error_code == -32601:
                    status = "SKIP"
                    summary = f"{method} is not advertised and returned method-not-found."
                else:
                    status = "WARN"
                    summary = f"Unadvertised {method} returned a non-standard error."
                self._add(
                    code,
                    status,
                    summary,
                    details=(
                        "The primitive was not advertised; no discovery result was expected."
                        if status == "SKIP"
                        else None
                    ),
                    expected="successful list result" if advertised else "-32601 or no capability",
                    actual=result.error_response.payload,
                    evidence=evidence,
                )
            elif not valid_pages:
                self._add(
                    code,
                    "FAIL",
                    f"{method} did not return {primitive} as an array on every page.",
                    expected=f"result.{primitive}: array",
                    actual=[item.payload for item in result.responses],
                    evidence=evidence,
                )
            elif not advertised:
                self._add(
                    code,
                    "FAIL",
                    f"{method} succeeded without the corresponding advertised capability.",
                    expected={capability_key: "advertised before successful use"},
                    actual={"advertised": False, "items": len(result.items)},
                    evidence=evidence,
                )
            else:
                self._add(
                    code,
                    "PASS",
                    f"Advertised {method} behavior is consistent.",
                    expected=f"result.{primitive}: array",
                    actual={"pages": result.pages, "items": len(result.items)},
                    evidence=evidence,
                )

            if result.cursors:
                pagination_with_cursors.append(primitive)
            if result.complete and result.pages > 1:
                pagination_complete.append(primitive)
            if result.malformed_cursor is not None:
                malformed.append(
                    (primitive, result.malformed_cursor, result.responses[-1] if result.responses else None)
                )
            if result.repeated_cursor is not None or result.page_limit_reached:
                loops.append(
                    (
                        primitive,
                        result.repeated_cursor,
                        result.responses[-1] if result.responses else None,
                    )
                )

        self._add_pagination_findings(
            pagination_with_cursors, pagination_complete, malformed, loops
        )
        tools_result = self.pagination.get("tools")
        if tools_result and tools_result.error_response is None:
            self._add_schema_findings(tools_result)
        else:
            self._add(
                "TOOL_SCHEMA_PORTABILITY",
                "SKIP",
                "Tool schema inspection could not run.",
                details="No successful tools/list result was available.",
            )

        self._add(
            "CAPABILITY_LOGGING",
            "SKIP",
            "Logging capability was not actively mutated by the safe suite.",
            details=(
                "setLevel changes server behavior and is better exercised by an explicit scenario."
            ),
        )

    def _add_pagination_findings(
        self,
        with_cursors: list[str],
        complete: list[str],
        malformed: list[tuple[str, Any, InboundMessage | None]],
        loops: list[tuple[str, str | None, InboundMessage | None]],
    ) -> None:
        if malformed:
            self._add(
                "PAGINATION_CURSOR_SHAPE",
                "FAIL",
                "A list result returned a non-string nextCursor.",
                expected="string or absent",
                actual={primitive: value for primitive, value, _ in malformed},
                evidence=tuple(item.evidence for _, _, item in malformed if item),
            )
        elif with_cursors:
            self._add(
                "PAGINATION_CURSOR_SHAPE",
                "PASS",
                "Returned pagination cursors were strings.",
                actual=with_cursors,
                evidence=self._pagination_evidence(with_cursors),
            )
        else:
            self._add(
                "PAGINATION_CURSOR_SHAPE",
                "SKIP",
                "No list operation returned a cursor.",
                details="Pagination is optional and was not present in these results.",
            )

        if loops:
            self._add(
                "PAGINATION_CURSOR_LOOP",
                "WARN",
                "Pagination stopped after a repeated cursor or the configured page limit.",
                basis="heuristic",
                expected="eventual cursor termination",
                actual={primitive: cursor for primitive, cursor, _ in loops},
                evidence=tuple(item.evidence for _, _, item in loops if item),
            )
        elif with_cursors:
            self._add(
                "PAGINATION_CURSOR_LOOP",
                "PASS",
                "Pagination completed without a cursor loop.",
                basis="heuristic",
                actual=complete,
                evidence=self._pagination_evidence(with_cursors),
            )
        else:
            self._add(
                "PAGINATION_CURSOR_LOOP",
                "SKIP",
                "Cursor loop detection was not applicable.",
                details="No nextCursor value was returned.",
            )

        if complete:
            self._add(
                "PAGINATION_CURSOR_PROGRESS",
                "PASS",
                "Paginated list operations advanced to completion.",
                expected="new cursor or terminal page",
                actual=complete,
                evidence=self._pagination_evidence(complete),
            )
        elif with_cursors:
            self._add(
                "PAGINATION_CURSOR_PROGRESS",
                "WARN",
                "At least one cursor sequence did not reach a terminal page.",
                basis="heuristic",
                expected="terminal page within configured limit",
                actual=with_cursors,
                evidence=self._pagination_evidence(with_cursors),
            )
        else:
            self._add(
                "PAGINATION_CURSOR_PROGRESS",
                "SKIP",
                "Cursor progress was not applicable.",
                details="No nextCursor value was returned.",
            )

    def _add_schema_findings(self, pagination: PaginationResult) -> None:
        tools = pagination.items
        response = pagination.responses[0] if pagination.responses else None
        if not tools:
            self._add(
                "TOOL_SCHEMA_PORTABILITY",
                "SKIP",
                "No tool descriptors were available for static inspection.",
                details="tools/list returned an empty array.",
                evidence=(response.evidence,) if response else (),
            )
            return

        issues = inspect_tool_schemas(tools)
        actual_issues = [issue for issue in issues if issue.code != "TOOL_SCHEMA_INSPECTION"]
        groups: dict[str, list[SchemaIssue]] = {
            "TOOL_SCHEMA_INPUT_PRESENT": [],
            "TOOL_SCHEMA_INPUT_OBJECT": [],
            "TOOL_SCHEMA_REQUIRED_SHAPE": [],
            "TOOL_SCHEMA_OUTPUT_OBJECT": [],
            "TOOL_NAME_UNIQUE": [],
            "TOOL_SCHEMA_PORTABILITY": [],
        }
        for issue in actual_issues:
            groups[self._schema_report_code(issue.code)].append(issue)

        summaries = {
            "TOOL_SCHEMA_INPUT_PRESENT": "Every tool descriptor includes inputSchema.",
            "TOOL_SCHEMA_INPUT_OBJECT": "Tool inputSchema values have the expected object shape.",
            "TOOL_SCHEMA_REQUIRED_SHAPE": "Tool required arrays passed limited structural checks.",
            "TOOL_SCHEMA_OUTPUT_OBJECT": "Tool outputSchema values are objects when present.",
            "TOOL_NAME_UNIQUE": "Tool descriptor names are present and unique.",
            "TOOL_SCHEMA_PORTABILITY": "No limited portability issue was detected.",
        }
        for code, group in groups.items():
            if not group:
                self._add(
                    code,
                    "PASS",
                    summaries[code],
                    basis="heuristic" if code == "TOOL_SCHEMA_PORTABILITY" else "normative",
                    evidence=tuple(
                        self._pointer(item, "/result/tools")
                        for item in pagination.responses
                    ),
                )
                continue
            status = max((issue.status for issue in group), key=_SEVERITY.__getitem__)
            basis = "heuristic" if all(issue.basis == "heuristic" for issue in group) else "normative"
            if code == "TOOL_SCHEMA_PORTABILITY" and not (
                self.session.profile.modern
                and isinstance(self.session.transport, HttpTransport)
            ):
                # x-mcp-header is defined by the 2026-07-28 HTTP binding.  On
                # older profiles it is useful portability evidence, not a
                # normative failure for that dated protocol.
                status = "WARN"
                basis = "heuristic"
            self._add(
                code,
                status,
                group[0].message if len(group) == 1 else f"{len(group)} related tool schema issues were found.",
                basis=basis,
                actual=[issue.to_dict() for issue in group],
                evidence=self._schema_issue_evidence(group, pagination),
            )

    def _schema_issue_evidence(
        self, issues: Iterable[SchemaIssue], pagination: PaginationResult
    ) -> tuple[EvidenceRef, ...]:
        """Map flattened tool indexes back to their actual page and pointer."""

        spans: list[tuple[int, int, InboundMessage]] = []
        offset = 0
        for response in pagination.responses:
            payload = response.payload
            result = payload.get("result") if isinstance(payload, dict) else None
            page_tools = result.get("tools") if isinstance(result, dict) else None
            count = len(page_tools) if isinstance(page_tools, list) else 0
            spans.append((offset, offset + count, response))
            offset += count

        refs: list[EvidenceRef] = []
        seen: set[tuple[str, str]] = set()
        for issue in issues:
            parts = issue.path.split("/")
            if len(parts) < 3 or parts[1] != "tools" or not parts[2].isdigit():
                if pagination.responses:
                    ref = self._pointer(pagination.responses[0], "/result/tools")
                    key = (ref.event, ref.pointer)
                    if key not in seen:
                        seen.add(key)
                        refs.append(ref)
                continue
            flattened_index = int(parts[2])
            suffix = "/".join(parts[3:])
            for start, end, page in spans:
                if start <= flattened_index < end:
                    pointer = f"/result/tools/{flattened_index - start}"
                    if suffix:
                        pointer += f"/{suffix}"
                    ref = self._pointer(page, pointer)
                    key = (ref.event, ref.pointer)
                    if key not in seen:
                        seen.add(key)
                        refs.append(ref)
                    break
        return tuple(refs)

    @staticmethod
    def _schema_report_code(issue_code: str) -> str:
        if issue_code == "TOOL_INPUT_SCHEMA_MISSING":
            return "TOOL_SCHEMA_INPUT_PRESENT"
        if issue_code.startswith("TOOL_INPUT_SCHEMA_REQUIRED"):
            return "TOOL_SCHEMA_REQUIRED_SHAPE"
        if issue_code.startswith("TOOL_INPUT_SCHEMA"):
            return "TOOL_SCHEMA_INPUT_OBJECT"
        if issue_code.startswith("TOOL_OUTPUT_SCHEMA"):
            return "TOOL_SCHEMA_OUTPUT_OBJECT"
        if issue_code.startswith("TOOL_X_MCP_HEADER"):
            return "TOOL_SCHEMA_PORTABILITY"
        return "TOOL_NAME_UNIQUE"

    def _check_unknown_method(self) -> None:
        try:
            outcome = self.session.rpc("mcp-probe/unknown-method", {}, self.options.timeout)
        except TransportError as exc:
            self._operation_exception = exc
            self._diagnose_exception(exc)
            return
        response = outcome.response
        self.responses.append(response)
        code = response_error_code(response.payload)
        http_status = outcome.http_exchange.status if outcome.http_exchange else None
        expected_status = 404 if self.session.profile.modern and outcome.http_exchange else None
        good = code == -32601 and (expected_status is None or http_status == expected_status)
        self._add(
            "JSONRPC_UNKNOWN_METHOD",
            "PASS" if good else "FAIL",
            "Unknown request methods return JSON-RPC method-not-found."
            if good
            else "Unknown request method behavior did not match the protocol profile.",
            expected={"errorCode": -32601, "httpStatus": expected_status},
            actual={"errorCode": code, "httpStatus": http_status},
            evidence=(response.evidence,),
        )
        self._add(
            "JSONRPC_INVALID_PARAMS",
            "SKIP",
            "Invalid parameters were not synthesized by the safe default suite.",
            details="Use an explicit scenario for method-specific invalid parameter cases.",
        )
        self._add(
            "JSONRPC_INVALID_REQUEST",
            "SKIP",
            "A deliberately invalid request object was not synthesized.",
            details="Use an exact-message scenario to exercise -32600 behavior.",
        )

    def _check_notification_no_response(self) -> None:
        message = make_notification("notifications/mcp-probe-test", {"source": "compatibility-check"})
        try:
            if isinstance(self.session.transport, HttpTransport):
                exchange = self.session.transport.send_message(message, self.options.timeout)
                responses = [item for item in exchange.messages if item.classification == "response"]
                idless_errors = [
                    item
                    for item in responses
                    if isinstance(item.payload, dict)
                    and "id" not in item.payload
                    and isinstance(item.payload.get("error"), dict)
                ]
                accepted = (
                    exchange.status == 202
                    and exchange.body == ""
                    and not responses
                )
                rejected = (
                    400 <= exchange.status < 500
                    and len(idless_errors) == len(responses)
                    and (
                        exchange.body == ""
                        or (bool(responses) and not exchange.parse_issues)
                    )
                )
                good = accepted or rejected
                evidence = tuple(item.evidence for item in responses) or self._last_evidence()
                actual: Any = {
                    "httpStatus": exchange.status,
                    "responseCount": len(responses),
                    "idlessErrorCount": len(idless_errors),
                    "emptyBody": exchange.body == "",
                }
            else:
                sent = self.session.transport.send_message(message)
                self._probe_notification_seq = int(sent.partition(":")[2])
                responses = []
                deadline = time.monotonic() + self.options.notification_observation_window
                while time.monotonic() < deadline:
                    try:
                        inbound = self.session.transport.receive(
                            min(0.025, max(0.001, deadline - time.monotonic()))
                        )
                    except ProbeTimeout:
                        continue
                    if inbound.classification == "response":
                        responses.append(inbound)
                    elif inbound.classification == "request":
                        self.observed_requests.append(inbound)
                good = not responses
                evidence = tuple(item.evidence for item in responses) or (sent,)
                actual = {"responseCount": len(responses)}
            self._add(
                "JSONRPC_NOTIFICATION_NO_RESPONSE",
                "PASS" if good else "FAIL",
                "The server did not send a JSON-RPC response to a notification."
                if good
                else "The server incorrectly responded to a JSON-RPC notification.",
                expected={"responseCount": 0},
                actual=actual,
                evidence=evidence,
            )
        except ProcessExited as exc:
            self._operation_exception = exc
            self._add(
                "JSONRPC_NOTIFICATION_NO_RESPONSE",
                "FAIL",
                "The server closed the connection after an unknown notification.",
                actual=str(exc),
                evidence=self._last_evidence(),
            )
            self._diagnose_exception(exc)
        except TransportError as exc:
            self._operation_exception = exc
            self._diagnose_exception(exc)

    def _add_batch_findings(self) -> None:
        batches = [
            event
            for event in self._events
            if event.get("direction") == "server_to_client"
            and event.get("classification") == "batch"
        ]
        invalid = [
            event
            for event in self._events
            if event.get("direction") == "server_to_client"
            and event.get("classification") == "invalid_batch"
        ]
        if invalid:
            self._add(
                "JSONRPC_BATCH_SUPPORT",
                "FAIL",
                "The server emitted a batch that is invalid for the selected protocol profile.",
                expected=(
                    "a bounded non-empty JSON-RPC batch"
                    if self.session.profile.batch_receive_required
                    else "individual JSON-RPC messages"
                ),
                actual={"invalidBatches": len(invalid)},
                evidence=tuple(self._event_ref(event) for event in invalid),
            )
        elif batches:
            self._add(
                "JSONRPC_BATCH_SUPPORT",
                "PASS" if self.session.profile.batch_receive_required else "FAIL",
                "An incoming JSON-RPC batch was accepted by the 2025-03-26 receive path."
                if self.session.profile.batch_receive_required
                else "The server emitted a JSON-RPC batch in a profile that does not use batching.",
                actual={"batches": len(batches)},
                evidence=tuple(self._event_ref(event) for event in batches),
            )
        else:
            self._add(
                "JSONRPC_BATCH_SUPPORT",
                "SKIP",
                "JSON-RPC batch receive behavior was not exercised."
                if self.session.profile.batch_receive_required
                else "JSON-RPC batching is not part of this selected compatibility profile.",
                details=(
                    "A PASS is reported only when an incoming 2025-03-26 batch is observed."
                    if self.session.profile.batch_receive_required
                    else "Later MCP profiles exchange individual JSON-RPC messages."
                ),
            )

    def _add_notification_findings(self) -> None:
        outstanding: dict[tuple[str, str | int | float], dict[str, Any]] = {}
        progress: list[tuple[dict[str, Any], bool]] = []
        logging: list[tuple[dict[str, Any], bool]] = []
        changes: list[tuple[dict[str, Any], str, str, bool]] = []

        for event in self._events:
            payload = event.get("payload")
            if not isinstance(payload, dict):
                continue
            direction = event.get("direction")
            classification = event.get("classification")
            if direction == "client_to_server" and classification == "request":
                key = _typed_rpc_key(payload.get("id"))
                if key is not None:
                    outstanding[key] = payload
                continue
            if direction == "server_to_client" and classification == "response":
                key = _typed_rpc_key(payload.get("id"))
                if key is not None:
                    outstanding.pop(key, None)
                continue
            if direction != "server_to_client" or classification != "notification":
                continue

            method = payload.get("method")
            params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
            active_meta = [
                request.get("params", {}).get("_meta", {})
                for request in outstanding.values()
                if isinstance(request.get("params"), dict)
                and isinstance(request["params"].get("_meta"), dict)
            ]
            if method == "notifications/progress":
                token = params.get("progressToken")
                token_key = _typed_rpc_key(token)
                allowed = token_key is not None and any(
                    token_key in {
                        _typed_rpc_key(meta.get("progressToken")),
                        _typed_rpc_key(meta.get("io.modelcontextprotocol/progressToken")),
                    }
                    for meta in active_meta
                )
                progress.append((event, allowed))
            elif method == "notifications/message" and self.session.profile.modern:
                allowed = any(
                    "io.modelcontextprotocol/logLevel" in meta for meta in active_meta
                )
                logging.append((event, allowed))
            elif method in _LIST_NOTIFICATION_CAPABILITIES:
                capability, code = _LIST_NOTIFICATION_CAPABILITIES[method]
                descriptor = self.session.capabilities.get(capability)
                if self.session.profile.modern:
                    # The safe suite never establishes subscriptions/listen.
                    allowed = False
                elif method == "notifications/resources/updated":
                    allowed = isinstance(descriptor, dict) and descriptor.get("subscribe") is True
                else:
                    allowed = isinstance(descriptor, dict) and descriptor.get("listChanged") is True
                changes.append((event, capability, code, allowed))

        if progress:
            bad = [event for event, allowed in progress if not allowed]
            self._add(
                "JSONRPC_PROGRESS_TOKEN",
                "FAIL" if bad else "PASS",
                "A progress notification did not match an active request token."
                if bad
                else "Progress notifications matched active request tokens.",
                evidence=tuple(self._event_ref(event) for event in (bad or [item[0] for item in progress])),
            )
        else:
            self._add(
                "JSONRPC_PROGRESS_TOKEN",
                "SKIP",
                "No progress notification was observed.",
                details="The safe suite did not request progress for any operation.",
            )

        if logging:
            bad = [event for event, allowed in logging if not allowed]
            self._add(
                "CAPABILITY_LOGGING",
                "FAIL" if bad else "PASS",
                "A modern logging notification was sent without a request-scoped logLevel."
                if bad
                else "Modern logging notifications matched request-scoped log levels.",
                evidence=tuple(self._event_ref(event) for event in (bad or [item[0] for item in logging])),
            )

        for event, capability, code, allowed in changes:
            self._add(
                code,
                "PASS" if allowed else "FAIL",
                f"The {capability} change notification matched negotiated behavior."
                if allowed
                else (
                    f"The modern {capability} change notification had no active subscription."
                    if self.session.profile.modern
                    else f"The {capability} change notification was not advertised."
                ),
                evidence=(self._event_ref(event),),
            )

    def _collect_server_request_findings(self) -> None:
        requests = list(self.observed_requests)
        if isinstance(self.session.transport, StdioTransport):
            requests.extend(self.session.transport.observed_server_requests())
        else:
            requests.extend(self._http_server_requests())

        deduplicated: dict[str, InboundMessage] = {}
        for request in requests:
            deduplicated.setdefault(request.evidence, request)
        requests = list(deduplicated.values())

        if not requests:
            self._add(
                "CLIENT_REQUEST_UNSUPPORTED",
                "PASS" if self.session.profile.modern else "SKIP",
                "No forbidden server-to-client request was observed."
                if self.session.profile.modern
                else "No server-to-client request was observed.",
                details=(
                    None
                    if self.session.profile.modern
                    else "The target did not exercise client request handling during this run."
                ),
            )
            self._add(
                "CAPABILITY_ROOTS",
                "SKIP",
                "roots/list capability handling was not exercised.",
                details="The server did not request roots/list.",
            )
            return

        ping_requests = [item for item in requests if self._method(item) == "ping"]
        roots_requests = [item for item in requests if self._method(item) == "roots/list"]
        unsupported = [
            item for item in requests if self._method(item) not in {"ping", "roots/list"}
        ]
        invalid = [
            item
            for item in requests
            if not isinstance(item.payload, dict)
            or _typed_rpc_key(item.payload.get("id")) is None
            or not isinstance(item.payload.get("method"), str)
        ]
        if invalid:
            outcomes = [self._server_request_outcome(item) for item in invalid]
            rejected = all(
                outcome["valid"]
                and response_error_code(outcome["payload"]) == -32600
                and not outcome["failures"]
                for outcome in outcomes
            )
            self._add(
                "JSONRPC_INVALID_REQUEST",
                "FAIL",
                "The server emitted a malformed request; MCP Probe rejected it with -32600."
                if rejected
                else "The server emitted a malformed request and the client rejection was incomplete.",
                expected={"serverRequest": "valid JSON-RPC", "clientErrorCode": -32600},
                actual=outcomes,
                evidence=tuple(
                    ref
                    for item, outcome in zip(invalid, outcomes)
                    for ref in (item.evidence, *outcome["evidence"])
                ),
            )
        if ping_requests:
            outcomes = [self._server_request_outcome(item) for item in ping_requests]
            handled = all(
                outcome["valid"]
                and isinstance(outcome["payload"].get("result"), dict)
                and not outcome["failures"]
                for outcome in outcomes
            )
            good = handled and not self.session.profile.modern
            self._add(
                "CLIENT_REQUEST_PING",
                "PASS" if good else "FAIL",
                "Legacy ping requests were handled explicitly."
                if good
                else (
                    "A modern server sent a forbidden server-to-client ping request."
                    if self.session.profile.modern
                    else "A legacy ping request did not receive a valid successful response."
                ),
                actual=outcomes,
                evidence=tuple(
                    ref
                    for item, outcome in zip(ping_requests, outcomes)
                    for ref in (item.evidence, *outcome["evidence"])
                ),
            )
        if roots_requests:
            roots_advertised = "roots" in self.session.config.client_capabilities
            early = [
                item for item in roots_requests if self._server_request_marker(item, "pre_initialized_server_request")
            ]
            outcomes = [self._server_request_outcome(item) for item in roots_requests]
            if early:
                early_outcomes = [self._server_request_outcome(item) for item in early]
                rejected = all(
                    outcome["valid"]
                    and response_error_code(outcome["payload"]) == -32002
                    and not outcome["failures"]
                    for outcome in early_outcomes
                )
                self._add(
                    "LIFECYCLE_ORDERING",
                    "WARN" if rejected else "FAIL",
                    "A roots/list request arrived before initialization and was explicitly rejected."
                    if rejected
                    else "A pre-initialization roots/list request was not rejected with -32002.",
                    expected={"errorCode": -32002},
                    actual=early_outcomes,
                    evidence=tuple(
                        ref
                        for item, outcome in zip(early, early_outcomes)
                        for ref in (item.evidence, *outcome["evidence"])
                    ),
                )

            normal_pairs = [
                (item, outcome)
                for item, outcome in zip(roots_requests, outcomes)
                if item not in early
            ]
            if self.session.profile.modern:
                good = False
            elif normal_pairs and roots_advertised:
                good = all(
                    outcome["valid"]
                    and isinstance(outcome["payload"].get("result"), dict)
                    and isinstance(outcome["payload"]["result"].get("roots"), list)
                    and not outcome["failures"]
                    for _, outcome in normal_pairs
                )
            elif normal_pairs:
                good = all(
                    outcome["valid"]
                    and response_error_code(outcome["payload"]) == -32601
                    and not outcome["failures"]
                    for _, outcome in normal_pairs
                )
            else:
                good = bool(early) and all(
                    outcome["valid"]
                    and response_error_code(outcome["payload"]) == -32002
                    and not outcome["failures"]
                    for outcome in outcomes
                )
            roots_status = "PASS" if good and not early else ("WARN" if good else "FAIL")
            self._add(
                "CLIENT_REQUEST_ROOTS_LIST",
                roots_status,
                "roots/list matched the advertised legacy client capability."
                if roots_status == "PASS"
                else (
                    "The pre-initialization roots/list request was rejected before normal roots handling."
                    if roots_status == "WARN"
                    else "roots/list did not receive the response required by lifecycle and capability state."
                ),
                expected={"clientCapabilities.roots": True, "era": "legacy", "response": "result or explicit error"},
                actual={"advertised": roots_advertised, "era": self.session.profile.era, "outcomes": outcomes},
                evidence=tuple(
                    ref
                    for item, outcome in zip(roots_requests, outcomes)
                    for ref in (item.evidence, *outcome["evidence"])
                ),
            )
            capability_good = bool(normal_pairs) and roots_advertised and roots_status == "PASS"
            self._add(
                "CAPABILITY_ROOTS",
                "PASS" if capability_good else ("SKIP" if early and not normal_pairs else "FAIL"),
                "Observed roots behavior is capability-consistent."
                if capability_good
                else (
                    "Normal roots capability behavior was not reached before initialization."
                    if early and not normal_pairs
                    else "Observed roots behavior contradicts capability negotiation."
                ),
                details=(
                    "The request was rejected during lifecycle establishment, before roots could be served."
                    if early and not normal_pairs
                    else None
                ),
                evidence=tuple(item.evidence for item in roots_requests),
            )
        if unsupported or (self.session.profile.modern and requests):
            relevant = requests if self.session.profile.modern else unsupported
            outcomes = [self._server_request_outcome(item) for item in relevant]
            handled = (
                not self.session.profile.modern
                and not invalid
                and all(
                    outcome["valid"]
                    and response_error_code(outcome["payload"]) == -32601
                    and not outcome["failures"]
                    for outcome in outcomes
                )
            )
            self._add(
                "CLIENT_REQUEST_UNSUPPORTED",
                "PASS" if handled else "FAIL",
                "Unsupported legacy server requests received explicit method-not-found errors."
                if handled
                else (
                    "A modern server sent a forbidden server-to-client request."
                    if self.session.profile.modern
                    else "An unsupported or malformed server request was not rejected correctly."
                ),
                expected=("no server requests or client responses" if self.session.profile.modern else {"errorCode": -32601}),
                actual=outcomes,
                evidence=tuple(
                    ref
                    for item, outcome in zip(relevant, outcomes)
                    for ref in (item.evidence, *outcome["evidence"])
                ),
            )

    def _server_request_marker(
        self, request: InboundMessage, classification: str
    ) -> dict[str, Any] | None:
        request_key = _typed_rpc_key(
            request.payload.get("id") if isinstance(request.payload, dict) else None
        )
        for event in self._events:
            if event.get("classification") != classification:
                continue
            source = event.get("sourceEvidence")
            if source == request.evidence or (
                isinstance(source, list) and request.evidence in source
            ):
                return event
            if request_key is not None and _typed_rpc_key(event.get("requestId")) == request_key:
                return event
            if request_key is not None and isinstance(event.get("requestIds"), list):
                if any(_typed_rpc_key(value) == request_key for value in event["requestIds"]):
                    return event
        return None

    def _server_request_outcome(self, request: InboundMessage) -> dict[str, Any]:
        request_id = request.payload.get("id") if isinstance(request.payload, dict) else None
        request_key = _typed_rpc_key(request_id)
        invalid_request = self._server_request_marker(request, "invalid_server_request")
        request_seq = int(request.evidence.partition(":")[2])
        response_candidates: list[tuple[dict[str, Any], dict[str, Any]]] = []
        for event in self._events:
            if event.get("seq", 0) <= request_seq or event.get("direction") != "client_to_server":
                continue
            payloads: list[Any]
            if event.get("classification") == "response":
                payloads = [event.get("payload")]
            elif event.get("classification") == "batch" and isinstance(event.get("payload"), list):
                payloads = event["payload"]
            else:
                continue
            for payload_candidate in payloads:
                if (
                    isinstance(payload_candidate, dict)
                    and (
                        (
                            request_key is not None
                            and _typed_rpc_key(payload_candidate.get("id")) == request_key
                        )
                        or (
                            invalid_request is not None
                            and request_key is None
                            and payload_candidate.get("id") is None
                        )
                    )
                    and (("result" in payload_candidate) ^ ("error" in payload_candidate))
                ):
                    response_candidates.append((event, payload_candidate))
        success_marker = self._server_request_marker(request, "server_request_response")
        failures = [
            marker
            for name in (
                "server_request_handler_error",
                "server_request_response_error",
                "server_request_response_http_error",
                "server_request_response_correlation_error",
                "server_request_response_skipped",
            )
            if (marker := self._server_request_marker(request, name)) is not None
        ]
        payload = response_candidates[0][1] if response_candidates else None
        valid = (
            isinstance(payload, dict)
            and payload.get("jsonrpc") == "2.0"
            and (
                (request_key is not None and _typed_rpc_key(payload.get("id")) == request_key)
                or (
                    invalid_request is not None
                    and request_key is None
                    and payload.get("id") is None
                )
            )
            and (("result" in payload) ^ ("error" in payload))
        )
        http_status = success_marker.get("httpStatus") if success_marker else None
        if type(http_status) is int and not 200 <= http_status < 300:
            valid = False
        evidence = list(
            dict.fromkeys(self._event_ref(event) for event, _ in response_candidates)
        )
        if success_marker:
            evidence.append(self._event_ref(success_marker))
        evidence.extend(self._event_ref(event) for event in failures)
        return {
            "requestId": request_id,
            "responseObserved": bool(response_candidates),
            "payload": payload,
            "httpStatus": http_status,
            "valid": valid,
            "failures": [event.get("classification") for event in failures],
            "evidence": evidence,
        }

    def _validate_response_envelopes(self) -> None:
        if not self.responses:
            return
        bad_version = [
            item
            for item in self.responses
            if not isinstance(item.payload, dict) or item.payload.get("jsonrpc") != "2.0"
        ]
        self._add(
            "JSONRPC_VERSION",
            "FAIL" if bad_version else "PASS",
            "One or more responses did not declare JSON-RPC 2.0."
            if bad_version
            else "Observed responses declared JSON-RPC 2.0.",
            expected="2.0",
            actual=[item.payload.get("jsonrpc") if isinstance(item.payload, dict) else None for item in bad_version]
            if bad_version
            else "2.0",
            evidence=tuple(item.evidence for item in (bad_version or self.responses)),
        )

        bad_shape: list[InboundMessage] = []
        for item in self.responses:
            payload = item.payload
            if not isinstance(payload, dict):
                bad_shape.append(item)
                continue
            result_present = "result" in payload
            error_present = "error" in payload
            if result_present == error_present:
                bad_shape.append(item)
                continue
            if error_present:
                error = payload.get("error")
                if not (
                    isinstance(error, dict)
                    and type(error.get("code")) is int
                    and isinstance(error.get("message"), str)
                ):
                    bad_shape.append(item)
            elif not isinstance(payload.get("result"), dict):
                bad_shape.append(item)
            elif self.session.profile.modern:
                result = payload["result"]
                if result.get("resultType") != "complete":
                    bad_shape.append(item)
        self._add(
            "JSONRPC_RESPONSE_SHAPE",
            "FAIL" if bad_shape else "PASS",
            "One or more JSON-RPC response envelopes were malformed."
            if bad_shape
            else "Observed JSON-RPC response envelopes had the expected shape.",
            expected="exactly one well-formed result or error",
            actual=[item.payload for item in bad_shape] if bad_shape else {"responses": len(self.responses)},
            evidence=tuple(item.evidence for item in (bad_shape or self.responses)),
        )
        unexpected_ids = self._response_id_anomalies()
        self._add(
            "JSONRPC_RESPONSE_ID",
            "FAIL" if unexpected_ids else "PASS",
            "The server emitted a response whose ID was not outstanding."
            if unexpected_ids
            else "All responses used the request ID selected for correlation.",
            expected="type-exact request ID",
            actual=[event.get("payload", {}).get("id") for event in unexpected_ids]
            if unexpected_ids
            else {"correlatedResponses": len(self.responses)},
            evidence=tuple(self._event_ref(event) for event in unexpected_ids)
            or tuple(item.evidence for item in self.responses),
        )
        if self._probe_notification_seq is not None:
            notification_responses = [
                event
                for event in unexpected_ids
                if event.get("seq", 0) > self._probe_notification_seq
            ]
            if notification_responses:
                self._add(
                    "JSONRPC_NOTIFICATION_NO_RESPONSE",
                    "FAIL",
                    "The server incorrectly responded to a JSON-RPC notification.",
                    expected={"responseCount": 0},
                    actual={"responseCount": len(notification_responses)},
                    evidence=tuple(
                        self._event_ref(event) for event in notification_responses
                    ),
                )

    def _diagnose_exception(self, exc: Exception) -> None:
        if isinstance(exc, ConfigurationError):
            self.errors.append(
                RunError(
                    code="CONFIG_INVALID_ARGUMENT",
                    kind="configuration",
                    summary="The compatibility check configuration is invalid.",
                    details=str(exc),
                    evidence=self._last_evidence(),
                )
            )
            return

        events = self._events
        outgoing = next(
            (
                event
                for event in reversed(events)
                if event.get("direction") == "client_to_server"
                and event.get("classification") == "request"
            ),
            None,
        )
        responses = [
            event
            for event in events
            if event.get("direction") == "server_to_client"
            and event.get("classification") == "response"
            and (outgoing is None or event.get("seq", 0) > outgoing.get("seq", 0))
        ]
        if outgoing is not None and responses:
            expected_id = outgoing.get("id")
            actual_ids = [event.get("id") for event in responses]
            expected_key = _typed_rpc_key(expected_id)
            if expected_key is not None and not any(
                _typed_rpc_key(actual_id) == expected_key for actual_id in actual_ids
            ):
                self._add(
                    "JSONRPC_RESPONSE_ID",
                    "FAIL",
                    "The server responded with an ID that did not match the request.",
                    expected=expected_id,
                    actual=actual_ids,
                    evidence=tuple(self._event_ref(event) for event in responses),
                )

        invalid_events = [
            event
            for event in events
            if event.get("direction") == "server_to_client"
            and event.get("classification") in (_INVALID_STDIO_CLASSES | {"invalid_body"})
        ]
        invalid_rpc = [
            event
            for event in invalid_events
            if isinstance(event.get("payload"), dict)
        ]
        if invalid_rpc:
            malformed = [event.get("payload") for event in invalid_rpc]
            self._add(
                "JSONRPC_RESPONSE_SHAPE",
                "FAIL",
                "The server emitted an invalid JSON-RPC response object.",
                expected="exactly one result or error",
                actual=malformed,
                evidence=tuple(self._event_ref(event) for event in invalid_rpc),
            )
            bad_version = [
                event
                for event in invalid_rpc
                if event.get("payload", {}).get("jsonrpc") != "2.0"
            ]
            if bad_version:
                self._add(
                    "JSONRPC_VERSION",
                    "FAIL",
                    "The invalid response did not declare JSON-RPC 2.0.",
                    expected="2.0",
                    actual=[event.get("payload", {}).get("jsonrpc") for event in bad_version],
                    evidence=tuple(self._event_ref(event) for event in bad_version),
                )
        parse_events = [event for event in events if event.get("classification") == "parse_issue"]
        unexpected_ids = [
            event
            for event in events
            if event.get("classification") == "unexpected_response_id"
        ]
        protocol_fault = bool(responses or invalid_events or parse_events or unexpected_ids)
        if protocol_fault:
            return

        if isinstance(exc, ProbeTimeout):
            code = (
                "TRANSPORT_HTTP_TIMEOUT"
                if isinstance(self.session.transport, HttpTransport)
                else "TRANSPORT_STDIO_TIMEOUT"
            )
            self.errors.append(
                RunError(
                    code=code,
                    kind="transport",
                    summary="The target did not respond before the timeout.",
                    details=str(exc),
                    evidence=self._last_evidence(),
                )
            )
        elif isinstance(exc, ProcessExited):
            code = (
                "TRANSPORT_STDIO_CHILD_EXIT"
                if self.session.transport.returncode not in {None, 0}
                else "TRANSPORT_STDIO_EOF"
            )
            self.errors.append(
                RunError(
                    code=code,
                    kind="transport",
                    summary="The stdio server exited before the required response.",
                    details=str(exc),
                    evidence=self._last_evidence(),
                )
            )
        else:
            code = (
                "TRANSPORT_HTTP_CONNECT"
                if isinstance(self.session.transport, HttpTransport)
                else "TRANSPORT_STDIO_STARTUP"
            )
            self.errors.append(
                RunError(
                    code=code,
                    kind="transport",
                    summary="The target transport could not complete the compatibility run.",
                    details=str(exc),
                    evidence=self._last_evidence(),
                )
            )

    def _diagnose_close_exception(self, exc: TransportError) -> None:
        http = isinstance(self.session.transport, HttpTransport)
        code = "TRANSPORT_HTTP_IO" if http else "TRANSPORT_STDIO_EOF"
        self.errors.append(
            RunError(
                code=code,
                kind="transport",
                summary="The target could not be closed cleanly.",
                details=str(exc),
                evidence=self._last_evidence(),
            )
        )
        self._add(
            "HTTP_SESSION_TERMINATION" if http else "STDIO_CLEANUP",
            "FAIL",
            "HTTP session termination failed."
            if http
            else "The stdio process could not be cleaned up reliably.",
            basis="operational",
            actual=str(exc),
            evidence=self._last_evidence(),
        )

    def _add_transport_findings(self) -> None:
        events = self._events
        if isinstance(self.session.transport, StdioTransport):
            started = any(event.get("classification") == "process_start" for event in events)
            invalid = [
                event
                for event in events
                if event.get("direction") == "server_to_client"
                and event.get("classification") in _INVALID_STDIO_CLASSES
            ]
            if not started:
                self._add(
                    "STDIO_INVALID_OUTPUT",
                    "SKIP",
                    "No server stdout was available for inspection.",
                    details="The stdio process could not be started.",
                )
            else:
                self._add(
                    "STDIO_INVALID_OUTPUT",
                    "FAIL" if invalid else "PASS",
                    "The server wrote malformed protocol output to stdout."
                    if invalid
                    else "Server stdout contained only parsed protocol messages.",
                    expected="one JSON-RPC object per UTF-8 line",
                    actual=[event.get("classification") for event in invalid] if invalid else "valid",
                    evidence=tuple(self._event_ref(event) for event in invalid),
                )
            timed_out = [event for event in events if event.get("classification") == "timeout"]
            if (
                timed_out
                and not self._has("JSONRPC_RESPONSE_ID", "FAIL")
                and not invalid
            ):
                self._add(
                    "STDIO_TIMEOUT",
                    "FAIL",
                    "A stdio request timed out.",
                    evidence=tuple(self._event_ref(event) for event in timed_out),
                )
            elif not timed_out and started:
                self._add(
                    "STDIO_TIMEOUT",
                    "PASS",
                    "No protocol request exceeded the configured stdio timeout.",
                    basis="operational",
                )
            elif not started:
                self._add(
                    "STDIO_TIMEOUT",
                    "SKIP",
                    "No stdio request timeout could be measured.",
                    details="The stdio process could not be started.",
                    basis="operational",
                )
            if isinstance(self._operation_exception, ProcessExited):
                self._add(
                    "STDIO_UNEXPECTED_EOF",
                    "FAIL",
                    "The stdio server closed stdout during an active check.",
                    actual=str(self._operation_exception),
                    evidence=self._last_evidence(),
                )
            cleanup_returncode = (
                self._cleanup.returncode
                if isinstance(self._cleanup, CleanupResult)
                else self.session.transport.returncode
            )
            child_exited_naturally = not isinstance(
                self._cleanup, CleanupResult
            ) or self._cleanup.graceful
            if cleanup_returncode not in {None, 0} and child_exited_naturally:
                cleanup_evidence = self._events_by_class("process_cleanup")
                self._add(
                    "STDIO_CHILD_EXIT",
                    "FAIL",
                    "The stdio server exited with a non-zero status.",
                    basis="operational",
                    expected=0,
                    actual=cleanup_returncode,
                    evidence=cleanup_evidence or self._last_evidence(),
                )
                if not any(
                    error.code == "TRANSPORT_STDIO_CHILD_EXIT"
                    for error in self.errors
                ):
                    self.errors.append(
                        RunError(
                            code="TRANSPORT_STDIO_CHILD_EXIT",
                            kind="transport",
                            summary="The stdio server exited with a non-zero status.",
                            details=(
                                f"The child returned exit status {cleanup_returncode} "
                                "during compatibility-run cleanup."
                            ),
                            evidence=cleanup_evidence or self._last_evidence(),
                        )
                    )
            if isinstance(self._cleanup, CleanupResult):
                if self._cleanup.killed:
                    status = "FAIL"
                elif self._cleanup.terminated:
                    status = "WARN"
                else:
                    status = "PASS"
                self._add(
                    "STDIO_CLEANUP",
                    status,
                    "The stdio process was cleaned up."
                    if status == "PASS"
                    else "The stdio process required forced cleanup.",
                    basis="operational",
                    actual={
                        "returncode": self._cleanup.returncode,
                        "graceful": self._cleanup.graceful,
                        "terminated": self._cleanup.terminated,
                        "killed": self._cleanup.killed,
                    },
                    evidence=self._events_by_class("process_cleanup"),
                )
            return

        exchanges = [
            (index, event)
            for index, event in enumerate(events)
            if event.get("classification") == "http_response"
        ]
        if not exchanges:
            for code, summary in (
                ("HTTP_STATUS", "No HTTP response status was available."),
                ("HTTP_CONTENT_TYPE", "No HTTP response content type was available."),
                ("HTTP_BODY_SHAPE", "No HTTP response body was available."),
                ("HTTP_SSE_PARSE", "No HTTP response stream was available."),
            ):
                self._add(
                    code,
                    "SKIP",
                    summary,
                    details="The transport failed before a response could be inspected.",
                )
            self._check_http_request_headers()
            self._add(
                "HTTP_SESSION_ID",
                "SKIP",
                "No MCP session ID was assigned.",
                details="The transport failed before session behavior could be inspected.",
            )
            self._add(
                "HTTP_SESSION_TERMINATION",
                "SKIP",
                "No HTTP session required termination.",
                details="No session was established.",
            )
            timeout_events = [
                event
                for event in events
                if event.get("classification") == "timeout"
            ]
            self._add(
                "HTTP_TIMEOUT",
                "FAIL" if timeout_events else "SKIP",
                "An HTTP interaction timed out."
                if timeout_events
                else "HTTP timeout behavior was not reached.",
                basis="operational",
                details=None if timeout_events else "The connection failed for another reason.",
                evidence=tuple(self._event_ref(event) for event in timeout_events),
            )
            return
        bad_status = [
            event for index, event in exchanges if not self._allowed_http_status(index, event)
        ]
        self._add(
            "HTTP_STATUS",
            "FAIL" if bad_status else "PASS",
            "One or more HTTP statuses did not match the protocol interaction."
            if bad_status
            else "Observed HTTP statuses matched the supported Streamable HTTP subset.",
            expected=(
                "successful 2xx, an HTTP notification rejection, "
                "or modern method-not-found 404"
            ),
            actual=[event.get("httpStatus") for event in bad_status]
            if bad_status
            else [event.get("httpStatus") for _, event in exchanges],
            evidence=tuple(self._event_ref(event) for event in bad_status),
        )

        bad_content: list[dict[str, Any]] = []
        sse_events: list[dict[str, Any]] = []
        for _, event in exchanges:
            if not event.get("byteLength"):
                continue
            content_type = self._header(event.get("headers", {}), "content-type") or ""
            media_type = content_type.partition(";")[0].strip().lower()
            if media_type == "text/event-stream":
                sse_events.append(event)
            if media_type not in {"application/json", "text/event-stream"}:
                bad_content.append(event)
        self._add(
            "HTTP_CONTENT_TYPE",
            "FAIL" if bad_content else "PASS",
            "A non-empty HTTP response used an unsupported content type."
            if bad_content
            else "Non-empty HTTP responses used JSON or SSE content types.",
            expected="application/json or text/event-stream",
            actual=[self._header(event.get("headers", {}), "content-type") for event in bad_content]
            if bad_content
            else "supported",
            evidence=tuple(self._event_ref(event) for event in bad_content),
        )
        parse = [event for event in events if event.get("classification") == "parse_issue"]
        body_parse = [
            event
            for event in parse
            if not str(event.get("error", "")).startswith("unexpected Content-Type")
        ]
        invalid_body = [event for event in events if event.get("classification") == "invalid_body"]
        empty_request_responses = [
            event
            for index, event in exchanges
            if not event.get("byteLength") and self._previous_client_class(index) == "request"
        ]
        body_bad = body_parse + invalid_body + empty_request_responses
        self._add(
            "HTTP_BODY_SHAPE",
            "FAIL" if body_bad else "PASS",
            "An HTTP request response was empty or could not be decoded."
            if body_bad
            else "HTTP response bodies decoded into the expected message shape.",
            evidence=tuple(self._event_ref(event) for event in body_bad),
        )
        if sse_events:
            self._add(
                "HTTP_SSE_PARSE",
                "FAIL" if body_parse else "PASS",
                "SSE contained parse errors."
                if body_parse
                else "SSE events were parsed successfully.",
                evidence=tuple(self._event_ref(event) for event in (body_parse or sse_events)),
            )
        else:
            self._add(
                "HTTP_SSE_PARSE",
                "SKIP",
                "No SSE response was returned.",
                details="The target used JSON or empty HTTP responses in this run.",
            )

        self._check_http_request_headers()
        assigned = [event for event in events if event.get("classification") == "session_assigned"]
        invalid_sessions = [
            event
            for event in events
            if event.get("classification")
            in {"invalid_session_id", "unexpected_session_id"}
        ]
        if invalid_sessions:
            self._add(
                "HTTP_SESSION_ID",
                "FAIL",
                "The server returned an invalid or lifecycle-incompatible MCP session ID.",
                expected=(
                    "no MCP-Session-Id for this protocol era"
                    if self.session.profile.modern
                    else "a valid visible-ASCII MCP-Session-Id"
                ),
                actual=[event.get("classification") for event in invalid_sessions],
                evidence=tuple(
                    self._event_ref(event) for event in invalid_sessions
                ),
            )
        elif assigned:
            assigned_seq = assigned[0]["seq"]
            subsequent = [
                event
                for event in events
                if event.get("direction") == "client_to_server"
                and event.get("transport") == "http"
                and event.get("seq", 0) > assigned_seq
                and event.get("classification") in {"request", "notification"}
            ]
            propagated = all(
                self._header(event.get("headers", {}), "mcp-session-id") is not None
                for event in subsequent
            )
            self._add(
                "HTTP_SESSION_ID",
                "PASS" if propagated else "FAIL",
                "The assigned MCP session ID was propagated on later requests."
                if propagated
                else "The assigned MCP session ID was omitted from a later request.",
                evidence=tuple(self._event_ref(event) for event in assigned + subsequent),
            )
        else:
            self._add(
                "HTTP_SESSION_ID",
                "SKIP",
                "The server did not assign an optional MCP session ID.",
                details="Session IDs are optional for the supported legacy Streamable HTTP profiles.",
            )

        if isinstance(self._cleanup, int):
            termination_ok = 200 <= self._cleanup < 300 or self._cleanup == 405
            self._add(
                "HTTP_SESSION_TERMINATION",
                "PASS" if termination_ok else "FAIL",
                (
                    "The assigned HTTP session was terminated."
                    if 200 <= self._cleanup < 300
                    else (
                        "The server explicitly does not permit client session termination."
                        if self._cleanup == 405
                        else "HTTP session termination returned an error status."
                    )
                ),
                expected="2xx or 405",
                actual=self._cleanup,
                evidence=self._events_by_class("session_terminated"),
            )
        else:
            self._add(
                "HTTP_SESSION_TERMINATION",
                "SKIP",
                "No HTTP session required termination.",
                details="The server did not assign a session, or this modern profile is stateless.",
            )
        timeout_events = [
            event
            for event in events
            if event.get("timedOut") or (
                event.get("classification") == "transport_error"
                and "timed out" in str(event.get("error", "")).lower()
            )
        ]
        self._add(
            "HTTP_TIMEOUT",
            "FAIL" if timeout_events else "PASS",
            "An HTTP interaction timed out."
            if timeout_events
            else "No HTTP interaction exceeded the configured timeout.",
            basis="operational",
            evidence=tuple(self._event_ref(event) for event in timeout_events),
        )

    def _check_http_request_headers(self) -> None:
        requests = [
            event
            for event in self._events
            if event.get("direction") == "client_to_server"
            and event.get("transport") == "http"
            and event.get("classification") == "request"
        ]
        if not self.session.profile.protocol_header:
            self._add(
                "HTTP_PROTOCOL_VERSION_HEADER",
                "SKIP",
                "This dated profile does not require MCP-Protocol-Version.",
                details="The requirement begins with the 2025-06-18 Streamable HTTP profile.",
            )
            return
        bad: list[dict[str, Any]] = []
        selected_version = self.session.negotiated_version or self.session.requested_version
        for event in requests:
            method = event.get("method")
            if method == "initialize" and not self.session.profile.modern:
                continue
            headers = event.get("headers", {})
            protocol = self._header(headers, "mcp-protocol-version")
            method_header = self._header(headers, "mcp-method")
            if protocol != selected_version:
                bad.append(event)
            elif self.session.profile.modern and method_header != method:
                bad.append(event)
        self._add(
            "HTTP_PROTOCOL_VERSION_HEADER",
            "FAIL" if bad else "PASS",
            "A request omitted or mismatched required MCP HTTP binding headers."
            if bad
            else "Required MCP protocol and method headers were sent.",
            expected=selected_version,
            actual=[event.get("headers") for event in bad] if bad else "present",
            evidence=tuple(self._event_ref(event) for event in bad),
        )

    def _allowed_http_status(self, event_index: int, event: dict[str, Any]) -> bool:
        status = event.get("httpStatus")
        if type(status) is not int:
            return False
        if 200 <= status < 300:
            return True
        action_index = self._previous_http_action_index(event_index)
        if (
            400 <= status < 500
            and action_index is not None
            and self._events[action_index].get("classification") == "notification"
            and self._valid_http_notification_rejection(action_index)
        ):
            return True
        if status != 404 or not self.session.profile.modern:
            return False
        # Incremental SSE delivers protocol messages before the terminal
        # http_response evidence record, while buffered JSON historically
        # delivered them on the other side. Correlate within the enclosing
        # client action window instead of depending on recorder order.
        action_id: Any = None
        if action_index is None:
            return False
        action_id = self._events[action_index].get("id")
        for candidate in self._events[action_index + 1 :]:
            if (
                candidate.get("direction") == "client_to_server"
                and candidate.get("classification")
                in {"request", "notification", "raw_wire"}
            ):
                break
            payload = candidate.get("payload")
            if (
                response_error_code(payload) == -32601
                and isinstance(payload, dict)
                and type(payload.get("id")) is type(action_id)
                and payload.get("id") == action_id
            ):
                return True
        return False

    def _previous_http_action_index(self, event_index: int) -> int | None:
        for index in range(event_index - 1, -1, -1):
            candidate = self._events[index]
            if candidate.get("direction") == "client_to_server" and candidate.get(
                "classification"
            ) in {"request", "notification", "raw_wire"}:
                return index
        return None

    def _http_action_events(self, action_index: int) -> list[dict[str, Any]]:
        output: list[dict[str, Any]] = []
        for candidate in self._events[action_index + 1 :]:
            if (
                candidate.get("direction") == "client_to_server"
                and candidate.get("classification")
                in {"request", "notification", "raw_wire"}
            ):
                break
            output.append(candidate)
        return output

    def _valid_http_notification_rejection(self, action_index: int) -> bool:
        events = self._http_action_events(action_index)
        protocol_messages = [
            event
            for event in events
            if event.get("direction") == "server_to_client"
            and event.get("classification") in {"request", "notification", "response", "invalid"}
        ]
        if not protocol_messages:
            response = next(
                (
                    event
                    for event in events
                    if event.get("classification") == "http_response"
                ),
                None,
            )
            return response is not None and not response.get("byteLength")
        return all(
            event.get("classification") == "response"
            and isinstance(event.get("payload"), dict)
            and "id" not in event["payload"]
            and isinstance(event["payload"].get("error"), dict)
            for event in protocol_messages
        )

    def _previous_client_class(self, event_index: int) -> str | None:
        for earlier in reversed(self._events[:event_index]):
            if earlier.get("direction") == "client_to_server":
                return earlier.get("classification")
        return None

    def _valid_list_page(self, response: InboundMessage, primitive: str) -> bool:
        payload = response.payload
        valid = (
            isinstance(payload, dict)
            and isinstance(payload.get("result"), dict)
            and isinstance(payload["result"].get(primitive), list)
        )
        if not valid or not self.session.profile.modern:
            return valid
        result = payload["result"]
        return (
            result.get("resultType") == "complete"
            and _finite_nonnegative_json_number(result.get("ttlMs"))
            and result.get("cacheScope") in {"public", "private"}
        )

    def _response_id_anomalies(self) -> list[dict[str, Any]]:
        outstanding: dict[tuple[str, str | int | float], int] = {}
        anomalies: list[dict[str, Any]] = []
        events = self._events
        for index, event in enumerate(events):
            direction = event.get("direction")
            classification = event.get("classification")
            payload = event.get("payload")
            if direction == "client_to_server" and classification == "request":
                key = _typed_rpc_key(payload.get("id") if isinstance(payload, dict) else None)
                if key is not None:
                    outstanding[key] = outstanding.get(key, 0) + 1
                continue
            if direction == "probe" and classification == "timeout":
                key = _typed_rpc_key(event.get("requestId"))
                if key is not None:
                    outstanding.pop(key, None)
                continue
            if direction != "server_to_client" or classification != "response":
                continue
            key = _typed_rpc_key(payload.get("id") if isinstance(payload, dict) else None)
            if key is not None and outstanding.get(key, 0):
                remaining = outstanding[key] - 1
                if remaining:
                    outstanding[key] = remaining
                else:
                    outstanding.pop(key, None)
                continue
            if self._allowed_idless_http_notification_error(index, payload):
                continue
            anomalies.append(event)
        return anomalies

    def _allowed_idless_http_notification_error(
        self, event_index: int, payload: Any
    ) -> bool:
        if not isinstance(self.session.transport, HttpTransport):
            return False
        if not (
            isinstance(payload, dict)
            and "id" not in payload
            and isinstance(payload.get("error"), dict)
        ):
            return False
        action_index: int | None = None
        for index in range(event_index - 1, -1, -1):
            candidate = self._events[index]
            if candidate.get("direction") == "client_to_server" and candidate.get(
                "classification"
            ) in {"request", "notification", "raw_wire"}:
                action_index = index
                break
        if action_index is None or self._events[action_index].get(
            "classification"
        ) != "notification":
            return False
        for candidate in self._events[action_index + 1 :]:
            if (
                candidate.get("direction") == "client_to_server"
                and candidate.get("classification")
                in {"request", "notification", "raw_wire"}
            ):
                break
            status = candidate.get("httpStatus")
            if candidate.get("classification") == "http_response" and type(status) is int:
                return 400 <= status < 600
        return False

    def _pagination_evidence(self, primitives: Iterable[str]) -> tuple[str, ...]:
        wanted = set(primitives)
        return tuple(
            response.evidence
            for primitive, pagination in self.pagination.items()
            if primitive in wanted
            for response in pagination.responses
        )

    def _http_server_requests(self) -> list[InboundMessage]:
        output: list[InboundMessage] = []
        for event in self._events:
            if (
                event.get("direction") == "server_to_client"
                and event.get("transport") == "http"
                and event.get("classification") == "request"
            ):
                output.append(
                    InboundMessage(
                        event.get("payload"),
                        str(event.get("raw", "")),
                        "request",
                        self._event_ref(event),
                        event.get("httpStatus"),
                        event.get("headers", {}),
                    )
                )
        return output

    @staticmethod
    def _method(message: InboundMessage) -> str | None:
        return message.payload.get("method") if isinstance(message.payload, dict) else None

    def _build_report(self) -> CompatibilityReport:
        transcript = {
            "path": str(self.recorder.path) if self.recorder.path else None,
            "eventCount": len(self._events),
            "firstSeq": self._events[0]["seq"] if self._events else None,
            "lastSeq": self._events[-1]["seq"] if self._events else None,
            "redacted": True,
        }
        return CompatibilityReport(
            target=self.session.target_description(),
            started_at=self._started_at,
            duration_ms=(time.monotonic() - self._started_mono) * 1000,
            requested_version=self.session.requested_version,
            negotiated_version=self.session.negotiated_version,
            era=self.session.profile.era,
            server_info=self.session.server_info,
            capabilities=self.session.capabilities,
            discovery=self.session.discovered,
            findings=tuple(self.findings),
            errors=tuple(self.errors),
            transcript=transcript,
            known_secrets=self.recorder.known_secrets,
        )

    def _add(
        self,
        code: str,
        status: str,
        summary: str,
        *,
        basis: str = "normative",
        details: str | None = None,
        expected: Any = None,
        actual: Any = None,
        evidence: Iterable[str | EvidenceRef | None] = (),
    ) -> None:
        refs = tuple(item for item in evidence if item is not None)
        finding = Finding(
            code=code,
            status=status,
            category=FINDING_CODE_CATEGORIES[code],
            basis=basis,
            summary=summary,
            details=details,
            expected=expected,
            actual=actual,
            evidence=refs,
        )
        for index, previous in enumerate(self.findings):
            if previous.code != code:
                continue
            if _SEVERITY[finding.status] > _SEVERITY[previous.status]:
                self.findings[index] = finding
            return
        self.findings.append(finding)

    def _has(self, code: str, status: str | None = None) -> bool:
        return any(
            item.code == code and (status is None or item.status == status)
            for item in self.findings
        )

    def _pointer(self, response: InboundMessage, pointer: str) -> EvidenceRef:
        return EvidenceRef(response.evidence, pointer)

    @staticmethod
    def _event_ref(event: dict[str, Any] | None) -> str:
        if event is None:
            raise ValueError("Cannot reference a missing transcript event.")
        return f"event:{event['seq']}"

    def _last_evidence(self) -> tuple[str, ...]:
        return (self._event_ref(self._events[-1]),) if self._events else ()

    def _events_by_class(self, classification: str) -> tuple[str, ...]:
        return tuple(
            self._event_ref(event)
            for event in self._events
            if event.get("classification") == classification
        )

    def _find_client_method_event(self, method: str) -> dict[str, Any] | None:
        return next(
            (
                event
                for event in self._events
                if event.get("direction") == "client_to_server"
                and event.get("method") == method
            ),
            None,
        )

    @property
    def _events(self) -> list[dict[str, Any]]:
        return self.recorder.events[self._event_start :]

    @staticmethod
    def _header(headers: Any, name: str) -> str | None:
        if not isinstance(headers, dict):
            return None
        wanted = name.lower()
        for key, value in headers.items():
            if str(key).lower() == wanted:
                return str(value)
        return None


__all__ = ["CheckOptions", "MAX_CHECK_PAGES", "run_check", "run_check_transport"]
