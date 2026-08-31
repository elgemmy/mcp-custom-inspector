"""Version-aware MCP session behavior layered over raw transports."""

from __future__ import annotations

import math
import re
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

from .errors import ConfigurationError, HttpExchangeError, ProbeTimeout, TransportError
from .protocol import (
    JsonObject,
    ProtocolProfile,
    classify_message,
    decorate_modern_request,
    encode_mcp_header_value,
    make_initialize_request,
    make_initialized_notification,
    make_request,
    message_id,
    negotiated_version,
    profile_for,
)
from .redaction import redact_command, redact_url
from .transcript import EventRecorder, compact_json
from .transports import (
    HttpExchange,
    HttpRpcResult,
    HttpTransport,
    InboundMessage,
    StdioTransport,
)


PRIMITIVES: dict[str, tuple[str, str]] = {
    "tools": ("tools/list", "tools"),
    "resources": ("resources/list", "resources"),
    "resourceTemplates": ("resources/templates/list", "resourceTemplates"),
    "prompts": ("prompts/list", "prompts"),
}
MAX_PAGINATION_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PAGINATION_TOTAL_ITEMS = 100_000


@dataclass
class SessionConfig:
    protocol_version: str
    client_info: JsonObject = field(
        default_factory=lambda: {"name": "mcp-probe", "version": "0.2.0"}
    )
    client_capabilities: JsonObject = field(default_factory=dict)
    initialize_message: JsonObject | None = None
    send_initialized: bool = True
    roots: list[JsonObject] = field(default_factory=list)

    @property
    def profile(self) -> ProtocolProfile:
        return profile_for(self.protocol_version)


@dataclass
class EstablishResult:
    response: InboundMessage
    success: bool
    negotiated_version: str
    evidence: list[str]
    http_exchange: HttpExchange | None = None


@dataclass
class RpcOutcome:
    response: InboundMessage
    http_exchange: HttpExchange | None = None


@dataclass
class PaginationResult:
    primitive: str
    items: list[Any]
    pages: int
    responses: list[InboundMessage]
    cursors: list[str]
    complete: bool
    repeated_cursor: str | None = None
    malformed_cursor: Any = None
    page_limit_reached: bool = False
    error_response: InboundMessage | None = None


class McpSession:
    def __init__(
        self,
        transport: StdioTransport | HttpTransport,
        config: SessionConfig,
        recorder: EventRecorder,
    ) -> None:
        self.transport = transport
        self.config = config
        self.recorder = recorder
        self.profile = config.profile
        self.requested_version = config.protocol_version
        self.negotiated_version: str | None = None
        self.server_info: JsonObject = {}
        self.capabilities: JsonObject = {}
        self.supported_versions: list[str] = []
        self.discovered: dict[str, list[Any]] = {
            "tools": [],
            "resources": [],
            "resourceTemplates": [],
            "prompts": [],
        }
        self.established = False
        self._initialized_notification_sent = False
        self._pagination_total_bytes = 0
        self._pagination_total_items = 0
        self.auto_respond_server_requests = True
        if isinstance(self.transport, StdioTransport):
            self.transport.profile = self.profile
        self._install_server_request_handler()

    def start(self) -> None:
        if isinstance(self.transport, StdioTransport):
            self.transport.start()

    def establish(self, timeout: float) -> EstablishResult:
        self.start()
        if self.profile.modern and self.config.initialize_message is None:
            outcome = self.rpc("server/discover", {}, timeout)
            response = outcome.response
            success = _is_result(response.payload)
            evidence = [response.evidence]
            if success:
                result = response.payload["result"]
                versions = result.get("supportedVersions")
                success = (
                    result.get("resultType") == "complete"
                    and isinstance(versions, list)
                    and all(isinstance(item, str) for item in versions)
                    and self.requested_version in versions
                    and isinstance(result.get("capabilities"), dict)
                    and _finite_nonnegative_number(result.get("ttlMs"))
                    and result.get("cacheScope") in {"public", "private"}
                )
                if isinstance(versions, list):
                    self.supported_versions = [item for item in versions if isinstance(item, str)]
                if success:
                    self.capabilities = _object_or_empty(result.get("capabilities"))
                    self.server_info = _modern_server_info(result)
                    self.negotiated_version = self.requested_version
                    self.established = True
            return EstablishResult(
                response,
                success,
                self.negotiated_version or self.requested_version,
                evidence,
                outcome.http_exchange,
            )

        initialize = deepcopy(self.config.initialize_message) if self.config.initialize_message else None
        if initialize is None:
            request_id = self._next_id()
            initialize = make_initialize_request(
                self.requested_version,
                request_id,
                self.config.client_info,
                self.config.client_capabilities,
            )
        request_id = message_id(initialize)
        if request_id is None:
            raise ConfigurationError(
                "The initialize request must use a finite number or string id for automatic correlation."
            )
        outcome = self.send_exact_request(initialize, timeout)
        response = outcome.response
        evidence = [response.evidence]
        result_success = _is_result(response.payload)
        selected = negotiated_version(response.payload, self.requested_version)
        selected_profile = _compatible_legacy_profile(selected, self.transport)
        success = (
            result_success
            and isinstance(response.payload["result"].get("protocolVersion"), str)
            and selected_profile is not None
        )
        self.negotiated_version = selected if success else None
        if success and selected_profile is not None:
            self.profile = selected_profile
            if isinstance(self.transport, HttpTransport):
                self.transport.profile = selected_profile
                self.transport.protocol_version = selected
            else:
                self.transport.profile = selected_profile
            self._install_server_request_handler()
            result = response.payload["result"]
            self.capabilities = _object_or_empty(result.get("capabilities"))
            self.server_info = _object_or_empty(result.get("serverInfo"))
            self.supported_versions = [selected]
            self.established = True
            if self.config.send_initialized:
                notification = make_initialized_notification()
                notification_evidence = self.send_notification(notification, timeout)
                self._initialized_notification_sent = True
                if notification_evidence:
                    evidence.append(notification_evidence)
        return EstablishResult(
            response,
            success,
            selected,
            evidence,
            outcome.http_exchange,
        )

    def rpc(self, method: str, params: JsonObject | None, timeout: float) -> RpcOutcome:
        request_id = self._next_id()
        message = make_request(method, request_id, params)
        if self.profile.modern:
            message = decorate_modern_request(
                message,
                self.requested_version,
                self.config.client_info,
                self.config.client_capabilities,
            )
        return self.send_exact_request(message, timeout, transport_headers=self._derived_headers(message))

    def send_exact_request(
        self,
        message: JsonObject,
        timeout: float,
        *,
        transport_headers: dict[str, str] | None = None,
    ) -> RpcOutcome:
        request_id = message_id(message)
        if request_id is None:
            raise ConfigurationError(
                "Automatic request correlation requires a finite number or string JSON-RPC id."
            )
        if isinstance(self.transport, StdioTransport):
            self.transport.send_message(message, timeout)
            response = self.transport.wait_for_response(request_id, timeout)
            return RpcOutcome(response)
        exchange = self.transport.send_message(
            message,
            timeout,
            derived_headers=transport_headers,
        )
        if exchange.timed_out:
            raise HttpExchangeError(
                f"HTTP response body timed out before response id={request_id!r} "
                "could be accepted.",
                exchange,
                finding_code="HTTP_RESPONSE_TIMEOUT",
            )
        if not exchange.body_complete:
            raise HttpExchangeError(
                f"HTTP response body framing was incomplete or invalid for "
                f"response id={request_id!r}.",
                exchange,
                finding_code="HTTP_RESPONSE_FRAMING",
            )
        response = _matching_http_response(exchange, request_id)
        if response is None:
            raise HttpExchangeError(
                f"HTTP exchange contained no response matching id={request_id!r}.",
                exchange,
                finding_code="HTTP_RESPONSE_CORRELATION",
            )
        self._service_http_server_requests(exchange, timeout)
        return RpcOutcome(response, exchange)

    def send_notification(self, message: JsonObject, timeout: float) -> str | None:
        if isinstance(self.transport, StdioTransport):
            return self.transport.send_message(message, timeout)
        exchange = self.transport.send_message(message, timeout)
        return exchange.messages[-1].evidence if exchange.messages else self.recorder.last_reference()

    def send_raw_object(self, message: JsonObject, timeout: float) -> RpcOutcome | HttpExchange | str:
        """Send a payload without adding MCP metadata or changing its ID."""
        if isinstance(self.transport, StdioTransport):
            evidence = self.transport.send_message(message, timeout)
            if classify_message(message) != "request":
                return evidence
            request_id = message_id(message)
            if request_id is None:
                # Raw-wire mode deliberately permits MCP-invalid/unusual IDs
                # which cannot enter the normal typed correlation map.  Keep
                # the old probe behavior by surfacing the next peer message.
                return RpcOutcome(self.transport.receive(timeout))
            return RpcOutcome(self.transport.wait_for_response(request_id, timeout))
        exchange = self.transport.send_message(message, timeout)
        if classify_message(message) != "request":
            return exchange
        request_id = message_id(message)
        if request_id is None:
            return exchange
        response = _matching_http_response(exchange, request_id)
        if response is None:
            # Exact raw-wire probing must expose wrong-ID, malformed, and empty
            # HTTP exchanges rather than convert the evidence into an exception.
            return exchange
        return RpcOutcome(response, exchange)

    def paginate(
        self,
        primitive: str,
        timeout: float,
        *,
        max_pages: int = 100,
    ) -> PaginationResult:
        if primitive not in PRIMITIVES:
            raise ConfigurationError(f"Unknown discovery primitive: {primitive}")
        method, result_key = PRIMITIVES[primitive]
        items: list[Any] = []
        responses: list[InboundMessage] = []
        cursors: list[str] = []
        seen: set[str] = set()
        cursor: str | None = None
        for page_number in range(1, max_pages + 1):
            params: JsonObject = {}
            if cursor is not None:
                params["cursor"] = cursor
            outcome = self.rpc(method, params, timeout)
            response = outcome.response
            responses.append(response)
            payload = response.payload
            if not _is_result(payload):
                return PaginationResult(
                    primitive, items, page_number, responses, cursors, False, error_response=response
                )
            result = payload["result"]
            page_items = result.get(result_key)
            if isinstance(page_items, list):
                page_bytes = len(compact_json(page_items).encode("utf-8"))
                next_item_total = self._pagination_total_items + len(page_items)
                next_byte_total = self._pagination_total_bytes + page_bytes
                if (
                    next_item_total > MAX_PAGINATION_TOTAL_ITEMS
                    or next_byte_total > MAX_PAGINATION_TOTAL_BYTES
                ):
                    self.recorder.record(
                        "probe",
                        self.target_description()["transport"],
                        classification="resource_limit",
                        error=(
                            "Cumulative pagination exceeded the session safety limit."
                        ),
                        sourceEvidence=response.evidence,
                        maxItems=MAX_PAGINATION_TOTAL_ITEMS,
                        maxBytes=MAX_PAGINATION_TOTAL_BYTES,
                        attemptedItems=next_item_total,
                        attemptedBytes=next_byte_total,
                    )
                    raise TransportError(
                        "Cumulative pagination exceeded the session safety limit "
                        f"({MAX_PAGINATION_TOTAL_ITEMS} items / "
                        f"{MAX_PAGINATION_TOTAL_BYTES} bytes)."
                    )
                self._pagination_total_items = next_item_total
                self._pagination_total_bytes = next_byte_total
                items.extend(page_items)
            if "nextCursor" not in result:
                self.discovered[primitive] = items
                return PaginationResult(
                    primitive, items, page_number, responses, cursors, True
                )
            next_cursor = result.get("nextCursor")
            if not isinstance(next_cursor, str):
                self.discovered[primitive] = items
                return PaginationResult(
                    primitive,
                    items,
                    page_number,
                    responses,
                    cursors,
                    False,
                    malformed_cursor=next_cursor,
                )
            cursors.append(next_cursor)
            if next_cursor in seen:
                self.discovered[primitive] = items
                return PaginationResult(
                    primitive,
                    items,
                    page_number,
                    responses,
                    cursors,
                    False,
                    repeated_cursor=next_cursor,
                )
            seen.add(next_cursor)
            cursor = next_cursor
        self.discovered[primitive] = items
        return PaginationResult(
            primitive,
            items,
            max_pages,
            responses,
            cursors,
            False,
            page_limit_reached=True,
        )

    def discover_all(self, timeout: float, *, max_pages: int = 100) -> dict[str, PaginationResult]:
        return {
            primitive: self.paginate(primitive, timeout, max_pages=max_pages)
            for primitive in PRIMITIVES
        }

    def target_description(self) -> JsonObject:
        if isinstance(self.transport, StdioTransport):
            return {
                "transport": "stdio",
                "command": redact_command(self.transport.command),
                "environmentKeys": sorted(self.transport.env),
            }
        return {
            "transport": "http",
            "url": redact_url(self.transport.url),
            "headerNames": sorted(self.transport.extra_headers),
        }

    def close(self, timeout: float = 2.0) -> Any:
        if isinstance(self.transport, StdioTransport):
            return self.transport.close()
        return self.transport.close(timeout)

    def _next_id(self) -> int:
        return self.transport.next_id()

    def _install_server_request_handler(self) -> None:
        if not self.auto_respond_server_requests:
            self.transport.server_request_handler = None
            return
        if self.profile.modern and self.config.initialize_message is None:
            self.transport.server_request_handler = self._reject_modern_server_request
        else:
            self.transport.server_request_handler = self._handle_legacy_server_request

    def _reject_modern_server_request(self, inbound: InboundMessage) -> None:
        self.recorder.record(
            "probe",
            self.target_description()["transport"],
            classification="forbidden_server_request",
            payload=inbound.payload,
            sourceEvidence=inbound.evidence,
        )
        return None

    def _handle_legacy_server_request(self, inbound: InboundMessage) -> JsonObject | None:
        message = inbound.payload
        if not isinstance(message, dict):
            return None
        raw_request_id = message.get("id")
        request_id = message_id(message)
        method = message.get("method")
        params = message.get("params")
        valid = (
            message.get("jsonrpc") == "2.0"
            and request_id is not None
            and isinstance(method, str)
            and method != ""
            and "result" not in message
            and "error" not in message
            and ("params" not in message or isinstance(params, (dict, list)))
        )
        if not valid:
            response_id: str | int | float | None = (
                raw_request_id
                if message_id({"id": raw_request_id}) is not None
                else None
            )
            self.recorder.record(
                "probe",
                self.target_description()["transport"],
                classification="invalid_server_request",
                payload=message,
                sourceEvidence=inbound.evidence,
            )
            return {
                "jsonrpc": "2.0",
                "id": response_id,
                "error": {"code": -32600, "message": "Invalid Request"},
            }
        assert request_id is not None and isinstance(method, str)
        if method != "ping" and not self._initialized_notification_sent:
            self.recorder.record(
                "probe",
                self.target_description()["transport"],
                classification="pre_initialized_server_request",
                payload=message,
                sourceEvidence=inbound.evidence,
            )
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32002,
                    "message": "MCP client is not initialized.",
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "roots/list" and "roots" in self.config.client_capabilities:
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {"roots": deepcopy(self.config.roots)},
            }
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": -32601,
                "message": f"MCP Probe does not implement client method: {method}",
            },
        }

    def _service_http_server_requests(self, exchange: HttpExchange, timeout: float) -> None:
        if not isinstance(self.transport, HttpTransport):
            return
        self.transport._service_http_server_requests(
            exchange.messages,
            time.monotonic() + max(0.0, timeout),
            0,
            grouped=False,
        )

    def _derived_headers(self, message: JsonObject) -> dict[str, str]:
        if not self.profile.modern or not isinstance(self.transport, HttpTransport):
            return {}
        if message.get("method") != "tools/call":
            return {}
        params = message.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            return {}
        tool = next(
            (
                item
                for item in self.discovered.get("tools", [])
                if isinstance(item, dict) and item.get("name") == params["name"]
            ),
            None,
        )
        if not tool or not isinstance(tool.get("inputSchema"), dict):
            return {}
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        return _schema_argument_headers(tool["inputSchema"], arguments)


def _matching_http_response(
    exchange: HttpExchange, request_id: str | int | float
) -> InboundMessage | None:
    wanted_type = type(request_id)
    for message in exchange.messages:
        if message.classification != "response" or not isinstance(message.payload, dict):
            continue
        candidate = message.payload.get("id")
        if type(candidate) is wanted_type and candidate == request_id:
            return message
    return None


def _is_result(payload: Any) -> bool:
    return isinstance(payload, dict) and isinstance(payload.get("result"), dict)


def _finite_nonnegative_number(value: Any) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value >= 0
    )


def _object_or_empty(value: Any) -> JsonObject:
    return deepcopy(value) if isinstance(value, dict) else {}


def _modern_server_info(result: JsonObject) -> JsonObject:
    metadata = result.get("_meta")
    if not isinstance(metadata, dict):
        return {}
    return _object_or_empty(metadata.get("io.modelcontextprotocol/serverInfo"))


def _compatible_legacy_profile(
    selected: str,
    transport: StdioTransport | HttpTransport,
) -> ProtocolProfile | None:
    try:
        profile = profile_for(selected)
    except ConfigurationError:
        return None
    if profile.modern:
        return None
    if isinstance(transport, HttpTransport) and not profile.streamable_http:
        return None
    return profile


# RFC 9110 ``tchar``.  Colons, whitespace, and CR/LF are deliberately absent.
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _schema_argument_headers(schema: JsonObject, arguments: JsonObject) -> dict[str, str]:
    headers: dict[str, str] = {}

    def visit(node: Any, value: Any) -> None:
        if not isinstance(node, dict):
            return
        annotation = node.get("x-mcp-header")
        if annotation is not None and value is not None:
            if not isinstance(annotation, str) or not _HEADER_NAME.fullmatch(annotation):
                return
            if isinstance(value, bool):
                rendered = "true" if value else "false"
            elif type(value) is int and -(2**53 - 1) <= value <= 2**53 - 1:
                rendered = str(value)
            elif isinstance(value, str):
                rendered = value
            else:
                return
            headers[f"Mcp-Param-{annotation}"] = encode_mcp_header_value(rendered)
        properties = node.get("properties")
        if isinstance(properties, dict) and isinstance(value, dict):
            for key, child in properties.items():
                if key in value:
                    visit(child, value[key])

    visit(schema, arguments)
    return headers
