"""MCP era profiles and small JSON-RPC helpers.

This module deliberately does not validate or normalize arbitrary raw messages.
Callers that ask for exact-wire behavior must be able to bypass these helpers.
"""

from __future__ import annotations

import base64
import json
import math
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

from .errors import ConfigurationError


JsonObject = dict[str, Any]

# These are parser safety limits, not MCP protocol limits.  They apply to every
# structured JSON input path so a small wire body cannot create an excessively
# deep or node-heavy Python object graph.
MAX_JSON_DEPTH = 100
MAX_JSON_NODES = 100_000

LATEST_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28",
)


@dataclass(frozen=True)
class ProtocolProfile:
    version: str
    era: str
    initialize: bool
    initialized_notification: bool
    streamable_http: bool
    http_sessions: bool
    protocol_header: bool
    server_requests: bool
    batch_receive_required: bool = False

    @property
    def modern(self) -> bool:
        return self.era == "modern"


PROTOCOL_PROFILES: dict[str, ProtocolProfile] = {
    "2024-11-05": ProtocolProfile(
        "2024-11-05", "legacy", True, True, False, False, False, True
    ),
    "2025-03-26": ProtocolProfile(
        "2025-03-26", "legacy", True, True, True, True, False, True, True
    ),
    "2025-06-18": ProtocolProfile(
        "2025-06-18", "legacy", True, True, True, True, True, True
    ),
    "2025-11-25": ProtocolProfile(
        "2025-11-25", "legacy", True, True, True, True, True, True
    ),
    "2026-07-28": ProtocolProfile(
        "2026-07-28", "modern", False, False, True, False, True, False
    ),
}


def profile_for(version: str) -> ProtocolProfile:
    try:
        return PROTOCOL_PROFILES[version]
    except KeyError as exc:
        supported = ", ".join(SUPPORTED_PROTOCOL_VERSIONS)
        raise ConfigurationError(
            f"Unsupported protocol profile {version!r}. Supported versions: {supported}"
        ) from exc


def make_request(
    method: str, request_id: str | int | float, params: JsonObject | None = None
) -> JsonObject:
    message: JsonObject = {"jsonrpc": "2.0", "id": request_id, "method": method}
    if params is not None:
        message["params"] = params
    return message


def make_notification(method: str, params: JsonObject | None = None) -> JsonObject:
    message: JsonObject = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        message["params"] = params
    return message


def make_initialize_request(
    version: str,
    request_id: str | int | float,
    client_info: JsonObject,
    client_capabilities: JsonObject,
) -> JsonObject:
    return make_request(
        "initialize",
        request_id,
        {
            "protocolVersion": version,
            "capabilities": deepcopy(client_capabilities),
            "clientInfo": deepcopy(client_info),
        },
    )


def make_initialized_notification() -> JsonObject:
    return make_notification("notifications/initialized")


def classify_message(value: Any) -> str:
    """Classify a decoded wire value without claiming full schema validity."""
    if not isinstance(value, dict):
        return "invalid"
    has_method = isinstance(value.get("method"), str)
    has_id = "id" in value
    has_result = "result" in value
    has_error = "error" in value
    if has_method:
        return "request" if has_id else "notification"
    if has_result ^ has_error:
        return "response"
    return "invalid"


def message_id(value: Any) -> str | int | float | None:
    if not isinstance(value, dict):
        return None
    candidate = value.get("id")
    if isinstance(candidate, str) or type(candidate) is int:
        return candidate
    if isinstance(candidate, float) and math.isfinite(candidate):
        return candidate
    return None


def message_method(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    candidate = value.get("method")
    return candidate if isinstance(candidate, str) else None


def modern_metadata(
    version: str,
    client_info: JsonObject,
    client_capabilities: JsonObject,
) -> JsonObject:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": deepcopy(client_info),
        "io.modelcontextprotocol/clientCapabilities": deepcopy(client_capabilities),
    }


def decorate_modern_request(
    message: JsonObject,
    version: str,
    client_info: JsonObject,
    client_capabilities: JsonObject,
) -> JsonObject:
    """Return a copy with the required 2026-07-28 per-request metadata."""
    if classify_message(message) != "request":
        raise ConfigurationError("Modern metadata can only be added to a JSON-RPC request.")
    decorated = deepcopy(message)
    params = decorated.get("params")
    if params is None:
        params = {}
        decorated["params"] = params
    if not isinstance(params, dict):
        raise ConfigurationError("Modern MCP request params must be an object so _meta can be attached.")
    existing_meta = params.get("_meta")
    if existing_meta is None:
        existing_meta = {}
        params["_meta"] = existing_meta
    if not isinstance(existing_meta, dict):
        raise ConfigurationError("Modern MCP request params._meta must be an object.")
    required = modern_metadata(version, client_info, client_capabilities)
    for key, value in required.items():
        existing_meta.setdefault(key, value)
    return decorated


def encode_mcp_header_value(value: str) -> str:
    """Encode 2026-07-28 mirrored values using the specified sentinel."""
    plain = all(ch == "\t" or 0x20 <= ord(ch) <= 0x7E for ch in value)
    ambiguous = value.startswith("=?base64?") and value.endswith("?=")
    if plain and value == value.strip() and not ambiguous:
        return value
    encoded = base64.b64encode(value.encode("utf-8")).decode("ascii")
    return f"=?base64?{encoded}?="


def modern_http_headers(message: JsonObject, version: str) -> dict[str, str]:
    method = message_method(message)
    if not method:
        return {"MCP-Protocol-Version": version}
    if not all(0x21 <= ord(character) <= 0x7E for character in method):
        raise ConfigurationError(
            "Modern HTTP cannot mirror this JSON-RPC method in Mcp-Method: "
            "only non-space visible ASCII is permitted."
        )
    headers = {
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }
    params = message.get("params")
    if isinstance(params, dict) and method in {"tools/call", "prompts/get", "resources/read"}:
        source_key = "uri" if method == "resources/read" else "name"
        name = params.get(source_key)
        if isinstance(name, str):
            headers["Mcp-Name"] = encode_mcp_header_value(name)
    return headers


def negotiated_version(response: Any, fallback: str) -> str:
    if not isinstance(response, dict):
        return fallback
    result = response.get("result")
    if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
        return result["protocolVersion"]
    return fallback


def response_error_code(response: Any) -> int | None:
    if not isinstance(response, dict) or not isinstance(response.get("error"), dict):
        return None
    code = response["error"].get("code")
    return code if isinstance(code, int) and not isinstance(code, bool) else None


def strict_json_loads(text: str) -> Any:
    """Decode finite JSON with unique names and a bounded object graph.

    The standard library decoder intentionally accepts duplicate object names
    and JavaScript numeric constants by default.  Both are ambiguous on a
    protocol wire, so the probe rejects them consistently across transports,
    scenarios, replay, and transcript loading.
    """

    def finite_float(value: str) -> float:
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("number is outside the finite JSON range")
        return number

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-standard JSON numeric constant {value}")

    def unique_object(pairs: list[tuple[str, Any]]) -> JsonObject:
        result: JsonObject = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate object key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(
            text,
            parse_float=finite_float,
            parse_constant=reject_constant,
            object_pairs_hook=unique_object,
        )
    except RecursionError as exc:
        raise ValueError(
            f"JSON nesting exceeds the supported depth of {MAX_JSON_DEPTH}"
        ) from exc

    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError(
                f"JSON value exceeds the supported node count of {MAX_JSON_NODES}"
            )
        if depth > MAX_JSON_DEPTH:
            raise ValueError(
                f"JSON nesting exceeds the supported depth of {MAX_JSON_DEPTH}"
            )
        if isinstance(node, dict):
            stack.extend((child, depth + 1) for child in node.values())
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node)
    return value
