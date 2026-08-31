"""Conservative active-tool detection shared by user-controlled workflows."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def resembles_tools_call_method(value: Any) -> bool:
    return isinstance(value, str) and value.strip().casefold() == "tools/call"


def find_active_tool_calls(value: Any) -> list[str | None]:
    """Return literal tool names, or ``None`` when a call name is ambiguous.

    Field names are matched case- and surrounding-whitespace-insensitively.
    This is intentionally stricter than JSON-RPC: exact/malformed workflows
    target permissive peers which may normalize such keys before dispatch.
    """

    found: list[str | None] = []
    stack = [value]
    visited: set[int] = set()
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in visited:
                continue
            visited.add(identity)
            method_values = _field_values(current, "method")
            if any(resembles_tools_call_method(item) for item in method_values):
                params_values = _field_values(current, "params")
                names: list[Any] = []
                for params in params_values:
                    if isinstance(params, Mapping):
                        names.extend(_field_values(params, "name"))
                literal = [item for item in names if isinstance(item, str) and item]
                found.append(literal[0] if len(literal) == 1 and len(names) == 1 else None)
            stack.extend(current.values())
        elif isinstance(current, (list, tuple)):
            identity = id(current)
            if identity in visited:
                continue
            visited.add(identity)
            stack.extend(current)
    return found


def _field_values(value: Mapping[Any, Any], field: str) -> list[Any]:
    return [
        item
        for key, item in value.items()
        if isinstance(key, str) and key.strip().casefold() == field
    ]


__all__ = ["find_active_tool_calls", "resembles_tools_call_method"]
