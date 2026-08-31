"""Limited, dependency-free inspection of discovered MCP tool schemas.

This module intentionally performs only small structural checks whose meaning is
clear without a JSON Schema implementation.  It does *not* claim to validate a
schema against JSON Schema 2020-12 (or any other dialect).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal


FindingStatus = Literal["PASS", "FAIL", "WARN"]
FindingBasis = Literal["normative", "heuristic"]


@dataclass(frozen=True, slots=True)
class SchemaIssue:
    """One immutable, machine-readable tool schema inspection finding."""

    code: str
    status: FindingStatus
    basis: FindingBasis
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-serializable representation with stable field names."""

        return {
            "code": self.code,
            "status": self.status,
            "basis": self.basis,
            "path": self.path,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class _HeaderAnnotation:
    path: str
    value: Any
    schema_type: Any
    valid_placement: bool


# RFC 9110 ``tchar``.  MCP further requires x-mcp-header to be non-empty.
_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MCP_HEADER_TYPES = frozenset({"string", "integer", "boolean"})


def _pointer_part(value: object) -> str:
    """Escape one segment using JSON Pointer's two substitutions."""

    return str(value).replace("~", "~0").replace("/", "~1")


def _child_path(path: str, part: object) -> str:
    return f"{path}/{_pointer_part(part)}"


def _issue(
    code: str,
    status: FindingStatus,
    basis: FindingBasis,
    path: str,
    message: str,
) -> SchemaIssue:
    return SchemaIssue(code, status, basis, path, message)


def _collect_header_annotations(
    node: Any,
    path: str,
    *,
    on_properties_chain: bool,
    is_property_schema: bool,
    output: list[_HeaderAnnotation],
) -> None:
    """Collect x-mcp-header keys and whether they are statically reachable.

    The MCP HTTP binding permits the annotation only on property schemas that
    are reachable from the input schema root through ``properties`` keys alone.
    Traversing any other keyword permanently leaves that chain.
    """

    if isinstance(node, list):
        for index, value in enumerate(node):
            _collect_header_annotations(
                value,
                _child_path(path, index),
                on_properties_chain=False,
                is_property_schema=False,
                output=output,
            )
        return

    if not isinstance(node, dict):
        return

    if "x-mcp-header" in node:
        output.append(
            _HeaderAnnotation(
                path=_child_path(path, "x-mcp-header"),
                value=node["x-mcp-header"],
                schema_type=node.get("type"),
                valid_placement=on_properties_chain and is_property_schema,
            )
        )

    for key, value in node.items():
        if key == "x-mcp-header":
            continue
        key_path = _child_path(path, key)
        if key == "properties" and isinstance(value, dict):
            for property_name, property_schema in value.items():
                _collect_header_annotations(
                    property_schema,
                    _child_path(key_path, property_name),
                    on_properties_chain=on_properties_chain,
                    is_property_schema=True,
                    output=output,
                )
            continue
        if isinstance(value, (dict, list)):
            _collect_header_annotations(
                value,
                key_path,
                on_properties_chain=False,
                is_property_schema=False,
                output=output,
            )


def _inspect_required(input_schema: dict[str, Any], schema_path: str) -> list[SchemaIssue]:
    if "required" not in input_schema:
        return []

    required_path = _child_path(schema_path, "required")
    required = input_schema["required"]
    if not isinstance(required, list):
        return [
            _issue(
                "TOOL_INPUT_SCHEMA_REQUIRED_NOT_ARRAY",
                "FAIL",
                "normative",
                required_path,
                "inputSchema.required must be an array when present.",
            )
        ]

    issues: list[SchemaIssue] = []
    properties = input_schema.get("properties", {})
    known_properties = set(properties) if isinstance(properties, dict) else None
    seen: dict[str, str] = {}
    unknown_reported: set[str] = set()

    for index, entry in enumerate(required):
        entry_path = _child_path(required_path, index)
        if not isinstance(entry, str):
            issues.append(
                _issue(
                    "TOOL_INPUT_SCHEMA_REQUIRED_ENTRY_NOT_STRING",
                    "FAIL",
                    "normative",
                    entry_path,
                    "Every inputSchema.required entry must be a string.",
                )
            )
            continue

        first_path = seen.get(entry)
        if first_path is not None:
            issues.append(
                _issue(
                    "TOOL_INPUT_SCHEMA_REQUIRED_DUPLICATE",
                    "FAIL",
                    "normative",
                    entry_path,
                    f"Required property {entry!r} is duplicated; first occurrence is at {first_path}.",
                )
            )
        else:
            seen[entry] = entry_path

        # JSON Schema permits a required name that has no corresponding
        # ``properties`` entry.  It is still suspicious for an MCP tool input,
        # so report it explicitly as a portability heuristic rather than a
        # schema validity failure.
        if (
            known_properties is not None
            and entry not in known_properties
            and entry not in unknown_reported
        ):
            issues.append(
                _issue(
                    "TOOL_INPUT_SCHEMA_REQUIRED_UNKNOWN",
                    "WARN",
                    "heuristic",
                    entry_path,
                    f"Required property {entry!r} is not declared in inputSchema.properties.",
                )
            )
            unknown_reported.add(entry)

    return issues


def _inspect_headers(input_schema: dict[str, Any], schema_path: str) -> list[SchemaIssue]:
    annotations: list[_HeaderAnnotation] = []
    _collect_header_annotations(
        input_schema,
        schema_path,
        on_properties_chain=True,
        is_property_schema=False,
        output=annotations,
    )

    issues: list[SchemaIssue] = []
    seen_names: dict[str, str] = {}
    for annotation in annotations:
        if not annotation.valid_placement:
            issues.append(
                _issue(
                    "TOOL_X_MCP_HEADER_MISPLACED",
                    "FAIL",
                    "normative",
                    annotation.path,
                    "x-mcp-header must be on a property schema reachable from the root through properties keys only.",
                )
            )

        if not isinstance(annotation.value, str):
            issues.append(
                _issue(
                    "TOOL_X_MCP_HEADER_NOT_STRING",
                    "FAIL",
                    "normative",
                    annotation.path,
                    "x-mcp-header must be a non-empty HTTP field-name string.",
                )
            )
            continue

        if not annotation.value or _HTTP_TOKEN.fullmatch(annotation.value) is None:
            issues.append(
                _issue(
                    "TOOL_X_MCP_HEADER_INVALID_NAME",
                    "FAIL",
                    "normative",
                    annotation.path,
                    "x-mcp-header must be a non-empty RFC 9110 field-name token.",
                )
            )
            continue

        if annotation.valid_placement and annotation.schema_type not in _MCP_HEADER_TYPES:
            issues.append(
                _issue(
                    "TOOL_X_MCP_HEADER_INVALID_TYPE",
                    "FAIL",
                    "normative",
                    annotation.path,
                    "x-mcp-header is allowed only on string, integer, or boolean property schemas.",
                )
            )

        normalized = annotation.value.casefold()
        first_path = seen_names.get(normalized)
        if first_path is not None:
            issues.append(
                _issue(
                    "TOOL_X_MCP_HEADER_DUPLICATE",
                    "FAIL",
                    "normative",
                    annotation.path,
                    f"x-mcp-header {annotation.value!r} duplicates the case-insensitive name at {first_path}.",
                )
            )
        else:
            seen_names[normalized] = annotation.path

    return issues


def inspect_tool_schemas(tools: Any) -> tuple[SchemaIssue, ...]:
    """Inspect decoded ``tools/list`` descriptors using limited stable rules.

    A non-empty, clean tool list returns one aggregate ``PASS`` finding.  An
    empty list returns no finding so callers can represent it as ``SKIP``.  Any
    failure or warning suppresses the aggregate pass.
    """

    if not isinstance(tools, list):
        return (
            _issue(
                "TOOL_LIST_NOT_ARRAY",
                "FAIL",
                "normative",
                "/tools",
                "The tools collection must be an array.",
            ),
        )
    if not tools:
        return ()

    issues: list[SchemaIssue] = []
    seen_names: dict[str, str] = {}

    for index, tool in enumerate(tools):
        tool_path = _child_path("/tools", index)
        if not isinstance(tool, dict):
            issues.append(
                _issue(
                    "TOOL_DESCRIPTOR_NOT_OBJECT",
                    "FAIL",
                    "normative",
                    tool_path,
                    "Each tool descriptor must be an object.",
                )
            )
            continue

        name_path = _child_path(tool_path, "name")
        if "name" not in tool:
            issues.append(
                _issue(
                    "TOOL_NAME_MISSING",
                    "FAIL",
                    "normative",
                    name_path,
                    "Tool descriptor is missing its required name.",
                )
            )
        elif not isinstance(tool["name"], str):
            issues.append(
                _issue(
                    "TOOL_NAME_NOT_STRING",
                    "FAIL",
                    "normative",
                    name_path,
                    "Tool name must be a string.",
                )
            )
        else:
            name = tool["name"]
            if not name:
                issues.append(
                    _issue(
                        "TOOL_NAME_EMPTY",
                        "WARN",
                        "normative",
                        name_path,
                        "Tool names should contain at least one character.",
                    )
                )
            first_path = seen_names.get(name)
            if first_path is not None:
                issues.append(
                    _issue(
                        "TOOL_NAME_DUPLICATE",
                        "WARN",
                        "normative",
                        name_path,
                        f"Tool name {name!r} is duplicated; first occurrence is at {first_path}.",
                    )
                )
            else:
                seen_names[name] = name_path

        input_path = _child_path(tool_path, "inputSchema")
        if "inputSchema" not in tool:
            issues.append(
                _issue(
                    "TOOL_INPUT_SCHEMA_MISSING",
                    "FAIL",
                    "normative",
                    input_path,
                    "Tool descriptor is missing its required inputSchema.",
                )
            )
        elif not isinstance(tool["inputSchema"], dict):
            issues.append(
                _issue(
                    "TOOL_INPUT_SCHEMA_NOT_OBJECT",
                    "FAIL",
                    "normative",
                    input_path,
                    "Tool inputSchema must be a JSON Schema object.",
                )
            )
        else:
            input_schema = tool["inputSchema"]
            if "type" in input_schema and input_schema["type"] != "object":
                issues.append(
                    _issue(
                        "TOOL_INPUT_SCHEMA_TYPE_NOT_OBJECT",
                        "FAIL",
                        "normative",
                        _child_path(input_path, "type"),
                        "Tool inputSchema.type must be 'object' when present.",
                    )
                )

            if "properties" in input_schema and not isinstance(
                input_schema["properties"], dict
            ):
                issues.append(
                    _issue(
                        "TOOL_INPUT_SCHEMA_PROPERTIES_NOT_OBJECT",
                        "FAIL",
                        "normative",
                        _child_path(input_path, "properties"),
                        "inputSchema.properties must be an object when present.",
                    )
                )

            issues.extend(_inspect_required(input_schema, input_path))
            issues.extend(_inspect_headers(input_schema, input_path))

        output_path = _child_path(tool_path, "outputSchema")
        if "outputSchema" in tool and not isinstance(tool["outputSchema"], dict):
            issues.append(
                _issue(
                    "TOOL_OUTPUT_SCHEMA_NOT_OBJECT",
                    "FAIL",
                    "normative",
                    output_path,
                    "Tool outputSchema must be a JSON Schema object when present.",
                )
            )

    if issues:
        return tuple(issues)
    return (
        _issue(
            "TOOL_SCHEMA_INSPECTION",
            "PASS",
            "normative",
            "/tools",
            f"No issues were found by the limited structural checks for {len(tools)} tool descriptor(s).",
        ),
    )


__all__ = ["FindingBasis", "FindingStatus", "SchemaIssue", "inspect_tool_schemas"]
