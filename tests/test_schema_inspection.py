from __future__ import annotations

import dataclasses
import unittest

from mcp_probe_core.schema_inspection import SchemaIssue, inspect_tool_schemas


def tool(name: str = "echo") -> dict[str, object]:
    return {
        "name": name,
        "description": "Fixture tool",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    }


def by_code(issues: tuple[SchemaIssue, ...], code: str) -> list[SchemaIssue]:
    return [issue for issue in issues if issue.code == code]


class SchemaInspectionTests(unittest.TestCase):
    def test_clean_non_empty_list_returns_one_immutable_pass(self) -> None:
        issues = inspect_tool_schemas([tool()])

        self.assertEqual(1, len(issues))
        self.assertEqual("TOOL_SCHEMA_INSPECTION", issues[0].code)
        self.assertEqual("PASS", issues[0].status)
        self.assertEqual("normative", issues[0].basis)
        self.assertEqual("/tools", issues[0].path)
        self.assertEqual(
            {
                "code": "TOOL_SCHEMA_INSPECTION",
                "status": "PASS",
                "basis": "normative",
                "path": "/tools",
                "message": issues[0].message,
            },
            issues[0].to_dict(),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            issues[0].code = "CHANGED"  # type: ignore[misc]

    def test_empty_list_returns_no_issue_for_caller_skip(self) -> None:
        self.assertEqual((), inspect_tool_schemas([]))

    def test_malformed_tool_collection_and_descriptor_are_reported(self) -> None:
        collection_issue = inspect_tool_schemas({"name": "not-a-list"})
        descriptor_issue = inspect_tool_schemas(["not-an-object"])

        self.assertEqual("TOOL_LIST_NOT_ARRAY", collection_issue[0].code)
        self.assertEqual("/tools", collection_issue[0].path)
        self.assertEqual("TOOL_DESCRIPTOR_NOT_OBJECT", descriptor_issue[0].code)
        self.assertEqual("/tools/0", descriptor_issue[0].path)

    def test_missing_non_string_empty_and_duplicate_names_have_stable_findings(self) -> None:
        missing = tool()
        del missing["name"]
        non_string = tool()
        non_string["name"] = 7
        issues = inspect_tool_schemas([missing, non_string, tool(""), tool("dup"), tool("dup")])

        self.assertEqual("FAIL", by_code(issues, "TOOL_NAME_MISSING")[0].status)
        self.assertEqual("/tools/0/name", by_code(issues, "TOOL_NAME_MISSING")[0].path)
        self.assertEqual("TOOL_NAME_NOT_STRING", by_code(issues, "TOOL_NAME_NOT_STRING")[0].code)
        self.assertEqual("WARN", by_code(issues, "TOOL_NAME_EMPTY")[0].status)
        duplicate = by_code(issues, "TOOL_NAME_DUPLICATE")[0]
        self.assertEqual("WARN", duplicate.status)
        self.assertEqual("normative", duplicate.basis)
        self.assertEqual("/tools/4/name", duplicate.path)
        self.assertIn("/tools/3/name", duplicate.message)

    def test_input_schema_presence_shape_and_type_are_checked(self) -> None:
        missing = tool("missing")
        del missing["inputSchema"]
        non_object = tool("non-object")
        non_object["inputSchema"] = []
        wrong_type = tool("wrong-type")
        wrong_type["inputSchema"] = {"type": "array"}
        malformed_properties = tool("bad-properties")
        malformed_properties["inputSchema"] = {"type": "object", "properties": []}

        issues = inspect_tool_schemas([missing, non_object, wrong_type, malformed_properties])

        expected = {
            "TOOL_INPUT_SCHEMA_MISSING": "/tools/0/inputSchema",
            "TOOL_INPUT_SCHEMA_NOT_OBJECT": "/tools/1/inputSchema",
            "TOOL_INPUT_SCHEMA_TYPE_NOT_OBJECT": "/tools/2/inputSchema/type",
            "TOOL_INPUT_SCHEMA_PROPERTIES_NOT_OBJECT": "/tools/3/inputSchema/properties",
        }
        for code, path in expected.items():
            issue = by_code(issues, code)[0]
            self.assertEqual("FAIL", issue.status)
            self.assertEqual("normative", issue.basis)
            self.assertEqual(path, issue.path)

    def test_required_entries_distinguish_invalidity_from_portability_warning(self) -> None:
        non_array = tool("non-array")
        non_array["inputSchema"] = {"type": "object", "required": "text"}
        entries = tool("entries")
        entries["inputSchema"] = {
            "type": "object",
            "properties": {"known": {"type": "string"}},
            "required": ["known", 3, "unknown", "known"],
        }

        issues = inspect_tool_schemas([non_array, entries])

        self.assertEqual(
            "/tools/0/inputSchema/required",
            by_code(issues, "TOOL_INPUT_SCHEMA_REQUIRED_NOT_ARRAY")[0].path,
        )
        self.assertEqual(
            "/tools/1/inputSchema/required/1",
            by_code(issues, "TOOL_INPUT_SCHEMA_REQUIRED_ENTRY_NOT_STRING")[0].path,
        )
        duplicate = by_code(issues, "TOOL_INPUT_SCHEMA_REQUIRED_DUPLICATE")[0]
        self.assertEqual("FAIL", duplicate.status)
        self.assertEqual("normative", duplicate.basis)
        self.assertEqual("/tools/1/inputSchema/required/3", duplicate.path)
        unknown = by_code(issues, "TOOL_INPUT_SCHEMA_REQUIRED_UNKNOWN")[0]
        self.assertEqual("WARN", unknown.status)
        self.assertEqual("heuristic", unknown.basis)
        self.assertEqual("/tools/1/inputSchema/required/2", unknown.path)

    def test_output_schema_must_be_an_object_when_present(self) -> None:
        descriptor = tool()
        descriptor["outputSchema"] = None

        issue = by_code(inspect_tool_schemas([descriptor]), "TOOL_OUTPUT_SCHEMA_NOT_OBJECT")[0]

        self.assertEqual("FAIL", issue.status)
        self.assertEqual("/tools/0/outputSchema", issue.path)

    def test_valid_nested_x_mcp_headers_pass(self) -> None:
        descriptor = tool()
        descriptor["inputSchema"] = {
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "nested": {
                    "type": "object",
                    "properties": {
                        "enabled": {"type": "boolean", "x-mcp-header": "Enabled"},
                        "count": {"type": "integer", "x-mcp-header": "Count"},
                    },
                },
            },
        }

        issues = inspect_tool_schemas([descriptor])

        self.assertEqual("TOOL_SCHEMA_INSPECTION", issues[0].code)

    def test_malformed_x_mcp_header_annotations_report_each_rule(self) -> None:
        descriptor = tool()
        descriptor["inputSchema"] = {
            "type": "object",
            "x-mcp-header": "AtRoot",
            "properties": {
                "not_string": {"type": "string", "x-mcp-header": 4},
                "bad_name": {"type": "string", "x-mcp-header": "Bad Header"},
                "bad_type": {"type": "number", "x-mcp-header": "Metric"},
                "one": {"type": "string", "x-mcp-header": "Tenant"},
                "two": {"type": "string", "x-mcp-header": "tenant"},
                "composed": {
                    "oneOf": [
                        {"type": "string", "x-mcp-header": "ViaComposition"}
                    ]
                },
            },
        }

        issues = inspect_tool_schemas([descriptor])

        self.assertEqual(2, len(by_code(issues, "TOOL_X_MCP_HEADER_MISPLACED")))
        self.assertEqual(1, len(by_code(issues, "TOOL_X_MCP_HEADER_NOT_STRING")))
        self.assertEqual(1, len(by_code(issues, "TOOL_X_MCP_HEADER_INVALID_NAME")))
        self.assertEqual(1, len(by_code(issues, "TOOL_X_MCP_HEADER_INVALID_TYPE")))
        duplicate = by_code(issues, "TOOL_X_MCP_HEADER_DUPLICATE")[0]
        self.assertEqual("/tools/0/inputSchema/properties/two/x-mcp-header", duplicate.path)
        self.assertIn("/tools/0/inputSchema/properties/one/x-mcp-header", duplicate.message)

    def test_paths_use_json_pointer_escaping(self) -> None:
        descriptor = tool()
        descriptor["inputSchema"] = {
            "type": "object",
            "properties": {
                "a/b~c": {"type": "string", "x-mcp-header": "Bad Header"}
            },
        }

        issue = by_code(inspect_tool_schemas([descriptor]), "TOOL_X_MCP_HEADER_INVALID_NAME")[0]

        self.assertEqual(
            "/tools/0/inputSchema/properties/a~1b~0c/x-mcp-header",
            issue.path,
        )

    def test_inspector_does_not_claim_full_json_schema_validation(self) -> None:
        descriptor = tool()
        descriptor["inputSchema"] = {
            "type": "object",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "properties": {
                "anything": True,
                "complex": {"allOf": [{"type": "string"}, {"minLength": 1}]},
            },
            "unevaluatedProperties": False,
        }
        descriptor["outputSchema"] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "array",
            "items": {"type": "string"},
        }

        issues = inspect_tool_schemas([descriptor])

        self.assertEqual("TOOL_SCHEMA_INSPECTION", issues[0].code)


if __name__ == "__main__":
    unittest.main()
