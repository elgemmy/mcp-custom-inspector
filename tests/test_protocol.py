from __future__ import annotations

import unittest

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.protocol import (
    LATEST_PROTOCOL_VERSION,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
    SUPPORTED_PROTOCOL_VERSIONS,
    classify_message,
    decorate_modern_request,
    encode_mcp_header_value,
    make_initialize_request,
    message_id,
    modern_http_headers,
    profile_for,
    strict_json_loads,
)


class ProtocolProfileTests(unittest.TestCase):
    def test_supported_revisions_and_lifecycle_eras_are_explicit(self) -> None:
        self.assertEqual(
            SUPPORTED_PROTOCOL_VERSIONS,
            (
                "2024-11-05",
                "2025-03-26",
                "2025-06-18",
                "2025-11-25",
                "2026-07-28",
            ),
        )
        self.assertEqual(LATEST_PROTOCOL_VERSION, "2026-07-28")
        for version in SUPPORTED_PROTOCOL_VERSIONS[:-1]:
            profile = profile_for(version)
            self.assertTrue(profile.initialize)
            self.assertTrue(profile.initialized_notification)
            self.assertTrue(profile.server_requests)
        modern = profile_for("2026-07-28")
        self.assertFalse(modern.initialize)
        self.assertFalse(modern.initialized_notification)
        self.assertFalse(modern.server_requests)
        self.assertTrue(modern.modern)

    def test_streamable_http_and_protocol_header_boundaries_are_explicit(self) -> None:
        self.assertFalse(profile_for("2024-11-05").streamable_http)
        self.assertTrue(profile_for("2025-03-26").streamable_http)
        self.assertFalse(profile_for("2025-03-26").protocol_header)
        self.assertTrue(profile_for("2025-06-18").protocol_header)
        self.assertFalse(profile_for("2026-07-28").http_sessions)

    def test_unknown_revision_is_a_configuration_error(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "Unsupported protocol profile"):
            profile_for("2099-01-01")


class ProtocolMessageTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_names_and_non_finite_numbers(self) -> None:
        for text in ('{"id":1,"id":2}', '{"value":NaN}', '{"value":Infinity}', '1e9999'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    strict_json_loads(text)

    def test_strict_json_enforces_depth_and_node_bounds_iteratively(self) -> None:
        within_depth = "[" * (MAX_JSON_DEPTH - 1) + "0" + "]" * (MAX_JSON_DEPTH - 1)
        self.assertIsInstance(strict_json_loads(within_depth), list)
        too_deep = "[" * MAX_JSON_DEPTH + "0" + "]" * MAX_JSON_DEPTH
        with self.assertRaisesRegex(ValueError, "depth"):
            strict_json_loads(too_deep)

        too_many_nodes = "[" + ",".join("0" for _ in range(MAX_JSON_NODES)) + "]"
        with self.assertRaisesRegex(ValueError, "node count"):
            strict_json_loads(too_many_nodes)

    def test_initialize_builder_keeps_caller_values(self) -> None:
        message = make_initialize_request(
            "2025-11-25",
            "init-1",
            {"name": "test", "version": "1"},
            {"roots": {"listChanged": True}},
        )
        self.assertEqual(message["method"], "initialize")
        self.assertEqual(message["params"]["protocolVersion"], "2025-11-25")
        self.assertEqual(message_id(message), "init-1")

    def test_modern_metadata_is_added_without_mutating_input(self) -> None:
        original = {"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}
        decorated = decorate_modern_request(
            original,
            "2026-07-28",
            {"name": "probe", "version": "1"},
            {"roots": {}},
        )
        self.assertNotIn("_meta", original["params"])
        meta = decorated["params"]["_meta"]
        self.assertEqual(meta["io.modelcontextprotocol/protocolVersion"], "2026-07-28")
        self.assertEqual(meta["io.modelcontextprotocol/clientCapabilities"], {"roots": {}})

    def test_modern_metadata_refuses_non_request_and_non_object_params(self) -> None:
        with self.assertRaises(ConfigurationError):
            decorate_modern_request(
                {"jsonrpc": "2.0", "method": "notice"}, "2026-07-28", {}, {}
            )
        with self.assertRaises(ConfigurationError):
            decorate_modern_request(
                {"jsonrpc": "2.0", "id": 1, "method": "x", "params": []},
                "2026-07-28",
                {},
                {},
            )

    def test_jsonrpc_classification_and_ids_do_not_conflate_booleans(self) -> None:
        self.assertEqual(classify_message({"jsonrpc": "2.0", "id": 1, "result": {}}), "response")
        self.assertEqual(classify_message({"jsonrpc": "2.0", "id": 1, "method": "x"}), "request")
        self.assertEqual(classify_message({"jsonrpc": "2.0", "method": "x"}), "notification")
        self.assertEqual(classify_message(42), "invalid")
        self.assertIsNone(message_id({"id": True}))

    def test_modern_http_headers_include_method_and_encoded_name(self) -> None:
        message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "tool/\N{SNOWMAN}"},
        }
        headers = modern_http_headers(message, "2026-07-28")
        self.assertEqual(headers["MCP-Protocol-Version"], "2026-07-28")
        self.assertEqual(headers["Mcp-Method"], "tools/call")
        self.assertTrue(headers["Mcp-Name"].startswith("=?base64?"))
        self.assertEqual(encode_mcp_header_value("plain-name"), "plain-name")


if __name__ == "__main__":
    unittest.main()
