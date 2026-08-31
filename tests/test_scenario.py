from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.scenario import (
    SCENARIO_SCHEMA,
    load_scenario,
    parse_scenario,
    run_scenario,
)
from mcp_probe_core.session import McpSession, SessionConfig
from mcp_probe_core.transcript import EventRecorder
from mcp_probe_core.transports import HttpTransport, StdioTransport
from tests.fixtures.mcp_fixture import running_http_fixture, stdio_fixture_command


LEGACY_VERSION = "2025-06-18"


def definition(actions: list[dict], **extra: object):
    return parse_scenario(
        {
            "schema": SCENARIO_SCHEMA,
            "name": "fixture scenario",
            "actions": actions,
            **extra,
        }
    )


def stdio_session(
    profile: str = "stdio-good-legacy",
    *,
    capabilities: dict | None = None,
    version: str = LEGACY_VERSION,
) -> tuple[McpSession, EventRecorder]:
    recorder = EventRecorder()
    transport = StdioTransport(
        stdio_fixture_command(profile),
        {},
        recorder,
        shutdown_timeout=0.25,
    )
    config = SessionConfig(
        protocol_version=version,
        client_capabilities=capabilities or {},
    )
    return McpSession(transport, config, recorder), recorder


def http_session(url: str, recorder: EventRecorder) -> McpSession:
    config = SessionConfig(protocol_version=LEGACY_VERSION)
    transport = HttpTransport(url, {}, recorder, config.profile)
    return McpSession(transport, config, recorder)


class ScenarioValidationTests(unittest.TestCase):
    def test_minimal_valid_scenario_and_timeout_precedence_data(self) -> None:
        scenario = definition(
            [
                {"action": "start"},
                {"action": "request", "method": "ping", "timeout": 0.25},
                {"action": "expect", "kind": "result"},
            ],
            timeout=1.5,
            description="small deterministic flow",
        )
        self.assertEqual(scenario.timeout, 1.5)
        self.assertNotIn("timeout", scenario.actions[0])
        self.assertEqual(scenario.actions[1]["timeout"], 0.25)
        self.assertEqual(scenario.actions[2]["assertions"], [])

    def test_unknown_fields_and_bad_order_are_rejected(self) -> None:
        cases = [
            [{"action": "request", "method": "ping", "surprise": True}],
            [{"action": "expect", "kind": "result"}],
            [
                {"action": "disconnect"},
                {"action": "request", "method": "ping"},
            ],
            [
                {"action": "start"},
                {"action": "connect"},
            ],
        ]
        for actions in cases:
            with self.subTest(actions=actions), self.assertRaises(ConfigurationError):
                definition(actions)

    def test_assertions_are_small_and_json_pointer_based(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "exactly one assertion"):
            definition(
                [
                    {"action": "request", "method": "ping"},
                    {
                        "action": "expect",
                        "kind": "result",
                        "assertions": [
                            {"path": "/result", "type": "object", "length": 0}
                        ],
                    },
                ]
            )
        with self.assertRaisesRegex(ConfigurationError, "JSON Pointer escape"):
            definition(
                [
                    {"action": "request", "method": "ping"},
                    {
                        "action": "expect",
                        "kind": "result",
                        "assertions": [{"path": "/bad~2path", "exists": True}],
                    },
                ]
            )

    def test_invalid_base64_is_rejected_before_connecting(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "valid base64"):
            definition(
                [
                    {
                        "action": "malformed",
                        "data": "not base64!",
                        "encoding": "base64",
                    }
                ]
            )

    def test_raw_http_header_grammar_prevents_request_injection(self) -> None:
        invalid_actions = [
            {
                "action": "malformed",
                "data": "{}",
                "headers": {"Bad Header": "value"},
            },
            {
                "action": "malformed",
                "data": "{}",
                "headers": {"X-Test": "safe\r\nInjected: value"},
            },
            {
                "action": "malformed",
                "data": "{}",
                "headers": {"X-Test": "one", "x-test": "two"},
            },
            {
                "action": "malformed",
                "data": "{}",
                "contentType": "application/json\nX-Bad: value",
            },
        ]
        for action in invalid_actions:
            with self.subTest(action=action), self.assertRaises(ConfigurationError):
                definition([action])

    def test_loader_rejects_duplicate_keys_and_nonstandard_numbers(self) -> None:
        for body in (
            '{"schema":"mcp-probe.scenario/v1","name":"x","name":"y","actions":[]}',
            '{"schema":"mcp-probe.scenario/v1","name":"x","timeout":NaN,"actions":[{"action":"start"}]}',
        ):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "scenario.json"
                path.write_text(body, encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    load_scenario(path)


class StdioScenarioTests(unittest.TestCase):
    def test_modern_establishment_and_requests_use_stateless_metadata(self) -> None:
        session, recorder = stdio_session(
            "stdio-good-modern", version="2026-07-28"
        )
        scenario = definition(
            [
                {"action": "connect", "establish": True},
                {
                    "action": "expect",
                    "kind": "result",
                    "assertions": [
                        {"path": "/result/resultType", "equals": "serverDiscovery"}
                    ],
                },
                {"action": "request", "method": "tools/list", "params": {}},
                {
                    "action": "expect",
                    "kind": "result",
                    "assertions": [
                        {"path": "/result/resultType", "equals": "toolsList"}
                    ],
                },
            ]
        )
        try:
            result = run_scenario(session, scenario)
            requests = [
                event["payload"]
                for event in recorder.events
                if event.get("direction") == "client_to_server"
                and event.get("classification") == "request"
            ]
        finally:
            recorder.close()
        self.assertEqual(result.errors, ())
        self.assertNotIn("FAIL", {item.status for item in result.findings})
        self.assertEqual([item["method"] for item in requests], ["server/discover", "tools/list"])
        self.assertEqual(
            requests[1]["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28",
        )

    def test_establishment_discovery_error_and_assertions(self) -> None:
        session, recorder = stdio_session()
        scenario = definition(
            [
                {"action": "connect", "establish": True},
                {
                    "action": "expect",
                    "kind": "result",
                    "assertions": [
                        {
                            "path": "/result/protocolVersion",
                            "equals": LEGACY_VERSION,
                        },
                        {"path": "/result/capabilities", "type": "object"},
                    ],
                },
                {"action": "discover", "primitive": "tools"},
                {
                    "action": "expect",
                    "kind": "result",
                    "assertions": [
                        {"path": "/result/tools", "type": "array"},
                        {"path": "/result/tools", "length": 1},
                    ],
                },
                {"action": "request", "method": "fixture/unknown", "params": {}},
                {"action": "expect", "kind": "error", "code": -32601},
                {"action": "disconnect"},
            ]
        )
        try:
            result = run_scenario(session, scenario)
        finally:
            recorder.close()

        self.assertEqual(result.errors, ())
        self.assertTrue(result.disconnected)
        self.assertEqual(result.completed_actions, len(scenario.actions))
        self.assertNotIn("FAIL", {item.status for item in result.findings})
        self.assertGreaterEqual(
            sum(item.code == "SCENARIO_ASSERTION" for item in result.findings), 4
        )

    def test_exact_objects_and_malformed_wire_input(self) -> None:
        session, recorder = stdio_session()
        scenario = definition(
            [
                {"action": "start"},
                {
                    "action": "exact",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": "custom-init",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": LEGACY_VERSION,
                            "capabilities": {},
                            "clientInfo": {"name": "scenario", "version": "1"},
                        },
                    },
                },
                {"action": "expect", "kind": "result"},
                {
                    "action": "exact",
                    "message": {
                        "jsonrpc": "2.0",
                        "method": "notifications/initialized",
                    },
                },
                {"action": "malformed", "data": "{not-json", "wait": True},
                {"action": "expect", "kind": "error", "code": -32700},
                {"action": "terminate"},
            ]
        )
        try:
            result = run_scenario(session, scenario)
            payloads = [event.get("payload") for event in recorder.events]
        finally:
            recorder.close()
        self.assertEqual(result.errors, ())
        self.assertNotIn("FAIL", {item.status for item in result.findings})
        self.assertTrue(
            any(
                item.get("error", {}).get("code") == -32700
                for item in payloads
                if isinstance(item, dict)
            )
        )

    def test_consecutive_expectations_observe_out_of_order_exact_responses(self) -> None:
        session, recorder = stdio_session("stdio-out-of-order")
        scenario = definition(
            [
                {
                    "action": "exact",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": "init",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": LEGACY_VERSION,
                            "capabilities": {},
                            "clientInfo": {"name": "scenario", "version": "1"},
                        },
                    },
                },
                {"action": "expect", "kind": "result"},
                {
                    "action": "exact",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": "first",
                        "method": "ping",
                        "params": {},
                    },
                },
                {
                    "action": "exact",
                    "message": {
                        "jsonrpc": "2.0",
                        "id": "second",
                        "method": "tools/list",
                        "params": {},
                    },
                },
                {
                    "action": "expect",
                    "kind": "result",
                    "assertions": [{"path": "/id", "equals": "second"}],
                },
                {
                    "action": "expect",
                    "kind": "result",
                    "assertions": [{"path": "/id", "equals": "first"}],
                },
            ]
        )
        try:
            result = run_scenario(session, scenario)
        finally:
            recorder.close()
        self.assertEqual(result.errors, ())
        self.assertNotIn("FAIL", {item.status for item in result.findings})

    def test_expected_timeout_is_not_a_transport_run_error(self) -> None:
        session, recorder = stdio_session("stdio-delayed-response")
        scenario = definition(
            [
                {"action": "start"},
                {"action": "request", "method": "fixture/slow"},
                {"action": "expect", "kind": "timeout"},
            ],
            timeout=0.5,
        )
        try:
            result = run_scenario(session, scenario, timeout=0.02)
        finally:
            recorder.close()
        self.assertEqual(result.errors, ())
        expectation = next(item for item in result.findings if item.code == "SCENARIO_EXPECTATION")
        self.assertEqual(expectation.status, "PASS")

    def test_expected_process_close_is_not_a_transport_run_error(self) -> None:
        session, recorder = stdio_session("stdio-crash")
        scenario = definition(
            [
                {"action": "start"},
                {"action": "request", "method": "ping", "timeout": 0.5},
                {"action": "expect", "kind": "close"},
            ]
        )
        try:
            result = run_scenario(session, scenario)
        finally:
            recorder.close()
        self.assertEqual(result.errors, ())
        self.assertEqual(
            next(item for item in result.findings if item.code == "SCENARIO_EXPECTATION").status,
            "PASS",
        )

    def test_server_request_can_be_expected_while_waiting_for_initialize(self) -> None:
        session, recorder = stdio_session(
            "stdio-server-request", capabilities={"roots": {"listChanged": False}}
        )
        scenario = definition(
            [
                {"action": "connect", "establish": True},
                {
                    "action": "expect",
                    "kind": "serverRequest",
                    "method": "roots/list",
                },
                {"action": "expect", "kind": "result"},
            ]
        )
        try:
            result = run_scenario(session, scenario)
        finally:
            recorder.close()
        self.assertEqual(result.errors, ())
        expectations = [
            item for item in result.findings if item.code == "SCENARIO_EXPECTATION"
        ]
        self.assertEqual([item.status for item in expectations], ["PASS", "PASS"])

    def test_active_tool_call_requires_exact_allow_list_entry(self) -> None:
        blocked_session, blocked_recorder = stdio_session()
        scenario = definition(
            [
                {"action": "connect", "establish": True},
                {
                    "action": "request",
                    "method": "tools/call",
                    "params": {"name": "fixture_echo", "arguments": {"text": "hi"}},
                },
                {"action": "expect", "kind": "result"},
            ]
        )
        try:
            blocked = run_scenario(blocked_session, scenario)
        finally:
            blocked_recorder.close()
        self.assertEqual([item.code for item in blocked.errors], ["CONFIG_UNSAFE_ACTION"])

        allowed_session, allowed_recorder = stdio_session()
        try:
            allowed = run_scenario(
                allowed_session, scenario, allow_tools={"fixture_echo"}
            )
        finally:
            allowed_recorder.close()
        self.assertEqual(allowed.errors, ())
        safety = next(
            item for item in allowed.findings if item.code == "SAFETY_ACTIVE_TOOL_OPT_IN"
        )
        self.assertEqual(safety.status, "PASS")
        self.assertTrue(safety.active)

    def test_tool_call_notification_is_also_active(self) -> None:
        scenario = definition(
            [
                {
                    "action": "notification",
                    "method": "tools/call",
                    "params": {"name": "fixture_echo", "arguments": {}},
                }
            ]
        )
        session, recorder = stdio_session()
        try:
            result = run_scenario(session, scenario)
            client_messages = [
                event
                for event in recorder.events
                if event.get("direction") == "client_to_server"
            ]
        finally:
            recorder.close()
        self.assertEqual([item.code for item in result.errors], ["CONFIG_UNSAFE_ACTION"])
        self.assertEqual(client_messages, [])

        allowed_session, allowed_recorder = stdio_session()
        try:
            allowed = run_scenario(
                allowed_session, scenario, allow_tools={"fixture_echo"}
            )
        finally:
            allowed_recorder.close()
        self.assertEqual(allowed.errors, ())
        notification_step = next(
            item
            for item in allowed.findings
            if item.code == "SCENARIO_STEP" and "notification" in item.summary
        )
        self.assertTrue(notification_step.active)

    def test_raw_tool_call_cannot_bypass_allow_list_over_stdio(self) -> None:
        for data, allow_tools in (
            (
                '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"fixture_echo","arguments":{}}}',
                (),
            ),
            ('{"method":"tools/call",', ("fixture_echo",)),
        ):
            with self.subTest(data=data):
                session, recorder = stdio_session()
                scenario = definition([{"action": "malformed", "data": data}])
                try:
                    result = run_scenario(
                        session, scenario, allow_tools=set(allow_tools)
                    )
                    client_messages = [
                        event
                        for event in recorder.events
                        if event.get("direction") == "client_to_server"
                    ]
                finally:
                    recorder.close()
                self.assertEqual(
                    [item.code for item in result.errors], ["CONFIG_UNSAFE_ACTION"]
                )
                self.assertEqual(client_messages, [])

    def test_failed_field_assertion_is_a_compatibility_failure(self) -> None:
        session, recorder = stdio_session()
        scenario = definition(
            [
                {"action": "connect", "establish": True},
                {
                    "action": "expect",
                    "kind": "result",
                    "assertions": [
                        {"path": "/result/protocolVersion", "equals": "1900-01-01"},
                        {
                            "path": "/result/capabilities/tools/listChanged",
                            "equals": 0,
                        },
                    ],
                },
            ]
        )
        try:
            result = run_scenario(session, scenario)
        finally:
            recorder.close()
        assertions = [
            item for item in result.findings if item.code == "SCENARIO_ASSERTION"
        ]
        self.assertEqual([item.status for item in assertions], ["FAIL", "FAIL"])
        self.assertEqual(result.errors, ())


class HttpScenarioTests(unittest.TestCase):
    def test_raw_tool_call_cannot_bypass_allow_list_over_http(self) -> None:
        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            session = http_session(fixture.url, recorder)
            scenario = definition(
                [
                    {
                        "action": "malformed",
                        "data": '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"fixture_echo"}}',
                    }
                ]
            )
            try:
                result = run_scenario(session, scenario)
            finally:
                recorder.close()
            self.assertEqual(
                [item.code for item in result.errors], ["CONFIG_UNSAFE_ACTION"]
            )
            self.assertEqual(fixture.state.received_http, [])

    def test_json_http_and_malformed_request_cross_real_socket(self) -> None:
        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            session = http_session(fixture.url, recorder)
            scenario = definition(
                [
                    {"action": "connect", "establish": True},
                    {"action": "expect", "kind": "result"},
                    {"action": "request", "method": "tools/list", "params": {}},
                    {
                        "action": "expect",
                        "kind": "result",
                        "assertions": [{"path": "/result/tools", "type": "array"}],
                    },
                    {
                        "action": "malformed",
                        "data": "{broken-http-json",
                        "contentType": "application/json",
                    },
                    {"action": "disconnect"},
                ]
            )
            try:
                result = run_scenario(session, scenario)
            finally:
                recorder.close()
            self.assertEqual(result.errors, ())
            self.assertNotIn("FAIL", {item.status for item in result.findings})
            self.assertTrue(
                any(record["body"] == "{broken-http-json" for record in fixture.state.received_http)
            )

    def test_sse_result_is_available_to_expectation(self) -> None:
        with running_http_fixture("http-sse") as fixture:
            recorder = EventRecorder()
            session = http_session(fixture.url, recorder)
            scenario = definition(
                [
                    {"action": "connect", "establish": True},
                    {"action": "expect", "kind": "result"},
                ]
            )
            try:
                result = run_scenario(session, scenario)
            finally:
                recorder.close()
        self.assertEqual(result.errors, ())
        self.assertEqual(
            next(item for item in result.findings if item.code == "SCENARIO_EXPECTATION").status,
            "PASS",
        )

    def test_http_close_expectation_is_explicitly_skipped(self) -> None:
        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            session = http_session(fixture.url, recorder)
            scenario = definition(
                [
                    {"action": "connect", "establish": True},
                    {"action": "expect", "kind": "close"},
                ]
            )
            try:
                result = run_scenario(session, scenario)
            finally:
                recorder.close()
        finding = next(item for item in result.findings if item.code == "SCENARIO_EXPECTATION")
        self.assertEqual(finding.status, "SKIP")
        self.assertEqual(result.errors, ())


if __name__ == "__main__":
    unittest.main()
