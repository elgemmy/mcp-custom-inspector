from __future__ import annotations

import math
import unittest

from mcp_probe_core.checks import CheckOptions, MAX_CHECK_PAGES, run_check
from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.protocol import profile_for
from mcp_probe_core.session import McpSession, SessionConfig
from mcp_probe_core.transcript import EventRecorder
from mcp_probe_core.transports import HttpTransport, StdioTransport
from tests.fixtures.mcp_fixture import running_http_fixture, stdio_fixture_command


LEGACY = "2025-06-18"
MODERN = "2026-07-28"


def finding(report, code):
    return next(item for item in report.findings if item.code == code)


class CheckOptionsTests(unittest.TestCase):
    def test_numeric_bounds_reject_bool_non_finite_and_unbounded_pages(self):
        for value in (True, "1", 0, -1, math.inf, -math.inf, math.nan):
            with self.subTest(timeout=value):
                with self.assertRaises(ConfigurationError):
                    CheckOptions(timeout=value)  # type: ignore[arg-type]
        for value in (True, 1.5, "2", 0, -1, MAX_CHECK_PAGES + 1):
            with self.subTest(max_pages=value):
                with self.assertRaises(ConfigurationError):
                    CheckOptions(max_pages=value)  # type: ignore[arg-type]
        for value in (True, "0", -1, math.inf, -math.inf, math.nan):
            with self.subTest(window=value):
                with self.assertRaises(ConfigurationError):
                    CheckOptions(notification_observation_window=value)  # type: ignore[arg-type]

        self.assertEqual(CheckOptions(max_pages=MAX_CHECK_PAGES).max_pages, MAX_CHECK_PAGES)
        self.assertEqual(CheckOptions(notification_observation_window=0).notification_observation_window, 0)


class CompatibilityChecksStdioTests(unittest.TestCase):
    def run_stdio(
        self,
        profile: str,
        *,
        version: str = LEGACY,
        extra: tuple[str, ...] = (),
        client_capabilities: dict | None = None,
        roots: list[dict] | None = None,
        timeout: float = 0.6,
        max_pages: int = 10,
    ):
        recorder = EventRecorder()
        transport = StdioTransport(stdio_fixture_command(profile, *extra), {}, recorder)
        config = SessionConfig(
            version,
            client_capabilities=client_capabilities or {},
            roots=roots or [],
        )
        session = McpSession(transport, config, recorder)
        report = run_check(session, timeout=timeout, max_pages=max_pages)
        self.assertIsNotNone(transport.process)
        self.assertIsNotNone(transport.returncode, "run_check must always reap its child")
        return report, recorder

    def test_good_legacy_server_passes_without_active_tool_calls(self):
        report, recorder = self.run_stdio("stdio-good-legacy")
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.overall["status"], "PASS")
        self.assertEqual(finding(report, "LIFECYCLE_INITIALIZE").status, "PASS")
        self.assertEqual(finding(report, "CAPABILITY_TOOLS_LIST").status, "PASS")
        self.assertEqual(finding(report, "STDIO_CLEANUP").status, "PASS")
        self.assertFalse(
            any(event.get("method") == "tools/call" for event in recorder.events)
        )

    def test_good_modern_server_uses_discover_and_required_result_types(self):
        report, recorder = self.run_stdio("stdio-good-modern", version=MODERN)
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.negotiated_version, MODERN)
        self.assertEqual(finding(report, "LIFECYCLE_INITIALIZE").status, "SKIP")
        client_methods = [
            event.get("method")
            for event in recorder.events
            if event.get("direction") == "client_to_server"
        ]
        self.assertEqual(client_methods[0], "server/discover")
        self.assertNotIn("initialize", client_methods)
        successful_results = [
            event["payload"]["result"]
            for event in recorder.events
            if event.get("direction") == "server_to_client"
            and isinstance(event.get("payload"), dict)
            and isinstance(event["payload"].get("result"), dict)
        ]
        self.assertTrue(successful_results)
        self.assertTrue(all("resultType" in result for result in successful_results))

    def test_capability_mismatch_is_a_compatibility_failure(self):
        report, _ = self.run_stdio("stdio-capability-mismatch")
        self.assertEqual(report.exit_code, 1)
        self.assertEqual(finding(report, "CAPABILITY_TOOLS_LIST").status, "FAIL")
        self.assertIn("without", finding(report, "CAPABILITY_TOOLS_LIST").summary)

    def test_pagination_collects_pages_and_detects_malformed_cursor(self):
        good, _ = self.run_stdio("stdio-pagination")
        self.assertEqual(good.exit_code, 0)
        self.assertEqual(len(good.discovery["tools"]), 2)
        self.assertEqual(finding(good, "PAGINATION_CURSOR_PROGRESS").status, "PASS")

        malformed, _ = self.run_stdio(
            "stdio-pagination", extra=("--pagination-mode", "malformed")
        )
        self.assertEqual(malformed.exit_code, 1)
        cursor = finding(malformed, "PAGINATION_CURSOR_SHAPE")
        self.assertEqual(cursor.status, "FAIL")
        self.assertTrue(cursor.evidence)

    def test_repeated_cursor_is_bounded_and_reported_as_heuristic_warning(self):
        report, _ = self.run_stdio(
            "stdio-pagination",
            extra=("--pagination-mode", "repeat"),
            max_pages=4,
        )
        loop = finding(report, "PAGINATION_CURSOR_LOOP")
        self.assertEqual(loop.status, "WARN")
        self.assertEqual(loop.basis, "heuristic")
        self.assertEqual(report.exit_code, 0)

    def test_malformed_stdout_and_invalid_response_are_evidence_backed(self):
        malformed, _ = self.run_stdio("stdio-malformed-output")
        output = finding(malformed, "STDIO_INVALID_OUTPUT")
        self.assertEqual(output.status, "FAIL")
        self.assertTrue(output.evidence)

        invalid, _ = self.run_stdio("stdio-invalid-response", timeout=0.25)
        self.assertEqual(finding(invalid, "JSONRPC_RESPONSE_SHAPE").status, "FAIL")
        self.assertEqual(finding(invalid, "JSONRPC_VERSION").status, "FAIL")
        self.assertEqual(invalid.exit_code, 1)

    def test_wrong_id_is_compatibility_failure_not_transport_error(self):
        report, _ = self.run_stdio("stdio-mismatched-id", timeout=0.25)
        mismatch = finding(report, "JSONRPC_RESPONSE_ID")
        self.assertEqual(mismatch.status, "FAIL")
        self.assertTrue(mismatch.evidence)
        self.assertFalse(report.errors)
        self.assertEqual(report.exit_code, 1)

    def test_child_crash_has_transport_exit_and_cleanup(self):
        report, _ = self.run_stdio("stdio-crash", timeout=0.25)
        self.assertEqual(report.exit_code, 3)
        self.assertIn("TRANSPORT_STDIO_CHILD_EXIT", [error.code for error in report.errors])
        self.assertEqual(finding(report, "STDIO_CHILD_EXIT").status, "FAIL")
        self.assertIn(finding(report, "STDIO_CLEANUP").status, {"PASS", "WARN"})

    def test_delayed_stdio_response_has_timeout_taxonomy(self):
        report, _ = self.run_stdio("stdio-delayed-response", timeout=0.04)
        self.assertEqual(report.exit_code, 3)
        self.assertIn("TRANSPORT_STDIO_TIMEOUT", [error.code for error in report.errors])
        self.assertEqual(finding(report, "STDIO_TIMEOUT").status, "FAIL")

    def test_server_roots_request_matches_negotiated_client_capability(self):
        report, _ = self.run_stdio(
            "stdio-server-request",
            client_capabilities={"roots": {"listChanged": False}},
            roots=[{"uri": "file:///fixture", "name": "fixture"}],
        )
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(finding(report, "CLIENT_REQUEST_ROOTS_LIST").status, "PASS")
        self.assertEqual(finding(report, "CAPABILITY_ROOTS").status, "PASS")

    def test_notification_response_is_a_jsonrpc_violation(self):
        report, _ = self.run_stdio("stdio-notification-response")
        self.assertEqual(
            finding(report, "JSONRPC_NOTIFICATION_NO_RESPONSE").status, "FAIL"
        )
        self.assertEqual(report.exit_code, 1)

    def test_schema_issues_map_to_stable_report_codes_and_evidence_pointers(self):
        report, _ = self.run_stdio(
            "stdio-good-legacy", extra=("--tool-schema-mode", "missing-input")
        )
        issue = finding(report, "TOOL_SCHEMA_INPUT_PRESENT")
        self.assertEqual(issue.status, "FAIL")
        self.assertEqual(issue.evidence[0].pointer, "/result/tools/0/inputSchema")

        legacy_header, _ = self.run_stdio(
            "stdio-good-legacy", extra=("--tool-schema-mode", "bad-header")
        )
        portability = finding(legacy_header, "TOOL_SCHEMA_PORTABILITY")
        self.assertEqual(portability.status, "WARN")
        self.assertEqual(portability.basis, "heuristic")

        modern_header, _ = self.run_stdio(
            "stdio-good-modern",
            version=MODERN,
            extra=("--tool-schema-mode", "bad-header"),
        )
        self.assertEqual(
            finding(modern_header, "TOOL_SCHEMA_PORTABILITY").status, "FAIL"
        )


class CompatibilityChecksHttpTests(unittest.TestCase):
    def run_http(
        self,
        profile: str,
        *,
        version: str = LEGACY,
        timeout: float = 0.6,
        fixture_options: dict | None = None,
    ):
        fixture = running_http_fixture(profile, **(fixture_options or {}))
        running = fixture.__enter__()
        self.addCleanup(fixture.__exit__, None, None, None)
        recorder = EventRecorder()
        transport = HttpTransport(running.url, {}, recorder, profile_for(version))
        session = McpSession(transport, SessionConfig(version), recorder)
        report = run_check(session, timeout=timeout, max_pages=10)
        return report, recorder, running

    def test_json_sse_and_modern_http_targets_pass(self):
        json_report, _, _ = self.run_http("http-json")
        self.assertEqual(json_report.exit_code, 0)
        self.assertEqual(finding(json_report, "HTTP_CONTENT_TYPE").status, "PASS")

        sse_report, _, _ = self.run_http("http-sse-multi")
        self.assertEqual(sse_report.exit_code, 0)
        self.assertEqual(finding(sse_report, "HTTP_SSE_PARSE").status, "PASS")

        modern_report, recorder, _ = self.run_http(
            "http-json",
            version=MODERN,
            fixture_options={"protocol_version": MODERN},
        )
        self.assertEqual(modern_report.exit_code, 0)
        self.assertEqual(
            finding(modern_report, "HTTP_PROTOCOL_VERSION_HEADER").status, "PASS"
        )
        unknown_responses = [
            event
            for event in recorder.events
            if event.get("httpStatus") == 404
            and isinstance(event.get("payload"), dict)
        ]
        self.assertTrue(unknown_responses)

    def test_session_id_is_propagated_and_terminated(self):
        report, _, running = self.run_http(
            "http-session", fixture_options={"require_protocol_header": True}
        )
        self.assertEqual(report.exit_code, 0)
        self.assertEqual(finding(report, "HTTP_SESSION_ID").status, "PASS")
        self.assertEqual(finding(report, "HTTP_SESSION_TERMINATION").status, "PASS")
        self.assertTrue(running.state.terminated)

    def test_malformed_body_and_wrong_content_type_are_protocol_failures(self):
        malformed, _, _ = self.run_http("http-malformed-body")
        self.assertEqual(malformed.exit_code, 1)
        self.assertEqual(finding(malformed, "HTTP_BODY_SHAPE").status, "FAIL")
        self.assertFalse(malformed.errors)

        wrong_type, _, _ = self.run_http("http-wrong-content-type")
        self.assertEqual(wrong_type.exit_code, 1)
        self.assertEqual(finding(wrong_type, "HTTP_CONTENT_TYPE").status, "FAIL")
        self.assertEqual(finding(wrong_type, "HTTP_BODY_SHAPE").status, "PASS")

    def test_http_error_status_is_reported_without_traceback_taxonomy(self):
        report, _, _ = self.run_http("http-error")
        self.assertEqual(report.exit_code, 1)
        self.assertEqual(finding(report, "HTTP_STATUS").status, "FAIL")
        self.assertEqual(finding(report, "LIFECYCLE_INITIALIZE").status, "FAIL")
        self.assertFalse(report.errors)

    def test_http_timeout_has_transport_taxonomy(self):
        report, _, _ = self.run_http(
            "http-delayed-response",
            timeout=0.04,
            fixture_options={"delay": 0.20},
        )
        self.assertEqual(report.exit_code, 3)
        self.assertIn("TRANSPORT_HTTP_TIMEOUT", [error.code for error in report.errors])
        self.assertEqual(finding(report, "HTTP_TIMEOUT").status, "FAIL")


if __name__ == "__main__":
    unittest.main()
