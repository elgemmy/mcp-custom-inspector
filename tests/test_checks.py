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
    def test_active_custom_initialize_is_rejected_before_check_target_start(self):
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command("stdio-good-legacy"), {}, recorder
        )
        session = McpSession(
            transport,
            SessionConfig(
                LEGACY,
                initialize_message={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        # Programmatic callers can supply tuples, which the
                        # JSON encoder serializes as arrays on the wire.
                        "nested": (
                            {
                                "method": "tools/call",
                                "params": {"name": "fixture_echo"},
                            },
                        )
                    },
                },
            ),
            recorder,
        )
        with self.assertRaisesRegex(ConfigurationError, "active tools/call"):
            run_check(session)
        self.assertIsNone(transport.process)
        recorder.close()

    def test_active_client_capabilities_are_rejected_in_both_lifecycle_eras(self):
        active_capabilities = {
            "extension": (
                {
                    "method": "tools/call",
                    "params": {"name": "fixture_echo"},
                },
            )
        }
        for version, profile in (
            (LEGACY, "stdio-good-legacy"),
            (MODERN, "stdio-good-modern"),
        ):
            with self.subTest(version=version):
                recorder = EventRecorder()
                transport = StdioTransport(
                    stdio_fixture_command(profile), {}, recorder
                )
                session = McpSession(
                    transport,
                    SessionConfig(
                        version,
                        client_capabilities=active_capabilities,
                    ),
                    recorder,
                )
                with self.assertRaisesRegex(ConfigurationError, "active tools/call"):
                    run_check(session)
                self.assertIsNone(transport.process)
                recorder.close()

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

    def test_malformed_capability_descriptor_and_flag_are_negotiation_failures(self):
        for mode in ("descriptor", "flag"):
            with self.subTest(mode=mode):
                report, _ = self.run_stdio(
                    "stdio-good-legacy",
                    extra=("--capability-shape-mode", mode),
                )
                issue = finding(report, "NEGOTIATION_CAPABILITIES")
                self.assertEqual(issue.status, "FAIL")
                self.assertTrue(issue.evidence)

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

    def test_wrong_then_correct_id_is_still_reported(self):
        report, _ = self.run_stdio(
            "stdio-mismatched-id", extra=("--mismatch-then-correct",)
        )
        self.assertEqual(finding(report, "JSONRPC_RESPONSE_ID").status, "FAIL")
        self.assertFalse(report.errors)
        self.assertEqual(report.exit_code, 1)

    def test_child_crash_has_transport_exit_and_cleanup(self):
        report, _ = self.run_stdio("stdio-crash", timeout=0.25)
        self.assertEqual(report.exit_code, 3)
        self.assertIn("TRANSPORT_STDIO_CHILD_EXIT", [error.code for error in report.errors])
        self.assertEqual(finding(report, "STDIO_CHILD_EXIT").status, "FAIL")
        self.assertIn(finding(report, "STDIO_CLEANUP").status, {"PASS", "WARN"})

    def test_nonzero_exit_after_successful_protocol_run_is_transport_failure(self):
        report, _ = self.run_stdio(
            "stdio-good-legacy",
            extra=("--eof-exit-code", "29"),
        )
        self.assertEqual(report.exit_code, 3)
        self.assertIn(
            "TRANSPORT_STDIO_CHILD_EXIT", [error.code for error in report.errors]
        )
        self.assertEqual(finding(report, "STDIO_CHILD_EXIT").actual, 29)
        self.assertEqual(finding(report, "STDIO_CLEANUP").status, "PASS")

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

    def test_ping_and_unsupported_server_requests_are_correlated_to_responses(self):
        ping, _ = self.run_stdio(
            "stdio-good-legacy", extra=("--server-request-mode", "ping-post")
        )
        self.assertEqual(finding(ping, "CLIENT_REQUEST_PING").status, "PASS")

        unsupported, _ = self.run_stdio(
            "stdio-good-legacy",
            extra=("--server-request-mode", "unsupported-post"),
        )
        self.assertEqual(
            finding(unsupported, "CLIENT_REQUEST_UNSUPPORTED").status, "PASS"
        )

    def test_server_request_handler_failure_cannot_be_reported_as_pass(self):
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command(
                "stdio-good-legacy", "--server-request-mode", "roots-post"
            ),
            {},
            recorder,
        )
        session = McpSession(
            transport,
            SessionConfig(
                LEGACY,
                client_capabilities={"roots": {}},
                roots=[{"uri": "file:///fixture"}],
            ),
            recorder,
        )

        def broken_handler(_message):
            raise RuntimeError("fixture handler failure")

        session._handle_legacy_server_request = broken_handler  # type: ignore[method-assign]
        report = run_check(session, timeout=0.6, max_pages=10)
        self.assertEqual(finding(report, "CLIENT_REQUEST_ROOTS_LIST").status, "FAIL")
        self.assertTrue(
            any(
                event.get("classification") == "server_request_handler_error"
                for event in recorder.events
            )
        )

    def test_pre_initialized_roots_is_rejected_without_claiming_roots_success(self):
        report, recorder = self.run_stdio(
            "stdio-server-request",
            extra=("--server-request-mode", "roots-early"),
            client_capabilities={"roots": {}},
        )
        self.assertEqual(finding(report, "LIFECYCLE_ORDERING").status, "WARN")
        self.assertEqual(finding(report, "CLIENT_REQUEST_ROOTS_LIST").status, "WARN")
        self.assertEqual(finding(report, "CAPABILITY_ROOTS").status, "SKIP")
        response = next(
            event
            for event in recorder.events
            if event.get("direction") == "client_to_server"
            and isinstance(event.get("payload"), dict)
            and event["payload"].get("id") == "fixture-roots-request"
        )
        self.assertEqual(response["payload"]["error"]["code"], -32002)

    def test_malformed_server_request_is_evidence_backed_and_rejected(self):
        report, recorder = self.run_stdio(
            "stdio-good-legacy",
            extra=("--server-request-mode", "invalid-id"),
            client_capabilities={"roots": {}},
        )
        issue = finding(report, "JSONRPC_INVALID_REQUEST")
        self.assertEqual(issue.status, "FAIL")
        self.assertTrue(issue.evidence)
        self.assertTrue(
            any(
                event.get("classification") == "invalid_server_request"
                for event in recorder.events
            )
        )
        self.assertTrue(
            any(
                event.get("direction") == "client_to_server"
                and isinstance(event.get("payload"), dict)
                and event["payload"].get("error", {}).get("code") == -32600
                for event in recorder.events
            )
        )

    def test_2025_03_batch_receive_and_grouped_server_responses_are_observed(self):
        report, recorder = self.run_stdio(
            "stdio-batch-server-request",
            version="2025-03-26",
            client_capabilities={"roots": {}},
        )
        self.assertEqual(finding(report, "JSONRPC_BATCH_SUPPORT").status, "PASS")
        self.assertEqual(finding(report, "CLIENT_REQUEST_PING").status, "PASS")
        self.assertEqual(finding(report, "CLIENT_REQUEST_ROOTS_LIST").status, "WARN")
        self.assertTrue(
            any(
                event.get("direction") == "client_to_server"
                and event.get("classification") == "batch"
                for event in recorder.events
            )
        )

    def test_2025_06_rejects_incoming_batch(self):
        report, _ = self.run_stdio(
            "stdio-batch-server-request",
            version="2025-06-18",
            client_capabilities={"roots": {}},
            timeout=0.25,
        )
        self.assertEqual(finding(report, "JSONRPC_BATCH_SUPPORT").status, "FAIL")

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
            finding(modern_header, "TOOL_SCHEMA_PORTABILITY").status, "WARN"
        )

        missing_type, _ = self.run_stdio(
            "stdio-good-legacy", extra=("--tool-schema-mode", "missing-type")
        )
        self.assertEqual(
            finding(missing_type, "TOOL_SCHEMA_INPUT_OBJECT").status, "FAIL"
        )

    def test_paginated_schema_evidence_points_to_the_faulting_page(self):
        report, recorder = self.run_stdio(
            "stdio-pagination",
            extra=("--tool-schema-mode", "page-two-missing-input"),
        )
        issue = finding(report, "TOOL_SCHEMA_INPUT_PRESENT")
        second_page = next(
            event
            for event in recorder.events
            if event.get("direction") == "server_to_client"
            and isinstance(event.get("payload"), dict)
            and event["payload"].get("result", {}).get("tools", [{}])[0].get("name")
            == "fixture_page_two"
        )
        self.assertEqual(issue.evidence[0].event, f"event:{second_page['seq']}")
        self.assertEqual(issue.evidence[0].pointer, "/result/tools/0/inputSchema")

        duplicate, _ = self.run_stdio(
            "stdio-pagination",
            extra=("--tool-schema-mode", "cross-page-duplicate"),
        )
        duplicate_issue = finding(duplicate, "TOOL_NAME_UNIQUE")
        self.assertEqual(duplicate_issue.status, "WARN")
        self.assertEqual(duplicate_issue.evidence[0].pointer, "/result/tools/0/name")

    def test_modern_ttl_accepts_finite_numbers_and_rejects_negative_values(self):
        valid, _ = self.run_stdio(
            "stdio-good-modern",
            version=MODERN,
            extra=("--modern-ttl-mode", "float"),
        )
        self.assertEqual(valid.exit_code, 0)

        invalid, _ = self.run_stdio(
            "stdio-good-modern",
            version=MODERN,
            extra=("--modern-ttl-mode", "negative"),
        )
        self.assertEqual(finding(invalid, "JSONRPC_RESPONSE_SHAPE").status, "FAIL")

    def test_modern_unsolicited_notifications_are_normatively_rejected(self):
        cases = {
            "logging": "CAPABILITY_LOGGING",
            "progress": "JSONRPC_PROGRESS_TOKEN",
            "tools": "CAPABILITY_TOOLS_LIST",
            "resources": "CAPABILITY_RESOURCES_LIST",
            "prompts": "CAPABILITY_PROMPTS_LIST",
            "resource-updated": "CAPABILITY_RESOURCES_LIST",
        }
        for mode, code in cases.items():
            with self.subTest(mode=mode):
                report, _ = self.run_stdio(
                    "stdio-good-modern",
                    version=MODERN,
                    extra=("--notification-mode", mode),
                )
                self.assertEqual(finding(report, code).status, "FAIL")

    def test_modern_forbidden_server_request_is_not_answered(self):
        report, recorder = self.run_stdio(
            "stdio-good-modern",
            version=MODERN,
            extra=("--server-request-mode", "modern-forbidden"),
        )
        self.assertEqual(
            finding(report, "CLIENT_REQUEST_UNSUPPORTED").status, "FAIL"
        )
        self.assertTrue(
            any(
                event.get("classification") == "forbidden_server_request"
                for event in recorder.events
            )
        )
        self.assertFalse(
            any(
                event.get("direction") == "client_to_server"
                and event.get("classification") == "response"
                and isinstance(event.get("payload"), dict)
                and event["payload"].get("id") == "fixture-roots-request"
                for event in recorder.events
            )
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

    def test_modern_server_session_id_is_a_lifecycle_failure(self):
        report, recorder, _ = self.run_http(
            "http-json",
            version=MODERN,
            fixture_options={
                "protocol_version": MODERN,
                "response_session_id": True,
            },
        )
        self.assertEqual(report.exit_code, 1)
        session_finding = finding(report, "HTTP_SESSION_ID")
        self.assertEqual(session_finding.status, "FAIL")
        self.assertTrue(
            any(
                event.get("classification") == "unexpected_session_id"
                for event in recorder.events
            )
        )

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

    def test_http_notification_may_be_rejected_with_idless_4xx_error(self):
        report, _, _ = self.run_http("http-notification-reject")
        self.assertEqual(
            finding(report, "JSONRPC_NOTIFICATION_NO_RESPONSE").status, "PASS"
        )
        self.assertEqual(finding(report, "HTTP_STATUS").status, "PASS")
        self.assertEqual(report.exit_code, 0)

    def test_http_wrong_id_and_wrong_then_correct_are_protocol_failures(self):
        wrong, _, _ = self.run_http("http-wrong-id")
        self.assertEqual(finding(wrong, "JSONRPC_RESPONSE_ID").status, "FAIL")
        self.assertFalse(wrong.errors)

        mixed, _, _ = self.run_http("http-wrong-then-correct")
        self.assertEqual(finding(mixed, "JSONRPC_RESPONSE_ID").status, "FAIL")
        self.assertFalse(mixed.errors)


if __name__ == "__main__":
    unittest.main()
