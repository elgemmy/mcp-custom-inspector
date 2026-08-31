from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mcp_probe_core.cli import build_parser, main
from mcp_probe_core.transcript import EventRecorder
from tests.fixtures.mcp_fixture import running_http_fixture, stdio_fixture_command


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "mcp_probe.py"


def invoke(*arguments: str) -> tuple[int, str, str]:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(list(arguments))
    return code, stdout.getvalue(), stderr.getvalue()


class ParserTests(unittest.TestCase):
    def test_parser_exposes_legacy_and_laboratory_commands(self) -> None:
        parser = build_parser()
        help_text = parser.format_help()
        for command in ("stdio", "http", "check", "matrix", "scenario", "replay"):
            self.assertIn(command, help_text)

    def test_script_help_and_leaf_help_exit_cleanly(self) -> None:
        commands = (
            ["--help"],
            ["stdio", "--help"],
            ["http", "--help"],
            ["check", "stdio", "--help"],
            ["matrix", "http", "--help"],
            ["scenario", "stdio", "--help"],
            ["replay", "http", "--help"],
        )
        for arguments in commands:
            with self.subTest(arguments=arguments):
                completed = subprocess.run(
                    [sys.executable, str(ENTRYPOINT), *arguments],
                    cwd=ROOT,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("usage:", completed.stdout)
                self.assertNotIn("Traceback", completed.stderr)

    def test_missing_stdio_command_is_configuration_error_without_traceback(self) -> None:
        code, _, stderr = invoke("stdio", "--protocol-version", "2025-06-18")
        self.assertEqual(code, 2)
        self.assertIn("Missing server command", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_invalid_timeout_is_configuration_error(self) -> None:
        code, _, stderr = invoke("stdio", "--timeout", "0", "--", "ignored")
        self.assertEqual(code, 2)
        self.assertIn("--timeout must be greater than zero", stderr)

    def test_pre_argparse_errors_redact_credential_shaped_arguments(self) -> None:
        secret = "parser-secret-must-not-leak"
        code, _, stderr = invoke("--auth-token", secret)
        self.assertEqual(code, 2)
        self.assertNotIn(secret, stderr)
        self.assertIn("[REDACTED]", stderr)

    def test_max_pages_has_a_bounded_configuration_limit(self) -> None:
        code, _, stderr = invoke(
            "check", "stdio", "--max-pages", "1001", "--", "ignored-server"
        )
        self.assertEqual(code, 2)
        self.assertIn("1 to 1000", stderr)

    def test_nonstandard_json_numbers_are_configuration_errors(self) -> None:
        code, _, stderr = invoke(
            "stdio", "--init-json", '{"value":NaN}', "--", "ignored-server"
        )
        self.assertEqual(code, 2)
        self.assertIn("Invalid JSON for --init-json", stderr)

    def test_deep_cli_json_is_rejected_before_starting_target(self) -> None:
        value: object = 0
        for _ in range(150):
            value = [value]
        code, _, stderr = invoke(
            "stdio",
            "--init-json",
            json.dumps({"nested": value}),
            "--",
            "definitely-not-started",
        )
        self.assertEqual(code, 2)
        self.assertIn("JSON nesting exceeds", stderr)
        self.assertNotIn("Could not start", stderr)

    def test_nested_normalized_tool_call_in_initialize_is_blocked(self) -> None:
        payload = {
            "protocolVersion": "2025-06-18",
            "capabilities": {
                "nested": {
                    " Method ": " TOOLS/CALL ",
                    " Params ": {" Name ": "fixture_echo"},
                }
            },
            "clientInfo": {"name": "unsafe", "version": "1"},
        }
        code, _, stderr = invoke(
            "stdio",
            "--init-json",
            json.dumps(payload),
            "--",
            "definitely-not-started",
        )
        self.assertEqual(code, 2)
        self.assertIn("nested tools/call-like object", stderr)
        self.assertNotIn("Could not start", stderr)

    def test_nested_tool_call_in_client_capabilities_is_blocked(self) -> None:
        capabilities = {
            "extension": [
                {
                    "method": "tools/call",
                    "params": {"name": "fixture_echo"},
                }
            ]
        }
        code, _, stderr = invoke(
            "stdio",
            "--client-capabilities",
            json.dumps(capabilities),
            "--",
            "definitely-not-started",
        )
        self.assertEqual(code, 2)
        self.assertIn("nested tools/call-like object", stderr)
        self.assertNotIn("Could not start", stderr)

    def test_missing_executable_is_transport_error_without_traceback(self) -> None:
        code, _, stderr = invoke(
            "stdio", "--timeout", "0.1", "--", "definitely-not-an-mcp-probe-command"
        )
        self.assertEqual(code, 3)
        self.assertIn("Could not start stdio server", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_replay_cannot_overwrite_its_input_transcript(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            transcript = Path(temp) / "trace.ndjson"
            original = '{"schema":"mcp-probe.transcript.event/v1","seq":1}\n'
            transcript.write_text(original, encoding="utf-8")
            code, _, stderr = invoke(
                "replay",
                "stdio",
                "--from",
                str(transcript),
                "--transcript",
                str(transcript),
                "--",
                "ignored-server",
            )
            self.assertEqual(code, 2)
            self.assertIn("must be different paths", stderr)
            self.assertEqual(transcript.read_text(encoding="utf-8"), original)

    def test_http_rejects_invalid_header_grammar_without_echoing_value(self) -> None:
        secret = "header-value-must-not-be-echoed"
        for header in (f"Bad Name: {secret}", f"X-Test: ok\r\nInjected: {secret}"):
            with self.subTest(header=header):
                code, _, stderr = invoke(
                    "http", "--url", "http://127.0.0.1:1/mcp", "--header", header
                )
                self.assertEqual(code, 2)
                self.assertIn("--header", stderr)
                self.assertNotIn(secret, stderr)

    def test_http_rejects_duplicate_user_headers_case_insensitively(self) -> None:
        for second_name in ("Accept", "accept"):
            with self.subTest(second_name=second_name):
                code, _, stderr = invoke(
                    "http",
                    "--url",
                    "http://127.0.0.1:1/mcp",
                    "--header",
                    "Accept: application/json",
                    "--header",
                    f"{second_name}: text/event-stream",
                )
                self.assertEqual(code, 2)
                self.assertIn("duplicate case-insensitive", stderr)

    def test_http_lowercase_builtin_header_overrides_match_origin_behavior(self) -> None:
        with running_http_fixture("http-json") as fixture:
            code, _, stderr = invoke(
                "http",
                "--url",
                fixture.url,
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "2",
                "--header",
                "accept: application/json",
                "--header",
                "content-type: application/json",
            )
        self.assertEqual(code, 0, stderr)
        self.assertTrue(fixture.state.received_http)
        for request in fixture.state.received_http:
            self.assertEqual(request["headers"]["accept"], "application/json")
            self.assertEqual(request["headers"]["content-type"], "application/json")

    def test_pre_streamable_http_profile_is_configuration_error(self) -> None:
        code, _, stderr = invoke(
            "http",
            "--url",
            "http://127.0.0.1:1/mcp",
            "--protocol-version",
            "2024-11-05",
        )
        self.assertEqual(code, 2)
        self.assertIn("predates Streamable HTTP", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_report_and_transcript_must_be_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "output.json"
            code, _, stderr = invoke(
                "stdio",
                "--report",
                str(destination),
                "--transcript",
                str(destination),
                "--",
                "ignored-server",
            )
            self.assertEqual(code, 2)
            self.assertIn("--report", stderr)
            self.assertIn("--transcript", stderr)
            self.assertFalse(destination.exists())

    def test_output_cannot_overwrite_initialize_or_scenario_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            init_path = Path(temp) / "init.json"
            init_text = '{"protocolVersion":"2025-06-18"}\n'
            init_path.write_text(init_text, encoding="utf-8")
            code, _, stderr = invoke(
                "stdio",
                "--init-file",
                str(init_path),
                "--report",
                str(init_path),
                "--",
                "ignored-server",
            )
            self.assertEqual(code, 2)
            self.assertIn("must be different paths", stderr)
            self.assertEqual(init_path.read_text(encoding="utf-8"), init_text)

            scenario_path = Path(temp) / "scenario.json"
            scenario_text = '{"schema":"mcp-probe.scenario/v1"}\n'
            scenario_path.write_text(scenario_text, encoding="utf-8")
            code, _, stderr = invoke(
                "scenario",
                "stdio",
                "--file",
                str(scenario_path),
                "--transcript",
                str(scenario_path),
                "--",
                "ignored-server",
            )
            self.assertEqual(code, 2)
            self.assertIn("must be different paths", stderr)
            self.assertEqual(scenario_path.read_text(encoding="utf-8"), scenario_text)

    def test_matrix_rejects_fixed_custom_initialize_payload(self) -> None:
        code, _, stderr = invoke(
            "matrix",
            "stdio",
            "--init-json",
            '{"protocolVersion":"2025-06-18"}',
            "--",
            "ignored-server",
        )
        self.assertEqual(code, 2)
        self.assertIn("unrecognized arguments: --init-json", stderr)

    def test_cli_restores_prior_sigterm_handler(self) -> None:
        signum = getattr(signal, "SIGTERM", None)
        if signum is None:
            self.skipTest("SIGTERM is unavailable")

        def previous_handler(_signum: int, _frame: object) -> None:
            return None

        original = signal.signal(signum, previous_handler)
        try:
            code, _, _ = invoke("stdio", "--timeout", "0", "--", "ignored")
            self.assertEqual(code, 2)
            self.assertIs(signal.getsignal(signum), previous_handler)
        finally:
            signal.signal(signum, original)


class InspectionCliTests(unittest.TestCase):
    def test_fractional_full_initialize_id_is_correlated(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        message = {
            "jsonrpc": "2.0",
            "id": 1.5,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "fractional", "version": "1"},
            },
        }
        code, stdout, stderr = invoke(
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--init-json",
            json.dumps(message),
            "--output",
            "json",
            "--",
            *command,
        )
        self.assertEqual(code, 0, stderr)
        document = json.loads(stdout)
        self.assertEqual(document["records"][0]["value"]["id"], 1.5)

    def test_late_raw_failure_preserves_successful_inspection_records(self) -> None:
        script = """
import json, os, sys
request = json.loads(sys.stdin.buffer.readline())
print(json.dumps({
    'jsonrpc': '2.0',
    'id': request['id'],
    'result': {
        'protocolVersion': '2025-06-18',
        'capabilities': {},
        'serverInfo': {'name': 'partial', 'version': '1'},
    },
}), flush=True)
sys.stdin.buffer.readline()
sys.stdin.buffer.readline()
os._exit(17)
"""
        raw = json.dumps(
            {"jsonrpc": "2.0", "id": 9, "method": "ping", "params": {}}
        )
        code, stdout, stderr = invoke(
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "1",
            "--output",
            "json",
            "--raw",
            raw,
            "--",
            sys.executable,
            "-u",
            "-c",
            script,
        )
        self.assertEqual(code, 3, stderr)
        self.assertEqual(stderr, "")
        document = json.loads(stdout)
        self.assertEqual(
            [item["label"] for item in document["records"]],
            ["initialize", "raw ping"],
        )
        self.assertIn("ProcessExited", document["records"][1]["value"]["error"]["code"])

    def test_http_correlation_failure_still_emits_wire_evidence_as_json(self) -> None:
        with running_http_fixture("http-malformed-body") as fixture:
            code, stdout, stderr = invoke(
                "http",
                "--url",
                fixture.url,
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "2",
                "--output",
                "json",
            )
        self.assertEqual(code, 3, stderr)
        document = json.loads(stdout)
        value = document["records"][0]["value"]
        self.assertEqual(value["status"], 200)
        self.assertIn('"jsonrpc":"2.0",broken', value["raw"])
        self.assertTrue(value["parseIssues"])
        self.assertEqual(value["error"]["code"], "HTTP_RESPONSE_CORRELATION")

    def test_malformed_http_status_is_structured_transport_failure(self) -> None:
        with running_http_fixture("http-malformed-status") as fixture:
            code, stdout, stderr = invoke(
                "http",
                "--url",
                fixture.url,
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "1",
                "--output",
                "json",
            )
        self.assertEqual(code, 3, stderr)
        self.assertEqual(stderr, "")
        document = json.loads(stdout)
        error = document["records"][0]["value"]["error"]
        self.assertEqual(error["code"], "TRANSPORT_HTTP_IO")
        self.assertNotIn("\x1b", error["message"])
        self.assertIn("\\x1b", error["message"])

    def test_http_wrong_initialize_id_is_visible_in_default_output(self) -> None:
        with running_http_fixture("http-wrong-id") as fixture:
            code, stdout, stderr = invoke(
                "http",
                "--url",
                fixture.url,
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "2",
            )
        self.assertEqual(code, 3, stderr)
        self.assertIn("== initialize ==", stdout)
        self.assertIn("HTTP_RESPONSE_CORRELATION", stdout)
        self.assertIn('"messages"', stdout)

    def test_default_profile_uses_modern_discovery_lifecycle(self) -> None:
        command = stdio_fixture_command("stdio-good-modern")
        code, stdout, stderr = invoke(
            "stdio", "--timeout", "2", "--output", "json", "--", *command
        )
        self.assertEqual(code, 0, stderr)
        value = json.loads(stdout)
        self.assertEqual(value["records"][0]["label"], "server/discover")
        result = value["records"][0]["value"]["result"]
        self.assertEqual(result["resultType"], "complete")
        self.assertEqual(result["supportedVersions"], ["2026-07-28"])

    def test_legacy_stdio_inspection_preserves_discover_and_raw(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        raw = json.dumps(
            {"jsonrpc": "2.0", "id": "raw-id", "method": "ping", "params": {}}
        )
        code, stdout, stderr = invoke(
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "2",
            "--discover",
            "--raw",
            raw,
            "--",
            *command,
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("== initialize ==", stdout)
        self.assertIn("== tools/list ==", stdout)
        self.assertIn("== resources/list ==", stdout)
        self.assertIn("== prompts/list ==", stdout)
        self.assertIn("== raw ping ==", stdout)
        self.assertNotIn("Traceback", stderr)

    def test_raw_stdio_fractional_id_response_is_not_silently_discarded(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        raw = json.dumps(
            {"jsonrpc": "2.0", "id": 1.5, "method": "ping", "params": {}}
        )
        code, stdout, stderr = invoke(
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "2",
            "--raw",
            raw,
            "--",
            *command,
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn('"id": 1.5', stdout)
        self.assertIn('"result"', stdout)

    def test_json_output_is_stable_machine_readable_document(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        code, stdout, stderr = invoke(
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "2",
            "--output",
            "json",
            "--",
            *command,
        )
        self.assertEqual(code, 0, stderr)
        value = json.loads(stdout)
        self.assertEqual(value["schema"], "mcp-probe.inspection/v1")
        self.assertEqual(value["records"][0]["label"], "initialize")

    def test_custom_initialize_params_remain_supported(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        params = {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "custom-client", "version": "9.1"},
        }
        code, stdout, stderr = invoke(
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "2",
            "--init-json",
            json.dumps(params),
            "--",
            *command,
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn('"protocolVersion": "2025-06-18"', stdout)

    def test_invalid_raw_json_is_configuration_error_and_child_is_cleaned_up(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        code, _, stderr = invoke(
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "2",
            "--raw",
            "not-json",
            "--",
            *command,
        )
        self.assertEqual(code, 2)
        self.assertIn("Invalid JSON for --raw", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_http_verbose_and_transcript_redact_configured_credentials(self) -> None:
        cases = (
            ("Authorization", "Bearer very-secret-cli-token"),
            ("GoogleApiKey", "AUDIT_DUMMY_GOOGLE_API_KEY_92741"),
            ("OcpApimSubscriptionKey", "AUDIT_DUMMY_SUBSCRIPTION_KEY_92741"),
            ("X-Client-Key", "AUDIT_X_CLIENT_KEY_88311"),
        )
        with running_http_fixture("http-json") as fixture:
            for header_name, header_value in cases:
                with self.subTest(header=header_name), tempfile.TemporaryDirectory() as temp:
                    transcript = Path(temp) / "trace.ndjson"
                    code, stdout, stderr = invoke(
                        "http",
                        "--url",
                        fixture.url,
                        "--protocol-version",
                        "2025-06-18",
                        "--timeout",
                        "2",
                        "--header",
                        f"{header_name}: {header_value}",
                        "--verbose",
                        "--transcript",
                        str(transcript),
                    )
                    self.assertEqual(code, 0, stderr)
                    combined = stdout + stderr + transcript.read_text(encoding="utf-8")
                    self.assertNotIn(header_value, combined)
                    self.assertIn("[REDACTED]", combined)

    def test_inspection_report_contains_no_environment_values(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        secret = "unprintable-environment-secret"
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "report.json"
            transcript = Path(temp) / "trace.ndjson"
            code, _, stderr = invoke(
                "stdio",
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "2",
                "--env",
                f"MCP_TOKEN={secret}",
                "--report",
                str(report),
                "--transcript",
                str(transcript),
                "--",
                *command,
            )
            self.assertEqual(code, 0, stderr)
            report_text = report.read_text(encoding="utf-8")
            self.assertNotIn(secret, report_text)
            value = json.loads(report_text)
            self.assertIn("MCP_TOKEN", value["target"]["environmentKeys"])
            self.assertEqual(
                value["transcript"]["eventCount"],
                len(transcript.read_text(encoding="utf-8").splitlines()),
            )

    def test_http_inspection_target_redacts_secret_reused_in_safe_query(self) -> None:
        secret = "target-query-secret"
        with running_http_fixture("http-json") as fixture, tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "report.json"
            code, _, stderr = invoke(
                "http",
                "--url",
                f"{fixture.url}?echo={secret}",
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "2",
                "--header",
                f"Authorization: Bearer {secret}",
                "--report",
                str(report),
            )
            self.assertEqual(code, 0, stderr)
            rendered = report.read_text(encoding="utf-8")
        self.assertNotIn(secret, rendered)
        self.assertEqual(json.loads(rendered)["target"]["transport"], "http")


class LaboratoryCliTests(unittest.TestCase):
    def test_modern_http_check_uses_nested_transport_cli(self) -> None:
        with running_http_fixture(
            "http-json", protocol_version="2026-07-28"
        ) as fixture:
            code, stdout, stderr = invoke(
                "check",
                "http",
                "--url",
                fixture.url,
                "--timeout",
                "2",
                "--output",
                "json",
            )
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["target"]["transport"], "http")
        self.assertEqual(report["protocol"]["requestedVersion"], "2026-07-28")
        self.assertEqual(report["overall"]["status"], "PASS")

    def test_check_json_report_and_compatibility_exit_status(self) -> None:
        good = stdio_fixture_command("stdio-good-legacy")
        code, stdout, stderr = invoke(
            "check",
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "2",
            "--output",
            "json",
            "--",
            *good,
        )
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["schema"], "mcp-probe.report/v1")
        self.assertEqual(report["reportType"], "compatibility")
        self.assertEqual(report["overall"]["status"], "PASS")
        cleanup = next(
            finding for finding in report["findings"] if finding["code"] == "STDIO_CLEANUP"
        )
        self.assertEqual(cleanup["status"], "PASS")

        mismatch = stdio_fixture_command("stdio-capability-mismatch")
        code, stdout, stderr = invoke(
            "check",
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--timeout",
            "2",
            "--output",
            "json",
            "--",
            *mismatch,
        )
        self.assertEqual(code, 1, stderr)
        report = json.loads(stdout)
        failures = {
            finding["code"]
            for finding in report["findings"]
            if finding["status"] == "FAIL"
        }
        self.assertIn("CAPABILITY_TOOLS_LIST", failures)

    def test_replay_nonzero_cleanup_is_structured_transport_failure(self) -> None:
        source_command = stdio_fixture_command("stdio-good-legacy")
        target_command = stdio_fixture_command(
            "stdio-good-legacy", "--eof-exit-code", "37"
        )
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.ndjson"
            code, _, stderr = invoke(
                "stdio",
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "2",
                "--transcript",
                str(source),
                "--",
                *source_command,
            )
            self.assertEqual(code, 0, stderr)

            code, stdout, stderr = invoke(
                "replay",
                "stdio",
                "--from",
                str(source),
                "--timeout",
                "2",
                "--output",
                "json",
                "--",
                *target_command,
            )

        self.assertEqual(code, 3, stderr)
        report = json.loads(stdout)
        self.assertFalse(report["replay"]["matchesSource"])
        self.assertIn(
            "TRANSPORT_STDIO_CHILD_EXIT",
            {error["code"] for error in report["errors"]},
        )
        replay_complete = next(
            item for item in report["findings"] if item["code"] == "REPLAY_COMPLETE"
        )
        self.assertEqual(replay_complete["status"], "FAIL")

    def test_replay_http_cleanup_error_cannot_report_a_clean_match(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "http-source.ndjson"
            recorder = EventRecorder(str(source))
            try:
                recorder.record(
                    "client_to_server",
                    "http",
                    payload={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "source", "version": "1"},
                        },
                    },
                    classification="request",
                )
                recorder.record(
                    "server_to_client",
                    "http",
                    payload={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {"protocolVersion": "2025-06-18"},
                    },
                    classification="response",
                    status=200,
                    headers={"Mcp-Session-Id": "source-session"},
                )
            finally:
                recorder.close()

            with running_http_fixture(
                "http-session", termination_status=500
            ) as fixture:
                code, stdout, stderr = invoke(
                    "replay",
                    "http",
                    "--from",
                    str(source),
                    "--url",
                    fixture.url,
                    "--protocol-version",
                    "2025-06-18",
                    "--timeout",
                    "1",
                    "--output",
                    "json",
                )

        self.assertEqual(code, 3, stderr)
        report = json.loads(stdout)
        self.assertFalse(report["replay"]["matchesSource"])
        self.assertIn(
            "TRANSPORT_HTTP_IO", {error["code"] for error in report["errors"]}
        )
        replay_complete = next(
            item for item in report["findings"] if item["code"] == "REPLAY_COMPLETE"
        )
        self.assertEqual(replay_complete["status"], "FAIL")

    def test_reproduced_explicit_http_termination_error_is_not_reclassified(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "http-explicit-delete.ndjson"
            recorder = EventRecorder(str(source))
            try:
                recorder.record(
                    "client_to_server",
                    "http",
                    payload={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "source", "version": "1"},
                        },
                    },
                    classification="request",
                )
                recorder.record(
                    "server_to_client",
                    "http",
                    payload={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "result": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "serverInfo": {"name": "source", "version": "1"},
                        },
                    },
                    classification="response",
                    status=200,
                    headers={"MCP-Session-Id": "captured-session"},
                )
                recorder.record(
                    "client_to_server",
                    "http",
                    classification="session_terminate",
                )
                recorder.record(
                    "probe",
                    "http",
                    classification="session_terminated",
                    status=500,
                )
            finally:
                recorder.close()

            with running_http_fixture(
                "http-session", termination_status=500
            ) as fixture:
                code, stdout, stderr = invoke(
                    "replay",
                    "http",
                    "--from",
                    str(source),
                    "--url",
                    fixture.url,
                    "--protocol-version",
                    "2025-06-18",
                    "--timeout",
                    "1",
                    "--output",
                    "json",
                )

        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertTrue(report["replay"]["matchesSource"])
        self.assertEqual(report["errors"], [])
        replay_complete = next(
            item for item in report["findings"] if item["code"] == "REPLAY_COMPLETE"
        )
        self.assertEqual(replay_complete["status"], "PASS")

    def test_replay_http_connection_failure_is_a_structured_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "http-source.ndjson"
            recorder = EventRecorder(str(source))
            recorder.record(
                "client_to_server",
                "http",
                classification="request",
                payload={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "fixture", "version": "1"},
                    },
                },
            )
            recorder.record(
                "server_to_client",
                "http",
                classification="response",
                status=200,
                payload={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {"protocolVersion": "2025-06-18"},
                },
            )
            recorder.close()

            code, stdout, stderr = invoke(
                "replay",
                "http",
                "--from",
                str(source),
                "--protocol-version",
                "2025-06-18",
                "--url",
                "http://127.0.0.1:1/mcp",
                "--timeout",
                "0.1",
                "--output",
                "json",
            )

        self.assertEqual(code, 3, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["reportType"], "replay")
        self.assertEqual(report["overall"]["status"], "ERROR")
        self.assertFalse(report["replay"]["completed"])
        self.assertFalse(report["replay"]["matchesSource"])
        self.assertIn(
            "TRANSPORT_HTTP_CONNECT", {error["code"] for error in report["errors"]}
        )
        replay_complete = next(
            finding
            for finding in report["findings"]
            if finding["code"] == "REPLAY_COMPLETE"
        )
        self.assertEqual(replay_complete["status"], "FAIL")

    def test_replay_stdio_startup_failure_is_a_structured_json_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "stdio-source.ndjson"
            recorder = EventRecorder(str(source))
            recorder.record(
                "client_to_server",
                "stdio",
                classification="notification",
                payload={"jsonrpc": "2.0", "method": "notifications/test"},
            )
            recorder.close()

            code, stdout, stderr = invoke(
                "replay",
                "stdio",
                "--from",
                str(source),
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "0.1",
                "--output",
                "json",
                "--",
                "definitely-not-an-mcp-probe-replay-command",
            )

        self.assertEqual(code, 3, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["reportType"], "replay")
        self.assertFalse(report["replay"]["completed"])
        self.assertIn(
            "TRANSPORT_STDIO_STARTUP",
            {error["code"] for error in report["errors"]},
        )
        replay_complete = next(
            finding
            for finding in report["findings"]
            if finding["code"] == "REPLAY_COMPLETE"
        )
        self.assertEqual(replay_complete["status"], "FAIL")


class LaboratoryCliContinuationTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX signal and process-group behavior")
    def test_sigterm_runs_finally_cleanup_for_server_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            pid_path = temp_path / "pids.txt"
            server_path = temp_path / "blocking_server.py"
            server_path.write_text(
                "\n".join(
                    (
                        "import os, pathlib, subprocess, sys, time",
                        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])",
                        f"pathlib.Path({str(pid_path)!r}).write_text(f'{{os.getpid()}} {{child.pid}}', encoding='utf-8')",
                        "for _line in sys.stdin.buffer:",
                        "    time.sleep(60)",
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(ENTRYPOINT),
                    "stdio",
                    "--protocol-version",
                    "2025-06-18",
                    "--timeout",
                    "30",
                    "--",
                    sys.executable,
                    str(server_path),
                ],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.addCleanup(self._terminate_if_running, process)
            deadline = time.monotonic() + 5
            while not pid_path.exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue(pid_path.exists(), "fixture server did not start")
            server_pid, descendant_pid = map(
                int, pid_path.read_text(encoding="utf-8").split()
            )
            self.addCleanup(self._terminate_fixture_group, server_pid)

            os.kill(process.pid, signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 130, stdout + stderr)
            self.assertIn("mcp-probe: interrupted", stderr)
            for pid in (server_pid, descendant_pid):
                self.assertTrue(
                    self._wait_until_group_member_gone(pid, server_pid, 3),
                    f"process-group member {pid} survived CLI SIGTERM",
                )

    @staticmethod
    def _terminate_if_running(process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=3)

    @staticmethod
    def _terminate_fixture_group(group_id: int) -> None:
        try:
            os.killpg(group_id, signal.SIGKILL)
        except ProcessLookupError:
            pass

    @staticmethod
    def _wait_until_group_member_gone(
        pid: int, expected_group: int, timeout: float
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
                state = stat[stat.rfind(")") + 2 :].split()[0]
                group = os.getpgid(pid)
            except (FileNotFoundError, ProcessLookupError):
                return True
            # A recycled PID or re-parented process in another group is not
            # the fixture member this assertion is tracking.
            if state == "Z" or group != expected_group:
                return True
            time.sleep(0.02)
        return False

    def test_matrix_runs_explicit_versions_in_order_and_deduplicates(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        code, stdout, stderr = invoke(
            "matrix",
            "stdio",
            "--version",
            "2025-06-18",
            "--version",
            "2025-11-25",
            "--version",
            "2025-06-18",
            "--timeout",
            "2",
            "--output",
            "json",
            "--",
            *command,
        )
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["reportType"], "matrix")
        self.assertEqual(
            report["matrix"]["versions"], ["2025-06-18", "2025-11-25"]
        )
        self.assertEqual(
            [run["overall"]["status"] for run in report["matrix"]["runs"]],
            ["PASS", "PASS"],
        )

    def test_scenario_cli_wraps_findings_in_stable_report(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        code, stdout, stderr = invoke(
            "scenario",
            "stdio",
            "--protocol-version",
            "2025-06-18",
            "--file",
            str(ROOT / "examples" / "scenario-discovery.json"),
            "--output",
            "json",
            "--",
            *command,
        )
        self.assertEqual(code, 0, stderr)
        report = json.loads(stdout)
        self.assertEqual(report["reportType"], "scenario")
        self.assertEqual(report["overall"]["status"], "PASS")
        self.assertIn("SCENARIO_EXPECTATION", {item["code"] for item in report["findings"]})
        self.assertEqual(report["scenario"]["name"], "safe-discovery-and-unknown-method")
        self.assertEqual(report["scenario"]["completedActions"], 6)
        self.assertEqual(report["scenario"]["actionCount"], 6)
        self.assertTrue(report["scenario"]["source"].endswith("scenario-discovery.json"))

    def test_replay_infers_version_and_requires_exact_tool_allow_list(self) -> None:
        command = stdio_fixture_command("stdio-good-legacy")
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "source.ndjson"
            replay_trace = Path(temp) / "replay.ndjson"
            code, _, stderr = invoke(
                "stdio",
                "--protocol-version",
                "2025-06-18",
                "--timeout",
                "2",
                "--transcript",
                str(source),
                "--",
                *command,
            )
            self.assertEqual(code, 0, stderr)

            code, stdout, stderr = invoke(
                "replay",
                "stdio",
                "--from",
                str(source),
                "--transcript",
                str(replay_trace),
                "--timeout",
                "2",
                "--output",
                "json",
                "--",
                *command,
            )
            self.assertEqual(code, 0, stderr)
            report = json.loads(stdout)
            self.assertEqual(report["reportType"], "replay")
            self.assertEqual(report["protocol"]["requestedVersion"], "2025-06-18")
            self.assertEqual(report["overall"]["status"], "PASS")
            self.assertEqual(report["replay"]["source"], str(source))
            self.assertTrue(report["replay"]["completed"])
            self.assertTrue(report["replay"]["matchesSource"])
            self.assertEqual(
                report["replay"]["sentActions"],
                report["replay"]["plannedActions"],
            )
            self.assertEqual(
                report["transcript"]["eventCount"],
                len(replay_trace.read_text(encoding="utf-8").splitlines()),
            )

            active_source = Path(temp) / "active.ndjson"
            recorder = EventRecorder(str(active_source))
            recorder.record(
                "client_to_server",
                "stdio",
                classification="request",
                payload={
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/call",
                    "params": {
                        "name": "fixture_echo",
                        "arguments": {"text": "hi"},
                    },
                },
            )
            recorder.record(
                "server_to_client",
                "stdio",
                classification="response",
                payload={"jsonrpc": "2.0", "id": 8, "result": {"isError": False}},
            )
            recorder.close()
            modern = stdio_fixture_command("stdio-good-modern")

            code, _, stderr = invoke(
                "replay", "stdio", "--from", str(active_source), "--", *modern
            )
            self.assertEqual(code, 2)
            self.assertIn("actively call tool", stderr)

            code, stdout, stderr = invoke(
                "replay",
                "stdio",
                "--from",
                str(active_source),
                "--allow-tool",
                "fixture_echo",
                "--output",
                "json",
                "--",
                *modern,
            )
            self.assertEqual(code, 0, stderr)
            report = json.loads(stdout)
            self.assertTrue(any(item["active"] for item in report["findings"]))


if __name__ == "__main__":
    unittest.main()
