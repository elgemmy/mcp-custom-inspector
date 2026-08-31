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

    def test_http_verbose_and_transcript_redact_authorization(self) -> None:
        secret = "very-secret-cli-token"
        with running_http_fixture("http-json") as fixture, tempfile.TemporaryDirectory() as temp:
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
                f"Authorization: Bearer {secret}",
                "--verbose",
                "--transcript",
                str(transcript),
            )
            self.assertEqual(code, 0, stderr)
            combined = stdout + stderr + transcript.read_text(encoding="utf-8")
            self.assertNotIn(secret, combined)
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
                    self._wait_until_gone(pid, 3),
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
    def _wait_until_gone(pid: int, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                state = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()[2]
            except (FileNotFoundError, ProcessLookupError):
                return True
            if state == "Z":
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
