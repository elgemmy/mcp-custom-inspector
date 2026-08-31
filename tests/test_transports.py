from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import sys
import tempfile
import textwrap
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, Iterator

from mcp_probe_core.errors import ProbeTimeout, ProcessExited, TransportError
from mcp_probe_core.protocol import make_notification, make_request, profile_for
from mcp_probe_core.redaction import REDACTED
from mcp_probe_core.transcript import EventRecorder
from mcp_probe_core.transports import (
    HttpTransport,
    StdioTransport,
    parse_http_messages,
    parse_sse_messages,
)
from tests.fixtures.mcp_fixture import running_http_fixture, stdio_fixture_command


LEGACY_VERSION = "2025-06-18"


def initialize_request(request_id: int = 1) -> dict[str, Any]:
    return make_request(
        "initialize",
        request_id,
        {
            "protocolVersion": LEGACY_VERSION,
            "capabilities": {"roots": {"listChanged": False}},
            "clientInfo": {"name": "transport-tests", "version": "1"},
        },
    )


def initialize_stdio(transport: StdioTransport, timeout: float = 1.0) -> Any:
    request = initialize_request()
    transport.send_message(request)
    response = transport.wait_for_response(1, timeout, cancel_on_timeout=False)
    transport.send_message(make_notification("notifications/initialized"))
    return response


@contextlib.contextmanager
def running_static_http(
    body: bytes,
    *,
    status: int = 200,
    content_type: str | None = "application/json",
    headers: dict[str, str] | None = None,
) -> Iterator[str]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args: Any) -> None:
            del args

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            for key, value in (headers or {}).items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)
                self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/mcp"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class StdioTransportTests(unittest.TestCase):
    def test_good_partial_response_stderr_and_cleanup_cross_process_boundary(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command(
                "stdio-partial-output",
                "--chunk-delay",
                "0.001",
                "--stderr-line",
                "fixture diagnostic",
            ),
            {},
            recorder,
        )
        transport.start()
        try:
            response = initialize_stdio(transport)
            self.assertEqual(response.payload["id"], 1)
            listed = transport.rpc("tools/list", {}, 1)
            self.assertEqual(listed.payload["result"]["tools"][0]["name"], "fixture_echo")
        finally:
            cleanup = transport.close()
        classes = [event["classification"] for event in recorder.events]
        self.assertIn("process_start", classes)
        self.assertIn("stderr", classes)
        self.assertIn("stdout_eof", classes)
        self.assertIn("process_exit", classes)
        self.assertEqual(classes[-1], "process_cleanup")
        self.assertEqual(cleanup.returncode, 0)
        self.assertTrue(cleanup.graceful)

    def test_malformed_json_and_non_utf8_are_evidenced_once_then_valid_response_wins(self) -> None:
        for profile, expected_class in (
            ("stdio-malformed-output", "invalid_json"),
            ("stdio-non-utf8", "invalid_utf8"),
        ):
            with self.subTest(profile=profile):
                recorder = EventRecorder()
                transport = StdioTransport(stdio_fixture_command(profile), {}, recorder)
                transport.start()
                try:
                    response = initialize_stdio(transport)
                    self.assertEqual(response.payload["id"], 1)
                    invalid = transport.observed_invalid_messages()
                    self.assertEqual(len(invalid), 1)
                    self.assertEqual(invalid[0].classification, expected_class)
                    self.assertEqual(
                        sum(
                            event["classification"] == expected_class
                            for event in recorder.events
                        ),
                        1,
                    )
                finally:
                    transport.close()

    def test_invalid_response_is_not_mistaken_for_a_correlated_response(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command("stdio-invalid-response"), {}, recorder
        )
        transport.start()
        try:
            transport.send_message(initialize_request())
            with self.assertRaises(ProbeTimeout):
                transport.wait_for_response(1, 0.5, cancel_on_timeout=False)
            invalid = transport.observed_invalid_messages()
            self.assertEqual(len(invalid), 1)
            self.assertEqual(invalid[0].classification, "invalid")
        finally:
            transport.close()

    def test_child_crash_causes_early_process_exited_not_full_timeout(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command("stdio-crash", "--crash-exit-code", "23"),
            {},
            recorder,
        )
        transport.start()
        started = time.monotonic()
        try:
            transport.send_message(initialize_request())
            with self.assertRaises(ProcessExited) as raised:
                transport.wait_for_response(1, 2, cancel_on_timeout=False)
            self.assertLess(time.monotonic() - started, 1)
            self.assertIn("exit 23", str(raised.exception))
        finally:
            cleanup = transport.close()
        self.assertEqual(cleanup.returncode, 23)

    def test_timeout_records_and_sends_cancellation_for_non_initialize_request(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command("stdio-delayed-response", "--delay", "0.15"),
            {},
            recorder,
        )
        transport.start()
        try:
            initialize_stdio(transport, 1)
            with self.assertRaises(ProbeTimeout):
                transport.rpc("tools/list", {}, 0.02)
            cancelled = [
                event
                for event in recorder.events
                if event.get("method") == "notifications/cancelled"
            ]
            self.assertEqual(len(cancelled), 1)
            self.assertEqual(cancelled[0]["payload"]["params"]["requestId"], 2)
            self.assertTrue(
                any(event["classification"] == "timeout" for event in recorder.events)
            )
        finally:
            transport.close()

    def test_out_of_order_responses_are_buffered_by_strict_id_type(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command("stdio-out-of-order"), {}, recorder
        )
        transport.start()
        try:
            initialize_stdio(transport)
            transport.send_message(make_request("tools/list", 2, {}))
            transport.send_message(make_request("resources/list", "2", {}))
            numeric = transport.wait_for_response(2, 1)
            string = transport.wait_for_response("2", 1)
            self.assertEqual(numeric.payload["id"], 2)
            self.assertEqual(string.payload["id"], "2")
        finally:
            transport.close()

    def test_server_request_is_answered_in_background_and_observed_exactly_once(self) -> None:
        script = textwrap.dedent(
            """
            import json, sys, time
            first = json.loads(sys.stdin.readline())
            print(json.dumps({"jsonrpc":"2.0","id":first["id"],"result":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "serverInfo":{"name":"late-request","version":"1"}}}), flush=True)
            time.sleep(0.05)
            print(json.dumps({"jsonrpc":"2.0","id":"late","method":"roots/list","params":{}}), flush=True)
            reply = json.loads(sys.stdin.readline())
            print(json.dumps({"jsonrpc":"2.0","method":"notifications/message","params":{"reply":reply}}), flush=True)
            for _line in sys.stdin:
                pass
            """
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-u", "-c", script], {}, recorder)
        replies: list[dict[str, Any]] = []

        def handler(message: Any) -> dict[str, Any]:
            reply = {"jsonrpc": "2.0", "id": message.payload["id"], "result": {"roots": []}}
            replies.append(reply)
            return reply

        transport.server_request_handler = handler
        transport.start()
        try:
            transport.send_message(initialize_request())
            transport.wait_for_response(1, 1)
            # Deliberately do not enter another response wait while the request arrives.
            deadline = time.monotonic() + 1
            while time.monotonic() < deadline and not replies:
                time.sleep(0.01)
            self.assertEqual(len(replies), 1)
            observed = transport.observed_server_requests()
            self.assertEqual(len(observed), 1)
            self.assertTrue(observed[0].handled)
            self.assertEqual(observed[0].payload["id"], "late")
            sent_replies = [
                event
                for event in recorder.events
                if event.get("direction") == "client_to_server"
                and event.get("id") == "late"
                and event.get("classification") == "response"
            ]
            self.assertEqual(len(sent_replies), 1)
        finally:
            transport.close()

    def test_max_plus_one_line_is_rejected_even_when_it_ends_in_newline(self) -> None:
        script = "import sys; sys.stdout.buffer.write(b'12345678\\n'); sys.stdout.flush()"
        recorder = EventRecorder()
        transport = StdioTransport(
            [sys.executable, "-u", "-c", script], {}, recorder, max_message_bytes=8
        )
        transport.start()
        try:
            message = transport.receive(1)
            self.assertEqual(message.classification, "message_too_large")
            self.assertEqual(len(transport.observed_invalid_messages()), 1)
        finally:
            transport.close()

    def test_raw_wire_transcript_preserves_newline_framing_choice(self) -> None:
        for append_newline in (True, False):
            with self.subTest(append_newline=append_newline):
                script = "import sys; sys.stdin.buffer.read()"
                recorder = EventRecorder()
                transport = StdioTransport(
                    [sys.executable, "-u", "-c", script], {}, recorder
                )
                transport.start()
                transport.send_wire("{broken", append_newline=append_newline)
                transport.close()
                event = next(
                    event
                    for event in recorder.events
                    if event["classification"] == "raw_wire"
                )
                self.assertEqual(event["appendNewline"], append_newline)

    def test_stubborn_process_is_force_killed(self) -> None:
        script = (
            "import signal,sys,time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "print('ready', file=sys.stderr, flush=True); "
            "time.sleep(30)"
        )
        recorder = EventRecorder()
        transport = StdioTransport(
            [sys.executable, "-u", "-c", script],
            {},
            recorder,
            shutdown_timeout=0.03,
        )
        transport.start()
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and not any(
            event["classification"] == "stderr" for event in recorder.events
        ):
            time.sleep(0.005)
        cleanup = transport.close()
        repeated = transport.close()
        self.assertIs(repeated, cleanup)
        self.assertTrue(cleanup.terminated)
        self.assertTrue(cleanup.killed)
        self.assertIsNotNone(cleanup.returncode)
        self.assertIsNotNone(transport.process)
        self.assertIsNotNone(transport.process.poll())
        self.assertEqual(
            sum(
                event["classification"] == "process_cleanup"
                for event in recorder.events
            ),
            1,
        )

    @unittest.skipUnless(os.name == "posix", "process-group cleanup is POSIX-specific")
    def test_orphan_grandchild_is_killed_after_group_leader_exits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = Path(temporary) / "grandchild.pid"
            script = textwrap.dedent(
                """
                import os, signal, subprocess, sys
                child = subprocess.Popen(
                    [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                with open(sys.argv[1], "w", encoding="ascii") as stream:
                    stream.write(str(child.pid))
                os._exit(0)
                """
            )
            recorder = EventRecorder()
            transport = StdioTransport(
                [sys.executable, "-u", "-c", script, str(pid_path)],
                {},
                recorder,
                shutdown_timeout=0.05,
            )
            transport.start()
            assert transport.process is not None
            leader_pid = transport.process.pid
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and (
                not pid_path.exists() or transport.process.poll() is None
            ):
                time.sleep(0.01)
            self.assertTrue(pid_path.exists())
            grandchild_pid = int(pid_path.read_text(encoding="ascii"))
            try:
                cleanup = transport.close()
                self.assertTrue(cleanup.graceful)
                self.assertTrue(cleanup.terminated)
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and self._process_is_running(grandchild_pid):
                    time.sleep(0.01)
                self.assertFalse(self._process_is_running(grandchild_pid))
            finally:
                try:
                    os.killpg(leader_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @staticmethod
    def _process_is_running(pid: int) -> bool:
        stat_path = Path(f"/proc/{pid}/stat")
        if stat_path.exists():
            try:
                return stat_path.read_text(encoding="ascii").split()[2] not in {"Z", "X"}
            except (OSError, IndexError):
                return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True


class HttpTransportTests(unittest.TestCase):
    def make_transport(
        self,
        url: str,
        recorder: EventRecorder,
        *,
        headers: dict[str, str] | None = None,
        version: str = LEGACY_VERSION,
        max_body_bytes: int = 8 * 1024 * 1024,
    ) -> HttpTransport:
        return HttpTransport(
            url,
            headers or {},
            recorder,
            profile_for(version),
            max_body_bytes=max_body_bytes,
        )

    def test_json_and_multi_event_sse_match_response_not_last_message(self) -> None:
        for profile, expected_messages in (("http-json", 1), ("http-sse", 1), ("http-sse-multi", 2)):
            with self.subTest(profile=profile), running_http_fixture(profile) as fixture:
                recorder = EventRecorder()
                transport = self.make_transport(fixture.url, recorder)
                result = transport.rpc("initialize", initialize_request()["params"], 1)
                self.assertEqual(result.response.payload["id"], 1)
                self.assertEqual(len(result.exchange.messages), expected_messages)
                if profile == "http-sse-multi":
                    self.assertEqual(result.exchange.messages[0].classification, "notification")
                    self.assertEqual(result.response, result.exchange.messages[1])

    def test_session_protocol_headers_termination_and_all_output_redaction(self) -> None:
        session_secret = "fixture-session-private"
        with running_http_fixture(
            "http-session",
            session_id=session_secret,
            require_protocol_header=True,
        ) as fixture:
            url_secret = "url-private"
            url = f"{fixture.url}?access_token={url_secret}"
            recorder = EventRecorder()
            transport = self.make_transport(
                url,
                recorder,
                headers={
                    "Authorization": "Bearer auth-private",
                    "Cookie": "cookie-private",
                    "Mcp-Param-X_Test": "argument-private",
                },
            )
            initialized = transport.rpc("initialize", initialize_request()["params"], 1)
            self.assertEqual(initialized.response.payload["id"], 1)
            self.assertEqual(transport.session_id, session_secret)
            listed = transport.rpc("tools/list", {}, 1)
            self.assertEqual(listed.response.payload["id"], 2)
            second_request = fixture.state.received_http[1]
            self.assertEqual(second_request["headers"]["mcp-session-id"], session_secret)
            self.assertEqual(second_request["headers"]["mcp-protocol-version"], LEGACY_VERSION)
            self.assertEqual(transport.terminate_session(1), 204)
            self.assertEqual(transport.close(1), 204)
            self.assertIsNone(transport.session_id)
            self.assertTrue(fixture.state.terminated)
            self.assertEqual(
                sum(request["method"] == "DELETE" for request in fixture.state.received_http),
                1,
            )
            self.assertEqual(
                sum(
                    event["classification"] == "session_terminated"
                    for event in recorder.events
                ),
                1,
            )

            rendered = json.dumps(recorder.events)
            for secret in (
                session_secret,
                url_secret,
                "auth-private",
                "cookie-private",
                "argument-private",
            ):
                self.assertNotIn(secret, rendered)
            self.assertIn(REDACTED, rendered)

    def test_http_error_status_is_retained_with_matching_jsonrpc_response(self) -> None:
        with running_http_fixture("http-error", http_error_status=503) as fixture:
            recorder = EventRecorder()
            transport = self.make_transport(fixture.url, recorder)
            result = transport.rpc("initialize", initialize_request()["params"], 1)
            self.assertEqual(result.exchange.status, 503)
            self.assertEqual(result.response.http_status, 503)
            self.assertEqual(result.response.payload["error"]["code"], -32000)

    def test_malformed_empty_wrong_content_and_invalid_utf8_are_explicit(self) -> None:
        for profile, expected_issue in (
            ("http-malformed-body", "invalid JSON body"),
            ("http-wrong-content-type", "unexpected Content-Type"),
        ):
            with self.subTest(profile=profile), running_http_fixture(profile) as fixture:
                recorder = EventRecorder()
                transport = self.make_transport(fixture.url, recorder)
                exchange = transport.send_message(initialize_request(), 1)
                self.assertTrue(any(expected_issue in issue for issue in exchange.parse_issues))
                if profile == "http-malformed-body":
                    self.assertEqual(exchange.messages, [])
                else:
                    self.assertEqual(len(exchange.messages), 1)

        with running_http_fixture("http-empty", empty_status=202) as fixture:
            recorder = EventRecorder()
            exchange = self.make_transport(fixture.url, recorder).send_message(
                make_notification("notifications/initialized"), 1
            )
            self.assertEqual(exchange.status, 202)
            self.assertEqual(exchange.messages, [])
            self.assertEqual(exchange.parse_issues, [])

        with running_static_http(b"\xff{broken", content_type="application/json") as url:
            recorder = EventRecorder()
            exchange = self.make_transport(url, recorder).send_message(initialize_request(), 1)
            self.assertTrue(any("not valid UTF-8" in issue for issue in exchange.parse_issues))
            self.assertTrue(any("invalid JSON body" in issue for issue in exchange.parse_issues))

    def test_mismatched_response_id_is_rejected(self) -> None:
        body = json.dumps({"jsonrpc": "2.0", "id": 999, "result": {}}).encode()
        with running_static_http(body) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder)
            with self.assertRaises(TransportError) as raised:
                transport.rpc("ping", {}, 1)
            self.assertIn("matching id=1", str(raised.exception))

    def test_timeout_raises_probe_timeout_and_redacts_exception_url(self) -> None:
        with running_http_fixture("http-delayed-response", delay=0.20) as fixture:
            secret = "exception-private"
            recorder = EventRecorder()
            transport = self.make_transport(
                f"{fixture.url}?access_token={secret}", recorder
            )
            with self.assertRaises(ProbeTimeout) as raised:
                transport.send_message(initialize_request(), 0.02)
            self.assertNotIn(secret, str(raised.exception))
            self.assertIn(REDACTED, str(raised.exception))
            self.assertTrue(
                any(event["classification"] == "timeout" for event in recorder.events)
            )

    def test_connection_failure_exception_and_events_do_not_leak_url_credentials(self) -> None:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        secret = "connection-private"
        recorder = EventRecorder()
        transport = self.make_transport(
            f"http://127.0.0.1:{port}/mcp?token={secret}", recorder
        )
        with self.assertRaises(TransportError) as raised:
            transport.send_message(initialize_request(), 0.1)
        rendered = str(raised.exception) + json.dumps(recorder.events)
        self.assertNotIn(secret, rendered)
        self.assertIn(REDACTED, rendered)

    def test_invalid_url_exception_does_not_leak_userinfo_query_or_fragment(self) -> None:
        secrets = ("query-private", "fragment-private")
        recorder = EventRecorder()
        transport = self.make_transport(
            "http://127.0.0.1:1/mcp\n?token=query-private#fragment-private",
            recorder,
        )
        with self.assertRaises(TransportError) as raised:
            transport.send_message(initialize_request(), 0.1)
        rendered = str(raised.exception) + json.dumps(recorder.events)
        for secret in secrets:
            self.assertNotIn(secret, rendered)
        self.assertIn(REDACTED, rendered)
        self.assertIsNone(raised.exception.__cause__)

    def test_body_size_limit_is_enforced(self) -> None:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": {"padding": "x" * 200}}
        ).encode()
        with running_static_http(body) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder, max_body_bytes=32)
            with self.assertRaises(TransportError) as raised:
                transport.send_message(initialize_request(), 1)
            self.assertIn("exceeded 32 bytes", str(raised.exception))

    def test_sse_parser_handles_multiple_data_lines_issues_and_persistent_event_id(self) -> None:
        body = (
            "id: event-1\n"
            "event: message\n"
            'data: {"jsonrpc":"2.0",\n'
            'data: "method":"notifications/message"}\n\n'
            'data: {"jsonrpc":"2.0","id":2,"result":{}}\n'
            "retry: nope\n\n"
        )
        parsed, issues = parse_sse_messages(body)
        self.assertEqual(len(parsed), 2)
        self.assertEqual([event_id for _payload, _event, event_id, _raw in parsed], ["event-1", "event-1"])
        self.assertTrue(any("retry" in issue for issue in issues))

    def test_non_json_content_type_issue_is_preserved_when_body_is_malformed(self) -> None:
        parsed, issues = parse_http_messages("not-json", "text/plain")
        self.assertEqual(parsed, [])
        self.assertTrue(any("unexpected Content-Type" in issue for issue in issues))
        self.assertTrue(any("invalid JSON body" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
