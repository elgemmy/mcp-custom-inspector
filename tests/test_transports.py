from __future__ import annotations

import contextlib
import json
import os
import signal
import socket
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, Iterator
from unittest import mock

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


@contextlib.contextmanager
def running_http_handler(
    handler: type[BaseHTTPRequestHandler],
) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
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
    def test_2025_03_batch_items_are_evidenced_and_server_replies_grouped(self) -> None:
        script = textwrap.dedent(
            """
            import json, sys
            request = json.loads(sys.stdin.readline())
            batch = [
                {"jsonrpc":"2.0","id":"server-ping","method":"ping","params":{}},
                {"jsonrpc":"2.0","id":request["id"],"result":{"ok":True}},
            ]
            print(json.dumps(batch, separators=(",", ":")), flush=True)
            reply = json.loads(sys.stdin.readline())
            print(json.dumps({"jsonrpc":"2.0","method":"fixture/batch-reply","params":{"reply":reply}}, separators=(",", ":")), flush=True)
            for _line in sys.stdin:
                pass
            """
        )
        recorder = EventRecorder()
        transport = StdioTransport(
            [sys.executable, "-u", "-c", script],
            {},
            recorder,
            profile=profile_for("2025-03-26"),
        )
        transport.server_request_handler = lambda inbound: {
            "jsonrpc": "2.0",
            "id": inbound.payload["id"],
            "result": {},
        }
        transport.start()
        try:
            transport.send_message(make_request("ping", 1, {}), 1)
            response = transport.wait_for_response(1, 1)
            self.assertEqual(response.payload["result"], {"ok": True})
            notification = transport.receive(1)
            self.assertEqual(notification.payload["method"], "fixture/batch-reply")
            reply = notification.payload["params"]["reply"]
            self.assertIsInstance(reply, list)
            self.assertEqual(reply[0]["id"], "server-ping")
        finally:
            transport.close()
        classes = [event["classification"] for event in recorder.events]
        self.assertIn("batch", classes)
        item_events = [event for event in recorder.events if "batchEvidence" in event]
        self.assertEqual(len(item_events), 2)

    def test_newer_profile_quarantines_inbound_batch(self) -> None:
        script = textwrap.dedent(
            """
            import json, sys
            request = json.loads(sys.stdin.readline())
            print(json.dumps([{"jsonrpc":"2.0","id":request["id"],"result":{}}]), flush=True)
            """
        )
        recorder = EventRecorder()
        transport = StdioTransport(
            [sys.executable, "-u", "-c", script],
            {},
            recorder,
            profile=profile_for("2025-06-18"),
        )
        transport.start()
        try:
            transport.send_message(make_request("ping", 1, {}), 1)
            with self.assertRaises(ProcessExited):
                transport.wait_for_response(1, 1, cancel_on_timeout=False)
            invalid = transport.observed_invalid_messages()
            self.assertTrue(any(item.classification == "invalid_batch" for item in invalid))
        finally:
            transport.close()

    def test_write_backpressure_times_out_and_kills_non_reader(self) -> None:
        script = "import time; time.sleep(60)"
        recorder = EventRecorder()
        transport = StdioTransport(
            [sys.executable, "-u", "-c", script],
            {},
            recorder,
            max_message_bytes=128 * 1024,
            shutdown_timeout=0.1,
            write_timeout=0.05,
        )
        transport.start()
        started = time.monotonic()
        with self.assertRaises(TransportError):
            transport.send_wire(b"x" * (128 * 1024 - 1), timeout=0.05)
        self.assertLess(time.monotonic() - started, 1.0)
        cleanup = transport.close()
        self.assertIsNotNone(cleanup.returncode)
        self.assertTrue(
            any(event["classification"] == "write_timeout" for event in recorder.events)
        )

    def test_outgoing_wire_limit_fails_before_full_payload_capture(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            [sys.executable, "-u", "-c", "import sys; list(sys.stdin)"],
            {},
            recorder,
            max_message_bytes=64,
        )
        transport.start()
        try:
            with self.assertRaises(TransportError):
                transport.send_wire(b"x" * 65)
        finally:
            transport.close()
        event = next(
            item
            for item in recorder.events
            if item["classification"] == "outgoing_message_too_large"
        )
        self.assertEqual(event["byteLength"], 66)
        self.assertNotIn("raw", event)

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

    def test_close_racing_server_request_handler_does_not_escape_reader_thread(self) -> None:
        script = textwrap.dedent(
            """
            import json, sys
            first = json.loads(sys.stdin.readline())
            print(json.dumps({"jsonrpc":"2.0","id":first["id"],"result":{
                "protocolVersion":"2025-06-18","capabilities":{},
                "serverInfo":{"name":"closing-request","version":"1"}}}), flush=True)
            print(json.dumps({"jsonrpc":"2.0","id":"late","method":"roots/list","params":{}}), flush=True)
            for _line in sys.stdin:
                pass
            """
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-u", "-c", script], {}, recorder)
        handler_started = threading.Event()
        release_handler = threading.Event()

        def handler(message: Any) -> dict[str, Any]:
            handler_started.set()
            release_handler.wait(1)
            return {"jsonrpc": "2.0", "id": message.payload["id"], "result": {}}

        transport.server_request_handler = handler
        transport.start()
        transport.send_message(initialize_request())
        transport.wait_for_response(1, 1)
        self.assertTrue(handler_started.wait(1))

        close_thread = threading.Thread(target=transport.close)
        close_thread.start()
        self.assertTrue(transport._closing.wait(1))
        release_handler.set()
        close_thread.join(2)
        self.assertFalse(close_thread.is_alive())
        for thread in transport._threads:
            thread.join(1)
        self.assertTrue(
            any(
                event["classification"] == "server_request_response_skipped"
                for event in recorder.events
            )
        )

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

    def test_http_json_batch_is_profile_gated_and_items_are_correlatable(self) -> None:
        body = json.dumps(
            [
                {"jsonrpc": "2.0", "method": "notifications/progress", "params": {}},
                {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}},
            ],
            separators=(",", ":"),
        ).encode()
        with running_static_http(body) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder, version="2025-03-26")
            result = transport.rpc("ping", {}, 1)
            self.assertEqual(result.response.payload["result"], {"ok": True})
            self.assertEqual(len(result.exchange.messages), 2)
            self.assertTrue(
                all(
                    "batchEvidence" in event
                    for event in recorder.events
                    if event.get("batchIndex") is not None
                )
            )

        with running_static_http(body) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder, version="2025-06-18")
            with self.assertRaises(TransportError):
                transport.rpc("ping", {}, 1)
            self.assertTrue(
                any(event["classification"] == "invalid_batch" for event in recorder.events)
            )

    def test_sse_parser_enforces_event_issue_id_and_line_limits(self) -> None:
        event = 'data: {"jsonrpc":"2.0","method":"n"}\n\n'
        with self.assertRaises(TransportError):
            parse_sse_messages(event * 1001)
        with self.assertRaises(TransportError):
            parse_sse_messages("retry: nope\n" * 101)
        with self.assertRaises(TransportError):
            parse_sse_messages("id: " + "x" * 4097 + "\n\n")
        with mock.patch("mcp_probe_core.transports.MAX_SSE_FIELD_BYTES", 32):
            with self.assertRaises(TransportError):
                parse_sse_messages(":" + "x" * 33 + "\n\n")

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

    def test_persistent_sse_returns_after_correlated_response_and_ignores_empty_priming(self) -> None:
        handler_finished = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *args: Any) -> None:
                del args

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(length))
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                response = {
                    "jsonrpc": "2.0",
                    "id": request["id"],
                    "result": {"ok": True},
                }
                # Bare CR is a valid SSE line terminator, including on a
                # response stream which deliberately remains open.
                self.wfile.write(b"id: primed\rdata:\r\r")
                self.wfile.write(
                    f"data: {json.dumps(response, separators=(',', ':'))}\r\r".encode()
                )
                self.wfile.flush()
                handler_finished.wait(0.75)

        with running_http_handler(Handler) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder)
            started = time.monotonic()
            result = transport.rpc("ping", {}, 0.4)
            elapsed = time.monotonic() - started
            handler_finished.set()
        self.assertLess(elapsed, 0.3)
        self.assertEqual(result.response.payload["result"], {"ok": True})
        self.assertEqual(len(result.exchange.messages), 1)
        self.assertEqual(result.response.sse_id, "primed")
        self.assertEqual(result.exchange.parse_issues, [])

    def test_sse_server_request_is_answered_before_final_response_exactly_once(self) -> None:
        reply_received = threading.Event()
        keep_outer_open = threading.Event()
        received_replies: list[Any] = []
        handler_calls: list[Any] = []

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *args: Any) -> None:
                del args

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                message = json.loads(self.rfile.read(length))
                if "method" not in message:
                    received_replies.append(message)
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    reply_received.set()
                    return

                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                server_request = {
                    "jsonrpc": "2.0",
                    "id": "server-roots",
                    "method": "roots/list",
                    "params": {},
                }
                self.wfile.write(
                    f"data: {json.dumps(server_request, separators=(',', ':'))}\n\n".encode()
                )
                self.wfile.flush()
                if not reply_received.wait(0.6):
                    return
                response = {"jsonrpc": "2.0", "id": message["id"], "result": {}}
                self.wfile.write(
                    f"data: {json.dumps(response, separators=(',', ':'))}\n\n".encode()
                )
                self.wfile.flush()
                keep_outer_open.wait(0.75)

        with running_http_handler(Handler) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder)

            def answer(inbound: Any) -> dict[str, Any]:
                handler_calls.append(inbound.payload)
                return {
                    "jsonrpc": "2.0",
                    "id": inbound.payload["id"],
                    "result": {"roots": []},
                }

            transport.server_request_handler = answer
            result = transport.rpc("ping", {}, 0.8)
            keep_outer_open.set()
        self.assertEqual(result.response.payload["id"], 1)
        self.assertEqual(len(handler_calls), 1)
        self.assertEqual(len(received_replies), 1)
        self.assertEqual(received_replies[0]["id"], "server-roots")
        request = next(
            message
            for message in result.exchange.messages
            if message.classification == "request"
        )
        self.assertTrue(request.handled)
        response_markers = [
            event
            for event in recorder.events
            if event["classification"] == "server_request_response"
        ]
        self.assertEqual(len(response_markers), 1)
        self.assertEqual(response_markers[0]["requestId"], "server-roots")
        self.assertEqual(response_markers[0]["httpStatus"], 202)
        self.assertTrue(response_markers[0]["idMatched"])

    def test_sse_trickle_is_bounded_by_total_deadline(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *args: Any) -> None:
                del args

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                request = json.loads(self.rfile.read(length))
                payload = (
                    f"data: {json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': {}})}\n\n"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                try:
                    for byte in payload:
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(0.025)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        with running_http_handler(Handler) as url:
            transport = self.make_transport(url, EventRecorder())
            started = time.monotonic()
            with self.assertRaises(ProbeTimeout):
                transport.rpc("ping", {}, 0.12)
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 0.35)

    def test_redirect_is_exposed_without_forwarding_credentials(self) -> None:
        target_received = threading.Event()
        target_headers: list[dict[str, str]] = []

        class TargetHandler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *args: Any) -> None:
                del args

            def do_POST(self) -> None:  # noqa: N802
                target_headers.append({key.lower(): value for key, value in self.headers.items()})
                target_received.set()
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        with running_http_handler(TargetHandler) as target_url:
            class RedirectHandler(BaseHTTPRequestHandler):
                protocol_version = "HTTP/1.1"

                def log_message(self, _format: str, *args: Any) -> None:
                    del args

                def do_POST(self) -> None:  # noqa: N802
                    length = int(self.headers.get("Content-Length", "0"))
                    self.rfile.read(length)
                    self.send_response(307)
                    self.send_header("Location", target_url)
                    self.send_header("Content-Length", "0")
                    self.end_headers()

            with running_http_handler(RedirectHandler) as redirect_url:
                transport = self.make_transport(
                    redirect_url,
                    EventRecorder(),
                    headers={"Authorization": "Bearer redirect-private"},
                )
                exchange = transport.send_message(initialize_request(), 0.5)
                time.sleep(0.05)
        self.assertEqual(exchange.status, 307)
        self.assertFalse(target_received.is_set())
        self.assertEqual(target_headers, [])

    def test_invalid_session_id_is_never_stored_or_resent(self) -> None:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": LEGACY_VERSION}}
        ).encode()
        with running_static_http(
            body, headers={"Mcp-Session-Id": "invalid session"}
        ) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder)
            with self.assertRaises(TransportError) as raised:
                transport.send_message(initialize_request(), 0.5)
        self.assertIsNone(transport.session_id)
        self.assertIn("invalid MCP-Session-Id", str(raised.exception))
        self.assertTrue(
            any(event["classification"] == "invalid_session_id" for event in recorder.events)
        )

    def test_http_raw_wire_marks_non_utf8_bytes_as_inexact(self) -> None:
        with running_static_http(b"", status=400, content_type=None) as url:
            recorder = EventRecorder()
            transport = self.make_transport(url, recorder)
            transport.send_wire(b"\xff\xfe", 0.5)
            transport.send_wire(b"{}", 0.5)
        raw_events = [
            event for event in recorder.events if event["classification"] == "raw_wire"
        ]
        self.assertEqual(
            [event["exactBytesRecorded"] for event in raw_events], [False, True]
        )

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

    def test_sse_parser_ignores_empty_data_priming_event(self) -> None:
        parsed, issues = parse_sse_messages(
            'id: prime\ndata:\n\ndata: {"jsonrpc":"2.0","id":1,"result":{}}\n\n'
        )
        self.assertEqual(issues, [])
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0][2], "prime")

    def test_non_json_content_type_issue_is_preserved_when_body_is_malformed(self) -> None:
        parsed, issues = parse_http_messages("not-json", "text/plain")
        self.assertEqual(parsed, [])
        self.assertTrue(any("unexpected Content-Type" in issue for issue in issues))
        self.assertTrue(any("invalid JSON body" in issue for issue in issues))


if __name__ == "__main__":
    unittest.main()
