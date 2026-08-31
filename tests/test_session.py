from __future__ import annotations

import contextlib
import json
import sys
import textwrap
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any, Iterator

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.protocol import make_request, profile_for
from mcp_probe_core.redaction import REDACTED
from mcp_probe_core.session import McpSession, SessionConfig, _schema_argument_headers
from mcp_probe_core.transcript import EventRecorder
from mcp_probe_core.transports import HttpTransport, StdioTransport
from tests.fixtures.mcp_fixture import running_http_fixture, stdio_fixture_command


LEGACY_VERSION = "2025-06-18"
MODERN_VERSION = "2026-07-28"


def modern_stdio_command(*, send_server_request: bool = False) -> list[str]:
    script = textwrap.dedent(
        f"""
        import json, sys
        SEND_REQUEST = {send_server_request!r}
        for line in sys.stdin:
            message = json.loads(line)
            if not isinstance(message, dict) or "method" not in message:
                continue
            method = message["method"]
            request_id = message.get("id")
            if method == "server/discover":
                if SEND_REQUEST:
                    print(json.dumps({{"jsonrpc":"2.0","id":"modern-forbidden","method":"roots/list","params":{{}}}}), flush=True)
                result = {{
                    "resultType":"complete",
                    "supportedVersions":["2026-07-28"],
                    "capabilities":{{"tools":{{}}}},
                    "ttlMs":1000,
                    "cacheScope":"private",
                    "_meta":{{"io.modelcontextprotocol/serverInfo":{{"name":"modern-fixture","version":"1"}}}},
                }}
            elif method == "tools/list":
                result = {{
                    "resultType":"complete",
                    "tools":[{{"name":"modern_echo","inputSchema":{{"type":"object"}}}}],
                    "ttlMs":1000,
                    "cacheScope":"private",
                }}
            elif method == "ping":
                result = {{"resultType":"complete"}}
            else:
                print(json.dumps({{"jsonrpc":"2.0","id":request_id,"error":{{"code":-32601,"message":"Method not found"}}}}), flush=True)
                continue
            print(json.dumps({{"jsonrpc":"2.0","id":request_id,"result":result}}), flush=True)
        """
    )
    return [sys.executable, "-u", "-c", script]


@contextlib.contextmanager
def running_modern_http() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    received: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, _format: str, *args: Any) -> None:
            del args

        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            message = json.loads(body)
            received.append(
                {
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "message": message,
                }
            )
            method = message.get("method")
            if method == "server/discover":
                result = {
                    "resultType": "complete",
                    "supportedVersions": [MODERN_VERSION],
                    "capabilities": {"tools": {}},
                    "ttlMs": 1000,
                    "cacheScope": "private",
                    "_meta": {
                        "io.modelcontextprotocol/serverInfo": {
                            "name": "modern-http",
                            "version": "1",
                        }
                    },
                }
            elif method == "tools/list":
                result = {
                    "resultType": "complete",
                    "tools": [
                        {
                            "name": "modern_header",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "value": {
                                        "type": "string",
                                        "x-mcp-header": "X_Test.foo~bar",
                                    }
                                },
                            },
                        }
                    ],
                    "ttlMs": 1000,
                    "cacheScope": "private",
                }
            elif method == "tools/call":
                result = {
                    "resultType": "complete",
                    "content": [{"type": "text", "text": "ok"}],
                    "isError": False,
                }
            else:
                result = {"resultType": "complete"}
            response = json.dumps(
                {"jsonrpc": "2.0", "id": message.get("id"), "result": result},
                separators=(",", ":"),
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
            self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/mcp", received
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class LegacySessionTests(unittest.TestCase):
    def make_stdio_session(
        self,
        profile: str,
        *,
        config: SessionConfig | None = None,
        extra_args: tuple[str, ...] = (),
    ) -> tuple[McpSession, StdioTransport, EventRecorder]:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command(profile, *extra_args), {}, recorder
        )
        session = McpSession(
            transport,
            config or SessionConfig(protocol_version=LEGACY_VERSION),
            recorder,
        )
        return session, transport, recorder

    def test_legacy_establish_negotiates_initializes_and_discovers(self) -> None:
        session, transport, recorder = self.make_stdio_session("stdio-good-legacy")
        try:
            established = session.establish(1)
            self.assertTrue(established.success)
            self.assertTrue(session.established)
            self.assertEqual(established.negotiated_version, LEGACY_VERSION)
            self.assertEqual(session.server_info["name"], "stdio-good-legacy")
            self.assertIn("tools", session.capabilities)
            tools = session.paginate("tools", 1)
            self.assertTrue(tools.complete)
            self.assertEqual(tools.items[0]["name"], "fixture_echo")
        finally:
            session.close()
        methods = [event.get("method") for event in recorder.events]
        self.assertEqual(methods.count("initialize"), 1)
        self.assertEqual(methods.count("notifications/initialized"), 1)
        self.assertEqual(methods.count("tools/list"), 1)
        self.assertEqual(transport.returncode, 0)

    def test_legacy_can_deliberately_omit_initialized_notification(self) -> None:
        config = SessionConfig(protocol_version=LEGACY_VERSION, send_initialized=False)
        session, _transport, recorder = self.make_stdio_session(
            "stdio-good-legacy", config=config
        )
        try:
            self.assertTrue(session.establish(1).success)
            result = session.paginate("tools", 1)
            self.assertFalse(result.complete)
            self.assertEqual(result.error_response.payload["error"]["code"], -32002)
        finally:
            session.close()
        self.assertFalse(
            any(event.get("method") == "notifications/initialized" for event in recorder.events)
        )

    def test_custom_initialize_payload_is_sent_without_normalization(self) -> None:
        custom = {
            "jsonrpc": "2.0",
            "id": "custom-id",
            "method": "initialize",
            "params": {
                "protocolVersion": "made-up-experiment",
                "capabilities": {"experimental": {"exact": True}},
                "clientInfo": {"name": "custom-client", "version": "0"},
                "extra": [1, 2, 3],
            },
        }
        config = SessionConfig(
            protocol_version=LEGACY_VERSION,
            initialize_message=custom,
            send_initialized=False,
        )
        session, _transport, recorder = self.make_stdio_session(
            "stdio-good-legacy", config=config
        )
        try:
            result = session.establish(1)
            self.assertFalse(result.success)
            sent = next(
                event
                for event in recorder.events
                if event["direction"] == "client_to_server"
                and event.get("method") == "initialize"
            )
            self.assertEqual(sent["payload"], custom)
        finally:
            session.close()

    def test_initialize_error_never_triggers_initialized_notification(self) -> None:
        script = textwrap.dedent(
            """
            import json, sys
            message = json.loads(sys.stdin.readline())
            print(json.dumps({"jsonrpc":"2.0","id":message["id"],"error":{"code":-32602,"message":"bad initialize"}}), flush=True)
            for _line in sys.stdin:
                pass
            """
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-u", "-c", script], {}, recorder)
        session = McpSession(
            transport, SessionConfig(protocol_version=LEGACY_VERSION), recorder
        )
        try:
            result = session.establish(1)
            self.assertFalse(result.success)
            self.assertFalse(session.established)
            self.assertFalse(
                any(
                    event.get("method") == "notifications/initialized"
                    for event in recorder.events
                )
            )
        finally:
            session.close()

    def test_roots_server_request_during_initialize_gets_not_initialized_error(self) -> None:
        roots = [{"uri": "file:///safe/root", "name": "fixture-root"}]
        config = SessionConfig(
            protocol_version=LEGACY_VERSION,
            client_capabilities={"roots": {"listChanged": False}},
            roots=roots,
        )
        session, transport, recorder = self.make_stdio_session(
            "stdio-server-request",
            config=config,
            extra_args=("--server-request-mode", "roots-early"),
        )
        try:
            self.assertTrue(session.establish(1).success)
            observed = transport.observed_server_requests()
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0].payload["method"], "roots/list")
            reply = next(
                event
                for event in recorder.events
                if event.get("id") == "fixture-roots-request"
                and event.get("classification") == "response"
            )
            self.assertEqual(reply["payload"]["error"]["code"], -32002)
            self.assertTrue(
                any(
                    event["classification"] == "pre_initialized_server_request"
                    for event in recorder.events
                )
            )
        finally:
            session.close()

    def test_unsupported_legacy_server_request_gets_explicit_method_not_found(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command(
                "stdio-good-legacy",
                "--server-request-mode",
                "unsupported-post",
            ),
            {},
            recorder,
        )
        session = McpSession(
            transport, SessionConfig(protocol_version=LEGACY_VERSION), recorder
        )
        try:
            self.assertTrue(session.establish(1).success)
            self.assertTrue(session.paginate("tools", 1).complete)
            response = next(
                event
                for event in recorder.events
                if event.get("id") == "fixture-roots-request"
                and event.get("classification") == "response"
            )
            self.assertEqual(response["payload"]["error"]["code"], -32601)
            self.assertIn(
                "fixture/unsupported-client-method",
                response["payload"]["error"]["message"],
            )
        finally:
            session.close()

    def test_pagination_collects_pages_and_detects_repeat_loop_and_malformed_cursor(self) -> None:
        cases = {
            "normal": (True, 2, None, None),
            "repeat": (False, 2, "page-2", None),
            "loop": (False, 3, "page-2", None),
            "malformed": (False, 1, None, {"not": "a string"}),
        }
        for mode, expected in cases.items():
            with self.subTest(mode=mode):
                session, _transport, _recorder = self.make_stdio_session(
                    "stdio-pagination",
                    extra_args=("--pagination-mode", mode),
                )
                try:
                    self.assertTrue(session.establish(1).success)
                    result = session.paginate("tools", 1, max_pages=10)
                    self.assertEqual(
                        (
                            result.complete,
                            result.pages,
                            result.repeated_cursor,
                            result.malformed_cursor,
                        ),
                        expected,
                    )
                    self.assertGreaterEqual(len(result.items), 1)
                finally:
                    session.close()

    def test_http_legacy_lifecycle_uses_session_for_initialized_and_closes_once(self) -> None:
        with running_http_fixture(
            "http-session", require_protocol_header=True
        ) as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            session = McpSession(
                transport, SessionConfig(protocol_version=LEGACY_VERSION), recorder
            )
            established = session.establish(1)
            self.assertTrue(established.success)
            requests = fixture.state.received_http
            self.assertEqual(requests[0]["body"].count("initialize"), 1)
            self.assertIn("notifications/initialized", requests[1]["body"])
            self.assertEqual(
                requests[1]["headers"]["mcp-session-id"], fixture.server.config.session_id
            )
            self.assertEqual(requests[1]["headers"]["mcp-protocol-version"], LEGACY_VERSION)
            self.assertEqual(session.close(), 204)
            self.assertEqual(session.close(), 204)
            self.assertEqual(
                sum(request["method"] == "DELETE" for request in requests), 1
            )


class ModernSessionTests(unittest.TestCase):
    def test_modern_establish_uses_discover_per_request_metadata_and_no_legacy_lifecycle(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(modern_stdio_command(), {}, recorder)
        config = SessionConfig(
            protocol_version=MODERN_VERSION,
            client_info={"name": "modern-client", "version": "1"},
            client_capabilities={"tools": {}},
        )
        session = McpSession(transport, config, recorder)
        try:
            established = session.establish(1)
            self.assertTrue(established.success)
            self.assertEqual(session.supported_versions, [MODERN_VERSION])
            self.assertEqual(session.server_info["name"], "modern-fixture")
            self.assertIn("tools", session.capabilities)
            tools = session.paginate("tools", 1)
            self.assertTrue(tools.complete)
            self.assertEqual(tools.items[0]["name"], "modern_echo")
        finally:
            session.close()
        requests = [
            event["payload"]
            for event in recorder.events
            if event["direction"] == "client_to_server"
            and event["classification"] == "request"
        ]
        self.assertEqual([request["method"] for request in requests], ["server/discover", "tools/list"])
        self.assertFalse(
            any(request["method"] == "initialize" for request in requests)
        )
        for request in requests:
            metadata = request["params"]["_meta"]
            self.assertEqual(
                metadata["io.modelcontextprotocol/protocolVersion"], MODERN_VERSION
            )
            self.assertEqual(
                metadata["io.modelcontextprotocol/clientInfo"]["name"], "modern-client"
            )
            self.assertEqual(
                metadata["io.modelcontextprotocol/clientCapabilities"], {"tools": {}}
            )

    def test_modern_server_request_is_visible_but_never_answered(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            modern_stdio_command(send_server_request=True), {}, recorder
        )
        session = McpSession(
            transport, SessionConfig(protocol_version=MODERN_VERSION), recorder
        )
        try:
            self.assertTrue(session.establish(1).success)
            observed = transport.observed_server_requests()
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0].payload["id"], "modern-forbidden")
            self.assertTrue(
                any(
                    event["classification"] == "forbidden_server_request"
                    for event in recorder.events
                )
            )
            self.assertFalse(
                any(
                    event.get("direction") == "client_to_server"
                    and event.get("id") == "modern-forbidden"
                    for event in recorder.events
                )
            )
        finally:
            session.close()

    def test_modern_http_headers_metadata_and_schema_mirrors_use_rfc_tchar_safely(self) -> None:
        with running_modern_http() as (url, received):
            recorder = EventRecorder()
            transport = HttpTransport(
                url, {}, recorder, profile_for(MODERN_VERSION)
            )
            session = McpSession(
                transport, SessionConfig(protocol_version=MODERN_VERSION), recorder
            )
            self.assertTrue(session.establish(1).success)
            tools = session.paginate("tools", 1)
            self.assertTrue(tools.complete)
            value = " leading ünicode\r\nvalue "
            called = session.rpc(
                "tools/call",
                {"name": "modern_header", "arguments": {"value": value}},
                1,
            )
            self.assertEqual(called.response.payload["result"]["isError"], False)

            discover_request, list_request, call_request = received
            for request in received:
                headers = request["headers"]
                self.assertEqual(headers["mcp-protocol-version"], MODERN_VERSION)
                self.assertEqual(headers["mcp-method"], request["message"]["method"])
                self.assertIn("_meta", request["message"]["params"])
            self.assertNotIn("mcp-session-id", discover_request["headers"])
            self.assertEqual(call_request["headers"]["mcp-name"], "modern_header")
            mirrored = call_request["headers"]["mcp-param-x_test.foo~bar"]
            self.assertTrue(mirrored.startswith("=?base64?"))
            self.assertNotIn("\r", mirrored)
            self.assertNotIn("\n", mirrored)

            rendered = json.dumps(recorder.events)
            self.assertNotIn(value, rendered)
            mirrored_events = [
                event
                for event in recorder.events
                if "headers" in event
                and any(key.lower().startswith("mcp-param-") for key in event["headers"])
            ]
            self.assertTrue(mirrored_events)
            for event in mirrored_events:
                for key, header_value in event["headers"].items():
                    if key.lower().startswith("mcp-param-"):
                        self.assertEqual(header_value, REDACTED)
            self.assertIsNone(session.close())
            self.assertIsNone(session.close())

    def test_header_annotation_accepts_full_tchar_and_rejects_injection(self) -> None:
        schema = {
            "type": "object",
            "properties": {
                "accepted": {"x-mcp-header": "X_Test.foo~bar"},
                "injected": {"x-mcp-header": "Bad\r\nInjected"},
                "colon": {"x-mcp-header": "Bad:Name"},
                "number": {"x-mcp-header": "Count"},
                "object": {"x-mcp-header": "Ignored"},
            },
        }
        headers = _schema_argument_headers(
            schema,
            {
                "accepted": "ünicode\r\nvalue",
                "injected": "secret",
                "colon": "secret",
                "number": 42,
                "object": {"not": "scalar"},
            },
        )
        self.assertEqual(set(headers), {"Mcp-Param-X_Test.foo~bar", "Mcp-Param-Count"})
        self.assertTrue(headers["Mcp-Param-X_Test.foo~bar"].startswith("=?base64?"))
        self.assertEqual(headers["Mcp-Param-Count"], "42")
        self.assertFalse(any("\r" in key or "\n" in key or ":" in key for key in headers))
        self.assertFalse(any("\r" in value or "\n" in value for value in headers.values()))

    def test_target_descriptions_redact_values_and_do_not_expose_header_values(self) -> None:
        recorder = EventRecorder()
        stdio = StdioTransport(
            ["server", "--token", "command-private"],
            {"NOTION_TOKEN": "env-private"},
            recorder,
        )
        stdio_session = McpSession(
            stdio, SessionConfig(protocol_version=MODERN_VERSION), recorder
        )
        self.assertEqual(
            stdio_session.target_description()["command"],
            ["server", "--token", REDACTED],
        )
        self.assertEqual(
            stdio_session.target_description()["environmentKeys"], ["NOTION_TOKEN"]
        )

        http = HttpTransport(
            "https://u:p@example.test/mcp?token=url-private#fragment-private",
            {"Authorization": "Bearer header-private"},
            recorder,
            profile_for(MODERN_VERSION),
        )
        http_session = McpSession(
            http, SessionConfig(protocol_version=MODERN_VERSION), recorder
        )
        description = http_session.target_description()
        rendered = json.dumps(description)
        for secret in ("u:p", "url-private", "fragment-private", "header-private"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(description["headerNames"], ["Authorization"])

    def test_invalid_profile_and_uncorrelatable_exact_id_are_configuration_errors(self) -> None:
        with self.assertRaises(ConfigurationError):
            SessionConfig(protocol_version="not-supported").profile

        recorder = EventRecorder()
        transport = StdioTransport(modern_stdio_command(), {}, recorder)
        session = McpSession(
            transport, SessionConfig(protocol_version=MODERN_VERSION), recorder
        )
        session.start()
        try:
            for bad_id in (True, [1]):
                with self.subTest(bad_id=bad_id), self.assertRaises(ConfigurationError):
                    session.send_exact_request(
                        {"jsonrpc": "2.0", "id": bad_id, "method": "ping"}, 0.1
                    )
        finally:
            session.close()


if __name__ == "__main__":
    unittest.main()
