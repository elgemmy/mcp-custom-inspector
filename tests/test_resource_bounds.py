from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from mcp_probe_core.errors import ConfigurationError, TransportError
from mcp_probe_core.scenario import MAX_SCENARIO_BYTES, load_scenario
from mcp_probe_core.session import McpSession, SessionConfig
from mcp_probe_core.transcript import EventRecorder, load_transcript
from mcp_probe_core.protocol import profile_for
from mcp_probe_core.transports import (
    MAX_HTTP_SERVER_REQUEST_DEPTH,
    HttpExchange,
    HttpTransport,
    InboundMessage,
    StdioTransport,
)
from tests.fixtures.mcp_fixture import stdio_fixture_command


class ArtifactBoundTests(unittest.TestCase):
    def test_scenario_loader_rejects_oversized_input_before_json_decode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.json"
            path.write_bytes(b" " * (MAX_SCENARIO_BYTES + 1))
            with self.assertRaises(ConfigurationError) as raised:
                load_scenario(path)
        self.assertIn("byte safety limit", str(raised.exception))

    def test_transcript_loader_enforces_total_bytes_while_streaming(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "large.ndjson"
            path.write_bytes(b" " * 33)
            with mock.patch("mcp_probe_core.transcript.MAX_TRANSCRIPT_BYTES", 32):
                with self.assertRaises(ConfigurationError) as raised:
                    load_transcript(path)
        self.assertIn("byte safety limit", str(raised.exception))


class RuntimeBoundTests(unittest.TestCase):
    def test_http_invalid_server_request_null_id_error_can_be_posted(self) -> None:
        recorder = EventRecorder()
        transport = HttpTransport(
            "http://127.0.0.1:1/mcp",
            {},
            recorder,
            profile_for("2025-06-18"),
        )
        inbound = InboundMessage(
            {"jsonrpc": "2.0", "id": True, "method": "roots/list", "params": {}},
            "",
            "request",
            "event:1",
        )
        transport.server_request_handler = lambda _message: {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request"},
        }
        exchange = HttpExchange(202, {}, "", [], [])
        with mock.patch.object(transport, "send_message", return_value=exchange) as send:
            transport._service_http_server_requests(
                [inbound], time.monotonic() + 1, 0, grouped=False
            )
        self.assertIsNone(send.call_args.args[0]["id"])
        marker = next(
            event
            for event in recorder.events
            if event["classification"] == "server_request_response"
        )
        self.assertTrue(marker["invalidRequestResponse"])
        self.assertFalse(marker["idMatched"])

    def test_nested_http_server_request_depth_is_a_hard_failure(self) -> None:
        recorder = EventRecorder()
        transport = HttpTransport(
            "http://127.0.0.1:1/mcp",
            {},
            recorder,
            profile_for("2025-06-18"),
        )
        inbound = InboundMessage(
            {"jsonrpc": "2.0", "id": "nested", "method": "ping", "params": {}},
            "",
            "request",
            "event:1",
        )
        transport.server_request_handler = lambda message: {
            "jsonrpc": "2.0",
            "id": message.payload["id"],
            "result": {},
        }
        with self.assertRaises(TransportError):
            transport._service_http_server_requests(
                [inbound],
                time.monotonic() + 1,
                MAX_HTTP_SERVER_REQUEST_DEPTH,
                grouped=False,
            )
        self.assertTrue(
            any(
                event["classification"] == "server_request_depth_limit"
                for event in recorder.events
            )
        )

    def test_stdio_queue_flood_is_a_hard_transport_failure(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            ["fixture-command"], {}, recorder, shutdown_timeout=0.1
        )
        for index in range(1000):
            message = InboundMessage(
                {"jsonrpc": "2.0", "method": "fixture/flood", "params": {"i": index}},
                "x",
                "notification",
                f"event:{index + 1}",
            )
            self.assertTrue(
                transport._queue_put(transport._incoming, message, "incoming messages")
            )
        overflow = InboundMessage({}, "x", "invalid", "event:overflow")
        self.assertFalse(
            transport._queue_put(transport._incoming, overflow, "incoming messages")
        )
        with self.assertRaises(TransportError) as raised:
            transport.raise_if_failed()
        self.assertIn("safety limit", str(raised.exception))
        self.assertTrue(
            any(event["classification"] == "resource_limit" for event in recorder.events)
        )

    def test_pagination_item_budget_is_cumulative_across_pages(self) -> None:
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command("stdio-pagination"),
            {},
            recorder,
            shutdown_timeout=0.25,
        )
        session = McpSession(
            transport,
            SessionConfig(protocol_version="2025-06-18"),
            recorder,
        )
        try:
            self.assertTrue(session.establish(1).success)
            with mock.patch("mcp_probe_core.session.MAX_PAGINATION_TOTAL_ITEMS", 1):
                with self.assertRaises(TransportError) as raised:
                    session.paginate("tools", 1)
            self.assertIn("pagination", str(raised.exception).lower())
        finally:
            session.close()
        self.assertTrue(
            any(event["classification"] == "resource_limit" for event in recorder.events)
        )


if __name__ == "__main__":
    unittest.main()
