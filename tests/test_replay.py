from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.protocol import profile_for
from mcp_probe_core.replay import (
    ReplayOptions,
    ensure_distinct_transcript_paths,
    load_replay_plan,
    replay_plan,
    replay_transcript,
)
from mcp_probe_core.session import McpSession, SessionConfig
from mcp_probe_core.transcript import EventRecorder, TRANSCRIPT_EVENT_SCHEMA
from mcp_probe_core.transports import HttpTransport, StdioTransport
from tests.fixtures.mcp_fixture import running_http_fixture, stdio_fixture_command


LEGACY_VERSION = "2025-06-18"
MODERN_VERSION = "2026-07-28"


def initialize(request_id: int | str = 1) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": LEGACY_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "replay-test", "version": "1"},
        },
    }


def result(request_id: int | str | None, value: object) -> dict[str, object]:
    return {"jsonrpc": "2.0", "id": request_id, "result": value}


class ReplayTestCase(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def manual_transcript(
        self, events: list[dict[str, object]], name: str = "source.ndjson"
    ) -> Path:
        path = self.directory / name
        recorder = EventRecorder(str(path))
        try:
            for event in events:
                recorder.record(**event)
        finally:
            recorder.close()
        return path

    def stdio_transport(self, profile: str, recorder: EventRecorder) -> StdioTransport:
        return StdioTransport(stdio_fixture_command(profile), {}, recorder)


class StdioReplayIntegrationTests(ReplayTestCase):
    def test_modern_stateless_replay_preserves_per_request_metadata_without_init(self) -> None:
        source_path = self.directory / "modern.ndjson"
        source_recorder = EventRecorder(str(source_path))
        source_transport = self.stdio_transport("stdio-good-modern", source_recorder)
        source_session = McpSession(
            source_transport,
            SessionConfig(protocol_version=MODERN_VERSION),
            source_recorder,
        )
        try:
            self.assertTrue(source_session.establish(2).success)
        finally:
            source_session.close()
            source_recorder.close()

        target_recorder = EventRecorder()
        target_transport = self.stdio_transport("stdio-good-modern", target_recorder)
        try:
            replay = replay_transcript(source_path, target_transport, target_recorder)
        finally:
            target_transport.close()

        self.assertTrue(replay.matches_source)
        self.assertEqual(replay.protocol_version, MODERN_VERSION)
        sent = [
            event["payload"]
            for event in target_recorder.events
            if event.get("direction") == "client_to_server" and "payload" in event
        ]
        self.assertEqual([message["method"] for message in sent], ["server/discover"])
        meta = sent[0]["params"]["_meta"]
        self.assertEqual(
            meta["io.modelcontextprotocol/protocolVersion"], MODERN_VERSION
        )

    def test_real_transcript_replays_messages_ids_notifications_and_order(self) -> None:
        source_path = self.directory / "captured.ndjson"
        source_recorder = EventRecorder(str(source_path))
        source_transport = self.stdio_transport("stdio-good-legacy", source_recorder)
        source_session = McpSession(
            source_transport,
            SessionConfig(protocol_version=LEGACY_VERSION),
            source_recorder,
        )
        try:
            self.assertTrue(source_session.establish(2).success)
            self.assertIn("result", source_session.rpc("tools/list", {}, 2).response.payload)
        finally:
            source_session.close()
            source_recorder.close()

        target_recorder = EventRecorder()
        target_transport = self.stdio_transport("stdio-good-legacy", target_recorder)
        try:
            replay = replay_transcript(source_path, target_transport, target_recorder)
        finally:
            target_transport.close()
            target_recorder.close()

        self.assertTrue(replay.completed)
        self.assertTrue(replay.matches_source)
        self.assertFalse(replay.credentials_reused)
        self.assertEqual(replay.negotiated_version, LEGACY_VERSION)
        self.assertEqual(
            len([finding for finding in replay.findings if finding.code == "REPLAY_EVENT"]),
            replay.planned_actions,
        )
        sent = [
            event["payload"]
            for event in target_recorder.events
            if event["direction"] == "client_to_server" and "payload" in event
        ]
        self.assertEqual([message.get("id") for message in sent if "id" in message], [1, 2])
        self.assertEqual(
            [message.get("method") for message in sent],
            ["initialize", "notifications/initialized", "tools/list"],
        )

    def test_replay_does_not_insert_initialize_or_initialized(self) -> None:
        request = {"jsonrpc": "2.0", "id": "preserved-id", "method": "tools/list", "params": {}}
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": request,
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result("preserved-id", {"tools": []}),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-good-modern", recorder)
        try:
            replay = replay_transcript(source, transport, recorder)
        finally:
            transport.close()

        self.assertTrue(replay.matches_source)
        methods = [
            event.get("method")
            for event in recorder.events
            if event.get("direction") == "client_to_server"
        ]
        self.assertEqual(methods, ["tools/list"])

    def test_captured_server_request_response_is_literal_not_auto_generated(self) -> None:
        server_request_id = "fixture-roots-request"
        captured_reply = {
            "jsonrpc": "2.0",
            "id": server_request_id,
            "result": {"roots": [{"uri": "file:///captured"}]},
        }
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": initialize(7),
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": server_request_id,
                        "method": "roots/list",
                        "params": {},
                    },
                    "classification": "request",
                },
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": captured_reply,
                    "classification": "response",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(
                        7,
                        {
                            "protocolVersion": LEGACY_VERSION,
                            "capabilities": {},
                            "serverInfo": {"name": "fixture", "version": "1"},
                        },
                    ),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-server-request", recorder)
        # Deliberately install the session's automatic roots/list response. A
        # literal replay must temporarily suppress it.
        session = McpSession(
            transport,
            SessionConfig(
                protocol_version=LEGACY_VERSION,
                client_capabilities={"roots": {}},
                roots=[{"uri": "file:///automatic"}],
            ),
            recorder,
        )
        installed_handler = transport.server_request_handler
        try:
            replay = replay_transcript(source, transport, recorder)
        finally:
            transport.close()

        self.assertTrue(replay.matches_source)
        self.assertIs(transport.server_request_handler, installed_handler)
        sent = [
            event["payload"]
            for event in recorder.events
            if event.get("direction") == "client_to_server" and "payload" in event
        ]
        self.assertEqual(sent, [initialize(7), captured_reply])

    def test_structural_response_difference_is_a_typed_failure(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": initialize(),
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(1, {"protocolVersion": LEGACY_VERSION}),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-mismatched-id", recorder)
        try:
            replay = replay_transcript(source, transport, recorder)
        finally:
            transport.close()

        self.assertTrue(replay.completed)
        self.assertFalse(replay.matches_source)
        failures = [finding for finding in replay.findings if finding.status == "FAIL"]
        self.assertEqual(
            [finding.code for finding in failures],
            ["REPLAY_RESPONSE_MATCH", "REPLAY_COMPLETE"],
        )
        self.assertIn("id expected", failures[0].details or "")

    def test_raw_wire_is_replayed_but_recognizable_credentials_are_redacted(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "raw": "Authorization: Bearer captured-secret",
                    "classification": "raw_wire",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error"},
                    },
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-good-modern", recorder)
        try:
            replay = replay_transcript(source, transport, recorder)
        finally:
            transport.close()

        self.assertTrue(replay.matches_source)
        self.assertTrue(replay.redactions_applied)
        serialized = json.dumps(recorder.events)
        self.assertNotIn("captured-secret", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_raw_stdio_replay_preserves_no_newline_framing(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "raw": '{"incomplete":true}',
                    "classification": "raw_wire",
                    "appendNewline": False,
                    "exactBytesRecorded": True,
                }
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-good-modern", recorder)
        try:
            replay = replay_transcript(source, transport, recorder)
            outgoing = next(
                event
                for event in recorder.events
                if event.get("direction") == "client_to_server"
            )
        finally:
            transport.close()
        self.assertTrue(replay.matches_source)
        self.assertIs(outgoing["appendNewline"], False)

    def test_raw_stdio_without_exact_bytes_is_rejected(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "raw": "replacement-characters-are-not-bytes",
                    "classification": "raw_wire",
                    "appendNewline": True,
                    "exactBytesRecorded": False,
                }
            ]
        )
        with self.assertRaisesRegex(ConfigurationError, "did not capture exact bytes"):
            load_replay_plan(source)

    def test_active_tool_replay_requires_exact_allow_list(self) -> None:
        call = {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {"name": "fixture_echo", "arguments": {"text": "hi"}},
        }
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": call,
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(8, {"content": [], "isError": False}),
                    "classification": "response",
                },
            ]
        )
        with self.assertRaisesRegex(ConfigurationError, "actively call tool 'fixture_echo'"):
            load_replay_plan(source)

        options = ReplayOptions(allow_tools=("fixture_echo",))
        authorized_plan = load_replay_plan(source, options)
        bypass_recorder = EventRecorder()
        bypass_transport = self.stdio_transport("stdio-good-modern", bypass_recorder)
        with self.assertRaisesRegex(ConfigurationError, "actively call tool 'fixture_echo'"):
            replay_plan(authorized_plan, bypass_transport, bypass_recorder)
        self.assertIsNone(bypass_transport.process)

        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-good-modern", recorder)
        try:
            replay = replay_transcript(source, transport, recorder, options)
        finally:
            transport.close()
        self.assertTrue(replay.matches_source)
        self.assertEqual(replay.active_tools, ("fixture_echo",))
        self.assertTrue(next(f for f in replay.findings if f.code == "REPLAY_EVENT").active)

    def test_valid_raw_tool_call_cannot_bypass_allow_list(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "raw": json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 9,
                            "method": "tools/call",
                            "params": {"name": "fixture_echo", "arguments": {}},
                        }
                    ),
                    "classification": "raw_wire",
                }
            ]
        )
        with self.assertRaisesRegex(ConfigurationError, "actively call tool 'fixture_echo'"):
            load_replay_plan(source)
        plan = load_replay_plan(
            source, ReplayOptions(allow_tools=("fixture_echo",))
        )
        self.assertEqual(plan.active_tools, ("fixture_echo",))

    def test_preserved_timing_is_individually_and_totally_bounded(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {"jsonrpc": "2.0", "method": "notifications/one"},
                    "classification": "notification",
                    "elapsedMs": 0,
                },
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {"jsonrpc": "2.0", "method": "notifications/two"},
                    "classification": "notification",
                    "elapsedMs": 100_000,
                },
            ]
        )
        # EventRecorder owns elapsedMs, so set deterministic source timing in the
        # loaded plan without hand-writing an invalid schema envelope.
        plan = load_replay_plan(source)
        mutable = [dict(event) for event in plan.events]
        client_events = [event for event in mutable if event["direction"] == "client_to_server"]
        client_events[0]["elapsedMs"] = 0
        client_events[1]["elapsedMs"] = 100_000
        plan = type(plan)(
            source=plan.source,
            source_transport=plan.source_transport,
            protocol_version=plan.protocol_version,
            events=tuple(mutable),
            client_event_count=plan.client_event_count,
            active_tools=plan.active_tools,
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-good-modern", recorder)
        options = ReplayOptions(
            preserve_timing=True,
            max_delay_seconds=0.01,
            max_total_delay_seconds=0.005,
        )
        try:
            with mock.patch("mcp_probe_core.replay.time.sleep") as sleep:
                replay = replay_plan(plan, transport, recorder, options)
        finally:
            transport.close()
        self.assertTrue(replay.matches_source)
        sleep.assert_called_once_with(0.005)


class HttpReplayIntegrationTests(ReplayTestCase):
    def test_raw_http_replay_preserves_only_safe_content_type(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "http",
                    "raw": "{malformed-json",
                    "classification": "raw_wire",
                    "headers": {
                        "Content-Type": "text/plain; captured=opaque-value",
                        "Authorization": "Bearer captured-secret",
                        "Mcp-Session-Id": "captured-session",
                    },
                },
                {
                    "direction": "server_to_client",
                    "transport": "http",
                    "raw": "malformed request body",
                    "classification": "invalid_body",
                    "status": 400,
                },
            ]
        )
        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                replay = replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION),
                )
                captured = fixture.state.received_http[0]
            finally:
                transport.close()
        self.assertTrue(replay.matches_source)
        self.assertEqual(captured["headers"].get("content-type"), "text/plain")
        self.assertNotIn("authorization", captured["headers"])
        self.assertNotIn("mcp-session-id", captured["headers"])
        self.assertNotIn("opaque-value", json.dumps(captured))

    def test_raw_http_initialize_derives_a_fresh_session_for_later_actions(self) -> None:
        init = initialize(41)
        listed = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/list",
            "params": {},
        }
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "http",
                    "raw": json.dumps(init),
                    "classification": "raw_wire",
                },
                {
                    "direction": "server_to_client",
                    "transport": "http",
                    "payload": result(
                        41,
                        {
                            "protocolVersion": LEGACY_VERSION,
                            "capabilities": {},
                            "serverInfo": {"name": "source", "version": "1"},
                        },
                    ),
                    "classification": "response",
                    "status": 200,
                    "headers": {"Mcp-Session-Id": "captured-session"},
                },
                {
                    "direction": "client_to_server",
                    "transport": "http",
                    "raw": json.dumps(listed),
                    "classification": "raw_wire",
                },
                {
                    "direction": "server_to_client",
                    "transport": "http",
                    "payload": result(42, {"tools": []}),
                    "classification": "response",
                    "status": 200,
                },
            ]
        )
        with running_http_fixture(
            "http-session", session_id="fresh-raw-session", require_protocol_header=True
        ) as target_fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                target_fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                replay = replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION),
                )
                received = list(target_fixture.state.received_http)
            finally:
                transport.close()

        self.assertTrue(replay.matches_source)
        self.assertEqual(len(received), 2)
        self.assertNotIn("mcp-session-id", received[0]["headers"])
        self.assertEqual(
            received[1]["headers"].get("mcp-session-id"), "fresh-raw-session"
        )
        self.assertEqual(
            received[1]["headers"].get("mcp-protocol-version"), LEGACY_VERSION
        )

    def test_http_replay_uses_fresh_session_and_never_captured_credentials(self) -> None:
        source_path = self.directory / "http-session.ndjson"
        with running_http_fixture(
            "http-session", session_id="captured-session", require_protocol_header=True
        ) as source_fixture:
            source_recorder = EventRecorder(str(source_path))
            source_transport = HttpTransport(
                source_fixture.url,
                {"Authorization": "Bearer captured-authorization"},
                source_recorder,
                profile_for(LEGACY_VERSION),
            )
            source_session = McpSession(
                source_transport,
                SessionConfig(
                    protocol_version=LEGACY_VERSION,
                    client_info={
                        "name": "replay-test",
                        "version": "1",
                        "client_secret": "captured-client-secret",
                    },
                ),
                source_recorder,
            )
            try:
                self.assertTrue(source_session.establish(2).success)
                source_session.rpc("tools/list", {}, 2)
            finally:
                source_session.close()
                source_recorder.close()

        with running_http_fixture(
            "http-session", session_id="fresh-session", require_protocol_header=True
        ) as target_fixture:
            target_recorder = EventRecorder()
            target_transport = HttpTransport(
                target_fixture.url, {}, target_recorder, profile_for(LEGACY_VERSION)
            )
            replay = replay_transcript(source_path, target_transport, target_recorder)

            self.assertTrue(replay.matches_source)
            self.assertFalse(replay.credentials_reused)
            self.assertTrue(target_fixture.state.terminated)
            records = target_fixture.state.received_http
            serialized = json.dumps(records)
            self.assertNotIn("captured-authorization", serialized)
            self.assertNotIn("captured-client-secret", serialized)
            self.assertNotIn("captured-session", serialized)
            self.assertIn("[REDACTED]", serialized)
            non_initialize = [
                record
                for record in records
                if record["method"] == "POST" and '"method":"initialize"' not in record["body"]
            ]
            self.assertTrue(non_initialize)
            self.assertTrue(
                all(
                    record["headers"].get("mcp-session-id") == "fresh-session"
                    for record in non_initialize
                )
            )

    def test_sse_multiple_events_are_compared_in_order(self) -> None:
        source_path = self.directory / "sse.ndjson"
        with running_http_fixture("http-sse-multi") as source_fixture:
            recorder = EventRecorder(str(source_path))
            transport = HttpTransport(
                source_fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            session = McpSession(
                transport, SessionConfig(protocol_version=LEGACY_VERSION), recorder
            )
            try:
                self.assertTrue(session.establish(2).success)
            finally:
                session.close()
                recorder.close()

        with running_http_fixture("http-sse-multi") as target_fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                target_fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                replay = replay_transcript(source_path, transport, recorder)
            finally:
                transport.close()
        self.assertTrue(replay.matches_source)
        self.assertEqual(replay.received_messages, 2)


class ReplayValidationTests(ReplayTestCase):
    def test_transport_mismatch_is_rejected_before_sending(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {"jsonrpc": "2.0", "method": "notifications/test"},
                    "classification": "notification",
                }
            ]
        )
        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            with self.assertRaisesRegex(ConfigurationError, "Cross-transport"):
                replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION),
                )
            self.assertEqual(fixture.state.received_http, [])

    def test_out_of_order_sequence_and_empty_transcript_are_invalid(self) -> None:
        out_of_order = self.directory / "out-of-order.ndjson"
        base = {
            "schema": TRANSCRIPT_EVENT_SCHEMA,
            "time": "2026-01-01T00:00:00Z",
            "elapsedMs": 0,
            "direction": "client_to_server",
            "transport": "stdio",
            "classification": "notification",
            "payload": {"jsonrpc": "2.0", "method": "notifications/test"},
        }
        lines = [{**base, "seq": 2}, {**base, "seq": 1}]
        out_of_order.write_text(
            "".join(json.dumps(line) + "\n" for line in lines), encoding="utf-8"
        )
        with self.assertRaisesRegex(ConfigurationError, "expected 1"):
            load_replay_plan(out_of_order)

        no_actions = self.manual_transcript(
            [
                {
                    "direction": "probe",
                    "transport": "stdio",
                    "classification": "process_start",
                }
            ],
            "no-actions.ndjson",
        )
        with self.assertRaisesRegex(ConfigurationError, "no client-originated"):
            load_replay_plan(no_actions)

    def test_source_and_destination_transcript_paths_must_differ(self) -> None:
        source = self.directory / "same.ndjson"
        source.write_text("preserve me\n", encoding="utf-8")
        with self.assertRaisesRegex(ConfigurationError, "refusing to overwrite"):
            ensure_distinct_transcript_paths(source, source)
        self.assertEqual(source.read_text(encoding="utf-8"), "preserve me\n")

        alias = self.directory / "." / "same.ndjson"
        with self.assertRaises(ConfigurationError):
            ensure_distinct_transcript_paths(source, alias)


if __name__ == "__main__":
    unittest.main()
