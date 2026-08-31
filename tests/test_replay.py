from __future__ import annotations

import json
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import mcp_probe_core.replay as replay_module
from mcp_probe_core.errors import ConfigurationError, HttpExchangeError
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
from mcp_probe_core.transports import (
    HttpExchange,
    HttpTransport,
    InboundMessage,
    StdioTransport,
)
from tests.fixtures.mcp_fixture import running_http_fixture, stdio_fixture_command


LEGACY_VERSION = "2025-06-18"
MODERN_VERSION = "2026-07-28"


class _ExitBeforeDrainRecorder(EventRecorder):
    """Force the real process watcher to record exit during stdout draining."""

    def __init__(self, path: str, *, block_at_message: int) -> None:
        super().__init__(path)
        self.block_at_message = block_at_message
        self.server_messages = 0
        self.exit_recorded = threading.Event()

    def record(
        self,
        direction: str,
        transport: str,
        *,
        classification: str | None = None,
        **metadata: object,
    ) -> str:
        if direction == "server_to_client" and transport == "stdio":
            self.server_messages += 1
            if self.server_messages == self.block_at_message:
                self.exit_recorded.wait(2)
        evidence = super().record(
            direction,
            transport,
            classification=classification,
            **metadata,
        )
        if transport == "stdio" and classification == "process_exit":
            self.exit_recorded.set()
        return evidence


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

    def stdio_transport(
        self, profile: str, recorder: EventRecorder, *extra: str
    ) -> StdioTransport:
        return StdioTransport(stdio_fixture_command(profile, *extra), {}, recorder)


class StdioReplayIntegrationTests(ReplayTestCase):
    def test_response_observed_before_source_action_is_an_ordering_mismatch(self) -> None:
        first = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}
        second = {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}}
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": first,
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(1, {}),
                    "classification": "response",
                },
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": second,
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(2, {}),
                    "classification": "response",
                },
            ]
        )
        script = (
            "import json,sys\n"
            "first=json.loads(sys.stdin.buffer.readline())\n"
            "print(json.dumps({'jsonrpc':'2.0','id':first['id'],'result':{}}), flush=True)\n"
            "print(json.dumps({'jsonrpc':'2.0','id':2,'result':{}}), flush=True)\n"
            "for _line in sys.stdin.buffer:\n"
            "    pass\n"
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", script], {}, recorder)
        original_send = replay_module._send_stdio_action

        def send_after_early_output(event, target, timeout):
            payload = event.get("payload")
            if isinstance(payload, dict) and payload.get("id") == 2:
                deadline = time.monotonic() + 1
                while time.monotonic() < deadline and sum(
                    item.get("direction") == "server_to_client"
                    for item in recorder.events
                ) < 2:
                    time.sleep(0.005)
            return original_send(event, target, timeout)

        try:
            with mock.patch(
                "mcp_probe_core.replay._send_stdio_action",
                side_effect=send_after_early_output,
            ):
                replay = replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.3),
                )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        mismatch = next(
            finding
            for finding in replay.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
            and finding.status == "FAIL"
        )
        self.assertIn("before the preceding source client action", mismatch.details)

    def test_delayed_message_after_unanswered_action_is_not_a_false_pass(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {
                        "jsonrpc": "2.0",
                        "method": "notifications/test",
                    },
                    "classification": "notification",
                }
            ]
        )
        script = (
            "import json,sys,time\n"
            "json.loads(sys.stdin.buffer.readline())\n"
            "time.sleep(0.15)\n"
            "print(json.dumps({'jsonrpc':'2.0','method':'notifications/late'}), flush=True)\n"
            "for _line in sys.stdin.buffer:\n"
            "    pass\n"
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", script], {}, recorder)
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.5),
            )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        self.assertEqual(replay.received_messages, 1)

    def test_duplicate_id_reuse_keeps_lifecycle_response_context(self) -> None:
        initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        ping = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}
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
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": initialized,
                    "classification": "notification",
                },
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": ping,
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(1, {}),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport(
            "stdio-good-legacy",
            recorder,
            "--protocol-version",
            "2025-11-25",
        )
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION),
            )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        mismatch = next(
            finding
            for finding in replay.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
            and finding.status == "FAIL"
        )
        self.assertIn("protocolVersion", mismatch.details)

    def test_captured_timeout_must_be_reproduced(self) -> None:
        request = {"jsonrpc": "2.0", "id": 12, "method": "ping", "params": {}}
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": request,
                    "classification": "request",
                },
                {
                    "direction": "probe",
                    "transport": "stdio",
                    "classification": "timeout",
                    "requestId": 12,
                    "timeoutSeconds": 0.05,
                },
            ]
        )
        silent_script = (
            "import sys\n"
            "for _line in sys.stdin.buffer:\n"
            "    pass\n"
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", silent_script], {}, recorder)
        try:
            reproduced = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.1),
            )
        finally:
            transport.close()
        self.assertTrue(reproduced.matches_source)
        timeout_match = next(
            finding
            for finding in reproduced.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertEqual(timeout_match.status, "PASS")
        self.assertEqual(timeout_match.expected["requestId"], 12)
        self.assertEqual(timeout_match.expected, timeout_match.actual)

        response_script = (
            "import json,sys\n"
            "message=json.loads(sys.stdin.buffer.readline())\n"
            "print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':{}}), flush=True)\n"
            "for _line in sys.stdin.buffer:\n"
            "    pass\n"
        )
        changed_recorder = EventRecorder()
        changed_transport = StdioTransport(
            [sys.executable, "-c", response_script], {}, changed_recorder
        )
        try:
            changed = replay_transcript(
                source,
                changed_transport,
                changed_recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.1),
            )
        finally:
            changed_transport.close()
        self.assertFalse(changed.matches_source)
        mismatch = next(
            finding
            for finding in changed.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
            and finding.status == "FAIL"
        )
        self.assertTrue(
            "instead of source timeout" in mismatch.summary
            or "extra message" in mismatch.summary
        )

    def test_extra_stdio_message_after_source_checkpoint_is_a_mismatch(self) -> None:
        request = {"jsonrpc": "2.0", "id": 13, "method": "ping", "params": {}}
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
                    "payload": result(13, {}),
                    "classification": "response",
                },
            ]
        )
        script = (
            "import json,sys\n"
            "message=json.loads(sys.stdin.buffer.readline())\n"
            "print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':{}}), flush=True)\n"
            "print(json.dumps({'jsonrpc':'2.0','method':'notifications/extra'}), flush=True)\n"
            "for _line in sys.stdin.buffer:\n"
            "    pass\n"
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", script], {}, recorder)
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.2),
            )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        self.assertEqual(replay.received_messages, 2)
        extra = [
            finding
            for finding in replay.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
            and finding.status == "FAIL"
        ]
        self.assertEqual(len(extra), 1)
        self.assertIn("extra message", extra[0].summary)

    def test_initialize_protocol_version_is_part_of_replay_signature(self) -> None:
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
        transport = self.stdio_transport(
            "stdio-good-legacy",
            recorder,
            "--protocol-version",
            "2025-11-25",
        )
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION),
            )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        mismatch = next(
            finding
            for finding in replay.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertEqual(mismatch.status, "FAIL")
        self.assertIn("protocolVersion", mismatch.details)

    def test_protocol_named_application_field_is_ignored_outside_lifecycle(self) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "extension/example",
            "params": {},
        }
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
                    "payload": result(31, {"protocolVersion": "application-value-a"}),
                    "classification": "response",
                },
            ]
        )
        script = (
            "import json,sys\n"
            "message=json.loads(sys.stdin.buffer.readline())\n"
            "print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':"
            "{'protocolVersion':'application-value-b'}}), flush=True)\n"
            "for _line in sys.stdin.buffer:\n"
            "    pass\n"
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", script], {}, recorder)
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION),
            )
        finally:
            transport.close()
        self.assertTrue(replay.matches_source)

    def test_modern_result_type_is_part_of_every_response_signature(self) -> None:
        request = {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
                }
            },
        }
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
                    "payload": result(32, {"resultType": "complete", "tools": []}),
                    "classification": "response",
                },
            ]
        )
        script = (
            "import json,sys\n"
            "message=json.loads(sys.stdin.buffer.readline())\n"
            "print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':"
            "{'resultType':'input_required','tools':[]}}), flush=True)\n"
            "for _line in sys.stdin.buffer:\n"
            "    pass\n"
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", script], {}, recorder)
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=MODERN_VERSION),
            )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        mismatch = next(
            finding
            for finding in replay.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertIn("resultType", mismatch.details)

    def test_forbidden_batch_is_a_replay_checkpoint_not_a_silent_pass(self) -> None:
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
                    "payload": [
                        {
                            "jsonrpc": "2.0",
                            "id": "fixture-batch-ping",
                            "method": "ping",
                            "params": {},
                        },
                        {
                            "jsonrpc": "2.0",
                            "id": "fixture-roots-request",
                            "method": "roots/list",
                            "params": {},
                        },
                    ],
                    "classification": "invalid_batch",
                },
            ]
        )
        options = ReplayOptions(protocol_version=LEGACY_VERSION, timeout=1)

        bad_recorder = EventRecorder()
        bad_transport = self.stdio_transport(
            "stdio-batch-server-request", bad_recorder
        )
        try:
            reproduced = replay_transcript(
                source, bad_transport, bad_recorder, options
            )
        finally:
            bad_transport.close()
        self.assertTrue(reproduced.matches_source)
        comparison = next(
            finding
            for finding in reproduced.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertEqual(comparison.status, "PASS")
        self.assertEqual(comparison.expected["classification"], "invalid_batch")
        self.assertEqual(comparison.actual["classification"], "invalid_batch")
        self.assertEqual(comparison.expected["batchSize"], 2)
        self.assertEqual(
            [item.get("method") for item in comparison.expected["batchItems"]],
            ["ping", "roots/list"],
        )

        fixed_recorder = EventRecorder()
        fixed_transport = self.stdio_transport("stdio-good-legacy", fixed_recorder)
        try:
            changed = replay_transcript(
                source, fixed_transport, fixed_recorder, options
            )
        finally:
            fixed_transport.close()
        self.assertFalse(changed.matches_source)
        mismatch = next(
            finding
            for finding in changed.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertEqual(mismatch.status, "FAIL")
        self.assertEqual(mismatch.expected["classification"], "invalid_batch")
        self.assertEqual(mismatch.actual["classification"], "response")

        different_source = self.manual_transcript(
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
                    "payload": [
                        {
                            "jsonrpc": "2.0",
                            "id": "COMPLETELY-DIFFERENT",
                            "result": {},
                        }
                    ],
                    "classification": "invalid_batch",
                },
            ],
            "different-batch.ndjson",
        )
        different_recorder = EventRecorder()
        different_transport = self.stdio_transport(
            "stdio-batch-server-request", different_recorder
        )
        try:
            different = replay_transcript(
                different_source, different_transport, different_recorder, options
            )
        finally:
            different_transport.close()
        self.assertFalse(different.matches_source)
        different_comparison = next(
            finding
            for finding in different.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertEqual(different_comparison.status, "FAIL")
        self.assertIn("batchSize", different_comparison.details)
        self.assertIn("batchItems", different_comparison.details)

    def test_structured_2025_03_batch_action_replays_as_one_wire_message(self) -> None:
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        ]
        responses = [result(1, {}), result(2, {"tools": []})]
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": batch,
                    "classification": "batch",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": responses,
                    "classification": "batch",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": responses[0],
                    "classification": "response",
                    "batchEvidence": "event:2",
                    "batchIndex": 0,
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": responses[1],
                    "classification": "response",
                    "batchEvidence": "event:2",
                    "batchIndex": 1,
                },
            ]
        )
        script = (
            "import json,sys\n"
            "messages=json.loads(sys.stdin.buffer.readline())\n"
            "responses=[{'jsonrpc':'2.0','id':messages[0]['id'],'result':{}},"
            "{'jsonrpc':'2.0','id':messages[1]['id'],'result':{'tools':[]}}]\n"
            "print(json.dumps(responses,separators=(',',':')), flush=True)\n"
            "for _line in sys.stdin.buffer: pass\n"
        )
        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", script], {}, recorder)
        options = ReplayOptions(protocol_version="2025-03-26")
        try:
            replay = replay_transcript(source, transport, recorder, options)
        finally:
            transport.close()
        self.assertTrue(replay.matches_source)
        outgoing = [
            event
            for event in recorder.events
            if event.get("direction") == "client_to_server"
        ]
        self.assertEqual(len(outgoing), 1)
        self.assertEqual(outgoing[0]["classification"], "batch")
        self.assertEqual(outgoing[0]["payload"], batch)

        split_script = (
            "import json,sys\n"
            "messages=json.loads(sys.stdin.buffer.readline())\n"
            "for message in messages:\n"
            "    value={'tools':[]} if message.get('method')=='tools/list' else {}\n"
            "    print(json.dumps({'jsonrpc':'2.0','id':message['id'],'result':value}), flush=True)\n"
            "for _line in sys.stdin.buffer: pass\n"
        )
        split_recorder = EventRecorder()
        split_transport = StdioTransport(
            [sys.executable, "-c", split_script], {}, split_recorder
        )
        try:
            split = replay_transcript(source, split_transport, split_recorder, options)
        finally:
            split_transport.close()
        self.assertFalse(split.matches_source)
        grouping_failures = [
            finding
            for finding in split.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
            and finding.status == "FAIL"
        ]
        self.assertTrue(grouping_failures)
        self.assertTrue(
            any("wireBatch" in (finding.details or "") for finding in grouping_failures)
        )

    def test_destination_credentials_are_redacted_before_structured_replay_send(self) -> None:
        secret = "destination-env-secret"
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {
                        "jsonrpc": "2.0",
                        "method": "notifications/test",
                        "params": {"echo": secret},
                    },
                    "classification": "notification",
                }
            ]
        )
        recorder = EventRecorder()
        transport = StdioTransport(
            stdio_fixture_command("stdio-good-modern"),
            {"DESTINATION_TOKEN": secret},
            recorder,
        )
        try:
            replay = replay_transcript(source, transport, recorder)
        finally:
            transport.close()

        self.assertTrue(replay.completed)
        self.assertTrue(replay.redactions_applied)
        sent = next(
            event["payload"]
            for event in recorder.events
            if event.get("direction") == "client_to_server"
        )
        self.assertEqual(sent["params"]["echo"], "[REDACTED]")
        self.assertNotIn(secret, json.dumps(recorder.events))

    def test_destination_secret_collisions_preserve_jsonrpc_envelope(self) -> None:
        parameter_secret = "destination-param-secret"
        request = {
            "jsonrpc": "2.0",
            "id": 44,
            "method": "ping",
            "params": {"echo": parameter_secret},
        }
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
                    "payload": result(44, {}),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        script = (
            "import json,sys\n"
            "request=json.loads(sys.stdin.buffer.readline())\n"
            "valid=(request.get('jsonrpc')=='2.0' and request.get('id')==44 "
            "and request.get('method')=='ping' and "
            "request.get('params',{}).get('echo')=='[REDACTED]')\n"
            "response={'jsonrpc':'2.0','id':44}\n"
            "response['result']={} if valid else None\n"
            "if not valid: response={'jsonrpc':'2.0','id':44,'error':"
            "{'code':-32000,'message':'rewritten envelope'}}\n"
            "print(json.dumps(response),flush=True)\n"
            "for _line in sys.stdin.buffer: pass\n"
        )
        transport = StdioTransport(
            [sys.executable, "-c", script],
            {
                "METHOD_SECRET": "ping",
                "ENVELOPE_SECRET": "id",
                "PARAM_SECRET": parameter_secret,
            },
            recorder,
        )
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION),
            )
        finally:
            transport.close()

        self.assertTrue(replay.matches_source)
        self.assertTrue(replay.redactions_applied)
        sent = next(
            event["payload"]
            for event in recorder.events
            if event.get("direction") == "client_to_server"
        )
        self.assertEqual(sent["jsonrpc"], "2.0")
        self.assertEqual(sent["id"], 44)
        self.assertEqual(sent["method"], "ping")
        self.assertEqual(sent["params"]["echo"], "[REDACTED]")

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
        request = {
            "jsonrpc": "2.0",
            "id": "preserved-id",
            "method": "tools/list",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
                }
            },
        }
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
                    "payload": result(
                        "preserved-id",
                        {"resultType": "complete", "tools": []},
                    ),
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
        transport = self.stdio_transport(
            "stdio-server-request",
            recorder,
            "--server-request-mode",
            "roots-early",
        )
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
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(allow_opaque_wire=True),
            )
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
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(allow_opaque_wire=True),
            )
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

    def test_batch_nested_and_normalized_tool_calls_require_exact_allow_list(self) -> None:
        payload = [
            {"jsonrpc": "2.0", "method": "notifications/test"},
            {
                "jsonrpc": "2.0",
                "method": "notifications/wrapper",
                "params": {
                    "nested": {
                        "method": "  TOOLS/CALL  ",
                        "params": {"name": "fixture_echo"},
                    }
                },
            },
        ]
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": payload,
                    "classification": "batch",
                }
            ]
        )
        with self.assertRaisesRegex(ConfigurationError, "fixture_echo"):
            load_replay_plan(source, ReplayOptions(protocol_version="2025-03-26"))
        plan = load_replay_plan(
            source,
            ReplayOptions(
                protocol_version="2025-03-26",
                allow_tools=("fixture_echo",),
            ),
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
            opaque_wire_event_count=plan.opaque_wire_event_count,
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

    def test_invalid_jsonrpc_version_is_a_structural_mismatch(self) -> None:
        request = initialize(71)
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
                    "payload": result(
                        71,
                        {
                            "protocolVersion": LEGACY_VERSION,
                            "capabilities": {},
                            "serverInfo": {"name": "source", "version": "1"},
                        },
                    ),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-invalid-response", recorder)
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION),
            )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        mismatch = next(
            item
            for item in replay.findings
            if item.code == "REPLAY_RESPONSE_MATCH" and item.status == "FAIL"
        )
        self.assertIn("jsonrpc", mismatch.details or "")

    def test_failed_initialize_does_not_claim_a_negotiated_version(self) -> None:
        request = initialize(72)
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
                    "payload": result(
                        72,
                        {
                            "protocolVersion": LEGACY_VERSION,
                            "capabilities": {},
                            "serverInfo": {"name": "source", "version": "1"},
                        },
                    ),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-invalid-response", recorder)
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION),
            )
        finally:
            transport.close()
        self.assertFalse(replay.matches_source)
        self.assertIsNone(replay.negotiated_version)

    def test_nonzero_process_exit_is_a_replay_checkpoint(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 73,
                        "method": "ping",
                        "params": {},
                    },
                    "classification": "request",
                },
                {
                    "direction": "probe",
                    "transport": "stdio",
                    "classification": "process_exit",
                    "exitCode": 17,
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-crash", recorder)
        try:
            reproduced = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.3),
            )
        finally:
            transport.close()
        self.assertTrue(reproduced.matches_source)

        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-good-legacy", recorder)
        try:
            changed = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.1),
            )
        finally:
            transport.close()
        self.assertFalse(changed.matches_source)

    def test_captured_exit_before_stdout_drain_replays_same_target(self) -> None:
        message_count = 300
        source_path = self.directory / "exit-before-drain.ndjson"
        source_recorder = _ExitBeforeDrainRecorder(
            str(source_path), block_at_message=251
        )
        script = (
            "import json,os,sys\n"
            "json.loads(sys.stdin.buffer.readline())\n"
            "message={'jsonrpc':'2.0','method':'notifications/burst'}\n"
            f"sys.stdout.write(''.join(json.dumps(message)+'\\n' for _ in range({message_count})))\n"
            "sys.stdout.flush()\n"
            "os._exit(17)\n"
        )
        source_transport = StdioTransport(
            [sys.executable, "-c", script], {}, source_recorder
        )
        try:
            source_transport.start()
            source_transport.send_message(
                {"jsonrpc": "2.0", "method": "notifications/start"},
                timeout=1,
            )
            deadline = time.monotonic() + 2
            while source_transport.returncode is None and time.monotonic() < deadline:
                time.sleep(0.005)
        finally:
            source_transport.close()
            source_recorder.close()

        source_exit = next(
            event
            for event in source_recorder.events
            if event.get("classification") == "process_exit"
        )
        source_messages = [
            event
            for event in source_recorder.events
            if event.get("direction") == "server_to_client"
        ]
        self.assertEqual(len(source_messages), message_count)
        self.assertLess(source_exit["seq"], source_messages[-1]["seq"])

        recorder = EventRecorder()
        transport = StdioTransport([sys.executable, "-c", script], {}, recorder)
        try:
            replay = replay_transcript(
                source_path,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=1),
            )
        finally:
            transport.close()

        self.assertTrue(replay.matches_source)
        self.assertEqual(replay.received_messages, message_count)

    def test_server_selected_legacy_profile_is_adopted_after_initialize(self) -> None:
        selected = "2025-03-26"
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": initialize(74),
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(
                        74,
                        {
                            "protocolVersion": selected,
                            "capabilities": {"tools": {"listChanged": True}},
                            "serverInfo": {"name": "fixture", "version": "1.0.0"},
                        },
                    ),
                    "classification": "response",
                },
            ]
        )
        recorder = EventRecorder()
        transport = self.stdio_transport(
            "stdio-good-legacy",
            recorder,
            "--protocol-version",
            selected,
        )
        try:
            replay = replay_transcript(
                source,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION),
            )
            self.assertEqual(transport.profile.version, selected)
        finally:
            transport.close()
        self.assertTrue(replay.matches_source)


class HttpReplayIntegrationTests(ReplayTestCase):
    def test_identical_invalid_session_initialize_replays_as_a_match(self) -> None:
        source_path = self.directory / "invalid-session.ndjson"
        source_recorder = EventRecorder(str(source_path))
        with running_http_fixture(
            "http-session", session_id="invalid session id"
        ) as fixture:
            source_transport = HttpTransport(
                fixture.url,
                {},
                source_recorder,
                profile_for(LEGACY_VERSION),
            )
            try:
                with self.assertRaises(HttpExchangeError) as raised:
                    source_transport.send_message(initialize(), 1)
                self.assertEqual(
                    raised.exception.finding_code, "HTTP_SESSION_ID"
                )
            finally:
                source_transport.close()
                source_recorder.close()

        with running_http_fixture(
            "http-session", session_id="invalid session id"
        ) as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                replay = replay_transcript(
                    source_path,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION),
                )
            finally:
                transport.close()

        self.assertTrue(replay.matches_source)
        self.assertFalse(transport.initialized)
        self.assertIsNone(transport.session_id)
        self.assertTrue(
            any(
                event.get("classification") == "invalid_session_id"
                for event in recorder.events
            )
        )

    def test_incomplete_http_initialize_never_updates_replay_lifecycle(self) -> None:
        response = result(
            1,
            {
                "protocolVersion": LEGACY_VERSION,
                "capabilities": {},
                "serverInfo": {"name": "fixture", "version": "1"},
            },
        )
        inbound = InboundMessage(
            response,
            json.dumps(response),
            "response",
            "event:1",
        )
        for timed_out, body_complete in ((True, True), (False, False)):
            with self.subTest(timed_out=timed_out, body_complete=body_complete):
                recorder = EventRecorder()
                transport = HttpTransport(
                    "http://127.0.0.1:1/mcp",
                    {},
                    recorder,
                    profile_for(LEGACY_VERSION),
                )
                exchange = HttpExchange(
                    200,
                    {"MCP-Session-Id": "must-not-be-adopted"},
                    json.dumps(response),
                    [inbound],
                    [],
                    timed_out=timed_out,
                    body_complete=body_complete,
                )
                replay_module._update_http_lifecycle(
                    transport, initialize(), exchange
                )
                self.assertFalse(transport.initialized)
                self.assertIsNone(transport.session_id)

    def test_destination_content_encoding_requires_opaque_wire_opt_in(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "http",
                    "raw": (
                        '{"jsonrpc":"2.0","method":"notifications/test",'
                        '"params":{}}'
                    ),
                    "classification": "raw_wire",
                }
            ]
        )
        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url,
                {"Content-Encoding": "base64"},
                recorder,
                profile_for(LEGACY_VERSION),
            )
            try:
                with self.assertRaisesRegex(ConfigurationError, "becomes opaque"):
                    replay_transcript(
                        source,
                        transport,
                        recorder,
                        ReplayOptions(protocol_version=LEGACY_VERSION),
                    )
            finally:
                transport.close()
        self.assertEqual(fixture.state.received_http, [])

    def test_http_sse_soft_timeout_state_is_compared_symmetrically(self) -> None:
        action = {
            "jsonrpc": "2.0",
            "id": 25,
            "method": "ping",
            "params": {},
        }
        emitted = {
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {"level": "info", "data": "fixture event"},
        }

        def source_with_timeout(value: bool, name: str) -> Path:
            return self.manual_transcript(
                [
                    {
                        "direction": "client_to_server",
                        "transport": "http",
                        "payload": action,
                        "classification": "request",
                    },
                    {
                        "direction": "server_to_client",
                        "transport": "http",
                        "payload": emitted,
                        "classification": "notification",
                        "status": 200,
                    },
                    {
                        "direction": "probe",
                        "transport": "http",
                        "classification": "http_response",
                        "status": 200,
                        "timedOut": value,
                    },
                ],
                name,
            )

        matching_source = source_with_timeout(True, "sse-timeout.ndjson")
        with running_http_fixture("http-sse-timeout", delay=0.15) as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                reproduced = replay_transcript(
                    matching_source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.03),
                )
            finally:
                transport.close()
        self.assertTrue(reproduced.matches_source)
        timeout_state = next(
            finding
            for finding in reproduced.findings
            if finding.expected == {"timedOut": True}
        )
        self.assertEqual(timeout_state.status, "PASS")

        non_timeout_source = source_with_timeout(False, "sse-no-timeout.ndjson")
        with running_http_fixture("http-sse-timeout", delay=0.15) as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                changed = replay_transcript(
                    non_timeout_source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.03),
                )
            finally:
                transport.close()
        self.assertFalse(changed.matches_source)
        timeout_mismatch = next(
            finding
            for finding in changed.findings
            if finding.expected == {"timedOut": False}
        )
        self.assertEqual(timeout_mismatch.status, "FAIL")
        self.assertEqual(timeout_mismatch.actual, {"timedOut": True})

    def test_http_timeout_checkpoint_must_be_reproduced(self) -> None:
        request = {"jsonrpc": "2.0", "id": 21, "method": "ping", "params": {}}
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "http",
                    "payload": request,
                    "classification": "request",
                },
                {
                    "direction": "probe",
                    "transport": "http",
                    "classification": "timeout",
                    "timeoutSeconds": 0.03,
                },
            ]
        )
        with running_http_fixture("http-delayed-response", delay=0.15) as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                reproduced = replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.1),
                )
            finally:
                transport.close()
        self.assertTrue(reproduced.matches_source)
        timeout_match = next(
            finding
            for finding in reproduced.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertEqual(timeout_match.status, "PASS")
        self.assertEqual(timeout_match.actual["timeoutSeconds"], 0.03)

        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                changed = replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.1),
                )
            finally:
                transport.close()
        self.assertFalse(changed.matches_source)
        mismatch = next(
            finding
            for finding in changed.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
        )
        self.assertEqual(mismatch.status, "FAIL")
        self.assertIn("instead of source timeout", mismatch.summary)

    def test_http_initialize_version_change_is_a_replay_mismatch(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "http",
                    "payload": initialize(),
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "http",
                    "payload": result(1, {"protocolVersion": LEGACY_VERSION}),
                    "classification": "response",
                    "status": 200,
                },
            ]
        )
        with running_http_fixture(
            "http-json", protocol_version="2025-11-25"
        ) as fixture:
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
            finally:
                transport.close()
        self.assertFalse(replay.matches_source)
        mismatch = next(
            finding
            for finding in replay.findings
            if finding.code == "REPLAY_RESPONSE_MATCH"
            and finding.status == "FAIL"
        )
        self.assertIn("protocolVersion", mismatch.details)

        with running_http_fixture(
            "http-json", protocol_version=MODERN_VERSION
        ) as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                incompatible = replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION),
                )
            finally:
                transport.close()
        self.assertFalse(incompatible.matches_source)
        self.assertEqual(incompatible.negotiated_version, MODERN_VERSION)
        self.assertTrue(
            any(
                finding.status == "FAIL"
                and "protocolVersion" in (finding.details or "")
                for finding in incompatible.findings
            )
        )

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
                    "direction": "probe",
                    "transport": "http",
                    "classification": "http_response",
                    "status": 400,
                    "timedOut": False,
                },
                {
                    "direction": "server_to_client",
                    "transport": "http",
                    "raw": "malformed request body",
                    "classification": "invalid_body",
                    "status": 400,
                },
                {
                    "direction": "probe",
                    "transport": "http",
                    "classification": "parse_issue",
                    "status": 400,
                    "error": (
                        "unexpected Content-Type 'text/plain'; expected "
                        "application/json or text/event-stream"
                    ),
                },
                {
                    "direction": "probe",
                    "transport": "http",
                    "classification": "parse_issue",
                    "status": 400,
                    "error": (
                        "invalid JSON body: Expecting value: line 1 column 1 "
                        "(char 0)"
                    ),
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
                    ReplayOptions(
                        protocol_version=LEGACY_VERSION,
                        allow_opaque_wire=True,
                    ),
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

    def test_modern_unexpected_session_header_is_a_replay_mismatch(self) -> None:
        source_path = self.directory / "modern-http.ndjson"
        with running_http_fixture(
            "http-json", protocol_version=MODERN_VERSION
        ) as source_fixture:
            recorder = EventRecorder(str(source_path))
            transport = HttpTransport(
                source_fixture.url, {}, recorder, profile_for(MODERN_VERSION)
            )
            session = McpSession(
                transport,
                SessionConfig(protocol_version=MODERN_VERSION),
                recorder,
            )
            try:
                self.assertTrue(session.establish(2).success)
            finally:
                session.close()
                recorder.close()

        with running_http_fixture(
            "http-json",
            protocol_version=MODERN_VERSION,
            response_session_id="unexpected-session",
        ) as target_fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                target_fixture.url, {}, recorder, profile_for(MODERN_VERSION)
            )
            try:
                replay = replay_transcript(source_path, transport, recorder)
            finally:
                transport.close()
        self.assertFalse(replay.matches_source)
        diagnostic = next(
            item
            for item in replay.findings
            if item.status == "FAIL"
            and item.actual is not None
            and "protocolDiagnostics" in item.actual
        )
        referenced = {
            int(item.event.split(":", 1)[1]) for item in diagnostic.evidence
        }
        self.assertTrue(
            any(
                event.get("seq") in referenced
                and event.get("classification") == "unexpected_session_id"
                for event in recorder.events
            )
        )

    def test_target_parse_issue_is_compared_and_cites_causal_event(self) -> None:
        source_path = self.directory / "clean-sse.ndjson"
        with running_http_fixture("http-sse") as source_fixture:
            recorder = EventRecorder(str(source_path))
            transport = HttpTransport(
                source_fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            session = McpSession(
                transport,
                SessionConfig(protocol_version=LEGACY_VERSION),
                recorder,
            )
            try:
                self.assertTrue(session.establish(2).success)
            finally:
                session.close()
                recorder.close()

        with running_http_fixture(
            "http-sse-malformed-then-valid"
        ) as target_fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                target_fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            try:
                replay = replay_transcript(source_path, transport, recorder)
            finally:
                transport.close()
        self.assertFalse(replay.matches_source)
        mismatch = next(
            item
            for item in replay.findings
            if item.status == "FAIL"
            and item.actual is not None
            and "parseIssues" in item.actual
        )
        referenced = {
            int(item.event.split(":", 1)[1]) for item in mismatch.evidence
        }
        self.assertTrue(
            any(
                event.get("seq") in referenced
                and event.get("classification") == "parse_issue"
                for event in recorder.events
            )
        )


class ReplayValidationTests(ReplayTestCase):
    def test_stdio_captured_timeout_cannot_be_shortened_before_start(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 90,
                        "method": "ping",
                    },
                    "classification": "request",
                },
                {
                    "direction": "probe",
                    "transport": "stdio",
                    "classification": "timeout",
                    "requestId": 90,
                    "timeoutSeconds": 0.5,
                },
            ]
        )
        plan = load_replay_plan(
            source,
            ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.5),
        )
        recorder = EventRecorder()
        transport = self.stdio_transport("stdio-good-legacy", recorder)
        with self.assertRaisesRegex(ConfigurationError, "without shortening"):
            replay_plan(
                plan,
                transport,
                recorder,
                ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.1),
            )
        self.assertIsNone(transport.process)

    def test_http_captured_timeout_cannot_be_shortened_before_request(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "http",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 91,
                        "method": "ping",
                    },
                    "classification": "request",
                },
                {
                    "direction": "probe",
                    "transport": "http",
                    "classification": "timeout",
                    "timeoutSeconds": 0.5,
                },
            ]
        )
        with running_http_fixture("http-json") as fixture:
            recorder = EventRecorder()
            transport = HttpTransport(
                fixture.url, {}, recorder, profile_for(LEGACY_VERSION)
            )
            with self.assertRaisesRegex(ConfigurationError, "without shortening"):
                replay_transcript(
                    source,
                    transport,
                    recorder,
                    ReplayOptions(protocol_version=LEGACY_VERSION, timeout=0.1),
                )
            self.assertEqual(fixture.state.received_http, [])

    def test_duplicate_id_occurrences_remain_independently_outstanding(self) -> None:
        request = {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": request,
                    "classification": "request",
                },
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": request,
                    "classification": "request",
                },
                {
                    "direction": "server_to_client",
                    "transport": "stdio",
                    "payload": result(1, {}),
                    "classification": "response",
                },
                {
                    "direction": "probe",
                    "transport": "stdio",
                    "classification": "timeout",
                    "requestId": 1,
                    "timeoutSeconds": 0.1,
                },
            ]
        )
        plan = load_replay_plan(source)
        self.assertEqual(plan.client_event_count, 2)

    def test_timeout_request_id_must_be_outstanding(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "ping",
                    },
                    "classification": "request",
                },
                {
                    "direction": "probe",
                    "transport": "stdio",
                    "classification": "timeout",
                    "requestId": 999,
                    "timeoutSeconds": 0.1,
                },
            ]
        )
        with self.assertRaisesRegex(ConfigurationError, "outstanding client request"):
            load_replay_plan(source)

    def test_incomplete_capture_marker_is_rejected_before_target_start(self) -> None:
        source = self.manual_transcript(
            [
                {
                    "direction": "client_to_server",
                    "transport": "stdio",
                    "payload": {"jsonrpc": "2.0", "method": "notifications/test"},
                    "classification": "notification",
                },
                {
                    "direction": "probe",
                    "transport": "probe",
                    "classification": "capture_limit",
                    "error": "capture truncated",
                },
            ]
        )
        with self.assertRaisesRegex(ConfigurationError, "interaction is incomplete"):
            load_replay_plan(source)

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
