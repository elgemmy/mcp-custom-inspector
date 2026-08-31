from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.redaction import REDACTED
from mcp_probe_core.transcript import (
    TRANSCRIPT_EVENT_SCHEMA,
    EventRecorder,
    load_transcript,
)


class TranscriptTests(unittest.TestCase):
    def test_event_has_stable_evidence_sequence_timing_and_rpc_fields(self) -> None:
        recorder = EventRecorder()
        first = recorder.record(
            "client_to_server",
            "stdio",
            payload={"jsonrpc": "2.0", "id": "req-1", "method": "tools/list"},
        )
        time.sleep(0.002)
        second = recorder.record(
            "server_to_client",
            "stdio",
            payload={"jsonrpc": "2.0", "id": "req-1", "result": {"tools": []}},
        )

        self.assertEqual((first, second), ("event:1", "event:2"))
        self.assertEqual(recorder.last_reference(), "event:2")
        request, response = recorder.events
        self.assertEqual(request["schema"], TRANSCRIPT_EVENT_SCHEMA)
        self.assertEqual(request["classification"], "request")
        self.assertEqual(request["method"], "tools/list")
        self.assertEqual(request["id"], "req-1")
        self.assertEqual(response["classification"], "response")
        self.assertGreaterEqual(response["elapsedMs"], request["elapsedMs"])
        for event in recorder.events:
            parsed_time = dt.datetime.fromisoformat(event["time"])
            self.assertIsNotNone(parsed_time.tzinfo)
            self.assertGreaterEqual(event["elapsedMs"], 0)

    def test_ndjson_is_flushed_loadable_and_close_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "nested" / "trace.ndjson"
            recorder = EventRecorder(str(path))
            recorder.record("probe", "stdio", classification="process_start", pid=123)
            on_disk_while_open = path.read_text(encoding="utf-8")
            self.assertTrue(on_disk_while_open.endswith("\n"))
            recorder.record(
                "probe",
                "stdio",
                classification="process_exit",
                exitCode=17,
                error="child crashed",
            )
            recorder.close()
            recorder.close()

            loaded = load_transcript(path)
            self.assertEqual([event["seq"] for event in loaded], [1, 2])
            self.assertEqual(loaded[1]["exitCode"], 17)
            self.assertEqual(loaded[1]["error"], "child crashed")

    def test_every_sink_receives_redacted_payload_raw_headers_url_error_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "trace.ndjson"
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                recorder = EventRecorder(str(path), verbose=True)
                recorder.record(
                    "client_to_server",
                    "http",
                    payload={
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {"arguments": {"token": "payload-secret"}},
                    },
                    raw=(
                        '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                        '"params":{"arguments":{"token":"raw-secret"}}}'
                    ),
                    headers={
                        "Authorization": "Bearer auth-secret",
                        "Cookie": "sid=cookie-secret",
                        "Mcp-Param-Name": "mirrored-secret",
                    },
                    url="https://u:p@example.test/mcp?access_token=url-secret",
                    error="Authorization: Bearer error-secret",
                    environment={"NOTION_TOKEN": "metadata-secret"},
                )
                recorder.close()

            representations = (
                json.dumps(recorder.events),
                path.read_text(encoding="utf-8"),
                stderr.getvalue(),
            )
            for representation in representations:
                for secret in (
                    "payload-secret",
                    "raw-secret",
                    "auth-secret",
                    "cookie-secret",
                    "mirrored-secret",
                    "url-secret",
                    "error-secret",
                    "metadata-secret",
                ):
                    self.assertNotIn(secret, representation)
                self.assertIn(REDACTED, representation)

    def test_http_status_headers_and_sse_metadata_are_recorded(self) -> None:
        recorder = EventRecorder()
        reference = recorder.record(
            "server_to_client",
            "http",
            payload={"jsonrpc": "2.0", "id": 7, "result": {}},
            status=200,
            headers={"Content-Type": "text/event-stream", "Set-Cookie": "private"},
            sseEvent="message",
            sseId="event-42",
        )
        event = recorder.events[0]
        self.assertEqual(reference, "event:1")
        self.assertEqual(event["httpStatus"], 200)
        self.assertEqual(event["headers"]["Content-Type"], "text/event-stream")
        self.assertEqual(event["headers"]["Set-Cookie"], REDACTED)
        self.assertEqual(event["sseEvent"], "message")
        self.assertEqual(event["sseId"], "event-42")

    def test_parallel_recording_keeps_contiguous_sequence_and_valid_ndjson(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "parallel.ndjson"
            recorder = EventRecorder(str(path))

            def record_batch(worker: int) -> None:
                for item in range(20):
                    recorder.record(
                        "probe",
                        "stdio",
                        classification="worker_event",
                        worker=worker,
                        item=item,
                    )

            threads = [threading.Thread(target=record_batch, args=(worker,)) for worker in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=2)
                self.assertFalse(thread.is_alive())
            recorder.close()

            loaded = load_transcript(path)
            self.assertEqual(len(loaded), 80)
            self.assertEqual([event["seq"] for event in loaded], list(range(1, 81)))

    def test_load_rejects_missing_empty_malformed_wrong_schema_and_bad_sequence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cases = {
                "missing.ndjson": None,
                "empty.ndjson": "\n",
                "malformed.ndjson": "{not json}\n",
                "schema.ndjson": json.dumps({"schema": "other", "seq": 1}) + "\n",
                "bool-seq.ndjson": json.dumps(
                    {
                        "schema": TRANSCRIPT_EVENT_SCHEMA,
                        "seq": True,
                        "direction": "probe",
                        "transport": "stdio",
                        "classification": "event",
                    }
                )
                + "\n",
                "gap.ndjson": json.dumps(
                    {
                        "schema": TRANSCRIPT_EVENT_SCHEMA,
                        "seq": 2,
                        "direction": "probe",
                        "transport": "stdio",
                        "classification": "event",
                    }
                )
                + "\n",
                "missing-field.ndjson": json.dumps(
                    {
                        "schema": TRANSCRIPT_EVENT_SCHEMA,
                        "seq": 1,
                        "direction": "probe",
                        "transport": "stdio",
                    }
                )
                + "\n",
            }
            for filename, content in cases.items():
                with self.subTest(filename=filename):
                    path = directory / filename
                    if content is not None:
                        path.write_text(content, encoding="utf-8")
                    with self.assertRaises(ConfigurationError):
                        load_transcript(path)


if __name__ == "__main__":
    unittest.main()
