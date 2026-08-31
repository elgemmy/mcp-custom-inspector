from __future__ import annotations

import unittest

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.matrix import default_matrix_versions, run_matrix, validate_matrix_versions
from mcp_probe_core.protocol import SUPPORTED_PROTOCOL_VERSIONS
from mcp_probe_core.report import stdio_target
from mcp_probe_core.session import McpSession, SessionConfig
from mcp_probe_core.transcript import EventRecorder
from mcp_probe_core.transports import StdioTransport
from tests.fixtures.mcp_fixture import stdio_fixture_command


class MatrixVersionTests(unittest.TestCase):
    def test_stdio_defaults_to_every_supported_revision(self) -> None:
        self.assertEqual(default_matrix_versions("stdio"), SUPPORTED_PROTOCOL_VERSIONS)

    def test_http_omits_pre_streamable_revision(self) -> None:
        versions = default_matrix_versions("http")
        self.assertNotIn("2024-11-05", versions)
        self.assertEqual(versions[-1], "2026-07-28")

    def test_validation_preserves_order_and_removes_duplicates(self) -> None:
        selected = validate_matrix_versions(
            ["2025-11-25", "2025-03-26", "2025-11-25"],
            transport="stdio",
        )
        self.assertEqual(selected, ("2025-11-25", "2025-03-26"))

    def test_http_rejects_revision_before_streamable_http(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "predates Streamable HTTP"):
            validate_matrix_versions(["2024-11-05"], transport="http")

    def test_empty_and_unknown_inputs_are_configuration_errors(self) -> None:
        with self.assertRaises(ConfigurationError):
            validate_matrix_versions([], transport="stdio")
        with self.assertRaises(ConfigurationError):
            validate_matrix_versions(["not-a-version"], transport="stdio")

    def test_runs_are_full_reports_and_shared_transcript_events_do_not_contaminate(self) -> None:
        recorder = EventRecorder()
        profiles = iter(("stdio-invalid-response", "stdio-good-legacy"))

        def factory(version: str) -> McpSession:
            transport = StdioTransport(
                stdio_fixture_command(next(profiles)), {}, recorder
            )
            return McpSession(
                transport,
                SessionConfig(version, client_capabilities={}),
                recorder,
            )

        try:
            report = run_matrix(
                factory,
                ("2025-06-18", "2025-11-25"),
                target=stdio_target(stdio_fixture_command("stdio-good-legacy")),
                transport="stdio",
                timeout=0.25,
                max_pages=2,
            ).to_dict()
        finally:
            recorder.close()

        runs = report["matrix"]["runs"]
        self.assertEqual(len(runs), 2)
        self.assertNotEqual(runs[0]["overall"]["status"], "PASS")
        self.assertEqual(runs[1]["overall"]["status"], "PASS")
        self.assertEqual(
            runs[1]["protocol"]["requestedVersion"], "2025-11-25"
        )
        self.assertGreater(runs[0]["transcript"]["eventCount"], 0)
        self.assertGreater(runs[1]["transcript"]["eventCount"], 0)
        self.assertLess(
            runs[0]["transcript"]["lastSeq"],
            runs[1]["transcript"]["firstSeq"],
        )


if __name__ == "__main__":
    unittest.main()
