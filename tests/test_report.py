from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.redaction import REDACTED
from mcp_probe_core.report import (
    REPORT_SCHEMA,
    CompatibilityReport,
    EvidenceRef,
    Finding,
    FINDING_CODES,
    RunError,
    aggregate_overall,
    derive_exit_code,
    http_target,
    render_json,
    render_markdown,
    render_text,
    stdio_target,
    write_report,
)


def finding(
    status: str = "PASS",
    *,
    code: str = "NEGOTIATION_PROTOCOL_VERSION",
    category: str = "negotiation",
    basis: str = "normative",
    summary: str = "The protocol version matched.",
    details: str | None = None,
    evidence: tuple[EvidenceRef, ...] = (),
) -> Finding:
    return Finding(
        code=code,
        status=status,
        category=category,
        basis=basis,
        summary=summary,
        details=details,
        evidence=evidence,
    )


def report_with(
    *findings: Finding,
    errors: tuple[RunError, ...] = (),
    target: dict | None = None,
) -> CompatibilityReport:
    return CompatibilityReport(
        target=target or stdio_target(["python3", "fixture.py"], ["FIXTURE_MODE"]),
        report_type="compatibility",
        started_at="2026-08-30T21:00:00.000+00:00",
        duration_ms=12.3456,
        requested_version="2025-06-18",
        negotiated_version="2025-06-18",
        era="legacy",
        server_info={"name": "fixture", "version": "1"},
        capabilities={"tools": {}},
        discovery={"tools": [], "resources": [], "prompts": []},
        findings=findings,
        errors=errors,
        transcript={
            "schema": "mcp-probe.transcript.event/v1",
            "path": "artifacts/run.ndjson",
            "eventCount": 5,
            "redacted": True,
        },
    )


class EvidenceAndFindingTests(unittest.TestCase):
    def test_batch_and_progress_codes_are_stable_registry_entries(self) -> None:
        self.assertIn("JSONRPC_BATCH_SUPPORT", FINDING_CODES)
        self.assertIn("JSONRPC_PROGRESS_TOKEN", FINDING_CODES)

    def test_evidence_serializes_stable_shape(self) -> None:
        evidence = EvidenceRef(event="event:7", pointer="/payload/result", note="response")
        self.assertEqual(
            evidence.to_dict(),
            {"event": "event:7", "pointer": "/payload/result", "note": "response"},
        )

    def test_evidence_requires_positive_event_reference(self) -> None:
        for invalid in ("event:0", "event:-1", "7", "event:01"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                EvidenceRef(event=invalid)

    def test_evidence_pointer_must_be_json_pointer(self) -> None:
        with self.assertRaises(ValueError):
            EvidenceRef(event="event:1", pointer="payload/result")
        self.assertEqual(EvidenceRef(event="event:1", pointer="").pointer, "")

    def test_finding_is_frozen_and_nested_values_are_immutable(self) -> None:
        item = Finding(
            code="CAPABILITY_TOOLS_LIST",
            status="FAIL",
            category="capability",
            basis="normative",
            summary="The observed behavior contradicted the capability.",
            actual={"advertised": False, "items": ["one"]},
        )
        with self.assertRaises(FrozenInstanceError):
            item.status = "PASS"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            item.actual["advertised"] = True  # type: ignore[index]
        with self.assertRaises(AttributeError):
            item.actual["items"].append("two")  # type: ignore[index,union-attr]

    def test_finding_normalizes_status_duration_and_all_fields(self) -> None:
        item = Finding(
            code="CAPABILITY_TOOLS_LIST",
            status="fail",
            category="capability",
            basis="normative",
            summary=" tools/list contradicted capabilities. ",
            duration_ms=1.23456,
            active=True,
        )
        self.assertEqual(item.status, "FAIL")
        self.assertEqual(item.duration_ms, 1.235)
        self.assertEqual(
            list(item.to_dict()),
            [
                "code",
                "status",
                "category",
                "basis",
                "summary",
                "details",
                "expected",
                "actual",
                "evidence",
                "durationMs",
                "active",
            ],
        )
        self.assertIsNone(item.to_dict()["details"])
        self.assertEqual(item.to_dict()["evidence"], [])

    def test_finding_code_must_be_registered_and_match_category(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unknown finding code"):
            Finding(
                code="SERVER_DYNAMIC_NAME",
                status="PASS",
                category="jsonrpc",
                basis="normative",
                summary="Dynamic code.",
            )
        with self.assertRaisesRegex(ValueError, "belongs to category"):
            Finding(
                code="CAPABILITY_TOOLS_LIST",
                status="PASS",
                category="jsonrpc",
                basis="normative",
                summary="Wrong category.",
            )

    def test_skip_requires_details(self) -> None:
        with self.assertRaisesRegex(ValueError, "SKIP"):
            finding("SKIP")
        item = finding("SKIP", details="The primitive was not advertised.")
        self.assertEqual(item.status, "SKIP")

    def test_finding_redacts_at_construction(self) -> None:
        item = Finding(
            code="HTTP_STATUS",
            status="WARN",
            category="transport",
            basis="operational",
            summary="Authorization: Bearer TOP_SECRET",
            details="Cookie: session=COOKIE_SECRET",
            expected={"Authorization": "Bearer TOP_SECRET"},
            actual={"headers": {"Set-Cookie": "session=COOKIE_SECRET"}},
        )
        rendered = json.dumps(item.to_dict())
        self.assertNotIn("TOP_SECRET", rendered)
        self.assertNotIn("COOKIE_SECRET", rendered)
        self.assertIn(REDACTED, rendered)

    def test_run_error_registry_and_redaction(self) -> None:
        error = RunError(
            code="TRANSPORT_HTTP_CONNECT",
            kind="transport",
            summary="Authorization: Bearer TOP_SECRET",
            details="Could not connect.",
        )
        self.assertNotIn("TOP_SECRET", json.dumps(error.to_dict()))
        with self.assertRaisesRegex(ValueError, "belongs to kind"):
            RunError(
                code="TRANSPORT_HTTP_CONNECT",
                kind="configuration",
                summary="Wrong kind.",
            )


class TargetTests(unittest.TestCase):
    def test_stdio_target_redacts_command_and_sorts_environment_keys(self) -> None:
        target = stdio_target(
            ["server", "--token", "TOP_SECRET", "--mode=fixture"],
            ["Z_KEY", "A_KEY", "Z_KEY"],
        )
        self.assertEqual(target["environmentKeys"], ["A_KEY", "Z_KEY"])
        self.assertEqual(target["command"][2], REDACTED)
        self.assertNotIn("TOP_SECRET", target["description"])

    def test_report_never_accepts_stdio_environment_values(self) -> None:
        report = CompatibilityReport(
            target={
                "transport": "stdio",
                "command": ["server"],
                "env": {"INNOCENT_NAME": "TOP_SECRET"},
            }
        )
        target = report.to_dict()["target"]
        self.assertEqual(target["environmentKeys"], ["INNOCENT_NAME"])
        self.assertNotIn("TOP_SECRET", json.dumps(target))

    def test_http_target_redacts_url_and_headers(self) -> None:
        target = http_target(
            "https://user:password@example.test/mcp?api_key=TOP_SECRET&safe=yes",
            {"Authorization": "Bearer TOP_SECRET", "X-Trace": "visible"},
        )
        rendered = json.dumps(target)
        self.assertNotIn("TOP_SECRET", rendered)
        self.assertNotIn("password", rendered)
        self.assertEqual(target["headers"]["Authorization"], REDACTED)
        self.assertEqual(target["headers"]["X-Trace"], "visible")


class AggregationAndExitTests(unittest.TestCase):
    def test_aggregation_precedence_and_fixed_counts(self) -> None:
        findings = (
            finding("PASS"),
            finding(
                "WARN",
                code="TOOL_SCHEMA_PORTABILITY",
                category="schema",
                basis="heuristic",
                summary="The schema may not be portable.",
            ),
            finding(
                "SKIP",
                code="CLIENT_REQUEST_ROOTS_LIST",
                category="client-request",
                summary="Roots were not exercised.",
                details="The server made no roots/list request.",
            ),
        )
        overall = aggregate_overall(findings, ())
        self.assertEqual(overall["status"], "WARN")
        self.assertEqual(
            overall["counts"], {"pass": 1, "fail": 0, "warn": 1, "skip": 1}
        )

        failed = aggregate_overall(findings + (finding("FAIL"),), ())
        self.assertEqual(failed["status"], "FAIL")

        errored = aggregate_overall(
            findings,
            (RunError("TRANSPORT_HTTP_CONNECT", "transport", "Could not connect."),),
        )
        self.assertEqual(errored["status"], "ERROR")

    def test_empty_or_all_skip_aggregates_to_skip(self) -> None:
        self.assertEqual(aggregate_overall((), ())["status"], "SKIP")
        self.assertEqual(
            aggregate_overall((finding("SKIP", details="Not applicable."),), ())["status"],
            "SKIP",
        )

    def test_exit_code_precedence(self) -> None:
        fail = finding("FAIL")
        transport_finding = finding(
            "FAIL",
            code="HTTP_STATUS",
            category="transport",
            basis="operational",
            summary="The response status was invalid.",
        )
        self.assertEqual(derive_exit_code((fail,), ()), 1)
        self.assertEqual(derive_exit_code((transport_finding,), ()), 1)
        self.assertEqual(
            derive_exit_code(
                (fail,),
                (RunError("TRANSPORT_HTTP_CONNECT", "transport", "Could not connect."),),
            ),
            3,
        )
        self.assertEqual(
            derive_exit_code(
                (fail,),
                (
                    RunError("TRANSPORT_HTTP_CONNECT", "transport", "Could not connect."),
                    RunError("CONFIG_INVALID_ARGUMENT", "configuration", "Bad option."),
                ),
            ),
            2,
        )
        self.assertEqual(
            derive_exit_code(
                (fail,),
                (
                    RunError("CONFIG_INVALID_ARGUMENT", "configuration", "Bad option."),
                    RunError("INTERNAL_UNEXPECTED", "internal", "Unexpected failure."),
                ),
            ),
            4,
        )


class ReportEnvelopeTests(unittest.TestCase):
    def test_known_secrets_never_corrupt_report_control_schema(self) -> None:
        item = Finding(
            code="NEGOTIATION_PROTOCOL_VERSION",
            status="PASS",
            category="negotiation",
            basis="normative",
            summary="PASS transport event path a",
            actual={
                "transport": "transport",
                "event": "event",
                "path": "path",
                "short": "a",
            },
            evidence=(EvidenceRef("event:1", pointer="/payload/result"),),
        )
        report = CompatibilityReport(
            target=stdio_target(["fixture"]),
            findings=(item,),
            transcript={
                "schema": "mcp-probe.transcript.event/v1",
                "path": "path",
                "eventCount": 1,
                "redacted": True,
            },
            known_secrets=("PASS", "transport", "event", "path", "a"),
        ).to_dict()

        self.assertEqual(report["overall"]["status"], "PASS")
        self.assertEqual(report["target"]["transport"], "stdio")
        self.assertEqual(
            set(report["transcript"]),
            {"schema", "path", "eventCount", "redacted"},
        )
        self.assertEqual(report["transcript"]["path"], REDACTED)
        finding_data = report["findings"][0]
        self.assertEqual(finding_data["status"], "PASS")
        self.assertEqual(finding_data["evidence"][0]["event"], "event:1")
        self.assertEqual(
            finding_data["evidence"][0]["pointer"], "/payload/result"
        )
        self.assertNotIn("transport", finding_data["actual"])

    def test_known_secrets_are_immutable_and_reject_bare_string(self) -> None:
        source = ["secret"]
        report = CompatibilityReport(
            target=stdio_target(["fixture"]), known_secrets=source
        )
        source.append("later")
        self.assertEqual(report.known_secrets, ("secret",))
        with self.assertRaisesRegex(ValueError, "iterable of strings"):
            CompatibilityReport(
                target=stdio_target(["fixture"]), known_secrets="secret"
            )

    def test_exact_required_envelope_and_duplicate_discovery_preserved(self) -> None:
        item = finding("PASS", evidence=(EvidenceRef("event:2"),))
        report = CompatibilityReport(
            target=stdio_target(["fixture"]),
            started_at="2026-08-30T21:00:00.000+00:00",
            discovery={"tools": [{"name": "same"}, {"name": "same"}]},
            findings=(item,),
        )
        data = report.to_dict()
        self.assertEqual(
            list(data),
            [
                "schema",
                "reportType",
                "tool",
                "run",
                "target",
                "protocol",
                "server",
                "discovery",
                "findings",
                "errors",
                "transcript",
                "overall",
            ],
        )
        self.assertEqual(data["schema"], REPORT_SCHEMA)
        self.assertEqual(data["tool"], {"name": "mcp-probe", "version": "0.2.0"})
        self.assertIsNone(data["protocol"]["requestedVersion"])
        self.assertIsNone(data["server"]["serverInfo"])
        self.assertIsNone(data["transcript"])
        self.assertEqual(data["discovery"]["tools"], [{"name": "same"}, {"name": "same"}])
        self.assertEqual(data["discovery"]["resourceTemplates"], [])

    def test_transcript_event_range_is_preserved_and_validated(self) -> None:
        report = CompatibilityReport(
            target=stdio_target(["fixture"]),
            transcript={
                "path": None,
                "eventCount": 3,
                "redacted": True,
                "firstSeq": 8,
                "lastSeq": 10,
            },
        ).to_dict()
        self.assertEqual(report["transcript"]["firstSeq"], 8)
        self.assertEqual(report["transcript"]["lastSeq"], 10)
        with self.assertRaisesRegex(ValueError, "firstSeq"):
            CompatibilityReport(
                target=stdio_target(["fixture"]),
                transcript={
                    "eventCount": 2,
                    "firstSeq": 10,
                    "lastSeq": 8,
                },
            )

    def test_report_is_deeply_immutable(self) -> None:
        report = report_with(finding())
        with self.assertRaises(FrozenInstanceError):
            report.era = "modern"  # type: ignore[misc]
        with self.assertRaises(TypeError):
            report.target["transport"] = "http"  # type: ignore[index]
        with self.assertRaises(TypeError):
            report.server_info["name"] = "changed"  # type: ignore[index,union-attr]

    def test_json_renderer_is_one_pure_document_with_trailing_newline(self) -> None:
        output = render_json(report_with(finding()))
        self.assertTrue(output.endswith("\n"))
        self.assertFalse(output.endswith("\n\n"))
        parsed = json.loads(output)
        self.assertEqual(parsed["overall"]["status"], "PASS")
        self.assertEqual(parsed["run"]["exitCode"], 0)

    def test_text_renderer_lists_passes_failures_and_evidence(self) -> None:
        output = render_text(
            report_with(
                finding("PASS", evidence=(EvidenceRef("event:2"),)),
                finding(
                    "FAIL",
                    code="CAPABILITY_TOOLS_LIST",
                    category="capability",
                    summary="tools/list contradicted capabilities.",
                    details="The tools member was absent.",
                    evidence=(EvidenceRef("event:5"),),
                ),
            )
        )
        self.assertIn("MCP Probe compatibility: FAIL", output)
        self.assertIn("PASS NEGOTIATION_PROTOCOL_VERSION", output)
        self.assertIn("FAIL CAPABILITY_TOOLS_LIST", output)
        self.assertIn("[event:5]", output)
        self.assertIn("The tools member was absent.", output)

    def test_markdown_renderer_escapes_table_cells(self) -> None:
        output = render_markdown(
            report_with(
                finding(
                    "WARN",
                    code="TOOL_SCHEMA_PORTABILITY",
                    category="schema",
                    basis="heuristic",
                    summary="Union | newline\nmay be less portable.",
                )
            )
        )
        self.assertIn("# MCP Probe compatibility: WARN", output)
        self.assertIn("Union \\| newline may be less portable.", output)
        self.assertIn("## Errors\n\nNone.", output)

    def test_renderers_redact_mapping_input_again(self) -> None:
        raw = {"Authorization": "Bearer TOP_SECRET", "nested": {"Cookie": "COOKIE_SECRET"}}
        for renderer in (render_json, render_text, render_markdown):
            with self.subTest(renderer=renderer.__name__):
                output = renderer(raw)
                self.assertNotIn("TOP_SECRET", output)
                self.assertNotIn("COOKIE_SECRET", output)

    def test_write_report_is_json_and_creates_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "report.json"
            write_report(path, report_with(finding()))
            parsed = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(parsed["schema"], REPORT_SCHEMA)
            self.assertEqual(parsed["overall"]["status"], "PASS")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])

    def test_write_report_replaces_regular_file_with_private_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("old", encoding="utf-8")
            path.chmod(0o644)
            write_report(path, report_with(finding()))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["schema"], REPORT_SCHEMA)

    def test_write_report_rejects_symlink_without_touching_victim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            victim = Path(directory) / "victim.txt"
            victim.write_text("unchanged", encoding="utf-8")
            path = Path(directory) / "report.json"
            path.symlink_to(victim)
            with self.assertRaisesRegex(ConfigurationError, "safe regular file|regular file"):
                write_report(path, report_with(finding()))
            self.assertTrue(path.is_symlink())
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")

    def test_write_report_rejects_hardlink_without_touching_victim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            victim = Path(directory) / "victim.txt"
            victim.write_text("unchanged", encoding="utf-8")
            path = Path(directory) / "report.json"
            os.link(victim, path)
            with self.assertRaisesRegex(ConfigurationError, "hard-linked"):
                write_report(path, report_with(finding()))
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
            self.assertTrue(path.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs are not available")
    def test_write_report_rejects_fifo_without_opening_it_for_io(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            os.mkfifo(path)
            with self.assertRaisesRegex(ConfigurationError, "regular file"):
                write_report(path, report_with(finding()))
            self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))

    def test_write_report_rejects_stdout_sentinel(self) -> None:
        with self.assertRaises(ConfigurationError):
            write_report("-", report_with(finding()))


class MatrixReportTests(unittest.TestCase):
    def test_matrix_redacts_all_children_without_corrupting_control_fields(self) -> None:
        child = CompatibilityReport(
            target=stdio_target(["fixture", "MATRIX_SECRET"]),
            requested_version="2025-06-18",
            negotiated_version="2025-06-18",
            findings=(
                Finding(
                    code="NEGOTIATION_PROTOCOL_VERSION",
                    status="PASS",
                    category="negotiation",
                    basis="normative",
                    summary="MATRIX_SECRET",
                    actual={"MATRIX_SECRET": "MATRIX_SECRET"},
                    evidence=(EvidenceRef("event:1", pointer="/payload/result"),),
                ),
            ),
            server_info={"name": "MATRIX_SECRET"},
        ).to_dict()
        report = CompatibilityReport(
            target=stdio_target(["fixture"]),
            report_type="matrix",
            matrix={"versions": ["2025-06-18"], "runs": [child]},
            known_secrets=("MATRIX_SECRET", "PASS", "event"),
        ).to_dict()

        rendered = json.dumps(report)
        self.assertNotIn("MATRIX_SECRET", rendered)
        self.assertEqual(report["overall"]["status"], "PASS")
        self.assertEqual(report["matrix"]["versions"], ["2025-06-18"])
        child_data = report["matrix"]["runs"][0]
        self.assertEqual(child_data["target"]["transport"], "stdio")
        self.assertEqual(child_data["findings"][0]["status"], "PASS")
        self.assertEqual(child_data["findings"][0]["evidence"][0]["event"], "event:1")
        self.assertEqual(
            child_data["findings"][0]["evidence"][0]["pointer"],
            "/payload/result",
        )

    def test_matrix_sums_children_and_derives_exit(self) -> None:
        matrix = {
            "versions": ["2024-11-05", "2025-06-18"],
            "runs": [
                {
                    "protocol": {"requestedVersion": "2024-11-05"},
                    "server": {"serverInfo": None, "capabilities": None},
                    "discovery": {key: [] for key in ("tools", "resources", "resourceTemplates", "prompts")},
                    "findings": [finding("PASS").to_dict()],
                    "errors": [],
                    "transcript": None,
                    "overall": {
                        "status": "PASS",
                        "counts": {"pass": 1, "fail": 0, "warn": 0, "skip": 0},
                        "errorCount": 0,
                    },
                },
                {
                    "protocol": {"requestedVersion": "2025-06-18"},
                    "server": {"serverInfo": None, "capabilities": None},
                    "discovery": {key: [] for key in ("tools", "resources", "resourceTemplates", "prompts")},
                    "findings": [finding("FAIL").to_dict()],
                    "errors": [],
                    "transcript": None,
                    "overall": {
                        "status": "FAIL",
                        "counts": {"pass": 0, "fail": 1, "warn": 0, "skip": 0},
                        "errorCount": 0,
                    },
                },
            ],
        }
        report = CompatibilityReport(
            target=stdio_target(["fixture"]),
            report_type="matrix",
            matrix=matrix,
        )
        data = report.to_dict()
        self.assertEqual(data["overall"]["status"], "FAIL")
        self.assertEqual(
            data["overall"]["counts"],
            {"pass": 1, "fail": 1, "warn": 0, "skip": 0},
        )
        self.assertEqual(data["run"]["exitCode"], 1)
        self.assertEqual(data["findings"], [])

        text_output = render_text(report)
        self.assertIn("Version runs:", text_output)
        self.assertIn("2024-11-05: PASS", text_output)
        self.assertIn("2025-06-18: FAIL", text_output)
        self.assertIn("PASS NEGOTIATION_PROTOCOL_VERSION", text_output)
        self.assertIn("FAIL NEGOTIATION_PROTOCOL_VERSION", text_output)

        markdown_output = render_markdown(report)
        self.assertIn("## Version summary", markdown_output)
        self.assertIn("| 2024-11-05 |", markdown_output)
        self.assertIn("| 2025-06-18 |", markdown_output)
        self.assertIn("| Protocol | Status | Code |", markdown_output)

    def test_matrix_error_kind_controls_exit(self) -> None:
        matrix = {
            "versions": ["2025-06-18"],
            "runs": [
                {
                    "findings": [],
                    "errors": [
                        RunError(
                            "TRANSPORT_HTTP_CONNECT", "transport", "Could not connect."
                        ).to_dict()
                    ],
                    "overall": {
                        "status": "ERROR",
                        "counts": {"pass": 0, "fail": 0, "warn": 0, "skip": 0},
                        "errorCount": 1,
                    },
                }
            ],
        }
        report = CompatibilityReport(
            target=http_target("https://example.test/mcp"),
            report_type="matrix",
            matrix=matrix,
        )
        self.assertEqual(report.exit_code, 3)
        self.assertEqual(report.overall["status"], "ERROR")
        self.assertIn(
            "2025-06-18: ERROR", render_text(report)
        )
        self.assertIn(
            "`2025-06-18` — **TRANSPORT_HTTP_CONNECT:**",
            render_markdown(report),
        )

    def test_matrix_rejects_unknown_error_kind_instead_of_returning_clean_exit(self) -> None:
        report = CompatibilityReport(
            target=stdio_target(["fixture"]),
            report_type="matrix",
            matrix={
                "versions": ["2025-06-18"],
                "runs": [
                    {
                        "findings": [],
                        "errors": [{"kind": "mystery"}],
                        "overall": {
                            "status": "ERROR",
                            "counts": {
                                "pass": 0,
                                "fail": 0,
                                "warn": 0,
                                "skip": 0,
                            },
                            "errorCount": 1,
                        },
                    }
                ],
            },
        )
        with self.assertRaisesRegex(ValueError, "error kind"):
            _ = report.exit_code


if __name__ == "__main__":
    unittest.main()
