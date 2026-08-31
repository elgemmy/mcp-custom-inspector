from __future__ import annotations

import json
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
            self.assertEqual(list(path.parent.glob(f".{path.name}.*.tmp")), [])

    def test_write_report_rejects_stdout_sentinel(self) -> None:
        with self.assertRaises(ConfigurationError):
            write_report("-", report_with(finding()))


class MatrixReportTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
