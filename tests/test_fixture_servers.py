from __future__ import annotations

import json
import socket
import subprocess
import unittest
import urllib.error
import urllib.request
from typing import Any

from tests.fixtures.mcp_fixture import (
    FixtureConfig,
    FixtureEngine,
    running_http_fixture,
    stdio_fixture_command,
)


def initialize_message(request_id: int = 1) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "fixture-self-test", "version": "1"},
        },
    }


def encoded_line(message: Any) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"


def run_stdio_once(profile: str, *extra_args: str) -> tuple[int, bytes, bytes]:
    process = subprocess.Popen(
        stdio_fixture_command(profile, *extra_args),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate(encoded_line(initialize_message()), timeout=3)
    return process.returncode, stdout, stderr


def post_json(
    url: str, message: Any, headers: dict[str, str] | None = None, timeout: float = 2
) -> tuple[int, dict[str, str], bytes]:
    request = urllib.request.Request(
        url,
        data=json.dumps(message).encode("utf-8"),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


class StdioFixtureTests(unittest.TestCase):
    def test_good_and_fault_profiles_cross_real_process_boundary(self) -> None:
        cases = {
            "stdio-good-legacy": (1, False),
            "stdio-good-modern": (1, False),
            "stdio-mismatched-id": (1001, False),
            "stdio-invalid-response": (1, True),
            "stdio-partial-output": (1, False),
        }
        for profile, (expected_id, has_error) in cases.items():
            with self.subTest(profile=profile):
                returncode, stdout, stderr = run_stdio_once(
                    profile, "--chunk-delay", "0.001"
                )
                self.assertEqual(returncode, 0, stderr.decode(errors="replace"))
                response = json.loads(stdout)
                self.assertEqual(response["id"], expected_id)
                self.assertEqual("error" in response, has_error)

    def test_malformed_and_non_utf8_profiles_recover_with_valid_response(self) -> None:
        for profile in ("stdio-malformed-output", "stdio-non-utf8"):
            with self.subTest(profile=profile):
                returncode, stdout, _stderr = run_stdio_once(profile)
                self.assertEqual(returncode, 0)
                invalid, valid = stdout.splitlines()
                self.assertTrue(invalid)
                self.assertEqual(json.loads(valid)["id"], 1)

    def test_crash_profile_uses_configured_exit_code(self) -> None:
        returncode, stdout, _stderr = run_stdio_once(
            "stdio-crash", "--crash-exit-code", "23"
        )
        self.assertEqual(returncode, 23)
        self.assertEqual(stdout, b"")

    def test_server_request_blocks_initialize_until_client_response(self) -> None:
        process = subprocess.Popen(
            stdio_fixture_command("stdio-server-request"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        try:
            process.stdin.write(encoded_line(initialize_message()))
            process.stdin.flush()
            server_request = json.loads(process.stdout.readline())
            self.assertEqual(server_request["method"], "roots/list")
            process.stdin.write(
                encoded_line(
                    {
                        "jsonrpc": "2.0",
                        "id": server_request["id"],
                        "result": {"roots": []},
                    }
                )
            )
            process.stdin.flush()
            self.assertEqual(json.loads(process.stdout.readline())["id"], 1)
        finally:
            process.stdin.close()
            process.wait(timeout=2)
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def test_out_of_order_profile_reverses_two_outstanding_responses(self) -> None:
        process = subprocess.Popen(
            stdio_fixture_command("stdio-out-of-order"),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert process.stdin is not None and process.stdout is not None
        try:
            messages = [
                initialize_message(),
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
                {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}},
            ]
            for message in messages:
                process.stdin.write(encoded_line(message))
                process.stdin.flush()
            ids = [json.loads(process.stdout.readline())["id"] for _ in range(3)]
            self.assertEqual(ids, [1, 3, 2])
        finally:
            process.stdin.close()
            process.wait(timeout=2)
            process.stdout.close()
            if process.stderr is not None:
                process.stderr.close()

    def test_pagination_modes_are_deterministic(self) -> None:
        for mode, expected_next in {
            "normal": None,
            "repeat": "page-2",
            "loop": "page-1",
        }.items():
            with self.subTest(mode=mode):
                engine = FixtureEngine(
                    FixtureConfig(profile="stdio-pagination", pagination_mode=mode)
                )
                engine.handle(initialize_message())
                first = engine.handle(
                    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
                )[0]
                second = engine.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/list",
                        "params": {"cursor": first["result"]["nextCursor"]},
                    }
                )[0]
                self.assertEqual(second["result"].get("nextCursor"), expected_next)


class HttpFixtureTests(unittest.TestCase):
    def test_http_body_profiles_cross_real_loopback_boundary(self) -> None:
        cases = {
            "http-json": (200, "application/json"),
            "http-sse": (200, "text/event-stream"),
            "http-sse-multi": (200, "text/event-stream"),
            "http-malformed-body": (200, "application/json"),
            "http-error": (503, "application/json"),
            "http-empty": (202, None),
            "http-wrong-content-type": (200, "text/plain"),
        }
        for profile, (expected_status, expected_type) in cases.items():
            with self.subTest(profile=profile), running_http_fixture(profile) as fixture:
                status, headers, body = post_json(fixture.url, initialize_message())
                self.assertEqual(status, expected_status)
                self.assertEqual(headers.get("Content-Type"), expected_type)
                if profile == "http-sse-multi":
                    self.assertEqual(body.count(b"event: message"), 2)

    def test_http_session_requires_session_and_optional_protocol_headers(self) -> None:
        with running_http_fixture(
            "http-session", require_protocol_header=True
        ) as fixture:
            status, headers, _body = post_json(fixture.url, initialize_message())
            self.assertEqual(status, 200)
            session_id = headers["Mcp-Session-Id"]
            listed = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            self.assertEqual(post_json(fixture.url, listed)[0], 404)
            self.assertEqual(
                post_json(fixture.url, listed, {"Mcp-Session-Id": session_id})[0], 400
            )
            valid_headers = {
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-06-18",
            }
            self.assertEqual(post_json(fixture.url, listed, valid_headers)[0], 200)

            request = urllib.request.Request(
                fixture.url, headers={"Mcp-Session-Id": session_id}, method="DELETE"
            )
            with urllib.request.urlopen(request, timeout=2) as response:
                self.assertEqual(response.status, 204)
            self.assertTrue(fixture.state.terminated)

    def test_http_delay_can_trigger_a_real_client_timeout(self) -> None:
        with running_http_fixture("http-delayed-response", delay=0.20) as fixture:
            with self.assertRaises((TimeoutError, socket.timeout)):
                post_json(fixture.url, initialize_message(), timeout=0.02)


if __name__ == "__main__":
    unittest.main()
