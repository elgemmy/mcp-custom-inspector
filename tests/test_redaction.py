from __future__ import annotations

import unittest

from mcp_probe_core.redaction import (
    REDACTED,
    contains_redaction,
    redact_command,
    redact_headers,
    redact_raw,
    redact_text,
    redact_url,
    redact_value,
    sensitive_header,
    sensitive_key,
)


class RedactionTests(unittest.TestCase):
    def test_sensitive_keys_cover_common_credentials_without_hiding_safe_names(self) -> None:
        for key in (
            "token",
            "NOTION_TOKEN",
            "accessToken",
            "refresh-token",
            "api_key",
            "client.secret",
            "private_key",
            "x-amz-signature",
            "sessionId",
            "Cookie",
        ):
            with self.subTest(key=key):
                self.assertTrue(sensitive_key(key))
        for key in ("name", "protocolVersion", "monkey", "sessionCount"):
            with self.subTest(key=key):
                self.assertFalse(sensitive_key(key))

    def test_headers_redact_credentials_and_every_mirrored_argument(self) -> None:
        headers = redact_headers(
            {
                "Authorization": "Bearer auth-secret",
                "set-cookie": "sid=cookie-secret",
                "X-Custom-Token": "custom-secret",
                "Mcp-Session-Id": "session-secret",
                "Mcp-Param-Name": "even-non-secret-tool-arguments-are-private",
                "mcp-param-API-Key": "mirrored-secret",
                "Content-Type": "application/json",
            }
        )
        for key in headers:
            if key == "Content-Type":
                self.assertEqual(headers[key], "application/json")
            else:
                self.assertEqual(headers[key], REDACTED, key)
        self.assertTrue(sensitive_header("MCP-PARAM-anything"))

    def test_nested_values_urls_and_sequences_are_redacted_without_mutation(self) -> None:
        original = {
            "headers": {"Authorization": "Bearer payload-secret"},
            "arguments": {
                "password": "password-secret",
                "uri": "https://user:hunter2@example.test/mcp?access_token=url-secret&safe=yes",
            },
            "tuple": ({"session_id": "session-secret"},),
        }
        redacted = redact_value(original)
        self.assertEqual(original["arguments"]["password"], "password-secret")
        rendered = repr(redacted)
        for secret in (
            "payload-secret",
            "password-secret",
            "url-secret",
            "session-secret",
            "user",
            "hunter2",
        ):
            self.assertNotIn(secret, rendered)
        self.assertIn("safe=yes", redacted["arguments"]["uri"])
        self.assertTrue(contains_redaction(redacted))

    def test_url_redacts_userinfo_sensitive_query_and_fragment_assignments(self) -> None:
        safe = redact_url(
            "https://alice:hunter2@[::1]:8443/mcp?token=abc&plain=yes#access_token=frag"
        )
        self.assertEqual(
            safe,
            "https://[REDACTED]@[::1]:8443/mcp?token=[REDACTED]&plain=yes#[REDACTED]",
        )
        for secret in ("alice", "hunter2", "abc", "frag"):
            self.assertNotIn(secret, safe)

    def test_malformed_url_does_not_raise_or_leak_query_token(self) -> None:
        safe = redact_url(
            "http://alice:hunter2@example.test:not-a-port/mcp?token=port-secret#fragment-secret"
        )
        self.assertIn(REDACTED, safe)
        for secret in ("alice", "hunter2", "port-secret", "fragment-secret"):
            self.assertNotIn(secret, safe)

    def test_commands_redact_separate_inline_env_header_and_url_secrets(self) -> None:
        safe = redact_command(
            [
                "server",
                "--token",
                "flag-secret",
                "--api-key=inline-secret",
                "NOTION_TOKEN=env-secret",
                "Authorization: Bearer header-secret",
                "--header=Authorization: Bearer inline-header-secret",
                "-H",
                "Cookie: sid=separate-header-secret",
                "https://example.test/mcp?access_token=url-secret&plain=yes",
            ]
        )
        rendered = repr(safe)
        for secret in (
            "flag-secret",
            "inline-secret",
            "env-secret",
            "header-secret",
            "inline-header-secret",
            "separate-header-secret",
            "url-secret",
        ):
            self.assertNotIn(secret, rendered)
        self.assertEqual(safe[2], REDACTED)

    def test_raw_valid_json_uses_structured_redaction(self) -> None:
        raw = (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":'
            '{"arguments":{"token":"wire-secret","safe":"visible"},'
            '"uri":"https://example.test/?api_key=url-secret"}}'
        )
        safe = redact_raw(raw)
        self.assertNotIn("wire-secret", safe)
        self.assertNotIn("url-secret", safe)
        self.assertIn('"safe":"visible"', safe)
        self.assertIn(REDACTED, safe)

    def test_raw_malformed_json_redacts_scalars_and_withholds_complex_secret_values(self) -> None:
        scalar = redact_raw('{"token":"malformed-secret", broken')
        self.assertNotIn("malformed-secret", scalar)
        self.assertIn(REDACTED, scalar)
        complex_value = redact_raw('{"secret":{"nested":"cannot-bound"}, broken')
        self.assertEqual(complex_value, REDACTED)

    def test_text_redacts_headers_cookies_and_environment_assignments(self) -> None:
        safe = redact_text(
            "request failed with Authorization: Bearer embedded-secret\n"
            "Authorization: Bearer auth-secret\n"
            "Set-Cookie: sid=cookie-secret\n"
            "NOTION_TOKEN=env-secret ordinary text"
        )
        for secret in (
            "embedded-secret",
            "auth-secret",
            "cookie-secret",
            "env-secret",
        ):
            self.assertNotIn(secret, safe)
        self.assertIn("ordinary text", safe)


if __name__ == "__main__":
    unittest.main()
