from __future__ import annotations

import base64
import time
import unittest

from mcp_probe_core.redaction import (
    REDACTED,
    contains_redaction,
    known_secrets_from_command,
    known_secrets_from_environment,
    known_secrets_from_headers,
    known_secrets_from_url,
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
            "GoogleApiKey",
            "openaiApiKey",
            "OcpApimSubscriptionKey",
            "AzureFunctionsKey",
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
        self.assertTrue(sensitive_header("GoogleApiKey"))
        self.assertTrue(sensitive_header("OcpApimSubscriptionKey"))
        self.assertTrue(sensitive_header("X-Client-Key"))

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

    def test_url_redacts_short_and_oauth_credential_query_names(self) -> None:
        safe = redact_url(
            "https://example.test/mcp?key=key-secret&sig=sig-secret&code=code-secret&"
            "code_verifier=verifier-secret&client_assertion=assertion-secret&plain=yes"
        )
        for secret in (
            "key-secret",
            "sig-secret",
            "code-secret",
            "verifier-secret",
            "assertion-secret",
        ):
            self.assertNotIn(secret, safe)
        self.assertIn("plain=yes", safe)

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
                "--auth-token",
                "auth-secret",
                "--private-key=private-secret",
                "--cookie",
                "cookie-flag-secret",
                "sh -c 'server --session-id shell-secret --token=shell-token'",
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
            "auth-secret",
            "private-secret",
            "cookie-flag-secret",
            "shell-secret",
            "shell-token",
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

    def test_raw_protocol_vocabulary_survives_secret_collision(self) -> None:
        raw = '{"jsonrpc":"2.0","id":1,"method":"ping","params":{}}'
        self.assertEqual(redact_raw(raw, ("id", "ping")), raw)

        duplicate = (
            '{"jsonrpc":"2.0","method":"ping",'
            '"token":"private","token":"safe"}'
        )
        self.assertEqual(redact_raw(duplicate), REDACTED)

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
            "DPoP: dpop-header-secret\n"
            "standalone Bearer bearer-secret and Basic basic-secret and DPoP dpop-secret\n"
            "NOTION_TOKEN=env-secret ordinary text"
        )
        for secret in (
            "embedded-secret",
            "auth-secret",
            "cookie-secret",
            "env-secret",
            "dpop-header-secret",
            "bearer-secret",
            "basic-secret",
            "dpop-secret",
        ):
            self.assertNotIn(secret, safe)
        self.assertIn("ordinary text", safe)

    def test_known_secret_extraction_covers_basic_cookies_userinfo_query_and_env(self) -> None:
        basic = base64.b64encode(b"alice:hunter2").decode("ascii")
        header_secrets = known_secrets_from_headers(
            {
                "Authorization": f"Basic {basic}",
                "Cookie": 'sid="cookie-secret"; csrf=csrf-secret',
                "GoogleApiKey": "compact-header-secret",
                "X-Client-Key": "client-key-secret",
            }
        )
        for secret in (
            basic,
            "alice",
            "hunter2",
            "cookie-secret",
            "csrf-secret",
            "compact-header-secret",
            "client-key-secret",
        ):
            self.assertIn(secret, header_secrets)

        url_secrets = known_secrets_from_url(
            "https://al%69ce:hunter%32@example.test/mcp?token=abc%2Fdef&plain=yes"
        )
        for secret in ("alice", "hunter2", "abc/def", "abc%2Fdef"):
            self.assertIn(secret, url_secrets)
        self.assertNotIn("yes", url_secrets)

        command_secrets = known_secrets_from_command(
            ["server", "--header", f"Authorization: Basic {basic}"]
        )
        self.assertIn("hunter2", command_secrets)
        self.assertEqual(
            known_secrets_from_environment(
                {"NOTION_TOKEN": "env-secret", "VISIBLE": "safe"}
            ),
            {"env-secret"},
        )

    def test_raw_redaction_is_linear_for_delimiter_free_hostile_input(self) -> None:
        started = time.monotonic()
        for raw in ("a" * (64 * 1024), '"' * (64 * 1024)):
            self.assertEqual(redact_raw(raw), raw)
        self.assertLess(time.monotonic() - started, 2.0)


if __name__ == "__main__":
    unittest.main()
