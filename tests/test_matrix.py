from __future__ import annotations

import unittest

from mcp_probe_core.errors import ConfigurationError
from mcp_probe_core.matrix import default_matrix_versions, validate_matrix_versions
from mcp_probe_core.protocol import SUPPORTED_PROTOCOL_VERSIONS


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


if __name__ == "__main__":
    unittest.main()
