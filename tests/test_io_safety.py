from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mcp_probe_core.io_safety import iter_utf8_lines_limited, read_utf8_limited


ROOT = Path(__file__).resolve().parent.parent


class InputFileTests(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs are not available")
    def test_fifo_loaders_reject_without_waiting_for_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            os.mkfifo(source)
            for expression in (
                "read_utf8_limited(path, max_bytes=1024, label='Input')",
                "list(iter_utf8_lines_limited(path, max_bytes=1024, "
                "max_lines=10, max_line_bytes=1024, label='Input'))",
            ):
                with self.subTest(expression=expression):
                    code = (
                        "from mcp_probe_core.io_safety import *\n"
                        "import sys\npath = sys.argv[1]\n"
                        "try:\n    " + expression + "\n"
                        "except InputLimitError as exc:\n    print(exc)\n"
                        "else:\n    raise SystemExit('accepted FIFO')\n"
                    )
                    result = subprocess.run(
                        [sys.executable, "-c", code, str(source)],
                        cwd=ROOT, capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("regular file", result.stdout)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFOs are not available")
    def test_cli_fifo_input_returns_configuration_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "init.json"
            os.mkfifo(source)
            result = subprocess.run(
                [sys.executable, "mcp_probe.py", "stdio", "--init-file",
                 str(source), "--", sys.executable, "-c", "raise SystemExit(99)"],
                cwd=ROOT, capture_output=True, text=True, timeout=5,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("regular file", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_regular_utf8_files_and_symlinks_remain_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input"
            source.write_text("héllo\nworld\n", encoding="utf-8")
            paths = [source]
            if hasattr(os, "symlink"):
                link = Path(directory) / "link"
                link.symlink_to(source)
                paths.append(link)
            for path in paths:
                with self.subTest(path=path):
                    self.assertEqual(
                        read_utf8_limited(path, max_bytes=100, label="Input"),
                        "héllo\nworld\n",
                    )
                    self.assertEqual(
                        list(iter_utf8_lines_limited(
                            path, max_bytes=100, max_lines=10,
                            max_line_bytes=100, label="Input",
                        )),
                        [(1, "héllo"), (2, "world")],
                    )
