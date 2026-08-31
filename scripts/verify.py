#!/usr/bin/env python3
"""Run every offline repository-local MCP Probe quality gate."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def run(*arguments: str) -> None:
    command = [sys.executable, *arguments]
    print("+", " ".join(command), flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode:
        raise SystemExit(completed.returncode)


def main() -> int:
    compile_targets = ["mcp_probe.py", "mcp_probe_core", "tests", "scripts"]
    if (ROOT / "examples").is_dir():
        compile_targets.append("examples")
    run("-m", "compileall", "-q", *compile_targets)
    run("-m", "unittest", "discover", "-s", "tests", "-v")
    print("Offline verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
