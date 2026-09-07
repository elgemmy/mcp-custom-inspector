"""Small bounded-I/O helpers shared by untrusted artifact loaders.

The helpers intentionally operate on bytes before decoding.  ``Path.read_text``
and iteration over a binary file can each allocate an arbitrarily long input or
line before a caller gets a chance to enforce a limit.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import os
from pathlib import Path
import stat
from typing import BinaryIO


class InputLimitError(ValueError):
    """An input exceeded a deterministic local resource limit."""


@contextmanager
def _open_regular_input(source: Path) -> Iterator[BinaryIO]:
    # Reject devices before opening them, and FIFOs before waiting for a writer.
    # Check the opened descriptor too: the path may change after stat().
    if not stat.S_ISREG(source.stat().st_mode):
        raise InputLimitError("Input must be a regular file")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    descriptor = os.open(source, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise InputLimitError("Input must be a regular file")
        stream = os.fdopen(descriptor, "rb")
        descriptor = None
        with stream:
            yield stream
    finally:
        if descriptor is not None:
            os.close(descriptor)


def read_utf8_limited(
    path: str | Path,
    *,
    max_bytes: int,
    label: str,
) -> str:
    """Read one UTF-8 file without ever buffering more than ``max_bytes + 1``."""

    source = Path(path)
    with _open_regular_input(source) as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise InputLimitError(f"{label} exceeds the {max_bytes}-byte safety limit")
    return data.decode("utf-8", errors="strict")


def iter_utf8_lines_limited(
    path: str | Path,
    *,
    max_bytes: int,
    max_lines: int,
    max_line_bytes: int,
    label: str,
) -> Iterator[tuple[int, str]]:
    """Yield bounded UTF-8 lines while enforcing aggregate and per-line limits."""

    source = Path(path)
    total = 0
    line_number = 0
    with _open_regular_input(source) as stream:
        while True:
            raw = stream.readline(max_line_bytes + 1)
            if not raw:
                return
            line_number += 1
            if line_number > max_lines:
                raise InputLimitError(
                    f"{label} exceeds the {max_lines}-line safety limit"
                )
            if len(raw) > max_line_bytes:
                raise InputLimitError(
                    f"{label} line {line_number} exceeds the "
                    f"{max_line_bytes}-byte safety limit"
                )
            total += len(raw)
            if total > max_bytes:
                raise InputLimitError(
                    f"{label} exceeds the {max_bytes}-byte safety limit"
                )
            yield line_number, raw.decode("utf-8", errors="strict").rstrip("\r\n")
