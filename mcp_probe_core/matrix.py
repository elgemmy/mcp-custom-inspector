"""Run the same safe compatibility probe across explicit MCP revisions."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .errors import ConfigurationError
from .protocol import SUPPORTED_PROTOCOL_VERSIONS, profile_for
from .report import CompatibilityReport
from .session import McpSession


SessionFactory = Callable[[str], McpSession]


def validate_matrix_versions(versions: Iterable[str], *, transport: str) -> tuple[str, ...]:
    """Validate and de-duplicate revisions while preserving caller order."""

    selected: list[str] = []
    seen: set[str] = set()
    for version in versions:
        profile = profile_for(version)
        if transport == "http" and not profile.streamable_http:
            raise ConfigurationError(
                f"Protocol {version} predates Streamable HTTP; use stdio for that revision."
            )
        if transport not in {"stdio", "http"}:
            raise ConfigurationError(f"Unsupported matrix transport: {transport!r}")
        if version not in seen:
            seen.add(version)
            selected.append(version)
    if not selected:
        raise ConfigurationError("Matrix mode requires at least one protocol version.")
    return tuple(selected)


def default_matrix_versions(transport: str) -> tuple[str, ...]:
    if transport == "stdio":
        return SUPPORTED_PROTOCOL_VERSIONS
    if transport == "http":
        return tuple(
            version
            for version in SUPPORTED_PROTOCOL_VERSIONS
            if profile_for(version).streamable_http
        )
    raise ConfigurationError(f"Unsupported matrix transport: {transport!r}")


def run_matrix(
    session_factory: SessionFactory,
    versions: Iterable[str],
    *,
    target: Mapping[str, Any],
    transport: str,
    timeout: float = 10.0,
    max_pages: int = 100,
) -> CompatibilityReport:
    """Run one isolated target process/session for every requested revision.

    The factory must return a fresh session. Reusing a process would make the
    matrix order-dependent and would invalidate lifecycle comparisons.
    """

    from .checks import run_check

    selected = validate_matrix_versions(versions, transport=transport)
    started = time.monotonic()
    runs: list[dict[str, Any]] = []
    for version in selected:
        session = session_factory(version)
        if session.requested_version != version:
            raise ConfigurationError(
                "Matrix session factory returned a session for a different protocol version."
            )
        try:
            report = run_check(
                session,
                timeout=timeout,
                max_pages=max_pages,
                close=False,
            )
        finally:
            session.close()
        runs.append(report.to_dict())

    return CompatibilityReport(
        target=target,
        report_type="matrix",
        duration_ms=(time.monotonic() - started) * 1000,
        matrix={"versions": list(selected), "runs": runs},
    )


__all__ = [
    "SessionFactory",
    "default_matrix_versions",
    "run_matrix",
    "validate_matrix_versions",
]
