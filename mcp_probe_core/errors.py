"""Error classes and documented process exit codes."""

from __future__ import annotations

from typing import Any


EXIT_OK = 0
EXIT_COMPATIBILITY_FAILURE = 1
EXIT_CONFIGURATION_ERROR = 2
EXIT_TRANSPORT_FAILURE = 3
EXIT_INTERNAL_ERROR = 4


class ProbeError(Exception):
    """Base class for failures that have a stable CLI exit category."""

    exit_code = EXIT_INTERNAL_ERROR


class ConfigurationError(ProbeError):
    exit_code = EXIT_CONFIGURATION_ERROR


class TransportError(ProbeError):
    exit_code = EXIT_TRANSPORT_FAILURE


class HttpExchangeError(TransportError):
    """HTTP wire evidence exists, but no usable correlated response did."""

    def __init__(self, message: str, exchange: Any, *, finding_code: str) -> None:
        super().__init__(message)
        self.exchange = exchange
        self.finding_code = finding_code


class ProbeTimeout(TransportError, TimeoutError):
    """A request exceeded the configured transport timeout."""


class ProcessExited(TransportError):
    """A stdio server exited before the expected protocol event."""
