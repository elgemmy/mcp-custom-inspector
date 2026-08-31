"""Conservative redaction for diagnostics, reports, and transcripts.

Redaction happens before values reach any output sink.  It is intentionally
broader for HTTP headers than for ordinary JSON objects: every ``Mcp-Param-*``
header mirrors a tool argument and therefore has to be treated as sensitive,
regardless of its user-chosen name.
"""

from __future__ import annotations

import json
import re
from copy import deepcopy
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"

_SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
    "mcp-session-id",
}

_SENSITIVE_HEADER_PREFIXES = ("mcp-param-",)

_SENSITIVE_KEY = re.compile(
    r"(?:^|[_\-.])(api[_\-.]?key|access[_\-.]?token|refresh[_\-.]?token|auth(?:orization)?|"
    r"token|password|passwd|secret|private[_\-.]?key|signing[_\-.]?key|signature|"
    r"client[_\-.]?secret|credential|cookie|session[_\-.]?id)(?:$|[_\-.])",
    re.IGNORECASE,
)
_SENSITIVE_FLAG = re.compile(
    r"^--?(?:api[-_]?key|token|access[-_]?token|password|passwd|secret|client[-_]?secret|credential)$",
    re.IGNORECASE,
)
_HEADER_LINE = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|"
    r"x-auth-token|x-access-token|mcp-session-id)\s*:\s*).*$"
)
_INLINE_SENSITIVE_HEADER = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|"
    r"x-auth-token|x-access-token|mcp-session-id)\s*:\s*)[^\r\n]+"
)
_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:TOKEN|PASSWORD|PASSWD|SECRET|PRIVATE_KEY|SIGNATURE|"
    r"API_KEY|CREDENTIAL|COOKIE|SESSION_ID)[A-Z0-9_]*)=([^\s]+)"
)
_JSON_PAIR = re.compile(
    r'("(?:\\.|[^"\\])*")(\s*:\s*)'
    r'("(?:\\.|[^"\\])*"|-?(?:\d+(?:\.\d+)?)|true|false|null)',
    re.IGNORECASE,
)
_JSON_COMPLEX_VALUE = re.compile(
    r'("(?:\\.|[^"\\])*"\s*:\s*)[\[{]', re.IGNORECASE
)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

_SENSITIVE_COMPACT_SUFFIXES = (
    "token",
    "password",
    "passwd",
    "secret",
    "privatekey",
    "signingkey",
    "signature",
    "credential",
    "cookie",
    "sessionid",
)


def sensitive_key(name: str) -> bool:
    normalized = name.strip().lower()
    compact = re.sub(r"[^a-z0-9]", "", normalized)
    return (
        normalized in _SENSITIVE_HEADERS
        or bool(_SENSITIVE_KEY.search(normalized))
        or compact.endswith(_SENSITIVE_COMPACT_SUFFIXES)
    )


def sensitive_header(name: str) -> bool:
    normalized = name.strip().lower()
    return (
        normalized in _SENSITIVE_HEADERS
        or normalized.startswith(_SENSITIVE_HEADER_PREFIXES)
        or sensitive_key(normalized)
    )


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, Any]:
    return {
        str(key): REDACTED if sensitive_header(str(key)) else redact_value(value)
        for key, value in (headers or {}).items()
    }


def redact_value(value: Any, parent_key: str | None = None) -> Any:
    if parent_key and sensitive_key(parent_key):
        return REDACTED
    if isinstance(value, dict):
        return {
            str(key): REDACTED if sensitive_key(str(key)) else redact_value(item, str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item) for item in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            return redact_url(value)
        return redact_text(value)
    return deepcopy(value)


def redact_url(url: str) -> str:
    parts = None
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        # ``urlsplit`` exposes ``.port`` lazily, so malformed ports reach this
        # path after the userinfo was already parsed.  Use a conservative text
        # fallback that still removes userinfo, query assignments, and the
        # entire fragment without recursively trying to parse the same URL.
        redacted = re.sub(
            r"(?i)(https?://)[^/@\s]+@",
            lambda match: match.group(1) + REDACTED + "@",
            url,
        )
        fragment_separator = redacted.find("#")
        if fragment_separator >= 0:
            redacted = redacted[: fragment_separator + 1] + REDACTED
        return _redact_non_url_text(redacted)
    if not parts.scheme and not parts.netloc:
        return _redact_non_url_text(url)
    hostname = parts.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    if port:
        hostname = f"{hostname}:{port}"
    if parts.username is not None:
        hostname = f"{REDACTED}@{hostname}"
    query = [
        (key, REDACTED if sensitive_key(key) else value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    # URI fragments are client-side opaque data and commonly carry OAuth
    # implicit-flow material.  There is no reliable key/value boundary, so a
    # non-empty fragment is withheld in full.
    fragment = REDACTED if parts.fragment else ""
    return urlunsplit(
        (parts.scheme, hostname, parts.path, urlencode(query, safe="[]"), fragment)
    )


def redact_text(text: str) -> str:
    redacted = _redact_non_url_text(text)
    redacted = _URL.sub(lambda match: redact_url(match.group(0)), redacted)
    return redacted


def _redact_non_url_text(text: str) -> str:
    redacted = _HEADER_LINE.sub(lambda match: match.group(1) + REDACTED, text)
    redacted = _INLINE_SENSITIVE_HEADER.sub(
        lambda match: match.group(1) + REDACTED, redacted
    )
    return _ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}={REDACTED}", redacted
    )


def redact_raw(raw: str) -> str:
    """Redact a wire/body string before it is persisted or printed.

    Valid JSON is parsed so nested sensitive keys and credential-bearing URLs
    receive the same treatment as structured payloads.  For deliberately
    malformed JSON we conservatively redact recognizable scalar pairs.  If a
    sensitive key begins a complex value that cannot be bounded reliably, the
    whole raw value is withheld.
    """

    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        for match in _JSON_COMPLEX_VALUE.finditer(raw):
            try:
                key = json.loads(match.group(1).split(":", 1)[0].strip())
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(key, str) and sensitive_key(key):
                return REDACTED

        def replace_pair(match: re.Match[str]) -> str:
            try:
                key = json.loads(match.group(1))
            except json.JSONDecodeError:
                return match.group(0)
            if isinstance(key, str) and sensitive_key(key):
                return f'{match.group(1)}{match.group(2)}"{REDACTED}"'
            return match.group(0)

        return redact_text(_JSON_PAIR.sub(replace_pair, raw))

    safe = redact_value(decoded)
    if safe != decoded:
        return json.dumps(safe, ensure_ascii=False, separators=(",", ":"))
    return redact_text(raw)


def redact_command(command: Sequence[str]) -> list[str]:
    result: list[str] = []
    redact_next = False
    for item in command:
        if redact_next:
            result.append(REDACTED)
            redact_next = False
            continue
        if _SENSITIVE_FLAG.match(item):
            result.append(item)
            redact_next = True
            continue
        if item.lower() in {"--header", "-h"}:
            result.append(item)
            redact_next = True
            continue
        if item.lower().startswith("--header="):
            result.append(f"{item.split('=', 1)[0]}={REDACTED}")
            continue
        if "=" in item:
            key, _value = item.split("=", 1)
            if sensitive_key(key.lstrip("-")):
                result.append(f"{key}={REDACTED}")
                continue
        if item.startswith(("http://", "https://")):
            result.append(redact_url(item))
        else:
            result.append(redact_text(item))
    return result


def contains_redaction(value: Any) -> bool:
    if value == REDACTED:
        return True
    if isinstance(value, dict):
        return any(contains_redaction(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_redaction(item) for item in value)
    if isinstance(value, str):
        return REDACTED in value
    return False
