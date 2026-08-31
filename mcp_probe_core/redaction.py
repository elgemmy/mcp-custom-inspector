"""Conservative redaction for diagnostics, reports, and transcripts.

Redaction happens before values reach any output sink.  It is intentionally
broader for HTTP headers than for ordinary JSON objects: every ``Mcp-Param-*``
header mirrors a tool argument and therefore has to be treated as sensitive,
regardless of its user-chosen name.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from copy import deepcopy
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit

from .protocol import strict_json_loads


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
    "dpop",
    "mcp-session-id",
}

_SENSITIVE_HEADER_PREFIXES = ("mcp-param-",)

_SENSITIVE_QUERY_NAMES = {
    "key",
    "sig",
    "code",
    "code_verifier",
    "client_assertion",
    "assertion",
    "id_token",
    "oauth_token",
    "saml_response",
    "state",
}

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
    r"x-auth-token|x-access-token|dpop|mcp-session-id)\s*:\s*).*$"
)
_INLINE_SENSITIVE_HEADER = re.compile(
    r"(?i)(\b(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|"
    r"x-auth-token|x-access-token|dpop|mcp-session-id)\s*:\s*)[^\r\n]+"
)
_AUTH_SCHEME = re.compile(r"(?i)\b(Bearer|Basic|DPoP)(\s+)[^\s,;]+")
_QUERY_ASSIGNMENT = re.compile(
    r"(?i)([?&](?:key|sig|code|code_verifier|client_assertion|assertion|"
    r"id_token|oauth_token|saml_response|state)=)[^&#\s]+"
)
_EMBEDDED_SENSITIVE_FLAG = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])"
    r"(?P<flag>--?(?:api[-_]?key|auth[-_]?(?:token)?|access[-_]?token|"
    r"refresh[-_]?token|token|password|passwd|secret|client[-_]?secret|"
    r"credential|private[-_]?key|signing[-_]?key|cookie|session[-_]?id))"
    r"(?P<sep>=|\s+)(?P<value>\"[^\"]*\"|'[^']*'|[^\s\"']+)"
)
_ASSIGNMENT = re.compile(r"(?i)\b([A-Z][A-Z0-9_.-]{1,100})=([^\s\"']+)")
_COLON_FIELD = re.compile(
    r"(?im)(^|\s)(?P<key>[A-Za-z][A-Za-z0-9_.-]{1,100})"
    r"(?P<sep>\s*:\s*)(?P<value>[^\r\n]+)"
)
_URL = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

_MAX_BASIC_CREDENTIAL_BYTES = 16 * 1024

# These are protocol vocabulary, not peer-owned opaque values.  Preserving a
# known public method keeps a coincidentally equal short credential from
# destroying transcript structure.  Unknown/extension method names are still
# exact-secret redacted.
_PUBLIC_MCP_METHODS = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "notifications/cancelled",
        "notifications/progress",
        "notifications/message",
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/tools/list_changed",
        "notifications/prompts/list_changed",
        "notifications/roots/list_changed",
        "notifications/tasks/status",
        "ping",
        "tools/list",
        "tools/call",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "resources/subscribe",
        "resources/unsubscribe",
        "prompts/list",
        "prompts/get",
        "logging/setLevel",
        "roots/list",
        "sampling/createMessage",
        "elicitation/create",
        "completion/complete",
        "tasks/get",
        "tasks/result",
        "tasks/list",
        "tasks/cancel",
        "server/discover",
    }
)
_JSONRPC_ENVELOPE_KEYS = frozenset(
    {"jsonrpc", "id", "method", "params", "result", "error"}
)
_JSONRPC_ERROR_KEYS = frozenset({"code", "message", "data"})

_SENSITIVE_COMPACT_SUFFIXES = (
    "apikey",
    "accesskey",
    "authkey",
    "credentialkey",
    "encryptionkey",
    "functionkey",
    "functionskey",
    "licensekey",
    "secretkey",
    "subscriptionkey",
    "webhookkey",
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
    compact = re.sub(r"[^a-z0-9]", "", normalized)
    return (
        normalized in _SENSITIVE_HEADERS
        or normalized.startswith(_SENSITIVE_HEADER_PREFIXES)
        # Custom API gateways use many non-standard names (for example
        # X-Client-Key or GoogleApiKey).  Header values ending in a key marker
        # are safer to over-redact; keep this broader rule header-specific so
        # ordinary JSON properties such as "monkey" remain visible.
        or compact.endswith("key")
        or sensitive_key(normalized)
    )


def expand_known_secrets(values: Iterable[Any]) -> set[str]:
    """Normalize configured credentials for one recorder/run."""
    candidates: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not value or value == REDACTED:
            continue
        candidates.add(value)
        stripped = value.strip()
        if stripped:
            candidates.add(stripped)
        scheme = re.match(r"(?i)^(Bearer|Basic|DPoP)\s+(.+)$", stripped)
        if scheme and scheme.group(2):
            token = scheme.group(2).strip()
            candidates.add(token)
            if scheme.group(1).lower() == "basic":
                candidates.update(_decoded_basic_parts(token))
    return candidates


def _decoded_basic_parts(token: str) -> set[str]:
    """Return bounded Basic-auth components for later echo redaction."""

    if not token or len(token) > (_MAX_BASIC_CREDENTIAL_BYTES * 2):
        return set()
    try:
        padded = token + ("=" * (-len(token) % 4))
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return set()
    if not decoded or len(decoded) > _MAX_BASIC_CREDENTIAL_BYTES:
        return set()
    try:
        text = decoded.decode("utf-8")
    except UnicodeDecodeError:
        text = decoded.decode("latin-1")
    parts = {text}
    if ":" in text:
        username, password = text.split(":", 1)
        if username:
            parts.add(username)
        if password:
            parts.add(password)
    return parts


def _unquoted_secret(value: str) -> str:
    candidate = value.strip()
    if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {
        "'",
        '"',
    }:
        candidate = candidate[1:-1]
    return candidate


def _cookie_values(value: str, *, set_cookie: bool) -> list[str]:
    parts = value.split(";")
    if set_cookie:
        parts = parts[:1]
    found: list[str] = []
    for part in parts:
        if "=" not in part:
            continue
        _name, candidate = part.split("=", 1)
        candidate = _unquoted_secret(candidate)
        if candidate:
            found.extend((candidate, unquote(candidate)))
    return found


def _header_secrets(name: str, value: str) -> list[str]:
    normalized = name.strip().lower()
    found = [value]
    if normalized == "cookie":
        found.extend(_cookie_values(value, set_cookie=False))
    elif normalized == "set-cookie":
        found.extend(_cookie_values(value, set_cookie=True))
    return found


def known_secrets_from_command(command: Sequence[str]) -> set[str]:
    """Extract literal credential values and credential-bearing URLs."""

    found: list[str] = []
    redact_next = False
    header_next = False
    for item in command:
        if item.startswith(("http://", "https://")):
            found.extend(known_secrets_from_url(item))
        if redact_next or header_next:
            found.append(item)
            if header_next and ":" in item:
                name, value = item.split(":", 1)
                found.extend(_header_secrets(name, value.strip()))
            redact_next = False
            header_next = False
            continue
        lowered = item.lower()
        if lowered in {"--header", "-h"}:
            header_next = True
            continue
        if lowered.startswith("--header="):
            header = item.split("=", 1)[1]
            found.append(header)
            if ":" in header:
                name, value = header.split(":", 1)
                found.extend(_header_secrets(name, value.strip()))
            continue
        if "=" in item:
            key, value = item.split("=", 1)
            if not any(character.isspace() for character in key) and sensitive_key(
                key.lstrip("-")
            ):
                found.append(value)
                continue
        if _SENSITIVE_FLAG.match(item) or (
            item.startswith("-") and sensitive_key(item.lstrip("-"))
        ):
            redact_next = True
        for match in _EMBEDDED_SENSITIVE_FLAG.finditer(item):
            found.append(match.group("value").strip("\"'"))
    return expand_known_secrets(found)


def known_secrets_from_url(url: str) -> set[str]:
    """Extract only credential-bearing URL components, never safe values."""

    found: list[str] = []
    userinfo = re.search(r"(?i)^https?://([^/@\s]+)@", url)
    if userinfo:
        for part in userinfo.group(1).split(":", 1):
            if part:
                found.extend((part, unquote(part)))
    query_text = url.partition("?")[2].partition("#")[0]
    for key, value in parse_qsl(query_text, keep_blank_values=True):
        if sensitive_key(key) or key.strip().lower() in _SENSITIVE_QUERY_NAMES:
            found.extend((value, unquote(value)))
    for assignment in query_text.split("&"):
        if "=" not in assignment:
            continue
        key, value = assignment.split("=", 1)
        if sensitive_key(unquote(key)) or unquote(key).strip().lower() in _SENSITIVE_QUERY_NAMES:
            found.extend((value, unquote(value)))
    fragment = url.partition("#")[2]
    if fragment:
        found.extend((fragment, unquote(fragment)))
        for key, value in parse_qsl(fragment, keep_blank_values=True):
            if sensitive_key(key) or key.strip().lower() in _SENSITIVE_QUERY_NAMES:
                found.extend((value, unquote(value)))
    return expand_known_secrets(found)


def known_secrets_from_headers(headers: Mapping[str, Any]) -> set[str]:
    found: list[str] = []
    for key, value in headers.items():
        if not isinstance(value, str):
            continue
        if sensitive_header(str(key)) or re.match(
            r"(?i)^\s*(?:Bearer|Basic|DPoP)\s+", value
        ):
            found.extend(_header_secrets(str(key), value))
    return expand_known_secrets(found)


def known_secrets_from_environment(environment: Mapping[str, Any]) -> set[str]:
    """Extract values from credential-shaped environment variable names."""

    return expand_known_secrets(
        value
        for key, value in environment.items()
        if isinstance(value, str) and sensitive_key(str(key))
    )


def _replace_known_secrets(text: str, known_secrets: Iterable[str]) -> str:
    secrets = sorted(set(known_secrets), key=len, reverse=True)
    for secret in secrets:
        if not secret:
            continue
        if text == secret:
            return REDACTED
        if len(secret) >= 4:
            text = text.replace(secret, REDACTED)
        else:
            text = re.sub(
                rf"(?<![A-Za-z0-9]){re.escape(secret)}(?![A-Za-z0-9])",
                REDACTED,
                text,
            )
    return text


def redact_headers(
    headers: Mapping[str, Any] | None, known_secrets: Iterable[str] = ()
) -> dict[str, Any]:
    return {
        _safe_key(str(key), known_secrets): REDACTED
        if sensitive_header(str(key))
        else redact_value(value, known_secrets=known_secrets)
        for key, value in (headers or {}).items()
    }


def redact_value(
    value: Any,
    parent_key: str | None = None,
    *,
    known_secrets: Iterable[str] = (),
) -> Any:
    if parent_key and sensitive_key(parent_key):
        return REDACTED
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for key, item in value.items():
            original_key = str(key)
            safe_key = _safe_key(original_key, known_secrets)
            if safe_key in output:
                suffix = 2
                while f"{safe_key}#{suffix}" in output:
                    suffix += 1
                safe_key = f"{safe_key}#{suffix}"
            output[safe_key] = (
                REDACTED
                if sensitive_key(original_key)
                else redact_value(
                    item,
                    original_key,
                    known_secrets=known_secrets,
                )
            )
        return output
    if isinstance(value, list):
        return [redact_value(item, known_secrets=known_secrets) for item in value]
    if isinstance(value, tuple):
        return [redact_value(item, known_secrets=known_secrets) for item in value]
    if isinstance(value, str):
        if value.startswith(("http://", "https://")):
            return redact_url(value, known_secrets)
        return redact_text(value, known_secrets)
    return deepcopy(value)


def redact_protocol_payload(
    value: Any, *, known_secrets: Iterable[str] = ()
) -> Any:
    """Redact peer data while preserving the fixed JSON-RPC envelope.

    Configured credentials can be short or can coincidentally equal control
    vocabulary such as ``result`` or ``tools/list``.  Generic key redaction is
    correct for peer-owned extension data, but applying it to the envelope
    makes transcripts impossible to classify or replay.  Only fixed envelope
    keys and the finite public MCP method vocabulary are preserved here.
    """

    secrets = tuple(known_secrets)
    if isinstance(value, list):
        return [redact_protocol_payload(item, known_secrets=secrets) for item in value]
    if not isinstance(value, dict):
        return redact_value(value, known_secrets=secrets)

    output: dict[str, Any] = {}
    for raw_key, item in value.items():
        key = str(raw_key)
        safe_key = key if key in _JSONRPC_ENVELOPE_KEYS else _safe_key(key, secrets)
        if safe_key in output:
            suffix = 2
            while f"{safe_key}#{suffix}" in output:
                suffix += 1
            safe_key = f"{safe_key}#{suffix}"

        if key == "jsonrpc" and item == "2.0":
            safe_item = "2.0"
        elif key == "method" and isinstance(item, str) and item in _PUBLIC_MCP_METHODS:
            safe_item = item
        elif key == "error" and isinstance(item, dict):
            safe_item = _redact_jsonrpc_error(item, secrets)
        else:
            safe_item = redact_value(item, key, known_secrets=secrets)
        output[safe_key] = safe_item
    return output


def _redact_jsonrpc_error(
    value: Mapping[Any, Any], known_secrets: Iterable[str]
) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for raw_key, item in value.items():
        key = str(raw_key)
        safe_key = key if key in _JSONRPC_ERROR_KEYS else _safe_key(key, known_secrets)
        if safe_key in output:
            suffix = 2
            while f"{safe_key}#{suffix}" in output:
                suffix += 1
            safe_key = f"{safe_key}#{suffix}"
        output[safe_key] = redact_value(item, key, known_secrets=known_secrets)
    return output


def _safe_key(key: str, known_secrets: Iterable[str]) -> str:
    return redact_text(key, known_secrets)


def redact_url(url: str, known_secrets: Iterable[str] = ()) -> str:
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
        return _redact_non_url_text(redacted, known_secrets)
    if not parts.scheme and not parts.netloc:
        return _redact_non_url_text(url, known_secrets)
    hostname = parts.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    if port:
        hostname = f"{hostname}:{port}"
    if parts.username is not None:
        hostname = f"{REDACTED}@{hostname}"
    query = [
        (
            key,
            REDACTED
            if sensitive_key(key) or key.strip().lower() in _SENSITIVE_QUERY_NAMES
            else redact_text(value, known_secrets),
        )
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
    ]
    # URI fragments are client-side opaque data and commonly carry OAuth
    # implicit-flow material.  There is no reliable key/value boundary, so a
    # non-empty fragment is withheld in full.
    fragment = REDACTED if parts.fragment else ""
    return urlunsplit(
        (
            parts.scheme,
            _replace_known_secrets(hostname, known_secrets),
            _replace_known_secrets(parts.path, known_secrets),
            urlencode(query, safe="[]"),
            fragment,
        )
    )


def redact_text(text: str, known_secrets: Iterable[str] = ()) -> str:
    redacted = _redact_non_url_text(text, known_secrets)
    redacted = _URL.sub(
        lambda match: redact_url(match.group(0), known_secrets), redacted
    )
    return redacted


def _redact_non_url_text(text: str, known_secrets: Iterable[str] = ()) -> str:
    redacted = _replace_known_secrets(text, known_secrets)
    redacted = _HEADER_LINE.sub(lambda match: match.group(1) + REDACTED, redacted)
    redacted = _INLINE_SENSITIVE_HEADER.sub(
        lambda match: match.group(1) + REDACTED, redacted
    )
    redacted = _AUTH_SCHEME.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}", redacted
    )
    redacted = _QUERY_ASSIGNMENT.sub(
        lambda match: f"{match.group(1)}{REDACTED}", redacted
    )
    redacted = _EMBEDDED_SENSITIVE_FLAG.sub(
        lambda match: f"{match.group('flag')}{match.group('sep')}{REDACTED}", redacted
    )
    redacted = _ASSIGNMENT.sub(
        lambda match: (
            f"{match.group(1)}={REDACTED}"
            if sensitive_key(match.group(1)) or sensitive_header(match.group(1))
            else match.group(0)
        ),
        redacted,
    )
    return _COLON_FIELD.sub(
        lambda match: (
            f"{match.group(1)}{match.group('key')}{match.group('sep')}{REDACTED}"
            if sensitive_key(match.group("key"))
            or sensitive_header(match.group("key"))
            else match.group(0)
        ),
        redacted,
    )


def redact_raw(raw: str, known_secrets: Iterable[str] = ()) -> str:
    """Redact a wire/body string before it is persisted or printed.

    Valid JSON is parsed so nested sensitive keys and credential-bearing URLs
    receive the same treatment as structured payloads.  For deliberately
    malformed JSON we conservatively redact recognizable scalar pairs.  If a
    sensitive key begins a complex value that cannot be bounded reliably, the
    whole raw value is withheld.
    """

    try:
        decoded = strict_json_loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        # A malformed value has no trustworthy closing boundary.  A single
        # linear scan looks only for key/colon syntax; if a credential-shaped
        # key is present, withhold the complete wire value.  Avoid regexes that
        # repeatedly rescan unterminated quoted input: a hostile 64 KiB line of
        # quote characters must remain O(n), not O(n^2).
        if _malformed_has_sensitive_key(raw):
            return REDACTED
        return redact_text(raw, known_secrets)

    safe = redact_protocol_payload(decoded, known_secrets=known_secrets)
    if safe != decoded:
        return json.dumps(safe, ensure_ascii=False, separators=(",", ":"))
    # Strict decoding proves there are no duplicate keys hiding an earlier
    # secret-bearing value. Preserve exact safe framing so a configured secret
    # which happens to equal JSON-RPC vocabulary (for example ``id`` or
    # ``ping``) cannot rewrite the protocol envelope or method.
    return raw


def _malformed_has_sensitive_key(raw: str) -> bool:
    """Recognize quoted or identifier keys in one bounded, linear pass."""

    length = len(raw)
    index = 0
    while index < length:
        character = raw[index]
        if character in {'"', "'"}:
            quote = character
            cursor = index + 1
            decoded: list[str] = []
            while cursor < length:
                current = raw[cursor]
                if current == "\\":
                    if cursor + 1 >= length:
                        cursor = length
                        break
                    escape = raw[cursor + 1]
                    if escape == "u" and cursor + 5 < length:
                        digits = raw[cursor + 2 : cursor + 6]
                        if all(digit in "0123456789abcdefABCDEF" for digit in digits):
                            decoded.append(chr(int(digits, 16)))
                            cursor += 6
                            continue
                    decoded.append(escape)
                    cursor += 2
                    continue
                if current == quote:
                    after = cursor + 1
                    while after < length and raw[after].isspace():
                        after += 1
                    if after < length and raw[after] == ":" and sensitive_key(
                        "".join(decoded)
                    ):
                        return True
                    index = cursor + 1
                    break
                decoded.append(current)
                cursor += 1
            else:
                index = length
            if cursor >= length:
                index = length
            continue

        if character.isalpha() or character == "_":
            cursor = index + 1
            while cursor < length and (
                raw[cursor].isalnum() or raw[cursor] in "_.-"
            ):
                cursor += 1
            after = cursor
            while after < length and raw[after].isspace():
                after += 1
            if after < length and raw[after] == ":" and sensitive_key(
                raw[index:cursor]
            ):
                return True
            index = cursor
            continue
        index += 1
    return False


def redact_command(
    command: Sequence[str], known_secrets: Iterable[str] = ()
) -> list[str]:
    result: list[str] = []
    redact_next = False
    for item in command:
        if redact_next:
            result.append(REDACTED)
            redact_next = False
            continue
        if item.lower().startswith("--header="):
            result.append(f"{item.split('=', 1)[0]}={REDACTED}")
            continue
        if "=" in item:
            key, _value = item.split("=", 1)
            if not any(character.isspace() for character in key) and sensitive_key(
                key.lstrip("-")
            ):
                result.append(f"{key}={REDACTED}")
                continue
        if item.lower() in {"--header", "-h"}:
            result.append(item)
            redact_next = True
            continue
        if _SENSITIVE_FLAG.match(item):
            result.append(item)
            redact_next = True
            continue
        if item.startswith("-") and sensitive_key(item.lstrip("-")):
            result.append(item)
            redact_next = True
            continue
        if item.startswith(("http://", "https://")):
            result.append(redact_url(item, known_secrets))
        else:
            result.append(redact_text(item, known_secrets))
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
