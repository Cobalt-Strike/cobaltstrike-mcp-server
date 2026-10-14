"""Bounded upstream diagnostics for opt-in custom tool errors."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

import httpx

from cs_content_safety import mark_untrusted_content

MAX_ERROR_BODY_BYTES = 16_384
MAX_UPSTREAM_ERROR_BYTES = 1_024
UPSTREAM_ERROR_UNAVAILABLE = "Upstream error details were unavailable or withheld."
_SENSITIVE_KEY = re.compile(
    r"password|passwd|secret|token|authorization|cookie|credential|api.?key|private.?key",
    re.IGNORECASE,
)
# Discard the rest of a sensitive assignment, including quoted/multiline
# values. Guessing where an arbitrary free-text credential ends risks disclosure.
_SENSITIVE_ASSIGNMENT = re.compile(
    r"\b(?:password|passwd|secret|(?:access[ _-]?|refresh[ _-]?)?token|"
    r"authorization|(?:set[ _-]?)?cookie|credentials?|api[ _-]?key|private[ _-]?key)"
    r"[\"']?\s*(?::|=|\bis\b)\s*[\s\S]*",
    re.IGNORECASE,
)
_AUTH_VALUE = re.compile(r"\b(?:Bearer|Basic)\s+[^\s,;\"']+", re.IGNORECASE)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_URL_USERINFO = re.compile(r"(https?://)[^\s/@]+@", re.IGNORECASE)


def _diagnostic(body: bytes, content_type: str, secrets: Iterable[str]) -> str:
    """Extract selected message fields; never serialize an arbitrary error object."""
    if not body or len(body) > MAX_ERROR_BODY_BYTES:
        return UPSTREAM_ERROR_UNAVAILABLE
    try:
        text = body.decode("utf-8", errors="strict")
        media_type = content_type.split(";", 1)[0].strip().lower()
        secret_values = {value for value in secrets if value}
        if media_type == "application/json" or media_type.endswith("+json"):
            data = json.loads(text)
            if not isinstance(data, dict):
                return UPSTREAM_ERROR_UNAVAILABLE
            # Sensitive values can also be echoed in a selected message field.
            # Bound traversal as well as bytes, and fail closed on deep structures.
            pending = [(data, 0, False)]
            visited = 0
            while pending:
                value, depth, sensitive = pending.pop()
                visited += 1
                if depth > 8 or visited > 256:
                    return UPSTREAM_ERROR_UNAVAILABLE
                if isinstance(value, dict):
                    pending.extend(
                        (item, depth + 1, sensitive or bool(_SENSITIVE_KEY.search(key)))
                        for key, item in value.items()
                    )
                elif isinstance(value, list):
                    pending.extend((item, depth + 1, sensitive) for item in value)
                elif sensitive and isinstance(value, (str, int, float)) and not isinstance(value, bool):
                    secret_values.add(str(value))
            candidates = [data.get(key) for key in ("message", "detail", "title", "error")]
            if isinstance(data.get("error"), dict):
                candidates.extend(data["error"].get(key) for key in ("message", "detail", "title"))
            text = next((item for item in candidates if isinstance(item, str) and item.strip()), "")
        elif media_type != "text/plain":
            return UPSTREAM_ERROR_UNAVAILABLE
    except (ValueError, UnicodeError, RecursionError):
        return UPSTREAM_ERROR_UNAVAILABLE

    # HTML, key material and control sequences are not useful public diagnostics.
    has_markup = re.search(r"<(?:!doctype|/?(?:html|head|body|script))\b", text, re.IGNORECASE)
    has_controls = any(
        (ord(char) < 32 and char not in "\r\n\t") or 127 <= ord(char) <= 159 for char in text
    )
    if not text.strip() or has_markup or "-----BEGIN" in text or has_controls:
        return UPSTREAM_ERROR_UNAVAILABLE
    for value in sorted(secret_values, key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    text = _URL_USERINFO.sub(r"\1[REDACTED]@", text)
    text = _AUTH_VALUE.sub("[REDACTED]", text)
    text = _JWT.sub("[REDACTED]", text)
    text = _SENSITIVE_ASSIGNMENT.sub("[REDACTED]", text)
    text = " ".join(text.split())
    encoded = text.encode("utf-8")
    if len(encoded) > MAX_UPSTREAM_ERROR_BYTES:
        text = encoded[:MAX_UPSTREAM_ERROR_BYTES - 3].decode("utf-8", errors="ignore") + "..."
    return text or UPSTREAM_ERROR_UNAVAILABLE


async def add_upstream_error(
    result: dict[str, Any], response: httpx.Response, *, secrets: Iterable[str] = (),
) -> dict[str, Any]:
    """Enrich an HTTP failure without letting diagnostic reads replace its status."""
    detail = UPSTREAM_ERROR_UNAVAILABLE
    try:
        secret_values = list(secrets)
        for key, value in response.request.headers.items():
            if _SENSITIVE_KEY.search(key):
                secret_values.append(value)
                if key.lower() == "authorization":
                    secret_values.append(value.split(" ", 1)[-1])
        if response.is_stream_consumed:
            body = response.content
        else:
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=MAX_ERROR_BODY_BYTES + 1):
                body.extend(chunk)
                if len(body) > MAX_ERROR_BODY_BYTES:
                    break
        detail = _diagnostic(bytes(body), response.headers.get("content-type", ""), secret_values)
    except (httpx.HTTPError, httpx.StreamError, RuntimeError, ValueError):
        # A closed, interrupted or malformed error body must not turn an HTTP
        # rejection into a transport failure or an uncertain task submission.
        pass
    result["upstream_error"] = detail
    return mark_untrusted_content(result, [*result.get("untrusted_content_fields", []), "upstream_error"])
