"""MCP tools for safe access to Cobalt Strike downloaded files."""

from __future__ import annotations

import hashlib
import json
import logging
import string
from typing import Any
from urllib.parse import quote

from fastmcp import FastMCP

from cs_client import CobaltStrikeClient, mcp_error

logger = logging.getLogger(__name__)

DEFAULT_MAX_DOWNLOAD_TEXT_BYTES = 65_536
MAX_DOWNLOAD_TEXT_BYTES = 1_048_576
TEXT_CONTROL_CHARS = set("\n\r\t\f\b")
PRINTABLE_ASCII = set(string.printable)


def add_cobalt_strike_file_tools(mcp_server: FastMCP, cs_client: CobaltStrikeClient) -> None:
    """Add MCP tools for controlled access to downloaded Cobalt Strike files."""

    @mcp_server.tool()
    async def getDownloadedFileText(file_id: str, max_bytes: int = DEFAULT_MAX_DOWNLOAD_TEXT_BYTES) -> str:
        """Return downloaded file contents when the file is text, otherwise metadata only."""
        result = await fetch_downloaded_file_text(cs_client, file_id=file_id, max_bytes=max_bytes)
        return json.dumps(result, indent=2)

    logger.info("Added MCP file tools")


async def fetch_downloaded_file_text(
    cs_client: CobaltStrikeClient,
    *,
    file_id: str,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_TEXT_BYTES,
) -> dict[str, Any]:
    """Fetch a Cobalt Strike downloaded file and return bounded text content if safe."""
    normalized_file_id = file_id.strip()
    if not normalized_file_id:
        return {"error": "file_id cannot be empty"}

    bounded_max_bytes = _bounded_max_bytes(max_bytes)
    encoded_file_id = quote(normalized_file_id, safe="")
    path = f"/api/v1/data/downloads/{encoded_file_id}"
    client = cs_client.get_authenticated_client()

    try:
        async with client.stream("GET", path) as response:
            content_type = response.headers.get("content-type", "")
            content_length = _parse_content_length(response.headers.get("content-length"))
            content_disposition = response.headers.get("content-disposition")
            response.raise_for_status()

            payload = bytearray()
            truncated = False
            async for chunk in response.aiter_bytes():
                if not chunk:
                    continue
                remaining = bounded_max_bytes + 1 - len(payload)
                if remaining <= 0:
                    truncated = True
                    break
                payload.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    truncated = True
                    break

            if len(payload) > bounded_max_bytes:
                truncated = True
                payload = payload[:bounded_max_bytes]

        data = bytes(payload)
        sha256 = hashlib.sha256(data).hexdigest()
        is_text, encoding, decoded = decode_text_payload(data, content_type)

        result: dict[str, Any] = {
            "file_id": normalized_file_id,
            "endpoint": path,
            "content_type": content_type or None,
            "content_disposition": content_disposition,
            "content_length": content_length,
            "bytes_read": len(data),
            "max_bytes": bounded_max_bytes,
            "truncated": truncated or (content_length is not None and content_length > len(data)),
            "sha256_read_bytes": sha256,
            "is_text": is_text,
        }

        if is_text:
            result.update(
                {
                    "encoding": encoding,
                    "text": decoded,
                }
            )
        else:
            result.update(
                {
                    "encoding": None,
                    "text": None,
                    "message": "Downloaded file appears to be binary; returning metadata only.",
                }
            )

        return result
    except Exception as exc:  # pylint: disable=broad-except
        result = mcp_error("Failed to fetch downloaded file", endpoint=path, exception=str(exc))
        result["file_id"] = normalized_file_id
        return result


def decode_text_payload(data: bytes, content_type: str = "") -> tuple[bool, str | None, str | None]:
    """Decode bytes if they look like text."""
    if not data:
        return True, "utf-8", ""

    lower_content_type = content_type.lower()
    content_type_says_text = (
        lower_content_type.startswith("text/")
        or "json" in lower_content_type
        or "xml" in lower_content_type
        or "javascript" in lower_content_type
        or "yaml" in lower_content_type
        or "csv" in lower_content_type
    )

    if b"\x00" in data[:4096] and not content_type_says_text:
        return False, None, None

    for encoding in ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "cp1252"):
        try:
            text = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if content_type_says_text or _looks_like_text(text):
            return True, encoding, text

    return False, None, None


def _looks_like_text(text: str) -> bool:
    if not text:
        return True
    sample = text[:4096]
    if not sample:
        return True
    printable = 0
    for char in sample:
        # Consider as printable if it's a known allowed control (newline, tab, etc.)
        # or if Python considers the character printable.
        if char in TEXT_CONTROL_CHARS or char.isprintable():
            printable += 1
    return printable / len(sample) >= 0.95


def _bounded_max_bytes(max_bytes: int) -> int:
    try:
        value = int(max_bytes)
    except (TypeError, ValueError):
        value = DEFAULT_MAX_DOWNLOAD_TEXT_BYTES
    return max(1, min(value, MAX_DOWNLOAD_TEXT_BYTES))


def _parse_content_length(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None
