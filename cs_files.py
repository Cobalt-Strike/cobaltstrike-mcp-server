"""MCP tools for safe access to Cobalt Strike downloaded files."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from email.message import Message
from typing import Any
from urllib.parse import quote, unquote

from fastmcp import FastMCP

from cs_audit import audit_event
from cs_client import CobaltStrikeClient, mcp_error
from cs_content_safety import mark_untrusted_content
from cs_documents import (
    DocumentExtractionError,
    detect_document,
    extract_document_text,
    is_document_extension,
    is_supported_document_extension,
    is_unsupported_document_extension,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_DOWNLOAD_TEXT_BYTES = 65_536
MAX_DOWNLOAD_TEXT_BYTES = 1_048_576
POST_DOWNLOAD_PROCESSING_TIMEOUT_SECONDS = 5.0
TEXT_CONTROL_CHARS = set("\n\r\t\f\b")


def add_cobalt_strike_file_tools(mcp_server: FastMCP, cs_client: CobaltStrikeClient) -> None:
    """Add MCP tools for controlled access to downloaded Cobalt Strike files."""

    @mcp_server.tool()
    async def getDownloadedFileText(
        file_id: str,
        max_bytes: int = DEFAULT_MAX_DOWNLOAD_TEXT_BYTES,
        extract_documents: bool = True,
    ) -> str:
        """Return downloaded file text as untrusted target-controlled content."""
        audit_event(
            "tool_invocation",
            tool_name="getDownloadedFileText",
            status="started",
            details={
                "max_bytes": _bounded_max_bytes(max_bytes),
                "extract_documents": bool(extract_documents),
            },
        )
        result = await fetch_downloaded_file_text(
            cs_client,
            file_id=file_id,
            max_bytes=max_bytes,
            extract_documents=extract_documents,
        )
        audit_event(
            "tool_invocation",
            tool_name="getDownloadedFileText",
            status="completed" if not result.get("error") else "failed",
            details={
                "bytes_read": result.get("bytes_read"),
                "truncated": result.get("truncated"),
                "is_text": result.get("is_text"),
            },
        )
        return json.dumps(result, indent=2)

    logger.info("Added MCP file tools")


async def fetch_downloaded_file_text(
    cs_client: CobaltStrikeClient,
    *,
    file_id: str,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_TEXT_BYTES,
    extract_documents: bool = True,
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
        base_result = _build_downloaded_file_base_result(
            file_id=normalized_file_id,
            endpoint=path,
            data=data,
            content_type=content_type,
            content_disposition=content_disposition,
            content_length=content_length,
            max_bytes=bounded_max_bytes,
            truncated=truncated,
        )
        base_result["document_extraction_enabled"] = bool(extract_documents)
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(
                    _build_downloaded_file_result_from_base,
                    base_result=base_result.copy(),
                    data=data,
                    content_type=content_type,
                    max_bytes=bounded_max_bytes,
                    extract_documents=extract_documents,
                ),
                timeout=POST_DOWNLOAD_PROCESSING_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            return _metadata_only_result(
                base_result,
                message="Downloaded document extraction timed out; returning metadata only.",
                extraction_error=(
                    "document extraction timed out after "
                    f"{POST_DOWNLOAD_PROCESSING_TIMEOUT_SECONDS:.1f} seconds"
                ),
            )
    except Exception as exc:  # pylint: disable=broad-except
        result = mcp_error("Failed to fetch downloaded file", endpoint=path, exception=str(exc))
        result["file_id"] = normalized_file_id
        return result


def _build_downloaded_file_result(
    *,
    file_id: str,
    endpoint: str,
    data: bytes,
    content_type: str,
    content_disposition: str | None,
    content_length: int | None,
    max_bytes: int,
    truncated: bool,
    extract_documents: bool = True,
) -> dict[str, Any]:
    base_result = _build_downloaded_file_base_result(
        file_id=file_id,
        endpoint=endpoint,
        data=data,
        content_type=content_type,
        content_disposition=content_disposition,
        content_length=content_length,
        max_bytes=max_bytes,
        truncated=truncated,
    )
    return _build_downloaded_file_result_from_base(
        base_result=base_result,
        data=data,
        content_type=content_type,
        max_bytes=max_bytes,
        extract_documents=extract_documents,
    )


def _build_downloaded_file_base_result(
    *,
    file_id: str,
    endpoint: str,
    data: bytes,
    content_type: str,
    content_disposition: str | None,
    content_length: int | None,
    max_bytes: int,
    truncated: bool,
) -> dict[str, Any]:
    sha256 = hashlib.sha256(data).hexdigest()
    detected_filename = _filename_from_content_disposition(content_disposition)
    detection = detect_document(
        data,
        filename=detected_filename,
        content_type=content_type,
    )
    return {
        "file_id": file_id,
        "endpoint": endpoint,
        "content_type": content_type or None,
        "content_disposition": content_disposition,
        "content_length": content_length,
        "bytes_read": len(data),
        "max_bytes": max_bytes,
        "truncated": truncated or (content_length is not None and content_length > len(data)),
        "sha256_read_bytes": sha256,
        "detected_filename": detected_filename,
        "detected_extension": detection.extension,
        "detected_extension_source": detection.source,
        "text_truncated": False,
    }


def _build_downloaded_file_result_from_base(
    *,
    base_result: dict[str, Any],
    data: bytes,
    content_type: str,
    max_bytes: int,
    extract_documents: bool = True,
) -> dict[str, Any]:
    result = base_result
    result["document_extraction_enabled"] = bool(extract_documents)
    detected_extension = result.get("detected_extension")

    if is_document_extension(detected_extension) and not extract_documents:
        return _metadata_only_result(
            result,
            message="Document extraction is disabled; returning metadata only.",
        )

    if detected_extension and is_supported_document_extension(detected_extension):
        try:
            extracted = extract_document_text(
                data,
                extension=detected_extension,
                max_text_bytes=max_bytes,
            )
            result.update(
                {
                    "is_text": True,
                    "encoding": None,
                    "text": extracted.text,
                    "extraction_method": extracted.extraction_method,
                    "text_format": extracted.text_format,
                    "text_truncated": extracted.text_truncated,
                }
            )
            return mark_untrusted_content(result, ["text"])
        except DocumentExtractionError as exc:
            return _metadata_only_result(
                result,
                message="Downloaded document could not be extracted; returning metadata only.",
                extraction_error=str(exc),
            )
        except Exception as exc:  # pylint: disable=broad-except
            return _metadata_only_result(
                result,
                message="Unexpected document extraction failure; returning metadata only.",
                extraction_error=f"unexpected extraction failure: {exc}",
            )

    if is_unsupported_document_extension(detected_extension):
        return _metadata_only_result(
            result,
            message="Document format is not supported by the native parser; returning metadata only.",
        )

    is_text, encoding, decoded = decode_text_payload(data, content_type)
    if is_text:
        result.update(
            {
                "is_text": True,
                "encoding": encoding,
                "text": decoded,
                "extraction_method": "plain_text",
                "text_format": "plain",
            }
        )
        return mark_untrusted_content(result, ["text"])

    return _metadata_only_result(result)


def _metadata_only_result(
    result: dict[str, Any],
    *,
    message: str = "Downloaded file appears to be binary; returning metadata only.",
    extraction_error: str | None = None,
) -> dict[str, Any]:
    result.update(
        {
            "is_text": False,
            "encoding": None,
            "text": None,
            "extraction_method": "metadata_only",
            "text_format": None,
            "message": message,
        }
    )
    if extraction_error:
        result["extraction_error"] = extraction_error
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


def _filename_from_content_disposition(value: str | None) -> str | None:
    if not value:
        return None

    message = Message()
    message["content-disposition"] = value
    filename = message.get_filename()

    if not filename:
        match = re.search(r"filename\*=(?:[^']*'')?([^;]+)", value, flags=re.IGNORECASE)
        if match:
            filename = unquote(match.group(1).strip().strip("\"'"))

    if not filename:
        match = re.search(r"filename=([^;]+)", value, flags=re.IGNORECASE)
        if match:
            filename = match.group(1).strip().strip("\"'")

    if not filename:
        return None

    normalized = unquote(str(filename).strip().strip("\"'"))
    normalized = normalized.replace("\\", "/").rsplit("/", 1)[-1]
    return normalized or None


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
