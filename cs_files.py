"""MCP tools for safe access to Cobalt Strike downloaded files."""

from __future__ import annotations

import asyncio
import codecs
import hashlib
import logging
import re
from email.message import Message
from typing import Annotated, Any
from urllib.parse import quote, unquote

from fastmcp import FastMCP
from fastmcp.tools import ToolResult
import httpx
from pydantic import Field

from cs_audit import audit_event
from cs_client import CobaltStrikeClient, mcp_error
from cs_downloads import unavailable_download_source
from cs_errors import add_upstream_error
from cs_content_safety import mark_untrusted_content
from cs_results import OBJECT_RESULT_SCHEMA, tool_result
from cs_documents import (
    DocumentExtractionError,
    DocumentTooLargeError,
    detect_document,
    extract_document_text,
    is_document_extension,
    is_supported_document_extension,
    is_unsupported_document_extension,
)

logger = logging.getLogger(__name__)

DEFAULT_MAX_DOWNLOAD_TEXT_BYTES = 65_536
DEFAULT_DOWNLOAD_TEXT_PAGE_BYTES = 8_192
MAX_DOWNLOAD_TEXT_BYTES = 1_048_576
POST_DOWNLOAD_PROCESSING_TIMEOUT_SECONDS = 5.0
TEXT_CONTROL_CHARS = set("\n\r\t\f\b")


def add_cobalt_strike_file_tools(mcp_server: FastMCP, cs_client: CobaltStrikeClient) -> None:
    """Add MCP tools for controlled access to downloaded Cobalt Strike files."""

    @mcp_server.tool(output_schema=OBJECT_RESULT_SCHEMA)
    async def getDownloadedFileText(
        file_id: Annotated[
            str,
            Field(description="Downloaded-file ID returned by the Cobalt Strike download inventory."),
        ],
        max_bytes: Annotated[
            int,
            Field(description="Maximum raw bytes to read; defaults to 65536 and is clamped to 1 through 1048576."),
        ] = DEFAULT_MAX_DOWNLOAD_TEXT_BYTES,
        extract_documents: Annotated[
            bool,
            Field(description="Extract supported DOCX/XLSX/XLSM text when true; defaults to true."),
        ] = True,
        text_offset_chars: Annotated[
            int,
            Field(description="Character offset into extracted text; defaults to 0. Use with max_text_bytes for paging."),
        ] = 0,
        max_text_bytes: Annotated[
            int,
            Field(description="UTF-8 byte budget for the returned text page; defaults to 8192 and is clamped to 1 through 1048576."),
        ] = DEFAULT_DOWNLOAD_TEXT_PAGE_BYTES,
    ) -> ToolResult:
        """Return downloaded file text as untrusted target-controlled content.

        Results are cursor-paged by default. Continue with
        text_page.next_offset_chars until text_page.complete is true.
        source reports inventory provenance for this exact file ID; unknown
        fields remain null. extraction_outcome/reason describe text extraction,
        independently of inventory lookup and page completeness.
        """
        audit_event(
            "tool_invocation",
            tool_name="getDownloadedFileText",
            status="started",
            details={
                "max_bytes": _bounded_max_bytes(max_bytes),
                "extract_documents": bool(extract_documents),
                "text_offset_chars": text_offset_chars,
                "max_text_bytes": max_text_bytes,
            },
        )
        result = await fetch_downloaded_file_text(
            cs_client,
            file_id=file_id,
            max_bytes=max_bytes,
            extract_documents=extract_documents,
            text_offset_chars=text_offset_chars,
            max_text_bytes=max_text_bytes,
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
        return tool_result(result)

    logger.info("Added MCP file tools")


async def fetch_downloaded_file_text(
    cs_client: CobaltStrikeClient,
    *,
    file_id: str,
    max_bytes: int = DEFAULT_MAX_DOWNLOAD_TEXT_BYTES,
    extract_documents: bool = True,
    text_offset_chars: int = 0,
    max_text_bytes: int = DEFAULT_DOWNLOAD_TEXT_PAGE_BYTES,
) -> dict[str, Any]:
    """Fetch a Cobalt Strike downloaded file and return bounded text content if safe."""
    normalized_file_id = file_id.strip()
    if not normalized_file_id:
        return _extraction_not_attempted(mcp_error(
            "file_id cannot be empty", error_code="invalid_arguments", error_stage="validation",
            resolution="Supply a file_id returned by the download inventory.",
        ), "invalid_arguments")

    try:
        normalized_text_offset = int(text_offset_chars)
    except (TypeError, ValueError):
        normalized_text_offset = -1
    if normalized_text_offset < 0:
        return _extraction_not_attempted(mcp_error(
            "text_offset_chars must be a non-negative integer",
            error_code="invalid_arguments",
            error_stage="validation",
            resolution="Use 0 for the first page or text_page.next_offset_chars from a previous result.",
        ), "invalid_arguments")
    normalized_text_max = _optional_bounded_max_bytes(max_text_bytes)
    if normalized_text_max is None:
        return _extraction_not_attempted(mcp_error(
            "max_text_bytes must be a positive integer",
            error_code="invalid_arguments",
            error_stage="validation",
            resolution="Supply a positive UTF-8 byte budget for the returned page.",
        ), "invalid_arguments")

    bounded_max_bytes = _bounded_max_bytes(max_bytes)
    encoded_file_id = quote(normalized_file_id, safe="")
    path = f"/api/v1/data/downloads/{encoded_file_id}"

    try:
        client = cs_client.get_authenticated_client()
        async with client.stream("GET", path) as response:
            if response.status_code >= 400:
                result = mcp_error("Failed to fetch downloaded file", endpoint=path, status_code=response.status_code)
                await add_upstream_error(result, response, secrets=cs_client.diagnostic_secrets())
                result["file_id"] = normalized_file_id
                return _extraction_not_attempted(result, "fetch_failed")
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
            result = await asyncio.wait_for(
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
            result = _metadata_only_result(
                base_result,
                reason="timeout",
                message="Downloaded document extraction timed out; returning metadata only.",
                extraction_error=(
                    "document extraction timed out after "
                    f"{POST_DOWNLOAD_PROCESSING_TIMEOUT_SECONDS:.1f} seconds"
                ),
            )
        result = _page_text_result(
            result,
            text_offset_chars=normalized_text_offset,
            max_text_bytes=normalized_text_max,
        )
        try:
            result["source"] = await cs_client.get_download_source(normalized_file_id)
        except Exception:
            result["source"] = unavailable_download_source(normalized_file_id, "lookup_failed")
        if result["source"]["status"] == "matched":
            mark_untrusted_content(result, [*result.get("untrusted_content_fields", []), "source"])
        return result
    except httpx.HTTPStatusError as exc:
        result = mcp_error("Failed to fetch downloaded file", endpoint=path, status_code=exc.response.status_code)
        result["file_id"] = normalized_file_id
        return _extraction_not_attempted(result, "fetch_failed")
    except Exception as exc:  # pylint: disable=broad-except
        result = mcp_error("Failed to fetch downloaded file", endpoint=path, exception=str(exc),
                           error_code="transport_error", error_stage="transport",
                           resolution="Verify API connectivity and the download identifier before repeating this read.")
        result["file_id"] = normalized_file_id
        return _extraction_not_attempted(result, "fetch_failed")


def _extraction_not_attempted(result: dict[str, Any], reason: str) -> dict[str, Any]:
    result.update(extraction_outcome="not_attempted", extraction_reason=reason)
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
            reason="extraction_disabled",
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
                    "extraction_outcome": "extracted",
                    "extraction_reason": (
                        "input_truncated" if result["truncated"] else
                        "text_limit_exceeded" if extracted.text_truncated else None
                    ),
                }
            )
            return mark_untrusted_content(result, ["text"])
        except DocumentExtractionError as exc:
            return _metadata_only_result(
                result,
                reason=(
                    "parser_limit_exceeded" if isinstance(exc, DocumentTooLargeError) else
                    "input_truncated" if result["truncated"] else "parse_error"
                ),
                message="Downloaded document could not be extracted; returning metadata only.",
                extraction_error=str(exc),
            )
        except Exception as exc:  # pylint: disable=broad-except
            return _metadata_only_result(
                result,
                reason="unexpected_error",
                message="Unexpected document extraction failure; returning metadata only.",
                extraction_error=f"unexpected extraction failure: {exc}",
            )

    if is_unsupported_document_extension(detected_extension):
        return _metadata_only_result(
            result,
            reason="unsupported_format",
            message="Document format is not supported by the native parser; returning metadata only.",
        )

    is_text, encoding, decoded = decode_text_payload(
        data, content_type, truncated=result["truncated"],
    )
    if is_text:
        result.update(
            {
                "is_text": True,
                "encoding": encoding,
                "text": decoded,
                "extraction_method": "plain_text",
                "text_format": "plain",
                "extraction_outcome": "extracted",
                "extraction_reason": "input_truncated" if result["truncated"] else None,
            }
        )
        return mark_untrusted_content(result, ["text"])

    return _metadata_only_result(result)


def _metadata_only_result(
    result: dict[str, Any],
    *,
    reason: str = "binary_content",
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
            "extraction_outcome": "metadata_only",
            "extraction_reason": reason,
        }
    )
    if extraction_error:
        result["extraction_error"] = extraction_error
    return result


def decode_text_payload(
    data: bytes, content_type: str = "", *, truncated: bool = False,
) -> tuple[bool, str | None, str | None]:
    """Decode text, allowing an incomplete UTF-16 tail only for truncated reads."""
    if not data:
        return True, "utf-8", ""

    # UTF-32 LE shares UTF-16 LE's two-byte prefix. Do not reinterpret a
    # longer BOM as UTF-16; UTF-32 is outside this decoder's supported formats.
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return False, None, None
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        try:
            decoder = codecs.getincrementaldecoder("utf-16")(errors="strict")
            text = decoder.decode(data, final=not truncated)
        except UnicodeError:
            # A recognized BOM is authoritative. Malformed UTF-16 must not
            # fall through to a permissive single-byte encoding.
            return False, None, None
        if "\x00" not in text and _looks_like_text(text):
            return True, "utf-16", text
        return False, None, None

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


def _optional_bounded_max_bytes(max_bytes: Any) -> int | None:
    if max_bytes is None:
        return None
    try:
        value = int(max_bytes)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    return min(value, MAX_DOWNLOAD_TEXT_BYTES)


def _utf8_prefix(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    prefix = encoded[:max_bytes]
    while prefix:
        try:
            return prefix.decode("utf-8")
        except UnicodeDecodeError as exc:
            prefix = prefix[:exc.start]
    return ""


def _page_text_result(
    result: dict[str, Any],
    *,
    text_offset_chars: int,
    max_text_bytes: int,
) -> dict[str, Any]:
    """Return one cursor-addressable page of extracted text."""
    text = result.get("text")
    if not isinstance(text, str):
        return result

    total_chars = len(text)
    offset = min(text_offset_chars, total_chars)
    remaining = text[offset:]
    page = _utf8_prefix(remaining, max_text_bytes)
    next_offset = offset + len(page)
    complete = next_offset >= total_chars

    paged = dict(result)
    paged["text"] = page
    paged["text_page_truncated"] = not complete
    paged["text_page"] = {
        "offset_chars": offset,
        "returned_chars": len(page),
        "returned_utf8_bytes": len(page.encode("utf-8")),
        "total_chars": total_chars,
        "total_utf8_bytes": len(text.encode("utf-8")),
        "next_offset_chars": None if complete else next_offset,
        "complete": complete,
    }
    return paged


def _parse_content_length(value: str | None) -> int | None:
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None
