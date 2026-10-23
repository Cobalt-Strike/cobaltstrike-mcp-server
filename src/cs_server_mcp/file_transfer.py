"""One-time transfer links for files read from the team server.

MCP gives a server no way to write to the client's disk, so a file is staged in a private
temporary directory and fetched once through a single-use URL. The token is the only
credential: 256 random bits, one fetch, a few minutes.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import mimetypes
import os
import re
import secrets
import shutil
import tempfile
import weakref
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, BinaryIO, Protocol

from mcp.server.mcpserver.exceptions import ToolError

from cs_server_mcp import agent_text

FILES_ROUTE = "/mcp/files"
_CHUNK_BYTES = 65_536
_HEAD_BYTES = 16

# Declared types that say nothing about the bytes.
_GENERIC_MEDIA_TYPES = frozenset({"", "application/octet-stream"})
_IMAGE_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"BM", "image/bmp"),
)
_EXTENSION_RE = re.compile(r"\.[A-Za-z0-9]{1,8}")
_LABEL_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")
_LABEL_MAX_CHARS = 40


class BinaryStream(Protocol):
    """An open file response; the consumer must await ``aclose`` on every path."""

    media_type: str
    filename: str | None
    content_length: int | None

    def chunks(self, size: int = _CHUNK_BYTES) -> AsyncIterator[bytes]: ...

    async def aclose(self) -> None: ...


@dataclass
class StagedFile:
    token: str
    path: Path
    filename: str
    media_type: str
    size_bytes: int
    sha256: str
    expires_at: datetime

    @property
    def url_path(self) -> str:
        return f"{FILES_ROUTE}/{self.token}"


class FileStaging:
    """Staged files, each fetchable once by token."""

    def __init__(self, *, ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self.directory = Path(tempfile.mkdtemp(prefix="cs-mcp-transfer-"))
        self._files: dict[str, StagedFile] = {}
        self._cleanup = weakref.finalize(self, shutil.rmtree, self.directory, ignore_errors=True)

    async def stage(self, stream: BinaryStream, *, name_for: Callable[[str], str]) -> StagedFile:
        """Write the stream to a private file and register a one-time token for it.

        ``name_for`` receives the resolved media type, so the extension can follow it.
        """
        path = self.directory / secrets.token_hex(16)
        try:
            size, digest, head = await _write_stream(stream, path)
        finally:
            await stream.aclose()
        media_type = _resolved_media_type(stream.media_type, head)
        try:
            name = name_for(media_type)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        staged = StagedFile(
            token=secrets.token_urlsafe(32),
            path=path,
            filename=name,
            media_type=media_type,
            size_bytes=size,
            sha256=digest,
            expires_at=datetime.now(UTC) + timedelta(seconds=self.ttl_seconds),
        )
        self._files[staged.token] = staged
        asyncio.get_running_loop().call_later(self.ttl_seconds, self._expire, staged.token)
        return staged

    def claim(self, token: str) -> StagedFile | None:
        staged = self._files.pop(token, None)
        if staged is None:
            return None
        if staged.expires_at <= datetime.now(UTC):
            self.discard(staged)
            return None
        return staged

    def discard(self, staged: StagedFile) -> None:
        staged.path.unlink(missing_ok=True)

    def close(self) -> None:
        self._files.clear()
        self._cleanup()

    def _expire(self, token: str) -> None:
        staged = self._files.pop(token, None)
        if staged is not None:
            self.discard(staged)


def _image_media_type(head: bytes) -> str | None:
    for signature, media_type in _IMAGE_SIGNATURES:
        if head.startswith(signature):
            return media_type
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    return None


def _resolved_media_type(declared: str, head: bytes) -> str:
    # Cobalt Strike serves every screenshot as application/octet-stream, so a generic
    # declared type defers to the image signature.
    normalized = declared.strip()
    if normalized.lower() not in _GENERIC_MEDIA_TYPES:
        return normalized
    return _image_media_type(head) or normalized or "application/octet-stream"


def _file_extension(media_type: str, suggested_name: str | None = None) -> str:
    if media_type.strip().lower() in _GENERIC_MEDIA_TYPES:
        suffix = PurePosixPath(transfer_file_name(suggested_name, "")).suffix
        if _EXTENSION_RE.fullmatch(suffix):
            return suffix
        media_type = "application/octet-stream"
    return mimetypes.guess_extension(media_type) or ""


def fallback_file_name(
    resource: str, label: str, media_type: str, suggested_name: str | None = None
) -> str:
    return f"{resource}-{label}{_file_extension(media_type, suggested_name)}"


def generic_file_name(name: str | None, resource: str) -> bool:
    """Whether a suggested name says no more than the resource word; Cobalt Strike names every
    screenshot ``screenshot.jpg``."""
    if not name:
        return True
    stem = PurePosixPath(transfer_file_name(name, "")).stem
    return stem.strip().lower() in {"", resource}


def capture_file_label(created_at: str | None, title: str | None, fallback: str) -> str:
    """A label such as ``20261019T183819Z-Downloads``."""
    label = _utc_stamp(created_at) or fallback
    slug = _LABEL_UNSAFE_RE.sub("_", title or "").strip("._-")[:_LABEL_MAX_CHARS].rstrip("._-")
    return f"{label}-{slug}" if slug else label


def _utc_stamp(created_at: str | None) -> str | None:
    if not created_at:
        return None
    try:
        moment = datetime.fromisoformat(created_at)
    except ValueError:
        return None
    if moment.tzinfo is not None:
        moment = moment.astimezone(UTC)
    return moment.strftime("%Y%m%dT%H%M%SZ")


def transfer_file_name(source_filename: str | None, fallback: str) -> str:
    if not source_filename:
        return fallback
    name = PureWindowsPath(PurePosixPath(source_filename).name).name.strip()
    if name in {"", ".", ".."} or "\x00" in name:
        return fallback
    return name


def public_base_url(request: Any, fallback: str) -> str:
    """The origin the client reached this server at. Forwarded headers are trusted because the
    URL only goes back to the client that sent them."""
    headers = getattr(request, "headers", None)
    if headers is None:
        return fallback
    url = getattr(request, "url", None)
    scheme = _first(headers.get("x-forwarded-proto")) or getattr(url, "scheme", None) or "http"
    host = (
        _first(headers.get("x-forwarded-host"))
        or headers.get("host")
        or getattr(url, "netloc", None)
    )
    if not host:
        return fallback
    return f"{scheme}://{host}"


def _first(value: str | None) -> str | None:
    if not value:
        return None
    return value.split(",")[0].strip() or None


async def _write_stream(stream: BinaryStream, destination: Path) -> tuple[int, str, bytes]:
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise _staging_failed(exc) from exc

    digest = hashlib.sha256()
    written = 0
    head = b""
    handle: BinaryIO | None = None
    try:
        # Only the write and the close catch OSError: one raised while awaiting the next
        # chunk is the transport's, even when the HTTP library raises it as an OSError.
        handle = os.fdopen(descriptor, "wb")
        async for chunk in stream.chunks(_CHUNK_BYTES):
            try:
                handle.write(chunk)
            except OSError as exc:
                raise _staging_failed(exc) from exc
            digest.update(chunk)
            written += len(chunk)
            if len(head) < _HEAD_BYTES:
                head += chunk[: _HEAD_BYTES - len(head)]
        try:
            handle.close()
        except OSError as exc:
            raise _staging_failed(exc) from exc
        if stream.content_length is not None and written != stream.content_length:
            raise ToolError(
                agent_text.STAGED_LENGTH_MISMATCH.format(
                    announced=stream.content_length, written=written
                )
            )
    except BaseException:
        if handle is not None:
            with contextlib.suppress(OSError):
                handle.close()
        destination.unlink(missing_ok=True)
        raise
    return written, digest.hexdigest(), head


def _staging_failed(exc: OSError) -> ToolError:
    return ToolError(agent_text.STAGING_FAILED.format(reason=exc.strerror or exc))
