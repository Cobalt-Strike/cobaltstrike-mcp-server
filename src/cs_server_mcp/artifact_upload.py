"""One-time upload links that store a PUT body as a team-server artifact.

The Cobalt Strike REST API has no upload call; it lists whatever its artifacts directory
holds, so the body is written there directly and this server must share the team
server's host.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cs_server_mcp import agent_text
from cs_server_mcp.file_transfer import FILES_ROUTE
from cs_server_mcp.tool_errors import InvalidArgument

_PATH_SEPARATORS = re.compile(r"[\\/]")


@dataclass
class UploadSlot:
    token: str
    name: str
    expires_at: datetime

    @property
    def url_path(self) -> str:
        return f"{FILES_ROUTE}/{self.token}"


class UploadSlots:
    """Pending uploads, each claimable once by token."""

    def __init__(self, *, ttl_seconds: float) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.ttl_seconds = ttl_seconds
        self._slots: dict[str, UploadSlot] = {}

    def open(self, *, name: str) -> UploadSlot:
        slot = UploadSlot(
            token=secrets.token_urlsafe(32),
            name=name,
            expires_at=datetime.now(UTC) + timedelta(seconds=self.ttl_seconds),
        )
        self._slots[slot.token] = slot
        asyncio.get_running_loop().call_later(self.ttl_seconds, self._slots.pop, slot.token, None)
        return slot

    def claim(self, token: str) -> UploadSlot | None:
        slot = self._slots.pop(token, None)
        if slot is None or slot.expires_at <= datetime.now(UTC):
            return None
        return slot

    def __len__(self) -> int:
        return len(self._slots)

    def close(self) -> None:
        self._slots.clear()


def artifact_upload_name(name: str) -> str:
    """A bare file name; anything with a path separator is refused so the file cannot leave
    the artifacts directory."""
    candidate = name.strip()
    if not candidate or candidate in {".", ".."} or "\x00" in candidate:
        raise InvalidArgument(agent_text.ARTIFACT_NAME_INVALID)
    if _PATH_SEPARATORS.search(candidate):
        raise InvalidArgument(agent_text.ARTIFACT_NAME_HAS_DIRECTORIES.format(candidate=candidate))
    return candidate


class UploadRejected(Exception):
    """A PUT refused before anything is stored; the route renders it as a JSON error."""

    def __init__(self, status: int, detail: str, next_step: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.next_step = next_step


async def read_upload_body(
    chunks: AsyncIterator[bytes], *, declared_length: int | None, max_bytes: int
) -> tuple[bytes, str]:
    """The body of at most ``max_bytes`` with its hex SHA-256; refused as soon as it grows past
    the cap."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    if declared_length is not None and declared_length > max_bytes:
        raise _too_large(
            agent_text.UPLOAD_DECLARED_SIZE.format(declared_length=declared_length), max_bytes
        )
    buffer = bytearray()
    digest = hashlib.sha256()
    async for chunk in chunks:
        buffer += chunk
        if len(buffer) > max_bytes:
            raise _too_large(agent_text.UPLOAD_OVER_LIMIT, max_bytes)
        digest.update(chunk)
    if not buffer:
        raise UploadRejected(
            400,
            agent_text.UPLOAD_EMPTY_BODY,
            agent_text.UPLOAD_EMPTY_BODY_NEXT_STEP.format(
                new_link=_lower(agent_text.NEW_LINK_NEXT_STEP)
            ),
        )
    return bytes(buffer), digest.hexdigest()


def _too_large(measured: str, max_bytes: int) -> UploadRejected:
    return UploadRejected(
        413,
        agent_text.UPLOAD_TOO_LARGE.format(measured=measured, max_bytes=max_bytes),
        agent_text.UPLOAD_TOO_LARGE_NEXT_STEP.format(
            new_link=_lower(agent_text.NEW_LINK_NEXT_STEP)
        ),
    )


def _lower(sentence: str) -> str:
    return sentence[0].lower() + sentence[1:]


def store_artifact(directory: Path, *, name: str, content: bytes, digest: str) -> Path:
    """Write ``content`` as ``<directory>/<name>``.

    An existing file with the same bytes is kept; one with different bytes is a 409. The
    bytes land in a part file first so the team server never lists a half-written artifact.
    """
    destination = directory / name
    try:
        if destination.exists():
            if hashlib.sha256(destination.read_bytes()).hexdigest() == digest:
                return destination
            raise UploadRejected(
                409,
                agent_text.UPLOAD_CONFLICT.format(name=name),
                agent_text.UPLOAD_CONFLICT_NEXT_STEP,
            )
        part = directory / f".{secrets.token_hex(8)}.part"
        try:
            with open(part, "xb") as handle:
                handle.write(content)
            os.replace(part, destination)
        except BaseException:
            part.unlink(missing_ok=True)
            raise
    except OSError as exc:
        raise UploadRejected(
            500,
            agent_text.UPLOAD_STORE_FAILED.format(directory=directory, reason=exc.strerror or exc),
            agent_text.UPLOAD_STORE_FAILED_NEXT_STEP,
        ) from exc
    return destination
