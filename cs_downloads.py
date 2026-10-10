"""Bounded, client-owned lookups of inventory-reported download provenance."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from time import monotonic
from typing import Any

import httpx

DOWNLOAD_INVENTORY_PATH = "/api/v1/data/downloads"
INVENTORY_CACHE_SECONDS = 30.0
INVENTORY_TIMEOUT_SECONDS = 3.0
MAX_INVENTORY_BYTES = 2_097_152


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record_source(row: dict[str, Any]) -> dict[str, Any]:
    timestamp = row.get("timestamp")
    recorded_at = None
    if type(timestamp) is int:
        try:
            recorded_at = datetime.fromtimestamp(timestamp / 1000, timezone.utc).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    else:
        timestamp = None

    def text(name: str) -> str | None:
        value = row.get(name)
        return value if isinstance(value, str) and value else None

    return {
        "beacon_id": text("bid"),
        "host": text("host"),
        "remote_path": text("path"),
        "file_name": text("name"),
        "inventory_timestamp_ms": timestamp,
        "recorded_at": recorded_at,
    }


def unavailable_download_source(file_id: str, reason: str | None) -> dict[str, Any]:
    """Report unavailable provenance without guessing any source fields."""
    return {
        "file_id": file_id,
        "inventory_endpoint": DOWNLOAD_INVENTORY_PATH,
        "inventory_observed_at": None,
        "status": "unavailable",
        "reason": reason,
        **_record_source({}),
    }


class DownloadInventory:
    """Cache a bounded inventory snapshot for one authenticated API client."""

    def __init__(self) -> None:
        self._records: dict[str, dict[str, Any] | None] = {}
        self._expires_at = 0.0
        self._observed_at: str | None = None
        self._reason: str | None = None
        self._lock = asyncio.Lock()

    async def lookup(self, client: httpx.AsyncClient, file_id: str) -> dict[str, Any]:
        async with self._lock:
            if monotonic() >= self._expires_at:
                try:
                    records = await asyncio.wait_for(
                        self._read(client), timeout=INVENTORY_TIMEOUT_SECONDS,
                    )
                    reason = None
                except (asyncio.TimeoutError, httpx.TimeoutException):
                    records, reason = {}, "timeout"
                except httpx.HTTPStatusError:
                    records, reason = {}, "http_error"
                except _InventoryTooLarge:
                    records, reason = {}, "size_limit_exceeded"
                except (ValueError, TypeError):
                    records, reason = {}, "invalid_response"
                except Exception:  # Metadata enrichment must not discard file content.
                    records, reason = {}, "lookup_failed"
                self._records = records
                self._reason = reason
                self._observed_at = _utc_now() if reason is None else None
                self._expires_at = monotonic() + INVENTORY_CACHE_SECONDS

            source = unavailable_download_source(file_id, self._reason)
            source["inventory_observed_at"] = self._observed_at
            if not self._reason:
                source["status"] = "missing"
            if not self._reason and file_id in self._records:
                record = self._records[file_id]
                if record is None:
                    source["status"] = "ambiguous"
                else:
                    source.update(record, status="matched")
            return source

    @staticmethod
    async def _read(client: httpx.AsyncClient) -> dict[str, dict[str, Any] | None]:
        async with client.stream("GET", DOWNLOAD_INVENTORY_PATH) as response:
            response.raise_for_status()
            body = bytearray()
            async for chunk in response.aiter_bytes():
                if len(body) + len(chunk) > MAX_INVENTORY_BYTES:
                    raise _InventoryTooLarge
                body.extend(chunk)
        rows = json.loads(body)
        if not isinstance(rows, list):
            raise ValueError("Expected a download inventory array")
        records: dict[str, dict[str, Any] | None] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
                raise ValueError("Expected an inventory record with a file ID")
            file_id = row["id"]
            # Duplicate IDs never select the first row or borrow its provenance.
            records[file_id] = None if file_id in records else _record_source(row)
        return records


class _InventoryTooLarge(Exception):
    pass
