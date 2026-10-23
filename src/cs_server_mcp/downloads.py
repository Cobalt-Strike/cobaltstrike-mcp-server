"""Bounded collection of per-beacon active-download observations."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from typing import Any

from cs_server_mcp.client import ClientCall
from cs_server_mcp.resource_views import identifier, present_active_download

_ACTIVE_DOWNLOAD_CONCURRENCY = 8


def _selected_beacons(
    beacons: Sequence[Mapping[str, Any]], beacon_id: str | None
) -> list[Mapping[str, Any]]:
    if beacon_id is None:
        return list(beacons)
    return [beacon for beacon in beacons if identifier(beacon, "bid") == beacon_id]


async def list_active_downloads(
    call_cs: ClientCall,
    *,
    beacons: Sequence[Mapping[str, Any]],
    beacon_id: str | None,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    """Read every selected beacon or fail; never present a partial scan as complete."""
    async with asyncio.timeout(timeout_seconds):
        # Dead beacons are included: a transfer can stay active while the beacon is offline.
        targets = {
            identifier(beacon, "bid"): beacon.get("computer")
            for beacon in _selected_beacons(beacons, beacon_id)
        }
        remaining = iter(sorted(targets))
        rows: list[dict[str, Any]] = []

        async def worker() -> None:
            for bid in remaining:
                active = await call_cs("list_active_downloads", bid)
                rows.extend(
                    present_active_download(row, beacon_id=bid, host=targets[bid]) for row in active
                )

        workers = [
            asyncio.create_task(worker())
            for _ in range(min(len(targets), _ACTIVE_DOWNLOAD_CONCURRENCY))
        ]
        try:
            await asyncio.gather(*workers)
        finally:
            # gather leaves siblings running when one raises; none may outlive the tool call.
            for task in workers:
                task.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
    return sorted(
        rows, key=lambda row: (row["beacon_id"], row["remote_directory"], row["remote_file_name"])
    )
